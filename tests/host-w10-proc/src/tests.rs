//! lx-proc's policy (`policy.rs`) against the model of the kernel's primitives: every call
//! it serves, its errors in the kernel's order, the compare-and-set retries, and what it
//! leaves to the kernel (approved calls, mechanism-only `prctl` options).

use super::*;
use policy::{serve, utsname, Call, Out};

const EPERM: i64 = -1;

/// Serves call `nr(args)` for the model's caller; `caps` as `LxCall::caps`.
fn call(k: &K, m: &Memory, nr: u64, args: &[u64]) -> Out {
    let (tgid, caps) = {
        let mm = k.0.borrow();
        let t = &mm.threads[&mm.caller];
        (t.tgid, if t.userns { 0 } else { t.eff })
    };
    let mut a = [0u64; 6];
    a[..args.len()].copy_from_slice(args);
    serve(k, m, &Call { nr, args: a, tgid, caps })
}

fn ret(o: Out) -> i64 {
    match o {
        Out::Ret(r) => r,
        Out::Kernel => panic!("sent to the kernel"),
    }
}

fn root() -> K {
    K(RefCell::new(Model::with(100, 0)))
}

fn user(uid: u32) -> K {
    K(RefCell::new(Model::with(100, uid)))
}

fn uid(k: &K) -> [u32; 3] {
    let m = k.0.borrow();
    m.threads[&m.caller].uid
}

const KEEP: u64 = u32::MAX as u64;

// ----------------------------------------------------------------------
// The setuid family
// ----------------------------------------------------------------------

#[test]
fn privileged_setuid_sets_all_three() {
    let k = root();
    assert_eq!(ret(call(&k, &Memory::default(), 105, &[1000])), 0);
    assert_eq!(uid(&k), [1000; 3]);
}

#[test]
fn unprivileged_setuid_only_to_real_or_saved() {
    let k = user(1000);
    k.0.borrow_mut().threads.get_mut(&100).unwrap().uid = [1000, 1000, 1001];
    assert_eq!(ret(call(&k, &Memory::default(), 105, &[1001])), 0);
    assert_eq!(uid(&k), [1000, 1001, 1001]);
    assert_eq!(ret(call(&k, &Memory::default(), 105, &[0])), EPERM);
    // a refused change never reaches the kernel's setter
    assert!(!k.0.borrow().ops.contains(&LXP_CREDS_SET) || uid(&k) == [1000, 1001, 1001]);
}

#[test]
fn capabilities_of_an_own_user_namespace_do_not_count() {
    let k = root();
    {
        let mut m = k.0.borrow_mut();
        let t = m.threads.get_mut(&100).unwrap();
        t.uid = [1000; 3];
        t.gid = [1000; 3];
        t.userns = true;
    }
    assert_eq!(ret(call(&k, &Memory::default(), 105, &[0])), EPERM);
    assert_eq!(ret(call(&k, &Memory::default(), 106, &[0])), EPERM);
}

#[test]
fn setreuid_and_setresuid_follow_the_rules() {
    let k = root();
    assert_eq!(ret(call(&k, &Memory::default(), 113, &[1000, 1001])), 0);
    assert_eq!(uid(&k), [1000, 1001, 1001]);
    // (the kernel drops the capabilities with root's ids; the model leaves that to the test)
    k.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 0;
    // unprivileged swap
    assert_eq!(ret(call(&k, &Memory::default(), 113, &[1001, 1000])), 0);
    assert_eq!(uid(&k), [1001, 1000, 1000]);
    // setresuid keeps what is -1, refuses a foreign id
    assert_eq!(ret(call(&k, &Memory::default(), 117, &[KEEP, 1001, KEEP])), 0);
    assert_eq!(uid(&k), [1001, 1001, 1000]);
    assert_eq!(ret(call(&k, &Memory::default(), 117, &[5, KEEP, KEEP])), EPERM);
}

#[test]
fn group_ids_and_fs_ids() {
    let k = root();
    assert_eq!(ret(call(&k, &Memory::default(), 106, &[50])), 0);
    assert_eq!(k.0.borrow().threads[&100].gid, [50; 3]);
    assert_eq!(ret(call(&k, &Memory::default(), 114, &[KEEP, 60])), 0);
    assert_eq!(ret(call(&k, &Memory::default(), 119, &[70, 70, 70])), 0);
    assert_eq!(k.0.borrow().threads[&100].gid, [70; 3]);
    // setfsuid / setfsgid answer the effective ids
    k.0.borrow_mut().threads.get_mut(&100).unwrap().uid = [3, 4, 5];
    assert_eq!(ret(call(&k, &Memory::default(), 122, &[KEEP])), 4);
    assert_eq!(ret(call(&k, &Memory::default(), 123, &[KEEP])), 70);
}

#[test]
fn setuid_of_a_thread_that_went_away_is_eperm() {
    let k = root();
    k.0.borrow_mut().caller = 100;
    k.0.borrow_mut().threads.get_mut(&100).unwrap().tgid = 100;
    // the setter fails: EPERM, as the kernel's code
    struct Gone;
    impl policy::Kernel for Gone {
        fn op(&self, _sub: u64, _io: &mut LxProcIo) -> i64 {
            -3
        }
    }
    let c = Call { nr: 105, args: [0; 6], tgid: 100, caps: ALL_CAPS };
    assert_eq!(serve(&Gone, &Memory::default(), &c), Out::Ret(EPERM));
}

// ----------------------------------------------------------------------
// setgroups
// ----------------------------------------------------------------------

#[test]
fn setgroups_checks_in_the_kernels_order() {
    let k = root();
    let g: Vec<u8> = [10u32, 20, 30].iter().flat_map(|v| v.to_le_bytes()).collect();
    let m = Memory::with(0x1000, &g);
    assert_eq!(ret(call(&k, &m, 116, &[65537, 0x1000])), EINVAL);
    assert_eq!(ret(call(&k, &m, 116, &[3, 0x9000])), EFAULT);
    assert_eq!(ret(call(&k, &m, 116, &[3, 0x1000])), 0);
    assert_eq!(k.0.borrow().procs[&100].groups, vec![10, 20, 30]);
    assert_eq!(ret(call(&k, &m, 116, &[0, 0])), 0);
    assert!(k.0.borrow().procs[&100].groups.is_empty());
    let u = user(1000);
    // unprivileged: EPERM before the pointer is read
    assert_eq!(ret(call(&u, &m, 116, &[3, 0x9000])), EPERM);
}

// ----------------------------------------------------------------------
// Process groups and sessions
// ----------------------------------------------------------------------

#[test]
fn getpgid_and_getsid() {
    let k = root();
    {
        let mut m = k.0.borrow_mut();
        let p = m.procs.get_mut(&100).unwrap();
        p.pgid = 7;
        p.sid = 3;
    }
    assert_eq!(ret(call(&k, &Memory::default(), 121, &[0])), 7);
    assert_eq!(ret(call(&k, &Memory::default(), 124, &[100])), 3);
    assert_eq!(ret(call(&k, &Memory::default(), 121, &[999])), ESRCH);
    assert_eq!(ret(call(&k, &Memory::default(), 124, &[999])), ESRCH);
    // a pid_t: the upper half of the register is ignored
    assert_eq!(ret(call(&k, &Memory::default(), 121, &[0xFFFF_FFFF_0000_0064])), 7);
}

#[test]
fn setpgid_of_self_and_child_and_others() {
    let k = root();
    k.0.borrow_mut().add(101, 100, 0);
    k.0.borrow_mut().add(200, 1, 0);
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[101, 0])), 0);
    assert_eq!(k.0.borrow().procs[&101].pgid, 101);
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[0, 0])), 0);
    assert_eq!(k.0.borrow().procs[&100].pgid, 100);
    // neither itself nor a child
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[200, 0])), ESRCH);
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[999, 0])), ESRCH);
    // a negative group
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[0, 0xFFFF_FFFF])), EINVAL);
}

#[test]
fn setpgid_decides_again_after_a_lost_race() {
    let k = root();
    k.0.borrow_mut().add(101, 100, 0);
    k.0.borrow_mut().races = 3;
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[101, 101])), 0);
    assert_eq!(k.0.borrow().procs[&101].pgid, 101);
    assert_eq!(k.0.borrow().ops.iter().filter(|&&o| o == LXP_PGRP_SET).count(), 4);
}

#[test]
fn a_session_leader_cannot_change_its_group() {
    let k = root();
    {
        let mut m = k.0.borrow_mut();
        let p = m.procs.get_mut(&100).unwrap();
        p.pgid = 100;
        p.sid = 100;
    }
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[0, 0])), EPERM);
}

#[test]
fn setsid_makes_a_session_once() {
    let k = root();
    assert_eq!(ret(call(&k, &Memory::default(), 112, &[])), 100);
    let p = k.0.borrow().procs[&100].clone();
    assert_eq!((p.pgid, p.sid), (100, 100));
    // now a group leader
    assert_eq!(ret(call(&k, &Memory::default(), 112, &[])), EPERM);
}

#[test]
fn setsid_is_refused_while_another_process_is_in_the_group_named_by_its_pid() {
    let k = root();
    k.0.borrow_mut().add(300, 1, 0);
    k.0.borrow_mut().procs.get_mut(&300).unwrap().pgid = 100;
    assert_eq!(ret(call(&k, &Memory::default(), 112, &[])), EPERM);
}

#[test]
fn setsid_decides_again_after_a_lost_race() {
    let k = root();
    k.0.borrow_mut().races = 2;
    assert_eq!(ret(call(&k, &Memory::default(), 112, &[])), 100);
}

#[test]
fn a_race_that_never_ends_gives_up_with_eagain() {
    let k = root();
    k.0.borrow_mut().races = 1000;
    assert_eq!(ret(call(&k, &Memory::default(), 112, &[])), EAGAIN);
    k.0.borrow_mut().add(101, 100, 0);
    assert_eq!(ret(call(&k, &Memory::default(), 109, &[101, 0])), EAGAIN);
}

// ----------------------------------------------------------------------
// Limits
// ----------------------------------------------------------------------

fn pair(s: u64, h: u64) -> Vec<u8> {
    let mut v = s.to_le_bytes().to_vec();
    v.extend_from_slice(&h.to_le_bytes());
    v
}

#[test]
fn setrlimit_rules_and_order() {
    let k = user(1000);
    let m = Memory::with(0x2000, &pair(512, 4096));
    assert_eq!(ret(call(&k, &m, 160, &[16, 0x2000])), EINVAL);
    assert_eq!(ret(call(&k, &m, 160, &[4, 0x9000])), EFAULT);
    assert_eq!(ret(call(&k, &m, 160, &[4, 0x2000])), 0);
    assert_eq!(k.0.borrow().procs[&100].limits[4], (512, 4096));
    // soft above hard
    let m2 = Memory::with(0x2000, &pair(5000, 4096));
    assert_eq!(ret(call(&k, &m2, 160, &[4, 0x2000])), EINVAL);
    // raising the hard limit needs CAP_SYS_RESOURCE
    let m3 = Memory::with(0x2000, &pair(10, 8192));
    assert_eq!(ret(call(&k, &m3, 160, &[4, 0x2000])), EPERM);
    let r = root();
    assert_eq!(ret(call(&r, &m3, 160, &[4, 0x2000])), 0);
    // RLIMIT_NOFILE's hard limit stops at the descriptor table
    let m4 = Memory::with(0x2000, &pair(10, 4096));
    r.0.borrow_mut().procs.get_mut(&100).unwrap().limits[7] = (1024, 1024);
    assert_eq!(ret(call(&r, &m4, 160, &[7, 0x2000])), EPERM);
}

#[test]
fn setrlimit_decides_again_after_a_lost_race() {
    let k = root();
    k.0.borrow_mut().races = 2;
    let m = Memory::with(0x2000, &pair(1, 2));
    assert_eq!(ret(call(&k, &m, 160, &[3, 0x2000])), 0);
    assert_eq!(k.0.borrow().procs[&100].limits[3], (1, 2));
}

#[test]
fn prlimit_of_itself_reports_the_old_value() {
    let k = user(1000);
    let m = Memory::with(0x2000, &pair(100, 200));
    assert_eq!(ret(call(&k, &m, 302, &[0, 4, 0x2000, 0x3000])), 0);
    assert_eq!(k.0.borrow().procs[&100].limits[4], (100, 200));
    assert_eq!(m.written.borrow()[&0x3000], pair(1024, 4096));
    // only reading
    assert_eq!(ret(call(&k, &m, 302, &[100, 4, 0, 0x3000])), 0);
    assert_eq!(m.written.borrow()[&0x3000], pair(100, 200));
    // bad resource, bad pid, bad output
    assert_eq!(ret(call(&k, &m, 302, &[0, 16, 0, 0])), EINVAL);
    assert_eq!(ret(call(&k, &m, 302, &[999, 4, 0, 0])), ESRCH);
    assert_eq!(ret(call(&k, &m, 302, &[0xFFFF_FFFF, 4, 0, 0])), ESRCH);
    let mut bad = Memory::with(0x2000, &pair(1, 2));
    bad.bad_out.push(0x3000);
    assert_eq!(ret(call(&k, &bad, 302, &[0, 4, 0, 0x3000])), EFAULT);
}

#[test]
fn prlimit_of_another_process() {
    let k = user(1000);
    k.0.borrow_mut().add(200, 1, 1000);
    k.0.borrow_mut().add(300, 1, 0);
    k.0.borrow_mut().add(400, 1, 1000);
    k.0.borrow_mut().threads.get_mut(&400).unwrap().service = true;
    let m = Memory::default();
    // the same user: yes; root's: no; a service: no
    assert_eq!(ret(call(&k, &m, 302, &[200, 4, 0, 0x3000])), 0);
    assert_eq!(ret(call(&k, &m, 302, &[300, 4, 0, 0x3000])), EPERM);
    assert_eq!(ret(call(&k, &m, 302, &[400, 4, 0, 0x3000])), EPERM);
    // CAP_SYS_RESOURCE may (also on root's); CAP_SYS_PTRACE may
    k.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 1 << 24;
    assert_eq!(ret(call(&k, &m, 302, &[300, 4, 0, 0x3000])), 0);
    k.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 1 << 19;
    assert_eq!(ret(call(&k, &m, 302, &[300, 4, 0, 0x3000])), 0);
    // a user whose saved id differs is not "the same credentials"
    k.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 0;
    k.0.borrow_mut().threads.get_mut(&200).unwrap().uid = [1000, 1000, 0];
    assert_eq!(ret(call(&k, &m, 302, &[200, 4, 0, 0x3000])), EPERM);
}

// ----------------------------------------------------------------------
// prctl
// ----------------------------------------------------------------------

#[test]
fn prctl_names() {
    let k = root();
    let m = Memory::with(0x4000, b"a-very-long-thread-name\0");
    assert_eq!(ret(call(&k, &m, 157, &[15, 0x4000])), 0);
    assert_eq!(&k.0.borrow().threads[&100].comm, b"a-very-long-thr\0");
    assert_eq!(ret(call(&k, &m, 157, &[16, 0x5000])), 0);
    assert_eq!(m.written.borrow()[&0x5000], b"a-very-long-thr\0".to_vec());
    // a bad pointer
    assert_eq!(ret(call(&k, &m, 157, &[15, 0x9000])), EFAULT);
    let mut bad = Memory::default();
    bad.bad_out.push(0x5000);
    assert_eq!(ret(call(&k, &bad, 157, &[16, 0x5000])), EFAULT);
}

#[test]
fn prctl_name_just_before_the_end_of_memory() {
    // no NUL within the readable bytes: read one at a time up to 15
    let k = root();
    let m = Memory::with(0x4000, b"short");
    assert_eq!(ret(call(&k, &m, 157, &[15, 0x4000])), EFAULT);
    let m = Memory::with(0x4000, b"exactly-fifteen-");
    assert_eq!(ret(call(&k, &m, 157, &[15, 0x4000])), 0);
    assert_eq!(&k.0.borrow().threads[&100].comm[..15], b"exactly-fifteen");
}

#[test]
fn prctl_dumpable_pdeathsig_keepcaps_subreaper_nnp() {
    let k = user(1000);
    let m = Memory::default();
    assert_eq!(ret(call(&k, &m, 157, &[3])), 1);
    assert_eq!(ret(call(&k, &m, 157, &[4, 0])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[3])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[4, 2])), EINVAL);
    assert_eq!(ret(call(&k, &m, 157, &[1, 65])), EINVAL);
    assert_eq!(ret(call(&k, &m, 157, &[1, 10])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[2, 0x6000])), 0);
    assert_eq!(m.written.borrow()[&0x6000], 10i32.to_le_bytes().to_vec());
    assert_eq!(ret(call(&k, &m, 157, &[8, 2])), EINVAL);
    assert_eq!(ret(call(&k, &m, 157, &[8, 1])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[7])), 1);
    assert_eq!(ret(call(&k, &m, 157, &[36, 5])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[37, 0x6008])), 0);
    assert_eq!(m.written.borrow()[&0x6008], 1i32.to_le_bytes().to_vec());
    assert_eq!(ret(call(&k, &m, 157, &[39])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[38, 0])), EINVAL);
    assert_eq!(ret(call(&k, &m, 157, &[38, 1])), 0);
    assert_eq!(ret(call(&k, &m, 157, &[39])), 1);
}

#[test]
fn prctl_options_of_the_kernels_mechanism_go_to_the_kernel() {
    let k = root();
    let m = Memory::default();
    // PR_GET_SECCOMP, PR_SET_SECCOMP, PR_GET_AUXV, PR_SET_MM, Hydra's access attributes, an
    // unknown option: the kernel's own code, without approval (it checks for itself)
    for opt in [21u64, 22, 0x41555856, 35, 0x4859_0001, 12345] {
        assert_eq!(call(&k, &m, 157, &[opt]), Out::Kernel, "option {opt:#x}");
    }
    assert!(k.0.borrow().approved.is_empty());
}

// ----------------------------------------------------------------------
// UTS names
// ----------------------------------------------------------------------

#[test]
fn uname_is_the_kernels_layout() {
    let u = utsname(b"host", b"dom");
    assert_eq!(&u[0..6], b"Linux\0");
    assert_eq!(&u[65..70], b"host\0");
    assert_eq!(&u[130..142], b"6.8.0-hydra\0");
    assert_eq!(&u[195..227], b"#1 SMP PREEMPT Hydra Microkernel");
    assert_eq!(&u[260..267], b"x86_64\0");
    assert_eq!(&u[325..329], b"dom\0");
    // a 64-byte name keeps its NUL in the 65th byte
    let long = [b'h'; 70];
    let u = utsname(&long, b"");
    assert_eq!(u[65 + 63], b'h');
    assert_eq!(u[65 + 64], 0);
}

#[test]
fn uname_and_sethostname() {
    let k = root();
    let m = Memory::with(0x7000, b"newhost");
    assert_eq!(ret(call(&k, &m, 170, &[0x7000, 7])), 0);
    assert_eq!(ret(call(&k, &m, 171, &[0x7000, 3])), 0);
    assert_eq!(ret(call(&k, &m, 63, &[0x8000])), 0);
    let u = m.written.borrow()[&0x8000].clone();
    assert_eq!(&u[65..73], b"newhost\0");
    assert_eq!(&u[325..329], b"new\0");
    // errors in the kernel's order: length, memory, permission
    assert_eq!(ret(call(&k, &m, 170, &[0x7000, 65])), EINVAL);
    assert_eq!(ret(call(&k, &m, 170, &[0x9000, 5])), EFAULT);
    let u = user(1000);
    assert_eq!(ret(call(&u, &m, 170, &[0x9000, 5])), EFAULT);
    assert_eq!(ret(call(&u, &m, 170, &[0x7000, 5])), EPERM);
    // an empty name needs no memory
    assert_eq!(ret(call(&k, &Memory::default(), 170, &[0, 0])), 0);
    // in a user namespace of its own, CAP_SYS_ADMIN there is enough
    {
        let mut mm = u.0.borrow_mut();
        let t = mm.threads.get_mut(&100).unwrap();
        t.eff = ALL_CAPS;
        t.userns = true;
    }
    assert_eq!(ret(call(&u, &m, 170, &[0x7000, 7])), 0);
    // uname to a bad buffer
    let mut bad = Memory::default();
    bad.bad_out.push(0x8000);
    assert_eq!(ret(call(&k, &bad, 63, &[0x8000])), EFAULT);
}

// ----------------------------------------------------------------------
// unshare, setns
// ----------------------------------------------------------------------

const NEWUTS: u64 = 0x0400_0000;
const NEWUSER: u64 = 0x1000_0000;
const NEWNET: u64 = 0x4000_0000;
const NEWPID: u64 = 0x2000_0000;

#[test]
fn unshare_decides_and_leaves_the_making_to_the_kernel() {
    let k = root();
    let m = Memory::default();
    assert_eq!(call(&k, &m, 272, &[0x8000_0000]), Out::Ret(EINVAL));
    // no namespace asked: nothing to do
    assert_eq!(call(&k, &m, 272, &[0x200]), Out::Ret(0));
    assert!(k.0.borrow().approved.is_empty());
    assert_eq!(call(&k, &m, 272, &[NEWUTS | NEWNET]), Out::Kernel);
    assert_eq!(k.0.borrow().approved, vec![(100, 272)]);
    // a user namespace needs one thread
    k.0.borrow_mut().procs.get_mut(&100).unwrap().threads = 2;
    assert_eq!(call(&k, &m, 272, &[NEWUSER]), Out::Ret(EINVAL));
    assert_eq!(call(&k, &m, 272, &[NEWUTS]), Out::Kernel);
}

#[test]
fn unshare_without_cap_sys_admin() {
    let k = user(1000);
    let m = Memory::default();
    assert_eq!(call(&k, &m, 272, &[NEWUTS]), Out::Ret(EPERM));
    // a new user namespace gives the capability for the rest
    assert_eq!(call(&k, &m, 272, &[NEWUSER | NEWUTS]), Out::Kernel);
}

/// Namespace facts: owner, relation bits, PID relation, threads.
fn facts(owner: u64, rel: u64, pid_rel: u64) -> [u64; 13] {
    let mut f = [0u64; 13];
    f[8] = owner;
    f[9] = rel;
    f[10] = pid_rel;
    f[11] = 1;
    f
}

#[test]
fn setns_rules() {
    let k = root();
    let m = Memory::default();
    // the descriptor's errors come back as they are
    k.0.borrow_mut().ns_fd = Some(Err(EINVAL));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EINVAL));
    k.0.borrow_mut().ns_fd = None;
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(-9));
    // a vanished target
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWUTS)));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(ESRCH));
    // root joins a UTS namespace
    k.0.borrow_mut().ns.insert(500, facts(0, 3, 0));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Kernel);
    assert_eq!(k.0.borrow().approved, vec![(100, 308)]);
    // the user namespace one is in already
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWUSER)));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EINVAL));
    // a PID namespace not below ours
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWPID)));
    k.0.borrow_mut().ns.insert(500, facts(0, 3, 2));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EINVAL));
    k.0.borrow_mut().ns.insert(500, facts(0, 3, 1));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Kernel);
}

#[test]
fn setns_of_a_user_namespace() {
    let k = user(1000);
    let m = Memory::default();
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWUSER)));
    // below ours and owned by us: yes
    k.0.borrow_mut().ns.insert(500, facts(1000, 1, 0));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Kernel);
    // owned by another user: no
    k.0.borrow_mut().ns.insert(500, facts(1001, 1, 0));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EPERM));
    // not below ours: no
    k.0.borrow_mut().ns.insert(500, facts(1000, 0, 0));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EPERM));
    // more than one thread
    k.0.borrow_mut().ns.insert(500, facts(1000, 1, 0));
    k.0.borrow_mut().procs.get_mut(&100).unwrap().threads = 3;
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EINVAL));
    // other kinds without CAP_SYS_ADMIN
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWNET)));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Ret(EPERM));
    // ... allowed together with a user namespace that gives it
    k.0.borrow_mut().procs.get_mut(&100).unwrap().threads = 1;
    k.0.borrow_mut().ns_fd = Some(Ok((500, NEWNET | NEWUSER)));
    assert_eq!(call(&k, &m, 308, &[3, 0]), Out::Kernel);
}

// ----------------------------------------------------------------------
// syslog, acct
// ----------------------------------------------------------------------

#[test]
fn syslog_and_acct_need_their_capabilities() {
    let u = user(1000);
    let m = Memory::default();
    assert_eq!(call(&u, &m, 103, &[3, 0x100, 10]), Out::Ret(EPERM));
    assert_eq!(call(&u, &m, 163, &[0]), Out::Ret(EPERM));
    assert!(u.0.borrow().approved.is_empty());
    // CAP_SYSLOG alone, CAP_SYS_ADMIN alone, CAP_SYS_PACCT
    u.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 1 << 34;
    assert_eq!(call(&u, &m, 103, &[10]), Out::Kernel);
    u.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 1 << 21;
    assert_eq!(call(&u, &m, 103, &[10]), Out::Kernel);
    u.0.borrow_mut().threads.get_mut(&100).unwrap().eff = 1 << 20;
    assert_eq!(call(&u, &m, 163, &[0]), Out::Kernel);
    assert_eq!(u.0.borrow().approved, vec![(100, 103), (100, 103), (100, 163)]);
    // capabilities of an own user namespace do not count
    {
        let mut mm = u.0.borrow_mut();
        let t = mm.threads.get_mut(&100).unwrap();
        t.eff = ALL_CAPS;
        t.userns = true;
    }
    assert_eq!(call(&u, &m, 103, &[10]), Out::Ret(EPERM));
}

#[test]
fn an_unknown_call_is_enosys() {
    let k = root();
    assert_eq!(call(&k, &Memory::default(), 39, &[]), Out::Ret(-38));
}

// ----------------------------------------------------------------------
// The shared rules (the kernel's proc_rules.rs, built into lx-proc)
// ----------------------------------------------------------------------

#[test]
fn the_rules_are_the_kernels() {
    use policy::rules;
    assert_eq!(rules::set_id([1, 2, 3], 3, false), Ok([1, 3, 3]));
    assert_eq!(rules::set_res([1, 2, 3], [rules::KEEP, 1, rules::KEEP], false), Ok([1, 1, 3]));
    assert_eq!(rules::set_limit(7, (10, 20), (10, 30), true, 25), Err(-1));
}
