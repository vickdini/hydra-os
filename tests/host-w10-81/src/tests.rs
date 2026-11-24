use super::*;
use rules::*;

fn who(uid: u32, gid: u32, caps: u64) -> Who {
    Who { uid: [uid; 3], gid: [gid; 3], caps, in_userns: false, seccomp: false }
}

fn tgt(uid: u32, gid: u32) -> Target {
    Target { tgid: 50, tid: 51, uid: [uid; 3], gid: [gid; 3], same: false, service: false, within: true, dumpable: 1 }
}

const PTRACE: u64 = 1 << CAP_SYS_PTRACE;
const ADMIN: u64 = 1 << CAP_SYS_ADMIN;
const PERFMON: u64 = 1 << CAP_PERFMON;
const RD: u32 = MODE_READ | MODE_REALCREDS;
const AT: u32 = MODE_ATTACH | MODE_REALCREDS;

// ---- the access rule ----

#[test]
fn own_process_always() {
    let t = Target { same: true, service: true, dumpable: 0, ..tgt(5, 5) };
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &t), Ok(()));
}

#[test]
fn service_never_even_with_cap() {
    let t = Target { service: true, ..tgt(1000, 1000) };
    assert_eq!(may_access(AT, &who(0, 0, u64::MAX), &t), Err(EPERM));
}

#[test]
fn same_ids_dumpable() {
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &tgt(1000, 1000)), Ok(()));
}

#[test]
fn other_user_refused() {
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &tgt(1001, 1000)), Err(EPERM));
}

#[test]
fn other_group_refused() {
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &tgt(1000, 1001)), Err(EPERM));
}

#[test]
fn set_id_target_refused() {
    // a set-user-ID program: euid differs; a set-group-ID program: egid differs
    let mut t = tgt(1000, 1000);
    t.uid[1] = 0;
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &t), Err(EPERM));
    let mut t = tgt(1000, 1000);
    t.gid[2] = 5;
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &t), Err(EPERM));
}

#[test]
fn not_dumpable_refused_without_cap() {
    let t = Target { dumpable: 0, ..tgt(1000, 1000) };
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &t), Err(EPERM));
    let t = Target { dumpable: 2, ..tgt(1000, 1000) };
    assert_eq!(may_access(AT, &who(1000, 1000, 0), &t), Err(EPERM));
}

#[test]
fn cap_sys_ptrace_over_anyone() {
    let t = Target { dumpable: 0, ..tgt(1001, 1001) };
    assert_eq!(may_access(AT, &who(1000, 1000, PTRACE), &t), Ok(()));
}

#[test]
fn cap_only_within_its_user_namespace() {
    let t = Target { within: false, ..tgt(1001, 1001) };
    let mut w = who(1000, 1000, PTRACE);
    w.in_userns = true;
    assert_eq!(may_access(AT, &w, &t), Err(EPERM));
    let t = Target { within: true, ..t };
    assert_eq!(may_access(AT, &w, &t), Ok(()));
    // not dumpable, cap not counting there: refused even with matching ids
    let t = Target { within: false, dumpable: 0, ..tgt(1000, 1000) };
    assert_eq!(may_access(AT, &w, &t), Err(EPERM));
}

#[test]
fn fscreds_compare_effective_realcreds_real() {
    let w = Who { uid: [1000, 1001, 1001], gid: [1000, 1001, 1001], caps: 0, in_userns: false, seccomp: false };
    assert_eq!(may_access(MODE_READ | MODE_FSCREDS, &w, &tgt(1001, 1001)), Ok(()));
    assert_eq!(may_access(MODE_READ | MODE_REALCREDS, &w, &tgt(1001, 1001)), Err(EPERM));
    assert_eq!(may_access(MODE_READ | MODE_REALCREDS, &w, &tgt(1000, 1000)), Ok(()));
}

#[test]
fn capable_needs_first_namespace() {
    let mut w = who(0, 0, ADMIN);
    assert!(w.capable(CAP_SYS_ADMIN));
    w.in_userns = true;
    assert!(!w.capable(CAP_SYS_ADMIN));
    assert!(!who(0, 0, 0).capable(CAP_SYS_ADMIN));
}

// ---- the decisions ----

fn ptrace_facts(kind: u8, w: Who, t: Option<Target>, extra: u32) -> Facts {
    Facts { nr: NR_PTRACE, kind, extra, cpu: 0, who: w, t: [t, None] }
}

#[test]
fn attach_and_seize() {
    let w = who(1000, 1000, 0);
    assert_eq!(decide(&ptrace_facts(K_ATTACH, w, Some(tgt(1000, 1000)), 0)), Ok(()));
    assert_eq!(decide(&ptrace_facts(K_SEIZE, w, Some(tgt(1000, 1000)), 0)), Ok(()));
    assert_eq!(decide(&ptrace_facts(K_ATTACH, w, Some(tgt(1001, 1000)), 0)), Err(EPERM));
    assert_eq!(decide(&ptrace_facts(K_ATTACH, w, None, 0)), Err(ESRCH));
    // one's own process: refused (unlike the access rule)
    let me = Target { same: true, ..tgt(1000, 1000) };
    assert_eq!(decide(&ptrace_facts(K_ATTACH, w, Some(me), 0)), Err(EPERM));
}

#[test]
fn suspend_seccomp_needs_admin_and_no_seccomp() {
    let o = O_SUSPEND_SECCOMP as u32;
    let user = who(1000, 1000, 0);
    assert_eq!(decide(&ptrace_facts(K_SEIZE, user, Some(tgt(1000, 1000)), o)), Err(EPERM));
    assert_eq!(decide(&ptrace_facts(K_SETOPTIONS, user, None, o)), Err(EPERM));
    assert_eq!(decide(&ptrace_facts(K_SETOPTIONS, user, None, 1)), Ok(()));
    let root = who(0, 0, ADMIN | PTRACE);
    assert_eq!(decide(&ptrace_facts(K_SEIZE, root, Some(tgt(1000, 1000)), o)), Ok(()));
    assert_eq!(decide(&ptrace_facts(K_SETOPTIONS, root, None, o)), Ok(()));
    let mut filtered = root;
    filtered.seccomp = true;
    assert_eq!(decide(&ptrace_facts(K_SETOPTIONS, filtered, None, o)), Err(EPERM));
    // ATTACH ignores the data word
    assert_eq!(decide(&ptrace_facts(K_ATTACH, user, Some(tgt(1000, 1000)), o)), Ok(()));
}

#[test]
fn traceme_and_unknown_kind() {
    assert_eq!(decide(&ptrace_facts(K_TRACEME, who(1000, 1000, 0), None, 0)), Ok(()));
    assert_eq!(decide(&ptrace_facts(0, who(1000, 1000, 0), None, 0)), Err(EINVAL));
}

fn perf(w: Who, kernel: bool, pid: u32, cpu: i32, t: Option<Target>) -> Facts {
    Facts { nr: NR_PERF_EVENT_OPEN, kind: 0, extra: kernel as u32 * PERF_KERNEL | pid << PERF_PID_SHIFT, cpu, who: w, t: [t, None] }
}

#[test]
fn perf_paranoid_two() {
    let u = who(1000, 1000, 0);
    assert_eq!(decide(&perf(u, false, PERF_PID_SELF, -1, None)), Ok(()));
    assert_eq!(decide(&perf(u, true, PERF_PID_SELF, -1, None)), Err(EACCES));
    assert_eq!(decide(&perf(u, false, PERF_PID_CPU, 0, None)), Err(EACCES));
    assert_eq!(decide(&perf(u, false, PERF_PID_CPU, -1, None)), Err(EINVAL));
    assert_eq!(decide(&perf(u, false, PERF_PID_SELF, 5, None)), Err(EINVAL));
    assert_eq!(decide(&perf(u, false, PERF_PID_SELF, -2, None)), Err(EINVAL));
    assert_eq!(decide(&perf(u, false, PERF_PID_BAD, -1, None)), Err(ESRCH));
    assert_eq!(decide(&perf(u, false, PERF_PID_OTHER, -1, None)), Err(ESRCH));
    assert_eq!(decide(&perf(u, false, PERF_PID_OTHER, -1, Some(tgt(1000, 1000)))), Ok(()));
    assert_eq!(decide(&perf(u, false, PERF_PID_OTHER, -1, Some(tgt(1001, 1000)))), Err(EACCES));
    assert_eq!(decide(&perf(u, false, PERF_PID_OTHER, -1, Some(Target { dumpable: 0, ..tgt(1000, 1000) }))), Err(EACCES));
    // the kernel-mode test comes first (the kernel's order)
    assert_eq!(decide(&perf(u, true, PERF_PID_SELF, 5, None)), Err(EACCES));
}

#[test]
fn perf_privileged() {
    for caps in [PERFMON, ADMIN] {
        let p = who(0, 0, caps);
        assert_eq!(decide(&perf(p, true, PERF_PID_SELF, -1, None)), Ok(()));
        assert_eq!(decide(&perf(p, false, PERF_PID_CPU, 0, None)), Ok(()));
        assert_eq!(decide(&perf(p, false, PERF_PID_CPU, -1, None)), Err(EINVAL));
    }
    // capabilities of a user namespace of its own do not count
    let mut ns = who(0, 0, PERFMON | ADMIN);
    ns.in_userns = true;
    assert_eq!(decide(&perf(ns, true, PERF_PID_SELF, -1, None)), Err(EACCES));
    // CAP_SYS_PTRACE over another user's task
    let p = who(1000, 1000, PTRACE);
    assert_eq!(decide(&perf(p, false, PERF_PID_OTHER, -1, Some(tgt(1001, 1001)))), Ok(()));
}

#[test]
fn vm_getfd_kcmp() {
    let u = who(1000, 1000, 0);
    for nr in [NR_PROCESS_VM_READV, NR_PROCESS_VM_WRITEV, NR_PIDFD_GETFD] {
        let f = |t| Facts { nr, who: u, t: [t, None], ..Facts::default() };
        assert_eq!(decide(&f(Some(tgt(1000, 1000)))), Ok(()));
        assert_eq!(decide(&f(Some(tgt(1001, 1000)))), Err(EPERM));
        assert_eq!(decide(&f(Some(Target { dumpable: 0, ..tgt(1000, 1000) }))), Err(EPERM));
        assert_eq!(decide(&f(None)), Err(ESRCH));
    }
    let k = |a, b| Facts { nr: NR_KCMP, who: u, t: [a, b], ..Facts::default() };
    assert_eq!(decide(&k(Some(tgt(1000, 1000)), Some(Target { same: true, ..tgt(0, 0) }))), Ok(()));
    assert_eq!(decide(&k(Some(tgt(1000, 1000)), Some(tgt(1001, 1001)))), Err(EPERM));
    assert_eq!(decide(&k(Some(tgt(1001, 1001)), Some(tgt(1000, 1000)))), Err(EPERM));
    assert_eq!(decide(&k(Some(tgt(1000, 1000)), None)), Err(ESRCH));
    assert_eq!(decide(&Facts { nr: 39, ..Facts::default() }), Err(ENOSYS));
}

#[test]
fn routed_requests() {
    assert!(ptrace_routed(PTRACE_ATTACH, 0));
    assert!(ptrace_routed(PTRACE_SEIZE, 0));
    assert!(ptrace_routed(PTRACE_TRACEME, 0));
    assert!(ptrace_routed(PTRACE_SETOPTIONS, O_SUSPEND_SECCOMP | 1));
    assert!(!ptrace_routed(PTRACE_SETOPTIONS, 0x7f));
    // PEEKDATA 2, POKEDATA 5, CONT 7, KILL 8, SINGLESTEP 9, GETREGS 12, DETACH 17, SYSCALL 24
    for r in [1u64, 2, 3, 4, 5, 6, 7, 8, 9, 12, 13, 14, 15, 17, 24, 0x4201, 0x4202, 0x4203, 0x4204, 0x4205, 0x4207, 0x4208, 0x420e] {
        assert!(!ptrace_routed(r, O_SUSPEND_SECCOMP), "request {:#x}", r);
    }
    assert_eq!(ptrace_kind(PTRACE_ATTACH), K_ATTACH);
    assert_eq!(ptrace_kind(PTRACE_SEIZE), K_SEIZE);
    assert_eq!(ptrace_kind(PTRACE_TRACEME), K_TRACEME);
    assert_eq!(ptrace_kind(PTRACE_SETOPTIONS), K_SETOPTIONS);
    assert_eq!(ptrace_kind(2), 0);
}

#[test]
fn dumpable_after_credential_changes() {
    assert!(!creds_clear_dumpable((1000, 1000, 0), (1000, 1000, 0)));
    assert!(creds_clear_dumpable((0, 0, u64::MAX), (1000, 0, 0)));
    assert!(creds_clear_dumpable((1000, 1000, 0), (1000, 5, 0)));
    // dropping capabilities alone: no; gaining: yes
    assert!(!creds_clear_dumpable((0, 0, 0xff), (0, 0, 0x0f)));
    assert!(creds_clear_dumpable((0, 0, 0x0f), (0, 0, 0xff)));
}

// ---- facts words and keys ----

fn sample() -> Facts {
    let w = Who { uid: [1, 2, 3], gid: [4, 5, 6], caps: 0xdead_beef_0000_0001, in_userns: true, seccomp: true };
    let a = Target { tgid: 77, tid: 78, uid: [10, 11, 12], gid: [13, 14, 15], same: false, service: true, within: true, dumpable: 2 };
    let b = Target { tgid: 0xffff_fff0, tid: 9, uid: [u32::MAX; 3], gid: [0; 3], same: true, service: false, within: false, dumpable: 0 };
    Facts { nr: NR_KCMP, kind: 3, extra: 0x8000_0001, cpu: -1, who: w, t: [Some(a), Some(b)] }
}

#[test]
fn facts_round_trip() {
    let f = sample();
    assert_eq!(Facts::decode(&f.encode()), f);
    let g = Facts { t: [None, None], cpu: 0, ..f };
    assert_eq!(Facts::decode(&g.encode()), g);
    assert_eq!(Facts::decode(&Facts::default().encode()), Facts::default());
}

#[test]
fn keys_carry_the_verdict_and_bind_every_fact() {
    let w = sample().encode();
    for v in [0i64, EPERM, EACCES, EINVAL, ESRCH] {
        let k = key(&w, v);
        assert_ne!(k, 0);
        assert!(k & 1 << 63 != 0);
        assert_eq!(verdict_of(k, &w), Some(v));
    }
    // any one fact changed: the mark means nothing
    for i in 0..16 {
        for bit in [0, 7, 31, 32, 63] {
            let mut x = w;
            x[i] ^= 1 << bit;
            assert_eq!(verdict_of(key(&w, 0), &x), None, "word {} bit {}", i, bit);
        }
    }
    assert_eq!(verdict(Ok(())), 0);
    assert_eq!(verdict(Err(EPERM)), EPERM);
}

// ---- lx-proc's half ----

fn call(nr: u64, args: [u64; 6]) -> policy::Call {
    policy::Call { nr, args, tgid: 10, caps: 0, ids: [1000; 6] }
}

fn no_mem() -> M {
    M { addr: 0, data: Vec::new() }
}

#[test]
fn handles_the_six_calls() {
    for nr in [101, 298, 310, 311, 312, 438] {
        assert!(trace::handles(nr));
    }
    for nr in [105, 157, 308, 0, 102] {
        assert!(!trace::handles(nr));
    }
}

fn key_of(a: trace::Answer) -> u64 {
    let trace::Answer::Kernel(k) = a;
    k
}

#[test]
fn allowed_call_redirected_with_its_key() {
    let f = ptrace_facts(K_ATTACH, who(1000, 1000, 0), Some(tgt(1000, 1000)), 0);
    let k = K::with(Ok(f));
    let key = key_of(trace::serve(&k, &no_mem(), &call(101, [PTRACE_ATTACH, 51, 0, 0, 0, 0])));
    let calls = k.calls.borrow();
    assert_eq!(calls.len(), 1, "one sub-op: the facts (the verdict rides on the redirect)");
    assert_eq!(calls[0].0, LXP_TRACE_FACTS);
    assert_eq!(&calls[0].1[..7], &[101, PTRACE_ATTACH, 51, 0, 0, 0, 0]);
    assert_eq!(verdict_of(key, &f.encode()), Some(0));
}

#[test]
fn refused_call_carries_its_errno() {
    let f = ptrace_facts(K_ATTACH, who(1000, 1000, 0), Some(tgt(1001, 1001)), 0);
    let k = K::with(Ok(f));
    let key = key_of(trace::serve(&k, &no_mem(), &call(101, [PTRACE_ATTACH, 51, 0, 0, 0, 0])));
    assert_eq!(verdict_of(key, &f.encode()), Some(EPERM));
}

#[test]
fn facts_error_left_to_the_kernel() {
    let k = K::with(Err(ESRCH));
    assert_eq!(trace::serve(&k, &no_mem(), &call(310, [99, 0, 0, 0, 0, 0])), trace::Answer::Kernel(0));
    assert_eq!(k.calls.borrow().len(), 1);
}

#[test]
fn perf_reads_the_attribute() {
    let mut attr = vec![0u8; 64];
    // exclude_kernel set: no kernel-mode bit
    attr[40] = 1 << 5;
    let m = M { addr: 0x1000, data: attr.clone() };
    let f = perf(who(1000, 1000, 0), false, PERF_PID_SELF, -1, None);
    let k = K::with(Ok(f));
    let key = key_of(trace::serve(&k, &m, &call(298, [0x1000, 0, u64::MAX, u64::MAX, 0, 0])));
    assert_eq!(k.calls.borrow()[0].1[7], 0);
    assert_eq!(verdict_of(key, &f.encode()), Some(0));
    // exclude_kernel clear: the kernel-mode bit
    attr[40] = 0;
    let m = M { addr: 0x1000, data: attr };
    let f = perf(who(1000, 1000, 0), true, PERF_PID_SELF, -1, None);
    let k = K::with(Ok(f));
    let key = key_of(trace::serve(&k, &m, &call(298, [0x1000, 0, u64::MAX, u64::MAX, 0, 0])));
    assert_eq!(k.calls.borrow()[0].1[7], PERF_KERNEL as u64);
    assert_eq!(verdict_of(key, &f.encode()), Some(EACCES));
    // an attribute that cannot be read: the kernel's code answers (EFAULT), nothing asked
    let k = K::with(Ok(Facts::default()));
    assert_eq!(trace::serve(&k, &no_mem(), &call(298, [0x2000, 0, 0, 0, 0, 0])), trace::Answer::Kernel(0));
    assert!(k.calls.borrow().is_empty());
}
