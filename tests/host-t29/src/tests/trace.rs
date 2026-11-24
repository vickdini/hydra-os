//! `src/lx/trace.rs` (wave 10, Group 8-1): the facts of the tracing calls as the kernel
//! gathers them, the check at use (lx-proc's verdict for exactly these facts, else the rule),
//! the kernel copy's access rule, and the dumpable flag across credential changes
//! (`lx::proc::task_creds_set`).

use super::common::*;
use crate::ipc::protocol::LxProcIo;
use crate::lx::proc as mech;
use crate::lx::ptrace_rules::{self as rules, *};
use crate::lx::trace;

fn caps(pid: u64, c: u64) {
    fake::task(pid, |t| t.caps.effective = c);
}

#[test]
fn check_takes_the_verdict_given_for_these_facts() {
    let _g = setup();
    spawn_as(700, 1, 1000, 1000);
    spawn_as(701, 1, 2000, 2000);
    run(700);
    let args = [700, 701, 1, 0, 0, 0];
    // the rule: another user
    assert_eq!(trace::check(NR_KCMP, &args, 0), Err(EPERM));
    // lx-proc allowed exactly these facts: its verdict counts
    let w = trace::gather(NR_KCMP, &args, 700, 0).unwrap().encode();
    assert!(mech::approve(700, NR_KCMP, rules::key(&w, 0)));
    assert_eq!(trace::check(NR_KCMP, &args, 0), Ok(()));
    // the mark went with that check
    assert_eq!(trace::check(NR_KCMP, &args, 0), Err(EPERM));
    // a refusal carries its errno
    assert!(mech::approve(700, NR_KCMP, rules::key(&w, ESRCH)));
    assert_eq!(trace::check(NR_KCMP, &args, 0), Err(ESRCH));
    // facts changed after the decision (the target changed its ids): the rule decides
    assert!(mech::approve(700, NR_KCMP, rules::key(&w, 0)));
    fake::task(701, |t| t.uid = 1000);
    assert_eq!(trace::check(NR_KCMP, &args, 0), Err(EPERM));
    // a mark for another call is not this call's
    assert!(mech::approve(700, NR_PIDFD_GETFD, rules::key(&w, 0)));
    assert_eq!(trace::check(NR_KCMP, &args, 0), Err(EPERM));
    assert!(trace::summary().contains("verdicts from lx-proc"));
}

#[test]
fn gather_resolves_like_the_calls() {
    let _g = setup();
    spawn_as(710, 1, 1000, 1000);
    spawn_as(711, 710, 1000, 1000);
    add_thread(711, 712);
    run(710);
    // ptrace ATTACH names a thread; SEIZE carries its options
    let f = trace::gather(NR_PTRACE, &[PTRACE_ATTACH, 712, 0, 0, 0, 0], 710, 0).unwrap();
    assert_eq!((f.kind, f.t[0].unwrap().tid, f.t[0].unwrap().tgid), (K_ATTACH, 712, 711));
    let f = trace::gather(NR_PTRACE, &[PTRACE_SEIZE, 711, 0, 0x81, 0, 0], 710, 0).unwrap();
    assert_eq!((f.kind, f.extra), (K_SEIZE, 0x81));
    assert_eq!(trace::gather(NR_PTRACE, &[PTRACE_ATTACH, 9999, 0, 0, 0, 0], 710, 0), Err(ESRCH));
    assert_eq!(trace::gather(NR_PTRACE, &[2, 711, 0, 0, 0, 0], 710, 0), Err(EINVAL));
    let f = trace::gather(NR_PTRACE, &[PTRACE_SETOPTIONS, 711, 0, O_SUSPEND_SECCOMP, 0, 0], 710, 0).unwrap();
    assert_eq!((f.kind, f.extra as u64), (K_SETOPTIONS, O_SUSPEND_SECCOMP));
    // TRACEME: the parent
    let f = trace::gather(NR_PTRACE, &[PTRACE_TRACEME, 0, 0, 0, 0, 0], 711, 0).unwrap();
    assert_eq!(f.t[0].unwrap().tgid, 710);
    // perf: the caller, a CPU, another task, a bad pid
    let f = trace::gather(NR_PERF_EVENT_OPEN, &[0, 0, u64::MAX, 0, 0, 0], 710, PERF_KERNEL).unwrap();
    assert_eq!((f.extra, f.cpu, f.t[0]), (PERF_KERNEL, -1, None));
    let f = trace::gather(NR_PERF_EVENT_OPEN, &[0, u32::MAX as u64, 0, 0, 0, 0], 710, 0).unwrap();
    assert_eq!(f.extra >> PERF_PID_SHIFT, PERF_PID_CPU);
    let f = trace::gather(NR_PERF_EVENT_OPEN, &[0, 711, u64::MAX, 0, 0, 0], 710, 0).unwrap();
    assert_eq!((f.extra >> PERF_PID_SHIFT, f.t[0].unwrap().tgid), (PERF_PID_OTHER, 711));
    let f = trace::gather(NR_PERF_EVENT_OPEN, &[0, 9999, u64::MAX, 0, 0, 0], 710, 0).unwrap();
    assert_eq!((f.extra >> PERF_PID_SHIFT, f.t[0]), (PERF_PID_OTHER, None));
    let f = trace::gather(NR_PERF_EVENT_OPEN, &[0, (-5i32) as u32 as u64, u64::MAX, 0, 0, 0], 710, 0).unwrap();
    assert_eq!(f.extra >> PERF_PID_SHIFT, PERF_PID_BAD);
    // process_vm_*: 0 is the caller, a thread names its process, negative is ESRCH
    let f = trace::gather(NR_PROCESS_VM_READV, &[0, 0, 0, 0, 0, 0], 710, 0).unwrap();
    assert!(f.t[0].unwrap().same);
    let f = trace::gather(NR_PROCESS_VM_WRITEV, &[712, 0, 0, 0, 0, 0], 710, 0).unwrap();
    assert_eq!(f.t[0].unwrap().tgid, 711);
    assert_eq!(trace::gather(NR_PROCESS_VM_READV, &[u32::MAX as u64, 0, 0, 0, 0, 0], 710, 0), Err(ESRCH));
    // kcmp: two threads, both must exist
    let f = trace::gather(NR_KCMP, &[710, 712, 0, 0, 0, 0], 710, 0).unwrap();
    assert!(f.t[0].unwrap().same && f.t[1].unwrap().tid == 712);
    assert_eq!(trace::gather(NR_KCMP, &[0, 712, 0, 0, 0, 0], 710, 0), Err(ESRCH));
    assert_eq!(trace::gather(NR_KCMP, &[710, 9999, 0, 0, 0, 0], 710, 0), Err(ESRCH));
    // anything else
    assert_eq!(trace::gather(39, &[0; 6], 710, 0), Err(ENOSYS));
    assert_eq!(trace::gather(NR_KCMP, &[710, 710, 0, 0, 0, 0], 9999, 0), Err(ESRCH));
}

#[test]
fn gather_pidfd_getfd_and_the_facts_op() {
    let _g = setup();
    spawn_as(720, 1, 1000, 1000);
    spawn_as(721, 1, 1000, 1000);
    run(720);
    // (a pidfd's process: the VM test ptperm; the fake keeps pidfds elsewhere)
    assert_eq!(trace::gather(NR_PIDFD_GETFD, &[60, 0, 0, 0, 0, 0], 720, 0), Err(-9));
    fake::task(720, |t| t.fds.lock().install(5, crate::fs::FileDescriptor::ConsoleOut));
    assert_eq!(trace::gather(NR_PIDFD_GETFD, &[5, 0, 0, 0, 0, 0], 720, 0), Err(EINVAL));
    // the sub-op: call number, arguments, extra in; the facts' words out
    let mut io = LxProcIo::EMPTY;
    io.a[0] = NR_KCMP;
    io.a[1] = 720;
    io.a[2] = 721;
    assert_eq!(trace::facts_op(720, &mut io), 0);
    assert_eq!(Facts::decode(&io.a), trace::gather(NR_KCMP, &[720, 721, 0, 0, 0, 0], 720, 0).unwrap());
    let mut io = LxProcIo::EMPTY;
    io.a[0] = 39;
    assert_eq!(trace::facts_op(720, &mut io), ENOSYS);
}

#[test]
fn access_rule_reads_dumpable_and_capabilities() {
    let _g = setup();
    spawn_as(730, 1, 1000, 1000);
    spawn_as(731, 1, 1000, 1000);
    spawn_as(732, 1, 0, 0);
    run(730);
    let rd = MODE_ATTACH | MODE_REALCREDS;
    assert_eq!(trace::may_access_mode(731, rd), Ok(()));
    mech::proc_attrs_set(731, |p| p.dumpable = 0);
    assert_eq!(trace::may_access_mode(731, rd), Err(EPERM));
    assert_eq!(trace::may_access_mode(732, rd), Err(EPERM));
    assert_eq!(trace::may_access_mode(9999, rd), Err(ESRCH));
    caps(730, 1 << CAP_SYS_PTRACE);
    assert_eq!(trace::may_access_mode(731, rd), Ok(()));
    assert_eq!(trace::may_access_mode(732, rd), Ok(()));
    // a service's process never
    fake::task(731, |t| t.service = Some(3));
    assert_eq!(trace::may_access_mode(731, rd), Err(EPERM));
    // the kernel copy's wrapper
    assert_eq!(crate::compat::linux::extra::may_access(732), Ok(()));
}

#[test]
fn credential_changes_clear_dumpable() {
    let _g = setup();
    spawn_as(740, 1, 0, 0);
    run(740);
    assert_eq!(mech::proc_attrs(740).dumpable, 1);
    // the same ids again: no change
    assert!(mech::task_creds_set(0, mech::Creds { uid: [0; 3], gid: [0; 3] }));
    assert_eq!(mech::proc_attrs(740).dumpable, 1);
    // another effective user id: not dumpable
    assert!(mech::task_creds_set(740, mech::Creds { uid: [0, 1000, 0], gid: [0; 3] }));
    assert_eq!(mech::proc_attrs(740).dumpable, 0);
    // an exec makes it dumpable again; then an effective group change clears it
    mech::attrs_on_exec(740, 740);
    assert_eq!(mech::proc_attrs(740).dumpable, 1);
    assert!(mech::task_creds_set(740, mech::Creds { uid: [0, 1000, 0], gid: [0, 5, 0] }));
    assert_eq!(mech::proc_attrs(740).dumpable, 0);
    assert!(!mech::task_creds_set(9999, mech::Creds { uid: [0; 3], gid: [0; 3] }));
}
