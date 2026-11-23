//! `src/lx/proc.rs` (wave 9, Group 7a): the kernel's process-identity primitives
//! (credentials, groups and sessions, the tree and PID view, limits, namespace ids, the call
//! context) and today's policy as pure rules.

use super::common::*;
use crate::compat::linux::ns::Ns;
use crate::lx::proc::{self as mech, rules, Creds, NsChange, NsIds, NsKind, Pgrp, Tree};

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EINVAL: i64 = -22;
const K: u32 = rules::KEEP;

// ---------------------------------------------------------------- rules: ids

#[test]
fn rule_set_id() {
    assert_eq!(rules::set_id([1, 2, 3], 9, true), Ok([9, 9, 9]), "privileged sets all three");
    assert_eq!(rules::set_id([1, 2, 3], 1, false), Ok([1, 1, 3]), "to the real id");
    assert_eq!(rules::set_id([1, 2, 3], 3, false), Ok([1, 3, 3]), "to the saved id");
    assert_eq!(rules::set_id([1, 2, 3], 2, false), Err(EPERM), "not to the effective one alone");
    assert_eq!(rules::set_id([1, 2, 3], 9, false), Err(EPERM));
}

#[test]
fn rule_set_re() {
    assert_eq!(rules::set_re([1, 2, 3], K, K, false), Ok([1, 2, 3]), "nothing set: saved stays");
    assert_eq!(rules::set_re([1, 2, 3], 2, K, false), Ok([2, 2, 2]), "real set: saved follows effective");
    assert_eq!(rules::set_re([1, 2, 3], K, 3, false), Ok([1, 3, 3]), "effective other than real");
    assert_eq!(rules::set_re([1, 2, 3], K, 1, false), Ok([1, 1, 3]), "effective = real: saved stays");
    assert_eq!(rules::set_re([1, 2, 3], 3, K, false), Err(EPERM), "real to the saved id");
    assert_eq!(rules::set_re([1, 2, 3], K, 9, false), Err(EPERM));
    assert_eq!(rules::set_re([1, 2, 3], 7, 8, true), Ok([7, 8, 8]));
}

#[test]
fn rule_set_res() {
    assert_eq!(rules::set_res([1, 2, 3], [3, 1, 2], false), Ok([3, 1, 2]), "a permutation");
    assert_eq!(rules::set_res([1, 2, 3], [K, K, 1], false), Ok([1, 2, 1]));
    assert_eq!(rules::set_res([1, 2, 3], [K, 9, K], false), Err(EPERM));
    assert_eq!(rules::set_res([1, 2, 3], [7, 8, 9], true), Ok([7, 8, 9]));
    assert_eq!(rules::set_res([1, 2, 3], [K, K, K], false), Ok([1, 2, 3]));
}

// ---------------------------------------------------------------- rules: groups, limits

fn pg(pid: u64, ppid: u64, pgid: u64, sid: u64) -> Option<Pgrp> {
    Some(Pgrp { pid, ppid, pgid, sid, zombie: false })
}

#[test]
fn rule_setpgid() {
    assert_eq!(rules::setpgid(10, pg(10, 1, 5, 5), -1i64 as u64), Err(EINVAL), "negative group first");
    assert_eq!(rules::setpgid(10, None, 0), Err(ESRCH));
    assert_eq!(rules::setpgid(10, pg(11, 9, 5, 5), 0), Err(ESRCH), "not self, not a child");
    assert_eq!(rules::setpgid(10, pg(10, 1, 10, 10), 0), Err(EPERM), "a session leader");
    assert_eq!(rules::setpgid(10, pg(10, 1, 5, 5), 0), Ok(10), "0: its own pid");
    assert_eq!(rules::setpgid(10, pg(11, 10, 5, 5), 7), Ok(7), "a parent moves its child");
}

#[test]
fn rule_setsid() {
    assert_eq!(rules::setsid(pg(10, 1, 5, 5), false), Ok(10));
    assert_eq!(rules::setsid(pg(10, 1, 10, 5), false), Err(EPERM), "a group leader");
    assert_eq!(rules::setsid(pg(10, 1, 5, 5), true), Err(EPERM), "its pid names a used group");
    assert_eq!(rules::setsid(None, true), Err(EPERM), "the used group is checked first");
    assert_eq!(rules::setsid(None, false), Err(ESRCH));
}

#[test]
fn rule_set_limit() {
    let inf = u64::MAX;
    assert_eq!(rules::set_limit(3, (8, 16), (17, 16), true, 4096), Err(EINVAL), "soft above hard");
    assert_eq!(rules::set_limit(3, (8, 16), (4, 32), false, 4096), Err(EPERM), "raising hard");
    assert_eq!(rules::set_limit(3, (8, 16), (4, 32), true, 4096), Ok(()));
    assert_eq!(rules::set_limit(3, (8, 16), (4, 8), false, 4096), Ok(()), "lowering is free");
    assert_eq!(rules::set_limit(7, (1024, 4096), (1024, 8192), true, 4096), Err(EPERM), "nofile past the table");
    assert_eq!(rules::set_limit(7, (1024, inf), (1024, inf), false, 4096), Ok(()), "nofile unchanged hard");
    assert_eq!(rules::set_limit(6, (1024, 4096), (1024, 8192), true, 4096), Ok(()), "other limits may");
}

// ---------------------------------------------------------------- credentials

#[test]
fn creds_get_set() {
    let _g = setup();
    spawn_as(7001, 1, 1000, 100);
    run(7001);
    fake::task(7001, |t| t.caps = crate::task::tcb::Caps::default());
    let (c, cu, cg) = mech::task_creds(0).expect("current");
    assert_eq!(c, Creds { uid: [1000; 3], gid: [100; 3] });
    assert_eq!((cu, cg), (false, false));
    assert_eq!(mech::task_creds(7001).map(|x| x.0), Some(c), "by thread id");
    assert!(mech::task_creds(4242).is_none());
    assert!(mech::task_creds_set(7001, Creds { uid: [1, 2, 3], gid: [4, 5, 6] }));
    assert_eq!(fake::task(7001, |t| (t.uid, t.euid, t.suid, t.gid, t.egid, t.sgid)), Some((1, 2, 3, 4, 5, 6)));
    assert!(!mech::task_creds_set(4242, c));
    fake::switch_to(0);
}

#[test]
fn creds_set_applies_capability_rules() {
    let _g = setup();
    spawn_as(7002, 1, 0, 0);
    run(7002);
    let full = fake::task(7002, |t| t.caps.effective).unwrap();
    assert_ne!(full, 0);
    let (_, cu, cg) = mech::task_creds(0).unwrap();
    assert!(cu && cg, "root holds CAP_SETUID and CAP_SETGID");
    // Effective uid leaves 0: the effective set empties (saved 0 keeps the permitted one)
    assert!(mech::task_creds_set(0, Creds { uid: [0, 1000, 0], gid: [0; 3] }));
    assert_eq!(fake::task(7002, |t| (t.caps.effective, t.caps.permitted)), Some((0, full)));
    // Back to 0: restored from the permitted set
    assert!(mech::task_creds_set(0, Creds { uid: [0; 3], gid: [0; 3] }));
    assert_eq!(fake::task(7002, |t| t.caps.effective), Some(full));
    // A gid-only change leaves capabilities alone
    assert!(mech::task_creds_set(0, Creds { uid: [0; 3], gid: [5; 3] }));
    assert_eq!(fake::task(7002, |t| t.caps.effective), Some(full));
    // Every uid leaves 0: all gone
    assert!(mech::task_creds_set(0, Creds { uid: [1000; 3], gid: [5; 3] }));
    assert_eq!(fake::task(7002, |t| (t.caps.effective, t.caps.permitted)), Some((0, 0)));
    fake::switch_to(0);
}

// ---------------------------------------------------------------- groups and sessions

#[test]
fn pgrp_primitives() {
    let _g = setup();
    spawn(7010, 1);
    spawn(7011, 7010);
    spawn(7012, 7010);
    // A fork inherits group and session
    assert_eq!(mech::task_pgrp(7011), Some(Pgrp { pid: 7011, ppid: 7010, pgid: 7010, sid: 7010, zombie: false }));
    assert_eq!(mech::task_pgrp(4242), None);
    assert!(mech::task_pgrp_set(7011, 7011, false));
    assert_eq!(mech::task_pgrp(7011).map(|p| (p.pgid, p.sid)), Some((7011, 7010)));
    assert!(mech::task_pgrp_set(7012, 7012, true), "a new session");
    assert_eq!(mech::task_pgrp(7012).map(|p| (p.pgid, p.sid)), Some((7012, 7012)));
    assert!(!mech::task_pgrp_set(4242, 1, false));
    assert!(mech::task_pgrp_set(7012, 7011, false), "the mechanism does not judge");
    assert_eq!(mech::pgrp_members(7011, None), vec![7011, 7012]);
    assert_eq!(mech::pgrp_members(7011, Some(7010)), vec![7011]);
    assert_eq!(mech::pgrp_members(7011, Some(7012)), vec![7012]);
    assert_eq!(mech::pgrp_in_session(7011, 7010), Some(true));
    assert_eq!(mech::pgrp_in_session(7011, 9999), Some(false), "only elsewhere");
    assert_eq!(mech::pgrp_in_session(4242, 7010), None);
    assert!(mech::pgrp_used(7011, 7011), "7012 is in it");
    assert!(!mech::pgrp_used(7010, 7010), "only 7010 itself");
    // A zombie: no member, but still uses the group
    crate::compat::linux::proc::PROCS.lock().get_mut(&7012).unwrap().zombie = true;
    assert_eq!(mech::pgrp_members(7011, None), vec![7011]);
    assert!(mech::pgrp_used(7011, 7011));
    assert_eq!(mech::pgrp_in_session(7011, 7012), Some(false));
    assert_eq!(mech::task_pgrp(7012).map(|p| p.zombie), Some(true));
}

#[test]
fn pgrp_signal_posts_to_live_members() {
    let _g = setup();
    spawn(7020, 1);
    spawn(7021, 7020);
    spawn(7022, 7020);
    mech::task_pgrp_set(7022, 7022, true);
    mech::task_pgrp_set(7022, 7020, false); // group 7020, session 7022
    let pending = |pid| crate::compat::linux::proc::PROCS.lock().get(&pid).unwrap().pending;
    assert_eq!(mech::pgrp_signal(7020, Some(7020), 10), 2, "the group's members in session 7020");
    assert_ne!(pending(7021) & (1 << 9), 0);
    assert_eq!(pending(7022) & (1 << 9), 0, "another session's member");
    assert_eq!(mech::pgrp_signal(7020, None, 12), 3);
    assert_ne!(pending(7022) & (1 << 11), 0);
    assert_eq!(mech::pgrp_signal(4242, None, 12), 0);
}

// ---------------------------------------------------------------- tree and PID view

#[test]
fn tree_and_pid_view() {
    let _g = setup();
    spawn(7030, 1);
    spawn(7031, 7030);
    add_thread(7031, 7032);
    let t = mech::task_tree(7031).expect("tree");
    assert_eq!(t, Tree { ppid: 7030, pgid: 7030, sid: 7030, threads: 2, start: t.start, zombie: false, pid_inits: vec![] });
    assert!(mech::task_tree(4242).is_none());
    assert_eq!(mech::pid_ns_init(7031), None, "the first namespace");
    crate::compat::linux::proc::PROCS.lock().get_mut(&7031).unwrap().ns.pid_inits = vec![7031];
    assert_eq!(mech::pid_ns_init(7031), Some(7031));
    assert_eq!(mech::task_tree(7031).unwrap().pid_inits, vec![7031]);
    assert_eq!(mech::pid_to_view(7031, Some(7031)), 1);
    assert_eq!(mech::pid_to_view(7030, Some(7031)), 7030);
    assert_eq!(mech::pid_to_view(7031, None), 7031);
    assert_eq!(mech::pid_from_view(1, Some(7031)), 7031);
    assert_eq!(mech::pid_from_view(5, Some(7031)), 5);
    assert_eq!(mech::pid_from_view(1, None), 1);
}

// ---------------------------------------------------------------- limits

#[test]
fn limits_get_set() {
    let _g = setup();
    spawn(7040, 1);
    let l = mech::task_limits(7040);
    assert_eq!(l[3], (8 << 20, u64::MAX), "Ubuntu's stack default");
    assert!(mech::task_limits_set(7040, 3, (1 << 20, 2 << 20)));
    assert_eq!(mech::task_limits(7040)[3], (1 << 20, 2 << 20));
    assert_eq!(mech::task_limits(7040)[7], l[7], "others untouched");
    assert!(!mech::task_limits_set(7040, 16, (0, 0)), "no such resource");
    assert_eq!(mech::task_limits(4242)[3], (8 << 20, u64::MAX), "unknown: the defaults");
}

// ---------------------------------------------------------------- namespace ids

#[test]
fn ns_apply_and_ids() {
    let mut ns = Ns::default();
    assert_eq!(NsIds::of(&ns), NsIds::default());
    mech::ns_apply(
        &mut ns,
        &[
            NsChange::Id(NsKind::Pid, 11),
            NsChange::Id(NsKind::PidForChildren, 12),
            NsChange::Id(NsKind::Net, 13),
            NsChange::Id(NsKind::Mnt, 14),
            NsChange::Id(NsKind::Ipc, 15),
            NsChange::Id(NsKind::Uts, 16),
            NsChange::Id(NsKind::Cgroup, 17),
        ],
    );
    assert_eq!(NsIds::of(&ns), NsIds { user: 0, pid: 11, pid_for_children: 12, net: 13, mnt: 14, ipc: 15, uts: 16, cgroup: 17 });
    assert_eq!(ns.pid_for_children, Some(12));
    mech::ns_apply(&mut ns, &[NsChange::Id(NsKind::PidForChildren, 0), NsChange::Id(NsKind::Net, 20), NsChange::Id(NsKind::Net, 21)]);
    assert_eq!(ns.pid_for_children, None, "0: back to its own");
    assert_eq!(ns.net, 21, "applied in order");
    mech::ns_apply(&mut ns, &[NsChange::User(None)]);
    assert!(ns.user.is_none());
}

#[test]
fn ns_set_on_a_process() {
    let _g = setup();
    spawn(7050, 1);
    let a = mech::ns_new_id();
    let b = mech::ns_new_id();
    assert!(a != 0 && b != a);
    assert_eq!(mech::ns_ids(7050), Some(NsIds::default()));
    let ids = mech::ns_set(7050, &[NsChange::Id(NsKind::Mnt, a), NsChange::Id(NsKind::Uts, b)]).expect("set");
    assert_eq!((ids.mnt, ids.uts, ids.net), (a, b, 0));
    assert_eq!(mech::ns_ids(7050), Some(ids));
    assert_eq!(mech::ns_set(4242, &[NsChange::Id(NsKind::Mnt, a)]), None);
    assert_eq!(mech::ns_ids(4242), None);
}

#[test]
fn call_ctx_reads_group_session_and_namespaces() {
    let _g = setup();
    spawn(7060, 1);
    mech::task_pgrp_set(7060, 7060, true);
    mech::ns_set(7060, &[NsChange::Id(NsKind::Mnt, 31), NsChange::Id(NsKind::Net, 32), NsChange::Id(NsKind::Pid, 33)]);
    let c = mech::call_ctx(7060, true).unwrap().unwrap();
    assert_eq!(c, mech::CallCtx { pgid: 7060, sid: 7060, mnt: 31, net: 32, pid: 33, user: false });
    assert_eq!(mech::call_ctx(4242, false), Ok(None));
    let held = crate::compat::linux::proc::PROCS.lock();
    assert_eq!(mech::call_ctx(7060, false), Err(()), "busy and not waiting");
    drop(held);
    assert!(mech::call_ctx(7060, false).unwrap().is_some());
}
