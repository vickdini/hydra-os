//! `src/compat/linux/ns.rs`: user, PID, network, mount, IPC, UTS and cgroup namespaces
//! (clone/unshare/setns rules, ID maps, the /proc files, PID translation).

use super::common::*;
use crate::compat::linux::ns::{self, *};
use crate::fs::FileDescriptor;
use crate::task::with_current_fds_mut;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EBADF: i64 = -9;
const ENOMEM: i64 = -12;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EUSERS: i64 = -87;

const CLONE_FS: u64 = 0x200;
const CLONE_THREAD: u64 = 0x10000;
const CAP_SYS_ADMIN: u64 = 1 << 21;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

fn user_proc(pid: u64, uid: u32) {
    spawn_as(pid, 1, uid, uid);
    run(pid);
}

fn caps(pid: u64, c: u64) {
    fake::task(pid, |t| {
        t.caps.effective = c;
        t.caps.in_userns = false;
    });
}

fn ns_of(pid: u64) -> ns::Ns {
    linux::proc::PROCS.lock().get(&pid).unwrap().ns.clone()
}

/// Opens `/proc/<who>/ns/<kind>` as a descriptor of the current process.
fn open_ns(fd: usize, who: &str, kind: &str) {
    with_current_fds_mut(|f| f.install(fd, FileDescriptor::file(&format!("/proc/{who}/ns/{kind}"))));
}

#[test]
fn check_clone_rules() {
    let _g = setup();
    user_proc(700, 1000);
    assert_eq!(check_clone(0), Ok(()));
    assert_eq!(check_clone(CLONE_NEWUSER | CLONE_THREAD), Err(EINVAL));
    assert_eq!(check_clone(CLONE_NEWUSER | CLONE_FS), Err(EINVAL));
    assert_eq!(check_clone(CLONE_NEWPID | CLONE_THREAD), Err(EINVAL));
    assert_eq!(check_clone(CLONE_NEWNET), Err(EPERM), "needs CAP_SYS_ADMIN");
    assert_eq!(check_clone(CLONE_NEWNET | CLONE_NEWUSER), Ok(()), "a new user namespace provides it");
    caps(700, CAP_SYS_ADMIN);
    assert_eq!(check_clone(CLONE_NEWNET | CLONE_NEWPID), Ok(()));
}

#[test]
fn clone_into_new_namespaces() {
    let _g = setup();
    user_proc(710, 1000);
    spawn_as(711, 710, 1000, 1000);
    after_clone(711, CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP);
    let n = ns_of(711);
    assert!(n.user.is_some() && n.net != 0 && n.pid != 0 && n.mnt != 0 && n.uts != 0 && n.ipc != 0 && n.cgroup != 0);
    assert_eq!(n.pid_inits, vec![711], "the child is its PID namespace's init");
    assert!(fake::called("mount::copy_ns(0,"), "the mount table is copied");
    assert_eq!(fake::task(711, |t| (t.caps.in_userns, t.caps.effective)), Some((true, (1 << 41) - 1)));
    // The child sees itself as PID 1, its parent as is
    run(711);
    assert_eq!(pid_to_caller(711), 1);
    assert_eq!(pid_from_caller(1), 711);
    assert_eq!(pid_to_caller(710), 710);
    assert_eq!(pid_from_caller(5), 5);
    assert!(net_isolated());
    assert_eq!(ipc_ns(), n.ipc);
    // A thread or a clone without namespace flags changes nothing
    let before = ns_of(710);
    after_clone(710, CLONE_NEWNET | CLONE_THREAD);
    after_clone(710, 0);
    assert_eq!(ns_of(710).net, before.net);
    // In the parent: nothing changed
    run(710);
    assert!(!net_isolated());
    assert_eq!(pid_to_caller(711), 711);
}

#[test]
fn unshare_rules() {
    let _g = setup();
    user_proc(720, 1000);
    assert_eq!(sys_unshare(1), EINVAL, "an unknown flag");
    assert_eq!(sys_unshare(0), 0);
    assert_eq!(sys_unshare(CLONE_FS), 0, "nothing to do for CLONE_FS");
    assert_eq!(sys_unshare(CLONE_NEWNET), EPERM);
    add_thread(720, 721);
    assert_eq!(sys_unshare(CLONE_NEWUSER), EINVAL, "two threads");
    remove_thread(720, 721);
    assert_eq!(sys_unshare(CLONE_NEWUSER | CLONE_NEWNET | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS), 0);
    let n = ns_of(720);
    assert!(n.user.is_some() && n.net != 0 && n.mnt != 0 && n.uts != 0);
    assert_eq!(n.pid, 0, "a new PID namespace is for the children");
    assert!(n.pid_for_children.is_some());
    assert!(fake::task(720, |t| t.caps.in_userns).unwrap());
    assert!(fake::called("mount::copy_ns("));
    // The first child becomes the namespace's init, the next joins it
    assert_eq!(check_fork(), Ok(()), "the child will be the init");
    spawn_as(722, 720, 1000, 1000);
    let c = ns_of(722);
    assert_eq!(c.pid, n.pid_for_children.unwrap());
    assert_eq!(c.pid_inits, vec![722]);
    assert_eq!(c.pid_for_children, None);
    spawn_as(723, 720, 1000, 1000);
    assert_eq!(ns_of(723).pid_inits, vec![722]);
    assert_eq!(check_fork(), Ok(()));
    // Once the init is gone, no new process can enter the namespace
    linux::proc::PROCS.lock().get_mut(&722).unwrap().zombie = true;
    assert_eq!(check_fork(), Err(ENOMEM));
    run(723);
    assert_eq!(check_fork(), Err(ENOMEM));
    assert_eq!(pid_from_caller(1), 722);
}

fn remove_thread(pid: u64, tid: u64) {
    fake::remove_task(tid);
    linux::proc::thread_exited(pid, tid, 0, 0, (0, 0));
}

#[test]
fn uid_and_gid_maps() {
    let _g = setup();
    user_proc(730, 1000);
    // Before unsharing: the identity map, no writes
    assert_eq!(read_file("self/uid_map"), format!("{:>10} {:>10} {:>10}\n", 0, 0, u32::MAX));
    assert_eq!(read_file("self/setgroups"), "allow\n");
    assert_eq!(write_file("self/uid_map", b"0 1000 1"), EPERM, "the initial namespace's maps are fixed");
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    assert_eq!(read_file("self/uid_map"), "", "not written yet");
    assert_eq!(id_for_caller(1000, false), 65534, "unmapped");
    // Unprivileged: only the creator's own ID, once
    assert_eq!(write_file("self/uid_map", b"0 0 1"), EPERM, "not our ID");
    assert_eq!(write_file("self/uid_map", b"0 1000 2"), EPERM, "more than one");
    assert_eq!(write_file("self/uid_map", b"0 1000"), EINVAL, "two fields");
    assert_eq!(write_file("self/uid_map", b"0 1000 1 4"), EINVAL, "four fields");
    assert_eq!(write_file("self/uid_map", b"0 1000 0"), EINVAL, "count 0");
    assert_eq!(write_file("self/uid_map", b"4294967295 1000 2"), EINVAL, "overflow");
    assert_eq!(write_file("self/uid_map", b"x 1000 1"), EINVAL);
    let epoch = linux::ident_epoch();
    assert_eq!(write_file("self/uid_map", b"0 1000 1\n"), 9);
    assert!(linux::ident_epoch() > epoch, "the identity caches are stale now");
    assert_eq!(read_file("self/uid_map"), format!("{:>10} {:>10} {:>10}\n", 0, 1000, 1));
    assert_eq!(write_file("self/uid_map", b"0 1000 1"), EPERM, "written once");
    assert_eq!(id_for_caller(1000, false), 0);
    assert_eq!(id_for_caller(1001, false), 65534);
    // gid_map: only after setgroups is denied
    assert_eq!(write_file("self/gid_map", b"0 1000 1"), EPERM);
    assert_eq!(write_file("self/setgroups", b"maybe"), EINVAL);
    assert_eq!(write_file("self/setgroups", b"deny"), 4);
    assert!(setgroups_denied());
    assert_eq!(read_file("self/setgroups"), "deny\n");
    assert_eq!(write_file("self/gid_map", b"0 1000 1"), 8);
    assert_eq!(read_file("self/gid_map"), format!("{:>10} {:>10} {:>10}\n", 0, 1000, 1));
    assert_eq!(id_for_caller(1000, true), 0);
    assert_eq!(write_file("self/setgroups", b"allow"), EPERM, "fixed once gid_map is written");
    // Bad paths
    assert_eq!(write_file("nonsense", b"x"), EINVAL);
    assert_eq!(write_file("4242/uid_map", b"0 0 1"), EPERM, "no such process");
    assert_eq!(read_file("4242/uid_map"), "");
    assert_eq!(read_file("nonsense"), "");
    // A process in the initial namespace reads identity maps and is not denied
    user_proc(731, 1000);
    assert!(!setgroups_denied());
    assert_eq!(id_for_caller(1234, false), 1234);
}

#[test]
fn privileged_maps_and_nesting() {
    let _g = setup();
    user_proc(735, 0);
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    // Root with CAP_SETUID/SETGID over the system: any map (caps are in_userns now, so give
    // them back as host capabilities for the test)
    caps(735, (1 << 6) | (1 << 7));
    assert_eq!(write_file("735/uid_map", b"0 100000 65536"), 14);
    assert_eq!(write_file("735/gid_map", b"0 100000 65536"), 14);
    assert_eq!(write_file("735/setgroups", b"deny"), EPERM, "after gid_map");
    assert_eq!(id_for_caller(100_005, false), 5);
    assert_eq!(id_for_caller(5, false), 65534);
    // A nested namespace maps through both
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    caps(735, (1 << 6) | (1 << 7));
    assert_eq!(write_file("self/uid_map", b"10 5 1"), 6);
    assert_eq!(id_for_caller(100_005, false), 10);
    assert_eq!(id_for_caller(100_006, false), 65534);
    // Unprivileged in a nested namespace: the creator's ID as the parent sees it
    user_proc(736, 0);
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    caps(736, (1 << 6) | (1 << 7));
    assert_eq!(write_file("self/uid_map", b"1000 0 1"), 8);
    assert_eq!(write_file("self/gid_map", b"1000 0 1"), 8);
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0, "a child of the mapped namespace");
    caps(736, 0);
    assert_eq!(write_file("self/uid_map", b"0 999 1"), EPERM, "999 is not the creator in the parent");
    assert_eq!(write_file("self/uid_map", b"0 1000 1"), 8, "1000 is the creator as the parent sees it");
    assert_eq!(write_file("self/setgroups", b"deny"), 4);
    assert_eq!(write_file("self/gid_map", b"0 1000 1"), 8);
}

#[test]
fn user_namespace_limits() {
    let _g = setup();
    user_proc(740, 1000);
    assert_eq!(max_user_namespaces_text(), "63621\n");
    assert_eq!(set_max_user_namespaces(b"5"), EPERM, "needs CAP_SYS_RESOURCE");
    caps(740, CAP_SYS_RESOURCE);
    assert_eq!(set_max_user_namespaces(b"5"), EPERM, "the initial namespace's limit is fixed");
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    assert_eq!(set_max_user_namespaces(b"x"), EINVAL);
    caps(740, CAP_SYS_RESOURCE);
    assert_eq!(set_max_user_namespaces(b"1\n"), 2);
    assert_eq!(max_user_namespaces_text(), "1\n");
    // One child namespace allowed below
    let base = ns_of(740).user.clone();
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    assert_eq!(max_user_namespaces_text(), "1\n", "inherited");
    let child = ns_of(740).user.clone();
    linux::proc::PROCS.lock().get_mut(&740).unwrap().ns.user = base.clone();
    assert_eq!(sys_unshare(CLONE_NEWUSER), ENOSPC, "the limit of the namespace above");
    // A namespace that is gone no longer counts
    drop(child);
    linux::proc::PROCS.lock().get_mut(&740).unwrap().ns.user = base.clone();
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0, "the first child is gone: room again");
    // clone with CLONE_NEWUSER over the limit: the child stays in the parent's namespace
    let _second = ns_of(740).user.clone();
    linux::proc::PROCS.lock().get_mut(&740).unwrap().ns.user = base.clone();
    spawn_as(741, 740, 1000, 1000);
    after_clone(741, CLONE_NEWUSER);
    assert!(std::sync::Arc::ptr_eq(ns_of(741).user.as_ref().unwrap(), base.as_ref().unwrap()));
}

#[test]
fn user_namespace_depth() {
    let _g = setup();
    user_proc(745, 1000);
    for _ in 0..32 {
        assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    }
    assert_eq!(sys_unshare(CLONE_NEWUSER), EUSERS, "33 levels");
}

#[test]
fn proc_ns_files() {
    let _g = setup();
    user_proc(750, 0);
    assert!(is_ns_file("self/uid_map"));
    assert!(is_ns_file("750/ns/net"));
    assert!(is_ns_file("thread-self/setgroups"));
    assert!(is_ns_file("self/ns/pid_for_children"));
    assert!(!is_ns_file("self/ns/bogus"));
    assert!(!is_ns_file("abc/uid_map"));
    assert!(!is_ns_file("/uid_map"));
    assert!(!is_ns_file("self"));
    assert!(!is_ns_file("self/status"));
    // Initial namespaces show Linux's well-known numbers
    assert_eq!(ns_link("self/ns/user").unwrap(), "user:[4026531837]");
    assert_eq!(ns_link("750/ns/pid").unwrap(), "pid:[4026531836]");
    assert_eq!(ns_link("self/ns/pid_for_children").unwrap(), "pid:[4026531836]");
    assert_eq!(ns_link("self/ns/cgroup").unwrap(), "cgroup:[4026531835]");
    assert_eq!(ns_link("self/ns/bogus"), None);
    assert_eq!(ns_link("self/uid_map"), None);
    assert_eq!(ns_link("4242/ns/net"), None);
    assert_eq!(ns_link("x/ns/net"), None);
    // New ones get fresh numbers; a PID namespace for children has none until its init
    assert_eq!(sys_unshare(CLONE_NEWNET | CLONE_NEWPID), 0);
    let net = ns_link("self/ns/net").unwrap();
    assert!(net.starts_with("net:[") && net != "net:[4026531840]");
    assert_eq!(ns_link("self/ns/pid_for_children"), None);
    spawn(751, 750);
    let pfc = ns_link("self/ns/pid_for_children").unwrap();
    assert_eq!(pfc, ns_link("751/ns/pid").unwrap());
}

#[test]
fn setns_through_proc_files() {
    let _g = setup();
    user_proc(760, 0);
    spawn(761, 760);
    run(761);
    assert_eq!(sys_unshare(CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWCGROUP | CLONE_NEWNS), 0);
    let theirs = ns_of(761);
    run(760);
    // Bad descriptors
    assert_eq!(sys_setns(9, 0), EBADF);
    with_current_fds_mut(|f| f.install(3, FileDescriptor::ConsoleOut));
    assert_eq!(sys_setns(3, 0), EINVAL, "not a namespace file");
    with_current_fds_mut(|f| f.install(4, FileDescriptor::file("/etc/passwd")));
    assert_eq!(sys_setns(4, 0), EINVAL);
    open_ns(5, "761", "bogus");
    assert_eq!(sys_setns(5, 0), EINVAL);
    open_ns(6, "4242", "net");
    assert_eq!(sys_setns(6, 0), ESRCH);
    // Join the network namespace
    open_ns(7, "761", "net");
    assert_eq!(sys_setns(7, CLONE_NEWUTS), EINVAL, "nstype must match");
    assert_eq!(sys_setns(7, CLONE_NEWNET), 0);
    assert_eq!(ns_of(760).net, theirs.net);
    for (fd, kind) in [(8, "uts"), (9, "ipc"), (10, "cgroup")] {
        open_ns(fd, "761", kind);
        assert_eq!(sys_setns(fd as u64, 0), 0, "{kind}");
    }
    let mine = ns_of(760);
    assert_eq!((mine.uts, mine.ipc, mine.cgroup), (theirs.uts, theirs.ipc, theirs.cgroup));
    // The mount namespace: root and working directory move to its root
    fake::task(761, |t| {
        let mut f = t.fds.lock();
        f.root_ino = 77;
        f.root_mnt = 3;
    });
    with_current_fds_mut(|f| f.cwd_path = "/home".into());
    open_ns(11, "761", "mnt");
    assert_eq!(sys_setns(11, 0), 0);
    assert_eq!(with_current_fds_mut(|f| (f.root_ino, f.cwd_ino, f.cwd_mnt, f.cwd_path.clone())), (77, 77, 3, "/".to_string()));
    // Without CAP_SYS_ADMIN: EPERM
    caps(760, 0);
    assert_eq!(sys_setns(7, 0), EPERM);
}

#[test]
fn setns_user_and_pid_namespaces() {
    let _g = setup();
    user_proc(770, 1000);
    spawn_as(771, 770, 1000, 1000);
    run(771);
    assert_eq!(sys_unshare(CLONE_NEWUSER | CLONE_NEWPID), 0);
    spawn_as(772, 771, 1000, 1000); // init of 771's PID namespace
    run(770);
    // Joining a user namespace we own (below ours) works; it gives capabilities there
    open_ns(3, "771", "user");
    add_thread(770, 773);
    assert_eq!(sys_setns(3, CLONE_NEWUSER), EINVAL, "multithreaded");
    remove_thread(770, 773);
    assert_eq!(sys_setns(3, CLONE_NEWUSER), 0);
    assert!(fake::task(770, |t| t.caps.in_userns).unwrap());
    assert_eq!(sys_setns(3, CLONE_NEWUSER), EINVAL, "already in it");
    // PID namespace: for children, only one below ours
    open_ns(4, "772", "pid");
    assert_eq!(sys_setns(4, 0), 0);
    assert_eq!(ns_of(770).pid_for_children, Some(ns_of(772).pid));
    open_ns(5, "770", "pid");
    assert_eq!(sys_setns(5, 0), 0, "our own PID namespace: children stay in it");
    assert_eq!(ns_of(770).pid_for_children, None);
    // From inside, the outer namespace cannot be joined
    run(772);
    open_ns(3, "770", "pid");
    caps(772, CAP_SYS_ADMIN);
    assert_eq!(sys_setns(3, 0), EINVAL);
    // Another user's namespace: EPERM
    user_proc(774, 2000);
    assert_eq!(sys_unshare(CLONE_NEWUSER), 0);
    run(770);
    caps(770, 0);
    fake::task(770, |t| t.euid = 1000);
    // (back in the initial namespace for this check)
    linux::proc::PROCS.lock().get_mut(&770).unwrap().ns.user = None;
    open_ns(6, "774", "user");
    assert_eq!(sys_setns(6, 0), EPERM);
    // Joining the initial namespace again from inside one: EPERM (not below ours)
    run(774);
    open_ns(3, "770", "user");
    assert_eq!(sys_setns(3, 0), EPERM);
}

#[test]
fn setns_through_a_pidfd() {
    let _g = setup();
    user_proc(780, 0);
    spawn(781, 780);
    run(781);
    assert_eq!(sys_unshare(CLONE_NEWNET | CLONE_NEWUTS), 0);
    let theirs = ns_of(781);
    run(780);
    let fd = linux::pidfd::install(781, false) as u64;
    assert_eq!(sys_setns(fd, 0), EINVAL, "a pidfd needs the namespaces named");
    assert_eq!(sys_setns(fd, 1), EINVAL, "not a namespace flag");
    assert_eq!(sys_setns(fd, CLONE_NEWNET | CLONE_NEWUTS), 0);
    assert_eq!((ns_of(780).net, ns_of(780).uts), (theirs.net, theirs.uts));
    // The same user namespace together with others: accepted (nothing to change there)
    assert_eq!(sys_setns(fd, CLONE_NEWUSER | CLONE_NEWNET), 0);
    // A pidfd of a process that is gone
    let gone = linux::pidfd::install(4242, false) as u64;
    assert_eq!(sys_setns(gone, CLONE_NEWNET), ESRCH);
}

#[test]
fn for_child_without_new_pid_namespace() {
    let _g = setup();
    let n = Ns::default();
    let c = n.for_child(5);
    assert_eq!(c.pid, 0);
    assert!(c.pid_inits.is_empty());
}

/// wave 7, Group 7-3: the mount namespace notes for vfs-server (LX_NOTE_MNTNS = 10).
#[test]
fn mount_namespace_notes() {
    let _g = setup();
    const GONE: u64 = u64::MAX;
    // No vfs-server: nothing posted
    user_proc(790, 0);
    caps(790, CAP_SYS_ADMIN);
    assert_eq!(sys_unshare(CLONE_NEWNS), 0);
    assert!(!fake::called("lx::note_to("));
    // vfs-server hosts the file service: made (from the initial one)
    fake::set_ret("lx::vfs_host", 2);
    user_proc(791, 0);
    caps(791, CAP_SYS_ADMIN);
    fake::take_calls();
    assert_eq!(sys_unshare(CLONE_NEWNS), 0);
    let a = ns_of(791).mnt;
    assert_eq!(fake::take_calls().iter().filter(|c| c.starts_with("lx::note_to(")).cloned().collect::<Vec<_>>(), vec![format!("lx::note_to(2,10,{a},0,0)")]);
    // Unsharing again: the new one made from `a`, and `a` gone (nobody else in it)
    assert_eq!(sys_unshare(CLONE_NEWNS), 0);
    let b = ns_of(791).mnt;
    let notes: Vec<String> = fake::take_calls().into_iter().filter(|c| c.starts_with("lx::note_to(")).collect();
    assert_eq!(notes, vec![format!("lx::note_to(2,10,{b},{a},0)"), format!("lx::note_to(2,10,{a},{GONE},0)")]);
    // A clone into a new one: made from the parent's
    spawn_as(792, 791, 0, 0);
    after_clone(792, CLONE_NEWNS);
    let c = ns_of(792).mnt;
    assert!(fake::take_calls().contains(&format!("lx::note_to(2,10,{c},{b},0)")));
    // Leaving with others still in it: not gone; the last one leaving: gone
    spawn_as(793, 791, 0, 0);
    ns::mntns_left(b);
    assert!(!fake::called("lx::note_to("), "791 and 793 are still in it");
    linux::proc::PROCS.lock().get_mut(&791).unwrap().zombie = true;
    linux::proc::PROCS.lock().get_mut(&793).unwrap().zombie = true;
    ns::mntns_left(b);
    assert_eq!(fake::take_calls().into_iter().filter(|c| c.starts_with("lx::note_to(")).collect::<Vec<_>>(), vec![format!("lx::note_to(2,10,{b},{GONE},0)")]);
    // The initial namespace is never reported
    ns::mntns_left(0);
    ns::note_mntns(0, 5);
    assert!(!fake::called("lx::note_to("));
    fake::set_ret("lx::vfs_host", 0);
}

// ---------------------------------------------------------------- wave10 G7b-1: lx-proc's helpers

#[test]
fn ns_fd_target_and_facts() {
    let _g = setup();
    user_proc(790, 1000);
    spawn_as(791, 790, 1000, 1000);
    run(791);
    assert_eq!(sys_unshare(CLONE_NEWUSER | CLONE_NEWUTS | CLONE_NEWPID), 0);
    spawn_as(792, 791, 1000, 1000); // init of 791's PID namespace
    run(790);
    // the descriptor's target, as setns reads it
    open_ns(3, "791", "uts");
    let t = with_current_fds_mut(|f| ns_fd_target(f, 3, 0));
    assert_eq!(t, Ok((791, CLONE_NEWUTS)));
    assert_eq!(with_current_fds_mut(|f| ns_fd_target(f, 3, CLONE_NEWNET)), Err(EINVAL), "kind mismatch");
    assert_eq!(with_current_fds_mut(|f| ns_fd_target(f, 9, 0)), Err(EBADF));
    with_current_fds_mut(|f| f.install(4, FileDescriptor::file("/etc/passwd")));
    assert_eq!(with_current_fds_mut(|f| ns_fd_target(f, 4, 0)), Err(EINVAL));
    // facts of 791 seen from 790: its own user namespace (owned by 1000, below ours), a PID
    // namespace for its children only (its own is ours), one thread
    let f = ns_facts(791, 790).unwrap();
    let n = ns_of(791);
    assert_eq!(f[6], n.uts);
    assert_eq!(f[8], 1000, "owner");
    assert_eq!(f[9], 1, "within ours, not ours");
    assert_eq!(f[10], 0, "the same PID namespace");
    assert_eq!(f[11], 1);
    // 792 lives in the new PID namespace: below ours
    assert_eq!(ns_facts(792, 790).unwrap()[10], 1);
    // 790 seen from 791: same? no; within? no (ours is the initial one, theirs below)
    let g = ns_facts(790, 791).unwrap();
    assert_eq!(g[9], 0);
    assert_eq!(g[8], 0, "the initial namespace: owner 0");
    assert_eq!(ns_facts(790, 790).unwrap()[9], 3, "its own: within and the same");
    assert_eq!(ns_facts(792, 791).unwrap()[10], 1);
    assert_eq!(ns_facts(790, 792).unwrap()[10], 2, "above: neither");
    assert!(ns_facts(4242, 790).is_none());
}

#[test]
fn approved_unshare_and_setns_run_only_the_mechanism() {
    let _g = setup();
    user_proc(795, 1000);
    // without CAP_SYS_ADMIN: refused, unless lx-proc decided (and marked the call)
    assert_eq!(sys_unshare(CLONE_NEWUTS), EPERM);
    crate::lx::proc::approve(795, 272);
    assert_eq!(sys_unshare(CLONE_NEWUTS), 0);
    assert_ne!(ns_of(795).uts, 0);
    assert_eq!(sys_unshare(CLONE_NEWNET), EPERM, "the mark was used up");
    spawn_as(796, 1, 1000, 1000);
    run(796);
    caps(796, CAP_SYS_ADMIN);
    assert_eq!(sys_unshare(CLONE_NEWNET), 0);
    run(795);
    open_ns(3, "796", "net");
    assert_eq!(sys_setns(3, 0), EPERM);
    crate::lx::proc::approve(795, 308);
    assert_eq!(sys_setns(3, 0), 0);
    assert_eq!(ns_of(795).net, ns_of(796).net);
}
