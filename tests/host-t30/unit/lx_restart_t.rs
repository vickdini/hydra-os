//! `src/lx/restart.rs`: configuration, the ladder through `gone`, waiting for a restarting
//! service, sending calls again, installs lost in a restart, ops 16..23.

use super::*;
use crate::ipc::protocol::*;
use crate::lx::tests::objs::{dev_at, new_obj, obj_handler};
use crate::lx::tests::{handler, start, world};
use crate::world::Task;
use std::sync::{Arc as StdArc, Mutex as StdMutex};

const T: u8 = LXS_TEST;

#[test]
fn configuration_boot_words_and_fw_cfg() {
    let _sim = world();
    assert_eq!(class(T), RestartClass::FailObjects);
    configure(T, RestartClass::Transparent);
    assert_eq!(class(T), RestartClass::Transparent);
    // A boot word wins over the supervisor's configuration
    boot_word(T, RestartClass::EndLinux);
    configure(T, RestartClass::Transparent);
    assert_eq!(class(T), RestartClass::EndLinux);
    assert!(crate::fake::logged("(set at boot)"));
    crate::fake::rec(|r| r.fwcfg.insert("opt/hydra/restart.sec".into(), b"transparent\n".to_vec()));
    fw_cfg(LXS_SEC, "sec");
    assert_eq!(class(LXS_SEC), RestartClass::Transparent);
    crate::fake::rec(|r| r.fwcfg.insert("opt/hydra/restart.ipc".into(), b"bogus".to_vec()));
    fw_cfg(LXS_IPC, "ipc");
    assert!(crate::fake::logged("unknown restart class"));
    fw_cfg(LXS_NET, "net");
    assert_eq!(class(LXS_NET), RestartClass::FailObjects);
    // Ids out of range share the last entry
    assert_eq!(idx(200), MAX_SVC - 1);
}

#[test]
fn the_ladder_through_gone() {
    let _sim = world();
    configure(T, RestartClass::Transparent);
    let d = gone(T);
    assert!(d.restart && d.class == RestartClass::Transparent);
    assert!(restarting(T) && keeps_objects(T) && may_restart(T) && !down(T));
    online(T);
    assert!(!restarting(T));
    // A second crash within 30 s: one class down, kept state reset
    let d = gone(T);
    assert!(d.reset_kept);
    assert!(crate::fake::logged("kept state reset"));
    online(T);
    // A third: given up
    let d = gone(T);
    assert!(!d.restart);
    assert!(down(T) && !may_restart(T) && !restarting(T));
    assert!(crate::fake::logged("not restarted again"));
    assert!(summary().contains("svc 11:"), "{}", summary());
    // Restarted by hand: a fresh ladder, callers wait from now on
    started_by_hand(T);
    assert!(restarting(T) && !down(T));
    // A deliberate restart is not counted
    online(T);
    deliberate(T);
    let d = gone(T);
    assert!(d.restart);
    // deliberate of a service given up makes it startable
    reset();
    for _ in 0..3 {
        gone(T);
    }
    assert!(down(T));
    deliberate(T);
    assert!(!down(T));
    // started_by_hand of a service that is up only resets the ladder
    online(T);
    started_by_hand(T);
    assert!(!restarting(T));
}

#[test]
fn waiting_for_a_restarting_service() {
    let sim = world();
    // Online already, or not restarting at all
    assert_eq!(wait_online(T, &|| true), Ok(()));
    assert_eq!(wait_online(T, &|| false), Err(EIO));
    // Restarting: it comes back
    set_restarting(T, true);
    let flag = StdArc::new(std::sync::atomic::AtomicBool::new(false));
    let f2 = flag.clone();
    sim.spawn(Task::linux(101, 101), move || {
        f2.store(true, core::sync::atomic::Ordering::Release);
        online(T);
    });
    let f3 = flag.clone();
    assert_eq!(wait_online(T, &move || f3.load(core::sync::atomic::Ordering::Acquire)), Ok(()));
    assert!(WAITED.load(core::sync::atomic::Ordering::Relaxed) >= 1);
    // It gives up meanwhile: EIO
    set_restarting(T, true);
    sim.spawn(Task::linux(102, 102), || set_restarting(T, false));
    assert_eq!(wait_online(T, &|| false), Err(EIO));
    // A signal: ERESTARTSYS
    set_restarting(T, true);
    crate::fake::set_signal(100, true);
    assert_eq!(wait_online(T, &|| false), Err(crate::compat::linux::proc::ERESTARTSYS));
}

#[test]
fn resend_closes_lost_installs_and_waits() {
    let sim = world();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let mark = install_mark();
    // An object installed for this thread's call whose answer was lost
    let fd = new_obj(40, LX_OBJ_KIND_SVCTEST);
    assert!(install_mark() > mark);
    let _ = dev_at(fd);
    // Not idempotent and being served: EIO (the install is closed anyway)
    assert_eq!(resend(T, LX_RESEND_MAYBE, LX_TEST_NR, &[3, 0, 0, 0, 0, 0], mark, &|| true), Err(EIO));
    assert!(crate::task::with_current_fds_mut(|t| t.get(fd as usize).is_none()));
    assert!(crate::fake::logged("closed 1 descriptor(s) installed for a call lost in a restart"));
    // Queued: sent again once the service is back
    assert_eq!(resend(T, LX_RESEND, LX_TEST_NR, &[3, 0, 0, 0, 0, 0], install_mark(), &|| true), Ok(()));
    assert_eq!(RESENT.load(core::sync::atomic::Ordering::Relaxed), 1);
    let _ = s;
}

#[test]
fn service_ops_kept_list_dead_adopt_info() {
    let sim = world();
    let r = StdArc::new(StdMutex::new(Vec::new()));
    let r2 = r.clone();
    let s = start(&sim, LXS_TEST, 300, 1, true, obj_handler());
    let _d = dev_at(new_obj(41, LX_OBJ_KIND_SVCTEST));
    let x = s.x;
    let mut t = Task::server(320, 300, s.ep);
    t.mm = Some(crate::memory::vm::Mm::shared());
    sim.spawn(t, move || {
        let push = |v: i64| r2.lock().unwrap().push(v);
        // Kept state: mapped; sizes out of range; another size later
        push((svc_op(T, LX_SVC_KEPT, 8192, 0, 0) > 0) as i64);
        push(svc_op(T, LX_SVC_KEPT, 0, 0, 0));
        push(svc_op(T, LX_SVC_KEPT, (KEPT_MAX_PAGES + 1) * 4096, 0, 0));
        push(svc_op(T, LX_SVC_KEPT, 4096, 0, 0));
        // The live objects
        let mut buf = [LxSvcObj { slot: 0, kind: 0, key: 0 }; 4];
        push(svc_op(T, LX_SVC_LIST, buf.as_mut_ptr() as u64, 4, 0));
        push(buf[0].slot as i64);
        push(svc_op(T, LX_SVC_LIST, buf.as_mut_ptr() as u64, 0, 0));
        push(svc_op(T, LX_SVC_LIST, 0, 4, 0));
        // Dead slots
        push(svc_op(T, LX_SVC_DEAD, 41, 0, 0));
        push(svc_op(T, LX_SVC_DEAD, LX_OBJ_SLOTS as u64, 0, 0));
        // Nothing to adopt (not restarting)
        push(svc_op(T, LX_SVC_ADOPT, 0, 0, 0));
        // Info: configured, current, crashes, kept new
        push(svc_op(T, LX_SVC_INFO, 0, 0, 0));
        push(svc_op(T, 99, 0, 0, 0));
        push(svc_op(0, LX_SVC_INFO, 0, 0, 0));
        push(svc_op(14, LX_SVC_INFO, 0, 0, 0));
        let _ = x;
    });
    sim.run_others();
    let v = r.lock().unwrap().clone();
    let fo = RestartClass::FailObjects as i64;
    assert_eq!(v, vec![1, EINVAL, EINVAL, EBUSY, 1, 41, 0, EFAULT, 0, EINVAL, EINVAL, fo | fo << 4 | 1 << 24, EINVAL, EPERM, EPERM]);
    // A Transparent restart: the new instance adopts
    configure(T, RestartClass::Transparent);
    gone(T);
    let r3 = r.clone();
    sim.spawn(Task::server(321, 300, s.ep), move || r3.lock().unwrap().push(svc_op(T, LX_SVC_ADOPT, 0, 0, 0)));
    sim.run_others();
    assert_eq!(*r.lock().unwrap().last().unwrap(), 0);
    assert!(adopting(T));
    online(T);
    assert!(!adopting(T));
    // Kept memory that cannot be mapped (no address space)
    let r4 = r.clone();
    sim.spawn(Task::server(322, 300, s.ep), move || r4.lock().unwrap().push(svc_op(T, LX_SVC_KEPT, 8192, 0, 0)));
    sim.run_others();
    assert_eq!(*r.lock().unwrap().last().unwrap(), EFAULT);
}

#[test]
fn installs_ring_keeps_the_last_64() {
    let _sim = world();
    for i in 0..70 {
        installed(100, i);
    }
    assert_eq!(install_mark(), 70);
    // close_installed for another thread: nothing
    close_installed(0);
    let _ = handler(|_| (0, 0));
}

// wave7 GB begin
#[test]
fn an_add_key_lost_in_a_crash_is_sent_again_unless_it_makes_a_keyring() {
    let _sim = world();
    crate::fake::user_space_on();
    let user = b"user\0";
    let ring = b"keyring\0";
    let args = |t: &[u8]| [t.as_ptr() as u64, 0, 0, 0, (-1i64) as u64, 0];
    // Being served when lx-sec died: a user key is updated in place by the new instance
    assert_eq!(resend(T, LX_RESEND_MAYBE, 248, &args(user), install_mark(), &|| true), Ok(()));
    // A keyring would be made anew: EIO
    assert_eq!(resend(T, LX_RESEND_MAYBE, 248, &args(ring), install_mark(), &|| true), Err(EIO));
    // An unreadable type string: EIO
    let bad = crate::fake::alloc_pages(1);
    crate::fake::make_bad(bad);
    assert_eq!(resend(T, LX_RESEND_MAYBE, 248, &[bad, 0, 0, 0, 0, 0], install_mark(), &|| true), Err(EIO));
    // Not yet taken: sent again whatever it is
    assert_eq!(resend(T, LX_RESEND, 248, &args(ring), install_mark(), &|| true), Ok(()));
    assert!(restart_policy::add_key_resendable(b"logon") && !restart_policy::add_key_resendable(b"keyring") && !restart_policy::add_key_resendable(b"x"));
}
// wave7 GB end

// wave8 GX2 begin
/// lx-net's Transparent restart keeps its objects, so the count of watched sockets (which
/// switches net-server's readiness relay on) stays; a restart that drops the objects resets
/// it.
#[test]
fn a_transparent_restart_of_the_network_service_keeps_the_watched_count() {
    let sim = world();
    crate::lx::svc::tests::reset();
    crate::lx::svc::init(b"");
    configure(LXS_NET, RestartClass::Transparent);
    let _s = start(&sim, LXS_NET, 310, 1, true, handler(|_| (0, 0)));
    assert_eq!(crate::lx::svc::host_of(LXS_NET), LXS_NET);
    crate::lx::WATCHED_NET.store(2, Ordering::Release);
    crate::lx::server_gone(LXS_NET);
    assert!(restarting(LXS_NET) && keeps_objects(LXS_NET));
    assert_eq!(crate::lx::WATCHED_NET.load(Ordering::Acquire), 2);
    online(LXS_NET);
    // A second crash within 30 s: FailObjects (the ladder), the objects go stale
    crate::lx::server_gone(LXS_NET);
    assert!(!keeps_objects(LXS_NET));
    assert_eq!(crate::lx::WATCHED_NET.load(Ordering::Acquire), 0);
    crate::lx::svc::tests::reset();
    crate::lx::svc::tests::init_colocated(b"net=linux+ipc=linux");
}
// wave8 GX2 end

// wave8 GX2 begin
/// lx-ipc's FailObjects restart with the login screen running: the desktop is ended and the
/// login screen started again (a kernel task, `lx::desktop`); a Transparent restart or no
/// login screen starts nothing.
#[test]
fn an_ipc_crash_brings_the_login_screen_back() {
    let sim = world();
    crate::lx::svc::tests::reset();
    crate::lx::svc::init(b"");
    configure(LXS_IPC, RestartClass::FailObjects);
    let _s = start(&sim, LXS_IPC, 320, 1, true, handler(|_| (0, 0)));
    // No login screen: nothing
    crate::lx::server_gone(LXS_IPC);
    assert!(!sim.spawned().contains(&"lx-desktop"));
    online(LXS_IPC);
    crate::fake::rec(|r| r.display_manager = true);
    let _s2 = start(&sim, LXS_IPC, 330, 1, true, handler(|_| (0, 0)));
    crate::lx::desktop::mark(330_000);
    crate::lx::server_gone(LXS_IPC);
    assert!(sim.spawned().contains(&"lx-desktop"));
    crate::fake::rec(|r| r.display_manager = false);
    crate::lx::svc::tests::reset();
    crate::lx::svc::tests::init_colocated(b"net=linux+ipc=linux");
}
// wave8 GX2 end

// wave10 G10-C begin
/// The cgroup device programs lx-sec handed to the kernel stay enforced while lx-sec
/// restarts (Transparent, then FailObjects on the ladder); only a service the ladder gave up
/// takes them away (an empty list is handed to the kernel).
#[test]
fn device_programs_stay_while_lx_sec_restarts() {
    let sim = world();
    crate::lx::svc::tests::reset();
    crate::lx::svc::init(b"");
    configure(LXS_SEC, RestartClass::Transparent);
    let _s = start(&sim, LXS_SEC, 340, 1, true, handler(|_| (0, 0)));
    assert_eq!(crate::lx::svc::host_of(LXS_SEC), LXS_SEC);
    crate::fake::rec(|r| r.bpf_programs.clear());
    // A Transparent restart, then a second crash within 30 s (FailObjects): kept
    crate::lx::server_gone(LXS_SEC);
    assert!(restarting(LXS_SEC));
    online(LXS_SEC);
    crate::lx::server_gone(LXS_SEC);
    assert!(restarting(LXS_SEC));
    assert!(crate::fake::rec(|r| r.bpf_programs.is_empty()), "nothing cleared while lx-sec restarts");
    online(LXS_SEC);
    // A third: given up: the programs go
    crate::lx::server_gone(LXS_SEC);
    assert!(down(LXS_SEC));
    assert_eq!(crate::fake::rec(|r| r.bpf_programs.clone()), vec![Vec::<u8>::new()]);
    crate::lx::svc::tests::reset();
    crate::lx::svc::tests::init_colocated(b"net=linux+ipc=linux");
}
// wave10 G10-C end
