//! The task subsystem's top-level API (`src/task/mod.rs`): spawning, blocking, sleeping,
//! exiting, killing, descriptor tables, and the per-CPU markers it keeps.
//!
//! Functions that never return (`exit`, `leave_retired`) are left through the yield: the
//! test's yield hook panics, and the test catches it.

mod common;
use common::*;

use hydra_hosttests_t31::task::{self, TaskId, TaskPersonality, TaskPriority, TaskState};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::Ordering;

fn escape() {
    panic!("escaped through the yield");
}

/// Runs `f`, which must end in a yield that never returns; returns the panic message.
fn run_until_yield(f: impl FnOnce()) -> String {
    *fake::YIELD_MODE.lock().unwrap() = fake::YieldMode::Hook;
    *fake::YIELD_HOOK.lock().unwrap() = Some(escape);
    let r = catch_unwind(AssertUnwindSafe(f));
    *fake::YIELD_MODE.lock().unwrap() = fake::YieldMode::Count;
    let e = r.expect_err("it returned");
    e.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| e.downcast_ref::<String>().cloned()).unwrap_or_default()
}

fn spawn(name: &'static str) -> u64 {
    task::spawn(name, noop, TaskPriority::Normal).0
}

#[test]
fn preemptible_marks_a_wait_point_while_it_runs() {
    let _w = booted();
    let inside = task::preemptible(|| task::PREEMPT_POINTS.load(Ordering::SeqCst));
    assert_eq!(inside, 1);
    assert_eq!(task::PREEMPT_POINTS.load(Ordering::SeqCst), 0);
}

#[test]
fn before_the_scheduler_starts_yields_and_blocks_do_nothing_and_sleeps_spin_on_the_clock() {
    let _w = world();
    assert!(!task::is_active());
    task::yield_now();
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 0);
    assert_eq!(task::block_current(), TaskId(0));
    task::sleep_ticks(3);
    assert_eq!(fake::PIT_SLEPT.load(Ordering::SeqCst), 3);
    task::sleep_ms(50);
    assert_eq!(fake::PIT_SLEPT.load(Ordering::SeqCst), 8);
    let deadline = fake::now_ns() + 25_000_000;
    task::sleep_until_ns(deadline);
    assert!(fake::now_ns() >= deadline);
    assert_eq!(task::current_service(), None);
    assert_eq!(task::current_personality(), TaskPersonality::Hydra);
    assert!(task::with_current_task_mut(|t| t.id).is_none());
    // The fallback descriptor table, set up on first use
    let open = task::with_current_fds_mut(|f| f.open);
    assert_eq!(open, 3);
    task::tick_on_return();
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 0);
}

#[test]
fn block_current_blocks_and_yields() {
    let _w = booted();
    assert_eq!(task::block_current(), TaskId(0));
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 1);
    assert!(task::unblock_task(TaskId(0)));
}

#[test]
fn sleeps_put_the_current_task_to_sleep_in_the_scheduler() {
    let _w = booted();
    let now = fake::ticks();
    task::sleep_ticks(4);
    assert_eq!(state(0), Some(TaskState::Sleeping { wake_tick: now + 4 }));
    with(0, |t| t.state = TaskState::Running);
    task::sleep_ms(25); // 2.5 ticks at 100 Hz: rounded up
    assert_eq!(state(0), Some(TaskState::Sleeping { wake_tick: now + 3 }));
    with(0, |t| t.state = TaskState::Running);
    task::sleep_ms(0); // at least one tick
    assert_eq!(state(0), Some(TaskState::Sleeping { wake_tick: now + 1 }));
    with(0, |t| t.state = TaskState::Running);
    // Precise: a deadline already past returns at once
    let yields = fake::YIELDS.load(Ordering::SeqCst);
    task::sleep_until_ns(fake::now_ns() - 1);
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), yields);
    let d = fake::now_ns() + 15_000_000;
    task::sleep_until_ns(d);
    assert_eq!(with(0, |t| t.wake_ns), d);
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), yields + 1);
    // Without a running timer the scheduler is not used
    with(0, |t| t.state = TaskState::Running);
    fake::PIT_ACTIVE.store(false, Ordering::SeqCst);
    task::sleep_ticks(2);
    task::sleep_ms(10);
    task::sleep_until_ns(fake::now_ns() + 10_000_000);
    assert_eq!(state(0), Some(TaskState::Running));
}

#[test]
fn a_tick_deferred_during_a_system_call_runs_on_its_way_out() {
    let _w = booted();
    task::tick_on_return();
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 0);
    task::TICK_DEFERRED.store(1, Ordering::SeqCst);
    task::tick_on_return();
    assert_eq!(fake::YIELDS.load(Ordering::SeqCst), 1);
    assert_eq!(task::TICK_DEFERRED.load(Ordering::SeqCst), 0);
    assert_eq!(task::TICK_YIELD.load(Ordering::SeqCst), 1, "the yield vector runs a tick's pass");
}

#[test]
fn on_current_kernel_stack_accepts_anything_when_the_stack_is_unknown() {
    let _w = booted();
    assert!(task::on_current_kernel_stack(0x1234));
    task::CURRENT_KSTACK[0].store(0x10_000, Ordering::SeqCst);
    task::CURRENT_KSTACK[1].store(0x20_000, Ordering::SeqCst);
    assert!(task::on_current_kernel_stack(0x18_000));
    assert!(!task::on_current_kernel_stack(0x20_000));
    assert!(!task::on_current_kernel_stack(0x8_000));
}

#[test]
fn exit_closes_its_descriptors_and_dies() {
    let _w = booted();
    let a = spawn("a");
    assert_eq!(yield_on(0), a);
    let msg = run_until_yield(|| task::exit());
    assert_eq!(msg, "escaped through the yield");
    assert_eq!(state(a), Some(TaskState::Dead));
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 1, "its own table was closed while it was alive");
}

#[test]
fn exit_group_ends_the_whole_process() {
    let _w = booted();
    let p = spawn("p");
    let t1 = spawn("t1");
    with(t1, |t| t.tgid = p);
    assert_eq!(yield_on(0), p);
    run_until_yield(|| task::exit_group());
    assert_eq!(state(p), Some(TaskState::Dead));
    assert_eq!(state(t1), Some(TaskState::Dead));
    // t1's table went to the pending list and was closed by exit's close_retired
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 2);
}

#[test]
fn leave_retired_buries_the_retired_task() {
    let _w = booted();
    let a = spawn("a");
    assert_eq!(yield_on(0), a);
    assert!(!task::current_retired());
    // Another CPU retired it while it ran here
    with(a, |t| t.retired = true);
    task::CURRENT_RETIRED[0].store(true, Ordering::SeqCst);
    assert!(task::current_retired());
    run_until_yield(|| task::leave_retired());
    assert_eq!(state(a), Some(TaskState::Dead));
}

#[test]
fn kill_closes_the_victims_descriptors_unless_a_driver_call_is_in_progress() {
    let _w = booted();
    let a = spawn("a");
    let b = spawn("b");
    assert!(task::kill(TaskId(a)));
    assert!(!task::kill(TaskId(a)));
    assert!(!task::is_task_alive(TaskId(a)));
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 1);
    // During a driver call, closing waits (its caller may hold the locks closing takes)
    let s = spawn("srv");
    task::SCHEDULER.lock().begin_handoff(s, u64::MAX);
    assert!(task::kill(TaskId(b)));
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 1);
    task::SCHEDULER.lock().end_handoff(s);
    // Nor in a driver process
    with(0, |t| t.service = Some(3));
    assert_eq!(task::current_service(), Some(3));
    task::close_retired();
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 1);
    with(0, |t| t.service = None);
    task::close_retired();
    assert_eq!(fake::FDS_CLOSED.load(Ordering::SeqCst), 2);
}

#[test]
fn wait_task_returns_when_the_task_dies_or_on_ctrl_c() {
    let _w = booted();
    let a = spawn("victim");
    // The task dies while the waiter sleeps
    fn kill_victim() {
        let id = task::SCHEDULER.lock().task_named("victim").unwrap();
        task::SCHEDULER.lock().kill_task(id);
        task::SCHEDULER.lock().with_task_mut(TaskId(0), |t| t.state = TaskState::Running);
    }
    *fake::YIELD_MODE.lock().unwrap() = fake::YieldMode::Hook;
    *fake::YIELD_HOOK.lock().unwrap() = Some(kill_victim);
    assert!(task::wait_task(TaskId(a)));
    // Ctrl+C kills it and gives up
    let b = spawn("other");
    fake::CTRL_C.store(true, Ordering::SeqCst);
    assert!(!task::wait_task(TaskId(b)));
    assert!(!task::is_task_alive(TaskId(b)));
    assert!(task::wait_task(TaskId(999)));
}

#[test]
fn snapshots_credentials_and_the_current_task() {
    let _w = booted();
    let a = spawn("a");
    assert_eq!(task::get_task_snapshots().len(), 3);
    task::set_task_credentials(TaskId(a), 1000, 1000);
    assert_eq!(with(a, |t| (t.uid, t.euid, t.caps.effective)), (1000, 1000, 0));
    with(0, |t| t.personality = TaskPersonality::Linux);
    assert_eq!(task::current_personality(), TaskPersonality::Linux);
    assert_eq!(task::with_current_task_mut(|t| t.id), Some(TaskId(0)));
    let open = task::with_current_fds_mut(|f| {
        f.open = 9;
        f.open
    });
    assert_eq!(open, 9);
    assert_eq!(with(0, |t| t.fds.lock().open), 9, "the current task's own table");
    let u = task::spawn_user("u", noop, TaskPriority::Low);
    assert_eq!(with(u.0, |t| t.mode), task::PrivilegeMode::User);
}

// ------------------------------------------------------------------ programs

const PF_RX: u32 = 5;

fn static_pie() -> Vec<u8> {
    common::elf::Elf::new(common::elf::ET_DYN, 0x100, &[common::elf::load_with(PF_RX, 0, 0, 0x1000, 0x1000)], 0x1000).put(0x100, b"MAIN").bytes
}

fn dynamic_pie(interp: &str) -> Vec<u8> {
    let mut path = interp.as_bytes().to_vec();
    path.push(0);
    common::elf::Elf::new(
        common::elf::ET_DYN,
        0x200,
        &[
            common::elf::Ph { ty: common::elf::PT_INTERP, flags: 4, offset: 0x800, vaddr: 0x800, filesz: path.len() as u64, memsz: path.len() as u64 },
            common::elf::load_with(PF_RX, 0, 0, 0x1000, 0x1000),
        ],
        0x1000,
    )
    .put(0x800, &path)
    .bytes
}

fn ld_so() -> Vec<u8> {
    common::elf::Elf::new(common::elf::ET_DYN, 0x400, &[common::elf::load_with(PF_RX, 0, 0, 0x800, 0x2000)], 0x800).put(0x400, b"LDSO").bytes
}

/// Frames for address spaces, and the vDSO made once.
fn frames() {
    common::global_frames();
    let mut mm = hydra_hosttests_t31::memory::vm::Mm::new().unwrap();
    let _ = hydra_hosttests_t31::arch::vdso::map(&mut mm);
}

#[test]
fn spawn_linux_elf_loads_a_pie_into_its_own_address_space() {
    let _w = booted();
    frames();
    let id = task::spawn_linux_elf("prog", &static_pie(), &["prog", "-v"], TaskPriority::Normal, 1000, 1000).unwrap().0;
    with(id, |t| {
        assert!(t.mm.is_some());
        assert_eq!(t.exe_path(), "/bin/prog", "bare names are in /bin");
        assert_eq!(&t.cmdline.as_ref().unwrap()[..], b"prog\0-v\0");
        assert_eq!(t.personality, TaskPersonality::Linux);
        assert_eq!((t.uid, t.gid), (1000, 1000));
        assert_ne!(t.regs.cr3, 0);
        assert_eq!(t.regs.cs, 0x2b);
    });
    let id2 = task::spawn_linux_elf("abs", &static_pie(), &["/opt/abs"], TaskPriority::Normal, 0, 0).unwrap().0;
    assert_eq!(with(id2, |t| t.exe_path().to_string()), "/opt/abs");
    // Another system's program is refused
    let mut bsd = static_pie();
    bsd[7] = 9; // ELFOSABI_FREEBSD
    assert!(task::spawn_linux_elf("bsd", &bsd, &["bsd"], TaskPriority::Normal, 0, 0).is_err());
    // A dynamic program finds its interpreter in the file system or on the boot volume
    fake::FILES.lock().unwrap().insert("/lib/ld.so".into(), ld_so());
    assert!(task::spawn_linux_elf("dyn", &dynamic_pie("/lib/ld.so"), &["dyn"], TaskPriority::Normal, 0, 0).is_ok());
    fake::TAKEOVER.store(false, Ordering::SeqCst);
    fake::BOOT_FILES.lock().unwrap().insert("\\efi\\ld.so".into(), ld_so());
    assert!(task::spawn_linux_elf("dyn2", &dynamic_pie("/efi/ld.so"), &["dyn2"], TaskPriority::Normal, 0, 0).is_ok());
    assert!(task::spawn_linux_elf("dyn3", &dynamic_pie("/missing/ld.so"), &["dyn3"], TaskPriority::Normal, 0, 0).is_err());
    // Not loadable in a private space: the legacy path (which refuses junk)
    assert!(task::spawn_linux_elf("junk", b"junk", &[], TaskPriority::Normal, 0, 0).is_err());
}

#[test]
fn spawn_linux_chroot_runs_a_program_inside_its_root() {
    let _w = booted();
    frames();
    fake::PATHS.lock().unwrap().insert("/srv/root".into(), 50);
    fake::PATHS.lock().unwrap().insert("50:/bin/tool".into(), 51);
    fake::PATHS.lock().unwrap().insert("50:/lib/ld.so".into(), 52);
    fake::INODES.lock().unwrap().insert(51, static_pie());
    let id = task::spawn_linux_chroot("/srv/root", "/bin/tool", &["tool"], 0, 0).unwrap().0;
    assert_eq!(with(id, |t| { let f = t.fds.lock(); (f.root_ino, f.cwd_ino) }), (50, 50));
    assert!(task::spawn_linux_chroot("/nope", "/bin/tool", &[], 0, 0).unwrap_err().contains("cannot open root directory"));
    assert!(task::spawn_linux_chroot("/srv/root", "/bin/none", &[], 0, 0).unwrap_err().contains("not found"));
    fake::PATHS.lock().unwrap().insert("50:/bin/broken".into(), 53);
    assert!(task::spawn_linux_chroot("/srv/root", "/bin/broken", &[], 0, 0).unwrap_err().contains("read failed"));
    fake::PATHS.lock().unwrap().insert("50:/bin/text".into(), 54);
    fake::INODES.lock().unwrap().insert(54, b"#!/bin/sh\n".to_vec());
    assert!(task::spawn_linux_chroot("/srv/root", "/bin/text", &[], 0, 0).unwrap_err().contains("not a position-independent"));
    // A dynamic program: its interpreter is looked up inside the root
    fake::PATHS.lock().unwrap().insert("50:/bin/dyn".into(), 55);
    fake::INODES.lock().unwrap().insert(55, dynamic_pie("/lib/ld.so"));
    fake::INODES.lock().unwrap().insert(52, ld_so());
    assert!(task::spawn_linux_chroot("/srv/root", "/bin/dyn", &["dyn"], 0, 0).is_ok());
}

// wave11 GD begin
#[test]
fn the_display_and_input_services_run_at_the_highest_priority() {
    let _w = booted();
    frames();
    for ep in [hydra_hosttests_t31::ipc::protocol::ENDPOINT_DISPLAY_DEV, hydra_hosttests_t31::ipc::protocol::ENDPOINT_INPUT_SERVER] {
        let s = task::spawn_service("ui", &static_pie(), &["/drivers/ui"], ep).unwrap().0;
        assert_eq!(with(s, |t| t.priority), TaskPriority::Realtime);
    }
}
// wave11 GD end

#[test]
fn spawn_service_starts_a_driver_as_a_native_server() {
    let _w = booted();
    frames();
    let id = task::spawn_service("disk", &static_pie(), &["/drivers/disk", "irq=11"], 0x40).unwrap().0;
    with(id, |t| {
        assert_eq!(t.personality, TaskPersonality::Hydra);
        assert_eq!(t.service, Some(0x40));
        assert_eq!(t.priority, TaskPriority::High);
        assert_eq!(t.exe_path(), "/drivers/disk");
    });
    assert!(task::spawn_service("bad", b"junk", &[], 1).is_err());
    // A native process can start threads that serve the same endpoint
    assert_eq!(yield_on(0), id);
    let f = hydra_hosttests_t31::arch::syscall::SyscallFrame { rip: 1, rsp: 2, ..Default::default() };
    let th = task::SCHEDULER.lock().spawn_native_thread(&f, 0x4000, 0x8000, 7).unwrap().0;
    with(th, |t| {
        assert_eq!((t.regs.rip, t.regs.rsp, t.regs.rdi), (0x4000, 0x8000, 7));
        assert_eq!((t.tgid, t.service, t.personality), (id, Some(0x40), TaskPersonality::Hydra));
    });
    assert!(std::sync::Arc::ptr_eq(with(id, |t| t.mm.clone()).as_ref().unwrap(), with(th, |t| t.mm.clone()).as_ref().unwrap()));
    // A forked native process gets a copy-on-write copy of the address space
    let child = task::SCHEDULER.lock().spawn_clone(&f, [0; 5]).unwrap().0;
    assert!(!std::sync::Arc::ptr_eq(with(id, |t| t.mm.clone()).as_ref().unwrap(), with(child, |t| t.mm.clone()).as_ref().unwrap()));
    // and its CLONE_CHILD_SETTID word is written into the child's own memory
    let c2 = task::SCHEDULER.lock().spawn_clone(&f, [0x0100_0000, 0, 0, 0x1000, 0]).unwrap().0;
    let _ = c2;
}
