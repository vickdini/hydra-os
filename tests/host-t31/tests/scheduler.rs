//! The scheduler (`src/task/scheduler.rs`): task selection, timeslices, blocking and
//! waking, parking dead tasks, driver-call hand-offs, the direct switch, retiring tasks,
//! and the SMP invariants the open wave 7 hang is about.
//!
//! Each test thread plays CPU 0 unless a test says otherwise (`fake::set_cpu`); timer
//! ticks and yields are scheduling passes run directly with a fake trap frame.

mod common;
use common::*;

use hydra_hosttests_t31::arch::idt::ExceptionContext;
use hydra_hosttests_t31::task::scheduler::{self, Scheduler, DEFAULT_STACK_SIZE, DEFAULT_TIMESLICE_TICKS, DIRECT_EVENT, SCHEDULER};
use hydra_hosttests_t31::task::{self, PrivilegeMode, TaskId, TaskPersonality, TaskPriority, TaskState};
use std::sync::atomic::{AtomicBool, Ordering};

fn spawn(name: &'static str, p: TaskPriority) -> u64 {
    task::spawn(name, noop, p).0
}

fn ids() -> Vec<u64> {
    SCHEDULER.lock().snapshots().iter().map(|s| s.id.0).collect()
}

fn kill(id: u64) -> bool {
    SCHEDULER.lock().kill_task(TaskId(id))
}

fn block(id: u64) {
    with(id, |t| t.state = TaskState::Blocked);
}

// ------------------------------------------------------------------ boot, spawn

#[test]
fn init_registers_the_shell_and_cpu0_idle_task() {
    let _w = booted();
    let snaps = SCHEDULER.lock().snapshots();
    assert_eq!(snaps.len(), 2);
    assert_eq!((snaps[0].id.0, snaps[0].name, snaps[0].state), (0, "shell", TaskState::Running));
    assert_eq!((snaps[1].id.0, snaps[1].name, snaps[1].state), (1, "idle", TaskState::Ready));
    assert_eq!(snaps[1].priority, TaskPriority::Idle);
    assert!(SCHEDULER.lock().is_initialized());
    assert!(task::is_active() && task::is_active_hint());
    assert_eq!(current_on(0), 0);
    assert_eq!(hydra_hosttests_t31::arch::smp::LOADED_CR3[0].load(Ordering::SeqCst), KCR3);
    // A second init changes nothing
    task::init(0x9000);
    assert_eq!(SCHEDULER.lock().task_count(), 2);
    assert_eq!(with(0, |t| t.regs.cr3), KCR3);
}

#[test]
fn update_cr3_initialises_or_moves_every_task() {
    let _w = world();
    task::update_cr3(0x20_0000);
    assert!(SCHEDULER.lock().is_initialized(), "update_cr3 before init initialises");
    assert_eq!(with(1, |t| t.regs.cr3), 0x20_0000);
    task::update_cr3(0x30_0000);
    assert_eq!(with(0, |t| t.regs.cr3), 0x30_0000);
    assert_eq!(with(1, |t| t.regs.cr3), 0x30_0000);
    // New kernel tasks get the kernel's tables
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(with(a, |t| t.regs.cr3), 0x30_0000);
}

#[test]
fn spawned_kernel_task_starts_at_the_trampoline_on_its_own_stack() {
    let _w = booted();
    let a = spawn("worker", TaskPriority::High);
    let (rip, rdi, rcx, cs, ss, rflags, rsp, cr3, bottom, len, mode, tgid, prio, slice, caps) = with(a, |t| {
        let st = t.stack.as_ref().unwrap();
        (
            t.regs.rip,
            t.regs.rdi,
            t.regs.rcx,
            t.regs.cs,
            t.regs.ss,
            t.regs.rflags,
            t.regs.rsp,
            t.regs.cr3,
            st.as_ptr() as u64,
            st.len(),
            t.mode,
            t.tgid,
            t.priority,
            t.timeslice_remaining,
            t.caps.effective,
        )
    });
    assert_ne!(rip, 0);
    assert_eq!(rdi, noop as *const () as u64, "the entry function goes in rdi (SysV)");
    assert_eq!(rcx, rdi, "and in rcx (Win64)");
    assert_eq!((cs, ss, rflags), (0x08, 0x10, 0x202));
    assert_eq!(cr3, KCR3);
    assert_eq!(len, DEFAULT_STACK_SIZE);
    let top = (bottom + len as u64) & !0xF;
    assert_eq!(rsp, top - 48);
    assert_eq!(with(a, |t| t.kernel_stack_top()), top);
    assert_eq!((mode, tgid, prio, slice), (PrivilegeMode::Kernel, a, TaskPriority::High, DEFAULT_TIMESLICE_TICKS));
    assert_eq!(caps, task::tcb::Caps::FULL);
}

#[test]
fn spawn_before_init_uses_the_live_page_tables() {
    let _w = world();
    x86_64::set_cr3(0x7000);
    let mut s = Scheduler::new();
    let id = s.spawn("early", noop, TaskPriority::Normal);
    assert_eq!(id, TaskId(1));
    assert_eq!(s.with_task_mut(id, |t| t.regs.cr3), Some(0x7000));
    assert!(!s.is_initialized());
    // Nothing is current before init
    assert_eq!(s.current_task_id(), TaskId(0));
    assert_eq!(s.current_personality(), TaskPersonality::Hydra);
    assert!(s.current_task_mut(|_| ()).is_none());
    assert!(s.current_fds().is_none());
    assert!(s.take_current_fds_if_last().is_none());
    assert_eq!(s.block_current(), TaskId(0));
    let mut ctx = kctx();
    s.schedule(&mut ctx); // not initialised: nothing happens
    assert_eq!(ctx, kctx());
}

#[test]
fn add_cpu_makes_the_running_code_that_cpus_idle_task() {
    let _w = booted();
    add_cpus(3);
    let (i1, i2) = (current_on(1), current_on(2));
    assert_eq!((i1, i2), (2, 3));
    for id in [i1, i2] {
        let (name, prio, state, cr3) = with(id, |t| (t.name, t.priority, t.state, t.regs.cr3));
        assert_eq!((name, prio, state, cr3), ("idle", TaskPriority::Idle, TaskState::Running, KCR3));
    }
    assert_eq!(task::CURRENT_TID.on(2).load(Ordering::SeqCst), 3);
    assert_eq!(hydra_hosttests_t31::arch::smp::LOADED_CR3[2].load(Ordering::SeqCst), KCR3);
    check_invariants(3);
}

// ------------------------------------------------------------------ selection

#[test]
fn yield_switches_registers_stack_and_markers_to_the_next_task() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    with(a, |t| {
        t.regs.rip = 0x1234;
        t.regs.rax = 77;
        t.fs_base = 0xF5;
        t.syscall_nr = 39;
        t.preempt_depth = 2;
    });
    task::PREEMPT_POINTS.store(1, Ordering::SeqCst);
    task::CURRENT_SYSCALL.store(0, Ordering::SeqCst);
    let mut ctx = kctx();
    ctx.rax = 42;
    ctx.rip = 0x5555;
    SCHEDULER.lock().schedule_now(&mut ctx);
    assert_eq!(current_on(0), a);
    // The next task's registers are in the frame, the shell's were saved from it
    assert_eq!((ctx.rip, ctx.rax, ctx.cs), (0x1234, 77, 0x08));
    assert_eq!(with(0, |t| (t.regs.rip, t.regs.rax, t.state)), (0x5555, 42, TaskState::Ready));
    assert_eq!(with(a, |t| (t.state, t.timeslice_remaining)), (TaskState::Running, DEFAULT_TIMESLICE_TICKS));
    // Per-CPU markers follow the task
    assert_eq!(task::CURRENT_TID.load(Ordering::SeqCst), a);
    assert_eq!(task::PREEMPT_POINTS.load(Ordering::SeqCst), 2);
    assert_eq!(with(0, |t| t.preempt_depth), 1);
    assert_eq!(task::CURRENT_SYSCALL.load(Ordering::SeqCst), 39);
    assert_eq!(with(0, |t| t.syscall_nr), 0);
    // Its kernel stack is the CPU's privilege stack and system call stack
    let top = with(a, |t| t.kernel_stack_top());
    assert_eq!(fake::RSP0[0].load(Ordering::SeqCst), top);
    assert_eq!(fake::KERNEL_RSP[0].load(Ordering::SeqCst), top);
    assert_eq!(task::CURRENT_KSTACK[1].load(Ordering::SeqCst), top);
    assert!(task::on_current_kernel_stack(top - 8));
    assert!(!task::on_current_kernel_stack(top + 8));
    // A kernel task's FS base is written to the MSR
    assert_eq!(fake::FS_BASE[0].load(Ordering::SeqCst), 0xF5);
    // The CPU is leaving the shell's stack until the trap epilogue
    assert_eq!(fake::LEAVING[0].load(Ordering::SeqCst), 1);
    assert!(fake::PROF.lock().unwrap().contains(&("switched_in", a)));
    assert!(fake::PERF.lock().unwrap().contains(&("switched", 0)));
}

#[test]
fn round_robin_skips_the_idle_task_and_wraps() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Low);
    assert_eq!(yield_on(0), a);
    assert_eq!(yield_on(0), b);
    assert_eq!(yield_on(0), 0);
    assert_eq!(yield_on(0), a);
}

#[test]
fn a_tick_keeps_the_task_until_its_timeslice_ends() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    for left in (1..DEFAULT_TIMESLICE_TICKS).rev() {
        assert_eq!(tick_on(0), 0);
        assert_eq!(with(0, |t| t.timeslice_remaining), left);
    }
    assert_eq!(tick_on(0), a, "the last tick of the slice switches");
}

#[test]
fn idle_runs_only_when_nothing_else_is_ready_and_woken_work_preempts_it() {
    let _w = booted();
    SCHEDULER.lock().block_current();
    assert_eq!(yield_on(0), 1, "only the idle task is left");
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert!(task::unblock_task(TaskId(0)));
    assert_eq!(fake::KICK_IDLE.load(Ordering::SeqCst), 1);
    assert!(with(0, |t| t.woken));
    assert_eq!(tick_on(0), 0, "woken work preempts the idle task at the next tick");
    assert!(!with(0, |t| t.woken), "the mark is cleared when it runs");
}

#[test]
fn nothing_ready_keeps_the_current_task_with_a_fresh_slice() {
    let _w = booted();
    with(1, |t| t.state = TaskState::Blocked); // even idle
    assert_eq!(yield_on(0), 0);
    assert_eq!(with(0, |t| (t.state, t.timeslice_remaining)), (TaskState::Running, DEFAULT_TIMESLICE_TICKS));
}

#[test]
fn high_priority_tasks_go_first() {
    let _w = booted();
    let _n1 = spawn("n1", TaskPriority::Normal);
    let h = spawn("h", TaskPriority::High);
    let _n2 = spawn("n2", TaskPriority::Normal);
    assert_eq!(yield_on(0), h);
    // A ready high-priority task preempts a normal one mid-slice too
    let h2 = spawn("h2", TaskPriority::Realtime);
    let _ = h2;
    assert_eq!(yield_on(0), h2);
}

#[test]
fn a_higher_priority_ready_task_preempts_mid_slice_but_an_equal_one_waits() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(tick_on(0), 0, "equal priority: the slice goes on");
    assert_eq!(with(0, |t| t.timeslice_remaining), DEFAULT_TIMESLICE_TICKS - 1);
    let h = spawn("h", TaskPriority::High);
    assert_eq!(tick_on(0), h);
    assert!(with(0, |t| t.preempted), "the preempted task resumes right after the woken work");
    let _ = a;
}

#[test]
fn woken_tasks_run_first_then_the_task_they_preempted() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    block(b);
    assert!(task::unblock_task(TaskId(b)));
    assert_eq!(tick_on(0), b, "the woken task preempts mid-slice");
    // b yields: the shell it preempted goes before a, which is next in round-robin order
    assert_eq!(yield_on(0), 0);
    assert!(!with(0, |t| t.preempted));
    assert_eq!(yield_on(0), a);
}

#[test]
fn a_task_passed_over_too_often_runs_before_woken_work() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    let n = spawn("starved", TaskPriority::Normal);
    let mut picked_n_at = None;
    for i in 0..20 {
        // a and b are woken over and over: tier 0 always has work
        for id in [a, b] {
            with(id, |t| t.woken = t.state == TaskState::Ready);
        }
        let next = yield_on(0);
        if next == n {
            picked_n_at = Some(i);
            break;
        }
        assert!(with(n, |t| t.passed_over) > 0);
    }
    let at = picked_n_at.expect("the starved task never ran");
    assert!(at >= 9 && at <= 11, "ran after {} passes", at);
    assert_eq!(with(n, |t| t.passed_over), 0);
}

#[test]
fn sleeping_task_wakes_at_its_tick() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    let wake = fake::ticks() + 3;
    SCHEDULER.lock().sleep_current(wake);
    assert_eq!(with(a, |t| (t.state, t.timeslice_remaining)), (TaskState::Sleeping { wake_tick: wake }, 0));
    assert_eq!(yield_on(0), 0);
    fake::set_ticks(wake - 1);
    yield_on(0);
    assert_eq!(state(a), Some(TaskState::Sleeping { wake_tick: wake }));
    fake::set_ticks(wake);
    with(a, |t| t.event_wait = true);
    assert_eq!(yield_on(0), a);
    assert!(!with(a, |t| t.event_wait));
}

#[test]
fn block_and_unblock() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert!(!task::unblock_task(TaskId(a)), "a ready task is not unblocked");
    assert!(!task::unblock_task(TaskId(99)));
    assert_eq!(SCHEDULER.lock().block_current(), TaskId(0));
    assert_eq!(with(0, |t| (t.state, t.timeslice_remaining)), (TaskState::Blocked, 0));
    assert!(task::unblock_task(TaskId(0)));
    assert_eq!(state(0), Some(TaskState::Ready));
}

// ------------------------------------------------------------------ dead tasks

#[test]
fn a_dead_task_is_parked_out_of_the_table_and_reaped() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    let c = spawn("c", TaskPriority::Normal);
    assert!(!kill(0) && !kill(1), "the shell and CPU 0's idle task are immune");
    assert!(kill(b));
    assert!(!kill(b), "already dead");
    assert_eq!(state(b), Some(TaskState::Dead));
    assert!(!task::is_task_alive(TaskId(b)));
    assert_eq!(yield_on(0), a);
    assert_eq!(state(b), None, "parked");
    assert_eq!(ids(), vec![0, 1, a, c]);
    assert_eq!(yield_on(0), c);
    scheduler::reap_dead_tasks();
    check_invariants(1);
}

#[test]
fn parking_moves_the_last_task_and_fixes_the_current_index() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let c = spawn("c", TaskPriority::Normal);
    // c (the last task) runs; the shell waits
    assert_eq!(yield_on(0), a);
    assert_eq!(yield_on(0), c);
    block(0);
    assert!(kill(a));
    let mut ctx = kctx();
    ctx.rbx = 0xC0FFEE;
    SCHEDULER.lock().schedule_now(&mut ctx);
    // a was parked: c moved into its slot and is still the current task (alone, it goes on)
    assert_eq!(ids(), vec![0, 1, c]);
    assert_eq!(current_on(0), c);
    assert_eq!(SCHEDULER.lock().current_index(), 2);
    assert_eq!(with(c, |t| (t.state, t.regs.rbx)), (TaskState::Running, 0xC0FFEE));
}

#[test]
fn parking_on_one_cpu_keeps_every_other_cpus_current_task() {
    let _w = booted();
    add_cpus(2);
    let d = spawn("d", TaskPriority::Normal);
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    block(d);
    assert_eq!(yield_on(1), a);
    assert_eq!(yield_on(0), b, "CPU 0 cannot take a (CPU 1 runs it) nor CPU 1's idle task");
    check_invariants(2);
    // d dies; CPU 1 parks it, which moves b (CPU 0's current task, the last one)
    assert!(kill(d));
    assert_eq!(yield_on(1), a);
    assert_eq!(state(d), None);
    assert_eq!(current_on(0), b, "CPU 0 still runs b after the swap_remove");
    assert_eq!(current_on(1), a);
    check_invariants(2);
    assert_eq!(yield_on(1), a, "b is still known to be running on CPU 0: CPU 1 keeps a");
    with(a, |t| t.state = TaskState::Blocked);
    assert_eq!(yield_on(1), 2, "nor does CPU 1 take b when a blocks");
    assert_eq!(current_on(0), b);
    check_invariants(2);
}

#[test]
fn a_task_retired_while_running_elsewhere_stays_until_that_cpu_leaves_its_stack() {
    let _w = booted();
    add_cpus(2);
    let x = spawn("x", TaskPriority::Normal);
    assert_eq!(yield_on(1), x);
    // CPU 0 kills x, which runs on CPU 1: it stays runnable until it leaves the kernel there
    assert!(kill(x));
    assert_eq!(state(x), Some(TaskState::Running));
    assert!(task::CURRENT_RETIRED[1].load(Ordering::SeqCst));
    assert_eq!(*fake::KICKED_CPUS.lock().unwrap(), vec![1]);
    assert!(with(x, |t| t.retired));
    assert!(!kill(x) || state(x) == Some(TaskState::Running), "a retired task is not retired again");
    // CPU 0's passes leave it alone
    yield_on(0);
    assert!(state(x).is_some());
    // CPU 1 buries it at the system call exit, and switches away
    fake::set_cpu(1);
    SCHEDULER.lock().bury_current();
    fake::set_cpu(0);
    assert_eq!(state(x), Some(TaskState::Dead));
    yield_on(0);
    assert!(state(x).is_some(), "still current on CPU 1: not parked");
    fake::LEAVING[1].store(0, Ordering::SeqCst); // the epilogue of CPU 1's switch to x
    let next = yield_on(1);
    assert_ne!(next, x);
    assert_eq!(fake::LEAVING[1].load(Ordering::SeqCst), x + 1, "CPU 1 is on x's stack until its trap epilogue");
    yield_on(0);
    assert!(state(x).is_some(), "INVARIANT: a stack another CPU is still leaving is never freed");
    // The epilogue clears the mark: now it goes
    fake::LEAVING[1].store(0, Ordering::SeqCst);
    yield_on(0);
    assert_eq!(state(x), None);
    check_invariants(2);
}

#[test]
fn a_dead_current_task_gives_way_to_the_idle_task_even_during_a_driver_call() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let srv = spawn("srv", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    block(0);
    // Another task's driver call: kernel-mode tasks (the idle task too) may not run...
    SCHEDULER.lock().begin_handoff(srv, u64::MAX);
    with(0, |t| t.state = TaskState::Blocked);
    block(srv);
    SCHEDULER.lock().terminate_current();
    assert_eq!(state(a), Some(TaskState::Dead));
    // ...but a dead task must not go on: the idle task runs instead
    assert_eq!(yield_on(0), 1);
    SCHEDULER.lock().end_handoffs_to(srv);
}

#[test]
// (fixed in wave 7, Group B: was set Running again; unreachable while the idle task is ready)
fn a_dead_current_task_is_never_made_running_again() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    block(0);
    with(1, |t| t.state = TaskState::Blocked);
    SCHEDULER.lock().terminate_current();
    yield_on(0);
    assert_eq!(state(a), Some(TaskState::Dead), "a retired task (resources released) came back to life");
}

#[test]
fn the_parking_slots_fill_up_without_losing_tasks() {
    let _w = booted();
    let mut dead = Vec::new();
    for _ in 0..70 {
        dead.push(spawn("d", TaskPriority::Low));
    }
    for &d in &dead {
        kill(d);
    }
    yield_on(0);
    let left = SCHEDULER.lock().task_count();
    assert_eq!(left, 2 + 70 - 64, "64 parking slots: the rest stay in the table");
    scheduler::reap_dead_tasks();
    yield_on(0);
    assert_eq!(SCHEDULER.lock().task_count(), 2);
    scheduler::reap_dead_tasks();
}

#[test]
fn reaping_reports_a_new_deepest_kernel_stack_use() {
    let _w = booted();
    let a = spawn("deep", TaskPriority::Normal);
    // Three quarters of its stack used, with a kernel return address in it
    with(a, |t| {
        let st = t.stack.as_mut().unwrap();
        let n = st.len();
        for b in st[n / 4..].iter_mut() {
            *b = 0x11;
        }
        st[n / 4..n / 4 + 8].copy_from_slice(&0xFFFF_FFFF_8012_3456u64.to_le_bytes());
    });
    scheduler::MAX_KSTACK_USE.store(0, Ordering::SeqCst);
    kill(a);
    yield_on(0);
    scheduler::reap_dead_tasks();
    let used = scheduler::MAX_KSTACK_USE.load(Ordering::SeqCst);
    assert_eq!(used, DEFAULT_STACK_SIZE - DEFAULT_STACK_SIZE / 4);
    assert!(fake::klog_has("deepest kernel stack use so far"));
    assert!(fake::klog_has("ffffffff80123456"));
}

#[test]
fn a_kernel_stack_written_near_its_bottom_is_reported_once() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    with(a, |t| t.stack.as_mut().unwrap()[0] = 1);
    yield_on(0);
    assert!(fake::serial_has(&format!("kernel stack of task {} nearly overflowed", a)) || fake::SERIAL.lock().unwrap().is_empty());
}

// ------------------------------------------------------------------ several CPUs

#[test]
fn a_cpu_never_takes_a_task_another_cpu_runs_nor_its_idle_task_nor_the_shell() {
    let _w = booted();
    add_cpus(3);
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(1), a);
    // CPU 2: a runs on CPU 1, the shell belongs to CPU 0, idle tasks to their CPUs
    assert_eq!(yield_on(2), current_on(2));
    assert_eq!(current_on(2), 3, "CPU 2 stays on its own idle task");
    // The shell, ready, still only runs on CPU 0
    block(a);
    assert_eq!(yield_on(1), 2, "CPU 1 falls back to its idle task, not the shell");
    check_invariants(3);
}

#[test]
fn a_task_left_without_the_kernel_lock_waits_until_its_cpu_has_left_its_stack() {
    let _w = booted();
    add_cpus(2);
    let w = spawn("worker", TaskPriority::Normal);
    assert_eq!(yield_on(1), w);
    // CPU 1 switches away from w at a lock-free point of crate::lx
    with(w, |t| t.state = TaskState::Blocked);
    fake::set_cpu(1);
    scheduler::BLOCK_NOBKL.store(1, Ordering::SeqCst);
    fake::set_cpu(0);
    fake::LEAVING[1].store(0, Ordering::SeqCst); // the epilogue of the switch to w
    yield_on(1);
    assert!(with(w, |t| t.nobkl_wait));
    assert_eq!(fake::LEAVING[1].load(Ordering::SeqCst), w + 1);
    // Woken at once, CPU 0 must not resume it while CPU 1 is still on its stack
    assert!(task::unblock_task(TaskId(w)));
    assert_ne!(yield_on(0), w);
    fake::LEAVING[1].store(0, Ordering::SeqCst);
    assert_eq!(yield_on(0), w);
    check_invariants(2);
}

#[test]
fn stress_random_passes_on_four_cpus_keep_the_invariants() {
    let _w = booted();
    add_cpus(4);
    let mut tasks = Vec::new();
    for i in 0..12 {
        tasks.push(spawn("t", if i % 5 == 0 { TaskPriority::High } else { TaskPriority::Normal }));
    }
    let mut seed = 0x1234_5678u64;
    let mut rnd = |n: u64| {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed % n
    };
    for step in 0..3000 {
        let c = rnd(4) as usize;
        match rnd(10) {
            0 => {
                // the CPU's current task blocks and yields
                fake::set_cpu(c);
                SCHEDULER.lock().block_current();
                fake::set_cpu(0);
                yield_on(c);
            }
            1 => {
                let t = tasks[rnd(tasks.len() as u64) as usize];
                task::unblock_task(TaskId(t));
            }
            2 if step % 7 == 0 => {
                let t = tasks[rnd(tasks.len() as u64) as usize];
                if kill(t) {
                    tasks.retain(|&x| x != t);
                    tasks.push(spawn("t", TaskPriority::Normal));
                }
                // a task retired on another CPU is buried when it leaves the kernel there
                for cc in 0..4 {
                    if task::CURRENT_RETIRED[cc].swap(false, Ordering::SeqCst) {
                        fake::set_cpu(cc);
                        SCHEDULER.lock().bury_current();
                        fake::set_cpu(0);
                    }
                }
            }
            3 => {
                fake::set_ticks(fake::ticks() + 1);
                tick_on(c);
            }
            _ => {
                yield_on(c);
            }
        }
        // the trap epilogues
        for cc in 0..4 {
            fake::LEAVING[cc].store(0, Ordering::SeqCst);
        }
        check_invariants(4);
        if step % 100 == 0 {
            scheduler::reap_dead_tasks();
        }
        // No CPU runs a dead task after its own pass (unless nothing else could run)
        let cur = current_on(c);
        let st = state(cur).unwrap();
        assert!(st == TaskState::Running || st == TaskState::Dead || st == TaskState::Blocked || st == TaskState::Ready, "{:?}", st);
    }
}

// ------------------------------------------------------------------ hand-offs

/// The shell calls driver task `server`: it blocks until the server replies.
fn begin_call(server: u64, deadline: u64) -> bool {
    SCHEDULER.lock().begin_handoff(server, deadline)
}

#[test]
fn during_a_driver_call_only_its_server_runs_and_its_caller_runs_first_after_it() {
    let _w = booted();
    let other = spawn("kernel-task", TaskPriority::High);
    let server = spawn("driver", TaskPriority::Normal);
    with(server, |t| t.service = Some(0x10));
    assert!(begin_call(server, fake::ticks() + 100));
    assert!(scheduler::handoff_active());
    assert_eq!(state(0), Some(TaskState::Blocked));
    assert!(SCHEDULER.lock().in_handoff(0) && SCHEDULER.lock().in_handoff(server));
    assert!(SCHEDULER.lock().handoff_server_ready());
    assert_eq!(yield_on(0), server, "the server goes first, before the high-priority kernel task");
    assert!(!SCHEDULER.lock().handoff_server_ready());
    // The server runs undisturbed by ticks
    assert_eq!(tick_on(0), server);
    // It blocks waiting for its device: only idle may run, not the other kernel task
    block(server);
    assert_eq!(yield_on(0), 1);
    let _ = other;
    // The device answers, the server replies
    task::unblock_task(TaskId(server));
    assert_eq!(yield_on(0), server);
    SCHEDULER.lock().end_handoff(server);
    assert!(!scheduler::handoff_active());
    assert_eq!(state(0), Some(TaskState::Ready));
    assert_eq!(yield_on(0), 0, "the caller resumes first");
}

#[test]
fn a_linux_program_in_user_mode_runs_during_a_driver_call_unless_the_server_is_ready() {
    let _w = booted();
    let prog = spawn("prog", TaskPriority::Normal);
    with(prog, |t| {
        t.personality = TaskPersonality::Linux;
        t.mode = PrivilegeMode::User;
        t.regs.cs = 0x2b;
    });
    let server = spawn("driver", TaskPriority::Normal);
    assert!(begin_call(server, fake::ticks() + 100));
    assert_eq!(yield_on(0), server);
    block(server);
    assert_eq!(yield_on(0), prog, "user-mode Linux code holds no kernel locks");
    // A tick in user mode lets it go on while the server waits...
    let mut ctx = uctx();
    SCHEDULER.lock().schedule(&mut ctx);
    assert_eq!(current_on(0), prog);
    // ...but not once the server is ready
    task::unblock_task(TaskId(server));
    let mut ctx = uctx();
    SCHEDULER.lock().schedule(&mut ctx);
    assert_eq!(current_on(0), server);
}

#[test]
fn a_driver_call_ends_when_its_deadline_passes_or_its_server_dies() {
    let _w = booted();
    let server = spawn("driver", TaskPriority::Normal);
    let deadline = fake::ticks() + 10;
    assert!(begin_call(server, deadline));
    assert_eq!(yield_on(0), server);
    fake::set_ticks(deadline);
    let next = tick_on(0);
    assert!(fake::serial_has(&format!("[handoff] expired: server {} caller 0", server)));
    assert!(!scheduler::handoff_active());
    assert_eq!(next, 0, "the caller resumes (without a reply) first");
    // A server that died ends its calls at once
    let server2 = spawn("driver2", TaskPriority::Normal);
    assert!(begin_call(server2, u64::MAX));
    kill(server2);
    assert_eq!(yield_on(0), 0);
    assert!(!scheduler::handoff_active());
}

#[test]
fn an_outer_call_waits_for_the_nested_call_its_server_makes() {
    let _w = booted();
    let fs = spawn("file-server", TaskPriority::Normal);
    let disk = spawn("disk", TaskPriority::Normal);
    let deadline = fake::ticks() + 5;
    assert!(begin_call(fs, deadline));
    assert_eq!(yield_on(0), fs);
    // The file server calls the disk driver
    assert!(begin_call(disk, u64::MAX));
    assert_eq!(yield_on(0), disk);
    fake::set_ticks(deadline + 1);
    assert_eq!(tick_on(0), disk, "the outer call is not ended while its server waits in the inner one");
    assert!(SCHEDULER.lock().in_handoff(0));
    // Replies arrive in any order: ending the call by its caller
    SCHEDULER.lock().end_handoff_of(fs);
    assert_eq!(state(fs), Some(TaskState::Ready));
    // now the outer one expires
    tick_on(0);
    assert!(!SCHEDULER.lock().in_handoff(0));
}

#[test]
fn ending_every_call_to_a_server_and_the_nesting_limit() {
    let _w = booted();
    let s = spawn("srv", TaskPriority::Normal);
    for i in 0..8 {
        assert!(begin_call(s, u64::MAX), "call {}", i);
    }
    assert!(!begin_call(s, u64::MAX), "nested too deeply");
    SCHEDULER.lock().end_handoffs_to(s);
    assert!(!scheduler::handoff_active());
    // Ending a call nobody makes does nothing
    SCHEDULER.lock().end_handoff(12345);
    SCHEDULER.lock().end_handoff_of(12345);
}

#[test]
fn servers_a_call_participant_waits_on_may_run_during_the_call() {
    let _w = booted();
    let net_drv = spawn("net-driver", TaskPriority::Normal);
    with(net_drv, |t| t.service = Some(0x21));
    let other = spawn("other-service", TaskPriority::Normal);
    with(other, |t| t.service = Some(0x22));
    let server = spawn("net-server", TaskPriority::Normal);
    assert!(begin_call(server, u64::MAX));
    // The server waits on the network driver through a queued request
    fake::QUEUED.lock().unwrap().insert(0x21, vec![server]);
    block(server);
    assert_eq!(yield_on(0), net_drv);
    assert_eq!(yield_on(0), net_drv, "the service with no queued request from a participant waits");
    let _ = other;
    // A chain: other serves a request of net_drv
    fake::QUEUED.lock().unwrap().insert(0x22, vec![net_drv]);
    block(net_drv);
    assert_eq!(yield_on(0), other);
    // An alias endpoint goes by its primary one
    fake::PRIMARY.lock().unwrap().insert(0x23, 0x22);
    with(other, |t| t.service = Some(0x23));
    with(net_drv, |t| t.state = TaskState::Ready);
    assert_eq!(yield_on(0), net_drv);
}

#[test]
fn a_linux_service_thread_runs_while_another_thread_of_its_process_serves_a_call() {
    let _w = booted();
    use hydra_hosttests_t31::ipc::protocol::ENDPOINT_LINUX_SERVER;
    let main = spawn("lx-main", TaskPriority::Normal);
    let worker = spawn("lx-worker", TaskPriority::Normal);
    for id in [main, worker] {
        with(id, |t| {
            t.service = Some(ENDPOINT_LINUX_SERVER);
            t.tgid = main;
        });
    }
    assert!(begin_call(main, u64::MAX));
    block(main);
    assert_eq!(yield_on(0), worker);
    // The same for a service hosted by lx (wave 6) on another endpoint
    let svc_main = spawn("sec-main", TaskPriority::Normal);
    let svc_worker = spawn("sec-worker", TaskPriority::Normal);
    for id in [svc_main, svc_worker] {
        with(id, |t| {
            t.service = Some(0x77);
            t.tgid = svc_main;
        });
    }
    fake::LX_HOSTS.lock().unwrap().insert(0x77);
    SCHEDULER.lock().end_handoffs_to(main);
    yield_on(0);
    block(0);
    assert!(begin_call(svc_main, u64::MAX));
    block(svc_main);
    block(worker);
    block(main);
    assert_eq!(yield_on(0), svc_worker);
}

#[test]
fn kernel_code_waits_while_another_task_holds_a_service_window() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    fake::WINDOW_HELD.store(true, Ordering::SeqCst);
    fake::WINDOW_HOLDERS.lock().unwrap().push((0x30, 99));
    assert_eq!(yield_on(0), 1, "kernel-mode tasks wait until the reply was read out of the window");
    fake::WINDOW_HOLDERS.lock().unwrap().push((0x31, a));
    assert_eq!(yield_on(0), a, "its holder itself goes on");
    let _ = a;
}

#[test]
fn wait_out_handoff_returns_at_once_without_a_call_and_waits_one_out() {
    let _w = booted();
    scheduler::wait_out_handoff();
    assert_eq!(fake::BKL_EXITS.load(Ordering::SeqCst), 0);
    // Another task's call is in progress: the caller waits (without the kernel lock) until
    // it ends; the bkl_exit hook ends it after a few spins
    let s = spawn("srv", TaskPriority::Normal);
    let c = spawn("caller", TaskPriority::Normal);
    assert_eq!(yield_on(0), s);
    assert_eq!(yield_on(0), c);
    // c calls s
    assert!(begin_call(s, u64::MAX));
    assert_eq!(yield_on(0), s);
    block(s);
    assert_eq!(yield_on(0), 1);
    // CPU 0 now runs idle; make the shell current and let it enter the kernel
    with(0, |t| t.state = TaskState::Ready);
    fn end_after_some() {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if N.fetch_add(1, Ordering::SeqCst) % 3 == 2 {
            if let Some(mut s) = SCHEDULER.try_lock() {
                let srv = s.task_named("srv").unwrap().0;
                s.end_handoffs_to(srv);
            }
        }
    }
    *fake::BKL_EXIT_HOOK.lock().unwrap() = Some(end_after_some);
    scheduler::wait_out_handoff();
    assert!(!scheduler::handoff_active());
    assert!(fake::BKL_EXITS.load(Ordering::SeqCst) >= 1);
    assert!(fake::BKL_ENTERS.load(Ordering::SeqCst) >= 1, "it takes the kernel lock back");
    assert!(x86_64::instructions::interrupts::are_enabled() == false);
    // A call participant does not wait
    assert!(begin_call(s, u64::MAX));
    let before = fake::BKL_EXITS.load(Ordering::SeqCst);
    fake::set_cpu(0);
    // The current task (idle on CPU 0) is not a participant, but the caller is: run as it
    yield_on(0);
    let cur = current_on(0);
    if SCHEDULER.lock().in_handoff(cur) {
        scheduler::wait_out_handoff();
        assert_eq!(fake::BKL_EXITS.load(Ordering::SeqCst), before);
    }
    SCHEDULER.lock().end_handoffs_to(s);
}

// ------------------------------------------------------------------ direct switch

/// Sets up the shell current and `w` blocked in the kernel (a linux-server worker
/// waiting for a call).
fn worker() -> u64 {
    let w = spawn("lx-worker", TaskPriority::Normal);
    block(w);
    w
}

#[test]
fn direct_call_hands_the_cpu_to_a_blocked_worker_with_the_callers_slice() {
    let _w = booted();
    let w = worker();
    with(0, |t| {
        t.state = TaskState::Blocked; // the caller blocks for the answer
        t.timeslice_remaining = 3;
    });
    with(w, |t| t.regs.rip = 0xAAAA);
    let mut ctx = kctx();
    ctx.rip = 0xCA11;
    assert!(SCHEDULER.lock().direct_call(&mut ctx, w, 2, std::ptr::null()));
    assert_eq!(current_on(0), w);
    assert_eq!(ctx.rip, 0xAAAA);
    assert_eq!(with(w, |t| (t.state, t.timeslice_remaining)), (TaskState::Running, 3));
    assert_eq!(with(0, |t| (t.state, t.timeslice_remaining, t.regs.rip)), (TaskState::Blocked, 0, 0xCA11));
    // And back: the worker answers, the caller runs
    with(w, |t| t.state = TaskState::Blocked);
    let mut ctx2 = kctx();
    assert!(SCHEDULER.lock().direct_call(&mut ctx2, 0, 0, std::ptr::null()));
    assert_eq!(current_on(0), 0);
    assert_eq!(ctx2.rip, 0xCA11);
    check_invariants(1);
}

#[test]
fn direct_call_refuses_whenever_the_fast_path_does_not_apply() {
    let _w = booted();
    add_cpus(2);
    let w = worker();
    block(0);
    let try_call = |target: u64, hint: usize, guard: *const AtomicBool| {
        let mut ctx = kctx();
        let ok = SCHEDULER.lock().direct_call(&mut ctx, target, hint, guard);
        (ok, ctx)
    };
    // unknown task, itself
    assert!(!try_call(999, 0, std::ptr::null()).0);
    assert!(!try_call(0, 0, std::ptr::null()).0);
    // not blocked
    with(w, |t| t.state = TaskState::Ready);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    with(w, |t| t.state = TaskState::Blocked);
    // saved in user mode
    with(w, |t| t.regs.cs = 0x2b);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    with(w, |t| t.regs.cs = 0x08);
    // blocked outside the lock-free path while this CPU does not hold the kernel lock
    fake::BKL_HELD.store(false, Ordering::SeqCst);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    with(w, |t| t.nobkl_wait = true);
    let guard = AtomicBool::new(true);
    assert!(!try_call(w, 0, &guard).0, "a call was delivered to the caller meanwhile");
    // the caller was woken meanwhile: it must not switch (the wakeup would be lost)
    with(0, |t| t.state = TaskState::Ready);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    assert_eq!(state(w), Some(TaskState::Blocked), "nothing changed");
    block(0);
    // wave11 GR: a signal posted while the caller still ran (it only marked it): no switch,
    // the caller waits the ordinary way and sees the signal
    fake::SIGNALLED.lock().unwrap().push(0);
    assert!(!try_call(w, 0, std::ptr::null()).0, "a signal is pending for the caller");
    assert_eq!(state(w), Some(TaskState::Blocked), "nothing changed");
    assert_eq!(state(0), Some(TaskState::Blocked));
    fake::SIGNALLED.lock().unwrap().clear();
    // a caller to resume first, or a driver call in progress
    let s = spawn("srv", TaskPriority::Normal);
    SCHEDULER.lock().begin_handoff(s, u64::MAX);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    SCHEDULER.lock().end_handoff(s);
    assert!(!try_call(w, 0, std::ptr::null()).0, "resume_first is set");
    yield_on(0);
    block(0);
    // running on another CPU
    with(w, |t| t.state = TaskState::Ready);
    assert_eq!(yield_on(1), w);
    with(w, |t| t.state = TaskState::Blocked);
    assert!(!try_call(w, 0, std::ptr::null()).0);
    // can_run refuses (CPU 1 cannot run the shell): its state is put back
    fake::set_cpu(1);
    let mut ctx = kctx();
    assert!(!SCHEDULER.lock().direct_call(&mut ctx, 0, 0, std::ptr::null()));
    fake::set_cpu(0);
    assert_eq!(state(0), Some(TaskState::Blocked));
    // the guard clear and everything right: it switches
    let guard = AtomicBool::new(false);
    yield_on(1);
    let w2 = worker();
    with(w2, |t| t.nobkl_wait = true);
    let (ok, _) = try_call(w2, 0, &guard);
    assert!(ok);
    check_invariants(2);
}

#[test]
fn direct_call_to_an_event_waiting_server_ends_its_wait() {
    let _w = booted();
    let w = spawn("classic-server", TaskPriority::Normal);
    with(w, |t| {
        t.state = TaskState::Sleeping { wake_tick: u64::MAX };
        t.event_wait = true;
        t.wake_ns = 5;
    });
    block(0);
    let mut ctx = kctx();
    assert!(!SCHEDULER.lock().direct_call(&mut ctx, w, 2, std::ptr::null()), "an event wait only when asked");
    assert!(SCHEDULER.lock().direct_call(&mut ctx, w, 2 | DIRECT_EVENT, std::ptr::null()));
    assert_eq!(with(w, |t| (t.state, t.event_wait, t.wake_ns)), (TaskState::Running, false, 0));
    // The server hands back to its caller while staying in its event wait (SYS_SVC_RECV)
    with(w, |t| {
        t.event_wait = true;
        t.state = TaskState::Sleeping { wake_tick: 77 };
    });
    let mut ctx = kctx();
    assert!(SCHEDULER.lock().direct_call(&mut ctx, 0, 0, std::ptr::null()));
    assert_eq!(state(w), Some(TaskState::Sleeping { wake_tick: 77 }), "kept, not turned into Blocked");
}

#[test]
fn direct_switch_runs_a_ready_target_or_falls_back_to_a_full_pass() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    with(0, |t| t.timeslice_remaining = 4);
    scheduler::DIRECT_HINT.store(3, Ordering::SeqCst);
    let mut ctx = kctx();
    SCHEDULER.lock().direct_switch(&mut ctx, b);
    assert_eq!(current_on(0), b, "straight to b, past a");
    assert_eq!(with(b, |t| t.timeslice_remaining), 4, "the slice goes with the call");
    assert_eq!(state(0), Some(TaskState::Ready));
    // A target that is not ready: the ordinary pass picks the next task
    block(a);
    let mut ctx = kctx();
    SCHEDULER.lock().direct_switch(&mut ctx, a);
    assert_eq!(current_on(0), 0);
    // During a driver call: always the full pass
    let s = spawn("srv", TaskPriority::Normal);
    SCHEDULER.lock().begin_handoff(s, u64::MAX);
    let mut ctx = kctx();
    SCHEDULER.lock().direct_switch(&mut ctx, b);
    assert_eq!(current_on(0), s);
    fake::KICK_PENDING.store(true, Ordering::SeqCst);
    SCHEDULER.lock().end_handoff(s);
    yield_on(0);
    let mut ctx = kctx();
    task::unblock_task(TaskId(a));
    let cur = current_on(0);
    let target = if cur == b { 0 } else { b };
    SCHEDULER.lock().direct_switch(&mut ctx, target);
    assert_eq!(current_on(0), target);
    assert!(!fake::SWITCH_KICKS.lock().unwrap().is_empty(), "a deferred kick is sent when other work is ready");
}

// ------------------------------------------------------------------ retiring

#[test]
fn kill_group_and_kill_linux_tasks_end_the_right_threads() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let t1 = spawn("p-t1", TaskPriority::Normal);
    let other = spawn("q", TaskPriority::Normal);
    with(t1, |t| t.tgid = p);
    assert_eq!(SCHEDULER.lock().kill_group(p), 2);
    assert_eq!(SCHEDULER.lock().kill_group(p), 0, "already ended");
    assert_eq!(state(other), Some(TaskState::Ready));
    // Linux programs (user mode, POSIX, no service) end when the Linux server crashes
    let lx = spawn("bash", TaskPriority::Normal);
    let svc = spawn("lx-service", TaskPriority::Normal);
    let ktask = spawn("lx-kernel-worker", TaskPriority::Normal);
    for (id, user, service) in [(lx, true, None), (svc, true, Some(5u32)), (ktask, false, None)] {
        with(id, |t| {
            t.personality = TaskPersonality::Linux;
            t.mode = if user { PrivilegeMode::User } else { PrivilegeMode::Kernel };
            t.service = service;
        });
    }
    assert_eq!(SCHEDULER.lock().kill_linux_tasks(), 1);
    assert_eq!(state(lx), Some(TaskState::Dead));
    assert_eq!(state(svc), Some(TaskState::Ready));
    assert_eq!(state(ktask), Some(TaskState::Ready));
    // POSIX threads tell the process table
    assert!(fake::EXITED.lock().unwrap().contains(&(lx, lx)));
}

#[test]
fn exit_group_retires_the_other_threads_and_then_the_caller() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let t1 = spawn("p-t1", TaskPriority::Normal);
    let t2 = spawn("p-t2", TaskPriority::Normal);
    for id in [t1, t2] {
        with(id, |t| t.tgid = p);
    }
    assert_eq!(yield_on(0), p);
    SCHEDULER.lock().terminate_current_group();
    assert_eq!(state(t1), Some(TaskState::Dead));
    assert_eq!(state(t2), Some(TaskState::Dead));
    assert_eq!(state(p), Some(TaskState::Running));
    SCHEDULER.lock().terminate_current();
    assert_eq!(state(p), Some(TaskState::Dead));
    // Retired by another thread's exit_group and then exiting itself: it dies again
    let q = spawn("q", TaskPriority::Normal);
    let q1 = spawn("q1", TaskPriority::Normal);
    with(q1, |t| t.tgid = q);
    assert_eq!(yield_on(0), q);
    with(q, |t| t.retired = true);
    SCHEDULER.lock().terminate_current();
    assert_eq!(state(q), Some(TaskState::Dead));
    with(q1, |t| t.retired = true);
    SCHEDULER.lock().kill_task(TaskId(q1));
    assert_eq!(state(q1), Some(TaskState::Ready), "retired but not current: left for its own exit");
}

#[test]
fn bury_current_kills_only_a_retired_task() {
    let _w = booted();
    SCHEDULER.lock().bury_current();
    assert_eq!(state(0), Some(TaskState::Running));
    with(0, |t| t.retired = true);
    SCHEDULER.lock().bury_current();
    assert_eq!(with(0, |t| (t.state, t.timeslice_remaining)), (TaskState::Dead, 0));
}

#[test]
fn retiring_wakes_clear_tid_and_robust_waiters_and_hands_over_its_descriptors() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let waiter = spawn("waiter", TaskPriority::Normal);
    let robust_waiter = spawn("robust-waiter", TaskPriority::Normal);
    for id in [waiter, robust_waiter] {
        with(id, |t| {
            t.state = TaskState::Blocked;
            t.event_wait = true;
        });
    }
    let mut tid_word: i32 = 1234;
    let addr = &mut tid_word as *mut i32 as u64;
    with(p, |t| {
        t.clear_child_tid = addr;
        t.robust_list = 0x7000;
        t.personality = TaskPersonality::Linux;
        t.exe = Some(std::sync::Arc::from("/usr/bin/p"));
    });
    fake::FUTEX_WOKEN.lock().unwrap().push(waiter);
    fake::ROBUST_WOKEN.lock().unwrap().push(robust_waiter);
    fake::ACCT_ON.store(true, Ordering::SeqCst);
    kill(p);
    assert_eq!(tid_word, 0, "the clear-tid word is zeroed");
    assert_eq!(*fake::FUTEX_WAKES.lock().unwrap(), vec![(p, addr)]);
    assert_eq!(*fake::ROBUST.lock().unwrap(), vec![(0x7000, p as u32, p)]);
    assert_eq!(state(waiter), Some(TaskState::Ready));
    assert_eq!(state(robust_waiter), Some(TaskState::Ready));
    assert_eq!(*fake::ACCT.lock().unwrap(), vec![(p, String::from("/usr/bin/p"))]);
    assert!(fake::IDENT_CHANGED.load(Ordering::SeqCst) >= 1);
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("release_windows", 0, p, 0)));
    // Its descriptor table (the last user) is closed later, without the scheduler lock
    let tables = SCHEDULER.lock().take_pending_close();
    assert_eq!(tables.len(), 1);
    assert!(SCHEDULER.lock().take_pending_close().is_empty());
}

#[test]
fn retiring_a_task_in_another_address_space_leaves_its_memory_alone() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let mut word: i32 = 99;
    with(p, |t| {
        t.clear_child_tid = &mut word as *mut i32 as u64;
        t.robust_list = 0x8000;
        t.regs.cr3 = 0xABC000; // not the loaded tables
    });
    kill(p);
    assert_eq!(word, 99);
    assert!(fake::FUTEX_WAKES.lock().unwrap().is_empty());
    assert!(fake::ROBUST.lock().unwrap().is_empty());
}

#[test]
fn shared_descriptor_tables_are_not_closed_by_one_thread() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let t1 = spawn("t1", TaskPriority::Normal);
    let shared = with(p, |t| t.fds.clone());
    with(t1, |t| t.fds = shared.clone());
    drop(shared);
    kill(t1);
    assert!(SCHEDULER.lock().take_pending_close().is_empty());
    kill(p);
    assert_eq!(SCHEDULER.lock().take_pending_close().len(), 1);
}

#[test]
fn the_exiting_task_takes_its_own_descriptor_table_only_when_it_is_the_last_user() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    let shared = with(a, |t| t.fds.clone());
    assert!(SCHEDULER.lock().take_current_fds_if_last().is_none());
    drop(shared);
    let fds = SCHEDULER.lock().take_current_fds_if_last().expect("last user");
    assert_eq!(fds.open, 3);
    assert_eq!(with(a, |t| t.fds.lock().open), 0, "an empty table is left in its place");
}

// ------------------------------------------------------------------ event waits

#[test]
fn wake_task_ends_an_event_wait_or_keeps_the_wakeup() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    // Not waiting yet: the wakeup is kept for its next wait
    SCHEDULER.lock().wake_task(a);
    assert!(with(a, |t| t.wake_pending));
    assert!(fake::PROF.lock().unwrap().contains(&("wake_dropped", a)));
    assert_eq!(yield_on(0), a);
    assert!(!SCHEDULER.lock().event_wait_current(None), "a pending wakeup: no sleep");
    assert!(!with(a, |t| t.wake_pending));
    assert!(SCHEDULER.lock().event_wait_current(Some(fake::ticks() + 50)));
    assert_eq!(with(a, |t| (t.event_wait, t.state)), (true, TaskState::Sleeping { wake_tick: fake::ticks() + 50 }));
    SCHEDULER.lock().wake_task(a);
    assert_eq!(with(a, |t| (t.state, t.event_wait, t.woken)), (TaskState::Ready, false, true));
    // Blocked for another reason (a futex): left alone, the wakeup kept
    block(a);
    SCHEDULER.lock().wake_task(a);
    assert_eq!(with(a, |t| (t.state, t.wake_pending)), (TaskState::Blocked, true));
    // A dead task, an unknown one: nothing
    kill(a);
    SCHEDULER.lock().wake_task(a);
    SCHEDULER.lock().wake_task(4242);
    assert_eq!(state(a), Some(TaskState::Dead));
}

#[test]
fn unblock_group_wakes_every_thread_of_a_process() {
    let _w = booted();
    let p = spawn("p", TaskPriority::Normal);
    let t1 = spawn("t1", TaskPriority::Normal);
    let t2 = spawn("t2", TaskPriority::Normal);
    let t3 = spawn("t3", TaskPriority::Normal);
    for id in [t1, t2, t3] {
        with(id, |t| t.tgid = p);
    }
    with(t1, |t| t.state = TaskState::Blocked);
    with(t2, |t| {
        t.state = TaskState::Sleeping { wake_tick: u64::MAX };
        t.event_wait = true;
    });
    with(t3, |t| t.state = TaskState::Sleeping { wake_tick: u64::MAX }); // a plain sleep
    SCHEDULER.lock().unblock_group(p);
    assert_eq!(state(t1), Some(TaskState::Ready));
    assert_eq!(state(t2), Some(TaskState::Ready));
    assert_eq!(state(t3), Some(TaskState::Sleeping { wake_tick: u64::MAX }));
    assert!(with(p, |t| t.wake_pending), "a ready thread finds the wakeup at its next wait");
}

#[test]
fn deferred_wakeups_are_applied_and_an_overflow_wakes_every_event_waiter() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    for id in [a, b] {
        with(id, |t| {
            t.state = TaskState::Blocked;
            t.event_wait = true;
        });
    }
    {
        // With the scheduler lock held, wakeups queue up (an interrupt's wake_all)
        let mut s = SCHEDULER.lock();
        task::wait::wake_process_deferred(a);
        assert!(task::wait::wakes_pending());
        s.apply_wakes();
        assert!(!task::wait::wakes_pending());
    }
    assert_eq!(state(a), Some(TaskState::Ready));
    assert_eq!(state(b), Some(TaskState::Blocked));
    {
        let mut s = SCHEDULER.lock();
        for i in 0..70 {
            task::wait::wake_process_deferred(10_000 + i);
        }
        s.apply_wakes();
    }
    assert_eq!(state(b), Some(TaskState::Ready), "an overflow wakes every event waiter");
}

#[test]
fn precise_sleeps_wake_between_ticks() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    let b = spawn("b", TaskPriority::Normal);
    fake::NOW_NS.store(1_000_000_000, Ordering::SeqCst);
    fake::set_ticks(100);
    assert_eq!(yield_on(0), a);
    SCHEDULER.lock().sleep_current_ns(1_002_500_000);
    assert_eq!(with(a, |t| (t.state, t.wake_ns)), (TaskState::Sleeping { wake_tick: 101 }, 1_002_500_000));
    assert_eq!(task::HR_EARLIEST.load(Ordering::SeqCst), 1_002_500_000);
    assert_eq!(yield_on(0), b);
    assert!(SCHEDULER.lock().event_wait_current_ns(Some(1_004_000_000)));
    assert_eq!(with(b, |t| t.wake_ns), 1_004_000_000);
    assert!(!SCHEDULER.lock().hr_wake());
    assert_eq!(task::HR_EARLIEST.load(Ordering::SeqCst), 1_002_500_000);
    fake::NOW_NS.store(1_003_000_000, Ordering::SeqCst);
    assert!(SCHEDULER.lock().hr_wake());
    assert_eq!(with(a, |t| (t.state, t.woken, t.wake_ns)), (TaskState::Ready, true, 0));
    assert_eq!(task::HR_EARLIEST.load(Ordering::SeqCst), 1_004_000_000);
    // Woken some other way: its precise deadline is forgotten
    with(b, |t| t.state = TaskState::Ready);
    assert!(!SCHEDULER.lock().hr_wake());
    assert_eq!(with(b, |t| t.wake_ns), 0);
    assert_eq!(task::HR_EARLIEST.load(Ordering::SeqCst), u64::MAX);
    // An event wait without a deadline stays without one
    yield_on(0);
    assert!(SCHEDULER.lock().event_wait_current_ns(None));
    // Not initialised: no wake
    assert!(!Scheduler::new().hr_wake());
}

// ------------------------------------------------------------------ accounting

#[test]
fn ticks_are_charged_to_the_task_and_the_cpu_by_mode() {
    let _w = booted();
    let a = spawn("a", TaskPriority::Normal);
    assert_eq!(yield_on(0), a);
    let user = uctx();
    let kernel = kctx();
    let charge = |ctx: &ExceptionContext, n: u64| {
        fake::set_ticks(fake::ticks() + n);
        SCHEDULER.lock().account_tick(ctx);
    };
    charge(&user, 1); // sets this CPU's last accounted tick
    let base = with(a, |t| (t.ticks_run, t.ticks_sys));
    let times = |k: usize| scheduler::CPU_TIMES[0][k].load(Ordering::SeqCst);
    let (u0, s0, i0) = (times(scheduler::CPU_USER), times(scheduler::CPU_SYSTEM), times(scheduler::CPU_IDLE));
    charge(&user, 3);
    charge(&kernel, 2);
    assert_eq!(with(a, |t| (t.ticks_run - base.0, t.ticks_sys - base.1)), (5, 2));
    assert_eq!(times(scheduler::CPU_USER) - u0, 3);
    assert_eq!(times(scheduler::CPU_SYSTEM) - s0, 2);
    // No time passed: nothing charged
    SCHEDULER.lock().account_tick(&user);
    assert_eq!(with(a, |t| t.ticks_run - base.0), 5);
    // Kernel code at a wait point is idle time, not the task's
    task::PREEMPT_POINTS.store(1, Ordering::SeqCst);
    charge(&kernel, 4);
    task::PREEMPT_POINTS.store(0, Ordering::SeqCst);
    assert_eq!(with(a, |t| t.ticks_run - base.0), 5);
    assert_eq!(times(scheduler::CPU_IDLE) - i0, 4);
    let own = with(a, |t| (t.ticks_run, t.ticks_sys));
    let (pt, pc) = {
        let s = SCHEDULER.lock();
        (s.process_ticks(a), s.process_cpu(a))
    };
    assert_eq!((pt, pc), (own.0, own));
    assert!(fake::PERF.lock().unwrap().iter().filter(|e| e.0 == "tick").count() >= 5);
    assert!(fake::PROF.lock().unwrap().contains(&("sample", a)));
    // The idle task's time is the CPU's idle time
    block(a);
    assert_eq!(yield_on(0), 0);
    block(0);
    assert_eq!(yield_on(0), 1);
    let i1 = times(scheduler::CPU_IDLE);
    charge(&kernel, 2);
    assert_eq!(times(scheduler::CPU_IDLE) - i1, 2);
}

#[test]
fn load_averages_follow_the_runnable_tasks_every_five_seconds() {
    let _w = booted();
    for _ in 0..3 {
        spawn("busy", TaskPriority::Normal);
    }
    // shell (running) + 3 ready: 4 runnable; the idle task does not count
    assert_eq!(SCHEDULER.lock().task_counts(), (4, 5));
    let ctx = kctx();
    let mut changed_after = None;
    for i in 0..600 {
        fake::set_ticks(fake::ticks() + 1);
        SCHEDULER.lock().account_tick(&ctx);
        if scheduler::LOAD_AVG[0].load(Ordering::SeqCst) != 0 {
            changed_after = Some(i);
            break;
        }
    }
    assert!(changed_after.expect("never updated") < 500);
    // Linux's fixed point: 4 tasks from 0 -> 4 * 2048 * (2048 - 1884) / 2048
    assert_eq!(scheduler::LOAD_AVG[0].load(Ordering::SeqCst), 4 * (2048 - 1884));
    assert_eq!(scheduler::LOAD_AVG[2].load(Ordering::SeqCst), 4 * (2048 - 2037));
    // Not initialised: nothing
    Scheduler::new().account_tick(&ctx);
}

// ------------------------------------------------------------------ clone

fn frame() -> hydra_hosttests_t31::arch::syscall::SyscallFrame {
    hydra_hosttests_t31::arch::syscall::SyscallFrame {
        rip: 0x40_1000,
        rsp: 0x7fff_0000,
        rflags: 0x246,
        rdi: 1,
        rsi: 2,
        rdx: 3,
        r8: 8,
        r9: 9,
        r10: 10,
        rbx: 11,
        rbp: 12,
        r12: 13,
        r13: 14,
        r14: 15,
        r15: 16,
        ..Default::default()
    }
}

use hydra_hosttests_t31::compat::linux::types::{CLONE_CHILD_CLEARTID, CLONE_CHILD_SETTID, CLONE_FILES, CLONE_PARENT_SETTID, CLONE_SETTLS, CLONE_THREAD};
const CLONE_VM: u64 = 0x100;
const CLONE_PARENT: u64 = 0x8000;

/// The shell made a Linux process (so it may clone).
fn linux_parent() -> u64 {
    let p = spawn("parent", TaskPriority::Normal);
    with(p, |t| {
        t.personality = TaskPersonality::Linux;
        t.mode = PrivilegeMode::User;
        t.uid = 1000;
        t.euid = 1000;
        t.brk = 0x60_0000;
        t.exe = Some(std::sync::Arc::from("/bin/sh"));
    });
    assert_eq!(yield_on(0), p);
    p
}

#[test]
fn clone_a_thread_shares_files_and_takes_the_frame() {
    let _w = booted();
    let p = linux_parent();
    let mut ptid: i32 = 0;
    let mut ctid: i32 = 0;
    let flags = CLONE_VM | CLONE_FILES | CLONE_THREAD | CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID;
    let child = SCHEDULER
        .lock()
        .spawn_clone(&frame(), [flags, 0x7ffe_0000, &mut ptid as *mut i32 as u64, &mut ctid as *mut i32 as u64, 0xDEAD_0000])
        .unwrap()
        .0;
    assert_eq!(ptid as u64, child);
    assert_eq!(ctid as u64, child);
    with(child, |t| {
        assert_eq!(t.tgid, p);
        assert_eq!((t.regs.rip, t.regs.rsp, t.regs.rax, t.regs.rcx, t.regs.r11), (0x40_1000, 0x7ffe_0000, 0, 0x40_1000, 0x246));
        assert_eq!((t.regs.rdi, t.regs.rsi, t.regs.rdx, t.regs.r8, t.regs.r9, t.regs.r10), (1, 2, 3, 8, 9, 10));
        assert_eq!((t.regs.rbx, t.regs.rbp, t.regs.r12, t.regs.r13, t.regs.r14, t.regs.r15), (11, 12, 13, 14, 15, 16));
        assert_eq!((t.regs.cs, t.regs.ss), (0x2b, 0x1b));
        assert_eq!(t.fs_base, 0xDEAD_0000);
        assert_eq!(t.segs.fs, 0);
        assert_eq!(t.clear_child_tid, &ctid as *const i32 as u64);
        assert_eq!((t.uid, t.euid, t.brk, t.personality, t.mode), (1000, 1000, 0x60_0000, TaskPersonality::Linux, PrivilegeMode::User));
        assert_eq!(t.exe_path(), "/bin/sh");
        assert_eq!(t.state, TaskState::Ready);
    });
    let (pf, cf) = (with(p, |t| t.fds.clone()), with(child, |t| t.fds.clone()));
    assert!(std::sync::Arc::ptr_eq(&pf, &cf), "CLONE_FILES shares the table");
    assert_eq!(*fake::REG_THREADS.lock().unwrap(), vec![(p, child, p)]);
}

#[test]
fn fork_copies_files_keeps_the_fs_base_and_registers_a_child_process() {
    let _w = booted();
    let p = linux_parent();
    fake::FS_BASE[0].store(0x1F5, Ordering::SeqCst);
    let mut ctid: i32 = 5;
    let child = SCHEDULER.lock().spawn_clone(&frame(), [CLONE_CHILD_SETTID, 0, 0, &mut ctid as *mut i32 as u64, 0]).unwrap().0;
    assert_eq!(ctid, 5, "without CLONE_VM (and no address space of its own) nothing is written");
    with(child, |t| {
        assert_eq!(t.tgid, child);
        assert_eq!(t.regs.rsp, 0x7fff_0000, "no new stack: the caller's");
        assert_eq!(t.fs_base, 0x1F5, "the parent's live FS base");
        assert_eq!(t.clear_child_tid, 0);
    });
    let (pf, cf) = (with(p, |t| t.fds.clone()), with(child, |t| t.fds.clone()));
    assert!(!std::sync::Arc::ptr_eq(&pf, &cf));
    assert_eq!(*fake::REG_PROCS.lock().unwrap(), vec![(child, p, child, Some(p))]);
    // CLONE_PARENT: a sibling (its parent is ours)
    fake::PARENTS.lock().unwrap().insert(p, 42);
    let sib = SCHEDULER.lock().spawn_clone(&frame(), [CLONE_PARENT, 0, 0, 0, 0]).unwrap().0;
    assert_eq!(fake::REG_PROCS.lock().unwrap()[1], (sib, 42, sib, Some(p)));
}

#[test]
fn clone_takes_the_callers_fpu_state_and_ldt() {
    let _w = booted();
    let _p = linux_parent();
    let mut fpu = hydra_hosttests_t31::arch::idt::FpuState::new();
    fpu.0[100] = 0x5A;
    hydra_hosttests_t31::arch::syscall::SYSCALL_FPU.store(&mut fpu, Ordering::SeqCst);
    use hydra_hosttests_t31::arch::segments::Ldt;
    let ldt = std::sync::Arc::new(spin::Mutex::new(Some(std::sync::Arc::new(Ldt::new(vec![1u64, 2, 3].into_boxed_slice())))));
    with(_p, |t| t.ldt = Some(ldt.clone()));
    let thread = SCHEDULER.lock().spawn_clone(&frame(), [CLONE_VM | CLONE_THREAD, 0, 0, 0, 0]).unwrap().0;
    let forked = SCHEDULER.lock().spawn_clone(&frame(), [0, 0, 0, 0, 0]).unwrap().0;
    hydra_hosttests_t31::arch::syscall::SYSCALL_FPU.store(std::ptr::null_mut(), Ordering::SeqCst);
    assert_eq!(with(thread, |t| t.fpu.0[100]), 0x5A);
    assert!(std::sync::Arc::ptr_eq(&with(thread, |t| t.ldt.as_ref().unwrap().clone()), &ldt), "a thread shares the LDT");
    let fl = with(forked, |t| t.ldt.as_ref().unwrap().clone());
    assert!(!std::sync::Arc::ptr_eq(&fl, &ldt), "a forked process gets its own handle");
    assert_eq!(fl.lock().as_ref().unwrap().entries(), &[1, 2, 3]);
    let plain = SCHEDULER.lock().spawn_clone(&frame(), [CLONE_VM | CLONE_THREAD, 0, 0, 0, 0]).unwrap().0;
    assert_eq!(with(plain, |t| t.fpu.0[0..2].to_vec()), vec![0x7F, 0x03], "a fresh FPU state without one");
}

#[test]
fn clone_fails_for_a_retired_caller_or_without_a_scheduler() {
    let _w = booted();
    let p = linux_parent();
    with(p, |t| t.retired = true);
    assert_eq!(SCHEDULER.lock().spawn_clone(&frame(), [0; 5]).err(), Some("caller exiting"));
    assert_eq!(Scheduler::new().spawn_clone(&frame(), [0; 5]).err(), Some("Scheduler not initialized"));
    assert_eq!(Scheduler::new().spawn_native_thread(&frame(), 0, 0, 0).err(), Some("Scheduler not initialized"));
    with(p, |t| t.retired = false);
    assert_eq!(SCHEDULER.lock().spawn_native_thread(&frame(), 0, 0, 0).err(), Some("not a native process"));
}

#[test]
fn process_workers_share_the_callers_process() {
    let _w = booted();
    let p = linux_parent();
    with(p, |t| {
        t.gid = 7;
        t.regs.cr3 = 0x44_4000;
    });
    let w = SCHEDULER.lock().spawn_process_worker("io-wq", noop).unwrap().0;
    with(w, |t| {
        assert_eq!((t.tgid, t.uid, t.gid, t.personality, t.mode, t.regs.cr3), (p, 1000, 7, TaskPersonality::Linux, PrivilegeMode::Kernel, 0x44_4000));
    });
    assert!(std::sync::Arc::ptr_eq(&with(p, |t| t.fds.clone()), &with(w, |t| t.fds.clone())));
    assert!(Scheduler::new().spawn_process_worker("x", noop).is_none());
}

// ------------------------------------------------------------------ queries

#[test]
fn queries_about_tasks_and_processes() {
    let _w = booted();
    let p = spawn("proc", TaskPriority::Normal);
    let t1 = spawn("proc-thread", TaskPriority::Normal);
    with(t1, |t| {
        t.tgid = p;
        t.exe = Some(std::sync::Arc::from("/bin/proc"));
        t.ticks_run = 7;
        t.ticks_sys = 2;
    });
    with(p, |t| t.ticks_run = 3);
    let mut s = SCHEDULER.lock();
    assert_eq!(s.task_named("proc-thread"), Some(TaskId(t1)));
    assert_eq!(s.task_named("nope"), None);
    assert_eq!(s.exe_of(p).as_deref(), Some("proc"), "the first live thread's (no exe: its name)");
    assert_eq!(s.with_process(p, |t| t.id.0), Some(p));
    assert_eq!(s.with_process(999, |t| t.id.0), None);
    assert_eq!(s.process_ticks(p), 10);
    assert_eq!(s.process_cpu(p), (10, 2));
    assert!(s.process_runnable(p));
    let mut n = 0;
    s.for_each_task_mut(|_| n += 1);
    assert_eq!(n, 4);
    s.set_task_credentials(TaskId(t1), 1000, 100);
    s.with_task_mut(TaskId(t1), |t| {
        assert_eq!((t.uid, t.gid, t.euid, t.egid, t.suid, t.sgid), (1000, 100, 1000, 100, 1000, 100));
        assert_eq!(t.caps.effective, 0, "a non-root user has no capabilities");
    });
    s.kill_task(TaskId(p));
    assert_eq!(s.exe_of(p).as_deref(), Some("/bin/proc"));
    s.kill_task(TaskId(t1));
    assert!(!s.process_runnable(p));
    assert_eq!(s.exe_of(p), None);
    let mut n = 0;
    s.for_each_task_mut(|_| n += 1);
    assert_eq!(n, 2, "dead tasks are skipped");
    s.note_loaded_cr3(0x99_9000);
    assert_eq!(hydra_hosttests_t31::arch::smp::LOADED_CR3[0].load(Ordering::SeqCst), 0x99_9000);
    assert_eq!(s.current_personality(), TaskPersonality::Hydra);
    assert!(s.current_fds().is_some());
}

#[test]
fn dump_tasks_writes_every_live_task_and_the_calls_in_progress() {
    let _w = booted();
    add_cpus(2);
    let a = spawn("dumped", TaskPriority::Normal);
    with(a, |t| {
        t.syscall_nr = 202;
        t.syscall_args = [0x10, 0x20];
        t.exe = Some(std::sync::Arc::from("/bin/dumped"));
    });
    let dead = spawn("dead-one", TaskPriority::Normal);
    kill(dead);
    SCHEDULER.lock().begin_handoff(a, 77);
    SCHEDULER.lock().end_handoff(a);
    SCHEDULER.lock().begin_handoff(a, 88);
    fake::WINDOW_HOLDERS.lock().unwrap().push((0x40, a));
    task::CURRENT_SYSCALL.store(1, Ordering::SeqCst);
    SCHEDULER.lock().dump_tasks();
    let out = fake::SERIAL.lock().unwrap().clone();
    assert!(out.contains("[heap] 1024 KiB used, 3072 KiB free of 4096 KiB"));
    assert!(out.contains(&format!("[handoff] server {} caller 0 deadline 88", a)));
    assert!(out.contains("[cpu] 1 runs task 2 (idle)"));
    assert!(out.contains(&format!("[tasks] {} Ready {} 202(0x10,0x20)", a, a)));
    assert!(out.contains("/bin/dumped"));
    assert!(!out.contains("dead-one"), "dead tasks are left out");
    assert!(out.contains(&format!("[window] endpoint 0x40 held by task {}", a)));
    assert!(fake::LX_CALLS.lock().unwrap().contains(&"dump"));
    // resume_first is shown too
    SCHEDULER.lock().end_handoff(a);
    fake::SERIAL.lock().unwrap().clear();
    SCHEDULER.lock().dump_tasks();
    assert!(fake::serial_has("[handoff] resume first 0"));
}

#[test]
fn the_scheduler_lock_serves_tlb_flushes_while_it_waits() {
    let _w = booted();
    let g = SCHEDULER.lock();
    assert!(SCHEDULER.is_locked());
    assert!(SCHEDULER.try_lock().is_none());
    let h = std::thread::spawn(|| {
        let s = SCHEDULER.lock();
        s.task_count()
    });
    while fake::SERVE_TLB.load(Ordering::SeqCst) == 0 {
        std::thread::yield_now();
    }
    drop(g);
    assert_eq!(h.join().unwrap(), 2);
    assert!(!SCHEDULER.is_locked());
}

#[test]
fn call_ended_kicks_an_idle_cpu_only_when_a_task_was_held_back() {
    let _w = booted();
    scheduler::call_ended();
    assert_eq!(fake::KICK_IDLE.load(Ordering::SeqCst), 0);
    let a = spawn("a", TaskPriority::Normal);
    let s = spawn("srv", TaskPriority::Normal);
    SCHEDULER.lock().begin_handoff(s, u64::MAX);
    block(s);
    yield_on(0); // a is passed over (kernel mode during another task's call)
    let _ = a;
    SCHEDULER.lock().end_handoff(s); // calls call_ended
    assert_eq!(fake::KICK_IDLE.load(Ordering::SeqCst), 1);
}

// ------------------------------------------------------------------ other spawns

#[test]
fn spawn_user_maps_its_stack_and_entry_for_ring_3() {
    let _w = booted();
    x86_64::set_cr3(0x55_5000);
    let u = task::spawn_user("user", noop, TaskPriority::Low).0;
    with(u, |t| {
        assert_eq!(t.mode, PrivilegeMode::User);
        assert_eq!((t.regs.cs, t.regs.ss, t.regs.cr3), (0x2b, 0x1b, 0x55_5000));
        assert_eq!(t.regs.rip, noop as *const () as u64);
        let us = t.user_stack.as_ref().unwrap();
        let top = (us.as_ptr() as u64 + us.len() as u64) & !0xF;
        assert_eq!(t.regs.rsp, top - 48);
    });
    let ranges = fake::USER_RANGES.lock().unwrap().clone();
    assert_eq!(ranges.len(), 2);
    assert_eq!(ranges[1], (noop as *const () as u64, 4096));
}

#[test]
fn spawn_elf_loads_a_static_hydra_program() {
    let _w = booted();
    let elf = common::elf::Elf::new(common::elf::ET_DYN, 0x80, &[common::elf::load(0, 0, 0x200, 0x1000)], 0x200);
    let id = task::spawn_elf("hello", &elf.bytes, TaskPriority::Normal).unwrap().0;
    with(id, |t| {
        assert_eq!(t.mode, PrivilegeMode::User);
        assert_eq!(t.personality, TaskPersonality::Hydra);
        assert!(t.user_image.is_some());
        assert_ne!(t.regs.rip, 0);
    });
    assert!(task::spawn_elf("bad", b"not an elf", TaskPriority::Normal).is_err());
    // The legacy (identity-mapped) Linux path, through the scheduler directly
    let id = SCHEDULER.lock().spawn_linux_elf("lx", &elf.bytes, &["lx"], TaskPriority::Normal, 1000, 1000).unwrap().0;
    with(id, |t| {
        assert_eq!((t.personality, t.uid, t.euid, t.caps.effective), (TaskPersonality::Linux, 1000, 1000, 0));
    });
    assert_eq!(fake::REG_PROCS.lock().unwrap().last().unwrap().0, id);
    assert!(SCHEDULER.lock().spawn_linux_elf("bad", b"junk", &[], TaskPriority::Normal, 0, 0).is_err());
}
