# Preemptive Multitasking & Context Switching

## Overview

The Hydra multitasking subsystem implements a **preemptive round-robin scheduler** driven by the 8254 Programmable Interval Timer (PIT) firing at 100 Hz on IDT Vector 32 (IRQ 0). Multitasking enables concurrent execution of independent kernel threads, background worker tasks, and the interactive shell with transparent hardware context switching.

The implementation resides in [`src/task/scheduler.rs`](file:///d:/os/src/task/scheduler.rs), with the public API exposed through [`src/task/mod.rs`](file:///d:/os/src/task/mod.rs) and the console's task commands in [`userland/drivers/hydra-shell/src/system.rs`](../../../userland/drivers/hydra-shell/src/system.rs) (through `src/admin`).

---

## Scheduling Architecture & Timeslicing

The scheduler operates on a fixed timeslice quantum of **5 PIT timer ticks (50 ms)** at 100 Hz.

```mermaid
sequenceDiagram
    autonumber
    participant Hardware as 8254 PIT Timer
    participant IDT as IDT Vector 32 (IRQ 0)
    participant Sched as Preemptive Scheduler
    participant CPU as x86_64 CPU Core

    Hardware->>IDT: Timer Interrupt (every 10 ms)
    IDT->>IDT: common_trap_handler: Push GPRs & Error Code
    IDT->>Sched: pit::on_timer_tick() & pic::send_eoi(0)
    IDT->>Sched: SCHEDULER.lock().schedule(&mut ExceptionContext)
    alt Timeslice > 1 Tick Remaining
        Sched-->>CPU: timeslice_remaining -= 1 (No switch)
    else Timeslice Expired (0 Ticks)
        Sched->>Sched: Save active task registers from ExceptionContext
        Sched->>Sched: Wake up sleeping tasks (ticks >= wake_tick)
        Sched->>Sched: Select next Ready task (Round-Robin)
        Sched->>Sched: Restore next task registers into ExceptionContext
        Sched-->>IDT: Return to assembly trampoline
        IDT->>CPU: Pop GPRs & iretq (Resumes new task context)
    end
```

### Scheduling Algorithm Details

1. **Sleep Accounting**: On every tick, the scheduler scans all registered tasks and transitions any task in `TaskState::Sleeping { wake_tick }` back to `TaskState::Ready` if the current PIT tick count has reached or exceeded `wake_tick`.
2. **Timeslice Depletion**: The currently running task has its `ticks_run` counter incremented and `timeslice_remaining` decremented. If more than 1 tick remains in its timeslice, the scheduler returns immediately without context switching.
3. **Round-Robin Selection**: When the timeslice expires, the outgoing task's registers and `CR3` paging root are saved from `ExceptionContext`. The run-queue is scanned in two passes:
   - **Pass 1 (Normal & High Priority)**: Scans for the next runnable non-idle task (`priority > Idle`).
   - **Pass 2 (Idle Fallback)**: If no normal tasks are ready, schedules Task 1 (`idle`) to execute low-power CPU halts (`hlt`).
4. **Context Switch Restoration**: The chosen task's registers are written back into `ExceptionContext`, its timeslice is reset to 50 ms, and if the task has a distinct `CR3` page table, the CPU paging root is updated via `arch::pcid::load_cr3()` (which keeps the TLB entries with PCID, see [`pcid.md`](../arch/pcid.md)).

---

## Ticks that land in kernel code, and signals at a tick

Kernel code is not preempted (only user mode and explicit wait points are), so a tick that
finds its CPU in a system call, or finds the kernel lock held by another CPU, cannot run its
scheduling pass. It sets the per-CPU flag `task::TICK_DEFERRED` instead, and the end of the
next Linux system call on that CPU runs the pass (`task::tick_on_return`: a yield whose
handler calls `schedule`, which may keep the task). Without this, threads busy in system
calls kept their CPUs: the timer daemons (`itimerd`, `ptimerd`) and timed sleepers starved,
and a 1 ms interval timer reached such a process 4 times in 3 s (wave 5, Group 17).

A tick from user mode delivers the task's pending signals **before** its scheduling pass,
while the trap frame is still on the task's own kernel stack. After a switch the frame
belongs to the task switched away from, so the return path cannot deliver there; when the
tick then switched again (to the timer daemon posting the next signal), a thread that never
made a system call saw almost none of its timer signals. Test: `tests/linux/sigbusy_test.c`.

## Hardware Context Switching via `iretq`

Hydra employs an in-place stack frame modification pattern for architectural context switching:

1. When IRQ 0 fires, the CPU pushes `SS`, `RSP`, `RFLAGS`, `CS`, and `RIP` onto the active stack.
2. The assembly entry point `common_trap_handler` pushes all fifteen general-purpose registers (`RAX` through `R15`) and points `RSP` to the `ExceptionContext`.
3. `SCHEDULER.lock().schedule(ctx)` modifies the values stored inside the `ExceptionContext` on the stack.
4. As `common_trap_handler` unwinds, `pop r15..rax` loads the incoming task's general-purpose registers.
5. The hardware `iretq` instruction pops `RIP`, `CS`, `RFLAGS`, `RSP`, and `SS`. In 64-bit long mode, `iretq` unconditionally pops `RSP` and `SS` regardless of privilege level, atomically switching execution to the new task's stack and instruction pointer.

---

## Task Trampoline & Calling Conventions

When a newly spawned kernel thread starts execution for the first time, it does not resume from a previously interrupted state. Instead, it enters through the **Task Trampoline**:

```rust
extern "C" fn task_trampoline(entry_fn_addr: usize) -> ! {
    let func: fn() = unsafe { core::mem::transmute(entry_fn_addr) };
    func();

    // Mark task Dead upon normal function exit and yield CPU
    crate::task::exit();
}
```

### ABI Alignment & Register Conventions

- **Win64 vs SysV Dual Argument Passing**: Under the UEFI target (`x86_64-unknown-uefi`), the Microsoft x64 calling convention passes the first function argument in **`RCX`** (in contrast to SysV AMD64, which uses `RDI`). `spawn_internal` initializes both `regs.rcx` and `regs.rdi` to the entry point address to guarantee cross-ABI compatibility.
- **Shadow Space & 16-Byte Stack Alignment**: The initial stack pointer is configured as `initial_rsp = stack_top.saturating_sub(48)`. This satisfies the mandatory 32-byte Microsoft x64 shadow spill space requirement and aligns the stack to a 16-byte boundary upon entry into `func()`.

---

## Background Idle Thread (`idle`)

Task 1 is initialized as the background `idle` thread with `TaskPriority::Idle` (Priority 0):

```rust
fn idle_task_entry() {
    loop {
        if x86_64::instructions::interrupts::are_enabled() {
            x86_64::instructions::hlt();
        } else {
            core::hint::spin_loop();
        }
    }
}
```

When no worker threads or shell tasks are runnable, the CPU enters the low-power halt state (`hlt`). The next timer tick or PS/2 keyboard interrupt automatically wakes the core to evaluate task readiness.

---

## Public Multitasking API

The [`src/task/mod.rs`](file:///d:/os/src/task/mod.rs) module provides a unified public interface for thread management:

| Function | Signature | Description |
| :--- | :--- | :--- |
| `init` | `fn init(current_cr3: u64)` | Initializes scheduler, creates Task 0 (`shell`), and spawns Task 1 (`idle`). |
| `is_active` | `fn is_active() -> bool` | Returns true if the multitasking subsystem is active. |
| `spawn` | `fn spawn(name, entry_fn, priority) -> TaskId` | Spawns a new concurrent kernel thread with a 16 KiB stack. |
| `yield_now` | `fn yield_now()` | Cooperatively relinquishes the remaining timeslice to the next task. |
| `sleep_ms` | `fn sleep_ms(ms: u64)` | Suspends the calling task for a duration in milliseconds. |
| `sleep_ticks` | `fn sleep_ticks(ticks: u64)` | Suspends the calling task for a specific number of 10ms PIT ticks. |
| `exit` | `fn exit() -> !` | Marks the calling task as `Dead` and yields the CPU permanently. |
| `kill` | `fn kill(id: TaskId) -> bool` | Terminates an active background thread by its Task ID. |
| `get_task_snapshots` | `fn get_task_snapshots() -> Vec<TaskSnapshot>` | Captures diagnostic thread telemetry for shell commands. |

---

## Shell Commands for Task Inspection & Control

Three built-in commands provide runtime task management in the interactive shell:

### 1. `ps` / `tasks` / `threads`
Displays all registered tasks, thread states, priorities, CPU tick consumption, and stack pointers:

```text
hydra:/bin> ps
PID   NAME             STATE        PRIORITY        TICKS        STACK (RSP)
---------------------------------------------------------------------------
0     shell            Running      Normal              0 0x0000000000000000
1     idle             Ready        Idle                0 0x00000000017a3150
2     bg_worker        Ready        Normal              0 0x00000000017a8950
---------------------------------------------------------------------------
Total tasks: 3 | Timeslice: 50 ms | Worker counter: 0
```

### 2. `spawn [worker]`
Spawns a new concurrent background kernel thread executing a counter loop with `task::sleep_ms(100)`.

```text
hydra:/bin> spawn worker
[+] Spawned background worker task #2 ('bg_worker').
    Type 'ps' to observe the task executing concurrently.
```

### 3. `kill <pid>`
Terminates an active background task by its numeric PID (system tasks PID 0 `shell` and PID 1 `idle` are protected from termination):

```text
hydra:/bin> kill 2
[+] Task #2 terminated.
```

---

## 5. MINIX 3-Style Process Reincarnation & Driver Supervision

Hydra implements an autonomous driver watchdog inspired by the **MINIX 3 Reincarnation Server (RS)** in [`src/task/supervisor.rs`](file:///d:/os/src/task/supervisor.rs):

```text
+--------------------------------------------------------------------------+
|                  MINIX 3 Reincarnation Server (Supervisor)               |
|       - Watchdog Health Checks & Heartbeat Pings (MSG_SUPERVISOR_PING)   |
|       - Dead Task Detection (!is_task_alive) & Unresponsive Timeouts     |
|       - Automatic Driver Restart & IPC Endpoint Flushing                 |
+--------------------------------------------------------------------------+
             │                                              │
             ▼ IPC Heartbeats                               ▼ Spawn / Terminate
+-----------------------------+               +----------------------------+
|  User-Space Driver Daemons  |               | Preemptive Task Scheduler  |
|  - ATA Block Driver (0x21)  |               | (spawn_user, kill)         |
|  - E1000 Net Driver (0x22)  |               +----------------------------+
|  - ZFS File Server  (0x20)  |
+-----------------------------+
```

### Heartbeat & Vitality Tracking
- **Heartbeat Protocol (`0x6001..0x6002`)**: Dispatches `MSG_SUPERVISOR_PING` to the driver's bound IPC endpoint. Drivers reply with `MSG_SUPERVISOR_PONG` acknowledging operational health.
- **Fault Detection**: If a driver crashes (`#GP`, `#PF`, or `#UD`), the kernel terminates the faulting user task without a panic. The supervisor detects `!is_task_alive(id)` on the next tick.
- **Reincarnation Action**:
  1. Terminates any lingering task state (`task::kill`).
  2. Flushes the driver's rendezvous endpoint queue (`Endpoint::reset`).
  3. Re-spawns a fresh driver task via `spawn_user`.
  4. Increments `restart_count` and updates system telemetry.

### Shell Management: `service` / `rs`
Operators can monitor and test driver reincarnation interactively:
- `service status`: Formats telemetry table showing driver name, PID, endpoint, state, and restart count.
- `service restart <name>`: Manually cycles and reincarnates a service daemon.
- `service kill <name>`: Simulates a sudden driver crash and triggers automated reincarnation.


### Interactive work first (wave 11, Group D)
What the NUC's desktop needed (pointer lag and a slow start menu while Firefox ran, on a
machine without a GPU driver where everything is drawn in software):

- **Recent CPU use per thread** (`Task::recent`): each tick a thread runs adds
  `RECENT_TICK`; every `RECENT_DECAY_TICKS` (250 ms) every thread's value loses a quarter.
  Among ready threads of one priority (and within the woken / preempted / other tiers)
  the least used runs first, then round-robin order; a yield puts the current thread last.
  This is the classic BSD idea, and what CFS's virtual runtime achieves on Linux: a
  thread that mostly sleeps (the shell drawing the start menu, the compositor) goes ahead
  of a browser's busy threads, without anyone marking it.
- **Wake-up preemption**: a woken thread preempts the running one mid-slice only if it
  has a higher priority, or the same and clearly less recent use (`RECENT_MARGIN`); two
  equally busy threads do not ping-pong. When no CPU is idle, `smp::kick_for` interrupts
  another CPU (the TLB vector with a resched flag, `idt.rs`) to run a woken thread at once
  rather than at its next tick: for a high or real-time priority thread any CPU running
  lower priority work; for a normal one only a CPU running a busy normal thread
  (`PREEMPT_BUSY`, used 4 x more lately: `PREEMPT_RATIO`). A system call's kick waits for
  its end and is dropped when the caller's own CPU runs the woken thread. What other CPUs
  see of a CPU (its task's priority and recent use) is refreshed at every switch and tick,
  and a pending request ends there too (a kick arriving in kernel mode is answered by the
  next tick).
- Of ready tasks of the highest priority the current one goes last (a yield lets its
  equals run), but a real-time task never gives way to a high one at the end of its slice.
- **Priorities**: the highest ready priority among services runs first; display-server and
  input-server run at `Realtime` (above the other services), so a cursor move waits for no
  file or network work. Linux threads asking for `SCHED_FIFO`/`SCHED_RR` or nice <= -10 run
  at `High`: kwin_wayland asks for `SCHED_RR` at start when it has `CAP_SYS_NICE` (the image
  sets that file capability, `tools/desktop/desktop-inside.sh`).
- The timeslice stays 50 ms: with wake-up preemption by use, the slice no longer bounds
  interactive latency, and shorter slices would only add switches between busy threads.
- display-server copies a flipped picture in 64-row bands on its screen thread (the flip
  returns at once; the lock is free between bands, so a cursor move waits for one band at
  most) and completes the flip at the first blank after the copy.
