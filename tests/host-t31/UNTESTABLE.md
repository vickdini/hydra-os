# Group 31: code the host tests do not reach

Every file of Group 31 is compiled into `tests/host-t31`. What is not covered, and why:

| File | Function / lines | Why |
|---|---|---|
| `src/sync/mod.rs` | whole file | Declarations only (`pub mod`, `pub use`): no executable line. It is compiled (the crate builds `src/sync/mod.rs` itself); `tools/host_coverage.py` lists it as "not compiled" because LLVM records no code region for it. |
| `src/syscall/mod.rs` | whole file | Same: `pub mod user; pub use ...` only. |
| `src/syscall/user.rs` | the `asm!("syscall")` blocks of `syscall0`..`syscall3` | The `syscall` instruction (kernel build only, `#[cfg(target_os = "uefi")]`). On the host the same functions call the tests' stand-in, so every wrapper's argument and result handling is covered. |
| `src/task/mod.rs` | `raise_yield` (the `asm!("int 0x81")` line); the `loop { hlt }` tails of `exit` and `leave_retired` | The yield vector (kernel build only); the tails run only after the scheduler switched away for good. The tests leave `exit`/`leave_retired` through the yield (the hook panics). |
| `src/task/scheduler.rs` | `task_trampoline` | `extern "C"` entry of a new kernel thread, reached only by `iretq` to its saved `rip`; a host test cannot unwind out of it (an unwind across `extern "C"` aborts). |
| `src/task/scheduler.rs` | `idle_task_entry` (about 35 lines) | The idle loop: never returns, halts with interrupts on. Its decisions are all calls into `arch::smp` (`idle_poll`, `idle_halting`, `idle_halt_ended`) and `hr_wake`, which are tested on their own. |
| `src/task/scheduler.rs` | `direct_switch_core`'s `kernel_only` branch | No caller passes `true` (only `direct_switch`, with `false`). |
| `src/task/supervisor.rs` | `watchdog_task` | The supervisor task's endless loop (sleep, `close_retired`, `supervisor_tick`, `iommu::poll_faults`); each step is tested on its own. |
| `src/task/elf.rs`, `src/task/exec.rs` | the rest | Tested in depth by `tests/host` (`tests/elf.rs`, `tests/exec.rs`: 97 % and 99 % at the base). This crate compiles them (they are part of the task module) and runs them through the scheduler's spawn paths. |
