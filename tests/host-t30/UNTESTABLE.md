# Group 30: what the host tests cannot run

Every file of `src/lx` and `src/ipc` is compiled into this crate. What is left out is the
hardware-only code below. It was kept thin: the testable logic around it was moved out of it
(test wave, Group 30) and is tested.

| File | Item | Lines | Why |
|---|---|---|---|
| `src/ipc/service.rs` | `int81()`, `int82()` (`#[cfg(target_os = "uefi")]`) | the two `asm!` helpers after `wait_clobbered` | The yield vector `int 0x81` and the direct-switch vector `int 0x82`: they switch tasks in the kernel's trap handler. On the host the `cfg(not(target_os = "uefi"))` twins call the simulated scheduler (`tests/host-t30/src/world.rs`, `yield_cpu` / `direct_vector`, which mirrors `Scheduler::direct_call`'s conditions). Every caller of them (`lx_yield`, `direct_to`, `switch_to_parked`, `park_wait`, `wait_clobbered`) runs on the host. |
| `src/lx/copy.rs` | `global_asm!` `hydra_uaccess_copy` / `hydra_uaccess_str` and their `extern "sysv64"` declarations (`#[cfg(target_os = "uefi")]`) | the `global_asm!` block | `rep movsb` / byte loop with fault fix-ups resumed by the trap entry (`arch::idt::uaccess_fixup`): needs a page fault in kernel mode. The host twins (`crate::host::uaccess_copy/str`) simulate a fault at pages a test marks missing, so `fill`, `try_str`, `with_faults`, `read_user*`, `write_user` and every Missing/Fault path are tested. |
| `src/ipc/mod.rs` | the whole file | all | No executable code (module declarations and `pub use` re-exports): llvm-cov records nothing for it, so the coverage tool counts its 11 lines as "not compiled". It is compiled (it is the `ipc` module root of this crate). |
| `src/ipc/service.rs` | `Service::new`, `Service::with_primary` (const fns) | ~419-442 | Only evaluated at compile time (the `SERVICES` static initializer). |

Not hardware-only but not reached on one simulated CPU (each file is above 94 % anyway): the
spin of `hold_window_as` with interrupts on is reached through a simulated timer tick in
`bkl_exit` (`PREEMPT_IN_BKL_EXIT`); cross-CPU races (a worker answering on another CPU between
a caller's placement and its direct switch) are driven by explicit yields at the points the
code would be preempted, not by real parallelism.
