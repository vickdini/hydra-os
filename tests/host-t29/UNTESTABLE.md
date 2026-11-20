# Group 29: what the host tests do not run

Every file of the brief is compiled into this crate and reaches at least 70 % (see the
final report). The lines left over are listed here when they cannot run on the host, or
cannot be reached at all; small gaps (an error branch here and there) are not listed.

| File | Lines / function | Why |
|---|---|---|
| proc.rs | `return_to_user` (about 2901-2947) | The `xrstor`/`fxrstor`, `swapgs` and `iretq` back to ring 3 (inline `asm!`). Its caller `sys_rt_sigreturn` is now `restore_sigframe` (tested) + this call. |
| proc.rs | `sys_rt_sigreturn` (2784-2786) | The two lines that call `return_to_user`. |
| proc.rs | `thread_exited`, the `admin::acct_on()` and `perf::active()` branches (506-518) | Process accounting and perf counting are other groups' modules, stubbed off here. |
| mod.rs | `slow_poll` (355-385) and `prof::slow` in `dispatch_linux_syscall` (338-341) | Only run while system call profiling is on (`prof::start` returns 0 on the host). |
| mod.rs | the legacy `SYS_MMAP`/`SYS_BRK` file-backed and memfd branches (798-849) | Kernel-heap mappings for tasks without an address space (`map_into_kernel_space` on the real page tables). |
| mod.rs | `SYS_NANOSLEEP` (1548-1555), `SYS_CLONE`/`SYS_EXIT`/`SYS_EXIT_GROUP` (1570-1576), `SYS_CAPGET`/`SYS_CAPSET` (1867-1889) | Dead code: these numbers are always answered earlier, by `process.rs` (35, 125, 126) or `dispatch_process_calls` (56, 60, 231). Kept as they are (not this wave's change to make). |
| ptrace.rs | — | 98.7 %; the rest are single error branches. |
| futex.rs | `futex_death` / `key_for` shared-mapping branches | Need a `MAP_SHARED` page behind a loaded address space whose user addresses the host can dereference (not available on the host). |
| execve.rs | `ElfError::AllocationFailed` → ENOMEM, Landlock refusing the interpreter | The frame allocator running dry mid-load; a Landlock domain (Group 33's) on the loader. |
| syscalls.rs | (none) | Only constants: covered through its own `#[cfg(test)]` module checking them against Linux's table. |

Files at 100 % or close with nothing hardware-only: limits.rs, extra.rs, ns.rs, ldt.rs,
process.rs, types.rs. mm.rs, seccomp.rs and userfaultfd.rs are covered mainly by
`tests/host` (80 %, 95 %, 93 %); this crate adds checks through the system call table.
