# Personalities: the hook for programs of other systems

Source: `src/personality/` (`mod.rs`, `abi.rs`, `freebsd.rs`). Built in microkernel wave 5
(Group 14) from the design in [docs/personality-design.md](../personality-design.md),
section 2 (the "as built" notes are in its section 2.10).

A **personality** is a property of a process, chosen when it `exec`s a program: which
system the program was built for. Everything that differs between systems hangs off it: the
system call numbers, how results come back, signal numbers and signal frames, the initial
stack. Linux is the default and its path did not change. Native Hydra tasks (drivers,
servers, hydra-shell) have the `Hydra` personality.

## What it does today

| Program file | What happens |
|---|---|
| Linux ELF (OS/ABI 0 without a FreeBSD note, or 3) | runs as before |
| FreeBSD ELF (OS/ABI 9, or the "FreeBSD" ABI note) | `execve` fails with `ENOEXEC`, log line `[exec] <path>: a FreeBSD program (ELF OS/ABI 9): refused, ENOEXEC (no FreeBSD front end yet)` |
| Mach-O (64-bit, 32-bit, universal) | `ENOEXEC`, `[exec] <path>: a Mach-O (macOS) program: refused, ...` |
| ELF of another system (NetBSD 2, Solaris 6, OpenBSD 12, ...) | `ENOEXEC`, `[exec] <path>: an ELF program for another system (OS/ABI n): refused, ENOEXEC` |
| A program whose `PT_INTERP` is of another system | `ENOEXEC`, `[exec] interpreter <path> is not a <system> program: refused, ENOEXEC` |

Before wave 5 a FreeBSD program was started as a Linux program and crashed at once.

**The test switch** `persona=fbsd-stub` (QEMU: `-fw_cfg name=opt/hydra/persona,string=fbsd-stub`;
real machines: the boot entry's option word) lets FreeBSD programs start with the FreeBSD
personality on a small **stub table**, which proves the hook before the FreeBSD front end
(wave 11) exists. It is off by default; the kernel logs `[persona] FreeBSD programs start
with the stub table` when it is on.

## How a system call finds its table

```text
syscall ─► hydra_syscall_dispatcher
             │ t = personality::CURRENT_TABLE[cpu]      (one per-CPU load)
             ├─ t != null ─► personality::syscall(frame, fpu, t)
             │                 e = t.entries[nr]        (one table load)
             │                 route: LINUX_AS(n) │ KERNEL(id) │ ENOSYS │ NOSYS (+ SIGSYS)
             │                 result in the personality's convention, signals, sysret
             └─ t == null (Linux, Hydra) ─► exactly the old path:
                   fast_syscall, lx::fast_entry (lx::route), dispatch ...
```

- `CURRENT_TABLE` is written by `Scheduler::switch_to` next to `CURRENT_TID` (both the
  normal and the direct switch go through it), and by `execve` when the personality
  changes. It is null for Linux and native tasks.
- **`lx::route(nr)` stays the one place that turns a Linux number into a route.** A
  `LINUX_AS(n)` entry runs Linux call `n` through `dispatch_linux_syscall`, which forwards
  it through `lx::forward` / `lx::route` like any Linux call. The Linux forwarding table and
  its interface (`MOVED`, `MOVED_STEP2`, `set_forwarding`, `route`) did not change.
- A table entry is `route | flags | arg << 16`. Flags: `F_RET2` (a second result in `rdx`),
  `F_INDIRECT` (FreeBSD's `syscall` 0 and `__syscall` 198: the number in `rdi`).

## Results, restarts

The kernel's calls answer in the internal (Linux) convention: `-errno`. For a BSD
personality the trap then sets the **carry flag** in the saved `rflags` and returns the
**positive errno** of that system (`abi::FREEBSD_ERRNO`, `abi::MACOS_ERRNO`, generated from
[personality-errno.md](../personality-errno.md)), or clears the flag on success. `rdx` is
written only for `F_RET2` calls; the argument registers come back as the program passed
them. A restarted call gets back the program's own number and arguments, also inside a
signal frame built meanwhile (`Task::pers_call` keeps them during the return).

## Signals

The kernel numbers signals as Linux does. `abi` maps FreeBSD's numbers to the internal ones
and back (`SIGUSR1` 30 ↔ 10, `SIGSYS` 12 ↔ 31, `SIGINFO` 29 → `SIGPWR`, FreeBSD's real-time
signals 65–95 ↔ 34–64). `compat::linux::proc::build_frame` has one dispatch point at its top:
for a task whose personality has a table, the table's frame builder runs instead of Linux's.

FreeBSD's frame (`freebsd::build_frame`) is FreeBSD's `struct sigframe`: the handler, a
`ucontext_t` (128-bit signal mask, the 800-byte `mcontext_t` with the FXSAVE area) and a
`siginfo_t`. The program enters FreeBSD's signal trampoline (`sigcode`, mapped read-only and
executable at `abi::FREEBSD_SIGCODE_ADDR` in every FreeBSD process), which calls the handler
and then `sigreturn(&sf_uc)` (417).

## The exec layout

`task::exec::load_linux_exec` takes the personality. For FreeBSD: FreeBSD's auxiliary vector
numbers (`abi::freebsd_at`, `AT_OSRELDATE` 1501000, `AT_PS_STRINGS`, `AT_PAGESIZES`, ...), no
vDSO, the trampoline page, and FreeBSD's entry registers: `rsp = ((stack - 8) & ~15) + 8`,
`rdi` = the address of `argc`.

## The FreeBSD stub table

| FreeBSD call | Route |
|---|---|
| `exit` 1, `read` 3, `write` 4, `close` 6, `getuid` 24, `geteuid` 25, `getppid` 39, `getegid` 43, `getgid` 47, `execve` 59, `nanosleep` 240 | Linux 231, 0, 1, 3, 102, 107, 110, 108, 104, 59, 35 |
| `getpid` 20 | kernel: the pid, the parent's pid in `rdx` (`F_RET2`) |
| `kill` 37, `sigaction` 416, `sigreturn` 417, `thr_self` 432 | kernel (numbers and structures translated) |
| `syscall` 0, `__syscall` 198 | indirect |
| anything else | `ENOSYS` (78) and `SIGSYS` |

## Tests

- `tests/linux/persona_test.c` (`persona.elf`, suite test `persona`): both modes; by default
  every refusal above, with the switch the stub table's checks below.
- `tests/freebsd/fbhook.c` (static FreeBSD program, no C library): entry registers, carry
  flag and positive errno, `rdx`, FreeBSD numbers, indirect calls, `sigaction`, a signal
  frame round trip; plus modes for `SIGSYS`, a signal sent by FreeBSD number, and exec of a
  Linux program. Group 11's `tests/freebsd/rawsys.c` passes too.
- Build: `tools/personality/build-fbhook.sh` (clang 15 in Group 11's build root).
- Host tests: `tests/host/tests/personality.rs` (marking, errno and signal maps),
  `tests/host/tests/exec.rs` (the FreeBSD exec layout, interpreter agreement).
