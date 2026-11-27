# Personalities: programs of other systems

Source: `src/personality/` (`mod.rs`, `abi.rs`, `freebsd.rs`, `fbsd_calls.rs`, `fbsd_xlat.rs`,
`fbsd_thr.rs`, `umtx.rs`, `fbsd_tmp.rs`, `fbsd_sysctl.rs`). The hook was built in microkernel
wave 5 (Group 14) from the design in [docs/personality-design.md](../personality-design.md),
section 2 (the "as built" notes are in its section 2.10); the FreeBSD kernel side in wave 12
(Group FK, design section 4; "as built" in section 4.7).

A **personality** is a property of a process, chosen when it `exec`s a program: which
system the program was built for. Everything that differs between systems hangs off it: the
system call numbers, how results come back, signal numbers and signal frames, the initial
stack. Linux is the default and its path did not change. Native Hydra tasks (drivers,
servers, hydra-shell) have the `Hydra` personality.

## What it does today

| Program file | What happens |
|---|---|
| Linux ELF (OS/ABI 0 without a FreeBSD note, or 3) | runs as before |
| FreeBSD ELF (OS/ABI 9, or the "FreeBSD" ABI note) | runs with the FreeBSD personality and its call table (wave 12) |
| Mach-O (64-bit, 32-bit, universal) | `ENOEXEC`, `[exec] <path>: a Mach-O (macOS) program: refused, ...` |
| ELF of another system (NetBSD 2, Solaris 6, OpenBSD 12, ...) | `ENOEXEC`, `[exec] <path>: an ELF program for another system (OS/ABI n): refused, ENOEXEC` |
| A program whose `PT_INTERP` is of another system | `ENOEXEC`, `[exec] interpreter <path> is not a <system> program: refused, ENOEXEC` |

**Switches** (QEMU: `-fw_cfg name=opt/hydra/persona,string=...`; real machines: the boot
entry's option word `persona=...`):
- `persona=off`: FreeBSD programs are refused with `ENOEXEC` as before wave 12
  (`[exec] <path>: a FreeBSD program (ELF OS/ABI 9): refused, ENOEXEC (persona=off)`).
- `persona=fbsd-stub`: FreeBSD programs run on wave 5's small stub table (a test switch;
  the kernel logs `[persona] FreeBSD programs start with the stub table`).

## Running FreeBSD programs

The FreeBSD 15.1 root (`base.txz` without `/boot`, made by
`tools/personality/make-freebsd-root.sh`) is installed by
`tools/personality/install-freebsd-root.sh`, run **inside the Ubuntu root as root**:

```text
install-freebsd-root.sh [TARBALL-OR-URL [SHA256-FILE-OR-URL]]   # last line FREEBSD-ROOT-OK
```

It checks the SHA-256, unpacks with numeric owners into `/freebsd` of the Ubuntu root (the
pool's `/ubuntu/freebsd`: the Ubuntu root cannot see the pool's own root, so it could not
install or enter a root "next to /ubuntu"), and is idempotent (a second run with the same
tarball only checks it). It also installs the wrapper `/usr/local/bin/freebsd`.

| From | How |
|---|---|
| hydra-shell | `freebsd [program [args]]` (alias `fbsd`): runs it in the FreeBSD root like `linux chroot`; the root is the pool's `/freebsd` if it has one, else `/ubuntu/freebsd`; a bare name is looked up in `/bin`, `/usr/bin`, `/sbin`, `/usr/sbin`, `/rescue`; no program: `/bin/sh` |
| Linux (Ubuntu) | `freebsd program [args]` (the wrapper: `chroot /freebsd ...`, through `sudo` for other users than root) |

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
  it through `lx::forward` / `lx::route` like any Linux call.
- A table entry is `route | flags | arg << 16`. Flags: `F_RET2` (a second result in `rdx`),
  `F_INDIRECT` (FreeBSD's `syscall` 0 and `__syscall` 198: the number in `rdi`).
- **Services see the caller's personality:** `lx::place` (every forwarded call, from the
  lock-free and the locked path, file handles, calls between services) sets `LxCall::pers`
  from this CPU's table (`personality::lx_pers`: 0 for Linux and native callers, 2 FreeBSD,
  3 macOS) unless the caller set it. `LxCall::nr` stays the **Linux** number; `pers` tells
  a service whose layouts and constants the caller's memory uses (wave 12 stage 2 keys
  FreeBSD's `stat`, `dirent`, `sockaddr`, `termios`... on it).

## The FreeBSD table (`freebsd.rs`)

Every one of FreeBSD 15.1's 411 live numbers has an entry (decision 39: the kernel keeps
only mechanism; layouts of objects a service owns are the services' work):

| Kind | Route | Where |
|---|---|---|
| the "D" calls (106: same operation, errno only) | `LINUX_AS` | `fbsd_xlat::DIRECT` |
| flag and constant translations the kernel owns: `open`/`openat`, the `AT_*` calls, `mmap` (`MAP_ANON`, `MAP_STACK`, `MAP_GUARD`, `MAP_EXCL`, `MAP_ALIGNED(n)`, `MAP_32BIT`, `PROT_MAX`), `mprotect`, `madvise`, `minherit`, `msync`, `break`, clock ids, `RLIMIT_*` and `RLIM_INFINITY`, `wait4` options and status, `getpriority`, `posix_fallocate`/`posix_fadvise` (POSIX-style results), scheduling policies, `fcntl`'s descriptor commands, `pipe2`, `timerfd_create`, message queue names, `cpuset_getaffinity` | kernel-local | `fbsd_calls.rs` (pure parts: `fbsd_xlat.rs`) |
| signals: `sigaction`, `sigreturn`, `sigprocmask`, `sigsuspend`, `sigpending`, `sigtimedwait`/`sigwaitinfo`/`sigwait`, `sigaltstack`, `sigqueue`, `kill`, `thr_kill(2)`, `ppoll`, `pselect` | kernel-local | `fbsd_calls.rs`, `freebsd.rs` |
| contexts and threads: `getcontext`/`setcontext`/`swapcontext`, `thr_new`/`thr_exit`/`thr_self`/`thr_set_name`/`thr_suspend`/`thr_wake` | kernel-local | `fbsd_thr.rs`, `umtx.rs` |
| `_umtx_op` (`WAIT`, `WAIT_UINT(_PRIVATE)`, `WAKE(_PRIVATE)`, `NWAKE_PRIVATE`, `MUTEX_TRYLOCK/LOCK/UNLOCK/WAIT/WAKE/WAKE2`, `CV_WAIT/SIGNAL/BROADCAST`, `RW_RDLOCK/WRLOCK/UNLOCK`, `SEM2_WAIT/WAKE`, `ROBUST_LISTS` accepted, `GET/SET_MIN_TIMEOUT`) | kernel-local | `umtx.rs` |
| `sysarch` (`AMD64_GET/SET_FSBASE`, `GET/SET_GSBASE`, `GET/SET_TLSBASE`), `issetugid`, `__getcwd`, `utrace` (no-op) | kernel-local | `fbsd_calls.rs` |
| **temporary** (until stage 2): `fstat`, `fstatat`, `getdirentries`, `fstatfs` layouts; `__sysctl`/`__sysctlbyname` for `kern.ostype/osrelease/osrevision/version/hostname/osreldate/usrstack/arandom/argmax/ngroups`, `kern.smp.cpus/maxid`, `kern.sched.cpusetsize(min)`, `kern.proc.osrel`, `hw.machine/machine_arch/ncpu/physmem/pagesize/pagesizes`, `vm.overcommit`, and the name-to-OID node `{0, 3}` | kernel-local, marked `// wave12 FK temporary: moves to <service> in stage 2` | `fbsd_tmp.rs`, `fbsd_sysctl.rs` |
| "S" stubs: Capsicum (`cap_enter`, `cap_rights_limit`, ... `ENOSYS`, quietly: `capsicum_helpers` carry on), jails (`jail_get` `ENOENT`, the rest `EPERM`), kld/mod (`*find` `ENOENT`, `*next` 0, `kldload` `EPERM`), mount/unmount/nmount/reboot/swapon/swapoff `EPERM`, `chflags` family `EOPNOTSUPP`, MAC and audit getters `ENOSYS` quietly, `cpuset_setaffinity` accepted, `sigfastblock` `ENOSYS` (never asked for: `AT_BSDFLAGS` has no `SIGFASTBLK`) | fixed answers | `freebsd::STUBS` |
| every other live call (sockets, `ioctl`, `kqueue`, paths' `stat`, `procctl`, ...) | `ENOSYS`, one kernel log line per call: `[persona] FreeBSD <prog>: <call> (<n>) not implemented yet: ENOSYS` | |
| a number that is no FreeBSD call | `ENOSYS` and `SIGSYS` (FreeBSD's `nosys`) | |

**Translated structures go through the caller's stack:** a call whose Linux form takes a
different structure (a 64-bit signal mask, Linux's `stack_t`, a `struct rlimit` with Linux's
infinity, a `timespec` pair with Linux's `UTIME_*`) writes the translated copy just below the
caller's stack pointer (past the red zone, 512 bytes down) and passes that address to the
Linux call. Calls whose Linux result is smaller than FreeBSD's structure (`fstat`, `fstatfs`,
`getdirentries`) let Linux write into the caller's own buffer and convert in place
(`getdirentries` asks for 3/4 of the buffer, so FreeBSD's longer records always fit).

### Threads and `_umtx_op`

- `thr_new` makes the thread with the Linux layer's `clone` (`CLONE_VM | CLONE_FS |
  CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM | CLONE_SETTLS |
  CLONE_PARENT_SETTID | CLONE_CHILD_SETTID`). The child would start with its creator's
  registers, so it starts at an 8-byte piece of code on the FreeBSD shared page
  (`abi::FREEBSD_THR_START` at `FREEBSD_SIGCODE_ADDR + 32`: `mov %r13,%rdi; xor %ebp,%ebp;
  jmp *%r12`) with `start_func` in `r12` and `arg` in `r13`, on the stack FreeBSD's
  `cpu_set_upcall` would give it. The thread id (the Linux thread id) is written as a full
  `long` to `child_tid` and `parent_tid`.
- `thr_exit(state)` stores 1 at `*state`, wakes its `UMTX_OP_WAKE` waiters (libthr's
  `pthread_join`), and ends the thread (the process when it is the last).
- `_umtx_op` follows FreeBSD's `kern_umtx.c` operation by operation over a wait queue of its
  own, keyed `(address space, address, kind)` (physical address for process-shared objects in
  shared memory). FreeBSD's per-key "busy" monitor is the kernel lock: every FreeBSD call runs
  under it and a sleeping thread lets go of it, exactly where FreeBSD unbusies. A sleep ends
  with 0 (woken), `ETIMEDOUT`, or `EINTR` for a signal (libthr loops). Priority-inheritance and
  -protection mutexes are handled as normal ones (libthr sends them to the kernel for every
  lock and unlock, so the word stays consistent); `UMTX_OP_SHM` (process-shared pthread
  objects) is `ENOSYS`; the robust list walk at a thread's death is not done.

### Contexts

`getcontext` saves the caller's state as it returns from the call (`rax`, `rdx` 0, carry
clear), its mask (FreeBSD's 128-bit set), alternate stack and FXSAVE area into FreeBSD's
`ucontext_t`; `setcontext` and `sigreturn` share one restore path (`freebsd::set_context`);
`swapcontext` is both. The `mcontext_t` layout (`fbsd_xlat::Mcontext`: `mc_rdi`..`mc_r15`,
`mc_rip`/`mc_cs`/`mc_rflags`/`mc_rsp`/`mc_ss`, `mc_len` 800, the FXSAVE area at 224,
`mc_fsbase` and `mc_tlsbase`) is the signal frame's too.

## Results, restarts

The kernel's calls answer in the internal (Linux) convention: `-errno`. For a BSD
personality the trap then sets the **carry flag** in the saved `rflags` and returns the
**positive errno** of that system (`abi::FREEBSD_ERRNO`, `abi::MACOS_ERRNO`, generated from
[personality-errno.md](../personality-errno.md)), or clears the flag on success. FreeBSD's
"POSIX-style" calls (`posix_fallocate`, `posix_fadvise`, `clock_nanosleep`, `sigwait`)
return the error number as the value with the flag clear. `rdx` is written only for
`F_RET2` calls; the argument registers come back as the program passed them. A restarted
call gets back the program's own number and arguments, also inside a signal frame built
meanwhile (`Task::pers_call` keeps them during the return).

## Signals

The kernel numbers signals as Linux does. `abi` maps FreeBSD's numbers to the internal ones
and back (`SIGUSR1` 30 ↔ 10, `SIGSYS` 12 ↔ 31, `SIGINFO` 29 → `SIGPWR`, FreeBSD's real-time
signals 65–95 ↔ 34–64). `compat::linux::proc::build_frame` has one dispatch point at its top:
for a task whose personality has a table, the table's frame builder runs instead of Linux's.

FreeBSD's frame (`freebsd::build_frame`) is FreeBSD's `struct sigframe`: the handler, a
`ucontext_t` (128-bit signal mask, the 800-byte `mcontext_t` with the FXSAVE area) and a
`siginfo_t` (`si_code` is `SI_USER` for now). The program enters FreeBSD's signal trampoline
(`sigcode`, mapped read-only and executable at `abi::FREEBSD_SIGCODE_ADDR` in every FreeBSD
process), which calls the handler and then `sigreturn(&sf_uc)` (417).

## The exec layout

`task::exec::load_linux_exec` takes the personality. For FreeBSD: FreeBSD's auxiliary vector
numbers (`abi::freebsd_at`, `AT_OSRELDATE` 1501000, `AT_PS_STRINGS`, `AT_PAGESIZES`,
`AT_USRSTACKBASE`/`LIM`, `AT_BSDFLAGS` 0, ...), `struct ps_strings` at the stack top, no vDSO,
the shared page (trampoline and thread start), and FreeBSD's entry registers:
`rsp = ((stack - 8) & ~15) + 8`, `rdi` = the address of `argc`.

## Tests

- `tests/linux/fbsdrun_test.c` (`fbsdrun.elf`, suite test `fbsdrun`, run as root in the Ubuntu
  root): milestones 1–3 and libthr in the FreeBSD root: `rawsys` (static, raw calls),
  `/rescue/echo hi` (static, libc), `/bin/echo hi` (dynamic, rtld), `fbsdthr` (threads,
  mutexes, condition variables, semaphores, TLS, `SA_SIGINFO` with the FreeBSD `ucontext`,
  `sigaltstack`, `pthread_cancel`), plus `/bin/sh -c 'echo $((1+2))'` as information. Without
  a FreeBSD root it prints `SKIP` and passes.
- `tests/linux/persona_test.c` (`persona.elf`, suite test `persona`): FreeBSD on (the default,
  or the stub table) and `persona=off`; refusals of Mach-O and other systems in both.
- `tests/freebsd/fbhook.c` (static FreeBSD program, no C library): entry registers, carry
  flag and positive errno, `rdx`, FreeBSD numbers, indirect calls, `sigaction`, a signal
  frame round trip; modes for `SIGSYS` (number 999), a signal sent by FreeBSD number, and
  exec of a Linux program. Group 11's `tests/freebsd/rawsys.c` and `fbsdthr.c` pass too.
- Build: `tools/personality/build-freebsd-tests.sh`, then `tools/personality/build-fbhook.sh`
  (clang 15 in Group 11's build root; writes `esp/bin/{fbhook,fbrawsys,fbinfo,persona,fbsdrun,fbsdthr}.elf`).
- Host tests: `tests/host/tests/personality.rs` (marking, errno and signal maps),
  `tests/host/tests/exec.rs` (the FreeBSD exec layout, interpreter agreement),
  `tests/host-w12-fk` (the call table's data, flag and constant translations, `mmap` plans,
  wait status, signal sets, `stack_t`, `siginfo_t`, the `mcontext_t` layout, `_umtx_op`
  decoding and word rules, `dev_t`, the temporary `stat`/`dirent`/`statfs`/`sysctl` pieces).
