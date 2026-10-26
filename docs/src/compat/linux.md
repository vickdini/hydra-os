# Stage 11: Linux Binary Compatibility Subsystem (ABI Layer)

## Architectural Role & Design Rationale

To support existing modern open-source graphical ecosystems—specifically standard C/C++ runtimes, `musl-libc`, and Wayland/KDE Plasma components—without requiring thousands of manual userspace ports, Hydra OS implements an in-kernel **Linux Binary Compatibility Subsystem** (`src/compat/linux`).

Similar in spirit to FreeBSD's *Linuxulator* or Windows Subsystem for Linux 1 (*WSL1*), the subsystem does not run a guest Linux kernel inside a virtual machine. Instead, it provides a direct, high-performance ABI translation layer that allows unprivileged 64-bit Linux ELF binaries to execute natively on the bare-metal hardware.

---

## Architectural Workflow

```text
+-------------------------------------------------------------------+
|               Linux Userland Application / Runtime                |
|        (musl libc, BusyBox, Wayland, Qt 6, KDE Plasma 6)          |
+-------------------------------------------------------------------+
                                 |  Linux x86_64 Syscall Convention
                                 |  (RAX: num, RDI, RSI, RDX, R10, R8, R9)
                                 v
+-------------------------------------------------------------------+
|                 Hydra Hardware SYSCALL Trampoline                 |
|                   (src/arch/syscall.rs: LSTAR)                    |
+-------------------------------------------------------------------+
                                 |
                 +---------------+---------------+
                 |                               |
    [TaskPersonality::Hydra]       [TaskPersonality::Linux]
                 |                               |
                 v                               v
+--------------------------------+ +--------------------------------+
|  Hydra Microkernel Dispatcher  | |   Linux ABI Compatibility      |
|  (SYS_YIELD, SYS_IPC, etc.)    | |   (src/compat/linux/mod.rs)    |
+--------------------------------+ +--------------------------------+
                                                 |
         +--------------------+------------------+------------------+
         |                    |                  |                  |
         v                    v                  v                  v
    [POSIX VFS / ZFS]     [Memory / Mmap]     [MSR / TLS]     [Pseudo-FS]
     open, read, write     brk, mmap, munmap   ARCH_SET_FS     /proc, /dev
```

---

## Key Capabilities & Features

### 1. Dual Personality Task Management
Every `Task` in Hydra microkernel holds a `personality: TaskPersonality` attribute:
* `TaskPersonality::Hydra`: Default microkernel tasks using Hydra syscall numbers (`SYS_YIELD = 1`, `SYS_SLEEP = 2`, `SYS_WRITE = 3`, etc.).
* `TaskPersonality::Linux`: Linux applications using standard Linux x86_64 syscall numbers (`SYS_READ = 0`, `SYS_WRITE = 1`, `SYS_OPEN = 2`, `SYS_CLOSE = 3`, `SYS_MMAP = 9`, `SYS_BRK = 12`, `SYS_ARCH_PRCTL = 158`, etc.).

### 2. Thread-Local Storage (TLS) via Hardware MSR
Standard Linux C runtimes (`glibc` and `musl`) depend heavily on x86_64 segment registers for thread-local variables and stack canary protection (`%fs:0x28`):
* The `arch_prctl(ARCH_SET_FS, addr)` system call is implemented using the CPU Model-Specific Register `IA32_FS_BASE` (`0xC000_0100`).
* During preemptive context switches in [`Scheduler::schedule()`](file:///d:/os/src/task/scheduler.rs), the active task's `fs_base` is saved via `rdmsr` and restored for the incoming task via `wrmsr`.

### 3. System V AMD64 Stack & Auxiliary Vectors (`Auxv`)
When launching a Linux binary via `spawn_linux_elf()`, the ELF loader constructs a standard Linux userspace stack containing:
* `argc`: Argument count.
* `argv[]`: Array of null-terminated string pointers pointing to stack strings.
* `envp[]`: Array of environment variables (`PATH=/bin:/usr/bin`, `USER=root`, `HOME=/`, `TERM=linux`).
* `Auxiliary Vectors (Auxv)`: Critical startup metadata consumed by dynamic linkers:
  - `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`: Program header memory locations.
  - `AT_PAGESZ`: Hardware page size (4096 bytes).
  - `AT_ENTRY`: Entry point address.
  - `AT_UID`, `AT_EUID`, `AT_GID`, `AT_EGID`: User identity credentials.
  - `AT_RANDOM`: Pointer to 16 cryptographic random bytes.

### 4. Linux Pseudo-Filesystem Emulation
Virtual Linux filesystem paths are intercepted and served directly in memory:
* `/dev/null`, `/dev/zero`: Standard POSIX sink and zero streams.
* `/dev/urandom`: Hardware pseudo-random generator stream.
* `/proc/version`: Identifies kernel as `Linux 6.8.0-hydra (gcc/rustc) #1 SMP PREEMPT Hydra Microkernel`.
* `/proc/meminfo`: Reports dynamic kernel heap allocation and free capacity.
* `/proc/cpuinfo`: Reports processor architecture and instruction set capabilities.

### 5. Multi-Threading & Futex Subsystem (`clone`, `futex`, `set_tid_address`)
Full multi-threaded POSIX execution is enabled via in-kernel thread creation and synchronization:
* **`sys_clone` (Syscall 56)**: Supports flags `CLONE_VM`, `CLONE_FS`, `CLONE_FILES`, `CLONE_THREAD`, `CLONE_SETTLS`, `CLONE_PARENT_SETTID`, `CLONE_CHILD_SETTID`, and `CLONE_CHILD_CLEARTID`.
  - Threads share address spaces (`CR3`), virtual filesystems, and file descriptor tables.
  - Sibling threads share the same Thread Group ID (`TGID`), with `sys_getpid` returning the process TGID and `sys_gettid` returning the thread's individual task ID.
  - Dedicated per-thread kernel stacks (`DEFAULT_STACK_SIZE = 16 KiB`) ensure re-entrant syscall execution and isolated interrupt stacks.
* **`sys_futex` (Syscall 202)**: Implements fast userspace mutex primitives:
  - `FUTEX_WAIT` / `FUTEX_WAIT_BITSET`: Atomic value comparison against `*uaddr`; blocks calling thread in scheduler if values match, or returns `-EAGAIN` (`-11`) if contested.
  - `FUTEX_WAKE` / `FUTEX_WAKE_BITSET`: Wakes up to `val` threads blocked on the target address without deadlock or lock inversion.
* **Robust Thread Exit (`clear_child_tid`)**: When a thread terminates via `sys_exit` or `exit()`, the kernel writes `0` to the userspace address designated by `CLONE_CHILD_CLEARTID` / `set_tid_address` and automatically triggers a futex wake, unblocking `pthread_join()` callers immediately.

### 6. User and Superuser (Root) Security Subsystem
Hydra OS implements a POSIX-compliant user identity and credential management model across both microkernel tasks and Linux ABI processes:
* **Task Credentials**: Each task control block maintains 6 credential attributes:
  - Real UID (`uid`) and Real GID (`gid`): Identifies the account owning the process.
  - Effective UID (`euid`) and Effective GID (`egid`): Used by the kernel for permission checks (file access, signal delivery, syscall capabilities).
  - Saved-Set UID (`suid`) and Saved-Set GID (`sgid`): Preserves identity across set-UID / privilege drop transitions.
* **Identity Management Syscalls**:
  - `sys_getuid` (102), `sys_getgid` (104), `sys_geteuid` (107), `sys_getegid` (108): Query active credentials.
  - `sys_setuid` (105), `sys_setgid` (106): Transition user identities; privileged processes (`euid == 0`) can switch to any UID/GID (updating real, effective, and saved IDs), while unprivileged processes can only switch `euid` to their real or saved ID.
  - `sys_seteuid` (115), `sys_setegid` (116): Change effective user/group identity.
  - `sys_setreuid` (113), `sys_setregid` (114), `sys_setresuid` (117), `sys_getresuid` (118), `sys_setresgid` (119), `sys_getresgid` (120): Precise multi-field credential swapping.
  - `sys_capget` (125), `sys_capset` (126): Linux capability mask inspection; UID 0 receives full capabilities (`0xFFFFFFFF`), while unprivileged users receive restricted capabilities (`0x0`).
* **OpenZFS System Account Database**:
  - `/etc/passwd`: Defines `root` (UID 0:0, `/root`, `/bin/sh`) and `hydra` (UID 1000:1000, `/home/hydra`, `/bin/sh`).
  - `/etc/group`: Defines `root` (GID 0), `wheel` (GID 10), and `hydra` (GID 1000).
* **Interactive Shell Privilege Management**:
  - Dynamic shell prompts: `hydra:/path# ` for superuser `root` (UID 0), `hydra:/path$ ` for unprivileged users (`hydra`, UID 1000).
  - `whoami` and `id`: Display active username, UID, GID, and security group membership.
  - `su [user]`: Seamlessly switch active shell credentials.
  - `sudo <command>`: Execute an individual command elevated with superuser UID 0 privileges.

---

## Interactive Shell Command: `linux`

The shell provides the `linux` command (aliased to `lx` and `linux64`):

```text
hydra:/bin# linux status
============================================================
           HYDRA OS - LINUX ABI COMPATIBILITY SUBSYSTEM      
============================================================
  Emulation Profile:    Linux 6.8.0-hydra (x86_64)
  Target C-Runtime:     musl-libc, glibc, Alpine userspace
  Syscall Interface:    Fast hardware SYSCALL / SYSRET
  TLS Subsystem:        MSR IA32_FS_BASE (arch_prctl)
  Memory Subsystem:     Page-backed brk + anonymous mmap
  Pseudo Filesystems:   /dev/null, /dev/urandom, /proc/version
------------------------------------------------------------
  Total Syscalls Dispatched:          28
  File & Terminal I/O Calls:          8
  Memory / mmap / brk Calls:          0
  Process & Signals Calls:            20
  arch_prctl (TLS) Calls:             0
  Time / Clock Calls:                 0
  Unsupported Syscalls:               0
============================================================

hydra:/bin# linux run roletest.elf
[+] Read 2760 bytes from OpenZFS (roletest.elf). Spawning Linux process...
[+] Linux process spawned with Task ID 2 (UID 0, GID 0). Executing...

=======================================================
   HYDRA OS POSIX CREDENTIAL & SECURITY ROLE TEST
=======================================================
[ROLETEST] Step 1: Initial credentials: UID=0, EUID=0, GID=0, EGID=0 (Superuser Root)
[ROLETEST] Step 1b: getresuid -> ruid=0, euid=0, suid=0
[ROLETEST] Step 2: Dropping privileges via setuid(1000)...
[ROLETEST] setuid(1000) result: 0
[ROLETEST] Current credentials: UID=1000, EUID=1000 [SUCCESS: Standard User Hydra]
[ROLETEST] Step 3: Attempting unauthorized escalation via setuid(0)...
[ROLETEST] setuid(0) result: -1 -> EPERM [DENIED: Security Enforced!]
[ROLETEST] Step 4: Attempting unauthorized escalation via seteuid(0)...
[ROLETEST] seteuid(0) result: -1 -> EPERM [DENIED: Security Enforced!]
[ROLETEST] Step 5: Testing authorized setuid(1000) as unprivileged user...
[ROLETEST] setuid(1000) result: 0 -> SUCCESS (allowed to retain self identity)
[ROLETEST] Step 6: capget -> effective mask=0x0 [SUCCESS: Capabilities restricted for UID 1000]
=======================================================
[+] ALL TESTS PASSED! User Role Security Verified.
=======================================================
[+] Linux process 2 finished execution.
```
