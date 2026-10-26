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

---

## Interactive Shell Command: `linux`

The shell provides the `linux` command (aliased to `lx` and `linux64`):

```text
hydra> linux status
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
  Total Syscalls Dispatched:          0
  File & Terminal I/O Calls:          0
  Memory / mmap / brk Calls:          0
  Process & Signals Calls:            0
  arch_prctl (TLS) Calls:             0
  Time / Clock Calls:                 0
  Unsupported Syscalls:               0
============================================================

hydra> linux test
[*] Running Linux ABI compatibility self-tests...
  [+] sys_uname: Linux 6.8.0-hydra
  [+] /proc/version: Linux version 6.8.0-hydra (gcc-13 / rustc-1.80) #1 SMP PREEMPT Hydra Microkernel
  [+] /dev/urandom: [54, e2, d1, 44, b0, 68, 77, 8a]
  [+] arch_prctl(ARCH_SET_FS): MSR 0xC0000100 read/write verified
[+] Linux ABI self-tests completed successfully.

hydra> linux run /bin/busybox ls -la
```
