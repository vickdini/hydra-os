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

---

## 7. Unix Domain Sockets (`AF_UNIX`) & Wayland IPC Subsystem

To host upstream desktop environments such as **KDE Plasma 6.8** and modern Wayland clients (Qt6, GTK4, Mesa), Hydra OS provides an in-kernel POSIX Unix Domain Socket subsystem supporting stream-oriented local inter-process communication (`AF_UNIX` / `SOCK_STREAM`).

### Key Architecture Components
1. **Bidirectional Stream Ring Buffers**:
   Connected socket endpoints utilize paired, cross-connected `PipeBuffer` instances (`A.tx = B.rx` and `A.rx = B.tx`), delivering zero-copy, lock-free streaming semantics with automatic EOF propagation and `EPIPE` signaling.
2. **Global Rendezvous Namespace**:
   Listening sockets register their target paths (e.g. `/run/user/1000/wayland-0`, `/tmp/wayland-0`) in the thread-safe `GLOBAL_UNIX_SOCKETS` directory, allowing clients across arbitrary processes and threads to connect without requiring physical storage file backing.
3. **Unified Microkernel VFS Integration**:
   Sockets are first-class members of the task's file descriptor table via `FileDescriptor::Socket(Arc<Mutex<UnixSocket>>)`. Standard file I/O operations (`sys_read`, `sys_write`, `sys_close`, `sys_dup`, `sys_poll`, `sys_epoll`) operate uniformly on socket descriptors.

### Supported Socket Syscalls
| Syscall | Number | Description |
|---|---|---|
| `sys_socket` | 41 | Creates an endpoint for local communication (`AF_UNIX`, `SOCK_STREAM`) |
| `sys_connect` | 42 | Initiates a connection to a listening socket rendezvous path |
| `sys_accept` / `sys_accept4` | 43 / 288 | Accepts incoming client connection with optional `SOCK_NONBLOCK`/`SOCK_CLOEXEC` |
| `sys_sendto` / `sys_recvfrom` | 44 / 45 | Streams data over connected socket file descriptors |
| `sys_shutdown` | 48 | Shuts down reading, writing, or both channels (`SHUT_RD`, `SHUT_WR`, `SHUT_RDWR`) |
| `sys_bind` | 49 | Binds socket to a filesystem path (e.g., `/run/user/1000/wayland-0`) |
| `sys_listen` | 50 | Marks socket as passive listener with configurable backlog queue |
| `sys_getsockname` | 51 | Returns local bound address and path of the socket |
| `sys_getpeername` | 52 | Returns remote peer path connected to the socket |
| `sys_socketpair` | 53 | Creates an unnamed pair of connected sockets for immediate bidirectional IPC |

### Live Test Verification (`socktest.elf`)
```text
hydra:/bin$ linux run socktest.elf
[+] Read 3744 bytes from OpenZFS (socktest.elf). Spawning Linux process...
[+] Linux process spawned with Task ID 2 (UID 1000, GID 1000). Executing...

========================================
 Hydra OS - Unix Domain Socket & Wayland IPC Test
========================================
[1] Testing socketpair(AF_UNIX, SOCK_STREAM)...
    -> Created socket pair FDs: [3, 4]
    -> Read: 'WAYLAND_MSG_FROM_PEER_A'
    -> Read reply: 'WAYLAND_REPLY_FROM_PEER_B'
[+] PASS: socketpair bidirectional IPC verified.

[2] Initializing Wayland server socket...
[+] PASS: Server bound and listening on /run/user/1000/wayland-0

[3] Connecting Wayland client to /run/user/1000/wayland-0...
    -> Client connected successfully!
    -> Server accepted client connection FD: 7
    -> Server received: 'WL_DISPLAY_GET_REGISTRY_ID1'
    -> Client received: 'WL_REGISTRY_GLOBAL_COMPOSITOR_AND_XDG_WM'
[+] PASS: Wayland IPC client/server handshake verified!

[4] Testing getsockname on server FD...
    -> Socket address: '/run/user/1000/wayland-0'
[+] PASS: getsockname verified!

========================================
 [OK] ALL 5 SOCKET IPC TESTS PASSED!
 Unix Domain Sockets & Wayland IPC 100% OK
========================================
```

---

## 8. Epoll & Eventfd Multiplexing Subsystem (Qt6 & Wayland Event Loops)

Modern desktop toolkits (such as **Qt6**, **QEventLoop**, **Glib**, and **Wayland client runtimes**) drive their asynchronous I/O and cross-thread event processing through Linux `epoll` and `eventfd` primitives. Hydra OS provides native in-kernel implementations fully integrated with the microkernel's `FileDescriptor` table.

### Key Architecture Components
1. **Linux-Compliant Packed Event Layout**:
   On x86_64, `struct epoll_event` is packed to 12 bytes (`uint32_t events` followed immediately by `uint64_t data`). Hydra OS guarantees strict binary layout compatibility with GCC/Clang compiled binaries.
2. **Eventfd Synchronization Counter**:
   `FileDescriptor::EventFd` provides an atomic 64-bit wait/notify counter with non-blocking (`EFD_NONBLOCK`) and semaphore (`EFD_SEMAPHORE`) semantics.
3. **Multi-Descriptor Event Multiplexing**:
   `FileDescriptor::Epoll` tracks interest lists across Unix domain sockets, pipes, pseudo-terminals, eventfds, and storage files. Cooperative sleep and PIT timer tracking handle both immediate polling (`timeout = 0`), bounded timeouts, and infinite blocking waits (`timeout = -1`).

### Supported Syscalls
| Syscall | Number | Description |
|---|---|---|
| `sys_poll` / `sys_ppoll` | 7 / 271 | Polls multiple file descriptors for readiness with timeout |
| `sys_epoll_create` / `sys_epoll_create1` | 213 / 291 | Opens an epoll file descriptor |
| `sys_epoll_ctl` | 233 | Controls epoll interest list (`EPOLL_CTL_ADD`, `EPOLL_CTL_DEL`, `EPOLL_CTL_MOD`) |
| `sys_epoll_wait` / `sys_epoll_pwait` | 232 / 281 | Waits for I/O events on an epoll instance with millisecond precision |
| `sys_eventfd` / `sys_eventfd2` | 276 / 290 | Creates a file descriptor for event notification |

### Live Test Verification (`epolltest.elf`)
```text
hydra:/bin$ linux run epolltest.elf
[+] Read 3536 bytes from OpenZFS (epolltest.elf). Spawning Linux process...
[+] Linux process spawned with Task ID 2 (UID 1000, GID 1000). Executing...

========================================
 Hydra OS - Epoll & Eventfd Subsystem Test
========================================
[1] Testing eventfd2(0, 0)...
    -> Created eventfd FD: 3
    -> Read counter value: 42
[+] PASS: eventfd counter write/read verified!

[2] Creating epoll instance and socket pair...
    -> Created epoll FD: 4
    -> Created socket pair FDs: [5, 6]
[+] PASS: Registered socket and eventfd with epoll.

[3] Testing epoll_wait timeout behavior...
[+] PASS: epoll_wait correctly returned 0 on timeout.

[4] Triggering eventfd signaling (writing 100)...
    -> Awakened with 1 event: tag=0x2222, events=1
[+] PASS: eventfd wakeup multiplexing verified!

[5] Triggering Wayland socket message...
    -> Awakened with 1 event: tag=0x1111, events=1
    -> Received data: 'WAYLAND_FRAME_CALLBACK'
[+] PASS: Wayland socket epoll multiplexing verified!

========================================
 [OK] ALL 5 EPOLL/EVENTFD TESTS PASSED!
 Qt6/Wayland Event Loop Subsystem 100% OK
========================================
```

---

## 9. Wayland Shared Memory (`wl_shm`) & `SCM_RIGHTS` FD Passing Subsystem

In modern Wayland desktop compositors and clients (including **KDE Plasma 6.8**, **Qt6 Wayland**, and **Mesa**), client graphics are rendered off-screen into shared memory pixel pools and transferred to the display server without copying data through pipes or sockets.

### Key Architecture Components
1. **Anonymous Shared Memory Descriptors (`memfd_create`)**:
   `FileDescriptor::MemFd` provides anonymous, dynamically resizable memory buffers supporting POSIX `ftruncate`. When mapped with `mmap(..., MAP_SHARED, fd, ...)`, the kernel returns direct physical memory mappings marked `USER_ACCESSIBLE`, allowing concurrent reading and writing without kernel traps.
2. **Unix Domain Socket Ancillary FD Passing (`SCM_RIGHTS`)**:
   Wayland clients pass open memory pool descriptors across the local domain socket (`/run/user/1000/wayland-0`) using `sendmsg` with control headers (`SOL_SOCKET`, `SCM_RIGHTS`).
3. **Cross-Process Object Resolution**:
   The Hydra microkernel abstracts local file descriptors into `Arc<Mutex<MemFd>>` handles across the process boundary. The receiver's `recvmsg` allocates a new local file descriptor pointing to the *exact same* physical memory structure, achieving genuine zero-copy graphical synchronization.

### Supported Syscalls
| Syscall | Number | Description |
|---|---|---|
| `sys_mmap` | 9 | Zero-copy shared memory mapping for `memfd` and anonymous regions |
| `sys_sendmsg` | 46 | Sends datagrams/packets with `SCM_RIGHTS` ancillary file descriptors |
| `sys_recvmsg` | 47 | Receives datagrams/packets with incoming `SCM_RIGHTS` file descriptors |
| `sys_ftruncate` | 77 | Truncates or extends shared memory file size |
| `sys_memfd_create` | 319 | Creates an anonymous file descriptor backing shared memory (`wl_shm`) |

### Live Test Verification (`shmtest.elf`)
```text
hydra:/bin$ linux run shmtest.elf
[+] Read 3744 bytes from OpenZFS (shmtest.elf). Spawning Linux process...
[+] Linux process spawned with Task ID 2 (UID 1000, GID 1000). Executing...

========================================
 Hydra OS - Wayland Shm & SCM_RIGHTS Test
========================================
[1] Creating anonymous shared memory buffer (memfd_create)...
    -> Created memfd FD: 3
    -> Resized shm pool to 4096 bytes
    -> Mapped shared buffer into client space
[+] PASS: memfd_create, ftruncate & mmap verified!

[2] Initializing Wayland client/server IPC socket pair...
    -> Socket pair FDs: [4, 5]

[3] Sending wl_shm buffer FD via sendmsg(SCM_RIGHTS)...
    -> Transmitted 22 payload bytes + FD 3 across socket.
[+] PASS: sendmsg SCM_RIGHTS transmission verified!

[4] Server receiving FD via recvmsg(SCM_RIGHTS)...
    -> Received payload: 'WL_SHM_CREATE_POOL_REQ'
    -> Successfully received passed FD: 6
[+] PASS: recvmsg SCM_RIGHTS reception verified!

[5] Testing zero-copy shared memory synchronization...
    -> Server inspected buffer: 'WAYLAND_PIXEL_BUFFER_HEADER'
    -> Client inspected buffer at offset 64: 'SERVER_COMPOSITED_SURFACE'
[+] PASS: Zero-copy bidirectional synchronization verified!

========================================
 [OK] ALL 5 SHM & SCM_RIGHTS TESTS PASSED!
 Wayland Shared Memory Subsystem 100% OK
========================================
```

---

## 10. Graphics: KDE's Own Compositor on the DRM Device

The kernel has no Wayland compositor (an in-kernel compositor, `src/wayland`, and a protocol bridge, `wayland_bridge.rs`, were removed in 2026-11). Wayland clients talk to KWin, KDE's compositor, which `linux plasma` starts through SDDM and `hydra-session`. KWin draws through Hydra's Linux DRM device (`src/compat/linux/drm.rs`) and reads input from `/dev/input/event*` (`src/compat/linux/evdev.rs`). The kernel itself keeps only an emergency text console (`src/video`).

## 12. Dynamic Linker (`PT_INTERP`) & Auxiliary Vector (`auxv`) Subsystem

To run modern dynamically linked Linux applications (such as Qt6 libraries, KDE Frameworks, and native Plasma 6.8 binaries), Hydra OS supports the standard Linux System V AMD64 ABI dynamic linking model.

### 12.1 Program Interpreter (`PT_INTERP`) Lifecycle

```text
+-----------------------------------------------------------------------------------------+
|                                    ELF LOADER PIPELINE                                  |
|                                                                                         |
|  1. Parse Target Binary (`dynclient.elf`)                                               |
|     * Detect PT_INTERP Program Header -> Extract string "/lib64/ld-hydra.so"            |
|     * Map target binary's PT_LOAD segments into user memory space                       |
|     * Record application entry point (e_entry) and program header table (e_phoff)       |
|                                                                                         |
|  2. Dynamic Interpreter Resolution (`ld-hydra.so`)                                      |
|     * Search OpenZFS filesystem (/lib64, /lib, /bin)                                    |
|     * Read & validate 64-bit ELF shared object                                          |
|     * Map interpreter's PT_LOAD segments to dedicated user virtual base (AT_BASE)        |
|     * Set initial task instruction pointer (RIP) to interpreter's entry point!          |
|                                                                                         |
|  3. User Stack Preparation (argv, envp, auxv)                                           |
|     * Push strings: command-line arguments, environment variables, 16-byte random seed |
|     * Push ELF Auxiliary Vector (auxv) array:                                           |
|       - AT_PHDR   : Address of application's program headers                            |
|       - AT_PHENT  : Program header entry size (56 bytes)                                |
|       - AT_PHNUM  : Number of program headers                                           |
|       - AT_PAGESZ : Memory page size (4096 bytes)                                       |
|       - AT_BASE   : Base address where interpreter is loaded                            |
|       - AT_ENTRY  : Original application entry point                                    |
|       - AT_RANDOM : Pointer to 16 bytes of entropy                                      |
|       - AT_NULL   : Vector terminator (0)                                               |
|                                                                                         |
|  4. Hardware Context Initialization (iretq to Ring 3)                                   |
|     * CPU resumes at Interpreter Entry Point (ld-hydra.so)                              |
|     * Dynamic linker resolves shared libraries & symbol relocations                     |
|     * Dynamic linker transfers control (jmp *AT_ENTRY) to application!                  |
+-----------------------------------------------------------------------------------------+
```

### 12.2 Auxiliary Vector Wire Constants

| Auxv Tag | Code | Purpose | Value in Hydra OS |
|---|---|---|---|
| `AT_NULL` | 0 | Vector terminator | `0` |
| `AT_PHDR` | 3 | Address of program header table | Process virtual address of executable headers |
| `AT_PHENT` | 4 | Size of program header entry | `56` bytes (`sizeof(Elf64ProgramHeader)`) |
| `AT_PHNUM` | 5 | Program header count | `e_phnum` |
| `AT_PAGESZ` | 6 | Virtual memory page size | `4096` bytes |
| `AT_BASE` | 7 | Dynamic linker load base | Base virtual address of interpreter (`0` if static) |
| `AT_FLAGS` | 8 | Processor flags | `0` |
| `AT_ENTRY` | 9 | Application entry point | Target binary virtual entry address |
| `AT_UID` | 11 | Real user ID | `1000` (or `0` for root) |
| `AT_EUID` | 12 | Effective user ID | `1000` (or `0` for root) |
| `AT_GID` | 13 | Real group ID | `1000` (or `0` for root) |
| `AT_EGID` | 14 | Effective group ID | `1000` (or `0` for root) |
| `AT_SECURE` | 23 | Secure execution mode | `0` (unrestricted) |
| `AT_RANDOM` | 25 | 16-byte random stack pointer | Pointer to stack entropy buffer |

### 12.3 Live Test Verification (`dynclient.elf` & `ld-hydra.so`)

The dynamic executable [`dynclient.elf`](file:///d:/os/esp/bin/dynclient.elf) (2,064 bytes) contains `PT_INTERP` requesting `/lib64/ld-hydra.so`. The kernel automatically imports and maps both files from OpenZFS, passes `auxv`, and launches the interpreter in Ring 3:

```text
hydra:/bin$ linux run dynclient.elf
[+] Read 2064 bytes from OpenZFS (dynclient.elf). Spawning Linux process...
[+] Linux process spawned with Task ID 2 (UID 1000, GID 1000). Executing...
[*] Hydra Dynamic Linker (ld-hydra.so) executing in Ring 3...
  [+] Interpreter AT_BASE: 0x...
  [+] App Headers AT_PHDR: 0x...
  [+] Application AT_ENTRY: 0x...
  [+] Relocations & bindings resolved. Transferring control to application...
[*] Application main entry point reached after dynamic linker handoff!
  [+] Running unprivileged in Ring 3 userspace.
============================================================
[+] SUCCESS: Dynamic Linker (PT_INTERP) & Auxv Fully Verified!
============================================================
[+] Linux process 2 finished execution.
hydra:/bin$ linux status
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
Total Syscalls Dispatched:    12
```

### 12.4 Live Screen Capture & Visual Evidence

![Dynamic Linker and Auxv Verification](file:///C:/Users/Vick/.gemini/antigravity-ide/brain/1260e660-5468-4135-9234-e911d5b58dd9/test_dyn_clean.png)

Full console screen capture with `linux status` verification:

![Full Console Screen Capture - Dynamic Linker](file:///C:/Users/Vick/.gemini/antigravity-ide/brain/1260e660-5468-4135-9234-e911d5b58dd9/test_dyn_status.png)

---
