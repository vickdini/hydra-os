# Moving the Linux layer out of the kernel: design (step 0)

Microkernel wave 2, Group 6, 2026-11-17. Base: `host-unit-tests` 2c6bc80. No code moves in this step. The numbers come from the kernel as it is today, measured in KVM virtual machines with 2 CPUs.

**Who this is for:** the user (technical, not a kernel specialist) and the agents of waves 3 and later, who will do the moves.

## 0. The answer in brief

- **Shape:** one ring-3 **Linux server** for the Linux personality, plus the servers Hydra already has or is building (zfs-server, net-server, the drivers). It is not a set of small servers: the descriptor table ties files, pipes, sockets, `poll`/`epoll` and processes together, and splitting them adds hops and complexity for little gain (section 4).
- **What stays in the kernel:**
  - a system-call trap that forwards calls to the server;
  - the mechanisms that must touch page tables, the scheduler or the CPU state: address spaces, page faults and the page cache, anonymous `mmap`/`munmap`/`mprotect`/`brk`, `futex`, threads, signal *delivery*, `seccomp`, and the per-thread calls (`rt_sigprocmask`, `rt_sigaction`, identity calls, clocks, `sched_yield`).
  - The server drives these through about 25 new primitives (section 5).
  - About 6,000 of today's 51,400 lines stay; about 45,000 move.
- **Cost today:**
  - forwarding one system call to a ring-3 server with today's IPC adds **6.5 µs** (Handoff mode) or **18 µs** (Queued mode);
  - a typical file call costs 1–5 µs today.
- **Effect on whole workloads.**
  - The desktop, the browser and the network are not system-call-bound. With today's Handoff IPC, forwarding would add an estimated **3–4 % to the KDE start**, 2 % to `apt-get update` and 1–3 % to Firefox's start. With Queued mode it would add up to 10 %.
  - **Metadata-heavy tools on warm caches pay in full.** A warm `find /usr` makes one call every 8 µs, and would be 88 % slower with Handoff.
- **Faster path:** a *direct switch*: the calling thread hands the CPU straight to a server thread, with the arguments in a per-thread shared page.
  - It should cost about **2 µs** per call (2.5 µs with the server's own kernel calls).
  - That brings the desktop workloads to about **1 %**, but warm `find` is still about **31 %** slower (21 % with PCID).
  - It is the first thing to build (step 1), about 5–6 agent-days.
- **Budget (section 6.6):** each step may make the desktop, browser and network workloads at most 5 % slower, the metadata-heavy tools at most 35 % slower, and no forwarded call more than 3 µs slower than its step-0 number.
- **Order:** the forwarding machinery first, with a small first tenant. Then the self-contained pieces, then the descriptor types one by one (the kernel's descriptor table stays a table of handles while they move), then the VFS, the descriptor table, and the process and signal policy last. That is 9 steps, about 53–64 agent-days (section 7).

Section 10 lists the decisions the user must make.

## 1. How a Linux system call runs today

1. The CPU enters `asm_syscall_entry`, then `hydra_syscall_dispatcher` (`src/arch/syscall.rs`).
2. **Lock-free fast path** (`compat::linux::fast_syscall`): `getpid`, `gettid`, `getppid`, the `getuid` family and private futex wakes are answered from a per-CPU cache, without the kernel lock.
3. **Everything else runs under the big kernel lock (BKL)** (`arch::smp::bkl_enter`). Only one CPU runs kernel code at a time; a call that blocks gives the lock up while it sleeps.
4. `dispatch_linux_syscall` (`compat/linux/mod.rs`) runs `seccomp`, then `dispatch_checked`, a large `match` that calls into the 60-odd files of `src/compat/linux`.
5. On the way back, `proc::deliver_on_syscall_return` delivers pending signals by building the signal frame on the user stack. `ptrace` stops happen around the call.
6. Data is copied straight between the kernel and the caller's memory (`vfs::copy_in`/`copy_out`): the caller's address space is the current one.
7. Page faults (`memory/vm.rs`) are handled in the kernel. File-backed pages come from the kernel's page cache (`compat/linux/mm.rs`), which asks zfs-server on a miss.
8. File-system metadata goes from the kernel's ZFS client (`src/fs/zfs`, with name, attribute and link caches) to **zfs-server** through IPC in Handoff mode.

Three facts from this matter for the design:
- **The BKL already serializes almost every Linux call.** A Linux server with one big lock of its own would not be less concurrent than today.
- **Today's Handoff mode is a global serialization point.** While any Handoff call is in progress, every other system call entry waits (`scheduler::wait_out_handoff`), and only the participants run (`handoff_participant`). Forwarding *every* system call in Handoff mode would keep today's one-at-a-time behaviour, but not improve on it.
- **A service has exactly one server thread** (`ipc::service`: "at most one server"). A Linux server that serves many callers at once needs several threads on one endpoint, which IPC does not support yet.

## 2. Map of the layer

### 2.1 The parts, their size, and what they need from the kernel

Lines are from `wc -l` (comments included) at 2c6bc80; the total is 51,452. The "Kind" column says how a part can move:
- **S** (self-contained): needs only descriptors, credentials and memory copies.
- **F** (descriptor-centred): an object behind a descriptor, needing readiness and wait queues.
- **V** (VFS): tied to path resolution and the ZFS client.
- **D** (device): tied to a driver, an interrupt path or the console.
- **P** (process and memory core): needs page tables, the scheduler, the CPU state or the return-to-user path.

| Part | Files (lines) | Lines | Needs from the kernel | Kind |
|---|---|---:|---|---|
| Dispatcher, ABI types, syscall numbers | mod 2,576, types 361, syscalls 229 | 3,166 | Everything: the trap frame, the BKL, the lock-free identity and futex-wake fast path, `prof`, `seccomp` | P (core) |
| Path and file calls (VFS) | vfs 3,816, recent 379 (openat2, ...), xfer 381 (sendfile, splice), misc 230, extra 1,119 | 5,925 | Descriptor table (`fs::fd`), ZFS client (`fs::zfs`, `fs::client`), page cache, credentials, ABAC/ACL/Landlock checks, user copies | V |
| Mounts and pseudo files | mount 1,892, fs 868 (/proc, /dev pseudo files), devices 1,926 (/dev, /sys, udev database), efivars 295, live 18 | 4,999 | ZFS client, process table (for /proc), PCI list, disks (`fs::blockdev`, `fs::gpt`), UEFI variables (`memory::paging`) | V |
| Descriptor objects and readiness | epoll 380, select 216, eventfd 278, timerfd 329, signalfd 162, pidfd 159, memfd 282, inotify 486, fanotify 846, locks 349 | 3,487 | Wait queues (`task::wait`), timers (`arch::pit`), signal state (signalfd), memory objects (memfd), hooks from `fs::zfs` and `fs::fd` (inotify, fanotify, locks) | F |
| Asynchronous I/O | io_uring 1,483, aio 367 | 1,850 | Ring pages mapped into the caller (`memory::vm`), descriptors, wait queues, timers | F |
| Unix sockets | unix 1,675, socket 500 | 2,175 | Descriptors (`SCM_RIGHTS` passes them), credentials (`SO_PEERCRED`), the VFS (socket files), wait queues | F |
| Internet sockets and netlink | inet 1,538, sockopt 463, rtnetlink 697, netlink 207 | 2,905 | The network stack: in-kernel today, net-server after Group 2. Wait queues | F (after Group 2) |
| Terminals | tty 848, pty 735, chardev 290 | 1,873 | Console keyboard and screen (`console`, `video::console`), signals (`SIGINT`, `SIGWINCH`, job control) | D/F |
| Devices | drm 1,620, evdev 689, snd 2,137, blockdev 361 | 4,807 | DRM: framebuffer, memory mapping, VT switch from the keyboard interrupt. evdev: called from the PS/2, mouse and USB interrupt paths. snd: hda-driver over IPC, DMA memory. blockdev: `fs::blockdev` | D |
| Processes and signals | proc 3,037, process 536, execve 501 | 4,074 | Task table and scheduler, signal frames (`arch::idt`, return-to-user path), exit and wait, ELF loader (`task::exec`, `task::elf`) | P |
| Memory | mm 917 (mmap family, page cache), userfaultfd 385, sysv 1,139 | 2,441 | Page tables and address spaces (`memory::vm`), page faults, frame allocator | P |
| Threads, futex, timers | futex 1,061, itimer 347, ptimer 356, ldt 271 | 2,035 | Scheduler sleep/wake, address-space keys, GDT/LDT and segment state (`arch::gdt`, `arch::segments`), timers, signals | P |
| Security and identity | ns 787, limits 605, seccomp 574, landlock 497, abac 845, abac_core 1,011, acl 326, keys 1,042 | 5,687 | Credentials and capabilities in the task (`task::tcb`), the syscall entry (seccomp), the VFS (Landlock, ACL, ABAC); keys and abac_core are almost pure | S (keys, abac_core); P (seccomp); V (others) |
| Debugging and tracing | ptrace 1,222, perf 496, prof 395, bpf 1,255 | 3,368 | ptrace: registers, the syscall entry and exit, signal stops. perf and prof: scheduler and fault hooks. bpf: descriptors only (an interpreter) | P (ptrace, perf, prof); S (bpf) |
| Other IPC and admin | mqueue 575, admin 770 (syslog, acct, ...), fuse 1,292 | 2,637 | mqueue: wait queues, signals (notification). admin: kernel log ring (`console`), accounting hook at task exit. fuse: called from the ZFS path walk | S (mqueue); P (admin hooks); V (fuse) |

The per-file counts of kernel references behind this table come from `tools/lxbench/depmatrix.py src/compat/linux`, a keyword count per file and kernel area, then reviewed by hand.

### 2.2 Linux code that lives outside `src/compat`

The personality is larger than `src/compat/linux`:

| Where | Lines | What |
|---|---:|---|
| `src/fs/fd.rs` | 1,260 | The descriptor table and `FileDescriptor` (one variant per Linux object: `Socket`, `Epoll`, `EventFd`, `Inet`, `Pty`, `SignalFd`, `Unix`, `TimerFd`, `Inotify`, `PidFd`, `Device`, ...), `poll` readiness, `dup`, `close`, `fcntl` |
| `src/fs/pipe.rs` | 242 | Pipes |
| `src/fs/zfs/mod.rs`, `src/fs/client.rs` | 2,658 | The ZFS client, with the name, attribute and symbolic link caches the VFS relies on |
| `src/task/tcb.rs` | (fields) | Linux state in every task: `tgid`, the six uids/gids, `caps`, `seccomp`, `fds`, `mm`, `brk`, `clear_child_tid`, `robust_list`, `fs_base`, segments, LDT, `exe`, `cmdline` |
| `src/task/exec.rs`, `src/task/elf.rs` | 1,423 | Starting a Linux program: ELF loading, the initial stack and auxiliary vector |
| `src/memory/vm.rs` | 1,830 | Address spaces (`Mm`), mappings, copy-on-write, page faults: this stays in the kernel |

### 2.3 What calls *into* the layer from the rest of the kernel

There are 161 references to `compat::linux` from 23 files outside `src/compat`; 17 of them are in the shell. The ones that matter:

| Caller | What it calls | Why it matters |
|---|---|---|
| `arch/syscall.rs` (syscall entry) | `fast_syscall`, `dispatch_linux_syscall`, `ptrace::syscall_entry/exit`, `proc::deliver_on_syscall_return`, `changes_identity`, `admin::flush`, `vfs::copy_in/copy_out` (also for native IPC calls) | This becomes the forwarding trap. `copy_in`/`copy_out` are generic user-memory helpers and must move to `memory::vm` |
| `arch/idt.rs` (traps) | `proc::deliver_on_trap_return`, `force_fault_signal`, `ldt::int80`, `tty::pump`, `perf::fault` | Signal delivery and fault signals stay in the kernel |
| `task/scheduler.rs` | `proc::register_process/register_thread/thread_exited`, `futex::exit_robust_list`, `futex::wake_key` (clear_child_tid), `admin::note_task`, `prof`/`perf` hooks, `mm::inode_source` | Thread exit must notify the server (an asynchronous message); futex and robust lists stay in the kernel |
| `fs/fd.rs` | 33 references: every descriptor type, `fanotify`, `locks`, `limits`, `tty` readiness | The descriptor table *is* Linux code; it moves with the descriptor objects |
| `fs/zfs/mod.rs`, `fs/client.rs` | `inotify`/`fanotify` events, page-cache updates (`mm::cache_*`), `fuse`, `acl::on_chmod`, supplementary groups | The ZFS client is used both by the VFS (moves) and by the page cache (stays): it splits |
| `memory/vm.rs`, `memory/frame_allocator.rs` | `userfaultfd`, `prof`, `mm::cache_shrink` | The page cache stays with memory |
| `arch/keyboard.rs`, `arch/mouse.rs`, `arch/usb_input` | `evdev::push_*`, `drm::request_vt_switch`, `tty::INPUT_WQ` | Input events must reach a ring-3 input owner through a notification, not a function call |
| `ipc/service.rs` | `proc::signal_pending` (to interrupt a queued call), `prof` | Generic: becomes a task-level "interrupted" flag |
| `task/supervisor.rs` | `snd::set_controller`, `snd::start` | Moves with sound |
| `task/tcb.rs`, `task/exec.rs`, `task/elf.rs` | `seccomp::State`, ABI types | Types only |
| `console.rs`, `video/mod.rs` | `admin::klog`, `drm` | The kernel log ring stays in the kernel; `syslog(2)` reads it through a primitive |
| `shell/*` (17) | `linux chroot`, `linux plasma`, `linux prof`, ... | Group 4 is moving the shell out; these become admin ops (section 8) |

### 2.4 Self-contained and deeply tied parts

- **Self-contained (they move almost as they are):** `keys`, `abac_core`, `bpf` (an interpreter behind descriptors), `mqueue`, most of `sysv` (messages and semaphores), `rtnetlink`/`netlink` (after Group 2), `sockopt`, `devices` (it writes files into the Linux root). Together about 8,000 lines.
- **Descriptor-centred (they move with the descriptor table, or one by one behind a "server object" descriptor):** epoll, select, eventfd, timerfd, signalfd, pidfd, inotify, fanotify, locks, io_uring, aio, unix and inet sockets, pty, pipes. About 10,000 lines.
- **VFS-tied:** vfs, mount, fs, recent, xfer, extra, misc, fuse, landlock, acl, abac. About 11,500 lines.
- **Devices:** drm, evdev, snd, tty, chardev, blockdev, efivars. About 6,200 lines. They are tied to interrupts, the console and the framebuffer, not to processes.
- **Deeply tied to processes and memory:** proc, process, execve, mm, futex, ptrace, seccomp, ldt, itimer, ptimer, userfaultfd, limits, ns, perf, prof, and the dispatcher. About 15,000 lines. Part of this stays in the kernel by design (section 5).

## 3. Measurements on today's kernel

### 3.1 How these numbers were measured

- **Kernel:** 2c6bc80 with no changes, built normally ("stock").
  - The IPC numbers come from the same kernel built with `--features g6-probe`.
  - That build adds one probe system call (`src/compat/linux/g6_probe.rs`, compiled only with that feature). Section 3.3 has the details.
  - Both builds give the same results for every test they share.
- **Machine:** QEMU/KVM, 2 virtual CPUs, 4 GiB, on the development PC under WSL2 (`tools/hydra_run.py --accel kvm --smp 2 --shared-host`).
  - Each run boots from an overlay of the pool.
  - The PC was shared with two other groups' VMs, so expect noise.
- **Programs:**
  - `tests/linux/lxbench.c` runs each test 5 times in a loop. It prints the lowest, median and highest loop, each loop being tens of thousands of iterations (100 for fork+exec).
  - It ran in 4 separate boots: 2 stock and 2 probe builds.
  - Workloads were timed with `time` and profiled with the kernel's own `linux prof` (calls per system call number, faults, file-server requests).
  - The KDE start (3 runs) was timed by screendumps every 0.7 s (`scratch/g6/kde.sh`, `frames.py`).
- **Time unit:** µs (microseconds) unless stated otherwise.

### 3.2 System calls today

The "median" is the median of the 4 boots' medians. The range is the lowest and highest single loop over all boots.

| Test | What it does | Median | Range | Where it runs today |
|---|---|---:|---|---|
| `getpid` | Raw `syscall(SYS_getpid)` | 0.16 | 0.15–0.23 | Lock-free fast path |
| `getpgrp` | A call that does nothing, on the normal path | 0.74 | 0.69–1.04 | BKL, dispatcher |
| `clock_gettime` | Monotonic clock | 0.02 | 0.02–0.04 | vDSO, no system call |
| `pread` 4 KiB, cached | Same 4 KiB of `/usr/bin/bash` again and again | 1.26 | 1.15–1.91 | Page cache |
| `pread` 64 KiB, cached | Same, 64 KiB | 5.12 | 4.50–6.57 | Page cache |
| `write` 64 bytes to `/dev/null` | | 1.09 | 0.98–1.83 | Pseudo file |
| `open` + `close` | `/etc/passwd` | 5.30 | 4.36–10.55 | VFS, ZFS client caches |
| `stat` | `/usr/bin/bash` (3 path components) | 2.63 | 2.28–3.09 | VFS, name cache |
| `fstat` | | 1.14 | 1.06–1.26 | VFS |
| Pipe round trip | Two processes, 1 byte each way | 25.9 | 24.8–33.6 | `fs/pipe.rs` |
| Unix socket round trip | `socketpair`, 1 byte each way | 32.3 | 26.3–73.2 | `unix.rs` |
| Futex round trip | Two threads wake each other | 2.84 | 1.72–4.86 | `futex.rs` |
| Futex wake, nobody waiting | | 0.19 | 0.18–0.26 | Lock-free fast path |
| `mmap` + `munmap` 1 MiB | No pages touched | 2.67 | 2.57–3.12 | `mm.rs`, `memory::vm` |
| Page fault, anonymous page | Per page, 1 MiB mapped and touched | 9.09 | 8.63–11.66 | `memory::vm` |
| `fork` + `wait` | Child exits at once | 215 | 206–321 | Scheduler, `memory::vm` |
| `fork` + `exec` + `wait` | `/bin/true` (dynamic) | 1,956 | 1,882–2,040 | Plus the ELF loader and the dynamic linker's calls |
| `sched_yield` | Nothing else to run | 2.71 | 2.47–3.70 | Scheduler |
| Switch between two processes on one CPU | `sched_yield` ping-pong, per switch | 3.39 | 3.16–5.45 | Scheduler, address-space switch |
| Pipe round trip, one CPU | | 29.4 | 25.1–32.8 | |
| Futex round trip, one CPU | Two threads of one process | 2.70 | 1.82–3.71 | |

Observations:
- **The normal path costs 0.74 µs before any work:** the BKL, `seccomp`, `ptrace` checks, and signal checks on return. The lock-free path costs 0.16 µs.
- **fork+exec+wait is now 1.96 ms** (it was about 3 ms earlier).
- **Pipes and Unix sockets are slow already: 26–32 µs per round trip, 10 times a futex round trip.** The time is in the pipe and socket wake-up paths, not in the system calls. A Linux server that implements them with futex-style waits could be *faster* than today.
- **A switch between two processes costs about 0.7–0.8 µs more than a switch between two threads**: `yield_switch_1cpu` 3.39 against `sched_yield` alone 2.71, and the futex round trip on one CPU suggests a thread switch of about 0.3 µs. This is mostly the address-space switch: the kernel does not use PCID, so every switch flushes the TLB.

### 3.3 The cost of one IPC round trip today

The probe system call (`syscall(0x6706, op, endpoint, count)`, compiled only with `--features g6-probe`) sends `count` supervisor pings from the calling Linux thread's system call to an existing ring-3 server. `hydra-rt` answers pings inside its receive loop, without running any handler, so the time is the IPC round trip alone. This is exactly the shape of a forwarded system call: a Linux thread in the kernel, a request to a ring-3 server, the reply, and back to user mode.

Measured against zfs-server (endpoint 0x20) and e1000-driver (0x22), in 2 boots each:

| Mode | One forward per system call, from user space | Added to a normal call (minus `probe_null` 0.63) | Many forwards in one system call (kernel loop) |
|---|---:|---:|---:|
| `probe_null` (op 0: return at once) | 0.63 (0.62–0.69) | | |
| **Handoff** (CPU handed straight to the server) | 7.1–7.5 (6.9–9.1) | **6.5–6.9** | 5.6–7.0 |
| **Queued** (caller sleeps on a wait queue) | 18.4–18.9 (17.3–22.1) | **17.8–18.3** | 8.8–9.5 |

What the numbers say:
- **Handoff costs about 6.5 µs** for an empty request. That is roughly 9 times the normal system call path. The time goes to the request table, the receive wait queue, `begin_handoff` and `yield_now` through the scheduler, the server's two system calls (`svc_reply`, `svc_recv`), the two address-space switches, and the BKL.
- **Queued costs about 18 µs per call, but 9 µs in a tight loop.** The difference is the other CPU going idle between calls: each call then has to wake a halted virtual CPU (an inter-processor interrupt and the KVM halt exit). When calls come back to back the server's CPU is still awake. On real hardware the wake-up is cheaper, but it is the same effect.
- **Neither mode is usable as is for forwarding every system call:**
  - Handoff stops every other system call entry in the machine while it runs (section 1). That is no worse than today's BKL, but it is not better either.
  - Queued is too slow.
  - Both allow only one server thread per endpoint.

### 3.4 Whole workloads

Wall-clock times, with the system calls each one makes on the normal path (from `linux prof`). The profiler does not count the lock-free fast-path calls (`getpid`, private futex wakes).

| Workload | Time | Normal-path system calls | Of them staying in the kernel in design C | Page faults (mapped object / anonymous) | Requests to zfs-server |
|---|---|---:|---:|---|---:|
| `apt-get update` (network, 9.5 MB fetched) | 27.9 s | 104,332 | 6,155 | 38,840 / 183,053 | 113,788 |
| Firefox headless screenshot, first start | 8.9 s | 20,084 | 6,747 | 41,723 / 17,762 | 11,562 |
| Firefox headless screenshot, warm start | 2.9 s | 18,669 | 6,464 | 40,342 / 17,160 | 8,573 |
| KDE: password entered to full desktop (taskbar shown), run 1 | 50.9 s | 332,763 | 67,351 | 366,730 / 211,811 | 99,882 |
| KDE, run 2 | 58.3 s | 337,184 | 70,756 | 366,847 / 230,414 | 97,730 |
| KDE, run 3 | 60.6 s | 331,176 | 66,646 | 367,794 / 211,776 | 95,286 |
| `apt-get update`, run 2 | 30.2 s | 106,017 | 6,162 | 38,853 / 143,252 | 114,548 |
| Firefox first start, run 2 | 9.0 s | 19,596 | 6,589 | 39,759 / 17,230 | 11,580 |
| Firefox warm start, run 2 | 3.0 s | 18,655 | 6,388 | 39,292 / 17,075 | 8,553 |
| `find /usr > /dev/null`, twice (cold 4.97 s, then warm 0.62 s) | 5.58 s | 154,206 (77,100 each) | 302 | 1,142 / 31,203 | 64,852 |
| `tar cf - /usr/share/doc \| cat > /dev/null` | 4.08 s | 39,772 | 234 | 1,786 / 18,276 | 25,491 |
| `du -s /usr/lib` (warm) | 0.75 s | 18,401 | 763 | 1,490 / 2,401 | 23,987 |

The two kinds of workload behave very differently:
- **Desktop, browser and network workloads** make one system call every 150–300 µs on average. Their time goes to page faults, disk reads and computation.
- **Metadata-heavy tools on warm caches** make one call every **8 µs**. The warm `find` is an example: `fcntl`, `close`, `fstat`, `getdents64`, `openat`, `newfstatat`. These tools are almost pure system-call cost, and every microsecond added per call shows.

KDE milestones (seconds after Enter on the SDDM password):

| Run | Splash shown | Welcome window | Wallpaper | Taskbar (desktop complete) |
|---|---:|---:|---:|---:|
| 1 | 1.0 | 41.0 | 45.2 | 50.9 |
| 2 | 1.0 | 43.2 | 50.4 | 58.3 |
| 3 (host busier: other groups' VMs ran) | 2.5 | 49.9 | 54.2 | 60.6 |
| **Median of 3** | | | | **58.3** (range 50.9–60.6) |

The KDE start is 23 % memory, futex, signal-mask and identity calls (in design C they stay in the kernel), then mostly path calls: `statx` 61,919, `access` 43,319, `openat` 18,175, `readlink` 16,986, `newfstatat` 13,903, plus `read` 19,925, `close` 15,744, `write` 11,472, `recvmsg`/`sendmsg` 14,704 (D-Bus and Wayland on Unix sockets). Its zfs-server requests are mostly `resolve_mnt` 43,740, `readlink` 15,334, `resolve` 11,656 and `getattr` 10,943: the name and attribute caches catch most path calls, but not all.

The raw logs and profiles are in `scratch/g6/` of the worktree (not committed: scratch is git-ignored). The scripts are `vm.sh`, `kde.sh`, `work.sh`, `profparse.py`, `estimate.py` and `agg.py`.

## 4. Choosing the target shape

### 4.1 The options

- **A. One Linux server** (gVisor's sentry, or MINIX's PM and VFS merged). One ring-3 process owns the whole personality: processes, signals policy, descriptors, VFS, pipes, sockets and the rest. The kernel forwards every call it does not handle itself.
- **B. Several servers** (MINIX style): for example a process server (fork, exec, wait, signals, credentials), a file server (VFS, descriptors, pipes, mounts) and a socket server (Unix and Internet sockets).
- **C. Mixed (recommended):** one Linux server as in A, but:
  - the kernel keeps the mechanisms that need page tables, the scheduler or the CPU state, plus the per-thread hot calls (section 5);
  - the protocol and device work stays in its own servers: zfs-server, net-server, the drivers, and later a display/input server.

### 4.2 Comparison

Hop counts are system-call forwards (trap to the Linux server and back) plus server-to-server calls. "Today" is the in-kernel layer.

| | Today | A: one server | B: several servers | C: mixed (recommended) |
|---|---|---|---|---|
| `read` of a cached file | 0 IPC | 1 forward (the server reads the kernel page cache through a primitive) | 1 forward (file server) | 1 forward |
| `stat`, `open`, `access` (name cache hit) | 0 IPC | 1 forward | 1 forward | 1 forward |
| `stat` with a name cache miss | 1 call to zfs-server | 1 forward + 1 zfs-server call | 1 + 1 | 1 + 1 |
| `poll` or `epoll_wait` on a pipe, a Unix socket and an eventfd | 0 IPC | 1 forward | 1 forward plus a readiness protocol between the file and socket servers (MINIX's `select` across servers was a known pain) | 1 forward |
| `send` on a TCP socket (net-server) | 1 call to net-server (after Group 2) | 1 forward + 1 net-server call | 1 + 1 | 1 + 1 |
| `fork` | 0 IPC | 1 forward + about 3 kernel primitives | 3 servers in a row (process, file, socket) | 1 forward + about 3 kernel primitives |
| `mmap` (anonymous), `mprotect`, `futex`, `rt_sigprocmask` | 0 IPC | 1 forward each, plus kernel primitives | 1 forward each | **0 IPC: stay in the kernel** |
| Page fault on a mapped file (cache hit) | 0 IPC | 0 if the page cache stays in the kernel | same | 0 |
| **Fault isolation** | A bug in the layer crashes the machine | A server bug kills the Linux world (every Linux process), not the kernel | A socket-server bug breaks only sockets, but in practice every desktop process uses all three | Same as A, but network and storage bugs are already isolated in their own servers |
| **Restart** | Reboot | Restart the server; every Linux program has lost its descriptors and must start again (log in again). The kernel, the emergency prompt and the drivers stay up | Partial: per-server state still lost, and the cross-server state (a socket's descriptor in a process) is hard to rebuild | As A |
| **Complexity** | Low (function calls) | Medium: one protocol (forwarded calls) plus kernel primitives | High: cross-server protocols for fork, exec, exit, descriptor passing (`SCM_RIGHTS`), credentials changes, `poll` | Medium; fewer kernel primitives on the hot path than A |
| **Fit with Hydra's servers** | Kernel is client of zfs-server and net-server | The server becomes their client directly (server to server, as zfs-server already calls the disk driver) | Each server is a client of zfs-server or net-server | As A |

### 4.3 Why C

1. **The descriptor table is the hub.** `poll`, `epoll`, `dup`, `fork`, `SCM_RIGHTS`, `close_range` and `/proc/self/fd` work across every kind of descriptor. Splitting files from sockets turns each of these into a multi-server protocol (B's main cost).
2. **Splitting processes from files gains nothing in practice.** A process-server crash or a file-server crash both end every Linux program. MINIX keeps PM and VFS apart and pays with a PM–VFS protocol on every fork, exec and exit.
3. **The hot per-thread calls must not leave the kernel.** In the KDE start, 23 % of the system calls are memory, futex, signal-mask and identity calls (67,000 of 333,000 normal-path calls), on top of the lock-free fast-path calls the profile does not count. They need page tables or the current thread's state; forwarding them would only add hops (A's cost).
4. **The page cache must stay in the kernel**, because page faults on mapped files need it without a hop. The KDE start has **367,000 faults on mapped objects**, more than its system calls. The server reaches the cache through primitives.
5. **Isolation already comes from the other servers.** The code that takes input from outside (network protocols, file-system code, drivers) is or will be in its own servers. The Linux server mostly holds bookkeeping.

## 5. What stays in the kernel, and the primitives the server drives

### 5.1 Calls answered in the kernel (never forwarded)

| Group | Calls |
|---|---|
| Memory | `mmap` without a file (anonymous or `MAP_ANONYMOUS\|MAP_SHARED`), `munmap`, `mprotect`, `brk`, `mremap`, `madvise`, `mincore`, `mlock`/`munlock`, `membarrier` |
| Threads and futex | `futex`, `set_robust_list`, `set_tid_address`, `rseq`, `sched_yield`, `sched_getaffinity`/`sched_setaffinity`, `getcpu`, `arch_prctl`, `set_thread_area`, `modify_ldt`, `exit` (one thread; the server is told) |
| Signals (this thread) | `rt_sigprocmask`, `rt_sigaction`, `sigaltstack`, `rt_sigreturn` |
| Identity and time | `getpid`, `gettid`, `getppid`, `getuid` family (the kernel keeps a copy the server updates), `clock_gettime`, `clock_getres`, `gettimeofday`, `time` (also in the vDSO), `nanosleep`, `clock_nanosleep`, `getrandom` |
| Entry checks | `seccomp` filters run before forwarding; `ptrace` system-call stops stay in the trap |

Everything else is forwarded, including `mmap` of a file (the server checks the descriptor and calls `as_map` with a memory-object handle), `clone`, `fork`, `execve`, `kill`, `wait4`, `exit_group`, and all descriptor calls.

### 5.2 The primitives

They are native system calls, allowed only for the task registered as the Linux server (like `SYS_SVC_*` are only for services). A *client* is a Linux thread. *Handles* are small integers the kernel gives the server. Every primitive that names a client checks that the client is a Linux task. Names are proposals.

**Forwarding (step 1)**

| Primitive | What it does |
|---|---|
| `lx_attach(workers)` | Registers the calling process as the Linux server and creates the per-worker syscall pages (section 6.3) |
| `lx_reply_recv(result, flags) -> request` | Answers the current request (unless it is the first call) and waits for the next one, in one trap. The request carries: client thread ID, process ID, syscall number, the 6 arguments, a request ID, and any data the kernel already copied in (paths, small structs; section 6.3). `flags`: restart the call (`ERESTARTSYS` semantics), the call blocks (keep the client asleep, answer later by ID) |
| `lx_complete(request id, result)` | Answers a call that was left pending (a blocking `read`, `poll`, `accept`, `wait4`) from any server thread |
| Notifications (kernel to server, on the same receive) | "Request X interrupted by a signal" (answer `-EINTR` or restart), "thread T exited", "process P's last thread exited" (with the fault signal, if any), "child stopped" (ptrace and job control) |

**Client memory**

| Primitive | What it does |
|---|---|
| `lx_read(client, addr, len, buf)` / `lx_write(client, addr, buf, len)` | Copies from or to the client's address space, faulting pages in as the client would (copy-on-write, file pages, `userfaultfd`); `-EFAULT` on bad addresses |
| `lx_read_str(client, addr, max, buf)` | Copies a NUL-terminated string |
| `lx_grant(client, addr, len, writable)` | Lends the client's pages for the length of the request (Group 5's page grants, for large reads and writes, `io_uring` rings) |

**Address spaces and memory objects**

| Primitive | What it does |
|---|---|
| `as_create() / as_clone(as) / as_drop(as)` | New empty address space; copy-on-write copy for `fork`; release |
| `as_map(as, addr, len, prot, flags, object, offset)` / `as_unmap` / `as_protect` | Mappings the server decides on: file `mmap`, `shmat`, the `io_uring` rings, the DRM dumb buffers |
| `obj_file(inode) -> object` | The kernel's page-cache object for a ZFS inode (the same one page faults use) |
| `obj_anon(size) -> object` | A shared anonymous object: `memfd`, System V shared memory, `MAP_SHARED\|MAP_ANONYMOUS` across `fork` |
| `obj_read(object, offset, client, addr, len)` / `obj_write(...)` | Moves file data between the page cache and the **client's** memory directly (no copy through the server): this is the `read`/`write` path for regular files |
| `obj_truncate`, `obj_sync`, `obj_size` | The rest of the file-data operations |

**Tasks, threads and exec**

| Primitive | What it does |
|---|---|
| `task_clone(parent thread, as, flags, tls, stack, child tid ptr) -> tid` | New thread or process (the server has already made the address space and its own tables); the child starts blocked until `task_start` |
| `task_exec(thread, exe object, interpreter object, argv/envp block, credentials) -> ok` | Runs the kernel's ELF loader on the objects (it stays in the kernel: it builds page tables and the initial stack) |
| `task_creds(process, uids, gids, caps, groups)` | The kernel's copy of the credentials (for the identity fast path, `seccomp`, the ELF loader and native checks) |
| `task_kill(process)`, `task_stop(thread)`, `task_cont(thread)` | Ending and stopping, for exit, signals and job control |
| `task_regs(thread, get/set)` | Registers and FPU state, for `ptrace` and core dumps |

**Signals**

| Primitive | What it does |
|---|---|
| `sig_post(process or thread, signal, siginfo)` | Queues a signal. The kernel delivers it on the next return to user mode with the handler table it keeps (`rt_sigaction` is kernel-side). It interrupts a pending forwarded call |
| `sig_take(thread, mask) -> siginfo` / `sig_state(thread)` | `signalfd`, `sigtimedwait`, `/proc/PID/status` |

**Waiting and time in the server**

| Primitive | What it does |
|---|---|
| Futexes in its own memory | The server's internal locks and waits: the existing `futex` |
| `timer_arm(deadline, cookie)` | A notification at a deadline (timerfd, POSIX timers, `poll` timeouts, interval timers) |
| Notifications from other servers | net-server's doorbell (Group 2's `SYS_SVC_SIGNAL`, forwarded to the Linux server), and later input and display events |

That is about 25 primitives. Several exist in some form today: `futex`, page grants, `svc_*`, `copy_in`/`copy_out`, and the ELF loader.

### 5.3 What the kernel keeps, in lines

At the end, about 6,000 of the 51,400 lines stay:
- the trap and forwarding: new, about 1,500;
- memory calls (`mm.rs` without the file parts): about 700;
- `futex`: 1,061;
- signal delivery and frames (part of `proc.rs`): about 1,000;
- `ldt`: 271;
- `seccomp`: 574;
- `prof`: 395;
- the ptrace mechanism (stops, registers): about 400;
- the identity fast path: about 200.

On top of that, `memory::vm`, the ELF loader, the page cache and the data half of the ZFS client stay where they are. About 45,000 lines move to the server.

## 6. Cost, the faster path, and the budget

### 6.1 Cost per forwarded call

The added cost per forwarded call is the IPC round trip minus the normal path's own cost (section 3.3). On top of that, the server sometimes calls the kernel itself, for example to copy the client's memory or to read the page cache. These calls average about 0.5 µs, and the estimates add them.

| Forwarding mechanism | Added per forwarded call | Notes |
|---|---:|---|
| Today's Handoff | 7.0 | Measured (6.5) + 0.5. Serializes the whole machine during each call |
| Today's Queued | 18.5 | Measured (18.0) + 0.5. Concurrent, but every call wakes the other CPU |
| Queued with the server's CPU kept awake | 9.3 | Measured in a loop (8.8) + 0.5. Would need a polling CPU |
| **Direct switch (proposed, section 6.3)** | **2.5** | Estimate: 2.0 + 0.5 (see 6.3) |
| Direct switch with PCID | about 1.7 | Estimate: no TLB flush on the two address-space switches |

### 6.2 Common calls, today and estimated after the move

In design C. "Forwards" is the number of trips to the Linux server, each costing 6.5 µs with today's Handoff or 2.0 µs with the direct switch. "+prim." means one server-side kernel primitive, about 0.5 µs.

| Call | Today | Forwards | With today's Handoff | With the direct switch |
|---|---:|---|---:|---:|
| `getpid`, `getuid` | 0.16 | 0 | 0.16 | 0.16 |
| `futex` round trip | 2.84 | 0 | 2.84 | 2.84 |
| `mmap`/`munmap` anonymous | 2.67 | 0 | 2.67 | 2.67 |
| Page fault | 9.09 | 0 | 9.09 | 9.09 |
| `fstat` | 1.14 | 1 | 7.6 | 3.1 |
| `stat` (name cache hit) | 2.63 | 1 | 9.1 | 4.6 |
| `pread` 4 KiB cached | 1.26 | 1 + prim. | 8.3 | 3.8 |
| `pread` 64 KiB cached | 5.12 | 1 + prim. | 12.1 | 7.6 |
| `open` + `close` | 5.30 | 2 | 18.3 | 9.3 |
| Pipe round trip | 25.9 | 4 | 52 | 34 (or less: today's pipe wake-up is the slow part) |
| `fork` + `wait` | 215 | 2 + about 4 prim. | about 233 (+8 %) | about 222 (+3 %) |
| `fork` + `exec` + `wait` of `/bin/true` | 1,956 | about 21 (exec, the dynamic linker's opens, reads and file mmaps, exit, wait) | about 2,100 (+8 %) | about 2,010 (+3 %) |

So a single file call becomes 2–7 times slower with today's IPC and 1.5–3 times slower with the direct switch. Calls that do real work (fork, exec, large reads) change little.

### 6.3 The faster path: a direct switch with a per-thread syscall page

What the forward would do, step by step:
1. **Trap.** The Linux thread's `syscall` enters the kernel as today. Calls of section 5.1 run locally, as today.
2. **Arguments in a shared page.** For a forwarded call, the kernel writes the number, the 6 arguments and the caller's IDs into the **syscall page** of an idle server worker. The page is mapped in both the kernel and the server. A small per-call table (the trace code in `arch/syscall.rs` already knows which arguments are paths) also lets the kernel copy in path strings and small input structures. Most path calls then need no `lx_read` primitive.
3. **Direct switch.** The kernel marks the caller "in a forwarded call" and switches the CPU straight to the worker: its address space and its saved registers. There is no run-queue pass, no wait queue, no other CPU and no BKL. This is the L4/seL4 "call" fast path, and LRPC's idea.
4. **Serve.** The worker returns to user mode inside its `lx_reply_recv` call, handles the request, and calls `lx_reply_recv` again with the result and any output in the same page.
5. **Switch back.** The kernel copies the output to the caller's buffers (the same table), switches straight back to the caller, and the caller returns to user mode.
6. **Blocking calls.** If the call must block (an empty pipe, `poll`), the worker answers "pending". The caller sleeps in the kernel and the worker is free; later any worker completes the call with `lx_complete`. A signal for the caller sends the server an "interrupted" notification.
7. **No idle worker.** If no worker is idle (all serving or busy), the request is queued and the caller sleeps. This is today's Queued mode, and the slow path.

Estimated cost, from the components measured in section 3.2:

| Part | Estimate |
|---|---:|
| Two trap entries and exits (the caller's, the worker's `lx_reply_recv`) | 0.3 |
| Two address-space switches without PCID (TLB flush, refill) | 1.2–1.6 |
| Argument page, copy-in/copy-out table, bookkeeping | 0.2–0.3 |
| **Total** | **about 2.0** (1.7–2.2) |

With PCID (tagged TLB entries, available on the NUC's Haswell CPU), the TLB flushes go away: about 1.2–1.5 µs, or about 1.7 µs with the server's own kernel calls (section 6.1).

What it takes to build (part of step 1):

| Piece | Where | Size | Agent-days |
|---|---|---|---|
| Several server threads on one endpoint (a worker pool) | `ipc::service`, scheduler | about 300 lines | 1 |
| Syscall pages, `lx_reply_recv`, `lx_complete`, notifications | new `src/lx` (or in `ipc`), `arch/syscall.rs` | about 800 lines | 1.5 |
| Direct switch in the scheduler (caller to worker and back, no run queue) | `task/scheduler.rs` | about 300 lines | 1.5 |
| Copy-in/copy-out table for the common calls | `src/lx` | about 300 lines | 0.5 |
| Server-side loop in `hydra-rt` and a test server | `userland/drivers` | about 400 lines | 0.5 |
| Stress tests: many threads, signals during forwarded calls, killing the server | `tests/linux`, scripts | | 1 |
| **Total** | | **about 2,100 lines** | **about 5–6** |
| Optional: PCID | `memory::paging`, scheduler | about 150 lines | 1–2 |

### 6.4 The other faster paths considered

- **A shared-memory syscall ring** (FlexSC-style): the kernel posts calls into a ring that a server polls on another CPU, so there is no switch on the calling CPU.
  - It needs a CPU that spins, or else it pays the cross-CPU wake-up of Queued mode: about 9–18 µs here.
  - The target machines have 2 cores (4 threads), so a dedicated polling core costs too much. Not recommended for calls; fine for batched notifications (as net-server's doorbell).
- **Keeping the hottest calls in the kernel:** design C already keeps the memory, futex, signal-mask, identity and time calls (23 % of the KDE start).
  - A further option is **"fast file handles"**: when the server opens a regular file, it tells the kernel which page-cache object and position the descriptor uses. The kernel then answers `read`, `write`, `pread`, `pwrite`, `lseek` and `fstat` on it locally.
  - In the KDE start that is about 12 % of the calls (`read` 19,925, `write` 11,472, `fstat` 10,060).
  - The cost is a kernel shadow table that the server must keep in step on `close`, `dup2` and `fork`: about 500 lines and subtle consistency rules.
  - Recommendation: not at first; only if a step misses the budget.
- **Today's Handoff for everything:** simplest, but it keeps the whole machine one-call-at-a-time and costs 7 µs per call.

### 6.5 Whole-workload estimates

Estimated added time = (forwarded calls) × (added cost per call). This assumes every added microsecond is on the critical path, which overstates it a little with 2 CPUs. The "everything forwarded" rows show design A, where even the memory, futex and signal-mask calls go to the server.

| Workload | Time today | Forwarded calls (design C) | Today's Handoff (7.0 µs) | Today's Queued (18.5 µs) | Queued, server CPU awake (9.3 µs) | **Direct switch (2.5 µs)** |
|---|---:|---:|---:|---:|---:|---:|
| KDE password to desktop, run 1 | 50.9 s | 265,412 | +1.9 s (4 %) | +4.9 s (10 %) | +2.5 s (5 %) | **+0.7 s (1 %)** |
| KDE password to desktop, run 2 | 58.3 s | 266,428 | +1.9 s (3 %) | +4.9 s (8 %) | +2.5 s (4 %) | **+0.7 s (1 %)** |
| KDE password to desktop, run 3 | 60.6 s | 264,530 | +1.9 s (3 %) | +4.9 s (8 %) | +2.5 s (4 %) | **+0.7 s (1 %)** |
| KDE, design A (every call forwarded), run 1 | 50.9 s | 332,763 | +2.3 s (5 %) | +6.2 s (12 %) | +3.1 s (6 %) | **+0.8 s (2 %)** |
| `apt-get update`, runs 1 and 2 | 27.9 / 30.2 s | 98,177 / 99,855 | +0.7 s (2 %) | +1.8 s (6–7 %) | +0.9 s (3 %) | **+0.25 s (1 %)** |
| Firefox headless, first start | 8.9 / 9.0 s | 13,337 / 13,007 | +0.09 s (1 %) | +0.24 s (3 %) | +0.12 s (1 %) | **+0.03 s (0.4 %)** |
| Firefox headless, warm start | 2.9 / 3.0 s | 12,205 / 12,267 | +0.09 s (3 %) | +0.23 s (8 %) | +0.11 s (4 %) | **+0.03 s (1 %)** |
| `tar` of `/usr/share/doc` | 4.08 s | 39,538 | +0.28 s (7 %) | +0.73 s (18 %) | +0.37 s (9 %) | **+0.10 s (2 %)** |
| `find /usr`, cold then warm | 5.58 s | 153,904 | +1.08 s (19 %) | +2.85 s (51 %) | +1.43 s (26 %) | **+0.38 s (7 %)** |
| `du -s /usr/lib`, warm | 0.75 s | 17,638 | +0.12 s (16 %) | +0.33 s (44 %) | +0.16 s (22 %) | **+0.04 s (6 %)** |
| `find /usr`, warm only | 0.62 s | about 77,000 | +0.54 s (88 %) | +1.43 s (231 %) | +0.72 s (116 %) | **+0.19 s (31 %)** |
| Same, direct switch with PCID (1.7 µs) | | | | | | +0.13 s (21 %) |

What this shows:
- **Desktop, browser and network workloads are not dominated by system calls.**
  - KDE's start is mostly page faults, disk reads and the programs' own work.
  - Even today's Handoff IPC would add only about 4 % (2 s of 51–61 s).
  - The direct switch keeps them near 1 %.
- **Metadata-heavy tools on warm caches are system-call-bound**, and they pay in full:
  - a warm `find /usr` would be about **31 % slower** with the direct switch (21 % with PCID);
  - it would be 88 % slower with today's Handoff, and more than 3 times slower with today's Queued mode.
  - `du` and `ls -R`, and probably `git status` and `make` on a large tree, belong to the same class.
- **This is the main cost of moving the VFS and the descriptor table out.**
  - The forwarded calls in `find` are cheap in the kernel (`fcntl` and `close` take well under 1 µs of work), so the forward is most of their new cost.
  - It can be reduced in three ways, none of them free:
    - PCID;
    - fewer zfs-server requests thanks to a server-side cache (today the warm `find` still makes many `open_ref`/`release`/`readdir` requests);
    - or keeping descriptor-table fast paths in the kernel (decision 2).
- **Design A would forward 23 % more calls in the KDE start** than design C, and those calls would also need kernel primitives.

### 6.6 The performance budget

Each step from step 1 on must meet these limits, measured as here with `lxbench`, `kde.sh` and `work.sh` (3 boots each) against the step-0 numbers above:

| What | Budget |
|---|---|
| A forwarded call that does nothing (the probe's `probe_null` becomes a real forwarded number) | **≤ 3.0 µs added** over the 0.74 µs normal path (target 2.0) |
| Calls that stay in the kernel (`getpid`, futex round trip, `mmap`/`munmap`, page faults) | Within **+10 %** of section 3.2 |
| Forwarded file calls (`stat`, `fstat`, `open`+`close`, `pread` 4 KiB) | At most **today + 3 µs per forward** (`stat` ≤ 5.6, `open`+`close` ≤ 11.3, `pread` 4 KiB ≤ 4.3) |
| Pipe and Unix socket round trips | **≤ today** (25.9 and 32.3): the new implementation must fix the slow wake-up, not add to it |
| `fork`+`exec`+`wait` | ≤ 2.15 ms (+10 %) |
| KDE password to full desktop | Median of 3 runs ≤ step-0 median **+5 %** (the step-0 runs spread from 50.9 to 60.6 s, about 20 %, so 3 runs are the minimum) |
| Firefox headless warm start, `apt-get update`, `tar` | **≤ +5 %** each (median of 3) |
| Metadata-heavy tools: warm `find /usr`, warm `du -s /usr/lib` | **≤ +35 %** (the direct-switch estimate is 31 % and 6 %); a stricter limit needs decision 2 |
| Concurrency | No global serialization: 2 threads making forwarded calls on 2 CPUs must not take longer than one thread making both sets (a new lxbench test in step 1) |

A step that misses the budget does not merge until it is fixed, or until the user accepts the cost.

## 7. Order of the steps

### 7.1 The idea that makes small steps possible

Moving the descriptor table first would force the VFS, pipes, sockets, `poll` and `epoll` to move at once: about 25,000 lines in one step. Instead, the descriptor table stays in the kernel as a **table of handles** while the descriptor *types* move out one at a time:
- **A "server object" descriptor.** A new descriptor kind, `FileDescriptor::Server { endpoint, handle }`. `read`, `write`, `ioctl`, `close` and the rest on it are forwarded to the object's owner.
- **Readiness without a call.** Each such object has a readiness word in memory shared with the kernel: Group 2's design for net-server sockets. `poll`, `select` and `epoll` in the kernel read the word without IPC. The owner rings a doorbell when words change, and the kernel wakes the waiters.
- **Temporary kernel primitives.** These serve server code that needs something still in the kernel (for example "resolve this path" before the VFS moves). Each is listed as temporary and removed by a later step.

The descriptor table itself moves in step 6, when nothing in the kernel needs it any more.

### 7.2 The steps

| Step | What moves (lines) | New kernel pieces | How it is tested | Agent-days |
|---|---|---|---|---:|
| **1. Forwarding machinery, first tenant** | `keys` (1,042: no descriptors, only credentials) | Worker pool on one endpoint, syscall pages, `lx_reply_recv`/`lx_complete`, client memory primitives, notifications, the direct switch (6.3); a forwarding table (syscall number to kernel or server); a ring-3 `linux-server` program started by the supervisor | Suite test `keys`; full suite; lxbench plus a forwarded null call against the budget; a concurrency test; killing `linux-server` (callers get errors, nothing hangs, the server comes back) | 6–7 |
| **2. Server-object descriptors; self-contained pieces** | `bpf` (1,255), `mqueue` (575), System V messages and semaphores (about 600 of `sysv`) | `FileDescriptor::Server`, readiness words and doorbell, `sig_post` (mqueue notification) | `bpf`, `mqaio`, `sysv`, full suite, budget | 4–5 |
| **3. Network sockets and netlink** (after Group 2 is merged) | `inet` (1,538), `sockopt` (463), `rtnetlink` (697), `netlink` (207) | None new: the Linux server becomes net-server's client | `socktest`, `ipv6`, `icmp`, `procnet`, `sockopt`, `listen`; `apt-get update`; Firefox loading a page; throughput before and after; killing net-server and `linux-server` | 4–5 |
| **4. Unix sockets, pipes, event descriptors** | `unix` + `socket` (2,175), `fs/pipe.rs` (242), `eventfd`, `timerfd`, `signalfd`, `pidfd` (928) | `timer_arm`, `sig_take`; temporary: `vfs_resolve` (socket files), descriptor passing between processes (`SCM_RIGHTS`) | `unixtest`, `unixgc`, `epollet`, `socktest`, pipe and Unix round trips (budget: no slower than today); KDE (D-Bus and Wayland run on Unix sockets) and Firefox | 5–6 |
| **5. Terminals and devices** (can be 5a sound, 5b the rest) | `tty`, `pty` (1,583) to the Linux server; `snd` (2,137) to the Linux server or next to hda-driver; `drm` + `evdev` (2,309) to a display/input server | Input events from the keyboard, mouse and USB interrupt paths become notifications; `as_map` for DRM buffers; the console hand-back (VT switch) as a protocol | `snd`, `ptytest`, `notty`, `drmtest`; KDE with PS/2 and USB input; Ctrl+Alt+F1/F2; sound plays | 6–7 |
| **6a. VFS, mounts, pseudo files, the descriptor table** | `vfs`, `recent`, `xfer`, `misc`, `extra`, `mount`, `fs`, `devices`, `efivars`, `epoll`, `select`, `locks`, `memfd` glue, `fs/fd.rs`, the name/attribute/link caches of `fs/zfs` (about 17,000) | `obj_file`/`obj_read`/`obj_write`/`obj_*`, `as_map` for file mappings; the kernel's descriptor table goes; temporary primitives from step 4 go | Nearly the whole suite (`vfs`, `mount`, `mountapi`, `fscache`, `pagecache`, `xattr`, `recent`, `batch1`–`3`, `stdfd`, `fsync`, `exelink`, `mmaptail`, ...); KDE, Firefox, Wine, the installer test; the full budget | 12–14 |
| **6b. The rest of the file side** | `io_uring`, `aio` (1,850), `inotify`, `fanotify` (1,332), `fuse` (1,292), `landlock`, `acl`, `abac` + `abac_core` (2,679) | `lx_grant` for ring pages | `iouring`, `mqaio`, `fanotify`, `fuse`, `landlock`, `acl`, `abac` | 5–6 |
| **7. Processes and signal policy** | `proc` (the policy part, about 2,000), `process` (536), `execve` (501), `ns` (787), `limits` (605), `itimer`/`ptimer` (703), `admin` (770) | `task_clone`, `task_exec`, `task_creds`, `task_kill`/`stop`/`cont`, exit notifications; signal *delivery* stays | `signals`, `sigctx`, `exitgroup`, `crashexit`, `pidns`, `nstest`, `limits`, `acct`, `ptimer`, `clonepar`, `robust`, `cmdline`, `procinfo`; fork+exec budget; Wine | 7–8 |
| **8. Debugging and the last pieces** | `ptrace` policy (about 800), `perf` (496), `userfaultfd` glue, System V shared memory; the dispatcher shrinks to the trap and the local calls | `task_regs`; the ptrace stop mechanism stays | `ptrace`, `uffd`, `perf`, `sysv`, full suite, gdb and strace by hand | 4–6 |
| **Total** | about 45,000 lines move | about 25 primitives | | **about 53–64** |

Every step:
- ends with the full suite (74/74), the host tests, KDE with Firefox, Wine, sound, the installer test, and the budget (6.6);
- keeps a switch that sends the moved calls back to the in-kernel code (until the next step deletes it), so a regression can be bisected inside one build.

### 7.3 Changes to the plan's probable order, and why

The plan (`docs/microkernel-plan.md`) proposed: BPF, FUSE, netlink, sound, DRM first, then file systems and descriptors, then processes, signals and memory. Changes:

1. **A step 1 of its own for the forwarding machinery.** Every later step depends on the cost of a forward, and the direct switch is the one large piece of new kernel code. It is built and measured with a harmless tenant (`keys`) before anything important depends on it.
2. **FUSE moves with the VFS (6b), not first.** The kernel's path walk calls into it (`fs/zfs/mod.rs` uses `fuse`), so it is not self-contained.
3. **DRM and sound move after the memory-object primitives exist (step 5).**
   - They are devices tied to the keyboard interrupt (VT switch), the console hand-back and mapped buffers.
   - Their natural home is a display/input server and the sound driver, not necessarily the Linux server.
4. **Netlink after Group 2: confirmed** (step 3, with the Internet sockets, which share net-server).
5. **Pipes and Unix sockets before the VFS (step 4)**, thanks to server-object descriptors. They are the descriptors the desktop uses most (D-Bus, Wayland), so their performance is proven early.
6. **"Processes, signals and memory last": confirmed for processes and signals.**
   - Memory mostly does not move at all (section 5).
   - The remaining memory policy (file `mmap`, `shmat`) moves with the VFS and System V pieces.

## 8. Coordination with the other groups

### 8.1 Group 2: net-server

Group 2's protocol (NOTES.md, 2026-11-17) is already a good fit:
- socket handles;
- payloads at an offset in the window, per client;
- requests that never block;
- readiness words in a status area;
- a doorbell.

The Linux server (step 3) needs:
1. **To be a second client:** `allow_client(0x28, <linux-server endpoint>)` and its own data range in the window. Group 2 planned per-client offsets.
2. **The doorbell as a notification to the Linux server**, instead of the kernel's wait-queue hook. Group 2 mentions this (`forward` the signal).
3. **Cleanup when a client dies:** when `linux-server` restarts, net-server must close every handle that client held. This needs a "client gone" notification or a `close all of client X` request.
4. **Concurrent requests from one client:** the Linux server's workers may have several requests in flight. NOTES says requests answer at once and never block, which is what is needed.
5. **Queued (not Handoff) calls from a server.** The Linux server never holds kernel locks, so its calls must not stop the machine. Today `driver_call_mode` picks Handoff only when the caller is inside a hand-off, so this works as long as the Linux server is never called in Handoff mode.

Until step 3, the kernel's `inet.rs` stays net-server's client, exactly as Group 2 is making it now.

### 8.2 Group 4: the shell and the admin interface

- **Admin ops after step 7.** The "Linux root" ops (`linux chroot`, `linux plasma`, and the like) start Linux programs, so after step 7 they must reach the Linux server, which will own the process table.
- **Proposal: keep the admin op group "linux" as the stable interface.**
  - hydra-shell calls `SYS_ADMIN` as Group 4 designed.
  - Until step 7 the kernel implements those ops itself.
  - From step 7 on, the kernel forwards them to the Linux server as messages of the same shape.
- **Ops as plain data.** For this to work, each op should be defined by data only, not by kernel internals: the root directory, program path, argv, environment, uid/gid, working directory, and which terminal to use.
- **`linux prof` and the kernel log stay kernel admin ops**, because the profiler and the log ring stay in the kernel.

### 8.3 zfs-server

- **A second client.** The Linux server becomes zfs-server's second client, for metadata: `lookup`, `resolve`, `getattr`, `create`, `readdir`, xattrs and the rest. File *data* keeps going through the kernel's page cache, so the kernel stays a client for `read`/`write` of blocks.
- **What it needs:**
  - `allow_client` and a separate window range per client, as for net-server;
  - one coherence rule: the Linux server tells the kernel (`obj_truncate`, `obj_forget`) when a metadata operation changes or removes data the page cache may hold. Today `fs/zfs/mod.rs` calls `mm::cache_truncated`/`cache_forget` for the same reason.

### 8.4 IPC (Group 5's code, merged)

- **Several threads serving one endpoint.** Step 1 needs this; today a service has exactly one server task.
- **The direct switch** is a third call mode next to Handoff and Queued.

### 8.5 Interface notes for the next waves

These are also written in `D:\os-mk-shared\NOTES.md`:
- The Linux server is a native ring-3 program in `userland/drivers` (on `hydra-rt`), started by the supervisor like the drivers.
- System calls reach it through the kernel's forwarding trap, not through `SYS_SVC_CALL`. The kernel keeps the calls of section 5.1.
- Other servers see it as an ordinary client (`svc_call`, windows, grants).

## 9. Risks

- **System-call-heavy workloads.** Builds, `git`, `dpkg` and `find` make many small calls. `find`, `tar` and `du` were measured (section 3.4); compiling large projects was not.
- **Restart means losing every Linux program.** The server holds every process's descriptors, so a crash of `linux-server` ends all Linux programs (the desktop goes back to the login screen). That is much better than today's kernel panic, but it is not MINIX-style transparent recovery. gVisor has the same property.
- **Signals and restarts across a forward.** `EINTR`, `SA_RESTART` and `ERESTART_RESTARTBLOCK` must work when a signal arrives while the call is in the server. The suite's `signals`, `sigctx`, `futex` and `exitgroup` tests cover much of this; step 1 adds a dedicated test.
- **Deadlocks between the kernel and the server.** Two rules prevent them:
  - the kernel never waits for the Linux server while it holds a lock;
  - the Linux server's own page faults and memory are native (never forwarded to itself).
  
  A page fault in a *client* during `lx_read` is handled by the kernel, as today.
- **Concurrency inside the server.** Today's BKL means almost no Linux code runs in parallel. The server can start with one big lock of its own (the same behaviour), then split it. The concurrency test in the budget catches a server that is *more* serial than today.
- **Memory.** One worker per concurrently blocked call, each with a stack. The KDE desktop has a few hundred threads; with 64 KiB stacks, 300 workers take about 20 MB. A pool that grows on demand keeps it lower.
- **KVM is not real hardware.** Inter-processor interrupts and TLB flushes cost differently on the NUC. The budget must also be checked there before the last steps are deployed.
- **The test harness types into the kernel shell** (Group 4's area). Each step must keep the harness commands working.

### 9.1 What was not measured

- Real hardware (only KVM, 2 virtual CPUs, on a shared PC).
- A prototype of the direct switch: its 2 µs cost is an estimate from measured parts (section 6.3).
- Workloads with heavy compilation or `git`; Wine programs; sound.
- Firefox in the desktop. The headless start (`firefox --headless --screenshot`) was used as a stand-in.

## 10. Decisions the user must make

1. **One Linux server or several?**
   - Recommended: one (design C), with the existing zfs-server and net-server and a later display/input server beside it.
   - Several servers (design B) cost more hops and much more protocol, for little real isolation (section 4).
2. **Which calls stay in the kernel?**
   - Recommended: memory, futex, this thread's signal mask and handlers, identity, time, and `seccomp`/ptrace stops (section 5.1).
   - Optional, only if the budget is missed: "fast file handles" for `read`/`write`/`fstat` on regular files (section 6.4).
   - The hard case is metadata-heavy tools (warm `find` +31 %). To avoid that cost completely, the descriptor table and the VFS's cached paths would have to stay in the kernel. That would be a hybrid end state: steps 1–5 and 7–8 only, with the VFS kept in the kernel.
3. **The acceptable slowdown.**
   - Proposed: at most 5 % on desktop, browser and network workloads; at most 35 % on metadata-heavy tools such as a warm `find`; at most 3 µs added per forwarded call (section 6.6).
   - Stricter would force fast file handles early, or keeping the VFS in the kernel; looser would allow skipping the direct switch.
4. **What happens when the Linux server crashes?**
   - Proposed: every Linux program ends, the supervisor restarts the server, and the desktop starts again at the login screen. The kernel, the drivers and the emergency prompt stay up.
   - The alternative is a reboot.
5. **Build the direct switch in step 1?**
   - Recommended: yes, about 5–6 agent-days. Forwarding with today's IPC would cost about 4–10 % on the desktop start and would keep the machine one-call-at-a-time.
6. **PCID (tagged TLB) as a small separate kernel task before or during step 1?** It cuts the cost of every address-space switch, which also helps today's drivers. About 1–2 agent-days.
7. **The changed order** (section 7.3): forwarding machinery first; FUSE with the VFS; DRM and sound after the memory primitives; pipes and Unix sockets before the VFS.
8. **Where sound and the display go:**
   - into the Linux server (simplest);
   - or next to their drivers: an ALSA layer beside hda-driver, a display/input server (better isolation, more protocol).

## 11. Step 1 as built (wave 3, Group 7, branch `mk-lxfwd`)

What step 1 built, and how it is used, is in [src/linux-server.md](src/linux-server.md). In short:
- one ring-3 `linux-server` (4 worker threads and a main thread, endpoint 0x29);
- a forwarding table in the trap: `add_key`, `request_key`, `keyctl` and a test call go to it;
- syscall pages, `SYS_LX_REPLY_RECV`/`SYS_LX_COMPLETE`, client memory primitives, a notification ring;
- a direct switch (vector 0x82, no run-queue pass, no FPU traffic, no machine-wide stop);
- the crash policy;
- a switch back to the in-kernel code (`opt/hydra/lx=kernel`).

### 11.1 Measured cost (KVM, 2 CPUs, same VM setup as section 3; µs, medians of 5 loops)

| What | b01f2e3 (before) | Step 1, no PCID | Step 1 + Group 8's PCID | Budget |
|---|---:|---:|---:|---|
| In-kernel null call (`getpgrp`; the test call with `lx=kernel`: 0.71) | 0.73 | 0.72 | 0.72 | |
| **Forwarded null call** (`lx_null`) | n/a | 4.52 | **3.42** | ≤ 3.74 (0.74 + 3) |
| Added per forwarded call | | +3.8 | **+2.7** | ≤ +3.0 |
| `keyctl` (in the kernel before, in the server after) | 0.735 | 4.88 | 3.46 | |
| Two threads on 2 CPUs, per call: `lx_null_par2` (one thread: `lx_null`) | n/a | 4.83 (4.52) | 3.99 (3.42) | not slower than one thread |
| Same for `keyctl_par2` | 1.04 (0.735) | 5.11 | 4.47 | |

- **The per-call budget is met with PCID, and missed without it** (+3.8 µs). The
  "with PCID" column is commit 333acaa plus Group 8's first PCID commit (146dbb5), built
  in a throw-away tree. The merged branch (mk-lxfwd + final mk-pcid) was built but not yet
  measured: WSL stopped executing commands before those runs.
- Where the time goes, without PCID (rdtsc profile of one round trip, about 2 GHz):
  - each of the two switches about 3,000 cycles: the trap about 1,300, saving the
    caller about 700, `switch_to` about 1,000;
  - the worker's return to user mode and its next system call about 2,100;
  - setting up the call about 1,000 and answering it about 400.
- Most of it is TLB refills after each CR3 write (the kernel has no global pages), which
  is why PCID helps so much. Two cuts made it from 6.4 to 4.5 µs before PCID:
  - index hints instead of searching the task table;
  - the switch vector that moves no FPU state.
- **Two threads are slower per call than one** (3.99 against 3.42 µs). The design's
  concurrency rule (section 6.6) is not met. Before step 1, the in-kernel `keyctl` showed
  the same effect: 1.04 µs per call with two threads against 0.735 with one.
  - The kernel lock serializes the kernel part of every call. Here each forwarded call
    holds it three times: the caller's entry, the worker's reply, and the switches.
  - There is no machine-wide stop (as with today's hand-off): other CPUs run user code
    and take the lock in turn.
  - Meeting the rule needs the forwarding path to run without the kernel lock. That is
    work for a later step: the request table and the direct switch would need their own
    locking, and the scheduler lock is still global.

**Calls that were not moved** (full lxbench, before → step 1 without PCID → with PCID):

| Call | Before | Step 1 | + PCID |
|---|---:|---:|---:|
| `getpid` | 0.152 | 0.153 | 0.154 |
| `pread` 4 KiB cached | 1.18 | 1.14 | 1.23 |
| `stat` | 2.34 | 2.38 | 2.43 |
| `open`+`close` | 4.46 | 4.50 | 4.65 |
| pipe round trip | 26.3 | 26.3 | 26.2 |
| futex round trip | 2.54 | 2.37 | 2.44 |
| `mmap`+`munmap` 1 MiB | 3.05 | 2.79 | 2.78 |
| `fork`+`exec`+`wait` | 2,465 | 2,122 | 2,191 |

These are within run-to-run noise: none got slower. The forwarding table costs one atomic
load per system call.

**Not measured:** the KDE password-to-desktop time with step 1. WSL stopped before those
runs; the desktop itself was used, including Firefox and the crash test, without anything
visibly slow.

### 11.2 What step 2 can build on, and what it still lacks

- **Ready to use:**
  - moving a call means adding its number to `lx::MOVED` and serving it in linux-server;
  - blocking calls answer `LX_REPLY_PENDING` and later `lx_complete`;
  - signals reach pending calls as notifications;
  - process events come through the ring, in order with the calls;
  - the crash policy and the switch back need no change.
- **Still missing:**
  - **A copy-in table.** Every pointer argument costs a client memory call, about one
    system call each; the design's per-call table of paths and small structures in the
    syscall page is not there yet.
  - **The other primitives** of section 5.2: `sig_post`, `task_*`, `as_*`, `obj_*`,
    `timer_arm`, and `lx_grant`.
  - **A growing worker pool.** It is fixed at 4 workers; with more blocking calls than
    workers, calls queue.
  - **Concurrency without the kernel lock** (section 11.1).
  - **A cheaper switch.** Global kernel pages, or a lighter switch entry, would help, and
    the metadata-heavy budget (warm `find` ≤ +35 %) depends on it once the VFS moves.
- **Restarting the desktop after a crash** re-runs the boot's `linux plasma` when SDDM
  had been started. It does not restore a desktop started by hand from the shell.

## 12. Step 2 as built (wave 4, Group 9, branch `mk-lxobj`)

How it is used, in detail, is in [src/linux-server.md](src/linux-server.md) ("Server-object
descriptors"). In short:
- **Server-object descriptors** (section 7.1): a new kind of open file whose object lives in
  linux-server. It is `FileDescriptor::Device` holding `lx::obj::ServerObject` (a server
  *slot* and the server's generation) rather than a new `FileDescriptor` variant: `dup`,
  `fork`, `SCM_RIGHTS`, close-on-exec and exit already share and drop `Device` descriptors
  correctly, and `poll`, `select`, `epoll` and aio already ask them for readiness and wait
  queues. The last reference going posts `LX_NOTE_CLOSE` to the server, exactly once.
  `read`, `write`, `readv`, `writev` and `ioctl` on one are forwarded with their user
  pointers; moved calls that take a descriptor carry its slot (`LxCall::obj`).
- **Readiness words**: 16 bytes per slot in the server's window, read by the kernel's
  `poll`/`select`/`epoll` without a call; a changed bitmap and the doorbell
  (`SYS_SVC_SIGNAL`) wake the waiters; an edge count makes edge-triggered epoll exact; a
  watched bitmap (set by the kernel when a task first waits on an object) lets the server
  skip the doorbell for objects nobody waits on.
- **New primitives**: `SYS_LX_OBJ` (60: install, descriptor lookup, flags, keeping a kernel
  descriptor for the server, `comm`, the temporary `FDPATH`, the bpf device list) and
  `SYS_LX_SIG` (61, `sig_post`).
- **Blocking calls** answer `LX_REPLY_PENDING` and are completed by the call that unblocks
  them, by the server's main thread at their timeout, by `EINTR` on a signal, or dropped at
  their process's exit. The worker pool stays at 4 threads and never blocks; 16 blocked
  receivers do not hold up other calls. (Kept from step 1, fixed here: a signal that arrived
  while a call was being served was never told to the server if it then went pending.)
- **Moved**: POSIX message queues (with `mq_notify` by `sig_post` and by glibc's
  `SIGEV_THREAD` netlink socket, kept for the server by the kernel), System V semaphores and
  message queues (with `SEM_UNDO` applied when the exit notification is taken, in order with
  the calls), and `bpf`. Shared memory stays in the kernel until step 8. The in-kernel copies
  stay for `lx=kernel`.

### 12.1 bpf device programs: decided in the kernel

`bpf::device_check` runs in the kernel's `open` and `mknod` paths (`vfs.rs`), with locks held
and on every device open; asking the server there would put an IPC call into the VFS for every
open of a device node. Instead, **the server hands the kernel the complete list of attached
device programs** (`LX_OBJ_BPF_DEVICE`: each cgroup and its programs' instructions) whenever it
changes (attach, detach, a link's last descriptor closed or `BPF_LINK_DETACH`), and the kernel
checks each program again with its own checker and runs it with its own interpreter
(`bpf::set_server_device_programs`; the interpreter is the in-kernel copy, which stays anyway
for `lx=kernel`). The kernel cannot reach the server's maps, so a device program that uses maps
is refused at attach (`EINVAL`); systemd's `DeviceAllow=` programs use none. When the server
dies, the list is emptied with it. Seccomp filters are classic BPF in `seccomp.rs` (not
`bpf.rs`) and stay in the kernel; no socket filter runs eBPF in Hydra, so nothing else needs
the same treatment. Two kernel facts the server needs are temporary primitives: the path of a
cgroup directory descriptor (`LX_OBJ_FDPATH`, until the VFS moves) and the caller's `comm`.

### 12.2 Measured cost (KVM, 2 CPUs, same VM setup as section 3; µs, medians of 5 loops)

Three runs of `tests/linux/lxbench.c` as root, one after the other on a quiet host:
5027d87 (before), 70c2216 with `lx=kernel` (the in-kernel code, same build) and 70c2216
forwarded. Run-to-run noise is about 10 % (compare the first two columns, both in the kernel).

| Call | 5027d87 | 70c2216, lx=kernel | 70c2216, forwarded | Added per call (vs lx=kernel) | Budget |
|---|---:|---:|---:|---:|---|
| Forwarded null call (`lx_null`) | 3.46 | 0.56 (answered in the kernel) | 3.35 | +2.8 | ≤ +3.0 |
| `mq_send` + `mq_receive`, 16 bytes (a pair) | 2.22 | 2.03 | 8.16 | +3.07 | ≤ +3.0 |
| `semop`, uncontended | 1.41 | 1.20 | 4.13 | +2.93 | ≤ +3.0 |
| `msgsnd` + `msgrcv`, 16 bytes (a pair) | 2.91 | 2.51 | 8.31 | +2.90 | ≤ +3.0 |
| bpf array map lookup | 1.56 | 1.40 | 5.49 | +4.09 | ≤ +3.0 |
| `poll` on a readable message queue | 1.17 | 1.00 | 1.00 | none (no call to the server) | |

- **Where the time goes:** the forwarding itself (+2.8, as step 1 measured) plus one client
  memory call per pointer the server must read or write (the message, the semaphore
  operations; for a bpf lookup the attribute block, the key and the value: three). Before the
  watched bitmap, each message also cost a doorbell (`mq_rtt` 9.55 → 8.16); before the trap
  looked the bpf map descriptor up, a lookup cost one more primitive call.
- **To meet the budget everywhere**, the client memory calls must go: Group 10's copy-in
  table (wave 4, branch `mk-lxfast`) carries small pointer arguments in the syscall page. The
  server already reads and writes through `Cx::copy_in`/`copy_out`, which use the table when
  the kernel filled it, so after the merge only the table's entries are needed (`describe` arms
  for 242, 243, 65/220, 69, 70 and bpf's element commands). Expected: about +2.8 to +3.0 per
  call for all four.
- **A blocked receive costs no worker**; the 16-receiver test runs 200 `keyctl` calls in a few
  milliseconds with 16 threads blocked in `mq_receive`.

**Calls that were not moved** (5027d87 → 70c2216 forwarded, same order of runs):

| Call | Before | After |
|---|---:|---:|
| `getpid` | 0.163 | 0.160 |
| `pread` 4 KiB cached | 1.22 | 1.16 |
| `open`+`close` | 4.55 | 4.57 |
| `stat` | 2.35 | 2.39 |
| `fstat` | 1.15 | 1.10 |
| pipe round trip | 25.7 | 25.4 |
| futex round trip | 2.35 | 2.46 |
| `mmap`+`munmap` 1 MiB | 2.71 | 2.53 |
| `fork`+`exec`+`wait` | 2,027 | 2,033 |
| `poll` on a readable pipe | 1.22 | 0.95 |
| `epoll_wait` on a readable pipe | 1.50 | 1.28 |
| `keyctl` (forwarded since step 1) | 3.63 | 3.41 |

**KDE password-to-desktop** (`tools/lxbench/kde.sh`, screen settled after Enter): 70c2216
39.8, 49.9 and 65.9 s; 5027d87 30.3 and 50.6 s, alternated. The host ran the other group's VMs
at the same time and the spread (30 to 66 s) is far larger than any difference, so these runs
do not measure step 2. What does: a profile of a whole login on 70c2216 (`linux prof`, 148
different system calls made) shows **no moved call at all** during the login except 3
`keyctl` (moved in step 1): the desktop does not use message queues, System V semaphores or
messages, or bpf, so step 2 cannot slow it down (the 5 % budget is met by construction).
Firefox, sound and Wine were checked working, not timed.

None got slower beyond the noise. Non-server descriptors pay nothing new in `poll` and
`epoll` (one more `match` arm for edge-triggered watches on devices); `read` and `write` on
devices check one trait method.

### 12.3 What step 3 (network sockets as net-server's client) can build on, and what it lacks

- **Ready to use:** a socket becomes a server object (`LX_OBJ_INSTALL` from `socket`,
  `accept`); calls taking the socket first (`connect`, `sendto`, `recvfrom`, `setsockopt`,
  ...) carry its slot (`T_FD0`); `read`/`write`/`readv`/`writev`/`ioctl` are forwarded;
  readiness words with the doorbell and exact edge-triggered epoll; blocking `accept`,
  `recv` and `connect` answer pending and complete later, without tying up a worker; the
  crash policy and the switch back need no change.
- **Still missing:**
  - **net-server's readiness reaching the words.** Today net-server rings the kernel's hook
    for its own sockets. As linux-server's client, either net-server's doorbell becomes a
    notification to linux-server, which copies the state into its words and rings the
    kernel (two hops), or net-server writes the readiness words of linux-server's objects
    itself (one hop, but a shared layout). To be decided in step 3.
  - **More slots.** 2048 objects fit in the window today (32 KiB of words); a browser opens
    hundreds of sockets, so step 3 may need a bigger or separate readiness area.
  - **Copy-in table entries** for the socket calls (Group 10's table).
  - **`timer_arm`.** The server's main thread sleeps until the earliest deadline and is woken
    when a worker adds one; a kernel timer primitive would be cleaner for socket timeouts.
  - **Byte transfers between a server object and a kernel file** (`sendfile`, `splice` with a
    server object on either side) and `mmap` of a server object are not supported.
  - **Passing server objects through Unix sockets** works today (the kernel passes the
    descriptor), but needs a primitive once Unix sockets move (step 4).

## 13. A faster forwarding path (wave 4, Group 10, branch `mk-lxfast`)

Three independent parts, each in its own commits (`docs/src/linux-server.md` and
`docs/src/arch/pcid.md` describe them as built):

1. **The copy-in/copy-out table** (section 6.3): per forwarded call, the kernel copies the
   pointer arguments it is known to have into the syscall page at trap time (a bad pointer
   fails with `EFAULT` without the server) and copies the server's output back after the
   answer. `keys` uses it; the server's helpers fall back to the client memory primitives
   for anything not copied.
2. **Forwarding without the kernel lock:** the forwarded call and the worker's answer run
   from the system call entry without the kernel lock; the request table has its own lock,
   the direct switch is one scheduler-lock step, and the scheduler now enforces itself what
   the kernel lock used to guarantee (no task resumed on a stack another CPU is still
   leaving, none picked while another CPU still runs it).
3. **Global kernel pages:** the kernel half's TLB entries survive every CR3 write (CR4.PGE,
   G bit), with a boot self-test and an off switch (`noglobal`, `hydra_run --global-off`).

### 13.1 Measured cost (KVM, 2 CPUs, same VM setup; µs, median of the runs' medians)

Before = 5027d87, after = mk-lxfast 0d72ee7, both with the IPC probe compiled in (it is
called only by its own benchmarks). Runs: before 3, after 3 (PCID on); 2 each (PCID off).
The host also ran other groups' VMs at times; single runs differ by up to 10 %.

| What | before, PCID | after, PCID | after, PCID, no global | before, no PCID | after, no PCID | after, no PCID, no global |
|---|---:|---:|---:|---:|---:|---:|
| `getpid` | 0.15 | 0.16 | 0.16 | 0.16 | 0.16 | 0.16 |
| In-kernel null call (`getpgrp`) | 0.72 | 0.73 | 0.79 | 0.73 | 0.80 | 0.73 |
| **Forwarded null call** (`lx_null`) | 3.21 | 2.73 | 2.75 | 4.53 | 2.96 | 3.92 |
| Two threads on 2 CPUs, per call (`lx_null_par2`) | 3.94 | 2.19 | 2.18 | 5.01 | 2.20 | 2.88 |
| `keyctl` (no pointer) | 3.38 | 2.81 | 2.84 | 4.77 | 3.00 | 4.06 |
| `keyctl_par2` | 4.10 | 2.21 | 2.23 | 5.27 | 2.26 | 2.96 |
| `add_key` (two strings and a 16-byte payload in) | 7.02 | 5.41 | 5.38 | 8.80 | 5.63 | 6.80 |
| `keyctl` DESCRIBE (a buffer out) | 5.67 | 5.04 | 4.93 | 7.26 | 5.38 | 6.50 |
| `pread` 4 KiB cached | 1.24 | 1.22 | 1.27 | 1.27 | 1.24 | 1.22 |
| `stat` | 2.40 | 2.39 | 2.41 | 2.42 | 2.41 | 2.33 |
| `fstat` | 1.07 | 1.09 | 1.12 | 1.08 | 1.10 | 1.08 |
| `open`+`close` | 4.59 | 4.53 | 4.56 | 4.71 | 4.86 | 4.48 |
| pipe round trip | 24.46 | 24.34 | 25.35 | 36.24 | 24.71 | 27.28 |
| Unix socket round trip | 24.96 | 25.00 | 26.44 | 30.10 | 25.34 | 27.90 |
| futex round trip | 2.24 | 2.33 | 2.55 | 2.30 | 2.30 | 2.32 |
| `sched_yield` | 2.81 | 2.99 | 3.02 | 2.91 | 2.98 | 2.97 |
| yield between two threads on 1 CPU | 3.37 | 3.63 | 3.61 | 3.49 | 3.58 | 3.65 |
| `mmap`+`munmap` 1 MiB | 2.59 | 2.65 | 2.61 | 2.60 | 2.65 | 2.61 |
| anonymous page fault | 9.06 | 9.05 | 8.98 | 9.24 | 8.96 | 9.09 |
| `fork`+`wait` | 251 | 246 | 253 | 253 | 251 | 240 |
| `fork`+`exec`+`wait` | 1,977 | 1,954 | 1,945 | 1,979 | 2,379 | 1,949 |
| IPC round trip to a ring-3 server, Handoff (from user) | 5.89 | 5.80 | 5.74 | 7.87 | 6.63 | 7.47 |
| same, Queued | 18.20 | 18.77 | 18.68 | 19.20 | 18.42 | 20.20 |
| same, Handoff, inside one system call | 6.04 | 5.58 | 4.94 | 8.25 | 4.82 | 6.09 |
| same, Queued, inside one system call | 8.57 | 9.03 | 9.01 | 9.38 | 8.88 | 9.88 |
| warm `find /usr` | 442 ms | 438 ms | 438 ms | 548 ms | 452 ms | 536 ms |
| `dd` of a 100+ MiB file (cached) | 183 ms | 182 ms | 179 ms | 196 ms | 190 ms | 207 ms |

- **Per forwarded call:** +2.0 µs over the in-kernel null call with PCID (was +2.5), and
  **+2.2 µs without PCID** (was +3.8): the 3 µs budget is now met both ways. Without PCID
  the gain is the global kernel pages (with them off: +3.2); with PCID they add little,
  since the kernel half's entries already stayed tagged per PCID; there the gain is part 2
  (no kernel lock taken three times per call, one scheduler-lock step per switch).
- **Concurrency rule met:** two threads on 2 CPUs now take 2.19 µs per call against 2.73
  for one thread (before: 3.94 against 3.21). Same for `keyctl` (2.21 against 2.81).
- **Copy-in table:** `add_key` (two strings and a payload) 7.0 → 5.4 µs, `keyctl`
  DESCRIBE (a buffer out) 5.7 → 5.0 µs: each pointer no longer costs a client memory call.
- **Calls that were not moved:** within noise, except the scheduler's own paths:
  `sched_yield` +6 % and a yield between two threads +8 %, futex round trip +4 % (the
  scheduler's new checks, and the per-CPU frame copy of kernel-mode trap returns). Within
  the +10 % budget of section 6.6 for calls that stay in the kernel; not zero. Without
  PCID the pipe and Unix socket round trips got 30 % and 16 % faster (global pages).
- **IPC to a ring-3 server** (the probe, endpoint 0x22): Handoff unchanged (5.9 → 5.8),
  Queued +3 % (18.2 → 18.8); inside one system call Queued +5 % (8.6 → 9.0).
- **KDE password to desktop** (`kde.sh`, 3 boots each, alternating, a suite VM running
  beside some of them): the desktop is drawn at 21.7 s before and 22.4 s after (+3 %),
  and fully settled at 25.3 and 25.9 s (+3 %). Within the 5 % budget (the spread between
  runs is about 3 %). (Wave 3 never measured this; under heavier host load the same
  kernel gave 31.7, 31.7 and 36.1 s, so only side-by-side runs compare.)
- **Not measured here:** apt-get, tar and the Firefox start (`work.sh`).

### 13.2 What it means for the budget and for step 6a

| What | Budget (6.6) | Before | After |
|---|---|---:|---:|
| Added per forwarded call, PCID | ≤ +3.0 µs | +2.5 | **+2.0** |
| Added per forwarded call, no PCID | ≤ +3.0 µs | +3.8 (missed) | **+2.2** |
| Calls that stay in the kernel | ≤ +10 % | | ≤ +8 % (`sched_yield`, yields), most unchanged |
| Concurrency: 2 threads on 2 CPUs not slower per call than 1 | met | missed (3.94 > 3.21) | **met (2.19 < 2.73)** |
| KDE password to desktop | ≤ +5 % | 21.7 s (median of 3: 22.4, 21.7, 21.7) | **22.4 s (+3 %)** (23.1, 22.4, 22.4) |

**For step 6a (the VFS):** a forwarded file call should now cost about **+2.0 µs** with
PCID, or +2.2 without it, plus what the server itself spends; path arguments and small
structures come with the call (no `SYS_LX_READ_STR` per path). A warm `find /usr` with
about 77,000 forwarded calls (section 6.5) would then add about 0.15 s: +25 % on the
section 6.5 baseline (0.62 s), +35 % on today's faster one (0.44 s here). That is at the
edge of the 35 % budget: step 6a should still cut forwards (a server-side name cache,
fewer `open_ref`/`release` round trips) or keep the descriptor-table fast paths (decision
2). The two-CPU case is no longer serialized, so concurrent tools scale.

### 13.3 Step 2's calls after the wave 4 merge

At the merge (af5c30e) Group 9's calls (`mq_*`, `semop`, `msg*`, `bpf`) were 3 to 10 times
slower forwarded than on Group 9's own branch. The cause, from the `[prof] lx:` counters:
their table entries carry extras (the descriptor's server object, the IPC namespace, the
umask), so the lock-free entry declined them; on the path under the kernel lock the caller
blocked as needing the lock, and the worker, answering without it, could never switch
straight back: every one of their answers (2,040,054 of 2,040,054 in the benchmark) woke
the caller through the scheduler, while every `lx_null`/`keyctl` answer switched back.

The fix (3f3fcdd): the lock-free entry gathers the extras itself (the IPC namespace with
the per-CPU identity; the descriptor table with `try_lock`, falling back to the ordinary
path when busy; the object held across the call as before), and the path under the kernel
lock waits lock-free and takes the lock again afterwards. Afterwards every answer of these
calls switched straight back.

| Call (µs, KVM, 2 CPUs) | In the kernel (`lx=kernel`) | Forwarded at the merge | Forwarded after the fix | Group 9's branch |
|---|---:|---:|---:|---:|
| `mq_timedsend`+`mq_timedreceive` round trip (2 calls) | 2.27 | 25.9 | **7.2** | 8.16 |
| `semop` | 1.40 | 12.9 | **3.5** | 4.13 |
| `msgsnd`+`msgrcv` round trip (2 calls) | 2.74 | 27.7 | **7.2** | 8.31 |
| `bpf` map lookup (as root) | 1.52 | 14.2 | **4.8** | 5.49 |
| `lx_null` / `keyctl` (unchanged) | 0.69 / 0.86 | 2.87 / 2.98 | 2.88 / 2.95 | |

So about +2.0 to +2.5 µs per forwarded call, as for the null call; `bpf` +3.3 (it also
reads the attribute block's descriptor from user memory in the trap).

## Appendix: reproducing the measurements

- **Benchmark program:** `tests/linux/lxbench.c`. Build it with `gcc -O1 -w -pthread tests/linux/lxbench.c -o esp/bin/lxbench.elf` in WSL, then `make build`.
  - In the VM: `cp /bin/lxbench.elf /ubuntu/tmp/lxbench.elf`, then `linux chroot /ubuntu /usr/bin/bash -c 'cat /tmp/lxbench.elf > /tmp/lxb; chmod 755 /tmp/lxb; /tmp/lxb'`.
  - Arguments name single tests. `PROBE_EP=0x22` picks the probe's server.
- **Probe kernel:** `cargo build --release --target x86_64-unknown-uefi --features g6-probe`. A normal build does not contain the probe.
  - The probe was left out when this branch was merged into host-unit-tests. To measure again, restore it from commit `90fe5ca` (`git show 90fe5ca -- Cargo.toml src/compat/linux`). Without it, `lxbench` skips its probe tests.
- **VM scripts:** in `tools/lxbench/`. `vm.sh` runs one VM on an overlay with an ISO kept on WSL's disk. `kde.sh` runs the KDE timing, `work.sh` the workload profiles. `frames.py`, `profparse.py`, `agg.py` and `estimate.py` turn the logs into the tables of this report.
