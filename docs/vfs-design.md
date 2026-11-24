# The file system as a service of its own: VFS, mounts, pseudo files and the descriptor table (step 0 for wave 7)

Microkernel wave 5, Group 16, 2026-11-18. Base: `host-unit-tests` 329aaf7; revised on d0d38ab for the user's **decision 9** ([microkernel-plan.md](microkernel-plan.md), "Decisions"): *"I don't want to merge the file system with linux. They should be separate things in order to be resilient. In fact later on we'll also split linux into different services."* No code moves in this step. This document designs step 6a of [linux-server-design.md](linux-server-design.md) for that decision.

**Who this is for:** the user (technical, not a kernel specialist) and the agents of wave 7. Group 18 (wave 5, `docs/linux-services-design.md`) designs the routing to several servers and the calls between services; this document states what the file service needs from it (section 6) and uses its interface once it is written.

**What changed from the first version.** The first version recommended putting the VFS inside linux-server ("B-lean"). The user rejected that. This version keeps the measurements (sections 1–3) and the descriptor-table conclusion, and redesigns the rest for a separate file service. Appendix B keeps the first version's option table for reference.

## 0. The answer in brief

- **The shape (recommended):** a new ring-3 **vfs-server**, a service of its own beside zfs-server, linux-server and net-server.
  - **vfs-server owns:**
    - path lookup and the name, attribute and link caches;
    - the mount tables and mount namespaces;
    - permission policy (owner, mode, ACLs, and later Landlock and ABAC);
    - `open`, every change (create, remove, rename, write, chmod, ...), directory listings, file locks;
    - `tmpfs`.
  - **zfs-server** stays the ZFS back end. vfs-server is its client for metadata.
  - **`/proc`, `/sys` and `/dev` are not the file service's.** They are Linux views of process and device state, so they are mounted from the Linux services that own that state (linux-server today, later its process and device services). vfs-server only redirects lookups under those mounts.
- **The kernel keeps the descriptor table as a table of handles,** and answers by handle, without any server:
  - on files: `read`, `pread`, `readv`, `lseek`, `mmap`, `fstat`;
  - on every descriptor: `close`, `dup`, `fcntl` (descriptor flags, `F_GETFL`), close-on-exec, `poll`/`select`/`epoll`.

  The process's **current directory, root and umask** are also kept in the kernel (cwd and root as handles).
- **Routing:** the kernel sends file calls straight to vfs-server, not through linux-server: one hop, as before. Calls on a descriptor go to whoever owns it. A lookup under `/proc` costs one extra hop: vfs-server answers "redirect to linux-server", and the kernel forwards the call again in the same trap.
- **Resilience, the point of the decision:**
  - **If vfs-server crashes, Linux programs keep running.** Their open files, current directories and `mmap`s are kernel handles and page-cache mappings, so they survive. Reads of open files and `mmap`s keep working while the service is down. Calls that need the service wait for its restart, about a second.
  - **What must be kept across the restart** (the mount tables, the file locks) lives in a kept-state object the kernel holds for the service. The caches are filled again from zfs-server.
  - The only thing a program can see is a failed change: one that was in flight at the crash and cannot be known to have finished gets `EIO`.
  - **If linux-server crashes,** every Linux program ends, as decided before (decision 6), but **vfs-server, its caches and the file system stay up**, and native programs keep their files.
  - **If zfs-server crashes,** vfs-server retries on the restarted zfs-server, as the kernel does today.
- **Cost:** the same number of forwarded calls as the first version's B-lean. The measured call counts and per-call costs give:
  - warm `find` +10 % (+24 % on wave 4's faster baseline);
  - `git status` +11 %, `tar` +4 %, a gcc build +4 %, a KDE login +2.6 %;
  - Firefox and `apt-get` under 0.5 %.

  The redirect for pseudo files adds under 0.1 % even in the KDE login. All within the budget (35 % for metadata tools, 5 % for the desktop).
- **The hop to zfs-server decides the rest.**
  - **With today's Queued calls between servers,** it adds another 6–17 % to the metadata tools: a warm `find` comes to +23 % (+55 % on the fast baseline, over budget).
  - **With a direct server-to-server call** (about 2.5 µs, against today's 5.8 µs kernel-to-zfs-server Handoff), each file-server request gets cheaper than today, which pays for the forwarding. Net, against today: `find` −3 %, `git status` −7 %, `ls -lR` −10 %, KDE +1.3 %. That is before vfs-server's larger caches cut the number of requests.
  - That call is **essential**, and it is Group 18's design.
  - A cheaper copy of system-call arguments is the second prerequisite.
- **Wave 7:** six groups in parallel and one closing group, about 25–29 agent-days, after the prerequisites (section 12). Section 11 has the decisions, in plain words.

## 1. What step 6a is about

### 1.1 The code

Lines from `wc -l` at 329aaf7 (comments included).

| Part | Files (lines) | Lines | What it does |
|---|---|---:|---|
| Path and file calls | `vfs` 3,823, `recent` 379 (openat2, ...), `xfer` 381 (sendfile, splice, copy_file_range), `misc` 230, `extra` 1,119 | 5,932 | Every path call, `read`/`write` on files, `getdents64`, `fcntl`, `chdir`/`chroot`, xattrs, permission checks (with the `acl`, `landlock` and `abac` hooks) |
| Mounts and pseudo files | `mount` 1,892, `fs` 872 (`/proc` and `/dev` texts), `devices` 1,926 (`/dev`, `/sys`, the udev database), `efivars` 295, `live` 18 | 5,003 | Mount namespaces, the new mount API, `/proc/<pid>/...`, `/proc/mounts`, `/sys` and `/dev` |
| Readiness and descriptor objects | `epoll` 382, `select` 215, `locks` 349, `memfd` 282 | 1,228 | `poll`/`select`/`epoll` over every descriptor kind, record and `flock` locks, `memfd_create` |
| The descriptor table | `src/fs/fd.rs` 1,260 | 1,260 | `FdTable`, `FileDescriptor` (one variant per object kind), `dup`, close-on-exec, the readiness glue |
| The ZFS client's VFS half | about 1,500 of `src/fs/zfs/mod.rs` (1,311) and `src/fs/client.rs` (1,347) | about 1,500 | The path walker and the name, attribute and link caches. The other half (data reads and writes for the page cache) stays in every option |
| **Total** | | **about 14,900** | The design's "about 17,000" also counted the VFS arms of the dispatcher (`mod.rs`) and the `/proc` parts of `proc.rs` |

### 1.2 What calls into it from elsewhere

These are the couplings step 6a must cut:

| Caller | What it needs from the VFS | In step 6a |
|---|---|---|
| `execve` (`execve.rs`, `process.rs`, `task/exec.rs`) | Resolve the program and its interpreter by path, check exec permission, `#!` scripts, `/proc/self/exe` | Process policy moves only in step 7. Recommended: forward `execve` to linux-server in 6a; it asks vfs-server to open the program and the interpreter, then calls a `task_exec` primitive (section 12, group 7-5) |
| File `mmap` (`mm.rs`) | Descriptor to page-cache object | Unchanged: the descriptor table and the page cache stay in the kernel (section 7) |
| Unix sockets (Group 13, wave 5) | Socket files: `bind` creates one, `connect` looks it up (`vfs_resolve`, temporary) | linux-server asks vfs-server (one server-to-server call); the primitive goes |
| `bpf::device_check` (step 2) | Runs in the kernel's `open` and `mknod` | Moves with `open` into vfs-server. linux-server (which holds the programs) hands vfs-server the list, as it hands it to the kernel today |
| `inotify`/`fanotify`/`fuse` hooks in the ZFS client | Events and FUSE lookups from the path walk | They move to vfs-server in step 6b. Until then vfs-server reports each event to the kernel's copies (a temporary primitive) |
| `/proc` | The process table, memory maps, CPU and memory statistics, signal state | `/proc` becomes a file system served by linux-server (section 4.1). It needs **info primitives** for what only the kernel knows: `task_info(pid)`, `mm_maps(pid)`, `sys_stats()` |
| Native programs (`arch/syscall.rs`: hydra-shell, the drivers) | The same `FdTable` type for their console, files and pipes | Unaffected: native processes keep a kernel table whatever happens on the Linux side |
| Admin ops (`admin/linux.rs`) | Prepare files in the Linux root; run programs in a chroot | Native file access through the ZFS client (stays); the run op is a process op (step 7) |

## 2. How this was measured

- **Machine:** QEMU/KVM, 2 virtual CPUs, 4 GiB, on the development PC under WSL2 (`tools/hydra_run.py --accel kvm --smp 2 --shared-host`). Each run booted an overlay of the pool. Five other groups shared the PC, so single numbers vary by 10–40 % between runs (section 3.2 shows two runs side by side).
- **Kernel:** 329aaf7 plus a **local prototype** (never committed; the exact diff is `tools/vfsbench/prototype.patch`):
  1. **Throwaway counters** while `linux prof` is on (`prof.rs`, `fs/zfs/mod.rs`, one hook in `dispatch_linux_syscall`):
     - every descriptor call counted by the kind of descriptor (regular file, directory, pseudo file, pipe, Unix or Internet socket, server object, device, terminal, event descriptor, memfd);
     - every path call counted by where its path starts (`/proc`, `/sys`, `/dev`, `/run`, `/tmp`, other absolute, relative);
     - hits and misses of the ZFS client's name, attribute and link caches.

     `linux prof show` prints them as `[g16]` lines.
  2. **Stub operations** of Hydra's test call (0x6710, operations 0x1605–0x1607) answered by linux-server, with entries in the copy-in/copy-out table:
     - a `stat` (the path in as a string, 144 bytes of `struct stat` out, a lookup in a server-side map);
     - a `getdents64` (600 bytes written into a 1 KiB or 32 KiB buffer);
     - a `read` (256 bytes or 4 KiB written).

     They have exactly the shape of a forwarded VFS call, but the server does no real file-system work.
- **Programs and scripts** (committed):
  - `tests/linux/vfsbench.c`: VFS micro-benchmarks and the stub tests, 5 loops each, medians;
  - `tools/vfsbench/work.sh`: the workloads, each run three times in the Ubuntu root: once to warm the caches, once timed without profiling, once under `linux prof` for the counts;
  - `tools/vfsbench/kde.sh`: a KDE login under `linux prof`;
  - `tools/vfsbench/vfsparse.py` and `vfscost.py`: the logs to the tables below.
- **The counts are exact and repeat:** the same workload gave the same counts within 0.1 % in two boots. The timings are the noisy part.

## 3. Measurements

### 3.1 VFS calls today (µs, medians of 5 loops; three boots)

| Call | What it does | Boot 1 | Boot 2 (busier host) | Boot 3 |
|---|---|---:|---:|---:|
| `getpgrp` | The in-kernel null call | 0.73 | 0.82 | 0.83 |
| `lx_null` | The forwarded null call | 2.77 | 3.24 | 3.22 |
| `stat("/usr/bin/bash")` | 3 path components, name cache hit | 2.20 | 2.83 | 2.87 |
| `fstatat(dirfd, "bash")` | Relative to a directory descriptor | 2.20 | 2.66 | 2.36 |
| `stat` of a missing file | | 4.90 | 6.22 | 5.74 |
| `statx` | | 2.66 | 2.80 | 2.60 |
| `access(X_OK)` | | 2.32 | 2.36 | 2.61 |
| `readlink` | A link in `/tmp` | 2.63 | 4.48 | 2.91 |
| `openat` + `close` of a file | | 4.73 | 5.58 | 5.20 |
| **`open` + `close` of a directory** | What `find` does per directory | **23.0** | **24.3** | **24.1** |
| `open` + `read` + `close` of `/proc/self/stat` | A pseudo file | 13.8 | 24.8 | 15.5 |
| `fstat` | | 1.16 | 2.21 | 1.22 |
| `fcntl(F_GETFD)` | | 0.83 | 1.07 | 0.90 |
| `dup` + `close` | | 1.89 | 1.96 | 2.01 |
| `lseek` | | 0.91 | 1.17 | 1.06 |
| `pread` 256 bytes / 4 KiB, cached | | 1.20 / 1.33 | 1.94 / 2.38 | 1.40 / 1.45 |
| **`getdents64` of a 20-entry directory** | One call | **30.9** | **28.7** | **22.5** |

What stands out:
- **Calls that need zfs-server are 10–30 times dearer than the rest.** Opening a directory costs 23 µs and listing it 29–31 µs, because each asks zfs-server (`open_ref`, `readdir`, `release`: about 9–20 µs each with the server's own work; directory listings are not cached in the kernel).
- **Calls answered from the kernel's caches cost 1–3 µs.** These are the ones forwarding would make relatively much slower.

### 3.2 The prototype: VFS-shaped calls answered by linux-server

| Stub call (forwarded, PCID on) | Boot 1 | Boot 2 | Boot 3 | Added over `getpgrp`: boot 1 / 3 | The design's estimate (section 13.2) |
|---|---:|---:|---:|---:|---|
| Null call (`lx_null`) | 2.77 | 3.24 | 3.22 | **+2.0 / +2.4** | +2.0 |
| `stat`: a path in (14 bytes), 144 bytes out, a lookup in the server's map | 5.17 | 5.19 | 4.16 | **+4.4 / +3.3** | +2.0 "plus what the server spends" |
| `getdents64` into a 1 KiB buffer (600 bytes out, through the page) | 5.90 | 5.22 | 4.05 | +5.2 / +3.2 | |
| `getdents64` into a 32 KiB buffer (600 bytes, through `SYS_LX_WRITE`) | 5.42 | 5.43 | 4.12 | **+4.7 / +3.3** | |
| `read` of 256 bytes (out through the page) | 3.73 | 6.63 | 3.96 | +3.0 / +3.1 | |
| `read` of 4 KiB (through `SYS_LX_WRITE`, as `obj_read` would copy) | 4.59 | 7.54 | 4.82 | **+3.9 / +4.0** (+3.3 / +3.4 net of today's own 4 KiB copy) | +2.0 + 0.5 for the primitive |

What this shows:
- **The forward itself costs +2.0 to +2.4 µs** (wave 4: +2.0 on a quieter host).
- **Every pointer costs more than expected: about 1–2 µs.** The `stat` stub is 2.4 µs dearer than the null call in boot 1 and 0.9 µs in boot 3, though the server's lookup takes about 0.2 µs (the three boots ran beside other groups' VMs; boot 3 had the tightest spread). The same shows in wave 4's numbers: `keyctl` DESCRIBE (one buffer out) is 2.2 µs dearer than plain `keyctl`.
  - The kernel side of the copy table takes the address-space lock and walks the page tables for every argument (`lx/copy.rs`, `each_piece`).
  - It also copies twice: user to a kernel buffer to the syscall page, and back the same way.
  - Almost every VFS call has a pointer (a path, a `struct stat`, a buffer), so this matters more for step 6a than for the earlier steps.
- **A buffer larger than the 3 KiB copy area costs a `SYS_LX_WRITE` instead,** about the same as through the page (`getdents64` 32 KiB: 4.7; 1 KiB: 5.2, within the noise).
- **So a forwarded VFS call adds about +2.0 µs without pointers, +4.2 µs for a path call, +4.7 µs for `getdents64` and +3.3 µs for a 4 KiB read** (boot 1, the dearer case for the pointer calls; boot 3 gives 3.3, 3.3 and 3.4). These are the numbers section 9 uses, so its estimates lean pessimistic; with `fwd=2.4` (boot 3) A's `find` gains another 24 ms. With a cheaper copy (section 8.2) the pointer part could drop from about 2 µs to well under 1 µs.
- **Against the per-call budget** (design 6.6: today + 3 µs per forward), `stat` would be 2.2 + 4.2 = 6.4 µs against a limit of 5.2: **missed by about 1 µs.** It is met only with the cheaper copy.

### 3.3 Real workloads: calls by kind

"Calls" are the calls on the kernel's normal path (`linux prof`; the lock-free `getpid`/futex-wake calls are not counted). Times are the unprofiled run (the second run of each workload). The counts of `find`, `ls -lR`, `git` and `tar` are from boot 2 (`vw2`), the others from boot 1 (`vw1`); the two boots agreed within 0.1 % where both ran.

| Workload | Time | Calls | Calls/s | Path calls (ZFS / pseudo) | of them `open` | Descriptor calls on files and directories (`fstat`, `close`, `fcntl`, ...) | `getdents64` | File reads / writes | `poll`/`epoll` | zfs-server requests (time) |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| `find /usr` (warm) | 1.07 s (0.81–1.35 in three boots) | 84,874 | 79,174 | 11,687 / 4 | 5,886 | 60,327 | 11,612 | 10 / 0 | 0 | 41,898 (0.64 s) |
| `ls -lR /usr/share` (warm) | 7.92 s | 262,269 | 33,111 | 105,497 / 5 | 9,634 | 19,240 | 9,644 | 19 / 0 | 1 | 396,719 (3.9 s) |
| `git status` (3,851 files, warm) | 0.58 s | 19,269 | 33,511 | 9,808 / 3 | 2,517 | 4,614 | 4,529 | 37 / 0 | 0 | 30,708 (0.38 s) |
| `tar cf - /usr/share/doc \| cat` | 1.41 s | 41,217 | 29,336 | 8,977 / 7 | 4,105 | 18,693 | 4,343 | 4,140 / 0 | 1 | 27,400 (0.35 s) |
| `apt-get install hello` (from the cache) | 11.8 s | 24,681 | 2,093 | 6,204 / 107 | 3,550 | 6,500 | 78 | 2,122 / 4,134 | 57 | 20,494 (2.7 s) |
| Firefox headless start (warm) | 5.05 s | 19,049 | 3,771 | 3,242 / 250 | 1,322 | 1,628 | 54 | 975 / 196 | 1,676 | 8,524 (0.87 s) |
| `make` of 30 C files (gcc, 4,372 lines; without `-j`, see below) | 8.30 s | 107,464 | 12,951 | 81,868 / 2 | 14,152 | 11,108 | 60 | 5,431 / 433 | 0 | 88,318 (1.0 s) |
| KDE: password to desktop (profile from the console before the login to after the desktop settled, about 80 s; the login itself settles in about 25 s, wave 4) | about 25 s | 341,804 | about 13,700 (over 25 s) | 148,179 / 3,420 | 16,673 | 28,435 | 2,064 | 13,823 / 331 | 17,569 | 99,466 |

What the calls are, workload by workload (`tools/vfsbench/vfsparse.py` prints the full lists):
- **`find`:** `fcntl` 27,200 (all on directories: `F_DUPFD_CLOEXEC`/`F_GETFD`), `close` 21,488, `fstat` 11,647, `getdents64` 11,612, `openat` 5,889 (relative to a directory descriptor), `newfstatat` 5,794, and 1,043 `write`s to `/dev/null`.
- **`ls -lR`:** `lgetxattr` 127,016 (looking for ACLs and security labels), `statx` 63,515, `readlink` 27,546, then the directory calls as in `find`.
- **`git status`:** `newfstatat` 7,227 (one `lstat` per tracked file), `getdents64` 4,517, `openat` 2,511.
- **`tar`:** `fstat` 10,282, `newfstatat` 4,451, `fcntl` 4,351, `read` 4,140 (file data), `getdents64`, `openat`, `close`; `write` and `splice` on the pipe.
- **`apt-get install`:** `write` 4,307 (file data: dpkg), `openat` 3,630, `close` 3,424, `newfstatat` 2,395, `read` 2,248, `fstat` 1,991, `mmap` 1,433, `ioctl` 1,302 (on files: dpkg's `FIFREEZE`-style checks and terminal queries), `rename` 24, `fsync` 28.
- **Firefox:** `mmap` 2,068, `read` 1,705 (half on pipes), `poll` 1,488, `openat` 1,451, `mprotect` 1,354, `close` 1,263, `access` 637; 250 path calls under `/proc`, `/sys` and `/dev`; `rename` 185 (its profile files).
- **gcc:** `readlink` 64,400 (the compiler driver and `cc1` resolve paths link by link; the kernel's link cache missed 56,043 times), `openat` 14,154 (headers searched along the include path), `close` 5,541, `fstat` 5,513, `read` 5,247.
- **KDE:** `statx` 62,153, `access` 43,532, `mmap` 26,176 (21,267 of files), `mprotect` 25,188, `read` 20,390 (13,486 of files, 5,214 of eventfds), `openat` 19,152, `readlink` 17,238, `close` 16,493, `newfstatat` 13,955, `write` 12,252 (11,553 to eventfds), `fstat` 10,460, `recvmsg` 9,664, `ppoll` 8,789. 3,420 path calls under `/proc`, `/sys`, `/dev` and `/run`. The name cache hit 88 % here (the desktop looks up the same few thousand paths again and again), yet zfs-server still got 99,466 requests, 43,533 of them `resolve_mnt`.

**A bug found on the way: `make -j` busy-loops.** The first compile run used `make -j2`. GNU make 4.x hands its jobserver to the compilers as a FIFO in `/tmp`, and opening a FIFO on Hydra gives a regular-file descriptor (`vfs.rs` has no FIFO open path). make then spins: `read` returns 0, `epoll_wait` reports the file ready, `wait4(WNOHANG)` finds nothing. That run made **954,000 rounds of `read`/`epoll_wait`/`wait4` in 8 s** for 30 small files (2.97 million calls). The compile row above is `make` without `-j`. The bug is reported to Group 13 (FIFOs are in their step) in NOTES.md.

**The name cache.** The kernel's name cache hit 55 % of its lookups in `find`, 39 % in `git status` and only **13 % in `ls -lR`** (attribute cache: 84 %, 73 %, 71 %). It holds 8,192 results and empties itself when full, so a walk over more than a few thousand names keeps emptying it. Every miss is a zfs-server request: `ls -lR` makes 204,518 `resolve` requests for 105,497 path calls.

**What this means for the options:**
1. **Only the metadata tools are at risk.** They make 17,000–79,000 calls a second, most of which take 1–3 µs in the kernel today. Firefox and package workloads make 2,000–4,000 a second; a KDE login about 14,000, but 38 % of those are `stat`-kind path calls that hit the name cache.
2. **In the tools, descriptor calls outnumber path calls.** `find` makes 5 descriptor calls (`fcntl`, `close`, `fstat`, `getdents64`) for every path call. A kernel descriptor table saves more than a kernel name cache.
3. **zfs-server requests are where today's time goes** (`find`: 0.64 s of 1.07 s; `ls -lR`: 3.9 of 7.9 s). A bigger cache in linux-server would win back more than forwarding loses, but only if linux-server reaches zfs-server as cheaply as the kernel does (section 8.2).

## 4. Where the file service lives: the shapes considered

The measurements of section 3 say where the calls are. This section decides who owns what. All shapes keep in the kernel what the Linux design already keeps there (page cache, page faults, address spaces, ELF loader, the data half of the ZFS client), and all keep the descriptor table in the kernel as a table of handles (section 7).

| | **F1. A new vfs-server (recommended)** | F2. The VFS inside zfs-server | F3. The VFS inside linux-server (first version's B-lean) |
|---|---|---|---|
| What it is | One new service: names, mounts, permissions, `open`, changes, locks, `tmpfs`. zfs-server stays the ZFS back end | zfs-server grows the VFS on top of its ZFS code: one file service | Rejected by decision 9 |
| A path call | Kernel → vfs-server; on a cache miss vfs-server → zfs-server | Kernel → zfs-server; no second hop | Kernel → linux-server → zfs-server |
| Cost of a cache miss | One server-to-server call (needs Group 18's direct call) | None (inside one process) | As F1 |
| Fault isolation | A VFS bug (permissions, mount parsing, path walk) does not touch the ZFS code and the pool; a ZFS bug does not lose the mount tables and locks | One fault domain: a bug in either half takes both down, and a zfs-server restart is heavy (pool import state, ARC) | A Linux-layer fault ends the file system too: what decision 9 rejects |
| Other file systems | `tmpfs`, FUSE (step 6b) and future ones (FAT for the ESP, ext4 for a FreeBSD or Linux root, a network file system) plug in as back ends of the same VFS | They would live in the ZFS process, or need a second VFS | |
| Native programs and other personalities | Use the same vfs-server (FreeBSD and macOS front ends: waves 11–12) | Same | Would have to call into the Linux server |
| Size | New: about 13,000 lines moved from the kernel (section 1.1) into a new program | Same lines, added to zfs-server's | |

- **F1 is recommended.** It is what decision 9 asks for: the generic file service is separate from both the Linux layer and the ZFS implementation.
- **F2's only gain is the second hop.** The direct server-to-server call removes most of that, and wave 7 needs the call anyway (linux-server already calls net-server, and will call vfs-server for `execve` and socket files).
- **F2 is the fallback** if the direct call turns out too slow: section 9 shows what the hop costs either way.

### 4.1 What is generic and what is Linux's

| Piece | Where (F1) | Why |
|---|---|---|
| Path walk, `..`, symbolic links, `chroot`, mount crossing, `O_NOFOLLOW`/`RESOLVE_*` rules | vfs-server | Every personality walks paths the same way |
| Name, attribute and link caches | vfs-server | They cache the back end |
| Mount tables, mount namespaces, the mount API (`fsopen`, `open_tree`, ...) | vfs-server | Namespaces are file-system state. The Linux system-call *syntax* is decoded in vfs-server too: there is one VFS front end per personality call set, small, inside the service |
| Permission policy: mode bits, ACLs; later Landlock and ABAC checks on paths | vfs-server | They decide file access. The caller's credentials come with each call (section 6) |
| `open`, create, remove, rename, link, `chmod`/`chown`/`utimens`, `truncate`, xattrs, `getdents64`, `statfs`, `fsync` | vfs-server | |
| Writes to regular files | vfs-server (through the page cache and zfs-server) | They change the size, times and set-ID bits, and make `inotify` events |
| Record locks and `flock` (`locks.rs`) | vfs-server, with the lock table in its kept state (section 8) | Lock state must survive a vfs-server restart |
| `tmpfs` (`/tmp`, `/run`, `/dev/shm`) | vfs-server | A memory file system: its file data stays in the kernel's page cache (anonymous objects), so it survives a restart too |
| FIFOs (`mkfifo`) | The node in vfs-server; opening it returns a pipe object of the local-IPC service (linux-server, Group 13) | The pipe is IPC, the name is a file. Opening a FIFO is broken today (section 3.3: `make -j` spins) |
| Unix socket files | The node in vfs-server; `bind`/`connect` by path: linux-server asks vfs-server (one server-to-server call) | Replaces Group 13's temporary `vfs_resolve` |
| `/proc` (process and kernel state) | **linux-server** (later its process service) as a pseudo file system mounted at `/proc` | Its text comes from the process table, signals, memory maps: Linux state |
| `/sys`, `/dev`, the udev database (`devices.rs`), `efivars` | **linux-server** (later the device service of wave 6: Group 15) | Views of devices; `/dev` nodes open device objects of their owners (DRM, input, sound, ttys) |
| `inotify`, `fanotify` (step 6b) | vfs-server | Events come from the changes it makes |
| FUSE (step 6b) | vfs-server, as a back end whose server is a user program | |

## 5. How a call flows

```text
 Linux program                kernel                                   services
  stat("/usr/bin/bash") ──> trap: route by number ──── forward ────> vfs-server: walk (cache), attributes
                                                                      on a miss ──── direct call ──> zfs-server
  open("/proc/self/stat") ─> trap ─────────────────── forward ────> vfs-server: "/proc is linux-server's"
                              <────────────────────── redirect(linux-server, "self/stat") ┘
                              same trap ────────────── forward ────> linux-server: a pseudo-file object
  read(fd 5) on a file ────> trap: fd 5 is a file handle: page cache, no server
  read(fd 6) on /proc ─────> trap: fd 6 is linux-server's object ── forward ──> linux-server
  getdents64(fd 7, dir) ───> trap: fd 7 is vfs-server's ─────────── forward ──> vfs-server
```

- **One hop for every file call,** as in the first version: the kernel never sends a file call through linux-server.
- **Two hops only for a lookup under a mount served by another service** (`/proc`, `/sys`, `/dev`, FUSE). Section 3.3 counts them: 4 in `find`, 250 in a Firefox start, 3,420 in a KDE login.
- Once open, a pseudo file is an ordinary server object of linux-server: its reads go there directly (the step-2 mechanism).

## 6. Routing, and what the file service needs from Group 18

Written to NOTES.md (2026-11-18) for Group 18, who designs the kernel's routing to several servers and the calls between services:

1. **Route by number:** the path calls go to vfs-server's endpoint:
   - `open`/`openat`/`openat2`/`creat`;
   - the `stat` family, `access`, `readlink`;
   - `mkdir`, `mknod`, `unlink`, `rmdir`, `rename*`, `link`, `symlink`;
   - `chmod`/`chown`/`utimensat`, `truncate`;
   - xattrs by path, `statfs`, `chdir`, `chroot`, `mount` and the mount API.
2. **Route by descriptor owner:** a call on a descriptor goes to the descriptor's owner. This is Group 12's `T_BYFD`, generalized from "server object or kernel" to "the owning endpoint":
   - vfs-server owns directory descriptors and the change calls on file handles (`write`, `ftruncate`, `fchmod`, `fsync`, `getdents64`, `flock`, `fcntl` locks);
   - the kernel answers the file-handle calls of section 7.
3. **A redirect answer:** vfs-server may answer "served by endpoint E: the mount's object and the rest of the path", and the kernel forwards the same call to E within the same trap. The redirect counts toward a small loop limit.
4. **What each forwarded call carries,** so that vfs-server keeps no per-process state:
   - the credentials and groups (as `LxCall` today), the umask;
   - the caller's **root and current directory as objects** (from the kernel task), and the object of an `*at` call's directory descriptor (`T_FD0`).
5. **Calls between services:**
   - vfs-server → zfs-server on every cache miss (warm `find`: 41,898 requests, `ls -lR`: 396,719, a KDE login: 99,466);
   - linux-server → vfs-server (`execve`'s lookup, socket files, FIFOs);
   - vfs-server → linux-server (none on the hot path).

   They need Group 18's direct server-to-server call: today a ring-3 server's call is Queued (9–18 µs).
6. **Kept state for restarts:** a memory object the kernel keeps for a service across its restarts (section 8). If Group 18 designs restart support for all services, vfs-server uses that.

The forward to vfs-server is the same mechanism as the forward to linux-server (the direct switch, the lock-free entry, the copy-in/copy-out table). Its cost is what section 3.2 measured.

## 7. The descriptor table: a kernel table of handles

Decision 9 strengthens the case for keeping the table in the kernel. If it moved, it would have to move into *some* service. Every service would then depend on that one for every descriptor call, and its crash would end every program.

**Handles.**
- Each descriptor names an owner (an endpoint, or the kernel), an object (a slot), the owner's generation, and the open flags.
- Two kinds carry kernel data:
  - a **file handle**, which vfs-server installs at `open` of a regular file: the page-cache object, the offset, the open flags, and a copy of the file's attributes that vfs-server keeps current;
  - a **directory handle:** the directory's object, and the cookie of the next `getdents64`.

**Answered in the kernel, by handle, with no server:**

| Call | On |
|---|---|
| `read`, `pread64`, `readv`, `preadv` | File handles (page cache; a miss reads from zfs-server as today) |
| `lseek` | File and directory handles |
| `mmap` of a file | File handles (as today) |
| `fstat`, `statx`/`newfstatat` with `AT_EMPTY_PATH` | File and directory handles (cached attributes); server objects (as since step 2) |
| `close`, `dup`, `dup2`, `dup3`, `fcntl(F_DUPFD*, F_GETFD, F_SETFD, F_GETFL)`, `close_range`, close-on-exec | Every descriptor; the owner hears of the last close (`LX_NOTE_CLOSE`, as for server objects) |
| `poll`, `select`, `epoll_*` | Every descriptor (readiness words, as today) |
| `fchdir` | Directory handles: the kernel task's cwd becomes that handle |

**Forwarded to the owner:**
- to vfs-server: `write`/`pwrite`/`writev` on files, `getdents64`, `ftruncate`, `fallocate`, `fsync`, `fchmod`/`fchown`, `flock`, the `fcntl` lock commands, and `F_SETFL` on files (append mode is enforced by vfs-server);
- to the owning service: every call on a server object.

**Kept in the kernel per process:** the root and current directory (directory handles) and the umask. They belong to the process, they survive a vfs-server restart, and they come with each call (section 6).

**In the first version's measurements** this table is what saved the most. In `find` it answers 60,327 of 84,874 calls, and in the KDE login 28,435 calls on files and directories, 17,569 `poll`/`epoll` and 13,823 file reads.

**Group 13's temporary primitives:**
- `vfs_resolve` becomes a linux-server → vfs-server call;
- descriptor passing (`SCM_RIGHTS`) stays, as the permanent "move a handle" primitive;
- `LX_OBJ_FDPATH` and `LxCall::ino` go: the path of a handle is asked from its owner.

## 8. Resilience: what happens when a service crashes

### 8.1 vfs-server crashes

| What a program has | What happens |
|---|---|
| Open regular files | **Survive.** The handle (page-cache object, offset, flags, attributes) is the kernel's. `read`, `pread`, `lseek`, `fstat` and `mmap` keep working while the service is down; a cache miss still reads from zfs-server |
| Memory mappings of files | **Survive.** They are page-cache objects; page faults never involve vfs-server |
| Current directory, root | **Survive.** They are kernel handles |
| Open directories | **Survive.** The handle keeps the object and the `getdents64` cookie; the next `getdents64` waits for the restart |
| Path calls and changes made while it is down | The caller waits (blocked in the kernel, like a queued call) until the new instance is online, about a second (linux-server restarts take that long today), then the call goes there. After a timeout (say 30 s) the call fails with `EIO` |
| Calls in flight at the crash | Calls that change nothing (`stat`, `open` without `O_CREAT`/`O_TRUNC`, `readlink`, `getdents64`) are re-sent to the new instance. A change in flight (`rename`, `unlink`, `write`, create) gets `EIO`, because zfs-server may or may not have done it. The program sees an error, not its death |
| Mount tables and namespaces, file locks | **Survive,** because vfs-server keeps them in a **kept-state object**: a memory object the kernel keeps for the service across restarts and hands to the next instance. The new instance checks it (a version and a checksum) before using it; if it is damaged, it starts from the boot mount table and the programs' locks are lost (they get `EIO` on unlock) |
| `tmpfs` contents | **Survive.** The data are anonymous page-cache objects in the kernel, and the directory tree is in the kept state |
| Caches | Lost and refilled from zfs-server: the first walks after a restart are slow |
| `inotify`/`fanotify` watches (step 6b) | Kept in the kept state; events of the crash window may be lost, so watchers get `IN_Q_OVERFLOW` (programs handle it by rescanning) |

What the restarted vfs-server must re-derive:
- the object behind each live kernel handle: the kernel can list them, since each handle has the zfs object number and its generation;
- the open-file reference counts zfs-server needs (`open_ref`): it sends them again from that list.

### 8.2 linux-server crashes

- Every Linux program ends (decision 6, unchanged until Group 18's split).
- The kernel closes their handles, and vfs-server hears of the last closes.
- **vfs-server, its caches, the mounts and zfs-server stay up.** Native programs (hydra-shell, the drivers) and, later, other personalities keep their files.
- `/proc` and `/sys` are unavailable until linux-server is back: lookups under them wait or fail with `EIO`.

### 8.3 zfs-server crashes

- vfs-server's requests fail and are retried on the restarted zfs-server, as the kernel's are today (`ipc::service`: retried once). Page-cache misses in the kernel do the same.
- Programs see a pause. A write that zfs-server never acknowledged gets `EIO`.

### 8.4 What this needs that does not exist yet

- **A kept-state object per service:** the supervisor keeps a memory object across the service's restarts and maps it into the next instance. Generic; Group 18 may make it the restart mechanism for every service.
- **Waiting instead of failing:** calls to a service that is restarting wait for it (today's forwarding fails them with `ENOSYS` or `EIO`).
- **A list of a service's live handles** (owner, object, generation) for the new instance.
- **Handles that survive their owner's restart:** the generation check of step 2 must become "the same service, a new instance, objects revalidated" for vfs-server's handles, instead of "stale: `EBADF`".

## 9. What it costs

The same per-call costs as section 3.2:
- path call +4.2 µs;
- `getdents64` +4.7;
- a write or other forwarded call +2.0;
- reads and the table calls of section 7: 0.

The redirect adds one forward (+2.4) to each pseudo-file lookup. "vfs-server" is F1 with no kernel name cache; "with a kernel name cache" is F1 plus the B-full cache of the first version (Appendix B.3), which would also answer `stat` during a vfs-server restart.

**The hop to zfs-server** is shown separately, as the change per file-server request against today's kernel → zfs-server Handoff (5.8 µs empty round trip):
- **Queued:** +3.2 µs, today's ring-3 call, CPU awake;
- **direct:** about −3.3 µs, Group 18's target of about 2.5 µs;
- **F2:** about −5.8 µs, no hop at all.

| Workload (time today) | vfs-server | with a kernel name cache | zfs hop Queued | zfs hop direct | zfs hop removed (F2) |
|---|---:|---:|---:|---:|---:|
| Warm `find /usr` (1.07 s) | +106 ms (+10 %) | +83 ms (+8 %) | +134 ms (+13 %) | −138 ms (−13 %) | −243 ms (−23 %) |
| same on wave 4's 0.44 s | +24 % | +19 % | +30 % | −31 % | −55 % |
| `ls -lR /usr/share` (7.9 s) | +490 ms (+6 %) | +107 ms (+1 %) | +1,270 ms (+16 %) | −1,309 ms (−17 %) | −2,301 ms (−29 %) |
| `git status` (0.58 s) | +63 ms (+11 %) | +33 ms (+6 %) | +98 ms (+17 %) | −101 ms (−18 %) | −178 ms (−31 %) |
| `tar` (1.41 s) | +58 ms (+4 %) | +39 ms (+3 %) | +88 ms (+6 %) | −90 ms (−6 %) | −159 ms (−11 %) |
| `make` of 30 C files (8.3 s) | +345 ms (+4.2 %) | +76 ms (+0.9 %) | +283 ms (+3.4 %) | −291 ms (−3.5 %) | −512 ms (−6 %) |
| `apt-get install` (11.8 s) | +36 ms (+0.3 %) | +26 ms (+0.2 %) | +66 ms (+0.6 %) | −68 ms (−0.6 %) | −119 ms (−1 %) |
| Firefox start (5.05 s) | +17 ms (+0.3 %) | +10 ms (+0.2 %) | +27 ms (+0.5 %) | −28 ms (−0.6 %) | −49 ms (−1 %) |
| KDE login (about 25 s) | +657 ms (+2.6 %) | +134 ms (+0.5 %) | +318 ms (+1.3 %) | −328 ms (−1.3 %) | −577 ms (−2.3 %) |

How to read it: the cost of a shape is its column plus one of the three zfs-hop columns.

- **vfs-server with the direct call:** `find` −3 % against today (−7 % on the fast baseline), `git status` −7 %, KDE +1.3 %. **Within every budget.**
- **vfs-server with Queued calls:** `find` +23 % (+55 % on the fast baseline), `git status` +28 %. **Over budget for `find`:** the direct call is a prerequisite.
- **The redirect** costs 8 ms in the KDE login (0.03 %) and under 1 ms elsewhere.
- **Fewer requests.** A cache in vfs-server that is larger than today's kernel one (8,192 names, emptied when full) would also cut the number of requests (`ls -lR` makes 205,000 `resolve` requests today). That gain is not in the table.
- **Per call:** a forwarded `stat` costs 2.2 + 4.2 = 6.4 µs against the per-call budget of 5.2 (today + 3). The cheaper argument copy (section 10.2) is still needed to meet it.

## 10. Recommendation

### 10.1 F1: vfs-server, a file service of its own, with a kernel handle table

1. **It is what decision 9 asks for.** The file system is neither in linux-server nor tied to the ZFS implementation:
   - a crash of the Linux layer leaves the file system up;
   - a crash of the file service leaves the programs running.
2. **It costs what the first version's B-lean cost:** one hop per file call, and the same calls answered in the kernel. With a direct server-to-server call, the metadata tools may even get faster than today.
3. **The kernel handle table is what makes restarts possible.** Open files, current directories and mappings live in the kernel, so a restarted vfs-server finds the programs as it left them.
4. **`/proc`, `/sys` and `/dev` go to the Linux services that own their state,** mounted into the VFS. They are reached with one redirect, and only at lookup.

### 10.2 Prerequisites (before or with wave 7)

| | What | Why | Who |
|---|---|---|---|
| P1 | **Direct server-to-server call** (and grants for buffers) | Without it `find` is 55 % slower on the fast baseline; with it the tools may be faster than today | Group 18's design; built in wave 6 |
| P2 | **Routing to several servers,** by number, by descriptor owner, with redirects (section 6) | Calls go straight to vfs-server | Group 18's design; built in wave 6 |
| P3 | **Cheaper argument copies** in the forwarding path (fault fix-ups instead of a page walk per pointer) | Path calls +4.2 → about +2.5 µs: inside the per-call budget | Wave 6, 2–3 agent-days |
| P4 | **Kept-state objects, waiting for a restarting service, live-handle lists** (section 8.4) | Restart without ending programs | Group 18's restart design, or wave 7 group 7-6 |
| P5 | **Fix FIFO opens** (`make -j` spins today) | A bug; it shapes how FIFOs work later | Group 13 (wave 5) or wave 6 |

## 11. Decisions for the user

1. **Where does the file service live?**
   - Recommended: **a new service, vfs-server,** next to zfs-server (which stays the ZFS back end). It owns names, mounts, permissions, opening and every change to files.
   - The alternative, building the VFS into zfs-server, saves one call per cache miss, but a bug in either part then takes both down.
2. **Should `/proc`, `/sys` and `/dev` belong to the Linux services, not to the file service?**
   - Recommended: **yes.** They show processes and devices, which the Linux services own. The file service only points lookups there.
   - The cost is one extra hop when such a file is opened (8 ms in a 25 s KDE login).
3. **Does the descriptor table stay in the kernel, as a table of handles?**
   - Recommended: **yes.** It answers most calls of the metadata tools without any service, and it is what lets programs keep their open files when the file service restarts.
4. **When the file service crashes, should programs keep running?**
   - Recommended: **yes.** Open files, current directories and memory mappings survive; file calls wait about a second for the restart.
   - The price is that a change in flight at the crash (a rename, a write) returns an error to the program, and some kept state (mounts, locks) must be saved in a kept-state object.
   - The simpler alternative is to end every program, as when linux-server crashes. That would undo much of the point of decision 9.
5. **A fast call between services is a prerequisite.** Should Group 18's direct call be built in wave 6?
   - Recommended: **yes.** Without it, a warm `find` would be about 23–55 % slower (over budget). With it, the metadata tools may get faster than today.
6. **A kernel cache for `stat`?**
   - Recommended: **not now.** It would bring the KDE login from +2.6 % to +0.5 % and keep `stat` working during a file-service restart, but it needs a coherence protocol between the kernel and vfs-server.
   - Revisit if the budget is missed.
7. **Splitting wave 7:** six groups in parallel, then one closing group (section 12), about 25–29 agent-days in 6–8 days of wall time.
   - Recommended: **yes,** after the prerequisites of wave 6.

## 12. Wave 7 plan (F1)

### 12.1 Before wave 7 (wave 6)

P1, P2 and P4 as Group 18 plans them; P3 (2–3 agent-days); P5 (Group 13, or 1 agent-day in wave 6).

### 12.2 Wave 7: seven groups

Each group owns its files. Shared files (the kernel routing table of P2, the copy table `src/lx/copy.rs`, the protocol file `src/ipc/protocol.rs`) get one marked block per group, planned in NOTES.md first, as in waves 4 and 5.

| Group | What | Files owned | Depends on | Agent-days | Tests |
|---|---|---|---|---:|---|
| **7-1. vfs-server core** | The new program: endpoint, workers on the direct switch, the path walk, the name/attribute/link caches, zfs-server client (`allow_client`, its window range), mount crossing, the redirect answer | new `userland/drivers/vfs-server/` (`main`, `walk`, `cache`, `zfs`); `src/task/supervisor.rs` (its entry); `src/ipc/protocol.rs` (its block) | P1, P2 | 4–5 | A walk test comparing vfs-server's results with the kernel's for every path of the section-3.3 workloads; `fscache`, `xattr` |
| **7-2. Path calls and kernel file handles** | `open*`, the stat family, `access`, `readlink`, creates, removes, `rename`, links, `chmod`/`chown`/`utimensat`, `truncate`, xattrs, `getdents64`, writes, `sendfile`/`copy_file_range` into vfs-server; the kernel side: file and directory handles, `obj_*` primitives, attribute updates, cwd/root/umask in the task | `vfs.rs`, `recent.rs`, `misc.rs`, `extra.rs`, `xfer.rs` → `vfs-server/src/calls/`; kernel: new `src/lx/fileh.rs`, `fs/fd.rs` (the new kinds only) | 7-1's interface (day 1) | 5–6 | `vfs`, `recent`, `batch1`–`3`, `stdfd`, `fsync`, `exelink`, `mmaptail`, `pagecache`, vfsbench, the section-3.3 workloads against the budget |
| **7-3. Mounts, namespaces, `tmpfs`** | Mount tables, namespaces, the mount API, `pivot_root`, `chroot`, `tmpfs` (directory tree in the server, data in kernel anonymous objects) | `mount.rs` → `vfs-server/src/mount.rs`, `tmpfs.rs` | 7-1's interface | 3–4 | `mount`, `mountapi`, `nstest`, `pidns`, portals in KDE (Flatpak-style `/proc/<pid>/root`), the installer test |
| **7-4. Pseudo file systems in linux-server** | `/proc`, `/sys`, `/dev`, the udev database, `efivars` as file systems served by linux-server and mounted in vfs-server; info primitives (`task_info`, `mm_maps`, `sys_stats`, `efivar`) | `fs.rs`, `devices.rs`, `efivars.rs`, `live.rs` → `linux-server/src/pseudo/`; kernel: new `src/lx/info.rs` | 7-1's redirect interface | 4 | `procinfo`, `proctest`, `procnet`, `cmdline`, `blockdev`, KDE and Firefox (they read `/proc` and `/sys`), `lsblk` |
| **7-5. `execve`, socket files, FIFOs** | linux-server asks vfs-server to open the program, the interpreter and `#!` scripts; `task_exec`; Unix socket nodes by path and FIFOs through vfs-server (Group 13's `vfs_resolve` goes) | `execve.rs` (front half), `task/exec.rs` (primitive entry); `linux-server/src/{unix,pipe}.rs` (only the path parts) | 7-1's interface, P1 | 3 | `exelink`, `cmdline`, `crashexit`, `unixtest`, `make -j` (FIFO jobserver), fork+exec budget, a Wine start |
| **7-6. Restart without ending programs** | Kept-state object (mount table, locks, `tmpfs` tree), waiting for a restarting service, re-sending idempotent calls, live-handle list and revalidation, the `open_ref` resync with zfs-server | `vfs-server/src/{kept,recover}.rs`, `locks.rs` → `vfs-server/src/locks.rs`; kernel: the restart parts of P4 (if Group 18 has not built them) | 7-1's interface, P4 | 3–4 | A new test: kill vfs-server while programs hold open files, mappings, a cwd, locks, and a `tmpfs` file; then everything still reads, `getcwd` works, locks hold, a change in flight gets `EIO`; kill it under KDE: the desktop keeps running |
| **7-7. Closing** (after 7-2 to 7-6 merge) | `Vnode` and `File { path }` removed; `fs/fd.rs` down to the handle table; `LX_OBJ_FDPATH`, `LxCall::ino` removed; the in-kernel VFS copies deleted after deployment; budget measurement | `fs/fd.rs`, `src/lx/obj.rs`, `memfd.rs` | 7-2 to 7-6 | 3 | Full suite, `suite_loop` ×3, IOMMU suite, KDE ×5 fresh logins, Firefox, Wine, sound, the installer test, the full budget, kill tests for vfs-server, linux-server and zfs-server |

- **Order:**
  - Day 1: 7-1 writes the walk, cache and redirect interface into NOTES.md.
  - 7-1 to 7-6 then run in parallel: they own different files.
  - 7-7 follows their merge. The lead merges 7-1 first, then 7-2, then the rest.
- **Total:** about 25–29 agent-days. Prerequisites: P3 2–3, P5 1, plus Group 18's P1/P2/P4.
- **The switch back** (`lx=kernel`) keeps every moved call working in the kernel until 7-7 deletes the copies.
- **Step 6b** (`io_uring`, `aio`, `inotify`, `fanotify`, FUSE, Landlock, ACLs, ABAC) follows in wave 8. Its file-side pieces go to vfs-server, and `io_uring`/`aio` to whichever service owns the descriptor.

## 12b. Wave 9 (6b-1): inotify and fanotify in vfs-server, as built

- **Objects.** An inotify instance and a fanotify group are vfs-server server objects (`LX_OBJ_KIND_INOTIFY` 73, `LX_OBJ_KIND_FANOTIFY` 74; `vfs-server/src/notify`). `inotify_init[1]`, `fanotify_init` (253/294/300) go to vfs-server by number; `inotify_add_watch`, `inotify_rm_watch`, `fanotify_mark` (254/255/301) only when `args[0]` is one of its objects (`fileh` shapes `Notify`/`NotifyAt3`), else the kernel answers (its own instance). `read` is pending while the queue is empty; `poll` reads the readiness word; `FIONREAD`; `write` answers a permission event.
- **Events.** vfs-server's own changes: from its zfs-server replies. The kernel's changes and open files: posted to vfs-server's note ring (`src/lx/notifyfwd.rs`: `LX_NOTE_FSEVENT` + `LX_NOTE_FSDATA` entries), only for inodes in the map vfs-server publishes in its window (flags word = note-ring header word 3, 16 Kbit inode hash at 0x20400). A call carries the ring position, so a `read` after a change sees its event.
- **Permission events.** The kernel posts the event with an id, then asks `LX_KCALL_FANPERM` (0x6792), pending until every group answered. While a mark wants descriptor or permission events, vfs-server sends its opens and `getdents` to the kernel, so those events are made where the open is.
- **Restart.** Groups, watches and marks are kept records (kept key 3); the objects are adopted; queued events become one `IN_Q_OVERFLOW`/`FAN_Q_OVERFLOW`. A second crash within 30 s (the ladder: FailObjects) makes the descriptors stale (`POLLERR|POLLHUP`).
- **kernel_mask.** The inotify/fanotify bits now come only from kernel-owned instances (switch back: `lx.vfs=kernel`, `lx=kernel`, vfs-server given up); with vfs-server serving them no call stays in the kernel because of a watch.

## 13. Not measured, and limits

- **KVM, not the NUC.** Forwarding costs and zfs-server request costs on real hardware were never measured.
- **Timings are noisy.** Five other groups' VMs shared the PC: the two boots of section 3.1 differ by up to 40 % on single calls, and a warm `find` took 0.81–1.35 s in three boots here against 0.44 s in wave 4 (same call counts each time). That is why section 9 shows both baselines. The counts, not the times, are the solid part.
- **The prototype measures a stub,** not a server VFS. The server's real work for `open` or `stat` is assumed to cost what the kernel's costs today; a server-side cache could make it cheaper (fewer zfs-server requests) or dearer (user-space locks).
- **Server-to-server calls were not measured.** Their cost is taken from the design's IPC numbers (Handoff 5.8 µs, Queued in a loop 9.0 µs) and, for the direct call, from Group 18's target (about 2.5 µs, like the direct switch to linux-server). The zfs-hop columns of section 9 are estimates, not measurements.
- **Restarts were not tried.** Section 8's restart behaviour is a design; no prototype of a restartable vfs-server was built.
- **The `git` repository was small** (3,851 files); a larger one would scale the counts, not change their mix.
- **Not profiled:** Wine, dpkg on a large upgrade, a large compile.
- **The no-PCID case** was not measured: wave 4's +2.2 µs per forward (against +2.0) would add about 10 % to every forwarding cost above.

## Appendix A: reproducing the measurements

- **Prototype build** (local only, never commit): `git apply tools/vfsbench/prototype.patch`, then build the drivers, the kernel and the ISO as usual. `git checkout -- src userland` removes it.
- **vfsbench:** `gcc -O1 -w -pthread tests/linux/vfsbench.c -o esp/bin/vfsbench.elf` in WSL, then `make build`; `tools/vfsbench/bench.sh NAME` runs it in one VM (as root). The stub tests run only on the prototype build.
- **Workloads:** `esp/bin/g16src.elf` is `vfsbench.elf` followed by a tar of 30 files of `tests/linux` plus a Makefile: the boot import copies only ELF files into `/bin`, and `work.sh` cuts the tar off the end. `tools/vfsbench/work.sh NAME [FIND LSLR GIT TAR GCC APT FF]` runs the workloads (`BENCH=1` runs vfsbench first; `REPO=...` picks what the git repository holds). It installs git, gcc and make in the overlay first.
- **KDE:** boot with `scratch/kde_kde.sh NAME`, then with `kde_ctl.sh`: console `linux prof on`, back to SDDM, log in, wait 60 s, console `linux prof off` and `linux prof show 400` (section 3.3's run). `tools/vfsbench/kde.sh` (typed steps without the control mode) lost the console login twice.
- **Tables:** `python tools/vfsbench/vfsparse.py LOG` (counts by kind; writes `LOG.vfs.json`), then `python tools/vfsbench/vfscost.py LOG.vfs.json` (the first version's option table, Appendix B; per-call costs can be overridden, e.g. `path=2.5`).
- **Logs:** the logs of these runs are in `scratch/g16/logs/` of the worktree (git-ignored, not committed).

## Appendix B: the first version's options (VFS inside linux-server), for reference

The first version (commits 6595714–72fe6d5) compared three options with the VFS in linux-server. Decision 9 rejected the recommended one (B-lean). Its analysis is kept here because the costs carry over: F1's forwarded calls are B-lean's. Section numbers inside this appendix refer to the first version's layout.

### B.1 The options

All three keep in the kernel what section 5 of the Linux design already keeps: the page cache, page faults, address spaces, the ELF loader, and the data half of the ZFS client. They differ in what else stays.

#### A. Everything out

- **linux-server owns:** path lookup and its caches, mounts, pseudo files, permission policy, the open-file objects, **and the descriptor table** of every Linux process (numbers to objects, close-on-exec, `dup`, `fork`'s copy, `poll`/`select`/`epoll`).
- **The kernel keeps:** the page cache with `obj_*` primitives (`obj_file(ino)`, and `obj_read`/`obj_write` between the page cache and the client's memory), and `as_map` for file mappings.
- **Every descriptor call is forwarded,** including `close`, `fcntl`, `fstat`, `dup`, `lseek`, `read` of cached data, and `poll`/`epoll_wait` on any descriptor.
- **Kernel-owned objects** (memfd, DRM until wave 6 moves it, page-cache objects) are reached through handles the server holds: Group 9's `LX_OBJ_PIN`, turned around.

#### B. Out, with kernel-side read-only fast paths

- **linux-server owns** the VFS as in A: path lookup, mounts, pseudo files, permissions, `open`, and every change.
- **The kernel keeps the descriptor table as a table of handles,** which it already is for server objects since step 2. A descriptor names either:
  - a server object (a slot); or
  - a kernel **file handle** (page-cache object, offset, open flags, a reference to the file's attributes) that the server creates at `open`.
- **Answered in the kernel:**
  - on file handles: `read`, `pread`, `readv`, `lseek`, `mmap` (through the page cache) and `fstat` (cached attributes);
  - on any descriptor: `close` (the server hears of the last one, as for server objects), `dup`, `fcntl(F_GETFD/F_SETFD/F_GETFL/F_DUPFD*)`, close-on-exec;
  - `poll`, `select` and `epoll`, through readiness words as today.
- **Forwarded:** `open` and every other path call, `getdents64`, everything that changes something (`write` on a file, `rename`, `chmod`, ...), and calls on pseudo files.
- **Two forms:**
  - **B-lean** is the above.
  - **B-full** adds a kernel **name and attribute cache** that answers `stat`, `access` and `readlink` on a hit. The server fills and invalidates it (section 6).

#### C. The VFS stays in the kernel for good

- The kernel keeps path lookup, mounts, pseudo files, the caches and the descriptor table.
- **What still moves** are the parts of 6a that are on no hot path and mostly self-contained: the udev database and `/sys` generation (`devices.rs`, which writes files into the Linux root), `efivars`, and the policy-only parts of the mount API.
- **Steps 6b, 7 and 8 still happen.** FUSE, Landlock, ACLs and ABAC are tied to the VFS, so in C they would also stay (about 3,500 more lines).

### B.2 What each option cost

#### B.2.1 Added time per workload

From the counts of section 3.3 and the per-call costs of section 3.2 (`tools/vfsbench/vfscost.py`):
- path calls +4.2 µs;
- `getdents64` +4.7;
- file reads +3.3;
- every other forwarded call +2.0.

The server's own work is assumed to cost what the kernel's does today.

The A, B-lean and B-full columns assume that linux-server's zfs-server requests cost what the kernel's cost today. The last column is the extra if they are today's Queued calls instead (+3.2 µs each). B-full assumes its name cache hits 95 % of the `stat`-kind calls (a cache sized for the workload; today's hits much less).

| Workload | Time today | A: everything out | B-lean | B-full | C | Extra with Queued server calls (A or B) |
|---|---:|---:|---:|---:|---:|---:|
| `find /usr` (warm) | 1.07 s | +227 ms (21 %) | +106 ms (10 %) | +83 ms (8 %) | 0 | +134 ms (13 %) |
| same, on wave 4's faster baseline (0.44 s, design 13.1) | 0.44 s | **+52 %** | **+24 %** | +19 % | 0 | +30 % |
| `ls -lR /usr/share` | 7.92 s | +528 ms (7 %) | +490 ms (6 %) | +107 ms (1 %) | 0 | +1,270 ms (16 %) |
| `git status` | 0.58 s | +72 ms (13 %) | +63 ms (11 %) | +33 ms (6 %) | 0 | +98 ms (17 %) |
| `tar` of `/usr/share/doc` | 1.41 s | +109 ms (8 %) | +58 ms (4 %) | +39 ms (3 %) | 0 | +88 ms (6 %) |
| `make` of 30 C files | 8.30 s | +391 ms (4.7 %) | +345 ms (4.2 %) | +76 ms (0.9 %) | 0 | +283 ms (3.4 %) |
| `apt-get install hello` | 11.8 s | +58 ms (0.5 %) | +36 ms (0.3 %) | +26 ms (0.2 %) | 0 | +66 ms (0.6 %) |
| Firefox headless start | 5.05 s | +27 ms (0.5 %) | +16 ms (0.3 %) | +9 ms (0.2 %) | 0 | +27 ms (0.5 %) |
| KDE: password to desktop (all its calls counted against 25 s) | about 25 s | +843 ms (3.4 %) | +649 ms (2.6 %) | +126 ms (0.5 %) | 0 | +318 ms (1.3 %) |

Against the budget (design 6.6; desktop, browser and network +5 %, metadata tools +35 %):
- **A misses the metadata budget** for a warm `find` on the faster baseline (+52 %), and meets it on today's slower one only if the server-to-server call is fast.
- **B-lean and B-full meet it** on both baselines, provided the server-to-server call is fast. With Queued server calls, B-lean's `find` comes to +54 % on the fast baseline: the fast call is a prerequisite in every option (section 8.2).
- **Firefox and `apt-get` stay under 1 % in every option. The KDE login** costs +3.4 % (A), +2.6 % (B-lean) or +0.5 % (B-full): within the 5 % budget, but with Queued server calls B-lean's +3.9 % leaves little room.
- **The name cache of B-full** saves 0.4 s in `ls -lR` (which calls `lgetxattr`, `statx` and `readlink` on every file) and 23–30 ms in `find` and `git status`. It costs a coherence protocol in the kernel (section 6). It also saves about 0.5 s of the KDE login's 0.65 s (131,000 `statx`, `access` and `readlink` calls). It is worth adding later only if a step misses the budget on a workload like `ls -lR` or the KDE login.
- **The cheaper copy changes the picture.** If the copy table's per-pointer cost dropped from about 2 µs to 0.5 µs, path calls would add about 2.5 µs. A's `find` would then come to about +42 % on the fast baseline (+17 % on today's) and B-lean's to about +15 % (+6 %); the KDE login to +2.3 % (A) and +1.5 % (B-lean).

#### B.2.2 The rest of the comparison

| | A: everything out | B-lean (recommended) | B-full | C: the VFS stays |
|---|---|---|---|---|
| **Lines that move to linux-server** | about 14,900 (all of section 1.1) | about 13,700: all but the table core and the file-handle I/O | about 13,400 | about 2,200 (`devices`, `efivars`, parts of `mount`) |
| **Lines that stay in the kernel for good** | page cache and `obj_*` primitives (new, about 600) | the descriptor table of handles (about 600 of `fd.rs`), file-handle I/O (about 500), per-file attributes for `fstat` (about 150), `poll`/`select`/`epoll` (about 600) | B-lean plus the name cache and its fill/forget primitives (about 600) | about 12,700 of today's VFS, plus FUSE, Landlock, ACLs and ABAC (about 3,500) |
| **New kernel primitives** | `obj_*`, `as_map`, info primitives for `/proc`, kernel-object handles and readiness words for the server, `task_exec` | `obj_*` (for writes), file-handle install, attribute fill/forget, info primitives, `task_exec` | B-lean plus name-cache fill/forget | none |
| **Cache coherence** | none in the kernel (the server's own caches are private) | per-file attributes only: the server forgets a file's attributes before it answers a call that changed them | names, attributes and link targets (section 6) | as today |
| **When linux-server crashes** | every Linux program ends (decision 6); nothing to repair in the kernel | the same; the kernel empties the attribute cache and the handles of the dead server fail with `EBADF` | the same, plus the name cache is emptied | a VFS bug is a kernel panic, as today |
| **Isolation gained** | everything that parses paths, mount options and pseudo-file text is out of the kernel | the same: the table and file reads are mechanism; no path is parsed in the kernel | the kernel compares path bytes for its cache, but parses nothing | none |
| **Agent-days (wave 7)** | 26–29: B-lean's work, plus moving the table, `poll`/`epoll`/`select`, kernel-object readiness to the server and the `mmap`/`ioctl`/`sendfile` forwards | **21–23** (section 10) | 24–26 | 3–5 |
| **Main risks** | Misses the metadata budget; every `poll`/`epoll_wait` of the desktop becomes a forward; the largest change to `fork`, `exec` and exit | The handle table must stay correct for objects owned by two parties (kernel file handles, server objects); `execve` and `mmap` couplings | B-lean's, plus a coherence protocol whose bugs would be silent stale results | The kernel keeps 15,000 lines of file-system policy for good, against decision 1 ("the whole layer moves out") |

### B.3 Cache coherence (option B-full)

B-full keeps a copy of the server's state in the kernel, so it needs a protocol. B-lean needs only its attribute part.

**Entries.**
- **Names.**
  - The key is (mount namespace, root object, base object, the path bytes as given, follow-the-last-link flag). That is what the kernel can compute without knowing anything about mounts, symbolic links or `/proc`: the server did that work when it filled the entry.
  - The value is (object, mount), or `ENOENT`/`ENOTDIR`, plus the list of directories on the way that not everyone may search (today's `SEARCH_DIRS`).
- **Attributes:** object → mode, owner, size, times, link count, device, blocks, and a "has an ACL or a security label" bit.
- **Link targets** (for `readlink`): object → bytes.
- **Never cached:**
  - paths the server serves itself (`/proc`, `/sys`, `/dev`, sockets under `/run`);
  - paths in a FUSE mount;
  - anything a Landlock domain or an ABAC rule of the caller restricts (a per-task flag says "forward everything").

**Filling.**
- The server answers a forwarded call and, in the same `SYS_LX_REPLY_RECV`, gives the kernel entries for it: the generation it read when it started, then the entries.
- The kernel drops the fill if the generation changed meanwhile: the same rule as today's `ATTR_GEN`/`NAMES_GEN`.

**Invalidating.**
- Every change goes through the server. Before it answers the call that made the change, it tells the kernel what to forget: one file's attributes, one name, or all names (a renamed directory, a mount change).
- That is one primitive `SYS_LX_CACHE(op, ...)`, or a ring of forgets that the kernel takes before its next lookup.
- The generation bump makes useless any fill that started before the change.

**What the kernel decides on its own:** only what today's cache decides, namely search permission on the listed directories (owner, group and mode bits from the cached attributes) and the `stat` fields. No mount, symbolic link, `/proc`, ACL or Landlock logic.

**File handles (B-lean and B-full).**
- The server creates a kernel file handle at `open`.
- Writes go through the server, which updates the page cache as today (`cache_written`) and forgets the file's attributes.
- Truncation and removal go through the server, which calls `obj_truncate`/`obj_forget` (Linux design, section 8.3).

**When the server dies:** the kernel empties the caches (one generation bump), and server objects and file handles of the old generation fail (`EBADF`), as server objects already do. The crash policy then ends every Linux program anyway.

### B.4 The descriptor table and Group 13's temporary primitives

#### B.4.1 If the table moves (option A)

1. **The table moves whole, per process,** into linux-server:
   - descriptor numbers, close-on-exec flags and the `RLIMIT_NOFILE` check;
   - `fork`'s copy: the server copies on `LX_NOTE_FORK`, before the child's first call (step 1's ring-order rule);
   - `CLONE_FILES` sharing and the close at exit.
2. **Every call that names a descriptor is forwarded.** The kernel no longer knows what descriptor 5 is.
3. **`poll`, `select` and `epoll` move** with the table.
   - Readiness of server objects is already in shared words.
   - Kernel-owned objects (memfd, DRM until wave 6, a pinned kernel descriptor) need readiness words written by the kernel and read by the server: the step-2 mechanism in the other direction.
4. **Calls the kernel answers but that take a descriptor** must be forwarded first:
   - `mmap` of a file (the server calls `as_map(obj)`);
   - `ioctl` on DRM (until wave 6);
   - `sendfile`/`splice` between kernel objects;
   - `io_uring`/`aio` (step 6b);
   - `fchdir`, and the directory descriptors of the `*at` calls.
5. **Native programs** keep the kernel's `FdTable` (they are not Linux tasks).
6. **The switch back** (`lx=kernel`) needs both tables to exist side by side during the step; a process uses one or the other for its whole life.

#### B.4.2 If the table stays as a table of handles (options B, C)

1. **`FileDescriptor` shrinks as the kinds move.** After waves 5 and 6 the variants left are:
   - `Device` (server objects and kernel devices);
   - the new **file handle** (page-cache object, offset, flags);
   - the console variants, for native programs.
2. **`Vnode` and `File { path }` go:** a pseudo file becomes a server object, and a regular file becomes a file handle.
3. **`fs/fd.rs` keeps** `dup`, `close`, close-on-exec, `fork`'s copy and the server-object bitmap (Group 12's `srv_bits`), and loses every per-kind arm: about 1,260 lines down to 600.
4. **`epoll`, `select` and `poll` stay in the kernel.** They are readiness mechanism over words, and the desktop calls them thousands of times a second (Firefox: 1,676 calls in a 5-second start).

#### B.4.3 Group 13's temporary primitives (wave 5)

| Primitive | In A | In B |
|---|---|---|
| `vfs_resolve` (socket files, FIFOs) | Goes: the server resolves its own paths | Goes, the same way |
| Descriptor passing (`SCM_RIGHTS` of any descriptor through a server-owned Unix socket: pin a descriptor of the sender, install it in the receiver) | Goes for server objects (one table); stays only to pin **kernel** objects (memfd, DRM) | **Stays, as permanent mechanism:** the table is the kernel's, so the server asks the kernel to move a handle. It should be renamed from "temporary" to the handle transfer primitive |
| `LX_OBJ_FDPATH` (step 2, temporary) | Goes | Goes: the server knows the path of its own objects, and a file handle carries the server's open-file slot |
| `LxCall::ino` (a socket node resolved at trap time) | Goes | Goes |

#### B.4.4 `execve`, the working directory and `umask`

- **The per-process "fs" record moves with the VFS in A and B:** `chdir`, `fchdir`, `chroot`, `getcwd`, `umask`, and the root and current directory per process (shared on `CLONE_FS`). The server keeps the record, created on `LX_NOTE_FORK`.
- **`execve` resolves files.** Recommended:
  - forward `execve` in 6a, and give the server the `task_exec(thread, exe object, interpreter object, argv/envp, credentials)` primitive now (it is in the design's list for step 7);
  - the rest of step 7 (the process table, the signal policy) still waits for wave 8.
- **The other way, a kernel-to-server "resolve for exec" request,** would make the kernel wait for the server inside `execve`: possible, since `execve` holds no lock there, but it is a temporary primitive that step 7 would delete again.

### B.5 The first recommendation (rejected by decision 9)

#### B.5.1 Option B-lean: the VFS moves out, the descriptor table stays as a table of handles

1. **It meets the budget,** with the two prerequisites below:
   - warm `find` about +10 % (+24 % on the faster baseline);
   - `git status` +11 %, `tar` +4 %;
   - the KDE login +2.6 % (+1.5 % with the cheaper copy); Firefox and `apt-get` under 1 %.
2. **It keeps the user's decision 1 ("the whole Linux layer moves out") for everything that is policy:**
   - paths, mounts, pseudo files, permissions, `open`, every change, the name caches;
   - what stays is mechanism that every microkernel keeps: a handle table (Zircon and seL4 keep their handle and capability tables in the kernel), readiness, and reads from the page cache, which stays in the kernel anyway.
3. **It needs no name-cache coherence protocol.** B-full's kernel name cache saves 0.4 s only in `ls -lR` and a few percent elsewhere. Keep it as a later option if a workload misses the budget.
4. **It is the shape step 2 already chose:** a descriptor is a handle to an object that someone owns. Groups 9, 12 and 13 built pipes, sockets and event descriptors on that shape, and B-lean adds one more kind, the file handle.
5. **A costs more and gains little.** It forwards 60,000 more calls in `find` (+120 ms) and turns every `poll`/`epoll_wait` of the desktop into a forward. Its isolation gain over B-lean is a table of numbers.
6. **C keeps 15,000 lines of file-system policy in the kernel for good,** and keeps FUSE, Landlock, ACLs and ABAC there with it. That goes against decision 1, and the measurements show it is not needed for speed.

#### B.5.2 Two prerequisites (small kernel tasks; best in wave 6)

1. **Cheaper user-memory copies in the forwarding path** (`src/lx/copy.rs`, the trap's copy-in/copy-out).
   - Today each pointer argument costs 1–2 µs: the address-space lock, a page-table walk per piece, and two copies.
   - The trap runs in the caller's address space, so the kernel can copy straight from user memory with a fault fix-up (an exception table, as Linux's `copy_from_user` does). That needs no lock and no walk, and copies straight into the syscall page.
   - Goal: under 0.5 µs per pointer, which brings a forwarded `stat` to about +2.5 µs, inside the per-call budget.
   - About 2–3 agent-days. It also speeds up every call moved in waves 3–5.
2. **A fast call from linux-server to zfs-server** (and net-server, which Group 12 meets in wave 5).
   - A ring-3 server's `SYS_SVC_CALL` is Queued unless it is inside a hand-off (`ipc::service::driver_call_mode`): 9.0 µs back to back and 18.8 µs when the other CPU sleeps, against the kernel's 5.8 µs Handoff.
   - On the metadata tools' 27,000–400,000 file-server requests that adds 6–17 % (on today's times; 30 % for `find` on the faster baseline).
   - A direct switch between two servers (step 1's mechanism, server to server) removes it.
   - About 3–4 agent-days. It also helps net-server and every server-to-server path (zfs-server to the disk driver).

**Worth doing at once, in any option: a larger kernel name cache.** Today's 8,192 entries, emptied when full, make `ls -lR` ask zfs-server 205,000 times. A cache that drops its oldest entries instead of emptying itself, sized at 64k entries, is a small change in `src/fs/zfs/mod.rs`. It would make today's kernel faster, and its logic moves to linux-server in wave 7. It also makes today's baseline faster, so the percentages above would grow a little.

### B.6 The first decision questions (superseded by section 11)

1. **Does the VFS move out of the kernel?**
   - Recommended: **yes** (option B-lean). Path lookup, mounts, `/proc`, `/sys`, `/dev`, permissions and every file change go to linux-server.
   - The cost is about +10 % on a warm `find` (up to +24 % on the fastest earlier measurement), +4–11 % on `git status` and `tar`, about +2.6 % on a KDE login, and under 1 % on Firefox and `apt-get`.
   - The alternative, keeping the VFS in the kernel for good (option C), costs nothing in speed but keeps about 15,000 lines of file-system code in the kernel.
2. **Does the descriptor table stay in the kernel for good?**
   - Recommended: **yes, as a table of handles.** The kernel keeps "descriptor 5 is that object" and answers `close`, `dup`, `fstat`, `lseek`, `poll` and reads of cached file data itself. It decides no file-system policy.
   - Moving the table too (option A) would make a warm `find` about 50 % slower on the faster baseline, over the 35 % budget.
3. **A kernel cache of names for `stat`** (option B-full)?
   - Recommended: **not now.** It would save 0.4 s of 8 s in `ls -lR` and little elsewhere, and it needs a coherence protocol in the kernel.
   - Revisit if a workload misses the budget.
4. **Two prerequisites first** (wave 6, beside step 5): cheaper copies of system-call arguments (2–3 agent-days) and a fast call between two servers (3–4 agent-days).
   - Recommended: **yes.** Without them every option misses the per-call budget, and the metadata tools lose another 10–17 %.
5. **Enlarge today's kernel name cache now** (a small fix, also a speed-up for today's system)?
   - Recommended: **yes**, as a small task in wave 6.
   - Note: it makes today's baseline faster, so wave 7's percentages are measured against a faster system.
6. **`execve` in wave 7:** let linux-server resolve the program and the interpreter, with the kernel's ELF loader behind a `task_exec` primitive (pulled forward from step 7)?
   - Recommended: **yes.** The alternative is a temporary kernel-to-server request that step 7 deletes again.
7. **Splitting wave 7:** five groups in parallel, then one closing group (section 10), about 21–23 agent-days in 6–8 days.
   - The other way is two waves: first the path calls and file handles, then mounts and pseudo files. That is slower, but each merge is smaller.
   - Recommended: **one wave, six groups,** because the groups own separate files and the interfaces are agreed in their first day.

### B.7 The first wave 7 plan (superseded by section 12)

#### B.7.1 Before wave 7 (wave 6, beside step 5)

| Task | Files | Agent-days | Tests |
|---|---|---:|---|
| **P1. Cheaper copies:** user copies with a fault fix-up in the trap, straight into the syscall page | `src/lx/copy.rs`, `src/arch/idt.rs` (the fix-up table), `src/lx/mod.rs` (deliver) | 2–3 | `lxfwd` (copy table at page edges, `EFAULT` cases), `sigstress`, lxbench `add_key`/`keyctl_describe` and vfsbench's stubs |
| **P2. Server-to-server direct call** | `src/ipc/service.rs`, `src/task/scheduler.rs` (`direct_call`), `hydra-rt` | 3–4 | A probe from linux-server to zfs-server (as the step-0 probe), the IPC suite tests, net-server throughput, killing either server |
| **P3. Larger kernel name and attribute caches** (drop the oldest instead of emptying) | `src/fs/zfs/mod.rs` | 1 | `fscache`, `vfs`, the vfsbench workloads before and after |

#### B.7.2 Wave 7: six groups

The groups own separate files. Shared files are handled as in waves 4 and 5: each group writes its plan in NOTES.md first and adds its own marked block. Those shared files are the `src/lx/mod.rs` tables, linux-server's `main.rs` dispatch and `src/lx/copy.rs`.

| Group | What | Files owned | Depends on | Agent-days | Tests |
|---|---|---|---|---:|---|
| **7-1. Server VFS core** | The path walk and the name/attribute/link caches in linux-server (from `fs/client.rs` and `fs/zfs/mod.rs`), linux-server as zfs-server's second client (`allow_client`, its own window range), the per-process fs record (root, cwd, umask) | new `linux-server/src/vfs/{walk,cache,zfs,fsrec}.rs`; zfs-server's client table; `task/supervisor.rs` (`allow_client`) | P2 | 4 | A server-side walk test against the kernel's results (both run, compared for every path of the vfsbench workloads), `fscache`, `xattr` |
| **7-2. Path calls and file handles** | `open*`, the stat family, `access`, `readlink`, `mkdir`, `unlink`, `rename`, `link`, `symlink`, `chmod`/`chown`/`utimensat`, `truncate`, xattrs, `getdents64`, `sendfile`/`copy_file_range` in the server; the kernel file handle (`FileDescriptor` variant), `obj_*` primitives, the attribute fill/forget primitive | `vfs.rs`, `recent.rs`, `misc.rs`, `extra.rs`, `xfer.rs` → `linux-server/src/vfs/calls.rs`; kernel: new `src/lx/file.rs`; `fs/fd.rs` (the new variant only) | 7-1's interface (first day) | 5–6 | `vfs`, `recent`, `batch1`–`3`, `stdfd`, `fsync`, `exelink`, `mmaptail`, `pagecache`, vfsbench, the workloads of section 3.3 against the budget |
| **7-3. Mounts and namespaces** | Mount tables, mount namespaces, the new mount API, `pivot_root`, `chroot`, tmpfs mounts, `/proc/<pid>/root` lookups | `mount.rs` → `linux-server/src/vfs/mount.rs` | 7-1's interface | 3–4 | `mount`, `mountapi`, `nstest`, `pidns`, Flatpak-style portals (KDE), the installer test |
| **7-4. Pseudo files** | `/proc` (with info primitives `task_info`, `mm_maps`, `sys_stats`), `/sys` and `/dev` (with `devices.rs`'s udev database), `efivars` (an `efivar` primitive) | `fs.rs`, `devices.rs`, `efivars.rs`, `live.rs` → `linux-server/src/pseudo/`; kernel: new `src/lx/info.rs` | 7-1's interface | 4 | `procinfo`, `proctest`, `procnet`, `cmdline`, `blockdev`, KDE (reads `/proc` and `/sys` at login), `systemd-detect-virt`-style checks |
| **7-5. `execve` front half** | The server resolves the program, the interpreter and `#!` scripts and checks exec permission; `task_exec` primitive; `/proc/self/exe` | `execve.rs` (front half), `task/exec.rs` (primitive entry) | 7-1's interface | 2 | `exelink`, `cmdline`, `crashexit`, fork+exec budget (≤ 2.15 ms), Wine start |
| **7-6. Closing: the table and the temporaries** (after 7-2 to 7-5 merge) | `Vnode` and `File { path }` variants removed; `fs/fd.rs` reduced to the handle table; `vfs_resolve`, `LX_OBJ_FDPATH`, `LxCall::ino` removed; descriptor passing renamed and kept; `locks.rs` (record locks) and `memfd` glue moved; the in-kernel VFS copies deleted after deployment | `fs/fd.rs`, `locks.rs`, `memfd.rs`, `src/lx/obj.rs` | 7-2 to 7-5 | 3 | The full suite, `suite_loop` ×3, IOMMU suite, `locks`, `unixgc`, KDE ×5 fresh logins, Firefox, Wine, sound, the installer test, the full budget |

- **Order:**
  - Day 1: 7-1 writes the walk and cache interface into NOTES.md. 7-2 to 7-5 start on it against a stub.
  - 7-1 to 7-5 then run in parallel.
  - 7-6 follows their merge. The lead merges 7-1 first, then 7-2, then the others.
- **Total:** about 21–23 agent-days, plus the prerequisites' 6–8.
- **The switch back** (`lx=kernel`) keeps every moved call working in the kernel until 7-6 deletes the in-kernel copies, as in every step.
- **Steps 6b and 7 can start in wave 8** as planned. 6b's `inotify`/`fanotify`/`fuse` hooks get events from the server's walk; until they move, 7-2 reports each event to the kernel's copies through one temporary primitive (`LX_OBJ_FSEVENT`).

#### B.7.3 If the user chooses another option

- **A:** add a seventh group for the table move: `poll`/`select`/`epoll` into the server, kernel-object readiness to the server, forwarded `mmap`/`ioctl`/`sendfile`, `fork`/`exec`/exit table handling (5–6 agent-days). 7-6 then deletes `fs/fd.rs` for Linux tasks.
- **B-full:** add the name cache and its coherence protocol to 7-1 (kernel side) and 7-2 (fills and forgets): about 3 agent-days more.
- **C:** one group: P3, `devices.rs` and `efivars` to linux-server, the mount API's policy checks; 3–5 agent-days. Step 6b then shrinks to `io_uring`, `aio`, `inotify` and `fanotify` (FUSE, Landlock, ACLs and ABAC stay).


## FUSE in vfs-server (wave 9, Group 6b-2)

- **The device:** while the file service is forwarded, `/dev/fuse` (char 10:229) opens in vfs-server (`chardev.rs` routes the one device number; major 10 is shared, so no major claim). Each open is a server object of kind `LX_OBJ_KIND_FUSE` and a new connection; the daemon reads requests (`read`/`readv` wait as PENDING calls), writes replies (`write`/`writev`), and polls the readiness word. Its close ends the connection: callers get `ENOTCONN`, other readers `ENODEV`. `FUSE_DEV_IOC_CLONE` is not supported (`ENOTTY`; libfuse goes on without).
- **The engine** (`userland/drivers/vfs-server/src/fuse/`): connection, INIT, node table, the daemon's handles per open node, and every operation as a short chain of requests. No worker ever waits for a daemon: a call that needs an answer is PENDING and the worker that takes the daemon's reply runs the next step or completes it, so a daemon that uses files itself (xdg-document-portal) cannot block vfs-server.
- **Inodes and handles:** files of vfs-server's connections have FUSE inode numbers with connection numbers from `0x8000` (the kernel's own client uses 1..0x3FFF). Open files stay kernel handles (`LX_FH_INSTALL` accepts these inodes); the kernel's `fuse.rs` sends every operation on such an inode to vfs-server (`LX_KCALL_FUSE`, `src/compat/linux/fuse_svc.rs`), lending its buffers: vfs-server reads and writes them with `SYS_LX_READ`/`SYS_LX_WRITE` at `FUSE_KBUF_IN`/`FUSE_KBUF_OUT` (128 KiB per call each way).
- **The walk:** mounts of vfs-server connections are `LX_MNT_FUSE` in the table copies. For the stat family, access, readlink and plain opens vfs-server walks into them itself: a lookup, attribute or link it does not have yet makes the call wait for the daemon, and the call runs again from the reply with the answer (kept 100 ms for that run). Other calls on FUSE paths go to the kernel, which reaches vfs-server through `fuse.rs`.
- **Mounts:** `mount(2)` of FUSE stays where wave 8 put it (the kernel's table for the initial namespace); with a vfs-server `/dev/fuse`, `fuse.rs::mount` asks vfs-server to start the connection and records the root inode.
- **Restarts:** a crash of vfs-server: the `/dev/fuse` objects are adopted and each connection's fixed part (number, owner, max_write, state) comes back from the kept state (`LX_SVC_KEPT`), so the daemon and the mount go on; the node table is not kept, so inodes the old instance gave answer `ESTALE` (each instance numbers its nodes from its own base). A daemon crash: `ENOTCONN`, as on Linux; `umount` still works.
- **Switch back:** `lx.fuse=kernel`, `lx.vfs=kernel` or `lx=kernel` at boot: the kernel's own client (`fuse.rs`) as before.

## Per-call cost (wave 9, Group P2)

- **memcpy/memset:** compiler_builtins' versions run three `rep` string instructions per copy, whose start-up cost dominated the many 8..512-byte copies of a forwarded call (the call record, `Attr`, `Ctx`, results returned by value): about a third of vfs-server's own stat time. `hydra-rt/src/memfast.rs` replaces them (straight-line overlapping 8-byte moves up to 64 bytes, one `rep movsq` plus tail beyond) in every hydra-rt program and in the kernel (`src/main.rs`).
- **open's handle from the answer:** on a forwarded `open`/`openat` the kernel sets `LX_CALL_FHANSWER`; vfs-server answers a plain open with a redirect to `LX_REDIR_FH` (0xFE, no service) naming the inode (`redir_obj`) and mount | directory bit (tail), and the kernel puts the handle in the caller's table itself (`fileh::fh_install`: flags and shown path from the call's own arguments, as `LX_FH_INSTALL` would get them). FUSE files, calls run again after a daemon reply and handles with flags beyond the plain ones still use `LX_FH_INSTALL`.
- **One table copy per call:** `calls::ctxt::Call` takes the caller's mount-table copy and context once for the stat family, access, readlink and open; the walk reuses the attributes of the step into a directory for that directory's search check.

## `/dev`, `/sys` and the last walks (wave 10, Group V2)

After wave 10's V1 the file service sent nothing that changes files back to the kernel; what it still sent back was walks into or relative to `/sys`, `/dev` and `/proc`, device opens, `chdir`/`fchdir` and FUSE mounts. V2 serves them (decision 19: `/dev` and `/sys` belong to the Linux services, mounted into vfs-server and reached with one redirect at lookup):

- **`/sys` and `/dev` are pool trees vfs-server walks.** They always were ordinary directories of the Linux root, written at boot by `compat/linux/devices.rs`; the kernel served a few names in them by name and sent the rest to its own walk. Now the boot rule redirects only `proc` under the caller's root; the kernel passes handles and working directories under `/sys` and `/dev` as pool handles (`fileh::pseudo_path` keeps only `/proc`), so systemd's and udev's walks relative to `/sys` descriptors stay in vfs-server.
- **The names other services serve** are redirected at lookup (`walk::Backend::served`, `calls/served.rs`): below the caller's root's `sys`, `devices/system/cpu/{online,possible,present}` and efivars opens go to linux-server with the tail below `/sys` (its rules unchanged), `fs/cgroup/**/cgroup.procs` to the kernel (the cgroup mechanism); below its `dev`, `pts` goes to tty-server (`tty-server/src/devpts.rs`: the stat family, access, open, chmod/chown and statfs of the slaves, with the kernel's devpts numbers). A walk test call there answers as linux-server's does.
- **Device nodes.** The devices the kernel served by name (`null`, `zero`, `full`, `random`, `urandom`, `tty`, `console`, `ptmx`, `tty0`..`tty63`) are now nodes of the pool's `/dev` like `/dev/dri/card0` (Linux's modes and owners, given back to root at each boot). vfs-server finds a device node and checks it like any file (mode bits, ACL, ABAC, Landlock); the open's answer is a redirect to `LX_REDIR_DEV` (0xFC, no service) naming the device number, and the kernel opens the device by number without walking (`vfs::open_device`: the device-number routing of `chardev.rs`, so the number's owner makes the object; the terminals through tty-server, the console, the memory devices). A socket node opens `ENXIO`; `O_CREAT|O_DIRECTORY` is `EINVAL` (Linux 6.4).
- **`statfs`.** Only the kernel knows the path of a handle and of a working directory, so it sends their tree (`src/lx/fstree.rs`, shared with vfs-server: pool, sysfs, cgroup2, efivarfs, `/dev`, devpts) in spare bits of `fh_flags` (23-25) and `fs_flags` (24-26); paths vfs-server walks are classified by the walk's own path.
- **`chdir`, `fchdir`** are vfs-server's: the walk, a directory, search permission and the access policies, then `LX_FH_CHDIR`. `getcwd`'s path is the path the walk took (`walk::Track`: links resolved, `..` applied; relative to the old working directory when the walk did not start at the root), as the kernel's `dir_path` gave it, without its directory scans.
- **FUSE in the initial namespace.** `mount(2)` of `fuse`/`fuse.<name>` (fusermount3) is decided in vfs-server: the target walk, the caller's `/dev/fuse` object (`LX_OBJ_FD`), the connection mounted (`fuse::mount_conn`), then the kernel's ns-0 list is written through (`SYS_LX_OBJ` op 81 `LX_FH_NS0FUSE`, ADD/REMOVE): it stays what `/proc/mounts` shows and the generation the table copies follow. `umount2` finds the mount point by a parent walk, ends the connection and removes the record. Other mount changes in the initial namespace are `EPERM` there, as the kernel's rule.
- **`O_CREAT` through a dangling symbolic link** makes the link's target (absolute, relative and chained links, `ELOOP` after 40).
- **`statfs` in a FUSE mount** asks the daemon (STATFS) as a walk question: the call waits and runs again from the reply, as the stat family does; the figures as the kernel's client showed them.
- **`..` is cached** in vfs-server's name cache (/sys's links are all `../../devices/...`); a rename forgets the names in the moved directory, `..` among them.

**What still goes to the kernel's walk** (V2's counter, see the wave 10 notes): `/proc` (7b-2's kernel-kept files: magic links `fd/N`, `exe`, `cwd`, `root`, `fdinfo`, `cgroup`, `mountinfo`, the directories, and walks relative to a `/proc` directory descriptor, symbolic links into `/proc` such as `/dev/fd/N`); `cgroup.procs`; efivars write opens; changes inside FUSE mounts (creates, mkdir, unlink, rename, setattr...: the kernel's `fuse.rs` reaches vfs-server for each operation) and `fstatfs` of FUSE handles; bind mounts of device nodes and `/proc/self/fd/N` paths in bubblewrap's namespaces (the kernel's table names them by name); `/dev/pts` directory opens (listing); callers in mount namespaces of their own whose tables name `sysfs`/`devtmpfs` (kernel mounts there). **Before vfs-server is up** nothing of a Linux program reaches the kernel's walk: vfs-server is online before the first Linux process; the kernel's own users of paths at boot are `ZfsClient` lookups, not the Linux walk (`devices::populate`, the boot-file import, `admin/linux.rs` starting a Linux root, `mount.rs` building a new namespace's table, `pkg/rootfs.rs`).

## Changes inside FUSE mounts, `/dev/pts`, efivars and bubblewrap (wave 11, Group F)

After wave 10 the file service still sent back every change inside a FUSE mount, `fstatfs` and the `f*`/`*at` calls on FUSE descriptors (the kernel did not even pass those: a FUSE inode was not a "handle"), the listing of `/dev/pts`, efivars writes, and the walks of bubblewrap's sandboxes. Group F serves them:

- **FUSE changes.** The change calls are "rerunnable" like the stat family: their walk (and the checks: write and search permission, the sticky bit, the types Linux's VFS checks before any file system — `EISDIR`, `ENOTDIR`, a directory moved below itself `EINVAL`, `.`/`..`) may wait for the daemon and run again; nothing changes before. The change itself is then one operation of vfs-server's FUSE engine (`fuse::start` with a `Req`: CREATE/MKNOD, MKDIR, SYMLINK, LINK, UNLINK, RMDIR, RENAME, SETATTR, GET/LIST/SET/REMOVEXATTR), and the daemon's reply answers the program's call directly (`Then`/`How`: 0, a value, a created file's handle installed from the reply — the open counted as `FUSE_OP_OPEN_REF` did —, or xattr bytes with the size rules); the call is PENDING meanwhile, so no worker waits for a daemon. `O_TRUNC` opens truncate with SETATTR after the install; `O_PATH` opens are counted and installed; the ACL names are passed to the daemon as plain xattrs (as Linux's client without `posix_acl`); `O_TMPFILE` is `EOPNOTSUPP`. A walk that reaches a mount before the daemon answered INIT waits for it.
- **FUSE descriptors and working directories.** The kernel passes vfs-server's FUSE inodes as handles and working directories (`fileh::served_ino`; `kernel_only` no longer keeps the calls of a process whose working directory is in an initial-namespace FUSE mount), and vfs-server walks from nodes in FUSE mounts (`View::walkable_or_fuse`; a FUSE node the kernel names without its mount gets the first mount of its connection). `chdir`/`fchdir` into FUSE mounts are served (`LX_FH_CHDIR` accepts those inodes).
- **FUSE mounts in a mount namespace of the caller's own** (`unshare -m`, sandboxes) are decided by vfs-server as in the initial namespace: the connection is mounted and the table written back with a tree whose root is the connection's root (`LX_MNT_FUSE` in the copies). The mount calls may wait for a daemon too (a bind of a FUSE directory).
- **`/dev/pts` listed.** An open of the directory `/dev/pts` itself is the pool's directory (vfs-server no longer redirects it, so `*at` calls start from it as before and its slaves are still tty-server's); the kernel's `getdents64` of such a handle asks tty-server for the entries (`LX_KCALL_TTY` op `LX_TTY_K_LIST`: `.`, `..`, `ptmx` and the live slaves, the offset an entry index; `devpts::entries`, `dirents64`).
- **efivars.** linux-server serves write opens (`CAP_SYS_ADMIN`; `O_CREAT` makes a variable) and unlinks of efivars files (vfs-server redirects an unlink in `<root>/sys/firmware/efi/efivars` there: since wave 10 it had been a plain pool unlink that left the variable); both call the kernel's firmware primitive `SYS_LX_OBJ` op 83 `LX_INFO_EFIVAR_SET` (linux-server's host only), which also rewrites the pool's efivars files.
- **Named mounts of a namespace table.** Wherever they are (also on top of an `rbind`, after a `pivot_root`): proc is `LX_MNT_PROC` (redirect to lx-proc with the rest below the mount), devpts `LX_MNT_DEVPTS` (tty-server, rest below `pts`), the standard `/dev` devtmpfs a tree of the pool's `/dev` (its devices are pool nodes since wave 10), a bind of a device served by name a tree rooted at its pool node. So bubblewrap's `--dev`/`--dev-bind`/`--proc` sandboxes walk in vfs-server and its device binds and remounts are decided there (a remount names no source).

**What still reaches the kernel's walk after wave 11 F** (counted with a temporary per-call print under KDE + Firefox + Dolphin + bwrap; see the wave 11 notes): walks relative to `/proc` descriptors and `/proc` magic links (Group P); `cgroup.procs` (the kernel's cgroup mechanism, by design); a mount whose *target* is the root of a proc or devpts mount (bubblewrap's `--proc` on top of the rbind's proc, `devpts` on its `/dev/pts`): the target cannot be located in vfs-server's walk (it is a redirect), so the kernel decides these few mount calls, as before; changes inside FUSE mounts by a landlocked caller (the kernel's lexical chain); `O_PATH` opens of `/dev/pts` itself; `execve` of a file inside a FUSE mount (xexec's pool-only check). Before vfs-server is up nothing of a Linux program reaches the walk (V2).
