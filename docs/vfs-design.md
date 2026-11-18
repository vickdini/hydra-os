# The VFS, mounts, pseudo files and the descriptor table: design (step 0 for wave 7)

Microkernel wave 5, Group 16, 2026-11-18. Base: `host-unit-tests` 329aaf7. No code moves in this step. This document answers the open decision of [microkernel-plan.md](microkernel-plan.md) ("whether the VFS fast paths stay in the kernel for good") for step 6a of [linux-server-design.md](linux-server-design.md).

**Who this is for:** the user (technical, not a kernel specialist) and the agents of wave 7.

## 0. The answer in brief

- **What was measured** (KVM, 2 CPUs, the same setup as the Linux design):
  - the system calls of eight real workloads, sorted by the kind of call and the kind of descriptor (section 3.3);
  - the cost of the VFS calls today, and of VFS-shaped calls answered by a stub in linux-server (a local prototype, not committed; section 3.2).
- **The metadata-heavy tools are the only workloads that care.** They make **17,000 to 79,000 system calls a second** (warm `find /usr`: 79,000/s). Firefox's start and `apt-get install` make 2,000 to 4,000 a second and no option costs them more than 1 %. A KDE login makes about 14,000 a second for 25 s; it costs +0.5 % to +3.4 % depending on the option.
- **Most of those calls are on descriptors, not paths.** A warm `find /usr` makes 84,900 calls: 60,300 of them are `fcntl`, `close` and `fstat` on directory descriptors, 11,600 `getdents64`, and only 11,700 path calls.
- **Today's time is mostly zfs-server requests,** not system calls: the kernel's name cache (8,192 entries, emptied when full) hits only 13–56 % in a tree walk, and `find` makes 42,000 file-server requests (about 0.64 s of its 1.07 s).
- **A forwarded VFS call costs more than a forwarded null call.** Measured with the stub: +2.0 µs for a call without pointers, **+4.2 µs for a path call** (the path in, a `struct stat` out), +4.7 µs for `getdents64`, +3.3 µs for a 4 KiB read. The copy-in/copy-out table costs 1–2 µs per pointer.
- **The three options** (section 4):
  - **A, everything out** (VFS, caches and the descriptor table in linux-server): warm `find` +227 ms. That is +21 % on this run's 1.07 s, but **+52 % on wave 4's 0.44 s**: over the 35 % budget.
  - **B, out with kernel fast paths.** Measured in two forms:
    - **B-lean:** the kernel keeps only the descriptor table as a table of handles and reads files by handle. Warm `find` +106 ms (+10 %, or +24 % on 0.44 s).
    - **B-full:** B-lean plus a kernel name cache. Warm `find` +83 ms (+19 % on 0.44 s). It helps mainly `ls -lR` and the KDE login (+0.5 % instead of +2.6 %).
  - **C, the VFS stays:** nothing added; the kernel keeps about 15,000 lines of file-system code for good.
- **Recommendation: B-lean.**
  - **What moves:** the whole VFS (path lookup and its caches, mounts, pseudo files, permission policy, `open`, every change) moves to linux-server.
  - **What stays:** **the descriptor table stays in the kernel for good, as a table of handles** (what it already is for server objects since step 2), with file reads, `fstat`, `lseek`, `close`, `dup`, `fcntl` and `poll` on it answered there.
  - No name cache in the kernel, so no cache-coherence protocol beyond per-file attributes.
- **Two prerequisites decide whether wave 7 meets the budget,** whatever the option:
  - **cheaper user-memory copies in the forwarding path** (1–2 µs per pointer today);
  - **a fast call from linux-server to zfs-server.** A ring-3 server's call is Queued today: about 3 µs more per request, which would add 10–17 % to the metadata tools.
  - Both are small, separate kernel tasks for wave 6.
- **Wave 7** splits into five groups in parallel plus one closing group (section 10), about 21–23 agent-days in total (plus 6–8 for the prerequisites), 6–8 days of wall time.

Section 9 lists the decisions, in plain words.

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

These are the couplings step 6a must cut, whichever option is chosen:

| Caller | What it needs from the VFS | In step 6a |
|---|---|---|
| `execve` (`execve.rs`, `process.rs`, `task/exec.rs`) | Resolve the program and its interpreter by path, check exec permission, `#!` scripts, `/proc/self/exe` | Process policy moves only in step 7. Recommended: forward `execve` in 6a; the server resolves the files and calls a `task_exec` primitive (section 7.4) |
| File `mmap` (`mm.rs`) | Descriptor to page-cache object | With a kernel descriptor table (B, C): unchanged. In A: forwarded, and the server calls `as_map` with the object |
| Unix sockets (Group 13, wave 5) | Socket files: `bind` creates one, `connect` looks it up (`vfs_resolve`, temporary) | A function call inside linux-server; the primitive goes |
| `bpf::device_check` (step 2) | Runs in the kernel's `open` and `mknod` | Moves with `open` into the server, which already holds the programs |
| `inotify`/`fanotify`/`fuse` hooks in the ZFS client | Events and FUSE lookups from the path walk | They move in step 6b. Until then the server reports each event to the kernel (a temporary primitive), unless 6b runs in the same wave |
| `/proc` | The process table, memory maps, CPU and memory statistics, signal state | Pseudo files move with the server and need **info primitives** for what only the kernel knows: `task_info(pid)`, `mm_maps(pid)`, `sys_stats()` |
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
- **So a forwarded VFS call adds about +2.0 µs without pointers, +4.2 µs for a path call, +4.7 µs for `getdents64` and +3.3 µs for a 4 KiB read** (boot 1, the dearer case for the pointer calls; boot 3 gives 3.3, 3.3 and 3.4). These are the numbers section 5 uses, so its estimates lean pessimistic; with `fwd=2.4` (boot 3) A's `find` gains another 24 ms. With a cheaper copy (section 8.2) the pointer part could drop from about 2 µs to well under 1 µs.
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

## 4. The three options, precisely

All three keep in the kernel what section 5 of the Linux design already keeps: the page cache, page faults, address spaces, the ELF loader, and the data half of the ZFS client. They differ in what else stays.

### A. Everything out

- **linux-server owns:** path lookup and its caches, mounts, pseudo files, permission policy, the open-file objects, **and the descriptor table** of every Linux process (numbers to objects, close-on-exec, `dup`, `fork`'s copy, `poll`/`select`/`epoll`).
- **The kernel keeps:** the page cache with `obj_*` primitives (`obj_file(ino)`, and `obj_read`/`obj_write` between the page cache and the client's memory), and `as_map` for file mappings.
- **Every descriptor call is forwarded,** including `close`, `fcntl`, `fstat`, `dup`, `lseek`, `read` of cached data, and `poll`/`epoll_wait` on any descriptor.
- **Kernel-owned objects** (memfd, DRM until wave 6 moves it, page-cache objects) are reached through handles the server holds: Group 9's `LX_OBJ_PIN`, turned around.

### B. Out, with kernel-side read-only fast paths

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

### C. The VFS stays in the kernel for good

- The kernel keeps path lookup, mounts, pseudo files, the caches and the descriptor table.
- **What still moves** are the parts of 6a that are on no hot path and mostly self-contained: the udev database and `/sys` generation (`devices.rs`, which writes files into the Linux root), `efivars`, and the policy-only parts of the mount API.
- **Steps 6b, 7 and 8 still happen.** FUSE, Landlock, ACLs and ABAC are tied to the VFS, so in C they would also stay (about 3,500 more lines).

## 5. What each option costs

### 5.1 Added time per workload

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

### 5.2 The rest of the comparison

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

## 6. Cache coherence (option B)

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

## 7. The descriptor table and Group 13's temporary primitives

### 7.1 If the table moves (option A)

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

### 7.2 If the table stays as a table of handles (options B, C)

1. **`FileDescriptor` shrinks as the kinds move.** After waves 5 and 6 the variants left are:
   - `Device` (server objects and kernel devices);
   - the new **file handle** (page-cache object, offset, flags);
   - the console variants, for native programs.
2. **`Vnode` and `File { path }` go:** a pseudo file becomes a server object, and a regular file becomes a file handle.
3. **`fs/fd.rs` keeps** `dup`, `close`, close-on-exec, `fork`'s copy and the server-object bitmap (Group 12's `srv_bits`), and loses every per-kind arm: about 1,260 lines down to 600.
4. **`epoll`, `select` and `poll` stay in the kernel.** They are readiness mechanism over words, and the desktop calls them thousands of times a second (Firefox: 1,676 calls in a 5-second start).

### 7.3 Group 13's temporary primitives (wave 5)

| Primitive | In A | In B |
|---|---|---|
| `vfs_resolve` (socket files, FIFOs) | Goes: the server resolves its own paths | Goes, the same way |
| Descriptor passing (`SCM_RIGHTS` of any descriptor through a server-owned Unix socket: pin a descriptor of the sender, install it in the receiver) | Goes for server objects (one table); stays only to pin **kernel** objects (memfd, DRM) | **Stays, as permanent mechanism:** the table is the kernel's, so the server asks the kernel to move a handle. It should be renamed from "temporary" to the handle transfer primitive |
| `LX_OBJ_FDPATH` (step 2, temporary) | Goes | Goes: the server knows the path of its own objects, and a file handle carries the server's open-file slot |
| `LxCall::ino` (a socket node resolved at trap time) | Goes | Goes |

### 7.4 `execve`, the working directory and `umask`

- **The per-process "fs" record moves with the VFS in A and B:** `chdir`, `fchdir`, `chroot`, `getcwd`, `umask`, and the root and current directory per process (shared on `CLONE_FS`). The server keeps the record, created on `LX_NOTE_FORK`.
- **`execve` resolves files.** Recommended:
  - forward `execve` in 6a, and give the server the `task_exec(thread, exe object, interpreter object, argv/envp, credentials)` primitive now (it is in the design's list for step 7);
  - the rest of step 7 (the process table, the signal policy) still waits for wave 8.
- **The other way, a kernel-to-server "resolve for exec" request,** would make the kernel wait for the server inside `execve`: possible, since `execve` holds no lock there, but it is a temporary primitive that step 7 would delete again.

## 8. Recommendation

### 8.1 Option B-lean: the VFS moves out, the descriptor table stays as a table of handles

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

### 8.2 Two prerequisites (small kernel tasks; best in wave 6)

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

## 9. Decisions for the user

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

## 10. Wave 7 plan (option B-lean)

### 10.1 Before wave 7 (wave 6, beside step 5)

| Task | Files | Agent-days | Tests |
|---|---|---:|---|
| **P1. Cheaper copies:** user copies with a fault fix-up in the trap, straight into the syscall page | `src/lx/copy.rs`, `src/arch/idt.rs` (the fix-up table), `src/lx/mod.rs` (deliver) | 2–3 | `lxfwd` (copy table at page edges, `EFAULT` cases), `sigstress`, lxbench `add_key`/`keyctl_describe` and vfsbench's stubs |
| **P2. Server-to-server direct call** | `src/ipc/service.rs`, `src/task/scheduler.rs` (`direct_call`), `hydra-rt` | 3–4 | A probe from linux-server to zfs-server (as the step-0 probe), the IPC suite tests, net-server throughput, killing either server |
| **P3. Larger kernel name and attribute caches** (drop the oldest instead of emptying) | `src/fs/zfs/mod.rs` | 1 | `fscache`, `vfs`, the vfsbench workloads before and after |

### 10.2 Wave 7: six groups

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

### 10.3 If the user chooses another option

- **A:** add a seventh group for the table move: `poll`/`select`/`epoll` into the server, kernel-object readiness to the server, forwarded `mmap`/`ioctl`/`sendfile`, `fork`/`exec`/exit table handling (5–6 agent-days). 7-6 then deletes `fs/fd.rs` for Linux tasks.
- **B-full:** add the name cache and its coherence protocol to 7-1 (kernel side) and 7-2 (fills and forgets): about 3 agent-days more.
- **C:** one group: P3, `devices.rs` and `efivars` to linux-server, the mount API's policy checks; 3–5 agent-days. Step 6b then shrinks to `io_uring`, `aio`, `inotify` and `fanotify` (FUSE, Landlock, ACLs and ABAC stay).

## 11. Not measured, and limits

- **KVM, not the NUC.** Forwarding costs and zfs-server request costs on real hardware were never measured.
- **Timings are noisy.** Five other groups' VMs shared the PC: the two boots of section 3.1 differ by up to 40 % on single calls, and a warm `find` took 0.81–1.35 s in three boots here against 0.44 s in wave 4 (same call counts each time). That is why section 5.1 shows both baselines. The counts, not the times, are the solid part.
- **The prototype measures a stub,** not a server VFS. The server's real work for `open` or `stat` is assumed to cost what the kernel's costs today; a server-side cache could make it cheaper (fewer zfs-server requests) or dearer (user-space locks).
- **Server-to-server calls were not measured.** Their cost is taken from the design's IPC numbers: Handoff 5.8 µs, Queued in a loop 9.0 µs.
- **The `git` repository was small** (3,851 files); a larger one would scale the counts, not change their mix.
- **Not profiled:** Wine, dpkg on a large upgrade, a large compile.
- **The no-PCID case** was not measured: wave 4's +2.2 µs per forward (against +2.0) would add about 10 % to every A and B number above.

## Appendix: reproducing the measurements

- **Prototype build** (local only, never commit): `git apply tools/vfsbench/prototype.patch`, then build the drivers, the kernel and the ISO as usual. `git checkout -- src userland` removes it.
- **vfsbench:** `gcc -O1 -w -pthread tests/linux/vfsbench.c -o esp/bin/vfsbench.elf` in WSL, then `make build`; `tools/vfsbench/bench.sh NAME` runs it in one VM (as root). The stub tests run only on the prototype build.
- **Workloads:** `esp/bin/g16src.elf` is a tar of 30 files of `tests/linux` plus a Makefile, named `.elf` because the boot import copies only `.elf` files into `/bin`. `tools/vfsbench/work.sh NAME [FIND LSLR GIT TAR GCC APT FF]` runs the workloads (`BENCH=1` runs vfsbench first; `REPO=...` picks what the git repository holds). It installs git, gcc and make in the overlay first.
- **KDE:** `tools/vfsbench/kde.sh NAME ISO` (the ISO in `/opt/u2604/tmp/os16/`).
- **Tables:** `python tools/vfsbench/vfsparse.py LOG` (counts by kind; writes `LOG.vfs.json`), then `python tools/vfsbench/vfscost.py LOG.vfs.json` (the table of section 5.1; per-call costs can be overridden, e.g. `path=2.5`).
- **Logs:** the logs of these runs are in `scratch/g16/logs/` of the worktree (git-ignored, not committed).
