# Plan: making Hydra more of a microkernel

This plan turns the six recommendations in [microkernel-comparison.md](microkernel-comparison.md) into work for parallel agents, organized in waves.
- It was first written 2026-11-17, while the installer round (groups E–H) was finishing.
- It was rewritten 2026-11-18 to cover every wave: what waves 1–3 delivered, what wave 4 is doing, and the planned waves after it.
- Moving the Linux layer is planned step by step in [linux-server-design.md](linux-server-design.md). This document maps those steps onto waves.

## Where things stand (2026-11-24, after wave 10)

| Wave | Groups | Status | Kernel `src/` lines after |
|---|---|---|---:|
| Before | | | 101,973 |
| 1 | IOMMU, retire compositor, concurrent IPC, shell part 1 | Merged, pushed (2c6bc80) | |
| 2 | net-server, shell part 2, Linux-layer design | Merged, pushed, deployed (ecca368) | 91,702 |
| 3 | PCID, Linux layer step 1 | Merged, pushed, deployed (5027d87) | 93,725 |
| 4 | Linux layer step 2, faster forwarding, FreeBSD/macOS step 0 | Merged, pushed, deployed (7ce83b7) | 96,061 |
| 5 | Steps 3–4 (network, Unix sockets, pipes), personality hook, open bugs, designs for display/VFS/services | Merged, pushed, deployed 2026-11-19 (5440095) | |
| 6 | Foundation for separate services: routing, direct calls, restarts, cheaper copies, memory objects, first split (lx-sec), open bugs | Merged, pushed, deployed 2026-11-20 | |
| 7 | The file service: vfs-server, path calls, mounts and namespaces, tmpfs, `/proc` in linux-server, execve front half, restarts that keep state; the two-load hang | Done 2026-11-21 (see "Wave 7") | 108,108 (the kernel copies stay as the switch back until wave 8) |
| 8 | Device services (display, input, sound, terminals), lx-net and lx-ipc split out, zfs-server durability, mount calls into vfs-server | Done, deployed 2026-11-22 | 112,746 (copies kept as switch-backs) |
| 9 | The rest of the file service (FUSE, inotify/fanotify, Landlock/ACL/ABAC, io_uring/aio routing, tmpfs in memory objects), the process mechanism; the kernel's file-code copy deleted (9-C) | Done, deployed 2026-11-23 | 113,823 |
| 10 | lx-proc (process calls, `/proc`, ptrace/perf policy), the change calls and `/dev` into vfs-server, SysV shm into lx-ipc, `tcp_connect`; then 10-C deleted every remaining in-kernel copy and switch-back word | Done 2026-11-24 (10-C: see "Wave 10") | 118,176 before 10-C → about 102,100 |
| 11+ | FreeBSD, then macOS programs, on the shared services | Planned; step 0 done in wave 4 | |

- **Why the line count rose in wave 3:** step 1 added the forwarding machinery (`src/lx`, 946 lines) and PCID (`src/arch/pcid.rs`, 365 lines). It also keeps the in-kernel copy of each moved piece, as the switch back to the kernel (`lx=kernel`), until a later step deletes it.
- **2026-11-18:** the Linux layer (`src/compat/linux`) was 51,444 lines, still mostly in the kernel; the ring-3 drivers and servers (`userland/drivers`) 22,339 lines.
- **After wave 10 (2026-11-24):** no service has an in-kernel copy and there is no switch back (decision 32). `src/compat/linux` is about 37,700 lines of mechanism (descriptor table, page cache, mm, exec's back half, the walk and path calls vfs-server sends back, `/proc` files lx-proc leaves to the kernel, signals, futexes, io_uring/aio rings, the ptrace stop mechanism); `userland/drivers` is about 68,900 lines.

## Ground rules (every wave)

- **Workspace:**
  - one git worktree and branch per group, numbered `E:\os-N` (wave 1 used `D:\os-N`, before the project moved to E:);
  - a `scratch\STATUS.md` per group, in its own worktree and never committed;
  - a brief per group and common rules in `D:\os-mk-shared\briefs\`;
  - a shared notes file `D:\os-mk-shared\NOTES.md` for interface agreements.
- **VMs:**
  - at most 2 test VMs at once (the gatekeeper `vmslot`);
  - all VM files stay on WSL's own disk, never on the 9p mounts `/mnt/d` or `/mnt/e` (the freeze found 2026-11-17);
  - tests use only qcow2 overlays: never boot or write the main pool.
- **Done means:**
  - the full suite passes (75 tests today), three times in a row with `suite_loop.sh`;
  - the IOMMU suite passes (74/75: only the known `lowmem` failure);
  - the host tests pass (663 today);
  - KDE reaches the desktop and runs Firefox, the console works, sound plays, and Wine runs `cmd`;
  - the installer test (stick → disk → first boot → login) still passes;
  - for Linux-layer steps, the performance budget (decision 7) is met.
- **Merging and deploying:**
  - the lead merges, then runs all the checks on the merge;
  - pushing and deploying to the main pool happen **only with your OK**;
  - a deploy is a backup of the pool followed by one verification boot of the real pool with the new kernel.

## Why some groups must go first: the dependencies

| Item | Depends on | Reason |
|---|---|---|
| 1 IOMMU | nothing | New code (`src/arch/iommu.rs`) plus hooks where drivers get DMA memory |
| 3 Retire compositor | nothing | KDE uses `kwin_wayland` on DRM. The in-kernel compositor (`src/wayland`, `wayland_bridge.rs`) is only a fallback |
| 5 Concurrent IPC | nothing, but it is the foundation | Changes how every driver call works (`src/ipc/service.rs`, scheduler hand-off) |
| 4 Shell out | 3 (partly) | Shell commands reference the compositor and video. Also **the whole test harness types commands into the kernel shell**, so the new shell must keep the same commands |
| 2 Network server | **5** | Every packet would cross the IPC path. With today's one-call-at-a-time hand-off, network speed and latency would suffer badly. The Linux socket layer (`inet.rs`, `rtnetlink.rs`, `select.rs`, `io_uring.rs`, `fs/fd.rs`) calls the stack directly today |
| 6 Linux ABI pieces | **5**, and **2** for netlink | A Linux piece moved out needs fast, concurrent calls. netlink talks to the network stack |

For the Linux-layer steps (waves 3 and later), section 7 of the design sets the order. Step 1's forwarding machinery comes first, and step 2's server-object descriptors come before any descriptor type moves.

## The waves

### Wave 1: four groups in parallel (done)

**Group 1: IOMMU (Intel VT-d)**
- **Plan:**
  - read the firmware's DMAR table;
  - give each ring-3 driver its own DMA domain;
  - turn on DMA remapping;
  - fall back cleanly without an IOMMU;
  - test with a q35 harness option and a rogue-DMA test.
- **Result:**
  - per-driver DMA domains, and harness options `--machine q35`, `--iommu`, `--iommu-test`, `--iommu-off`;
  - the rogue-DMA test is blocked and logged;
  - the IOMMU suite has one known failure (`lowmem`: on q35 the firmware loads the kernel at 0x140000000, a memory-layout issue);
  - page grants are mapped into the driver's domain (a11f4a4).
  - **Not yet tested on the NUC:** its firmware needs VT-d turned on.

**Group 3: retire the in-kernel compositor and console graphics**
- **Plan:**
  - remove `src/wayland`, `wayland_bridge.rs` and the compositor paths in DRM, keyboard, mouse and evdev;
  - reduce `src/video` to an emergency text console and the boot splash.
- **Result:**
  - 3,754 lines removed, and the kernel image shrank from 8.8 to 4.9 MB;
  - the console takes the screen back 10 s after KDE's last display handle closes.

**Group 5: concurrent IPC and page grants**
- **Plan:**
  - queued, asynchronous requests next to the strict hand-off;
  - page grants instead of copying through the 256 KiB window.
- **Result:**
  - requests carry IDs, with two call modes (`Handoff` and `Queued`) and page grants (syscalls 33/34);
  - grants are used for single-block AHCI I/O;
  - the main disk path keeps the hand-off because of file-system locks;
  - disk read speed went from 74 to 77 MB/s.

**Group 4 (part 1): get the shell ready to leave the kernel**
- **Plan:**
  - decouple the boot-file helpers;
  - design an admin interface;
  - build a ring-3 `hydra-shell` skeleton.
- **Result:** `src/fs/bootfs.rs`, the admin interface (`SYS_ADMIN` 40, [shell-admin-interface.md](shell-admin-interface.md)) and the skeleton.

### Wave 2: after wave 1 (done)

**Group 2: network protocols as a server**
- **Plan:** move `src/net` (TCP, UDP, IP, ARP, DHCP, DNS) into a ring-3 `net-server`, with the Linux socket layer as its client.
- **Result:**
  - `net-server` runs at endpoint 0x28 and the kernel's client is `src/net/client.rs`;
  - a new doorbell system call (35);
  - socket readiness lives in a status area shared with the kernel;
  - downloads went from 17 to 20 MB/s and a small web request from 502 to 2.7 ms, while UDP round trips are 6–9 % slower;
  - killing the server during a download fails it cleanly, and the server restarts.

**Group 4 (part 2): move the shell commands out**
- **Result:**
  - the console is now `hydra-shell`, and admin interface v2 has about 45 operations;
  - `src/shell` is now only the 244-line emergency prompt, which appears after 3 quick shell deaths or with the boot option `emergency`;
  - every test script works unchanged.

**Group 6 (step 0): design for moving the whole Linux layer out**
- **Result:** [linux-server-design.md](linux-server-design.md):
  - one ring-3 Linux server;
  - about 6,000 lines stay in the kernel (trap, memory and faults, futex, threads, signal delivery);
  - about 25 new kernel primitives;
  - a measured performance budget;
  - 8 steps, about 53–64 agent-days.

### Wave 3: Linux layer step 1, plus PCID (done)

**Group 8: PCID (tagged TLB)**
- **Result:**
  - address-space switches keep their TLB entries, all CR3 loading goes through one helper (`pcid::load_cr3`), and shootdowns are per address space;
  - a boot self-test checks it, and it can be turned off with `nopcid`, `\hydra\nopcid` or fw_cfg `opt/hydra/pcid=off`;
  - IPC round trips went from 7.4 to 5.5 µs (Handoff) and from 19.3 to 16.6 µs (Queued), and a warm `find` from 0.69 to 0.53 s.

**Group 7: step 1 of the design**
- **Result:**
  - a ring-3 `linux-server` (endpoint 0x29, 4 workers) with a forwarding table, per-thread syscall pages, client memory primitives, notifications and a direct switch (vector 0x82);
  - `keys` moved into the server, with a switch back to the kernel (`lx=kernel`);
  - the crash policy works: killing the server under KDE ended 363 threads, and the login screen was back in 12 s;
  - a forwarded call adds 2.5 µs with PCID (budget 3 µs) and 4.0 µs without it;
  - calls that were not moved are unchanged, and KDE starts in 28–32 s.
- **Not met:** two threads making forwarded calls are slower per call than one, because the kernel lock serializes the kernel part. Wave 4 takes this on.

### Wave 4: Linux layer step 2, a faster forwarding path, and step 0 for FreeBSD/macOS (done, 2026-11-18)

**Group 9: step 2 of the design** ([linux-server-design.md](linux-server-design.md) section 12)
- **Server-object descriptors:** linux-server owns them, and their readiness lives in words shared with the kernel, so `poll`, `select` and `epoll` (edge-triggered too) need no call to the server. There are 2,048 slots.
- **`sig_post`** and native calls 60–61. Blocking calls answer "pending" and are finished later, so 16 callers blocked in `mq_receive` do not hold up anything else.
- **Moved:** message queues, System V messages and semaphores, and `bpf`. bpf's device programs are handed back to the kernel, which still decides device opens itself (programs that use maps are refused).
- **An old bug found during the checks:** the kernel's `FUTEX_WAKE_OP` changed its second word without an atomic operation. This crashed `kwin_wayland` about one KDE start in five (Qt keeps that word on a thread's stack). Fixed, with a new suite test (`wakeop`).

**Group 10: a faster forwarding path** (design section 13)
- **The copy-in/copy-out table:** the kernel copies pointer arguments into the syscall page.
- **Forwarding without the kernel lock:** two threads are now faster per call than one, so the concurrency rule is met.
- **Global kernel pages:** with a self-test and an off switch (`noglobal`).
- **After the merge,** it also put step 2's calls on the lock-free path.

**Group 11: step 0 for FreeBSD and macOS programs** ([personality-design.md](personality-design.md), see "Waves 10–13").

**Measured on the final merge** (KVM, 2 CPUs; µs; "in-kernel" is the same build with `lx=kernel`):

| Call | In-kernel | Forwarded | Added |
|---|---:|---:|---:|
| Null call | 0.65 | 2.87 | +2.2 |
| `keyctl` (one thread / two threads) | 0.72 / 0.77 | 3.40 / 3.00 | +2.7 / +2.2 |
| `semop` | 1.28 | 3.54 | +2.3 |
| `mq_send` + `mq_receive` (2 calls) | 2.22 | 7.62 | +2.7 per call |
| `msgsnd` + `msgrcv` (2 calls) | 2.61 | 7.57 | +2.5 per call |
| bpf map lookup | 1.46 | 4.84 | +3.4 (reads two more pointers the table cannot describe) |

- Calls that were not moved are unchanged.
- Fresh KDE logins settle in 25–30 s.

**Checks on the final merge:**
- full suite 78/78, and 3 runs in a row with no freeze;
- IOMMU suite 77/78 (`lowmem` only);
- host tests 663;
- KDE with Firefox, console, sound and Wine;
- KDE with USB input;
- 4 fresh KDE logins with no crash;
- the installer test (stick → disk → first boot → new user's desktop).

**Kernel size:** `src/` grew to 96,061 lines, because each moved piece's in-kernel copy stays as the `lx=kernel` switch back. Wave 5 deletes the copies of waves 3 and 4.

### Waves 6–10: separate services (replaces the table below, 2026-11-19)

Decision 9 and the user's answers of 2026-11-19 (decisions 10–18) replace the one-server step plan below with [linux-services-design.md](linux-services-design.md) section 9. The table below is kept for history: wave 5 was done as written; its waves 6–9 rows are superseded.

**Wave 6 (started 2026-11-19, base 5440095), seven groups:**

| Group | Work | Worktree / branch |
|---|---|---|
| 19 (R1) | Routing core: service registry, per-service request tables, workers and readiness, the service runtime in `hydra-rt`, per-service switch back, a test service | E:\os-19, `mk-route` |
| 20 (R2) | Direct call between services (syscalls 70/71), also to zfs-server and net-server; linux-server's net-server calls use it | E:\os-20, `mk-dcall` |
| 21 (R3) | Restart support: kept state, the three crash classes, the 30 s ladder, re-sending safe calls | E:\os-21, `mk-restart` |
| 22 (P3) | Cheaper argument copies (fault fix-up, copy straight into the syscall page) | E:\os-22, `mk-copy` |
| 23 (M) | Memory objects: `mmap` of service objects, objects kept across a restart, sharing between services | E:\os-23, `mk-memobj` |
| 24 (X1) | First split: keys and bpf into `lx-sec` (keys restart invisibly); merges last | E:\os-24, `mk-lxsec` |
| 25 (B) | Open bugs: sound underruns, linux-server on 1 CPU, the 2,048-object limit, `timerfd_settime`/bpf lookup over budget, the slirp stall, the cold-cache polkit hang | E:\os-25, `mk-fixes2` |

Merge order: 19 first; then 22, 23, 20, 21, 25; 24 last.

**Carried into wave 7 (found in the wave 6 merge checks, 2026-11-20; the user's call: wave 7):**
- **Forwarded mode on 1 CPU:** linux-server now starts there (Group 25's svcrt fix), but `lxfwd`'s signal stress gets too few timer signals (`lx=kernel` on 1 CPU: ~300 of 300, 0 errors), and one run hung the whole session in its first `lxfwd`. Never worked before wave 6 (no forwarding on 1 CPU at all); the NUC has 2 cores. Tools: scratch/smp1.sh, smp1k.sh (lx=kernel), smp1s.sh (sigstress numbers).
- **FIXED 2026-11-21 (wave 7, Group H, 5314b95): the cause was the direction flag. `common_trap_handler` and `asm_direct_switch` never cleared DF; an interrupt inside compiler_builtins' backward `memmove` (`std; rep movs; cld`) ran the handler and the scheduler with DF=1, so every memcpy/memset there ran backwards (writing below its destination: freed heap data in another thread's stack). Both stubs now start with `cld`; regression test tests/host-t32/tests/entry_df.rs; the two loads 3/3 clean, all 11 load combinations clean. Open from H: `netbench lolat` reports FAILED when net_server is killed under it (likely expected); `lxsec hammer` sometimes counts 1 error across an lx_sec kill (candidate for B).** Original entry: whole-system hang under two concurrent loads (a pre-existing bug: wave 5, the deployed one, has it too; deployed wave 6 anyway at the user's call, 2026-11-20).** `restart 40` (linux-server's null/pending/copy/keyid/obj/pipe calls, 8 threads) plus `lxsec hammer 4 40` (4 keyctl threads) freeze both CPUs within seconds (each alone, and every other pair of the kill-test loads, runs clean). A CPU ends up executing with RSP inside another live thread's kernel stack (always the same addresses for a given build), on memory holding freed data (region-record `BTreeMap` nodes; with heap poisoning on, 0xDD): the callee-saved registers come back as that data and it jumps into data, under the scheduler lock, and the other CPU then spins on that lock. Ruled out with instrumentation (none fired): a task resumed on two CPUs or while another CPU leaves its stack, kernel stack overflow, a saved kernel RSP outside the task's stack at a switch, a syscall entered on a foreign stack, a bad exception-return frame, heap overruns (red zones), double frees, wrong-size frees, writes into freed large blocks, overlapping large allocations, small frees of stack pointers, and freeing a live task's stack. Next ideas: bisect older waves with this load; a QEMU gdbstub hardware watchpoint on the victim stack range. Tools and notes: scratch/kill6e.sh (`LOADS="..." bash kill6e.sh NAME`: monitor socket, register/stack sampling on a stall), scratch/wave6/hang-debug-instrumentation.patch (all the detectors), the kernel's lock-free `[!] KERNEL ...` fault lines (kept, commit after 270bb9a).
- **Open findings of the test wave (2026-11-20; tests marked `#[ignore = "BUG: ..."]`):** `fs/fd.rs` a `dup` of a by-path file gets its own offset instead of sharing the open file (tests/host-t33 `dup_of_a_path_file_shares_the_open_file`; the fix touches `File { .. }` constructors in several areas); `compat/linux/abac.rs` the what-if `evaluate` treats two equal never-interned values as different (host-t33 `evaluate_matches_equal_unseen_values`); `task/scheduler.rs` a dead current task is set back to Running when nothing at all can run (host-t31 `a_dead_current_task_is_never_made_running_again`; unreachable while the idle task is ready). Notes: the heap's size-class lists accept a double free silently and hand the block out twice (Group 32; relevant to the hang above); `tests/linux/userfaultfd_test.c` checks `handled == 5` before the handler thread increments it (a race in the test, seen once); the PIT's 18 Hz floor really runs at 18.2 Hz.
- **Restart from the live session with the stick pulled:** logind gets `Reboot` and nothing follows for 220 s+ while the live system's reads from the missing stick fail (`ZFS: disk read failed`). Not logind's polkit wait: its time limit fires on this build (polkit stopped: "polkit did not answer" after 25 s / 120 s, scratch/lgd6.sh). Group 25's own runs of the same test hung the same way. The installer's "Restart now" after an install works. Tools: scratch/inst6/livestress.sh NAME 1.

### Wave 7: the file service (done, 2026-11-21)

Groups H (the two-load hang), 7-1 (vfs-server core), 7-2 (path calls, kernel file handles), 7-3 (mount tables, namespaces, tmpfs), B (carried-over bugs), then 7-4 (`/proc` and `/sys` in linux-server, info primitives), 7-5 (execve front half, socket names, FIFOs), 7-6 (restart keeps programs and state), and 7-7 (closing). Every branch got a Gemini pre-merge review (decision 24); each finding was checked against the code before anything was changed. Stages 1 and 2 deployed 2026-11-21 20:00 (f07ee85).

- **Result:** under a KDE login, vfs-server serves about 180,000 file calls and the kernel keeps about 700 (before 7-7: 47,000 served, 136,000 kept, almost all because of xdg-document-portal's FUSE mount in the initial namespace). vfs-server walks with read-only copies of the kernel's mount tables; the kernel stays their one owner this wave (7-7's decision). vfs-server restarts without ending programs and keeps its mount tables, tmpfs data and lock table (7-6).
- **Budget:** real workloads within budget (KDE login settled 30.1 s vs 30.2 s with `lx.vfs=kernel`; warm `find` about +12%, tar +2%). Single calls over the +3 µs per-call budget (stat family +3.2–3.8 µs, open+close +4.1 µs, open of a directory +5 µs); fork+exec at the 2.15 ms limit. Served `/proc` opens about +18 µs.
- **Fixed on the way:** the direction-flag hang; the test wave's `dup` offset bug; the in-kernel FIFO's two bugs; registration/teardown race in the supervisor; logind policy gaps; two flaky host tests.

**Carried into wave 8:**
- Move the mount calls into vfs-server and delete the kernel's file-code copies (needs vfs-server tmpfs handles and FUSE in a service); then exec front halves and socket names for callers in their own namespace.
- **zfs-server loses up to ~5 s of acknowledged changes when it is killed** (it answers once a change is in the in-memory transaction group; commits every 5 s). Fix: an intent log in a kept memory object replayed before going online, or a commit before answering metadata changes.
- Per-call cost of the stat family and open over budget; fork+exec at the limit; slow served `/proc` opens (a kernel-held snapshot handle).
- The ladder resets vfs-server's kept state on a second crash within 30 s (tmpfs data lost): by design, revisit if it bites.
- Still open from before: the live-stick restart hang (B's item 5); the 1-CPU forwarded signal shortfall; the loopback TCP stall until net-server restarts; the installer test with a stick image built from this tree.

### Wave 8: device services, the lx-net/lx-ipc split, zfs-server durability (2026-11-22)

Stage 1 (deployed a6729b7): display, input, sound and terminal services (D, I, S, T), lx-net and lx-ipc split out of linux-server (X2), zfs-server intent log (Z). Stage 2: device remove/add announcements, so input and sound come back after a second crash (H); vfs-server decides mount, umount2 and pivot_root and makes tmpfs mounts, the kernel's table a write-through copy (F); a profiling aid (P); the remove-the-stick prompt at the end of a live session, mlock'ed logind, the zfs log dropping deleted files' writes when full (B). Gemini was turned off by the user mid-wave; pre-merge reviews were done by a Claude (Sonnet) reviewer; stage 2 ran one group at a time on low usage, H/F/P/B without a separate review.

**Carried into wave 9:** the per-call budget is still missed (stat family +3.2 µs, open+close +3.8 µs, served `/proc` opens +25 µs; P's experiments in E:\os-52\scratch\p\wip_clean.patch did not measure faster); tmpfs data in memory objects (needs a kernel handle type); zfs append-then-delete still ~5x slower than without the log; the one-off `crashexit` hang (never reproduced); stage-2 checks skipped for usage (kderep, Wine, suite_loop, kill tests of every service under KDE).

**8-C closing (2026-11-22, done by the lead on low usage, no agent):** kernel `src/` lines 112,746 (108,108 after wave 7; the in-kernel copies of every moved piece stay as the switch back). Budget: P's measurements on the near-final tree stand (above). Device crash test under KDE on the final tip (`tools/devcrash/devcrash.sh c8 input+sound+tty+display`): input killed twice within 30 s (Transparent, then FailObjects; "remove"/"add" announced, logind re-handed the devices), sound killed twice (playback went on, longest gap 336 ms), 0 desktop crashes; the tty and display steps did not run in that VM (tested earlier by Groups T, D and H). Not done: a kill of every service in one KDE session (vfs-server, zfs-server, lx-net, lx-ipc were kill-tested by their groups).

### Wave 9: the rest of the file service, then its kernel copy deleted (done, 2026-11-23)

Groups 6b-1 (inotify and fanotify into vfs-server), 6b-2 (FUSE as a vfs-server back end), 6b-3 (Landlock, ACL and ABAC checks in vfs-server), 6b-4 (io_uring and aio forwarded to each descriptor's owner), 7a (the process mechanism), X3 (lx-ipc restarts invisibly), M (tmpfs data in memory objects), P2 (per-call cost), then 9-C (closing). Pre-merge reviews by a Claude (Sonnet) reviewer (Gemini paused). Deployed in three steps; the last, 32f584e, on 2026-11-23 (pool backup `pre-w9d`).

- **Result:** under KDE + Firefox + Dolphin, vfs-server serves about 267,000 file calls; the kernel's file code answers about 8,000, almost all sent back by vfs-server (creates, truncates, devices, `/dev`, read-only mounts, FUSE leftovers). The file service has no switch back: `lx.vfs=kernel`, `lx.vfsmnt=kernel`, `lx.fuse=kernel`, `lx.policy=kernel` and `lx.tmpfs=pool` are ignored with a boot-log line, and `lx=kernel` now takes every *other* service back. File calls wait for a restarting vfs-server (the 30 s ladder) instead of the kernel answering. The kernel's own inotify/fanotify instances and FUSE client are deleted. Kernel `src/` 115,841 → 113,823 lines.
- **Found on the way:** since wave 7 a sticky `fanotify::ANY` flag sent every suite test after `fanotify` down the kernel path; fixed by 6b-1, so the suite (now 94 tests) covers vfs-server for real.
- **Budget (P2):** stat family and open+close now about at the +3 µs budget. Still over: served `/proc` opens (+22 µs) and `tcp_connect` (+12%).
- **Checks on 32f584e:** suite 94/94 forwarded, with `lx=kernel` and with the IOMMU; 2,735 host tests; KDE 2 boots clean (settled 27–30 s); every service killed under KDE with the desktop staying up (9-C); installer test passed.

**Carried into wave 10:** the change calls vfs-server still sends back (creates, truncates, mknod, link, xattrs, utimes, `/dev`, EROFS) move into vfs-server, then the kernel walk and path calls can go; FUSE `mount(2)` in the initial namespace (so `mount.rs` can go); served `/proc` (lx-proc, a kernel-held snapshot handle) and `tcp_connect` over budget; io_uring rings into linux-server; delete wave 8's device copies and the lx-net/lx-ipc copies (decision 30).

### Wave 10: the process service, the last file calls, and the cleanup (approved 2026-11-23, decisions 31–33)

Built from [linux-services-design.md](linux-services-design.md) section 9.5 plus what wave 9 carried over. Up to four groups at once, Sonnet pre-merge reviews, a deploy after each stage.

**Stage 1 (four groups, independent of each other):**

| Group | Work | Agent-days |
|---|---|---:|
| **7b-1** | lx-proc as its own service: `setuid` family policy, `prctl`, `unshare`/`setns` orchestration (direct calls to each namespace owner), UTS names, accounting, `syslog`; restarts invisibly (decision 12); on 7a's primitives | 4–5 |
| **V1** | The change calls into vfs-server: creating and truncating opens, `O_TMPFILE`, `mknod`, `link`, xattrs, `utimes`, the remaining `chown`/`chmod`, read-only-mount answers; vfs-server stops sending them back (9-C's counter shows what is left) | 4–5 |
| **8-2** | System V shared memory into lx-ipc on memory objects (semaphores and message queues are already there) | 2–3 |
| **N** | Carry-over: `tcp_connect` back under budget (the previous connection's close off the next call's path); `io_uring` rings into linux-server | 3 |

**Stage 2 (after 7b-1 is merged):**

| Group | Work | Agent-days |
|---|---|---:|
| **7b-2** | `/proc` from linux-server to lx-proc, on the kernel info primitives; served `/proc` opens back under budget (the kernel-held snapshot handle) | 3–4 |
| **8-1** | ptrace and perf policy into lx-proc (the stop mechanism stays in the kernel) | 3–4 |
| **V2** | `/dev` lookups and FUSE `mount(2)` in the initial namespace into vfs-server; the kernel's `mount.rs` shrinks to what boot needs | 3 |

**Then 10-C (closing):** delete the in-kernel copies of waves 6–8 (display, input, sound, terminals, lx-net, lx-ipc, lx-sec) and their switch-back words; delete the kernel walk and path calls that nothing sends back any more, keeping only the read-only walk boot needs before vfs-server runs; linux-server reduced to what is left (`io_uring`/`aio`); line counts, the final budget run, a kill test of every service under KDE in one session, the installer test.

About 26–32 agent-days, eight groups.

**10-C as done (2026-11-24, E:\os-70, `w10-close`):**
- **Map first:** under KDE + Firefox + Dolphin with a temporary counter, 525,978 calls were forwarded and no in-kernel copy answered any (the only moved numbers reaching the kernel were lx-proc's approved `prctl`/`unshare` redirects, i.e. mechanism).
- **Deleted:** every switch-back word (`lx=kernel`, `lx.<name>=kernel`, `lx.<name>=linux`, `lx.uring=kernel`: ignored with a boot-log line), the "service not running" fallbacks into the kernel, and the copies: keys, POSIX queues, SysV semaphores/messages, bpf objects, Internet/Unix/netlink sockets, pipes/eventfd/signalfd/timerfd/pidfd objects, the kernel's DRM, evdev, ALSA and terminal devices, the process-policy arms lx-proc serves, the kernel's socket client in `net/client.rs`; linux-server's co-located lx-net/lx-ipc/lx-sec builds. Kernel `src/` 118,176 → about 102,100 lines; 449 host tests of deleted code went with it (2,890 → 2,441, all passing).
- **Kept (mechanism, see `docs/src/linux-server.md`):** the walk and path calls (vfs-server still sends back the kernel-kept `/proc` files, `mount`/`pivot_root` and FUSE changes), `mount.rs`, the io_uring/aio rings (decision 34), the ptrace stop mechanism, the device services' kernel side. linux-server stays (`/sys`, exec's front half, test calls), now FailObjects.
- **Checks:** suite 100/100 forwarded, with `--lx kernel` (now only logged as ignored) and with the IOMMU; suite_loop; host crates; budget A/B against a2c070d (2 rounds alternating): every call within noise (forwarded `lx_null` 2.8 µs both, stat 4.6 vs 4.7–5.2, open+close 7.0–7.1 vs 7.3–7.9, `tcp_connect` 110 vs 108–111, fork+exec 2.05–2.17 ms vs 2.09 ms); every service killed once in one KDE session (desktop, Firefox, Dolphin, sound and Wine fine, 0 crashes). The installer test was not run: the lead runs it after the merge.

### Wave 11: consolidation before other systems (approved 2026-11-24, decisions 36–38)

Chosen by the user over starting FreeBSD at once: close what waves 6–10 left open, then prove it on real hardware. Up to four groups at once, Sonnet pre-merge reviews, a deploy after each stage.

**Stage 1 (four groups):**

| Group | Work | Agent-days |
|---|---|---:|
| **R** | Restart robustness: Firefox's SIGSEGV in libxul when vfs-server is killed under KDE (seen on wave 9 and 10 builds); lx-sec reads its cgroup device list back from the kernel after a reset (today `BPF_PROG_DETACH` fails after a second quick crash); the hang after repeated ptrace attach/detach/kill cycles (`ptperm bench` twice); a tty read in flight at a tty-server crash | 3–4 |
| **F** | The last walks into vfs-server: changes inside FUSE mounts (create, mkdir, unlink, rename, setattr) and `fstatfs` on FUSE handles, `/dev/pts` listing, efivars writes, bubblewrap's device binds in its own namespace | 3–4 |
| **P** | The `/proc` files the kernel still serves into lx-proc: `fd/`, `fdinfo/`, `exe`/`cwd`/`root` links, `mountinfo`/`mounts`, `ns/`, `cgroup`, `auxv`, `net/`, directory listings, and callers in their own PID or user namespace (ID translation); re-reading `/proc` back under budget if possible | 4–5 |
| **H** | Real hardware, prepared: a NUC checklist and a stick built from this tree; boot-log capture without a serial port (a log file on the stick's EFI partition, or netconsole); the drivers the NUC needs (AHCI, e1000e, xHCI, HDA, IOMMU/DMAR tables of a 2014 machine) checked against QEMU's q35 models; the power path: restart with the stick pulled early (the old hang), poweroff | 2–3 |

**Stage 2:** the NUC run itself (the user boots the stick and installs; H's tools collect the logs), fixes for what it finds, and **11-C closing**: delete the kernel's walk and path calls that nothing sends back any more (keeping only what boot needs before vfs-server runs) and the kernel's `/proc` copy; line counts; the final budget and kill tests; the installer test (`MODE=prompt`).

Also carried, if a group has room: lx-ipc's SysV `shmget`/`IPC_STAT` cost (+4 µs; per-segment kept records instead of the whole-table rewrite), the 1-CPU forwarded signal shortfall.

About 15–20 agent-days.

### Waves 5–9: the rest of the Linux layer (one-server plan, superseded after wave 5)

Each wave does one or two steps of section 7.2 of the design. Two habits carry through every step:
- **Cleanup:** each wave deletes the in-kernel copies of the previous wave's moved code, once that wave has been deployed and used without problems.
- **Line count:** after each wave, measure the kernel's line count again and update the table at the top.

| Wave | Steps (design 7.2) | What moves | Needs first | Agent-days |
|---|---|---|---|---:|
| **5** | **3:** network sockets and netlink, as net-server's client<br>**4:** Unix sockets, pipes, event descriptors (in parallel: different files)<br>**Personality hook** (a small third group, see "Waves 10–13") | `inet`, `sockopt`, `rtnetlink`, `netlink` (about 2,900 lines); `unix`, `socket`, pipes, `eventfd`, `timerfd`, `signalfd`, `pidfd` (about 3,300); nothing moves for the hook | Wave 4's server-object descriptors | 4–5, 5–6 and 3–4 |
| **6** | **5a:** sound<br>**5b:** terminals, DRM and input | `snd` (2,137); `tty`, `pty` (1,583); `drm`, `evdev` (2,309) | **Your decision:** where sound and the display go | 6–7 |
| **7** | **6a:** VFS, mounts, pseudo files, the descriptor table (alone: the largest and riskiest step) | about 17,000 lines | **Your decision:** whether the VFS fast paths stay in the kernel | 12–14 |
| **8** | **6b:** the rest of the file side<br>**7:** processes and signal policy (in parallel) | `io_uring`, `aio`, `inotify`, `fanotify`, `fuse`, `landlock`, `acl`, `abac` (about 7,150); `proc` policy, `process`, `execve`, `ns`, `limits`, timers, `admin` (about 5,900) | Step 6a | 5–6 and 7–8 |
| **9** | **8:** debugging and the last pieces, plus the final cleanup | `ptrace` policy, `perf`, `userfaultfd` glue, System V shared memory; the dispatcher shrinks to the trap and the local calls | Steps 6b and 7 | 4–6 |

- **Total left after wave 4:** about 46–56 agent-days of group work for waves 5–9 (including the personality hook), plus the lead's merges and checks.
- **The end state:** about 45,000 lines moved out. The kernel keeps the trap, memory management and faults, futex, threads, signal delivery and the ptrace stop mechanism (about 6,000 lines of Linux support), and should be about 50,000 lines in total.

**Wave 5 detail:**
- **Step 3:** the Linux server becomes net-server's client directly, using the protocol wave 2 shaped for this.
  - Tests: `apt-get update`, Firefox loading pages, download throughput before and after, and killing net-server and linux-server.
- **Step 4:** pipes and Unix sockets carry D-Bus and Wayland, so their speed shows at once on the desktop. Budget: pipe and Unix round trips no slower than today.
- **Temporary primitives:** step 4 adds two, path lookup for socket files and descriptor passing between processes. Step 6a removes them.
- **Personality hook:** small kernel changes that prepare for programs from other systems (waves 11–13). It changes no behavior for Linux programs. Section-by-section design: [personality-design.md](personality-design.md) (about 1,070 kernel lines).
  - **First:** today's kernel starts FreeBSD programs as Linux programs, and they crash at once (FreeBSD enters programs with a different stack layout). Until a FreeBSD front end exists, they must fail cleanly with `ENOEXEC`.
  - Each process gets a personality, chosen from its ELF marking (the OS/ABI byte and the ABI note) or by its loader. Linux stays the default.
  - The forwarding table is looked up per personality instead of being one global Linux table. The cost must stay one load per system call.
  - The trap returns results in the personality's convention. Linux returns a negative error number; the BSDs set the carry flag and return a positive error.
  - Signal numbers and the signal frame are chosen per personality.
  - Tests: the full suite, the forwarded-call budget unchanged, and a tiny test program marked as a non-Linux personality whose calls reach a stub table.

**Wave 6 detail:** the natural home for DRM and input is a display/input server, not necessarily the Linux server. Sound can live in the Linux server or next to the hda driver. The same display server could later serve native (non-Linux) programs, such as a native Wine back end or Mac programs.

**Wave 7 detail:**
- If the VFS moves out completely, the warm-`find` budget (at most 35 % slower) rests on wave 4's faster forwarding.
- If its fast paths stay in the kernel, the step is smaller, but the kernel keeps file-system code for good.
- Wave 4's numbers will show which is realistic, so this decision is best made after wave 4.

### Waves 10–13: programs from other systems (planned)

By the end of wave 9, `linux-server` owns the files, descriptors, sockets, pipes, processes and signal policy. It is then really a general POSIX server with a Linux front end. These waves use that to run FreeBSD and macOS programs **without Linux as an intermediary**: their calls go to a shared core, not through Linux system calls.

**Why FreeBSD and macOS go together.** The BSD half of macOS (system calls, sockets, signals, `kqueue`, `sysctl`) came from FreeBSD. The two are not binary-compatible: system call numbers, structure layouts and constants differ. But they share one model, which differs from Linux in the same ways:
- `kqueue` instead of `epoll`;
- `sysctl` instead of most of `/proc`;
- socket addresses that carry their length;
- errors returned in the carry flag.

So one **BSD core** serves both, with a thin front end each. macOS adds Mach on top.

**Why FreeBSD first.** It is the easier proving ground for the BSD core:
- its user space (C library, base system, `pkg` packages) is open source, and installs as a `/freebsd` root like today's `/ubuntu`;
- its programs are ELF, which Hydra already loads;
- its desktop programs use the same Wayland, Mesa and Qt stack as Linux. They can draw through the KDE compositor over a shared Unix socket, so graphics come almost free;
- it has its own test suite (`kyua`) to measure progress.

**Step 0 is done** (wave 4, Group 11): [personality-design.md](personality-design.md), with full tables of FreeBSD's 409 and macOS's 455 system calls and 62 Mach traps ([FreeBSD](personality-freebsd-syscalls.md), [macOS](personality-macos-syscalls.md), [error numbers](personality-errno.md)), scripts in `tools/personality/` and test programs in `tests/freebsd/` and `tests/macos/`. The estimates below are its revised ones.

| Wave | What | Needs first | Agent-days (rough) |
|---|---|---|---:|
| **10** | **The core split:** `linux-server` becomes a shared POSIX core (VFS, descriptors, sockets, pipes, processes, signals) with Linux as one front end. No behavior change for Linux programs | Wave 9 | 6–8 |
| **11a** | **FreeBSD programs, part 1:** the FreeBSD front end, the `/freebsd` root from `base.txz`, the dynamic linker (30 calls) and the base system's command-line tools | Waves 5 (hook) and 10 | 10–13 |
| **11b** | **FreeBSD programs, part 2:** `kqueue`, threads, `sysctl` in full, `pkg`, graphical programs through the KDE compositor, and **Windows programs through FreeBSD's own Wine package** (Windows without Linux in the path) | Wave 11a | 11–15 |
| **12** | **macOS command-line programs (Intel builds only):** a Mach-O loader, a macOS front end on the BSD core, a `mach-server` for Mach traps and ports (started from darlingserver), and a root of Darling's open-source frameworks | Wave 11 | 35–55 |
| **13 and later** | **macOS graphical programs:** Darling's AppKit through its Wayland back end, CoreGraphics; Metal needs a Metal-on-Vulkan layer and a GPU driver | Wave 12 | not estimated |

**Wave 11 detail, the FreeBSD front end:**
- **Threads and locks:** `thr_new` and `_umtx_op`, mapped onto the kernel's existing thread and futex primitives.
- **`kqueue`:** built on wave 4's readiness words.
- **`sysctl`:** FreeBSD's C library asks it for many things: the CPU count, the OS version, random bytes.
- **File and socket calls:** FreeBSD's `stat`, `getdirentries` and `fcntl` layouts and the socket constants.
- **Security features:** Capsicum (`cap_enter`) and jails, first as stubs, later mapped onto Hydra's ABAC and namespaces.
- **Tests:** the base system's tools, `pkg install`, parts of `kyua`, and a graphical FreeBSD program on the KDE desktop.
- **Not included:** FreeBSD's own `zfs` and `zpool` tools. They talk to a kernel module, which Hydra's zfs-server does not provide.

**Wave 12 detail, macOS:**
- **The bottom layer:** Darling's frameworks are macOS code. Its Linux-emulating bottom layer (about 39,000 lines) can be dropped, not rewritten: with a macOS personality, Apple's original system-call stubs work unchanged.
- **Mach:** Hydra's IPC (endpoints, request IDs, page grants) is close to Mach's ports and out-of-line memory. `darlingserver` (with its XNU Mach code) is the natural start for `mach-server`, built as a FreeBSD-personality program after wave 11.
- **Kernel pieces:** a Mach-O loader (about 1,200 lines), a commpage at its fixed address (which lies in Hydra's default stack area, so macOS programs get a lower stack top), the 4 GiB `__PAGEZERO` floor, TLS in `%gs`.
- **Graphics are the hard part.** Darling's AppKit has a Wayland back end, so it could draw through the KDE compositor, but AppKit and CoreGraphics are incomplete, and its GUI pieces did not build in step 0 (they need newer compilers and libraries). Metal needs a Metal-on-Vulkan layer and a GPU driver, which Hydra does not have. Command-line Mac programs are the realistic first goal.
- **Limits:**
  - only Intel or universal binaries run on x86_64 machines, and macOS 26 is the last macOS for Intel;
  - Apple's own frameworks cannot be shipped.

**Windows programs without Linux** come before macOS, in wave 11b: FreeBSD's own Wine package runs on the FreeBSD front end. Step 0 found this cheaper than a separate native Wine back end.

**A shortcut, if FreeBSD programs are wanted sooner.** Translate FreeBSD calls into Linux calls inside `linux-server`, as FreeBSD's own "Linuxulator" does in the other direction. It works earlier, with only the wave 5 hook, but it puts Linux in the path, and the core split would throw most of it away. Use it only if a specific FreeBSD program is needed before wave 10.

### Alongside the waves (open items)

These are not group work yet, but should not be forgotten:
- **First test on the real NUC** (i5-4250U): VT-d on in the firmware, the IOMMU log lines, the PCID boot line, e1000e networking, xHCI input, and the installer. No wave has run on real hardware yet. This needs you at the machine; a good time is after wave 4.
- **The rare `regstress` hang:** both virtual CPUs spinning, once in 6 runs on wave 2's merge, not reproduced since. `suite_loop.sh` takes a task dump if it happens again.
- **The `lowmem` failure on q35:** the firmware loads the kernel where the test wants to map memory.
- **A Wi-Fi driver is needed eventually** (user, 2026-11-24): the NUC uses a **USB Wi-Fi adapter** (model and chipset to be identified: the chipset — e.g. Realtek, MediaTek or Atheros — decides the driver). Needs a USB driver for that chipset on Hydra's xHCI stack, firmware loading, an 802.11 layer and a WPA2 supplicant (or the Linux one through lx-net). Hydra has no Wi-Fi support today; wave 11's NUC run uses an Ethernet cable. Group H estimates the work; to be scheduled in a later wave.
- **Live session copied to memory, chosen by RAM size** (user's idea, 2026-11-24; to do in a later wave, ~3–4 agent-days): at boot Hydra measures free RAM and picks a mode, shown on screen and in the boot log: **≥ 8 GB** copy the whole live pool's used blocks (~3.5 GB system + ~1 GB install set) into a RAM-backed disk for zfs-server, then "you can remove the stick now" (pulling it early is fully safe); **4–8 GB** copy only the install set (the installer finishes and restart works; desktop programs may still crash); **< 4 GB** run from the stick as today. Start-menu entries override it (from the stick / copy to memory / safe mode). Pieces: RAM-backed disk on memory objects, boot-time copy of used blocks with progress and fallback, the mode choice, tests pulling the stick at every phase. Today's protection is wave 11 Group H's restart timeout only.

## Merge order and testing

1. **Within a wave:** the group that changes the kernel's core merges first. That was wave 1's IPC, wave 2's net-server and wave 3's PCID. The suite runs after each merge.
2. **After each wave:** the full "Done means" list on the merge, then push and deploy **only with your OK**.
3. **Line count:** after each wave, update the table at the top and the comparison document's tables.

## Risks

- **Core changes are subtle.** Group H's lost-reply bug (2026-11-17), the TLB work (wave 3) and the lock-free forwarding (wave 4) can all fail silently. Each gets a stress test and `suite_loop.sh` before it merges.
- **IOMMU and PCID on real hardware:** firmware tables on 2014 machines are sometimes wrong, and nested KVM tests can't prove the NUC works. Every feature falls back cleanly and has a boot option to turn it off.
- **Performance:** every moved piece adds a server hop. Each step measures against the budget, and a merge that misses it needs your OK.
- **Test harness:** it types into the console. Every change must keep the commands and the prompt identical.
- **Step 6a is large** (about 17,000 lines, 12–14 agent-days). It may need splitting into two groups or two waves once its design is clear.

## Decisions

### Made 2026-11-17

1. **Linux ABI:** the whole layer moves out of the kernel, in separate steps.
2. **Emergency prompt:** a tiny in-kernel prompt stays for when user space is broken; the rest of the shell moves out.
3. **Wave 1 size:** four groups at once (1, 3, 5 and 4 part 1).

### For moving the Linux layer (made 2026-11-17, from section 10 of [linux-server-design.md](linux-server-design.md))

4. **Shape:** one ring-3 Linux server (design C), beside zfs-server and net-server. *Refined by decision 9: one Linux server for now, split into several services later.*
5. **Fast path:** build the direct switch in step 1. PCID (tagged TLB) is done as a separate small task in the same wave and merges first.
6. **When the Linux server crashes:** every Linux program ends, the supervisor restarts the server, and the desktop comes back at the login screen. The kernel, the drivers and the emergency prompt stay up.
7. **Budget and order:** the proposed budget (at most 3 µs added per forwarded call; desktop, browser and network at most 5 % slower; metadata-heavy tools at most 35 % slower) and the order of section 7 of the design are accepted.

### Made 2026-11-18

9. **Separate services, for resilience.**
   - **The file system does not go into linux-server.** It becomes a service of its own, so a fault in the Linux layer and a fault in the file system do not take each other down.
   - **Later, the Linux layer itself is split into several services.**
   - **Consequences:**
     - the kernel's forwarding must route calls to more than one server;
     - fast server-to-server calls become essential;
     - every service needs its own crash and restart behavior.
   - Group 16's "B-lean" option, the VFS inside linux-server ([vfs-design.md](vfs-design.md)), is therefore rejected. The designs for waves 6 and 7 are being revised to match.

### Made 2026-11-19 (the nine questions of [linux-services-design.md](linux-services-design.md) section 8, all as recommended)

10. **The services:** the ten of section 2.1: vfs-server, lx-ipc, lx-net, display, input, sound, terminals, lx-sec, lx-proc, and linux-server for what is left. Display, input and sound are separate services (Group 15's revised design), which also settles where sound and the display go.
11. **Process identity stays in the kernel:** credentials, the process tree, process groups and sessions, PID translation, namespace ids, limits, cwd/root/umask and the descriptor table (about 2,500 more kernel lines than first planned).
12. **Crash behavior:** the classes of section 5.2. vfs-server, lx-net, keys and lx-proc restart invisibly; lx-ipc, the device services and bpf fail only their own objects; a second crash within 30 s drops one class. Decision 6 stays only for linux-server while it hosts unsplit pieces.
13. **Routing:** the kernel sends each call straight to the owning service, never through linux-server.
14. **Direct calls between services** are built in wave 6, to Linux services and to zfs-server and net-server.
15. **First split as proof:** keys and bpf (lx-sec) in wave 6.
16. **Order:** wave 6 foundation, wave 7 the file service, wave 8 the device services plus splitting lx-net and lx-ipc out.
17. **A switch back per service** (for example `lx.vfs=kernel`), next to `lx=kernel`.
18. **FreeBSD and macOS later:** each service learns those systems' calls itself; no separate shared "POSIX core" wave first.

Also 2026-11-19: a seventh, bug-fixing group joins wave 6, and wave 6 starts right after wave 5's deploy.

### Made 2026-11-21 (Group 16's VFS questions, [vfs-design.md](vfs-design.md) section 11, all as recommended; and how wave 7 runs)

19. **`/proc`, `/sys` and `/dev` belong to the Linux services** (linux-server now; the process and device services later), mounted into vfs-server and reached with one redirect at lookup.
20. **The descriptor table stays in the kernel** as a table of handles.
21. **Programs keep running when vfs-server crashes:** open files, current directories and mappings survive; mounts and locks live in kept state.
22. **No kernel `stat` cache for now;** revisit if the budget is missed.
23. **Wave 7 is split as section 12.2:** 7-1 to 7-6 in parallel, then 7-7 closing; plus group H (the two-load hang) and group B (carried-over bugs). **Started in stages:** H and 7-1 to 7-3 first, 7-4 to 7-6 and B added as those settle.
24. **Gemini as a read-only second opinion** (the user's Gemini subscription, through Google's Antigravity CLI `agy`; Gemini CLI with a personal account is no longer supported by Google): `tools/gemini_review.py` and the `gemini-reviewer` subagent (`.claude/agents/gemini-reviewer.md`) review each branch before merge and help on hard bugs. Gemini may see Hydra's source, diffs and logs. It never writes to the tree; its findings are checked against the code before anyone acts on them.
25. **7-7 does the mounts step, not the deletion** (2026-11-21): after stage 2, nearly all of KDE still ran on the kernel's file code, because almost every KDE process carries `LX_FS_MOUNTS` and those calls stay in the kernel. 7-7 therefore teaches vfs-server every namespace's mounts (the joint 7-2/7-3 step, chroot, the mount calls), fixes the leftovers and measures the budget. The kernel copies stay as the switch back; deleting them moves to wave 8, once KDE really runs on the services. Stage 2 is pushed and deployed before 7-7 starts.
26. **Wave 8 lineup** (2026-11-22): stage 1 D (display service), I (input), S (sound), T (terminals), X2 (lx-net and lx-ipc split out of linux-server), Z (zfs-server durability: no acknowledged change lost on a kill); stage 2 H (restart and hot-plug), F (mount calls and tmpfs ownership into vfs-server), P (per-call cost back under budget), B (open bugs); then 8-C closing.
27. **The kernel's copy of the file code is deleted after FUSE moves into vfs-server** (wave 9's closing), not in wave 8: `lx.vfs=kernel` stays one more wave.
28. **Group 15's last device questions, as recommended:** a display-service crash ends the desktop session for now (a desktop-keeping restart later); fix the two waste findings now (pictures paced to 60 a second, no drawing behind the console); design the display core for a real graphics driver, build only the firmware framebuffer now.
29. **Wave 9 lineup** (2026-11-22), two groups at a time, deployed after each pair: (1) 6b-2 FUSE as a vfs-server back end + 7a the process mechanism; (2) 6b-1 inotify/fanotify + X3 lx-ipc Transparent; (3) 6b-3 Landlock/ACL/ABAC + 6b-4 io_uring/aio; (4) P2 per-call cost + M tmpfs data in memory objects; then 9-C closing. Starts after the user's weekly usage limit resets. Gemini stays off; Sonnet reviewers.
30. **9-C deletes the kernel's copy of the file code only** (after FUSE moves and the deploy; `lx.vfs=kernel` goes away). The wave 8 device and lx-net/lx-ipc copies stay as switch-backs until wave 10's cleanup.

31. **Wave 10 lineup** (2026-11-23): stage 1 7b-1 (lx-proc), V1 (the change calls into vfs-server), 8-2 (SysV shared memory into lx-ipc), N (`tcp_connect` budget, `io_uring` rings); stage 2 7b-2 (`/proc` into lx-proc), 8-1 (ptrace/perf policy), V2 (`/dev` and FUSE `mount(2)` into vfs-server); then 10-C closing. Four groups at once, a deploy after each stage.
32. **No switch back after wave 10:** 10-C deletes every remaining in-kernel copy, and `lx=kernel` with every `lx.<service>=kernel` word is ignored with a boot-log line (as `lx.vfs=kernel` in 9-C). Crashes are handled by restarts; the emergency prompt stays for broken user space.
33. **Wave 10 starts right away** (2026-11-23).
34. **The io_uring and aio rings stay in the kernel as mechanism** (2026-11-24, Group N's measurement): moving them into linux-server would add about +4 µs to a one-request read, fail every ring on a linux-server crash, and save only about 1,000–1,300 kernel lines. Each request is already routed to its descriptor's owner (wave 9 6b-4). 10-C drops `lx.uring=kernel` and says whether linux-server can then be retired.
35. **The ptrace/perf permission decisions stay in lx-proc although over budget** (2026-11-24, Group 8-1): `kcmp` +3.7 µs, `process_vm_readv` +3.5, `perf_event_open` +4.1, `PTRACE_ATTACH` about +7.5 (+14 in a tight loop); the floor is the hop (~3 µs). These calls are rare (debuggers, tracers, profilers); the per-request ptrace operations stay in the kernel and are unchanged.
36. **Wave 11 is a consolidation wave** (2026-11-24): FreeBSD waits one wave. Stage 1 R (restart robustness), F (the last walks and FUSE changes into vfs-server), P (the remaining `/proc` files into lx-proc), H (real-hardware preparation for the NUC); stage 2 the NUC run, fixes, 11-C closing. Four groups at once.
37. **The user runs Hydra on the NUC in wave 11's stage 2** (boots the stick H prepares, installs, returns the logs).
38. **Wave 11 starts right away** (2026-11-24).

### Still open, and when they are needed

| Decision | Needed before | Notes |
|---|---|---|
| Which other systems' programs to support, and in what order (FreeBSD, macOS, a native Wine back end) | Wave 11 | Decision 18 sets the shape; the wave 5 hook serves all of them |
