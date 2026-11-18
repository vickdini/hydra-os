# Plan: making Hydra more of a microkernel

This plan turns the six recommendations in [microkernel-comparison.md](microkernel-comparison.md) into work for parallel agents, organized in waves.
- It was first written 2026-11-17, while the installer round (groups E–H) was finishing.
- It was rewritten 2026-11-18 to cover every wave: what waves 1–3 delivered, what wave 4 is doing, and the planned waves after it.
- Moving the Linux layer is planned step by step in [linux-server-design.md](linux-server-design.md). This document maps those steps onto waves.

## Where things stand (2026-11-18)

| Wave | Groups | Status | Kernel `src/` lines after |
|---|---|---|---:|
| Before | | | 101,973 |
| 1 | IOMMU, retire compositor, concurrent IPC, shell part 1 | Merged, pushed (2c6bc80) | |
| 2 | net-server, shell part 2, Linux-layer design | Merged, pushed, deployed (ecca368) | 91,702 |
| 3 | PCID, Linux layer step 1 | Merged, pushed, deployed (5027d87) | 93,725 |
| 4 | Linux layer step 2, faster forwarding | **Running**, started 2026-11-18 | |
| 5–9 | Linux layer steps 3–8 | Planned (below) | about 50,000 expected at the end |

- **Why the line count rose in wave 3:** step 1 added the forwarding machinery (`src/lx`, 946 lines) and PCID (`src/arch/pcid.rs`, 365 lines). It also keeps the in-kernel copy of each moved piece, as the switch back to the kernel (`lx=kernel`), until a later step deletes it.
- **Today:** the Linux layer (`src/compat/linux`) is 51,444 lines, still mostly in the kernel. The ring-3 drivers and servers (`userland/drivers`) are 22,339 lines.

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

### Wave 4: Linux layer step 2, plus a faster forwarding path (running, started 2026-11-18)

**Group 9 (`E:\os-9`, `mk-lxobj`): step 2 of the design**
- **Server-object descriptors:** a descriptor kind whose operations go to linux-server.
  - Readiness lives in a word shared with the kernel, so `poll`, `select` and `epoll` need no call to the server.
  - Steps 3, 4 and 6 build on it.
- **`sig_post`:** the server sends signals to processes.
- **Blocking calls:** they answer "pending" and finish later, so they no longer tie up one of the 4 workers.
- **What moves:**
  - message queues (`mqueue`);
  - System V messages and semaphores (shared memory stays in the kernel until step 8);
  - `bpf`.
  - The hard spot: the kernel's open path checks device permissions with bpf programs (`device_check`), which can't wait on an IPC call.
- **Estimate:** 4–5 agent-days.

**Group 10 (`E:\os-10`, `mk-lxfast`): a faster forwarding path**

Three parts, each in its own commits, so a subset can be merged:
- **A copy-in table in the syscall page:** the kernel copies pointer arguments for the server, instead of the server fetching each one with an extra call.
- **Forwarding without the kernel lock,** to meet the concurrency rule.
- **Global kernel pages,** so kernel mappings survive address-space switches. A boot option turns them off.
- **Also:** it measures KDE start time with step 1, which wave 3 never did.

The goal is a forwarded call clearly under +3 µs with PCID, and within +3 µs without it. Later steps forward much hotter calls, and the metadata-heavy budget for step 6a depends on this.

**Merge order:** decided when both are done; expect one rebase or a lead merge. After the merge: all checks, then push and deploy with your OK.

### Waves 5–9: the rest of the Linux layer (planned)

Each wave does one or two steps of section 7.2 of the design. Two habits carry through every step:
- **Cleanup:** each wave deletes the in-kernel copies of the previous wave's moved code, once that wave has been deployed and used without problems.
- **Line count:** after each wave, measure the kernel's line count again and update the table at the top.

| Wave | Steps (design 7.2) | What moves | Needs first | Agent-days |
|---|---|---|---|---:|
| **5** | **3:** network sockets and netlink, as net-server's client<br>**4:** Unix sockets, pipes, event descriptors (in parallel: different files) | `inet`, `sockopt`, `rtnetlink`, `netlink` (about 2,900 lines); `unix`, `socket`, pipes, `eventfd`, `timerfd`, `signalfd`, `pidfd` (about 3,300) | Wave 4's server-object descriptors | 4–5 and 5–6 |
| **6** | **5a:** sound<br>**5b:** terminals, DRM and input | `snd` (2,137); `tty`, `pty` (1,583); `drm`, `evdev` (2,309) | **Your decision:** where sound and the display go | 6–7 |
| **7** | **6a:** VFS, mounts, pseudo files, the descriptor table (alone: the largest and riskiest step) | about 17,000 lines | **Your decision:** whether the VFS fast paths stay in the kernel | 12–14 |
| **8** | **6b:** the rest of the file side<br>**7:** processes and signal policy (in parallel) | `io_uring`, `aio`, `inotify`, `fanotify`, `fuse`, `landlock`, `acl`, `abac` (about 7,150); `proc` policy, `process`, `execve`, `ns`, `limits`, timers, `admin` (about 5,900) | Step 6a | 5–6 and 7–8 |
| **9** | **8:** debugging and the last pieces, plus the final cleanup | `ptrace` policy, `perf`, `userfaultfd` glue, System V shared memory; the dispatcher shrinks to the trap and the local calls | Steps 6b and 7 | 4–6 |

- **Total left after wave 4:** about 43–52 agent-days of group work, plus the lead's merges and checks.
- **The end state:** about 45,000 lines moved out. The kernel keeps the trap, memory management and faults, futex, threads, signal delivery and the ptrace stop mechanism (about 6,000 lines of Linux support), and should be about 50,000 lines in total.

**Wave 5 detail:**
- **Step 3:** the Linux server becomes net-server's client directly, using the protocol wave 2 shaped for this.
  - Tests: `apt-get update`, Firefox loading pages, download throughput before and after, and killing net-server and linux-server.
- **Step 4:** pipes and Unix sockets carry D-Bus and Wayland, so their speed shows at once on the desktop. Budget: pipe and Unix round trips no slower than today.
- **Temporary primitives:** step 4 adds two, path lookup for socket files and descriptor passing between processes. Step 6a removes them.

**Wave 6 detail:** the natural home for DRM and input is a display/input server, not necessarily the Linux server. Sound can live in the Linux server or next to the hda driver. The same display server could later serve native (non-Linux) programs, such as a native Wine back end or Mac programs.

**Wave 7 detail:**
- If the VFS moves out completely, the warm-`find` budget (at most 35 % slower) rests on wave 4's faster forwarding.
- If its fast paths stay in the kernel, the step is smaller, but the kernel keeps file-system code for good.
- Wave 4's numbers will show which is realistic, so this decision is best made after wave 4.

### Alongside the waves (open items)

These are not group work yet, but should not be forgotten:
- **First test on the real NUC** (i5-4250U): VT-d on in the firmware, the IOMMU log lines, the PCID boot line, e1000e networking, xHCI input, and the installer. No wave has run on real hardware yet. This needs you at the machine; a good time is after wave 4.
- **The rare `regstress` hang:** both virtual CPUs spinning, once in 6 runs on wave 2's merge, not reproduced since. `suite_loop.sh` takes a task dump if it happens again.
- **The `lowmem` failure on q35:** the firmware loads the kernel where the test wants to map memory.
- **Native personalities (ideas, not planned):**
  - a Wine back end that talks to Hydra directly instead of through Linux system calls;
  - Mac programs through a `mach-server` and a Darling-based root.
  - Both would use the per-process forwarding table from step 1.

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

4. **Shape:** one ring-3 Linux server (design C), beside zfs-server and net-server.
5. **Fast path:** build the direct switch in step 1. PCID (tagged TLB) is done as a separate small task in the same wave and merges first.
6. **When the Linux server crashes:** every Linux program ends, the supervisor restarts the server, and the desktop comes back at the login screen. The kernel, the drivers and the emergency prompt stay up.
7. **Budget and order:** the proposed budget (at most 3 µs added per forwarded call; desktop, browser and network at most 5 % slower; metadata-heavy tools at most 35 % slower) and the order of section 7 of the design are accepted.

### Still open, and when they are needed

| Decision | Needed before | Notes |
|---|---|---|
| Where sound and the display go | Wave 6 (step 5) | A display/input server serving Linux programs, and later native ones too, is the design's suggestion |
| Whether the VFS fast paths stay in the kernel for good | Wave 7 (step 6a) | Best decided with wave 4's forwarding numbers in hand |
