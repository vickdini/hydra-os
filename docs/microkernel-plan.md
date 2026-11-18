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
| 4 | Linux layer step 2, faster forwarding, FreeBSD/macOS step 0 | Merged (e15cd6a), checked | 96,061 |
| 5–9 | Linux layer steps 3–8, plus the personality hook (wave 5) | Planned (below) | about 50,000 expected at the end |
| 10–13 | Shared POSIX core, then FreeBSD and macOS programs | Planned (below); step 0 done in wave 4 | |

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

### Waves 5–9: the rest of the Linux layer (planned)

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

### Still open, and when they are needed

| Decision | Needed before | Notes |
|---|---|---|
| Where sound and the display go | Wave 6 (step 5) | A display/input server serving Linux programs, and later native ones too, is the design's suggestion |
| How the separate file-system service is shaped (what it owns, what stays in the kernel, crash behavior) | Wave 7 (step 6a) | The VFS is a service of its own (decision 9); Group 16 revises [vfs-design.md](vfs-design.md) |
| How the Linux layer is split into services, and how the kernel routes calls to several servers | Before wave 6 (its foundation is wave 6's work) | Decision 9; step 0 done in wave 5 (Group 18): [linux-services-design.md](linux-services-design.md), nine questions in its section 8 |
| Which other systems' programs to support, and in what order (FreeBSD, macOS, a native Wine back end) | Wave 10 (the core split) | The wave 5 hook is cheap and serves all of them; the FreeBSD shortcut is only worth it for a specific program needed early |
