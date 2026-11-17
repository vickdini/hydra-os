# Plan: making Hydra more of a microkernel

This plan turns the six recommendations in [microkernel-comparison.md](microkernel-comparison.md) into work for parallel agents. It was written 2026-11-17 while the installer round (groups E–H) was finishing.

## Starting point and ground rules

- **Base:** start only after the installer round is merged into `host-unit-tests` (branch `i-merge`), tested and pushed. Starting earlier would stack two rounds of conflicts.
- **Same setup as earlier rounds:**
  - one git worktree and branch per group, numbered `D:\os-1` … `D:\os-4`, `D:\os-5`;
  - a `STATUS.md` per group (in its own worktree only, not committed into the shared file: last round every group overwrote it);
  - a shared notes file `D:\os-mk-shared\NOTES.md` for interface agreements.
- **VMs:** at most 2 test VMs at once (the existing gatekeeper). All VM files stay on WSL's own disk, never on `/mnt/d`, because of the 9p freeze found on 2026-11-17. Never boot or write the main pool.
- **Done means:**
  - the full suite passes on 4 CPUs (or 2 under the gatekeeper);
  - the host tests pass;
  - KDE reaches the desktop and runs Firefox;
  - sound plays;
  - the installer test (stick → disk → first boot) still passes.

## Why some groups must go first: the dependencies

| Item | Depends on | Reason |
|---|---|---|
| 1 IOMMU | nothing | New code (`src/arch/iommu.rs`) plus hooks where drivers get DMA memory |
| 3 Retire compositor | nothing | KDE uses `kwin_wayland` on DRM. The in-kernel compositor (`src/wayland`, `wayland_bridge.rs`) is only a fallback |
| 5 Concurrent IPC | nothing, but it is the foundation | Changes how every driver call works (`src/ipc/service.rs`, scheduler hand-off) |
| 4 Shell out | 3 (partly) | Shell commands reference the compositor and video. Also **the whole test harness types commands into the kernel shell**, so the new shell must keep the same commands |
| 2 Network server | **5** | Every packet would cross the IPC path. With today's one-call-at-a-time hand-off, network speed and latency would suffer badly. The Linux socket layer (`inet.rs`, `rtnetlink.rs`, `select.rs`, `io_uring.rs`, `fs/fd.rs`) calls the stack directly today |
| 6 Linux ABI pieces | **5**, and **2** for netlink | A Linux piece moved out needs fast, concurrent calls. netlink talks to the network stack |

## The waves

### Wave 1: four groups in parallel (estimated 1–2 days of agent time)

**Group 1: IOMMU (Intel VT-d)**
- **Steps:**
  - Read the firmware's DMAR table.
  - Give each ring-3 driver its own DMA domain: memory from `dma_alloc` is mapped only into that driver's device's page table.
  - Turn on DMA remapping.
  - Optional: interrupt remapping.
  - Fall back cleanly when there is no IOMMU or the firmware's table is broken.
- **Test in QEMU:** `-machine q35 -device intel-iommu`. This needs a q35 harness option; q35 is also closer to the NUC.
  - A rogue-DMA test: a driver tries to DMA outside its buffers, and the IOMMU blocks it and logs a fault.
  - The full suite with the IOMMU on.
- **Touches:**
  - new `src/arch/iommu.rs`;
  - `src/memory`;
  - `dma_alloc`/`set_grants` in `src/ipc/service.rs`;
  - `supervisor.rs`;
  - `tools/hydra_run.py`.
- **Real hardware:** the NUC needs "VT-d" enabled in its firmware setup. To check on the real machine later.

**Group 3: retire the in-kernel compositor and console graphics**
- **Steps:**
  - Remove `src/wayland` and `src/compat/linux/wayland_bridge.rs`.
  - Remove the compositor paths in `drm.rs`, `keyboard.rs`, `mouse.rs` and `evdev.rs`.
  - Remove the shell commands that start or use the compositor.
  - Reduce `src/video` to a minimal emergency text console (panics, early boot, the login prompt when KDE is not running) and the boot splash. The splash may move to the display server if that is simpler.
- **Check first:** whether anything still uses the in-kernel compositor, such as a fallback when KDE fails, or tests (`wlclient`, `wlseat`). Report before deleting.
- **Test:** KDE desktop, the console after logout, a panic still visible on screen, the full suite with the compositor tests removed or replaced.

**Group 5: concurrent IPC and page grants**
- **Steps:**
  - Keep the strict hand-off only for kernel callers that hold subsystem locks.
  - Add queued, asynchronous requests for everything else: several requests outstanding per service, and servers may be multi-threaded.
  - Add page grants: lend pages to a server for one request instead of copying through the 256 KiB window. Use them for disk blocks and network frames.
  - Fix the 5-second "kernel waits on a user process with locks held" problem, at least for paths that no longer need the hand-off.
- **Test:**
  - the full suite;
  - a stress test with many parallel disk readers and USB input at the same time (the case behind Group H's lost-reply bug);
  - disk throughput before and after (copying a 16 GiB image: 208 s today).
- **Touches:** `src/ipc/*`, `src/task/scheduler.rs`, `hydra-rt`, and every driver's request loop (small changes). **The highest-risk group:** it must merge first in wave 1 and get the most testing.

**Group 4 (part 1): get the shell ready to leave the kernel**
- **Steps:**
  - **Decouple:** move the boot-file helpers (`shell::fs::read_boot_file`, `open_root_volume`, …) that `fs/client.rs`, `task/elf.rs` and `task/scheduler.rs` use into `src/fs/bootfs.rs`. Move `usbdisk::POOL_ON_USB` into the supervisor or `fs`.
  - **Design the interface:** a small "admin" interface for what the shell needs from the kernel. That covers tasks, memory, services, ZFS, network status, power and Linux-root commands. Each command must work through that interface instead of calling kernel internals.
  - **Build the program:** a ring-3 `hydra-shell` program (native, like the drivers) attached to the serial and screen console, with the same prompt and commands. The harness and every test script must keep working unchanged.
- **This part leaves the in-kernel shell in place.** It only prepares; commands move in part 2.

### Wave 2: after wave 1 is merged (estimated 1–2 days)

**Group 2: network protocols as a server**
- **Steps:**
  - Move `src/net` (TCP, UDP, IP, ARP, DHCP, DNS) into a ring-3 `net-server` next to `e1000-driver`, using wave 1's concurrent IPC and page grants.
  - The Linux socket layer becomes a client of it.
  - The HTTP client in `src/net/http.rs` goes to the server or into a shell command.
- **Test:**
  - `apt update`, Firefox loading pages, DNS, DHCP;
  - throughput before and after;
  - `kill` the net server during a download: it should restart, and the download fails cleanly instead of hanging.

**Group 4 (part 2): move the shell commands out**
- **Steps:**
  - Port every command to `hydra-shell`.
  - Switch the console to it.
  - Keep a tiny in-kernel emergency prompt only if the user wants one (decision below).
  - Delete `src/shell`.
- **Test:** the full suite through the new shell, unchanged, plus the KDE and installer tests.

**Group 6 (step 0): design for moving the whole Linux layer out**

Decision (2026-11-17): the **whole** Linux layer moves out of the kernel, in separate steps. Step 0 is a design report; no code moves in it.
- **Map the layer:** list every part of `src/compat/linux` (52,600 lines) with what it needs from the kernel: memory maps, page faults, signals, scheduling and blocking, futex, file descriptors.
- **Choose the target shape:**
  - one "Linux server" process, like MINIX's PM and VFS servers or a gVisor-style sentry; or
  - a few servers, for example files, network sockets, processes and signals.
- **Decide what stays in the kernel:** a minimal system-call trap that forwards to the server. Possibly the hot paths that need direct page-table access (page faults, `mmap`, futex), as primitives the server drives.
- **Plan the cost:** every Linux system call would cross into another process. That needs wave 1's concurrent IPC, probably a faster path for system calls than today's driver calls, and a performance budget measured on today's kernel (for example fork+exec 3 ms and the KDE desktop start time).
- **Order the steps** so each one leaves a working, tested system.

### Wave 3 and later: moving the Linux layer in steps (several weeks in total)

**Group 6 (steps 1…n)**, one step per round, in the order step 0 sets. The probable order:
1. **Self-contained pieces first:** BPF emulation (`bpf.rs`), FUSE (`fuse.rs`), netlink (`rtnetlink.rs`, after group 2), sound (`snd.rs`), DRM (`drm.rs`).
2. **File systems and descriptors:** `vfs.rs`, `mount.rs`, `proc.rs`, pipes, Unix sockets.
3. **Processes, signals and memory management** last: the deepest and most performance-sensitive part.

After each step: the full suite, KDE, Firefox, Wine and the installer test, plus the performance numbers against the step-0 budget.

## Merge order and testing

1. **Wave 1 merge order:**
   - 5 (concurrent IPC) first, then a full test cycle;
   - then 3 (compositor), 1 (IOMMU) and 4 part 1, each followed by the suite.
2. **After each wave:** the full test list from "Done means" above, then deploy to the main pool **only with your OK**.
3. **Line count:** after each wave, measure the kernel's line count again and update the comparison document's tables. The kernel is about 98,000 lines today. The expected result after waves 1–2 is roughly 75,000–80,000: the compositor, console graphics, network stack and shell move out or are removed.

## Risks

- **Group 5 changes the core of the kernel.** H's lost-reply bug on 2026-11-17 shows how subtle this code is. It gets a stress test and must merge first and alone.
- **IOMMU on real hardware:** firmware tables on 2014 machines are sometimes wrong. The code must fall back to "no IOMMU" with a warning, never fail to boot. QEMU tests can't prove the NUC works.
- **Performance:** moving the network stack out adds a server hop per packet. Group 2 must measure before and after, and the merge needs your OK if it is noticeably slower.
- **Test harness:** it depends on the kernel shell. Group 4 must keep every command and prompt identical, or every test script breaks at once.

## Decisions (made 2026-11-17)

1. **Linux ABI:** the whole layer moves out of the kernel, in separate steps (group 6 above).
2. **Emergency prompt:** a tiny in-kernel prompt stays for when user space is broken; the rest of the shell moves out.
3. **Wave 1 size:** four groups at once (1, 3, 5 and 4 part 1).

### Decisions for moving the Linux layer (made 2026-11-17, from section 10 of [linux-server-design.md](linux-server-design.md))

4. **Shape:** one ring-3 Linux server (design C), beside zfs-server and net-server.
5. **Fast path:** build the direct switch in step 1. PCID (tagged TLB) is done as a separate small task in the same wave and merges first.
6. **When the Linux server crashes:** every Linux program ends, the supervisor restarts the server, and the desktop comes back at the login screen. The kernel, the drivers and the emergency prompt stay up.
7. **Budget and order:** the proposed budget (at most 3 µs added per forwarded call; desktop, browser and network at most 5 % slower; metadata-heavy tools at most 35 % slower) and the order of section 7 of the design are accepted.
8. **Still open, decided before the steps that need them:**
   - whether the VFS fast paths stay in the kernel for good (before step 6a);
   - where sound and the display go (before step 5).

### Wave 3 (started 2026-11-17)

- **Group 7:** step 1 of the design. The forwarding machinery and the direct switch, a ring-3 `linux-server`, and `keys` as the first tenant.
- **Group 8:** PCID. It merges first.
