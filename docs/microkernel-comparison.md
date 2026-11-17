# How much of a microkernel is Hydra?

A comparison of Hydra with MINIX 3, Linux, FreeBSD, Windows and macOS, written to answer one question: how well does Hydra follow the microkernel pattern, and where does it depart from it?

The Hydra figures were measured on branch `host-unit-tests` on 2026-11-17. The installer branches (`i-disk`, `i-live`, `i-setup`, `i-usb`) were not merged yet. Line counts are Rust source including comments, and Hydra's code is heavily commented, so read them as proportions, not absolute sizes. Figures for the other systems are the well-known design facts, not measurements.

## 1. The pattern in one paragraph

A microkernel keeps only what *must* run with full hardware privilege:
- address spaces;
- scheduling;
- interrupts;
- message passing (IPC).

Everything else runs as ordinary isolated processes ("servers"): device drivers, file systems, network protocols and the POSIX layer. The promised benefits:

1. **Fault isolation:** a buggy driver crashes itself, not the machine.
2. **Restartability:** a crashed server can be restarted (MINIX 3's "reincarnation server").
3. **Least privilege:** each server gets only the hardware and memory it needs.
4. **A small trusted core** that can be reviewed, tested or even proven.

The price is IPC overhead and more complex design, because servers must cooperate through messages instead of function calls.

## 2. The six systems at a glance

| | **Hydra** | **MINIX 3** | **Linux** | **FreeBSD** | **Windows (NT)** | **macOS (XNU)** |
|---|---|---|---|---|---|---|
| Kernel type | Hybrid: microkernel structure for drivers and storage, monolithic for the rest | True microkernel | Monolithic, loadable modules | Monolithic, loadable modules | "Hybrid": NT executive in one kernel space | "Hybrid": Mach and BSD in one kernel space |
| Disk drivers | **User space** (ata-driver, ahci-driver) | User space | Kernel | Kernel | Kernel (some storage stacks via UMDF are rare) | Kernel (IOKit); DriverKit for some |
| File system | **User space** (zfs-server) | User space (VFS + MFS servers) | Kernel (FUSE optional) | Kernel | Kernel | Kernel (FSKit for some, since macOS 15) |
| Network card driver | **User space** (e1000-driver) | User space | Kernel | Kernel | Kernel (NDIS) | Kernel; DriverKit possible |
| TCP/IP stack | Kernel | User space (inet / lwIP server) | Kernel | Kernel | Kernel | Kernel |
| USB | **User space** (usb-driver) | User space | Kernel | Kernel | Kernel; UMDF for many devices | DriverKit (user space) for many devices |
| Sound | **User space** (hda-driver) | User space | Kernel | Kernel | Kernel (miniport) plus user-mode audio engine | Kernel / DriverKit |
| Graphics output | **User space** (display-server); a legacy Wayland compositor is also in the kernel | User space | Kernel (DRM) plus user space | Kernel plus user space | Kernel part (win32k, dxgkrnl) plus user-mode driver half | Kernel plus user space |
| POSIX / OS personality | **Kernel** (Linux ABI layer) | User space (PM, VFS servers) | Kernel (native) | Kernel (native, plus Linuxulator in kernel) | Kernel (Win32 partly in win32k; WSL1 was a kernel Linux layer) | Kernel (BSD layer inside XNU) |
| Driver restart after crash | **Yes:** supervisor, heartbeat, up to 10 restarts | Yes: reincarnation server | No (an oops often means reboot) | No | Partly: GPU driver reset (TDR); UMDF drivers restart | Partly: DriverKit extensions restart |
| Driver memory protection from DMA (IOMMU) | **No** | Mostly no (research versions only) | Yes (optional, for VFIO and so on) | Yes (optional) | Yes (Kernel DMA Protection) | Yes (VT-d / DART, always on for Apple silicon) |
| Main IPC | Synchronous call with CPU hand-off; fixed 32-byte messages plus a 256 KiB shared window per service | Synchronous fixed-size messages, memory grants | Function calls in kernel; pipes, sockets and so on for processes | Function calls; Capsicum for process rights | Function calls; ALPC between processes | Function calls; Mach ports between processes |

## 3. Where Hydra's code actually runs

### Kernel (ring 0): about 98,000 lines

| Part | Lines | Microkernel view |
|---|---:|---|
| Linux ABI layer (`src/compat`) | 51,400 | Would be a server in a pure design (as MINIX's PM and VFS are) |
| Kernel shell (`src/shell`) | 10,200 | Would never be in a microkernel |
| Architecture: CPU, interrupts, timers, PCI, SMP, PS/2 keyboard and mouse (`src/arch`) | 8,100 | Mostly belongs in the kernel; the PS/2 and mouse drivers would be servers |
| Tasks, scheduler, ELF loading, supervisor (`src/task`) | 6,400 | Belongs in the kernel (supervisor policy could be a server) |
| File layer and ZFS *client* (`src/fs`) | 5,300 | Partly: the client side is fine; in MINIX even VFS is a server |
| Network protocols: TCP, UDP, IP, DHCP, DNS, HTTP (`src/net`) | 4,500 | Would be a server |
| Memory management (`src/memory`) | 3,700 | Belongs in the kernel |
| Console video, splash (`src/video`) | 2,100 | Mostly a server in a pure design |
| IPC (`src/ipc`) | 2,000 | The heart of a microkernel |
| Wayland compositor (`src/wayland`) | 1,800 | Would be a server; partly superseded by display-server |
| Other: capabilities, sync, syscall entry, package handling, compression | 3,100 | Mixed |

### User-space servers (ring 3): about 12,100 lines

| Server | Lines | What it owns |
|---|---:|---|
| zfs-server | 5,000 | The whole OpenZFS stack: pool, DMU, directories, POSIX layer |
| display-server | 1,900 | The framebuffer |
| usb-driver | 1,400 | xHCI, keyboards and pointers (USB storage and hubs added on `i-usb`) |
| ahci-driver | 900 | SATA disks |
| hda-driver | 900 | Intel HD Audio |
| ata-driver | 700 | IDE disks |
| e1000-driver | 650 | Intel network card |
| hydra-rt | 700 | Shared runtime library for the servers |

**About 11% of Hydra's own system code runs outside the kernel.** That sounds low, but the 11% is the *right* 11%. It is the hardware-facing driver code plus the file system: the code that in Linux, Windows and macOS causes most crashes and security bugs. The large ring-0 share is mostly the Linux ABI layer, which is not driver code.

## 4. Scorecard: Hydra against the microkernel goals

| Goal | Rating | Why |
|---|---|---|
| **Drivers out of the kernel** | ✅ Strong | Every hardware driver with real complexity (disks, USB, network, sound, display) is a separate ring-3 process with its own address space. This is MINIX 3's model, and better than Windows or macOS achieve by default. Exceptions: PS/2 keyboard and mouse, vmmouse, timers and PCI scanning are still in the kernel. |
| **File system out of the kernel** | ✅ Strong | ZFS, a big and complex file system, runs entirely as a server. MINIX does this; none of Linux, FreeBSD, Windows or macOS does it for their main file system. |
| **Restart after a crash** | ✅ Good | A supervisor sends heartbeats every second, restarts a dead or hung server (up to 10 times), and a kernel caller whose driver died revives it on the spot. This is directly modelled on MINIX 3. Limits: requests in flight at the time of the crash fail, and there is no recorded test of killing zfs-server under load. ZFS's copy-on-write design should keep the disk consistent, but this is not verified. |
| **Least privilege** | ⚠️ Partial | Each driver gets only the device memory ranges and interrupt lines the supervisor granted (`set_grants`, `irq_register`). **But there is no IOMMU support:** a driver can program its device to DMA into any physical memory, including the kernel's. A malicious or badly broken driver can still take over the machine. MINIX 3 has the same gap; Windows, macOS and Linux (when configured) close it. |
| **Small trusted core** | ❌ Weak | The kernel is about 98,000 lines, about half of it the Linux ABI. MINIX 3's kernel is in the low tens of thousands of lines, seL4's about 10,000. Hydra's trusted core is far smaller than Linux's (tens of millions of lines with drivers) but not microkernel-sized. |
| **IPC design** | ⚠️ Pragmatic | See section 5. Fast and simple, but calls are serialized and the kernel waits on user processes while holding its own locks. |
| **Personality as a server** | ❌ Not done | The Linux ABI runs in the kernel. That is the same choice as macOS (the BSD layer in XNU) and Windows' WSL1 (a Linux layer in the NT kernel), not MINIX's (PM and VFS servers). It is the main reason Hydra is a hybrid. |

**Overall:** Hydra is a **hybrid kernel with a genuine microkernel driver model**. By the "where do drivers and file systems live" test, it is closer to MINIX 3 than to any mainstream OS. By the "how big is the trusted core" test, it sits with Windows and macOS, because like them it keeps its OS personality in the kernel.

## 5. Hydra's IPC: the main design trade-off

How a call works today (`src/ipc/service.rs`):

1. The client copies data into the service's shared window (256 KiB).
2. It sends a 32-byte message containing offsets, never pointers.
3. **The CPU is handed straight to the server** (`begin_handoff`), and nothing else runs for that caller until the server replies or the 5-second deadline passes.

**Why it was built this way:** most clients are the *kernel itself*, deep inside a subsystem with its locks held. An example is the file layer asking the disk driver for a block. Handing the CPU over makes the driver behave exactly like an in-kernel function call: nobody else can grab those locks meanwhile. This made it possible to move drivers out without rewriting the kernel's locking.

**What it costs:**
- **Serialization:** requests to a service run one at a time, and nested calls form a stack.
  - Group H found a real bug here on 2026-11-17: with two CPUs, a reply could be lost if it wasn't for the call on top of the stack (fix in `bba48c0`, being tested).
  - A pure microkernel lets servers run concurrently and queue requests.
- **Inverted dependency:**
  - In MINIX, the file-system *process* calls the driver *process*, and the kernel only carries messages.
  - In Hydra, the *kernel* is the client and waits on user processes.
  - A hung driver therefore stalls a kernel path for up to the 5-second deadline, with locks held.
- **Copying:** bulk data is copied into and out of the window.
  - This is fine at today's speeds (about 128–177 MiB/s disk reads in VMs).
  - It will matter for NVMe and fast networks.
  - MINIX uses grants and L4-family kernels map pages instead of copying.

## 6. What each other system teaches

- **MINIX 3:** the reference Hydra follows for drivers and restart. It shows that putting even VFS and process management in servers is possible. The cost is that performance was never MINIX's strength.
- **Linux:** shows the alternative: everything in the kernel, very fast, enormous driver coverage, but a single driver bug can crash the machine. It offers escape hatches: FUSE for file systems, and UIO and VFIO for user-space drivers, which rely on the IOMMU.
- **FreeBSD:** monolithic like Linux. Its contribution is **Capsicum**: fine-grained capability rights for processes. Hydra's ABAC and Landlock work covers similar ground.
- **Windows NT:**
  - Started with microkernel ideas, then moved graphics into the kernel (NT 4) for speed. It now moves pieces back out:
    - the user-mode driver framework (UMDF);
    - the user-mode half of graphics drivers;
    - GPU driver reset (TDR) so a display-driver crash no longer means a blue screen.
  - WSL1 was a Linux syscall layer inside the NT kernel: the same architecture as Hydra's Linux layer.
- **macOS:** Mach was a microkernel, but XNU runs Mach and BSD in one address space. Apple now moves drivers out with **DriverKit** (user-space driver extensions that restart on crash, protected by the IOMMU). This is the most mainstream example of the direction Hydra already took.

## 7. If you want Hydra to be more of a microkernel

In order of value for effort:

1. **IOMMU (Intel VT-d) support.** Without it, user-space drivers are isolated from *bugs* but not from *malice* or wild DMA. This is the single biggest gap in the isolation story. The target NUC (i5-4250U) supports VT-d.
2. **Move the network protocols (`src/net`, 4,500 lines) into a server** next to e1000-driver, as MINIX does. They take input from the network, so they are attack surface; moving them out adds isolation where it matters most.
3. **Retire the in-kernel Wayland compositor and console graphics** now that display-server and KDE's own compositor exist. This leaves the kernel with only a minimal emergency console.
4. **Move the kernel shell (10,200 lines) out** into a user-space program for diagnostics. It is useful, but nothing about it needs ring 0.
5. **Let servers run concurrently.** Replace the strict hand-off for calls that don't hold kernel locks with queued, asynchronous requests. Use page grants instead of copying for large transfers.
6. **Move the Linux ABI into a server** (a big project: half the kernel). This is what would make Hydra a true microkernel. Neither Windows nor macOS did it, for performance reasons. A middle path is to keep the system-call entry in the kernel and move self-contained pieces out (for example netlink, io_uring or BPF emulation).

Items 1–4 are realistic and would materially strengthen the design. Item 6 is optional: Hydra's goal is to be the easiest Unix for Windows users, and a hybrid with user-space drivers already gives most of the crash-resistance benefit the user can feel.
