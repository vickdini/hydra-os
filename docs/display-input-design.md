# Display, input, sound and terminals out of the kernel: design (step 0 for wave 6)

Microkernel wave 5, Group 15, 2026-11-18. Base: `host-unit-tests` 329aaf7. **No kernel or
driver changes in this step**: this document, the measurement hooks in
`tools/displaybench/` (applied to a throw-away build only) and nothing else. The numbers come
from two KDE sessions in a KVM virtual machine with 2 CPUs, on a kernel built with those hooks.

**Who this is for:** the user (technical, not a kernel specialist), who has to decide where
sound and the display go (`docs/microkernel-plan.md`, "Still open"), and the agents of wave 6,
which does step 5 of [linux-server-design.md](linux-server-design.md) (section 7.2).

## 0. The answer in brief

- **What moves:** about 6,000 lines: `drm` (1,621), `evdev` (689), `snd` (2,137), `tty`
  (848) and `pty` (735). **What stays in the kernel in every option:** the text console and
  its scrollback, the boot splash, the panic screen, the emergency prompt, the PS/2 and USB
  input interrupt paths, and the **hot keys** (Ctrl+Alt+F1/F2, F12, Scroll Lock), so the
  console still works when user space is stuck.
- **Measured today** (KDE in a 2-CPU VM, section 2):
  - a busy desktop (Firefox open, sound playing, pointer moving) makes about **730 device
    calls a second** (DRM 640, sound 83, input 9) out of about 6,400 Linux calls; an idle
    desktop makes **none**;
  - each picture is **10 DRM calls** and a **0.65–1.0 ms copy** of 4 MB to the screen inside
    the call, under the kernel lock: about **60 ms a second** at 64–77 pictures a second;
  - a pointer move reaches kwin in **about 1–5 ms** on an idle desktop, 11 ms on average on a
    busy one: kwin's own time, not the kernel's;
  - sound: PipeWire makes about 80 `SYNC_PTR` calls a second (one per 10.7 ms period); it
    underruns about **1.3 times a second**, busy desktop or quiet (a problem today, section
    2.5);
  - two kinds of waste: the desktop **keeps drawing at full speed while the console is shown**,
    and pictures are **not paced to 60 a second** (up to 77).
- **Cost of moving, for every option: about 0.2 % of a CPU** on a busy desktop (730 calls ×
  2.2 µs, plus a few hops per picture). Forwarding cost does not decide the question; every
  option also takes the 60 ms a second of copying out of the kernel lock.
- **Options** (section 3): (A) everything into linux-server; (B) a display/input server that
  speaks the Linux interfaces itself, sound beside hda-driver; (C) a small **native display
  server** that owns the screen and input, with the Linux interfaces in linux-server as its
  client, as for the network and file servers.
- **Recommendation** (section 4): **C for display and input; sound into linux-server as
  hda-driver's client; both terminals into linux-server**; fix the two kinds of waste in the
  display server (60 Hz pacing, no drawing behind the console).
- **Effort:** A 18–23, B 25–33, **C 23–28 agent-days**; C splits into **five parallel
  groups** (section 7): memory objects, terminals, display server, sound, Linux display front
  end.
- **Decisions for the user:** section 6 (seven questions).

## 1. What the code does today

### 1.1 The parts and their size

Lines are `wc -l` at 329aaf7 (comments included).

| Part | File (lines) | What it does | What it needs from the kernel |
|---|---|---|---|
| **DRM/KMS display** | `compat/linux/drm.rs` (1,621) | `/dev/dri/card0`, a `simpledrm`-like driver for the firmware's framebuffer: one CRTC, one connector, one mode (the firmware's resolution); dumb buffers, framebuffers, the legacy `SETCRTC`/`PAGE_FLIP`/`DIRTYFB` calls, a 64x64 cursor blended in software, PRIME (DMA-BUF export and import), properties, events read from the descriptor. A flip **copies the whole picture** (1280x800x4 = 4 MB in the VM) to the screen inside the `ioctl`, and the "flip complete" event is queued at once | Page frames for the buffers (`alloc_user_frame`) and a `MappedObject` so `mmap` maps them; the screen (`video::console::release_display`/`reclaim_display`); the caller's descriptor table (PRIME); a kernel task `vtd` for console switches; a `drmgone` task that gives the screen back 10 s after the last desktop file closes |
| **evdev input** | `compat/linux/evdev.rs` (689) | `/dev/input/event0..2`: the PS/2 keyboard, the PS/2 mouse, and QEMU's absolute pointer as Linux event devices: capability bitmaps, `EVIOCG*` queries, `EVIOCGRAB`, `EVIOCREVOKE`, a queue of 24-byte events per open file | The interrupt handlers push raw scancodes and mouse packets into a fixed ring (`push_scancode`, `push_mouse`, `push_abs`) and wake `INPUT_WQ`; translation to events happens when a reader reads or polls. Timestamps come from the 10 ms timer tick |
| **ALSA sound** | `compat/linux/snd.rs` (2,137) | `/dev/snd/controlC0`, `pcmC0D0p`, `pcmC0D0c`: mixer controls, the full `HW_REFINE` parameter negotiation, `SYNC_PTR`, `WRITEI`/`READI`, `mmap` of the ring, drain, xrun; `/proc/asound` text | DMA memory for the rings and the position buffer (`ContiguousFrames`, mapped into the sound controller's IOMMU domain), IPC calls to `hda-driver` (`MSG_SND_INFO/SETUP/TRIGGER/VOLUME`, only when a stream is set up, started, stopped or its volume changes), a kernel task `snd-position` that reads the controller's position buffer every 10 ms tick while a stream runs |
| **Console terminal** | `compat/linux/tty.rs` (848) | The line discipline (termios, canonical editing, echo, `ISIG` signals), shared with pseudo-terminals; the console as a Linux terminal while a Linux program runs in the foreground of `hydra-shell` (`linux chroot ...`, every suite test); the `VT_*`/`KD*` calls SDDM and logind make (answered as stubs) | Keys from the console keyboard buffer (`console::read_key`), output to the kernel console (`console::print_raw`), `proc::post_group` for Ctrl+C, `tty::pump` on every return to user mode, `attach_session`/`detach_session` from the admin interface (`admin/linux.rs`) |
| **Pseudo-terminals** | `compat/linux/pty.rs` (735) | `/dev/ptmx`, `/dev/pts/N` (Konsole, `script`, `ssh`, dpkg's log): pairs of queues around the shared line discipline, window size and `SIGWINCH`, controlling terminals | Only descriptors, sessions and process groups (`proc::session_of`, `post_group`), and `FileDescriptor::Pty` in `fs/fd.rs`. It is a pure descriptor object, like a pipe |
| Character device glue | `compat/linux/chardev.rs` (302) | The `CharDevice` trait; opening by major number (226 DRM, 13 input, 116 sound) | |

**What stays in the kernel in every option** (it is the emergency console, not Linux code):

| Part | File (lines) | Why it stays |
|---|---|---|
| The text console, scrollback, shadow framebuffer | `console.rs` (1,288), `video/console.rs` (868), `video/framebuffer.rs` (283), `video/font.rs` (239), `video/gop.rs` (153) | Boot messages, the emergency prompt and the panic screen must work with no user space at all. `release_display` lends the screen and keeps drawing into a shadow copy; `reclaim_display` and `panic_reclaim` take it back |
| The boot splash | `video/splash.rs` (391) | Drawn from the timer interrupt until the desktop's first picture (`compositor_took`) |
| PS/2 keyboard and mouse interrupts, QEMU's absolute pointer | `arch/keyboard.rs` (494), `arch/mouse.rs` (448), `arch/vmmouse.rs` (141) | Port I/O and IRQ 1/12. The keyboard handler also decides the **hot keys**: F12 (task dump), Scroll Lock (syscall trace), Ctrl+Alt+F1 (to the console) and Ctrl+Alt+F2 (back to the desktop). These must work when user space is stuck |
| USB input | `arch/usb_input.rs` (85) | A kernel task that fetches HID records from the ring-3 `usb-driver` (queued IPC, at each controller interrupt) and feeds them to the same code as PS/2 |

### 1.2 What they need from the kernel, in short

- **Mapped buffers:** DRM dumb buffers (`mmap` of `/dev/dri/card0` at the buffer's offset,
  and of exported DMA-BUF descriptors) and the ALSA ring (`mmap` of the PCM at offset 0) are
  pages a program maps. Today they are kernel page frames behind a `MappedObject`. A server
  cannot do that yet: step 2's server objects have no `mmap` (design section 12.3).
- **Interrupt input:** keyboard, mouse and USB input arrive in interrupt context or in the
  kernel's `usb-input` task. Today they go into a ring that evdev drains in process context.
- **The screen:** the GOP framebuffer, lent by the console (`release_display`) to the DRM
  device on the first picture, taken back on Ctrl+Alt+F1, when the desktop's master closes,
  10 s after the last DRM file closes, and on a kernel panic.
- **The console hand-back** (Ctrl+Alt+F1/F2): the keyboard interrupt sees the keys, asks the
  `vtd` task to switch, which hides the session (input routed back to the console, held keys
  released, the console repainted from its shadow) or shows it again (repainted from the
  current framebuffer). hydra-logind (a ring-3 Linux program, `userland/hydra-logind`) handles
  the *Linux* side of session switches (DRM master, `EVIOCREVOKE`); the kernel's switch is
  between "the console" and "the desktop", which Linux does not know about.
- **The boot splash** ends when the desktop draws its first picture (`compositor_took`, called
  from `release_display`).
- **Signals and sessions:** Ctrl+C and Ctrl+\ on a terminal signal its foreground process
  group; window size changes send `SIGWINCH`; the console terminal is pumped on every return
  to user mode (`arch/idt.rs`), so Ctrl+C works while a program computes.
- **Sound DMA:** the rings and the position buffer are kernel memory mapped into the sound
  controller's IOMMU domain; they live as long as the kernel, across driver restarts.

### 1.3 How KDE uses them

Measured with the hooks (section 2) and read from the code.

- **kwin_wayland draws in software** (no GPU in the VM) and shows each frame with the legacy
  KMS calls. Per frame it makes **10 DRM `ioctl`s**: it imports the frame's buffer as a
  DMA-BUF (`PRIME_FD_TO_HANDLE`, twice), wraps it in a new framebuffer (`ADDFB2`), flips to it
  (`PAGE_FLIP` with an event), removes the previous one (`CLOSEFB`, then `RMFB`, and
  `GEM_CLOSE` twice), asks for the CRTC (`GETCRTC`), and sets the cursor (`CURSOR2`). It then
  waits in `epoll_wait` for the DRM descriptor to become readable and reads the flip event.
- **The cursor** is a separate path: each pointer move is a `CURSOR2` call that repairs the
  64x64 area under the old position and blends the cursor at the new one.
- **libinput** (inside kwin) reads `/dev/input/event*` from the same `epoll` loop. logind
  (`hydra-logind`) opens the devices for kwin (`TakeDevice`) and revokes them on a session
  switch (`EVIOCREVOKE`, `DROP_MASTER`).
- **PipeWire** opens `pcmC0D0p` through ALSA's library, maps the ring, and keeps it filled
  on its own timer (it never `poll`s the PCM); it learns the hardware position with
  `SYNC_PTR`.
  WirePlumber watches the mixer (`controlC0`).
- **SDDM** (the login screen) runs its own kwin on DRM, and switches "VTs" with `VT_ACTIVATE`
  (a stub: Hydra has one Linux VT).
- **Konsole** uses a pseudo-terminal; the console terminal is used only by programs run from
  `hydra-shell` (`linux chroot ...`), which includes every suite test.

### 1.4 What calls into them from the rest of the kernel

| Caller | Calls | After the move |
|---|---|---|
| `arch/keyboard.rs`, `arch/mouse.rs`, `arch/usb_input.rs` | `evdev::push_*`, `evdev::routing`, `drm::request_vt_switch`, `drm::session_hidden`, `tty::INPUT_WQ` | Raw input goes to a shared ring plus a notification; the hot keys stay here |
| `arch/idt.rs` | `tty::pump` on every return to user mode | Goes: console keys reach the terminal's owner through the same notification |
| `video/console.rs` | (called by `drm`) | Lends the screen to a server instead of to `drm.rs`; must be able to take it back without the server's help |
| `admin/linux.rs`, `admin/console.rs` | `tty::attach_session`/`detach_session`, `tty::INPUT_WQ` | A notification to the terminal's owner |
| `task/supervisor.rs` | `snd::set_controller`, `snd::start` | Moves with sound |
| `compat/linux/vfs.rs` (19 references), `fs/fd.rs` (3), `select.rs`, `mod.rs` | console reads/writes/`ioctl`s, `FileDescriptor::Pty`, pty paths and `stat`, `tty::pump` | Routed by descriptor kind to the server (Group 12's routing in wave 5) |
| `compat/linux/devices.rs`, `fs.rs` | evdev capability lists for udev's database, `/proc/asound` text | Asked from the owner, or written by it into the Linux root |

## 2. Measurements today

### 2.1 How they were measured

- **Hooks** (`tools/displaybench/instrument.py` applied to 329aaf7, built, measured, then
  removed; never committed): counters in `drm.rs`, `evdev.rs`, `snd.rs`, `tty.rs` and `pty.rs`;
  the time of each picture copy (`present`) and cursor update; and input latency. A kernel task
  prints one `[dstat]` block on the serial port every 5 s. Linux system call totals come from
  the kernel's own profiler (`linux prof on`). `tools/displaybench/dstat.py` turns the log into
  the tables below.
- **Input latency** is measured from the interrupt that delivered the oldest unread raw input
  (keyboard byte or pointer report) to (1) the `read` of `/dev/input/event*` that returned it,
  (2) the next cursor update and (3) the next picture shown. (2) and (3) are upper bounds: when
  an input changes nothing on screen, the next update belongs to something else.
- **One KDE session, KVM, 2 CPUs, 1280x800**, `kde_kde.sh` (SDDM, login, then scripted
  phases: idle, pointer moves, typing into KRunner, Firefox on Wikipedia, PgDn/PgUp, sound with
  `pw-play` in a loop, the console shown with Ctrl+Alt+F1). Pointer moves come from the
  harness's `>move` steps, about 2.4 per second: slower than a real hand. A second session
  repeated the sound measurements and logged the stream parameters; its Firefox launch was
  lost (a keystroke), so its sound phase ran on a quiet desktop.
- **No crash** in either session (`signal N at` in the log: none); the sound card's WAV
  output had samples.
- Run-to-run noise was not measured (one session each); the host ran other groups' VMs.

### 2.2 Call rates (per second)

| Phase | All Linux calls | DRM `ioctl`s | Pictures shown | Cursor updates | evdev `read`s | PCM `ioctl`s | tty + pty |
|---|---:|---:|---:|---:|---:|---:|---:|
| SDDM login screen, idle | (profiler off) | 22 | 2.2 | 2.2 | 0 | 0 | 0 |
| Desktop, idle | 35 | 0 | 0 | 0 | 0 | 0 | 0 |
| Desktop, pointer moving | 246 | 39 | 3.6 | 8.4 | 9.5 | 0 | 0 |
| Typing into KRunner | 4,133 | 204 | 20 | 20 | 4.8 | 0 | 2 |
| Firefox page open (it animates) | 6,390 | 640 | 64 | 64 | 0 | 0 | 0 |
| Firefox, PgDn/PgUp once a second | 4,690 | 730 | 73 | 73 | 3.1 | 0 | 0 |
| Sound playing, Firefox open | 5,450 | 553 | 48 | 48 | 0 | 82 | 0 |
| Sound, Firefox, pointer moving | 6,432 | 638 | 63 | 68 | 8.9 | 83 | 0 |
| Console shown (Ctrl+Alt+F1), Firefox open behind it | 5,436 | 623 | 0 | 0 | 0 | 0 | 0 |

- **The device calls are a small share of all calls:** at most about 730 a second (DRM, evdev
  and PCM together) out of 5,000–6,500 when the desktop is busy, about 11 %. An idle desktop
  makes none.
- **Per picture kwin makes 10 DRM `ioctl`s** (from the per-number counts over 2,965 pictures):
  2 `PRIME_FD_TO_HANDLE`, 2 `GEM_CLOSE`, and one each of `ADDFB2`, `PAGE_FLIP`, `RMFB`,
  `CLOSEFB` (unknown to Hydra: it answers `EINVAL` and kwin falls back to `RMFB`), `GETCRTC`
  and `CURSOR2`. A pointer move without a new picture is one `CURSOR2`.
- **Terminals are quiet** on the desktop: no pty traffic without Konsole; the console terminal
  is busy only during the suite and `linux chroot` commands.
- **Two waste findings** (they matter more than any forwarding cost):
  1. **The desktop keeps drawing while the console is shown:** 623 DRM calls a second behind
     Ctrl+Alt+F1, pictures copied nowhere. The kernel hides the session from the screen but
     kwin is never told (a Linux VT switch would make logind pause the session's devices).
  2. **Flips are not paced:** the "flip complete" event is queued at once, so kwin draws as
     fast as it can: up to 77 pictures a second, 43 % of the gaps under 10 ms. A real screen
     completes flips at its refresh rate (60 Hz).

### 2.3 Pictures and frame time

| What | Value |
|---|---|
| Copying one picture to the screen (4 MB, inside `PAGE_FLIP`, under the kernel lock) | **0.65–1.03 ms** average per 5-second block, maximum 15.6 ms |
| Busy desktop (Firefox): pictures per second | 48–77 |
| Time spent copying pictures, busy desktop | about **60 ms per second** (6 % of one CPU), all of it holding the kernel lock |
| Gaps between pictures, Firefox with PgDn/PgUp (2,965 pictures) | < 10 ms: 43 %; 10–17 ms: 41 %; 17–20 ms: 7 %; 20–34 ms: 6 %; 34–100 ms: 3 %; more: 0.4 % |
| Cursor update (64x64 repair and blend) | 40–85 µs average (one per picture, and one per pointer move) |
| SDDM login screen | 2.2 pictures a second (its clock and animation) |

### 2.4 Input latency (from the interrupt; ms)

| Phase | Events | To the evdev `read` | To the next cursor update | To the next picture |
|---|---:|---|---|---|
| Pointer, idle desktop | 84 | average 2.2; 55 % < 1, 90 % < 5; max 35 | average 4.0; 86 % < 5 | average 9.1; 43 % < 5, 90 % < 17 |
| Pointer, Firefox animating and sound playing | 56 | average 11; 71 % < 5; max 96 | average 21; 63 % < 5 | average 26 |
| Keys, Firefox scrolling | 31 | average 38; max 105 | average 61 | average 62 |
| Keys into KRunner as it starts | 25 | average 42; max 223 | | |

- With an idle desktop a pointer move reaches kwin in about 1–5 ms and the screen within one
  frame. With a busy desktop the time is **kwin's own**: its main thread draws in software and
  reads input between frames. The kernel's part (interrupt, ring, wake-up) is in the
  microseconds and does not show at this scale.
- So an extra IPC hop on the input path (tens of microseconds at most) is invisible next to
  these numbers.

### 2.5 Sound

| What | Value |
|---|---|
| Stream PipeWire chose (from `HW_PARAMS`) | 48 kHz, 16-bit stereo, **period 512 frames (10.7 ms)**, 32 periods, buffer 16,384 frames (341 ms), `mmap` access. (At startup WirePlumber also probes 960 x 5 and 2048 x 32 with read/write access.) |
| PCM calls while playing | **75–83 a second**: `SYNC_PTR` (about one per period) and, after each underrun, `STATUS_EXT`, `DROP`, `PREPARE`, `START`. PipeWire never `poll`s the PCM: it runs on its own timer |
| The kernel's position task | Every 10 ms timer tick while a stream runs (100 wake-ups a second); it calls hda-driver only to start or stop a stream |
| **Underruns (xruns)** | **81 in 65 s** with Firefox animating (run 1); **60 in 50 s** with a quiet desktop (run 2, 2 pictures a second). About 1.3 a second **whatever the desktop does** |
| Mixer (`controlC0`) | no calls while playing |

- **Underruns are a problem today**, independent of the desktop's load: PipeWire keeps only a
  little audio queued in the large buffer, and something in the path (the 10 ms position
  tick against a 10.7 ms period, QEMU's controller fetching ahead in 8 KiB steps, or
  PipeWire's timing on Hydra) lets it run dry about once a second. The sound plays (the WAV
  has the samples), with short gaps. This was not investigated further here; wave 6's sound
  group should measure it before and after its move (and may find the cause on the way).
- The **audio hot path never reaches hda-driver**: the position is read from a page the
  controller writes. Moving the ALSA layer keeps that property in every option, as long as
  the page is mapped into whichever server owns the ALSA layer.

## 3. The options

All three options move the same Linux code out of the kernel and keep the same things in it
(section 1.1: the console, the splash, the interrupt handlers and the hot keys). They differ
in **which process owns the screen and the input devices**, and **where the Linux interfaces
(`ioctl` formats, KMS objects, evdev queues, ALSA's parameter rules) are served**.

### 3.1 (A) Everything into linux-server

- `drm`, `evdev`, `snd`, `tty` and `pty` become linux-server's server objects, like message
  queues in step 2. A call on `/dev/dri/card0` is one forward (+2.0–2.5 µs).
- The kernel lends the framebuffer **to linux-server** (mapped into its address space), and
  hands it the raw input ring and the sound rings.
- linux-server's worker copies the picture to the screen during `PAGE_FLIP` (as the kernel
  does today, but outside the kernel lock), a linux-server thread translates input and another
  follows the sound position every 10 ms.
- **Simplest**: one server, no new protocol between servers, the fewest new primitives.
- **But** the process that runs every Linux program's descriptors also gets direct access
  to the screen and the input devices, and any future real display driver (a GPU) would have
  to live there too.

### 3.2 (B) A display/input server with the Linux interfaces in it; sound beside hda-driver

- A new ring-3 **display server** serves `/dev/dri/card0` and `/dev/input/event*` itself,
  with the whole Linux `ioctl` interface; terminals go to linux-server; the **ALSA layer goes
  into the sound driver's process** (`hda-driver`), which then serves `/dev/snd/*` itself.
- The kernel must forward a call on such a descriptor **to a server other than
  linux-server**. Two ways:
  - **B1, relay:** linux-server owns the descriptor and passes each call on to the display
    or sound server by IPC: a forward (+2.2 µs) plus an IPC round trip (Handoff 5.8 µs,
    Queued 9–19 µs; design section 13.1), about **+8–11 µs per call** instead of +2.2.
  - **B2, direct:** the forwarding machinery of step 1 (syscall pages, workers, direct
    switch, readiness words) is generalized to several servers, each server object naming its
    owner. +2.2 µs per call, but it is a large change to `src/lx` (2,467 lines, built around
    one server: one forwarding table, one request table and worker list, one server task, one
    readiness window), in the files waves 5 and 6 all edit. And from step 6a on the
    descriptor table lives in linux-server, so the kernel no longer knows which descriptor
    belongs to which server: B2 then needs a kernel shadow table (the "fast file handles" of
    design section 6.4) or falls back to B1.
- **Better isolation for sound:** a bug in the ALSA code ends only sound, not every Linux
  program.

### 3.3 (C) A native display/input server; the Linux interfaces in linux-server

- A new ring-3 **display server** owns the screen and the input devices and speaks a **small
  native protocol**: "show this buffer" (with a completion), "set or move the cursor", "the
  screen was taken / given back", and batches of input records. It knows nothing of Linux.
- **linux-server serves the Linux interfaces** (`/dev/dri/card0`, `/dev/input/event*`) as a
  *front end*, as its client. This is the pattern the design already follows everywhere else:
  zfs-server is native and the Linux VFS is its client; net-server is native and the Linux
  socket layer becomes its client in step 3 (wave 5).
- **Sound follows the same pattern with no new server:** hda-driver already *is* a native
  sound driver with a small protocol (`MSG_SND_SETUP/TRIGGER/VOLUME` and a position buffer the
  controller writes), and the ALSA layer moves into linux-server as its client. For sound, A
  and C are the same thing.
- Calls from programs are one forward each (+2.0–2.5 µs), as in A. The extra hop to the
  display server happens **once per frame** (the "show this buffer" message, asynchronous) and
  **once per input batch** (a notification), not per call.
- **Later uses:** the display server is where a real display driver goes (virtio-gpu in VMs,
  the NUC's Intel graphics, real monitor modes), and where any non-Linux front end connects:
  the BSD core's DRM and evdev front ends (FreeBSD's DRM, `drm-kmod`, and its evdev are ports
  of the Linux interfaces), or a native Hydra program that draws (a graphical recovery screen).
- **Honest limit:** FreeBSD, macOS and Wine programs draw through **kwin over Wayland**
  ([personality-design.md](personality-design.md) section 3.5), not on the display device, so
  for *programs* a native display server brings nothing soon. Its value is the device
  ownership, a future GPU driver, and a clean split.

### 3.4 IPC hops on the hot paths

"Forward" is the step 1 direct switch, measured at **+2.0–2.5 µs** per call after wave 4
(design sections 13.1 and 13.3). An IPC round trip between two servers is 5.8 µs (Handoff) or
9–19 µs (Queued) (section 13.1). A doorbell (`SYS_SVC_SIGNAL`) is about 1.4 µs (section 12.2:
`mq_rtt` 9.55 → 8.16 µs without it). Waking a sleeping server thread on another CPU costs
roughly 5–10 µs more (an estimate from the Queued numbers, not measured alone).

| Hot path | Today | A | B1 (relay) | B2 (direct) | C |
|---|---|---|---|---|---|
| **Picture shown** (`PAGE_FLIP`, 10 DRM calls per picture) | 10 calls in the kernel; the 4 MB copy inside the call, under the kernel lock | 10 forwards; the copy in a linux-server worker | 10 × (forward + IPC) | 10 forwards to the display server; the copy there | 10 forwards; one asynchronous "show" message to the display server, which copies and answers with a completion (flip event) |
| **Input event** (interrupt → kwin's `read`) | ring → wake kwin → `read` in the kernel | ring + notification → linux-server translates → readiness word + doorbell → kwin's `read` forwarded | as C, plus the IPC relay on `read` | ring + notification → display server → readiness → `read` forwarded to it | ring + notification → display server routes and translates → a batch to linux-server (notification) → readiness → `read` forwarded |
| **Audio period** (PipeWire's `SYNC_PTR`, about 80 a second) | in the kernel; the position task reads the controller's position page every 10 ms | 1 forward; a linux-server thread reads the position page | forward + IPC | 1 forward to hda-driver's process | as A |
| **Console terminal** (a Linux program's `write` to the console) | in the kernel | 1 forward + a console-write primitive | same | same | same |

### 3.5 Estimated cost

From section 2.2's busiest phase (sound, Firefox and the pointer: about 638 DRM, 9 evdev and
83 PCM calls a second, 64 pictures and about 10 input batches a second).

| | A | B1 | B2 | C |
|---|---:|---:|---:|---:|
| Added per device call | +2.2 µs | +8–11 µs | +2.2 µs | +2.2 µs |
| Device calls per second (busy) | 730 | 730 | 730 | 730 |
| Per-picture and per-input-batch hops | none | none | none | 74 × about 10 µs |
| **Added CPU time per second, busy desktop** | **1.6 ms (0.16 %)** | 6–8 ms (0.7 %) | 1.6 ms | **2.4 ms (0.24 %)** |
| Added latency, input | + 1 wake-up + 1 forward (tens of µs) | + IPC on the read | as A | + 2 wake-ups + 1 forward (tens of µs) |
| Picture copy (about 60 ms per second today) | moves to linux-server, **outside the kernel lock** | to the display server | to the display server | to the display server, outside the caller's call |

- **Every option is far inside the budget** (desktop at most 5 % slower; design section 6.6),
  even B1. The forwarding cost does not decide this question.
- **Every option gains** what is today the largest display cost in the kernel: 60 ms a second
  of copying under the kernel lock, during which no other CPU can enter the kernel for a
  system call that needs the lock. Fixing the two waste findings of section 2.2 (pace flips at
  60 Hz, stop drawing while hidden) would cut it further: from 64–77 to at most 60 pictures a
  second, and to none behind the console.
- **KDE start:** the login makes few device calls (25–250 DRM calls a second during the
  Plasma start, against 3,600–10,900 calls in all); at +2.2 µs that is under 1 ms a second,
  under 0.1 %.

### 3.6 What the user sees when something crashes

| What crashes | Today | A | B | C |
|---|---|---|---|---|
| DRM or evdev code (a bug) | Kernel panic: the machine stops, the panic text shows | linux-server dies: **every Linux program ends**, the desktop comes back at the login screen (decision 6 of the plan) | The display server dies: the screen goes back to the console at once, kwin loses its devices and the session ends; SDDM's greeter returns when the server is restarted. **Non-graphical Linux programs keep running** | Bug in the Linux front end: as A. Bug in the display server: as B |
| ALSA code | Kernel panic | linux-server dies: as above | **Only sound stops**; PipeWire sees errors on the device and (to be verified) reopens it after the restart | as A |
| hda-driver (the sound driver) | Restarted; the kernel's calls fail meanwhile; streams must be set up again | same as today, linux-server reprograms the stream | the ALSA layer dies with it: sound stops, restarts | as A |
| Terminal code | Kernel panic | linux-server dies | linux-server dies | linux-server dies |
| linux-server | every Linux program ends (today's crash policy) | same; the screen goes back to the console when the desktop's files close | same | same |
| The display server itself | n/a | n/a | as row 1 | console at once, desktop session ends, login screen back after the restart |
| User space stuck (no server answers) | Ctrl+Alt+F1 and the emergency prompt work: the kernel handles the keys | same: **the hot keys and the screen take-back stay in the kernel** in every option | same | same |

The kernel can always take the screen back without the server's help: it lent the
framebuffer by mapping it into the server, so it can map that range to a blank page instead
(no protocol needed for safety; the notification only stops wasted work).

### 3.7 Size, new primitives, effort

| | A | B | C |
|---|---|---|---|
| Lines moved out of the kernel | about 6,000 (`drm` 1,621, `evdev` 689, `snd` 2,137, `tty` 848, `pty` 735) | same | same |
| New code | about 600 in the kernel (primitives), the moved code in linux-server | about 600 + multi-server forwarding (B2, about 1,000) or object passing between servers (B1); a new server; ALSA inside hda-driver | about 600 in the kernel; a new display server of about 800–1,000 lines (screen, copy, cursor, input routing and translation, hand-back); a native protocol of about 200 |
| New primitives | memory objects and server-object `mmap` (below), screen lending, the raw input ring with notification, console terminal I/O | the same, plus forwarding to several servers (B2) or relaying with memory objects passed between servers (B1) | the same as A, plus sharing a memory object with a second server (the display server reads the clients' buffers) |
| Agent-days | **18–23** | **25–33** | **23–28** |
| Parallel groups in wave 6 | 4 | 4 (the forwarding change blocks the others) | **5** |

The primitives, in every option:
- **Memory objects for server objects** (the `obj_anon` and `as_map` of design section 5.2,
  in the form these devices need): a server makes an anonymous object (`obj_anon`), or the
  kernel hands it one made of DMA frames (`obj_dma`, the sound rings); when a program calls
  `mmap` on the server's descriptor, the server names the object and offset and the kernel
  maps its pages (`LX_OBJ_MMAP`). A DMA-BUF descriptor is a second server object for the same
  memory object. Step 6a (file `mmap`) and step 8 (System V shared memory) reuse it.
- **Screen lending:** the kernel maps the framebuffer into the owning server, takes it back
  (maps a blank range) on Ctrl+Alt+F1, on a panic and when the server dies, and tells the
  server with a notification; the server says when it no longer needs the screen. The boot
  splash ends on the first lend, as today.
- **Raw input ring:** a page shared with the owner: scancodes, pointer packets and absolute
  reports with their interrupt time (in nanoseconds, not 10 ms ticks), plus a notification.
  The hot keys are decided in the interrupt before the ring, as today; while the console owns
  the keyboard, nothing goes to the ring.
- **Console terminal I/O:** "write these bytes to the console" and "console keys" (a
  notification while a Linux program owns the console), and attach/detach notifications from
  hydra-shell's `linux chroot`.
- **Signals to a process group** (`sig_post` with a group, for Ctrl+C and `SIGWINCH`) and,
  until step 7, a query for a process's session and group.

### 3.8 Risks

- **The desktop is the test.** Every option changes the path of every picture and every key.
  A subtle mistake (a lost flip event, a lost wake-up) freezes the desktop rather than failing
  a test. The switch back (`lx=kernel`) and the per-group KDE checks are the protection.
- **`mmap` of server objects is new kernel ground:** pages that a server owns, mapped into
  many programs, shared across `fork`, outliving the descriptor, and a server that dies while
  they are mapped (programs then get `SIGBUS` on new faults; existing pages stay valid until
  unmapped). A dedicated test comes first.
- **The console terminal carries the whole suite.** Every suite test prints through it; a
  bug there fails all 78 tests at once (easy to see, but it blocks every other group's
  testing). Group T should merge early or keep the console terminal on the kernel path until
  its own tests pass.
- **SDDM's recovery after a display server crash** (option B or C) is not verified: kwin
  exits when its DRM device fails, and SDDM normally restarts its greeter, but this has not
  been tried on Hydra.
- **PipeWire's recovery after a sound server crash** (option B) is not verified either.
- **Sound underruns already happen today**, about once a second, busy desktop or not
  (section 2.5). A move must not make them worse; a server thread that follows the position
  must run with a priority at least that of today's kernel task.
- **Real hardware:** only QEMU's standard VGA, PS/2, vmmouse and intel-hda were measured.
  The NUC (Intel HD 5000 under GOP, xHCI keyboard, Realtek-type HDA codec) is untested.

## 4. Recommendation

- **Display and input: option C.** A small native **display server** owns the screen and the
  input devices; **linux-server serves `/dev/dri/card0` and `/dev/input/event*`** as its
  client.
  - It is the pattern of the whole design: native servers (zfs-server, net-server, the
    drivers) and the Linux interfaces in linux-server as their clients. Program calls stay one
    forward each (+2.2 µs), like every other moved call, and the descriptor table can move in
    step 6a without a second forwarding target.
  - The extra hop is once per picture and once per input batch, asynchronous: about 0.1 % of
    a CPU on a busy desktop (section 3.5).
  - The process that runs every Linux program's descriptors does not get the screen and the
    input hardware, and a future real display driver (virtio-gpu, the NUC's Intel graphics,
    real monitor modes) has its home.
  - It costs about 4–5 agent-days more than A (the server and its protocol), but splits wave 6
    into five groups instead of four.
  - **Not B:** B puts the Linux interface in a second server, which needs either a relay
    (4–5 times the cost per call, still within budget) or forwarding to several servers, a
    large change in the middle of `src/lx` that step 6a would undo or complicate. Its one real
    advantage, sound isolation, is not worth that.
- **Sound: in linux-server, as hda-driver's client** (A and C agree). hda-driver already is a
  native sound driver with a small protocol, and the hot path (the position) needs no call to
  it. A bug in the ALSA code then ends every Linux program (as any linux-server bug does); the
  alternative (B) isolates it at the price above.
- **Terminals: both the console terminal and pseudo-terminals into linux-server.** The line
  discipline is shared by both; the console terminal needs two small primitives (write, keys).
- **The hot keys, the screen take-back, the boot splash and the emergency console stay in the
  kernel**, in every option.
- **Fix the two waste findings in the same wave** (section 2.2): the display server completes
  flips at 60 Hz (an emulated vertical blank), and while the console is shown it holds the
  completions back, so kwin stops drawing. That saves more CPU than the whole move costs.

## 5. The native display protocol (sketch for wave 6)

Messages between linux-server's front end and the display server (endpoint 0x23, the old
display endpoint, still reserved in `ipc/protocol.rs`). Buffers are memory objects (section
3.7) the front end shares with the display server; nothing is copied through IPC.

| Message | Direction | Meaning |
|---|---|---|
| `DISP_INFO` | front end → server | Screen size, stride, pixel format, refresh rate (60 Hz for the firmware framebuffer), whether the screen is lent |
| `DISP_SHOW(object, offset, pitch, format, damage, cookie)` | → server, asynchronous | Show this buffer; a doorbell, no reply. The server copies (only the damaged rows when given) and completes |
| `DISP_DONE(cookie, time)` | server → front end, notification ring | The picture is on screen (at the emulated vertical blank). The front end then queues the DRM flip event. Held back while the console is shown |
| `DISP_CURSOR(object or none, hot x, y)` / `DISP_MOVE(x, y)` | → server, asynchronous | Cursor image and position |
| `DISP_STATE(shown or hidden)` | server → front end | The console took the screen (Ctrl+Alt+F1) or gave it back; the front end reports nothing to programs (as today), but completions stop |
| `DISP_INPUT` | server → front end, a shared ring + notification | Batches of evdev records per device (24 bytes each, with nanosecond time stamps), already translated and routed |
| `DISP_RELEASE` | front end → server | No session needs the screen (the last master closed): the server returns it to the console (today's 10 s grace stays) |

The front end keeps everything Linux-specific: KMS objects and ids, properties, GEM handles,
PRIME descriptors, the per-file DRM event queues, master and revoke rules, evdev capability
bitmaps and `EVIOCG*` queries, the per-file input queues and `SYN_DROPPED`.

## 6. Decisions for the user

1. **Where do the display and input go?**
   - Recommended: **(C)** a small native display server that owns the screen and the keyboard
     and mouse, with the Linux display interface in linux-server as its client, the same way
     the network and file servers are used. About 23–28 agent-days for the whole wave.
   - Simpler: **(A)** everything inside linux-server: about 5 agent-days less, but the server
     that runs all Linux programs then also drives the screen, and a future graphics driver
     would have to live there.
   - Not recommended: **(B)** a display server that speaks the Linux interface itself: the
     most work, for little gain.
   - None of them makes the desktop measurably slower (about 0.2 % of a CPU).
2. **Where does sound go?**
   - Recommended: **into linux-server**, talking to today's sound driver. A bug in the sound
     code would then end all Linux programs (the desktop restarts at the login screen), like any
     other bug in linux-server.
   - Alternative: **next to the sound driver**, in its own process: a sound bug would then stop
     only the sound, but every sound call costs a second hop and the forwarding machinery must
     learn to serve a second server. About 5 agent-days more.
3. **Terminals:** move both the console terminal (what Linux programs started from the Hydra
   console print to) and pseudo-terminals (Konsole, ssh) into linux-server?
   - Recommended: **yes, both** (they share their code).
   - Alternative: move only pseudo-terminals and keep the console terminal in the kernel as part
     of the emergency console: less risk for the test suite, but about 500 lines of terminal
     code stay in the kernel twice.
4. **When the display server crashes** (option C): the screen goes back to the console at once,
   the desktop session ends, and the login screen comes back when the server has restarted;
   Linux programs without windows keep running. Accept? (The alternative is to treat it like a
   linux-server crash and end every Linux program.)
5. **Fix the two waste findings in wave 6?** (the desktop draws at full speed behind the
   console; pictures are not paced to 60 a second). Recommended: yes, in the display server; it
   saves up to 60 ms of CPU a second on a busy desktop.
6. **Wave 6 with five groups at once** (section 7)? Each needs a VM now and then; the merge
   order is fixed (memory objects first). Recommended: yes. With four groups, merge the display
   server and the Linux front end into one group (about 11–13 agent-days, the longest).
7. **Should the display server be designed for a real graphics driver later** (virtio-gpu in
   VMs, the NUC's Intel graphics, choosing the monitor's resolution)? Recommended: design its
   protocol for it (several modes, a vertical blank), but build only today's firmware
   framebuffer in wave 6.

## 7. Wave 6 plan

The plan assumes the recommendation (display: option C; sound: in linux-server, hda-driver
unchanged; terminals: in linux-server). Each group keeps the in-kernel copy as the switch back
(`lx=kernel`), as every step has.

### 7.1 Five groups at once

| Group | What | Owns (files) | Needs | Agent-days |
|---|---|---|---|---:|
| **M: memory objects** | `obj_anon`, `obj_dma` (kernel-owned DMA frames handed to a server), `LX_OBJ_MMAP` (a server object's `mmap` maps a memory object), `obj_share` (map an object into another server, read-only or read-write), dropping objects with their last mapping | new `src/lx/mem.rs`; the `mmap` hook for server objects in `compat/linux/mm.rs` (one arm); `memory/vm.rs` (a `MappedObject` for server memory objects); `linux-server/src/mem.rs` helpers; host-test mirrors | nothing new | 3–4 |
| **T: terminals** | `tty` (line discipline, console terminal) and `pty` into linux-server; console terminal I/O through two primitives; pty descriptors become server objects; job-control signals to process groups | `compat/linux/tty.rs`, `pty.rs` (kept for `lx=kernel`); new `linux-server/src/tty.rs`, `pty.rs`; new `src/lx/console.rs` (console write, console keys to the server, attach/detach notes); `admin/linux.rs` (attach/detach hooks: two lines); `arch/idt.rs` (`tty::pump` guarded by the route: one line) | wave 5's routing by descriptor (Group 12's `T_BYFD` and `srv_bits`: the console descriptors a Linux program inherits must become server objects, or get their own bit) and `timer_arm` (Group 13's `SYS_LX_TIMER`, for `VTIME`); `sig_post` to a process group (one new op of `SYS_LX_SIG`); temporary: session and process group of a pid (until step 7) | 5–6 |
| **D: display/input server** | New ring-3 `display-server` (endpoint 0x23, the old display endpoint): screen lending with revocation, the picture copy, the cursor, input routing and translation to evdev records, console hand-back; kernel side: framebuffer lending (`video/console.rs`), the raw input ring and its notification (`arch/keyboard.rs`, `mouse.rs`, `usb_input.rs`), the hot keys stay in the interrupt | new `userland/drivers/display-server`; `src/video/*`; `src/arch/{keyboard,mouse,vmmouse,usb_input}.rs`; new `src/ipc/display.rs` (the kernel half of the lending protocol); `task/supervisor.rs` (one service entry); the native display protocol in `src/ipc/protocol.rs` (appended section) | Group M's `obj_share` for reading clients' buffers (stub with a copy until M merges) | 6–7 |
| **S: sound** | `snd` into linux-server; the kernel hands the rings and the position buffer to linux-server as `obj_dma` objects; linux-server becomes `hda-driver`'s client; the position task becomes a linux-server thread | `compat/linux/snd.rs` (kept for `lx=kernel`); new `linux-server/src/snd.rs`; `task/supervisor.rs` (`snd::start` hook: a few lines); `compat/linux/fs.rs` (`/proc/asound` asked from the server) | Group M (`obj_dma`, `LX_OBJ_MMAP`); `WRITEI` (no `mmap`) works before M merges | 4–5 |
| **F: Linux display front end** | `drm` and `evdev` into linux-server as the display server's client: KMS objects, GEM handles, PRIME, properties, events, evdev queues and queries | `compat/linux/drm.rs`, `evdev.rs` (kept for `lx=kernel`); new `linux-server/src/drm.rs`, `evdev.rs`; `compat/linux/chardev.rs` (majors 226 and 13 routed to the server); `compat/linux/devices.rs` (evdev capability lists from the server) | Groups M and D (their interfaces on day 0; works against a stub display server until D merges) | 5–6 |
| **Total** | | | | **23–28** |

### 7.2 Order and shared files

- **Day 0:** M writes the memory-object interface into NOTES.md (op numbers, handle rules);
  D writes the native display protocol (section 5) and the lending calls. F and S build
  against them from the start.
- **Native system call numbers:** M and D each take new numbers after the ones wave 5 used
  (60–61 are step 2's, 62–63 Group 13's `SYS_LX_TIMER`/`SYS_LX_SIGTAKE` in wave 5; so 64
  and up, checked in `ipc/protocol.rs` after the wave 5 merge); T adds operations to existing
  calls (`SYS_LX_SIG` with a process group) and one console call. Write them in
  NOTES.md before use.
- **`src/lx/mod.rs` and `linux-server/src/main.rs`** (dispatch): T, S and F each add table
  entries and dispatch arms; append-only, mark them by group, and agree in NOTES.md as wave 5
  did.
- **Merge order:** M first (S and F need it), then D, then T and S (independent), then F
  (needs M and D). T can merge any time after the wave 5 merges it builds on.
- **Every group ends with:** the full suite (78 + new tests), suite_loop if it touches the
  trap or descriptors (T, F), the IOMMU suite (S and D touch DMA and MMIO grants), host
  tests, KDE with Firefox, sound and Wine, Ctrl+Alt+F1/F2 and the boot splash, at least 3
  fresh KDE logins with no crash, USB input (`--usb`), and both `lx=kernel` and the moved
  path.

### 7.3 Tests per group

| Group | Tests |
|---|---|
| M | New `srvmap` test (a test server object whose `mmap` maps an `obj_anon`; fork shares it; unmap after close; a second process maps the same object; the server dying makes later faults `SIGBUS`, not a hang); the full suite; `lxbench` unchanged |
| T | `ptytest`, `notty`, `stdfd`, `signals` (Ctrl+C as `ISIG`), the whole suite (every test prints through the console terminal); Konsole in KDE; `apt-get install` (dpkg's pty log); `lxbench` with a new pty round trip (budget: ≤ today + 2 forwards) |
| D | Boot splash, SDDM, the desktop, Ctrl+Alt+F1/F2 back and forth 5 times, `panic 30` over the desktop, killing `display-server` under KDE (console at once; desktop back when it restarts), PS/2 and USB input, flip rate and copy time with `tools/displaybench` |
| S | `snd` (suite), `pw-play` in KDE with the WAV checked for samples, xruns over 60 s with the pointer moving, killing linux-server and hda-driver during playback, `lxbench` `SYNC_PTR` round trip |
| F | `drmtest` (add it to the suite: it needs no desktop), KDE start time (3 boots, ≤ +5 %), flip rate and input latency with `tools/displaybench` against section 2, Firefox scrolling, SDDM login and logout, two logins in a row |

## 8. What was not measured or verified

- **One session per configuration**, on a shared host: no run-to-run spread. The picture
  copy times and the call rates are stable within a phase (block to block), the latencies are
  not (they depend on what kwin is doing).
- **Input latency to the screen** is an upper bound (section 2.1), and the harness's pointer
  moves are slow (2.4 a second); a fast real mouse (100+ reports a second) would make more
  evdev reads and cursor calls, still well under the busy rate of DRM calls.
- **No prototype** of any option: the per-picture and per-batch hop cost of C (about 10 µs) is
  an estimate from the measured doorbell and Queued IPC numbers.
- **Not tried:** SDDM's and PipeWire's recovery after a server crash; Konsole or ssh traffic
  through pty (no pty traffic in these sessions); USB input (only PS/2 and the vmmouse); real
  hardware.
- **The cause of the sound underruns** (section 2.5) was not investigated: whether it is the
  10 ms position tick, the kernel lock held by the picture copy, or PipeWire's timing.

## Appendix: reproducing

- **Hooks:** `python tools/displaybench/instrument.py E:\os-N` adds them to a tree (it copies
  `dispstat.rs` and edits `drm.rs`, `evdev.rs`, `snd.rs`, `tty.rs`, `pty.rs`, `prof.rs`,
  `mod.rs`); build the kernel and the ISO as usual; `instrument.py E:\os-N --undo` restores the
  files with git. **Never commit an instrumented tree.**
- **Session:** boot with `scratch/kde_kde.sh NAME --login=` (in WSL, as for the KDE checks) and
  drive it with steps like Group 15's (`tools/displaybench/session_example.sh`, run 1's
  steps: `linux prof on` on the console before the login, so the `[dstat]` blocks include all
  Linux calls; then phases of at least 15 s each, separated by idle waits). The `[dstat]` blocks come every 5 s on the serial log.
- **Tables:** `python tools/displaybench/dstat.py LOG` prints one row per block;
  `dstat.py LOG 61-67:pointer 97-99:firefox ...` adds averages, the gap histogram, the
  latency histograms and the per-`ioctl` totals for named ranges of blocks.
- **Sound:** QEMU's `-audiodev wav` output (`kde_kde.sh` adds it) shows whether samples
  arrived; the `[dstat] snd HW_PARAMS` lines give the period and buffer each stream chose.
