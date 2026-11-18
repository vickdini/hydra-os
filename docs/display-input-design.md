# Display, input, sound and terminals out of the kernel: design (step 0 for wave 6)

Microkernel wave 5, Group 15, 2026-11-18. Base: `host-unit-tests` 329aaf7; **revised the same
day for the user's decision 9** (d0d38ab: separate services for resilience; the Linux layer is
split into several services later). **No kernel or driver changes in this step**: this
document, the measurement hooks in `tools/displaybench/` (applied to a throw-away build only)
and nothing else. The numbers come from two KDE sessions in a KVM virtual machine with 2 CPUs,
on a kernel built with those hooks.

**Who this is for:** the user (technical, not a kernel specialist), who has to decide where
sound and the display go (`docs/microkernel-plan.md`, "Still open"), and the agents of wave 6,
which does step 5 of [linux-server-design.md](linux-server-design.md) (section 7.2).

**What the revision changed.** The first version recommended option C: a small display server
with the Linux display interface inside linux-server, and sound and terminals inside
linux-server. Its main argument against separate services was that the kernel could forward
calls to only one server, and teaching it several was a large change. Decision 9 makes that
change happen anyway (Group 18, `docs/linux-services-design.md`, designs the routing to several
services). This version therefore recommends **four separate device services, each called
directly by the kernel**: display, input, sound and terminals. Sections 0, 3 to 8 are
rewritten; the code map (section 1) and the measurements (section 2) are unchanged.

## 0. The answer in brief

- **What moves:** about 6,000 lines: `drm` (1,621), `evdev` (689), `snd` (2,137), `tty`
  (848) and `pty` (735). **What stays in the kernel:** the text console and its scrollback,
  the boot splash, the panic screen, the emergency prompt, the PS/2 and USB input interrupt
  paths, the **hot keys** (Ctrl+Alt+F1/F2, F12, Scroll Lock), and who owns the screen and the
  keyboard. So the console still works when every service is stuck.
- **Measured today** (KDE in a 2-CPU VM, section 2):
  - a busy desktop (Firefox, sound, pointer moving) makes about **730 device calls a second**
    (DRM 640, sound 83, input 9) out of about 6,400 Linux calls; an idle desktop makes
    **none**;
  - each picture is **10 DRM calls** and a **0.65–1.0 ms copy** of 4 MB to the screen inside
    the call, under the kernel lock: about **60 ms a second** at 64–77 pictures a second;
  - a pointer move reaches kwin in **about 1–5 ms** on an idle desktop, 11 ms on average on a
    busy one: kwin's own time, not the kernel's;
  - sound: PipeWire makes about 80 `SYNC_PTR` calls a second (one per 10.7 ms period); it
    underruns about **1.3 times a second**, busy desktop or quiet (a problem today, section
    2.5);
  - two kinds of waste: the desktop **keeps drawing at full speed while the console is shown**,
    and pictures are **not paced to 60 a second** (up to 77).
- **Recommendation** (section 4): four services, each owning its devices, **called directly by
  the kernel** (no hop through linux-server):
  - **display** (`/dev/dri/card0`: the Linux display interface on top of a small native core
    that owns the screen);
  - **input** (`/dev/input/event*`);
  - **sound** (`/dev/snd/*`, the ALSA layer, as a client of today's hda-driver);
  - **terminals** (pseudo-terminals and the console terminal).
- **Cost: about 0.16 % of a CPU** on a busy desktop (730 calls × 2.2 µs), the same as keeping
  everything in linux-server, and cheaper than the first version's option C. Every option also
  takes the 60 ms a second of copying out of the kernel lock.
- **Resilience** (section 3.6), what the user sees when one service crashes:
  - **display:** the console appears at once; the desktop session ends and the login screen
    comes back when the service restarts; all other programs (sound, downloads, servers) keep
    running;
  - **input:** keyboard and mouse stop for a few seconds and come back; **the desktop keeps
    running** (needs device "removed/added" announcements, which Hydra does not send today:
    to build and verify in wave 6);
  - **sound:** a gap in the sound; **programs and the desktop keep running** (same
    announcements); a crash of the sound *driver* is hidden completely (at most a click);
  - **terminals:** programs in terminal windows and ssh sessions end; the desktop keeps running.
- **Effort:** about **24–30 agent-days** in **six parallel groups** (section 7), seven with
  Group 18's routing core, which they build on.
- **Decisions for the user:** section 6 (eight questions; several changed in this revision).

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
| `compat/linux/vfs.rs` (19 references), `fs/fd.rs` (3), `select.rs`, `mod.rs` | console reads/writes/`ioctl`s, `FileDescriptor::Pty`, pty paths and `stat`, `tty::pump` | Routed to the owning service by descriptor (Group 12's routing in wave 5, generalized by Group 18) |
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

All options move the same Linux code out of the kernel and keep the same things in it
(section 1.1: the console, the splash, the interrupt handlers, the hot keys). They differ in
**which process owns the screen, the input devices and the sound streams**, and **where the
Linux interfaces (`ioctl` formats, KMS objects, evdev queues, ALSA's parameter rules) are
served**.

### 3.1 (A) Everything into linux-server

- `drm`, `evdev`, `snd`, `tty` and `pty` become linux-server's server objects, like message
  queues in step 2. A call on `/dev/dri/card0` is one forward (+2.0–2.5 µs).
- The kernel lends the framebuffer, the raw input ring and the sound rings **to linux-server**.
- Simplest, but **it contradicts decision 9**: a bug in any device code ends every Linux
  program, and the devices cannot restart alone. Kept here only as the baseline.

### 3.2 (B) Separate device services, called directly by the kernel (revised)

- Each device family is **a ring-3 service of its own** that serves the Linux interface for
  its devices: display (`/dev/dri/card0`), input (`/dev/input/event*`), sound (`/dev/snd/*`)
  and terminals (`/dev/ptmx`, `/dev/pts/*`, the console terminal).
- **The kernel routes each call straight to the descriptor's owner**: a server object records
  which service owns it, and the call goes to that service's workers with the same direct
  switch and lock-free path linux-server uses today (+2.0–2.5 µs). This is Group 18's routing
  to several servers (decision 9); the device services are its first users besides
  linux-server.
- **Opening a device** (`open("/dev/dri/card0")`): path resolution finds a character-device
  node (today in the kernel's VFS, after step 6a in the file service), and the open is handed
  to the service registered for that device number (226 display, 13 input, 116 sound, 5:2 and
  136 terminals), which creates the object. One extra hop per `open`; opens are rare (a few
  dozen per login).
- **After step 6a too:** Group 16's revised VFS design (`docs/vfs-design.md`, decision 9) keeps
  the descriptor table in the kernel as a table of handles, so the kernel still knows each
  descriptor's owner and the direct route stays (the first version feared it would be lost).
- **What changed since the first version:** this option used to need either a relay through
  linux-server (+8–11 µs per call) or forwarding to several servers, "a large change in
  `src/lx`". Decision 9 makes that forwarding a planned piece of work for every service, so it
  no longer counts against this option.
- **Inside the display and input services**, the code keeps two layers, as option C proposed
  between processes: a native core (the screen, the copy, the cursor, input routing and
  translation) and the Linux interface on top. A FreeBSD front end (its DRM and evdev are ports
  of Linux's) or a real graphics driver later joins the same service, without a new hop.

### 3.3 (C) A native display server, the Linux interfaces in linux-server (first version)

- A small native display server owns the screen and input; linux-server serves
  `/dev/dri/card0` and `/dev/input/event*` as its client; sound and terminals inside
  linux-server.
- With decision 9 it loses its two advantages: routing to several servers is coming anyway,
  and the Linux display interface inside linux-server ties a display bug to every Linux
  program. It also costs one extra hop per picture (linux-server → display server) that B
  does not need.

### 3.4 How many services: the boundaries inside B

| Boundary | Separate? | Why |
|---|---|---|
| Display / input | **Two services** | They share nothing but "who owns the screen", which the kernel decides anyway (the hot keys are in the keyboard interrupt). Separate, an input crash can be survived by the desktop (libinput handles devices that disappear and come back); a display crash cannot (kwin ends without its screen). Input is small (about 700 lines) |
| Sound / hda-driver | **Two processes** | hda-driver is the hardware-facing part (registers, codec commands); the sound service is the ALSA interface and the stream state. A driver crash is then hidden: the service sets the stream up again after the restart. The hot path (the position) needs no call to the driver |
| Terminals / process and session service | **Separate** | Terminals need the caller's process group and session on each `read` and `write` (job control), which the kernel can put in the call header, and a query to the process service only for `setsid`, `TIOCSCTTY` and `tcsetpgrp` (rare). A terminal bug then ends the programs in terminals, not every Linux program. (Merged, a terminal bug ends everything; the process service is the most critical one) |
| Console terminal / pseudo-terminals | **One service** | They share the line discipline (about 500 lines) |

### 3.5 IPC hops on the hot paths

"Forward" is the step 1 direct switch, measured at **+2.0–2.5 µs** per call after wave 4
(design sections 13.1 and 13.3). An IPC round trip between two servers is 5.8 µs (Handoff) or
9–19 µs (Queued) (section 13.1). A doorbell (`SYS_SVC_SIGNAL`) is about 1.4 µs (section 12.2).
Waking a sleeping server thread on another CPU costs roughly 5–10 µs more (an estimate from
the Queued numbers, not measured alone).

| Hot path | Today | A | B (revised) | C |
|---|---|---|---|---|
| **Picture shown** (10 DRM calls per picture) | 10 calls in the kernel; the 4 MB copy inside the call, under the kernel lock | 10 forwards to linux-server; the copy there | **10 forwards to the display service; the copy there** | 10 forwards to linux-server, plus one message to the display server per picture |
| **Input event** (interrupt → kwin's `read`) | ring → wake kwin → `read` in the kernel | ring + notification → linux-server → readiness word → `read` forwarded | **ring + notification → input service → readiness word → `read` forwarded to it** | ring → display server → batch to linux-server → readiness → `read` |
| **Audio period** (about 80 `SYNC_PTR` a second) | in the kernel; position page read every 10 ms | 1 forward | **1 forward to the sound service** | 1 forward |
| **Terminal `write`** | in the kernel | 1 forward | **1 forward to the terminal service** (+ a console-write primitive for the console) | 1 forward |
| **`open` of a device** | in the kernel | 1 forward | **1 forward + 1 hand-off to the owner** (rare) | 1 forward |

### 3.6 Resilience: what the user sees when each service crashes

Decision 6 (a linux-server crash ends every Linux program) is the baseline. In option B the
device services fail and restart **independently** of linux-server and of each other.

| Service crashes | What the user sees | Programs that keep running | Restart without ending programs? | What that needs |
|---|---|---|---|---|
| **Display** | The console appears at once (the kernel takes the screen back without asking). kwin loses `/dev/dri/card0` and exits: the desktop session ends; the login screen comes back when the service has restarted (about 1–2 s, plus SDDM's start) | Everything without a window: sound already playing to the end of its buffer, downloads, servers, `apt`, programs on the Hydra console. Programs with windows end with kwin | **Not in wave 6.** Possible later: the service keeps its KMS state (framebuffer and handle tables, the master, the current picture) in a kernel-held memory object and reloads it after the restart; kwin's buffers are already memory objects that survive. kwin would see a picture frozen for about a second. About 3–4 agent-days | Kernel keeps the screen arbitration; supervisor restarts the service; SDDM restarts its greeter after its kwin exits (to verify on Hydra) |
| **Input** | Keyboard and pointer stop for a few seconds, then work again; keys held at the crash are released. The console's keyboard keeps working meanwhile (Ctrl+Alt+F1 is in the kernel) | **Everything, the desktop included** | **Yes**, through hot-plug: kwin's libinput treats the failing descriptors as removed devices, and reopens them when they are announced again | The kernel announces "remove" and "add" for the input devices (udev messages on the netlink socket: **today Hydra's uevent socket never sends anything**); hydra-logind gives kwin the new descriptors (`TakeDevice`) for devices that appear during a session; the kernel keeps the raw input ring, so nothing typed during the restart is lost to the console. To verify with kwin |
| **Sound** (the ALSA service) | A gap of a second or two in the sound | **Everything**: PipeWire, music players and browsers keep running; PipeWire's sink reports an error and WirePlumber recreates it when the card is announced again | **Yes**, through the same "remove/add" announcements | The kernel keeps the DMA rings and the position page (it already owns them); the service restores the mixer volume (kept by the kernel or read back from hda-driver). To verify with PipeWire and WirePlumber |
| **hda-driver** (the sound driver) | At most a click | **Everything; no program notices** | **Yes, already the design** | The sound service sets the stream up again after the driver's restart (`MSG_SND_SETUP`, `TRIGGER`) from its own state |
| **Terminals** | Konsole tabs and ssh sessions end; a Linux program started from the Hydra console loses its output (the console itself and hydra-shell keep working) | Everything not attached to a terminal, **the desktop included** | No (the shells on the terminals get end-of-file and hang-up, as when a terminal window closes) | Keeping pty queues and sessions outside the service is possible but not worth it now |
| **linux-server** (or, after the split, the process service) | Every Linux program ends; the console comes back at once (the display service gives the screen back when its last client closes); the login screen returns (decision 6) | The device services keep running and lose only their clients | No (decision 6) | Unchanged |
| **User space stuck** | Ctrl+Alt+F1 and the emergency prompt work: the kernel handles the keys and owns the screen | | | Unchanged |

What every service needs from the kernel for this: **its resources outlive it** (the lent
screen, the raw input ring, the DMA rings, the memory objects of programs' buffers), its
objects fail cleanly when it dies (the existing generation number: `POLLERR | POLLHUP`, calls
fail with `ENODEV`), and the supervisor restarts it with a policy of its own (Group 18).

### 3.7 Estimated cost

From section 2.2's busiest phase (sound, Firefox and the pointer: about 638 DRM, 9 evdev and
83 PCM calls a second, 64 pictures and about 10 input batches a second).

| | A | B (revised) | C |
|---|---:|---:|---:|
| Added per device call | +2.2 µs | +2.2 µs | +2.2 µs |
| Device calls per second (busy) | 730 | 730 | 730 |
| Extra hops between servers per second | none | none (one per `open`) | about 74 (one per picture and per input batch), about 10 µs each |
| **Added CPU time per second, busy desktop** | **1.6 ms (0.16 %)** | **1.6 ms (0.16 %)** | 2.4 ms (0.24 %) |
| Added latency, input | 1 wake-up + 1 forward (tens of µs) | the same | 2 wake-ups + 1 forward |
| Picture copy (about 60 ms per second today) | in linux-server, outside the kernel lock | **in the display service, outside the kernel lock** | in the display server |
| Memory | none extra | 4 more service processes (about 1–2 MB each) | 1 more |

- **Every option is far inside the budget** (desktop at most 5 % slower; design section 6.6).
  The forwarding cost does not decide the question; resilience does.
- **Every option gains** what is today the largest display cost in the kernel: 60 ms a second
  of copying under the kernel lock. Fixing the two waste findings of section 2.2 (pace flips at
  60 Hz, stop drawing while hidden) cuts it further: from 64–77 to at most 60 pictures a
  second, and to none behind the console.
- **KDE start:** the login makes few device calls (25–250 DRM calls a second during the
  Plasma start, against 3,600–10,900 calls in all) and a few dozen device `open`s; under 0.1 %.

### 3.8 Size, new primitives, effort

| | A | B (revised) | C |
|---|---|---|---|
| Lines moved out of the kernel | about 6,000 | same | same |
| New code | about 600 in the kernel; the moved code in linux-server | about 700 in the kernel; four small service programs around the moved code (about 300 lines of service frame each, on `hydra-rt`); the restart and "remove/add" pieces | about 600 in the kernel; a display server of 800–1,000 lines; a native protocol of about 200 |
| Depends on | nothing new | **Group 18's routing to several services** (owner per object, open hand-off by device number, caller identity in the call header, per-service crash policy) | nothing new |
| Agent-days (wave 6 groups) | 18–23 | **24–30** (without Group 18's routing core) | 23–28 |
| Parallel groups | 4 | **6** (7 with Group 18's routing core) | 5 |

The kernel primitives, for B (most were in every option already):
- **Memory objects for server objects** (the `obj_anon` and `as_map` of design section 5.2):
  a service makes an anonymous object (`obj_anon`), or the kernel hands it one made of DMA
  frames (`obj_dma`, the sound rings); when a program calls `mmap` on the service's
  descriptor, the service names the object and offset and the kernel maps its pages. A
  DMA-BUF descriptor is a second object for the same memory. Objects live as long as anything
  maps or holds them, **not as long as the service**: that is what lets buffers survive a
  restart. Step 6a (file `mmap`) and step 8 (System V shared memory) reuse it.
- **Screen lending:** the kernel maps the framebuffer into the display service, takes it back
  (maps a blank range) on Ctrl+Alt+F1, on a panic and when the service dies, and tells the
  service; the service says when no session needs the screen. The boot splash ends on the
  first lend, as today.
- **Raw input ring:** a page shared with the input service: scancodes, pointer packets and
  absolute reports with their interrupt time in nanoseconds, plus a notification. The hot keys
  are decided in the interrupt before the ring, as today; while the console owns the keyboard
  (the kernel decides, from the screen's owner), nothing goes to the ring.
- **Console terminal I/O:** "write these bytes to the console" and "console keys" (a
  notification while a Linux program owns the console), and attach/detach notifications from
  hydra-shell's `linux chroot`.
- **Signals to a process group** from any service (Ctrl+C, `SIGWINCH`, `SIGHUP`), and the
  caller's process group and session in the call header.
- **Device announcements:** "remove" and "add" messages for a service's devices, in the format
  libudev reads (kwin's libinput and WirePlumber listen for them), sent when a service dies and
  when it is back.

### 3.9 Risks

- **The desktop is the test.** Every option changes the path of every picture and every key.
  A subtle mistake (a lost flip event, a lost wake-up) freezes the desktop rather than failing
  a test. The switch back (`lx=kernel`) and the per-group KDE checks are the protection.
- **B depends on Group 18's routing core.** If it slips, the device services cannot start; the
  fallback is to host the four services' code in linux-server for one wave (option A) and move
  it out when the routing exists. The service code itself does not change.
- **`mmap` of server objects is new kernel ground:** pages a service owns, mapped into many
  programs, shared across `fork`, outliving the descriptor and the service. A dedicated test
  comes first.
- **Restart through hot-plug is unproven on Hydra:** Hydra has never sent a device
  announcement. Whether kwin, libinput, hydra-logind, PipeWire and WirePlumber really recover
  must be tried; if one does not, that service's crash ends the desktop session instead (still
  better than today's kernel panic).
- **The console terminal carries the whole suite.** Every suite test prints through it; a bug
  there fails all 78 tests at once. Group T should keep the console terminal on the kernel path
  until its own tests pass.
- **SDDM's recovery after a display crash** (kwin exits; SDDM should restart its greeter) is
  not verified.
- **Sound underruns already happen today**, about once a second, busy desktop or not
  (section 2.5). A move must not make them worse; the service's position thread must run with
  a priority at least that of today's kernel task.
- **More processes:** four more services to supervise, each with its restart policy, and a
  little more memory.
- **Real hardware:** only QEMU's standard VGA, PS/2, vmmouse and intel-hda were measured.

## 4. Recommendation

- **Option B (revised): four device services, each called directly by the kernel.**
  - **Display service:** `/dev/dri/card0`; the native core owns the screen, copies pictures,
    draws the cursor; the Linux interface sits on it as a layer of the same program. Its
    protocol is designed for a real graphics driver later (several modes, a vertical blank),
    but wave 6 builds only the firmware framebuffer.
  - **Input service:** `/dev/input/event*`, fed by the kernel's raw input ring.
  - **Sound service:** the ALSA interface and the stream state, a client of today's
    hda-driver, which stays as it is.
  - **Terminal service:** pseudo-terminals and the console terminal (they share the line
    discipline); the process service is asked only about sessions.
- **Why:** it is what decision 9 asks for. Each device family fails and restarts on its own;
  input, sound and the sound driver can come back **without ending any program**, the display
  without ending anything but the desktop session. It costs the same as keeping everything in
  linux-server (0.16 % of a CPU on a busy desktop), because the kernel routes each call
  straight to its owner.
- **Stays in the kernel:** the hot keys, who owns the screen and the keyboard, the screen
  take-back, the boot splash, the emergency console, and the resources each service borrows
  (screen, input ring, DMA rings, buffers), so they outlive a service crash.
- **Fix the two waste findings in the display service** (section 2.2): complete flips at
  60 Hz (an emulated vertical blank), and hold the completions back while the console is shown,
  so kwin stops drawing. That saves more CPU than the whole move costs.
- **Wave 6 builds the hot-plug restart** (device announcements, hydra-logind handing out new
  descriptors) and **tests every crash**; a transparent restart of the display service (keeping
  the desktop) is left for later (decision question 6).

## 5. Interfaces of the device services

| Between | What | Notes |
|---|---|---|
| Kernel → display service | Screen lending (map, take back, notifications); the boot splash ends on the first picture | The kernel never waits for the service: taking the screen back is a remapping |
| Kernel → input service | The raw input ring and its notification; routing on or off, decided by the kernel from the screen's owner | Replaces today's `evdev::set_routing` called from `drm.rs` |
| Kernel → sound service | The DMA rings and the position page as `obj_dma` memory objects; the controller's identity (today `snd::set_controller`) | The rings live as long as the kernel, as today |
| Sound service ↔ hda-driver | Today's `MSG_SND_INFO/SETUP/TRIGGER/VOLUME` (`ipc/protocol.rs`), unchanged | Only on stream set-up, start, stop and volume changes |
| Terminal service → kernel | Console write, console keys, attach/detach of hydra-shell's foreground program | |
| Terminal service → process service | "Is process group P in session S", the session of a process, a session leader's exit (hang-up) | Rare calls (Group 18's server-to-server call); the caller's own group and session come in the call header |
| Display service → input service | Nothing | Both follow the kernel's screen ownership |
| Any service → programs | Device "remove/add" announcements around a restart | Through the kernel's uevent netlink socket |
| Inside the display service | The native core interface below | A code boundary, not IPC: a FreeBSD front end or a graphics driver plugs in here |

The native core interface inside the display service (from the first version's protocol):

| Operation | Meaning |
|---|---|
| `info` | Screen size, stride, pixel format, refresh rate (60 Hz for the firmware framebuffer), whether the screen is lent |
| `show(object, offset, pitch, format, damage, cookie)` | Show this buffer; the core copies (only the damaged rows when given) and completes at the next emulated vertical blank |
| `done(cookie, time)` | The picture is on screen: the Linux layer queues the DRM flip event. Held back while the console is shown |
| `cursor(object or none, hot x, y)`, `move(x, y)` | Cursor image and position |
| `state(shown or hidden)` | The console took the screen or gave it back |
| `release` | No session needs the screen: give it back to the console (today's 10 s grace stays) |

The Linux layer keeps everything Linux-specific: KMS objects and ids, properties, GEM handles,
PRIME descriptors, the per-file DRM event queues, master and revoke rules.

## 6. Decisions for the user

1. **Should display, input, sound and terminals each be a separate service, called directly by
   the kernel?**
   - Recommended: **yes** (option B, revised). Each can crash and restart on its own; it costs
     the same as keeping them in linux-server (about 0.16 % of a CPU on a busy desktop). About
     24–30 agent-days, in six groups (seven with Group 18's routing core).
   - Alternatives: inside linux-server (A, simplest, but it goes against decision 9), or the
     first version's recommendation (C: a small display server with the Linux display interface
     in linux-server), which decision 9 has overtaken.
2. **Input separate from display?**
   - Recommended: **yes**. Then a crash of the input code costs a few seconds without keyboard
     and mouse, and the desktop keeps running. Together, an input bug would also end the
     desktop session.
3. **Sound: a sound service separate from the sound driver?**
   - Recommended: **yes**. A driver crash is then hidden completely (at most a click), and a
     crash of the sound service is a short gap in the sound. Merged into the driver, one process
     fewer, but a driver crash also loses the streams.
4. **Terminals: their own service, or part of the process and session service?**
   - Recommended: **their own service**. A terminal bug then ends only the programs running in
     terminal windows and ssh sessions; inside the process service it would end every Linux
     program. It costs a rare call to the process service (when a program starts a session or
     changes its terminal's foreground group).
5. **What happens when each service crashes** (section 3.6): display → the console appears, the
   desktop session ends and the login screen returns, other programs keep running; input → a
   few seconds without keyboard and mouse, nothing ends; sound → a gap in the sound, nothing
   ends; sound driver → nothing visible; terminals → terminal and ssh sessions end, the desktop
   keeps running. **Accept this as the target?** (The input and sound recoveries need device
   announcements Hydra does not send yet; wave 6 builds them and tests them. If kwin or
   PipeWire do not recover, that service's crash ends the desktop session instead.)
6. **A display crash that keeps the desktop** (the service saves its state in the kernel and
   picks it up after the restart; kwin sees a picture frozen for about a second): build it
   later, about 3–4 agent-days? Recommended: **later**, after wave 6 works.
7. **Fix the two waste findings in wave 6?** (the desktop draws at full speed behind the
   console; pictures are not paced to 60 a second). Recommended: **yes**, in the display
   service; it saves up to 60 ms of CPU a second on a busy desktop. (Unchanged.)
8. **Design the display service for a real graphics driver later** (virtio-gpu in VMs, the
   NUC's Intel graphics, choosing the monitor's resolution)? Recommended: design its core for
   it, build only today's firmware framebuffer in wave 6. (Unchanged.)

## 7. Wave 6 plan

The plan assumes the recommendation and **Group 18's routing core** (owner per server object,
the open hand-off by device number, caller identity in the call header, per-service crash and
restart). If Group 18's plan builds that core in wave 6, it is one more group (R) and merges
first; the groups below develop their services against its interface from day 0. Each group
keeps the in-kernel copy as the switch back (`lx=kernel`).

### 7.1 Six groups at once (seven with Group 18's routing core)

| Group | What | Owns (files) | Needs | Agent-days |
|---|---|---|---|---:|
| **M: memory objects** | `obj_anon`, `obj_dma`, `mmap` of a server object maps a memory object, objects outliving their service, sharing an object with another service | new `src/lx/mem.rs`; the `mmap` hook for server objects in `compat/linux/mm.rs` (one arm); `memory/vm.rs` (a `MappedObject` for memory objects); new `hydra-rt/src/mem.rs` (the service side, for every service); host-test mirrors | Group 18's owner per object | 3–4 |
| **D: display service** | New `display-server` (endpoint 0x23, the old display endpoint): the native core (screen, copy, cursor, 60 Hz completions, held back behind the console) and the Linux DRM layer moved from `drm.rs`; kernel side: screen lending | new `userland/drivers/display-server`; `src/video/*`; new `src/ipc/screen.rs` (lending, the screen's owner, the hot keys' switch target); `compat/linux/drm.rs` (kept for `lx=kernel`) | M (dumb buffers, PRIME); R | 6–7 |
| **I: input service** | New `input-server` (endpoint 0x2A, proposed): the evdev layer moved from `evdev.rs`; kernel side: the raw input ring and its notification, routing from the screen's owner | new `userland/drivers/input-server`; `src/arch/{keyboard,mouse,vmmouse,usb_input}.rs`; new `src/ipc/input.rs`; `compat/linux/evdev.rs` (kept) | R; one agreed call from D's `screen.rs` (`input::set_routing`) and one from `keyboard.rs` to `screen::request_switch` | 3–4 |
| **S: sound service** | New `sound-server` (endpoint 0x2B, proposed): the ALSA layer moved from `snd.rs`, the position thread, re-setup after an hda-driver restart, the mixer kept across a restart | new `userland/drivers/sound-server`; new `src/ipc/sound.rs` (hands the rings and the position page as `obj_dma`); `compat/linux/snd.rs` (kept); `compat/linux/fs.rs` (`/proc/asound` from the service) | M (`obj_dma`, `mmap`); R. `WRITEI` (no `mmap`) works before M merges | 4–5 |
| **T: terminal service** | New `tty-server` (endpoint 0x2C, proposed): `tty` and `pty`; console terminal I/O; job control from the call header; session queries to the process service | new `userland/drivers/tty-server`; new `src/lx/console.rs`; `admin/linux.rs` (attach/detach: two lines); `arch/idt.rs` (`tty::pump` guarded: one line); `compat/linux/tty.rs`, `pty.rs` (kept) | R (identity in the header, process-group `sig_post`, a server-to-server call to linux-server for session queries) | 5–6 |
| **H: restart and hot-plug** | Device "remove/add" announcements in libudev's format on the uevent socket; hydra-logind handing new descriptors to the active session (`TakeDevice` for devices that appear) and dropping them on "remove"; the restart policies of the four services; a crash test per service | `compat/linux/netlink.rs` (the uevent socket; Group 12 owns netlink in wave 5, so after its merge); `compat/linux/devices.rs` (udev database entries); `userland/hydra-logind/*`; new `tests/linux/hotplug_test.c`; scripts `tools/devcrash/` | The services to test against (stubs before they merge) | 3–4 |
| **Total** | | | | **24–30** |

(R, Group 18's routing core, is not counted: it belongs to Group 18's plan.)

### 7.2 Order and shared files

- **Day 0:** R publishes the routing interface (if not already merged), M the memory-object
  interface, D the `screen.rs` calls that I uses, and each service its endpoint, all in
  NOTES.md.
- **`task/supervisor.rs`:** D, I, S and T each add one service entry and its restart policy
  (H writes the policy rules first); append-only, marked by group.
- **`src/ipc/protocol.rs`:** endpoints 0x2A–0x2C and any new native numbers (64 and up, after
  wave 5's 60–63) are appended, agreed in NOTES.md.
- **`userland/drivers/Cargo.toml`:** four new workspace members, one line each.
- **No two groups edit the same kernel file otherwise**: D owns `video/*` and `ipc/screen.rs`,
  I the input interrupt files, S `ipc/sound.rs`, T `lx/console.rs`, M `lx/mem.rs` and the
  `mmap` hook, H `netlink.rs` and `devices.rs`.
- **Merge order:** R and M first; then D, I, S and T in any order; H last (it tests the others'
  restarts), though it develops the announcements and hydra-logind from day 0.
- **Every group ends with:** the full suite (78 + new tests), suite_loop if it touches the
  trap or descriptors (M, T), the IOMMU suite (D and S touch MMIO and DMA), host tests, KDE
  with Firefox, sound and Wine, Ctrl+Alt+F1/F2 and the boot splash, at least 3 fresh KDE logins
  with no crash, USB input (`--usb`), both `lx=kernel` and the moved path, and **killing its
  service under KDE**.

### 7.3 Tests per group

| Group | Tests |
|---|---|
| M | New `srvmap` test: a test service's object mapped by two processes, shared across `fork`, unmapped after `close`, still mapped after the service is killed and restarted; the full suite; `lxbench` unchanged |
| D | Boot splash, SDDM, the desktop, Ctrl+Alt+F1/F2 five times, `panic 30` over the desktop, `drmtest` (added to the suite), flip rate at most 60 a second and no DRM calls behind the console (`tools/displaybench`), killing the display service (console at once; login screen back after the restart; sound and a download keep going) |
| I | PS/2 and USB keyboard and pointer in KDE, Ctrl+Alt+F1/F2, input latency against section 2.4 (`tools/displaybench`), killing the input service while typing (with H: the desktop keeps running, input back within seconds) |
| S | `snd` (suite), `pw-play` in KDE with the WAV checked, underruns over 60 s against section 2.5, killing hda-driver during playback (no program notices), killing the sound service (with H: sound back, PipeWire still running) |
| T | `ptytest`, `notty`, `stdfd`, `signals` (Ctrl+C), the whole suite (it prints through the console terminal), Konsole in KDE, `apt-get install` (dpkg's pty), a new pty round trip in `lxbench`, killing the terminal service (Konsole's shell ends, the desktop stays) |
| H | `hotplug_test` (a program that watches the uevent socket sees "remove" and "add" when a service restarts), each service's crash test above, hydra-logind giving kwin the new input descriptors |

## 8. What was not measured or verified

- **One session per configuration**, on a shared host: no run-to-run spread. The picture
  copy times and the call rates are stable within a phase (block to block), the latencies are
  not (they depend on what kwin is doing).
- **Input latency to the screen** is an upper bound (section 2.1), and the harness's pointer
  moves are slow (2.4 a second); a fast real mouse (100+ reports a second) would make more
  evdev reads and cursor calls, still well under the busy rate of DRM calls.
- **No prototype** of any option. The per-call cost of B assumes Group 18's routing to several
  services keeps step 1's +2.0–2.5 µs (the direct switch to another server's workers is the
  same mechanism); Group 18 will measure it.
- **Restart behaviour not tried:** none of the recoveries in section 3.6 (kwin after a display
  crash via SDDM, libinput after input devices are removed and added, PipeWire and WirePlumber
  after the sound card is removed and added) has been run on Hydra; Hydra has never sent a
  device announcement.
- **Not tried:** Konsole or ssh traffic through pty (no pty traffic in these sessions); USB
  input (only PS/2 and the vmmouse); real hardware.
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
  Linux calls; then phases of at least 15 s each, separated by idle waits). The `[dstat]`
  blocks come every 5 s on the serial log.
- **Tables:** `python tools/displaybench/dstat.py LOG` prints one row per block;
  `dstat.py LOG 61-67:pointer 97-99:firefox ...` adds averages, the gap histogram, the
  latency histograms and the per-`ioctl` totals for named ranges of blocks.
- **Sound:** QEMU's `-audiodev wav` output (`kde_kde.sh` adds it) shows whether samples
  arrived; the `[dstat] snd HW_PARAMS` lines give the period and buffer each stream chose.
