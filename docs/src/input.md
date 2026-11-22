# The input service (wave 8, Group I)

Keyboard and pointer input reaches Linux programs (kwin's libinput, SDDM) through
`/dev/input/event0..2`. Since wave 8 a ring-3 service serves them: **input-server**
(`userland/drivers/input-server`, endpoint `0x2A`, service `LXS_INPUT`). The kernel keeps
the interrupt paths, the hot keys and the routing decision.

## Pieces

| Where | What |
|---|---|
| `src/arch/keyboard.rs`, `mouse.rs`, `vmmouse.rs`, `usb_input.rs` | Interrupts (PS/2, QEMU's absolute pointer) and the USB input task. The hot keys (F12, Scroll Lock, Ctrl+Alt+F1/F2) stay here. Raw input goes to `ipc::input::push_*`. |
| `src/ipc/input.rs` | The **raw input ring**: 2 pages of kernel frames (a header page and 256 records of 16 bytes, `InputRec`), routing (`set_routing`), the notification `NOTIFY_INPUT` on `0x2A`, `SYS_LX_OBJ` ops 62 (`LX_OBJ_INPUT_RING`: a memory-object handle to the ring) and 63 (`LX_OBJ_INPUT_CTL`, `a = 0`: is input forwarded). |
| `src/ipc/input_ring.rs` | The ring's layout and both ends (`RingView::push` / `take`), shared by the kernel, the service and the host tests. |
| `userland/drivers/input-server` | `main.rs`: opens (major 13 claimed), reads (whole events; a blocking read is answered later), `ioctl`, revoke, readiness words, restart. `xlate.rs`: records to Linux events, the per-file queue, the `EVIOC*` answers (pure; host-tested in `tests/host-w8-i`). |
| `src/compat/linux/evdev.rs` | The switch-back copy (`lx=kernel`, `lx.input=kernel`): drains the same ring itself. Only one of the two ever consumes it. |
| `src/compat/linux/chardev.rs` | Major 13 goes to the service while input is forwarded (an open waits up to 5 s for a restarting service). |

## Flow

1. An interrupt (or the USB task) calls `push_scancode` / `push_mouse` / `push_abs`. If a
   desktop session shows (routing on), the record is stamped with `now_ns` (the clock
   `CLOCK_MONOTONIC` reads) and appended under the producer lock; the service is notified.
2. input-server's main thread wakes, takes the new records, translates them, appends the
   events to every open file of the device, completes waiting reads and sets the files'
   readiness words (`poll`/`epoll` in the kernel read them; the doorbell wakes waiters).
3. kwin reads whole 24-byte events; their timestamps are the interrupt's time.

Routing off (the console shows, or the screen goes back) appends a "release" record, so the
session sees every held key and button go up.

## Restart

Transparent (fw_cfg `opt/hydra/restart.input`, the harness's `--restart input=CLASS`, changes it): the new instance adopts the open files
(`LX_SVC_LIST`/`LX_SVC_ADOPT`; the key is the device number, revoked files are listed in
the kept state), so kwin's descriptors keep working; input typed meanwhile waits in the
kernel's ring. A second crash within 30 s lowers it to FailObjects: the old descriptors fail
(`ENODEV`, `POLLERR|POLLHUP`) and kwin gets no input until device announcements exist (Group
H, stage 2). A third stops the service (`service start input_server` restarts it).

## Tests

`tests/linux/evdevtest.c` (names, ids, bits, `st_rdev`, `EAGAIN`, `EINTR`, revoke; run as
root), `tests/linux/evlat.c` (interrupt-to-read latency), host crate `tests/host-w8-i`.
