# Group 28: what the host tests do not reach

None of the ten files is hardware-only: every one is compiled into this crate and
tested through its real entry points. The few privileged or hardware-facing calls they
make are already behind other modules, which `src/fake.rs` replaces:

| File | Call | Stand-in |
|---|---|---|
| `evdev.rs` | `x86_64::instructions::interrupts::without_interrupts` (`ring_pending`, `pump`) | the crate's `shim/x86_64` runs the closure |
| `devices.rs` | `arch::pci::{find_class, pci_read_u32, pci_read_u8}` (port I/O) | `fake::PCI`, `fake::PCI_CONFIG` |
| `drm.rs` | `video::console::{release_display, reclaim_display}` (the GOP framebuffer) | a heap framebuffer (`fake::DISPLAY`) |
| `snd.rs` | `ipc::service::*` (the ring-3 HDA driver), `arch::iommu::map_dma` | `fake::SOUND` with a scripted responder |
| `blockdev.rs`, `devices.rs` | `fs::blockdev` (the disk drivers) | in-memory disks (`fake::DISKS`) |
| `devices.rs` | `fs::zfs::with_server` (the ZFS file server) | an in-memory file system (`fake::FS`) |
| `tty.rs` | `console::{print_raw, read_key}` | `fake::CONSOLE_OUT`, `fake::KEYS` |

## Lines left uncovered (all files at 96 % or more)

Not hardware, just not worth a fake of their own:

- `drm.rs` `Bo::new` (lines ~97-104): the frame allocator running out in the middle of a
  dumb buffer (the shared test pool is not exhausted on purpose).
- `memfd.rs` `write_at` (`None => break`, ~219) and `frames_for` (~263): the same,
  out of frames.
- `snd.rs` `chip_name` for other codec vendors (~276-279): the card is fixed per test
  binary (Realtek and QEMU are tested); `start` failing to allocate its DMA buffers.
- A handful of `?`/`return e` lines after a user-memory copy that cannot fail once the
  copy before it succeeded (the same pointer, checked just before).
