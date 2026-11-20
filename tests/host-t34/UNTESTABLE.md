# Group 34: code the host tests cannot run

Every file of the group is compiled into `tests/host-t34`. The lines below stay uncovered
on purpose: they need the real firmware or hardware, or they cannot be reached. Line
numbers are those of branch `tw-misc` at the time of the final report (they move with
later edits; the function names do not).

Coverage of the group with `tools/host_coverage.py --crates host-t34` (raw numbers of the
tool, untestable lines included in the denominator): see the final report in
`scratch/STATUS.md`; every file is at 95 % or more except `src/video/gop.rs` (79.7 %) and
`src/video/mod.rs` (no code).

## Needs the UEFI firmware (boot services with real protocols)

The host tests install a fake UEFI system table (`src/uefi_fake.rs`): a working text
console, and boot services that answer `UNSUPPORTED` to everything. So code after a
successful `open_protocol` cannot run.

| File | Function | Lines | Why |
|---|---|---|---|
| `src/video/gop.rs` | `init_gop` | 59-77 | Opens the Graphics Output Protocol and reads the mode and framebuffer from it. The logic after it is in `mode_info_for` and `install` (both tested); the failure path (no GOP) is tested. |
| `src/admin/boot.rs` | `load_options_text` | 83-84 | Reads the boot entry's load options from the LoadedImage protocol. The conversion is `options_text` and the decisions `discover_with` (both tested); the failure path is tested. |
| `src/video/splash.rs` | `decide` | 62 | Same, for the splash (`options_text`, `wants_splash` tested). |
| `src/main.rs` | `main` | 203-207 | The UEFI entry point (`#[entry]` on the kernel target). `boot()`, which it calls, is tested end to end. |
| `src/main.rs` | `boot` | 398 | The success arm of `video::init_gop()` (needs a GOP); the report it calls, `framebuffer_online`, is tested. |

## Hardware or CPU state

| File | Function | Lines | Why |
|---|---|---|---|
| `src/console.rs` | `is_scroll_lock_active` | 1053-1056 | Reads the BIOS data area at physical address `0x417` (identity-mapped only under UEFI). On the host this address is unmapped. The software switch and the hardware-mode answer are tested. |
| `src/main.rs` | `panic` | 133-138 | The `#[panic_handler]` (interrupts off, `hlt` forever). It takes a `core::panic::PanicInfo`, which cannot be built outside a panic. Its body is `report_panic`, which is tested. |

## Not reachable (defensive code)

| File | Function | Lines | Why |
|---|---|---|---|
| `src/admin/mod.rs` | `copy_out` | 124 | Copying an empty answer: every caller checks for a non-empty one first. |
| `src/admin/mod.rs` | `syscall` | 180 | `read_record` of the call block fails only if fewer bytes than its size were copied, and exactly its size is copied. |
| `src/admin/system.rs` | `translate` | 230 | A virtual address that translates to a physical one but whose page has no table entry: the page table walk cannot give that. |
| `src/console.rs` | `draw_scroll_viewport` | 1258-1259, 1280-1281 | `get_line_with_attrs(i)` fails only for `i >= total_lines()`, and the loops stay below it. |
| `src/net/client.rs` | `track` | 152 | Skips handle 0 when the 32-bit handle counter wraps (after 4 billion sockets). The counter is private and starts at 1. |
| `src/shell/mod.rs` | `read_input` | 70 | `char::from_u32` of a UEFI key fails only for UTF-16 surrogates, which a `Char16` key never holds. |
| `src/video/console.rs` | `show_cursor` | 175-176 | Redraws a cursor that is shown elsewhere; every cursor move, write and escape hides the cursor first, so the drawn cursor is always at the current cell when this runs. |
| `src/video/splash.rs` | `tick` | 165-166 | The spinner's lock is taken by `stop()` on another CPU at the same moment (a race between the timer interrupt and the end of the splash). |
| `src/video/splash.rs` | `decode_logo` | 261 | The embedded logo always has its `HLG1` header. |

## No executable code

| File | Why |
|---|---|
| `src/video/mod.rs` | Module declarations and a `pub use` only. It is compiled into the crate, but LLVM reports no lines for it, so the tool counts its 6 lines as "not compiled" (an estimate). |
