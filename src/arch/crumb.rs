//! # Boot breadcrumbs (diagnostic stick)
//!
//! The first NUC start showed a black screen and left no boot log: whatever stopped it came
//! before the log file is made. When the boot volume has a file `\hydra\crumbs`, each early
//! boot step ([`step`]) is written as one line into `\logs\steps.txt` on the boot volume through
//! the firmware's own file protocol (from the very first instruction of the entry point, before
//! the move to the higher half), and shown on the firmware's text console with a short pause,
//! so a photo catches it. The last line in the file names the last step reached.
//!
//! Nothing here may hang or stop the boot: every firmware call's status is checked and the
//! first failure turns the breadcrumbs off. Only before `ExitBootServices`.

use core::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};

/// 0: not decided yet, 1: on, 2: off.
static STATE: AtomicU8 = AtomicU8::new(0);
/// Lines written so far.
static COUNT: AtomicU32 = AtomicU32::new(0);
/// A firmware page at an identity address for the file writes (0: none yet).
static BOUNCE: AtomicU64 = AtomicU64::new(0);

/// Bytes per line in the file (fixed: line `n` is at `n * LINE`).
const LINE: usize = 160;
/// How long each step stays on the screen (ms).
const SHOW_MS: u64 = 150;

/// Records boot step `name`.
pub fn step(name: &str) {
    step_fmt(format_args!("{}", name));
}

/// Records a boot step with a formatted text (at most 150 characters are kept).
pub fn step_fmt(args: core::fmt::Arguments) {
    record(args, true);
}

/// After the start menu: breadcrumbs on the screen only ([`screen_only_from_now`]).
static SCREEN_ONLY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// From now on breadcrumbs go to the screen only, not to `\logs\steps.txt` (called after
/// the start menu). The NUC's firmware stopped in its boot-file reads when breadcrumb lines
/// were written to the same FAT volume between them (wave 11, start-menu bisect); the boot
/// log file (written after ExitBootServices through the kernel's own disk path) carries
/// the rest.
pub fn screen_only_from_now() {
    SCREEN_ONLY.store(true, Ordering::Relaxed);
}

/// While set, a line goes to the file even after [`screen_only_from_now`] ([`force_line`]).
static FORCE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// A breadcrumb written to the file whatever the boot words say (the start variant's name).
pub fn force_line(args: core::fmt::Arguments) {
    FORCE.store(true, Ordering::Relaxed);
    record(args, true);
    FORCE.store(false, Ordering::Relaxed);
}

/// A breadcrumb in the file only (no screen line, no pause): for the many small steps.
/// Once the breadcrumbs are on the screen only, these show there too, without the pause
/// (where a boot-file read stops: wave 11, run 9).
pub fn quiet_fmt(args: core::fmt::Arguments) {
    record(args, false);
}

/// A firmware read's breadcrumb: on the screen once the breadcrumbs are screen-only, else
/// none (file writes between the firmware's reads stopped the NUC; wave 11).
pub fn read_fmt(args: core::fmt::Arguments) {
    if SCREEN_ONLY.load(Ordering::Relaxed) {
        record(args, false);
    }
}

/// Writes a breadcrumb line (and shows it when `show`).
fn record(args: core::fmt::Arguments, show: bool) {
    match STATE.load(Ordering::Relaxed) {
        2 => return,
        0 => {
            if !decide() {
                STATE.store(2, Ordering::Relaxed);
                return;
            }
            STATE.store(1, Ordering::Relaxed);
        }
        _ => {}
    }
    if ENDED.load(Ordering::Relaxed) {
        return;
    }
    // (the start menu's test entries 5-7: screen lines only, no file writes)
    let screen_only = SCREEN_ONLY.load(Ordering::Relaxed) && !FORCE.load(Ordering::Relaxed);
    // wave11 GH: screen-only, the small steps show too, without the pause
    let pause = show;
    let show = show || screen_only;
    let n = COUNT.fetch_add(1, Ordering::Relaxed);
    let mut text = crate::console::FixedBuf::new();
    let _ = core::fmt::Write::write_fmt(&mut text, format_args!("{:02} ", n));
    let _ = core::fmt::Write::write_fmt(&mut text, args);
    let t = text.as_str().as_bytes();
    let mut line = [b' '; LINE];
    let k = t.len().min(LINE - 2);
    line[..k].copy_from_slice(&t[..k]);
    line[LINE - 2] = b'\r';
    line[LINE - 1] = b'\n';
    if !screen_only && !write_line(n, &line) {
        STATE.store(2, Ordering::Relaxed);
    }
    if !show {
        return;
    }
    // On the firmware's text console too, a moment long
    uefi::system::with_stdout(|o| {
        let _ = core::fmt::Write::write_str(o, "[hydra] ");
        let _ = core::fmt::Write::write_str(o, core::str::from_utf8(&t[..k]).unwrap_or("?"));
        let _ = core::fmt::Write::write_str(o, "\r\n");
    });
    if pause {
        uefi::boot::stall(core::time::Duration::from_millis(SHOW_MS));
    }
}

/// Boot services end next: no more breadcrumbs.
static ENDED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The last breadcrumb: called just before `ExitBootServices`.
pub fn end(name: &str) {
    step(name);
    ENDED.store(true, Ordering::Relaxed);
}

/// The boot volume's root directory, through the firmware (whatever the console does).
fn open_root() -> Result<uefi::proto::media::file::Directory, ()> {
    let mut fs = uefi::boot::get_image_file_system(uefi::boot::image_handle()).map_err(|_| ())?;
    fs.open_volume().map_err(|_| ())
}

/// Whether the boot volume asks for breadcrumbs (`\hydra\crumbs`), and the page for writes.
fn decide() -> bool {
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    let Ok(mut root) = open_root() else { return false };
    let mut b = [0u16; 32];
    let Some(c) = crate::fs::bootfs::path_to_cstr16("hydra\\crumbs", &mut b) else { return false };
    if root.open(c, FileMode::Read, FileAttribute::empty()).is_err() {
        return false;
    }
    let Ok(p) = uefi::boot::allocate_pages(uefi::boot::AllocateType::MaxAddress(0xFFFF_FFFF), uefi::boot::MemoryType::LOADER_DATA, 1) else { return false };
    BOUNCE.store(p.as_ptr() as u64, Ordering::Relaxed);
    // A fresh file for this start
    let mut b2 = [0u16; 32];
    if let Some(c) = crate::fs::bootfs::path_to_cstr16("logs\\steps.txt", &mut b2) {
        if let Ok(f) = root.open(c, FileMode::ReadWrite, FileAttribute::empty()) {
            let _ = f.delete();
        }
    }
    true
}

/// Writes line `n` of `\logs\steps.txt` (made with its folder when missing), flushed.
fn write_line(n: u32, line: &[u8; LINE]) -> bool {
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    let bounce = BOUNCE.load(Ordering::Relaxed);
    if bounce == 0 {
        return false;
    }
    let Ok(mut root) = open_root() else { return false };
    let mut b = [0u16; 32];
    let Some(c) = crate::fs::bootfs::path_to_cstr16("logs", &mut b) else { return false };
    let Some(mut dir) = root.open(c, FileMode::CreateReadWrite, FileAttribute::DIRECTORY).ok().and_then(|h| h.into_directory()) else { return false };
    let mut b2 = [0u16; 32];
    let Some(c) = crate::fs::bootfs::path_to_cstr16("steps.txt", &mut b2) else { return false };
    let Some(mut f) = dir.open(c, FileMode::CreateReadWrite, FileAttribute::empty()).ok().and_then(|h| h.into_regular_file()) else { return false };
    let buf = unsafe { core::slice::from_raw_parts_mut(bounce as *mut u8, LINE) };
    buf.copy_from_slice(line);
    let ok = f.set_position(n as u64 * LINE as u64).is_ok() && f.write(buf).is_ok() && f.flush().is_ok();
    f.close();
    ok
}

/// The graphics outputs the firmware offers, each as a breadcrumb, and the one to use: the
/// first with a real framebuffer (not 0, a direct pixel format) whose device path ends in
/// an attached display output (ACPI _ADR node), else the first with a real framebuffer.
/// Never a handle without a framebuffer (EDK2's console splitter has one without).
pub fn pick_gop() -> Option<uefi::Handle> {
    use uefi::proto::console::gop::{GraphicsOutput, PixelFormat};
    let handles = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::from_proto::<GraphicsOutput>()).ok()?;
    let conout = uefi::table::system_table_raw().map(|st| unsafe { st.as_ref().stdout_handle });
    let mut first_valid = None;
    let mut with_output = None;
    for (i, &h) in handles.iter().enumerate() {
        let params = uefi::boot::OpenProtocolParams { handle: h, agent: uefi::boot::image_handle(), controller: None };
        let Ok(mut gop) = (unsafe { uefi::boot::open_protocol::<GraphicsOutput>(params, uefi::boot::OpenProtocolAttributes::GetProtocol) }) else {
            step_fmt(format_args!("GOP {}: cannot open", i));
            continue;
        };
        let mi = gop.current_mode_info();
        let (w, hgt) = mi.resolution();
        let pf = mi.pixel_format();
        let modes = gop.modes().count();
        let mut fb = gop.frame_buffer();
        let (base, size) = (fb.as_mut_ptr() as u64, fb.size());
        drop(gop);
        // Its device path's last node: an ACPI _ADR (type 2, sub-type 3) names a display output
        let mut adr = false;
        if let Ok(path) = unsafe {
            uefi::boot::open_protocol::<uefi::proto::device_path::DevicePath>(
                uefi::boot::OpenProtocolParams { handle: h, agent: uefi::boot::image_handle(), controller: None },
                uefi::boot::OpenProtocolAttributes::GetProtocol,
            )
        } {
            if let Some(last) = path.node_iter().last() {
                let (t, s) = last.full_type();
                adr = t.0 == 2 && s.0 == 3;
            }
        }
        let valid = base != 0 && size != 0 && w != 0 && hgt != 0 && matches!(pf, PixelFormat::Rgb | PixelFormat::Bgr);
        let is_conout = conout.map(|c| c as usize) == Some(h.as_ptr() as usize);
        step_fmt(format_args!(
            "GOP {}: {}x{} {:?} fb {:#x}+{:#x}, {} modes, output node {}, ConOut handle {}, usable {}",
            i, w, hgt, pf, base, size, modes, adr, is_conout, valid
        ));
        if valid {
            if first_valid.is_none() {
                first_valid = Some((i, h));
            }
            if adr && with_output.is_none() {
                with_output = Some((i, h));
            }
        }
    }
    let chosen = with_output.or(first_valid);
    match chosen {
        Some((i, _)) => step_fmt(format_args!("GOP: using {} of {}", i, handles.len())),
        None => step_fmt(format_args!("GOP: none of {} has a usable framebuffer", handles.len())),
    }
    chosen.map(|(_, h)| h)
}

/// Whether to move to the higher half (`relocate::go_high`): not when `\hydra\options.txt`
/// on the boot volume has the word `nohigh`, nor (on a breadcrumb stick) when N is pressed
/// within 2 s of the prompt. Read with the firmware's file protocol before anything else
/// (no heap; nothing here can stop the boot).
pub fn want_high() -> bool {
    use uefi::proto::console::text::Key;
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    let mut text = [0u8; 2048];
    let mut n = 0;
    if let Ok(mut root) = open_root() {
        let mut b = [0u16; 32];
        if let Some(c) = crate::fs::bootfs::path_to_cstr16("hydra/options.txt", &mut b) {
            if let Some(mut f) = root.open(c, FileMode::Read, FileAttribute::empty()).ok().and_then(|h| h.into_regular_file()) {
                n = f.read(&mut text).unwrap_or(0);
                f.close();
            }
        }
    }
    let lower = |c: &u8| c.to_ascii_lowercase();
    let words: [u8; 2048] = core::array::from_fn(|i| lower(&text[i]));
    if words[..n].windows(6).any(|w| w == b"nohigh") {
        step("options.txt says nohigh: staying at the load address");
        return false;
    }
    if STATE.load(Ordering::Relaxed) != 1 {
        return true;
    }
    uefi::system::with_stdout(|o| {
        let _ = core::fmt::Write::write_str(o, "[hydra] Press N within 2 s to start without the higher-half move (diagnostics)\r\n");
    });
    for _ in 0..64 {
        if uefi::system::with_stdin(|i| i.read_key().ok().flatten()).is_none() {
            break;
        }
    }
    for _ in 0..20 {
        if let Some(Key::Printable(c)) = uefi::system::with_stdin(|i| i.read_key().ok().flatten()) {
            if matches!(char::from(c), 'n' | 'N') {
                step("N pressed: staying at the load address");
                return false;
            }
        }
        uefi::boot::stall(core::time::Duration::from_millis(100));
    }
    true
}

/// The identity address of the line [`high_arrived`] prints (0: none).
static ARRIVAL: AtomicU64 = AtomicU64::new(0);

/// Before the jump to the higher half: the arrival line in a firmware page (UCS-2, at an
/// identity address), so that the first thing at the high target can show it without
/// handing the firmware any higher-half address but its own stack frames.
pub fn prepare_arrival() {
    if STATE.load(Ordering::Relaxed) != 1 {
        return;
    }
    let Ok(p) = uefi::boot::allocate_pages(uefi::boot::AllocateType::MaxAddress(0xFFFF_FFFF), uefi::boot::MemoryType::LOADER_DATA, 1) else { return };
    let text = "[hydra] 09a high code reached (identity-buffer print)\r\n";
    let w = p.as_ptr() as *mut u16;
    for (i, b) in text.bytes().enumerate() {
        unsafe { w.add(i).write(b as u16) };
    }
    unsafe { w.add(text.len()).write(0) };
    ARRIVAL.store(p.as_ptr() as u64, Ordering::Relaxed);
}

/// The first thing at the high target: the prepared line through the firmware's text
/// output, called through the system table's raw pointers (all identity addresses).
pub fn high_arrived() {
    let msg = ARRIVAL.load(Ordering::Relaxed);
    if msg == 0 {
        return;
    }
    if let Some(st) = uefi::table::system_table_raw() {
        unsafe {
            let out = st.as_ref().stdout;
            if !out.is_null() {
                let _ = ((*out).output_string)(out, msg as *const u16);
            }
        }
    }
}

/// Whether `p` may be handed to the firmware: an identity address (the firmware's stack,
/// its pool, bounce pages), not a higher-half one (the kernel's stack, statics or heap
/// after the move: a real firmware's drivers use such addresses for DMA or cut them to 32
/// bits). A higher-half pointer is recorded as a breadcrumb (`what`), so QEMU runs show it.
pub fn fw_ptr_ok(p: *const u8, what: &str) -> bool {
    if (p as u64) < 0xFFFF_8000_0000_0000 {
        return true;
    }
    step_fmt(format_args!("HIGH POINTER {:#x} for the firmware: {}", p as u64, what));
    false
}

/// Once, at "reading the boot files": where the firmware is handed things while the kernel
/// runs (the page-table root, the stack, the IDT): every one of them should be below 4 GiB.
pub fn machine_state() {
    let cr3 = x86_64::registers::control::Cr3::read().0.start_address().as_u64();
    let rsp: u64;
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack, preserves_flags)) };
    let idt = x86_64::instructions::tables::sidt();
    let rflags = x86_64::registers::rflags::read_raw();
    step_fmt(format_args!(
        "state: CR3 {:#x}, stack {:#x}, IDT {:#x}+{:#x}, interrupts {}, high stack {:?}",
        cr3,
        rsp,
        idt.base.as_u64(),
        idt.limit,
        if rflags & (1 << 9) != 0 { "on" } else { "off" },
        crate::arch::relocate::stack_phys()
    ));
}
