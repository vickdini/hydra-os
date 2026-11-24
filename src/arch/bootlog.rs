//! # The boot log on the EFI partition (machines without a serial port)
//!
//! Everything the kernel and the services print (what a test harness reads from the serial
//! port) is also kept in memory ([`super::logring`]) and written to a file on the EFI
//! system partition Hydra started from: `\logs\bootNNN.txt` (the newest has the highest
//! number; the last 10 are kept). On the installation stick that partition is the drive
//! Windows shows when the stick is plugged in, so the log can be read and sent on another
//! computer. Only when Hydra started from a GPT partition (a stick, an installed disk):
//! booted from a CD or ISO (the test harnesses) nothing is written.
//!
//! How the text reaches the file, so that a hang or a crash still leaves a log:
//! 1. **Before `ExitBootServices`** ([`prepare_file`]): the firmware's own FAT driver
//!    creates the file at its full size ([`logring::FILE_SIZE`], empty lines) and writes
//!    what the log has so far. The file never changes size afterwards, so the FAT never
//!    changes either.
//! 2. **While Hydra runs** ([`start_writer`]): a kernel task finds the file's clusters on
//!    the partition (read-only FAT walk, [`crate::fs::fat32`]) and rewrites the new part
//!    of the log into them every [`PERIOD_MS`] through the disk driver
//!    ([`crate::fs::blockdev`]).
//! 3. **At power-off and restart** ([`at_power`]): a last write, before the stick prompt.
//! 4. **After a kernel panic, or when the pool's disk never came** (nothing can be written
//!    then): the log stays in memory at a fixed physical address; the screen says so and
//!    the machine restarts after [`PANIC_WAIT_S`] seconds (a warm restart keeps the memory).
//!    The next start ([`early`], [`prepare_file`]) finds the old log there and writes it
//!    into the old boot's file before anything else.

use super::logring::{self, Header};
use crate::fs::fat32;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// How often the writer task writes the new part of the log.
pub const PERIOD_MS: u64 = 20_000;
/// How long the panic screen stays before the restart that saves the log.
pub const PANIC_WAIT_S: u64 = 60;
/// Log files kept on the partition.
const KEEP: usize = 10;
/// Directory of the log files (8.3 names: the kernel's FAT walk reads only those).
const DIR: &str = "logs";

/// Physical addresses tried for the log's memory, in order (the same at every start, so
/// the next start finds a crashed boot's log): above 4 GiB first (the firmware rarely uses
/// it), then two below.
const PLACES: [u64; 3] = [0x1_1000_0000, 0x7000_0000, 0x3000_0000];

/// Physical address of this boot's log region (0: none).
static REGION: AtomicU64 = AtomicU64::new(0);
/// Physical address of a copy of the previous boot's log, still to be saved (0: none).
static PREV: AtomicU64 = AtomicU64::new(0);
/// The previous boot was itself a restart made only to save a log (no second one now).
static PREV_WAS_SAVE: AtomicBool = AtomicBool::new(false);
/// The log goes to a file (Hydra started from a GPT partition and the file was made).
static FILE_ON: AtomicBool = AtomicBool::new(false);
/// The last write was made (power-off, restart): the writer task writes no more, so the
/// file keeps its end line.
static STOPPED: AtomicBool = AtomicBool::new(false);
/// Serializes changes of the region ([`append`] gives up rather than wait long).
static LOCK: Mutex<()> = Mutex::new(());

/// The log file as the writer task found it on the partition.
struct Target {
    /// Disk index (`fs::blockdev`).
    disk: usize,
    /// The partition's first byte on the disk.
    part_start: u64,
    /// The partition's length (no write goes past it).
    part_len: u64,
    /// Where the file's bytes are.
    map: fat32::FileMap,
    /// Bytes of the rendered log already in the file (when the ring has not wrapped).
    written: usize,
}

static TARGET: Mutex<Option<Target>> = Mutex::new(None);

/// The region as a byte slice.
///
/// # Safety
/// The region exists (`REGION` != 0) and the caller holds [`LOCK`] when it changes it.
unsafe fn region<'a>(phys: u64) -> &'a mut [u8] {
    core::slice::from_raw_parts_mut(crate::memory::frame_allocator::phys_to_virt(phys), logring::REGION)
}

/// Pages of a region.
const PAGES: usize = logring::REGION.div_ceil(4096);

/// First thing at boot (firmware running, no heap): takes the log's memory at one of
/// [`PLACES`]. A previous boot's log found there that was not written to its file is
/// copied aside for [`prepare_file`].
pub fn early() {
    use uefi::boot::{allocate_pages, AllocateType, MemoryType};
    for &at in &PLACES {
        if allocate_pages(AllocateType::Address(at), MemoryType::LOADER_DATA, PAGES).is_err() {
            continue;
        }
        let r = unsafe { region(at) };
        let old = logring::header(r);
        if old.unsaved() {
            if let Ok(copy) = allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, PAGES) {
                unsafe { core::ptr::copy_nonoverlapping(r.as_ptr(), copy.as_ptr(), logring::REGION) };
                PREV.store(copy.as_ptr() as u64, Ordering::Relaxed);
            }
        }
        PREV_WAS_SAVE.store(old.valid() && old.flags & (logring::F_SAVE_RESTART | logring::F_PANIC) != 0, Ordering::Relaxed);
        logring::set_header(r, &Header::new(0));
        REGION.store(at, Ordering::Release);
        return;
    }
}

/// Adds console text to the log (from the console and the serial port's writers). Never
/// waits long: text that comes while another CPU holds the log for long is left out.
pub fn append(text: &[u8]) {
    let at = REGION.load(Ordering::Acquire);
    if at == 0 {
        return;
    }
    for _ in 0..2000 {
        if let Some(_g) = LOCK.try_lock() {
            logring::append(unsafe { region(at) }, text);
            return;
        }
        core::hint::spin_loop();
    }
}

/// The rendered log and its header, taken under the lock.
fn snapshot() -> Option<(Vec<u8>, Header)> {
    let at = REGION.load(Ordering::Acquire);
    if at == 0 {
        return None;
    }
    let _g = LOCK.lock();
    let r = unsafe { region(at) };
    Some((logring::render(r), logring::header(r)))
}

/// Sets flags in this boot's header.
fn set_flags(flags: u32) {
    let at = REGION.load(Ordering::Acquire);
    if at == 0 {
        return;
    }
    // (also from the panic handler: a lock another CPU holds must not stop it)
    let _g = LOCK.try_lock();
    let r = unsafe { region(at) };
    let mut h = logring::header(r);
    h.flags |= flags;
    logring::set_header(r, &h);
}

/// Whether the log goes to a file on the EFI partition.
pub fn file_on() -> bool {
    FILE_ON.load(Ordering::Acquire)
}

/// Writes `data` at byte `at` of the open firmware file through a buffer at an identity
/// address (the firmware's disk drivers may take a buffer's address for a physical one).
fn fw_write(file: &mut uefi::proto::media::file::RegularFile, at: u64, data: &[u8], bounce: &mut [u8]) -> bool {
    if file.set_position(at).is_err() {
        return false;
    }
    for chunk in data.chunks(bounce.len()) {
        bounce[..chunk.len()].copy_from_slice(chunk);
        if file.write(&bounce[..chunk.len()]).is_err() {
            return false;
        }
    }
    true
}

/// Before `ExitBootServices`, with the heap (step 6 of boot): when Hydra started from a GPT
/// partition, makes this boot's log file (deleting the oldest beyond [`KEEP`]), writes a
/// previous boot's unsaved log into its file, and writes the log so far.
pub fn prepare_file() {
    use uefi::boot::{allocate_pages, free_pages, AllocateType, MemoryType};
    use uefi::proto::media::file::{File, FileAttribute, FileInfo, FileMode};
    if REGION.load(Ordering::Acquire) == 0 || crate::arch::bootdisk::info().boot_part.is_none() {
        return;
    }
    let Ok(mut root) = crate::fs::bootfs::open_root_volume() else { return };
    let mut name = [0u16; 64];
    let Some(dname) = crate::fs::bootfs::path_to_cstr16(DIR, &mut name) else { return };
    let Some(mut dir) = root.open(dname, FileMode::CreateReadWrite, FileAttribute::DIRECTORY).ok().and_then(|h| h.into_directory()) else {
        crate::kprintln!("[bootlog] cannot make \\{} on the EFI partition (read-only?): no log file", DIR);
        return;
    };
    // The files there
    let mut have = Vec::new();
    #[repr(C, align(8))]
    struct EntryBuf([u8; 1024]);
    let mut eb = EntryBuf([0; 1024]);
    while let Ok(Some(info)) = dir.read_entry(&mut eb.0) {
        let n = alloc::format!("{}", info.file_name());
        if let Some(k) = logring::file_number(&n) {
            if !info.attribute().contains(FileAttribute::DIRECTORY) {
                have.push(k);
            }
        }
    }
    let Ok(bounce) = allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, 16) else { return };
    let bounce = unsafe { core::slice::from_raw_parts_mut(bounce.as_ptr(), 16 * 4096) };
    let open = |dir: &mut uefi::proto::media::file::Directory, n: u32, mode: FileMode| {
        let mut buf = [0u16; 32];
        let fname = logring::file_name(n);
        let c = crate::fs::bootfs::path_to_cstr16(&fname, &mut buf)?;
        dir.open(c, mode, FileAttribute::empty()).ok()?.into_regular_file()
    };
    // The previous boot's log that it could not write itself
    let prev = PREV.swap(0, Ordering::Relaxed);
    if prev != 0 {
        let r = unsafe { region(prev) };
        let h = logring::header(r);
        let text = logring::render(r);
        // (only into this partition's files: the last start may have been from another disk)
        if have.contains(&h.seq) && Some(h.part) == crate::arch::bootdisk::info().boot_part {
            if let Some(mut f) = open(&mut dir, h.seq, FileMode::ReadWrite) {
                let mut ok = fw_write(&mut f, 0, &text, bounce);
                let why = if h.flags & logring::F_PANIC != 0 { "a kernel panic" } else { "a restart to save it" };
                let end = alloc::format!("\r\n--- end of the log: saved by the next start of Hydra after {} ---\r\n", why);
                ok &= fw_write(&mut f, text.len() as u64, end.as_bytes(), bounce);
                let _ = f.flush();
                crate::kprintln!("[bootlog] the previous start's log ({} bytes, {}) {} {}", text.len(), why, if ok { "saved to" } else { "could NOT be saved to" }, logring::file_name(h.seq));
            }
        }
        let _ = unsafe { free_pages(core::ptr::NonNull::new_unchecked(prev as *mut u8), PAGES) };
    }
    let (next, delete) = logring::next_number(&have, KEEP);
    for n in delete {
        if let Some(f) = open(&mut dir, n, FileMode::ReadWrite) {
            let _ = f.delete();
        }
    }
    let Some(mut f) = open(&mut dir, next, FileMode::CreateReadWrite) else {
        crate::kprintln!("[bootlog] cannot create \\{}\\{}: no log file", DIR, logring::file_name(next));
        return;
    };
    // Its full size first (the clusters the writer task fills later), then the log so far
    let fill = logring::filler(bounce.len());
    let mut ok = true;
    let mut at = 0u64;
    while ok && (at as usize) < logring::FILE_SIZE {
        let n = (logring::FILE_SIZE - at as usize).min(fill.len());
        ok = fw_write(&mut f, at, &fill[..n], bounce);
        at += n as u64;
    }
    // This boot's number in the header (the log so far is written with it)
    {
        let at = REGION.load(Ordering::Acquire);
        let _g = LOCK.lock();
        let r = unsafe { region(at) };
        let old = logring::header(r);
        let mut h = Header::new(next);
        h.head_len = old.head_len;
        h.ring_written = old.ring_written;
        h.part = crate::arch::bootdisk::info().boot_part.unwrap_or_default();
        logring::set_header(r, &h);
    }
    crate::kprintln!("[bootlog] this start's log: \\{}\\{} on the EFI partition", DIR, logring::file_name(next));
    if let Some((text, _)) = snapshot() {
        ok &= fw_write(&mut f, 0, &text, bounce);
    }
    let _ = f.flush();
    let size = f.get_info::<FileInfo>(&mut [0u8; 256][..]).map(|i| i.file_size()).unwrap_or(0);
    f.close();
    // From the stick: the installed system's logs too, so one stick carries them all
    if crate::arch::bootdisk::info().live {
        collect_disk_logs(&mut dir, bounce);
    }
    let _ = unsafe { free_pages(core::ptr::NonNull::new_unchecked(bounce.as_mut_ptr()), 16) };
    if ok && size as usize == logring::FILE_SIZE {
        FILE_ON.store(true, Ordering::Release);
    } else {
        crate::kprintln!("[bootlog] the log file could not be made at its full size ({} bytes): no log file", size);
    }
}

/// The live stick's start (before `ExitBootServices`): copies the log files of every other
/// Hydra EFI partition the firmware sees (an installed system's: `\EFI\hydra\hydra.efi`
/// and no `\hydra\live`) into `\logs\disk\` on the stick. So after a test of the installed
/// system, starting the stick once more brings its logs to where Windows can read them.
///
/// Only disks are connected (handles with the block I/O protocol: their partitions and file
/// systems), never every controller (network boot stacks...). A copy is written only when
/// the source changed since the last start: `\logs\disk\index.txt` keeps each copied file's
/// name and fingerprint.
fn collect_disk_logs(stick_logs: &mut uefi::proto::media::file::Directory, bounce: &mut [u8]) {
    use uefi::proto::media::block::BlockIO;
    use uefi::proto::media::file::{File, FileAttribute, FileMode};
    use uefi::proto::media::fs::SimpleFileSystem;
    let own = uefi::boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(uefi::boot::image_handle()).ok().and_then(|i| i.device());
    // The disks' partitions and file systems (the firmware may have connected only the
    // device it booted from); at most 16 disks
    if let Ok(disks) = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::from_proto::<BlockIO>()) {
        for &h in disks.iter().take(16) {
            let _ = uefi::boot::connect_controller(h, &[], None, true);
        }
    }
    let Ok(handles) = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::from_proto::<SimpleFileSystem>()) else { return };
    let mut hydra_volumes = 0;
    #[repr(C, align(8))]
    struct EntryBuf([u8; 1024]);
    let mut eb = EntryBuf([0; 1024]);
    let (mut copied, mut same) = (0, 0);
    for &h in handles.iter() {
        if Some(h) == own {
            continue;
        }
        let Ok(mut sfs) = uefi::boot::open_protocol_exclusive::<SimpleFileSystem>(h) else { continue };
        let Ok(mut root) = sfs.open_volume() else { continue };
        let mut b = [0u16; 64];
        let is = |root: &mut uefi::proto::media::file::Directory, p: &str, b: &mut [u16; 64]| {
            crate::fs::bootfs::path_to_cstr16(p, b).is_some_and(|c| root.open(c, FileMode::Read, FileAttribute::empty()).is_ok())
        };
        if !is(&mut root, "EFI\\hydra\\hydra.efi", &mut b) || is(&mut root, "hydra\\live", &mut b) {
            continue;
        }
        hydra_volumes += 1;
        let Some(c) = crate::fs::bootfs::path_to_cstr16(DIR, &mut b) else { continue };
        let Some(mut logs) = root.open(c, FileMode::Read, FileAttribute::empty()).ok().and_then(|f| f.into_directory()) else { continue };
        let mut b2 = [0u16; 64];
        let Some(dc) = crate::fs::bootfs::path_to_cstr16("disk", &mut b2) else { continue };
        let Some(mut out) = stick_logs.open(dc, FileMode::CreateReadWrite, FileAttribute::DIRECTORY).ok().and_then(|f| f.into_directory()) else { return };
        let mut names = Vec::new();
        while let Ok(Some(info)) = logs.read_entry(&mut eb.0) {
            let n = alloc::format!("{}", info.file_name());
            if logring::file_number(&n).is_some() && !info.attribute().contains(FileAttribute::DIRECTORY) {
                names.push(n);
            }
        }
        // What was copied at earlier starts (name and fingerprint per line)
        let mut ib = [0u16; 64];
        let Some(ic) = crate::fs::bootfs::path_to_cstr16("index.txt", &mut ib) else { continue };
        let mut index = alloc::string::String::new();
        if let Some(mut f) = out.open(ic, FileMode::Read, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) {
            let mut buf = alloc::vec![0u8; 4096];
            let n = crate::fs::bootfs::fw_read(&mut f, &mut buf).unwrap_or(0);
            index = alloc::string::String::from_utf8_lossy(&buf[..n]).into_owned();
        }
        let mut new_index = alloc::string::String::new();
        for n in names {
            let mut nb = [0u16; 64];
            let Some(c) = crate::fs::bootfs::path_to_cstr16(&n, &mut nb) else { continue };
            let Some(mut src) = logs.open(c, FileMode::Read, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) else { continue };
            let mut data = alloc::vec![0u8; logring::FILE_SIZE + 4096];
            let mut len = 0;
            while len < data.len() {
                match crate::fs::bootfs::fw_read(&mut src, &mut data[len..]) {
                    Ok(0) | Err(_) => break,
                    Ok(k) => len += k,
                }
            }
            let line = alloc::format!("{} {:016x}\r\n", n.to_ascii_lowercase(), logring::fingerprint(&data[..len]));
            new_index.push_str(&line);
            if index.contains(&line) {
                same += 1;
                continue;
            }
            // A fresh copy (an older one of the same name goes first)
            if let Some(old) = out.open(c, FileMode::ReadWrite, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) {
                let _ = old.delete();
            }
            if let Some(mut dst) = out.open(c, FileMode::CreateReadWrite, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) {
                if fw_write(&mut dst, 0, &data[..len], bounce) {
                    copied += 1;
                }
                let _ = dst.flush();
            }
        }
        // The index last: a copy cut short is copied again at the next start
        if let Some(old) = out.open(ic, FileMode::ReadWrite, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) {
            let _ = old.delete();
        }
        if let Some(mut f) = out.open(ic, FileMode::CreateReadWrite, FileAttribute::empty()).ok().and_then(|f| f.into_regular_file()) {
            let _ = fw_write(&mut f, 0, new_index.as_bytes(), bounce);
            let _ = f.flush();
        }
    }
    crate::kprintln!(
        "[bootlog] {} other EFI volumes, {} with an installed Hydra: {} of its log files copied to \\{}\\disk on the stick, {} unchanged",
        handles.len().saturating_sub(1),
        hydra_volumes,
        copied,
        DIR,
        same
    );
}

/// After the disks are known (`blockdev::scan`): starts the task that writes the log into
/// its file every [`PERIOD_MS`].
pub fn start_writer() {
    if file_on() {
        crate::task::spawn("bootlog", writer_task, crate::task::TaskPriority::Low);
    }
}

/// The disk (`fs::blockdev` index) holding the partition Hydra started from, and the
/// partition's first byte and length.
fn boot_partition() -> Option<(usize, u64, u64)> {
    let guid = crate::arch::bootdisk::info().boot_part?;
    crate::fs::blockdev::disks().iter().enumerate().find_map(|(idx, d)| {
        let p = d.parts.iter().find(|p| p.entry.as_ref().is_some_and(|e| e.part_guid == guid))?;
        Some((idx, p.start, p.len))
    })
}

/// Whether disk `idx` still answers (reads its first sector into `sector`).
pub fn disk_present(idx: usize, sector: &mut [u8; 512]) -> bool {
    crate::fs::blockdev::read_at(idx, 0, sector).is_ok()
}

/// The disk Hydra started from (the stick of a live session), if the drivers found it.
pub fn boot_disk() -> Option<usize> {
    boot_partition().map(|(idx, _, _)| idx)
}

/// Finds the log file's clusters on the boot partition.
fn find_target() -> Result<Target, &'static str> {
    let seq = snapshot().map(|(_, h)| h.seq).unwrap_or(0);
    let (idx, start, len) = boot_partition().ok_or("the boot partition is on no disk the drivers found")?;
    let mut read = |off: u64, buf: &mut [u8]| off + buf.len() as u64 <= len && crate::fs::blockdev::read_at(idx, start + off, buf) == Ok(buf.len());
    let name = logring::file_name(seq);
    let map = fat32::locate(&mut read, len, &[DIR, &name])?;
    if map.size as usize != logring::FILE_SIZE {
        return Err("the log file does not have its full size");
    }
    if map.extents.iter().any(|e| e.part_off + e.len > len) {
        return Err("the log file's clusters lie past the partition's end");
    }
    Ok(Target { disk: idx, part_start: start, part_len: len, map, written: 0 })
}

/// Writes the new part of the log (all of it after the head once the ring wrapped) and
/// `end` after it. Returns whether it worked.
fn write_out(end: &str, last: bool, wait_ms: u64) -> bool {
    // (the lock is held across disk calls: never spin for it, wait with a deadline; with one
    // processor a spinning high-priority task would starve the holder)
    let Some(mut t) = lock_target(wait_ms) else {
        if last {
            STOPPED.store(true, Ordering::Release);
        }
        return false;
    };
    // After the last write nothing more (the file keeps its end line)
    if STOPPED.load(Ordering::Acquire) {
        return true;
    }
    if last {
        STOPPED.store(true, Ordering::Release);
    }
    if t.is_none() {
        match find_target() {
            Ok(found) => {
                crate::kprintln!("[bootlog] writing the log into its file on {} every {} s", crate::fs::blockdev::disk(found.disk).map_or(alloc::string::String::from("?"), |d| d.name), PERIOD_MS / 1000);
                *t = Some(found)
            }
            Err(e) => {
                crate::kprintln!("[bootlog] the log file cannot be written: {}", e);
                return false;
            }
        }
    }
    let t = t.as_mut().unwrap();
    // The disk the drivers have under that index must still hold the boot partition where
    // it was (a stick replaced by another disk must never get the log)
    if boot_partition() != Some((t.disk, t.part_start, t.part_len)) {
        crate::kprintln!("[bootlog] the boot partition is not where it was: no more log writes");
        STOPPED.store(true, Ordering::Release);
        return false;
    }
    let Some((mut text, h)) = snapshot() else { return false };
    let from = if logring::wrapped(&h) { (h.head_len as usize).min(t.written) } else { t.written };
    let from = from & !4095;
    text.extend_from_slice(end.as_bytes());
    text.truncate(logring::FILE_SIZE);
    let mut ok = true;
    for (part_off, file_off, len) in t.map.pieces(from as u64, (text.len() - from.min(text.len())) as u64) {
        let data = &text[file_off as usize..(file_off + len) as usize];
        if part_off + len > t.part_len {
            ok = false;
            break;
        }
        if crate::fs::blockdev::write_at(t.disk, t.part_start + part_off, data) != Ok(data.len()) {
            ok = false;
            break;
        }
    }
    if ok {
        let _ = crate::fs::blockdev::flush(t.disk);
        t.written = text.len() - end.len().min(text.len());
    }
    ok
}

/// The writer's state, waiting at most `ms` for it (sleeping, not spinning).
fn lock_target(ms: u64) -> Option<spin::MutexGuard<'static, Option<Target>>> {
    let mut waited = 0;
    loop {
        if let Some(g) = TARGET.try_lock() {
            return Some(g);
        }
        if waited >= ms {
            return None;
        }
        crate::task::sleep_ms(10);
        waited += 10;
    }
}

/// The writer task: every [`PERIOD_MS`], the new part of the log.
fn writer_task() {
    let mut failures = 0;
    loop {
        if STOPPED.load(Ordering::Acquire) {
            crate::task::exit();
        }
        let up = crate::arch::pit::now_ns() / 1_000_000_000;
        let end = alloc::format!("\r\n--- the log so far (Hydra was running, {} s after the start) ---\r\n", up);
        if write_out(&end, false, 60_000) {
            failures = 0;
        } else {
            failures += 1;
            if failures == 3 {
                crate::kprintln!("[bootlog] the log file could not be written 3 times; trying again every minute");
            }
        }
        crate::task::sleep_ms(if failures >= 3 { 60_000 } else { PERIOD_MS });
    }
}

/// The final write at power-off or restart (`what`: "powered off", "restarted"), at most
/// a few seconds (the stick may be gone: then the log stays as last written).
pub fn at_power(what: &'static str) {
    if !file_on() || !crate::task::is_active() {
        return;
    }
    static DONE: AtomicBool = AtomicBool::new(false);
    static WHAT: Mutex<&str> = Mutex::new("");
    *WHAT.lock() = what;
    DONE.store(false, Ordering::SeqCst);
    fn last() {
        let what = *WHAT.lock();
        let end = alloc::format!("\r\n--- end of the log: Hydra {} ---\r\n", what);
        if write_out(&end, true, 4_000) {
            set_flags(logring::F_WRITTEN);
        }
        DONE.store(true, Ordering::SeqCst);
        crate::task::exit();
    }
    crate::kprintln!("[bootlog] writing the log file before Hydra is {}", what);
    crate::task::spawn("bootlog-last", last, crate::task::TaskPriority::High);
    for _ in 0..50 {
        if DONE.load(Ordering::SeqCst) {
            return;
        }
        crate::task::sleep_ms(100);
    }
    crate::kprintln!("[bootlog] the last write did not finish within 5 s (the disk gone?)");
}

/// Busy-waits `s` seconds (interrupts may be off).
fn wait_s(s: u64) {
    let end = crate::arch::pit::now_ns() + s * 1_000_000_000;
    while crate::arch::pit::now_ns() < end {
        core::hint::spin_loop();
    }
}

/// After a kernel panic was shown: when the log goes to a file, says on screen that the
/// machine restarts to save it, waits [`PANIC_WAIT_S`] and restarts (warm: the memory and
/// the log in it stay). Returns otherwise (the panic stays on screen).
pub fn after_panic() {
    if !file_on() {
        return;
    }
    set_flags(logring::F_PANIC);
    if PREV_WAS_SAVE.load(Ordering::Relaxed) {
        crate::console::print_raw("\n[!] Hydra stopped again after a restart. Take a photo of this screen, then switch the computer off (hold the power button).\n");
        return;
    }
    let mut line = crate::console::FixedBuf::new();
    let _ = core::fmt::Write::write_fmt(&mut line, format_args!("\n[!] Take a photo of this screen. Hydra restarts in {} s to save its log on the EFI partition (\\logs).\n", PANIC_WAIT_S));
    crate::console::print_raw(line.as_str());
    wait_s(PANIC_WAIT_S);
    crate::arch::power::hard_reset();
}

/// After the ZFS file server started: if the pool's disk never came, the log cannot reach
/// the boot disk through the drivers either (the same disk, usually): restart once so the
/// next start saves it. Waits for the writer first (it may still manage).
pub fn check_pool() {
    if !file_on() || crate::fs::zfs::disk_info().is_some() {
        return;
    }
    crate::kprintln!("[bootlog] the pool's disk was not found");
    if write_out("\r\n--- the log so far (the pool's disk was not found) ---\r\n", false, 10_000) {
        return;
    }
    if PREV_WAS_SAVE.load(Ordering::Relaxed) {
        crate::kprintln!("[bootlog] the log could not be written (again); not restarting a second time");
        return;
    }
    set_flags(logring::F_SAVE_RESTART);
    crate::kprintln!("");
    crate::kprintln!("    Hydra cannot reach its disk and cannot save its log there.");
    crate::kprintln!("    It restarts in 30 s; start Hydra from the same stick again and the log is saved.");
    crate::task::sleep_ms(30_000);
    crate::arch::power::hard_reset();
}
