//! # Boot-volume files (UEFI FAT)
//!
//! Reads files from the UEFI boot volume (and other attached FAT volumes) while UEFI Boot
//! Services are still running. These helpers used to live in `shell::fs`; the kernel needs
//! them without the shell (the ELF loader, the scheduler, the ZFS client's `/bin` sync, the
//! boot-disk probe and the first-boot settings), so they live here now. The shell re-exports
//! them.
//!
//! ## Key functions
//! - `read_boot_file` / `read_media_file`: whole files into heap memory.
//! - `file_exists`: whether a regular file exists on the boot volume.
//! - `open_root_volume`, `path_to_cstr16`, `fw_read`: building blocks for callers that walk
//!   the volume themselves.
//!
//! ## Context
//! - Ring 0, only before `ExitBootServices` (each function fails cleanly in hardware mode).

use uefi::boot::{allocate_pages, AllocateType};
use uefi::mem::memory_map::MemoryType;
use uefi::proto::media::file::{Directory, File, FileAttribute, FileInfo, FileMode};
use uefi::CStr16;

/// wave11 GH: a buffer for the firmware's file information and directory entries, aligned
/// as they need (8 bytes: the `uefi` crate panics on a buffer that is not). A plain byte
/// array happened to be aligned on the old stack and was not on the NUC's firmware stack.
#[repr(C, align(8))]
pub struct InfoBuf(pub [u8; 1024]);

impl InfoBuf {
    /// A zeroed buffer.
    pub const fn new() -> Self {
        InfoBuf([0; 1024])
    }

    /// The bytes, for the firmware (a higher-half buffer is recorded: `crumb::fw_ptr_ok`).
    pub fn bytes(&mut self) -> &mut [u8] {
        crate::arch::crumb::fw_ptr_ok(self.0.as_ptr(), "a file information buffer");
        &mut self.0
    }
}

/// Maximum size of a boot file loaded into memory by [`read_boot_file`] (16 MiB).
pub const MAX_LOAD_SIZE: usize = 16 * 1024 * 1024;

/// Converts an ASCII/UTF-8 path string into a NUL-terminated UTF-16 [`CStr16`].
///
/// Strips leading slashes (`/` or `\`) and normalizes forward slashes (`/`) to UEFI
/// backslashes (`\`) so the path opens relative to the root of a UEFI volume.
///
/// # Arguments
///
/// * `path` - Input UTF-8 path string.
/// * `buf` - Caller-provided `u16` scratch buffer to hold the encoded UTF-16 code units.
///
/// # Returns
///
/// * `Some(&CStr16)` - Valid NUL-terminated UTF-16 string slice backed by `buf`.
/// * `None` - If `buf` is too small to hold the converted path plus NUL terminator.
///
/// # Panics
///
/// - *Guaranteed to never panic under normal execution.*
pub fn path_to_cstr16<'a>(path: &str, buf: &'a mut [u16]) -> Option<&'a CStr16> {
    let clean = path.trim_start_matches(['\\', '/']);
    if clean.len() + 1 > buf.len() {
        return None;
    }
    for (i, b) in clean.bytes().enumerate() {
        buf[i] = if b == b'/' { b'\\' as u16 } else { b as u16 };
    }
    buf[clean.len()] = 0;
    // wave11 GH: the name goes to the firmware: never from a higher-half buffer
    if !crate::arch::crumb::fw_ptr_ok(buf.as_ptr() as *const u8, "a file name") {
        return None;
    }
    CStr16::from_u16_with_nul(&buf[..=clean.len()]).ok()
}

/// Opens the root directory of the UEFI boot volume from which the kernel image was loaded.
///
/// # Returns
///
/// * `Ok(Directory)` - Handle to the open root directory of the boot volume.
/// * `Err(&'static str)` - If UEFI Boot Services have been terminated or the protocol cannot be opened.
///
/// # Errors
///
/// Returns an error if the kernel has already transitioned to bare-metal hardware mode or if
/// the UEFI `SimpleFileSystem` protocol fails.
pub fn open_root_volume() -> Result<Directory, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("UEFI Boot Services terminated (operating in bare-metal hardware mode)");
    }
    let handle = uefi::boot::image_handle();
    let mut fs = uefi::boot::get_image_file_system(handle)
        .map_err(|_| "Failed to access boot file system protocol")?;
    fs.open_volume()
        .map_err(|_| "Failed to open root volume directory")
}

/// Firmware buffer for [`fw_read`] (identity address; 0 until first used).
static FW_BOUNCE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Size of [`FW_BOUNCE`].
const FW_BOUNCE_SIZE: usize = 256 * 1024;

/// Reads from a firmware file into `buf`, as `file.read`. A buffer of the kernel's (in the
/// higher half: heap, stack, statics) is filled through one at an identity address: the
/// firmware's disk drivers may have the device write straight into the caller's buffer,
/// taking its address for a physical one.
///
/// # Returns
/// The bytes read (0 at the end of the file), or `Err` on an I/O error.
pub fn fw_read(file: &mut uefi::proto::media::file::RegularFile, buf: &mut [u8]) -> Result<usize, ()> {
    if (buf.as_ptr() as u64) < 0x8000_0000_0000_0000 {
        // wave11 GH: each read on the screen too (where one stops: NUC run 9)
        crate::arch::crumb::read_fmt(format_args!("  firmware read: {} bytes into {:#x}", buf.len(), buf.as_ptr() as u64));
        let r = file.read(buf);
        match &r { Ok(n) => crate::arch::crumb::read_fmt(format_args!("  read returned: {} bytes", n)), Err(e) => crate::arch::crumb::read_fmt(format_args!("  read returned: error {:?}", e.status())) } // (no heap: the boot words are read before it)
        return r.map_err(|_| ());
    }
    let mut bounce = FW_BOUNCE.load(core::sync::atomic::Ordering::Relaxed);
    if bounce == 0 {
        bounce = allocate_pages(AllocateType::MaxAddress(0xFFFF_FFFF), MemoryType::LOADER_DATA, FW_BOUNCE_SIZE / 4096).map_err(|_| ())?.as_ptr() as u64;
        FW_BOUNCE.store(bounce, core::sync::atomic::Ordering::Relaxed);
    }
    let n = buf.len().min(FW_BOUNCE_SIZE);
    crate::arch::crumb::read_fmt(format_args!("  firmware read: {} bytes into {:#x}", n, bounce)); // wave11 GH
    let tmp = unsafe { core::slice::from_raw_parts_mut(bounce as *mut u8, n) };
    let r = file.read(tmp);
    match &r { Ok(n) => crate::arch::crumb::read_fmt(format_args!("  read returned: {} bytes", n)), Err(e) => crate::arch::crumb::read_fmt(format_args!("  read returned: error {:?}", e.status())) } // (no heap: the boot words are read before it) // wave11 GH
    let got = r.map_err(|_| ())?;
    buf[..got].copy_from_slice(&tmp[..got]);
    Ok(got)
}

/// Largest file `read_media_file` will load into memory (1 GiB, used for root filesystem archives).
const MAX_MEDIA_FILE: usize = 1024 * 1024 * 1024;

/// Reads an entire file from the first attached UEFI FAT volume that contains it.
///
/// Searches all handles implementing `SimpleFileSystem` (both the boot volume and any
/// attached installation media) and supports payloads up to [`MAX_MEDIA_FILE`] (1 GiB).
///
/// # Arguments
///
/// * `path` - Relative or root-anchored path to the target file on the FAT volume.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Heap-allocated vector containing the complete file contents.
/// * `Err(&'static str)` - Static error description if in hardware mode, not found, or an I/O error occurs.
///
/// # Errors
///
/// Returns an error if Boot Services are inactive, the path exceeds buffer limits, the file
/// exceeds 1 GiB, or no attached volume contains `path`.
pub fn read_media_file(path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("Boot media reading unavailable in hardware mode");
    }
    let mut path_u16 = [0u16; 128];
    let cstr = path_to_cstr16(path, &mut path_u16).ok_or("Path too long or invalid")?;
    let handles = uefi::boot::locate_handle_buffer(uefi::boot::SearchType::from_proto::<uefi::proto::media::fs::SimpleFileSystem>())
        .map_err(|_| "No file systems available")?;
    for handle in handles.iter() {
        let mut fs = match uefi::boot::open_protocol_exclusive::<uefi::proto::media::fs::SimpleFileSystem>(*handle) {
            Ok(fs) => fs,
            Err(_) => continue,
        };
        let mut root = match fs.open_volume() {
            Ok(r) => r,
            Err(_) => continue,
        };
        let mut file = match root.open(cstr, FileMode::Read, FileAttribute::empty()).ok().and_then(|h| h.into_regular_file()) {
            Some(f) => f,
            None => continue,
        };
        let mut info_buf = InfoBuf::new();
        let size = file.get_info::<FileInfo>(info_buf.bytes()).map_err(|_| "Failed to query file info")?.file_size() as usize;
        if size > MAX_MEDIA_FILE {
            return Err("File too large");
        }
        let mut buf = alloc::vec![0u8; size];
        let mut total = 0;
        while total < size {
            match fw_read(&mut file, &mut buf[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(_) => return Err("I/O error reading media file"),
            }
        }
        buf.truncate(total);
        return Ok(buf);
    }
    Err("File not found on any attached volume")
}

/// Reads an entire file (up to 16 MiB) from the UEFI boot volume into a heap-allocated buffer.
///
/// # Arguments
///
/// * `path` - File path on the boot volume.
///
/// # Returns
///
/// * `Ok(Vec<u8>)` - Heap-allocated buffer containing the file bytes.
/// * `Err(&'static str)` - Error message if the file is missing, empty, larger than 16 MiB, or unreadable.
///
/// # Errors
///
/// Returns an error if UEFI Boot Services are terminated, `path` is a directory or missing,
/// or the file size is outside `1..=MAX_LOAD_SIZE`.
pub fn read_boot_file(path: &str) -> Result<alloc::vec::Vec<u8>, &'static str> {
    if crate::console::is_hardware_mode() {
        return Err("Boot media reading unavailable in hardware mode");
    }
    let mut root = open_root_volume()?;
    let mut path_u16 = [0u16; 128];
    let cstr = path_to_cstr16(path, &mut path_u16).ok_or("Path too long or invalid")?;

    let file_handle = root.open(cstr, FileMode::Read, FileAttribute::empty())
        .map_err(|_| "File not found on boot media")?;
    let mut file = file_handle.into_regular_file().ok_or("Path is directory, not file")?;

    let mut info_buf = InfoBuf::new();
    let file_info = file.get_info::<FileInfo>(info_buf.bytes()).map_err(|_| "Failed to query file info")?;
    let file_size = file_info.file_size() as usize;
    if file_size == 0 || file_size > MAX_LOAD_SIZE {
        return Err("Invalid file size");
    }

    let mut buf = alloc::vec![0u8; file_size];
    let mut total_read = 0;
    while total_read < file_size {
        match fw_read(&mut file, &mut buf[total_read..]) {
            Ok(0) => break,
            Ok(n) => total_read += n,
            Err(_) => return Err("I/O error reading boot file"),
        }
    }
    buf.truncate(total_read);
    Ok(buf)
}

/// Checks whether a regular file exists at the given path on the UEFI boot volume.
///
/// # Arguments
///
/// * `path` - File path on the boot volume.
///
/// # Returns
///
/// `true` if UEFI Boot Services are active and `path` resolves to a regular file; `false` otherwise.
pub fn file_exists(path: &str) -> bool {
    if crate::console::is_hardware_mode() {
        return false;
    }
    let mut root = match open_root_volume() {
        Ok(r) => r,
        Err(_) => return false,
    };
    let mut path_u16 = [0u16; 128];
    let cstr = match path_to_cstr16(path, &mut path_u16) {
        Some(s) => s,
        None => return false,
    };

    match root.open(cstr, FileMode::Read, FileAttribute::empty()) {
        Ok(handle) => handle.into_regular_file().is_some(),
        Err(_) => false,
    }
}
