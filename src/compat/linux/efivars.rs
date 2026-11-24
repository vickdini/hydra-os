//! # UEFI variables: `/sys/firmware/efi/efivars` (efivarfs)
//!
//! The firmware's variables as Linux's efivarfs shows them, so `efibootmgr` (libefivar)
//! can list, create and delete boot entries: one file per variable named
//! `<Name>-<vendor GUID>`, whose contents are the 4-byte attributes followed by the data.
//!
//! The files exist in the Linux root as ordinary files (written at boot and after every
//! change, [`refresh`]) so directory listings and `stat` work as for the rest of `/sys`.
//! Opening one gives a device file that reads the variable from the firmware and sets it
//! with a write (the attributes, then the data, in one `write`, as efivarfs requires);
//! deleting the file deletes the variable ([`unlink`]). `statfs` reports efivarfs's
//! magic, which libefivar checks.
//!
//! The firmware is called through its runtime services (`GetVariable`, `SetVariable`,
//! `GetNextVariableName`) with the kernel's page tables loaded (the firmware reaches its
//! memory at identity addresses), one call at a time.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::chardev::CharDevice;
use super::types::LinuxStat;
use crate::task::wait::WaitSet;
use uefi::runtime::{VariableAttributes, VariableVendor};
use uefi::{CStr16, Guid, Status};

/// The directory, as programs in the Linux root see it.
pub const DIR: &str = "/sys/firmware/efi/efivars";

/// `statfs` magic of efivarfs.
pub const EFIVARFS_MAGIC: i64 = 0xde5e_81e4;

const ENOENT: i64 = -2;
const EIO: i64 = -5;
const EBADF: i64 = -9;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const EPERM: i64 = -1;

/// One firmware call at a time.
static FIRMWARE: Mutex<()> = Mutex::new(());

/// Inode of the efivars directory in the pool (0: not written yet), for [`unlink`].
pub static DIR_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Runs a firmware runtime service call.
fn firmware<R>(f: impl FnOnce() -> R) -> R {
    let _one = FIRMWARE.lock();
    crate::memory::paging::with_kernel_tables(f)
}

/// The firmware's variable services: the UEFI runtime ([`Runtime`]); host tests put a
/// model of their own ([`set_services`]), so the file logic runs without firmware.
pub trait VarServices: Sync {
    /// `GetVariable`: the data's length and the attributes, or the status (and the size
    /// needed when the buffer is too small).
    fn get(&self, name: &CStr16, vendor: &VariableVendor, buf: &mut [u8]) -> Result<(usize, u32), (Status, Option<usize>)>;
    /// `SetVariable` (no data: delete).
    fn set(&self, name: &CStr16, vendor: &VariableVendor, attrs: VariableAttributes, data: &[u8]) -> Result<(), Status>;
    /// `GetNextVariableName`: the name after `name` (in place), or the status (and the size
    /// needed when the name buffer is too small).
    fn next(&self, name: &mut [u16], vendor: &mut VariableVendor) -> Result<(), (Status, Option<usize>)>;
}

/// The UEFI runtime services (hardware: only the calls themselves).
struct Runtime;

impl VarServices for Runtime {
    fn get(&self, name: &CStr16, vendor: &VariableVendor, buf: &mut [u8]) -> Result<(usize, u32), (Status, Option<usize>)> {
        uefi::runtime::get_variable(name, vendor, buf).map(|(d, a)| (d.len(), a.bits())).map_err(|e| (e.status(), *e.data()))
    }
    fn set(&self, name: &CStr16, vendor: &VariableVendor, attrs: VariableAttributes, data: &[u8]) -> Result<(), Status> {
        uefi::runtime::set_variable(name, vendor, attrs, data).map_err(|e| e.status())
    }
    fn next(&self, name: &mut [u16], vendor: &mut VariableVendor) -> Result<(), (Status, Option<usize>)> {
        uefi::runtime::get_next_variable_key(name, vendor).map_err(|e| (e.status(), *e.data()))
    }
}

static SERVICES: Mutex<&'static dyn VarServices> = Mutex::new(&Runtime);

/// Replaces the firmware's variable services (host tests).
pub fn set_services(s: &'static dyn VarServices) {
    *SERVICES.lock() = s;
}

fn services() -> &'static dyn VarServices {
    *SERVICES.lock()
}

fn errno(s: Status) -> i64 {
    match s {
        Status::NOT_FOUND => ENOENT,
        Status::INVALID_PARAMETER => EINVAL,
        Status::WRITE_PROTECTED | Status::SECURITY_VIOLATION => EPERM,
        Status::OUT_OF_RESOURCES => ENOSPC,
        _ => EIO,
    }
}

/// Splits a file name `<Name>-<GUID>` into the name and the GUID.
pub fn parse_name(file: &str) -> Option<(String, Guid)> {
    if file.len() < 38 || file.as_bytes()[file.len() - 37] != b'-' {
        return None;
    }
    let (name, guid) = (&file[..file.len() - 37], &file[file.len() - 36..]);
    let g = crate::fs::gpt::parse_guid(guid)?;
    (!name.is_empty()).then(|| (String::from(name), Guid::from_bytes(g)))
}

/// The file name of a variable.
pub fn file_name(name: &str, guid: &Guid) -> String {
    alloc::format!("{}-{}", name, crate::fs::gpt::guid_string(&guid.to_bytes()))
}

/// Reads a variable: its attributes and data.
pub fn get(name: &str, guid: &Guid) -> Result<(u32, Vec<u8>), i64> {
    let mut wide = [0u16; 512];
    let cname = CStr16::from_str_with_buf(name, &mut wide).map_err(|_| EINVAL)?;
    let vendor = VariableVendor(*guid);
    let mut buf = alloc::vec![0u8; 1024];
    loop {
        let r = firmware(|| services().get(cname, &vendor, &mut buf));
        match r {
            Ok((n, attrs)) => {
                buf.truncate(n);
                return Ok((attrs, buf));
            }
            Err((Status::BUFFER_TOO_SMALL, Some(need))) if need > buf.len() && need <= 1 << 20 => buf.resize(need, 0),
            Err((s, _)) => return Err(errno(s)),
        }
    }
}

/// Sets (or, with no data, deletes) a variable. `data` must be kernel memory (the
/// firmware runs with the kernel's page tables).
pub fn set(name: &str, guid: &Guid, attrs: u32, data: &[u8]) -> Result<(), i64> {
    let mut wide = [0u16; 512];
    let cname = CStr16::from_str_with_buf(name, &mut wide).map_err(|_| EINVAL)?;
    let vendor = VariableVendor(*guid);
    let attrs = VariableAttributes::from_bits_retain(attrs);
    firmware(|| services().set(cname, &vendor, attrs, data)).map_err(errno)
}

/// Every variable's name and vendor (`None`: the firmware has no variable services now).
pub fn list() -> Option<Vec<(String, Guid)>> {
    let mut out = Vec::new();
    let mut name = alloc::vec![0u16; 512];
    let mut vendor = VariableVendor(Guid::from_bytes([0; 16]));
    loop {
        let r = firmware(|| services().next(&mut name, &mut vendor));
        match r {
            Ok(()) => {
                let len = name.iter().position(|&c| c == 0).unwrap_or(name.len());
                out.push((String::from_utf16_lossy(&name[..len]), vendor.0));
                if out.len() > 4096 {
                    break;
                }
            }
            Err((Status::BUFFER_TOO_SMALL, Some(need))) if need > name.len() && need <= 32768 => {
                // The name buffer holds the previous name: keep it, larger
                name.resize(need, 0);
            }
            Err((Status::NOT_FOUND, _)) => break,
            Err((s, _)) => {
                if out.is_empty() {
                    crate::kprintln!("[efivars] GetNextVariableName: {:?}", s);
                    return None;
                }
                break;
            }
        }
    }
    Some(out)
}

/// Every variable as its efivarfs file: name and contents (attributes, then data).
pub fn snapshot() -> Option<Vec<(String, Vec<u8>)>> {
    let vars = list()?;
    Some(
        vars.into_iter()
            .filter_map(|(n, g)| {
                let (attrs, data) = get(&n, &g).ok()?;
                let mut c = attrs.to_le_bytes().to_vec();
                c.extend_from_slice(&data);
                Some((file_name(&n, &g), c))
            })
            .collect(),
    )
}

/// Rewrites the files after a change.
pub fn refresh() {
    super::devices::refresh_efivars();
}

/// Whether the caller has `CAP_SYS_ADMIN` (changing variables needs it).
fn admin() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1u64 << 21) != 0).unwrap_or(false)
}

/// An open variable file.
pub struct VarFile {
    name: String,
    guid: Guid,
    read: bool,
    write: bool,
    /// Bytes already read (reads go on from there; the contents are read at the first).
    pos: Mutex<(u64, Option<Vec<u8>>)>,
}

/// Opens `abs` if it names a variable file in [`DIR`] (`None`: not ours).
pub fn open(abs: &str, flags: u32) -> Option<Result<Arc<dyn CharDevice>, i64>> {
    let file = abs.strip_prefix(DIR)?.strip_prefix('/')?;
    if file.contains('/') {
        return None;
    }
    let (name, guid) = parse_name(file)?;
    let acc = flags & 3;
    let exists = get(&name, &guid).is_ok();
    if !exists && flags & 0o100 == 0 {
        return Some(Err(ENOENT));
    }
    if acc != 0 && !admin() {
        return Some(Err(EACCES));
    }
    Some(Ok(Arc::new(VarFile { name, guid, read: acc != 1, write: acc != 0, pos: Mutex::new((0, None)) })))
}

/// `unlink` of a file in the efivars directory `dir`: deletes the variable. `None`: the
/// directory is another one.
pub fn unlink(dir: u64, name: &[u8]) -> Option<Result<(), i64>> {
    if dir == 0 || dir != DIR_INO.load(core::sync::atomic::Ordering::Relaxed) {
        return None;
    }
    let (n, g) = parse_name(core::str::from_utf8(name).ok()?)?;
    if !admin() {
        return Some(Err(EACCES));
    }
    Some(match set(&n, &g, 0, &[]) {
        Ok(()) | Err(ENOENT) => Ok(()),
        Err(e) => Err(e),
    })
}

impl CharDevice for VarFile {
    fn read(&self, buf: &mut [u8]) -> i64 {
        if !self.read {
            return EBADF;
        }
        let mut p = self.pos.lock();
        if p.1.is_none() {
            match get(&self.name, &self.guid) {
                Ok((attrs, data)) => {
                    let mut c = attrs.to_le_bytes().to_vec();
                    c.extend_from_slice(&data);
                    p.1 = Some(c);
                }
                Err(e) => return e,
            }
        }
        let at = p.0 as usize;
        let c = p.1.as_ref().unwrap();
        let n = buf.len().min(c.len().saturating_sub(at));
        buf[..n].copy_from_slice(&c[at..at + n]);
        p.0 += n as u64;
        n as i64
    }

    fn write(&self, data: &[u8]) -> i64 {
        if !self.write {
            return EBADF;
        }
        if data.len() < 4 {
            return EINVAL;
        }
        let attrs = u32::from_le_bytes(data[0..4].try_into().unwrap());
        // The firmware runs with the kernel's page tables, which do not map the caller's
        // memory: the data goes through a kernel buffer
        let value = data[4..].to_vec();
        let r = set(&self.name, &self.guid, attrs, &value);
        refresh();
        match r {
            Ok(()) => data.len() as i64,
            Err(e) => {
                crate::kprintln!("[efivars] SetVariable {} ({} bytes, attributes {:#x}): errno {}", self.name, data.len() - 4, attrs, -e);
                e
            }
        }
    }

    fn ioctl(&self, cmd: u64, arg: u64) -> i64 {
        match cmd {
            // FS_IOC_GETFLAGS / FS_IOC_SETFLAGS: no immutable flag here
            0x8008_6601 => super::vfs::copy_out(arg, &0u32.to_le_bytes()).map_or_else(|e| e, |_| 0),
            0x4008_6602 => 0,
            _ => -25,
        }
    }

    fn poll_events(&self) -> u32 {
        0x5
    }

    fn add_wait_queues(&self, _waits: &mut WaitSet) {}

    fn rdev(&self) -> u64 {
        0
    }

    fn path(&self) -> String {
        alloc::format!("{}/{}", DIR, file_name(&self.name, &self.guid))
    }

    fn set_nonblock(&self, _on: bool) {}

    fn nonblock(&self) -> bool {
        false
    }

    fn stat(&self) -> LinuxStat {
        let mut st = LinuxStat::default();
        st.st_dev = 0x2d; // efivarfs
        st.st_ino = 0x4546_4900 ^ (self.name.len() as u64) << 32;
        st.st_mode = 0o100644;
        st.st_nlink = 1;
        st.st_size = get(&self.name, &self.guid).map_or(0, |(_, d)| d.len() as i64 + 4);
        st.st_blksize = 4096;
        st
    }
}

// wave11 GF begin: writes and deletes decided by linux-server (efivarfs is its tree)
/// `SYS_LX_OBJ` op `LX_INFO_EFIVAR_SET` (linux-server's host only: `lx::obj` checks): variable
/// file `name` (`name_len` bytes) set to the `len` bytes at `buf` (attributes, then the data,
/// as an efivarfs `write`); `len` 0 deletes it (gone already: 0). The pool's files are
/// written again afterwards. linux-server checked `CAP_SYS_ADMIN`.
pub fn set_for(name: u64, lens: u64, buf: u64) -> i64 {
    let (name_len, len) = ((lens & 0xFFFF_FFFF) as usize, (lens >> 32) as usize);
    if name_len == 0 || name_len > 512 || len > 1 << 20 || (len != 0 && len < 4) {
        return EINVAL;
    }
    let Ok(raw) = super::vfs::copy_in(name, name_len) else { return -14 };
    let Some((n, guid)) = core::str::from_utf8(&raw).ok().and_then(parse_name) else { return ENOENT };
    // (the firmware runs with the kernel's page tables: the data is copied into the kernel)
    let r = if len == 0 {
        match set(&n, &guid, 0, &[]) {
            Ok(()) | Err(ENOENT) => Ok(()),
            Err(e) => Err(e),
        }
    } else {
        let Ok(data) = super::vfs::copy_in(buf, len) else { return -14 };
        let attrs = u32::from_le_bytes(data[0..4].try_into().unwrap());
        set(&n, &guid, attrs, &data[4..])
    };
    refresh();
    match r {
        Ok(()) => 0,
        Err(e) => {
            crate::kprintln!("[efivars] SetVariable {} for linux-server ({} bytes): errno {}", n, len, -e);
            e
        }
    }
}
// wave11 GF end
