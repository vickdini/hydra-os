//! Landlock (ABI 4): unprivileged, stackable sandboxing of file system and TCP access.
//!
//! - **Rulesets**: `landlock_create_ruleset` returns a descriptor naming the rights a layer
//!   handles; `landlock_add_rule` grants some of them beneath a directory (or on a file) or
//!   on a TCP port.
//! - **Domains**: `landlock_restrict_self` stacks a snapshot of the ruleset onto the calling
//!   thread's domain (at most 16 layers). Children and new threads inherit it, `execve`
//!   keeps it, and nothing removes it.
//! - **Checks**: an access a layer handles must be granted by one of that layer's rules on
//!   the object or a directory above it. Rules sit on pool inodes; the walk upwards follows
//!   each directory's `..` in the pool. Moving or linking a file to another directory needs
//!   `REFER` on both sides and must not gain rights; a layer that does not handle `REFER`
//!   (ABI 1) never allows it. A landlocked thread cannot change mounts.
//! - **Exec** needs `EXECUTE` on the program, a script's interpreter and the dynamic loader.
//! - **Not covered**: device `ioctl` (ABI 5) and scoping (ABI 6) are not offered, so
//!   programs fall back as they would on Linux 6.7.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::copy_in;
use crate::fs::ZfsClient;
use crate::fs::FileDescriptor;
use crate::task::wait::WaitSet;

const EPERM: i64 = -1;
const E2BIG: i64 = -7;
const EBADF: i64 = -9;
const EMFILE: i64 = -24;
const EACCES: i64 = -13;
const EXDEV: i64 = -18;
const EINVAL: i64 = -22;
const ENOMSG: i64 = -42;
const EBADFD: i64 = -77;

/// The Landlock ABI version offered.
pub const ABI: i64 = 4;

/// `LANDLOCK_ACCESS_*`: Run a file.
pub const EXECUTE: u64 = 1 << 0;
/// `LANDLOCK_ACCESS_*`: Open a file for writing.
pub const WRITE_FILE: u64 = 1 << 1;
/// `LANDLOCK_ACCESS_*`: Open a file for reading.
pub const READ_FILE: u64 = 1 << 2;
/// `LANDLOCK_ACCESS_*`: Open a directory to list it.
pub const READ_DIR: u64 = 1 << 3;
/// `LANDLOCK_ACCESS_*`: Remove a directory.
pub const REMOVE_DIR: u64 = 1 << 4;
/// `LANDLOCK_ACCESS_*`: Remove a file.
pub const REMOVE_FILE: u64 = 1 << 5;
/// `LANDLOCK_ACCESS_*`: Make a character device.
pub const MAKE_CHAR: u64 = 1 << 6;
/// `LANDLOCK_ACCESS_*`: Make a directory.
pub const MAKE_DIR: u64 = 1 << 7;
/// `LANDLOCK_ACCESS_*`: Make a regular file.
pub const MAKE_REG: u64 = 1 << 8;
/// `LANDLOCK_ACCESS_*`: Make a Unix socket.
pub const MAKE_SOCK: u64 = 1 << 9;
/// `LANDLOCK_ACCESS_*`: Make a named pipe.
pub const MAKE_FIFO: u64 = 1 << 10;
/// `LANDLOCK_ACCESS_*`: Make a block device.
pub const MAKE_BLOCK: u64 = 1 << 11;
/// `LANDLOCK_ACCESS_*`: Make a symbolic link.
pub const MAKE_SYM: u64 = 1 << 12;
/// `LANDLOCK_ACCESS_*`: Link or move a file to another directory.
pub const REFER: u64 = 1 << 13;
/// `LANDLOCK_ACCESS_*`: Truncate a file.
pub const TRUNCATE: u64 = 1 << 14;
const FS_ALL: u64 = (1 << 15) - 1;
/// The rights a rule on a file (not a directory) may grant.
const FILE_ONLY: u64 = EXECUTE | WRITE_FILE | READ_FILE | TRUNCATE;

/// `LANDLOCK_ACCESS_*`: Bind a TCP socket to a port.
pub const BIND_TCP: u64 = 1;
/// `LANDLOCK_ACCESS_*`: Connect a TCP socket to a port.
pub const CONNECT_TCP: u64 = 2;
const NET_ALL: u64 = BIND_TCP | CONNECT_TCP;

const MAX_LAYERS: usize = 16;

/// One ruleset: the rights it handles and the rules granting them.
#[derive(Clone, Default)]
struct Layer {
    fs: u64,
    net: u64,
    paths: BTreeMap<u64, u64>,
    ports: BTreeMap<u16, u64>,
}

impl Layer {
    /// Rights this layer's rules grant on any of `chain`.
    fn granted(&self, chain: &[u64]) -> u64 {
        chain.iter().fold(0, |a, i| a | self.paths.get(i).copied().unwrap_or(0))
    }
}

/// A thread's stack of layers.
pub struct Domain {
    layers: Vec<Arc<Layer>>,
}

/// A ruleset descriptor.
pub struct Ruleset {
    layer: Mutex<Layer>,
}

impl CharDevice for Ruleset {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::from("anon_inode:[landlock-ruleset]")
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_landlock(&self) -> Option<&Ruleset> {
        Some(self)
    }
}

/// Set once any thread is landlocked: until then every check returns at once.
static ANY: AtomicBool = AtomicBool::new(false);

/// The calling thread's domain.
fn domain() -> Option<Arc<Domain>> {
    if !ANY.load(Ordering::Relaxed) {
        return None;
    }
    crate::task::with_current_task_mut(|t| t.seccomp.landlock.clone()).flatten()
}

/// Whether the calling thread is landlocked.
pub fn active() -> bool {
    domain().is_some()
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

/// `landlock_create_ruleset(attr, size, flags)`.
fn create_ruleset(attr: u64, size: u64, flags: u64) -> i64 {
    // LANDLOCK_CREATE_RULESET_VERSION
    if flags == 1 {
        return if attr == 0 && size == 0 { ABI } else { EINVAL };
    }
    if flags != 0 {
        return EINVAL;
    }
    if size < 8 {
        return EINVAL;
    }
    if size > 4096 {
        return E2BIG;
    }
    let raw = match copy_in(attr, size as usize) {
        Ok(r) => r,
        Err(e) => return e,
    };
    // Fields this ABI does not know must be zero (`scoped`, at offset 16, is ABI 6)
    if raw.len() > 16 && raw[16..].iter().any(|&b| b != 0) {
        return E2BIG;
    }
    let fs = u64_at(&raw, 0);
    let net = if raw.len() >= 16 { u64_at(&raw, 8) } else { 0 };
    if fs & !FS_ALL != 0 || net & !NET_ALL != 0 {
        return EINVAL;
    }
    if fs == 0 && net == 0 {
        return ENOMSG;
    }
    let rs: Arc<dyn CharDevice> = Arc::new(Ruleset { layer: Mutex::new(Layer { fs, net, ..Layer::default() }) });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(FileDescriptor::Device(rs)) {
        Ok(fd) => {
            fds.set_cloexec(fd, true);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

/// The ruleset behind descriptor `fd`.
fn ruleset_of(fd: u64) -> Result<Arc<dyn CharDevice>, i64> {
    let desc = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    match desc {
        Some(FileDescriptor::Device(d)) if d.as_landlock().is_some() => Ok(d),
        Some(_) => Err(EBADFD),
        None => Err(EBADF),
    }
}

/// `(inode, is a directory)` a rule on descriptor `fd` attaches to.
fn rule_target(fd: i32) -> Result<(u64, bool), i64> {
    let desc = crate::task::with_current_fds_mut(|fds| if fd < 0 { None } else { fds.get(fd as usize).cloned() });
    let ino = match desc {
        Some(FileDescriptor::Vnode(f)) => f.lock().ino,
        // A by-name file (/proc, /dev): the nearest directory in the pool
        Some(FileDescriptor::File { path, .. }) => return Ok((*lexical_chain(&path).first().ok_or(EBADFD)?, true)),
        Some(_) => return Err(EBADFD),
        None => return Err(EBADF),
    };
    let attr = ZfsClient::getattr(ino)?;
    Ok((ino, attr.is_dir()))
}

/// `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`.
fn add_rule(fd: u64, rule_type: u64, attr: u64, flags: u64) -> i64 {
    let r: Result<i64, i64> = (|| {
        if flags != 0 {
            return Err(EINVAL);
        }
        let rs = ruleset_of(fd)?;
        let rs = rs.as_landlock().unwrap();
        match rule_type {
            // LANDLOCK_RULE_PATH_BENEATH { u64 allowed_access; s32 parent_fd } (packed)
            1 => {
                let raw = copy_in(attr, 12)?;
                let allowed = u64_at(&raw, 0);
                let pfd = i32::from_le_bytes(raw[8..12].try_into().unwrap());
                if allowed == 0 {
                    return Err(ENOMSG);
                }
                let handled = rs.layer.lock().fs;
                if allowed & !handled != 0 {
                    return Err(EINVAL);
                }
                let (ino, is_dir) = rule_target(pfd)?;
                if !is_dir && allowed & !FILE_ONLY != 0 {
                    return Err(EINVAL);
                }
                *rs.layer.lock().paths.entry(ino).or_insert(0) |= allowed;
                Ok(0)
            }
            // LANDLOCK_RULE_NET_PORT { u64 allowed_access; u64 port }
            2 => {
                let raw = copy_in(attr, 16)?;
                let (allowed, port) = (u64_at(&raw, 0), u64_at(&raw, 8));
                if allowed == 0 {
                    return Err(ENOMSG);
                }
                let mut l = rs.layer.lock();
                if allowed & !l.net != 0 || port > 65535 {
                    return Err(EINVAL);
                }
                *l.ports.entry(port as u16).or_insert(0) |= allowed;
                Ok(0)
            }
            _ => Err(EINVAL),
        }
    })();
    r.unwrap_or_else(|e| e)
}

/// `landlock_restrict_self(ruleset_fd, flags)`.
fn restrict_self(fd: u64, flags: u64) -> i64 {
    if flags != 0 {
        return EINVAL;
    }
    // no_new_privs, or CAP_SYS_ADMIN
    let allowed = crate::task::with_current_task_mut(|t| t.seccomp.no_new_privs || t.caps.effective & (1 << 21) != 0).unwrap_or(false);
    if !allowed {
        return EPERM;
    }
    let rs = match ruleset_of(fd) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let layer = Arc::new(rs.as_landlock().unwrap().layer.lock().clone());
    ANY.store(true, Ordering::Relaxed);
    crate::task::with_current_task_mut(|t| {
        let mut layers = t.seccomp.landlock.as_ref().map(|d| d.layers.clone()).unwrap_or_default();
        if layers.len() >= MAX_LAYERS {
            return E2BIG;
        }
        layers.push(layer);
        t.seccomp.landlock = Some(Arc::new(Domain { layers }));
        0
    })
    .unwrap_or(EPERM)
}

/// System calls 444–446.
pub fn dispatch(num: u64, a: [u64; 6]) -> i64 {
    match num {
        444 => create_ruleset(a[0], a[1], a[2]),
        445 => add_rule(a[0], a[1], a[2], a[3]),
        _ => restrict_self(a[0], a[1]),
    }
}

/// Directory `dir` and every directory above it in the pool.
fn dir_chain(dir: u64) -> Vec<u64> {
    let mut v = vec![dir];
    let mut cur = dir;
    for _ in 0..256 {
        match ZfsClient::resolve(cur, b"..", false) {
            Ok(p) if p != cur => {
                v.push(p);
                cur = p;
            }
            _ => break,
        }
    }
    v
}

/// Splits an absolute path into its directory and last name.
fn split(abs: &str) -> (&str, &str) {
    match abs.rfind('/') {
        Some(0) => ("/", &abs[1..]),
        Some(i) => (&abs[..i], &abs[i + 1..]),
        None => ("/", abs),
    }
}

/// The nearest existing directory at or above `abs` (process view) and those above it,
/// for objects outside the pool (/proc, /dev files).
fn lexical_chain(abs: &str) -> Vec<u64> {
    let mut p = String::from(abs);
    loop {
        if let Ok(ino) = super::vfs::resolve(0, p.as_bytes(), true) {
            if ZfsClient::getattr(ino).map(|a| a.is_dir()).unwrap_or(false) {
                return dir_chain(ino);
            }
        }
        if p == "/" || p.is_empty() {
            return Vec::new();
        }
        p = String::from(split(&p).0);
    }
}

/// File `ino`, reached by absolute path `abs` (process view), and the directories above it.
/// A followed symbolic link is chased to where the file really sits, as far as the path
/// walker goes (`SYMLOOP_MAX` links). Past that the walker gave up (`ELOOP`), and only the
/// file's own rules count: never the rights of the directory of the last link reached.
fn file_chain(abs: &str, ino: u64, follow: bool) -> Vec<u64> {
    const SYMLOOP_MAX: usize = 40;
    let mut abs = String::from(abs);
    for hop in 0..=SYMLOOP_MAX {
        let (dir, name) = split(&abs);
        let d = match super::vfs::resolve(0, dir.as_bytes(), true) {
            Ok(d) => d,
            Err(_) => break,
        };
        if follow {
            if let Ok(i) = super::vfs::resolve(d, name.as_bytes(), false) {
                if i != ino {
                    if let Ok(t) = ZfsClient::readlink(i) {
                        if hop == SYMLOOP_MAX {
                            return vec![ino];
                        }
                        abs = super::vfs::join_path(dir, &t);
                        continue;
                    }
                }
            }
        }
        let mut v = vec![ino];
        v.extend(dir_chain(d));
        return v;
    }
    let mut v = vec![ino];
    v.extend(lexical_chain(split(&abs).0));
    v
}

/// Which of `want` some layer of `d` refuses on `chain`.
fn refused(d: &Domain, chain: &[u64], want: u64) -> u64 {
    d.layers.iter().fold(0, |acc, l| {
        let need = want & l.fs;
        if need == 0 {
            acc
        } else {
            acc | (need & !l.granted(chain))
        }
    })
}

/// Which of `want` are refused on the object at `abs` (inode `ino`; 0 for one outside the
/// pool). Empty when the thread is not landlocked.
pub fn refused_at(abs: &str, ino: u64, is_dir: bool, follow: bool, want: u64) -> u64 {
    let Some(d) = domain() else { return 0 };
    let chain = if ino == 0 {
        lexical_chain(abs)
    } else if is_dir {
        dir_chain(ino)
    } else {
        file_chain(abs, ino, follow)
    };
    refused(&d, &chain, want)
}

/// Checks `want` on the object at `abs` (see [`refused_at`]): `EACCES` when refused.
pub fn check_at(abs: &str, ino: u64, is_dir: bool, follow: bool, want: u64) -> Result<(), i64> {
    if refused_at(abs, ino, is_dir, follow, want) != 0 {
        Err(EACCES)
    } else {
        Ok(())
    }
}

/// Checks creating or removing an entry in directory `dir`: `EACCES` when refused.
pub fn check_dir(dir: u64, want: u64) -> Result<(), i64> {
    let Some(d) = domain() else { return Ok(()) };
    if refused(&d, &dir_chain(dir), want) != 0 {
        Err(EACCES)
    } else {
        Ok(())
    }
}

/// The right to make an entry of file type `ftype` (`S_IFMT` bits).
pub fn make_right(ftype: u32) -> u64 {
    match ftype {
        0o040000 => MAKE_DIR,
        0o120000 => MAKE_SYM,
        0o140000 => MAKE_SOCK,
        0o010000 => MAKE_FIFO,
        0o020000 => MAKE_CHAR,
        0o060000 => MAKE_BLOCK,
        _ => MAKE_REG,
    }
}

/// The right to remove an entry of file type `ftype`.
pub fn remove_right(ftype: u32) -> u64 {
    if ftype == 0o040000 {
        REMOVE_DIR
    } else {
        REMOVE_FILE
    }
}

/// Checks moving (`remove_src` set) or linking an entry of type `ftype` from directory
/// `sdir` to `ddir`, replacing an entry whose removal needs `remove_dst` (0 if none).
/// `EACCES` for a refused make or remove, `EXDEV` for a refused change of parent.
pub fn check_move(sdir: u64, ddir: u64, ftype: u32, remove_src: bool, remove_dst: u64) -> Result<(), i64> {
    let Some(d) = domain() else { return Ok(()) };
    let schain = dir_chain(sdir);
    let dchain = if sdir == ddir { schain.clone() } else { dir_chain(ddir) };
    if remove_src && refused(&d, &schain, remove_right(ftype)) != 0 {
        return Err(EACCES);
    }
    if refused(&d, &dchain, make_right(ftype) | remove_dst) != 0 {
        return Err(EACCES);
    }
    if sdir == ddir {
        return Ok(());
    }
    for l in &d.layers {
        if l.fs == 0 {
            continue;
        }
        let (gs, gd) = (l.granted(&schain), l.granted(&dchain));
        // REFER unhandled (ABI 1) is never granted; the new place must not add rights
        if l.fs & REFER == 0 || gs & gd & REFER == 0 || gd & !gs & l.fs & !REFER != 0 {
            return Err(EXDEV);
        }
    }
    Ok(())
}

/// Checks a TCP `bind` or `connect` (`want`) to `port`: `EACCES` when refused.
pub fn check_port(port: u16, want: u64) -> Result<(), i64> {
    let Some(d) = domain() else { return Ok(()) };
    for l in &d.layers {
        let need = want & l.net;
        if need != 0 && need & !l.ports.get(&port).copied().unwrap_or(0) != 0 {
            return Err(EACCES);
        }
    }
    Ok(())
}

/// Mount changes: refused (`EPERM`) to a landlocked thread.
pub fn check_mount() -> Result<(), i64> {
    if active() {
        Err(EPERM)
    } else {
        Ok(())
    }
}
