//! Landlock's decisions on vfs-server's copy of a caller's domain (wave 9, Group 6b-3): the
//! kernel's `compat/linux/landlock.rs` rules (`refused`, `check_move`, the rights of an
//! open), on a domain the kernel serialized (`LX_FH_LANDLOCK`). Pure: unit-tested on the
//! host (`tests/host-w9-6b3`).

use alloc::vec::Vec;

/// Run a file.
pub const EXECUTE: u64 = 1 << 0;
/// Open a file for writing.
pub const WRITE_FILE: u64 = 1 << 1;
/// Open a file for reading.
pub const READ_FILE: u64 = 1 << 2;
/// Open a directory (list it).
pub const READ_DIR: u64 = 1 << 3;
/// Remove a directory.
pub const REMOVE_DIR: u64 = 1 << 4;
/// Remove a file.
pub const REMOVE_FILE: u64 = 1 << 5;
/// Make a character device.
pub const MAKE_CHAR: u64 = 1 << 6;
/// Make a directory.
pub const MAKE_DIR: u64 = 1 << 7;
/// Make a regular file.
pub const MAKE_REG: u64 = 1 << 8;
/// Make a socket.
pub const MAKE_SOCK: u64 = 1 << 9;
/// Make a FIFO.
pub const MAKE_FIFO: u64 = 1 << 10;
/// Make a block device.
pub const MAKE_BLOCK: u64 = 1 << 11;
/// Make a symbolic link.
pub const MAKE_SYM: u64 = 1 << 12;
/// Link or rename a file to another directory.
pub const REFER: u64 = 1 << 13;
/// Truncate a file.
pub const TRUNCATE: u64 = 1 << 14;

/// `EACCES`.
pub const EACCES: i64 = -13;
/// `EXDEV`.
pub const EXDEV: i64 = -18;

/// The most layers and rules a copy may have (the kernel's 16 layers; rules beyond this
/// make the copy unusable: the kernel answers).
const MAX_LAYERS: usize = 16;
const MAX_RULES: usize = 1 << 16;

/// One ruleset of a domain: the rights it handles, and its rules `(inode, rights)` sorted
/// by inode.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    /// The file-system rights the layer handles.
    pub fs: u64,
    /// `(inode, rights)`, sorted by inode, one per inode.
    pub rules: Vec<(u64, u64)>,
}

impl Layer {
    /// Rights this layer's rules grant on any of `chain`.
    pub fn granted(&self, chain: &[u64]) -> u64 {
        chain.iter().fold(0, |a, i| a | self.rules.binary_search_by_key(i, |r| r.0).map_or(0, |k| self.rules[k].1))
    }
}

/// A caller's domain: its layers, oldest first.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Domain {
    /// The kernel's id (`LxCall::ll_dom`).
    pub id: u64,
    /// The layers.
    pub layers: Vec<Layer>,
}

/// The domain in `b` (`LX_FH_LANDLOCK`'s format: `id`, `layers`, then per layer `fs`, `n`
/// and `n` pairs `(inode, rights)`, all little-endian `u64`); `None` if malformed.
pub fn parse(b: &[u8]) -> Option<Domain> {
    let mut at = 0usize;
    let mut next = || -> Option<u64> {
        let v = u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?);
        at += 8;
        Some(v)
    };
    let id = next()?;
    let n = next()? as usize;
    if n > MAX_LAYERS {
        return None;
    }
    let mut layers = Vec::with_capacity(n);
    for _ in 0..n {
        let fs = next()?;
        let k = next()? as usize;
        if k > MAX_RULES {
            return None;
        }
        let mut rules = Vec::with_capacity(k);
        for _ in 0..k {
            let ino = next()?;
            let r = next()?;
            rules.push((ino, r));
        }
        rules.sort_unstable_by_key(|r| r.0);
        // (the kernel's map has one entry per inode; merge any repeats)
        rules.dedup_by(|b, a| {
            if a.0 == b.0 {
                a.1 |= b.1;
                true
            } else {
                false
            }
        });
        layers.push(Layer { fs, rules });
    }
    drop(next);
    if at != b.len() {
        return None;
    }
    Some(Domain { id, layers })
}

/// Which of `want` some layer of `d` refuses on `chain` (the object, then the directories
/// above it).
pub fn refused(d: &Domain, chain: &[u64], want: u64) -> u64 {
    d.layers.iter().fold(0, |acc, l| {
        let need = want & l.fs;
        if need == 0 {
            acc
        } else {
            acc | (need & !l.granted(chain))
        }
    })
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

/// The rights an open of an existing object with `flags` needs (the kernel's
/// `vfs::open_rights` for an object the open did not create).
pub fn open_rights(flags: u32, is_dir: bool) -> u64 {
    const O_ACCMODE: u32 = 3;
    const O_RDONLY: u32 = 0;
    const O_WRONLY: u32 = 1;
    const O_TRUNC: u32 = 0o1000;
    if is_dir {
        return READ_DIR;
    }
    let acc = flags & O_ACCMODE;
    let mut r = 0;
    if acc != O_WRONLY {
        r |= READ_FILE;
    }
    if acc != O_RDONLY {
        r |= WRITE_FILE;
    }
    if flags & O_TRUNC != 0 {
        r |= TRUNCATE;
    }
    r
}

/// Checks moving (`remove_src`) or linking an entry of type `ftype` from the directory
/// with chain `schain` to the one with `dchain` (`same`: the same directory), replacing an
/// entry whose removal needs `remove_dst` (0 if none): `EACCES` for a refused make or
/// remove, `EXDEV` for a refused change of parent (the kernel's `check_move`).
pub fn check_move(d: &Domain, schain: &[u64], dchain: &[u64], same: bool, ftype: u32, remove_src: bool, remove_dst: u64) -> Result<(), i64> {
    if remove_src && refused(d, schain, remove_right(ftype)) != 0 {
        return Err(EACCES);
    }
    if refused(d, dchain, make_right(ftype) | remove_dst) != 0 {
        return Err(EACCES);
    }
    if same {
        return Ok(());
    }
    for l in &d.layers {
        if l.fs == 0 {
            continue;
        }
        let (gs, gd) = (l.granted(schain), l.granted(dchain));
        // REFER unhandled (ABI 1) is never granted; the new place must not add rights
        if l.fs & REFER == 0 || gs & gd & REFER == 0 || gd & !gs & l.fs & !REFER != 0 {
            return Err(EXDEV);
        }
    }
    Ok(())
}
