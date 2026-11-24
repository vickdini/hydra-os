//! # `/dev/pts` (devpts) served here (wave 10, Group V2)
//!
//! vfs-server walks `/dev` (a pool tree) and redirects a walk that reaches `<root>/dev/pts`
//! to this service at lookup (decision 19: the pseudo-terminal slaves are this service's
//! nodes): the same call arrives with `LxCall::svc` = `LXS_TTY`, `redir_obj` =
//! `LX_VFS_PSEUDO_DEVPTS` and `redir_tail` = where `pts` starts in the path argument.
//! Served: the `stat` family, `access`, `readlink`, `open` (as the kernel's `LX_TTY_K_OPEN`
//! of the slave's number), `chmod` and `chown` of the slaves (the node table's rules); the
//! numbers are the kernel's devpts ones (`st_dev` 0x18, slave `N` is inode `N + 3`, the
//! directory inode 1), as `fstat` of a slave reports them. [`parse`] is plain code
//! (host-tested in `tests/host-w10-v2`).

/// vfs-server's redirect object bit: the tail starts below `pts` (`calls/served.rs`).
pub const PTS_BELOW: u64 = 0x100;

/// `st_dev` of devpts (the kernel's `pty::PTS_DEV`).
pub const PTS_DEV: u64 = 0x18;

/// What a tail below the redirect names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pts {
    /// `/dev/pts` itself.
    Dir,
    /// Slave `/dev/pts/N`.
    Node(u32),
    /// `/dev/pts/ptmx` (review 5: Linux's devpts instance has one, mode 0, char 5:2).
    Ptmx,
    /// A name that cannot exist (`ENOENT`).
    Missing,
    /// A file named as a directory (`ENOTDIR`).
    NotDir,
    /// Not decided here (`..` leaving the directory: the kernel's walk).
    Kernel,
}

/// What `tail` (starting at `pts`) names.
pub fn parse(tail: &[u8]) -> Pts {
    let trailing = tail.last() == Some(&b'/');
    let comps: alloc::vec::Vec<&[u8]> = tail.split(|&b| b == b'/').filter(|c| !c.is_empty() && *c != b".").collect();
    if comps.first() != Some(&&b"pts"[..]) || comps.iter().any(|c| *c == b"..") {
        return Pts::Kernel;
    }
    match &comps[1..] {
        [] => Pts::Dir,
        [b"ptmx"] if !trailing => Pts::Ptmx,
        [n] => match number(n) {
            Some(_) if trailing => Pts::NotDir,
            Some(i) => Pts::Node(i),
            None => Pts::Missing,
        },
        [n, ..] => {
            if number(n).is_some() {
                Pts::NotDir
            } else {
                Pts::Missing
            }
        }
    }
}

/// A slave number as Linux names it (decimal, no leading zeros, below 2^20).
fn number(n: &[u8]) -> Option<u32> {
    if n.is_empty() || n.len() > 7 || (n.len() > 1 && n[0] == b'0') || !n.iter().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let v: u32 = core::str::from_utf8(n).ok()?.parse().ok()?;
    (v < 1 << 20).then_some(v)
}

/// The access bits `want` (`r` 4, `w` 2, `x` 1) of user `euid` (`in_group` for its groups)
/// on a node of `mode`, `uid`, `gid` (user 0: all but `x` without an `x` bit).
pub fn may(mode: u32, uid: u32, gid: u32, euid: u32, want: u32, in_group: &dyn Fn(u32) -> bool) -> bool {
    if euid == 0 {
        return want & 1 == 0 || mode & 0o111 != 0;
    }
    let bits = if euid == uid {
        (mode >> 6) & 7
    } else if in_group(gid) {
        (mode >> 3) & 7
    } else {
        mode & 7
    };
    bits & want == want
}

/// `struct stat` (144 bytes) of a devpts node: `ino`, `mode` (with type), owner, `rdev`.
pub fn stat_bytes(ino: u64, mode: u32, uid: u32, gid: u32, rdev: u64, nlink: u64) -> [u8; 144] {
    let mut b = [0u8; 144];
    b[0..8].copy_from_slice(&PTS_DEV.to_le_bytes());
    b[8..16].copy_from_slice(&ino.to_le_bytes());
    b[16..24].copy_from_slice(&nlink.to_le_bytes());
    b[24..28].copy_from_slice(&mode.to_le_bytes());
    b[28..32].copy_from_slice(&uid.to_le_bytes());
    b[32..36].copy_from_slice(&gid.to_le_bytes());
    b[40..48].copy_from_slice(&rdev.to_le_bytes());
    b[56..64].copy_from_slice(&1024u64.to_le_bytes());
    b
}

/// `struct statfs` (120 bytes) of devpts (the kernel's `statfs_out`: the type, block size
/// 1024, no counts).
pub fn statfs_bytes() -> [u8; 120] {
    let mut b = [0u8; 120];
    b[0..8].copy_from_slice(&0x1cd1u64.to_le_bytes());
    b[8..16].copy_from_slice(&1024u64.to_le_bytes());
    b[64..72].copy_from_slice(&255u64.to_le_bytes());
    b[72..80].copy_from_slice(&4096u64.to_le_bytes());
    b
}

/// `struct statx` (256 bytes) of a devpts node, as the kernel's `write_statx`.
pub fn statx_bytes(ino: u64, mode: u32, uid: u32, gid: u32, rdev: u64, nlink: u32) -> [u8; 256] {
    let mut b = [0u8; 256];
    let p32 = |b: &mut [u8; 256], o: usize, v: u32| b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    p32(&mut b, 0, 0x17FF);
    b[144..152].copy_from_slice(&(20 + (PTS_DEV & 0xFFFF)).to_le_bytes());
    p32(&mut b, 4, 1024);
    p32(&mut b, 16, nlink);
    p32(&mut b, 20, uid);
    p32(&mut b, 24, gid);
    b[28..30].copy_from_slice(&(mode as u16).to_le_bytes());
    b[32..40].copy_from_slice(&ino.to_le_bytes());
    p32(&mut b, 128, ((rdev >> 8) & 0xFFF) as u32);
    p32(&mut b, 132, (rdev & 0xFF) as u32);
    p32(&mut b, 136, ((PTS_DEV >> 8) & 0xFFF) as u32);
    p32(&mut b, 140, (PTS_DEV & 0xFF) as u32);
    b
}
