//! # FreeBSD personality: temporary in-kernel translations (wave 12, Group FK)
//!
//! **Everything in this file is temporary** (decision 39): the layouts belong to the services
//! that own the objects, keyed by `LxCall.pers`, and move there in wave 12's stage 2. They are
//! here only because milestone 3 (the dynamic `/bin/echo` through rtld) needs them first:
//!
//! - `struct stat` for `fstat`/`fstatat` ([`stat_from_linux`]):
//!   // wave12 FK temporary: moves to vfs-server in stage 2
//! - `struct dirent` for `getdirentries` ([`dirents_from_linux`]):
//!   // wave12 FK temporary: moves to vfs-server in stage 2
//! - `struct statfs` for `fstatfs` ([`statfs_from_linux`]):
//!   // wave12 FK temporary: moves to vfs-server in stage 2
//! - the few `sysctl` names libc, libthr and rtld ask for ([`sysctl_oid`], [`sysctl_name`]):
//!   // wave12 FK temporary: moves to lx-proc in stage 2
//!
//! Pure (no kernel state): the host unit tests compile it as it is (`tests/host-w12-fk`).

use super::fbsd_xlat::dev_to_fbsd;

// ----------------------------------------------------------------------
// struct stat
// ----------------------------------------------------------------------

/// `sizeof(struct stat)` on FreeBSD/amd64 (FreeBSD 12 and later: 64-bit inode numbers).
pub const FBSD_STAT: usize = 224;
/// `sizeof(struct stat)` on Linux/x86_64.
pub const LINUX_STAT: usize = 144;

/// A Linux `struct stat` (144 bytes) as FreeBSD's (224): `st_dev, st_ino, st_nlink` (64-bit),
/// `st_mode` (16-bit), `st_bsdflags`, `st_uid, st_gid`, `st_rdev` (FreeBSD's encoding), the
/// four times (birth time = change time), `st_size, st_blocks, st_blksize, st_flags, st_gen`.
// wave12 FK temporary: moves to vfs-server in stage 2
pub fn stat_from_linux(l: &[u8]) -> [u8; FBSD_STAT] {
    let u64_at = |o: usize| u64::from_le_bytes(l[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(l[o..o + 4].try_into().unwrap());
    let mut b = [0u8; FBSD_STAT];
    let mut put = |o: usize, v: &[u8]| b[o..o + v.len()].copy_from_slice(v);
    put(0, &dev_to_fbsd(u64_at(0)).to_le_bytes()); // st_dev
    put(8, &u64_at(8).to_le_bytes()); // st_ino
    put(16, &u64_at(16).to_le_bytes()); // st_nlink
    put(24, &(u32_at(24) as u16).to_le_bytes()); // st_mode
    put(28, &u32_at(28).to_le_bytes()); // st_uid
    put(32, &u32_at(32).to_le_bytes()); // st_gid
    put(40, &dev_to_fbsd(u64_at(40)).to_le_bytes()); // st_rdev
    // st_atim 48, st_mtim 64, st_ctim 80, st_birthtim 96 (Linux: 72, 88, 104)
    for (i, lo) in [72usize, 88, 104].iter().enumerate() {
        put(48 + i * 16, &l[*lo..*lo + 16]);
    }
    put(96, &l[104..120]);
    put(112, &u64_at(48).to_le_bytes()); // st_size
    put(120, &u64_at(64).to_le_bytes()); // st_blocks
    put(128, &(u64_at(56) as u32).to_le_bytes()); // st_blksize
    b
}

// ----------------------------------------------------------------------
// struct dirent
// ----------------------------------------------------------------------

/// The FreeBSD `struct dirent` size of a name of `namlen` bytes (`_GENERIC_DIRSIZ`).
pub fn fbsd_dirsiz(namlen: usize) -> usize {
    (24 + namlen + 1 + 7) & !7
}

/// How many bytes of Linux `linux_dirent64` records to ask for so that their FreeBSD form
/// fits in `nbytes` (a FreeBSD record is at most 8 bytes longer than Linux's, and both are
/// at least 24 bytes long, so 3/4 always fits).
pub fn linux_dirent_budget(nbytes: usize) -> usize {
    (nbytes / 4 * 3) & !7
}

/// Linux `linux_dirent64` records (`d_ino, d_off, d_reclen, d_type, d_name`) to FreeBSD
/// `struct dirent`s (`d_fileno, d_off, d_reclen, d_type, d_pad0, d_namlen, d_pad1,
/// d_name`), appended to `out`; stops at a record that would not fit in `cap` bytes of
/// output and answers `(bytes of input used, d_off of the last record taken)`.
// wave12 FK temporary: moves to vfs-server in stage 2
pub fn dirents_from_linux(l: &[u8], out: &mut alloc_vec::Vec<u8>, cap: usize) -> (usize, Option<u64>) {
    let mut p = 0;
    let mut last = None;
    while p + 19 <= l.len() {
        let reclen = u16::from_le_bytes([l[p + 16], l[p + 17]]) as usize;
        if reclen < 20 || p + reclen > l.len() {
            break;
        }
        let ino = &l[p..p + 8];
        let off = u64::from_le_bytes(l[p + 8..p + 16].try_into().unwrap());
        let ty = l[p + 18];
        let name = &l[p + 19..p + reclen];
        let namlen = name.iter().position(|&c| c == 0).unwrap_or(name.len()).min(255);
        let size = fbsd_dirsiz(namlen);
        if out.len() + size > cap {
            break;
        }
        let at = out.len();
        out.resize(at + size, 0);
        out[at..at + 8].copy_from_slice(ino);
        out[at + 8..at + 16].copy_from_slice(&off.to_le_bytes());
        out[at + 16..at + 18].copy_from_slice(&(size as u16).to_le_bytes());
        out[at + 18] = ty;
        out[at + 20..at + 22].copy_from_slice(&(namlen as u16).to_le_bytes());
        out[at + 24..at + 24 + namlen].copy_from_slice(&name[..namlen]);
        p += reclen;
        last = Some(off);
    }
    (p, last)
}

/// `Vec` for the host build and the kernel alike.
pub mod alloc_vec {
    extern crate alloc;
    pub use alloc::vec::Vec;
}

// ----------------------------------------------------------------------
// struct statfs
// ----------------------------------------------------------------------

/// `sizeof(struct statfs)` on FreeBSD (`STATFS_VERSION` 0x20140518).
pub const FBSD_STATFS: usize = 2344;
/// `sizeof(struct statfs)` on Linux/x86_64.
pub const LINUX_STATFS: usize = 120;

/// A file system's FreeBSD type name from Linux's magic number.
pub fn fstypename(magic: u64) -> &'static [u8] {
    match magic {
        0x2fc1_2fc1 => b"zfs",
        0x0102_1994 => b"tmpfs",
        0x9fa0 => b"procfs",
        0x6265_6572 => b"sysfs",
        0x1cd1 => b"devpts",
        0x6573_5546 => b"fusefs",
        0xEF53 => b"ext2fs",
        _ => b"unknown",
    }
}

/// A Linux `struct statfs` (120 bytes) as FreeBSD's (2,344): sizes, counts, `f_fsid`,
/// `f_namemax`, the type name, and `f_flags` (`ST_RDONLY` -> `MNT_RDONLY` 1, `ST_NOSUID` ->
/// `MNT_NOSUID` 8, `ST_NOEXEC` -> `MNT_NOEXEC` 4, `ST_NODEV` 4 -> -, `ST_SYNCHRONOUS` 16 ->
/// `MNT_SYNCHRONOUS` 2, `ST_NOATIME` 1024 -> `MNT_NOATIME` 0x10000000). The mount names
/// are left empty (the mount table is the file service's).
// wave12 FK temporary: moves to vfs-server in stage 2
pub fn statfs_from_linux(l: &[u8], out: &mut [u8]) {
    let u64_at = |o: usize| u64::from_le_bytes(l[o..o + 8].try_into().unwrap());
    out[..FBSD_STATFS].fill(0);
    let put = |out: &mut [u8], o: usize, v: &[u8]| out[o..o + v.len()].copy_from_slice(v);
    let magic = u64_at(0);
    let bsize = u64_at(8);
    let frsize = if u64_at(72) != 0 { u64_at(72) } else { bsize };
    let lf = u64_at(80);
    let mut f = 0u64;
    for (l, b) in [(1u64, 1u64), (2, 8), (8, 4), (16, 2), (1024, 0x1000_0000)] {
        if lf & l != 0 {
            f |= b;
        }
    }
    f |= 0x1000; // MNT_LOCAL
    put(out, 0, &0x2014_0518u32.to_le_bytes()); // f_version
    put(out, 4, &(magic as u32).to_le_bytes()); // f_type
    put(out, 8, &f.to_le_bytes());
    put(out, 16, &frsize.to_le_bytes()); // f_bsize (fragment size)
    put(out, 24, &bsize.to_le_bytes()); // f_iosize
    put(out, 32, &u64_at(16).to_le_bytes()); // f_blocks
    put(out, 40, &u64_at(24).to_le_bytes()); // f_bfree
    put(out, 48, &u64_at(32).to_le_bytes()); // f_bavail
    put(out, 56, &u64_at(40).to_le_bytes()); // f_files
    put(out, 64, &u64_at(48).to_le_bytes()); // f_ffree
    put(out, 184, &(u64_at(64) as u32).to_le_bytes()); // f_namemax
    put(out, 192, &l[56..64]); // f_fsid
    put(out, 280, fstypename(magic));
}

// ----------------------------------------------------------------------
// sysctl: the few names libc, libthr and rtld ask for
// ----------------------------------------------------------------------

/// The `sysctl` nodes answered before lx-proc has the tree (stage 2).
// wave12 FK temporary: moves to lx-proc in stage 2
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Node {
    /// `kern.ostype` ("FreeBSD").
    Ostype,
    /// `kern.osrelease`.
    Osrelease,
    /// `kern.osrevision`.
    Osrevision,
    /// `kern.version`.
    Version,
    /// `kern.hostname`.
    Hostname,
    /// `kern.osreldate`.
    Osreldate,
    /// `kern.usrstack`.
    Usrstack,
    /// `kern.arandom` (random bytes, up to 256).
    Arandom,
    /// `kern.argmax`.
    Argmax,
    /// `kern.ngroups`.
    Ngroups,
    /// `hw.machine`, `hw.machine_arch` ("amd64").
    Machine,
    /// `hw.ncpu`, `kern.smp.cpus`.
    Ncpu,
    /// `kern.smp.maxid`.
    Maxid,
    /// `hw.pagesize`.
    Pagesize,
    /// `hw.pagesizes`.
    Pagesizes,
    /// `vm.overcommit`.
    Overcommit,
    /// `kern.sched.cpusetsize`.
    Cpusetsize,
    /// `kern.sched.cpusetsizemin`.
    Cpusetsizemin,
    /// `kern.proc.osrel.<pid>` (read: the release date; a write is accepted and ignored).
    ProcOsrel,
    /// `hw.physmem`.
    Physmem,
}

/// The nodes by name, with the OID FreeBSD gives them (dynamic nodes get numbers from
/// 0x1000 on, which `sysctlnametomib` hands out and [`sysctl_oid`] takes back).
// wave12 FK temporary: moves to lx-proc in stage 2
pub const NODES: &[(&str, &[u32], Node)] = &[
    ("kern.ostype", &[1, 1], Node::Ostype),
    ("kern.osrelease", &[1, 2], Node::Osrelease),
    ("kern.osrevision", &[1, 3], Node::Osrevision),
    ("kern.version", &[1, 4], Node::Version),
    ("kern.argmax", &[1, 8], Node::Argmax),
    ("kern.hostname", &[1, 10], Node::Hostname),
    ("kern.ngroups", &[1, 18], Node::Ngroups),
    ("kern.osreldate", &[1, 24], Node::Osreldate),
    ("kern.usrstack", &[1, 33], Node::Usrstack),
    ("kern.arandom", &[1, 37], Node::Arandom),
    ("hw.machine", &[6, 1], Node::Machine),
    ("hw.ncpu", &[6, 3], Node::Ncpu),
    ("hw.physmem", &[6, 5], Node::Physmem),
    ("hw.pagesize", &[6, 7], Node::Pagesize),
    ("hw.machine_arch", &[6, 11], Node::Machine),
    ("vm.overcommit", &[2, 12], Node::Overcommit),
    ("hw.pagesizes", &[6, 0x1000], Node::Pagesizes),
    ("kern.smp.cpus", &[1, 0x1001, 1], Node::Ncpu),
    ("kern.smp.maxid", &[1, 0x1001, 2], Node::Maxid),
    ("kern.sched.cpusetsize", &[1, 0x1002, 1], Node::Cpusetsize),
    ("kern.sched.cpusetsizemin", &[1, 0x1002, 2], Node::Cpusetsizemin),
];

/// `{CTL_KERN, KERN_PROC, KERN_PROC_OSREL, pid}`.
const PROC_OSREL: [u32; 3] = [1, 14, 40];

/// The node of OID `oid`.
pub fn sysctl_oid(oid: &[u32]) -> Option<Node> {
    if oid.len() == 4 && oid[..3] == PROC_OSREL {
        return Some(Node::ProcOsrel);
    }
    NODES.iter().find(|n| n.1 == oid).map(|n| n.2)
}

/// The node and OID of name `name` (`sysctlbyname`, the name-to-OID meta node `{0, 3}`).
pub fn sysctl_name(name: &[u8]) -> Option<(&'static [u32], Node)> {
    let name = name.split(|&c| c == 0).next().unwrap_or(&[]);
    NODES.iter().find(|n| n.0.as_bytes() == name).map(|n| (n.1, n.2))
}

/// What a read of a node answers when it is a constant.
pub fn sysctl_const(n: Node) -> Option<&'static [u8]> {
    Some(match n {
        Node::Ostype => b"FreeBSD\0",
        Node::Osrelease => b"15.1-RELEASE\0",
        Node::Version => b"FreeBSD 15.1-RELEASE Hydra\0",
        Node::Machine => b"amd64\0",
        _ => return None,
    })
}

/// The `sysctl` answer convention: a value of `len` bytes into a buffer of `cap` bytes
/// (`None`: no buffer, only the size asked for). Answers `(bytes to copy, ENOMEM)`: a too
/// small buffer gets what fits and `ENOMEM`.
pub fn sysctl_fit(len: usize, cap: Option<usize>) -> (usize, bool) {
    match cap {
        None => (0, false),
        Some(c) if c < len => (c, true),
        Some(_) => (len, false),
    }
}
