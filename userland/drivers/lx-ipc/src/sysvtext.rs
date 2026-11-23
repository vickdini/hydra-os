//! System V shared memory's plain parts (wave 10, Group 8-2): `/proc/sysvipc/*` lines in
//! Linux's format, `struct shmid64_ds` and `struct shm_info`, the limits, and the chunks of
//! the info call. No system calls: host-tested in `tests/host-w10-82`.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

/// Largest segment (as `/proc/sys/kernel/shmmax`).
pub const SHMMAX: u64 = 1 << 40;
/// Smallest segment.
pub const SHMMIN: u64 = 1;
/// Most segments (as `/proc/sys/kernel/shmmni`).
pub const SHMMNI: usize = 4096;
/// Most pages of all segments (as `/proc/sys/kernel/shmall`).
pub const SHMALL: u64 = SHMMAX >> 12;

/// `shm_perm.mode` bit: removed (`IPC_RMID`), gone once the last attachment is.
pub const SHM_DEST: u32 = 0o1000;
/// `shm_perm.mode` bit: `SHM_LOCK`ed.
pub const SHM_LOCKED: u32 = 0o2000;

/// What `/proc/sysvipc/*` and `IPC_STAT` show of one object's owner and rights.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ids {
    pub key: i32,
    pub id: i32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub cuid: u32,
    pub cgid: u32,
}

/// One segment, as the tables and the kernel's count show it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ShmView {
    pub ids: Ids,
    pub size: u64,
    pub cpid: u32,
    pub lpid: u32,
    pub nattch: u64,
    pub atime: i64,
    pub dtime: i64,
    pub ctime: i64,
}

/// `/proc/sysvipc/shm`'s first line (64-bit Linux).
pub const SHM_HEADER: &str = "       key      shmid perms                  size  cpid  lpid nattch   uid   gid  cuid  cgid      atime      dtime      ctime                   rss                  swap\n";
/// `/proc/sysvipc/sem`'s first line.
pub const SEM_HEADER: &str = "       key      semid perms      nsems   uid   gid  cuid  cgid      otime      ctime\n";
/// `/proc/sysvipc/msg`'s first line.
pub const MSG_HEADER: &str = "       key      msqid perms      cbytes       qnum lspid lrpid   uid   gid  cuid  cgid      stime      rtime      ctime\n";

/// The header of kind `kind` (0 shm, 1 sem, 2 msg).
pub fn header(kind: u64) -> &'static str {
    match kind {
        0 => SHM_HEADER,
        1 => SEM_HEADER,
        _ => MSG_HEADER,
    }
}

/// One `/proc/sysvipc/shm` line (`rss` in bytes; nothing is ever swapped).
pub fn shm_line(s: &ShmView, rss: u64) -> String {
    let i = &s.ids;
    let mut o = String::new();
    let _ = write!(
        o,
        "{:>10} {:>10}  {:>4o} {:>21} {:>5} {:>5}  {:>5} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10} {:>10} {:>21} {:>21}\n",
        i.key, i.id, i.mode & 0o7777, s.size, s.cpid, s.lpid, s.nattch, i.uid, i.gid, i.cuid, i.cgid, s.atime, s.dtime, s.ctime, rss, 0
    );
    o
}

/// One `/proc/sysvipc/sem` line.
pub fn sem_line(i: &Ids, nsems: u64, otime: i64, ctime: i64) -> String {
    let mut o = String::new();
    let _ = write!(o, "{:>10} {:>10}  {:>4o} {:>10} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10}\n", i.key, i.id, i.mode & 0o7777, nsems, i.uid, i.gid, i.cuid, i.cgid, otime, ctime);
    o
}

/// One `/proc/sysvipc/msg` line.
#[allow(clippy::too_many_arguments)]
pub fn msg_line(i: &Ids, cbytes: u64, qnum: u64, lspid: u32, lrpid: u32, stime: i64, rtime: i64, ctime: i64) -> String {
    let mut o = String::new();
    let _ = write!(
        o,
        "{:>10} {:>10}  {:>4o}  {:>10} {:>10} {:>5} {:>5} {:>5} {:>5} {:>5} {:>5} {:>10} {:>10} {:>10}\n",
        i.key, i.id, i.mode & 0o7777, cbytes, qnum, lspid, lrpid, i.uid, i.gid, i.cuid, i.cgid, stime, rtime, ctime
    );
    o
}

/// `struct ipc64_perm` (48 bytes).
pub fn perm_bytes(i: &Ids, seq: u16) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..4].copy_from_slice(&i.key.to_le_bytes());
    b[4..8].copy_from_slice(&i.uid.to_le_bytes());
    b[8..12].copy_from_slice(&i.gid.to_le_bytes());
    b[12..16].copy_from_slice(&i.cuid.to_le_bytes());
    b[16..20].copy_from_slice(&i.cgid.to_le_bytes());
    b[20..22].copy_from_slice(&(i.mode as u16).to_le_bytes());
    b[24..26].copy_from_slice(&seq.to_le_bytes());
    b
}

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// `struct shmid64_ds` (112 bytes) of `s` (`IPC_STAT`, `SHM_STAT`).
pub fn shmid_ds(s: &ShmView, seq: u16) -> [u8; 112] {
    let mut b = [0u8; 112];
    b[..48].copy_from_slice(&perm_bytes(&s.ids, seq));
    put(&mut b, 48, s.size);
    put(&mut b, 56, s.atime as u64);
    put(&mut b, 64, s.dtime as u64);
    put(&mut b, 72, s.ctime as u64);
    b[80..84].copy_from_slice(&s.cpid.to_le_bytes());
    b[84..88].copy_from_slice(&s.lpid.to_le_bytes());
    put(&mut b, 88, s.nattch);
    b
}

/// `struct shminfo64` (`IPC_INFO`, 40 bytes used): shmmax, shmmin, shmmni, shmseg, shmall.
pub fn shminfo() -> [u8; 40] {
    let mut b = [0u8; 40];
    for (i, v) in [SHMMAX, SHMMIN, SHMMNI as u64, SHMMNI as u64, SHMALL].into_iter().enumerate() {
        put(&mut b, i * 8, v);
    }
    b
}

/// `struct shm_info` (`SHM_INFO`, 48 bytes): used ids, total pages, resident pages, then
/// swap (0).
pub fn shm_info(used: usize, pages: u64, resident: u64) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..4].copy_from_slice(&(used as i32).to_le_bytes());
    put(&mut b, 8, pages);
    put(&mut b, 16, resident);
    b
}

/// Pages of a segment of `size` bytes.
pub fn pages(size: u64) -> u64 {
    size.div_ceil(4096)
}

/// The `shmget` size check of a new segment: `Err(EINVAL)` outside `SHMMIN..=SHMMAX`.
pub fn new_size_ok(size: u64) -> bool {
    (SHMMIN..=SHMMAX).contains(&size)
}

/// One chunk of the info call: from line `cursor` of `lines` (line 0 is the header), as
/// many whole lines as fit in `cap` bytes (at least one, cut if it alone is longer).
/// Returns the bytes and the next cursor (0: that was all).
pub fn chunk(lines: &[String], cursor: usize, cap: usize) -> (Vec<u8>, usize) {
    let mut out = Vec::new();
    let mut i = cursor;
    while i < lines.len() {
        let l = lines[i].as_bytes();
        if out.len() + l.len() > cap {
            if out.is_empty() {
                out.extend_from_slice(&l[..cap.min(l.len())]);
                i += 1;
            }
            break;
        }
        out.extend_from_slice(l);
        i += 1;
    }
    (out, if i >= lines.len() { 0 } else { i })
}
