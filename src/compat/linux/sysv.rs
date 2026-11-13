//! # System V IPC: shared memory, semaphores, message queues
//!
//! - **Shared memory** (`shmget`, `shmat`, `shmdt`, `shmctl`): a segment is a [`MemFd`]
//!   object; `shmat` maps it shared into the caller, so every attached process sees the
//!   same physical pages. A segment lives until it is removed (`IPC_RMID`) and the last
//!   process has detached. Attachments are inherited by `fork` and dropped at exit and
//!   `execve`.
//! - **Semaphores** (`semget`, `semop`, `semtimedop`, `semctl`): the operations of one
//!   call apply all together or not at all; a call that cannot proceed waits (unless
//!   `IPC_NOWAIT`) and is woken by every change. `SEM_UNDO` adjustments are applied when
//!   the process exits.
//! - **Message queues** (`msgget`, `msgsnd`, `msgrcv`, `msgctl`): typed messages, the
//!   `msgrcv` type selection rules (`MSG_EXCEPT`, lowest type, `MSG_NOERROR`, `MSG_COPY`),
//!   a byte limit per queue.
//!
//! Keys and IDs belong to an IPC namespace ([`super::ns`]): a process in a new one sees
//! none of the others' objects. Access follows the objects' owner/group/other mode bits
//! (`CAP_IPC_OWNER` bypasses them).

use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use alloc::vec::Vec;
use spin::Mutex;

use super::memfd::MemFd;
use super::vfs::{copy_in, copy_out};
use crate::memory::vm::{Backing, MappedObject};
use crate::task::wait::WaitQueue;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const E2BIG: i64 = -7;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const ERANGE: i64 = -34;
const EFBIG: i64 = -27;
const ENOMSG: i64 = -42;
const EIDRM: i64 = -43;

const IPC_PRIVATE: i32 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
/// `cmd` flag for the 64-bit structure layouts (the only ones here).
const IPC_64: u64 = 0x100;

const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_EXEC: u64 = 0o100000;
const SHM_LOCK: u64 = 11;
const SHM_UNLOCK: u64 = 12;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const SHM_STAT_ANY: u64 = 15;
/// Largest segment.
const SHMMAX: u64 = 1 << 40;
/// Most segments.
const SHMMNI: usize = 4096;

const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const SEM_STAT_ANY: u64 = 20;
const SEM_UNDO: i16 = 0x1000;
/// Most semaphores per set, highest value, most operations per call, most sets.
const SEMMSL: u64 = 32000;
const SEMVMX: i32 = 32767;
const SEMOPM: u64 = 500;
const SEMMNI: usize = 32000;

const MSG_STAT: u64 = 11;
const MSG_INFO: u64 = 12;
const MSG_STAT_ANY: u64 = 13;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;
const MSG_COPY: u64 = 0o40000;
/// Largest message, default queue byte limit, most queues.
const MSGMAX: u64 = 8192;
const MSGMNB: u64 = 16384;
const MSGMNI: usize = 32000;

/// `CAP_IPC_OWNER`: bypasses the permission checks.
const CAP_IPC_OWNER: u64 = 1 << 15;

/// Owner and access rights of an object (`struct ipc64_perm`).
#[derive(Clone, Copy)]
struct Perm {
    key: i32,
    uid: u32,
    gid: u32,
    cuid: u32,
    cgid: u32,
    mode: u32,
    seq: u16,
}

/// A shared memory segment.
struct Shm {
    perm: Perm,
    size: u64,
    mem: Arc<Mutex<MemFd>>,
    atime: i64,
    dtime: i64,
    ctime: i64,
    cpid: u32,
    lpid: u32,
    nattch: u64,
    removed: bool,
}

/// One semaphore.
#[derive(Clone, Copy, Default)]
struct Sem {
    val: i32,
    pid: u32,
    ncnt: u32,
    zcnt: u32,
}

/// A semaphore set.
struct SemSet {
    perm: Perm,
    sems: Vec<Sem>,
    otime: i64,
    ctime: i64,
}

/// A message queue.
struct MsgQueue {
    perm: Perm,
    msgs: VecDeque<(i64, Vec<u8>)>,
    bytes: u64,
    qbytes: u64,
    stime: i64,
    rtime: i64,
    ctime: i64,
    lspid: u32,
    lrpid: u32,
}

/// The objects of every IPC namespace. IDs are unique across namespaces; each object
/// records its namespace.
struct Ipc {
    shm: BTreeMap<i32, (u64, Shm)>,
    sem: BTreeMap<i32, (u64, SemSet)>,
    msg: BTreeMap<i32, (u64, MsgQueue)>,
    next_seq: u16,
    /// Shared memory attachments: (process, address) -> segment ID.
    attach: BTreeMap<(u64, u64), i32>,
    /// `SEM_UNDO` adjustments: (process, set ID) -> per-semaphore adjustment.
    undo: BTreeMap<(u64, i32), Vec<i32>>,
}

static IPC: Mutex<Ipc> = Mutex::new(Ipc {
    shm: BTreeMap::new(),
    sem: BTreeMap::new(),
    msg: BTreeMap::new(),
    next_seq: 1,
    attach: BTreeMap::new(),
    undo: BTreeMap::new(),
});
/// Woken on every semaphore and message queue change (waiters re-check).
static CHANGED: WaitQueue = WaitQueue::new();

/// The caller's credentials, taken before the IPC lock (the scheduler's and the process
/// table's locks are never taken under it: process exit takes them in the other order).
struct Who {
    euid: u32,
    egid: u32,
    groups: Vec<u32>,
    privileged: bool,
}

/// The caller's process ID, credentials and IPC namespace.
fn caller() -> (u64, Who, u64) {
    let (_, pid) = super::proc::current_ids();
    let (euid, egid, privileged) =
        crate::task::with_current_task_mut(|t| (t.euid, t.egid, t.caps.has(CAP_IPC_OWNER))).unwrap_or((u32::MAX, u32::MAX, false));
    let groups = super::proc::PROCS.lock().get(&pid).map(|p| p.groups.clone()).unwrap_or_default();
    (pid, Who { euid, egid, groups, privileged }, super::ns::ipc_ns())
}

fn now() -> i64 {
    crate::arch::rtc::now().0 as i64
}

/// Whether the caller may access an object with `perm` for `want` (4 read, 2 write).
fn allowed(perm: &Perm, who: &Who, want: u32) -> bool {
    if who.privileged || want == 0 {
        return true;
    }
    let bits = if who.euid == perm.uid || who.euid == perm.cuid {
        perm.mode >> 6
    } else if who.egid == perm.gid || who.egid == perm.cgid || who.groups.contains(&perm.gid) {
        perm.mode >> 3
    } else {
        perm.mode
    } & 7;
    bits & want == want
}

/// Whether the caller owns or created an object (`IPC_SET`, `IPC_RMID`).
fn owner(perm: &Perm, who: &Who) -> bool {
    who.privileged || who.euid == perm.uid || who.euid == perm.cuid
}

/// `struct ipc64_perm` (48 bytes).
fn perm_bytes(p: &Perm) -> [u8; 48] {
    let mut b = [0u8; 48];
    b[0..4].copy_from_slice(&p.key.to_le_bytes());
    b[4..8].copy_from_slice(&p.uid.to_le_bytes());
    b[8..12].copy_from_slice(&p.gid.to_le_bytes());
    b[12..16].copy_from_slice(&p.cuid.to_le_bytes());
    b[16..20].copy_from_slice(&p.cgid.to_le_bytes());
    b[20..22].copy_from_slice(&(p.mode as u16).to_le_bytes());
    b[24..26].copy_from_slice(&p.seq.to_le_bytes());
    b
}

/// Applies the `uid`, `gid` and mode of a user `struct ipc64_perm` (`IPC_SET`).
fn set_perm(p: &mut Perm, raw: &[u8]) {
    p.uid = u32::from_le_bytes(raw[4..8].try_into().unwrap());
    p.gid = u32::from_le_bytes(raw[8..12].try_into().unwrap());
    p.mode = (p.mode & !0o777) | (u16::from_le_bytes([raw[20], raw[21]]) as u32 & 0o777);
}

fn put(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A new object ID: a sequence number in the high bits, the slot in the low 15, as Linux.
fn new_id<T>(map: &BTreeMap<i32, T>, seq: &mut u16, limit: usize) -> Option<(i32, u16)> {
    if map.len() >= limit {
        return None;
    }
    let s = *seq;
    *seq = seq.wrapping_add(1).max(1);
    let slot = (0..32768i32).find(|i| !map.keys().any(|k| k & 0x7fff == *i))?;
    Some(((s as i32 & 0xffff) << 15 | slot, s))
}

/// The `get` part shared by the three object kinds: finds `key` in namespace `ns`, or
/// tells the caller to create one. `Ok(Some(id))` for an existing object, `Ok(None)` to
/// create.
fn lookup<T>(map: &BTreeMap<i32, (u64, T)>, perm_of: impl Fn(&T) -> &Perm, key: i32, ns: u64, flags: u64, who: &Who) -> Result<Option<i32>, i64> {
    let want = wanted(flags);
    if key == IPC_PRIVATE {
        return Ok(None);
    }
    let found = map.iter().find(|(_, (n, o))| *n == ns && perm_of(o).key == key).map(|(id, _)| *id);
    match found {
        Some(_) if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 => Err(EEXIST),
        Some(id) => {
            if !allowed(perm_of(&map[&id].1), who, want) {
                return Err(EACCES);
            }
            Ok(Some(id))
        }
        None if flags & IPC_CREAT != 0 => Ok(None),
        None => Err(ENOENT),
    }
}

/// Access rights `flags` asks a `get` for: the read/write bits of its mode, for the owner.
fn wanted(flags: u64) -> u32 {
    ((flags >> 6) & 6) as u32
}

fn new_perm(key: i32, flags: u64, seq: u16, who: &Who) -> Perm {
    let (euid, egid) = (who.euid, who.egid);
    Perm { key, uid: euid, gid: egid, cuid: euid, cgid: egid, mode: (flags & 0o777) as u32, seq }
}

// ---------------------------------------------------------------------------------------
// Shared memory

fn shmget(key: i32, size: u64, flags: u64) -> i64 {
    let (pid, who, ns) = caller();
    let mut ipc = IPC.lock();
    match lookup(&ipc.shm, |s: &Shm| &s.perm, key, ns, flags, &who) {
        Err(e) => e,
        Ok(Some(id)) => {
            if size > ipc.shm[&id].1.size {
                return EINVAL;
            }
            id as i64
        }
        Ok(None) => {
            if size == 0 || size > SHMMAX {
                return EINVAL;
            }
            let ipc = &mut *ipc;
            let Some((id, seq)) = new_id(&ipc.shm, &mut ipc.next_seq, SHMMNI) else { return ENOSPC };
            let mem = MemFd::new("SYSV");
            let _ = mem.lock().truncate(size as usize); // size <= SHMMAX
            let shm = Shm { perm: new_perm(key, flags, seq, &who), size, mem, atime: 0, dtime: 0, ctime: now(), cpid: pid as u32, lpid: 0, nattch: 0, removed: false };
            ipc.shm.insert(id, (ns, shm));
            id as i64
        }
    }
}

fn shmat(id: i32, addr: u64, flags: u64) -> i64 {
    let (pid, who, ns) = caller();
    let want = if flags & SHM_RDONLY != 0 { 4 } else { 6 };
    let (mem, size) = {
        let ipc = IPC.lock();
        let Some((n, shm)) = ipc.shm.get(&id) else { return EINVAL };
        if *n != ns {
            return EINVAL;
        }
        if !allowed(&shm.perm, &who, want) {
            return EACCES;
        }
        (shm.mem.clone(), shm.size)
    };
    let addr = if flags & SHM_RND != 0 { addr & !0xfff } else { addr };
    if addr & 0xfff != 0 {
        return EINVAL;
    }
    let prot = if flags & SHM_RDONLY != 0 { 1 } else { 3 } | if flags & SHM_EXEC != 0 { 4 } else { 0 };
    let Some(mm) = super::mm::current_mm() else { return EINVAL };
    let obj: Arc<dyn MappedObject> = mem;
    let fixed = addr != 0;
    let noreplace = fixed && flags & SHM_REMAP == 0;
    let at = {
        let mut m = mm.lock();
        match m.mmap(addr, size, prot, true, fixed, noreplace, Backing::Object { obj, pgoff: 0 }) {
            Ok(a) => {
                // Read permission was all that was checked: mprotect may not add write
                // (Linux: no VM_MAYWRITE, EACCES)
                if flags & SHM_RDONLY != 0 {
                    m.deny_write(a, a + size);
                }
                a
            }
            Err(e) => return if e == -17 { EINVAL } else { e },
        }
    };
    let mut ipc = IPC.lock();
    match ipc.shm.get_mut(&id) {
        Some((_, shm)) => {
            shm.nattch += 1;
            shm.atime = now();
            shm.lpid = pid as u32;
        }
        None => {
            // Removed meanwhile: undo the mapping
            drop(ipc);
            mm.lock().unmap(at, at + ((size + 0xfff) & !0xfff));
            return EIDRM;
        }
    }
    ipc.attach.insert((pid, at), id);
    at as i64
}

/// Drops one attachment of segment `id`, deleting the segment if it was removed and this
/// was the last.
fn detach(ipc: &mut Ipc, id: i32, pid: u64) {
    let gone = match ipc.shm.get_mut(&id) {
        Some((_, shm)) => {
            shm.nattch = shm.nattch.saturating_sub(1);
            shm.dtime = now();
            shm.lpid = pid as u32;
            shm.removed && shm.nattch == 0
        }
        None => false,
    };
    if gone {
        ipc.shm.remove(&id);
    }
}

fn shmdt(addr: u64) -> i64 {
    let (pid, _who, _) = caller();
    let (id, size) = {
        let mut ipc = IPC.lock();
        let Some(id) = ipc.attach.remove(&(pid, addr)) else { return EINVAL };
        let size = ipc.shm.get(&id).map_or(0, |(_, s)| s.size);
        detach(&mut ipc, id, pid);
        (id, size)
    };
    let _ = id;
    if let Some(mm) = super::mm::current_mm() {
        mm.lock().unmap(addr, addr + ((size + 0xfff) & !0xfff));
    }
    0
}

fn shmctl(id: i32, cmd: u64, buf: u64) -> i64 {
    let (_, who, ns) = caller();
    let cmd = cmd & !IPC_64;
    let mut ipc = IPC.lock();
    match cmd {
        IPC_INFO => {
            // struct shminfo: shmmax, shmmin, shmmni, shmseg, shmall
            let mut b = [0u8; 40];
            for (i, v) in [SHMMAX, 1, SHMMNI as u64, SHMMNI as u64, SHMMAX >> 12].into_iter().enumerate() {
                put(&mut b, i * 8, v);
            }
            drop(ipc);
            return if copy_out(buf, &b).is_ok() { (SHMMNI - 1) as i64 } else { EFAULT };
        }
        SHM_INFO => {
            // struct shm_info: used_ids, shm_tot, shm_rss, shm_swp, swap_attempts, swap_successes
            let mine: Vec<&Shm> = ipc.shm.values().filter(|(n, _)| *n == ns).map(|(_, s)| s).collect();
            let pages: u64 = mine.iter().map(|s| (s.size + 0xfff) >> 12).sum();
            let mut b = [0u8; 48];
            b[0..4].copy_from_slice(&(mine.len() as i32).to_le_bytes());
            put(&mut b, 8, pages);
            put(&mut b, 16, pages);
            let max = ipc.shm.keys().map(|k| k & 0x7fff).max().unwrap_or(0);
            drop(ipc);
            return if copy_out(buf, &b).is_ok() { max as i64 } else { EFAULT };
        }
        _ => {}
    }
    // SHM_STAT takes a slot index instead of an ID
    let id = if matches!(cmd, SHM_STAT | SHM_STAT_ANY) {
        match ipc.shm.keys().find(|k| *k & 0x7fff == id) {
            Some(k) => *k,
            None => return EINVAL,
        }
    } else {
        id
    };
    let Some((n, shm)) = ipc.shm.get_mut(&id) else { return EINVAL };
    if *n != ns {
        return EINVAL;
    }
    match cmd {
        IPC_STAT | SHM_STAT | SHM_STAT_ANY => {
            if cmd != SHM_STAT_ANY && !allowed(&shm.perm, &who, 4) {
                return EACCES;
            }
            let mut b = [0u8; 112];
            b[..48].copy_from_slice(&perm_bytes(&shm.perm));
            put(&mut b, 48, shm.size);
            put(&mut b, 56, shm.atime as u64);
            put(&mut b, 64, shm.dtime as u64);
            put(&mut b, 72, shm.ctime as u64);
            b[80..84].copy_from_slice(&shm.cpid.to_le_bytes());
            b[84..88].copy_from_slice(&shm.lpid.to_le_bytes());
            put(&mut b, 88, shm.nattch);
            drop(ipc);
            if copy_out(buf, &b).is_err() {
                return EFAULT;
            }
            if cmd == IPC_STAT { 0 } else { id as i64 }
        }
        IPC_SET => {
            if !owner(&shm.perm, &who) {
                return EPERM;
            }
            let raw = match copy_in(buf, 48) {
                Ok(r) => r,
                Err(e) => return e,
            };
            set_perm(&mut shm.perm, &raw);
            shm.ctime = now();
            0
        }
        IPC_RMID => {
            if !owner(&shm.perm, &who) {
                return EPERM;
            }
            // No longer found by key; gone once the last process detaches
            shm.removed = true;
            shm.perm.key = IPC_PRIVATE;
            shm.perm.mode |= 0o1000; // SHM_DEST
            if shm.nattch == 0 {
                ipc.shm.remove(&id);
            }
            0
        }
        SHM_LOCK | SHM_UNLOCK => {
            if !owner(&shm.perm, &who) {
                return EPERM;
            }
            0 // nothing is ever swapped out
        }
        _ => EINVAL,
    }
}

// ---------------------------------------------------------------------------------------
// Semaphores

fn semget(key: i32, nsems: u64, flags: u64) -> i64 {
    let (_, who, ns) = caller();
    let mut ipc = IPC.lock();
    match lookup(&ipc.sem, |s: &SemSet| &s.perm, key, ns, flags, &who) {
        Err(e) => e,
        Ok(Some(id)) => {
            if nsems > ipc.sem[&id].1.sems.len() as u64 {
                return EINVAL;
            }
            id as i64
        }
        Ok(None) => {
            if nsems == 0 || nsems > SEMMSL {
                return EINVAL;
            }
            let ipc = &mut *ipc;
            let Some((id, seq)) = new_id(&ipc.sem, &mut ipc.next_seq, SEMMNI) else { return ENOSPC };
            let set = SemSet { perm: new_perm(key, flags, seq, &who), sems: alloc::vec![Sem::default(); nsems as usize], otime: 0, ctime: now() };
            ipc.sem.insert(id, (ns, set));
            id as i64
        }
    }
}

/// `semop`/`semtimedop`: applies all operations at once, waiting until they can be.
fn semop(id: i32, sops: u64, nsops: u64, timeout: u64) -> i64 {
    if nsops == 0 || nsops > SEMOPM {
        return if nsops == 0 { EINVAL } else { E2BIG };
    }
    let raw = match copy_in(sops, nsops as usize * 6) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let ops: Vec<(usize, i32, i16)> =
        raw.chunks(6).map(|c| (u16::from_le_bytes([c[0], c[1]]) as usize, i16::from_le_bytes([c[2], c[3]]) as i32, i16::from_le_bytes([c[4], c[5]]))).collect();
    let deadline = if timeout != 0 {
        let t = match copy_in(timeout, 16) {
            Ok(t) => t,
            Err(e) => return e,
        };
        let (s, ns) = (i64::from_le_bytes(t[0..8].try_into().unwrap()), i64::from_le_bytes(t[8..16].try_into().unwrap()));
        if s < 0 || !(0..1_000_000_000).contains(&ns) {
            return EINVAL;
        }
        let hz = crate::arch::pit::frequency_hz().max(1) as u128;
        Some(crate::arch::pit::ticks() + ((s as u128 * 1_000_000_000 + ns as u128) * hz).div_ceil(1_000_000_000) as u64)
    } else {
        None
    };
    let (pid, who, ns) = caller();
    let alters = ops.iter().any(|o| o.1 != 0);
    let mut counted: Option<(usize, bool)> = None;
    let result = loop {
        CHANGED.register();
        let mut guard = IPC.lock();
        let ipc = &mut *guard;
        let Some((n, set)) = ipc.sem.get_mut(&id) else { break EIDRM };
        if *n != ns {
            break EINVAL;
        }
        if counted.is_none() {
            if ops.iter().any(|o| o.0 >= set.sems.len()) {
                break EFBIG;
            }
            if !allowed(&set.perm, &who, if alters { 2 } else { 4 }) {
                break EACCES;
            }
        }
        // Try every operation on a copy: all or nothing
        let mut vals: Vec<i32> = set.sems.iter().map(|s| s.val).collect();
        let mut blocked: Option<(usize, bool, bool)> = None; // (sem, waiting for zero, nowait)
        let mut overflow = false;
        for &(num, op, flg) in &ops {
            let v = vals[num];
            if op > 0 {
                if v + op > SEMVMX {
                    overflow = true;
                    break;
                }
                vals[num] = v + op;
            } else if op == 0 {
                if v != 0 {
                    blocked = Some((num, true, flg as u64 & IPC_NOWAIT != 0));
                    break;
                }
            } else if v + op < 0 {
                blocked = Some((num, false, flg as u64 & IPC_NOWAIT != 0));
                break;
            } else {
                vals[num] = v + op;
            }
        }
        if overflow {
            break ERANGE;
        }
        // Stop counting this caller as a waiter while it looks again
        if let Some((num, zero)) = counted.take() {
            if let Some(s) = set.sems.get_mut(num) {
                if zero {
                    s.zcnt = s.zcnt.saturating_sub(1);
                } else {
                    s.ncnt = s.ncnt.saturating_sub(1);
                }
            }
        }
        match blocked {
            None => {
                for (i, s) in set.sems.iter_mut().enumerate() {
                    if s.val != vals[i] {
                        s.pid = pid as u32;
                    }
                    s.val = vals[i];
                }
                for &(num, _, _) in &ops {
                    set.sems[num].pid = pid as u32;
                }
                set.otime = now();
                let undo: Vec<(usize, i32)> = ops.iter().filter(|o| o.2 & SEM_UNDO != 0 && o.1 != 0).map(|o| (o.0, o.1)).collect();
                if !undo.is_empty() {
                    let len = set.sems.len();
                    let adj = ipc.undo.entry((pid, id)).or_insert_with(|| alloc::vec![0; len]);
                    for (num, op) in undo {
                        adj[num] -= op;
                    }
                }
                break 0;
            }
            Some((_, _, true)) => break EAGAIN,
            Some((num, zero, false)) => {
                if zero {
                    set.sems[num].zcnt += 1;
                } else {
                    set.sems[num].ncnt += 1;
                }
                counted = Some((num, zero));
            }
        }
        drop(guard);
        if deadline.is_some_and(|d| crate::arch::pit::ticks() >= d) {
            break EAGAIN;
        }
        if super::proc::signal_pending() {
            break EINTR;
        }
        crate::task::wait::wait(deadline);
    };
    CHANGED.unregister();
    if let Some((num, zero)) = counted {
        if let Some((_, set)) = IPC.lock().sem.get_mut(&id) {
            if let Some(s) = set.sems.get_mut(num) {
                if zero {
                    s.zcnt = s.zcnt.saturating_sub(1);
                } else {
                    s.ncnt = s.ncnt.saturating_sub(1);
                }
            }
        }
    }
    if result == 0 {
        CHANGED.wake_all();
    }
    result
}

fn semctl(id: i32, num: u64, cmd: u64, arg: u64) -> i64 {
    let (pid, who, ns) = caller();
    let cmd = cmd & !IPC_64;
    let mut ipc = IPC.lock();
    if matches!(cmd, IPC_INFO | SEM_INFO) {
        // struct seminfo: semmap semmni semmns semmnu semmsl semopm semume semusz semvmx semaem
        let (sets, sems) = ipc.sem.values().filter(|(n, _)| *n == ns).fold((0, 0), |a, (_, s)| (a.0 + 1, a.1 + s.sems.len() as i32));
        let vals: [i32; 10] = if cmd == SEM_INFO {
            [sets, SEMMNI as i32, sems, 0, SEMMSL as i32, SEMOPM as i32, 0, 0, SEMVMX, 0]
        } else {
            [0, SEMMNI as i32, i32::MAX, 0, SEMMSL as i32, SEMOPM as i32, 0, 0, SEMVMX, SEMVMX]
        };
        let b: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
        let max = ipc.sem.keys().map(|k| k & 0x7fff).max().unwrap_or(0);
        drop(ipc);
        return if copy_out(arg, &b).is_ok() { max as i64 } else { EFAULT };
    }
    let id = if matches!(cmd, SEM_STAT | SEM_STAT_ANY) {
        match ipc.sem.keys().find(|k| **k & 0x7fff == id) {
            Some(k) => *k,
            None => return EINVAL,
        }
    } else {
        id
    };
    let Some((n, set)) = ipc.sem.get_mut(&id) else { return EINVAL };
    if *n != ns {
        return EINVAL;
    }
    let nsems = set.sems.len();
    let read_ok = allowed(&set.perm, &who, 4);
    let write_ok = allowed(&set.perm, &who, 2);
    let sem = |num: u64| -> Result<usize, i64> { if (num as usize) < nsems { Ok(num as usize) } else { Err(EINVAL) } };
    let r = match cmd {
        IPC_STAT | SEM_STAT | SEM_STAT_ANY => {
            if cmd != SEM_STAT_ANY && !read_ok {
                return EACCES;
            }
            let mut b = [0u8; 104];
            b[..48].copy_from_slice(&perm_bytes(&set.perm));
            put(&mut b, 48, set.otime as u64);
            put(&mut b, 64, set.ctime as u64);
            put(&mut b, 80, nsems as u64);
            drop(ipc);
            if copy_out(arg, &b).is_err() {
                return EFAULT;
            }
            return if cmd == IPC_STAT { 0 } else { id as i64 };
        }
        IPC_SET => {
            if !owner(&set.perm, &who) {
                return EPERM;
            }
            let raw = match copy_in(arg, 48) {
                Ok(r) => r,
                Err(e) => return e,
            };
            set_perm(&mut set.perm, &raw);
            set.ctime = now();
            0
        }
        IPC_RMID => {
            if !owner(&set.perm, &who) {
                return EPERM;
            }
            ipc.sem.remove(&id);
            ipc.undo.retain(|k, _| k.1 != id);
            drop(ipc);
            CHANGED.wake_all(); // waiters get EIDRM
            return 0;
        }
        GETVAL | GETPID | GETNCNT | GETZCNT => {
            if !read_ok {
                return EACCES;
            }
            let s = match sem(num) {
                Ok(i) => set.sems[i],
                Err(e) => return e,
            };
            match cmd {
                GETVAL => s.val as i64,
                GETPID => s.pid as i64,
                GETNCNT => s.ncnt as i64,
                _ => s.zcnt as i64,
            }
        }
        GETALL => {
            if !read_ok {
                return EACCES;
            }
            let b: Vec<u8> = set.sems.iter().flat_map(|s| (s.val as u16).to_le_bytes()).collect();
            drop(ipc);
            return if copy_out(arg, &b).is_ok() { 0 } else { EFAULT };
        }
        SETVAL => {
            if !write_ok {
                return EACCES;
            }
            let i = match sem(num) {
                Ok(i) => i,
                Err(e) => return e,
            };
            let v = arg as i32;
            if !(0..=SEMVMX).contains(&v) {
                return ERANGE;
            }
            set.sems[i].val = v;
            set.sems[i].pid = pid as u32;
            set.ctime = now();
            // A set value cancels the undo adjustments for that semaphore
            for (k, adj) in ipc.undo.iter_mut() {
                if k.1 == id {
                    adj[i] = 0;
                }
            }
            0
        }
        SETALL => {
            if !write_ok {
                return EACCES;
            }
            let raw = match copy_in(arg, nsems * 2) {
                Ok(r) => r,
                Err(e) => return e,
            };
            let vals: Vec<i32> = raw.chunks(2).map(|c| u16::from_le_bytes([c[0], c[1]]) as i32).collect();
            if vals.iter().any(|v| *v > SEMVMX) {
                return ERANGE;
            }
            for (s, v) in set.sems.iter_mut().zip(vals) {
                s.val = v;
                s.pid = pid as u32;
            }
            set.ctime = now();
            ipc.undo.retain(|k, _| k.1 != id);
            0
        }
        _ => return EINVAL,
    };
    drop(ipc);
    if matches!(cmd, SETVAL | SETALL) {
        CHANGED.wake_all();
    }
    r
}

// ---------------------------------------------------------------------------------------
// Message queues

fn msgget(key: i32, flags: u64) -> i64 {
    let (_, who, ns) = caller();
    let mut ipc = IPC.lock();
    match lookup(&ipc.msg, |q: &MsgQueue| &q.perm, key, ns, flags, &who) {
        Err(e) => e,
        Ok(Some(id)) => id as i64,
        Ok(None) => {
            let ipc = &mut *ipc;
            let Some((id, seq)) = new_id(&ipc.msg, &mut ipc.next_seq, MSGMNI) else { return ENOSPC };
            let q = MsgQueue {
                perm: new_perm(key, flags, seq, &who),
                msgs: VecDeque::new(),
                bytes: 0,
                qbytes: MSGMNB,
                stime: 0,
                rtime: 0,
                ctime: now(),
                lspid: 0,
                lrpid: 0,
            };
            ipc.msg.insert(id, (ns, q));
            id as i64
        }
    }
}

fn msgsnd(id: i32, msgp: u64, size: u64, flags: u64) -> i64 {
    if size > MSGMAX {
        return EINVAL;
    }
    let raw = match copy_in(msgp, 8 + size as usize) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mtype = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    if mtype <= 0 {
        return EINVAL;
    }
    let (pid, who, ns) = caller();
    let r = loop {
        CHANGED.register();
        let mut ipc = IPC.lock();
        let Some((n, q)) = ipc.msg.get_mut(&id) else { break EIDRM };
        if *n != ns {
            break EINVAL;
        }
        if !allowed(&q.perm, &who, 2) {
            break EACCES;
        }
        // As Linux's msgsnd, msg_qbytes also bounds the number of messages: an empty one
        // still costs kernel memory
        if q.bytes + size <= q.qbytes && q.msgs.len() as u64 + 1 <= q.qbytes {
            q.msgs.push_back((mtype, raw[8..].to_vec()));
            q.bytes += size;
            q.stime = now();
            q.lspid = pid as u32;
            break 0;
        }
        drop(ipc);
        if flags & IPC_NOWAIT != 0 {
            break EAGAIN;
        }
        if super::proc::signal_pending() {
            break EINTR;
        }
        crate::task::wait::wait(None);
    };
    CHANGED.unregister();
    if r == 0 {
        CHANGED.wake_all();
    }
    r
}

/// Index of the message `msgrcv` takes for `msgtyp` and `flags`.
fn pick(msgs: &VecDeque<(i64, Vec<u8>)>, msgtyp: i64, flags: u64) -> Option<usize> {
    if flags & MSG_COPY != 0 {
        return (msgtyp >= 0 && (msgtyp as usize) < msgs.len()).then_some(msgtyp as usize);
    }
    match msgtyp {
        0 => (!msgs.is_empty()).then_some(0),
        t if t > 0 => msgs.iter().position(|m| if flags & MSG_EXCEPT != 0 { m.0 != t } else { m.0 == t }),
        t => {
            // The lowest type not above |t|, the oldest of those
            let limit = t.unsigned_abs() as i64;
            let best = msgs.iter().filter(|m| m.0 <= limit).map(|m| m.0).min()?;
            msgs.iter().position(|m| m.0 == best)
        }
    }
}

fn msgrcv(id: i32, msgp: u64, size: u64, msgtyp: i64, flags: u64) -> i64 {
    if (size as i64) < 0 {
        return EINVAL;
    }
    if flags & MSG_COPY != 0 && (flags & IPC_NOWAIT == 0 || flags & MSG_EXCEPT != 0) {
        return EINVAL;
    }
    let (pid, who, ns) = caller();
    let r = loop {
        CHANGED.register();
        let mut ipc = IPC.lock();
        let Some((n, q)) = ipc.msg.get_mut(&id) else { break Err(EIDRM) };
        if *n != ns {
            break Err(EINVAL);
        }
        if !allowed(&q.perm, &who, 4) {
            break Err(EACCES);
        }
        if let Some(i) = pick(&q.msgs, msgtyp, flags) {
            if q.msgs[i].1.len() as u64 > size && flags & MSG_NOERROR == 0 {
                break Err(E2BIG);
            }
            let (mtype, mut data) = if flags & MSG_COPY != 0 { q.msgs[i].clone() } else { q.msgs.remove(i).unwrap() };
            if flags & MSG_COPY == 0 {
                q.bytes -= data.len() as u64;
                q.rtime = now();
                q.lrpid = pid as u32;
            }
            data.truncate(size as usize);
            break Ok((mtype, data));
        }
        drop(ipc);
        if flags & IPC_NOWAIT != 0 {
            break Err(ENOMSG);
        }
        if super::proc::signal_pending() {
            break Err(EINTR);
        }
        crate::task::wait::wait(None);
    };
    CHANGED.unregister();
    match r {
        Ok((mtype, data)) => {
            CHANGED.wake_all(); // room for senders
            let mut out = mtype.to_le_bytes().to_vec();
            out.extend_from_slice(&data);
            if copy_out(msgp, &out).is_err() {
                return EFAULT;
            }
            data.len() as i64
        }
        Err(e) => e,
    }
}

fn msgctl(id: i32, cmd: u64, buf: u64) -> i64 {
    let (_, who, ns) = caller();
    // Raising a queue's limit beyond the default takes CAP_SYS_RESOURCE (asked before the
    // IPC lock: the scheduler's lock is never taken under it)
    let resource = crate::task::with_current_task_mut(|t| t.caps.has(1 << 24)).unwrap_or(false);
    let cmd = cmd & !IPC_64;
    let mut ipc = IPC.lock();
    if matches!(cmd, IPC_INFO | MSG_INFO) {
        // struct msginfo: msgpool msgmap msgmax msgmnb msgmni msgssz msgtql msgseg
        let (queues, msgs, bytes) =
            ipc.msg.values().filter(|(n, _)| *n == ns).fold((0i32, 0i32, 0i32), |a, (_, q)| (a.0 + 1, a.1 + q.msgs.len() as i32, a.2 + q.bytes as i32));
        let vals: [i32; 8] = if cmd == MSG_INFO {
            [queues, msgs, MSGMAX as i32, MSGMNB as i32, MSGMNI as i32, 16, bytes, 0xffff]
        } else {
            [(MSGMNI * MSGMNB as usize / 1024) as i32, 0, MSGMAX as i32, MSGMNB as i32, MSGMNI as i32, 16, i32::MAX, 0xffff]
        };
        let b: Vec<u8> = vals.iter().flat_map(|v| v.to_le_bytes()).collect();
        let max = ipc.msg.keys().map(|k| k & 0x7fff).max().unwrap_or(0);
        drop(ipc);
        return if copy_out(buf, &b).is_ok() { max as i64 } else { EFAULT };
    }
    let id = if matches!(cmd, MSG_STAT | MSG_STAT_ANY) {
        match ipc.msg.keys().find(|k| **k & 0x7fff == id) {
            Some(k) => *k,
            None => return EINVAL,
        }
    } else {
        id
    };
    let Some((n, q)) = ipc.msg.get_mut(&id) else { return EINVAL };
    if *n != ns {
        return EINVAL;
    }
    match cmd {
        IPC_STAT | MSG_STAT | MSG_STAT_ANY => {
            if cmd != MSG_STAT_ANY && !allowed(&q.perm, &who, 4) {
                return EACCES;
            }
            let mut b = [0u8; 120];
            b[..48].copy_from_slice(&perm_bytes(&q.perm));
            put(&mut b, 48, q.stime as u64);
            put(&mut b, 56, q.rtime as u64);
            put(&mut b, 64, q.ctime as u64);
            put(&mut b, 72, q.bytes);
            put(&mut b, 80, q.msgs.len() as u64);
            put(&mut b, 88, q.qbytes);
            b[96..100].copy_from_slice(&q.lspid.to_le_bytes());
            b[100..104].copy_from_slice(&q.lrpid.to_le_bytes());
            drop(ipc);
            if copy_out(buf, &b).is_err() {
                return EFAULT;
            }
            if cmd == IPC_STAT { 0 } else { id as i64 }
        }
        IPC_SET => {
            if !owner(&q.perm, &who) {
                return EPERM;
            }
            let raw = match copy_in(buf, 120) {
                Ok(r) => r,
                Err(e) => return e,
            };
            let qbytes = u64::from_le_bytes(raw[88..96].try_into().unwrap());
            if qbytes > MSGMNB && qbytes > q.qbytes && !resource {
                return EPERM;
            }
            set_perm(&mut q.perm, &raw);
            q.qbytes = qbytes;
            q.ctime = now();
            drop(ipc);
            CHANGED.wake_all();
            0
        }
        IPC_RMID => {
            if !owner(&q.perm, &who) {
                return EPERM;
            }
            ipc.msg.remove(&id);
            drop(ipc);
            CHANGED.wake_all(); // waiters get EIDRM
            0
        }
        _ => EINVAL,
    }
}

// ---------------------------------------------------------------------------------------
// Process lifecycle

/// A forked child inherits its parent's shared memory attachments (its address space is a
/// copy, mappings included).
///
/// # Arguments
/// * `parent` - Parent process ID.
/// * `child` - Child process ID.
pub fn on_fork(parent: u64, child: u64) {
    let mut ipc = IPC.lock();
    let inherited: Vec<(u64, i32)> = ipc.attach.iter().filter(|((p, _), _)| *p == parent).map(|((_, a), id)| (*a, *id)).collect();
    for (addr, id) in inherited {
        if let Some((_, shm)) = ipc.shm.get_mut(&id) {
            shm.nattch += 1;
            ipc.attach.insert((child, addr), id);
        }
    }
}

/// Drops a process's attachments (its address space is gone or replaced) and, at exit,
/// applies its `SEM_UNDO` adjustments.
///
/// # Arguments
/// * `pid` - Process ID.
/// * `exiting` - The process is exiting (not just replacing its image).
pub fn forget_process(pid: u64, exiting: bool) {
    let mut ipc = IPC.lock();
    let ipc = &mut *ipc;
    let mine: Vec<((u64, u64), i32)> = ipc.attach.iter().filter(|((p, _), _)| *p == pid).map(|(k, v)| (*k, *v)).collect();
    for (k, id) in mine {
        ipc.attach.remove(&k);
        detach(ipc, id, pid);
    }
    if !exiting {
        return;
    }
    let undos: Vec<((u64, i32), Vec<i32>)> = ipc.undo.iter().filter(|((p, _), _)| *p == pid).map(|(k, v)| (*k, v.clone())).collect();
    let mut changed = false;
    for (k, adj) in undos {
        ipc.undo.remove(&k);
        if let Some((_, set)) = ipc.sem.get_mut(&k.1) {
            for (s, a) in set.sems.iter_mut().zip(adj) {
                if a != 0 {
                    s.val = (s.val + a).clamp(0, SEMVMX);
                    s.pid = pid as u32;
                    changed = true;
                }
            }
        }
    }
    if changed {
        CHANGED.wake_all();
    }
}

/// Handles the System V IPC system calls.
///
/// # Arguments
/// * `num` - System call number.
/// * `a` - Argument registers.
///
/// # Returns
/// `Some(result)` for these calls, `None` otherwise.
pub fn dispatch(num: u64, a: [u64; 6]) -> Option<i64> {
    let id = a[0] as i32;
    Some(match num {
        29 => shmget(a[0] as i32, a[1], a[2]),
        30 => shmat(id, a[1], a[2]),
        31 => shmctl(id, a[1], a[2]),
        67 => shmdt(a[0]),
        64 => semget(a[0] as i32, a[1], a[2]),
        65 => semop(id, a[1], a[2], 0),
        66 => semctl(id, a[1], a[2], a[3]),
        220 => semop(id, a[1], a[2], a[3]),
        68 => msgget(a[0] as i32, a[1]),
        69 => msgsnd(id, a[1], a[2], a[3]),
        70 => msgrcv(id, a[1], a[2], a[3] as i64, a[4]),
        71 => msgctl(id, a[1], a[2]),
        _ => return None,
    })
}
