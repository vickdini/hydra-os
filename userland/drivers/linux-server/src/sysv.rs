//! System V message queues and semaphores, moved here from the kernel's
//! `src/compat/linux/sysv.rs` (wave 4, step 2). Shared memory (`shm*`) stays in the kernel
//! until step 8: it is memory mapping.
//!
//! Objects are per IPC namespace (the call carries the caller's: `LxCall::ipc_ns`); IDs are
//! Linux's (a sequence number above the slot in the low 15 bits).
//!
//! **Blocking without tying up a worker:** a `semop` that cannot proceed, a `msgsnd` to a
//! full queue and a `msgrcv` with no matching message answer "pending"; the waiter is kept
//! with its operation. Every change to a set or queue (an operation, `SETVAL`/`SETALL`,
//! `IPC_SET`, `IPC_RMID`, a process's `SEM_UNDO` adjustments at exit) retries its waiters in
//! order and completes those that can now proceed (`SYS_LX_COMPLETE`, after writing a
//! received message into the waiter's memory). `semtimedop` timeouts are answered by the
//! main thread (`EAGAIN`), signals with `EINTR`, a removed object with `EIDRM`.
//!
//! **Process exit:** the kernel's `LX_NOTE_EXIT` comes through the notification ring, in
//! order with the calls: a process's `SEM_UNDO` adjustments are applied before any call made
//! after its exit is served.

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;

use hydra_rt::protocol::LX_REPLY_PENDING;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;
use crate::timeout;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ESRCH: i64 = -3;
const EINTR: i64 = -4;
const E2BIG: i64 = -7;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EFBIG: i64 = -27;
const ENOSPC: i64 = -28;
const ERANGE: i64 = -34;
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
const IPC_64: u64 = 0x100;

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

const MSGMAX: u64 = 8192;
const MSGMNB: u64 = 16384;
const MSGMNI: usize = 32000;

const CAP_IPC_OWNER: u32 = 15;
const CAP_SYS_RESOURCE: u32 = 24;

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

/// One semaphore.
#[derive(Clone, Copy, Default)]
struct Sem {
    val: i32,
    pid: u32,
    ncnt: u32,
    zcnt: u32,
}

/// A `semop` waiting (its call is pending).
struct SemWaiter {
    id: u64,
    tgid: u64,
    ops: Vec<(usize, i32, i16)>,
    deadline: Option<u64>,
    /// The semaphore it waits on, and whether for zero (counted in `ncnt`/`zcnt`).
    on: (usize, bool),
}

/// A semaphore set.
struct SemSet {
    perm: Perm,
    sems: Vec<Sem>,
    otime: i64,
    ctime: i64,
    waiters: Vec<SemWaiter>,
}

/// A `msgsnd` waiting for room.
struct MsgSender {
    id: u64,
    tgid: u64,
    mtype: i64,
    data: Vec<u8>,
}

/// A `msgrcv` waiting for a message.
struct MsgReceiver {
    id: u64,
    tgid: u64,
    msgp: u64,
    size: u64,
    msgtyp: i64,
    flags: u64,
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
    senders: Vec<MsgSender>,
    receivers: Vec<MsgReceiver>,
}

/// The objects of every IPC namespace. IDs are unique across namespaces; each object
/// records its namespace.
struct Ipc {
    sem: BTreeMap<i32, (u64, SemSet)>,
    msg: BTreeMap<i32, (u64, MsgQueue)>,
    next_seq: u16,
    /// `SEM_UNDO` adjustments: (process, set ID) -> per-semaphore adjustment.
    undo: BTreeMap<(u64, i32), Vec<i32>>,
}

static IPC: YLock<Ipc> = YLock::new(Ipc { sem: BTreeMap::new(), msg: BTreeMap::new(), next_seq: 1, undo: BTreeMap::new() });

/// Answers to give once the lock is let go: `(request id, result)`.
type Done = Vec<(u64, i64)>;

fn finish(done: Done) {
    for (id, r) in done {
        let _ = sys::lx_complete(id, r);
    }
}

fn now() -> i64 {
    sys::clock().0 as i64
}

/// Whether the caller may access an object with `perm` for `want` (4 read, 2 write).
fn allowed(perm: &Perm, cx: &Cx, want: u32) -> bool {
    if cx.has_cap(CAP_IPC_OWNER) || want == 0 {
        return true;
    }
    let (euid, egid) = (cx.c.euid, cx.c.egid);
    let bits = if euid == perm.uid || euid == perm.cuid {
        perm.mode >> 6
    } else if egid == perm.gid || egid == perm.cgid || cx.in_group(perm.gid) {
        perm.mode >> 3
    } else {
        perm.mode
    } & 7;
    bits & want == want
}

/// Whether the caller owns or created an object (`IPC_SET`, `IPC_RMID`).
fn owner(perm: &Perm, cx: &Cx) -> bool {
    cx.has_cap(CAP_IPC_OWNER) || cx.c.euid == perm.uid || cx.c.euid == perm.cuid
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

/// The `get` part shared by the object kinds: `Ok(Some(id))` for an existing object,
/// `Ok(None)` to create one.
fn lookup<T>(map: &BTreeMap<i32, (u64, T)>, perm_of: impl Fn(&T) -> &Perm, key: i32, ns: u64, flags: u64, cx: &Cx) -> Result<Option<i32>, i64> {
    let want = ((flags >> 6) & 6) as u32;
    if key == IPC_PRIVATE {
        return Ok(None);
    }
    let found = map.iter().find(|(_, (n, o))| *n == ns && perm_of(o).key == key).map(|(id, _)| *id);
    match found {
        Some(_) if flags & IPC_CREAT != 0 && flags & IPC_EXCL != 0 => Err(EEXIST),
        Some(id) => {
            if !allowed(perm_of(&map[&id].1), cx, want) {
                return Err(EACCES);
            }
            Ok(Some(id))
        }
        None if flags & IPC_CREAT != 0 => Ok(None),
        None => Err(ENOENT),
    }
}

fn new_perm(key: i32, flags: u64, seq: u16, cx: &Cx) -> Perm {
    let (euid, egid) = (cx.c.euid, cx.c.egid);
    Perm { key, uid: euid, gid: egid, cuid: euid, cgid: egid, mode: (flags & 0o777) as u32, seq }
}

// ---------------------------------------------------------------------------------------
// Semaphores

fn semget(cx: &Cx) -> i64 {
    let (key, nsems, flags) = (cx.args[0] as i32, cx.args[1], cx.args[2]);
    let ns = cx.c.ipc_ns;
    let mut ipc = IPC.lock();
    match lookup(&ipc.sem, |s: &SemSet| &s.perm, key, ns, flags, cx) {
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
            let set = SemSet { perm: new_perm(key, flags, seq, cx), sems: alloc::vec![Sem::default(); nsems as usize], otime: 0, ctime: now(), waiters: Vec::new() };
            ipc.sem.insert(id, (ns, set));
            id as i64
        }
    }
}

/// What trying a `semop` gave.
enum Try {
    /// Applied; the `SEM_UNDO` adjustments to record.
    Done(Vec<(usize, i32)>),
    /// Must wait on semaphore `.0` (for zero: `.1`); `.2`: the caller asked not to wait.
    Blocked(usize, bool, bool),
    Err(i64),
}

/// Tries every operation on a copy, all or nothing; applies them when they all can be.
fn try_semop(set: &mut SemSet, ops: &[(usize, i32, i16)], pid: u64) -> Try {
    let mut vals: Vec<i32> = set.sems.iter().map(|s| s.val).collect();
    for &(num, op, flg) in ops {
        let v = vals[num];
        if op > 0 {
            if v + op > SEMVMX {
                return Try::Err(ERANGE);
            }
            vals[num] = v + op;
        } else if op == 0 {
            if v != 0 {
                return Try::Blocked(num, true, flg as u64 & IPC_NOWAIT != 0);
            }
        } else if v + op < 0 {
            return Try::Blocked(num, false, flg as u64 & IPC_NOWAIT != 0);
        } else {
            vals[num] = v + op;
        }
    }
    for (i, s) in set.sems.iter_mut().enumerate() {
        if s.val != vals[i] {
            s.pid = pid as u32;
        }
        s.val = vals[i];
    }
    for &(num, _, _) in ops {
        set.sems[num].pid = pid as u32;
    }
    set.otime = now();
    Try::Done(ops.iter().filter(|o| o.2 & SEM_UNDO != 0 && o.1 != 0).map(|o| (o.0, o.1)).collect())
}

/// Records `SEM_UNDO` adjustments of process `pid` on set `id` (of `len` semaphores).
fn add_undo(undo: &mut BTreeMap<(u64, i32), Vec<i32>>, pid: u64, id: i32, len: usize, adj: &[(usize, i32)]) {
    if adj.is_empty() {
        return;
    }
    let a = undo.entry((pid, id)).or_insert_with(|| alloc::vec![0; len]);
    for &(num, op) in adj {
        a[num] -= op;
    }
}

fn count(set: &mut SemSet, on: (usize, bool), add: bool) {
    if let Some(s) = set.sems.get_mut(on.0) {
        let c = if on.1 { &mut s.zcnt } else { &mut s.ncnt };
        *c = if add { *c + 1 } else { c.saturating_sub(1) };
    }
}

/// Set `id` changed: retries its waiting `semop`s in order until none can proceed.
fn retry_sem(ipc: &mut Ipc, id: i32, done: &mut Done) {
    loop {
        let Some((_, set)) = ipc.sem.get_mut(&id) else { return };
        let mut progressed = false;
        let mut i = 0;
        while i < set.waiters.len() {
            let on = set.waiters[i].on;
            count(set, on, false);
            let ops = core::mem::take(&mut set.waiters[i].ops);
            let tgid = set.waiters[i].tgid;
            match try_semop(set, &ops, tgid) {
                Try::Done(adj) => {
                    let w = set.waiters.remove(i);
                    done.push((w.id, 0));
                    let len = set.sems.len();
                    add_undo(&mut ipc.undo, tgid, id, len, &adj);
                    progressed = true;
                    break; // the set changed: start again from the oldest
                }
                Try::Err(e) => {
                    let w = set.waiters.remove(i);
                    done.push((w.id, e));
                }
                Try::Blocked(num, zero, _) => {
                    set.waiters[i].ops = ops;
                    set.waiters[i].on = (num, zero);
                    count(set, (num, zero), true);
                    i += 1;
                }
            }
        }
        if !progressed {
            return;
        }
    }
}

/// `semop`/`semtimedop`: applies all operations at once, waiting until they can be.
fn semop(cx: &Cx, timed: bool) -> (i64, u64) {
    let (id, sops, nsops) = (cx.args[0] as i32, cx.args[1], cx.args[2]);
    if nsops == 0 || nsops > SEMOPM {
        return (if nsops == 0 { EINVAL } else { E2BIG }, 0);
    }
    let raw = match cx.copy_in(sops, nsops as usize * 6) {
        Ok(r) => r,
        Err(e) => return (e, 0),
    };
    let ops: Vec<(usize, i32, i16)> =
        raw.chunks(6).map(|c| (u16::from_le_bytes([c[0], c[1]]) as usize, i16::from_le_bytes([c[2], c[3]]) as i32, i16::from_le_bytes([c[4], c[5]]))).collect();
    let deadline = if timed {
        match timeout::relative(cx, cx.args[3]) {
            Ok(d) => d,
            Err(e) => return (e, 0),
        }
    } else {
        None
    };
    let (pid, ns) = (cx.c.tgid, cx.c.ipc_ns);
    let alters = ops.iter().any(|o| o.1 != 0);
    let mut done = Done::new();
    let r = {
        let mut guard = IPC.lock();
        let ipc = &mut *guard;
        let Some((n, set)) = ipc.sem.get_mut(&id) else { return (EINVAL, 0) };
        if *n != ns {
            return (EINVAL, 0);
        }
        if ops.iter().any(|o| o.0 >= set.sems.len()) {
            return (EFBIG, 0);
        }
        if !allowed(&set.perm, cx, if alters { 2 } else { 4 }) {
            return (EACCES, 0);
        }
        match try_semop(set, &ops, pid) {
            Try::Done(adj) => {
                let len = set.sems.len();
                add_undo(&mut ipc.undo, pid, id, len, &adj);
                if alters {
                    retry_sem(ipc, id, &mut done);
                }
                (0, 0)
            }
            Try::Err(e) => (e, 0),
            Try::Blocked(_, _, true) => (EAGAIN, 0),
            Try::Blocked(_, _, false) if timeout::passed(deadline) => (EAGAIN, 0),
            Try::Blocked(num, zero, false) => {
                count(set, (num, zero), true);
                set.waiters.push(SemWaiter { id: cx.id, tgid: pid, ops, deadline, on: (num, zero) });
                (0, LX_REPLY_PENDING)
            }
        }
    };
    finish(done);
    if r.1 == LX_REPLY_PENDING && deadline.is_some() {
        timeout::kick();
    }
    r
}

fn semctl(cx: &Cx) -> i64 {
    let (id, num, cmd, arg) = (cx.args[0] as i32, cx.args[1], cx.args[2] & !IPC_64, cx.args[3]);
    let (pid, ns) = (cx.c.tgid, cx.c.ipc_ns);
    let mut guard = IPC.lock();
    let ipc = &mut *guard;
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
        drop(guard);
        return if cx.copy_out(arg, &b).is_ok() { max as i64 } else { EFAULT };
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
    let read_ok = allowed(&set.perm, cx, 4);
    let write_ok = allowed(&set.perm, cx, 2);
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
            drop(guard);
            if cx.copy_out(arg, &b).is_err() {
                return EFAULT;
            }
            return if cmd == IPC_STAT { 0 } else { id as i64 };
        }
        IPC_SET => {
            if !owner(&set.perm, cx) {
                return EPERM;
            }
            let raw = match cx.copy_in(arg, 48) {
                Ok(r) => r,
                Err(e) => return e,
            };
            set_perm(&mut set.perm, &raw);
            set.ctime = now();
            0
        }
        IPC_RMID => {
            if !owner(&set.perm, cx) {
                return EPERM;
            }
            let (_, set) = ipc.sem.remove(&id).unwrap();
            ipc.undo.retain(|k, _| k.1 != id);
            drop(guard);
            // Waiters get EIDRM
            finish(set.waiters.iter().map(|w| (w.id, EIDRM)).collect());
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
            drop(guard);
            return if cx.copy_out(arg, &b).is_ok() { 0 } else { EFAULT };
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
            let raw = match cx.copy_in(arg, nsems * 2) {
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
    let mut done = Done::new();
    if matches!(cmd, SETVAL | SETALL) {
        retry_sem(ipc, id, &mut done);
    }
    drop(guard);
    finish(done);
    r
}

// ---------------------------------------------------------------------------------------
// Message queues

fn msgget(cx: &Cx) -> i64 {
    let (key, flags) = (cx.args[0] as i32, cx.args[1]);
    let ns = cx.c.ipc_ns;
    let mut ipc = IPC.lock();
    match lookup(&ipc.msg, |q: &MsgQueue| &q.perm, key, ns, flags, cx) {
        Err(e) => e,
        Ok(Some(id)) => id as i64,
        Ok(None) => {
            let ipc = &mut *ipc;
            let Some((id, seq)) = new_id(&ipc.msg, &mut ipc.next_seq, MSGMNI) else { return ENOSPC };
            let q = MsgQueue {
                perm: new_perm(key, flags, seq, cx),
                msgs: VecDeque::new(),
                bytes: 0,
                qbytes: MSGMNB,
                stime: 0,
                rtime: 0,
                ctime: now(),
                lspid: 0,
                lrpid: 0,
                senders: Vec::new(),
                receivers: Vec::new(),
            };
            ipc.msg.insert(id, (ns, q));
            id as i64
        }
    }
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

impl MsgQueue {
    fn has_room(&self, size: u64) -> bool {
        // As Linux's msgsnd, msg_qbytes also bounds the number of messages
        self.bytes + size <= self.qbytes && (self.msgs.len() as u64) < self.qbytes
    }

    /// Hands queued messages to waiting receivers and lets waiting senders in, until neither
    /// can go on.
    fn settle(&mut self, done: &mut Done) {
        loop {
            let mut progressed = false;
            // Receivers, oldest first
            let mut i = 0;
            while i < self.receivers.len() {
                let w = &self.receivers[i];
                let Some(at) = pick(&self.msgs, w.msgtyp, w.flags) else {
                    i += 1;
                    continue;
                };
                if self.msgs[at].1.len() as u64 > w.size && w.flags & MSG_NOERROR == 0 {
                    let w = self.receivers.remove(i);
                    done.push((w.id, E2BIG));
                    continue;
                }
                let (mtype, data) = &self.msgs[at];
                let n = data.len().min(w.size as usize);
                let mut out = mtype.to_le_bytes().to_vec();
                out.extend_from_slice(&data[..n]);
                match sys::lx_write(w.id, w.msgp, &out) {
                    Err(e) if e == ESRCH => {
                        let w = self.receivers.remove(i);
                        done.push((w.id, EINTR));
                        continue;
                    }
                    r => {
                        let w = self.receivers.remove(i);
                        let (_, data) = self.msgs.remove(at).unwrap();
                        self.bytes -= data.len() as u64;
                        self.rtime = now();
                        self.lrpid = w.tgid as u32;
                        done.push((w.id, if r.is_ok() { n as i64 } else { EFAULT }));
                        progressed = true;
                    }
                }
            }
            // Senders, oldest first, while there is room
            while let Some(s) = self.senders.first() {
                if !self.has_room(s.data.len() as u64) {
                    break;
                }
                let s = self.senders.remove(0);
                self.bytes += s.data.len() as u64;
                self.stime = now();
                self.lspid = s.tgid as u32;
                self.msgs.push_back((s.mtype, s.data));
                done.push((s.id, 0));
                progressed = true;
            }
            if !progressed {
                return;
            }
        }
    }
}

fn msgsnd(cx: &Cx) -> (i64, u64) {
    let (id, msgp, size, flags) = (cx.args[0] as i32, cx.args[1], cx.args[2], cx.args[3]);
    if size > MSGMAX {
        return (EINVAL, 0);
    }
    let raw = match cx.copy_in(msgp, 8 + size as usize) {
        Ok(r) => r,
        Err(e) => return (e, 0),
    };
    let mtype = i64::from_le_bytes(raw[0..8].try_into().unwrap());
    if mtype <= 0 {
        return (EINVAL, 0);
    }
    let (pid, ns) = (cx.c.tgid, cx.c.ipc_ns);
    let mut done = Done::new();
    let r = {
        let mut ipc = IPC.lock();
        let Some((n, q)) = ipc.msg.get_mut(&id) else { return (EINVAL, 0) };
        if *n != ns {
            return (EINVAL, 0);
        }
        if !allowed(&q.perm, cx, 2) {
            return (EACCES, 0);
        }
        if q.has_room(size) {
            q.msgs.push_back((mtype, raw[8..].to_vec()));
            q.bytes += size;
            q.stime = now();
            q.lspid = pid as u32;
            q.settle(&mut done);
            (0, 0)
        } else if flags & IPC_NOWAIT != 0 {
            (EAGAIN, 0)
        } else {
            q.senders.push(MsgSender { id: cx.id, tgid: pid, mtype, data: raw[8..].to_vec() });
            (0, LX_REPLY_PENDING)
        }
    };
    finish(done);
    r
}

fn msgrcv(cx: &Cx) -> (i64, u64) {
    let (id, msgp, size, msgtyp, flags) = (cx.args[0] as i32, cx.args[1], cx.args[2], cx.args[3] as i64, cx.args[4]);
    if (size as i64) < 0 {
        return (EINVAL, 0);
    }
    if flags & MSG_COPY != 0 && (flags & IPC_NOWAIT == 0 || flags & MSG_EXCEPT != 0) {
        return (EINVAL, 0);
    }
    let (pid, ns) = (cx.c.tgid, cx.c.ipc_ns);
    let mut done = Done::new();
    let got = {
        let mut ipc = IPC.lock();
        let Some((n, q)) = ipc.msg.get_mut(&id) else { return (EINVAL, 0) };
        if *n != ns {
            return (EINVAL, 0);
        }
        if !allowed(&q.perm, cx, 4) {
            return (EACCES, 0);
        }
        match pick(&q.msgs, msgtyp, flags) {
            Some(i) => {
                if q.msgs[i].1.len() as u64 > size && flags & MSG_NOERROR == 0 {
                    return (E2BIG, 0);
                }
                let (mtype, mut data) = if flags & MSG_COPY != 0 { q.msgs[i].clone() } else { q.msgs.remove(i).unwrap() };
                if flags & MSG_COPY == 0 {
                    q.bytes -= data.len() as u64;
                    q.rtime = now();
                    q.lrpid = pid as u32;
                    q.settle(&mut done); // room for senders
                }
                data.truncate(size as usize);
                Ok((mtype, data))
            }
            None if flags & IPC_NOWAIT != 0 => Err(ENOMSG),
            None => {
                q.receivers.push(MsgReceiver { id: cx.id, tgid: pid, msgp, size, msgtyp, flags });
                Err(0)
            }
        }
    };
    finish(done);
    match got {
        Ok((mtype, data)) => {
            let mut out = mtype.to_le_bytes().to_vec();
            out.extend_from_slice(&data);
            if cx.copy_out(msgp, &out).is_err() {
                return (EFAULT, 0);
            }
            (data.len() as i64, 0)
        }
        Err(0) => (0, LX_REPLY_PENDING),
        Err(e) => (e, 0),
    }
}

fn msgctl(cx: &Cx) -> i64 {
    let (id, cmd, buf) = (cx.args[0] as i32, cx.args[1] & !IPC_64, cx.args[2]);
    let ns = cx.c.ipc_ns;
    let resource = cx.has_cap(CAP_SYS_RESOURCE);
    let mut guard = IPC.lock();
    let ipc = &mut *guard;
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
        drop(guard);
        return if cx.copy_out(buf, &b).is_ok() { max as i64 } else { EFAULT };
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
            if cmd != MSG_STAT_ANY && !allowed(&q.perm, cx, 4) {
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
            drop(guard);
            if cx.copy_out(buf, &b).is_err() {
                return EFAULT;
            }
            if cmd == IPC_STAT {
                0
            } else {
                id as i64
            }
        }
        IPC_SET => {
            if !owner(&q.perm, cx) {
                return EPERM;
            }
            let raw = match cx.copy_in(buf, 120) {
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
            let mut done = Done::new();
            q.settle(&mut done);
            drop(guard);
            finish(done);
            0
        }
        IPC_RMID => {
            if !owner(&q.perm, cx) {
                return EPERM;
            }
            let (_, q) = ipc.msg.remove(&id).unwrap();
            drop(guard);
            // Waiters get EIDRM
            finish(q.senders.iter().map(|w| (w.id, EIDRM)).chain(q.receivers.iter().map(|w| (w.id, EIDRM))).collect());
            0
        }
        _ => EINVAL,
    }
}

// ---------------------------------------------------------------------------------------
// Events from the kernel and the main thread

/// Handles `semget` (64), `semop` (65), `semctl` (66), `semtimedop` (220), `msgget` (68),
/// `msgsnd` (69), `msgrcv` (70), `msgctl` (71): `(result, reply flags)`.
pub fn dispatch(cx: &Cx) -> (i64, u64) {
    match cx.nr {
        64 => (semget(cx), 0),
        65 => semop(cx, false),
        66 => (semctl(cx), 0),
        220 => semop(cx, true),
        68 => (msgget(cx), 0),
        69 => msgsnd(cx),
        70 => msgrcv(cx),
        71 => (msgctl(cx), 0),
        _ => (-38, 0),
    }
}

/// Removes the waiters `keep` refuses from every set and queue, collecting `(id, result)`.
fn drop_waiters(ipc: &mut Ipc, keep: impl Fn(u64, u64) -> bool, result: i64, done: &mut Done) {
    for (_, set) in ipc.sem.values_mut() {
        let mut i = 0;
        while i < set.waiters.len() {
            if keep(set.waiters[i].id, set.waiters[i].tgid) {
                i += 1;
            } else {
                let w = set.waiters.remove(i);
                count(set, w.on, false);
                done.push((w.id, result));
            }
        }
    }
    for (_, q) in ipc.msg.values_mut() {
        q.senders.retain(|w| keep(w.id, w.tgid) || {
            done.push((w.id, result));
            false
        });
        q.receivers.retain(|w| keep(w.id, w.tgid) || {
            done.push((w.id, result));
            false
        });
    }
}

/// A signal arrived for the caller of pending call `id`: a waiting `semop`, `msgsnd` or
/// `msgrcv` ends with `EINTR`. Whether `id` was one of ours.
pub fn interrupted(id: u64) -> bool {
    let mut done = Done::new();
    drop_waiters(&mut IPC.lock(), |i, _| i != id, EINTR, &mut done);
    let found = !done.is_empty();
    finish(done);
    found
}

/// Process `tgid` ended: its `SEM_UNDO` adjustments are applied (waiters that can proceed
/// now do), and calls it still had waiting end.
pub fn on_exit(tgid: u64) {
    let mut done = Done::new();
    {
        let mut guard = IPC.lock();
        let ipc = &mut *guard;
        drop_waiters(ipc, |_, t| t != tgid, EINTR, &mut done);
        let undos: Vec<((u64, i32), Vec<i32>)> = ipc.undo.iter().filter(|((p, _), _)| *p == tgid).map(|(k, v)| (*k, v.clone())).collect();
        for (k, adj) in undos {
            ipc.undo.remove(&k);
            let mut changed = false;
            if let Some((_, set)) = ipc.sem.get_mut(&k.1) {
                for (s, a) in set.sems.iter_mut().zip(adj) {
                    if a != 0 {
                        s.val = (s.val + a).clamp(0, SEMVMX);
                        s.pid = tgid as u32;
                        changed = true;
                    }
                }
            }
            if changed {
                retry_sem(ipc, k.1, &mut done);
            }
        }
    }
    finish(done);
}

/// Answers the `semtimedop`s whose timeout passed (`EAGAIN`); returns the earliest deadline
/// still waiting.
pub fn tick(now: u64) -> Option<u64> {
    let mut done = Done::new();
    let mut next: Option<u64> = None;
    {
        let mut ipc = IPC.lock();
        for (_, set) in ipc.sem.values_mut() {
            let mut i = 0;
            while i < set.waiters.len() {
                match set.waiters[i].deadline {
                    Some(d) if d <= now => {
                        let w = set.waiters.remove(i);
                        count(set, w.on, false);
                        done.push((w.id, EAGAIN));
                    }
                    Some(d) => {
                        next = Some(next.map_or(d, |n| n.min(d)));
                        i += 1;
                    }
                    None => i += 1,
                }
            }
        }
    }
    finish(done);
    next
}
