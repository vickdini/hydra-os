//! # File locks in vfs-server (wave 7, Group 7-6)
//!
//! The lock table of the kernel's `compat/linux/locks.rs` as plain data, for vfs-server's
//! kept state (`docs/vfs-design.md` 8.1: "Mount tables and namespaces, file locks survive"):
//!
//! - **`flock`** locks a whole file, shared or exclusive, for an open file description
//!   ([`Owner::Flock`]); a conversion releases first, as on Linux.
//! - **POSIX record locks** ([`Owner::Posix`]) lock byte ranges for a process: its own ranges
//!   merge and split; all of them on a file go when the process closes any descriptor of it
//!   ([`LockTable::closed`]) or exits ([`LockTable::process_exited`]).
//! - **Open file description locks** ([`Owner::Ofd`]) are byte ranges owned by the
//!   description; they and POSIX locks conflict with each other, not with `flock`.
//!
//! Owners are numbers: a process id, or the kernel's identity of an open file description
//! (a handle id the kernel gives with the call). No waiting here: [`LockTable::try_lock`]
//! answers the conflicting lock, and the caller decides to wait (`F_SETLKW`) or fail.
//!
//! **Not wired yet:** `flock` and the `fcntl` lock commands stay the kernel's this wave (they
//! need close and exit notes from the kernel and blocking answers; the in-kernel copy goes
//! with Group 7-7). The table is in the kept-state snapshot from now on (empty), so moving
//! the calls changes no format.
//!
//! Plain `core`/`alloc`: the host tests (`tests/host-w7-42`) run it.

use alloc::string::String;
use alloc::vec::Vec;

use crate::mtab::{seal, unseal, Dec, Enc};

const EINVAL: i64 = -22;
const EOVERFLOW: i64 = -75;

/// Who holds a lock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// A process (POSIX record locks).
    Posix(u64),
    /// An open file description (OFD locks).
    Ofd(u64),
    /// An open file description (`flock`).
    Flock(u64),
}

impl Owner {
    fn whole_file(self) -> bool {
        matches!(self, Owner::Flock(_))
    }

    fn code(self) -> (u8, u64) {
        match self {
            Owner::Posix(p) => (0, p),
            Owner::Ofd(i) => (1, i),
            Owner::Flock(i) => (2, i),
        }
    }

    fn from_code(k: u8, v: u64) -> Result<Owner, i64> {
        Ok(match k {
            0 => Owner::Posix(v),
            1 => Owner::Ofd(v),
            2 => Owner::Flock(v),
            _ => return Err(EINVAL),
        })
    }
}

/// One lock: `[start, end]` of file `ino` (`end` inclusive; `u64::MAX` reaches the end of
/// the file however it grows).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lock {
    pub ino: u64,
    pub owner: Owner,
    pub write: bool,
    pub start: u64,
    pub end: u64,
    /// Who took it (`F_GETLK`, `/proc/locks`).
    pub pid: u64,
}

/// Every lock.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LockTable {
    pub locks: Vec<Lock>,
}

/// The byte range of a `struct flock` (`whence` 0/1/2 with `base` = 0, the offset or the
/// size; `start`, `len` as given): `(start, end)` with `end` inclusive (`u64::MAX`: to the
/// end), or `EINVAL`.
pub fn range(base: i64, start: i64, len: i64) -> Result<(u64, u64), i64> {
    let mut s = base.checked_add(start).ok_or(EINVAL)?;
    let mut e: i64 = if len == 0 {
        i64::MAX
    } else if len > 0 {
        // (a range past the largest offset: EOVERFLOW, as Linux)
        s.checked_add(len - 1).ok_or(EOVERFLOW)?
    } else {
        s.checked_sub(1).ok_or(EINVAL)?
    };
    if len < 0 {
        s = s.checked_add(len).ok_or(EINVAL)?;
    }
    if s < 0 || e < s {
        return Err(EINVAL);
    }
    if len == 0 || e == i64::MAX {
        e = -1;
    }
    Ok((s as u64, if e < 0 { u64::MAX } else { e as u64 }))
}

impl LockTable {
    pub const fn new() -> LockTable {
        LockTable { locks: Vec::new() }
    }

    /// The first lock of another owner (of the same family: `flock`, or record locks) that
    /// conflicts with taking `write` on `[start, end]` of `ino`.
    pub fn conflict(&self, ino: u64, owner: Owner, write: bool, start: u64, end: u64) -> Option<Lock> {
        self.locks
            .iter()
            .find(|l| l.ino == ino && l.owner != owner && l.owner.whole_file() == owner.whole_file() && l.start <= end && start <= l.end && (write || l.write))
            .copied()
    }

    /// Removes `owner`'s locks on `[start, end]` of `ino` (splitting the ones reaching past):
    /// whether anything changed (waiters should look again).
    pub fn unlock(&mut self, ino: u64, owner: Owner, start: u64, end: u64) -> bool {
        // (an inverted range unlocks nothing)
        if start > end {
            return false;
        }
        let before = self.locks.clone();
        let mut out = Vec::with_capacity(self.locks.len() + 1);
        for l in self.locks.drain(..) {
            if l.ino != ino || l.owner != owner || l.end < start || end < l.start {
                out.push(l);
                continue;
            }
            if l.start < start {
                out.push(Lock { end: start - 1, ..l });
            }
            if l.end > end {
                out.push(Lock { start: end + 1, ..l });
            }
        }
        self.locks = out;
        self.locks != before
    }

    /// Takes `write` on `[start, end]` of `ino` for `owner` (merging with its touching locks
    /// of the same kind, replacing its own overlapping ones), or answers the conflicting lock.
    /// A `flock` conversion first drops the owner's lock (as Linux: not atomic).
    pub fn try_lock(&mut self, ino: u64, owner: Owner, write: bool, start: u64, end: u64, pid: u64) -> Result<(), Lock> {
        // A flock is always the whole file; an inverted range takes nothing
        let (start, end) = if owner.whole_file() { (0, u64::MAX) } else { (start, end) };
        if start > end {
            return Ok(());
        }
        if owner.whole_file() {
            self.unlock(ino, owner, 0, u64::MAX);
        }
        if let Some(l) = self.conflict(ino, owner, write, start, end) {
            return Err(l);
        }
        self.unlock(ino, owner, start, end);
        let mut new = Lock { ino, owner, write, start, end, pid };
        while let Some(i) = self.locks.iter().position(|l| {
            l.ino == new.ino && l.owner == new.owner && l.write == new.write && (l.end != u64::MAX && l.end + 1 == new.start || new.end != u64::MAX && new.end + 1 == l.start)
        }) {
            let l = self.locks.remove(i);
            new.start = new.start.min(l.start);
            new.end = new.end.max(l.end);
        }
        self.locks.push(new);
        Ok(())
    }

    fn retain(&mut self, keep: impl Fn(&Lock) -> bool) -> bool {
        let before = self.locks.len();
        self.locks.retain(keep);
        self.locks.len() != before
    }

    /// An open file description is gone: its `flock` and OFD locks go.
    pub fn release_file(&mut self, id: u64) -> bool {
        self.retain(|l| l.owner != Owner::Flock(id) && l.owner != Owner::Ofd(id))
    }

    /// Process `pid` closed a descriptor of `ino`: its POSIX locks on it go.
    pub fn closed(&mut self, pid: u64, ino: u64) -> bool {
        self.retain(|l| !(l.ino == ino && l.owner == Owner::Posix(pid)))
    }

    /// Process `pid` ended: its POSIX locks go.
    pub fn process_exited(&mut self, pid: u64) -> bool {
        self.retain(|l| l.owner != Owner::Posix(pid))
    }

    /// `/proc/locks` (pids as given: the caller maps them to the reader's namespace).
    pub fn proc_locks(&self) -> String {
        let mut s = String::new();
        for (i, l) in self.locks.iter().enumerate() {
            let (class, pid) = match l.owner {
                Owner::Posix(_) => ("POSIX ", l.pid as i64),
                Owner::Ofd(_) => ("OFDLCK", -1),
                Owner::Flock(_) => ("FLOCK ", l.pid as i64),
            };
            let end = if l.end == u64::MAX { String::from("EOF") } else { alloc::format!("{}", l.end) };
            s.push_str(&alloc::format!("{}: {} ADVISORY  {} {} 08:01:{} {} {}\n", i + 1, class, if l.write { "WRITE" } else { "READ " }, pid, l.ino, l.start, end));
        }
        s
    }

    /// Consistency for kept state read back: ranges in order, no two locks of different
    /// owners in conflict, an owner's own locks not overlapping, `flock`s whole-file.
    pub fn check(&self) -> Result<(), i64> {
        for (i, l) in self.locks.iter().enumerate() {
            if l.start > l.end || l.owner.whole_file() && (l.start != 0 || l.end != u64::MAX) {
                return Err(EINVAL);
            }
            for m in &self.locks[i + 1..] {
                let overlap = l.ino == m.ino && l.start <= m.end && m.start <= l.end && l.owner.whole_file() == m.owner.whole_file();
                if overlap && (l.owner == m.owner || l.write || m.write) {
                    return Err(EINVAL);
                }
            }
        }
        Ok(())
    }

    /// The table, sealed.
    pub fn encode(&self) -> Vec<u8> {
        let mut e = Enc::default();
        e.u32(self.locks.len() as u32);
        for l in &self.locks {
            let (k, v) = l.owner.code();
            e.u64(l.ino);
            e.u8(k);
            e.u64(v);
            e.u8(l.write as u8);
            e.u64(l.start);
            e.u64(l.end);
            e.u64(l.pid);
        }
        seal(LOCKS_MAGIC, LOCKS_VERSION, &e.buf)
    }

    /// Reads back what [`Self::encode`] wrote and checks it.
    pub fn decode(b: &[u8]) -> Result<LockTable, i64> {
        let body = unseal(LOCKS_MAGIC, LOCKS_VERSION, b)?;
        let mut d = Dec::new(body);
        let n = d.u32()? as usize;
        if n > d.remaining() / 42 {
            return Err(EINVAL);
        }
        let mut locks = Vec::with_capacity(n);
        for _ in 0..n {
            let ino = d.u64()?;
            let k = d.u8()?;
            let owner = Owner::from_code(k, d.u64()?)?;
            let write = match d.u8()? {
                0 => false,
                1 => true,
                _ => return Err(EINVAL),
            };
            locks.push(Lock { ino, owner, write, start: d.u64()?, end: d.u64()?, pid: d.u64()? });
        }
        if !d.done() {
            return Err(EINVAL);
        }
        let t = LockTable { locks };
        t.check()?;
        Ok(t)
    }
}

const LOCKS_MAGIC: u32 = 0x4c4f_434b; // "LOCK"
const LOCKS_VERSION: u32 = 1;
