//! # The kernel's half of System V shared memory in lx-ipc: who has which segment attached
//! (wave 10, Group 8-2)
//!
//! Plain data and rules, host-tested in `tests/host-w10-82`; [`super::shm`] holds one
//! [`Table`] under a lock and does the mapping, the calls and the notifications.
//!
//! - An **attachment** is a mapping one process made with `shmat` (or inherited by `fork`):
//!   `(process, address) -> (segment id, length)`.
//! - Per segment id the kernel keeps what the attachments decide ([`Info`]): `shm_nattch`
//!   (with `shmat` calls in flight: [`Table::pre_attach`]), `shm_atime`, `shm_dtime` and
//!   `shm_lpid` (as Linux's `shm_open`/`shm_close`: attach, fork, detach, exit), and whether
//!   lx-ipc removed the segment (`IPC_RMID` with attachments left: [`Table::rmid`]). lx-ipc
//!   reads them for `IPC_STAT` and `/proc/sysvipc/shm` and drops them when the segment goes
//!   ([`Table::forget_id`]).
//! - Only the last attachment of a *removed* segment makes a [`Note`] for lx-ipc (it then
//!   lets the segment go): the common attach/detach posts nothing.
//! - A **generation** ([`Table::reset`]): when lx-ipc starts without its segments (first
//!   start, or the restart ladder dropped its kept state), the attachments made before stop
//!   counting: their ids may be given to new segments.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

/// One attachment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Att {
    /// The segment.
    pub id: i32,
    /// Bytes mapped (whole pages).
    pub len: u64,
    /// The generation it was made in.
    pub gen: u64,
}

/// What the kernel knows of one segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Info {
    /// Attachments (and `shmat` calls in flight).
    pub nattch: u64,
    /// Last attach (seconds since 1970; 0: never).
    pub atime: i64,
    /// Last detach.
    pub dtime: i64,
    /// The process of the last attach or detach.
    pub lpid: u32,
    /// lx-ipc removed it: its last attachment going is told ([`Note`]).
    pub removed: bool,
}

/// A notification for the IPC service: the last attachment of removed segment `id` went
/// (process `pid`): the segment can go.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Note {
    /// The segment.
    pub id: i32,
    /// The process whose attachment (or failed `shmat`) went last.
    pub pid: u64,
}

/// The attachments of every process and what they decide per segment.
#[derive(Default)]
pub struct Table {
    att: BTreeMap<(u64, u64), Att>,
    info: BTreeMap<i32, Info>,
    gen: u64,
    /// Attachments made since boot (diagnostics).
    pub made: u64,
    /// Attachments dropped since boot (diagnostics).
    pub dropped: u64,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self { att: BTreeMap::new(), info: BTreeMap::new(), gen: 0, made: 0, dropped: 0 }
    }

    /// What the kernel knows of segment `id` (all zero: nothing yet).
    pub fn info(&self, id: i32) -> Info {
        self.info.get(&id).copied().unwrap_or_default()
    }

    /// The attachment count of segment `id` (with `shmat` calls in flight).
    pub fn nattch(&self, id: i32) -> u64 {
        self.info(id).nattch
    }

    /// Attachments in the table (all generations).
    pub fn len(&self) -> usize {
        self.att.len()
    }

    /// Whether no attachment is in the table.
    pub fn is_empty(&self) -> bool {
        self.att.is_empty()
    }

    /// One count of `id` less, by `pid` at `now` (`detach`: a real detach, which Linux's
    /// `shm_close` stamps); the note when that was the last of a removed segment.
    fn dec(&mut self, id: i32, pid: u64, now: i64, detach: bool) -> Option<Note> {
        // (a segment lx-ipc let go: nothing to count)
        let e = self.info.get_mut(&id)?;
        e.nattch = e.nattch.saturating_sub(1);
        if detach {
            e.dtime = now;
            e.lpid = pid as u32;
        }
        (e.nattch == 0 && e.removed).then_some(Note { id, pid })
    }

    /// A `shmat` of `id` starts: counted now. Returns the generation to give to
    /// [`Table::attached`] or [`Table::undo`].
    pub fn pre_attach(&mut self, id: i32) -> u64 {
        self.info.entry(id).or_default().nattch += 1;
        self.gen
    }

    /// The `shmat` counted at generation `gen` failed: its count goes back.
    pub fn undo(&mut self, id: i32, pid: u64, gen: u64) -> Option<Note> {
        if gen != self.gen {
            return None;
        }
        self.dec(id, pid, 0, false)
    }

    /// The `shmat` counted at generation `gen` mapped `len` bytes at `addr` of process
    /// `pid` at `now`. A mapping that replaced another attachment at the same address
    /// (`SHM_REMAP`) drops that one: its note is returned. (If lx-ipc started afresh
    /// meanwhile, `gen` is old and the attachment never counts.)
    pub fn attached(&mut self, pid: u64, addr: u64, id: i32, len: u64, gen: u64, now: i64) -> Option<Note> {
        if gen == self.gen {
            let e = self.info.entry(id).or_default();
            e.atime = now;
            e.lpid = pid as u32;
        }
        let old = self.att.insert((pid, addr), Att { id, len, gen });
        self.made += 1;
        old.and_then(|o| self.drop_att(pid, o, now))
    }

    /// Counts an attachment going away.
    fn drop_att(&mut self, pid: u64, a: Att, now: i64) -> Option<Note> {
        self.dropped += 1;
        if a.gen != self.gen {
            return None;
        }
        self.dec(a.id, pid, now, true)
    }

    /// `shmdt(addr)` of process `pid` at `now`: the attachment there (to unmap) and its note.
    pub fn detach(&mut self, pid: u64, addr: u64, now: i64) -> Option<(Att, Option<Note>)> {
        let a = self.att.remove(&(pid, addr))?;
        let n = self.drop_att(pid, a, now);
        Some((a, n))
    }

    /// Process `parent` forked `child` at `now`: the child has the same attachments (its
    /// address space is a copy; as Linux's `shm_open`, the parent is the last user).
    pub fn fork(&mut self, parent: u64, child: u64, now: i64) {
        let mine: Vec<(u64, Att)> = self.att.range((parent, 0)..=(parent, u64::MAX)).map(|(k, a)| (k.1, *a)).collect();
        for (addr, a) in mine {
            if a.gen == self.gen {
                let e = self.info.entry(a.id).or_default();
                e.nattch += 1;
                e.atime = now;
                e.lpid = parent as u32;
            }
            if let Some(old) = self.att.insert((child, addr), a) {
                // (a stale entry of a dead process with the same number)
                let _ = self.drop_att(child, old, now);
            }
            self.made += 1;
        }
    }

    /// Process `pid` exited or called `execve` at `now`: its attachments go. The notes to
    /// post.
    pub fn forget(&mut self, pid: u64, now: i64) -> Vec<Note> {
        let keys: Vec<(u64, u64)> = self.att.range((pid, 0)..=(pid, u64::MAX)).map(|(k, _)| *k).collect();
        let mut notes = Vec::new();
        for k in keys {
            if let Some(a) = self.att.remove(&k) {
                if let Some(n) = self.drop_att(pid, a, now) {
                    notes.push(n);
                }
            }
        }
        notes
    }

    /// lx-ipc removed segment `id` (`IPC_RMID`): its attachment count; when attachments are
    /// left, their last one going makes a [`Note`].
    pub fn rmid(&mut self, id: i32) -> u64 {
        let e = self.info.entry(id).or_default();
        e.removed = true;
        e.nattch
    }

    /// Segment `id` is gone in lx-ipc: what the kernel knew of it goes (attachments still
    /// mapped keep their pages, and count for nothing).
    pub fn forget_id(&mut self, id: i32) {
        self.info.remove(&id);
    }

    /// The IPC service starts without segments: what is attached now no longer counts.
    pub fn reset(&mut self) {
        self.gen += 1;
        self.info.clear();
    }

    /// The current generation.
    pub fn generation(&self) -> u64 {
        self.gen
    }
}
