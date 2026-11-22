//! The terminals' state: the pseudo-terminal pairs (moved from the kernel's
//! `src/compat/linux/pty.rs`, wave 8) and the console terminal (the kernel's `tty.rs`), with
//! their waiting readers and writers.
//!
//! A **pair** joins a master end (`/dev/ptmx`, held by Konsole, `script`, `ssh`, dpkg) and
//! a slave end that looks like a real terminal to the programs on it. Bytes written to the
//! master are input to the slave's line discipline ([`crate::ldisc`]): line editing, echo
//! (back to the master) and `ISIG` characters raising signals in the slave's foreground
//! group. Bytes written to the slave get output processing and become readable on the
//! master. Each open end is one server-object slot (`dup` and `fork` share the kernel's
//! descriptor, so a slot is an open file description).
//!
//! **Blocking without tying up a worker:** a `read` with nothing to give and a slave `write`
//! that does not fit are answered "pending" and kept here; the call that brings bytes (or
//! room) completes them. A signal completes them with `ERESTARTSYS`; a process exit drops
//! them.
//!
//! **Hang-ups:** closing the master ends the slave (reads see end-of-file, writes fail
//! `EIO`) and, as on Linux, sends `SIGHUP` and `SIGCONT` to the session leader and `SIGHUP`
//! to the foreground group of a terminal that is some session's controlling terminal; the
//! last slave closing makes master reads fail `EIO`; `vhangup` kills the session's earlier
//! descriptors; a session leader's exit gives its terminal up.
//!
//! Plain logic: system calls go through [`Io`], so the host tests run it as it is.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::ldisc::{self, Effects, Mem, Tty};

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const EAGAIN: i64 = -11;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const ENOTTY: i64 = -25;
pub const ERESTARTSYS: i64 = -512;

pub const POLLIN: u32 = 0x0001;
pub const POLLOUT: u32 = 0x0004;
pub const POLLHUP: u32 = 0x0010;

const SIGHUP: u32 = 1;
const SIGCONT: u32 = 18;

/// Most slave output buffered for the master before slave writers wait.
pub const OUTPUT_LIMIT: usize = 64 * 1024;
/// Most pairs: Linux's slave majors 136..143 of 256 minors each.
pub const MAX_PTYS: u32 = 2048;
/// `ENOSPC`.
pub const ENOSPC: i64 = -28;
/// Most pty reads and writes kept waiting at once, all terminals together: each holds one of
/// the service's 128 request slots, and the console needs some (beyond: `EAGAIN`).
pub const MAX_PTY_WAITERS: usize = 96;
/// `EACCES`.
pub const EACCES: i64 = -13;
/// Most console reads kept waiting at once (each holds one of the service's request slots).
pub const MAX_CONSOLE_WAITERS: usize = 32;

/// Console-terminal and pty `ioctl` numbers handled here.
pub const TIOCGPTN: u64 = 0x8004_5430;
pub const TIOCSPTLCK: u64 = 0x4004_5431;
pub const TIOCGPTLCK: u64 = 0x8004_5439;
pub const TIOCGPTPEER: u64 = 0x5441;
pub const TIOCPKT: u64 = 0x5420;

/// What the service does for the state: client memory of calls, answers, signals, readiness
/// words, the console. `put` and `pgrp_in` happen at once (under the state's lock); the rest
/// may be done after it is let go.
pub trait Io {
    /// Writes `data` into the buffers `iov` of request `id`'s caller.
    fn put(&mut self, id: u64, iov: &Iov, data: &[u8]) -> Result<(), i64>;
    /// Answers pending request `id`.
    fn complete(&mut self, id: u64, result: i64);
    /// Posts `sig` to process group `pgid` of session `sid` (the terminal's: the kernel posts
    /// only to the group's members in that session, and only terminal signals).
    fn signal_group(&mut self, pgid: u64, sid: u64, sig: u32);
    /// Posts `sig` (`SIGHUP`, `SIGCONT`) to session leader `pid` (the kernel refuses a process
    /// that does not lead the session `pid`).
    fn signal_proc(&mut self, pid: u64, sig: u32);
    /// Sets object `slot`'s poll bits (`arrived`: something new came, for edge-triggered
    /// waiters).
    fn ready(&mut self, slot: u32, bits: u32, arrived: bool);
    /// Prints on the console.
    fn cons_out(&mut self, data: &[u8]);
    /// Tells the kernel whether a console `read` would return (attach generation `gen`).
    fn cons_ready(&mut self, gen: u64, readable: bool);
    /// Whether process group `pgid` has a member in session `sid` (0), only elsewhere (1),
    /// or none (`-ESRCH`).
    fn pgrp_in(&mut self, pgid: u64, sid: u64) -> i64;
}

/// A caller's buffers: `(address, length)` pieces.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Iov(pub Vec<(u64, u64)>);

impl Iov {
    /// One buffer.
    pub fn one(ptr: u64, len: u64) -> Self {
        Self(alloc::vec![(ptr, len)])
    }

    /// Bytes in all pieces (saturating: the callers check the sum first, see `fits`).
    pub fn total(&self) -> usize {
        self.0.iter().fold(0usize, |a, &(_, l)| a.saturating_add(l as usize))
    }

    /// Whether the pieces' sum fits `ssize_t` (Linux's `readv`/`writev` rule: `EINVAL`).
    pub fn fits(&self) -> bool {
        let mut t: u64 = 0;
        for &(_, l) in &self.0 {
            match t.checked_add(l) {
                Some(v) if v <= i64::MAX as u64 => t = v,
                _ => return false,
            }
        }
        true
    }
}

/// Who makes a call: process, its group and session, effective user.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caller {
    pub tgid: u64,
    pub pgid: u64,
    pub sid: u64,
    pub euid: u32,
}

/// A call's answer: now, or later (the call is kept and completed through [`Io::complete`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ans {
    Now(i64),
    Pending,
}

/// A reader waiting for bytes.
#[derive(Clone, Debug)]
struct RWait {
    id: u64,
    tgid: u64,
    iov: Iov,
}

/// A slave writer waiting for room: its bytes, taken from it when the call came.
#[derive(Clone, Debug)]
struct WWait {
    id: u64,
    tgid: u64,
    data: Vec<u8>,
}

/// One pseudo-terminal pair.
struct Pair {
    /// Its slave's number (`/dev/pts/N`).
    index: u32,
    tty: Tty,
    /// Slave output (and input echo) waiting for the master.
    to_master: VecDeque<u8>,
    /// The master's slot (`None` once it closed).
    master: Option<u32>,
    /// Open slave slots.
    slaves: BTreeSet<u32>,
    /// A slave was opened at least once (master reads fail `EIO` after it closes).
    slave_opened: bool,
    /// `TIOCSPTLCK`: the slave cannot be opened while locked.
    locked: bool,
    /// Owner, group and permissions of the slave device node (`grantpt` sets them).
    uid: u32,
    gid: u32,
    mode: u32,
    /// Hang-ups so far (`vhangup`): slave slots opened before the last one are dead.
    hangups: u64,
    rm: VecDeque<RWait>,
    rs: VecDeque<RWait>,
    ws: VecDeque<WWait>,
}

/// What a slot is.
#[derive(Clone, Copy, Debug)]
struct Slot {
    pair: u64,
    master: bool,
    /// The pair's hang-up count when it was opened.
    gen: u64,
}

/// The console terminal: its line discipline and who holds it.
pub struct Console {
    pub tty: Tty,
    /// The kernel's attach generation.
    pub gen: u64,
    /// The console's size, the default `TIOCGWINSZ`.
    pub cols: u16,
    pub rows: u16,
    readers: VecDeque<RWait>,
    /// What the kernel was last told ([`Io::cons_ready`]).
    told: Option<(u64, bool)>,
}

/// Every terminal.
pub struct Ttys {
    pairs: BTreeMap<u64, Pair>,
    /// Slave number -> pair, while the master is open.
    live: BTreeMap<u32, u64>,
    slots: BTreeMap<u32, Slot>,
    next: u64,
    pub console: Console,
}

impl Default for Ttys {
    fn default() -> Self {
        Self::new()
    }
}

/// The signals to post for one input batch: each distinct signal once, in their order (a
/// write of a million ^C posts one SIGINT, not a million).
pub fn distinct(signals: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    for &s in signals {
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
}

/// `peek` + deliver + commit for the readers of a terminal: each waiting reader takes what
/// a `read` of its size would; one whose memory is gone is dropped.
fn feed_tty_readers(tty: &mut Tty, readers: &mut VecDeque<RWait>, io: &mut dyn Io) -> bool {
    let mut any = false;
    while tty.has_input() {
        let Some(w) = readers.front().cloned() else { break };
        let Some((bytes, used)) = ldisc::peek_input(tty, w.iov.total()) else { break };
        readers.pop_front();
        match io.put(w.id, &w.iov, &bytes) {
            Ok(()) => {
                ldisc::commit(tty, used);
                io.complete(w.id, bytes.len() as i64);
                any = true;
            }
            Err(e) => io.complete(w.id, e),
        }
    }
    any
}

impl Ttys {
    /// No terminals; the console detached.
    pub const fn new() -> Self {
        Self {
            pairs: BTreeMap::new(),
            live: BTreeMap::new(),
            slots: BTreeMap::new(),
            next: 1,
            console: Console { tty: Tty::new(), gen: 0, cols: 80, rows: 25, readers: VecDeque::new(), told: None },
        }
    }

    /// Live pairs (for tests and the log).
    pub fn pair_count(&self) -> usize {
        self.pairs.len()
    }

    /// Pty reads and writes waiting now, all pairs together.
    fn pty_waiters(&self) -> usize {
        self.pairs.values().map(|p| p.rm.len() + p.rs.len() + p.ws.len()).sum()
    }

    /// Whether `slot` is one of ours.
    pub fn has_slot(&self, slot: u32) -> bool {
        self.slots.contains_key(&slot)
    }

    /// Sets the readiness words of every slot of pair `pid` (`arrived_m`/`arrived_s`: new
    /// bytes for the master / the slave side).
    fn publish(&self, pid: u64, arrived_m: bool, arrived_s: bool, io: &mut dyn Io) {
        let Some(p) = self.pairs.get(&pid) else { return };
        if let Some(m) = p.master {
            let mut ev = POLLOUT;
            if !p.to_master.is_empty() {
                ev |= POLLIN;
            }
            if p.slave_opened && p.slaves.is_empty() {
                ev |= POLLHUP;
            }
            io.ready(m, ev, arrived_m);
        }
        for &s in &p.slaves {
            let hung = self.slots.get(&s).is_some_and(|sl| sl.gen != p.hangups);
            let mut ev = if p.to_master.len() < OUTPUT_LIMIT { POLLOUT } else { 0 };
            if p.tty.has_input() {
                ev |= POLLIN;
            }
            if p.master.is_none() {
                ev |= POLLHUP;
            }
            if hung {
                ev |= POLLIN | POLLHUP;
            }
            io.ready(s, ev, arrived_s);
        }
    }

    /// Hands what waits to the waiting readers and writers of pair `pid`, then publishes.
    fn settle(&mut self, pid: u64, io: &mut dyn Io) {
        self.settle_with(pid, false, io);
    }

    /// [`Ttys::settle`]; `input`: new input came for the slave (an edge for its pollers).
    fn settle_with(&mut self, pid: u64, input: bool, io: &mut dyn Io) {
        let mut arrived_m = false;
        let mut arrived_s = input;
        if let Some(p) = self.pairs.get_mut(&pid) {
            // Slave readers take lines (or bytes) from the line discipline
            arrived_s |= feed_tty_readers(&mut p.tty, &mut p.rs, io);
            // Slave writers whose output now fits
            while p.to_master.len() < OUTPUT_LIMIT {
                let Some(w) = p.ws.pop_front() else { break };
                let mut out = Vec::with_capacity(w.data.len() + 8);
                ldisc::process_output(&p.tty, &w.data, &mut out);
                p.to_master.extend(out);
                io.complete(w.id, w.data.len() as i64);
                arrived_m = true;
            }
            // Master readers take slave output
            while !p.to_master.is_empty() {
                let Some(w) = p.rm.pop_front() else { break };
                let n = w.iov.total().min(p.to_master.len());
                let bytes: Vec<u8> = p.to_master.iter().take(n).copied().collect();
                match io.put(w.id, &w.iov, &bytes) {
                    Ok(()) => {
                        p.to_master.drain(..n);
                        io.complete(w.id, n as i64);
                    }
                    Err(e) => io.complete(w.id, e),
                }
            }
            // Writers again (the master readers made room)
            while p.to_master.len() < OUTPUT_LIMIT && !p.ws.is_empty() {
                let w = p.ws.pop_front().unwrap();
                let mut out = Vec::with_capacity(w.data.len() + 8);
                ldisc::process_output(&p.tty, &w.data, &mut out);
                p.to_master.extend(out);
                io.complete(w.id, w.data.len() as i64);
                arrived_m = true;
            }
            if !p.to_master.is_empty() && p.master.is_some() {
                arrived_m = true;
            }
        }
        self.publish(pid, arrived_m, arrived_s, io);
    }

    /// The pair of `/dev/pts/index` while its master is open.
    fn live_pair(&self, index: u32) -> Option<u64> {
        self.live.get(&index).copied()
    }

    /// The pair that is session `sid`'s controlling terminal.
    fn controlling(&self, sid: u64) -> Option<u64> {
        if sid == 0 {
            return None;
        }
        self.pairs.iter().find(|(_, p)| p.tty.session == sid).map(|(&id, _)| id)
    }

    /// Whether session `sid` has a controlling terminal (one of the pairs, or the console).
    fn has_controlling(&self, sid: u64) -> bool {
        sid != 0 && (self.console.tty.session == sid || self.controlling(sid).is_some())
    }

    // ------------------------------------------------------------------
    // Opening
    // ------------------------------------------------------------------

    /// Opens `/dev/ptmx` as slot `slot` for a caller of effective user `uid`: a new pair
    /// (the lowest free number); returns the slave's number (`ENOSPC` past [`MAX_PTYS`]).
    pub fn open_master(&mut self, slot: u32, uid: u32, io: &mut dyn Io) -> Result<u32, i64> {
        // (a number stays taken while any end of its pair is open, as Linux's devpts keeps it:
        // `ttyname` of an old slave never names a new pair)
        let taken: BTreeSet<u32> = self.pairs.values().map(|p| p.index).collect();
        let index = (0..MAX_PTYS).find(|i| !taken.contains(i)).ok_or(ENOSPC)?;
        let id = self.next;
        self.next += 1;
        self.pairs.insert(
            id,
            Pair {
                index,
                tty: Tty::new(),
                to_master: VecDeque::new(),
                master: Some(slot),
                slaves: BTreeSet::new(),
                slave_opened: false,
                locked: true,
                uid,
                gid: 5, // tty
                mode: 0o620,
                hangups: 0,
                rm: VecDeque::new(),
                rs: VecDeque::new(),
                ws: VecDeque::new(),
            },
        );
        self.live.insert(index, id);
        self.slots.insert(slot, Slot { pair: id, master: true, gen: 0 });
        self.publish(id, false, false, io);
        Ok(index)
    }

    /// Opens the slave of pair `pid` as slot `slot`; a session leader without a controlling
    /// terminal acquires it unless `noctty`. Returns the node's `(mode, uid, gid)`.
    fn open_slave_of(&mut self, pid: u64, slot: u32, noctty: bool, who: &Caller, io: &mut dyn Io) -> Result<(u32, u32, u32), i64> {
        self.open_slave_x(pid, slot, noctty, false, who, io)
    }

    /// [`Ttys::open_slave_of`]; `reopen`: `/dev/tty` naming the caller's own terminal (the
    /// slave lock is for opening by name only).
    fn open_slave_x(&mut self, pid: u64, slot: u32, noctty: bool, reopen: bool, who: &Caller, io: &mut dyn Io) -> Result<(u32, u32, u32), i64> {
        let acquire = !noctty && who.sid != 0 && who.sid == who.tgid && !self.has_controlling(who.sid);
        let p = self.pairs.get_mut(&pid).ok_or(ENOENT)?;
        if (p.locked && !reopen) || p.master.is_none() {
            return Err(EIO);
        }
        p.slaves.insert(slot);
        p.slave_opened = true;
        if acquire && p.tty.session == 0 {
            p.tty.session = who.sid;
            p.tty.fg_pgrp = who.pgid;
        }
        let gen = p.hangups;
        let r = (0o020000 | p.mode, p.uid, p.gid);
        self.slots.insert(slot, Slot { pair: pid, master: false, gen });
        self.publish(pid, false, false, io);
        Ok(r)
    }

    /// Opens `/dev/pts/index` as slot `slot`: the node's `(mode, uid, gid)`. `want` is the
    /// access asked for (4 read, 2 write) and `in_group` says whether the caller is in a group;
    /// the node's owner, group and mode decide (root may always), as for any device node.
    pub fn open_slave(&mut self, index: u32, slot: u32, noctty: bool, want: u32, who: &Caller, in_group: &dyn Fn(u32) -> bool, io: &mut dyn Io) -> Result<(u32, u32, u32), i64> {
        let pid = self.live_pair(index).ok_or(ENOENT)?;
        let p = self.pairs.get(&pid).ok_or(ENOENT)?;
        if !may_open(p.mode, p.uid, p.gid, want, who.euid, in_group) {
            return Err(EACCES);
        }
        self.open_slave_of(pid, slot, noctty, who, io)
    }

    /// Opens `/dev/tty` as slot `slot` for a caller whose controlling terminal is one of our
    /// pairs: its slave's number and `(mode, uid, gid)`. `None`: not one of ours.
    pub fn open_controlling(&mut self, slot: u32, who: &Caller, io: &mut dyn Io) -> Option<Result<(u32, (u32, u32, u32)), i64>> {
        let pid = self.controlling(who.sid)?;
        let index = self.pairs.get(&pid)?.index;
        Some(self.open_slave_x(pid, slot, true, true, who, io).map(|n| (index, n)))
    }

    /// `TIOCGPTPEER` on master slot `master`: opens its slave as slot `slot` (no controlling
    /// terminal); the slave's number and `(mode, uid, gid)`.
    pub fn open_peer(&mut self, master: u32, slot: u32, who: &Caller, io: &mut dyn Io) -> Result<(u32, (u32, u32, u32)), i64> {
        let s = *self.slots.get(&master).ok_or(EBADF)?;
        if !s.master {
            return Err(ENOTTY);
        }
        let index = self.pairs.get(&s.pair).ok_or(EBADF)?.index;
        self.open_slave_of(s.pair, slot, true, who, io).map(|n| (index, n))
    }

    // ------------------------------------------------------------------
    // Calls on an end
    // ------------------------------------------------------------------

    /// `read` (or `readv`) on slot `slot` into `iov` of request `id`.
    pub fn read(&mut self, slot: u32, id: u64, tgid: u64, iov: Iov, nonblock: bool, io: &mut dyn Io) -> Ans {
        let Some(s) = self.slots.get(&slot).copied() else { return Ans::Now(EBADF) };
        let total = iov.total();
        let Some(p) = self.pairs.get_mut(&s.pair) else { return Ans::Now(EBADF) };
        if total == 0 {
            return Ans::Now(0);
        }
        if s.master {
            if !p.to_master.is_empty() {
                let n = total.min(p.to_master.len());
                let bytes: Vec<u8> = p.to_master.iter().take(n).copied().collect();
                if let Err(e) = io.put(id, &iov, &bytes) {
                    return Ans::Now(e);
                }
                p.to_master.drain(..n);
                self.settle(s.pair, io); // room for slave writers
                return Ans::Now(n as i64);
            }
            if p.slave_opened && p.slaves.is_empty() {
                return Ans::Now(EIO);
            }
            if nonblock {
                return Ans::Now(EAGAIN);
            }
            let full = self.pty_waiters() >= MAX_PTY_WAITERS;
            let Some(p) = self.pairs.get_mut(&s.pair) else { return Ans::Now(EBADF) };
            if full {
                return Ans::Now(EAGAIN);
            }
            p.rm.push_back(RWait { id, tgid, iov });
            return Ans::Pending;
        }
        if s.gen != p.hangups {
            return Ans::Now(0);
        }
        if let Some((bytes, used)) = ldisc::peek_input(&p.tty, total) {
            if let Err(e) = io.put(id, &iov, &bytes) {
                return Ans::Now(e);
            }
            ldisc::commit(&mut p.tty, used);
            self.publish(s.pair, false, false, io);
            return Ans::Now(bytes.len() as i64);
        }
        if p.master.is_none() {
            return Ans::Now(0);
        }
        if nonblock {
            return Ans::Now(EAGAIN);
        }
        let full = self.pty_waiters() >= MAX_PTY_WAITERS;
        let Some(p) = self.pairs.get_mut(&s.pair) else { return Ans::Now(EBADF) };
        if full {
            return Ans::Now(EAGAIN);
        }
        p.rs.push_back(RWait { id, tgid, iov });
        Ans::Pending
    }

    /// `write` (or `writev`) of `data` on slot `slot` by request `id`.
    pub fn write(&mut self, slot: u32, id: u64, tgid: u64, data: Vec<u8>, nonblock: bool, io: &mut dyn Io) -> Ans {
        let Some(s) = self.slots.get(&slot).copied() else { return Ans::Now(EBADF) };
        let Some(p) = self.pairs.get_mut(&s.pair) else { return Ans::Now(EBADF) };
        if s.master {
            // Input for the slave's line discipline: echo goes back to the master, ISIG
            // characters signal the slave's foreground group
            let mut echo = Vec::new();
            let mut signals = Vec::new();
            ldisc::feed_input(&mut p.tty, &data, &mut echo, &mut signals);
            // The echo is bounded like the slave's output (Linux drops echo when the output
            // buffer is full): a writer nobody reads cannot grow it without end
            let room = OUTPUT_LIMIT.saturating_sub(p.to_master.len());
            p.to_master.extend(echo.into_iter().take(room));
            let (fg, sess) = (p.tty.fg_pgrp, p.tty.session);
            if fg != 0 && sess != 0 {
                for sig in distinct(&signals) {
                    io.signal_group(fg, sess, sig);
                }
            }
            let input = p.tty.has_input();
            self.settle_with(s.pair, input, io);
            return Ans::Now(data.len() as i64);
        }
        if s.gen != p.hangups || p.master.is_none() {
            return Ans::Now(EIO);
        }
        if data.is_empty() {
            return Ans::Now(0);
        }
        if p.to_master.len() < OUTPUT_LIMIT && p.ws.is_empty() {
            let mut out = Vec::with_capacity(data.len() + 8);
            ldisc::process_output(&p.tty, &data, &mut out);
            p.to_master.extend(out);
            self.settle(s.pair, io);
            return Ans::Now(data.len() as i64);
        }
        if nonblock {
            return Ans::Now(EAGAIN);
        }
        let full = self.pty_waiters() >= MAX_PTY_WAITERS;
        let Some(p) = self.pairs.get_mut(&s.pair) else { return Ans::Now(EBADF) };
        if full {
            return Ans::Now(EAGAIN);
        }
        p.ws.push_back(WWait { id, tgid, data });
        Ans::Pending
    }

    /// An `ioctl` on slot `slot`. `Err(flags)`: `TIOCGPTPEER` with these flags (the caller
    /// allocates a slot, calls [`Ttys::open_peer`] and installs it).
    pub fn ioctl(&mut self, slot: u32, request: u64, arg: u64, who: &Caller, mem: &dyn Mem, io: &mut dyn Io) -> Result<i64, u32> {
        let Some(s) = self.slots.get(&slot).copied() else { return Ok(EBADF) };
        let pid = s.pair;
        // (TIOCSCTTY's rules need the other terminals: decided before the pair is borrowed)
        let caller_has_other = who.sid != 0 && self.has_controlling(who.sid) && self.controlling(who.sid) != Some(pid);
        let Some(p) = self.pairs.get_mut(&pid) else { return Ok(EBADF) };
        if !s.master && s.gen != p.hangups {
            // A descriptor from before a vhangup is dead (Linux: EIO)
            return Ok(EIO);
        }
        let put32 = |v: u32| mem.put(arg, &v.to_le_bytes()).map_or_else(|e| e, |()| 0);
        let r = match request {
            TIOCGPTN if s.master => put32(p.index),
            TIOCSPTLCK if s.master => match mem.get(arg, 4) {
                Ok(b) => {
                    p.locked = u32::from_le_bytes([b[0], b[1], b[2], b[3]]) != 0;
                    0
                }
                Err(e) => e,
            },
            TIOCGPTLCK if s.master => put32(p.locked as u32),
            TIOCGPTPEER if s.master => return Err(arg as u32),
            TIOCPKT if s.master => match mem.get(arg, 4) {
                // Packet mode is not supported; turning it off is fine
                Ok(b) if b == [0, 0, 0, 0] => 0,
                Ok(_) => EINVAL,
                Err(e) => e,
            },
            // FIONREAD on the master: output the slave wrote that waits to be read
            ldisc::FIONREAD if s.master => put32(p.to_master.len().min(i32::MAX as usize) as u32),
            ldisc::TIOCSCTTY => {
                // Linux: only a session leader without a controlling terminal; a terminal
                // another session holds only by force (arg 1) and as root
                if p.tty.session != 0 && p.tty.session == who.sid {
                    0
                } else if who.sid == 0 || who.sid != who.tgid || caller_has_other {
                    EPERM
                } else if p.tty.session != 0 && !(arg == 1 && who.euid == 0) {
                    EPERM
                } else {
                    p.tty.session = who.sid;
                    p.tty.fg_pgrp = who.pgid;
                    0
                }
            }
            ldisc::TCFLSH if arg == 1 || arg == 2 => {
                // The output queue is the slave's output waiting for the master
                p.to_master.clear();
                if arg == 2 {
                    p.tty.ready.clear();
                    p.tty.line.clear();
                }
                self.settle(pid, io);
                0
            }
            ldisc::TIOCSPGRP => {
                // Linux: the terminal must be the caller's controlling terminal and the group
                // one of its session's (a terminal no session holds is nobody's: ENOTTY)
                let sess = p.tty.session;
                if sess == 0 || who.sid != sess {
                    ENOTTY
                } else {
                    match mem.get(arg, 4) {
                        Ok(b) => {
                            let pg = i32::from_le_bytes([b[0], b[1], b[2], b[3]]);
                            if pg < 0 {
                                EINVAL
                            } else {
                                match io.pgrp_in(pg as u64, sess) {
                                    0 => {
                                        p.tty.fg_pgrp = pg as u64;
                                        0
                                    }
                                    1 => EPERM,
                                    e => e,
                                }
                            }
                        }
                        Err(e) => e,
                    }
                }
            }
            _ => {
                let mut fx = Effects::default();
                let r = ldisc::ioctl(&mut p.tty, request, arg, mem, (24, 80), &mut fx);
                if fx.resized && p.tty.fg_pgrp != 0 && p.tty.session != 0 {
                    io.signal_group(p.tty.fg_pgrp, p.tty.session, ldisc::SIGWINCH);
                }
                if r == 0 {
                    // Mode changes (leaving canonical mode, a flush) may make input readable
                    self.settle(pid, io);
                }
                r
            }
        };
        Ok(r)
    }

    /// The last descriptor of slot `slot` went (`LX_NOTE_CLOSE`).
    pub fn closed(&mut self, slot: u32, io: &mut dyn Io) {
        let Some(s) = self.slots.remove(&slot) else { return };
        let pid = s.pair;
        let Some(p) = self.pairs.get_mut(&pid) else { return };
        if s.master {
            p.master = None;
            if self.live.get(&p.index) == Some(&pid) {
                self.live.remove(&p.index);
            }
            // Slave readers see end-of-file, writers EIO
            for w in p.rs.drain(..) {
                io.complete(w.id, 0);
            }
            for w in p.ws.drain(..) {
                io.complete(w.id, EIO);
            }
            for w in p.rm.drain(..) {
                io.complete(w.id, EIO);
            }
            p.to_master.clear();
            // The hang-up Linux sends: the session leader gets SIGHUP and SIGCONT, the
            // foreground group SIGHUP; the session loses its terminal
            let (sid, fg) = (p.tty.session, p.tty.fg_pgrp);
            p.tty.session = 0;
            p.tty.fg_pgrp = 0;
            if sid != 0 {
                io.signal_proc(sid, SIGHUP);
                io.signal_proc(sid, SIGCONT);
                if fg != 0 {
                    io.signal_group(fg, sid, SIGHUP);
                }
            }
        } else {
            p.slaves.remove(&slot);
            if p.slaves.is_empty() && p.slave_opened {
                for w in p.rm.drain(..) {
                    io.complete(w.id, EIO);
                }
            }
        }
        if p.master.is_none() && p.slaves.is_empty() {
            self.pairs.remove(&pid);
        } else {
            self.publish(pid, false, false, io);
        }
    }

    /// Request `id` was interrupted by a signal: a waiting call ends with `ERESTARTSYS`.
    pub fn interrupt(&mut self, id: u64, io: &mut dyn Io) -> bool {
        for p in self.pairs.values_mut() {
            for q in [&mut p.rm, &mut p.rs] {
                if let Some(i) = q.iter().position(|w| w.id == id) {
                    q.remove(i);
                    io.complete(id, ERESTARTSYS);
                    return true;
                }
            }
            if let Some(i) = p.ws.iter().position(|w| w.id == id) {
                p.ws.remove(i);
                io.complete(id, ERESTARTSYS);
                return true;
            }
        }
        if let Some(i) = self.console.readers.iter().position(|w| w.id == id) {
            self.console.readers.remove(i);
            io.complete(id, ERESTARTSYS);
            return true;
        }
        false
    }

    /// Process `tgid` ended (`LX_NOTE_EXIT`): its waiting calls are gone, and a terminal
    /// whose session it led has no session any more.
    pub fn exited(&mut self, tgid: u64) {
        for p in self.pairs.values_mut() {
            p.rm.retain(|w| w.tgid != tgid);
            p.rs.retain(|w| w.tgid != tgid);
            p.ws.retain(|w| w.tgid != tgid);
            if p.tty.session == tgid {
                p.tty.session = 0;
                p.tty.fg_pgrp = 0;
            }
        }
        self.console.readers.retain(|w| w.tgid != tgid);
    }

    /// `(mode, uid, gid)` of `/dev/pts/index`.
    pub fn stat(&self, index: u32) -> Option<(u32, u32, u32)> {
        let p = self.pairs.get(&self.live_pair(index)?)?;
        Some((p.mode, p.uid, p.gid))
    }

    /// `chmod`/`chown` of `/dev/pts/index` by effective user `euid` (the owner may change
    /// the mode and group; only root may give the node away).
    pub fn setattr(&mut self, index: u32, euid: u32, mode: Option<u32>, uid: Option<u32>, gid: Option<u32>, in_group: &dyn Fn(u32) -> bool) -> i64 {
        let Some(pid) = self.live_pair(index) else { return ENOENT };
        let Some(p) = self.pairs.get_mut(&pid) else { return ENOENT };
        let owner = euid == 0 || euid == p.uid;
        if !owner || (euid != 0 && uid.is_some_and(|u| u != p.uid)) {
            return EPERM;
        }
        // (Linux: the owner may give the node only to a group it is in)
        if euid != 0 && gid.is_some_and(|g| g != p.gid && !in_group(g)) {
            return EPERM;
        }
        if let Some(m) = mode {
            p.mode = m & 0o7777;
        }
        if let Some(u) = uid {
            p.uid = u;
        }
        if let Some(g) = gid {
            p.gid = g;
        }
        0
    }

    /// `vhangup` of session `sid`'s terminal: the session loses it and earlier slave
    /// descriptors are dead. `(foreground group, leader)` to signal.
    pub fn hangup(&mut self, sid: u64, io: &mut dyn Io) -> Option<(u64, u64)> {
        let pid = self.controlling(sid)?;
        let p = self.pairs.get_mut(&pid)?;
        let fg = p.tty.fg_pgrp;
        p.tty.session = 0;
        p.tty.fg_pgrp = 0;
        p.tty.line.clear();
        p.tty.ready.clear();
        p.hangups += 1;
        for w in p.rs.drain(..) {
            io.complete(w.id, 0);
        }
        for w in p.ws.drain(..) {
            io.complete(w.id, EIO);
        }
        self.publish(pid, false, true, io);
        Some((fg, sid))
    }

    // ------------------------------------------------------------------
    // The console terminal
    // ------------------------------------------------------------------

    /// Tells the kernel the console's readiness if it changed.
    fn cons_publish(&mut self, io: &mut dyn Io) {
        let now = (self.console.gen, self.console.tty.has_input());
        if self.console.told != Some(now) {
            self.console.told = Some(now);
            io.cons_ready(now.0, now.1);
        }
    }

    /// The kernel's console state (from the console thread, or carried by a console call): a
    /// newer attach generation resets the terminal (a new program owns it) and ends the
    /// readers of the previous one; an older one changes nothing (generations only grow, and
    /// a program's first call may arrive before the console thread saw its attach).
    pub fn cons_state(&mut self, gen: u64, sid: u64, pgrp: u64, cols: u16, rows: u16, io: &mut dyn Io) {
        let c = &mut self.console;
        if cols != 0 && rows != 0 {
            c.cols = cols;
            c.rows = rows;
        }
        if gen <= c.gen {
            return;
        }
        c.gen = gen;
        if sid != 0 {
            c.tty.reset();
        } else {
            c.tty.line.clear();
            c.tty.ready.clear();
        }
        c.tty.session = sid;
        c.tty.fg_pgrp = pgrp;
        for w in c.readers.drain(..) {
            io.complete(w.id, EIO);
        }
        self.cons_publish(io);
    }

    /// Console keys (encoded as the kernel gives them) typed in attach generation `gen`:
    /// through the line discipline, echo to the console, `ISIG` signals to the foreground
    /// group, bytes to the readers. Keys of another generation are dropped.
    pub fn cons_keys(&mut self, gen: u64, keys: &[u32], io: &mut dyn Io) {
        let c = &mut self.console;
        if c.tty.session == 0 || keys.is_empty() || gen != c.gen {
            return;
        }
        let mut echo = Vec::new();
        let mut signals = Vec::new();
        for &k in keys {
            ldisc::feed_input(&mut c.tty, &ldisc::key_bytes(k), &mut echo, &mut signals);
        }
        if !echo.is_empty() {
            io.cons_out(&echo);
        }
        let fg = c.tty.fg_pgrp;
        if fg != 0 {
            for sig in distinct(&signals) {
                io.signal_group(fg, c.tty.session, sig);
            }
        }
        feed_tty_readers(&mut c.tty, &mut c.readers, io);
        self.cons_publish(io);
    }

    /// `read` of the console terminal by request `id` (`who`: the caller, from the call's
    /// header). `Ans::Now(LX_TTY_BGREAD)`: a background reader (the kernel stops it).
    pub fn cons_read(&mut self, id: u64, who: &Caller, iov: Iov, nonblock: bool, bgread: i64, io: &mut dyn Io) -> Ans {
        let c = &mut self.console;
        if iov.total() == 0 {
            return Ans::Now(0);
        }
        let (sid, fg) = (c.tty.session, c.tty.fg_pgrp);
        if sid != 0 && who.sid == sid && fg != 0 && who.pgid != fg {
            return Ans::Now(bgread);
        }
        if let Some((bytes, used)) = ldisc::peek_input(&c.tty, iov.total()) {
            if let Err(e) = io.put(id, &iov, &bytes) {
                return Ans::Now(e);
            }
            ldisc::commit(&mut c.tty, used);
            self.cons_publish(io);
            return Ans::Now(bytes.len() as i64);
        }
        if nonblock {
            return Ans::Now(EAGAIN);
        }
        if c.readers.len() >= MAX_CONSOLE_WAITERS {
            return Ans::Now(EIO);
        }
        c.readers.push_back(RWait { id, tgid: who.tgid, iov });
        Ans::Pending
    }

    /// `write` of `data` to the console terminal: output processing, then the console.
    pub fn cons_write(&mut self, data: &[u8], io: &mut dyn Io) -> i64 {
        let mut out = Vec::with_capacity(data.len() + 8);
        ldisc::process_output(&self.console.tty, data, &mut out);
        io.cons_out(&out);
        data.len() as i64
    }

    /// A terminal `ioctl` on the console by `who` (the VT requests stay the kernel's).
    pub fn cons_ioctl(&mut self, request: u64, arg: u64, who: &Caller, mem: &dyn Mem, io: &mut dyn Io) -> i64 {
        let c = &mut self.console;
        if ldisc::canonical_request(request) == ldisc::TIOCSPGRP {
            // Linux's rules (as on a pty): the console must be the caller's controlling
            // terminal and the group one of its session's
            let sess = c.tty.session;
            if sess == 0 || who.sid != sess {
                return ENOTTY;
            }
            return match mem.get(arg, 4) {
                Ok(b) => match i32::from_le_bytes([b[0], b[1], b[2], b[3]]) {
                    pg if pg < 0 => EINVAL,
                    pg => match io.pgrp_in(pg as u64, sess) {
                        0 => {
                            c.tty.fg_pgrp = pg as u64;
                            0
                        }
                        1 => EPERM,
                        e => e,
                    },
                },
                Err(e) => e,
            };
        }
        let size = (c.rows, c.cols);
        let mut fx = Effects::default();
        let r = ldisc::ioctl(&mut c.tty, request, arg, mem, size, &mut fx);
        if r == 0 && fx.input_changed {
            feed_tty_readers(&mut c.tty, &mut c.readers, io);
            self.cons_publish(io);
        }
        r
    }
}

/// Whether a caller of effective user `euid` may open a node of `mode`, `uid`, `gid` for `want`
/// (4 read, 2 write, both 6): root always; else the owner's, group's or others' bits.
pub fn may_open(mode: u32, uid: u32, gid: u32, want: u32, euid: u32, in_group: &dyn Fn(u32) -> bool) -> bool {
    if euid == 0 {
        return true;
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
