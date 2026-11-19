//! The key retention service (`add_key`, `request_key`, `keyctl`), moved out of the kernel
//! (wave 3, step 1: the Linux server's first tenant). It is the kernel's
//! `src/compat/linux/keys.rs` with the kernel's internals replaced: the caller's identity
//! comes with the call ([`Cx`]), its memory is reached through the client memory
//! primitives, and processes ending, forking and exec'ing are notifications
//! ([`on_exit`], [`on_fork`], [`on_exec`]). The in-kernel copy stays until a later step
//! deletes it (QEMU fw_cfg `opt/hydra/lx=kernel` switches back to it).
//!
//! Keys live in one table indexed by serial number. Keyrings are keys whose payload is
//! a list of linked serials. Each thread, process and session can have a keyring, each
//! user has a user keyring and a user-session keyring, and a key is "possessed" when it
//! is reachable from the caller's thread, process or session keyring. Keys no longer
//! reachable from any anchor are collected when keys are unlinked or processes go away.
//!
//! There is no upcall: `request_key` finds existing keys only (`ENOKEY` otherwise).

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use crate::client::{Caller, Cx};
use crate::lock::YLock as Mutex;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EDEADLK: i64 = -35;
const EOPNOTSUPP: i64 = -95;
const EDQUOT: i64 = -122;
const ENOKEY: i64 = -126;
const EKEYEXPIRED: i64 = -127;
const EKEYREVOKED: i64 = -128;

// Special keyring IDs
const THREAD: i32 = -1;
const PROCESS: i32 = -2;
const SESSION: i32 = -3;
const USER: i32 = -4;
const USER_SESSION: i32 = -5;
const GROUP: i32 = -6;
const REQKEY_AUTH: i32 = -7;
const REQUESTOR: i32 = -8;

// Permission bits (per class: view read write search link setattr)
const VIEW: u32 = 0x01;
const READ: u32 = 0x02;
const WRITE: u32 = 0x04;
const SEARCH: u32 = 0x08;
const LINK: u32 = 0x10;
const SETATTR: u32 = 0x20;
const ALL: u32 = 0x3f;
const POS: u32 = 24;
const USR: u32 = 16;
const GRP: u32 = 8;

/// Default permissions of a key made by `add_key` (possessor all, user view)
const DEFAULT_PERM: u32 = (ALL << POS) | (VIEW << USR);

const MAX_KEYS_USER: usize = 200;
const MAX_BYTES_USER: usize = 20_000;
const MAX_KEYS_ROOT: usize = 1_000_000;
const MAX_BYTES_ROOT: usize = 25_000_000;
const MAX_DEPTH: usize = 6;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Type {
    User,
    Logon,
    BigKey,
    Keyring,
}

impl Type {
    fn parse(name: &[u8]) -> Result<Type, i64> {
        Ok(match name {
            b"user" => Type::User,
            b"logon" => Type::Logon,
            b"big_key" => Type::BigKey,
            b"keyring" => Type::Keyring,
            b"" => return Err(EINVAL),
            n if n.starts_with(b".") => return Err(EPERM),
            _ => return Err(ENODEV),
        })
    }

    fn name(self) -> &'static str {
        match self {
            Type::User => "user",
            Type::Logon => "logon",
            Type::BigKey => "big_key",
            Type::Keyring => "keyring",
        }
    }

    fn max_payload(self) -> usize {
        match self {
            Type::User | Type::Logon => 32767,
            Type::BigKey => 1 << 20,
            Type::Keyring => 0,
        }
    }
}

struct Key {
    ktype: Type,
    desc: String,
    payload: Vec<u8>,
    /// Linked keys (keyrings only)
    ring: Vec<i32>,
    uid: u32,
    gid: u32,
    perm: u32,
    /// Expiry in uptime milliseconds
    expiry: Option<u64>,
    revoked: bool,
    invalid: bool,
}

impl Key {
    fn new(ktype: Type, desc: String, uid: u32, gid: u32, perm: u32) -> Key {
        Key { ktype, desc, payload: Vec::new(), ring: Vec::new(), uid, gid, perm, expiry: None, revoked: false, invalid: false }
    }

    fn usable(&self, now: u64) -> Result<(), i64> {
        if self.revoked {
            Err(EKEYREVOKED)
        } else if self.invalid {
            Err(ENOKEY)
        } else if self.expiry.map_or(false, |e| now >= e) {
            Err(EKEYEXPIRED)
        } else {
            Ok(())
        }
    }

    fn size(&self) -> usize {
        self.desc.len() + 1 + self.payload.len()
    }
}

struct Keys {
    keys: BTreeMap<i32, Key>,
    next: u32,
    /// Thread keyrings: tid -> (tgid, keyring)
    thread: BTreeMap<u64, (u64, i32)>,
    /// Process keyrings by tgid
    process: BTreeMap<u64, i32>,
    /// Session keyrings by tgid (inherited on fork)
    session: BTreeMap<u64, i32>,
    /// Default destination of request_key, by tid
    reqkey_dest: BTreeMap<u64, i32>,
    /// User and user-session keyrings by uid
    user: BTreeMap<u32, (i32, i32)>,
    /// Persistent keyrings by uid
    persistent: BTreeMap<u32, i32>,
    /// Changed since the kept copy was last written ([`KGuard`] writes it when the lock goes).
    dirty: bool,
}

static KEYS: KeysLock = KeysLock(Mutex::new(Keys {
    keys: BTreeMap::new(),
    next: 0,
    thread: BTreeMap::new(),
    process: BTreeMap::new(),
    session: BTreeMap::new(),
    reqkey_dest: BTreeMap::new(),
    user: BTreeMap::new(),
    persistent: BTreeMap::new(),
    dirty: false,
}));

/// The key table's lock: a guard whose table changed writes the kept copy when it goes, so
/// every answer and every notification leaves the keyrings kept (keys restart invisibly,
/// `docs/linux-services-design.md` 2.1).
struct KeysLock(Mutex<Keys>);

struct KGuard<'a>(crate::lock::YGuard<'a, Keys>);

impl KeysLock {
    fn lock(&self) -> KGuard<'_> {
        KGuard(self.0.lock())
    }
}

impl core::ops::Deref for KGuard<'_> {
    type Target = Keys;
    fn deref(&self) -> &Keys {
        &self.0
    }
}

impl core::ops::DerefMut for KGuard<'_> {
    fn deref_mut(&mut self) -> &mut Keys {
        &mut self.0
    }
}

impl Drop for KGuard<'_> {
    fn drop(&mut self) {
        if self.0.dirty {
            self.0.dirty = false;
            persist(&self.0);
        }
    }
}

/// Key writes to the kept copy that did not fit (the copy then stays at the last that did).
static KEPT_FULL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Writes the table to the kept object (when there is one).
fn persist(ks: &Keys) {
    let Some(k) = crate::kept::get() else { return };
    let data = encode(ks);
    if !k.write(crate::kept::KEYS, &data) && KEPT_FULL.fetch_add(1, core::sync::atomic::Ordering::Relaxed) == 0 {
        hydra_rt::println!("[lx-sec] keys: {} bytes do not fit the kept state; a restart would lose the newest keys", data.len());
    }
}

fn encode(ks: &Keys) -> Vec<u8> {
    let mut e = crate::kept::Enc::default();
    e.u32(ks.next);
    e.u32(ks.keys.len() as u32);
    for (&s, k) in &ks.keys {
        e.i32(s);
        e.u8(match k.ktype {
            Type::User => 0,
            Type::Logon => 1,
            Type::BigKey => 2,
            Type::Keyring => 3,
        });
        e.u8(k.revoked as u8 | (k.invalid as u8) << 1 | (k.expiry.is_some() as u8) << 2);
        e.u32(k.uid);
        e.u32(k.gid);
        e.u32(k.perm);
        e.u64(k.expiry.unwrap_or(0));
        e.bytes(k.desc.as_bytes());
        e.bytes(&k.payload);
        e.u32(k.ring.len() as u32);
        for &r in &k.ring {
            e.i32(r);
        }
    }
    e.u32(ks.thread.len() as u32);
    for (&t, &(g, r)) in &ks.thread {
        e.u64(t);
        e.u64(g);
        e.i32(r);
    }
    for m in [&ks.process, &ks.session] {
        e.u32(m.len() as u32);
        for (&g, &r) in m {
            e.u64(g);
            e.i32(r);
        }
    }
    e.u32(ks.reqkey_dest.len() as u32);
    for (&t, &v) in &ks.reqkey_dest {
        e.u64(t);
        e.i32(v);
    }
    e.u32(ks.user.len() as u32);
    for (&u, &(a, b)) in &ks.user {
        e.u32(u);
        e.i32(a);
        e.i32(b);
    }
    e.u32(ks.persistent.len() as u32);
    for (&u, &r) in &ks.persistent {
        e.u32(u);
        e.i32(r);
    }
    e.buf
}

#[allow(dead_code)]
fn decode(b: &[u8]) -> Option<Keys> {
    let mut d = crate::kept::Dec::new(b);
    let mut ks = Keys {
        keys: BTreeMap::new(),
        next: d.u32()?,
        thread: BTreeMap::new(),
        process: BTreeMap::new(),
        session: BTreeMap::new(),
        reqkey_dest: BTreeMap::new(),
        user: BTreeMap::new(),
        persistent: BTreeMap::new(),
        dirty: false,
    };
    for _ in 0..d.u32()? {
        let s = d.i32()?;
        let ktype = match d.u8()? {
            0 => Type::User,
            1 => Type::Logon,
            2 => Type::BigKey,
            3 => Type::Keyring,
            _ => return None,
        };
        let f = d.u8()?;
        let (uid, gid, perm, exp) = (d.u32()?, d.u32()?, d.u32()?, d.u64()?);
        let desc = String::from(core::str::from_utf8(d.bytes()?).ok()?);
        let payload = d.bytes()?.to_vec();
        let n = d.u32()? as usize;
        let mut ring = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            ring.push(d.i32()?);
        }
        let key = Key { ktype, desc, payload, ring, uid, gid, perm, expiry: (f & 4 != 0).then_some(exp), revoked: f & 1 != 0, invalid: f & 2 != 0 };
        ks.keys.insert(s, key);
    }
    for _ in 0..d.u32()? {
        let (t, g, r) = (d.u64()?, d.u64()?, d.i32()?);
        ks.thread.insert(t, (g, r));
    }
    for m in [&mut ks.process, &mut ks.session] {
        for _ in 0..d.u32()? {
            let (g, r) = (d.u64()?, d.i32()?);
            m.insert(g, r);
        }
    }
    for _ in 0..d.u32()? {
        let (t, v) = (d.u64()?, d.i32()?);
        ks.reqkey_dest.insert(t, v);
    }
    for _ in 0..d.u32()? {
        let (u, a, b) = (d.u32()?, d.i32()?, d.i32()?);
        ks.user.insert(u, (a, b));
    }
    for _ in 0..d.u32()? {
        let (u, r) = (d.u32()?, d.i32()?);
        ks.persistent.insert(u, r);
    }
    d.done().then_some(ks)
}

/// A restart: the keyrings the previous instance kept come back. Thread, process and
/// session anchors of processes that ended meanwhile (their exit notification went to the
/// dead instance) go, with the keys only they reached. Returns the number of keys.
#[allow(dead_code)] // lx-sec only (linux-server keeps nothing)
pub fn restore() -> usize {
    let Some(k) = crate::kept::get() else { return 0 };
    let Some(data) = k.read(crate::kept::KEYS) else { return 0 };
    let Some(mut table) = decode(data) else {
        hydra_rt::println!("[lx-sec] keys: the kept copy does not decode; starting without keys");
        k.clear(crate::kept::KEYS);
        return 0;
    };
    let alive = |tgid: u64| hydra_rt::sys::lx_proc_info(tgid).is_ok();
    table.thread.retain(|_, (g, _)| alive(*g));
    table.process.retain(|g, _| alive(*g));
    table.session.retain(|g, _| alive(*g));
    table.reqkey_dest.retain(|t, _| alive(*t));
    table.collect();
    table.dirty = true;
    let n = table.keys.len();
    let mut ks = KEYS.lock();
    *ks = table;
    n
}

fn now() -> u64 {
    crate::client::now_ms()
}

impl Keys {
    /// Key `serial` to change (it must exist): marks the table changed.
    fn km(&mut self, serial: i32) -> &mut Key {
        self.dirty = true;
        self.keys.get_mut(&serial).unwrap()
    }

    fn alloc(&mut self, key: Key) -> i32 {
        self.dirty = true;
        // Serials look random to callers (as on Linux) but are unique and positive
        loop {
            self.next = self.next.wrapping_mul(1_103_515_245).wrapping_add(12_345 + (now() as u32 & 0xff));
            let serial = (self.next & 0x3fff_ffff) as i32 + 3;
            if !self.keys.contains_key(&serial) {
                self.keys.insert(serial, key);
                return serial;
            }
        }
    }

    fn quota_ok(&self, uid: u32, extra: usize) -> bool {
        let (mut n, mut bytes) = (0usize, 0usize);
        for k in self.keys.values().filter(|k| k.uid == uid) {
            n += 1;
            bytes += k.size();
        }
        let (max_n, max_b) = if uid == 0 { (MAX_KEYS_ROOT, MAX_BYTES_ROOT) } else { (MAX_KEYS_USER, MAX_BYTES_USER) };
        n < max_n && bytes + extra <= max_b
    }

    /// Whether key `serial`'s payload may become `new_len` bytes: growth is charged to its
    /// owner's byte quota, as Linux's `key_payload_reserve` (EDQUOT otherwise).
    fn payload_fits(&self, serial: i32, new_len: usize) -> bool {
        let Some(k) = self.keys.get(&serial) else { return false };
        match new_len.checked_sub(k.payload.len()) {
            None | Some(0) => true,
            Some(grow) => {
                let bytes: usize = self.keys.values().filter(|o| o.uid == k.uid).map(|o| o.size()).sum();
                let max_b = if k.uid == 0 { MAX_BYTES_ROOT } else { MAX_BYTES_USER };
                bytes + grow <= max_b
            }
        }
    }

    fn new_keyring(&mut self, desc: String, uid: u32, gid: u32, perm: u32) -> i32 {
        self.alloc(Key::new(Type::Keyring, desc, uid, gid, perm))
    }

    /// The user and user-session keyrings of `uid` (created on first use)
    fn user_rings(&mut self, uid: u32) -> (i32, i32) {
        if let Some(r) = self.user.get(&uid) {
            if self.keys.contains_key(&r.0) && self.keys.contains_key(&r.1) {
                return *r;
            }
        }
        self.dirty = true;
        let perm = (ALL << POS) | ((VIEW | READ | WRITE | SEARCH | LINK | SETATTR) << USR);
        let user = self.new_keyring(format!("_uid.{}", uid), uid, u32::MAX, perm);
        let ses = self.new_keyring(format!("_uid_ses.{}", uid), uid, u32::MAX, perm);
        // The user-session keyring links the user keyring
        if let Some(k) = self.keys.get_mut(&ses) {
            k.ring.push(user);
        }
        self.user.insert(uid, (user, ses));
        (user, ses)
    }

    fn session_of(&self, tgid: u64) -> Option<i32> {
        self.session.get(&tgid).copied().filter(|s| self.keys.contains_key(s))
    }

    /// Resolves a key ID (special IDs included); `create` makes missing keyrings
    fn lookup(&mut self, c: &Caller, id: i32, create: bool) -> Result<i32, i64> {
        let perm = (ALL << POS) | (VIEW << USR);
        match id {
            THREAD => {
                if let Some(&(_, r)) = self.thread.get(&c.tid).filter(|(_, r)| self.keys.contains_key(r)) {
                    return Ok(r);
                }
                if !create {
                    return Err(ENOKEY);
                }
                let r = self.new_keyring(String::from("_tid"), c.uid, c.gid, perm);
                self.dirty = true;
                self.thread.insert(c.tid, (c.tgid, r));
                Ok(r)
            }
            PROCESS => {
                if let Some(&r) = self.process.get(&c.tgid).filter(|r| self.keys.contains_key(r)) {
                    return Ok(r);
                }
                if !create {
                    return Err(ENOKEY);
                }
                let r = self.new_keyring(String::from("_pid"), c.uid, c.gid, perm);
                self.dirty = true;
                self.process.insert(c.tgid, r);
                Ok(r)
            }
            SESSION => {
                if let Some(r) = self.session_of(c.tgid) {
                    return Ok(r);
                }
                if !create {
                    // Without a session keyring the user-session keyring stands in
                    return Ok(self.user_rings(c.uid).1);
                }
                let r = self.new_keyring(String::from("_ses"), c.uid, c.gid, (ALL << POS) | ((VIEW | READ) << USR));
                self.dirty = true;
                self.session.insert(c.tgid, r);
                Ok(r)
            }
            USER => Ok(self.user_rings(c.uid).0),
            USER_SESSION => Ok(self.user_rings(c.uid).1),
            GROUP => Err(EINVAL),
            REQKEY_AUTH | REQUESTOR => Err(ENOKEY),
            id if id > 0 => {
                if self.keys.contains_key(&id) {
                    Ok(id)
                } else {
                    Err(ENOKEY)
                }
            }
            _ => Err(EINVAL),
        }
    }

    /// The caller's anchor keyrings (thread, process, session or user-session)
    fn anchors(&mut self, c: &Caller) -> Vec<i32> {
        let mut out = Vec::new();
        if let Some(&(_, r)) = self.thread.get(&c.tid) {
            out.push(r);
        }
        if let Some(&r) = self.process.get(&c.tgid) {
            out.push(r);
        }
        match self.session_of(c.tgid) {
            Some(r) => out.push(r),
            None => out.push(self.user_rings(c.uid).1),
        }
        out.retain(|r| self.keys.contains_key(r));
        out
    }

    /// Whether `id` is reachable from the caller's anchors through searchable keyrings
    fn possessed(&mut self, c: &Caller, id: i32) -> bool {
        let anchors = self.anchors(c);
        let mut seen = BTreeSet::new();
        let mut stack: Vec<(i32, usize)> = anchors.into_iter().map(|a| (a, 0)).collect();
        let t = now();
        while let Some((r, depth)) = stack.pop() {
            if r == id {
                return true;
            }
            if depth > MAX_DEPTH || !seen.insert(r) {
                continue;
            }
            let Some(k) = self.keys.get(&r) else { continue };
            if k.ktype != Type::Keyring || k.usable(t).is_err() {
                continue;
            }
            for &child in &k.ring {
                stack.push((child, depth + 1));
            }
        }
        false
    }

    /// The permission bits the caller holds on a key
    fn granted(&mut self, c: &Caller, id: i32) -> u32 {
        let pos = self.possessed(c, id);
        let Some(k) = self.keys.get(&id) else { return 0 };
        let p = k.perm;
        let mut g = if k.uid == c.uid {
            (p >> USR) & ALL
        } else if k.gid != u32::MAX && (k.gid == c.gid || c.in_groups(k.gid)) {
            (p >> GRP) & ALL
        } else {
            p & ALL
        };
        if pos {
            g |= (p >> POS) & ALL;
        }
        g
    }

    fn check(&mut self, c: &Caller, id: i32, need: u32) -> Result<(), i64> {
        if self.granted(c, id) & need == need {
            Ok(())
        } else {
            Err(EACCES)
        }
    }

    /// Looks a key up for an operation: resolves `id`, checks the key is live and the
    /// caller holds `need`
    fn get(&mut self, c: &Caller, id: i32, create: bool, need: u32) -> Result<i32, i64> {
        let serial = self.lookup(c, id, create)?;
        self.keys[&serial].usable(now())?;
        self.check(c, serial, need)?;
        Ok(serial)
    }

    fn ring_of(&self, serial: i32) -> Result<(), i64> {
        if self.keys[&serial].ktype == Type::Keyring {
            Ok(())
        } else {
            Err(ENOTDIR)
        }
    }

    /// Links `key` into `ring` (replacing a link to a key of the same type and description)
    fn link(&mut self, ring: i32, key: i32) -> Result<(), i64> {
        // A keyring may not end up inside itself
        if key == ring || (self.keys[&key].ktype == Type::Keyring && self.reaches(key, ring)) {
            return Err(EDEADLK);
        }
        let (kt, kd) = {
            let k = &self.keys[&key];
            (k.ktype, k.desc.clone())
        };
        let same: Vec<i32> = self.keys[&ring]
            .ring
            .iter()
            .copied()
            .filter(|&o| o != key && self.keys.get(&o).map_or(false, |k| k.ktype == kt && k.desc == kd))
            .collect();
        let r = self.km(ring);
        r.ring.retain(|o| !same.contains(o));
        if !r.ring.contains(&key) {
            r.ring.push(key);
        }
        Ok(())
    }

    fn reaches(&self, from: i32, to: i32) -> bool {
        let mut seen = BTreeSet::new();
        let mut stack = alloc::vec![from];
        while let Some(r) = stack.pop() {
            if r == to {
                return true;
            }
            if !seen.insert(r) {
                continue;
            }
            if let Some(k) = self.keys.get(&r) {
                stack.extend(k.ring.iter().copied());
            }
        }
        false
    }

    /// Depth-first search of `ring` for a key of the given type and description
    fn search(&mut self, c: &Caller, ring: i32, ktype: Type, desc: &str) -> Result<i32, i64> {
        let t = now();
        let mut seen = BTreeSet::new();
        let mut stack = alloc::vec![(ring, 0usize)];
        let mut err = ENOKEY;
        while let Some((r, depth)) = stack.pop() {
            if depth > MAX_DEPTH || !seen.insert(r) {
                continue;
            }
            let children = match self.keys.get(&r) {
                Some(k) if k.ktype == Type::Keyring && k.usable(t).is_ok() => k.ring.clone(),
                _ => continue,
            };
            if r != ring && self.check(c, r, SEARCH).is_err() {
                continue;
            }
            for &child in children.iter().rev() {
                let Some(k) = self.keys.get(&child) else { continue };
                if k.ktype == ktype && k.desc == desc {
                    if let Err(e) = k.usable(t) {
                        err = e;
                        continue;
                    }
                    if self.check(c, child, SEARCH).is_ok() {
                        return Ok(child);
                    }
                    err = EACCES;
                } else if k.ktype == Type::Keyring {
                    stack.push((child, depth + 1));
                }
            }
        }
        Err(err)
    }

    /// Drops keys no anchor reaches any more (the anchors of processes that are gone are
    /// dropped by [`on_exit`])
    fn collect(&mut self) {
        let mut roots: Vec<i32> = Vec::new();
        roots.extend(self.thread.values().map(|v| v.1));
        roots.extend(self.process.values());
        roots.extend(self.session.values());
        for (u, s) in self.user.values() {
            roots.push(*u);
            roots.push(*s);
        }
        roots.extend(self.persistent.values());
        let mut live = BTreeSet::new();
        while let Some(r) = roots.pop() {
            if !live.insert(r) {
                continue;
            }
            if let Some(k) = self.keys.get(&r) {
                roots.extend(k.ring.iter().copied());
            }
        }
        let before = self.keys.len();
        self.keys.retain(|s, _| live.contains(s));
        if self.keys.len() != before {
            self.dirty = true;
        }
        let mut cut = false;
        for k in self.keys.values_mut() {
            let n = k.ring.len();
            k.ring.retain(|s| live.contains(s));
            cut |= k.ring.len() != n;
        }
        self.dirty |= cut;
    }
}

const ENOTDIR: i64 = -20;

fn user_str(cx: &Cx, ptr: u64, max: usize) -> Result<String, i64> {
    let raw = cx.user_cstr(ptr)?;
    if raw.len() > max {
        return Err(EINVAL);
    }
    String::from_utf8(raw).map_err(|_| EINVAL)
}

/// Copies `data` out like Linux: the full length is returned, the buffer gets what fits
fn copy_result(cx: &Cx, buf: u64, len: u64, data: &[u8]) -> i64 {
    if buf != 0 && len > 0 {
        let n = data.len().min(len as usize);
        if cx.copy_out(buf, &data[..n]).is_err() {
            return EFAULT;
        }
    }
    data.len() as i64
}

// ----------------------------------------------------------------------
// Process lifecycle
// ----------------------------------------------------------------------

/// A new process inherits its parent's session keyring
pub fn on_fork(parent_tgid: u64, child_tgid: u64) {
    let mut ks = KEYS.lock();
    if let Some(s) = ks.session_of(parent_tgid) {
        ks.session.insert(child_tgid, s);
        ks.dirty = true;
    }
}

/// `execve` drops the thread and process keyrings
pub fn on_exec(tid: u64, tgid: u64) {
    let mut ks = KEYS.lock();
    if ks.thread.remove(&tid).is_some() | ks.process.remove(&tgid).is_some() {
        ks.dirty = true;
        ks.collect();
    }
}

/// Process `tgid` ended (its last thread): its thread, process and session anchors go,
/// and the keys only they reached
pub fn on_exit(tgid: u64) {
    let mut ks = KEYS.lock();
    let before = ks.thread.len() + ks.process.len() + ks.session.len();
    ks.thread.retain(|_, (t, _)| *t != tgid);
    ks.process.remove(&tgid);
    ks.session.remove(&tgid);
    if ks.thread.len() + ks.process.len() + ks.session.len() != before {
        ks.dirty = true;
        ks.collect();
    }
}

/// `/proc/keys` text: the keys caller `c` may view
pub fn proc_keys(c: &Caller) -> String {
    let c = *c;
    let mut ks = KEYS.lock();
    let t = now();
    let serials: Vec<i32> = ks.keys.keys().copied().collect();
    let mut out = String::new();
    for s in serials {
        if ks.granted(&c, s) & VIEW == 0 {
            continue;
        }
        let k = &ks.keys[&s];
        let flags = format!(
            "{}{}{}",
            if k.revoked { 'R' } else { 'I' },
            if k.expiry.is_some() { 'T' } else { '-' },
            if k.invalid { 'i' } else { '-' }
        );
        let timeout = match k.expiry {
            None => String::from("perm"),
            Some(e) if e <= t => String::from("expd"),
            Some(e) => format!("{}s", (e - t) / 1000),
        };
        let extra = match k.ktype {
            Type::Keyring => format!("{} link{}", k.ring.len(), if k.ring.len() == 1 { "" } else { "s" }),
            _ => format!("{}", k.payload.len()),
        };
        out.push_str(&format!(
            "{:08x} {} {:5} {:>5} {:08x} {:5} {:5} {:<9} {}: {}\n",
            s,
            flags,
            1,
            timeout,
            k.perm,
            k.uid,
            k.gid as i32,
            k.ktype.name(),
            k.desc,
            extra
        ));
    }
    out
}

// ----------------------------------------------------------------------
// System calls
// ----------------------------------------------------------------------

/// Serves `add_key` (248), `request_key` (249) and `keyctl` (250)
pub fn dispatch(cx: &Cx) -> Option<i64> {
    let a = cx.args;
    Some(match cx.nr {
        248 => add_key(cx, a[0], a[1], a[2], a[3], a[4] as i32),
        249 => request_key(cx, a[0], a[1], a[2], a[3] as i32),
        250 => keyctl(cx, a[0] as u32, a[1], a[2], a[3], a[4]),
        _ => return None,
    })
}

fn add_key(cx: &Cx, type_ptr: u64, desc_ptr: u64, payload_ptr: u64, plen: u64, ring_id: i32) -> i64 {
    let ktype = match cx.user_cstr(type_ptr).and_then(|t| Type::parse(&t)) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let desc = match user_str(cx, desc_ptr, 4095) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => return EINVAL,
        Err(e) => return e,
    };
    if ktype == Type::Logon && desc.find(':').map_or(true, |i| i == 0) {
        return EINVAL;
    }
    if plen as usize > ktype.max_payload().max(0) || (ktype == Type::Keyring && plen != 0) {
        return EINVAL;
    }
    if ktype != Type::Keyring && plen == 0 && ktype != Type::User {
        return EINVAL;
    }
    let payload = if plen > 0 {
        if payload_ptr == 0 {
            return EFAULT;
        }
        match cx.copy_in(payload_ptr, plen as usize) {
            Ok(p) => p,
            Err(e) => return e,
        }
    } else {
        Vec::new()
    };
    let c = cx.caller();
    let mut ks = KEYS.lock();
    let ring = match ks.get(&c, ring_id, true, WRITE) {
        Ok(r) => r,
        Err(e) => return e,
    };
    if let Err(e) = ks.ring_of(ring) {
        return e;
    }
    // A key of the same type and description in the keyring is updated in place
    if ktype != Type::Keyring {
        let existing =
            ks.keys[&ring].ring.iter().copied().find(|s| ks.keys.get(s).map_or(false, |k| k.ktype == ktype && k.desc == desc));
        if let Some(e) = existing {
            if ks.keys[&e].usable(now()).is_ok() && ks.check(&c, e, WRITE).is_ok() {
                if !ks.payload_fits(e, payload.len()) {
                    return EDQUOT;
                }
                ks.km(e).payload = payload;
                return e as i64;
            }
        }
    }
    if !ks.quota_ok(c.uid, desc.len() + 1 + payload.len()) {
        return EDQUOT;
    }
    let mut key = Key::new(ktype, desc, c.uid, c.gid, DEFAULT_PERM);
    if ktype == Type::Logon {
        // Logon keys cannot be read from user space
        key.perm &= !((READ << POS) | (READ << USR));
    }
    key.payload = payload;
    let serial = ks.alloc(key);
    if let Err(e) = ks.link(ring, serial) {
        ks.keys.remove(&serial);
        return e;
    }
    serial as i64
}

fn request_key(cx: &Cx, type_ptr: u64, desc_ptr: u64, _callout: u64, dest_id: i32) -> i64 {
    let ktype = match cx.user_cstr(type_ptr).and_then(|t| Type::parse(&t)) {
        Ok(t) => t,
        Err(e) => return e,
    };
    let desc = match user_str(cx, desc_ptr, 4095) {
        Ok(d) if !d.is_empty() => d,
        Ok(_) => return EINVAL,
        Err(e) => return e,
    };
    let c = cx.caller();
    let mut ks = KEYS.lock();
    let dest = if dest_id != 0 {
        match ks.get(&c, dest_id, true, WRITE) {
            Ok(d) => Some(d),
            Err(e) => return e,
        }
    } else {
        None
    };
    let mut err = ENOKEY;
    for anchor in ks.anchors(&c) {
        match ks.search(&c, anchor, ktype, &desc) {
            Ok(found) => {
                if let Some(d) = dest {
                    if let Err(e) = ks.ring_of(d).and_then(|_| ks.link(d, found)) {
                        return e;
                    }
                }
                return found as i64;
            }
            Err(e) if e != ENOKEY => err = e,
            Err(_) => {}
        }
    }
    // No /sbin/request-key upcall: a key that does not exist cannot be constructed
    err
}

fn keyctl(cx: &Cx, op: u32, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    match keyctl_inner(cx, op, a2, a3, a4, a5) {
        Ok(v) => v,
        Err(e) => e,
    }
}

fn keyctl_inner(cx: &Cx, op: u32, a2: u64, a3: u64, a4: u64, a5: u64) -> Result<i64, i64> {
    let c = cx.caller();
    let id = a2 as i32;
    match op {
        // KEYCTL_GET_KEYRING_ID
        0 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, a3 != 0)?;
            Ok(s as i64)
        }
        // KEYCTL_JOIN_SESSION_KEYRING
        1 => {
            let name = if a2 == 0 { None } else { Some(user_str(cx, a2, 4095)?) };
            let mut ks = KEYS.lock();
            let ring = match name {
                None => ks.new_keyring(String::from("_ses"), c.uid, c.gid, (ALL << POS) | ((VIEW | READ) << USR)),
                Some(n) => {
                    // Join a named session keyring the caller may search, or make one
                    let found = ks
                        .keys
                        .iter()
                        .filter(|(_, k)| k.ktype == Type::Keyring && k.desc == n && k.usable(now()).is_ok())
                        .map(|(s, _)| *s)
                        .next();
                    match found {
                        Some(s) => {
                            if ks.granted(&c, s) & SEARCH == 0 {
                                return Err(EACCES);
                            }
                            s
                        }
                        None => {
                            if !ks.quota_ok(c.uid, n.len() + 1) {
                                return Err(EDQUOT);
                            }
                            ks.new_keyring(n, c.uid, c.gid, (ALL << POS) | ((VIEW | READ) << USR))
                        }
                    }
                }
            };
            ks.session.insert(c.tgid, ring);
            ks.dirty = true;
            ks.collect();
            Ok(ring as i64)
        }
        // KEYCTL_UPDATE
        2 => {
            let payload = if a4 > 0 { cx.copy_in(a3, a4 as usize)? } else { Vec::new() };
            let mut ks = KEYS.lock();
            let s = ks.get(&c, id, false, WRITE)?;
            let k = &ks.keys[&s];
            if k.ktype == Type::Keyring {
                return Err(EOPNOTSUPP);
            }
            if payload.len() > k.ktype.max_payload() || (payload.is_empty() && k.ktype != Type::User) {
                return Err(EINVAL);
            }
            if !ks.payload_fits(s, payload.len()) {
                return Err(EDQUOT);
            }
            ks.km(s).payload = payload;
            Ok(0)
        }
        // KEYCTL_REVOKE
        3 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, false)?;
            if ks.check(&c, s, WRITE).is_err() && ks.check(&c, s, SETATTR).is_err() {
                return Err(EACCES);
            }
            ks.km(s).revoked = true;
            Ok(0)
        }
        // KEYCTL_CHOWN
        4 => {
            let (uid, gid) = (a3 as u32, a4 as u32);
            let mut ks = KEYS.lock();
            let s = ks.get(&c, id, true, SETATTR)?;
            let k = ks.km(s);
            if uid != u32::MAX && uid != k.uid && !c.admin {
                return Err(EACCES);
            }
            if gid != u32::MAX && gid != k.gid && !c.admin && !(k.uid == c.uid && (gid == c.gid || c.in_groups(gid))) {
                return Err(EACCES);
            }
            if uid != u32::MAX {
                k.uid = uid;
            }
            if gid != u32::MAX {
                k.gid = gid;
            }
            Ok(0)
        }
        // KEYCTL_SETPERM
        5 => {
            let perm = a3 as u32;
            if perm & !0x3f3f_3f3f != 0 {
                return Err(EINVAL);
            }
            let mut ks = KEYS.lock();
            let s = ks.get(&c, id, true, SETATTR)?;
            let k = ks.km(s);
            if k.uid != c.uid && !c.admin {
                return Err(EACCES);
            }
            k.perm = perm;
            Ok(0)
        }
        // KEYCTL_DESCRIBE
        6 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, true)?;
            if ks.check(&c, s, VIEW).is_err() {
                return Err(EACCES);
            }
            let k = &ks.keys[&s];
            let text = format!("{};{};{};{:08x};{}\0", k.ktype.name(), k.uid, k.gid as i32, k.perm, k.desc);
            Ok(copy_result(cx, a3, a4, text.as_bytes()))
        }
        // KEYCTL_CLEAR
        7 => {
            let mut ks = KEYS.lock();
            let s = ks.get(&c, id, true, WRITE)?;
            ks.ring_of(s)?;
            ks.km(s).ring.clear();
            ks.collect();
            Ok(0)
        }
        // KEYCTL_LINK
        8 => {
            let mut ks = KEYS.lock();
            let key = ks.get(&c, id, true, LINK)?;
            let ring = ks.get(&c, a3 as i32, true, WRITE)?;
            ks.ring_of(ring)?;
            ks.link(ring, key)?;
            Ok(0)
        }
        // KEYCTL_UNLINK
        9 => {
            let mut ks = KEYS.lock();
            let key = ks.lookup(&c, id, false)?;
            let ring = ks.get(&c, a3 as i32, false, WRITE)?;
            ks.ring_of(ring)?;
            let r = ks.km(ring);
            let before = r.ring.len();
            r.ring.retain(|&s| s != key);
            if r.ring.len() == before {
                return Err(ENOENT);
            }
            ks.collect();
            Ok(0)
        }
        // KEYCTL_SEARCH
        10 => {
            let ktype = Type::parse(&cx.user_cstr(a3)?)?;
            let desc = user_str(cx, a4, 4095)?;
            let mut ks = KEYS.lock();
            let ring = ks.get(&c, id, false, SEARCH)?;
            ks.ring_of(ring)?;
            let found = ks.search(&c, ring, ktype, &desc)?;
            if a5 != 0 {
                let dest = ks.get(&c, a5 as i32, true, WRITE)?;
                ks.ring_of(dest)?;
                ks.check(&c, found, LINK)?;
                ks.link(dest, found)?;
            }
            Ok(found as i64)
        }
        // KEYCTL_READ
        11 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, false)?;
            ks.keys[&s].usable(now())?;
            // A possessed key is readable even without read permission (as on Linux)
            if ks.granted(&c, s) & READ == 0 && !ks.possessed(&c, s) {
                return Err(EACCES);
            }
            let k = &ks.keys[&s];
            match k.ktype {
                Type::Keyring => {
                    let data: Vec<u8> = k.ring.iter().flat_map(|s| s.to_ne_bytes()).collect();
                    Ok(copy_result(cx, a3, a4, &data))
                }
                Type::Logon => Err(EOPNOTSUPP),
                _ => Ok(copy_result(cx, a3, a4, &k.payload)),
            }
        }
        // KEYCTL_INSTANTIATE, NEGATE, REJECT, INSTANTIATE_IOV: only for an upcall's
        // authorisation key, which never exists here
        12 | 13 | 19 | 20 => Err(EPERM),
        // KEYCTL_SET_REQKEY_KEYRING: returns the old setting
        14 => {
            let v = a2 as i32;
            if !(-1..=7).contains(&v) {
                return Err(EINVAL);
            }
            let mut ks = KEYS.lock();
            let old = ks.reqkey_dest.get(&c.tid).copied().unwrap_or(0);
            if v != -1 {
                ks.reqkey_dest.insert(c.tid, v);
                ks.dirty = true;
            }
            Ok(old as i64)
        }
        // KEYCTL_SET_TIMEOUT
        15 => {
            let mut ks = KEYS.lock();
            let s = ks.get(&c, id, true, SETATTR)?;
            ks.km(s).expiry = if a3 == 0 { None } else { Some(now() + a3.saturating_mul(1000)) };
            Ok(0)
        }
        // KEYCTL_ASSUME_AUTHORITY
        16 => {
            if a2 == 0 {
                Ok(0)
            } else {
                Err(EPERM)
            }
        }
        // KEYCTL_GET_SECURITY: no security module labels
        17 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, false)?;
            ks.check(&c, s, VIEW)?;
            Ok(copy_result(cx, a3, a4, b"\0"))
        }
        // KEYCTL_SESSION_TO_PARENT
        18 => {
            let ppid = hydra_rt::sys::lx_proc_info(c.tgid).map(|p| p[0]).unwrap_or(0);
            if ppid <= 1 {
                return Err(EPERM);
            }
            // As Linux's keyctl_session_to_parent: the parent must run as exactly the caller
            // (real, effective and saved ids all the caller's effective ones: not another
            // user, not set-id), or a process could plant keys in another user's session
            let same_creds = hydra_rt::sys::lx_proc_info(ppid)
                .map(|p| p[1..4].iter().all(|&u| u == c.uid as u64) && p[4..7].iter().all(|&g| g == c.gid as u64))
                .unwrap_or(false);
            if !same_creds {
                return Err(EPERM);
            }
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, SESSION, false)?;
            ks.check(&c, s, LINK)?;
            // Both the new session keyring and the one it replaces must be the caller's
            let owned_by_caller = |k: Option<&Key>| k.map_or(true, |k| k.uid == c.uid);
            if !owned_by_caller(ks.keys.get(&s)) || !owned_by_caller(ks.session.get(&ppid).and_then(|o| ks.keys.get(o))) {
                return Err(EPERM);
            }
            ks.session.insert(ppid, s);
            ks.dirty = true;
            Ok(0)
        }
        // KEYCTL_INVALIDATE
        21 => {
            let mut ks = KEYS.lock();
            let s = ks.lookup(&c, id, false)?;
            if ks.check(&c, s, SEARCH).is_err() && !c.admin {
                return Err(EACCES);
            }
            ks.km(s).invalid = true;
            for k in ks.keys.values_mut() {
                k.ring.retain(|&o| o != s);
            }
            ks.dirty = true;
            ks.collect();
            Ok(0)
        }
        // KEYCTL_GET_PERSISTENT(uid, dest)
        22 => {
            let uid = if a2 as i64 == -1 { c.uid } else { a2 as u32 };
            if uid != c.uid && !c.admin {
                return Err(EPERM);
            }
            let mut ks = KEYS.lock();
            let dest = ks.get(&c, a3 as i32, true, WRITE)?;
            ks.ring_of(dest)?;
            let ring = match ks.persistent.get(&uid).copied().filter(|r| ks.keys.contains_key(r)) {
                Some(r) => r,
                None => {
                    let perm = (ALL << POS) | ((VIEW | READ | SEARCH) << USR);
                    let r = ks.new_keyring(format!("_persistent.{}", uid), uid, u32::MAX, perm);
                    ks.persistent.insert(uid, r);
                    ks.dirty = true;
                    r
                }
            };
            ks.link(dest, ring)?;
            Ok(ring as i64)
        }
        // Public-key operations, Diffie-Hellman, keyring restrictions: no such key types
        23..=29 => Err(EOPNOTSUPP),
        // KEYCTL_MOVE(id, from, to, flags)
        30 => {
            const KEYCTL_MOVE_EXCL: u64 = 1;
            if a5 & !KEYCTL_MOVE_EXCL != 0 {
                return Err(EINVAL);
            }
            let mut ks = KEYS.lock();
            let key = ks.get(&c, id, true, LINK)?;
            let from = ks.get(&c, a3 as i32, false, WRITE)?;
            let to = ks.get(&c, a4 as i32, true, WRITE)?;
            ks.ring_of(from)?;
            ks.ring_of(to)?;
            if !ks.keys[&from].ring.contains(&key) {
                return Err(ENOENT);
            }
            if a5 & KEYCTL_MOVE_EXCL != 0 {
                let (kt, kd) = (ks.keys[&key].ktype, ks.keys[&key].desc.clone());
                let clash = ks.keys[&to].ring.iter().any(|s| *s != key && ks.keys.get(s).map_or(false, |k| k.ktype == kt && k.desc == kd));
                if clash {
                    return Err(EEXIST);
                }
            }
            ks.link(to, key)?;
            if from != to {
                ks.km(from).ring.retain(|&s| s != key);
            }
            Ok(0)
        }
        // KEYCTL_CAPABILITIES: persistent keyrings, invalidate, move, namespaced
        31 => {
            const CAPS0_PERSISTENT_KEYRINGS: u8 = 0x02;
            const CAPS0_INVALIDATE: u8 = 0x20;
            const CAPS1_NS_KEYRING_NAME: u8 = 0x01;
            const CAPS1_MOVE: u8 = 0x04;
            let caps = [CAPS0_PERSISTENT_KEYRINGS | CAPS0_INVALIDATE, CAPS1_NS_KEYRING_NAME | CAPS1_MOVE];
            Ok(copy_result(cx, a2, a3, &caps))
        }
        // KEYCTL_WATCH_KEY: no notification queues
        32 => Err(EOPNOTSUPP),
        _ => Err(EOPNOTSUPP),
    }
}
