//! # lx-ipc's kept records (wave 9, Group X3)
//!
//! lx-ipc restarts Transparently (`docs/linux-services-design.md` 5.2): a new instance takes
//! the old one's pipes, Unix sockets, eventfds, timerfds, signalfds and pidfds and goes on.
//! What it needs is here and in [`crate::arena`]:
//!
//! - **One record per thing** (a pipe, a Unix socket, a connection, an eventfd, ...), in
//!   `hydra_rt::kept`'s format (each record twice, with a checksum: a crash in the middle of
//!   a write leaves the previous value) over kept memory object [`KEY_REC`]. Its first byte
//!   says what it is (`K_*`). Records hold numbers and offsets, never pointers.
//! - **Ids:** a thing's id *is* its record number (1..=[`COUNT`]); the kernel object of a
//!   descriptor carries it as its key, so the kernel's list of live objects (`LX_SVC_LIST`)
//!   names each object's record. When the records run out, things get ids from
//!   [`UNKEPT_BASE`] up: they work, but do not survive a restart.
//! - **Writes** happen under the owner's lock, before the call that changed the thing is
//!   answered (and before waiting callers it completes are).
//!
//! The calls in flight at a crash (X2's words in the worker's page): a read or write marks
//! itself safe to send again until its change is written ([`resend_safe`]), then records
//! its count as the answer if lx-ipc dies before it answers ([`partial`]).
//!
//! In linux-server (`lx.ipc=linux`) nothing is opened: ids come from the same counter and
//! every write does nothing.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};

use hydra_rt::kept::Kept;
use hydra_rt::protocol::*;

use crate::lock::YLock;

/// The record layout's version ("IPC" 1).
pub const LAYOUT: u32 = 0x4950_4301;
/// Bytes of a record (a Unix socket with two path names fits).
pub const REC: usize = 288;
/// Records.
pub const COUNT: usize = 16384;
/// Bytes of the record object.
pub const SIZE: usize = (Kept::size_for(COUNT, REC) + 0xFFF) & !0xFFF;
/// Kept memory object keys of lx-ipc: the records, the data arena.
pub const KEY_REC: u64 = 1;
pub const KEY_ARENA: u64 = 2;
/// Ids from here on are not kept.
pub const UNKEPT_BASE: u64 = 1 << 20;

/// Record kinds (first byte).
pub const K_PIPE: u8 = 1;
pub const K_USOCK: u8 = 2;
pub const K_UPAIR: u8 = 3;
pub const K_EFD: u8 = 4;
pub const K_TFD: u8 = 5;
pub const K_SFD: u8 = 6;
pub const K_MQ: u8 = 8;
pub const K_SYSV: u8 = 9;

struct Store {
    k: Option<Kept>,
    /// Record numbers handed out, a bit each (record `i + 1` is bit `i`).
    used: Vec<u64>,
    next_unkept: u64,
}

static S: YLock<Store> = YLock::new(Store { k: None, used: Vec::new(), next_unkept: UNKEPT_BASE });
static ACTIVE: AtomicBool = AtomicBool::new(false);

/// Whether records are kept (lx-ipc with its kept objects).
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

/// Takes the record area of `size` bytes at `base`: the records found (id, data) when it
/// held some (a restart), else none.
///
/// # Safety
///
/// `base` must point to `size` writable bytes owned by this process for its life.
pub unsafe fn open(base: *mut u8, size: usize) -> (hydra_rt::kept::Adopted, Vec<(u64, Vec<u8>)>) {
    // SAFETY: the caller's promise
    let (k, a) = unsafe { Kept::open(base, size, LAYOUT, REC) };
    let mut found = Vec::new();
    for i in 0..k.count() {
        if let Some(d) = k.get(i) {
            found.push((i as u64 + 1, d.to_vec()));
        }
    }
    let mut s = S.lock();
    s.used = alloc::vec![0u64; COUNT.div_ceil(64)];
    s.k = Some(k);
    ACTIVE.store(true, Ordering::Relaxed);
    (a, found)
}

/// Keeps the records of `ids` (taken again: a restart found them in use) and clears every
/// other one.
pub fn keep_only(ids: &[u64]) {
    let mut s = S.lock();
    if s.used.is_empty() {
        s.used = alloc::vec![0u64; COUNT.div_ceil(64)];
    }
    let mut keep = alloc::vec![0u64; COUNT.div_ceil(64)];
    for &id in ids {
        if id >= 1 && id as usize <= COUNT {
            keep[(id as usize - 1) / 64] |= 1 << ((id as usize - 1) % 64);
        }
    }
    let Store { k, used, .. } = &mut *s;
    if let Some(k) = k.as_mut() {
        for i in 0..k.count().min(COUNT) {
            if keep[i / 64] & (1 << (i % 64)) == 0 && k.get(i).is_some() {
                k.clear(i);
            }
        }
    }
    *used = keep;
}

/// A new id (see the module comment).
pub fn id() -> u64 {
    let mut s = S.lock();
    if s.used.is_empty() {
        s.used = alloc::vec![0u64; COUNT.div_ceil(64)];
    }
    for w in 0..s.used.len() {
        let word = s.used[w];
        if word != u64::MAX {
            let b = (!word).trailing_zeros() as usize;
            let i = w * 64 + b;
            if i < COUNT {
                s.used[w] |= 1 << b;
                return i as u64 + 1;
            }
        }
    }
    let id = s.next_unkept;
    s.next_unkept += 1;
    id
}

/// Whether `id` has a record (it survives a restart).
pub fn kept(id: u64) -> bool {
    active() && id >= 1 && id as usize <= COUNT
}

/// The key the kernel object of thing `id` carries (0: not kept, the object dies with the
/// instance).
pub fn key(id: u64) -> u64 {
    if kept(id) {
        id
    } else {
        0
    }
}

/// Writes thing `id`'s record (nothing if it is not kept); `false` if it does not fit.
pub fn put(id: u64, data: &[u8]) -> bool {
    if !kept(id) {
        return false;
    }
    let mut s = S.lock();
    match s.k.as_mut() {
        Some(k) => k.put(id as usize - 1, data),
        None => false,
    }
}

/// Thing `id` is gone: its record is cleared and its id free again.
pub fn release(id: u64) {
    if id == 0 || id as usize > COUNT {
        return;
    }
    let i = id as usize - 1;
    let mut s = S.lock();
    if let Some(k) = s.k.as_mut() {
        k.clear(i);
    }
    if let Some(w) = s.used.get_mut(i / 64) {
        *w &= !(1 << (i % 64));
    }
}

// ----------------------------------------------------------------------
// Calls in flight at a crash (X2's words in the worker's syscall page)
// ----------------------------------------------------------------------

/// Marks the call being served safe to send again after a crash (`on`), or no longer.
pub fn resend_safe(page: *mut u8, id: u64, on: bool) {
    if !active() || page.is_null() {
        return;
    }
    // SAFETY: the worker's own syscall page; the word lies after the call
    unsafe { core::ptr::write_volatile(page.add(LX_CALL_RESEND_OFF) as *mut u64, if on { id } else { 0 }) };
}

/// The call `id` did its change: `n` is its answer if lx-ipc dies before it answers (a
/// count; 0 or less: the call is no longer safe to send again, and fails with `EIO`). A
/// waiting call completed by another one (no page) tells the kernel instead.
pub fn partial(page: *mut u8, id: u64, n: i64) {
    if !active() {
        return;
    }
    if page.is_null() {
        if n > 0 {
            let _ = hydra_rt::sys::lx_obj(LX_OBJ_PARTIAL, id, n as u64, 0);
        }
        return;
    }
    // SAFETY: the worker's own syscall page; the words lie after the call
    unsafe {
        if n > 0 {
            core::ptr::write_volatile(page.add(LX_CALL_PARTIAL_OFF + 8) as *mut i64, n);
            core::ptr::write_volatile(page.add(LX_CALL_PARTIAL_OFF) as *mut u64, id);
        }
        core::ptr::write_volatile(page.add(LX_CALL_RESEND_OFF) as *mut u64, 0);
    }
}

// ----------------------------------------------------------------------
// Record bytes (little-endian)
// ----------------------------------------------------------------------

/// Builds a record.
pub struct W(pub Vec<u8>);

impl W {
    pub fn new(kind: u8) -> Self {
        let mut v = Vec::with_capacity(64);
        v.push(kind);
        Self(v)
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.0.push(v);
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.0.extend_from_slice(&v.to_le_bytes());
        self
    }
    /// A length byte, then the bytes (at most 255).
    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        let n = b.len().min(255);
        self.0.push(n as u8);
        self.0.extend_from_slice(&b[..n]);
        self
    }
    pub fn raw(&mut self, b: &[u8]) -> &mut Self {
        self.0.extend_from_slice(b);
        self
    }
}

/// Reads a record.
pub struct R<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> R<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.p)?;
        self.p += 1;
        Some(v)
    }
    pub fn u16(&mut self) -> Option<u16> {
        let v = u16::from_le_bytes(self.b.get(self.p..self.p + 2)?.try_into().ok()?);
        self.p += 2;
        Some(v)
    }
    pub fn u32(&mut self) -> Option<u32> {
        let v = u32::from_le_bytes(self.b.get(self.p..self.p + 4)?.try_into().ok()?);
        self.p += 4;
        Some(v)
    }
    pub fn u64(&mut self) -> Option<u64> {
        let v = u64::from_le_bytes(self.b.get(self.p..self.p + 8)?.try_into().ok()?);
        self.p += 8;
        Some(v)
    }
    pub fn bytes(&mut self) -> Option<&'a [u8]> {
        let n = self.u8()? as usize;
        self.raw(n)
    }
    pub fn raw(&mut self, n: usize) -> Option<&'a [u8]> {
        let v = self.b.get(self.p..self.p + n)?;
        self.p += n;
        Some(v)
    }
}
