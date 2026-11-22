//! lx-net's kept state (wave 8, Group X2): one record per socket in the service's kept-state
//! object (`hydra_rt::kept`), so that a restarted lx-net takes its sockets back
//! (the Transparent restart class, `docs/linux-services-design.md` section 5).
//!
//! - **A record per socket** (an Internet socket: [`crate::inet`]; a netlink socket:
//!   [`crate::netlink`]): what the socket is (its kind, its net-server handles, its
//!   addresses, flags and options), never pointers. Its first byte says whose it is
//!   ([`KIND_INET`], [`KIND_NETLINK`]).
//! - **The key of the kernel object** is the record's number plus one (`LxObjDesc::key`), so
//!   the kernel's list of live objects (`LX_SVC_LIST`) names the record of each one.
//! - **Writes**: a socket writes its record when its image changed (each socket keeps the
//!   image it last wrote, so an unchanged socket costs a comparison, not a checksum), before
//!   the answer of the call that changed it leaves the worker. A record is cleared when the
//!   socket's last descriptor goes.
//!
//! In linux-server (which builds these files for `lx.net=linux`) no kept object is opened:
//! every function here does nothing and sockets get record 0 ("not kept").

use alloc::vec::Vec;

use hydra_rt::kept::{Adopted, Kept};

use crate::lock::YLock;

/// The record layout's version ("NET" 1).
pub const LAYOUT: u32 = 0x4E45_5401;
/// Bytes of a record.
pub const REC: usize = 160;
/// Records (sockets that survive a restart; more are made, but not kept).
pub const COUNT: usize = 2048;
/// Bytes of the kept-state object.
pub const SIZE: usize = (Kept::size_for(COUNT, REC) + 0xFFF) & !0xFFF;

/// A record's first byte: an Internet socket.
pub const KIND_INET: u8 = 1;
/// A record's first byte: a netlink socket.
pub const KIND_NETLINK: u8 = 2;

struct State {
    k: Kept,
    /// Records in use (taken by [`alloc`], even before their first write), a bit each.
    used: Vec<u64>,
}

static KEPT: YLock<Option<State>> = YLock::new(None);

/// Takes the kept-state area of `size` bytes at `base` (the address `lx_svc_kept` gave).
///
/// # Safety
///
/// `base` must point to `size` bytes of writable memory owned by this process for its life.
pub unsafe fn open(base: *mut u8, size: usize) -> Adopted {
    // SAFETY: the caller's promise
    let (k, a) = unsafe { Kept::open(base, size, LAYOUT, REC) };
    let mut used = alloc::vec![0u64; k.count().div_ceil(64)];
    for i in 0..k.count() {
        if k.get(i).is_some() {
            used[i / 64] |= 1 << (i % 64);
        }
    }
    *KEPT.lock() = Some(State { k, used });
    a
}

/// A free record for a new socket: its number plus one, 0 when none (not kept).
pub fn alloc() -> u32 {
    let mut g = KEPT.lock();
    let Some(st) = g.as_mut() else { return 0 };
    let n = st.k.count();
    for (w, word) in st.used.iter_mut().enumerate() {
        if *word != u64::MAX {
            let b = (!*word).trailing_zeros() as usize;
            let i = w * 64 + b;
            if i >= n {
                return 0;
            }
            *word |= 1 << b;
            return i as u32 + 1;
        }
    }
    0
}

/// Writes record `rec` (a number from [`alloc`]): `false` if it does not fit.
pub fn put(rec: u32, data: &[u8]) -> bool {
    if rec == 0 {
        return false;
    }
    let mut g = KEPT.lock();
    let Some(st) = g.as_mut() else { return false };
    st.k.put(rec as usize - 1, data)
}

/// Clears record `rec` and lets it go.
pub fn clear(rec: u32) {
    if rec == 0 {
        return;
    }
    let mut g = KEPT.lock();
    let Some(st) = g.as_mut() else { return };
    let i = rec as usize - 1;
    st.k.clear(i);
    if let Some(w) = st.used.get_mut(i / 64) {
        *w &= !(1 << (i % 64));
    }
}

/// Record `rec`'s data (a copy), if it has any.
pub fn get(rec: u32) -> Option<Vec<u8>> {
    if rec == 0 {
        return None;
    }
    let g = KEPT.lock();
    g.as_ref()?.k.get(rec as usize - 1).map(|d| d.to_vec())
}

/// Clears every record not in `keep` (record numbers): after a restart, the records of
/// sockets the kernel no longer lists (closed meanwhile) or that were not adopted.
pub fn keep_only(keep: &[u32]) {
    let mut g = KEPT.lock();
    let Some(st) = g.as_mut() else { return };
    for i in 0..st.k.count() {
        let rec = i as u32 + 1;
        if st.used[i / 64] & (1 << (i % 64)) != 0 && !keep.contains(&rec) {
            st.k.clear(i);
            st.used[i / 64] &= !(1 << (i % 64));
        }
    }
}

// ----------------------------------------------------------------------
// The byte image (little-endian), shared by inet and netlink
// ----------------------------------------------------------------------

/// Reads little-endian numbers from a record.
pub struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
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

    pub fn ip(&mut self) -> Option<[u8; 4]> {
        let v: [u8; 4] = self.b.get(self.p..self.p + 4)?.try_into().ok()?;
        self.p += 4;
        Some(v)
    }

    /// What is left.
    pub fn rest(&self) -> &'a [u8] {
        &self.b[self.p.min(self.b.len())..]
    }
}
