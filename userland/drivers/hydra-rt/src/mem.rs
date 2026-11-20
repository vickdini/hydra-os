//! # Memory objects: the service side (wave 6, Group 23)
//!
//! A service makes memory objects, maps them into itself, hands them to programs (as the
//! answer to an `mmap` of one of its descriptors) and shares them with other services. The
//! kernel side is `src/lx/mem.rs`; the calls are `SYS_LX_MEM` (native 64).
//!
//! ```ignore
//! let buf = MemObj::anon(64 * 1024)?;          // zeroed, pages on first touch
//! let p = buf.map(0, 64 * 1024, PROT_RW)?;     // the service's own view
//! // a program's mmap of one of our descriptors, answered:
//! (lx_mmap_answer(buf.handle(), 0, false), 0)
//! ```
//!
//! **Lifetimes:** a handle and every mapping (the service's, a program's) hold the object;
//! dropping a [`MemObj`] closes only the handle. A program's mapping outlives the service.
//! **Kept objects** ([`MemObj::kept`]) belong to the service registry and survive a restart
//! of the service: the new instance asks for the same key and finds the old contents.
//!
//! Rule for `mmap` answers: the handle named must still be open when the kernel reads the
//! answer. Close a descriptor's memory when its `LX_NOTE_CLOSE` arrives (a close never
//! overtakes a call on the same descriptor).

use crate::protocol::{LX_MEM_ANON, LX_MEM_CLOSE, LX_MEM_DMA, LX_MEM_EXISTED, LX_MEM_INFO, LX_MEM_KEPT, LX_MEM_MAP, LX_MEM_SHARE, LX_MEM_UNKEEP, LX_MEM_UNMAP};
use crate::sys::lx_mem;

pub use crate::protocol::{lx_mmap_answer, lx_mmap_parts};

/// `PROT_READ`.
pub const PROT_READ: u32 = 1;
/// `PROT_READ | PROT_WRITE`.
pub const PROT_RW: u32 = 3;

fn check(r: i64) -> Result<u64, i64> {
    if r < 0 {
        Err(r)
    } else {
        Ok(r as u64)
    }
}

/// A handle to a memory object in this service's table. Dropping it closes the handle
/// (mappings stay); [`MemObj::into_raw`] keeps it open.
pub struct MemObj {
    handle: u32,
}

impl MemObj {
    /// A new anonymous object of `size` bytes (rounded up to pages), zero-filled.
    ///
    /// # Errors
    /// `-EINVAL` (0 or more than 1 GiB), `-EMFILE` (too many handles), `-EPERM` (not a
    /// registered service).
    pub fn anon(size: u64) -> Result<MemObj, i64> {
        check(lx_mem(LX_MEM_ANON, size, 0, 0, 0)).map(|h| MemObj { handle: h as u32 })
    }

    /// The service's kept object `key` (not 0), made with `size` zeroed bytes the first
    /// time. The flag is `true` when it already existed: a restarted instance gets the old
    /// contents (and should check them before trusting them).
    ///
    /// # Errors
    /// As [`MemObj::anon`]; `-EPERM` for a service without a Linux service id.
    pub fn kept(key: u64, size: u64) -> Result<(MemObj, bool), i64> {
        let r = check(lx_mem(LX_MEM_ANON, size, LX_MEM_KEPT, key, 0))?;
        Ok((MemObj { handle: r as u32 }, r & LX_MEM_EXISTED as u64 != 0))
    }

    /// The service forgets its kept object `key` (the next [`MemObj::kept`] makes a new one).
    pub fn unkeep(key: u64) -> Result<(), i64> {
        check(lx_mem(LX_MEM_UNKEEP, key, 0, 0, 0)).map(|_| ())
    }

    /// New DMA memory: physically contiguous, zeroed, reachable by this driver's device.
    /// Returns the object and its device address.
    pub fn dma(size: u64) -> Result<(MemObj, u64), i64> {
        let mut dev = 0u64;
        let h = check(lx_mem(LX_MEM_DMA, size, &mut dev as *mut u64 as u64, 0, 0))?;
        Ok((MemObj { handle: h as u32 }, dev))
    }

    /// Takes over a handle number (one another service shared with us, or one kept with
    /// [`MemObj::into_raw`]).
    pub fn from_raw(handle: u32) -> MemObj {
        MemObj { handle }
    }

    /// Gives up ownership of the handle without closing it.
    pub fn into_raw(self) -> u32 {
        let h = self.handle;
        core::mem::forget(self);
        h
    }

    /// The handle number (for [`lx_mmap_answer`]).
    pub fn handle(&self) -> u32 {
        self.handle
    }

    /// Maps `len` bytes from byte `offset` (page-aligned) into this service, shared, with
    /// `prot` ([`PROT_READ`], [`PROT_RW`]); returns the address.
    pub fn map(&self, offset: u64, len: u64, prot: u32) -> Result<*mut u8, i64> {
        check(lx_mem(LX_MEM_MAP, self.handle as u64, offset, len, prot as u64)).map(|a| a as *mut u8)
    }

    /// The object's size in pages, and whether it is kept and DMA memory.
    pub fn info(&self) -> Result<(u64, bool, bool), i64> {
        let r = check(lx_mem(LX_MEM_INFO, self.handle as u64, 0, 0, 0))?;
        Ok((r & 0xFFFF_FFFF_FFFF, r >> 48 & 1 == 1, r >> 49 & 1 == 1))
    }

    /// The design's `LX_SVC_SHARE`: puts the object into service `peer_endpoint`'s table
    /// and returns the peer's handle number (tell the peer by your own protocol).
    pub fn share(&self, peer_endpoint: u32) -> Result<u32, i64> {
        check(lx_mem(LX_MEM_SHARE, self.handle as u64, peer_endpoint as u64, 0, 0)).map(|h| h as u32)
    }
}

impl Drop for MemObj {
    fn drop(&mut self) {
        lx_mem(LX_MEM_CLOSE, self.handle as u64, 0, 0, 0);
    }
}

/// Unmaps `len` bytes at `addr` (a range [`MemObj::map`] returned).
pub fn unmap(addr: *mut u8, len: u64) -> Result<(), i64> {
    check(lx_mem(LX_MEM_UNMAP, addr as u64, len, 0, 0)).map(|_| ())
}
