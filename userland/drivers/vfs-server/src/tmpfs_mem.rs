//! # tmpfs file data in kernel memory objects (wave 7, Group 7-3)
//!
//! vfs-server's [`DataStore`] for [`super::tmpfs`]: one anonymous memory object
//! (`LX_MEM_ANON`, `src/lx/mem.rs`) per file with data, [`MAX_FILE`] bytes long. Anonymous
//! objects are sparse (a page exists once written), so the size costs nothing; the same
//! object is what a program's file handle reads and maps (Group 7-2's tmpfs handles), so
//! the data never passes through the server on those paths.
//!
//! The server reaches the data through short-lived windows: [`MemObj::map`] of the pages a
//! request touches (at most [`WINDOW`] at a time), the copy, [`unmap`]. The key of an
//! object is its handle number in the server's table.
//!
//! The copies use raw pointers, never Rust references, over the window: programs may map
//! the same pages and change them at any time (shared memory, as between processes).
//!
//! Limits of the kernel side today (see NOTES.md, Group 7-3): a service has at most
//! `LX_MEM_HANDLES` (4096) handles, so at most that many tmpfs files can hold data; there
//! is no call that frees pages inside an object, so a truncation **zeroes** the cut range
//! instead of freeing it, which touches (and so allocates) the holes in that range: a large
//! sparse file cut down costs memory until `LX_MEM_TRUNC` exists; the handles go when the
//! service ends (`service_gone`), so the data does not yet survive a restart of
//! vfs-server. A request that fails in a later window leaves the earlier windows done.

use alloc::collections::BTreeMap;

use hydra_rt::mem::{unmap, MemObj, PROT_READ, PROT_RW};

use crate::tmpfs::{DataStore, MAX_FILE, PAGE};

/// Largest window mapped at once.
pub const WINDOW: u64 = 1 << 20;
const EINVAL: i64 = -22;
const EBADF: i64 = -9;

/// The memory objects of every tmpfs file with data, by handle number.
#[derive(Default)]
pub struct MemStore {
    objs: BTreeMap<u64, MemObj>,
}

impl MemStore {
    pub fn new() -> MemStore {
        MemStore { objs: BTreeMap::new() }
    }

    /// The handle of key `key` (for a kernel file handle or an `mmap` answer).
    pub fn handle(&self, key: u64) -> Option<u32> {
        self.objs.get(&key).map(|o| o.handle())
    }

    /// Number of objects held.
    pub fn len(&self) -> usize {
        self.objs.len()
    }

    /// Runs `f` on the bytes `[off, off + len)` of object `key`, window by window (mapped
    /// with `prot`): `f` gets a pointer to the window's first byte, its length, and its
    /// position in the range.
    fn each_window(&self, key: u64, off: u64, len: u64, prot: u32, mut f: impl FnMut(*mut u8, usize, usize)) -> Result<(), i64> {
        let obj = self.objs.get(&key).ok_or(EBADF)?;
        if off.checked_add(len).map_or(true, |end| end > MAX_FILE) {
            return Err(EINVAL);
        }
        let mut done = 0u64;
        while done < len {
            let pos = off + done;
            let base = pos & !(PAGE - 1);
            let n = (len - done).min(WINDOW - (pos - base));
            let map_len = (pos - base + n).div_ceil(PAGE) * PAGE;
            let p = obj.map(base, map_len, prot)?;
            // SAFETY: the kernel just mapped `map_len` bytes at `p`; `n` bytes from
            // `pos - base` lie inside the mapping, which stays until the unmap below
            f(unsafe { p.add((pos - base) as usize) }, n as usize, done as usize);
            unmap(p, map_len)?;
            done += n;
        }
        Ok(())
    }
}

impl DataStore for MemStore {
    fn create(&mut self) -> Result<u64, i64> {
        let o = MemObj::anon(MAX_FILE)?;
        let key = o.handle() as u64;
        self.objs.insert(key, o);
        Ok(key)
    }

    fn write(&mut self, key: u64, off: u64, data: &[u8]) -> Result<(), i64> {
        // SAFETY (all three): `w` points at `n` mapped bytes (see each_window); the other
        // side is a slice of at least `at + n` bytes; raw copies make no reference to the
        // shared pages
        self.each_window(key, off, data.len() as u64, PROT_RW, |w, n, at| unsafe { core::ptr::copy_nonoverlapping(data.as_ptr().add(at), w, n) })
    }

    fn read(&mut self, key: u64, off: u64, buf: &mut [u8]) -> Result<(), i64> {
        let len = buf.len() as u64;
        let dst = buf.as_mut_ptr();
        self.each_window(key, off, len, PROT_READ, |w, n, at| unsafe { core::ptr::copy_nonoverlapping(w, dst.add(at), n) })
    }

    fn truncate(&mut self, key: u64, size: u64, old: u64) -> Result<(), i64> {
        if old <= size {
            return Ok(());
        }
        self.each_window(key, size, old - size, PROT_RW, |w, n, _| unsafe { core::ptr::write_bytes(w, 0, n) })
    }

    fn free(&mut self, key: u64) {
        // Dropping the handle closes it; programs' mappings keep their pages
        self.objs.remove(&key);
    }
}
