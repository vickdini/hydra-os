//! Fakes for the DRM layer: a caller whose "user pointers" are host pointers, and a screen in
//! memory whose state and clock the test sets.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::RefCell;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Mutex;

use crate::kms::{BoMem, Env};
use crate::native::{Screen, Target};
use crate::proto::{SCREEN_CONSOLE, SCREEN_HIDDEN, SCREEN_SHOWN};

/// Buffer memory on the host heap (a raw allocation: the DRM layer writes through `ptr`).
pub struct HeapMem {
    pub data: *mut [u8],
    pub handle: u32,
}

// SAFETY: plain heap memory owned by this value
unsafe impl Send for HeapMem {}
unsafe impl Sync for HeapMem {}

impl Drop for HeapMem {
    fn drop(&mut self) {
        // SAFETY: made by Box::into_raw in `new_mem`, dropped once
        drop(unsafe { Box::from_raw(self.data) });
    }
}

impl BoMem for HeapMem {
    fn ptr(&self) -> *mut u8 {
        self.data as *mut u8
    }
    fn handle(&self) -> u32 {
        self.handle
    }
}

/// The caller: user memory is host memory; DMA-BUF descriptors are numbered from 100.
#[derive(Default)]
pub struct FakeEnv {
    pub next_handle: RefCell<u32>,
    /// (fd, slot) of each DMA-BUF installed.
    pub dmabufs: RefCell<Vec<(i64, u32)>>,
    /// Fail the next `new_mem`.
    pub no_mem: RefCell<bool>,
    /// The caller lacks CAP_SYS_ADMIN.
    pub unprivileged: RefCell<bool>,
}

impl Env for FakeEnv {
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(-14);
        }
        // SAFETY: the tests pass pointers to their own live buffers
        Ok(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) }.to_vec())
    }

    fn copy_out(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(-14);
        }
        // SAFETY: as `copy_in`
        unsafe { core::ptr::copy_nonoverlapping(data.as_ptr(), ptr as *mut u8, data.len()) };
        Ok(())
    }

    fn new_mem(&self, size: u64) -> Result<Box<dyn BoMem>, i64> {
        if self.no_mem.replace(false) {
            return Err(-12);
        }
        let mut h = self.next_handle.borrow_mut();
        *h += 1;
        Ok(Box::new(HeapMem { data: Box::into_raw(alloc::vec![0u8; size as usize].into_boxed_slice()), handle: *h }))
    }

    fn install_dmabuf(&self, _flags: u32, _size: u64) -> Result<(i64, u32), i64> {
        let mut d = self.dmabufs.borrow_mut();
        let n = d.len() as i64;
        let x = (100 + n, 500 + n as u32);
        d.push(x);
        Ok(x)
    }

    fn privileged(&self) -> bool {
        !*self.unprivileged.borrow()
    }

    fn dmabuf_slot(&self, fd: u32) -> Result<u32, i64> {
        self.dmabufs.borrow().iter().find(|x| x.0 == fd as i64).map(|x| x.1).ok_or(-9)
    }
}

/// What a test sees of its screen.
pub struct ScreenView {
    pub state: AtomicU32,
    pub now: AtomicU64,
    pub takes: AtomicU32,
    pub gives: AtomicU32,
    /// `take` answers hidden (the console shows).
    pub take_hidden: AtomicU32,
    /// `begin`/`end` balance (must be 0 between calls).
    pub open: AtomicU32,
    pub pixels: Mutex<Vec<u8>>,
    pub w: u32,
    pub h: u32,
    pub bgr: bool,
}

impl ScreenView {
    pub fn pixel(&self, x: u32, y: u32) -> u32 {
        let p = self.pixels.lock().unwrap();
        let i = ((y * self.w + x) * 4) as usize;
        u32::from_le_bytes(p[i..i + 4].try_into().unwrap())
    }
    pub fn set_now(&self, ns: u64) {
        self.now.store(ns, Ordering::SeqCst);
    }
}

/// A screen in memory.
pub struct FakeScreen(pub Arc<ScreenView>);

impl FakeScreen {
    pub fn new(w: u32, h: u32, bgr: bool) -> (Box<dyn Screen>, Arc<ScreenView>) {
        let v = Arc::new(ScreenView {
            state: AtomicU32::new(SCREEN_CONSOLE),
            now: AtomicU64::new(1_000_000_000),
            takes: AtomicU32::new(0),
            gives: AtomicU32::new(0),
            take_hidden: AtomicU32::new(0),
            open: AtomicU32::new(0),
            pixels: Mutex::new(alloc::vec![0x55u8; (w * h * 4) as usize]),
            w,
            h,
            bgr,
        });
        (Box::new(FakeScreen(v.clone())), v)
    }
}

impl Screen for FakeScreen {
    fn size(&self) -> (u32, u32) {
        (self.0.w, self.0.h)
    }
    fn take(&mut self) -> i64 {
        self.0.takes.fetch_add(1, Ordering::SeqCst);
        // As the kernel: after a panic the console keeps the screen
        if self.0.state.load(Ordering::SeqCst) == crate::proto::SCREEN_PANIC {
            return -6;
        }
        let st = if self.0.take_hidden.load(Ordering::SeqCst) != 0 { SCREEN_HIDDEN } else { SCREEN_SHOWN };
        self.0.state.store(st, Ordering::SeqCst);
        st as i64
    }
    fn give(&mut self) {
        self.0.gives.fetch_add(1, Ordering::SeqCst);
        self.0.state.store(SCREEN_CONSOLE, Ordering::SeqCst);
    }
    fn state(&self) -> u32 {
        self.0.state.load(Ordering::SeqCst)
    }
    fn begin(&mut self) -> Option<Target> {
        if self.state() != SCREEN_SHOWN {
            return None;
        }
        self.0.open.fetch_add(1, Ordering::SeqCst);
        let ptr = self.0.pixels.lock().unwrap().as_mut_ptr();
        Some(Target { ptr, stride: self.0.w as usize, width: self.0.w, height: self.0.h, bgr: self.0.bgr })
    }
    fn end(&mut self) {
        self.0.open.fetch_sub(1, Ordering::SeqCst);
    }
    fn now_ns(&self) -> u64 {
        self.0.now.load(Ordering::SeqCst)
    }
}
