//! Server objects (wave 4, step 2): the server's side of the kernel's server-object
//! descriptors (`src/lx/obj.rs`).
//!
//! An object (an open message queue, a bpf map, ...) has a *slot* chosen here. The kernel
//! keeps the descriptor and tells us when its last reference goes ([`LX_NOTE_CLOSE`]); we
//! keep the object's readiness word in our window ([`LX_OBJ_OFF`]): `poll`, `select` and
//! `epoll` read it in the kernel without asking us. After changing words we mark the slots
//! in the changed bitmap and ring the doorbell once ([`flush`]), and the kernel wakes the
//! waiters.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use hydra_rt::protocol::*;
use hydra_rt::sys;

use crate::client::Cx;
use crate::lock::YLock;

const ENFILE: i64 = -23;

/// The window's address (0: not set yet).
static BASE: AtomicU64 = AtomicU64::new(0);
/// Words changed since the last doorbell.
static DIRTY: AtomicBool = AtomicBool::new(false);
/// Slots in use, and each one's kind.
static SLOTS: YLock<[u8; LX_OBJ_SLOTS]> = YLock::new([0; LX_OBJ_SLOTS]);
/// Where the next search for a free slot starts (slots are reused late).
static NEXT: AtomicU32 = AtomicU32::new(0);

/// Sets the window (the kernel empties the slots when the server goes online).
pub fn init(window: *mut u8) {
    BASE.store(window as u64, Ordering::Release);
}

/// A free slot for an object of `kind`, its readiness word cleared.
pub fn alloc(kind: u32) -> Result<u32, i64> {
    let mut s = SLOTS.lock();
    let start = NEXT.load(Ordering::Relaxed) as usize;
    for k in 0..LX_OBJ_SLOTS {
        let i = (start + k) % LX_OBJ_SLOTS;
        if s[i] == 0 {
            s[i] = kind as u8;
            NEXT.store(((i + 1) % LX_OBJ_SLOTS) as u32, Ordering::Relaxed);
            write_word(i as u32, 0, 0, 0);
            // Nobody waits for the new object yet
            // SAFETY: the bitmap lies in the window; the kernel sets bits with atomic or
            unsafe { (*bitmap(LX_OBJ_WATCHED_OFF).add(i / 64)).fetch_and(!(1 << (i % 64)), Ordering::AcqRel) };
            return Ok(i as u32);
        }
    }
    Err(ENFILE)
}

/// The kind of the object in slot `slot` (0: free).
pub fn kind_of(slot: u32) -> u32 {
    if (slot as usize) < LX_OBJ_SLOTS {
        SLOTS.lock()[slot as usize] as u32
    } else {
        0
    }
}

/// Lets slot `slot` go (its object ended).
pub fn free(slot: u32) {
    if (slot as usize) < LX_OBJ_SLOTS {
        SLOTS.lock()[slot as usize] = 0;
    }
}

/// The bitmap at window offset `off`, as u64 words.
fn bitmap(off: usize) -> *const AtomicU64 {
    (BASE.load(Ordering::Acquire) + off as u64) as *const AtomicU64
}

fn word_ptr(slot: u32) -> *mut u32 {
    (BASE.load(Ordering::Acquire) + LX_OBJ_OFF as u64 + 16 * slot as u64) as *mut u32
}

fn write_word(slot: u32, ready: u32, edges: u32, size: u64) {
    let p = word_ptr(slot);
    // SAFETY: the slot lies in the mapped window
    unsafe {
        core::ptr::write_volatile(p.add(2) as *mut u64, size);
        core::ptr::write_volatile(p.add(1), edges);
        core::ptr::write_volatile(p, ready);
    }
}

/// Sets slot `slot`'s readiness to `ready` (poll bits) and its size; when anything changed
/// the slot is marked for the next [`flush`]. The edge count grows when bits are added.
pub fn set_ready(slot: u32, ready: u32, size: u64) {
    set_ready_ev(slot, ready, size, false);
}

/// [`set_ready`]; `event`: something new happened (a message arrived) even if the bits stay
/// the same, so an edge-triggered watch reports again (as Linux's wakeups do).
pub fn set_ready_ev(slot: u32, ready: u32, size: u64, event: bool) {
    if BASE.load(Ordering::Acquire) == 0 || slot as usize >= LX_OBJ_SLOTS {
        return;
    }
    let p = word_ptr(slot);
    // SAFETY: the slot lies in the mapped window; only the server writes it
    let (old, edges, old_size) = unsafe { (core::ptr::read_volatile(p), core::ptr::read_volatile(p.add(1)), core::ptr::read_volatile(p.add(2) as *const u64)) };
    let event = event && ready != 0;
    if old == ready && old_size == size && !event {
        return;
    }
    let edges = if ready & !old != 0 || event { edges.wrapping_add(1) } else { edges };
    write_word(slot, ready, edges, size);
    // The doorbell only for an object someone waits on (the kernel marks it before it reads
    // the word; the fence orders this write before that read)
    core::sync::atomic::fence(Ordering::SeqCst);
    let (w, b) = (slot as usize / 64, 1u64 << (slot % 64));
    // SAFETY: the bitmaps lie in the window
    let watched = unsafe { (*bitmap(LX_OBJ_WATCHED_OFF).add(w)).load(Ordering::SeqCst) } & b != 0;
    if watched {
        // SAFETY: as above; the kernel takes the changed bits with atomic swaps
        unsafe { (*bitmap(LX_OBJ_CHANGED_OFF).add(w)).fetch_or(b, Ordering::AcqRel) };
        DIRTY.store(true, Ordering::Release);
    }
}

/// Rings the doorbell if words changed since the last time: the kernel wakes the waiters of
/// the marked slots.
pub fn flush() {
    if DIRTY.swap(false, Ordering::AcqRel) {
        sys::svc_signal(ENDPOINT_LINUX_SERVER, LX_SIGNAL_OBJS);
    }
}

/// Installs a descriptor for the object in slot `slot` in the caller's table and returns it.
/// On an error the caller frees the slot and its own state.
#[allow(clippy::too_many_arguments)]
pub fn install(cx: &Cx, slot: u32, kind: u32, flags: u32, mode: u32, uid: u32, gid: u32, name: &[u8]) -> Result<i64, i64> {
    let mut d = LxObjDesc { slot, kind, flags, mode, uid, gid, name_len: 0, pad: 0, name: [0; LX_OBJ_NAME_MAX] };
    let n = name.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&name[..n]);
    d.name_len = n as u32;
    sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0).map(|fd| fd as i64)
}

/// The object behind descriptor `fd` of the caller: `(slot, kind, nonblock)`.
pub fn of_fd(cx: &Cx, fd: u64) -> Result<(u32, u32, bool), i64> {
    let v = sys::lx_obj(LX_OBJ_FD, cx.id, fd, 0)?;
    Ok((v as u32, (v >> 32) as u32 & 0xFFFF, v & (1 << 62) != 0))
}

/// The last descriptor of slot `slot` (an object of `kind`) went away.
pub fn closed(slot: u32, kind: u32) {
    match kind {
        LX_OBJ_KIND_TEST => {
            TEST_CLOSES.fetch_add(1, Ordering::Relaxed);
        }
        LX_OBJ_KIND_MQ => crate::mqueue::closed(slot),
        LX_OBJ_KIND_BPF_MAP | LX_OBJ_KIND_BPF_PROG | LX_OBJ_KIND_BPF_LINK | LX_OBJ_KIND_BPF_BTF => crate::bpf::closed(slot),
        LX_OBJ_KIND_INET => {
            crate::socket::closed(slot);
            crate::inet::closed(slot);
        }
        LX_OBJ_KIND_NETLINK => {
            crate::socket::closed(slot);
            crate::netlink::closed(slot);
        }
        _ => {}
    }
    set_ready(slot, 0, 0);
    free(slot);
}

// ----------------------------------------------------------------------
// The test object (LX_NULL_OBJ)
// ----------------------------------------------------------------------

/// Test objects closed since the server started.
pub static TEST_CLOSES: AtomicU64 = AtomicU64::new(0);

/// [`LX_NULL_OBJ`]: a new test object; returns its descriptor.
pub fn test_new(cx: &Cx, flags: u64) -> i64 {
    let slot = match alloc(LX_OBJ_KIND_TEST) {
        Ok(s) => s,
        Err(e) => return e,
    };
    match install(cx, slot, LX_OBJ_KIND_TEST, flags as u32 & 0o2004000, 0o100600, cx.c.euid, cx.c.egid, b"anon_inode:[hydra-test]") {
        Ok(fd) => fd,
        Err(e) => {
            free(slot);
            e
        }
    }
}

/// `read`/`write`/`ioctl` on a test object.
pub fn test_io(cx: &Cx) -> i64 {
    let slot = cx.c.obj as u32;
    match cx.nr {
        0 => {
            let text = alloc::format!("slot {}\n", slot);
            let n = text.len().min(cx.args[2] as usize);
            match cx.copy_out(cx.args[1], &text.as_bytes()[..n]) {
                Ok(()) => n as i64,
                Err(e) => e,
            }
        }
        1 => {
            let len = (cx.args[2] as usize).min(64);
            let data = match cx.copy_in(cx.args[1], len) {
                Ok(d) => d,
                Err(e) => return e,
            };
            let p = word_ptr(slot);
            // SAFETY: the slot lies in the mapped window
            let mut ready = unsafe { core::ptr::read_volatile(p) };
            for b in &data {
                match b {
                    b'r' => ready |= 0x41,
                    b'w' => ready |= 0x104,
                    b'c' => ready = 0,
                    _ => {}
                }
            }
            set_ready(slot, ready, 0);
            len as i64
        }
        _ => -25, // ENOTTY
    }
}
