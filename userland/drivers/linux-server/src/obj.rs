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

/// Slots in use, and the most ever (Group 13: logged every 256, to size the window).
static USED: AtomicU32 = AtomicU32::new(0);
static PEAK: AtomicU32 = AtomicU32::new(0);

/// A free slot for an object of `kind`, its readiness word cleared.
pub fn alloc(kind: u32) -> Result<u32, i64> {
    let r = alloc_slot(kind);
    if r.is_ok() {
        let n = USED.fetch_add(1, Ordering::Relaxed) + 1;
        if n > PEAK.load(Ordering::Relaxed) {
            PEAK.store(n, Ordering::Relaxed);
            if n % 256 == 0 {
                let mut kinds = [0u32; 32];
                for &k in SLOTS.lock().iter() {
                    kinds[(k as usize).min(31)] += 1;
                }
                hydra_rt::println!(
                    "[linux-server] {} objects in use (pipe ends {}, unix {}, eventfd {}, timerfd {}, signalfd {}, pidfd {}, other {})",
                    n,
                    kinds[16] + kinds[17],
                    kinds[18],
                    kinds[19],
                    kinds[20],
                    kinds[21],
                    kinds[22],
                    n - (kinds[16] + kinds[17] + kinds[18] + kinds[19] + kinds[20] + kinds[21] + kinds[22])
                );
            }
        }
    } else {
        hydra_rt::println!("[linux-server] out of object slots ({} in use)", USED.load(Ordering::Relaxed));
    }
    r
}

fn alloc_slot(kind: u32) -> Result<u32, i64> {
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
        let mut s = SLOTS.lock();
        if s[slot as usize] != 0 {
            USED.fetch_sub(1, Ordering::Relaxed);
        }
        s[slot as usize] = 0;
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
    install_tag(cx, slot, kind, flags, mode, uid, gid, name, 0)
}

/// [`install`] with the kernel's value `tag` (`LxObjDesc::tag`: an inode number, a pid).
#[allow(clippy::too_many_arguments)]
pub fn install_tag(cx: &Cx, slot: u32, kind: u32, flags: u32, mode: u32, uid: u32, gid: u32, name: &[u8], tag: u64) -> Result<i64, i64> {
    let mut d = LxObjDesc { slot, kind, flags, mode, uid, gid, name_len: 0, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag, key: 0 }; // wave6 G21: key (LX_SVC_LIST)
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
            test_mem_closed(slot);
        }
        LX_OBJ_KIND_MQ => crate::mqueue::closed(slot),
        LX_OBJ_KIND_BPF_MAP | LX_OBJ_KIND_BPF_PROG | LX_OBJ_KIND_BPF_LINK | LX_OBJ_KIND_BPF_BTF => crate::bpf::closed(slot),
        LX_OBJ_KIND_EVENTFD => crate::eventfd::closed(slot),
        LX_OBJ_KIND_PIPE_R | LX_OBJ_KIND_PIPE_W | LX_OBJ_KIND_PIPE_RW => crate::pipe::closed(slot),
        LX_OBJ_KIND_UNIX => crate::unix::closed(slot),
        LX_OBJ_KIND_PIDFD => crate::pidfd::closed(slot),
        LX_OBJ_KIND_SIGNALFD => crate::signalfd::closed(slot),
        LX_OBJ_KIND_TIMERFD => crate::timerfd::closed(slot),
        LX_OBJ_KIND_PSEUDO => crate::pseudo::closed(slot), // wave7 G7-4
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
    // wave6 G23: bit 32 of the flags: the object's memory is a kept memory object; bit 33:
    // DMA memory
    test_mem_new(slot, flags & 1 << 32 != 0, flags & 1 << 33 != 0);
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
        16 => test_ioctl(slot, cx.args[1], cx.args[2]),
        _ => -25, // ENOTTY
    }
}

// wave6 G23 begin: the test object's memory (memory objects, `srvmap` test)

/// Size of a test object's memory.
const TEST_MEM: u64 = 64 * 1024;
/// The kept test memory's key.
const TEST_KEPT_KEY: u64 = 0x5352_564D_4150; // "SRVMAP"

/// A test object's memory: the handle (0: not made yet), our own view, kept or not.
#[derive(Clone, Copy)]
struct TestMem {
    slot: u32,
    handle: u32,
    addr: u64,
    kept: bool,
    dma: bool,
}

static TEST_MEMS: YLock<alloc::vec::Vec<TestMem>> = YLock::new(alloc::vec::Vec::new());

fn test_mem_new(slot: u32, kept: bool, dma: bool) {
    let mut m = TEST_MEMS.lock();
    m.retain(|t| t.slot != slot);
    m.push(TestMem { slot, handle: 0, addr: 0, kept, dma });
}

/// The test object's memory, made (and mapped here) on first use.
fn test_mem(slot: u32) -> Result<TestMem, i64> {
    let mut m = TEST_MEMS.lock();
    let Some(t) = m.iter_mut().find(|t| t.slot == slot) else { return Err(-22) };
    if t.handle == 0 {
        let (obj, existed) = if t.kept {
            hydra_rt::mem::MemObj::kept(TEST_KEPT_KEY, TEST_MEM)?
        } else if t.dma {
            (hydra_rt::mem::MemObj::dma(TEST_MEM)?.0, false)
        } else {
            (hydra_rt::mem::MemObj::anon(TEST_MEM)?, false)
        };
        let addr = obj.map(0, TEST_MEM, hydra_rt::mem::PROT_RW)? as u64;
        if t.kept {
            hydra_rt::println!("[linux-server] srvmap: kept test memory (handle {}, {})", obj.handle(), if existed { "existed: contents kept" } else { "new" });
        }
        t.handle = obj.into_raw();
        t.addr = addr;
    }
    Ok(*t)
}

fn test_mem_drop(t: &TestMem) {
    if t.addr != 0 {
        let _ = hydra_rt::mem::unmap(t.addr as *mut u8, TEST_MEM);
    }
    if t.handle != 0 {
        drop(hydra_rt::mem::MemObj::from_raw(t.handle));
    }
}

fn test_mem_closed(slot: u32) {
    let t = {
        let mut m = TEST_MEMS.lock();
        let i = m.iter().position(|t| t.slot == slot);
        i.map(|i| m.swap_remove(i))
    };
    if let Some(t) = t {
        test_mem_drop(&t);
    }
}

/// `mmap` of a test object: its memory, from the page `offset` names.
pub fn test_mmap(cx: &Cx) -> i64 {
    let slot = cx.c.obj as u32;
    let (len, offset) = (cx.args[1], cx.args[5]);
    if offset % 4096 != 0 || len == 0 || offset.checked_add(len).map_or(true, |e| e > TEST_MEM) {
        return -22;
    }
    match test_mem(slot) {
        Ok(t) => hydra_rt::mem::lx_mmap_answer(t.handle, offset / 4096, false),
        Err(e) => e,
    }
}

/// `ioctl` on a test object: the server's side of the memory. `0x4D50` peek (`arg` = byte
/// offset; returns the u32 there), `0x4D51` poke (`arg` = offset | value << 32), `0x4D52`
/// drop (the server lets go of its handle and view: only programs' mappings hold the memory),
/// `0x4D53` share (the object goes to a second handle through `LX_MEM_SHARE` with ourselves,
/// which is mapped and written: `arg` as poke), `0x4D54` info (pages | flags << 48).
fn test_ioctl(slot: u32, cmd: u64, arg: u64) -> i64 {
    let off = (arg & 0xFFFF_FFFF) & !3;
    if off >= TEST_MEM {
        return -22;
    }
    match cmd {
        0x4D50 | 0x4D51 | 0x4D53 | 0x4D54 => {
            let t = match test_mem(slot) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let p = (t.addr + off) as *mut u32;
            match cmd {
                // SAFETY: inside our 64 KiB view of the memory
                0x4D50 => unsafe { core::ptr::read_volatile(p) as i64 },
                0x4D51 => {
                    unsafe { core::ptr::write_volatile(p, (arg >> 32) as u32) };
                    0
                }
                0x4D53 => {
                    let me = hydra_rt::mem::MemObj::from_raw(t.handle);
                    let r = me.share(ENDPOINT_LINUX_SERVER);
                    let _ = me.into_raw();
                    let h = match r {
                        Ok(h) => h,
                        Err(e) => return e,
                    };
                    let second = hydra_rt::mem::MemObj::from_raw(h);
                    let q = match second.map(0, TEST_MEM, hydra_rt::mem::PROT_RW) {
                        Ok(q) => q,
                        Err(e) => return e,
                    };
                    // SAFETY: inside the second 64 KiB view
                    unsafe { core::ptr::write_volatile(q.add(off as usize) as *mut u32, (arg >> 32) as u32) };
                    let _ = hydra_rt::mem::unmap(q, TEST_MEM);
                    drop(second);
                    h as i64
                }
                _ => {
                    let me = hydra_rt::mem::MemObj::from_raw(t.handle);
                    let r = me.info();
                    // (the handle stays ours)
                    let _ = me.into_raw();
                    match r {
                        Ok((pages, kept, dma)) => (pages | (kept as u64) << 48 | (dma as u64) << 49) as i64,
                        Err(e) => e,
                    }
                }
            }
        }
        // Share with service endpoint `arg`: the peer's handle number
        0x4D55 => {
            let t = match test_mem(slot) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let me = hydra_rt::mem::MemObj::from_raw(t.handle);
            let r = me.share(arg as u32);
            let _ = me.into_raw();
            r.map_or_else(|e| e, |h| h as i64)
        }
        0x4D52 => {
            let t = {
                let mut m = TEST_MEMS.lock();
                match m.iter_mut().find(|t| t.slot == slot) {
                    Some(t) => {
                        let old = *t;
                        t.handle = 0;
                        t.addr = 0;
                        old
                    }
                    None => return -22,
                }
            };
            test_mem_drop(&t);
            0
        }
        _ => -25, // ENOTTY
    }
}
// wave6 G23 end
