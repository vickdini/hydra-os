//! # The copy-in/copy-out table (wave 4, Group 10)
//!
//! Without it, every pointer argument of a forwarded call costs the server a client memory
//! call (`SYS_LX_READ*` / `SYS_LX_WRITE`), about one system call each. With it, the kernel
//! copies the pointer arguments a call is known to have (a NUL-terminated string, a
//! fixed-size structure, a buffer whose length is another argument) into the syscall page
//! at trap time, and copies back what the server leaves there for output after the answer
//! (`docs/linux-server-design.md` 6.3; the page layout is [`LxCopy`] in `ipc::protocol`).
//!
//! - [`describe`] is the table: one `match` arm per forwarded call that has pointer
//!   arguments, giving a [`Desc`] (what each of the six arguments is). Multiplexed calls
//!   (`keyctl`) pick the `Desc` by an argument.
//! - A NULL pointer is never copied and never faults: the server decides what it means.
//! - A non-NULL input pointer that faults makes the call fail with `-EFAULT` at once,
//!   without the server.
//! - Anything that does not fit (a string without a NUL within its limit, a buffer larger
//!   than what is left of the copy area) is not copied, and the server uses the client
//!   memory primitives as before. The server's helpers (`linux-server/src/client.rs`) look
//!   in the page first and fall back by themselves.
//! - Output is copied after an immediate answer only; a copy-out that faults turns the
//!   result into `-EFAULT`.
//!
//! The user memory is reached through the kernel's direct map while the caller's address
//! space lock is held (so another thread cannot unmap it meanwhile), and only pages present
//! now are used; a missing page is faulted in the ordinary way ([`fault_in`]) and the copy
//! tried again.

use crate::ipc::protocol::{LxCopy, LX_DATA_OFF, LX_DATA_SIZE};

const EFAULT: i64 = -14;

/// A length: `fixed + mul * args[arg]` bytes (`arg` [`NO_ARG`]: just `fixed`).
#[derive(Clone, Copy)]
pub struct Len {
    /// Bytes always.
    pub fixed: u16,
    /// The argument holding a count, or [`NO_ARG`].
    pub arg: u8,
    /// Bytes per unit of that count.
    pub mul: u16,
}

/// [`Len::arg`]: no argument.
pub const NO_ARG: u8 = 0xFF;

/// A fixed size (a structure).
pub const fn fixed(n: u16) -> Len {
    Len { fixed: n, arg: NO_ARG, mul: 0 }
}

/// A buffer whose length in bytes is argument `i`.
pub const fn len_arg(i: u8) -> Len {
    Len { fixed: 0, arg: i, mul: 1 }
}

impl Len {
    /// The length for these arguments (`None`: more than fits anyway).
    fn of(&self, args: &[u64; 6]) -> Option<usize> {
        let var = if self.arg == NO_ARG { 0 } else { args.get(self.arg as usize)?.checked_mul(self.mul as u64)? };
        let n = var.checked_add(self.fixed as u64)?;
        (n <= LX_DATA_SIZE as u64).then_some(n as usize)
    }
}

/// What one argument of a call is.
#[derive(Clone, Copy)]
pub enum Arg {
    /// Not a pointer the table copies.
    None,
    /// A NUL-terminated string of at most this many bytes, the NUL included.
    Str(u16),
    /// Input bytes.
    In(Len),
    /// Output bytes (space in the page; the server says how much it wrote).
    Out(Len),
    /// Input bytes that the server may change and send back.
    InOut(Len),
}

/// What the six arguments of a call are.
pub type Desc = [Arg; 6];

use Arg::{In, None as N, Out, Str};

/// Strings of the key service (type, description, keyring name): Linux limits them to
/// 4095 bytes plus the NUL.
const KEY_STR: u16 = 4096;

static ADD_KEY: Desc = [Str(KEY_STR), Str(KEY_STR), In(len_arg(3)), N, N, N];
static REQUEST_KEY: Desc = [Str(KEY_STR), Str(KEY_STR), Str(KEY_STR), N, N, N];
/// `keyctl(op, a2, a3, a4, a5)`: `args[0]` is the operation.
static KEYCTL_JOIN: Desc = [N, Str(KEY_STR), N, N, N, N];
static KEYCTL_UPDATE: Desc = [N, N, In(len_arg(3)), N, N, N];
static KEYCTL_BUF_OUT: Desc = [N, N, Out(len_arg(3)), N, N, N];
static KEYCTL_SEARCH: Desc = [N, N, Str(KEY_STR), Str(KEY_STR), N, N];
static KEYCTL_CAPS: Desc = [N, Out(len_arg(2)), N, N, N, N];

/// A length of `fixed` bytes plus argument `i` bytes (a header before a buffer).
const fn fixed_plus_arg(fixed: u16, i: u8) -> Len {
    Len { fixed, arg: i, mul: 1 }
}
/// A `struct timespec`.
const TIMESPEC: Len = fixed(16);
/// `struct sembuf` entries: 6 bytes each, their count in argument `i`.
const fn sembufs(i: u8) -> Len {
    Len { fixed: 0, arg: i, mul: 6 }
}

// Step 2's calls (Group 9's server reads exactly these lengths; anything else falls back to
// the client memory calls)
/// mq_timedsend(mqd, msg, len, prio, abs_timeout)
static MQ_SEND: Desc = [N, In(len_arg(2)), N, N, In(TIMESPEC), N];
/// mq_timedreceive(mqd, msg, len, prio_ptr, abs_timeout)
static MQ_RECEIVE: Desc = [N, Out(len_arg(2)), N, Out(fixed(4)), In(TIMESPEC), N];
/// semop(id, sops, nsops)
static SEMOP: Desc = [N, In(sembufs(2)), N, N, N, N];
/// semtimedop(id, sops, nsops, timeout)
static SEMTIMEDOP: Desc = [N, In(sembufs(2)), N, In(TIMESPEC), N, N];
/// msgsnd(id, msgp, size, flags): `mtype` (8 bytes) and the text
static MSGSND: Desc = [N, In(fixed_plus_arg(8, 2)), N, N, N, N];
/// msgrcv(id, msgp, size, type, flags)
static MSGRCV: Desc = [N, Out(fixed_plus_arg(8, 2)), N, N, N, N];
/// bpf(cmd, attr, size): the attribute block in only (some commands write parts of it back
/// themselves, which a copy-back of the whole block would overwrite)
static BPF: Desc = [N, In(len_arg(2)), N, N, N, N];

/// The table: what the pointer arguments of forwarded call `nr` (with arguments `a`) are,
/// or `None` when it has none the table copies. One arm per call.
pub fn describe(nr: u64, a: &[u64; 6]) -> Option<&'static Desc> {
    match nr {
        // add_key, request_key
        248 => Some(&ADD_KEY),
        249 => Some(&REQUEST_KEY),
        // keyctl, by operation
        250 => match a[0] {
            1 => Some(&KEYCTL_JOIN),            // JOIN_SESSION_KEYRING
            2 => Some(&KEYCTL_UPDATE),          // UPDATE
            6 | 11 | 17 => Some(&KEYCTL_BUF_OUT), // DESCRIBE, READ, GET_SECURITY
            10 => Some(&KEYCTL_SEARCH),         // SEARCH
            31 => Some(&KEYCTL_CAPS),           // CAPABILITIES
            _ => None,
        },
        242 => Some(&MQ_SEND),
        243 => Some(&MQ_RECEIVE),
        65 => Some(&SEMOP),
        220 => Some(&SEMTIMEDOP),
        69 => Some(&MSGSND),
        70 => Some(&MSGRCV),
        321 => Some(&BPF),
        _ => None,
    }
}

/// The copies of one call: the header for the page and the copy area's bytes (offset
/// `LX_DATA_OFF` of the page is `data[0]`).
#[repr(C)]
pub struct CopyBuf {
    /// The page's [`LxCopy`].
    pub hdr: LxCopy,
    /// Bytes of `data` in use (copied in, or reserved for output).
    pub used: usize,
    /// The copy area.
    pub data: [u8; LX_DATA_SIZE],
}

impl CopyBuf {
    /// No copies.
    pub const EMPTY: Self = Self { hdr: LxCopy::EMPTY, used: 0, data: [0; LX_DATA_SIZE] };

    /// Room for `n` bytes in the copy area: its page offset.
    fn take(&mut self, n: usize) -> Option<u16> {
        if n == 0 || self.used + n > LX_DATA_SIZE {
            return None;
        }
        let off = LX_DATA_OFF + self.used;
        self.used += n;
        Some(off as u16)
    }

    /// The copy area at page offset `off`.
    fn at(&mut self, off: u16, n: usize) -> &mut [u8] {
        let o = off as usize - LX_DATA_OFF;
        &mut self.data[o..o + n]
    }

    /// Bytes in use from the start of the copy area (what [`super::deliver`] copies).
    pub fn used_bytes(&self) -> &[u8] {
        &self.data[..self.used]
    }
}

/// Copies call `args`' pointer arguments that `desc` describes into `buf` (empty before).
///
/// # Errors
///
/// `-EFAULT` for a non-NULL input pointer that faults.
pub fn fill(buf: &mut CopyBuf, desc: &Desc, args: &[u64; 6]) -> Result<(), i64> {
    for (i, d) in desc.iter().enumerate() {
        let ptr = args[i];
        if ptr == 0 {
            continue;
        }
        match *d {
            Arg::None => {}
            Arg::Str(max) => {
                // The string and its NUL, within its limit and what is left
                let room = (max as usize).min(LX_DATA_SIZE - buf.used);
                if room == 0 {
                    continue;
                }
                let off = (LX_DATA_OFF + buf.used) as u16;
                let found = read_user_str(ptr, buf.at(off, room))?;
                if let Some(n) = found {
                    buf.used += n + 1;
                    buf.hdr.in_off[i] = off;
                    buf.hdr.in_len[i] = n as u16;
                }
            }
            Arg::In(len) | Arg::InOut(len) => {
                let Some(n) = len.of(args) else { continue };
                if n == 0 {
                    continue;
                }
                let Some(off) = buf.take(n) else { continue };
                read_user(ptr, buf.at(off, n))?;
                buf.hdr.in_off[i] = off;
                buf.hdr.in_len[i] = n as u16;
                if matches!(*d, Arg::InOut(_)) {
                    buf.hdr.out_off[i] = off;
                    buf.hdr.out_cap[i] = n as u16;
                }
            }
            Arg::Out(len) => {
                // As much space as is left, up to the buffer's length: a short answer still
                // fits when the buffer is large
                let want = match len.of(args) {
                    Some(n) => n,
                    None => LX_DATA_SIZE,
                };
                let n = want.min(LX_DATA_SIZE - buf.used);
                let Some(off) = buf.take(n) else { continue };
                buf.hdr.out_off[i] = off;
                buf.hdr.out_cap[i] = n as u16;
            }
        }
    }
    Ok(())
}

/// Takes the output the server wrote (`out_len` of the page's header, `page_data` = the
/// page's copy area) into `buf`, whose offsets and capacities (set by [`fill`]) are the
/// kernel's own: the server cannot point the copy anywhere else.
pub fn take_output(buf: &mut CopyBuf, out_len: &[u16; 6], page_data: &[u8]) {
    for i in 0..6 {
        let (off, cap) = (buf.hdr.out_off[i], buf.hdr.out_cap[i]);
        let n = if off == 0 { 0 } else { out_len[i].min(cap) };
        buf.hdr.out_len[i] = n;
        if n > 0 {
            let o = off as usize - LX_DATA_OFF;
            buf.data[o..o + n as usize].copy_from_slice(&page_data[o..o + n as usize]);
        }
    }
}

/// Copies the output in `buf` (after [`take_output`]) to the caller's pointers.
///
/// # Errors
///
/// `-EFAULT` if an output pointer faults.
pub fn copy_out(buf: &CopyBuf, args: &[u64; 6]) -> Result<(), i64> {
    for i in 0..6 {
        let n = buf.hdr.out_len[i] as usize;
        if n > 0 {
            let o = buf.hdr.out_off[i] as usize - LX_DATA_OFF;
            write_user(args[i], &buf.data[o..o + n])?;
        }
    }
    Ok(())
}

/// Whether the call has output to copy back.
pub fn has_output(buf: &CopyBuf) -> bool {
    buf.hdr.out_len.iter().any(|&n| n > 0)
}

// ----------------------------------------------------------------------
// User memory of the calling task
// ----------------------------------------------------------------------

/// Locks `m`, serving TLB flush requests while waiting: its holder may be waiting for this
/// CPU's flush (interrupts are off here), as with the scheduler's lock.
pub fn lock_serving<T>(m: &spin::Mutex<T>) -> spin::MutexGuard<'_, T> {
    loop {
        if let Some(g) = m.try_lock() {
            return g;
        }
        while m.is_locked() {
            crate::arch::smp::serve_tlb();
            core::hint::spin_loop();
        }
    }
}

/// Runs `f(kernel address, bytes)` on each piece of `len` bytes at user address `addr`
/// (within one page each), with the calling task's address space locked and every page
/// present (writable, for `write`). A missing page is faulted in ([`fault_in`]) once.
/// `f` returns `false` to stop early.
fn each_piece(addr: u64, len: usize, write: bool, mut f: impl FnMut(*mut u8, usize) -> bool) -> Result<(), i64> {
    if len == 0 {
        return Ok(());
    }
    if !crate::memory::vm::is_user_range(addr, len as u64) {
        return Err(EFAULT);
    }
    let mm = crate::memory::vm::CURRENT_MM.load(core::sync::atomic::Ordering::Acquire);
    if mm.is_null() {
        return Err(EFAULT);
    }
    // SAFETY: the current task's address space, alive while it runs
    let mm = unsafe { &*mm };
    let mut done = 0usize;
    let mut faulted = false;
    // Announced before the lock is taken, withdrawn after it is released: a fault handler
    // on another CPU finding the lock busy then waits (memory::vm::LX_COPY_MM)
    let marker = &crate::memory::vm::LX_COPY_MM[crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1)];
    struct Unmark<'a>(&'a core::sync::atomic::AtomicU64);
    impl Drop for Unmark<'_> {
        fn drop(&mut self) {
            self.0.store(0, core::sync::atomic::Ordering::SeqCst);
        }
    }
    while done < len {
        let at = addr + done as u64;
        let n = (4096 - (at & 0xFFF) as usize).min(len - done);
        // Without the kernel lock, never wait for an address-space lock: its holder may be in a
        // driver call (a page fault reading a file) that needs this CPU's patience under the
        // ordinary rules; take the kernel lock and wait out driver calls first
        marker.store(mm as *const spin::Mutex<crate::memory::vm::Mm> as u64, core::sync::atomic::Ordering::SeqCst);
        let unmark = Unmark(marker);
        let mut m = match mm.try_lock() {
            Some(g) => g,
            None => {
                // (under the kernel lock no fault handler runs meanwhile: no mark needed)
                marker.store(0, core::sync::atomic::Ordering::SeqCst);
                if !crate::arch::smp::bkl_held() {
                    crate::arch::smp::bkl_enter();
                    crate::task::scheduler::wait_out_handoff();
                }
                lock_serving(mm)
            }
        };
        let Some(phys) = m.present_user(at, write) else {
            drop(m);
            drop(unmark);
            if faulted || !fault_in(at, n as u64, write) {
                return Err(EFAULT);
            }
            faulted = true;
            continue;
        };
        faulted = false;
        let p = crate::memory::frame_allocator::phys_to_virt(phys.as_u64());
        let more = f(p, n);
        drop(m);
        drop(unmark);
        if !more {
            return Ok(());
        }
        done += n;
    }
    Ok(())
}

/// Faults `len` bytes at user address `addr` of the calling task in, the ordinary way (it
/// may read a file: under the kernel lock, outside other tasks' driver calls, interrupts
/// on while it runs). The kernel lock, if taken here, stays until the return to user mode.
pub fn fault_in(addr: u64, len: u64, write: bool) -> bool {
    if !crate::arch::smp::bkl_held() {
        crate::arch::smp::bkl_enter();
        crate::task::scheduler::wait_out_handoff();
    }
    let was_on = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::enable();
    let ok = crate::memory::vm::prefault_current(addr, len, write);
    if !was_on {
        x86_64::instructions::interrupts::disable();
    }
    ok
}

/// Copies `dst.len()` bytes at user address `addr` of the calling task into `dst`.
pub fn read_user(addr: u64, dst: &mut [u8]) -> Result<(), i64> {
    let mut o = 0;
    each_piece(addr, dst.len(), false, |p, n| {
        // SAFETY: a present page of the caller, reached through the direct map, locked
        unsafe { core::ptr::copy_nonoverlapping(p as *const u8, dst.as_mut_ptr().add(o), n) };
        o += n;
        true
    })
}

/// Writes `src` to user address `addr` of the calling task.
pub fn write_user(addr: u64, src: &[u8]) -> Result<(), i64> {
    let mut o = 0;
    each_piece(addr, src.len(), true, |p, n| {
        // SAFETY: as in `read_user`, the page writable
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr().add(o), p, n) };
        o += n;
        true
    })
}

/// Reads the NUL-terminated string at user address `addr` into `dst` (the NUL too):
/// `Some(length without the NUL)`, or `None` when there is no NUL within `dst.len()` bytes.
/// Pages after the NUL are never touched.
pub fn read_user_str(addr: u64, dst: &mut [u8]) -> Result<Option<usize>, i64> {
    let mut o = 0;
    let mut found = None;
    let max = dst.len();
    // One page at a time: the string may end just before an unmapped page
    while o < max && found.is_none() {
        let at = match addr.checked_add(o as u64) {
            Some(a) => a,
            None => return Err(EFAULT),
        };
        let n = (4096 - (at & 0xFFF) as usize).min(max - o);
        each_piece(at, n, false, |p, k| {
            // SAFETY: as in `read_user`
            let src = unsafe { core::slice::from_raw_parts(p as *const u8, k) };
            let end = src.iter().position(|&b| b == 0);
            let take = end.map_or(k, |e| e + 1);
            dst[o..o + take].copy_from_slice(&src[..take]);
            if let Some(e) = end {
                found = Some(o + e);
            }
            o += take;
            true
        })?;
    }
    Ok(found)
}
