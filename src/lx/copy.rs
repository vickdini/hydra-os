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
//! Wave 6 (Group 22): the user memory is copied straight through the caller's own address
//! space, with fault fix-ups in the trap ([`try_copy`], `arch::idt::uaccess_fixup`), not
//! through the direct map under the address-space lock. The copy-in is made when the call
//! is placed, under the request table's lock, straight into the idle worker's syscall page
//! ([`fill`]); a page not there yet is faulted in the ordinary way ([`fault_in`]) with that
//! lock let go, and the call placed again.

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

use Arg::{In, InOut, None as N, Out, Str};

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
// Group 13 (step 4): timerfd_settime(fd, flags, new, old), timerfd_gettime(fd, cur),
// signalfd4(fd, mask, size, flags)
static TFD_SET: Desc = [N, N, In(fixed(32)), Out(fixed(32)), N, N];
static TFD_GET: Desc = [N, Out(fixed(32)), N, N, N, N];
static SIGNALFD: Desc = [N, In(fixed(8)), N, N, N, N];
// read/write/readv/writev on a server object (forwarded only for those): the buffer, or the
// iovec array (the server reads and writes the pieces themselves)
static READ: Desc = [N, Out(len_arg(2)), N, N, N, N];
static WRITE: Desc = [N, In(len_arg(2)), N, N, N, N];
static IOVEC: Desc = [N, In(Len { fixed: 0, arg: 2, mul: 16 }), N, N, N, N];
// (the socket calls' arms are Group 12's, below; recvmsg's msghdr is InOut: Group 13's
// Unix sockets write it back whole)

// Step 3's socket calls (Group 12; family-independent: Group 13's Unix sockets get the
// same arms). A socket address goes out into 128 bytes of room (the server writes only
// what the caller's `*addrlen` allows) and its length in/out as 4 bytes; a `msghdr` comes
// whole (the server writes it back whole: `msg_namelen`, `msg_controllen`, `msg_flags`),
// its iovecs and control data through the client memory calls.
/// Room for a socket address the server writes (`sockaddr_storage`).
const SOCKADDR_OUT: Len = fixed(128);
/// A `socklen_t`.
const SOCKLEN: Len = fixed(4);
/// connect, bind (fd, addr, addrlen)
static SOCK_ADDR_IN: Desc = [N, In(len_arg(2)), N, N, N, N];
/// accept, accept4, getsockname, getpeername (fd, addr, addrlen*)
static SOCK_ADDR_OUT: Desc = [N, Out(SOCKADDR_OUT), InOut(SOCKLEN), N, N, N];
/// sendto(fd, buf, len, flags, dest, addrlen)
static SENDTO: Desc = [N, In(len_arg(2)), N, N, In(len_arg(5)), N];
/// recvfrom(fd, buf, len, flags, src, addrlen*)
static RECVFROM: Desc = [N, Out(len_arg(2)), N, N, Out(SOCKADDR_OUT), InOut(SOCKLEN)];
/// sendmsg(fd, msg, flags)
static SENDMSG: Desc = [N, In(fixed(56)), N, N, N, N];
/// recvmsg(fd, msg, flags)
static RECVMSG: Desc = [N, InOut(fixed(56)), N, N, N, N];
/// setsockopt(fd, level, name, val, len)
static SETSOCKOPT: Desc = [N, N, N, In(len_arg(4)), N, N];
/// getsockopt(fd, level, name, val, len*): `TCP_INFO` is the largest (232 bytes)
static GETSOCKOPT: Desc = [N, N, N, Out(fixed(256)), InOut(SOCKLEN), N];
/// socketpair(family, type, protocol, sv[2])
static SOCKETPAIR: Desc = [N, N, N, Out(fixed(8)), N, N];

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
        0 => Some(&READ),
        1 => Some(&WRITE),
        19 | 20 => Some(&IOVEC),
        286 => Some(&TFD_SET),
        287 => Some(&TFD_GET),
        282 | 289 => Some(&SIGNALFD),
        // Sockets (step 3)
        42 | 49 => Some(&SOCK_ADDR_IN),
        43 | 288 | 51 | 52 => Some(&SOCK_ADDR_OUT),
        44 => Some(&SENDTO),
        45 => Some(&RECVFROM),
        46 => Some(&SENDMSG),
        47 => Some(&RECVMSG),
        54 => Some(&SETSOCKOPT),
        55 => Some(&GETSOCKOPT),
        53 => Some(&SOCKETPAIR),
        _ => None,
    }
}

/// The copies of one call: the header for the page and the copy area's bytes (offset
/// `LX_DATA_OFF` of the page is `data[0]`). Used for calls that wait in the queue (their
/// bytes wait with them), for kernel-buffer calls, and for the output after the answer.
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

    /// Bytes in use from the start of the copy area (what [`super::deliver`] copies).
    pub fn used_bytes(&self) -> &[u8] {
        &self.data[..self.used]
    }
}

/// Where a call's copies come from.
#[derive(Clone, Copy)]
pub enum Src<'a> {
    /// None (no table entry).
    None,
    /// Made already, in kernel memory (`lx::call_obj_kbuf`).
    Kernel(&'a CopyBuf),
    /// The caller's memory, as this table entry describes: copied when the call is placed.
    /// (By value: lx-sec's bpf element commands add entries per call, `sec::bpf_desc`.)
    User(Desc),
}

/// Why [`fill`] stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FillErr {
    /// A bad pointer: the call fails with `-EFAULT`.
    Fault,
    /// The page at user address `.0` (and the `.1` bytes from there that the argument still
    /// needs) is not there yet: fault it in ([`fault_in`]) and fill again.
    Missing(u64, u64),
}

/// Copies call `args`' pointer arguments that `desc` describes into a copy area `data` (the
/// worker's page from `LX_DATA_OFF`, or a [`CopyBuf`]'s) and sets `hdr` (empty before).
/// Returns the bytes of `data` in use.
///
/// Wave 6, Group 22: this runs under the request table's lock, straight into the worker's
/// syscall page. The user memory is read through the caller's own address space with fault
/// fix-ups ([`try_copy`]), so nothing here waits or faults pages in: a page not there yet is
/// reported as [`FillErr::Missing`], and the caller faults it in after letting the lock go
/// and fills again. A NULL pointer is never copied.
pub fn fill(hdr: &mut LxCopy, data: &mut [u8; LX_DATA_SIZE], desc: &Desc, args: &[u64; 6]) -> Result<usize, FillErr> {
    let mut used = 0usize;
    for (i, d) in desc.iter().enumerate() {
        let ptr = args[i];
        if ptr == 0 {
            continue;
        }
        match *d {
            Arg::None => {}
            Arg::Str(max) => {
                // The string and its NUL, within its limit and what is left
                let room = (max as usize).min(LX_DATA_SIZE - used);
                if room == 0 {
                    continue;
                }
                let off = LX_DATA_OFF + used;
                match try_str(ptr, &mut data[used..used + room]) {
                    StrCopy::Found(n) => {
                        used += n + 1;
                        hdr.in_off[i] = off as u16;
                        hdr.in_len[i] = n as u16;
                    }
                    StrCopy::NoNul => {}
                    StrCopy::Bad => return Err(FillErr::Fault),
                    StrCopy::Missing(at) => return Err(FillErr::Missing(at, 1)),
                }
            }
            Arg::In(len) | Arg::InOut(len) => {
                let Some(n) = len.of(args) else { continue };
                if n == 0 || used + n > LX_DATA_SIZE {
                    continue;
                }
                let off = LX_DATA_OFF + used;
                if !user_ok(ptr, n) {
                    return Err(FillErr::Fault);
                }
                // SAFETY: `ptr..ptr + n` is user memory (checked) of the current address
                // space; `data[used..used + n]` is within the copy area
                let left = unsafe { try_copy(data.as_mut_ptr().add(used), ptr as *const u8, n) };
                if left != 0 {
                    let done = (n - left) as u64;
                    return Err(FillErr::Missing(ptr + done, n as u64 - done));
                }
                used += n;
                hdr.in_off[i] = off as u16;
                hdr.in_len[i] = n as u16;
                if matches!(*d, Arg::InOut(_)) {
                    hdr.out_off[i] = off as u16;
                    hdr.out_cap[i] = n as u16;
                }
            }
            Arg::Out(len) => {
                // As much space as is left, up to the buffer's length: a short answer still
                // fits when the buffer is large
                let want = len.of(args).unwrap_or(LX_DATA_SIZE);
                let n = want.min(LX_DATA_SIZE - used);
                if n == 0 {
                    continue;
                }
                hdr.out_off[i] = (LX_DATA_OFF + used) as u16;
                hdr.out_cap[i] = n as u16;
                used += n;
            }
        }
    }
    Ok(used)
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
// User memory of the calling task (wave 6, Group 22: copies with fault fix-ups)
// ----------------------------------------------------------------------
//
// The forwarding path runs in the caller's own address space (its CR3), so the kernel
// copies straight from and to the user addresses, as Linux's `copy_from_user` does: no
// address-space lock, no page-table walk, no kernel lock. The copying instructions sit in
// the small routines below. A page fault on one of them (a page not there yet, a bad
// pointer, a read-only page written) does not go to the ordinary fault handler: the trap
// entry finds the instruction in its fix-up table (`arch::idt::uaccess_fixup`) and resumes
// at the routine's fix-up label, which returns how far the copy got. The caller then faults
// the page in the ordinary way ([`fault_in`]: demand paging, copy-on-write, file pages,
// under the kernel lock) and tries again; a page that cannot be faulted in is `-EFAULT`.
//
// The addresses are checked to be user addresses first ([`user_ok`]): the routines would
// copy kernel memory just as well. Supervisor write protection (CR0.WP) is on, so a write
// to a read-only (copy-on-write) user page faults as it would from user mode.

#[cfg(target_os = "uefi")]
core::arch::global_asm!(
    r#"
    .text
    // hydra_uaccess_copy(dst rdi, src rsi, n rdx) -> rax = bytes NOT copied (0: all)
    .global hydra_uaccess_copy
    hydra_uaccess_copy:
        mov rcx, rdx
    .global hydra_uaccess_copy_insn
    hydra_uaccess_copy_insn:
        rep movsb
    .global hydra_uaccess_copy_insn_end
    hydra_uaccess_copy_insn_end:
        xor eax, eax
        ret
    // Its fix-up: a fault on `rep movsb` resumes here, rcx = the bytes left
    .global hydra_uaccess_copy_fix
    hydra_uaccess_copy_fix:
        mov rax, rcx
        ret

    // hydra_uaccess_str(dst rdi, src rsi, max rdx) -> rax = the string's length without
    // its NUL (the NUL copied too), -1 = no NUL within max bytes, -2 - k = a fault at src + k
    .global hydra_uaccess_str
    hydra_uaccess_str:
        xor ecx, ecx
    2:
        cmp rcx, rdx
        jae 3f
    .global hydra_uaccess_str_insn
    hydra_uaccess_str_insn:
        movzx eax, byte ptr [rsi + rcx]
    .global hydra_uaccess_str_insn_end
    hydra_uaccess_str_insn_end:
        mov byte ptr [rdi + rcx], al
        test eax, eax
        jz 4f
        inc rcx
        jmp 2b
    4:
        mov rax, rcx
        ret
    3:
        mov rax, -1
        ret
    // Its fix-up: rcx = the offset of the byte that faulted
    .global hydra_uaccess_str_fix
    hydra_uaccess_str_fix:
        mov rax, -2
        sub rax, rcx
        ret
    "#
);

#[cfg(target_os = "uefi")]
extern "sysv64" {
    fn hydra_uaccess_copy(dst: *mut u8, src: *const u8, n: usize) -> usize;
    fn hydra_uaccess_str(dst: *mut u8, src: *const u8, max: usize) -> isize;
}

/// Host tests (test wave, Group 30): the routines' simulation (pages marked missing fault).
#[cfg(not(target_os = "uefi"))]
unsafe fn hydra_uaccess_copy(dst: *mut u8, src: *const u8, n: usize) -> usize {
    crate::host::uaccess_copy(dst, src, n)
}

/// See the other `hydra_uaccess_copy`.
#[cfg(not(target_os = "uefi"))]
unsafe fn hydra_uaccess_str(dst: *mut u8, src: *const u8, max: usize) -> isize {
    crate::host::uaccess_str(dst, src, max)
}

/// Copies `n` bytes from `src` to `dst`, one side being user memory of the current address
/// space: the bytes NOT copied (0: all) when a page faults.
///
/// # Safety
///
/// The kernel side must be valid for `n` bytes; the user side must be a user range
/// ([`user_ok`]).
#[inline]
pub unsafe fn try_copy(dst: *mut u8, src: *const u8, n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    // SAFETY: as the caller promises; a fault is fixed up (see above)
    unsafe { hydra_uaccess_copy(dst, src, n) }
}

/// What [`try_str`] found.
enum StrCopy {
    /// The string's length without its NUL (the NUL copied too).
    Found(usize),
    /// No NUL within the room.
    NoNul,
    /// Not a user address.
    Bad,
    /// The page at this user address is not there yet.
    Missing(u64),
}

/// Copies the NUL-terminated user string at `addr` into `dst`, one page at a time (pages
/// after the NUL are never touched: the string may end just before an unmapped page).
fn try_str(addr: u64, dst: &mut [u8]) -> StrCopy {
    let max = dst.len();
    let mut o = 0usize;
    while o < max {
        let Some(at) = addr.checked_add(o as u64) else { return StrCopy::Bad };
        let n = (4096 - (at & 0xFFF) as usize).min(max - o);
        if !user_ok(at, n) {
            return StrCopy::Bad;
        }
        // SAFETY: `at..at + n` is a user range; `dst[o..o + n]` is ours
        let r = unsafe { hydra_uaccess_str(dst.as_mut_ptr().add(o), at as *const u8, n) };
        if r >= 0 {
            return StrCopy::Found(o + r as usize);
        }
        if r == -1 {
            o += n;
            continue;
        }
        return StrCopy::Missing(at + (-2 - r) as u64);
    }
    StrCopy::NoNul
}

/// `len` bytes at `addr` are user memory of the calling task, which has an address space of
/// its own (the loaded one; legacy tasks share the kernel's and get nothing copied).
#[inline]
fn user_ok(addr: u64, len: usize) -> bool {
    crate::memory::vm::is_user_range(addr, len as u64) && !crate::memory::vm::CURRENT_MM.load(core::sync::atomic::Ordering::Relaxed).is_null()
}

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

/// Pages faulted in for the copies ([`fault_in`]).
pub static FAULT_INS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// Faults `len` bytes at user address `addr` of the calling task in, the ordinary way (it
/// may read a file: under the kernel lock, outside other tasks' driver calls, interrupts
/// on while it runs). The kernel lock, if taken here, stays until the return to user mode.
pub fn fault_in(addr: u64, len: u64, write: bool) -> bool {
    FAULT_INS.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    if crate::memory::vm::CURRENT_MM.load(core::sync::atomic::Ordering::Acquire).is_null() {
        return false;
    }
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

/// Copies `n` bytes between the kernel and user address `addr` (`write`: to it), faulting
/// pages in as needed: `copy(done)` copies from byte `done` on and returns the bytes left.
fn with_faults(addr: u64, n: usize, write: bool, mut copy: impl FnMut(usize) -> usize) -> Result<(), i64> {
    if n == 0 {
        return Ok(());
    }
    if !user_ok(addr, n) {
        return Err(EFAULT);
    }
    let mut done = 0usize;
    // The page faulted in last: when it faults again at once, it cannot be had
    let mut last = u64::MAX;
    loop {
        let left = copy(done);
        if left == 0 {
            return Ok(());
        }
        done = n - left;
        let at = addr + done as u64;
        if at & !0xFFF == last || !fault_in(at, left as u64, write) {
            return Err(EFAULT);
        }
        last = at & !0xFFF;
    }
}

/// Copies `dst.len()` bytes at user address `addr` of the calling task into `dst`.
pub fn read_user(addr: u64, dst: &mut [u8]) -> Result<(), i64> {
    let n = dst.len();
    let p = dst.as_mut_ptr();
    // SAFETY: `dst` is ours; the user range is checked by `with_faults`
    with_faults(addr, n, false, |done| unsafe { try_copy(p.add(done), (addr + done as u64) as *const u8, n - done) })
}

/// Writes `src` to user address `addr` of the calling task.
pub fn write_user(addr: u64, src: &[u8]) -> Result<(), i64> {
    let n = src.len();
    let p = src.as_ptr();
    // SAFETY: as in `read_user`
    with_faults(addr, n, true, |done| unsafe { try_copy((addr + done as u64) as *mut u8, p.add(done), n - done) })
}

/// Reads the NUL-terminated string at user address `addr` into `dst` (the NUL too):
/// `Some(length without the NUL)`, or `None` when there is no NUL within `dst.len()` bytes.
/// Pages after the NUL are never touched.
pub fn read_user_str(addr: u64, dst: &mut [u8]) -> Result<Option<usize>, i64> {
    let mut last = u64::MAX;
    loop {
        match try_str(addr, dst) {
            StrCopy::Found(n) => return Ok(Some(n)),
            StrCopy::NoNul => return Ok(None),
            StrCopy::Bad => return Err(EFAULT),
            StrCopy::Missing(at) => {
                if at & !0xFFF == last || !fault_in(at, 1, false) {
                    return Err(EFAULT);
                }
                last = at & !0xFFF;
            }
        }
    }
}
