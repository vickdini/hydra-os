//! Native Hydra system calls (`syscall`: number in `rax`, arguments in `rdi`, `rsi`,
//! `rdx`; result in `rax`, negative errno on failure). Numbers as in the kernel's
//! `arch/syscall.rs`.

const SYS_YIELD: u64 = 1;
const SYS_SLEEP: u64 = 2;
const SYS_WRITE: u64 = 3;
const SYS_EXIT: u64 = 4;
const SYS_GETPID: u64 = 5;
const SYS_UPTIME: u64 = 6;
const SYS_IOPL: u64 = 20;
const SYS_PHYSMAP: u64 = 21;
const SYS_DMA_ALLOC: u64 = 22;
const SYS_IRQ_REGISTER: u64 = 23;
const SYS_SVC_REGISTER: u64 = 24;
const SYS_SVC_RECV: u64 = 25;
const SYS_SVC_REPLY: u64 = 26;
const SYS_SVC_CALL: u64 = 27;
const SYS_MAP_ANON: u64 = 28;
const SYS_IRQ_WAIT: u64 = 29;
const SYS_IRQ_ACK: u64 = 30;
const SYS_CLOCK: u64 = 31;
const SYS_SVC_ATTACH: u64 = 32;
const SYS_SVC_GRANT: u64 = 33;
const SYS_SVC_CALL_GRANT: u64 = 34;
const SYS_SVC_SIGNAL: u64 = 35;
const SYS_THREAD_CREATE: u64 = 50;
const SYS_LX_CTL: u64 = 51;
const SYS_LX_REPLY_RECV: u64 = 52;
const SYS_LX_COMPLETE: u64 = 53;
const SYS_LX_READ: u64 = 54;
const SYS_LX_WRITE: u64 = 55;
const SYS_LX_READ_STR: u64 = 56;
const SYS_LX_PROC_INFO: u64 = 57;
const SYS_LX_OBJ: u64 = 60;
const SYS_LX_SIG: u64 = 61;
const SYS_LX_TIMER: u64 = 62;
const SYS_LX_SIGTAKE: u64 = 63;
// wave6 G23
const SYS_LX_MEM: u64 = 64;

/// A service message (the kernel's `ipc::service::WireMessage`).
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct Message {
    /// Operation or reply code.
    pub label: u64,
    /// Arguments.
    pub args: [u64; 4],
}

impl Message {
    /// A message with `label` and `args`.
    pub const fn new(label: u64, args: [u64; 4]) -> Self {
        Self { label, args }
    }
}

/// Invokes a raw Hydra syscall with 3 arguments.
///
/// # Arguments
/// * `num` - Syscall number.
/// * `a0` - First argument.
/// * `a1` - Second argument.
/// * `a2` - Third argument.
///
/// # Returns
/// Raw integer return value from `rax`.
///
/// # Safety
/// Executing a syscall can violate memory safety or cause undefined behavior if passed invalid arguments.
#[inline(always)]
unsafe fn syscall3(num: u64, a0: u64, a1: u64, a2: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as i64 => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Invokes a raw Hydra syscall with 4 arguments (the fourth in `r10`).
///
/// # Safety
/// As [`syscall3`].
#[inline(always)]
unsafe fn syscall4(num: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as i64 => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Converts a raw syscall return integer into a `Result<u64, i64>`.
///
/// # Arguments
/// * `r` - Return code from syscall.
///
/// # Returns
/// `Ok(val)` on non-negative values, `Err(err)` on negative values.
///
/// # Errors
/// Returns `r` if `r < 0`.
fn check(r: i64) -> Result<u64, i64> {
    if r < 0 {
        Err(r)
    } else {
        Ok(r as u64)
    }
}

/// Writes `data` to descriptor `fd` (1: console).
///
/// # Arguments
/// * `fd` - Destination file descriptor.
/// * `data` - Byte slice to write.
pub fn write(fd: u64, data: &[u8]) {
    if !data.is_empty() {
        unsafe { syscall3(SYS_WRITE, fd, data.as_ptr() as u64, data.len() as u64) };
    }
}

/// Ends the process.
///
/// # Arguments
/// * `code` - Exit status code.
///
/// # Returns
/// Does not return (`!`).
pub fn exit(code: u64) -> ! {
    unsafe { syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// Ends every thread of the process (a program with threads that cannot go on).
///
/// # Returns
/// Does not return (`!`).
pub fn exit_group(code: u64) -> ! {
    unsafe { syscall3(SYS_EXIT, code, 1, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// Starts a thread of this process at `entry` with stack pointer `stack` and `arg` as its
/// argument (in `rdi`); `entry` must never return (it ends with [`exit`]).
///
/// # Returns
/// The new thread's task ID.
///
/// # Errors
/// Returns negative error code on failure.
///
/// # Safety
/// `stack` must point just past (16-byte aligned, minus 8 for the missing return address)
/// memory the thread alone uses for its stack, and `entry` must follow the C ABI.
pub unsafe fn thread_create(entry: extern "C" fn(u64) -> !, stack: u64, arg: u64) -> Result<u64, i64> {
    check(syscall3(SYS_THREAD_CREATE, entry as usize as u64, stack, arg))
}

/// Linux server: `op` ([`crate::protocol::LX_CTL_ATTACH`]: returns this worker's syscall
/// page; [`crate::protocol::LX_CTL_ONLINE`]: start forwarding).
///
/// # Errors
/// Returns negative error code on failure.
pub fn lx_ctl(op: u64) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_LX_CTL, op, 0, 0) })
}

/// Linux server: answers the call this worker serves with `result` (`flags`:
/// [`crate::protocol::LX_REPLY_PENDING`], [`crate::protocol::LX_REPLY_NONE`]) and waits for
/// the next call, which is in the syscall page when this returns `Ok`.
///
/// # Errors
/// Returns negative error code on failure.
pub fn lx_reply_recv(result: i64, flags: u64) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_LX_REPLY_RECV, result as u64, flags, 0) }).map(|_| ())
}

/// Linux server: answers pending call `id` with `result`.
///
/// # Errors
/// `-EINVAL` if `id` is not a pending call.
pub fn lx_complete(id: u64, result: i64) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_LX_COMPLETE, id, result as u64, 0) }).map(|_| ())
}

/// Linux server: copies `buf.len()` bytes at `addr` of the caller of call `id` into `buf`.
///
/// # Errors
/// `-EFAULT` for a bad address, `-ESRCH` if `id` is not being served.
pub fn lx_read(id: u64, addr: u64, buf: &mut [u8]) -> Result<(), i64> {
    check(unsafe { syscall4(SYS_LX_READ, id, addr, buf.len() as u64, buf.as_mut_ptr() as u64) }).map(|_| ())
}

/// Linux server: copies `data` to `addr` of the caller of call `id`.
///
/// # Errors
/// `-EFAULT` for a bad address, `-ESRCH` if `id` is not being served.
pub fn lx_write(id: u64, addr: u64, data: &[u8]) -> Result<(), i64> {
    check(unsafe { syscall4(SYS_LX_WRITE, id, addr, data.len() as u64, data.as_ptr() as u64) }).map(|_| ())
}

/// Linux server: copies the NUL-terminated string at `addr` of the caller of call `id`
/// into `buf` (without the NUL) and returns its length.
///
/// # Errors
/// `-EFAULT` for a bad address, `-ENAMETOOLONG` if no NUL is within `buf.len()` bytes.
pub fn lx_read_str(id: u64, addr: u64, buf: &mut [u8]) -> Result<usize, i64> {
    check(unsafe { syscall4(SYS_LX_READ_STR, id, addr, buf.len() as u64, buf.as_mut_ptr() as u64) }).map(|n| n as usize)
}

/// Linux server: process `tgid`'s `[ppid, uid, euid, suid, gid, egid, sgid]`.
///
/// # Errors
/// `-ESRCH` if there is no such process.
pub fn lx_proc_info(tgid: u64) -> Result<[u64; 7], i64> {
    let mut out = [0u64; 7];
    check(unsafe { syscall3(SYS_LX_PROC_INFO, tgid, out.as_mut_ptr() as u64, 0) })?;
    Ok(out)
}

/// Invokes a raw Hydra syscall with 5 arguments (`rdi`, `rsi`, `rdx`, `r10`, `r8`).
unsafe fn syscall5(num: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as i64 => ret,
        in("rdi") a0,
        in("rsi") a1,
        in("rdx") a2,
        in("r10") a3,
        in("r8") a4,
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Linux server: a server-object operation (`SYS_LX_OBJ`, [`crate::protocol::LX_OBJ_INSTALL`]
/// and the others); returns its non-negative result.
///
/// # Errors
/// Returns the negative errno.
pub fn lx_obj(op: u64, a: u64, b: u64, c: u64) -> Result<u64, i64> {
    check(unsafe { syscall4(SYS_LX_OBJ, op, a, b, c) }).map(|v| v as u64)
}

/// Linux server: queues signal `sig` for process `tgid` with `si_code` `code`, the sender
/// `spid`/`suid` and `si_value` `value` (`sig_post`).
///
/// # Errors
/// `-ESRCH` if there is no such process.
pub fn lx_sig(tgid: u64, sig: u32, code: i32, spid: u32, suid: u32, value: u64) -> Result<(), i64> {
    check(unsafe { syscall5(SYS_LX_SIG, tgid, sig as u64, code as i64 as u64, spid as u64 | (suid as u64) << 32, value) }).map(|_| ())
}

/// Linux server (Group 13): `timer_arm` and friends (`op`: [`crate::protocol::LX_TIMER_ARM`],
/// `LX_TIMER_CANCEL`, `LX_TIMER_NOW`); returns the operation's value.
pub fn lx_timer(op: u64, cookie: u64, ns: u64) -> i64 {
    unsafe { syscall3(SYS_LX_TIMER, op, cookie, ns) }
}

/// Linux server (Group 13): `sig_take` (`SYS_LX_SIGTAKE`, signalfd); returns its value or the
/// negative errno.
pub fn lx_sigtake(op: u64, a: u64, b: u64, c: u64) -> i64 {
    unsafe { syscall4(SYS_LX_SIGTAKE, op, a, b, c) }
}

// wave6 G23 begin
/// Memory objects (`SYS_LX_MEM`, see [`crate::mem`]): operation `op` (`LX_MEM_*`); returns
/// its value or the negative errno.
pub fn lx_mem(op: u64, a: u64, b: u64, c: u64, d: u64) -> i64 {
    unsafe { syscall5(SYS_LX_MEM, op, a, b, c, d) }
}
// wave6 G23 end

/// Gives up the rest of the time slice.
pub fn yield_now() {
    unsafe { syscall3(SYS_YIELD, 0, 0, 0) };
}

/// Sleeps for `ms` milliseconds.
///
/// # Arguments
/// * `ms` - Duration to sleep in milliseconds.
pub fn sleep_ms(ms: u64) {
    unsafe { syscall3(SYS_SLEEP, ms, 0, 0) };
}

/// Process id.
///
/// # Returns
/// Current process ID.
pub fn getpid() -> u64 {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as u64 }
}

/// Timer ticks since boot (100 Hz).
///
/// # Returns
/// Number of 100 Hz timer ticks since boot.
pub fn uptime_ticks() -> u64 {
    unsafe { syscall3(SYS_UPTIME, 0, 0, 0) as u64 }
}

/// Maps `len` bytes of zeroed private memory.
///
/// # Arguments
/// * `len` - Number of bytes to map.
///
/// # Returns
/// Virtual address of the mapped region on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn map_anon(len: usize) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_MAP_ANON, len as u64, 0, 0) })
}

/// Allows this driver to use I/O ports.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn iopl() -> Result<(), i64> {
    check(unsafe { syscall3(SYS_IOPL, 3, 0, 0) }).map(|_| ())
}

/// Maps device memory the supervisor granted this driver.
///
/// # Arguments
/// * `phys` - Physical address to map.
/// * `len` - Length of the physical memory range in bytes.
///
/// # Returns
/// Pointer to mapped virtual address on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn physmap(phys: u64, len: usize) -> Result<*mut u8, i64> {
    check(unsafe { syscall3(SYS_PHYSMAP, phys, len as u64, 0) }).map(|a| a as *mut u8)
}

/// Allocates physically contiguous memory for DMA: `(address, physical address)`.
///
/// # Arguments
/// * `len` - Number of bytes to allocate.
///
/// # Returns
/// Tuple of `(virtual_pointer, physical_address)` on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn dma_alloc(len: usize) -> Result<(*mut u8, u64), i64> {
    let mut phys = 0u64;
    let addr = check(unsafe { syscall3(SYS_DMA_ALLOC, len as u64, &mut phys as *mut u64 as u64, 0) })?;
    Ok((addr as *mut u8, phys))
}

/// Routes interrupt line `irq` to this driver.
///
/// # Arguments
/// * `irq` - Hardware IRQ line number.
///
/// # Returns
/// `Ok(())` on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn irq_register(irq: u8) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_IRQ_REGISTER, irq as u64, 0, 0) }).map(|_| ())
}

/// Unmasks `irq` and waits up to `timeout_ticks` (0: forever) for it.
///
/// # Arguments
/// * `irq` - Hardware IRQ line number.
/// * `timeout_ticks` - Timeout in 100 Hz ticks (0 for indefinite wait).
///
/// # Returns
/// Count of interrupts that arrived (0 on timeout) on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn irq_wait(irq: u8, timeout_ticks: u64) -> Result<u32, i64> {
    check(unsafe { syscall3(SYS_IRQ_WAIT, irq as u64, timeout_ticks, 0) }).map(|n| n as u32)
}

/// Unmasks `irq` after servicing the device, without waiting.
///
/// # Arguments
/// * `irq` - Hardware IRQ line number.
///
/// # Returns
/// Count of interrupts that arrived since last wait/acknowledgement on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn irq_ack(irq: u8) -> Result<u32, i64> {
    check(unsafe { syscall3(SYS_IRQ_ACK, irq as u64, 0, 0) }).map(|n| n as u32)
}

/// Wall-clock time: `(seconds since 1970, nanoseconds)`.
///
/// # Returns
/// Tuple of `(seconds_since_epoch, nanoseconds)`.
pub fn clock() -> (u64, u32) {
    let mut t = [0u64; 2];
    unsafe { syscall3(SYS_CLOCK, t.as_mut_ptr() as u64, 0, 0) };
    (t[0], t[1] as u32)
}

/// Maps the window of service `endpoint`, which this driver uses.
///
/// # Arguments
/// * `endpoint` - Target service endpoint ID.
///
/// # Returns
/// Base virtual address of the attached service window on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn svc_attach(endpoint: u32) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_SVC_ATTACH, endpoint as u64, 0, 0) })
}

/// Becomes the server of `endpoint`; returns the service window's address.
///
/// # Arguments
/// * `endpoint` - Service endpoint ID.
///
/// # Returns
/// Base virtual address of the registered service window on success.
///
/// # Errors
/// Returns negative error code on failure.
pub fn svc_register(endpoint: u32) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_SVC_REGISTER, endpoint as u64, 0, 0) })
}

/// Waits for the next request to `endpoint`.
///
/// # Returns
/// `(request ID, request)`: the reply names the ID ([`svc_reply`]). Several requests may be
/// taken before answering them, and answered in any order.
///
/// # Errors
/// Returns negative error code on failure.
pub fn svc_recv(endpoint: u32) -> Result<(u64, Message), i64> {
    let mut m = Message::default();
    let id = check(unsafe { syscall3(SYS_SVC_RECV, endpoint as u64, &mut m as *mut Message as u64, 0) })?;
    Ok((id, m))
}

/// As [`svc_recv`], but also returns notifications raised for this server (the kernel's
/// `MSG_SVC_NOTIFY` with the bits in `args[0]`, request ID 0, no reply), and gives up after
/// `timeout_ticks` (0: never) with ID 0 and no bits.
///
/// # Errors
/// Returns negative error code on failure.
pub fn svc_recv_notify(endpoint: u32, timeout_ticks: u64) -> Result<(u64, Message), i64> {
    let mut m = Message::default();
    let flags = crate::protocol::RECV_NOTIFY | timeout_ticks;
    let id = check(unsafe { syscall3(SYS_SVC_RECV, endpoint as u64, &mut m as *mut Message as u64, flags) })?;
    Ok((id, m))
}

/// Rings the doorbell of the kernel client of `endpoint` (which this process serves) with
/// `bits` (net-server: socket readiness changed).
pub fn svc_signal(endpoint: u32, bits: u64) {
    unsafe { syscall3(SYS_SVC_SIGNAL, endpoint as u64, bits, 0) };
}

/// Answers request `id` taken on `endpoint` (0: the oldest one taken and unanswered).
///
/// # Errors
/// Returns negative error code on failure.
pub fn svc_reply(endpoint: u32, id: u64, reply: &Message) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_SVC_REPLY, endpoint as u64, reply as *const Message as u64, id) }).map(|_| ())
}

/// Most address ranges lent with one call (the kernel's `ipc::service::GRANT_RANGES`).
pub const GRANT_RANGES: usize = 4;

/// Most physical segments one grant has (the kernel's `GRANT_PAGES`).
pub const GRANT_SEGMENTS_MAX: usize = 72;

/// The argument block of [`svc_call_grant`] (the kernel's `GrantCall`).
#[repr(C)]
struct GrantCall {
    msg: Message,
    timeout: u64,
    n: u64,
    flags: u64,
    ranges: [[u64; 2]; GRANT_RANGES],
}

/// Calls another service lending it `ranges` of this process's memory for the request
/// (the pages are pinned until it answers; a disk driver points its device's DMA at
/// them). `server_writes`: the server fills them (a read).
///
/// # Errors
/// Returns negative error code on failure or timeout (`-EINVAL` from a server that does
/// not take grants for this request).
pub fn svc_call_grant(endpoint: u32, request: Message, timeout_ticks: u64, ranges: &[(u64, u64)], server_writes: bool) -> Result<Message, i64> {
    let mut gc = GrantCall { msg: request, timeout: timeout_ticks, n: ranges.len().min(GRANT_RANGES) as u64, flags: server_writes as u64, ranges: [[0; 2]; GRANT_RANGES] };
    for (d, r) in gc.ranges.iter_mut().zip(ranges.iter()) {
        *d = [r.0, r.1];
    }
    check(unsafe { syscall3(SYS_SVC_CALL_GRANT, endpoint as u64, &mut gc as *mut GrantCall as u64, 0) })?;
    Ok(gc.msg)
}

/// The physical segments `(address, length)` lent with request `id` (being served on
/// `endpoint`), in the order of the lent bytes; returns how many were stored in `out`.
///
/// # Errors
/// `-EINVAL` if the request lends nothing or is not being served.
pub fn svc_grant(endpoint: u32, id: u64, out: &mut [(u64, u64); GRANT_SEGMENTS_MAX]) -> Result<usize, i64> {
    check(unsafe { syscall3(SYS_SVC_GRANT, endpoint as u64, id, out.as_mut_ptr() as u64) }).map(|n| n as usize)
}

/// Calls another service; `timeout_ticks` 0 means the kernel's default.
///
/// # Arguments
/// * `endpoint` - Target service endpoint ID.
/// * `request` - Request message payload.
/// * `timeout_ticks` - Timeout in ticks (0 for default).
///
/// # Returns
/// Reply [`Message`] on success.
///
/// # Errors
/// Returns negative error code on failure or timeout.
pub fn svc_call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    let mut m = request;
    check(unsafe { syscall3(SYS_SVC_CALL, endpoint as u64, &mut m as *mut Message as u64, timeout_ticks) })?;
    Ok(m)
}
