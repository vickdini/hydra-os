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

fn check(r: i64) -> Result<u64, i64> {
    if r < 0 {
        Err(r)
    } else {
        Ok(r as u64)
    }
}

/// Writes `data` to descriptor `fd` (1: console).
pub fn write(fd: u64, data: &[u8]) {
    if !data.is_empty() {
        unsafe { syscall3(SYS_WRITE, fd, data.as_ptr() as u64, data.len() as u64) };
    }
}

/// Ends the process.
pub fn exit(code: u64) -> ! {
    unsafe { syscall3(SYS_EXIT, code, 0, 0) };
    loop {
        core::hint::spin_loop();
    }
}

/// Gives up the rest of the time slice.
pub fn yield_now() {
    unsafe { syscall3(SYS_YIELD, 0, 0, 0) };
}

/// Sleeps for `ms` milliseconds.
pub fn sleep_ms(ms: u64) {
    unsafe { syscall3(SYS_SLEEP, ms, 0, 0) };
}

/// Process id.
pub fn getpid() -> u64 {
    unsafe { syscall3(SYS_GETPID, 0, 0, 0) as u64 }
}

/// Timer ticks since boot (100 Hz).
pub fn uptime_ticks() -> u64 {
    unsafe { syscall3(SYS_UPTIME, 0, 0, 0) as u64 }
}

/// Maps `len` bytes of zeroed private memory.
pub fn map_anon(len: usize) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_MAP_ANON, len as u64, 0, 0) })
}

/// Allows this driver to use I/O ports.
pub fn iopl() -> Result<(), i64> {
    check(unsafe { syscall3(SYS_IOPL, 3, 0, 0) }).map(|_| ())
}

/// Maps device memory the supervisor granted this driver.
pub fn physmap(phys: u64, len: usize) -> Result<*mut u8, i64> {
    check(unsafe { syscall3(SYS_PHYSMAP, phys, len as u64, 0) }).map(|a| a as *mut u8)
}

/// Allocates physically contiguous memory for DMA: `(address, physical address)`.
pub fn dma_alloc(len: usize) -> Result<(*mut u8, u64), i64> {
    let mut phys = 0u64;
    let addr = check(unsafe { syscall3(SYS_DMA_ALLOC, len as u64, &mut phys as *mut u64 as u64, 0) })?;
    Ok((addr as *mut u8, phys))
}

/// Routes interrupt line `irq` to this driver.
pub fn irq_register(irq: u8) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_IRQ_REGISTER, irq as u64, 0, 0) }).map(|_| ())
}

/// Unmasks `irq` and waits up to `timeout_ticks` (0: forever) for it; returns how many
/// interrupts arrived (0 on timeout).
pub fn irq_wait(irq: u8, timeout_ticks: u64) -> Result<u32, i64> {
    check(unsafe { syscall3(SYS_IRQ_WAIT, irq as u64, timeout_ticks, 0) }).map(|n| n as u32)
}

/// Unmasks `irq` after servicing the device, without waiting; returns how many
/// interrupts arrived since the last wait or acknowledgement.
pub fn irq_ack(irq: u8) -> Result<u32, i64> {
    check(unsafe { syscall3(SYS_IRQ_ACK, irq as u64, 0, 0) }).map(|n| n as u32)
}

/// Becomes the server of `endpoint`; returns the service window's address.
pub fn svc_register(endpoint: u32) -> Result<u64, i64> {
    check(unsafe { syscall3(SYS_SVC_REGISTER, endpoint as u64, 0, 0) })
}

/// Waits for the next request to `endpoint`.
pub fn svc_recv(endpoint: u32) -> Result<Message, i64> {
    let mut m = Message::default();
    check(unsafe { syscall3(SYS_SVC_RECV, endpoint as u64, &mut m as *mut Message as u64, 0) })?;
    Ok(m)
}

/// Answers the request being served on `endpoint`.
pub fn svc_reply(endpoint: u32, reply: &Message) -> Result<(), i64> {
    check(unsafe { syscall3(SYS_SVC_REPLY, endpoint as u64, reply as *const Message as u64, 0) }).map(|_| ())
}

/// Calls another service; `timeout_ticks` 0 means the kernel's default.
pub fn svc_call(endpoint: u32, request: Message, timeout_ticks: u64) -> Result<Message, i64> {
    let mut m = request;
    check(unsafe { syscall3(SYS_SVC_CALL, endpoint as u64, &mut m as *mut Message as u64, timeout_ticks) })?;
    Ok(m)
}
