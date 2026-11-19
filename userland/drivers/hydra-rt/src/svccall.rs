//! Calls between services (wave 6, Group 20; design `docs/linux-services-design.md` 4.2).
//!
//! - [`reply_recv`]: a classic server (net-server, zfs-server, a driver) answers a request
//!   and waits for the next one in one system call. A caller on the kernel's direct path
//!   then gets the CPU straight back, and the next call finds the server waiting.
//! - [`dcall`]: a Linux-facing service calls another one (`SYS_SVC_DCALL`, 70); the callee's
//!   worker sees an `LxCall` with `nr == LX_DCALL_NR` (see [`DcallArgs`]).
//! - [`post`]: a one-way event to another service's notification ring (`SYS_SVC_POST`, 71).

use crate::protocol::{LxCall, RECV_NOTIFY, RECV_REPLY};
use crate::Message;

const SYS_SVC_RECV: u64 = 25;
/// `SYS_SVC_DCALL`.
pub const SYS_SVC_DCALL: u64 = 70;
/// `SYS_SVC_POST`.
pub const SYS_SVC_POST: u64 = 71;

#[inline(always)]
unsafe fn syscall6(num: u64, a: [u64; 6]) -> i64 {
    let ret: i64;
    core::arch::asm!(
        "syscall",
        inlateout("rax") num as i64 => ret,
        in("rdi") a[0],
        in("rsi") a[1],
        in("rdx") a[2],
        in("r10") a[3],
        in("r8") a[4],
        in("r9") a[5],
        out("rcx") _,
        out("r11") _,
        options(nostack)
    );
    ret
}

/// Answers request `id` of `endpoint` with `reply`, then waits for the next request (or a
/// notification, or `timeout_ticks`, as `sys::svc_recv_notify`; 0: no timeout) in one
/// system call. Returns `(request id, message)`; id 0 is a notification (or the timeout).
pub fn reply_recv(endpoint: u32, id: u64, reply: &Message, timeout_ticks: u64) -> Result<(u64, Message), i64> {
    let mut m = *reply;
    let flags = RECV_NOTIFY | RECV_REPLY | timeout_ticks;
    // SAFETY: the kernel reads the answer from `m` and writes the next request into it
    let r = unsafe { syscall6(SYS_SVC_RECV, [endpoint as u64, &mut m as *mut Message as u64, flags, id, 0, 0]) };
    if r < 0 {
        return Err(r);
    }
    Ok((r as u64, m))
}

/// Calls service `svc` (an `LXS_*` id) with operation `op`, input `input` and room for output
/// `out` (input and output together at most 3 KiB). Returns the callee's result (by
/// convention the output's length, or a negative errno); `-EPERM` for an edge the
/// supervisor did not allow, `-ENOSYS` when the service is not running, `-EIO` when it went
/// away during the call.
pub fn dcall(svc: u8, op: u64, input: &[u8], out: &mut [u8]) -> i64 {
    // SAFETY: the kernel reads `input` and writes at most `out.len()` bytes to `out`
    unsafe { syscall6(SYS_SVC_DCALL, [svc as u64, op, input.as_ptr() as u64, input.len() as u64, out.as_mut_ptr() as u64, out.len() as u64]) }
}

/// Posts event `op` with up to 16 bytes of `data` to service `svc` (nobody waits).
pub fn post(svc: u8, op: u32, data: &[u8]) -> Result<(), i64> {
    // SAFETY: the kernel reads `data`
    let r = unsafe { syscall6(SYS_SVC_POST, [svc as u64, op as u64, data.as_ptr() as u64, data.len() as u64, 0, 0]) };
    if r < 0 {
        Err(r)
    } else {
        Ok(())
    }
}

/// What a direct call's callee finds in its `LxCall` (`nr == LX_DCALL_NR`).
#[derive(Clone, Copy, Debug)]
pub struct DcallArgs {
    /// The operation.
    pub op: u64,
    /// The input: pass to `Cx::copy_in(input, input_len)` (it is in the page).
    pub input: u64,
    pub input_len: usize,
    /// The output: pass to `Cx::copy_out(output, ..)` (at most `output_cap` bytes).
    pub output: u64,
    pub output_cap: usize,
    /// The calling service (`LXS_*`).
    pub from: u8,
}

impl DcallArgs {
    /// The direct call's arguments, from its `LxCall`.
    pub fn of(c: &LxCall) -> Self {
        Self { op: c.args[0], input: c.args[1], input_len: c.args[3] as usize, output: c.args[2], output_cap: c.args[4] as usize, from: c.args[5] as u8 }
    }
}
