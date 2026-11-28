//! # FreeBSD personality: contexts and threads (wave 12, Group FK)
//!
//! - `getcontext`/`setcontext`/`swapcontext` (421-423) with FreeBSD's `ucontext_t`
//!   ([`super::fbsd_xlat::Mcontext`], the same layout as the signal frame's).
//! - `thr_new` (455): a thread of the caller's process through the Linux layer's `clone`
//!   (`CLONE_VM | CLONE_THREAD | ...`, `CLONE_SETTLS` with `tls_base`). The new thread must
//!   start at `start_func(arg)` on its own stack, but `clone`'s child gets the creator's
//!   registers: so it starts at a small piece of code on the FreeBSD shared page
//!   ([`super::abi::FREEBSD_THR_START`]) with `start_func` in `r12` and `arg` in `r13`, which
//!   moves `arg` into `rdi` and jumps.
//! - `thr_exit(state)` (431): stores 1 at `*state` and wakes its waiters (libthr's
//!   `pthread_join`), then ends the thread (the process, when it was the last one).
//! - `thr_set_name` (464): the calling thread's name (`prctl(PR_SET_NAME)`); names of
//!   other threads are accepted and dropped.

use super::fbsd_xlat::{MC_LEN, MC_RAX, MC_RDX, UC_FLAGS, UC_LEN, UC_MCONTEXT, UC_STACK};
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::vfs::{copy_in, copy_out};

const EFAULT: i64 = -14;
const EINVAL: i64 = -22;

/// `getcontext(ucp)`: the caller's state as it returns from this call (with `rax` and `rdx`
/// 0 and the carry flag clear, so a `setcontext` to it looks like `getcontext` returning
/// 0), its signal mask, alternate stack and FPU state.
pub fn getcontext(f: &SyscallFrame, ucp: u64) -> Result<i64, i64> {
    let mut uc = [0u8; UC_LEN];
    // The mask, read straight from the thread (no stack copy: a thread near an unmapped
    // stack page must not get EFAULT)
    let m = crate::compat::linux::proc::change_mask(None)?;
    uc[0..16].copy_from_slice(&super::fbsd_xlat::mask_to_freebsd(m));
    let (stack, on_alt) = super::freebsd::uc_stack(f.rsp);
    let regs = crate::compat::linux::proc::UserRegs {
        rdi: f.rdi,
        rsi: f.rsi,
        rdx: 0,
        rcx: f.rip,
        r8: f.r8,
        r9: f.r9,
        rax: 0,
        rbx: f.rbx,
        rbp: f.rbp,
        r10: f.r10,
        r11: f.rflags,
        r12: f.r12,
        r13: f.r13,
        r14: f.r14,
        r15: f.r15,
        rip: f.rip,
        rflags: f.rflags & !1,
        rsp: f.rsp,
    };
    let mut mc = super::freebsd::mcontext_of(&regs, crate::arch::gdt::USER_CS as u64, on_alt);
    mc.gprs[MC_RAX] = 0;
    mc.gprs[MC_RDX] = 0;
    let fpu = crate::arch::syscall::SYSCALL_FPU.load(core::sync::atomic::Ordering::Acquire);
    let mut fx = [0u8; 512];
    let have_fpu = !fpu.is_null();
    if have_fpu {
        // SAFETY: the FPU state saved at this system call's entry
        fx.copy_from_slice(unsafe { &(&(*fpu).0)[..512] });
    }
    mc.pack(if have_fpu { Some(&fx) } else { None }, &mut uc[UC_MCONTEXT..UC_MCONTEXT + MC_LEN]);
    uc[UC_STACK..UC_STACK + 24].copy_from_slice(&stack);
    uc[UC_FLAGS..UC_FLAGS + 4].copy_from_slice(&0u32.to_le_bytes());
    copy_out(ucp, &uc).map_err(|_| EFAULT)?;
    Ok(0)
}

/// `setcontext(ucp)`: no return when it works.
pub fn setcontext(ucp: u64) -> i64 {
    let fpu = crate::arch::syscall::SYSCALL_FPU.load(core::sync::atomic::Ordering::Acquire);
    // SAFETY: the FPU state saved at this system call's entry (kept when the context has none)
    let cur = if fpu.is_null() { None } else { Some(unsafe { &*fpu }) };
    super::freebsd::set_context(ucp, cur)
}

/// `sizeof(struct thr_param)`.
const THR_PARAM: usize = 104;

/// `thr_new(param, size)`: `struct thr_param { start_func, arg, stack_base, stack_size,
/// tls_base, tls_size, child_tid, parent_tid, int flags, rtp, spare[3] }`.
pub fn thr_new(f: &SyscallFrame, param: u64, size: u64) -> Result<i64, i64> {
    if size as usize > THR_PARAM || size < 64 {
        return Err(EINVAL);
    }
    let mut p = [0u8; THR_PARAM];
    p[..size as usize].copy_from_slice(&copy_in(param, size as usize).map_err(|_| EFAULT)?);
    let w = |i: usize| u64::from_le_bytes(p[i * 8..i * 8 + 8].try_into().unwrap());
    let (start, arg, stack_base, stack_size, tls_base, child_tid, parent_tid) = (w(0), w(1), w(2), w(3), w(4), w(6), w(7));
    let flags = u32::from_le_bytes(p[64..68].try_into().unwrap());
    // THR_SUSPENDED 1, THR_SYSTEM_SCOPE 2, THR_C_RUNTIME 4
    if flags & !7 != 0 || start == 0 {
        return Err(EINVAL);
    }
    // FreeBSD's cpu_set_upcall: the stack as if `start_func` had been called
    let sp = ((stack_base.wrapping_add(stack_size)) & !0xF).wrapping_sub(8);
    const CLONE: u64 = 0x100 | 0x200 | 0x400 | 0x800 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x10_0000 | 0x100_0000;
    // VM FS FILES SIGHAND THREAD SYSVSEM SETTLS PARENT_SETTID CHILD_SETTID
    let mut g = SyscallFrame {
        r9: 0,
        r8: tls_base,
        r10: child_tid,
        rdx: parent_tid,
        rsi: sp,
        rdi: CLONE,
        rax: 56,
        r15: f.r15,
        r14: f.r14,
        r13: arg,
        r12: start,
        rbp: 0,
        rbx: f.rbx,
        rip: super::abi::FREEBSD_THR_START_ADDR,
        rflags: f.rflags,
        rsp: f.rsp,
    };
    let tid = crate::compat::linux::dispatch_linux_syscall(&mut g);
    if tid < 0 {
        return Err(tid);
    }
    // FreeBSD's ids are `long`s: the Linux layer wrote 4 bytes; the full word goes too
    for p in [parent_tid, child_tid] {
        if p != 0 {
            let _ = copy_out(p, &(tid as u64).to_le_bytes());
        }
    }
    Ok(0)
}

/// `thr_exit(state)`.
pub fn thr_exit(state: u64) -> i64 {
    if state != 0 {
        let _ = copy_out(state, &1u64.to_le_bytes());
        super::umtx::wake(state, i32::MAX as u64, false);
    }
    let (tid, _) = crate::compat::linux::proc::current_ids();
    super::umtx::thread_gone(tid);
    super::linux_call(60, [0; 6])
}

/// `thr_set_name(id, name)`.
pub fn thr_set_name(id: u64, name: u64) -> i64 {
    let (tid, _) = crate::compat::linux::proc::current_ids();
    if id as i64 == -1 || id == tid {
        if name == 0 {
            return 0;
        }
        return super::linux_call(157, [15, name, 0, 0, 0, 0]); // prctl(PR_SET_NAME)
    }
    0
}
