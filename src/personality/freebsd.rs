//! # The FreeBSD personality: the wave 5 stub table
//!
//! Only reachable with the test switch `persona=fbsd-stub` ([`super::freebsd_stub`]); wave
//! 11's front end replaces the table. It holds the calls the hook's test programs need
//! (`tests/freebsd/rawsys.c`, `tests/freebsd/fbhook.c`), as `docs/personality-design.md`
//! section 2.9 lists them, plus what proves signals and exec:
//!
//! | FreeBSD | Route |
//! |---|---|
//! | `exit` 1, `read` 3, `write` 4, `close` 6, `getuid` 24, `geteuid` 25, `getppid` 39, `getegid` 43, `getgid` 47, `execve` 59, `nanosleep` 240 | Linux 231, 0, 1, 3, 102, 107, 110, 108, 104, 59, 35 (same arguments) |
//! | `getpid` 20 | kernel: pid, and the parent's pid in `rdx` (FreeBSD's COMPAT_43 second result) |
//! | `kill` 37, `sigaction` 416, `sigreturn` 417, `thr_self` 432 | kernel (signal numbers and structures translated) |
//! | `syscall` 0, `__syscall` 198 | indirect: the number in `rdi` |
//! | everything else | `ENOSYS` (78) and `SIGSYS` |
//!
//! **Signal frames** are FreeBSD's `struct sigframe` (`sys/x86/include/sigframe.h`): the
//! handler pointer, a `ucontext_t` (FreeBSD's 128-bit `uc_sigmask`, the 800-byte
//! `mcontext_t` with the FXSAVE area) and a `siginfo_t`. FreeBSD enters its signal
//! trampoline (`sigcode`) first, which calls the handler and then `sigreturn(&sf_uc)`; the
//! trampoline lives on one page mapped into every FreeBSD process at [`SIGCODE_ADDR`] (the
//! "shared page"; wave 11 adds the rest of it). Not yet: the XSAVE extension (AVX upper
//! halves are not saved across a handler), fault details in `siginfo`, delivery of a signal
//! that became deliverable by `sigreturn`'s mask before the next system call or trap.

use super::{abi, linux_as, local, Ret, Table, F_INDIRECT, R_NOSYS, TABLE_LEN};
use crate::arch::idt::FpuState;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::proc::{SigAction, UserRegs};
use crate::task::TaskPersonality;

/// Negative `EINVAL`.
const EINVAL: i64 = -22;
/// Negative `EFAULT`.
const EFAULT: i64 = -14;

/// Kernel-local call: `getpid` (and the parent in `rdx`).
const L_GETPID: u16 = 1;
/// Kernel-local call: `kill` (FreeBSD signal number).
const L_KILL: u16 = 2;
/// Kernel-local call: `sigaction` (FreeBSD `struct sigaction`).
const L_SIGACTION: u16 = 3;
/// Kernel-local call: `sigreturn` (FreeBSD `ucontext_t`).
const L_SIGRETURN: u16 = 4;
/// Kernel-local call: `thr_self` (the thread's ID).
const L_THR_SELF: u16 = 5;

pub use super::abi::FREEBSD_OSRELDATE as OSRELDATE;

/// The stub table.
pub static TABLE: Table = Table {
    entries: entries(),
    pers: TaskPersonality::FreeBsd,
    local: local_call,
    errno: &abi::FREEBSD_ERRNO,
    nosys_signal: 31, // SIGSYS
    frame: build_frame,
};

const fn entries() -> [u32; TABLE_LEN] {
    let mut e = [R_NOSYS; TABLE_LEN];
    e[0] = R_NOSYS | F_INDIRECT; // syscall
    e[1] = linux_as(231); // exit: the whole process
    e[3] = linux_as(0); // read
    e[4] = linux_as(1); // write
    e[6] = linux_as(3); // close
    e[20] = local(L_GETPID, super::F_RET2);
    e[24] = linux_as(102); // getuid
    e[25] = linux_as(107); // geteuid
    e[37] = local(L_KILL, 0);
    e[39] = linux_as(110); // getppid
    e[43] = linux_as(108); // getegid
    e[47] = linux_as(104); // getgid
    e[59] = linux_as(59); // execve
    e[198] = R_NOSYS | F_INDIRECT; // __syscall
    e[240] = linux_as(35); // nanosleep (same struct timespec)
    e[416] = local(L_SIGACTION, 0);
    e[417] = local(L_SIGRETURN, 0);
    e[432] = local(L_THR_SELF, 0);
    e
}

fn local_call(id: u16, frame: &mut SyscallFrame, a: [u64; 6]) -> Ret {
    match id {
        L_GETPID => Ret { r: super::linux_call(39, [0; 6]), r2: Some(super::linux_call(110, [0; 6]) as u64) },
        L_KILL => Ret::of(match a[1] {
            0 => super::linux_call(62, [a[0], 0, 0, 0, 0, 0]),
            s => match abi::freebsd_sig_to_internal(s) {
                Some(sig) => super::linux_call(62, [a[0], sig as u64, 0, 0, 0, 0]),
                None => EINVAL,
            },
        }),
        L_SIGACTION => Ret::of(sigaction(a[0], a[1], a[2])),
        L_SIGRETURN => Ret::of(sigreturn(frame, a[0])),
        L_THR_SELF => {
            let (tid, _) = crate::compat::linux::proc::current_ids();
            Ret::of(match crate::compat::linux::vfs::copy_out(a[0], &tid.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            })
        }
        _ => Ret::of(-38),
    }
}

// ----------------------------------------------------------------------
// Signals
// ----------------------------------------------------------------------

/// FreeBSD `sa_flags` and the internal (Linux) bits they stand for.
const SA_FLAGS: [(u64, u64); 7] = [
    (0x01, 0x0800_0000), // SA_ONSTACK
    (0x02, 0x1000_0000), // SA_RESTART
    (0x04, 0x8000_0000), // SA_RESETHAND
    (0x08, 0x1),         // SA_NOCLDSTOP
    (0x10, 0x4000_0000), // SA_NODEFER
    (0x20, 0x2),         // SA_NOCLDWAIT
    (0x40, 0x4),         // SA_SIGINFO
];
const LINUX_SA_ONSTACK: u64 = 0x0800_0000;
const LINUX_SA_SIGINFO: u64 = 0x4;

/// A FreeBSD signal set (128 bits, signal `n` is bit `n - 1`) to the internal mask.
fn mask_from_freebsd(b: &[u8]) -> u64 {
    let mut m = 0u64;
    for n in 1..=128u64 {
        let i = (n - 1) as usize;
        if b[i / 8] & (1 << (i % 8)) != 0 {
            if let Some(s) = abi::freebsd_sig_to_internal(n) {
                m |= 1 << (s - 1);
            }
        }
    }
    m
}

/// The internal mask to a FreeBSD signal set.
fn mask_to_freebsd(m: u64) -> [u8; 16] {
    let mut b = [0u8; 16];
    for s in 1..=64u32 {
        if m & (1 << (s - 1)) != 0 {
            let n = abi::internal_sig_to_freebsd(s) as usize;
            if (1..=128).contains(&n) {
                b[(n - 1) / 8] |= 1 << ((n - 1) % 8);
            }
        }
    }
    b
}

/// FreeBSD `sigaction(sig, act, oact)`: `struct sigaction { handler; int sa_flags;
/// sigset_t sa_mask; }` (32 bytes), translated to the internal action.
fn sigaction(sig: u64, act: u64, oact: u64) -> i64 {
    let Some(s) = abi::freebsd_sig_to_internal(sig) else { return EINVAL };
    let new = if act != 0 {
        if s == 9 || s == 19 {
            return EINVAL; // SIGKILL, SIGSTOP
        }
        let b = match crate::compat::linux::vfs::copy_in(act, 32) {
            Ok(b) => b,
            Err(_) => return EFAULT,
        };
        let handler = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let fl = u32::from_le_bytes(b[8..12].try_into().unwrap()) as u64;
        let flags = SA_FLAGS.iter().filter(|(f, _)| fl & f != 0).fold(0, |a, (_, l)| a | l);
        Some(SigAction { handler, flags, restorer: 0, mask: mask_from_freebsd(&b[12..28]) })
    } else {
        None
    };
    let old = match crate::compat::linux::proc::set_action(s, new) {
        Ok(o) => o,
        Err(e) => return e,
    };
    if oact != 0 {
        let mut b = [0u8; 32];
        b[0..8].copy_from_slice(&old.handler.to_le_bytes());
        let fl = SA_FLAGS.iter().filter(|(_, l)| old.flags & l != 0).fold(0u32, |a, (f, _)| a | *f as u32);
        b[8..12].copy_from_slice(&fl.to_le_bytes());
        b[12..28].copy_from_slice(&mask_to_freebsd(old.mask));
        if crate::compat::linux::vfs::copy_out(oact, &b).is_err() {
            return EFAULT;
        }
    }
    0
}

pub use super::abi::{FREEBSD_SIGCODE as SIGCODE, FREEBSD_SIGCODE_ADDR as SIGCODE_ADDR};
const _: () = assert!(SIGCODE_ADDR == crate::memory::vm::STACK_TOP - crate::memory::vm::STACK_SIZE - 0x1000_0000);

/// `sizeof(struct sigframe)`: `sf_ahu` 8 (+8 padding), `ucontext_t` 880, `siginfo_t` 80.
const SIGFRAME: usize = 976;
/// Offset of `sf_uc` in the frame.
const UC: usize = 16;
/// Offset of `uc_mcontext` in `ucontext_t`.
const MC: usize = 16;
/// Offset of `sf_si` in the frame.
const SI: usize = 896;
/// `sizeof(mcontext_t)` (`mc_len`).
const MC_LEN: u64 = 800;
/// `mc_fpformat`: `_MC_FPFMT_XMM`.
const FPFMT_XMM: u64 = 0x10002;
/// `mc_ownedfp`: `_MC_FPOWNED_FPU`.
const FPOWNED_FPU: u64 = 0x20001;
/// FreeBSD `si_code` for `kill`: `SI_USER`.
const SI_USER: i32 = 0x10001;
/// The registers of `mcontext_t` from `mc_rdi` (offset 8) to `mc_r15` (offset 120).
const MC_GPRS: usize = 15;

fn mc_gprs(r: &UserRegs) -> [u64; MC_GPRS] {
    [r.rdi, r.rsi, r.rdx, r.rcx, r.r8, r.r9, r.rax, r.rbx, r.rbp, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15]
}

/// Builds FreeBSD's signal frame for internal signal `sig` (the dispatch point in
/// `compat::linux::proc::build_frame`): the frame below the interrupted stack (or on the
/// alternate stack), then `rip` = the trampoline, `rdi` = the FreeBSD signal number, `rsi`
/// = `&sf_si` (or the code without `SA_SIGINFO`), `rdx` = `&sf_uc`, `rcx` = the fault address.
pub fn build_frame(regs: &mut UserRegs, fpu: &FpuState, sig: u32, act: &SigAction, old_mask: u64, cs: u16) -> bool {
    // The context as the program sees it: a system call's result in FreeBSD's convention
    super::fix_saved_context(&TABLE, regs);
    let (alt_sp, alt_size, alt_on) = crate::compat::linux::proc::alt_stack();
    let on_alt = alt_on && regs.rsp > alt_sp && regs.rsp <= alt_sp + alt_size;
    let top = if act.flags & LINUX_SA_ONSTACK != 0 && alt_size != 0 && !on_alt { alt_sp + alt_size } else { regs.rsp - 128 };
    let sfp = (top - SIGFRAME as u64) & !0xF;
    let fsig = abi::internal_sig_to_freebsd(sig);

    let mut f = [0u8; SIGFRAME];
    let put = |f: &mut [u8; SIGFRAME], off: usize, v: u64| f[off..off + 8].copy_from_slice(&v.to_le_bytes());
    put(&mut f, 0, act.handler);
    f[UC..UC + 16].copy_from_slice(&mask_to_freebsd(old_mask));
    let mc = UC + MC;
    put(&mut f, mc, on_alt as u64); // mc_onstack
    for (i, v) in mc_gprs(regs).iter().enumerate() {
        put(&mut f, mc + 8 + i * 8, *v);
    }
    put(&mut f, mc + 160, regs.rip);
    put(&mut f, mc + 168, cs as u64);
    put(&mut f, mc + 176, regs.rflags);
    put(&mut f, mc + 184, regs.rsp);
    put(&mut f, mc + 192, crate::arch::gdt::USER_DS as u64);
    put(&mut f, mc + 200, MC_LEN);
    put(&mut f, mc + 208, FPFMT_XMM);
    put(&mut f, mc + 216, FPOWNED_FPU);
    f[mc + 224..mc + 736].copy_from_slice(&fpu.0[..512]);
    put(&mut f, mc + 736, crate::task::with_current_task_mut(|t| t.fs_base).unwrap_or(0));
    // uc_link 0; uc_stack { ss_sp, ss_size, ss_flags (SS_ONSTACK 1, SS_DISABLE 4) }
    put(&mut f, UC + 824, alt_sp);
    put(&mut f, UC + 832, alt_size);
    f[UC + 840..UC + 844].copy_from_slice(&(if on_alt { 1u32 } else if alt_size == 0 { 4 } else { 0 }).to_le_bytes());
    // siginfo: si_signo, si_errno, si_code, si_pid, si_uid
    f[SI..SI + 4].copy_from_slice(&(fsig as i32).to_le_bytes());
    f[SI + 8..SI + 12].copy_from_slice(&SI_USER.to_le_bytes());
    if crate::compat::linux::vfs::copy_out(sfp, &f).is_err() {
        return false;
    }
    regs.rsp = sfp;
    regs.rip = SIGCODE_ADDR;
    regs.rdi = fsig as u64;
    regs.rsi = if act.flags & LINUX_SA_SIGINFO != 0 { sfp + SI as u64 } else { SI_USER as u64 };
    regs.rdx = sfp + UC as u64;
    regs.rcx = 0;
    regs.rflags &= !(0x100 | 0x400); // TF, DF
    true
}

/// FreeBSD `sigreturn(ucp)`: back to the context a signal frame saved (no return when it
/// works: the full register set goes back with `iretq`).
fn sigreturn(frame: &mut SyscallFrame, ucp: u64) -> i64 {
    let _ = frame;
    let uc = match crate::compat::linux::vfs::copy_in(ucp, 880) {
        Ok(b) => b,
        Err(_) => return EFAULT,
    };
    let get = |off: usize| u64::from_le_bytes(uc[off..off + 8].try_into().unwrap());
    let mc = MC;
    if get(mc + 200) != MC_LEN {
        return EINVAL;
    }
    let g = |i: usize| get(mc + 8 + i * 8);
    let regs = UserRegs {
        rdi: g(0),
        rsi: g(1),
        rdx: g(2),
        rcx: g(3),
        r8: g(4),
        r9: g(5),
        rax: g(6),
        rbx: g(7),
        rbp: g(8),
        r10: g(9),
        r11: g(10),
        r12: g(11),
        r13: g(12),
        r14: g(13),
        r15: g(14),
        rip: get(mc + 160),
        // User code may only change the arithmetic flags, DF, TF...: IF stays set
        rflags: (get(mc + 176) & 0x0000_0000_0025_4DD5) | 0x202,
        rsp: get(mc + 184),
    };
    if regs.rip >= crate::memory::vm::USER_SPACE_END || regs.rsp >= crate::memory::vm::USER_SPACE_END {
        return EINVAL;
    }
    let mut fpu = FpuState::new();
    if get(mc + 216) == FPOWNED_FPU {
        fpu.0[..512].copy_from_slice(&uc[mc + 224..mc + 736]);
        // MXCSR's reserved bits clear, or FXRSTOR faults
        let mxcsr = u32::from_le_bytes(fpu.0[24..28].try_into().unwrap()) & 0xFFFF;
        fpu.0[24..28].copy_from_slice(&mxcsr.to_le_bytes());
        fpu.legacy_written();
    }
    crate::compat::linux::proc::set_current_mask(mask_from_freebsd(&uc[0..16]));
    crate::task::CURRENT_SYSCALL.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: a user context checked above; the kernel lock is released on the way out
    unsafe { crate::compat::linux::proc::return_to_user(&regs, &fpu, crate::arch::gdt::USER_CS) }
}
