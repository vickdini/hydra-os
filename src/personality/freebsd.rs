//! # The FreeBSD personality: the call table (wave 12, Group FK)
//!
//! FreeBSD programs (ELF OS/ABI 9 or the "FreeBSD" note) run with this table by default
//! (boot option `persona=off` refuses them again; `persona=fbsd-stub` gives the wave 5 stub
//! table, [`STUB_TABLE`]). Design: `docs/personality-design.md` sections 2, 4; module page
//! `docs/src/personality.md`; the list of all 409 calls with their classes:
//! `docs/personality-freebsd-syscalls.md`.
//!
//! **What each FreeBSD call becomes** (decision 39: the kernel keeps only mechanism):
//!
//! | Kind | Route |
//! |---|---|
//! | the "D" calls (same operation, errno only) | `LINUX_AS`: the Linux call, same arguments; the result in FreeBSD's convention |
//! | flag and constant translations the kernel owns: `open`/`openat` and the `AT_*` calls, `mmap`/`mprotect`/`madvise`/`minherit`/`msync`, clocks, `RLIMIT_*`, `wait4`, signal sets, `fcntl`'s descriptor commands, `pipe2`, `getpriority`, `posix_fallocate`/`posix_fadvise`, scheduling policies | kernel-local, in [`super::fbsd_calls`] |
//! | mechanism: signals (`sigaction`, `sigreturn`, `sigprocmask`...), `getcontext`/`setcontext`/`swapcontext`, `thr_*`, `_umtx_op` ([`super::umtx`]), `sysarch`, `issetugid`, `__getcwd`, `utrace` | kernel-local |
//! | **temporary**: `fstat`, `fstatat`, `getdirentries`, `fstatfs` and a few `sysctl` names ([`super::fbsd_tmp`]) | kernel-local until stage 2 moves them into vfs-server and lx-proc |
//! | the "S" stubs: Capsicum (`ENOSYS`, quietly: `capsicum_helpers` carry on), jails, kld, mount, MAC, audit | fixed answers, see [`entries`] |
//! | every other FreeBSD call (sockets, `ioctl`, `kqueue`, `stat` by path, ...) | `ENOSYS` with one log line per call naming it (`[persona] FreeBSD <prog>: <call> (n) not implemented yet`) |
//! | a number FreeBSD does not have | `ENOSYS` and `SIGSYS` (FreeBSD's `nosys`) |
//!
//! **Signal frames** are FreeBSD's `struct sigframe` (`sys/x86/include/sigframe.h`): the
//! handler pointer, a `ucontext_t` (FreeBSD's 128-bit `uc_sigmask`, the 800-byte
//! `mcontext_t` with the FXSAVE area) and a `siginfo_t`. FreeBSD enters its signal
//! trampoline (`sigcode`) first, which calls the handler and then `sigreturn(&sf_uc)`; the
//! trampoline lives on one page mapped into every FreeBSD process at [`SIGCODE_ADDR`] (the
//! "shared page"), next to `thr_new`'s thread start ([`super::abi::FREEBSD_THR_START`]). Not
//! yet: the XSAVE extension (AVX upper halves are not saved across a handler), fault details
//! in `siginfo` (`si_code` is `SI_USER`), delivery of a signal that became deliverable by
//! `sigreturn`'s mask before the next system call or trap.

use super::fbsd_calls as c;
use super::fbsd_xlat::{mask_from_freebsd, mask_to_freebsd, Mcontext, MC_LEN, UC_LEN, UC_MCONTEXT};
use super::{abi, linux_as, local, Table, F_INDIRECT, F_RET2, R_ENOSYS, R_NOSYS, TABLE_LEN};
use crate::arch::idt::FpuState;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::proc::{SigAction, UserRegs};
use crate::task::TaskPersonality;

/// Negative `EINVAL`.
const EINVAL: i64 = -22;
/// Negative `EFAULT`.
const EFAULT: i64 = -14;

pub use super::abi::FREEBSD_OSRELDATE as OSRELDATE;

/// The FreeBSD table (the default).
pub static TABLE: Table = Table {
    entries: entries(),
    pers: TaskPersonality::FreeBsd,
    local: c::local_call,
    errno: &abi::FREEBSD_ERRNO,
    nosys_signal: 31, // SIGSYS
    frame: build_frame,
};

/// The wave 5 stub table (test switch `persona=fbsd-stub`): the calls of the hook's test
/// programs only.
pub static STUB_TABLE: Table = Table {
    entries: stub_entries(),
    pers: TaskPersonality::FreeBsd,
    local: c::local_call,
    errno: &abi::FREEBSD_ERRNO,
    nosys_signal: 31,
    frame: build_frame,
};

/// The stub table's entries (design 2.9).
const fn stub_entries() -> [u32; TABLE_LEN] {
    let mut e = [R_NOSYS; TABLE_LEN];
    e[0] = R_NOSYS | F_INDIRECT; // syscall
    e[1] = linux_as(231); // exit: the whole process
    e[3] = linux_as(0); // read
    e[4] = linux_as(1); // write
    e[6] = linux_as(3); // close
    e[20] = local(c::L_GETPID, F_RET2);
    e[24] = linux_as(102); // getuid
    e[25] = linux_as(107); // geteuid
    e[37] = local(c::L_KILL, 0);
    e[39] = linux_as(110); // getppid
    e[43] = linux_as(108); // getegid
    e[47] = linux_as(104); // getgid
    e[59] = linux_as(59); // execve
    e[198] = R_NOSYS | F_INDIRECT; // __syscall
    e[240] = linux_as(35); // nanosleep (same struct timespec)
    e[416] = local(c::L_SIGACTION, 0);
    e[417] = local(c::L_SIGRETURN, 0);
    e[432] = local(c::L_THR_SELF, 0);
    e
}

pub use super::fbsd_xlat::DIRECT;


/// The kernel-local calls: FreeBSD number, handler ([`super::fbsd_calls`]).
pub const LOCAL: [(u16, u16); 89] = [
    (5, c::L_OPEN),
    (7, c::L_WAIT4),
    (17, c::L_BREAK),
    (20, c::L_GETPID),
    (37, c::L_KILL),
    (53, c::L_SIGALTSTACK),
    (65, c::L_MSYNC),
    (74, c::L_MPROTECT),
    (75, c::L_MADVISE),
    (89, c::L_GETDTABLESIZE),
    (92, c::L_FCNTL),
    (100, c::L_GETPRIORITY),
    (132, c::L_MKFIFO),
    (165, c::L_SYSARCH),
    (182, c::L_SETEGID),
    (183, c::L_SETEUID),
    (194, c::L_GETRLIMIT),
    (195, c::L_SETRLIMIT),
    (202, c::L_SYSCTL),
    (232, c::L_CLOCK_GETTIME),
    (233, c::L_CLOCK_SETTIME),
    (234, c::L_CLOCK_GETRES),
    (244, c::L_CLOCK_NANOSLEEP),
    (250, c::L_MINHERIT),
    (253, c::L_ISSETUGID),
    (326, c::L_GETCWD),
    (329, c::L_SCHED_SETSCHEDULER),
    (330, c::L_SCHED_GETSCHEDULER),
    (332, c::L_SCHED_GET_PRIORITY_MAX),
    (333, c::L_SCHED_GET_PRIORITY_MIN),
    (335, c::L_ZERO), // utrace: nobody traces
    (340, c::L_SIGPROCMASK),
    (341, c::L_SIGSUSPEND),
    (343, c::L_SIGPENDING),
    (345, c::L_SIGTIMEDWAIT),
    (346, c::L_SIGWAITINFO),
    (376, c::L_EACCESS),
    (416, c::L_SIGACTION),
    (417, c::L_SIGRETURN),
    (421, c::L_GETCONTEXT),
    (422, c::L_SETCONTEXT),
    (423, c::L_SWAPCONTEXT),
    (429, c::L_SIGWAIT),
    (431, c::L_THR_EXIT),
    (432, c::L_THR_SELF),
    (433, c::L_THR_KILL),
    (442, c::L_THR_SUSPEND),
    (443, c::L_THR_WAKE),
    (454, c::L_UMTX_OP),
    (455, c::L_THR_NEW),
    (456, c::L_SIGQUEUE),
    (457, c::L_KMQ_OPEN),
    (462, c::L_KMQ_UNLINK),
    (464, c::L_THR_SET_NAME),
    (477, c::L_MMAP),
    (481, c::L_THR_KILL2),
    (487, c::L_CPUSET_GETAFFINITY),
    (488, c::L_ZERO), // cpuset_setaffinity: accepted (one scheduler domain)
    (489, c::L_FACCESSAT),
    (490, c::L_FCHMODAT),
    (491, c::L_FCHOWNAT),
    (495, c::L_LINKAT),
    (497, c::L_MKFIFOAT),
    (499, c::L_OPENAT),
    (503, c::L_UNLINKAT),
    (522, c::L_PSELECT),
    (530, c::L_POSIX_FALLOCATE),
    (531, c::L_POSIX_FADVISE),
    (542, c::L_PIPE2),
    (545, c::L_PPOLL),
    (546, c::L_FUTIMENS),
    (547, c::L_UTIMENSAT),
    (551, c::L_FSTAT),
    (552, c::L_FSTATAT),
    (554, c::L_GETDIRENTRIES),
    (556, c::L_FSTATFS),
    (559, c::L_MKNODAT),
    (568, c::L_FUNLINKAT),
    (570, c::L_SYSCTLBYNAME),
    (573, c::L_ENOSYS_QUIET), // sigfastblock: never asked for (AT_BSDFLAGS has no SIGFASTBLK)
    (581, c::L_SCHED_GETCPU),
    (585, c::L_TIMERFD_CREATE),
    (602, c::L_RENAMEAT2),
    // "S" stubs, quiet: the C library's helpers take ENOSYS as "not here"
    (516, c::L_ENOSYS_QUIET), // cap_enter
    (517, c::L_ENOSYS_QUIET), // cap_getmode
    (515, c::L_ENOSYS_QUIET), // __cap_rights_get
    (533, c::L_ENOSYS_QUIET), // cap_rights_limit
    (534, c::L_ENOSYS_QUIET), // cap_ioctls_limit
    (536, c::L_ENOSYS_QUIET), // cap_fcntls_limit
];

/// The "S" stubs with fixed answers (design 4.3): FreeBSD number, handler.
pub const STUBS: [(u16, u16); 37] = [
    (535, c::L_ENOSYS_QUIET), // cap_ioctls_get
    (537, c::L_ENOSYS_QUIET), // cap_fcntls_get
    // Jails: not jailed; jail_get finds none, the rest is not allowed
    (338, c::L_EPERM),  // jail
    (436, c::L_EPERM),  // jail_attach
    (506, c::L_ENOENT), // jail_get
    (507, c::L_EPERM),  // jail_set
    (508, c::L_EPERM),  // jail_remove
    (597, c::L_EPERM),  // jail_attach_jd
    (598, c::L_EPERM),  // jail_remove_jd
    // Kernel modules: none to find, none to load
    (300, c::L_ZERO),   // modnext: no modules
    (301, c::L_ENOENT), // modstat
    (302, c::L_ZERO),   // modfnext
    (303, c::L_ENOENT), // modfind
    (304, c::L_EPERM),  // kldload
    (305, c::L_EPERM),  // kldunload
    (306, c::L_ENOENT), // kldfind
    (307, c::L_ZERO),   // kldnext: no files
    (308, c::L_ENOENT), // kldstat
    (309, c::L_ZERO),   // kldfirstmod
    (337, c::L_ENOENT), // kldsym
    (444, c::L_EPERM),  // kldunloadf
    // Mounts, swap, reboot belong to Hydra's admin interface
    (21, c::L_EPERM),  // mount
    (22, c::L_EPERM),  // unmount
    (378, c::L_EPERM), // nmount
    (55, c::L_EPERM),  // reboot
    (85, c::L_EPERM),  // swapon
    (582, c::L_EPERM), // swapoff
    // File flags (chflags): none here
    (34, c::L_EOPNOTSUPP),  // chflags
    (35, c::L_EOPNOTSUPP),  // fchflags
    (391, c::L_EOPNOTSUPP), // lchflags
    (540, c::L_EOPNOTSUPP), // chflagsat
    // MAC and audit: not here (the C library takes ENOSYS as "no MAC")
    (384, c::L_ENOSYS_QUIET), // __mac_get_proc
    (386, c::L_ENOSYS_QUIET), // __mac_get_fd
    (387, c::L_ENOSYS_QUIET), // __mac_get_file
    (409, c::L_ENOSYS_QUIET), // __mac_get_pid
    (410, c::L_ENOSYS_QUIET), // __mac_get_link
    (447, c::L_ENOSYS_QUIET), // getauid
];

/// The full table. Every live FreeBSD number gets an entry: unlisted ones are `R_ENOSYS`
/// (logged once per call); numbers FreeBSD does not have stay `R_NOSYS` (`SIGSYS`).
const fn entries() -> [u32; TABLE_LEN] {
    let mut e = [R_NOSYS; TABLE_LEN];
    // Every live call first: "not implemented yet" (ENOSYS, logged)
    let mut i = 0;
    while i < super::fbsd_xlat::NAMES.len() {
        e[super::fbsd_xlat::NAMES[i].0 as usize] = R_ENOSYS;
        i += 1;
    }
    e[0] = R_NOSYS | F_INDIRECT; // syscall
    e[198] = R_NOSYS | F_INDIRECT; // __syscall
    let mut i = 0;
    while i < DIRECT.len() {
        e[DIRECT[i].0 as usize] = linux_as(DIRECT[i].1);
        i += 1;
    }
    let mut i = 0;
    while i < LOCAL.len() {
        e[LOCAL[i].0 as usize] = local(LOCAL[i].1, if LOCAL[i].0 == 20 { F_RET2 } else { 0 });
        i += 1;
    }
    let mut i = 0;
    while i < STUBS.len() {
        e[STUBS[i].0 as usize] = local(STUBS[i].1, 0);
        i += 1;
    }
    e
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

/// FreeBSD `sigaction(sig, act, oact)`: `struct sigaction { handler; int sa_flags;
/// sigset_t sa_mask; }` (32 bytes), translated to the internal action.
pub fn sigaction(sig: u64, act: u64, oact: u64) -> i64 {
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
/// Offset of `sf_si` in the frame.
const SI: usize = 896;
/// FreeBSD `si_code` for `kill`: `SI_USER`.
const SI_USER: i32 = 0x10001;

/// The `mcontext_t` state of user registers `r` (code segment `cs`).
pub fn mcontext_of(r: &UserRegs, cs: u64, onstack: bool) -> Mcontext {
    Mcontext {
        onstack: onstack as u64,
        gprs: [r.rdi, r.rsi, r.rdx, r.rcx, r.r8, r.r9, r.rax, r.rbx, r.rbp, r.r10, r.r11, r.r12, r.r13, r.r14, r.r15],
        rip: r.rip,
        cs,
        rflags: r.rflags,
        rsp: r.rsp,
        ss: crate::arch::gdt::USER_DS as u64,
        fsbase: crate::task::with_current_task_mut(|t| t.fs_base).unwrap_or(0),
        flags: 0,
    }
}

/// The user registers of an `mcontext_t` state.
pub fn regs_of(m: &Mcontext) -> UserRegs {
    let g = &m.gprs;
    UserRegs {
        rdi: g[0],
        rsi: g[1],
        rdx: g[2],
        rcx: g[3],
        r8: g[4],
        r9: g[5],
        rax: g[6],
        rbx: g[7],
        rbp: g[8],
        r10: g[9],
        r11: g[10],
        r12: g[11],
        r13: g[12],
        r14: g[13],
        r15: g[14],
        rip: m.rip,
        rflags: Mcontext::user_rflags(m.rflags),
        rsp: m.rsp,
    }
}

/// The `uc_stack` of the calling thread (`ss_sp, ss_size, ss_flags`: `SS_ONSTACK 1`,
/// `SS_DISABLE 4`) when it runs at `rsp`, and whether that is on the alternate stack.
pub fn uc_stack(rsp: u64) -> ([u8; 24], bool) {
    let (alt_sp, alt_size, alt_on) = crate::compat::linux::proc::alt_stack();
    let on_alt = alt_on && rsp > alt_sp && rsp <= alt_sp + alt_size;
    let mut b = [0u8; 24];
    b[0..8].copy_from_slice(&alt_sp.to_le_bytes());
    b[8..16].copy_from_slice(&alt_size.to_le_bytes());
    b[16..20].copy_from_slice(&(if on_alt { 1u32 } else if alt_size == 0 { 4 } else { 0 }).to_le_bytes());
    (b, on_alt)
}

/// Builds FreeBSD's signal frame for internal signal `sig` (the dispatch point in
/// `compat::linux::proc::build_frame`): the frame below the interrupted stack (or on the
/// alternate stack), then `rip` = the trampoline, `rdi` = the FreeBSD signal number, `rsi`
/// = `&sf_si` (or the code without `SA_SIGINFO`), `rdx` = `&sf_uc`, `rcx` = the fault address.
pub fn build_frame(regs: &mut UserRegs, fpu: &FpuState, sig: u32, act: &SigAction, old_mask: u64, cs: u16) -> bool {
    // The context as the program sees it: a system call's result in FreeBSD's convention
    super::fix_saved_context(&TABLE, regs);
    let (alt_sp, alt_size, alt_on) = crate::compat::linux::proc::alt_stack();
    let (stack, on_alt) = uc_stack(regs.rsp);
    let top = if act.flags & LINUX_SA_ONSTACK != 0 && alt_on && !on_alt { alt_sp + alt_size } else { regs.rsp - 128 };
    let sfp = (top - SIGFRAME as u64) & !0xF;
    let fsig = abi::internal_sig_to_freebsd(sig);

    let mut f = [0u8; SIGFRAME];
    f[0..8].copy_from_slice(&act.handler.to_le_bytes());
    f[UC..UC + 16].copy_from_slice(&mask_to_freebsd(old_mask));
    let mut fx = [0u8; 512];
    fx.copy_from_slice(&fpu.0[..512]);
    mcontext_of(regs, cs as u64, on_alt).pack(Some(&fx), &mut f[UC + UC_MCONTEXT..UC + UC_MCONTEXT + MC_LEN]);
    f[UC + super::fbsd_xlat::UC_STACK..UC + super::fbsd_xlat::UC_STACK + 24].copy_from_slice(&stack);
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

/// Returns to user context `ucp` (a FreeBSD `ucontext_t`): its signal mask and registers,
/// and its FPU state when it holds one (else `cur_fpu` stays, or a fresh state). No return
/// when it works: the full register set goes back with `iretq`.
pub fn set_context(ucp: u64, cur_fpu: Option<&FpuState>) -> i64 {
    let uc = match crate::compat::linux::vfs::copy_in(ucp, UC_LEN) {
        Ok(b) => b,
        Err(_) => return EFAULT,
    };
    let Ok((m, fx)) = Mcontext::unpack(&uc[UC_MCONTEXT..UC_MCONTEXT + MC_LEN]) else { return EINVAL };
    let regs = regs_of(&m);
    if regs.rip >= crate::memory::vm::USER_SPACE_END || regs.rsp >= crate::memory::vm::USER_SPACE_END {
        return EINVAL;
    }
    let mut fpu = FpuState::new();
    match (fx, cur_fpu) {
        (Some(fx), _) => {
            fpu.0[..512].copy_from_slice(&fx);
            fpu.legacy_written();
        }
        (None, Some(cur)) => fpu.0.copy_from_slice(&cur.0),
        (None, None) => {}
    }
    crate::compat::linux::proc::set_current_mask(mask_from_freebsd(&uc[0..16]));
    crate::task::CURRENT_SYSCALL.store(u64::MAX, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: a user context checked above; the kernel lock is released on the way out
    unsafe { crate::compat::linux::proc::return_to_user(&regs, &fpu, crate::arch::gdt::USER_CS) }
}

/// FreeBSD `sigreturn(ucp)`: back to the context a signal frame saved.
pub fn sigreturn(_frame: &mut SyscallFrame, ucp: u64) -> i64 {
    set_context(ucp, None)
}
