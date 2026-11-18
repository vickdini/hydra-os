//! # Personalities: programs of other systems (wave 5, the personality hook)
//!
//! A personality is a property of a process, chosen when it `exec`s a program
//! (`docs/personality-design.md`, section 2). Linux stays the default; everything that
//! differs between systems is selected by it. This module is the hook later front ends
//! (FreeBSD in wave 11, macOS in wave 12) plug into; it changes nothing for Linux programs.
//!
//! - **Choosing at exec** ([`choose`]): from the program file's marking ([`abi::classify`]).
//!   Until a front end exists, FreeBSD programs, Mach-O files and ELF files of other systems
//!   are refused with `ENOEXEC` and one kernel log line. (Before wave 5 a FreeBSD program was
//!   started as a Linux program and crashed at once.) A program and its interpreter must
//!   have the same personality ([`interp_agrees`]).
//! - **A system call table per personality** ([`Table`]), reached through a per-CPU pointer
//!   ([`CURRENT_TABLE`]) that `Scheduler::switch_to` writes next to `CURRENT_TID` (and
//!   `execve` when the personality changes). It is **null for Linux and native tasks**: the
//!   system call entry tests it first (one per-CPU load), and a Linux call then goes on
//!   exactly as before (`lx::route` stays the one place that routes a Linux number). A
//!   non-null pointer sends the call to [`syscall`], which looks the number up in the
//!   personality's table (one load) and runs it:
//!   - [`R_LINUX_AS`]: the in-kernel Linux call `arg` with the same arguments (a bridge until
//!     the core split of wave 10; the Linux call is routed by `lx::route` as usual);
//!   - [`R_KERNEL`]: a kernel-local handler of the personality (`arg` names it);
//!   - [`R_ENOSYS`]: a deliberate stub; [`R_NOSYS`] (every number without an entry): `ENOSYS`
//!     plus the personality's signal for unknown calls (FreeBSD: `SIGSYS`);
//!   - [`R_SERVER`], [`R_MACH`]: reserved for the front ends in the servers (wave 10+), `ENOSYS`.
//!
//!   Entry flags: [`F_RET2`] (the call has a second result, in `rdx`), [`F_INDIRECT`]
//!   (FreeBSD's `syscall`/`__syscall`: the real number is in `rdi`).
//! - **The result convention** ([`Table::errno`]): BSD personalities return a positive errno
//!   with the carry flag set in the saved `rflags`, and clear it on success. Restarts put the
//!   personality's own number and arguments back.
//! - **Signals**: the kernel numbers signals as Linux does; each personality has its maps
//!   ([`abi`]) and its own frame builder ([`Table::frame`], called from the one dispatch
//!   point at the top of `compat::linux::proc::build_frame`).
//! - **The FreeBSD stub table** ([`freebsd`], test only): with QEMU's fw_cfg
//!   `opt/hydra/persona=fbsd-stub` or the boot option word `persona=fbsd-stub`, FreeBSD
//!   programs start with the FreeBSD personality and a small stub table (design 2.9), which
//!   proves the hook before wave 11's front end. Off by default.

pub mod abi;
pub mod freebsd;

use core::sync::atomic::{AtomicBool, Ordering};

use crate::arch::idt::FpuState;
use crate::arch::syscall::SyscallFrame;
use crate::task::TaskPersonality;

/// Negative `ENOEXEC`.
const ENOEXEC: i64 = -8;
/// Negative `ENOSYS`.
const ENOSYS: i64 = -38;
/// Negative `EINTR`.
const EINTR: i64 = -4;

// ----------------------------------------------------------------------
// Choosing the personality at exec
// ----------------------------------------------------------------------

/// The boot entry asked for the FreeBSD stub table (`persona=fbsd-stub`).
pub static STUB_BY_BOOT_OPTION: AtomicBool = AtomicBool::new(false);
/// FreeBSD programs start with the stub table (else they are refused).
static FREEBSD_STUB: AtomicBool = AtomicBool::new(false);

/// Reads the switch for the FreeBSD stub table (fw_cfg `opt/hydra/persona` or the boot
/// option word, see [`STUB_BY_BOOT_OPTION`]); called once at boot.
pub fn init() {
    let mut cfg = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/persona", &mut cfg).map(|n| &cfg[..n]);
    let on = fw.is_some_and(|v| v.starts_with(b"fbsd-stub")) || STUB_BY_BOOT_OPTION.load(Ordering::Acquire);
    FREEBSD_STUB.store(on, Ordering::Release);
    if on {
        crate::kprintln!("[persona] FreeBSD programs start with the stub table (test switch persona=fbsd-stub)");
    }
}

/// Whether the FreeBSD stub table is switched on.
pub fn freebsd_stub() -> bool {
    FREEBSD_STUB.load(Ordering::Relaxed)
}

/// The personality the program file starting with `head` runs with, or `-ENOEXEC` (with a
/// kernel log line naming `path`) for what cannot run yet (design 2.2).
pub fn choose(head: &[u8], path: &str) -> Result<TaskPersonality, i64> {
    match abi::classify(head) {
        abi::Kind::Linux => Ok(TaskPersonality::Linux),
        abi::Kind::FreeBsd if freebsd_stub() => Ok(TaskPersonality::FreeBsd),
        abi::Kind::FreeBsd => {
            crate::kprintln!("[exec] {}: a FreeBSD program (ELF OS/ABI {}): refused, ENOEXEC (no FreeBSD front end yet)", path, head[7]);
            Err(ENOEXEC)
        }
        abi::Kind::MachO => {
            crate::kprintln!("[exec] {}: a Mach-O (macOS) program: refused, ENOEXEC (no macOS front end yet)", path);
            Err(ENOEXEC)
        }
        abi::Kind::OtherOs(b) => {
            crate::kprintln!("[exec] {}: an ELF program for another system (OS/ABI {}): refused, ENOEXEC", path, b);
            Err(ENOEXEC)
        }
    }
}

/// The personality of a program's interpreter (`PT_INTERP`) must be the program's own: a
/// FreeBSD program is never started by Linux's `ld.so`, nor the other way round. `false`
/// (with a log line) when they differ.
pub fn interp_agrees(pers: TaskPersonality, interp_head: &[u8], interp: &str) -> bool {
    let k = abi::classify(interp_head);
    let ok = match pers {
        TaskPersonality::FreeBsd => k == abi::Kind::FreeBsd,
        _ => k == abi::Kind::Linux,
    };
    if !ok {
        crate::kprintln!("[exec] interpreter {} is not a {} program: refused, ENOEXEC", interp, pers.as_str());
    }
    ok
}

// ----------------------------------------------------------------------
// The tables
// ----------------------------------------------------------------------

/// Route (entry bits 0-2): an unknown number (`ENOSYS` and the personality's signal).
pub const R_NOSYS: u32 = 0;
/// Route: a kernel-local handler of the personality ([`Table::local`]; `arg` names it).
pub const R_KERNEL: u32 = 1;
/// Route: the personality's front end in the POSIX server (wave 10+; `ENOSYS` until then).
pub const R_SERVER: u32 = 2;
/// Route: the in-kernel Linux call number `arg`, same arguments (bridge until wave 10).
pub const R_LINUX_AS: u32 = 3;
/// Route: a deliberate stub, `ENOSYS` without a signal.
pub const R_ENOSYS: u32 = 4;
/// Route: mach-server (wave 12; `ENOSYS` until then).
pub const R_MACH: u32 = 5;
/// Entry flag: the call has a second result, returned in `rdx` (else `rdx` is kept).
pub const F_RET2: u32 = 1 << 3;
/// Entry flag: an indirect call (FreeBSD `syscall` 0, `__syscall` 198): the number is in
/// `rdi`, the arguments follow.
pub const F_INDIRECT: u32 = 1 << 4;
/// Entries per table (FreeBSD's numbers end below 600, macOS's BSD class below 560).
pub const TABLE_LEN: usize = 1024;

/// An entry routing to Linux call `nr`.
pub const fn linux_as(nr: u16) -> u32 {
    R_LINUX_AS | (nr as u32) << 16
}
/// An entry routing to kernel-local handler `id`, with entry flags `flags`.
pub const fn local(id: u16, flags: u32) -> u32 {
    R_KERNEL | flags | (id as u32) << 16
}

/// What a call answered: the result in the internal (Linux) convention, and its second
/// result for [`F_RET2`] calls.
#[derive(Clone, Copy)]
pub struct Ret {
    /// The result (internal convention: `-errno` on failure).
    pub r: i64,
    /// The second result ([`F_RET2`]).
    pub r2: Option<u64>,
}

impl Ret {
    /// A plain result.
    pub const fn of(r: i64) -> Self {
        Self { r, r2: None }
    }
}

/// A signal frame builder: as `compat::linux::proc::build_frame` (the registers to point at
/// the handler, the FPU state, the internal signal number, the action, the mask to restore,
/// the interrupted code segment); `false` if the frame could not be written.
pub type FrameFn = fn(&mut crate::compat::linux::proc::UserRegs, &FpuState, u32, &crate::compat::linux::proc::SigAction, u64, u16) -> bool;

/// One personality's system call table.
#[repr(C, align(64))]
pub struct Table {
    /// Indexed by the personality's own call number: route | flags | arg << 16.
    pub entries: [u32; TABLE_LEN],
    /// Whose table it is.
    pub pers: TaskPersonality,
    /// The personality's kernel-local calls ([`R_KERNEL`]): handler id, the frame (for
    /// calls that change it: `sigreturn`), the arguments.
    pub local: fn(u16, &mut SyscallFrame, [u64; 6]) -> Ret,
    /// Internal errno (1..=133) to the personality's (positive, with the carry flag).
    pub errno: &'static [u8; 134],
    /// The signal an unknown number sends (internal number; 0: none).
    pub nosys_signal: u32,
    /// The signal frame builder.
    pub frame: FrameFn,
}

impl Table {
    /// The entry for call `nr` ([`R_NOSYS`] past the end).
    #[inline(always)]
    pub fn entry(&self, nr: u64) -> u32 {
        if (nr as usize) < TABLE_LEN {
            self.entries[nr as usize]
        } else {
            R_NOSYS
        }
    }
}

/// Per CPU: the system call table of the task running there; null for Linux and native
/// tasks (their calls take the path they always took). Written by `Scheduler::switch_to`
/// and by `execve`.
pub static CURRENT_TABLE: crate::arch::percpu::PerCpuPtr<Table> = crate::arch::percpu::PerCpuPtr::new();

/// The table of personality `p` (null for Linux and Hydra).
#[inline(always)]
pub fn table_for(p: TaskPersonality) -> *mut Table {
    match p {
        TaskPersonality::FreeBsd => &freebsd::TABLE as *const Table as *mut Table,
        _ => core::ptr::null_mut(),
    }
}

/// Sets this CPU's table for a task of personality `p` that runs here now (`execve`).
pub fn set_current(p: TaskPersonality) {
    CURRENT_TABLE.store(table_for(p), Ordering::Relaxed);
}

/// The frame builder of the personality running on this CPU, if it is not Linux's (the
/// dispatch point in `compat::linux::proc::build_frame`).
#[inline]
pub fn frame_builder() -> Option<FrameFn> {
    let t = CURRENT_TABLE.load(Ordering::Relaxed);
    if t.is_null() {
        None
    } else {
        // SAFETY: tables are statics
        Some(unsafe { (*t).frame })
    }
}

// ----------------------------------------------------------------------
// The system call path of a non-Linux personality
// ----------------------------------------------------------------------

/// The registers of the call in progress on a CPU, as the program made it: the frame
/// builders put them back into a saved context when the call is restarted after the
/// handler, and turn an error result into the personality's convention.
#[derive(Clone, Copy)]
struct InCall {
    /// A call of a non-Linux personality is between its answer and the return to user mode.
    active: bool,
    /// rax, rdi, rsi, rdx, r10, r8, r9 as the program passed them.
    raw: [u64; 7],
    /// The address after the `syscall` instruction.
    rip: u64,
}

struct InCalls([core::cell::UnsafeCell<InCall>; crate::arch::smp::MAX_CPUS]);
// SAFETY: each CPU touches only its own entry, under the kernel lock, for the call it runs
unsafe impl Sync for InCalls {}
static IN_CALL: InCalls = InCalls([const { core::cell::UnsafeCell::new(InCall { active: false, raw: [0; 7], rip: 0 }) }; crate::arch::smp::MAX_CPUS]);

fn in_call() -> &'static mut InCall {
    let cpu = crate::arch::percpu::cpu().min(crate::arch::smp::MAX_CPUS - 1);
    // SAFETY: see InCalls
    unsafe { &mut *IN_CALL.0[cpu].get() }
}

/// Is `r` one of the internal restart codes (`ERESTARTSYS`, `ERESTARTNOINTR`,
/// `ERESTARTNOHAND`, `ERESTART_RESTARTBLOCK`)?
fn restart_code(r: i64) -> bool {
    matches!(r, -512 | -513 | -514 | -516)
}

/// Writes result `r` (internal convention) into `rax`/`rflags`/`rdx` in table `t`'s
/// convention (BSD: positive errno and the carry flag).
fn encode(t: &Table, rax: &mut u64, rflags: &mut u64, rdx: &mut u64, r: i64, r2: Option<u64>) {
    let r = if restart_code(r) { EINTR } else { r };
    if (-4095..0).contains(&r) {
        *rax = abi::bsd_errno(t.errno, (-r) as u64);
        *rflags |= 1;
    } else {
        *rax = r as u64;
        *rflags &= !1;
        if let Some(v) = r2 {
            *rdx = v;
        }
    }
}

/// For a frame builder: the context it saves (registers as the signal interrupted them) in
/// the personality's convention. During a system call's return, an error result becomes
/// a positive errno with the carry flag, and a call restarted after the handler gets back
/// the personality's own number and arguments (the trap had put a Linux number there).
pub fn fix_saved_context(t: &Table, regs: &mut crate::compat::linux::proc::UserRegs) {
    let c = in_call();
    if !c.active {
        return;
    }
    if regs.rip == c.rip.wrapping_sub(2) {
        [regs.rax, regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9] = c.raw;
    } else if regs.rip == c.rip {
        let r = regs.rax as i64;
        if (-4095..0).contains(&r) {
            let mut fl = regs.rflags;
            let mut rdx = regs.rdx;
            encode(t, &mut regs.rax, &mut fl, &mut rdx, r, None);
            regs.rflags = fl;
            regs.r11 = fl;
        }
    }
}

/// Runs Linux call `nr` in the kernel with `args` (a scratch frame: only for calls that do
/// not change the caller's registers), for kernel-local handlers.
pub fn linux_call(nr: u64, args: [u64; 6]) -> i64 {
    let mut f = SyscallFrame {
        r9: args[5],
        r8: args[4],
        r10: args[3],
        rdx: args[2],
        rsi: args[1],
        rdi: args[0],
        rax: nr,
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        rbp: 0,
        rbx: 0,
        rip: 0,
        rflags: 0,
        rsp: 0,
    };
    crate::compat::linux::dispatch_linux_syscall(&mut f)
}

/// A system call of a task whose personality has a table (`t`, from [`CURRENT_TABLE`]),
/// called by `arch::syscall`'s entry before anything else. Runs under the kernel lock like
/// the ordinary path, delivers signals on the way out, and returns in the personality's
/// convention.
pub fn syscall(frame: &mut SyscallFrame, fpu: *mut FpuState, t: &'static Table) {
    crate::arch::smp::bkl_enter();
    crate::arch::syscall::SYSCALL_ENTRIES.fetch_add(1, Ordering::Relaxed);
    crate::task::scheduler::wait_out_handoff();
    crate::arch::syscall::SYSCALL_FPU.store(fpu, Ordering::Release);
    crate::arch::syscall::reap_retired();
    x86_64::instructions::interrupts::enable();

    let raw = [frame.rax, frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    let rip = frame.rip;
    let mut nr = frame.rax;
    let mut e = t.entry(nr);
    if e & F_INDIRECT != 0 {
        // syscall(nr, a0..a4) / __syscall(nr, ...): the arguments move down by one (a sixth
        // would be on the stack; no call that matters on amd64 has one)
        nr = frame.rdi;
        [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9] = [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9, 0];
        e = t.entry(nr);
        if e & F_INDIRECT != 0 {
            e = R_NOSYS;
        }
    }
    let arg = (e >> 16) as u16;
    let args = [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9];
    // What the task dump shows: 0x2_0000 + the personality's number
    crate::task::CURRENT_SYSCALL.store(0x2_0000 | nr, Ordering::Relaxed);
    let mut linux_nr = u64::MAX;
    let ret = match e & 7 {
        R_LINUX_AS => {
            linux_nr = arg as u64;
            frame.rax = linux_nr;
            Ret::of(crate::compat::linux::dispatch_linux_syscall(frame))
        }
        R_KERNEL => (t.local)(arg, frame, args),
        R_ENOSYS | R_SERVER | R_MACH => Ret::of(ENOSYS),
        _ => {
            // Unknown: ENOSYS, and the personality's signal (FreeBSD's nosys sends SIGSYS)
            if t.nosys_signal != 0 {
                let (tid, pid) = crate::compat::linux::proc::current_ids();
                crate::compat::linux::proc::post_thread(pid, tid, t.nosys_signal);
            }
            Ret::of(ENOSYS)
        }
    };
    crate::task::CURRENT_SYSCALL.store(u64::MAX, Ordering::Relaxed);
    if linux_nr != u64::MAX && crate::compat::linux::changes_identity(linux_nr) {
        crate::compat::linux::ident_changed();
    }

    if (linux_nr == 59 || linux_nr == 322) && ret.r == 0 {
        // A new program (perhaps of another personality: execve set this CPU's table): its
        // registers are in the frame already
        crate::compat::linux::proc::deliver_on_syscall_return(frame, fpu, linux_nr);
    } else {
        // The registers the program passed come back (FreeBSD and macOS keep them), then
        // the result; a restart code stays internal until the delivery decided
        [frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9] = [raw[1], raw[2], raw[3], raw[4], raw[5], raw[6]];
        let restart = restart_code(ret.r);
        if restart {
            frame.rax = ret.r as u64;
        } else {
            encode(t, &mut frame.rax, &mut frame.rflags, &mut frame.rdx, ret.r, ret.r2);
        }
        *in_call() = InCall { active: true, raw, rip };
        let orig = if linux_nr != u64::MAX { linux_nr } else { raw[0] };
        crate::compat::linux::proc::deliver_on_syscall_return(frame, fpu, orig);
        in_call().active = false;
        if frame.rip == rip.wrapping_sub(2) {
            // Restarted: the program's own number and arguments
            [frame.rax, frame.rdi, frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9] = raw;
        } else if restart && frame.rip == rip {
            // Not restarted, no handler (or one whose frame is built: rip moved): the result
            let r = frame.rax as i64;
            encode(t, &mut frame.rax, &mut frame.rflags, &mut frame.rdx, r, None);
        }
    }
    if crate::task::current_retired() {
        crate::task::leave_retired();
    }
    x86_64::instructions::interrupts::disable();
    crate::arch::smp::flush_kick();
    crate::arch::smp::bkl_exit();
}
