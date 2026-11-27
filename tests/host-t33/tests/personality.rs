//! The personality hook (`src/personality/mod.rs`) and FreeBSD's stub table
//! (`src/personality/freebsd.rs`): choosing a personality at exec, the system call path of
//! a table (routes, indirect calls, BSD error convention, restarts around signal
//! delivery), and FreeBSD's signal frames, `sigaction` and `sigreturn`.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;

use hydra_hosttests_t33::arch::idt::FpuState;
use hydra_hosttests_t33::arch::syscall::SyscallFrame;
use hydra_hosttests_t33::compat::linux::proc::{Returned, SigAction, UserRegs};
use hydra_hosttests_t33::compat::linux::{ACTIONS, ALT, DELIVERED, DELIVER_HOOK, IDENT_CHANGES, LINUX_CALLS, LINUX_RESULTS, MASK};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::personality::{self, abi, freebsd, linux_as, local, Ret, Table, F_INDIRECT, F_RET2, R_ENOSYS, R_KERNEL, R_LINUX_AS, R_MACH, R_NOSYS, R_SERVER, TABLE_LEN};
use hydra_hosttests_t33::task::{TaskPersonality, CURRENT_SYSCALL};

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

fn elf(osabi: u8) -> Vec<u8> {
    let mut h = vec![0u8; 64];
    h[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
    h[4] = 2;
    h[5] = 1;
    h[7] = osabi;
    h
}

fn frame(nr: u64, args: [u64; 6]) -> SyscallFrame {
    SyscallFrame { rax: nr, rdi: args[0], rsi: args[1], rdx: args[2], r10: args[3], r8: args[4], r9: args[5], rip: 0x40_1000, rflags: 0x202, ..Default::default() }
}

// ---------------------------------------------------------------- choosing

#[test]
fn exec_chooses_a_personality_or_refuses() {
    let _g = serial();
    // No switch (no fw_cfg file, no boot option): FreeBSD programs run (wave 12)
    personality::init();
    assert!(!personality::freebsd_stub());
    assert_eq!(personality::choose(&elf(0), "/bin/ls"), Ok(TaskPersonality::Linux));
    assert_eq!(personality::choose(&elf(3), "/bin/ls"), Ok(TaskPersonality::Linux));
    assert_eq!(personality::choose(&elf(9), "/bsd/ls"), Ok(TaskPersonality::FreeBsd));
    // persona=off (fw_cfg or the boot option): refused as before wave 12
    fake::FWCFG.with_borrow_mut(|m| m.insert("opt/hydra/persona".into(), b"off
".to_vec()));
    personality::init();
    assert!(fake::klog_take().contains("refused (persona=off)"));
    assert_eq!(personality::choose(&elf(9), "/bsd/ls"), Err(-8));
    assert!(fake::klog_take().contains("/bsd/ls: a FreeBSD program (ELF OS/ABI 9): refused, ENOEXEC (persona=off)"));
    fake::FWCFG.with_borrow_mut(|m| m.clear());
    personality::OFF_BY_BOOT_OPTION.store(true, std::sync::atomic::Ordering::Release);
    personality::init();
    assert_eq!(personality::choose(&elf(9), "/bsd/ls"), Err(-8));
    personality::OFF_BY_BOOT_OPTION.store(false, std::sync::atomic::Ordering::Release);
    personality::init();
    assert_eq!(personality::choose(&elf(9), "/bsd/ls"), Ok(TaskPersonality::FreeBsd));
    let _ = fake::klog_take();
    assert_eq!(personality::choose(&[0xCF, 0xFA, 0xED, 0xFE, 7, 0, 0, 1], "/mac/ls"), Err(-8));
    assert!(fake::klog_take().contains("Mach-O"));
    assert_eq!(personality::choose(&elf(6), "/sol/ls"), Err(-8));
    assert!(fake::klog_take().contains("another system (OS/ABI 6)"));
    // Switched on through fw_cfg
    fake::FWCFG.with_borrow_mut(|m| m.insert("opt/hydra/persona".into(), b"fbsd-stub\n".to_vec()));
    personality::init();
    assert!(personality::freebsd_stub());
    assert!(fake::klog_take().contains("stub table"));
    assert_eq!(personality::choose(&elf(9), "/bsd/ls"), Ok(TaskPersonality::FreeBsd));
    // ... or by the boot option
    fake::FWCFG.with_borrow_mut(|m| m.clear());
    personality::STUB_BY_BOOT_OPTION.store(true, std::sync::atomic::Ordering::Release);
    personality::init();
    assert!(personality::freebsd_stub());
    personality::STUB_BY_BOOT_OPTION.store(false, std::sync::atomic::Ordering::Release);
    personality::init();
    assert!(!personality::freebsd_stub());
}

#[test]
fn the_interpreter_must_match() {
    let _g = serial();
    assert!(personality::interp_agrees(TaskPersonality::Linux, &elf(0), "/lib64/ld-linux-x86-64.so.2"));
    assert!(personality::interp_agrees(TaskPersonality::FreeBsd, &elf(9), "/libexec/ld-elf.so.1"));
    assert!(!personality::interp_agrees(TaskPersonality::FreeBsd, &elf(0), "/lib64/ld-linux-x86-64.so.2"));
    assert!(fake::klog_take().contains("interpreter /lib64/ld-linux-x86-64.so.2 is not a FreeBSD program"));
    assert!(!personality::interp_agrees(TaskPersonality::Linux, &elf(9), "/libexec/ld-elf.so.1"));
}

#[test]
fn entries_tables_and_the_current_table() {
    let _g = serial();
    assert_eq!(linux_as(231), R_LINUX_AS | 231 << 16);
    assert_eq!(local(5, F_RET2), R_KERNEL | F_RET2 | 5 << 16);
    let r = Ret::of(-2);
    assert_eq!((r.r, r.r2), (-2, None));
    let t = &freebsd::TABLE;
    assert_eq!(t.pers, TaskPersonality::FreeBsd);
    assert_eq!(t.entry(4), linux_as(1));
    assert_eq!(t.entry(TABLE_LEN as u64), R_NOSYS);
    assert_eq!(t.entry(u64::MAX), R_NOSYS);
    assert!(personality::table_for(TaskPersonality::Linux).is_null());
    assert!(personality::table_for(TaskPersonality::Hydra).is_null());
    assert_eq!(personality::table_for(TaskPersonality::FreeBsd) as *const Table, t as *const Table);
    personality::set_current(TaskPersonality::FreeBsd);
    assert!(personality::frame_builder().is_some());
    personality::set_current(TaskPersonality::Linux);
    assert!(personality::frame_builder().is_none());
    assert_eq!(freebsd::OSRELDATE, abi::FREEBSD_OSRELDATE);
}

// ------------------------------------------------------------ the call path

fn call(t: &'static Table, f: &mut SyscallFrame) {
    let mut fpu = FpuState::new();
    personality::syscall(f, &mut fpu, t);
}

#[test]
fn bridged_calls_return_in_the_bsd_convention() {
    let _g = serial();
    // write(1, buf, 5) -> Linux write, 5 bytes
    LINUX_RESULTS.with_borrow_mut(|m| m.insert(1, 5));
    let mut f = frame(4, [1, 0x1000, 5, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(LINUX_CALLS.with_borrow(|v| v.last().copied()), Some((1, [1, 0x1000, 5, 0, 0, 0])));
    assert_eq!((f.rax, f.rflags & 1), (5, 0));
    assert_eq!((f.rdi, f.rsi, f.rdx), (1, 0x1000, 5), "the arguments come back");
    assert_eq!(fake::BKL.get(), 0, "the kernel lock is let go");
    assert_eq!(CURRENT_SYSCALL.load(std::sync::atomic::Ordering::Relaxed), u64::MAX);
    assert_eq!(DELIVERED.with_borrow(|v| v.last().copied()), Some(1), "delivery sees the Linux number");
    // An error: positive FreeBSD errno and the carry flag
    LINUX_RESULTS.with_borrow_mut(|m| m.insert(0, -11)); // EAGAIN
    let mut f = frame(3, [0, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (35, 1));
    // getpid: a second result in rdx (the parent)
    LINUX_RESULTS.with_borrow_mut(|m| {
        m.insert(39, 77);
        m.insert(110, 66);
    });
    let mut f = frame(20, [0; 6]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rdx, f.rflags & 1), (77, 66, 0));
}

#[test]
fn indirect_and_unknown_calls() {
    let _g = serial();
    LINUX_RESULTS.with_borrow_mut(|m| m.insert(102, 1000));
    // syscall(24 = getuid): the number in rdi, the arguments move down
    let mut f = frame(0, [24, 9, 8, 7, 6, 5]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 1000);
    assert_eq!(LINUX_CALLS.with_borrow(|v| v.last().copied()), Some((102, [9, 8, 7, 6, 5, 0])));
    assert_eq!((f.rdi, f.rsi), (24, 9), "the program's registers come back");
    // __syscall(0, ...): an indirect call of an indirect call is unknown
    fake::PROCS.lock().entry(1).or_default();
    let mut f = frame(198, [0, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (78, 1), "ENOSYS");
    // A live FreeBSD call not implemented yet (statfs 555): ENOSYS, a log line, no signal
    fake::POSTED.with_borrow_mut(|v| v.clear());
    let _ = fake::klog_take();
    let mut f = frame(555, [0; 6]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (78, 1));
    assert_eq!(fake::POSTED.with_borrow(|v| v.len()), 0);
    assert!(fake::klog_take().contains("statfs (555) not implemented yet"));
    // A number FreeBSD does not have: ENOSYS and SIGSYS
    let mut f = frame(999, [0; 6]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (78, 1));
    assert_eq!(fake::POSTED.with_borrow(|v| v.last().map(|p| p.1)), Some(31));
    let mut f = frame(5000, [0; 6]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 78);
}

static CUSTOM: Table = Table {
    entries: custom_entries(),
    pers: TaskPersonality::MacOs,
    local: custom_local,
    errno: &abi::MACOS_ERRNO,
    nosys_signal: 0,
    frame: freebsd::build_frame,
};

const fn custom_entries() -> [u32; TABLE_LEN] {
    let mut e = [R_NOSYS; TABLE_LEN];
    e[1] = R_ENOSYS;
    e[2] = R_SERVER;
    e[3] = R_MACH;
    e[4] = linux_as(105); // setuid: changes identity
    e[5] = linux_as(59); // execve
    e[6] = local(7, 0);
    e[7] = linux_as(7); // poll: restartable
    e
}

fn custom_local(id: u16, f: &mut SyscallFrame, a: [u64; 6]) -> Ret {
    f.r15 = id as u64;
    Ret { r: a[0] as i64, r2: Some(a[1]) }
}

#[test]
fn routes_identity_changes_and_exec() {
    let _g = serial();
    for nr in [1, 2, 3] {
        let mut f = frame(nr, [0; 6]);
        call(&CUSTOM, &mut f);
        assert_eq!((f.rax, f.rflags & 1), (78, 1), "route {nr}: ENOSYS");
    }
    // No signal for an unknown number in this table
    fake::POSTED.with_borrow_mut(|v| v.clear());
    let mut f = frame(9, [0; 6]);
    call(&CUSTOM, &mut f);
    assert!(fake::POSTED.with_borrow(|v| v.is_empty()));
    // A kernel-local handler with a second result
    let mut f = frame(6, [42, 43, 0, 0, 0, 0]);
    call(&CUSTOM, &mut f);
    assert_eq!((f.rax, f.rdx, f.r15), (42, 43, 7));
    // setuid changes identity: the fast path's caches are told
    let before = IDENT_CHANGES.get();
    let mut f = frame(4, [1000, 0, 0, 0, 0, 0]);
    call(&CUSTOM, &mut f);
    assert_eq!(IDENT_CHANGES.get(), before + 1);
    // A successful execve: the new program's registers stay as they are
    DELIVERED.with_borrow_mut(|v| v.clear());
    DELIVER_HOOK.with_borrow_mut(|h| *h = None);
    let mut f = frame(5, [0x1111, 0x2222, 0x3333, 0, 0, 0]);
    f.rdi = 0x1111;
    call(&CUSTOM, &mut f);
    assert_eq!(DELIVERED.with_borrow(|v| v.clone()), vec![59]);
    assert_eq!(f.rax, 59, "the frame is the new program's (the stub execve left it)");
}

#[test]
fn restarts_around_signal_delivery() {
    let _g = serial();
    // poll returns ERESTARTSYS; a handler that restarts moves rip back by two
    LINUX_RESULTS.with_borrow_mut(|m| m.insert(7, -512));
    DELIVER_HOOK.with_borrow_mut(|h| {
        *h = Some(Box::new(|f: &mut SyscallFrame| {
            assert_eq!(f.rax as i64, -512, "the restart code is internal until delivery decided");
            f.rip -= 2;
        }))
    });
    let mut f = frame(7, [0xA, 0xB, 0xC, 0xD, 0xE, 0xF]);
    call(&CUSTOM, &mut f);
    assert_eq!((f.rax, f.rdi, f.rsi, f.rdx, f.r10, f.r8, f.r9), (7, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF), "the program's own number and arguments");
    // No handler: EINTR in the BSD convention
    DELIVER_HOOK.with_borrow_mut(|h| *h = None);
    let mut f = frame(7, [0; 6]);
    call(&CUSTOM, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (4, 1));
    // A handler's frame was built (rip moved elsewhere): left alone
    DELIVER_HOOK.with_borrow_mut(|h| *h = Some(Box::new(|f: &mut SyscallFrame| f.rip = 0x7000)));
    let mut f = frame(7, [0; 6]);
    call(&CUSTOM, &mut f);
    assert_eq!(f.rax as i64, -512);
    assert_eq!(fake::PERS_CALL.get(), None, "the call record is gone after delivery");
}

#[test]
fn saved_context_in_the_personality_convention() {
    let _g = serial();
    let rip = 0x40_2000;
    // No call in progress: unchanged
    let mut r = UserRegs { rip, rax: (-2i64) as u64, ..Default::default() };
    personality::fix_saved_context(&freebsd::TABLE, &mut r);
    assert_eq!(r.rax as i64, -2);
    // Interrupted while returning an error: errno and carry (also in r11)
    fake::PERS_CALL.set(Some([4, 1, 2, 3, 4, 5, 6, rip]));
    let mut r = UserRegs { rip, rax: (-2i64) as u64, rflags: 0x202, ..Default::default() };
    personality::fix_saved_context(&freebsd::TABLE, &mut r);
    assert_eq!((r.rax, r.rflags & 1, r.r11 & 1), (2, 1, 1));
    // A success is left alone
    let mut r = UserRegs { rip, rax: 5, ..Default::default() };
    personality::fix_saved_context(&freebsd::TABLE, &mut r);
    assert_eq!(r.rax, 5);
    // To be restarted: the personality's number and arguments
    let mut r = UserRegs { rip: rip - 2, rax: 0, ..Default::default() };
    personality::fix_saved_context(&freebsd::TABLE, &mut r);
    assert_eq!([r.rax, r.rdi, r.rsi, r.rdx, r.r10, r.r8, r.r9], [4, 1, 2, 3, 4, 5, 6]);
    // linux_call
    LINUX_RESULTS.with_borrow_mut(|m| m.insert(62, -3));
    assert_eq!(personality::linux_call(62, [9, 15, 0, 0, 0, 0]), -3);
    assert_eq!(LINUX_CALLS.with_borrow(|v| v.last().copied()), Some((62, [9, 15, 0, 0, 0, 0])));
}

// ----------------------------------------------------------------- FreeBSD

#[test]
fn kill_and_thr_self() {
    let _g = serial();
    // kill(pid, 0): Linux kill with signal 0
    let mut f = frame(37, [44, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(LINUX_CALLS.with_borrow(|v| v.last().copied()), Some((62, [44, 0, 0, 0, 0, 0])));
    // A FreeBSD signal number is translated (SIGUSR1 = 30 -> 10)
    let mut f = frame(37, [44, 30, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(LINUX_CALLS.with_borrow(|v| v.last().copied()), Some((62, [44, 10, 0, 0, 0, 0])));
    // An invalid one
    let mut f = frame(37, [44, 200, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (22, 1));
    // thr_self(&id)
    fake::IDS.set((321, 300));
    let mut id = 0u64;
    let mut f = frame(432, [&mut id as *mut u64 as u64, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, id), (0, 321));
    let mut f = frame(432, [0, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!((f.rax, f.rflags & 1), (14, 1), "EFAULT");
}

fn bsd_sigaction(handler: u64, flags: u32, mask_bits: &[u32]) -> [u8; 32] {
    let mut b = [0u8; 32];
    b[0..8].copy_from_slice(&handler.to_le_bytes());
    b[8..12].copy_from_slice(&flags.to_le_bytes());
    for &n in mask_bits {
        let i = (n - 1) as usize;
        b[12 + i / 8] |= 1 << (i % 8);
    }
    b
}

#[test]
fn sigaction_translates_flags_and_masks() {
    let _g = serial();
    // SIGUSR1 (FreeBSD 30), SA_SIGINFO | SA_RESTART | SA_ONSTACK, mask {SIGUSR2 (31), SIGINT (2)}
    let act = bsd_sigaction(0x40_5000, 0x40 | 0x02 | 0x01, &[31, 2]);
    let mut f = frame(416, [30, act.as_ptr() as u64, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 0);
    let a = ACTIONS.with_borrow(|m| m[&10]);
    assert_eq!(a.handler, 0x40_5000);
    assert_eq!(a.flags, 0x4 | 0x1000_0000 | 0x0800_0000);
    assert_eq!(a.mask, (1 << (12 - 1)) | (1 << (2 - 1)), "SIGUSR2 is Linux 12");
    // Read it back in FreeBSD's form
    let mut old = [0u8; 32];
    let mut f = frame(416, [30, 0, old.as_mut_ptr() as u64, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 0);
    assert_eq!(old, act);
    // Refused: unknown signal, SIGKILL/SIGSTOP with a new action, unreadable pointers
    for (sig, ptr) in [(200u64, act.as_ptr() as u64), (9, act.as_ptr() as u64), (17, act.as_ptr() as u64)] {
        let mut f = frame(416, [sig, ptr, 0, 0, 0, 0]);
        call(&freebsd::TABLE, &mut f);
        assert_eq!((f.rax, f.rflags & 1), (22, 1), "signal {sig}");
    }
    // SIGKILL may be read
    let mut f = frame(416, [9, 0, old.as_mut_ptr() as u64, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 0);
}

/// A FreeBSD `ucontext_t` for `sigreturn`.
fn ucontext(rip: u64, rsp: u64, mc_len: u64, fpu_owned: bool, mask: &[u32]) -> Vec<u8> {
    let mut uc = vec![0u8; 880];
    for &n in mask {
        let i = (n - 1) as usize;
        uc[i / 8] |= 1 << (i % 8);
    }
    let mc = 16;
    let put = |uc: &mut Vec<u8>, off: usize, v: u64| uc[off..off + 8].copy_from_slice(&v.to_le_bytes());
    for i in 0..15 {
        put(&mut uc, mc + 8 + i * 8, 0x100 + i as u64);
    }
    put(&mut uc, mc + 160, rip);
    put(&mut uc, mc + 176, 0xFFFF_FFFF);
    put(&mut uc, mc + 184, rsp);
    put(&mut uc, mc + 200, mc_len);
    if fpu_owned {
        put(&mut uc, mc + 216, 0x20001);
        // MXCSR with reserved bits set
        uc[mc + 224 + 24..mc + 224 + 28].copy_from_slice(&0xFFFF_1F80u32.to_le_bytes());
    }
    uc
}

fn sigreturn(uc: &[u8]) -> Result<SyscallFrame, Returned> {
    let mut f = frame(417, [uc.as_ptr() as u64, 0, 0, 0, 0, 0]);
    let r = catch_unwind(AssertUnwindSafe(|| call(&freebsd::TABLE, &mut f)));
    // The stub's return_to_user unwinds out of the kernel lock: balance it
    fake::BKL.set(0);
    match r {
        Ok(()) => Ok(f),
        Err(p) => Err(p.downcast::<Returned>().map(|b| *b).expect("return_to_user")),
    }
}

#[test]
fn sigreturn_restores_a_checked_context() {
    let _g = serial();
    let ok = ucontext(0x40_1234, 0x7FFF_0000, 800, true, &[2, 31]);
    let r = sigreturn(&ok).unwrap_err();
    assert_eq!(r.regs.rip, 0x40_1234);
    assert_eq!(r.regs.rsp, 0x7FFF_0000);
    assert_eq!((r.regs.rdi, r.regs.r15), (0x100, 0x10E));
    assert_eq!(r.regs.rflags, (0xFFFF_FFFF & 0x0025_4DD5) | 0x202, "only the user flags, IF set");
    assert_eq!(r.mxcsr, 0x1F80, "MXCSR's reserved bits cleared");
    assert!(r.fpu_written);
    assert_eq!(r.cs, 0x2b);
    assert_eq!(MASK.get(), (1 << 1) | (1 << 11), "the mask comes back (SIGUSR2 = 12)");
    // Without an FPU state the default one is loaded
    let r = sigreturn(&ucontext(0x40_1234, 0x7FFF_0000, 800, false, &[])).unwrap_err();
    assert_eq!((r.mxcsr, r.fpu_written), (0x1F80, false));
    // Refused contexts return EINVAL / EFAULT
    let f = sigreturn(&ucontext(0x40_1234, 0x7FFF_0000, 700, false, &[])).unwrap();
    assert_eq!((f.rax, f.rflags & 1), (22, 1), "wrong mc_len");
    let f = sigreturn(&ucontext(0xFFFF_8000_0000_0000, 0x7FFF_0000, 800, false, &[])).unwrap();
    assert_eq!(f.rax, 22, "rip in the kernel");
    let f = sigreturn(&ucontext(0x40_0000, 0xFFFF_8000_0000_0000, 800, false, &[])).unwrap();
    assert_eq!(f.rax, 22, "rsp in the kernel");
    let mut f = frame(417, [0, 0, 0, 0, 0, 0]);
    call(&freebsd::TABLE, &mut f);
    assert_eq!(f.rax, 14, "EFAULT");
}

#[test]
fn signal_frames_follow_freebsds_layout() {
    let _g = serial();
    let mut stack = vec![0u8; 8192];
    let top = stack.as_mut_ptr() as u64 + 8192;
    let mut regs = UserRegs { rsp: top, rip: 0x40_1000, rdi: 1, rax: 2, rflags: 0x302 | 0x400, ..Default::default() };
    let mut fpu = FpuState::new();
    fpu.0[0] = 0x7F;
    fake::FS_BASE.set(0xABC0);
    let act = SigAction { handler: 0x40_9000, flags: 0x4, restorer: 0, mask: 0 };
    assert!(freebsd::build_frame(&mut regs, &fpu, 10, &act, 1 << 1, 0x2b));
    let sfp = regs.rsp;
    assert_eq!(sfp % 16, 0);
    assert!(sfp <= top - 128 - 976);
    assert_eq!(regs.rip, freebsd::SIGCODE_ADDR);
    assert_eq!(regs.rdi, 30, "SIGUSR1 in FreeBSD's numbering");
    assert_eq!(regs.rsi, sfp + 896, "SA_SIGINFO: &sf_si");
    assert_eq!(regs.rdx, sfp + 16);
    assert_eq!(regs.rflags & 0x500, 0, "TF and DF cleared");
    let off = (sfp - stack.as_ptr() as u64) as usize;
    let f = &stack[off..off + 976];
    let get = |o: usize| u64::from_le_bytes(f[o..o + 8].try_into().unwrap());
    assert_eq!(get(0), 0x40_9000, "sf_ahu: the handler");
    assert_eq!(f[16], 0b10, "the old mask (SIGINT)");
    assert_eq!(get(32 + 8), 1, "mc_rdi");
    assert_eq!(get(32 + 160), 0x40_1000, "mc_rip");
    assert_eq!(get(32 + 168), 0x2b);
    assert_eq!(get(32 + 200), 800, "mc_len");
    assert_eq!(f[32 + 224], 0x7F, "the FPU state");
    assert_eq!(get(32 + 736), 0xABC0, "fs base");
    assert_eq!(u32::from_le_bytes(f[16 + 840..16 + 844].try_into().unwrap()), 4, "no alternate stack: SS_DISABLE");
    assert_eq!(i32::from_le_bytes(f[896..900].try_into().unwrap()), 30);
    assert_eq!(i32::from_le_bytes(f[904..908].try_into().unwrap()), 0x10001, "SI_USER");
    // Without SA_SIGINFO the code goes in rsi; SA_ONSTACK moves to the alternate stack
    let mut alt = vec![0u8; 8192];
    let alt_sp = alt.as_mut_ptr() as u64;
    ALT.set((alt_sp, 8192, true));
    let mut regs = UserRegs { rsp: top, rip: 0x40_1000, ..Default::default() };
    let act = SigAction { handler: 1, flags: 0x0800_0000, restorer: 0, mask: 0 };
    assert!(freebsd::build_frame(&mut regs, &fpu, 2, &act, 0, 0x2b));
    assert_eq!(regs.rsi, 0x10001);
    assert!(regs.rsp >= alt_sp && regs.rsp < alt_sp + 8192, "on the alternate stack");
    // Already on the alternate stack: below the current rsp, ss_flags SS_ONSTACK
    let mut regs = UserRegs { rsp: alt_sp + 4096, rip: 0x40_1000, ..Default::default() };
    assert!(freebsd::build_frame(&mut regs, &fpu, 2, &act, 0, 0x2b));
    let off = (regs.rsp - alt_sp) as usize;
    assert_eq!(u32::from_le_bytes(alt[off + 16 + 840..off + 16 + 844].try_into().unwrap()), 1);
}
