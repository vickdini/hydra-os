//! Tests for seccomp (`src/compat/linux/seccomp.rs`): the classic-BPF
//! validator and interpreter, filter installation rules, verdict precedence
//! across stacked filters, every return action, strict mode, TSYNC and the
//! prctl interface. Chromium, Firefox, Flatpak/bubblewrap, systemd and
//! Docker all rely on these semantics for their sandboxes.
//!
//! Programs are installed with `sys_seccomp` from host memory (a
//! `struct sock_fprog`), then system calls are judged with `seccomp::check`
//! on a register frame. A "kill" verdict calls `die_by_signal`, which the
//! fake reports as a panic: "killed by signal N".

use std::panic::{catch_unwind, AssertUnwindSafe};

use hydra_hosttests::arch::syscall::SyscallFrame;
use hydra_hosttests::compat::linux::seccomp::{check, prctl, status_of, sys_seccomp, Verdict, AUDIT_ARCH_X86_64};
use hydra_hosttests::fake;

const SET_MODE_STRICT: u64 = 0;
const SET_MODE_FILTER: u64 = 1;
const GET_ACTION_AVAIL: u64 = 2;
const GET_NOTIF_SIZES: u64 = 3;
const FLAG_TSYNC: u64 = 1;
const FLAG_LOG: u64 = 2;
const FLAG_NEW_LISTENER: u64 = 8;

const KILL_PROCESS: u32 = 0x8000_0000;
const KILL_THREAD: u32 = 0;
const TRAP: u32 = 0x0003_0000;
const ERRNO: u32 = 0x0005_0000;
const USER_NOTIF: u32 = 0x7FC0_0000;
const TRACE: u32 = 0x7FF0_0000;
const LOG: u32 = 0x7FFC_0000;
const ALLOW: u32 = 0x7FFF_0000;

const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;
const ENOSYS: i64 = -38;
const EOPNOTSUPP: i64 = -95;

const CAP_SYS_ADMIN: u64 = 1 << 21;

// Syscall numbers used in filters.
const READ: u64 = 0;
const WRITE: u64 = 1;
const OPEN: u64 = 2;
const RT_SIGRETURN: u64 = 15;
const GETPID: u64 = 39;
const EXIT: u64 = 60;
const EXIT_GROUP: u64 = 231;

// ------------------------------------------------------- BPF assembler

#[derive(Clone, Copy)]
struct Insn(u16, u8, u8, u32);

fn stmt(code: u16, k: u32) -> Insn {
    Insn(code, 0, 0, k)
}
fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Insn {
    Insn(code, jt, jf, k)
}

const LD_W_ABS: u16 = 0x20;
const LD_IMM: u16 = 0x00;
const LD_MEM: u16 = 0x60;
const LD_LEN: u16 = 0x80;
const LDX_IMM: u16 = 0x01;
const LDX_MEM: u16 = 0x61;
const ST: u16 = 0x02;
const STX: u16 = 0x03;
const ALU_K: u16 = 0x04; // | op
const ALU_X: u16 = 0x0c; // | op
const JA: u16 = 0x05;
const JEQ_K: u16 = 0x15;
const JGT_K: u16 = 0x25;
const JGE_K: u16 = 0x35;
const JSET_K: u16 = 0x45;
const JEQ_X: u16 = 0x1d;
const RET_K: u16 = 0x06;
const RET_A: u16 = 0x16;
const TAX: u16 = 0x07;
const TXA: u16 = 0x87;

const ADD: u16 = 0x00;
const SUB: u16 = 0x10;
const MUL: u16 = 0x20;
const DIV: u16 = 0x30;
const OR: u16 = 0x40;
const AND: u16 = 0x50;
const LSH: u16 = 0x60;
const RSH: u16 = 0x70;
const NEG: u16 = 0x80;
const MOD: u16 = 0x90;
const XOR: u16 = 0xa0;

// struct seccomp_data word offsets
const NR: u32 = 0;
const ARCH: u32 = 4;
const IP_LO: u32 = 8;
const IP_HI: u32 = 12;
const fn arg_lo(i: u32) -> u32 {
    16 + i * 8
}
const fn arg_hi(i: u32) -> u32 {
    20 + i * 8
}

fn encode(prog: &[Insn]) -> Vec<u8> {
    prog.iter().flat_map(|i| [&i.0.to_le_bytes()[..], &[i.1, i.2], &i.3.to_le_bytes()].concat()).collect()
}

/// sys_seccomp(SECCOMP_SET_MODE_FILTER) with a `struct sock_fprog` in host memory.
fn install_with(flags: u64, prog: &[Insn]) -> i64 {
    let code = encode(prog);
    let fprog: [u64; 2] = [prog.len() as u64, code.as_ptr() as u64];
    sys_seccomp(SET_MODE_FILTER, flags, fprog.as_ptr() as u64)
}

fn install(prog: &[Insn]) -> i64 {
    install_with(0, prog)
}

/// "Return `action` for syscall `nr`, allow everything else."
fn block(nr: u64, action: u32) -> Vec<Insn> {
    vec![stmt(LD_W_ABS, NR), jump(JEQ_K, nr as u32, 0, 1), stmt(RET_K, action), stmt(RET_K, ALLOW)]
}

/// Runs `prog` (which leaves its result in A) and returns A via RET_A.
fn compute(prog: &[Insn]) -> u32 {
    let mut p = prog.to_vec();
    p.push(stmt(RET_A, 0));
    // The result is turned into an ERRNO action we can observe: ERRNO | (A & 0xfff).
    fresh();
    let mut wrapped = p.clone();
    wrapped.pop();
    wrapped.extend([stmt(ALU_K | AND, 0xfff), stmt(ALU_K | OR, ERRNO), stmt(RET_A, 0)]);
    assert_eq!(install(&wrapped), 0, "program rejected");
    match check(&mut frame(GETPID)) {
        Verdict::Return(r) => (-r) as u32,
        Verdict::Allow => panic!("ERRNO expected"),
    }
}

fn frame(nr: u64) -> SyscallFrame {
    SyscallFrame { rax: nr, rip: 0x0000_5555_1234_5678, ..Default::default() }
}

/// Fresh task allowed to install filters (no_new_privs set).
fn fresh() {
    fake::reset();
    assert_eq!(prctl(38, 1, 0), Some(0), "PR_SET_NO_NEW_PRIVS");
}

fn verdict(nr: u64) -> Result<Option<i64>, String> {
    verdict_frame(frame(nr))
}

/// Ok(None) = allowed, Ok(Some(r)) = call returns r, Err(msg) = task killed.
fn verdict_frame(mut f: SyscallFrame) -> Result<Option<i64>, String> {
    match catch_unwind(AssertUnwindSafe(|| check(&mut f))) {
        Ok(Verdict::Allow) => Ok(None),
        Ok(Verdict::Return(r)) => Ok(Some(r)),
        Err(e) => Err(e.downcast_ref::<String>().cloned().unwrap_or_default()),
    }
}

fn killed(sig: u32) -> Result<Option<i64>, String> {
    Err(format!("killed by signal {sig}"))
}

// ------------------------------------------------------------ validator

#[test]
fn valid_programs_are_accepted() {
    fresh();
    assert_eq!(install(&block(GETPID, ERRNO | 1)), 0);
    assert_eq!(status_of(fake::IDS.get().1), (true, 2), "no_new_privs, filter mode");
}

#[test]
fn validator_rejects_unsafe_programs() {
    let bad: Vec<(&str, Vec<Insn>)> = vec![
        ("empty", vec![]),
        ("no final return", vec![stmt(LD_W_ABS, NR)]),
        ("unaligned load", vec![stmt(LD_W_ABS, 1), stmt(RET_K, ALLOW)]),
        ("load past seccomp_data", vec![stmt(LD_W_ABS, 64), stmt(RET_K, ALLOW)]),
        ("byte-sized load", vec![stmt(0x30, 0), stmt(RET_K, ALLOW)]),
        ("half-word load", vec![stmt(0x28, 0), stmt(RET_K, ALLOW)]),
        ("indirect load", vec![stmt(0x40, 0), stmt(RET_K, ALLOW)]),
        ("LDX absolute", vec![stmt(0x21, 0), stmt(RET_K, ALLOW)]),
        ("LDX MSH (packet only)", vec![stmt(0xb1, 0), stmt(RET_K, ALLOW)]),
        ("scratch store out of range", vec![stmt(ST, 16), stmt(RET_K, ALLOW)]),
        ("scratch load out of range", vec![stmt(LD_MEM, 16), stmt(RET_K, ALLOW)]),
        ("division by constant zero", vec![stmt(ALU_K | DIV, 0), stmt(RET_K, ALLOW)]),
        ("modulo by constant zero", vec![stmt(ALU_K | MOD, 0), stmt(RET_K, ALLOW)]),
        ("unknown ALU op", vec![stmt(ALU_K | 0xb0, 1), stmt(RET_K, ALLOW)]),
        ("JA past the end", vec![stmt(JA, 1), stmt(RET_K, ALLOW)]),
        ("JEQ true branch past the end", vec![jump(JEQ_K, 0, 1, 0), stmt(RET_K, ALLOW)]),
        ("JEQ false branch past the end", vec![jump(JEQ_K, 0, 0, 1), stmt(RET_K, ALLOW)]),
        ("unknown jump", vec![jump(0x55, 0, 0, 0), stmt(RET_K, ALLOW)]),
        ("RET X", vec![stmt(0x0e, 0)]),
        ("unknown misc op", vec![stmt(0x0f, 0), stmt(RET_K, ALLOW)]),
        ("too long", vec![stmt(RET_K, ALLOW); 4097]),
    ];
    for (what, prog) in bad {
        fresh();
        let code = encode(&prog);
        let fprog: [u64; 2] = [prog.len() as u64 & 0xffff, code.as_ptr() as u64];
        assert_eq!(sys_seccomp(SET_MODE_FILTER, 0, fprog.as_ptr() as u64), EINVAL, "{what}");
        assert_eq!(status_of(fake::IDS.get().1).1, 0, "{what}: nothing installed");
    }
}

#[test]
fn the_longest_allowed_program() {
    fresh();
    assert_eq!(install(&vec![stmt(RET_K, ALLOW); 4096]), 0);
}

#[test]
fn bad_pointers() {
    fresh();
    assert_eq!(sys_seccomp(SET_MODE_FILTER, 0, 0), EFAULT);
    let fprog: [u64; 2] = [1, 0];
    assert_eq!(sys_seccomp(SET_MODE_FILTER, 0, fprog.as_ptr() as u64), EFAULT, "null filter array");
}

// ------------------------------------------------------- installation

#[test]
fn installing_needs_no_new_privs_or_cap_sys_admin() {
    fake::reset();
    assert_eq!(install(&block(GETPID, ERRNO | 1)), EACCES);
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(install(&block(GETPID, ERRNO | 1)), 0);
}

#[test]
fn flags() {
    fresh();
    assert_eq!(install_with(FLAG_NEW_LISTENER, &block(GETPID, ERRNO)), EOPNOTSUPP, "no user notification listeners");
    assert_eq!(install_with(0x40, &block(GETPID, ERRNO)), EINVAL);
    assert_eq!(install_with(FLAG_LOG, &block(GETPID, ERRNO | 3)), 0);
    assert_eq!(verdict(GETPID), Ok(Some(-3)));
}

#[test]
fn stacked_filters_are_limited_in_total_length() {
    fresh();
    let big = vec![stmt(RET_K, ALLOW); 4096];
    for i in 0..8 {
        assert_eq!(install(&big), 0, "filter {i}");
    }
    assert_eq!(install(&big), ENOMEM, "32768 instructions per syscall path");
    assert_eq!(verdict(GETPID), Ok(None));
}

// ---------------------------------------------------------- data layout

#[test]
fn filters_see_nr_arch_ip_and_args() {
    fresh();
    let prog = vec![
        stmt(LD_W_ABS, ARCH),
        jump(JEQ_K, AUDIT_ARCH_X86_64, 1, 0),
        stmt(RET_K, KILL_PROCESS),
        stmt(LD_W_ABS, NR),
        jump(JEQ_K, 77, 0, 6),
        stmt(LD_W_ABS, arg_lo(0)),
        jump(JEQ_K, 42, 0, 4),
        stmt(LD_W_ABS, arg_hi(0)),
        jump(JEQ_K, 1, 0, 2),
        stmt(LD_W_ABS, arg_lo(5)),
        jump(JEQ_K, 0xabc, 1, 0),
        stmt(RET_K, ALLOW),
        stmt(RET_K, ERRNO | 7),
    ];
    assert_eq!(install(&prog), 0);
    let mut f = frame(77);
    f.rdi = 0x1_0000_002a; // args[0] = 2^32 + 42
    f.r9 = 0xabc; // args[5]
    assert_eq!(verdict_frame(f.clone()), Ok(Some(-7)), "64-bit argument split into two words");
    f.rdi = 42;
    assert_eq!(verdict_frame(f.clone()), Ok(None), "high word differs");
    assert_eq!(verdict(78), Ok(None));

    fresh();
    let ip = vec![
        stmt(LD_W_ABS, IP_HI),
        jump(JEQ_K, 0x5555, 0, 2),
        stmt(LD_W_ABS, IP_LO),
        jump(JEQ_K, 0x1234_5678, 1, 0),
        stmt(RET_K, ALLOW),
        stmt(RET_K, ERRNO | 9),
    ];
    assert_eq!(install(&ip), 0);
    assert_eq!(verdict(1), Ok(Some(-9)), "instruction pointer words");
}

#[test]
fn every_argument_register_maps_to_its_slot() {
    for (i, reg) in ["rdi", "rsi", "rdx", "r10", "r8", "r9"].iter().enumerate() {
        fresh();
        let prog = vec![stmt(LD_W_ABS, arg_lo(i as u32)), jump(JEQ_K, 0x51, 0, 1), stmt(RET_K, ERRNO | 1), stmt(RET_K, ALLOW)];
        assert_eq!(install(&prog), 0);
        let mut f = frame(1);
        match *reg {
            "rdi" => f.rdi = 0x51,
            "rsi" => f.rsi = 0x51,
            "rdx" => f.rdx = 0x51,
            "r10" => f.r10 = 0x51,
            "r8" => f.r8 = 0x51,
            _ => f.r9 = 0x51,
        }
        assert_eq!(verdict_frame(f), Ok(Some(-1)), "args[{i}] is {reg}");
    }
}

// ------------------------------------------------------------- actions

#[test]
fn errno_action() {
    fresh();
    install(&block(GETPID, ERRNO | 13));
    assert_eq!(verdict(GETPID), Ok(Some(-13)));
    assert_eq!(verdict(WRITE), Ok(None));
    fresh();
    install(&block(GETPID, ERRNO | 0xffff));
    assert_eq!(verdict(GETPID), Ok(Some(-4095)), "capped at MAX_ERRNO");
}

#[test]
fn kill_actions() {
    fresh();
    install(&block(GETPID, KILL_PROCESS));
    assert_eq!(verdict(GETPID), killed(31), "SIGSYS");
    fresh();
    install(&block(GETPID, KILL_THREAD));
    assert_eq!(verdict(GETPID), killed(31));
    fresh();
    install(&block(GETPID, 0x0001_0000));
    assert_eq!(verdict(GETPID), killed(31), "unknown actions kill");
}

#[test]
fn trap_sends_sigsys() {
    fresh();
    install(&block(GETPID, TRAP | 0x42));
    assert_eq!(verdict(GETPID), Ok(Some(GETPID as i64)), "rax holds the call number for the handler");
    assert_eq!(fake::SIGSYS.with_borrow(|v| v.clone()), vec![(GETPID as i32, 0x0000_5555_1234_5678, 0x42)]);
}

#[test]
fn log_and_allow() {
    fresh();
    install(&block(GETPID, LOG));
    assert_eq!(verdict(GETPID), Ok(None));
}

#[test]
fn user_notif_and_trace_without_a_listener_fail_with_enosys() {
    fresh();
    install(&block(GETPID, USER_NOTIF));
    assert_eq!(verdict(GETPID), Ok(Some(ENOSYS)));
    fresh();
    install(&block(GETPID, TRACE | 5));
    assert_eq!(verdict(GETPID), Ok(Some(ENOSYS)), "RET_TRACE with no tracer");
}

#[test]
fn trace_lets_the_tracer_decide() {
    fresh();
    install(&block(GETPID, TRACE | 5));
    fake::TRACER.with_borrow_mut(|t| *t = Some(Box::new(|_f, data| {
        assert_eq!(data, 5, "SECCOMP_RET_DATA reaches the tracer");
        Ok(())
    })));
    assert_eq!(verdict(GETPID), Ok(None), "tracer allowed it; filters do not ask again");

    fake::TRACER.with_borrow_mut(|t| *t = Some(Box::new(|_f, _d| Err(-1))));
    assert_eq!(verdict(GETPID), Ok(Some(-1)), "tracer skipped the call with an error");
}

#[test]
fn a_tracer_changing_the_call_is_filtered_again() {
    fresh();
    let prog = vec![
        stmt(LD_W_ABS, NR),
        jump(JEQ_K, GETPID as u32, 0, 1),
        stmt(RET_K, TRACE),
        jump(JEQ_K, OPEN as u32, 0, 1),
        stmt(RET_K, ERRNO | 13),
        stmt(RET_K, ALLOW),
    ];
    install(&prog);
    fake::TRACER.with_borrow_mut(|t| *t = Some(Box::new(|f, _| {
        f.rax = OPEN; // rewrite getpid into open
        Ok(())
    })));
    assert_eq!(verdict(GETPID), Ok(Some(-13)), "the new call must pass the filters too");
}

// ------------------------------------------------------- stacked filters

#[test]
fn most_restrictive_action_wins() {
    fresh();
    install(&block(GETPID, ERRNO | 5));
    install(&block(GETPID, ALLOW));
    assert_eq!(verdict(GETPID), Ok(Some(-5)), "a newer ALLOW cannot undo an older ERRNO");

    fresh();
    install(&block(GETPID, ERRNO | 5));
    install(&block(GETPID, TRAP));
    assert_eq!(verdict(GETPID), Ok(Some(GETPID as i64)), "TRAP outranks ERRNO");

    fresh();
    install(&block(GETPID, KILL_THREAD));
    install(&block(GETPID, KILL_PROCESS));
    assert_eq!(verdict(GETPID), killed(31));

    fresh();
    install(&block(GETPID, TRACE));
    install(&block(GETPID, ERRNO | 2));
    assert_eq!(verdict(GETPID), Ok(Some(-2)), "ERRNO outranks TRACE");
}

#[test]
fn same_action_newest_filter_data_wins() {
    fresh();
    install(&block(GETPID, ERRNO | 5));
    install(&block(GETPID, ERRNO | 9));
    assert_eq!(verdict(GETPID), Ok(Some(-9)));
}

#[test]
fn filters_are_inherited_by_fork() {
    // `State` is cloned into the child; a cloned chain judges the same.
    fresh();
    install(&block(GETPID, ERRNO | 5));
    let state = fake::SECCOMP.with_borrow(|s| s.clone());
    fake::SECCOMP.set(Default::default());
    assert_eq!(verdict(GETPID), Ok(None), "a task without filters");
    fake::SECCOMP.set(state);
    assert_eq!(verdict(GETPID), Ok(Some(-5)));
}

// ------------------------------------------------------------ interpreter

#[test]
fn alu_operations() {
    let li = |v: u32| stmt(LD_IMM, v);
    assert_eq!(compute(&[li(40), stmt(ALU_K | ADD, 2)]), 42);
    assert_eq!(compute(&[li(50), stmt(ALU_K | SUB, 8)]), 42);
    assert_eq!(compute(&[li(6), stmt(ALU_K | MUL, 7)]), 42);
    assert_eq!(compute(&[li(85), stmt(ALU_K | DIV, 2)]), 42);
    assert_eq!(compute(&[li(142), stmt(ALU_K | MOD, 100)]), 42);
    assert_eq!(compute(&[li(0x28), stmt(ALU_K | OR, 0x2)]), 42);
    assert_eq!(compute(&[li(0xfaa), stmt(ALU_K | AND, 0x2a)]), 42);
    assert_eq!(compute(&[li(0x2b), stmt(ALU_K | XOR, 1)]), 42);
    assert_eq!(compute(&[li(21), stmt(ALU_K | LSH, 1)]), 42);
    assert_eq!(compute(&[li(84), stmt(ALU_K | RSH, 1)]), 42);
    assert_eq!(compute(&[li(1), stmt(ALU_K | LSH, 40)]), 0, "shift by >= 32 gives 0");
    assert_eq!(compute(&[li(0xffff_ffd6), stmt(ALU_K | NEG, 0)]), 42, "two's complement");
    assert_eq!(compute(&[li(u32::MAX), stmt(ALU_K | ADD, 43)]), 42, "wraps at 32 bits");
}

#[test]
fn x_register_scratch_memory_and_len() {
    assert_eq!(compute(&[stmt(LDX_IMM, 40), stmt(LD_IMM, 2), stmt(ALU_X | ADD, 0)]), 42);
    assert_eq!(compute(&[stmt(LD_IMM, 42), stmt(TAX, 0), stmt(LD_IMM, 0), stmt(TXA, 0)]), 42);
    assert_eq!(compute(&[stmt(LD_IMM, 42), stmt(ST, 15), stmt(LD_IMM, 0), stmt(LD_MEM, 15)]), 42);
    assert_eq!(compute(&[stmt(LDX_IMM, 42), stmt(STX, 3), stmt(LDX_MEM, 3), stmt(TXA, 0)]), 42);
    assert_eq!(compute(&[stmt(LD_MEM, 7)]), 0, "scratch memory starts zeroed");
    assert_eq!(compute(&[stmt(LD_LEN, 0)]), 64, "sizeof(struct seccomp_data)");
}

#[test]
fn division_by_zero_in_x_kills() {
    fresh();
    install(&[stmt(LDX_IMM, 0), stmt(LD_IMM, 5), stmt(ALU_X | DIV, 0), stmt(RET_K, ALLOW)]);
    assert_eq!(verdict(GETPID), killed(31), "returns KILL_THREAD");
}

#[test]
fn jumps() {
    let pick = |test: Insn| -> u32 {
        compute(&[stmt(LD_IMM, 10), test, stmt(LD_IMM, 1), stmt(JA, 1), stmt(LD_IMM, 2)])
    };
    // test jumps to "LD 2" when its condition is true (jt = 2), else falls through to "LD 1".
    assert_eq!(pick(jump(JEQ_K, 10, 2, 0)), 2);
    assert_eq!(pick(jump(JEQ_K, 11, 2, 0)), 1);
    assert_eq!(pick(jump(JGT_K, 9, 2, 0)), 2);
    assert_eq!(pick(jump(JGT_K, 10, 2, 0)), 1, "strict");
    assert_eq!(pick(jump(JGE_K, 10, 2, 0)), 2);
    assert_eq!(pick(jump(JSET_K, 0b0010, 2, 0)), 2, "10 = 0b1010");
    assert_eq!(pick(jump(JSET_K, 0b0101, 2, 0)), 1);
    assert_eq!(compute(&[stmt(LDX_IMM, 10), stmt(LD_IMM, 10), jump(JEQ_X, 0, 0, 1), stmt(LD_IMM, 42)]), 42, "compare with X");
}

// ------------------------------------------------------------ strict mode

#[test]
fn strict_mode() {
    fake::reset();
    assert_eq!(sys_seccomp(SET_MODE_STRICT, 1, 0), EINVAL, "no flags");
    assert_eq!(sys_seccomp(SET_MODE_STRICT, 0, 8), EINVAL, "no argument");
    assert_eq!(sys_seccomp(SET_MODE_STRICT, 0, 0), 0, "needs no privilege");
    for nr in [READ, WRITE, EXIT, RT_SIGRETURN] {
        assert_eq!(verdict(nr), Ok(None), "syscall {nr}");
    }
    assert_eq!(verdict(OPEN), killed(9), "everything else: SIGKILL");
    assert_eq!(verdict(EXIT_GROUP), killed(9), "including exit_group, as on Linux");
    assert_eq!(prctl(21, 0, 0), Some(1), "PR_GET_SECCOMP");
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(install(&block(GETPID, ERRNO)), EINVAL, "no filters on top of strict mode");
}

#[test]
fn no_strict_mode_after_filters() {
    fresh();
    install(&block(GETPID, ERRNO));
    assert_eq!(sys_seccomp(SET_MODE_STRICT, 0, 0), EINVAL);
}

// --------------------------------------------------------------- other ops

#[test]
fn get_action_avail() {
    fake::reset();
    for (a, want) in [(ALLOW, 0), (KILL_PROCESS, 0), (KILL_THREAD, 0), (TRAP, 0), (ERRNO, 0), (TRACE, 0), (LOG, 0), (USER_NOTIF, EOPNOTSUPP), (0x1234, EOPNOTSUPP)] {
        let v = a;
        assert_eq!(sys_seccomp(GET_ACTION_AVAIL, 0, &v as *const u32 as u64), want, "{a:#x}");
    }
    let v = ALLOW;
    assert_eq!(sys_seccomp(GET_ACTION_AVAIL, 1, &v as *const u32 as u64), EINVAL);
    assert_eq!(sys_seccomp(GET_ACTION_AVAIL, 0, 0), EFAULT);
    assert_eq!(sys_seccomp(GET_NOTIF_SIZES, 0, 0), EOPNOTSUPP);
    assert_eq!(sys_seccomp(9, 0, 0), EINVAL);
}

#[test]
fn prctl_interface() {
    fake::reset();
    assert_eq!(prctl(39, 0, 0), Some(0), "PR_GET_NO_NEW_PRIVS");
    assert_eq!(prctl(38, 0, 0), Some(EINVAL), "only 1 can be set");
    assert_eq!(prctl(38, 1, 0), Some(0));
    assert_eq!(prctl(39, 0, 0), Some(1));
    let prog = encode(&block(GETPID, ERRNO | 4));
    let fprog: [u64; 2] = [4, prog.as_ptr() as u64];
    assert_eq!(prctl(22, 2, fprog.as_ptr() as u64), Some(0), "PR_SET_SECCOMP, SECCOMP_MODE_FILTER");
    assert_eq!(prctl(21, 0, 0), Some(2));
    assert_eq!(verdict(GETPID), Ok(Some(-4)));
    assert_eq!(prctl(22, 3, 0), Some(EINVAL));
    assert_eq!(prctl(1, 0, 0), None, "not a seccomp prctl");
}

#[test]
fn tsync_applies_the_filter_to_every_thread() {
    fresh();
    let tid = fake::IDS.get().0;
    fake::SIBLINGS.with_borrow_mut(|v| v.push(fake::Task::sibling(tid + 1)));
    assert_eq!(install_with(FLAG_TSYNC, &block(GETPID, ERRNO | 6)), 0);
    fake::SIBLINGS.with_borrow(|v| {
        assert_eq!(v[0].seccomp.mode, 2);
        assert!(v[0].seccomp.no_new_privs, "TSYNC also sets no_new_privs");
    });
}

#[test]
#[ignore = "BUG (low): SECCOMP_FILTER_FLAG_TSYNC overwrites every sibling thread's filter chain \
            with the caller's, dropping filters a sibling installed itself; Linux refuses (returns \
            the sibling's tid) unless each sibling's chain is an ancestor of the caller's \
            (src/compat/linux/seccomp.rs, set_filter)"]
fn tsync_never_removes_a_siblings_own_filters() {
    fresh();
    // The sibling sandboxed itself with a filter the caller does not have.
    let tid = fake::IDS.get().0;
    let mine = fake::SECCOMP.take();
    fake::SECCOMP.set(Default::default());
    prctl(38, 1, 0);
    install(&block(OPEN, ERRNO | 13));
    let sibling_state = fake::SECCOMP.take();
    fake::SECCOMP.set(mine);
    let mut sib = fake::Task::sibling(tid + 1);
    sib.seccomp = sibling_state;
    fake::SIBLINGS.with_borrow_mut(|v| v.push(sib));

    let r = install_with(FLAG_TSYNC, &block(GETPID, ERRNO | 6));
    // Judge open() as the sibling now would.
    let sib_state = fake::SIBLINGS.with_borrow(|v| v[0].seccomp.clone());
    fake::SECCOMP.set(sib_state);
    let open = verdict(OPEN);
    assert!(r != 0 || open == Ok(Some(-13)), "TSYNC succeeded and the sibling's own open() filter is gone ({open:?})");
}
