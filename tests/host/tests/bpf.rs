//! Tests for eBPF (`src/compat/linux/bpf.rs`): the privilege rule, the load
//! checker, the interpreter (registers, ALU, memory regions and their bounds,
//! jumps, helpers, maps, atomics, bpf-to-bpf calls, the step limit), map
//! syscalls, `BPF_PROG_TEST_RUN`, and device-cgroup programs, which decide
//! whether a container may open a device.
//!
//! Programs are assembled here, loaded with `sys_bpf(BPF_PROG_LOAD)` and run
//! with `BPF_PROG_TEST_RUN` (or `device_check`), exactly as user space would.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hydra_hosttests::compat::linux::bpf::{device_check, sys_bpf, DEV_BLOCK, DEV_CHAR, DEV_READ, DEV_WRITE};
use hydra_hosttests::fake;
use hydra_hosttests::fs::FileDescriptor;

const MAP_CREATE: u64 = 0;
const MAP_LOOKUP: u64 = 1;
const MAP_UPDATE: u64 = 2;
const PROG_LOAD: u64 = 5;
const PROG_ATTACH: u64 = 8;
const PROG_TEST_RUN: u64 = 10;

const SOCKET_FILTER: u32 = 1;
const CGROUP_DEVICE: u32 = 15;
const ATTACH_CGROUP_DEVICE: u32 = 6;
const MAP_ARRAY: u32 = 2;
const MAP_HASH: u32 = 1;

const EPERM: i64 = -1;
const E2BIG: i64 = -7;
const EACCES: i64 = -13;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;

const CAP_BPF: u64 = 1 << 39;

// --------------------------------------------------------------- assembler

#[derive(Clone, Copy)]
struct I(u8, u8, u8, i16, i32); // code, dst, src, off, imm

fn encode(p: &[I]) -> Vec<u8> {
    p.iter().flat_map(|i| [&[i.0, i.1 | (i.2 << 4)][..], &i.3.to_le_bytes(), &i.4.to_le_bytes()].concat()).collect()
}

fn mov(d: u8, imm: i32) -> I {
    I(0xb7, d, 0, 0, imm)
}
fn mov_r(d: u8, s: u8) -> I {
    I(0xbf, d, s, 0, 0)
}
fn alu64(op: u8, d: u8, imm: i32) -> I {
    I(0x07 | op, d, 0, 0, imm)
}
fn alu64_r(op: u8, d: u8, s: u8) -> I {
    I(0x0f | op, d, s, 0, 0)
}
fn alu32(op: u8, d: u8, imm: i32) -> I {
    I(0x04 | op, d, 0, 0, imm)
}
fn ldx(size: u8, d: u8, s: u8, off: i16) -> I {
    I(0x61 | size, d, s, off, 0)
}
fn st(size: u8, d: u8, off: i16, imm: i32) -> I {
    I(0x62 | size, d, 0, off, imm)
}
fn jmp(op: u8, d: u8, imm: i32, off: i16) -> I {
    I(0x05 | op, d, 0, off, imm)
}
fn ja(off: i16) -> I {
    I(0x05, 0, 0, off, 0)
}
fn call(helper: i32) -> I {
    I(0x85, 0, 0, 0, helper)
}
fn call_local(rel: i32) -> I {
    I(0x85, 0, 1, 0, rel)
}
const EXIT: I = I(0x95, 0, 0, 0, 0);
/// LD_IMM64 of a map fd (BPF_PSEUDO_MAP_FD): two slots.
fn ld_map(d: u8, fd: i64) -> [I; 2] {
    [I(0x18, d, 1, 0, fd as i32), I(0, 0, 0, 0, 0)]
}
fn ld_imm64(d: u8, v: u64) -> [I; 2] {
    [I(0x18, d, 0, 0, v as u32 as i32), I(0, 0, 0, 0, (v >> 32) as u32 as i32)]
}

// sizes for ldx/stx/st
const W: u8 = 0x00;
const H: u8 = 0x08;
const B: u8 = 0x10;
const DW: u8 = 0x18;
// ALU ops
const ADD: u8 = 0x00;
const SUB: u8 = 0x10;
const MUL: u8 = 0x20;
const DIV: u8 = 0x30;
const LSH: u8 = 0x60;
const RSH: u8 = 0x70;
const NEG: u8 = 0x80;
const MOD: u8 = 0x90;
const XOR: u8 = 0xa0;
const ARSH: u8 = 0xc0;
// jump ops
const JEQ: u8 = 0x10;
const JGT: u8 = 0x20;
const JNE: u8 = 0x50;
const JSGT: u8 = 0x60;
const JLT: u8 = 0xa0;

// --------------------------------------------------------------- syscalls

static NEXT: AtomicU64 = AtomicU64::new(60_000);

/// Fresh fakes with CAP_BPF.
fn setup() -> u64 {
    fake::reset();
    fake::CAPS.set(Some(CAP_BPF));
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    fake::IDS.set((n, n));
    n
}

fn bpf(cmd: u64, attr: &mut [u8]) -> i64 {
    sys_bpf(cmd, attr.as_mut_ptr() as u64, attr.len() as u64)
}

fn load_kind(kind: u32, prog: &[I]) -> i64 {
    let code = encode(prog);
    let mut a = [0u8; 128];
    a[0..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&(prog.len() as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(code.as_ptr() as u64).to_le_bytes());
    bpf(PROG_LOAD, &mut a)
}

fn load(prog: &[I]) -> i64 {
    load_kind(SOCKET_FILTER, prog)
}

/// Load with a verifier log; returns (result, log text).
fn load_logged(prog: &[I]) -> (i64, String) {
    let code = encode(prog);
    let mut log = vec![0u8; 256];
    let mut a = [0u8; 128];
    a[0..4].copy_from_slice(&SOCKET_FILTER.to_le_bytes());
    a[4..8].copy_from_slice(&(prog.len() as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(code.as_ptr() as u64).to_le_bytes());
    a[24..28].copy_from_slice(&1u32.to_le_bytes());
    a[28..32].copy_from_slice(&(log.len() as u32).to_le_bytes());
    a[32..40].copy_from_slice(&(log.as_mut_ptr() as u64).to_le_bytes());
    let r = bpf(PROG_LOAD, &mut a);
    let end = log.iter().position(|&b| b == 0).unwrap_or(0);
    (r, String::from_utf8_lossy(&log[..end]).trim_end().to_string())
}

/// BPF_PROG_TEST_RUN on `packet` (Ethernet frame); returns (result, retval, packet out).
fn test_run(fd: i64, packet: &[u8]) -> (i64, u32, Vec<u8>) {
    let mut out = vec![0u8; packet.len() + 64];
    let mut a = [0u8; 80];
    a[0..4].copy_from_slice(&(fd as u32).to_le_bytes());
    a[8..12].copy_from_slice(&(packet.len() as u32).to_le_bytes());
    a[12..16].copy_from_slice(&(out.len() as u32).to_le_bytes());
    a[16..24].copy_from_slice(&(packet.as_ptr() as u64).to_le_bytes());
    a[24..32].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    let r = bpf(PROG_TEST_RUN, &mut a);
    let retval = u32::from_le_bytes(a[4..8].try_into().unwrap());
    let n = u32::from_le_bytes(a[12..16].try_into().unwrap()) as usize;
    out.truncate(n.min(out.len()));
    (r, retval, out)
}

fn frame(payload_len: usize) -> Vec<u8> {
    let mut f = vec![0u8; 14 + payload_len];
    f[12] = 0x08; // IPv4
    for (i, b) in f[14..].iter_mut().enumerate() {
        *b = i as u8 + 1;
    }
    f
}

/// Load `prog` and run it on a 20-byte packet; returns the program's r0.
fn eval(prog: &[I]) -> u32 {
    let fd = load(prog);
    assert!(fd >= 0, "program rejected: {fd}");
    let (r, ret, _) = test_run(fd, &frame(20));
    assert_eq!(r, 0, "program faulted");
    ret
}

fn map_create(kind: u32, key: u32, value: u32, max: u32) -> i64 {
    let mut a = [0u8; 64];
    for (i, v) in [kind, key, value, max].iter().enumerate() {
        a[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    bpf(MAP_CREATE, &mut a)
}

fn map_elem(cmd: u64, fd: i64, key: &[u8], value: &mut [u8], flags: u64) -> i64 {
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&(fd as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(key.as_ptr() as u64).to_le_bytes());
    a[16..24].copy_from_slice(&(value.as_mut_ptr() as u64).to_le_bytes());
    a[24..32].copy_from_slice(&flags.to_le_bytes());
    bpf(cmd, &mut a)
}

// --------------------------------------------------------------- privilege

#[test]
fn bpf_needs_cap_bpf_or_cap_sys_admin_outside_user_namespaces() {
    setup();
    fake::CAPS.set(Some(0));
    assert_eq!(load(&[mov(0, 0), EXIT]), EPERM);
    fake::CAPS.set(Some(CAP_BPF));
    fake::IN_USERNS.set(true);
    assert_eq!(load(&[mov(0, 0), EXIT]), EPERM, "namespaced capability is not enough");
    fake::IN_USERNS.set(false);
    fake::CAPS.set(Some(1 << 21));
    assert!(load(&[mov(0, 0), EXIT]) >= 0, "CAP_SYS_ADMIN");
    assert_eq!(sys_bpf(PROG_LOAD, 0, 4097), E2BIG, "attr larger than a page");
}

// ------------------------------------------------------------------ loader

#[test]
fn simple_program_runs() {
    setup();
    assert_eq!(eval(&[mov(0, 42), EXIT]), 42);
}

#[test]
fn checker_rejects_bad_programs() {
    setup();
    let cases: Vec<(&str, Vec<I>)> = vec![
        ("invalid register", vec![mov(11, 0), EXIT]),
        ("frame pointer is read only", vec![mov(10, 0), EXIT]),
        ("invalid BPF_LD", vec![I(0x20, 0, 0, 0, 0), EXIT]), // legacy LD_ABS
        ("invalid BPF_LD", vec![I(0x18, 0, 0, 0, 0), EXIT]), // LD_IMM64 without its second half
        ("unsupported pseudo load", vec![I(0x18, 0, 3, 0, 0), I(0, 0, 0, 0, 0), EXIT]),
        ("unsupported load/store mode", vec![I(0x41, 0, 1, 0, 0), EXIT]),
        ("unsupported atomic operation", vec![I(0xdb, 10, 1, -8, 0x02), EXIT]),
        ("invalid ALU operation", vec![I(0xe7, 0, 0, 0, 0), EXIT]),
        ("invalid byte swap", vec![I(0xd4, 0, 0, 0, 8), EXIT]),
        ("unknown helper", vec![call(99), EXIT]),
        ("call out of range", vec![call_local(5), EXIT]),
        ("jump out of range", vec![ja(5), EXIT]),
        ("jump into the middle of an instruction", vec![ja(1), ld_imm64(0, 1)[0], ld_imm64(0, 1)[1], EXIT]),
        ("last instruction is not an exit or jump", vec![mov(0, 0)]),
        ("invalid jump", vec![I(0xe5, 0, 0, 0, 0), EXIT]),
    ];
    for (why, prog) in cases {
        let (r, log) = load_logged(&prog);
        assert_eq!(r, EACCES, "{why}: verifier refusals are EACCES");
        assert_eq!(log, why, "log explains the refusal");
    }
    assert_eq!(load(&[]), E2BIG, "no instructions");
    assert_eq!(load_kind(99, &[mov(0, 0), EXIT]), EINVAL, "unsupported program type");
}

#[test]
fn maps_must_be_real_map_descriptors() {
    setup();
    let (r, log) = load_logged(&[ld_map(1, 77)[0], ld_map(1, 77)[1], mov(0, 0), EXIT]);
    assert_eq!((r, log.as_str()), (EACCES, "fd is not a map"));
}

// --------------------------------------------------------------- arithmetic

#[test]
fn alu_semantics() {
    setup();
    assert_eq!(eval(&[mov(0, 40), alu64(ADD, 0, 2), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 50), alu64(SUB, 0, 8), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 6), alu64(MUL, 0, 7), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 84), alu64(DIV, 0, 2), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 84), alu64(DIV, 0, 0), EXIT]), 0, "division by zero gives 0");
    assert_eq!(eval(&[mov(0, 42), alu64(MOD, 0, 0), EXIT]), 42, "modulo by zero keeps dst");
    assert_eq!(eval(&[mov(0, 142), alu64(MOD, 0, 100), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 21), alu64(LSH, 0, 1), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 84), alu64(RSH, 0, 1), EXIT]), 42);
    assert_eq!(eval(&[mov(0, 0x2b), alu64(XOR, 0, 1), EXIT]), 42);
    assert_eq!(eval(&[mov(0, -42), alu64(NEG, 0, 0), EXIT]), 42);
    assert_eq!(eval(&[mov(0, -84), alu64(ARSH, 0, 1), EXIT]), (-42i32) as u32, "arithmetic shift keeps the sign");
    assert_eq!(eval(&[mov(1, 40), mov(2, 2), alu64_r(ADD, 1, 2), mov_r(0, 1), EXIT]), 42);
}

#[test]
fn alu32_zero_extends() {
    setup();
    // r0 = 2^32 + 5, then 32-bit add 1: upper half cleared
    let mut p = ld_imm64(0, (1 << 32) + 5).to_vec();
    p.extend([alu32(ADD, 0, 1), alu64(RSH, 0, 32), EXIT]);
    assert_eq!(eval(&p), 0);
    let mut q = ld_imm64(0, (1 << 32) + 5).to_vec();
    q.extend([alu32(ADD, 0, 1), EXIT]);
    assert_eq!(eval(&q), 6);
}

#[test]
fn byte_swaps() {
    setup();
    assert_eq!(eval(&[mov(0, 0x1234), I(0xdc, 0, 0, 0, 16), EXIT]), 0x3412, "to big endian, 16 bits");
    assert_eq!(eval(&[mov(0, 0x12345678), I(0xdc, 0, 0, 0, 32), EXIT]), 0x78563412);
    assert_eq!(eval(&[mov(0, 0x12345678), I(0xd4, 0, 0, 0, 16), EXIT]), 0x5678, "to little endian truncates");
}

#[test]
fn jumps_and_signed_comparisons() {
    setup();
    // r0 = 1 if condition else 2
    let pick = |cond: I| eval(&[mov(1, -5), mov(0, 1), cond, mov(0, 2), EXIT]);
    assert_eq!(pick(jmp(JEQ, 1, -5, 1)), 1);
    assert_eq!(pick(jmp(JNE, 1, -5, 1)), 2);
    assert_eq!(pick(jmp(JGT, 1, 0, 1)), 1, "unsigned: -5 is huge");
    assert_eq!(pick(jmp(JSGT, 1, 0, 1)), 2, "signed: -5 < 0");
    assert_eq!(pick(jmp(JLT, 1, 3, 1)), 2);
    assert_eq!(pick(I(0x16, 1, 0, 1, -5)), 1, "32-bit JEQ");
}

#[test]
fn bounded_loops_run_and_infinite_ones_are_stopped() {
    setup();
    // for (r0 = 0, r1 = 10; r1 != 0; r1--) r0 += 3;
    assert_eq!(eval(&[mov(0, 0), mov(1, 10), alu64(ADD, 0, 3), alu64(SUB, 1, 1), jmp(JNE, 1, 0, -3), EXIT]), 30);
    let fd = load(&[ja(-1), EXIT]);
    assert!(fd >= 0, "backward jumps are allowed");
    assert_eq!(test_run(fd, &frame(20)).0, EINVAL, "stopped after a million steps, not a hang");
}

// ------------------------------------------------------------------ memory

#[test]
fn stack_is_512_bytes_below_r10() {
    setup();
    assert_eq!(eval(&[st(DW, 10, -8, 42), ldx(DW, 0, 10, -8), EXIT]), 42);
    assert_eq!(eval(&[st(DW, 10, -512, 7), ldx(DW, 0, 10, -512), EXIT]), 7, "bottom of the stack");
    let above = load(&[st(DW, 10, 0, 1), mov(0, 0), EXIT]);
    assert_eq!(test_run(above, &frame(20)).0, EINVAL, "above the frame pointer");
    let below = load(&[st(DW, 10, -520, 1), mov(0, 0), EXIT]);
    assert_eq!(test_run(below, &frame(20)).0, EINVAL, "below the stack");
    let forged = load(&[mov(1, 0x1234), ldx(DW, 0, 1, 0), EXIT]);
    assert_eq!(test_run(forged, &frame(20)).0, EINVAL, "an integer is not a pointer");
}

#[test]
fn context_fields() {
    setup();
    assert_eq!(eval(&[ldx(W, 0, 1, 0), EXIT]), 20, "__sk_buff.len: bytes after the Ethernet header");
    assert_eq!(eval(&[ldx(H, 0, 1, 16), EXIT]), 0x0008, "protocol in network byte order");
    let beyond = load(&[ldx(W, 0, 1, 192), EXIT]);
    assert_eq!(test_run(beyond, &frame(20)).0, EINVAL, "past the context");
}

#[test]
fn packet_access_is_bounds_checked_and_writes_are_returned() {
    setup();
    // r2 = skb->data; r0 = first payload byte
    assert_eq!(eval(&[ldx(W, 2, 1, 76), ldx(B, 0, 2, 0), EXIT]), 1);
    assert_eq!(eval(&[ldx(W, 2, 1, 76), ldx(B, 0, 2, 19), EXIT]), 20, "last byte");
    let past = load(&[ldx(W, 2, 1, 76), ldx(B, 0, 2, 20), EXIT]);
    assert_eq!(test_run(past, &frame(20)).0, EINVAL, "one past the end");
    let write = load(&[ldx(W, 2, 1, 76), st(B, 2, 0, 0x77), mov(0, 0), EXIT]);
    let (r, _, out) = test_run(write, &frame(20));
    assert_eq!(r, 0);
    assert_eq!(out[14], 0x77, "the program's packet write is returned");
    assert_eq!(&out[..14], &frame(20)[..14], "Ethernet header untouched");
}

#[test]
fn test_run_input_limits() {
    setup();
    let fd = load(&[mov(0, 0), EXIT]);
    assert_eq!(test_run(fd, &[0u8; 13]).0, EINVAL, "shorter than an Ethernet header");
    let dev = load_kind(CGROUP_DEVICE, &[mov(0, 1), EXIT]);
    assert_eq!(test_run(dev, &frame(20)).0, -524, "ENOTSUPP for device programs");
}

#[test]
#[ignore = "BUG: BPF_PROG_TEST_RUN ignores data_size_out (the caller's buffer size) and copies the \
            whole packet to data_out, writing past the caller's buffer; Linux copies at most \
            data_size_out bytes and returns ENOSPC (src/compat/linux/bpf.rs, sys_bpf PROG_TEST_RUN)"]
fn test_run_respects_the_output_buffer_size() {
    setup();
    let fd = load(&[mov(0, 0), EXIT]);
    let packet = frame(50);
    let mut out = vec![0xCCu8; 128];
    let mut a = [0u8; 80];
    a[0..4].copy_from_slice(&(fd as u32).to_le_bytes());
    a[8..12].copy_from_slice(&(packet.len() as u32).to_le_bytes());
    a[12..16].copy_from_slice(&20u32.to_le_bytes()); // caller's buffer: 20 bytes
    a[16..24].copy_from_slice(&(packet.as_ptr() as u64).to_le_bytes());
    a[24..32].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    let r = bpf(PROG_TEST_RUN, &mut a);
    assert!(out[20..].iter().all(|&b| b == 0xCC), "wrote {} bytes into a 20-byte buffer", out.iter().rposition(|&b| b != 0xCC).unwrap() + 1);
    assert_eq!(r, ENOSPC);
}

// -------------------------------------------------------------------- maps

#[test]
fn map_create_limits() {
    setup();
    assert_eq!(map_create(99, 4, 4, 1), EINVAL, "unknown type");
    assert_eq!(map_create(MAP_HASH, 0, 4, 1), EINVAL, "zero key size");
    assert_eq!(map_create(MAP_HASH, 513, 4, 1), EINVAL, "key too large");
    assert_eq!(map_create(MAP_HASH, 4, 65537, 1), EINVAL, "value too large");
    assert_eq!(map_create(MAP_ARRAY, 8, 4, 1), EINVAL, "arrays have 4-byte keys");
    assert_eq!(map_create(MAP_ARRAY, 4, 65536, 2000), -12, "more than 64 MiB: ENOMEM");
    assert!(map_create(MAP_ARRAY, 4, 8, 4) >= 0);
}

#[test]
fn programs_update_maps_and_user_space_sees_it() {
    setup();
    let m = map_create(MAP_ARRAY, 4, 8, 4);
    // key 2 on the stack; v = lookup(map, &key); if (v) *v += 5 (atomic add)
    let mut p = vec![st(W, 10, -4, 2), mov_r(2, 10), alu64(ADD, 2, -4)];
    p.extend(ld_map(1, m));
    p.extend([call(1), jmp(JEQ, 0, 0, 2), mov(1, 5), I(0xdb, 0, 1, 0, 0x00), mov(0, 0), EXIT]);
    let fd = load(&p);
    assert!(fd >= 0);
    for _ in 0..3 {
        assert_eq!(test_run(fd, &frame(20)).0, 0);
    }
    let mut v = [0u8; 8];
    assert_eq!(map_elem(MAP_LOOKUP, m, &2u32.to_le_bytes(), &mut v, 0), 0);
    assert_eq!(u64::from_le_bytes(v), 15);
}

#[test]
fn programs_read_values_user_space_wrote() {
    setup();
    let m = map_create(MAP_HASH, 4, 8, 16);
    let mut v = 4242u64.to_le_bytes();
    assert_eq!(map_elem(MAP_UPDATE, m, &7u32.to_le_bytes(), &mut v, 0), 0);
    let mut p = vec![st(W, 10, -4, 7), mov_r(2, 10), alu64(ADD, 2, -4)];
    p.extend(ld_map(1, m));
    p.extend([call(1), jmp(JEQ, 0, 0, 1), ldx(DW, 0, 0, 0), EXIT]);
    assert_eq!(eval(&p), 4242);
    let mut q = vec![st(W, 10, -4, 8), mov_r(2, 10), alu64(ADD, 2, -4)];
    q.extend(ld_map(1, m));
    q.extend([call(1), EXIT]);
    assert_eq!(eval(&q), 0, "missing key: NULL");
}

#[test]
fn map_values_are_bounds_checked() {
    setup();
    let m = map_create(MAP_ARRAY, 4, 8, 1);
    let mut p = vec![st(W, 10, -4, 0), mov_r(2, 10), alu64(ADD, 2, -4)];
    p.extend(ld_map(1, m));
    p.extend([call(1), jmp(JEQ, 0, 0, 1), ldx(DW, 0, 0, 8), EXIT]); // reads value[8..16] of an 8-byte value
    let fd = load(&p);
    assert_eq!(test_run(fd, &frame(20)).0, EINVAL);
}

// ------------------------------------------------------------------ calls

#[test]
fn bpf_to_bpf_calls() {
    setup();
    // main: call f; r0 += 1; exit.  f: r0 = 41; exit
    assert_eq!(eval(&[call_local(2), alu64(ADD, 0, 1), EXIT, mov(0, 41), EXIT]), 42);
}

#[test]
fn callee_saved_registers_survive_calls() {
    setup();
    // r6 = 40; call f (clobbers r6 locally); r0 = r6 + 2
    assert_eq!(eval(&[mov(6, 40), call_local(3), mov_r(0, 6), alu64(ADD, 0, 2), EXIT, mov(6, 0), EXIT]), 42);
}

#[test]
fn recursion_depth_is_limited() {
    setup();
    let fd = load(&[call_local(-1), EXIT]);
    assert!(fd >= 0);
    assert_eq!(test_run(fd, &frame(20)).0, EINVAL, "more than 8 nested calls");
}

#[test]
#[ignore = "BUG: bpf-to-bpf calls push a new stack on every call and never pop it; on return r10 is \
            recomputed from the call depth, which is the wrong stack once earlier calls have \
            returned. A function then reads another call's stack, and loops of calls grow kernel \
            heap by 512 bytes per call (src/compat/linux/bpf.rs, Run::exec)"]
fn a_function_keeps_its_stack_across_nested_calls() {
    setup();
    let prog = [
        call_local(2),            // 0: call A (3)
        call_local(3),            // 1: call B (5)
        EXIT,                     // 2: return B's r0
        mov(0, 0),                // 3: A
        EXIT,                     // 4
        st(DW, 10, -8, 42),       // 5: B: local = 42
        call_local(2),            // 6: call C (9)
        ldx(DW, 0, 10, -8),       // 7: r0 = local
        EXIT,                     // 8
        EXIT,                     // 9: C
    ];
    assert_eq!(eval(&prog), 42, "B's local variable was lost across its call to C");
}

#[test]
fn helpers() {
    setup();
    fake::IDS.set((0x1111, 0x2222));
    assert_eq!(eval(&[call(14), EXIT]), 0x1111, "get_current_pid_tgid: tid in the low half");
    assert_eq!(eval(&[call(14), alu64(RSH, 0, 32), EXIT]), 0x2222);
    fake::UID.set(1000);
    assert_eq!(eval(&[call(15), EXIT]), 1000, "get_current_uid_gid");
    // get_current_comm(r10 - 16, 16); r0 = first byte
    assert_eq!(eval(&[mov_r(1, 10), alu64(ADD, 1, -16), mov(2, 16), call(16), ldx(B, 0, 10, -16), EXIT]), b'h' as u32);
    let bad = load(&[mov_r(1, 10), alu64(ADD, 1, -16), mov(2, 0), call(16), EXIT]);
    assert_eq!(test_run(bad, &frame(20)).0, EINVAL, "comm size 0");
    // r1-r5 are clobbered by helper calls
    assert_eq!(eval(&[mov(3, 9), call(8), mov_r(0, 3), EXIT]), 0);
}

// ---------------------------------------------------------- device cgroups

/// Put the current process in a fresh cgroup and attach `prog` to it.
fn device_policy(prog: &[I]) -> i64 {
    let pid = fake::IDS.get().1;
    let cg = format!("/test-{pid}");
    fake::PROCS.lock().insert(pid, fake::Process { cgroup: Some(Arc::from(cg.as_str())), ..Default::default() });
    fake::FDS.with_borrow_mut(|f| f.install(40, FileDescriptor::File { path: format!("/sys/fs/cgroup{cg}"), readable: true, writable: false }));
    let pfd = load_kind(CGROUP_DEVICE, prog);
    assert!(pfd >= 0);
    let mut a = [0u8; 32];
    a[0..4].copy_from_slice(&40u32.to_le_bytes());
    a[4..8].copy_from_slice(&(pfd as u32).to_le_bytes());
    a[8..12].copy_from_slice(&ATTACH_CGROUP_DEVICE.to_le_bytes());
    bpf(PROG_ATTACH, &mut a)
}

#[test]
fn device_cgroup_programs_decide_device_access() {
    let pid = setup();
    // Allow char devices 1:3 (/dev/null) and 1:5 (/dev/zero); deny everything else.
    // ctx: u32 access_type (access << 16 | type), u32 major, u32 minor
    let prog = [
        mov(0, 0),                        // 0: r0 = deny
        ldx(W, 2, 1, 0),                  // 1: r2 = access_type
        alu64(0x50, 2, 0xffff),           // 2: r2 &= 0xffff (device type)
        jmp(JNE, 2, DEV_CHAR as i32, 7),  // 3: not a char device -> 11
        ldx(W, 3, 1, 4),                  // 4: r3 = major
        jmp(JNE, 3, 1, 5),                // 5: major != 1 -> 11
        ldx(W, 4, 1, 8),                  // 6: r4 = minor
        jmp(JEQ, 4, 3, 2),                // 7: minor 3 -> 10
        jmp(JEQ, 4, 5, 1),                // 8: minor 5 -> 10
        ja(1),                            // 9: -> 11
        mov(0, 1),                        // 10: r0 = allow
        EXIT,                             // 11
    ];
    assert_eq!(device_policy(&prog), 0);
    assert_eq!(device_check(DEV_CHAR, 1, 3, DEV_READ | DEV_WRITE), Ok(()), "/dev/null");
    assert_eq!(device_check(DEV_CHAR, 1, 5, DEV_READ), Ok(()), "/dev/zero");
    assert_eq!(device_check(DEV_BLOCK, 8, 0, DEV_READ), Err(EPERM), "/dev/sda");
    assert_eq!(device_check(DEV_CHAR, 1, 1, DEV_READ), Err(EPERM), "/dev/mem");
    fake::PROCS.lock().remove(&pid);
}

#[test]
fn faulting_device_programs_deny() {
    let pid = setup();
    assert_eq!(device_policy(&[ldx(DW, 0, 1, 64), EXIT]), 0); // reads past the 12-byte context
    assert_eq!(device_check(DEV_CHAR, 1, 3, DEV_READ), Err(EPERM), "fail closed");
    fake::PROCS.lock().remove(&pid);
}

#[test]
fn device_programs_only_affect_their_cgroup() {
    let pid = setup();
    assert_eq!(device_policy(&[mov(0, 0), EXIT]), 0); // deny all
    assert_eq!(device_check(DEV_CHAR, 1, 3, DEV_READ), Err(EPERM));
    fake::PROCS.lock().insert(pid, fake::Process { cgroup: Some(Arc::from(format!("/test-{pid}x").as_str())), ..Default::default() });
    assert_eq!(device_check(DEV_CHAR, 1, 3, DEV_READ), Ok(()), "a sibling cgroup whose name merely shares the prefix");
    fake::PROCS.lock().insert(pid, fake::Process { cgroup: Some(Arc::from(format!("/test-{pid}/child").as_str())), ..Default::default() });
    assert_eq!(device_check(DEV_CHAR, 1, 3, DEV_READ), Err(EPERM), "descendants inherit the policy");
    fake::PROCS.lock().remove(&pid);
}
