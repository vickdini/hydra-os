//! The eBPF interpreter, checker and maps of `src/compat/linux/bpf.rs`, run through the
//! system call (`PROG_TEST_RUN` of socket filters): ALU operations of both widths, jumps,
//! stack memory and atomics, bpf-to-bpf calls, helpers, the checker's refusals, map
//! elements from the system call and from programs.

use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::bpf;
use hydra_hosttests_t33::fake;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    fake::CAPS.set(Some(1 << 39)); // CAP_BPF
    g
}

fn insn(code: u8, dst: u8, src: u8, off: i16, imm: i32) -> [u8; 8] {
    let mut b = [0u8; 8];
    b[0] = code;
    b[1] = dst | src << 4;
    b[2..4].copy_from_slice(&off.to_le_bytes());
    b[4..8].copy_from_slice(&imm.to_le_bytes());
    b
}

fn prog(insns: &[[u8; 8]]) -> Vec<u8> {
    insns.iter().flatten().copied().collect()
}

fn sys(cmd: u64, attr: &mut [u8]) -> i64 {
    bpf::sys_bpf(cmd, attr.as_mut_ptr() as u64, attr.len() as u64)
}

fn u32s(v: &[u32]) -> Vec<u8> {
    let mut a: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    a.resize(64, 0);
    a
}

fn load(kind: u32, code: &[u8]) -> i64 {
    let mut a = vec![0u8; 128];
    a[0..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&((code.len() / 8) as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(code.as_ptr() as u64).to_le_bytes());
    sys(5, &mut a)
}

/// Runs a socket filter on a 20-byte packet: its return value.
fn eval(code: &[u8]) -> Result<u32, i64> {
    let fd = load(1, code);
    if fd < 0 {
        return Err(fd);
    }
    let pkt = [0x45u8; 20];
    let mut t = u32s(&[fd as u32, 0, 20, 0]);
    t[16..24].copy_from_slice(&(pkt.as_ptr() as u64).to_le_bytes());
    let r = sys(10, &mut t);
    if r < 0 {
        return Err(r);
    }
    Ok(u32::from_le_bytes(t[4..8].try_into().unwrap()))
}

fn ld64(d: u8, v: u64) -> Vec<u8> {
    prog(&[insn(0x18, d, 0, 0, v as u32 as i32), insn(0, 0, 0, 0, (v >> 32) as u32 as i32)])
}

const EXIT: [u8; 8] = [0x95, 0, 0, 0, 0, 0, 0, 0];

#[test]
fn alu_operations_64_and_32_bit() {
    let _g = serial();
    let a: u64 = 0xF000_0000_0000_1234;
    let b: u64 = 5;
    let cases: Vec<(u8, u64)> = vec![
        (0x00, a.wrapping_add(b)),
        (0x10, a.wrapping_sub(b)),
        (0x20, a.wrapping_mul(b)),
        (0x30, a / b),
        (0x40, a | b),
        (0x50, a & b),
        (0x60, a << 5),
        (0x70, a >> 5),
        (0x90, a % b),
        (0xa0, a ^ b),
        (0xb0, b),
        (0xc0, ((a as i64) >> 5) as u64),
    ];
    for (op, want) in cases {
        // 64-bit, register source; the high half comes back
        let mut p = ld64(2, a);
        p.extend(prog(&[insn(0xb7, 3, 0, 0, b as i32), insn(0x07 | 0x08 | op, 2, 3, 0, 0), insn(0xbf, 0, 2, 0, 0), insn(0x77, 0, 0, 0, 32), EXIT]));
        assert_eq!(eval(&p).unwrap(), (want >> 32) as u32, "op {op:#x} (high half)");
        // 32-bit, immediate source
        let a32 = a as u32;
        let w32: u32 = match op {
            0x00 => a32.wrapping_add(5),
            0x10 => a32.wrapping_sub(5),
            0x20 => a32.wrapping_mul(5),
            0x30 => a32 / 5,
            0x40 => a32 | 5,
            0x50 => a32 & 5,
            0x60 => a32 << 5,
            0x70 => a32 >> 5,
            0x90 => a32 % 5,
            0xa0 => a32 ^ 5,
            0xb0 => 5,
            _ => ((a32 as i32) >> 5) as u32,
        };
        let mut p = ld64(0, a);
        p.extend(prog(&[insn(0x04 | op, 0, 0, 0, 5), EXIT]));
        assert_eq!(eval(&p).unwrap(), w32, "op {op:#x} (32-bit)");
    }
    // Division and modulo by zero; negation; byte swaps
    assert_eq!(eval(&prog(&[insn(0xb7, 0, 0, 0, 9), insn(0x37, 0, 0, 0, 0), EXIT])).unwrap(), 0);
    assert_eq!(eval(&prog(&[insn(0xb7, 0, 0, 0, 9), insn(0x97, 0, 0, 0, 0), EXIT])).unwrap(), 9);
    assert_eq!(eval(&prog(&[insn(0xb4, 0, 0, 0, 9), insn(0x34, 0, 0, 0, 0), EXIT])).unwrap(), 0);
    assert_eq!(eval(&prog(&[insn(0xb4, 0, 0, 0, 9), insn(0x94, 0, 0, 0, 0), EXIT])).unwrap(), 9);
    assert_eq!(eval(&prog(&[insn(0xb7, 0, 0, 0, 7), insn(0x87, 0, 0, 0, 0), EXIT])).unwrap(), (-7i32) as u32);
    let v = 0x1122_3344u32 as i32;
    for (code, imm, want) in [(0xdc, 16, 0x4433u32), (0xdc, 32, 0x4433_2211), (0xdc, 64, 0), (0xd4, 16, 0x3344), (0xd4, 32, 0x1122_3344), (0xd4, 64, 0x1122_3344)] {
        assert_eq!(eval(&prog(&[insn(0xb7, 0, 0, 0, v), insn(code, 0, 0, 0, imm), EXIT])).unwrap(), want, "{code:#x}/{imm}");
    }
}

#[test]
fn jumps_memory_atomics_calls_and_helpers() {
    let _g = serial();
    let jt = |op: u8, a: i32, b: i32, wide: bool| {
        let class = if wide { 0x05 } else { 0x06 };
        eval(&prog(&[insn(0xb7, 2, 0, 0, a), insn(0xb7, 0, 0, 0, 0), insn(class | op, 2, 0, 1, b), EXIT, insn(0xb7, 0, 0, 0, 1), EXIT])).unwrap()
    };
    for wide in [true, false] {
        assert_eq!(jt(0x10, 3, 3, wide), 1);
        assert_eq!(jt(0x20, 4, 3, wide), 1);
        assert_eq!(jt(0x30, 3, 3, wide), 1);
        assert_eq!(jt(0x40, 6, 2, wide), 1);
        assert_eq!(jt(0x50, 3, 3, wide), 0);
        assert_eq!(jt(0x60, -1, -2, wide), 1);
        assert_eq!(jt(0x70, -2, -2, wide), 1);
        assert_eq!(jt(0xa0, 2, 3, wide), 1);
        assert_eq!(jt(0xb0, 3, 3, wide), 1);
        assert_eq!(jt(0xc0, -3, -2, wide), 1);
        assert_eq!(jt(0xd0, -2, -2, wide), 1);
        assert_eq!(jt(0x20, -1, 3, wide), 1, "unsigned: -1 is large");
    }
    // Stack stores and loads of every width; atomic add and fetch_or
    let p = prog(&[
        insn(0x7a, 10, 0, -8, 0x1111),
        insn(0x72, 10, 0, -16, 0x22),
        insn(0x6a, 10, 0, -24, 0x3333),
        insn(0x62, 10, 0, -32, 0x4444),
        insn(0xb7, 1, 0, 0, 0x10),
        insn(0xdb, 10, 1, -8, 0x00),
        insn(0xb7, 1, 0, 0, 0x0F),
        insn(0xdb, 10, 1, -8, 0x41),
        insn(0x79, 0, 10, -8, 0),
        insn(0x71, 3, 10, -16, 0),
        insn(0x0f, 0, 3, 0, 0),
        insn(0x69, 3, 10, -24, 0),
        insn(0x0f, 0, 3, 0, 0),
        insn(0x61, 3, 10, -32, 0),
        insn(0x0f, 0, 3, 0, 0),
        insn(0x0f, 0, 1, 0, 0),
        EXIT,
    ]);
    assert_eq!(eval(&p).unwrap(), (0x1121 | 0xF) + 0x22 + 0x3333 + 0x4444 + 0x1121);
    // and, xor, cmpxchg, xchg on a 32-bit word
    let p = prog(&[
        insn(0x62, 10, 0, -4, 0xFF),
        insn(0xb7, 1, 0, 0, 0x0F),
        insn(0xc3, 10, 1, -4, 0x50),
        insn(0xb7, 1, 0, 0, 0x01),
        insn(0xc3, 10, 1, -4, 0xa0),
        insn(0xb7, 0, 0, 0, 0x0E),
        insn(0xb7, 1, 0, 0, 0x77),
        insn(0xc3, 10, 1, -4, 0xf1),
        insn(0xb7, 1, 0, 0, 0x55),
        insn(0xc3, 10, 1, -4, 0xe1),
        insn(0x61, 0, 10, -4, 0),
        insn(0x0f, 0, 1, 0, 0),
        EXIT,
    ]);
    assert_eq!(eval(&p).unwrap(), 0x55 + 0x77);
    // Out-of-bounds stack access, an endless loop: the run fails
    assert_eq!(eval(&prog(&[insn(0x79, 0, 10, 8, 0), EXIT])), Err(-22));
    assert_eq!(eval(&prog(&[insn(0x05, 0, 0, -1, 0), EXIT])), Err(-22));
    // bpf-to-bpf call: the callee doubles r1; r6 is kept
    let p = prog(&[
        insn(0xb7, 6, 0, 0, 100),
        insn(0xb7, 1, 0, 0, 21),
        insn(0x85, 0, 1, 0, 2),
        insn(0x0f, 0, 6, 0, 0),
        EXIT,
        insn(0xbf, 0, 1, 0, 0),
        insn(0x27, 0, 0, 0, 2),
        insn(0xb7, 6, 0, 0, 0),
        EXIT,
    ]);
    assert_eq!(eval(&p).unwrap(), 142);
    // Helpers
    fake::IDS.set((5, 9));
    let h = |id: i32| eval(&prog(&[insn(0x85, 0, 0, 0, id), EXIT])).unwrap();
    assert_eq!(h(14), 5);
    assert_eq!(h(8), 0);
    assert_eq!(h(6), 0);
    let _ = (h(7), h(5), h(125), h(15));
    let p = prog(&[insn(0xbf, 1, 10, 0, 0), insn(0x07, 1, 0, 0, -16), insn(0xb7, 2, 0, 0, 16), insn(0x85, 0, 0, 0, 16), insn(0x71, 0, 10, -16, 0), EXIT]);
    assert_eq!(eval(&p).unwrap(), b'h' as u32);
    let p = prog(&[insn(0xb7, 2, 0, 0, 0), insn(0x85, 0, 0, 0, 16), EXIT]);
    assert_eq!(eval(&p), Err(-22), "size 0");
}

#[test]
fn the_checker_refuses_bad_programs() {
    let _g = serial();
    let bad = [
        prog(&[insn(0xb7, 11, 0, 0, 0), EXIT]),
        prog(&[insn(0xb7, 10, 0, 0, 0), EXIT]),
        prog(&[insn(0x20, 0, 0, 0, 0), EXIT]),
        prog(&[insn(0x18, 0, 3, 0, 0), insn(0, 0, 0, 0, 0), EXIT]),
        prog(&[insn(0x18, 0, 1, 0, 1), insn(0, 0, 0, 0, 0), EXIT]),
        prog(&[insn(0x41, 0, 10, 0, 0), EXIT]),
        prog(&[insn(0xdb, 10, 1, -8, 0x07), EXIT]),
        prog(&[insn(0xe7, 0, 0, 0, 0), EXIT]),
        prog(&[insn(0xd4, 0, 0, 0, 8), EXIT]),
        prog(&[insn(0x86, 0, 0, 0, 1), EXIT]),
        prog(&[insn(0x85, 0, 1, 0, 9), EXIT]),
        prog(&[insn(0x85, 0, 0, 0, 999), EXIT]),
        prog(&[insn(0x96, 0, 0, 0, 0)]),
        prog(&[insn(0xe5, 0, 0, 0, 0), EXIT]),
        prog(&[insn(0x05, 0, 0, 5, 0), EXIT]),
    ];
    for (i, p) in bad.iter().enumerate() {
        assert_eq!(load(1, p), -13, "case {i}");
    }
    // The reason goes to the log buffer
    let mut log = [0u8; 64];
    let p = &bad[11];
    let mut a = vec![0u8; 128];
    a[0..4].copy_from_slice(&1u32.to_le_bytes());
    a[4..8].copy_from_slice(&((p.len() / 8) as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(p.as_ptr() as u64).to_le_bytes());
    a[24..28].copy_from_slice(&1u32.to_le_bytes());
    a[28..32].copy_from_slice(&64u32.to_le_bytes());
    a[32..40].copy_from_slice(&(log.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(5, &mut a), -13);
    assert!(String::from_utf8_lossy(&log).starts_with("unknown helper"));
    a[28..32].copy_from_slice(&0u32.to_le_bytes());
    assert_eq!(sys(5, &mut a), -22, "a log level without a log");
    assert_eq!(load(99, &prog(&[insn(0xb7, 0, 0, 0, 0), EXIT])), -22);
    assert_eq!(load(1, &[]), -7);
}

fn map(kind: u32, key: u32, value: u32, max: u32) -> i64 {
    let mut a = u32s(&[kind, key, value, max, 0]);
    a.resize(64, 0);
    sys(0, &mut a)
}

#[test]
fn maps_from_the_system_call_and_from_programs() {
    let _g = serial();
    assert_eq!(map(77, 4, 4, 4), -22);
    let m = map(1, 4, 8, 2);
    assert!(m >= 3);
    let op = |cmd: u64, key: Option<&[u8]>, val: &mut [u8], flags: u64| {
        let mut a = vec![0u8; 32];
        a[0..4].copy_from_slice(&(m as u32).to_le_bytes());
        a[8..16].copy_from_slice(&key.map_or(0, |k| k.as_ptr() as u64).to_le_bytes());
        a[16..24].copy_from_slice(&(val.as_mut_ptr() as u64).to_le_bytes());
        a[24..32].copy_from_slice(&flags.to_le_bytes());
        sys(cmd, &mut a)
    };
    let (k1, k2, k3) = (1u32.to_le_bytes(), 2u32.to_le_bytes(), 3u32.to_le_bytes());
    let mut v = 7u64.to_le_bytes();
    assert_eq!(op(1, Some(&k1), &mut v, 0), -2);
    assert_eq!(op(2, Some(&k1), &mut v, 0), 0);
    assert_eq!(op(2, Some(&k1), &mut v, 1), -17, "BPF_NOEXIST");
    assert_eq!(op(2, Some(&k2), &mut v, 2), -2, "BPF_EXIST");
    assert_eq!(op(2, Some(&k2), &mut v, 0), 0);
    assert_eq!(op(2, Some(&k3), &mut v, 0), -7, "full");
    let mut out = [0u8; 8];
    assert_eq!(op(1, Some(&k1), &mut out, 0), 0);
    assert_eq!(u64::from_le_bytes(out), 7);
    let mut nk = [0u8; 4];
    assert_eq!(op(4, None, &mut nk, 0), 0);
    assert_eq!(nk, k1);
    assert_eq!(op(4, Some(&k1), &mut nk, 0), 0);
    assert_eq!(nk, k2);
    assert_eq!(op(4, Some(&k2), &mut nk, 0), -2);
    // A program: look key 2 up and write 40 into it; insert key 9 (full: -E2BIG); delete key 1
    let mut p = prog(&[insn(0x62, 10, 0, -4, 2)]);
    p.extend(prog(&[insn(0x18, 1, 1, 0, m as i32), insn(0, 0, 0, 0, 0)]));
    p.extend(prog(&[insn(0xbf, 2, 10, 0, 0), insn(0x07, 2, 0, 0, -4), insn(0x85, 0, 0, 0, 1)]));
    p.extend(prog(&[insn(0x15, 0, 0, 3, 0), insn(0x79, 6, 0, 0, 0), insn(0x7a, 0, 0, 0, 40), insn(0x05, 0, 0, 1, 0), insn(0xb7, 6, 0, 0, 999)]));
    p.extend(prog(&[insn(0x18, 1, 1, 0, m as i32), insn(0, 0, 0, 0, 0)]));
    p.extend(prog(&[insn(0x62, 10, 0, -4, 9), insn(0xbf, 2, 10, 0, 0), insn(0x07, 2, 0, 0, -4)]));
    p.extend(prog(&[insn(0x7a, 10, 0, -16, 5), insn(0xbf, 3, 10, 0, 0), insn(0x07, 3, 0, 0, -16), insn(0xb7, 4, 0, 0, 0)]));
    p.extend(prog(&[insn(0x85, 0, 0, 0, 2), insn(0x0f, 6, 0, 0, 0)]));
    p.extend(prog(&[insn(0x18, 1, 1, 0, m as i32), insn(0, 0, 0, 0, 0)]));
    p.extend(prog(&[insn(0x62, 10, 0, -4, 1), insn(0xbf, 2, 10, 0, 0), insn(0x07, 2, 0, 0, -4)]));
    p.extend(prog(&[insn(0x85, 0, 0, 0, 3), insn(0x0f, 6, 0, 0, 0), insn(0xbf, 0, 6, 0, 0), EXIT]));
    assert_eq!(eval(&p).unwrap(), 0, "7 + (-7: full) + 0 (deleted)");
    assert_eq!(op(1, Some(&k2), &mut out, 0), 0);
    assert_eq!(u64::from_le_bytes(out), 40, "written through the value pointer");
    assert_eq!(op(1, Some(&k1), &mut out, 0), -2, "deleted by the program");
    // Lookup-and-delete; delete
    assert_eq!(op(21, Some(&k2), &mut out, 0), 0);
    assert_eq!(op(3, Some(&k2), &mut out, 0), -2);
    // Array maps: fixed keys, no deletes
    let a = map(2, 4, 4, 2);
    let aop = |cmd: u64, key: &[u8], val: &mut [u8], flags: u64| {
        let mut x = vec![0u8; 32];
        x[0..4].copy_from_slice(&(a as u32).to_le_bytes());
        x[8..16].copy_from_slice(&(key.as_ptr() as u64).to_le_bytes());
        x[16..24].copy_from_slice(&(val.as_mut_ptr() as u64).to_le_bytes());
        x[24..32].copy_from_slice(&flags.to_le_bytes());
        sys(cmd, &mut x)
    };
    let mut w = [9u8; 4];
    assert_eq!(aop(2, &1u32.to_le_bytes(), &mut w, 0), 0);
    assert!(aop(2, &5u32.to_le_bytes(), &mut w, 0) < 0, "index past the end");
    assert_eq!(aop(1, &0u32.to_le_bytes(), &mut w, 0), 0, "array entries always exist");
    assert!(aop(3, &0u32.to_le_bytes(), &mut w, 0) < 0, "no deletes in arrays");
    assert_eq!(aop(21, &1u32.to_le_bytes(), &mut w, 0), -22);
    // Element ops on something that is not a map
    let mut x = u32s(&[1]);
    assert_eq!(sys(1, &mut x), -22);
}
