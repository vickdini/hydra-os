//! The eBPF interpreter, checker and maps of `src/compat/linux/bpf.rs`, run through the
//! system call (`PROG_TEST_RUN` of socket filters): ALU operations of both widths, jumps,
//! stack memory and atomics, bpf-to-bpf calls, helpers, the checker's refusals, map
//! elements from the system call and from programs.
#![allow(dead_code, unused_imports, unused_variables)] // (wave10 G10-C: helpers of tests deleted with the kernel copies)

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


fn u32s(v: &[u32]) -> Vec<u8> {
    let mut a: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    a.resize(64, 0);
    a
}



fn ld64(d: u8, v: u64) -> Vec<u8> {
    prog(&[insn(0x18, d, 0, 0, v as u32 as i32), insn(0, 0, 0, 0, (v >> 32) as u32 as i32)])
}

const EXIT: [u8; 8] = [0x95, 0, 0, 0, 0, 0, 0, 0];





