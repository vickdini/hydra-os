//! eBPF objects of `src/compat/linux/bpf.rs` beyond the interpreter (which `tests/host`
//! covers): pinning, ids, object info, cgroup attachment through cgroup directory
//! descriptors, links, the device controller (kernel and linux-server programs), test
//! runs of the wrong kind, BTF and frozen maps.
#![allow(dead_code, unused_imports, unused_variables)] // (wave10 G10-C: helpers of tests deleted with the kernel copies)

use std::sync::{Arc, Mutex};

use hydra_hosttests_t33::compat::linux::bpf::{self, DEV_BLOCK, DEV_CHAR, DEV_MKNOD, DEV_READ, DEV_WRITE};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fs::FileDescriptor;

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

/// `r0 = v; exit`
fn ret(v: i32) -> Vec<u8> {
    prog(&[insn(0xb7, 0, 0, 0, v), insn(0x95, 0, 0, 0, 0)])
}

/// Device program: deny major `m` (any access), allow the rest.
fn deny_major(m: i32) -> Vec<u8> {
    prog(&[
        insn(0x61, 2, 1, 4, 0),  // r2 = ctx->major
        insn(0x15, 2, 0, 2, m),  // if r2 == m goto deny
        insn(0xb7, 0, 0, 0, 1),  // r0 = 1
        insn(0x95, 0, 0, 0, 0),  // exit
        insn(0xb7, 0, 0, 0, 0),  // deny: r0 = 0
        insn(0x95, 0, 0, 0, 0),
    ])
}




fn u32s(v: &[u32]) -> Vec<u8> {
    let mut a: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
    a.resize(64, 0);
    a
}

/// A descriptor for cgroup directory `rel` (below /sys/fs/cgroup).
fn cgroup_fd(rel: &str) -> u32 {
    let path = format!("/sys/fs/cgroup{rel}");
    fake::fds_mut(|t| t.alloc_fd(FileDescriptor::File { path, cursor: hydra_hosttests_t33::fs::FileCursor::new(0), readable: true, writable: false, append: false, shown: None }).unwrap()) as u32
}




#[test]
fn linux_server_device_programs() {
    let _g = serial();
    // Encoded as: cgroup length, cgroup, instruction count, instructions
    let entry = |cg: &str, code: &[u8]| {
        let mut v = (cg.len() as u32).to_le_bytes().to_vec();
        v.extend_from_slice(cg.as_bytes());
        v.extend_from_slice(&((code.len() / 8) as u32).to_le_bytes());
        v.extend_from_slice(code);
        v
    };
    let blob = entry("/srv", &deny_major(8));
    assert_eq!(bpf::set_server_device_programs(&blob), 0);
    fake::IDS.set((3100, 3100));
    fake::PROCS.lock().insert(3100, fake::Process { cgroup: Some(Arc::from("/srv")), ..Default::default() });
    assert_eq!(bpf::device_check(DEV_BLOCK, 8, 0, DEV_MKNOD), Err(-1));
    assert_eq!(bpf::device_check(DEV_BLOCK, 7, 0, DEV_MKNOD), Ok(()));
    // An empty cgroup name applies to everyone
    assert_eq!(bpf::set_server_device_programs(&entry("", &deny_major(7))), 0);
    fake::PROCS.lock().remove(&3100);
    assert_eq!(bpf::device_check(DEV_BLOCK, 7, 0, DEV_MKNOD), Err(-1), "no cgroup: root's programs apply");
    // Malformed lists
    assert_eq!(bpf::set_server_device_programs(&[1, 0]), -22, "short length");
    assert_eq!(bpf::set_server_device_programs(&[9, 0, 0, 0, b'x']), -22, "short cgroup");
    let mut no_count = 1u32.to_le_bytes().to_vec();
    no_count.push(b'x');
    assert_eq!(bpf::set_server_device_programs(&no_count), -22);
    assert_eq!(bpf::set_server_device_programs(&entry("/a", &[])), -22, "no instructions");
    let mut short = entry("/a", &ret(1));
    short.truncate(short.len() - 4);
    assert_eq!(bpf::set_server_device_programs(&short), -22);
    let map_ref = prog(&[insn(0x18, 1, 1, 0, 3), insn(0, 0, 0, 0, 0), insn(0xb7, 0, 0, 0, 1), insn(0x95, 0, 0, 0, 0)]);
    assert_eq!(bpf::set_server_device_programs(&entry("/a", &map_ref)), -22, "maps are the server's");
    let bad = prog(&[insn(0xb7, 0, 0, 0, 1)]); // no exit
    assert_eq!(bpf::set_server_device_programs(&entry("/a", &bad)), -22);
    // An empty list switches it off
    assert_eq!(bpf::set_server_device_programs(&[]), 0);
    assert_eq!(bpf::device_check(DEV_BLOCK, 7, 0, DEV_MKNOD), Ok(()));
}
