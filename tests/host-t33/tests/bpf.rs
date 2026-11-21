//! eBPF objects of `src/compat/linux/bpf.rs` beyond the interpreter (which `tests/host`
//! covers): pinning, ids, object info, cgroup attachment through cgroup directory
//! descriptors, links, the device controller (kernel and linux-server programs), test
//! runs of the wrong kind, BTF and frozen maps.

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

fn sys(cmd: u64, attr: &mut [u8]) -> i64 {
    bpf::sys_bpf(cmd, attr.as_mut_ptr() as u64, attr.len() as u64)
}

fn load(kind: u32, code: &[u8], name: &str) -> i64 {
    let mut a = vec![0u8; 128];
    a[0..4].copy_from_slice(&kind.to_le_bytes());
    a[4..8].copy_from_slice(&((code.len() / 8) as u32).to_le_bytes());
    a[8..16].copy_from_slice(&(code.as_ptr() as u64).to_le_bytes());
    a[48..48 + name.len()].copy_from_slice(name.as_bytes());
    sys(5, &mut a)
}

fn map(kind: u32, key: u32, value: u32, max: u32) -> i64 {
    let mut a = vec![0u8; 64];
    for (i, v) in [kind, key, value, max, 0].iter().enumerate() {
        a[i * 4..i * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    a[28..32].copy_from_slice(b"mapn");
    sys(0, &mut a)
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
fn pins_ids_and_fds_by_id() {
    let _g = serial();
    let p = load(1, &ret(0), "pinned");
    assert!(p >= 3);
    let path = std::ffi::CString::new("/sys/fs/bpf/p1").unwrap();
    let mut a = vec![0u8; 16];
    a[0..8].copy_from_slice(&(path.as_ptr() as u64).to_le_bytes());
    a[8..12].copy_from_slice(&(p as u32).to_le_bytes());
    assert_eq!(sys(6, &mut a), 0);
    assert_eq!(sys(6, &mut a), -17, "pinned already");
    let got = sys(7, &mut a);
    assert!(got > p, "OBJ_GET: a new descriptor");
    assert!(fake::fds(|t| t.cloexec(got as usize)));
    let none = std::ffi::CString::new("/sys/fs/bpf/none").unwrap();
    a[0..8].copy_from_slice(&(none.as_ptr() as u64).to_le_bytes());
    assert_eq!(sys(7, &mut a), -2);
    a[0..8].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(sys(7, &mut a), -14);
    a[0..8].copy_from_slice(&(none.as_ptr() as u64).to_le_bytes());
    a[8..12].copy_from_slice(&1u32.to_le_bytes()); // stdout
    assert_eq!(sys(6, &mut a), -22, "not a bpf object");
    a[8..12].copy_from_slice(&900u32.to_le_bytes());
    assert_eq!(sys(6, &mut a), -9);
    // Object info: the id, then walk the ids
    let mut info = vec![0u8; 256];
    let mut q = u32s(&[p as u32, 256]);
    q[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(15, &mut q), 0);
    assert_eq!(u32::from_le_bytes(q[4..8].try_into().unwrap()), 228, "bpf_prog_info size");
    assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 1, "socket filter");
    let id = u32::from_le_bytes(info[4..8].try_into().unwrap());
    assert_eq!(u32::from_le_bytes(info[20..24].try_into().unwrap()), 16, "two instructions");
    assert_eq!(&info[64..70], b"pinned");
    let mut by_id = u32s(&[id]);
    let fd2 = sys(13, &mut by_id);
    assert!(fd2 >= 3);
    let mut next = u32s(&[id - 1]);
    assert_eq!(sys(11, &mut next), 0);
    assert_eq!(u32::from_le_bytes(next[4..8].try_into().unwrap()), id);
    let mut next = u32s(&[u32::MAX - 1]);
    assert_eq!(sys(11, &mut next), -2);
    assert_eq!(sys(13, &mut u32s(&[u32::MAX - 5])), -2);
    // Maps: info, next id, fd by id, freeze
    let m = map(2, 4, 8, 4);
    assert!(m >= 3);
    let mut q = u32s(&[m as u32, 40]);
    q[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(15, &mut q), 0);
    assert_eq!(u32::from_le_bytes(q[4..8].try_into().unwrap()), 40, "cut to the caller's size");
    assert_eq!([info[0], info[8], info[12], info[16]], [2, 4, 8, 4]);
    assert_eq!(&info[24..28], b"mapn");
    let mid = u32::from_le_bytes(info[4..8].try_into().unwrap());
    let mut next = u32s(&[mid - 1]);
    assert_eq!(sys(12, &mut next), 0);
    assert!(sys(14, &mut u32s(&[mid])) >= 3);
    assert_eq!(sys(22, &mut u32s(&[m as u32])), 0);
    assert_eq!(sys(22, &mut u32s(&[p as u32])), -22, "not a map");
    // A frozen map refuses updates from the system call
    let key = 0u32.to_le_bytes();
    let val = [1u8; 8];
    let mut e = vec![0u8; 32];
    e[0..4].copy_from_slice(&(m as u32).to_le_bytes());
    e[8..16].copy_from_slice(&(key.as_ptr() as u64).to_le_bytes());
    e[16..24].copy_from_slice(&(val.as_ptr() as u64).to_le_bytes());
    assert_ne!(sys(2, &mut e), 0);
    // BTF: kept
    let b = sys(18, &mut vec![0u8; 32]);
    let mut q = u32s(&[b as u32, 32]);
    q[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(15, &mut q), 0);
    assert!(u32::from_le_bytes(info[16..20].try_into().unwrap()) > 0);
    // Info into a bad buffer; info of a non-object
    let mut q = u32s(&[p as u32, 16]);
    assert_eq!(sys(15, &mut q), -14);
    assert_eq!(sys(15, &mut u32s(&[1, 16])), -22);
    // Unknown commands; size and privilege
    assert_eq!(sys(99, &mut vec![0u8; 16]), -22);
    assert_eq!(bpf::sys_bpf(0, 0, 8192), -7);
    assert_eq!(bpf::sys_bpf(0, 0, 16), -14);
    fake::CAPS.set(Some(0));
    assert_eq!(sys(0, &mut vec![0u8; 16]), -1);
    // The device's answers
    let d = match fake::fds(|t| t.get(p as usize).cloned()) {
        Some(FileDescriptor::Device(d)) => d,
        _ => unreachable!(),
    };
    assert_eq!(d.read(&mut [0u8; 4]), -22);
    assert_eq!((d.poll_events(), d.rdev(), d.nonblock()), (0, 0, false));
    assert!(d.path().starts_with("anon_inode:bpf"));
    d.set_nonblock(true);
    let mut w = hydra_hosttests_t33::task::wait::WaitSet::new();
    d.add_wait_queues(&mut w);
}

#[test]
fn attaching_detaching_and_querying_cgroup_programs() {
    let _g = serial();
    let cg = cgroup_fd("/user.slice/");
    let skb = load(8, &ret(1), "skb");
    let skb2 = load(8, &ret(1), "skb2");
    let dev = load(15, &ret(1), "dev");
    // Wrong kind for the hook; not a cgroup; not a program
    assert_eq!(sys(8, &mut u32s(&[cg, dev as u32, 0])), -22, "a device program on ingress");
    let notcg = fake::fds_mut(|t| t.alloc_fd(FileDescriptor::File { path: "/etc/x".into(), cursor: hydra_hosttests_t33::fs::FileCursor::new(0), readable: true, writable: false, append: false, shown: None }).unwrap()) as u32;
    assert_eq!(sys(8, &mut u32s(&[notcg, skb as u32, 0])), -22);
    assert_eq!(sys(8, &mut u32s(&[1, skb as u32, 0])), -22, "stdout");
    assert_eq!(sys(8, &mut u32s(&[777, skb as u32, 0])), -9);
    assert_eq!(sys(8, &mut u32s(&[cg, 1, 0])), -22);
    // Attach two with ALLOW_MULTI, then replace without it
    assert_eq!(sys(8, &mut u32s(&[cg, skb as u32, 0, 2])), 0);
    assert_eq!(sys(8, &mut u32s(&[cg, skb2 as u32, 0, 2])), 0);
    let mut ids = [0u32; 4];
    let query = |room: u32, ids: &mut [u32; 4]| {
        let mut q = u32s(&[cg, 0, 0, 0]);
        q[16..24].copy_from_slice(&(ids.as_mut_ptr() as u64).to_le_bytes());
        q[24..28].copy_from_slice(&room.to_le_bytes());
        let r = sys(16, &mut q);
        (r, u32::from_le_bytes(q[24..28].try_into().unwrap()))
    };
    assert_eq!(query(4, &mut ids), (0, 2));
    assert_eq!(query(1, &mut ids), (-28, 2), "room for one");
    assert_eq!(sys(8, &mut u32s(&[cg, skb as u32, 0, 0])), 0);
    assert_eq!(query(4, &mut ids), (0, 1));
    // Query with no buffer: just the count
    let mut q = u32s(&[cg, 0]);
    assert_eq!(sys(16, &mut q), 0);
    assert_eq!(sys(16, &mut u32s(&[777, 0])), -9);
    // Detach a named program, then any, then nothing left
    assert_eq!(sys(9, &mut u32s(&[cg, skb2 as u32, 0])), -2, "not attached");
    assert_eq!(sys(9, &mut u32s(&[cg, skb as u32, 0])), 0);
    assert_eq!(sys(9, &mut u32s(&[cg, 0, 0])), -2);
    assert_eq!(sys(9, &mut u32s(&[777, 0, 0])), -9);
    // Kinds and hooks
    let sock = load(9, &ret(1), "sock");
    assert_eq!(sys(8, &mut u32s(&[cg, sock as u32, 2])), 0);
    let addr = load(18, &ret(1), "addr");
    assert_eq!(sys(8, &mut u32s(&[cg, addr as u32, 9])), 0);
    let sysctl = load(23, &ret(1), "sysctl");
    assert_eq!(sys(8, &mut u32s(&[cg, sysctl as u32, 18])), 0);
    let filter = load(1, &ret(1), "filter");
    assert_eq!(sys(8, &mut u32s(&[cg, filter as u32, 0])), -22, "a socket filter attaches to no cgroup hook");
    // Test runs are only for packet programs
    let mut t = u32s(&[sysctl as u32]);
    assert_eq!(sys(10, &mut t), -524);
    let pkt = [0u8; 20];
    let mut t = u32s(&[skb as u32, 0, 10]);
    t[16..24].copy_from_slice(&(pkt.as_ptr() as u64).to_le_bytes());
    assert_eq!(sys(10, &mut t), -22, "shorter than an Ethernet header");
    let mut t = u32s(&[skb as u32, 0, 20, 4]);
    t[16..24].copy_from_slice(&(pkt.as_ptr() as u64).to_le_bytes());
    let mut out = [0u8; 4];
    t[24..32].copy_from_slice(&(out.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(10, &mut t), -28, "the packet did not fit the output");
    assert_eq!(sys(10, &mut u32s(&[777])), -9);
}

#[test]
fn links_attach_until_detached() {
    let _g = serial();
    let cg = cgroup_fd("/links");
    let dev = load(15, &deny_major(1), "devl");
    assert_eq!(sys(28, &mut u32s(&[dev as u32, cg, 0])), -22, "wrong hook for the kind");
    assert_eq!(sys(28, &mut u32s(&[1, cg, 6])), -22);
    assert_eq!(sys(28, &mut u32s(&[dev as u32, 777, 6])), -9);
    let l = sys(28, &mut u32s(&[dev as u32, cg, 6]));
    assert!(l >= 3);
    let mut info = vec![0u8; 64];
    let mut q = u32s(&[l as u32, 64]);
    q[8..16].copy_from_slice(&(info.as_mut_ptr() as u64).to_le_bytes());
    assert_eq!(sys(15, &mut q), 0);
    assert_eq!(u32::from_le_bytes(info[0..4].try_into().unwrap()), 3, "cgroup link");
    assert_eq!(u32::from_le_bytes(info[24..28].try_into().unwrap()), 6);
    let lid = u32::from_le_bytes(info[4..8].try_into().unwrap());
    let mut next = u32s(&[lid - 1]);
    assert_eq!(sys(31, &mut next), 0);
    assert!(sys(30, &mut u32s(&[lid])) >= 3);
    // The link's program is in force for the cgroup's processes
    fake::IDS.set((3000, 3000));
    fake::PROCS.lock().insert(3000, fake::Process { cgroup: Some(Arc::from("/links/child")), ..Default::default() });
    assert_eq!(bpf::device_check(DEV_CHAR, 1, 3, DEV_READ), Err(-1));
    assert_eq!(bpf::device_check(DEV_CHAR, 4, 1, DEV_READ | DEV_WRITE), Ok(()));
    // A process outside the cgroup
    fake::PROCS.lock().insert(3000, fake::Process { cgroup: Some(Arc::from("/other")), ..Default::default() });
    assert_eq!(bpf::device_check(DEV_CHAR, 1, 3, DEV_READ), Ok(()));
    // Detach: no longer in force; twice is fine; not a link
    assert_eq!(sys(34, &mut u32s(&[l as u32])), 0);
    assert_eq!(sys(34, &mut u32s(&[l as u32])), 0);
    fake::PROCS.lock().insert(3000, fake::Process { cgroup: Some(Arc::from("/links")), ..Default::default() });
    assert_eq!(bpf::device_check(DEV_CHAR, 1, 3, DEV_READ), Ok(()));
    assert_eq!(sys(34, &mut u32s(&[dev as u32])), -22);
    assert_eq!(sys(34, &mut u32s(&[777])), -9);
    fake::PROCS.lock().remove(&3000);
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
