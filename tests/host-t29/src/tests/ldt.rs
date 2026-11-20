//! `src/compat/linux/ldt.rs`: `set_thread_area`, `get_thread_area`, `modify_ldt`,
//! `arch_prctl` and the 32-bit `int $0x80` entry.

use super::common::*;
use crate::arch::segments::UserDesc;
use crate::compat::linux::ldt::*;
use crate::memory::vm::Mm;
use std::sync::Arc;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSYS: i64 = -38;

/// A `struct user_desc` for a present 32-bit data segment.
fn desc(entry: u32, base: u32, limit: u32) -> [u8; 16] {
    UserDesc {
        entry_number: entry,
        base_addr: base,
        limit,
        seg_32bit: true,
        contents: 0,
        read_exec_only: false,
        limit_in_pages: true,
        seg_not_present: false,
        useable: true,
        lm: false,
    }
    .bytes()
}

fn proc_(pid: u64) {
    spawn(pid, 1);
    run(pid);
}

/// `modify_ldt`'s result as the low 32 bits of `rax`, sign-extended (what a program sees).
fn ldt(func: u64, p: u64, n: u64) -> i64 {
    sys_modify_ldt(func, p, n) as u32 as i32 as i64
}

#[test]
fn thread_area_set_and_get() {
    let _g = setup();
    proc_(800);
    // entry -1: the first free one (12), written back
    let mut d = desc(u32::MAX, 0x1000, 0xfffff);
    assert_eq!(sys_set_thread_area(mptr(&mut d)), 0);
    assert_eq!(u32::from_le_bytes(d[0..4].try_into().unwrap()), 12);
    assert!(fake::called("set_current_tls(12,"));
    let mut d2 = desc(u32::MAX, 0x2000, 0xfff);
    assert_eq!(sys_set_thread_area(mptr(&mut d2)), 0);
    assert_eq!(u32::from_le_bytes(d2[0..4].try_into().unwrap()), 13);
    // get_thread_area reads it back as a user_desc
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&12u32.to_le_bytes());
    assert_eq!(sys_get_thread_area(mptr(&mut out)), 0);
    let u = UserDesc::parse(&out);
    assert_eq!((u.entry_number, u.base_addr, u.limit, u.seg_32bit, u.limit_in_pages, u.useable), (12, 0x1000, 0xfffff, true, true, true));
    // An explicit entry, then all three taken: -1 finds none
    let mut d3 = desc(14, 0x3000, 1);
    assert_eq!(sys_set_thread_area(mptr(&mut d3)), 0);
    let mut d4 = desc(u32::MAX, 0, 1);
    assert_eq!(sys_set_thread_area(mptr(&mut d4)), ESRCH);
    // Clearing an entry with an empty descriptor (LDT_empty) or an all-zero one
    let mut empty = UserDesc { entry_number: 13, read_exec_only: true, seg_not_present: true, ..Default::default() }.bytes();
    assert_eq!(sys_set_thread_area(mptr(&mut empty)), 0);
    assert_eq!(fake::task(800, |t| t.segs.tls[1]), Some(0));
    let mut zero = UserDesc { entry_number: 14, ..Default::default() }.bytes();
    assert_eq!(sys_set_thread_area(mptr(&mut zero)), 0);
    assert_eq!(fake::task(800, |t| t.segs.tls[2]), Some(0));
    // Not 32-bit, code, or not present: EINVAL
    let mut bad = UserDesc { entry_number: 12, base_addr: 1, seg_32bit: false, ..Default::default() }.bytes();
    assert_eq!(sys_set_thread_area(mptr(&mut bad)), EINVAL);
    let mut code = UserDesc { entry_number: 12, base_addr: 1, seg_32bit: true, contents: 2, ..Default::default() }.bytes();
    assert_eq!(sys_set_thread_area(mptr(&mut code)), EINVAL);
    let mut np = UserDesc { entry_number: 12, base_addr: 1, seg_32bit: true, seg_not_present: true, ..Default::default() }.bytes();
    assert_eq!(sys_set_thread_area(mptr(&mut np)), EINVAL);
    // Entries outside 12..=14
    let mut d5 = desc(11, 0, 1);
    assert_eq!(sys_set_thread_area(mptr(&mut d5)), EINVAL);
    let mut d6 = desc(15, 0, 1);
    assert_eq!(sys_set_thread_area(mptr(&mut d6)), EINVAL);
    out[0..4].copy_from_slice(&15u32.to_le_bytes());
    assert_eq!(sys_get_thread_area(mptr(&mut out)), EINVAL);
    assert_eq!(sys_set_thread_area(0), EFAULT);
    assert_eq!(sys_get_thread_area(0), EFAULT);
}

#[test]
fn modify_ldt_reads_and_writes() {
    let _g = setup();
    proc_(810);
    global_frames();
    let mm = Arc::new(spin::Mutex::new(Mm::new().unwrap()));
    fake::task(810, |t| t.mm = Some(mm.clone()));
    // A second thread sharing the address space, and another process
    add_thread(810, 811);
    fake::task(811, |t| t.mm = Some(mm.clone()));
    spawn(812, 1);
    // No LDT yet: reads return 0 bytes
    let mut buf = [0xffu8; 64];
    assert_eq!(ldt(0, mptr(&mut buf), 64), 0);
    // The default LDT: zeros, at most 128 bytes
    assert_eq!(ldt(2, mptr(&mut buf), 64), 64);
    assert!(buf.iter().all(|&b| b == 0));
    let mut big = [1u8; 200];
    assert_eq!(ldt(2, mptr(&mut big), 200), 128);
    assert!(big[..128].iter().all(|&b| b == 0) && big[128] == 1);
    // Write entry 2 (new mode), read it back
    let d = desc(2, 0x5000, 0xff);
    assert_eq!(ldt(0x11, ptr(&d), 16), 0);
    assert!(fake::called("publish_ldt(2)"));
    let mut buf = [0u8; 32];
    assert_eq!(ldt(0, mptr(&mut buf), 32), 32, "the whole buffer (Linux returns bytecount)");
    let raw = u64::from_le_bytes(buf[16..24].try_into().unwrap());
    let u = UserDesc::from_descriptor(2, raw);
    assert_eq!((u.base_addr, u.limit, u.useable), (0x5000, 0xff, true));
    assert_eq!(&buf[24..], &[0u8; 8], "zero-filled past the table");
    // Every thread of the address space got the same holder; the other process none
    let h0 = fake::task(810, |t| t.ldt.clone()).unwrap().unwrap();
    let h1 = fake::task(811, |t| t.ldt.clone()).unwrap().unwrap();
    assert!(Arc::ptr_eq(&h0, &h1));
    assert!(fake::task(812, |t| t.ldt.is_none()).unwrap());
    // A partial read cuts a descriptor
    let mut five = [0u8; 5];
    assert_eq!(ldt(0, mptr(&mut five), 5), 5);
    // Old mode: the "useable" bit is dropped; base and limit 0 clears the entry
    let d = desc(1, 0x6000, 0xff);
    assert_eq!(ldt(1, ptr(&d), 16), 0);
    let mut buf = [0u8; 24];
    assert_eq!(ldt(0, mptr(&mut buf), 24), 24);
    let u = UserDesc::from_descriptor(1, u64::from_le_bytes(buf[8..16].try_into().unwrap()));
    assert_eq!((u.base_addr, u.useable), (0x6000, false));
    let clear = UserDesc { entry_number: 1, seg_32bit: true, ..Default::default() }.bytes();
    assert_eq!(ldt(1, ptr(&clear), 16), 0);
    assert_eq!(ldt(0, mptr(&mut buf), 24), 24);
    assert_eq!(&buf[8..16], &[0u8; 8]);
    // Checks: size, entry, contents 3 (code, conforming) and unsupported segments
    assert_eq!(ldt(1, ptr(&d), 8), EINVAL);
    let far = desc(8192, 0, 1);
    assert_eq!(ldt(0x11, ptr(&far), 16), EINVAL);
    let conf = UserDesc { entry_number: 3, base_addr: 1, seg_32bit: true, contents: 3, ..Default::default() }.bytes();
    assert_eq!(ldt(1, ptr(&conf), 16), EINVAL, "old mode never takes contents 3");
    assert_eq!(ldt(0x11, ptr(&conf), 16), EINVAL, "new mode only if not present");
    let code16 = UserDesc { entry_number: 3, base_addr: 1, seg_32bit: false, contents: 2, ..Default::default() }.bytes();
    assert_eq!(ldt(0x11, ptr(&code16), 16), EINVAL, "only 32-bit data segments");
    assert_eq!(ldt(1, 0, 16), EFAULT);
    assert_eq!(ldt(7, 0, 0), ENOSYS);
    // The result is an int: an error reads as 0x00000000ffffffea in rax
    assert_eq!(sys_modify_ldt(7, 0, 0), 0xffff_ffda);
}

#[test]
fn modify_ldt_needs_an_address_space() {
    let _g = setup();
    proc_(815);
    let d = desc(0, 0x5000, 0xff);
    assert_eq!(ldt(0x11, ptr(&d), 16), EINVAL, "a task without an address space");
    // No current task at all
    fake::switch_to(0);
    assert_eq!(ldt(0x11, ptr(&d), 16), EINVAL);
}

#[test]
fn int80_serves_thread_area_only() {
    let _g = setup();
    proc_(820);
    // Arguments are 32-bit: a buffer below 4 GiB
    let arena = Arena::new(29);
    let p = arena.base;
    unsafe { *(p as *mut [u8; 16]) = desc(u32::MAX, 0x1000, 0xfffff) };
    assert_eq!(int80(243, p | 0xdead_0000_0000_0000), 0, "only the low 32 bits of ebx count");
    assert_eq!(int80(244, p), 0);
    let u = UserDesc::parse(unsafe { &*(p as *const [u8; 16]) });
    assert_eq!((u.entry_number, u.base_addr), (12, 0x1000));
    assert_eq!(int80(1, 0), ENOSYS, "everything else");
    // A task with a seccomp filter gets ENOSYS for all of it
    fake::task(820, |t| t.seccomp.mode = 2);
    assert_eq!(int80(244, 0), ENOSYS);
    fake::switch_to(0);
    assert_eq!(int80(244, 0), ENOSYS, "no task");
}

#[test]
fn arch_prctl_bases() {
    let _g = setup();
    proc_(830);
    assert_eq!(sys_arch_prctl(0x1002, 0x7000_0000), 0, "ARCH_SET_FS");
    assert_eq!(fake::task(830, |t| t.fs_base), Some(0x7000_0000));
    assert_eq!(sys_arch_prctl(0x1001, 0x7100_0000), 0, "ARCH_SET_GS");
    assert_eq!(fake::task(830, |t| t.segs.gs_base), Some(0x7100_0000));
    let mut v = 0u64;
    assert_eq!(sys_arch_prctl(0x1003, mptr(&mut v)), 0);
    assert_eq!(v, 0x7000_0000);
    assert_eq!(sys_arch_prctl(0x1004, mptr(&mut v)), 0);
    assert_eq!(v, 0x7100_0000);
    assert_eq!(sys_arch_prctl(0x1002, crate::memory::vm::USER_SPACE_END), EPERM, "a kernel address");
    assert_eq!(sys_arch_prctl(0x1003, 0), EFAULT);
    assert_eq!(sys_arch_prctl(0x9999, 0), EINVAL);
}
