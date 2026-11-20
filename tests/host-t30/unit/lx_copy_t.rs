//! `src/lx/copy.rs`: the table, `fill` (strings, inputs, outputs, faults, room), output,
//! user memory with fault-ins.

use super::*;
use crate::ipc::protocol::LxCopy;

const EFAULT: i64 = -14;

fn setup() -> std::sync::MutexGuard<'static, ()> {
    let g = crate::world::serial();
    crate::fake::reset();
    crate::fake::user_space_on();
    g
}

#[test]
fn the_table_describes_each_call() {
    let a = [0u64; 6];
    for nr in [248, 249, 242, 243, 65, 220, 69, 70, 321, 0, 1, 19, 20, 286, 287, 282, 289, 42, 49, 43, 288, 51, 52, 44, 45, 46, 47, 54, 55, 53] {
        assert!(describe(nr, &a).is_some(), "{nr}");
    }
    assert!(describe(39, &a).is_none());
    for op in [1, 2, 6, 11, 17, 10, 31] {
        assert!(describe(250, &[op, 0, 0, 0, 0, 0]).is_some(), "keyctl {op}");
    }
    assert!(describe(250, &[99, 0, 0, 0, 0, 0]).is_none());
    // Lengths: a fixed size, an argument, a count times a size, too large
    assert_eq!(fixed(16).of(&a), Some(16));
    assert_eq!(len_arg(2).of(&[0, 0, 100, 0, 0, 0]), Some(100));
    assert_eq!(sembufs(2).of(&[0, 0, 3, 0, 0, 0]), Some(18));
    assert_eq!(len_arg(2).of(&[0, 0, LX_DATA_SIZE as u64 + 1, 0, 0, 0]), None);
    assert_eq!(Len { fixed: 0, arg: 2, mul: 2 }.of(&[0, 0, u64::MAX, 0, 0, 0]), None);
    assert_eq!(Len { fixed: 1, arg: 9, mul: 1 }.of(&a), None);
    assert_eq!(fixed_plus_arg(8, 2).of(&[0, 0, 4, 0, 0, 0]), Some(12));
}

#[test]
fn fill_copies_strings_inputs_and_makes_room_for_outputs() {
    let _g = setup();
    let s = b"name\0".to_vec();
    let inp = [1u8, 2, 3, 4];
    let desc: Desc = [Arg::Str(64), Arg::In(len_arg(2)), Arg::None, Arg::Out(fixed(8)), Arg::InOut(fixed(4)), Arg::Out(len_arg(2))];
    let args = [s.as_ptr() as u64, inp.as_ptr() as u64, 4, 0x1000, inp.as_ptr() as u64, 0];
    let mut h = LxCopy::EMPTY;
    let mut data = [0u8; LX_DATA_SIZE];
    let used = fill(&mut h, &mut data, &desc, &args).unwrap();
    // The string with its NUL, then the input, the output room, the in-out bytes
    assert_eq!((h.in_off[0], h.in_len[0]), (LX_DATA_OFF as u16, 4));
    assert_eq!(&data[..5], b"name\0");
    assert_eq!((h.in_off[1], h.in_len[1]), (LX_DATA_OFF as u16 + 5, 4));
    assert_eq!((h.out_off[3], h.out_cap[3]), (LX_DATA_OFF as u16 + 9, 8));
    assert_eq!((h.in_off[4], h.out_off[4], h.out_cap[4]), (LX_DATA_OFF as u16 + 17, LX_DATA_OFF as u16 + 17, 4));
    // A NULL pointer is never copied
    assert_eq!(h.out_cap[5], 0);
    assert_eq!(used, 21);
}

#[test]
fn fill_skips_what_does_not_fit() {
    let _g = setup();
    let long = vec![b'x'; 100];
    let big = vec![0u8; LX_DATA_SIZE];
    // A string without a NUL within its limit; an input larger than what is left; an
    // empty input; an output that only partly fits
    let desc: Desc = [Arg::Str(16), Arg::In(len_arg(2)), Arg::In(len_arg(3)), Arg::Out(fixed(4000)), Arg::Str(8), Arg::None];
    let args = [long.as_ptr() as u64, big.as_ptr() as u64, LX_DATA_SIZE as u64, 0, 0x1000, long.as_ptr() as u64];
    let mut h = LxCopy::EMPTY;
    let mut data = [0u8; LX_DATA_SIZE];
    let used = fill(&mut h, &mut data, &desc, &[args[0], args[1], args[2], 0, args[4], args[5]]).unwrap();
    assert_eq!(h.in_off[0], 0);
    assert_eq!((h.in_off[1], h.in_len[1] as usize), (LX_DATA_OFF as u16, LX_DATA_SIZE));
    assert_eq!(h.out_cap[3], 0);
    assert_eq!(used, LX_DATA_SIZE);
    // No room left for a string
    let desc2: Desc = [Arg::In(len_arg(2)), Arg::Str(8), Arg::None, Arg::None, Arg::None, Arg::None];
    let s = b"a\0".to_vec();
    let mut h = LxCopy::EMPTY;
    assert_eq!(fill(&mut h, &mut data, &desc2, &[big.as_ptr() as u64, s.as_ptr() as u64, LX_DATA_SIZE as u64, 0, 0, 0]).unwrap(), LX_DATA_SIZE);
    assert_eq!(h.in_off[1], 0);
    // An output whose length argument is too large takes what is left
    let desc3: Desc = [Arg::Out(len_arg(1)), Arg::None, Arg::None, Arg::None, Arg::None, Arg::None];
    let mut h = LxCopy::EMPTY;
    assert_eq!(fill(&mut h, &mut data, &desc3, &[0x1000, u64::MAX, 0, 0, 0, 0]).unwrap(), LX_DATA_SIZE);
    assert_eq!(h.out_cap[0] as usize, LX_DATA_SIZE);
}

#[test]
fn fill_reports_faults_and_missing_pages() {
    let _g = setup();
    let base = crate::fake::alloc_pages(2);
    let mut h = LxCopy::EMPTY;
    let mut data = [0u8; LX_DATA_SIZE];
    let ind: Desc = [Arg::In(fixed(16)), Arg::None, Arg::None, Arg::None, Arg::None, Arg::None];
    let strd: Desc = [Arg::Str(64), Arg::None, Arg::None, Arg::None, Arg::None, Arg::None];
    // An input spanning into a missing page: where it stopped and what is left
    crate::fake::make_missing(base + 4096, 1);
    assert_eq!(fill(&mut h, &mut data, &ind, &[base + 4088, 0, 0, 0, 0, 0]), Err(FillErr::Missing(base + 4096, 8)));
    assert_eq!(fill(&mut h, &mut data, &strd, &[base + 4096, 0, 0, 0, 0, 0]), Err(FillErr::Missing(base + 4096, 1)));
    // Kernel addresses and no address space: faults
    assert_eq!(fill(&mut h, &mut data, &ind, &[0xFFFF_8000_0000_0000, 0, 0, 0, 0, 0]), Err(FillErr::Fault));
    assert_eq!(fill(&mut h, &mut data, &strd, &[0xFFFF_8000_0000_0000, 0, 0, 0, 0, 0]), Err(FillErr::Fault));
    assert_eq!(fill(&mut h, &mut data, &strd, &[u64::MAX - 2, 0, 0, 0, 0, 0]), Err(FillErr::Fault));
    crate::memory::vm::CURRENT_MM.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    assert_eq!(fill(&mut h, &mut data, &ind, &[base, 0, 0, 0, 0, 0]), Err(FillErr::Fault));
}

#[test]
fn output_is_taken_within_the_kernels_room_and_copied_out() {
    let _g = setup();
    let mut b = CopyBuf::EMPTY;
    b.hdr.out_off[2] = LX_DATA_OFF as u16 + 8;
    b.hdr.out_cap[2] = 4;
    let mut page = [0u8; LX_DATA_SIZE];
    page[8..16].copy_from_slice(b"abcdefgh");
    // The server says 8; the room is 4: only 4; argument 0 had no room
    take_output(&mut b, &[5, 0, 8, 0, 0, 0], &page);
    assert_eq!(b.hdr.out_len, [0, 0, 4, 0, 0, 0]);
    assert!(has_output(&b));
    assert_eq!(b.used_bytes().len(), 0);
    let mut out = [0u8; 8];
    copy_out(&b, &[0, 0, out.as_mut_ptr() as u64, 0, 0, 0]).unwrap();
    assert_eq!(&out[..4], b"abcd");
    assert_eq!(copy_out(&b, &[0, 0, 0, 0, 0, 0]), Err(EFAULT));
    take_output(&mut b, &[0; 6], &page);
    assert!(!has_output(&b));
}

#[test]
fn user_memory_with_fault_ins() {
    let _g = setup();
    let base = crate::fake::alloc_pages(2);
    let mut buf = [0u8; 16];
    // A missing page is faulted in once
    crate::fake::make_missing(base + 4096, 1);
    let before = FAULT_INS.load(core::sync::atomic::Ordering::Relaxed);
    read_user(base + 4090, &mut buf).unwrap();
    assert_eq!(FAULT_INS.load(core::sync::atomic::Ordering::Relaxed), before + 1);
    write_user(base, b"hello\0").unwrap();
    let mut s = [0u8; 32];
    assert_eq!(read_user_str(base, &mut s), Ok(Some(5)));
    assert_eq!(read_user_str(base, &mut s[..3]), Ok(None));
    // A string whose page comes in on the way
    crate::fake::make_missing(base, 1);
    assert_eq!(read_user_str(base, &mut s), Ok(Some(5)));
    // Bad pages
    crate::fake::make_bad(base + 4096);
    assert_eq!(read_user(base + 4090, &mut buf), Err(EFAULT));
    assert_eq!(read_user_str(base + 4096, &mut s), Err(EFAULT));
    assert_eq!(read_user_str(0xFFFF_8000_0000_0000, &mut s), Err(EFAULT));
    assert_eq!(write_user(0xFFFF_8000_0000_0000, b"x"), Err(EFAULT));
    // Nothing to copy
    assert_eq!(read_user(0, &mut []), Ok(()));
    // No address space: nothing can be faulted in
    crate::memory::vm::CURRENT_MM.store(core::ptr::null_mut(), core::sync::atomic::Ordering::Release);
    assert!(!fault_in(base, 1, false));
    // SAFETY: zero bytes
    assert_eq!(unsafe { try_copy(buf.as_mut_ptr(), base as *const u8, 0) }, 0);
}

#[test]
fn a_page_faulting_again_is_bad() {
    let _g = setup();
    let base = crate::fake::alloc_pages(1);
    // fault_in "succeeds" but the page stays missing: the second fault at once fails
    crate::fake::make_missing(base, 1);
    crate::fake::BAD.lock().unwrap().clear();
    let mut b = [0u8; 4];
    // Make prefault leave the page missing by marking it bad only for translation:
    // simulate with a page that is missing again after each fault-in
    let r = with_faults(base, 4, false, |_| {
        crate::fake::make_missing(base, 1);
        4
    });
    assert_eq!(r, Err(EFAULT));
    let _ = &mut b;
    // lock_serving takes a free lock at once
    let m = spin::Mutex::new(5);
    assert_eq!(*lock_serving(&m), 5);
}
