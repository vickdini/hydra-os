//! linux-server's `execplan.rs` and the kernel's `xplan.rs`: `execve`'s front half.

use hydra_hosttests_w7_41::execplan::{self, elf_interp, encode_plan, join_path, parse_shebang, script_prefix, trim_nul, Interp, PLAN_HEAD};
use hydra_hosttests_w7_41::xplan::{decode_plan, ExecPlan};

fn v(s: &str) -> Vec<u8> {
    s.as_bytes().to_vec()
}

#[test]
fn shebang_lines() {
    assert_eq!(parse_shebang(b"#!/bin/sh\necho"), Some((v("/bin/sh"), None)));
    assert_eq!(parse_shebang(b"#! \t/usr/bin/env  python3 -u \r\nx"), Some((v("/usr/bin/env"), Some(v("python3 -u")))));
    assert_eq!(parse_shebang(b"#!/bin/sh"), Some((v("/bin/sh"), None)), "no newline");
    assert_eq!(parse_shebang(b"#!\n"), None, "no interpreter");
    assert_eq!(parse_shebang(b"#!   \n"), None);
    assert_eq!(parse_shebang(b"#"), None);
    assert_eq!(parse_shebang(b"\x7fELF"), None);
    assert_eq!(parse_shebang(b""), None);
    // The line is cut at 256 bytes
    let mut long = b"#!/".to_vec();
    long.extend(std::iter::repeat(b'a').take(400));
    let (i, a) = parse_shebang(&long).unwrap();
    assert_eq!(i.len(), 254);
    assert_eq!(a, None);
}

/// A 64-bit ELF header with `n` program headers at 64; header `k` is PT_INTERP pointing at
/// (`off`, `len`) when given.
fn elf(n: u16, interp: Option<(usize, u64, u64)>, total: usize) -> Vec<u8> {
    let mut b = vec![0u8; total];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2;
    b[5] = 1;
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&n.to_le_bytes());
    for k in 0..n as usize {
        let o = 64 + k * 56;
        if o + 56 > total {
            break;
        }
        b[o..o + 4].copy_from_slice(&1u32.to_le_bytes());
    }
    if let Some((k, off, len)) = interp.filter(|&(k, _, _)| 64 + k * 56 + 40 <= total) {
        let o = 64 + k * 56;
        b[o..o + 4].copy_from_slice(&3u32.to_le_bytes());
        b[o + 8..o + 16].copy_from_slice(&off.to_le_bytes());
        b[o + 32..o + 40].copy_from_slice(&len.to_le_bytes());
    }
    b
}

#[test]
fn elf_interpreters() {
    let mut b = elf(4, Some((1, 0x200, 28)), 1024);
    b[0x200..0x200 + 28].copy_from_slice(b"/lib64/ld-linux-x86-64.so.2\0");
    assert_eq!(elf_interp(&b), Interp::Path(v("/lib64/ld-linux-x86-64.so.2")));
    // Past the head: its place
    let b = elf(4, Some((2, 0x800, 28)), 1024);
    assert_eq!(elf_interp(&b), Interp::At(0x800, 28));
    // Static: none
    assert_eq!(elf_interp(&elf(4, None, 1024)), Interp::None);
    // Not ELF, 32-bit, big-endian, short
    assert_eq!(elf_interp(b"#!/bin/sh\n"), Interp::None);
    let mut b32 = elf(1, Some((0, 0x100, 4)), 512);
    b32[4] = 1;
    assert_eq!(elf_interp(&b32), Interp::None);
    let mut be = elf(1, Some((0, 0x100, 4)), 512);
    be[5] = 2;
    assert_eq!(elf_interp(&be), Interp::None);
    assert_eq!(elf_interp(&elf(1, None, 64)), Interp::None);
    // Program headers past the head count as none (the kernel asks by path then)
    assert_eq!(elf_interp(&elf(40, Some((30, 0x100, 4)), 512)), Interp::None);
    // Bad lengths
    assert_eq!(elf_interp(&elf(2, Some((0, 0x100, 0)), 512)), Interp::None);
    assert_eq!(elf_interp(&elf(2, Some((0, 0x100, 5000)), 512)), Interp::None);
    assert_eq!(elf_interp(&elf(2, Some((0, u64::MAX - 1, 10)), 512)), Interp::None);
    let mut small = elf(2, None, 512);
    small[54..56].copy_from_slice(&20u16.to_le_bytes());
    assert_eq!(elf_interp(&small), Interp::None, "phentsize too small");
    assert_eq!(trim_nul(b"ab\0cd"), b"ab");
    assert_eq!(trim_nul(b"ab"), b"ab");
}

#[test]
fn script_argv() {
    // One level: interp [arg] script, then argv[1..] (the kernel adds those)
    let p = script_prefix(&[], b"/bin/sh", None, b"./s");
    assert_eq!(p, vec![v("/bin/sh"), v("./s")]);
    let p = script_prefix(&[], b"/usr/bin/env", Some(b"python3"), b"/x/s.py");
    assert_eq!(p, vec![v("/usr/bin/env"), v("python3"), v("/x/s.py")]);
    // Two levels: the second interpreter replaces the first's name
    let p2 = script_prefix(&p, b"/i2", Some(b"a2"), b"/usr/bin/env");
    assert_eq!(p2, vec![v("/i2"), v("a2"), v("/usr/bin/env"), v("python3"), v("/x/s.py")]);
}

#[test]
fn lexical_paths() {
    assert_eq!(join_path(b"/usr/bin", b"python3"), v("/usr/bin/python3"));
    assert_eq!(join_path(b"/usr/bin", b"/bin/sh"), v("/bin/sh"));
    assert_eq!(join_path(b"/a/b", b"../c/./d//e"), v("/a/c/d/e"));
    assert_eq!(join_path(b"/", b".."), v("/"));
    assert_eq!(join_path(b"/a", b""), v("/a"));
    assert_eq!(join_path(b"", b"x"), v("/x"));
}

#[test]
fn plans_round_trip() {
    let pre = vec![v("/bin/sh"), v("-e"), v("./s")];
    let b = encode_plan(77, 99, b"/usr/lib/x/prog", false, &pre, b"/lib64/ld.so", 3000).unwrap();
    assert_eq!(b.len(), PLAN_HEAD + 15 + (8 + 3 + 4) + 12);
    let p = decode_plan(&b).unwrap();
    assert_eq!(p, ExecPlan { ino: 77, shown: "/usr/lib/x/prog".into(), prefix: pre.clone(), interp: Some(("/lib64/ld.so".into(), 99)) });
    // No script, no interpreter (static), interpreter not found
    let p = decode_plan(&encode_plan(5, 0, b"/bin/x", true, &[], b"", 3000).unwrap()).unwrap();
    assert_eq!(p, ExecPlan { ino: 5, shown: "/bin/x".into(), prefix: vec![], interp: None });
    let p = decode_plan(&encode_plan(5, 0, b"/bin/x", true, &[], b"/nope", 3000).unwrap()).unwrap();
    assert_eq!(p.interp, Some(("/nope".into(), 0)));
    // An empty argv string survives (`#!/bin/sh ""` cannot make one, but the encoding allows it)
    let pre = vec![v("a"), v(""), v("b")];
    assert_eq!(decode_plan(&encode_plan(1, 0, b"/a", true, &pre, b"", 3000).unwrap()).unwrap().prefix, pre);
    // Too large for the room: None
    assert_eq!(encode_plan(1, 0, b"/a", true, &[], b"", PLAN_HEAD), None);
    assert!(encode_plan(1, 0, b"/a", true, &[], b"", PLAN_HEAD + 2).is_some());
}

#[test]
fn bad_plans_are_refused() {
    let good = encode_plan(7, 0, b"/bin/x", true, &[v("/bin/sh"), v("s")], b"", 3000).unwrap();
    assert!(decode_plan(&good).is_some());
    // Short, cut, no program, no path
    assert_eq!(decode_plan(&good[..10]), None);
    assert_eq!(decode_plan(&good[..good.len() - 1]), None);
    let mut zero = good.clone();
    zero[..8].copy_from_slice(&0u64.to_le_bytes());
    assert_eq!(decode_plan(&zero), None);
    let nopath = encode_plan(7, 0, b"", true, &[], b"", 3000).unwrap();
    assert_eq!(decode_plan(&nopath), None);
    // The string count disagrees with the strings
    let mut count = good.clone();
    count[20..24].copy_from_slice(&3u32.to_le_bytes());
    assert_eq!(decode_plan(&count), None);
    // Strings without their last NUL
    let mut nonul = good.clone();
    let end = PLAN_HEAD + 6 + 10;
    nonul[end - 1] = b'x';
    assert_eq!(decode_plan(&nonul), None);
    // Huge lengths do not overflow
    let mut huge = good.clone();
    huge[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    huge[24..28].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(decode_plan(&huge), None);
    let _ = execplan::INTERP_MAX;
}
