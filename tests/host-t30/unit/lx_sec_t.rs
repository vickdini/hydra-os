//! `src/lx/sec.rs`: bpf map element commands through the copy area.

use super::*;
use crate::ipc::protocol::LX_DATA_SIZE;

fn bpf(cmd: u64, size: u64) -> LxCall {
    let mut c = LxCall::EMPTY;
    c.nr = NR_BPF;
    c.args = [cmd, 0x1000, size, 0xA, 0xB, 0xC];
    c
}

fn head(key: u64, val: u64) -> [u8; ATTR_HEAD] {
    let mut h = [0u8; ATTR_HEAD];
    h[8..16].copy_from_slice(&key.to_le_bytes());
    h[16..24].copy_from_slice(&val.to_le_bytes());
    h
}

#[test]
fn clear_and_attribute_length() {
    let mut c = bpf(1, 24);
    bpf_clear(&mut c);
    assert_eq!(&c.args[3..], &[0, 0, 0]);
    assert_eq!(attr_len(&c), ATTR_HEAD);
    assert_eq!(attr_len(&bpf(1, 8)), 4);
    // Other calls keep their words
    let mut o = bpf(1, 24);
    o.nr = 250;
    bpf_clear(&mut o);
    assert_eq!(o.args[3], 0xA);
    assert_eq!(attr_len(&o), 4);
}

#[test]
fn prepare_puts_key_and_value_by_command() {
    let tag = 4 | 8 << 32;
    let h = head(0x10, 0x20);
    let mut c = bpf(1, 24);
    bpf_prepare(&mut c, &h, LX_OBJ_KIND_BPF_MAP, tag);
    assert_eq!(&c.args[3..], &[0x10, 0x20, 4 | 8 << 20 | V_OUT]);
    let mut c = bpf(21, 24);
    bpf_prepare(&mut c, &h, LX_OBJ_KIND_BPF_MAP, tag);
    assert_eq!(c.args[5] & V_OUT, V_OUT);
    let mut c = bpf(2, 24);
    bpf_prepare(&mut c, &h, LX_OBJ_KIND_BPF_MAP, tag);
    assert_eq!(&c.args[3..], &[0x10, 0x20, 4 | 8 << 20 | V_IN]);
    let mut c = bpf(3, 24);
    bpf_prepare(&mut c, &h, LX_OBJ_KIND_BPF_MAP, tag);
    assert_eq!(&c.args[3..], &[0x10, 0, 4 | 8 << 20]);
    let mut c = bpf(4, 24);
    bpf_prepare(&mut c, &h, LX_OBJ_KIND_BPF_MAP, tag);
    assert_eq!(&c.args[3..], &[0x10, 0x20, 4 | 4 << 20 | V_OUT]);
    // Not an element command, not a map, no tag, a short head, another call: unchanged
    for (cmd, kind, t, n, nr) in [(5, LX_OBJ_KIND_BPF_MAP, tag, 24, NR_BPF), (1, 2, tag, 24, NR_BPF), (1, LX_OBJ_KIND_BPF_MAP, 0, 24, NR_BPF), (1, LX_OBJ_KIND_BPF_MAP, tag, 8, NR_BPF), (1, LX_OBJ_KIND_BPF_MAP, tag, 24, 250)] {
        let mut c = bpf(cmd, 24);
        c.nr = nr;
        bpf_prepare(&mut c, &h[..n], kind, t);
        assert_eq!(&c.args[3..], &[0xA, 0xB, 0xC]);
    }
}

#[test]
fn desc_adds_the_key_and_value() {
    let base: Desc = [Arg::None; 6];
    let d = bpf_desc(base, NR_BPF, &[0, 0, 0, 1, 2, 4 | 8 << 20 | V_OUT]);
    assert!(matches!(d[3], Arg::In(l) if l.fixed == 4));
    assert!(matches!(d[4], Arg::Out(l) if l.fixed == 8));
    let d = bpf_desc(base, NR_BPF, &[0, 0, 0, 1, 2, 4 | 8 << 20 | V_IN]);
    assert!(matches!(d[4], Arg::In(l) if l.fixed == 8));
    let d = bpf_desc(base, NR_BPF, &[0, 0, 0, 1, 0, 4]);
    assert!(matches!(d[4], Arg::None));
    // Too large to fit: not copied
    let big = LX_DATA_SIZE as u64 + 1;
    let d = bpf_desc(base, NR_BPF, &[0, 0, 0, 1, 2, big | big << 20 | V_OUT]);
    assert!(matches!(d[3], Arg::None) && matches!(d[4], Arg::None));
    // Another call, or nothing described
    assert!(matches!(bpf_desc(base, 250, &[0, 0, 0, 1, 2, 4 | V_OUT])[3], Arg::None));
    assert!(matches!(bpf_desc(base, NR_BPF, &[0; 6])[3], Arg::None));
}
