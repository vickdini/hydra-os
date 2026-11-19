//! # lx-sec's kernel side (wave 6, Group 24)
//!
//! Keys and bpf moved out of linux-server into their own service, lx-sec
//! (`userland/drivers/lx-sec`, `LXS_SEC`, endpoint 0x31). Routing, restart and the rest are
//! the generic service machinery; what is specific to lx-sec lives here.
//!
//! ## bpf map element commands through the copy area
//!
//! `bpf(BPF_MAP_LOOKUP_ELEM, attr, size)` names its key and value by pointers *inside* the
//! attribute block, which the copy-in table cannot see: the server had to fetch the key and
//! store the value with two client-memory calls (about 0.8 us each), which put a forwarded
//! lookup over the 3 us budget. The `T_FDAT1` step reads the block's first word anyway (the
//! map's descriptor); it now reads its first 24 bytes, and for a bpf map object and an element
//! command [`bpf_prepare`] puts the key and value pointers into the call's unused argument
//! words `args[3]` and `args[4]` (bpf has three arguments; the kernel clears 3 to 5 first, so
//! nothing the program left in those registers reaches the server), with the lengths in
//! `args[5]`. [`bpf_fill`] then copies them like any other pointer argument: the key in, the
//! value in (update) or room for it out (lookup), so the server's `Cx::copy_in`/`copy_out`
//! find them in the page. The lengths come from the object's tag, which lx-sec sets when it
//! installs a map's descriptor (`key_size | user_value_size << 32`).

use crate::ipc::protocol::{LxCall, LX_OBJ_KIND_BPF_MAP};
use crate::lx::copy::{self, fixed, Arg, CopyBuf};

/// bpf's system call number.
pub const NR_BPF: u64 = 321;
/// Bytes of the attribute block [`bpf_prepare`] looks at: map fd (4), pad (4), key (8),
/// value (8).
pub const ATTR_HEAD: usize = 24;

/// `args[5]`: the value is output (lookup).
const V_OUT: u64 = 1 << 40;
/// `args[5]`: the value is input (update).
const V_IN: u64 = 1 << 41;

/// Clears bpf's unused argument words (before anything else looks at them).
pub fn bpf_clear(c: &mut LxCall) {
    if c.nr == NR_BPF {
        c.args[3] = 0;
        c.args[4] = 0;
        c.args[5] = 0;
    }
}

/// How many bytes of the attribute block to read for the `T_FDAT1` step: [`ATTR_HEAD`] when
/// the caller's block is that long, otherwise just the descriptor.
pub fn attr_len(c: &LxCall) -> usize {
    if c.nr == NR_BPF && c.args[2] as usize >= ATTR_HEAD {
        ATTR_HEAD
    } else {
        4
    }
}

/// A bpf call whose attribute block names a server object of kind `kind` with tag `tag`
/// (`head`: the block's first bytes, as read): for a map element command, the key and value
/// pointers go to `args[3]`/`args[4]` and their lengths to `args[5]`, for [`bpf_fill`].
pub fn bpf_prepare(c: &mut LxCall, head: &[u8], kind: u32, tag: u64) {
    if c.nr != NR_BPF || kind != LX_OBJ_KIND_BPF_MAP || tag == 0 || head.len() < ATTR_HEAD {
        return;
    }
    let key = u64::from_le_bytes(head[8..16].try_into().unwrap());
    let val = u64::from_le_bytes(head[16..24].try_into().unwrap());
    let (klen, vlen) = (tag & 0xF_FFFF, (tag >> 32) & 0xF_FFFF);
    let mode = match c.args[0] {
        // LOOKUP_ELEM, LOOKUP_AND_DELETE_ELEM: key in, value out
        1 | 21 => V_OUT,
        // UPDATE_ELEM: key and value in
        2 => V_IN,
        // DELETE_ELEM: the key only
        3 => 0,
        // GET_NEXT_KEY: key in (may be NULL), the next key out where the value pointer is
        4 => {
            c.args[3] = key;
            c.args[4] = val;
            c.args[5] = klen | klen << 20 | V_OUT;
            return;
        }
        _ => return,
    };
    c.args[3] = key;
    c.args[4] = if mode == 0 { 0 } else { val };
    c.args[5] = klen | vlen << 20 | mode;
}

/// Copies what [`bpf_prepare`] described into `buf` (after the ordinary [`copy::fill`]).
/// What does not fit is simply not copied (the server falls back by itself).
///
/// # Errors
///
/// `-EFAULT` for a key or input value that faults (as Linux's copy of the key would).
pub fn bpf_fill(buf: &mut CopyBuf, nr: u64, args: &[u64; 6]) -> Result<(), i64> {
    let x = args[5];
    // (only bpf: other calls' sixth argument is theirs)
    if nr != NR_BPF || x == 0 {
        return Ok(());
    }
    let (klen, vlen) = (x & 0xF_FFFF, (x >> 20) & 0xF_FFFF);
    let fits = |n: u64| n > 0 && n <= crate::ipc::protocol::LX_DATA_SIZE as u64;
    let key = if fits(klen) { Arg::In(fixed(klen as u16)) } else { Arg::None };
    let value = if !fits(vlen) {
        Arg::None
    } else if x & V_OUT != 0 {
        Arg::Out(fixed(vlen as u16))
    } else if x & V_IN != 0 {
        Arg::In(fixed(vlen as u16))
    } else {
        Arg::None
    };
    copy::fill(buf, &[Arg::None, Arg::None, Arg::None, key, value, Arg::None], args)
}
