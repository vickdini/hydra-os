//! In-memory tmpfs files (wave 9, Group M): their data is the kernel's (`fs::tmem`: a
//! memory object per file, which the kernel's handles read, write and map), their names
//! and attributes stay in the pool tree. The pool object of such a file stays empty, so
//! only a regular file of size 0 can be one: for those the kernel tells the real size,
//! blocks and data time ([`overlay`]), and the calls that change data or a file's last
//! name go to the kernel ([`is_tmem`]: truncation, data times, unlink, rename).

use hydra_rt::sys;

use crate::fs::fsproto::Attr;
use crate::proto::{LxTmemAttr, LX_FH_TMEM, LX_TMEM_ATTR, LX_TMEM_LIMIT};

/// What the kernel knows of `ino` if it is an in-memory file.
fn query(ino: u64) -> Option<LxTmemAttr> {
    let mut r = LxTmemAttr::default();
    sys::lx_obj(LX_FH_TMEM, LX_TMEM_ATTR, ino, &mut r as *mut LxTmemAttr as u64).ok()?;
    Some(r)
}

/// Whether `a` could be an in-memory file's pool attributes (a regular file of size 0).
pub fn candidate(a: &Attr) -> bool {
    a.mode & 0o170000 == 0o100000 && a.size == 0
}

/// Shows an in-memory file's size, blocks and data time in its pool attributes `a`.
pub fn overlay(a: &mut Attr) {
    if !candidate(a) {
        return;
    }
    let Some(t) = query(a.ino) else { return };
    a.size = t.size;
    a.blocks = t.blocks;
    if t.mtime_ns != 0 {
        let m = ((t.mtime_ns / 1_000_000_000) as i64, (t.mtime_ns % 1_000_000_000) as u32);
        if m > a.mtime {
            a.mtime = m;
        }
        if m > a.ctime {
            a.ctime = m;
        }
    }
}

/// Whether object `ino` is an in-memory file (one kernel call; a quick "no" there).
pub fn is_tmem(ino: u64) -> bool {
    query(ino).is_some()
}

/// Whether walked node `n` is an in-memory file (its cached attributes first).
pub fn node_is_tmem(n: crate::ctx::Node) -> bool {
    use crate::walk::Backend;
    match crate::calls::ctxt::BE.getattr(n) {
        Ok(a) => candidate(&a) && is_tmem(n.ino),
        Err(_) => false,
    }
}

/// tmpfs `n`'s `size=` (bytes with `k`/`m`/`g`, or `%` of the memory) to the kernel.
pub fn set_limit(n: u32, data: Option<&str>) {
    let v = data.and_then(parse_size).unwrap_or(0);
    let _ = sys::lx_obj(LX_FH_TMEM, LX_TMEM_LIMIT, n as u64, v);
}

/// `size=` of mount data as `LX_TMEM_LIMIT` takes it (bit 63: a percentage).
pub fn parse_size(data: &str) -> Option<u64> {
    let v = data.split(',').find_map(|o| o.strip_prefix("size="))?;
    let (num, mul) = match v.as_bytes().last()? {
        b'k' | b'K' => (&v[..v.len() - 1], 1u64 << 10),
        b'm' | b'M' => (&v[..v.len() - 1], 1 << 20),
        b'g' | b'G' => (&v[..v.len() - 1], 1 << 30),
        b'%' => return v[..v.len() - 1].parse::<u64>().ok().map(|p| (1 << 63) | p.min(100)),
        _ => (v, 1),
    };
    num.parse::<u64>().ok()?.checked_mul(mul).filter(|&b| b >> 63 == 0)
}
