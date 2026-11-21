//! # `execve`'s front half: the decisions (wave 7, Group 7-5)
//!
//! What [`crate::exec`] decides from bytes alone: a `#!` line, the ELF interpreter
//! (`PT_INTERP`) of a program, the argv strings scripts put in front, the lexical absolute
//! path, and the plan the kernel gets back. Pure (`alloc` only): host tests in
//! `tests/host-w7-41`.

use alloc::vec::Vec;

/// Parses a `#!interpreter [optional-arg]` line at the start of `data` (the kernel's
/// `execve.rs` rule: the first line, at most 256 bytes, blanks around the interpreter, one
/// optional argument that keeps inner blanks).
///
/// # Returns
/// `Some((interpreter, argument))`, or `None` when `data` is not a `#!` script or names no
/// interpreter.
pub fn parse_shebang(data: &[u8]) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
    if !data.starts_with(b"#!") {
        return None;
    }
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len()).min(256);
    if end < 2 {
        return None;
    }
    let mut line: Vec<u8> = data[2..end].iter().copied().skip_while(|b| *b == b' ' || *b == b'\t').collect();
    while matches!(line.last(), Some(b' ' | b'\t' | b'\r')) {
        line.pop();
    }
    if line.is_empty() {
        return None;
    }
    match line.iter().position(|&b| b == b' ' || b == b'\t') {
        Some(i) => {
            let arg: Vec<u8> = line[i..].iter().copied().skip_while(|b| *b == b' ' || *b == b'\t').collect();
            Some((line[..i].to_vec(), if arg.is_empty() { None } else { Some(arg) }))
        }
        None => Some((line, None)),
    }
}

/// Where a program's ELF interpreter path is.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Interp {
    /// Not a 64-bit little-endian ELF file, or no `PT_INTERP` (a static program): the
    /// kernel decides what it is.
    None,
    /// The path (without its NUL), found in the bytes given.
    Path(Vec<u8>),
    /// The path lies at `(offset, length)` of the file, past the bytes given.
    At(u64, u64),
}

fn u16_at(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32_at(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}
fn u64_at(b: &[u8], o: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(o..o + 8)?.try_into().ok()?))
}

/// Longest interpreter path looked for (Linux refuses longer ones: `PATH_MAX`).
pub const INTERP_MAX: u64 = 4096;

/// The `PT_INTERP` of the ELF file whose first bytes are `head`. Program headers past
/// `head` count as none ([`Interp::None`]: the kernel's loader still reads the file and
/// asks for the interpreter by path then).
pub fn elf_interp(head: &[u8]) -> Interp {
    if head.len() < 64 || &head[..4] != b"\x7fELF" || head[4] != 2 || head[5] != 1 {
        return Interp::None;
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (u64_at(head, 32), u16_at(head, 54), u16_at(head, 56)) else { return Interp::None };
    if phentsize < 56 {
        return Interp::None;
    }
    for i in 0..phnum as u64 {
        let o = phoff.saturating_add(i * phentsize as u64);
        if o > head.len() as u64 {
            return Interp::None;
        }
        let o = o as usize;
        let Some(ty) = u32_at(head, o) else { return Interp::None };
        if ty != 3 {
            continue;
        }
        let (Some(off), Some(len)) = (u64_at(head, o + 8), u64_at(head, o + 32)) else { return Interp::None };
        if len == 0 || len > INTERP_MAX {
            return Interp::None;
        }
        return match off.checked_add(len) {
            Some(end) if end <= head.len() as u64 => Interp::Path(trim_nul(&head[off as usize..end as usize]).to_vec()),
            Some(_) => Interp::At(off, len),
            None => Interp::None,
        };
    }
    Interp::None
}

/// `b` up to its first NUL.
pub fn trim_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
}

/// The argv strings that replace `argv[0]` once a script `script` (its path as given)
/// turned out to run through `interp [arg]`, on top of the strings `pre` an earlier script
/// level put there (empty: the program's own `argv[0]` is replaced). Linux's rule:
/// `interp [arg] script argv[1..]`.
pub fn script_prefix(pre: &[Vec<u8>], interp: &[u8], arg: Option<&[u8]>, script: &[u8]) -> Vec<Vec<u8>> {
    let mut v = alloc::vec![interp.to_vec()];
    if let Some(a) = arg {
        v.push(a.to_vec());
    }
    v.push(script.to_vec());
    v.extend(pre.iter().skip(1).cloned());
    v
}

/// Joins `base` (an absolute path) and `path` and removes `.`, `..` and repeated slashes,
/// lexically (the kernel's `join_path_raw`). An absolute `path` ignores `base`.
pub fn join_path(base: &[u8], path: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    if path.first() != Some(&b'/') {
        parts.extend(base.split(|&c| c == b'/').filter(|c| !c.is_empty()));
    }
    for c in path.split(|&c| c == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            _ => parts.push(c),
        }
    }
    let mut out = alloc::vec![b'/'];
    for (i, p) in parts.iter().enumerate() {
        if i > 0 {
            out.push(b'/');
        }
        out.extend_from_slice(p);
    }
    out
}

/// The plan's bytes: the fixed part (`ino`, `interp_ino`, the lengths, `lexical`: as the
/// kernel's `LxExecPlan`, little-endian) then the shown path, the argv strings (each with a
/// NUL) and the interpreter path. `None` when it does not fit `cap` bytes.
pub fn encode_plan(ino: u64, interp_ino: u64, shown: &[u8], lexical: bool, pre: &[Vec<u8>], interp: &[u8], cap: usize) -> Option<Vec<u8>> {
    let pre_len: usize = pre.iter().map(|p| p.len() + 1).sum();
    let total = PLAN_HEAD + shown.len() + pre_len + interp.len();
    if total > cap {
        return None;
    }
    let mut v = Vec::with_capacity(total);
    v.extend_from_slice(&ino.to_le_bytes());
    v.extend_from_slice(&interp_ino.to_le_bytes());
    v.extend_from_slice(&(shown.len() as u32).to_le_bytes());
    v.extend_from_slice(&(pre.len() as u32).to_le_bytes());
    v.extend_from_slice(&(pre_len as u32).to_le_bytes());
    v.extend_from_slice(&(interp.len() as u32).to_le_bytes());
    v.extend_from_slice(&(lexical as u32).to_le_bytes());
    v.extend_from_slice(&0u32.to_le_bytes());
    v.extend_from_slice(shown);
    for p in pre {
        v.extend_from_slice(p);
        v.push(0);
    }
    v.extend_from_slice(interp);
    Some(v)
}

/// Bytes of the plan's fixed part (`LxExecPlan`).
pub const PLAN_HEAD: usize = 40;
