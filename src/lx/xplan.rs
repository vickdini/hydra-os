//! # The exec plan (wave 7, Group 7-5)
//!
//! What linux-server answers to `LX_KCALL_EXEC` (`linux-server/src/execplan.rs`
//! `encode_plan`, the `LxExecPlan` layout of `ipc/protocol.rs`), decoded for
//! `compat::linux::execve`. Pure (`alloc` only): host tests in `tests/host-w7-41` and
//! `tests/host-t29`.

use alloc::string::String;
use alloc::vec::Vec;

/// What linux-server decided `execve` runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecPlan {
    /// The program (pool object).
    pub ino: u64,
    /// The path `/proc/self/exe` shows (links resolved), or the lexical absolute path.
    pub shown: String,
    /// The argv strings that replace `argv[0]` (scripts); empty: argv unchanged.
    pub prefix: Vec<Vec<u8>>,
    /// The ELF interpreter linux-server looked up: `(path, ino)`, ino 0 = not found.
    pub interp: Option<(String, u64)>,
}

/// Decodes linux-server's plan (`execplan::encode_plan`, the `LxExecPlan` layout).
pub fn decode_plan(b: &[u8]) -> Option<ExecPlan> {
    const HEAD: usize = 40;
    if b.len() < HEAD {
        return None;
    }
    let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
    let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap()) as usize;
    let (ino, interp_ino) = (u64_at(0), u64_at(8));
    let (real, npre, pre_len, interp_len) = (u32_at(16), u32_at(20), u32_at(24), u32_at(28));
    let end = HEAD.checked_add(real)?.checked_add(pre_len)?.checked_add(interp_len)?;
    if end > b.len() || ino == 0 || real == 0 {
        return None;
    }
    let shown = String::from_utf8_lossy(&b[HEAD..HEAD + real]).into_owned();
    let pre = &b[HEAD + real..HEAD + real + pre_len];
    let mut prefix: Vec<Vec<u8>> = Vec::new();
    if npre == 0 && pre_len != 0 {
        return None;
    }
    if npre > 0 {
        // Each string ends with a NUL
        if pre.last() != Some(&0) {
            return None;
        }
        prefix = pre[..pre.len() - 1].split(|&c| c == 0).map(|s| s.to_vec()).collect();
        if prefix.len() != npre {
            return None;
        }
    }
    let interp = (interp_len > 0).then(|| (String::from_utf8_lossy(&b[HEAD + real + pre_len..end]).into_owned(), interp_ino));
    Some(ExecPlan { ino, shown, prefix, interp })
}
