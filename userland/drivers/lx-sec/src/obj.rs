//! lx-sec's server objects (bpf maps, programs, links, BTF) on the service runtime's slot
//! allocator (`svcrt::objs`), under the names bpf.rs uses (the same as linux-server's
//! `obj` module, which serves bpf when lx-sec is co-located back, `lx.sec=linux`).

use hydra_rt::protocol::*;
use hydra_rt::svcrt::{objs, Cx};
use hydra_rt::sys;

/// A free slot (bpf objects are never "ready": their readiness word stays 0).
pub fn alloc(_kind: u32) -> Result<u32, i64> {
    objs::alloc()
}

/// Lets slot `slot` go.
pub fn free(slot: u32) {
    objs::free(slot);
}

/// Installs a descriptor for the object in slot `slot` in the caller's table; `tag`: the
/// kernel's value (a bpf map's key and value sizes).
#[allow(clippy::too_many_arguments)]
pub fn install_tag(cx: &Cx, slot: u32, kind: u32, flags: u32, mode: u32, uid: u32, gid: u32, name: &[u8], tag: u64) -> Result<i64, i64> {
    let mut d = LxObjDesc { slot, kind, flags, mode, uid, gid, name_len: 0, pad: 0, name: [0; LX_OBJ_NAME_MAX], tag };
    let n = name.len().min(LX_OBJ_NAME_MAX);
    d.name[..n].copy_from_slice(&name[..n]);
    d.name_len = n as u32;
    sys::lx_obj(LX_OBJ_INSTALL, cx.id, &d as *const LxObjDesc as u64, 0).map(|fd| fd as i64)
}

/// The object behind descriptor `fd` of the caller: `(slot, kind, nonblock)`.
pub fn of_fd(cx: &Cx, fd: u64) -> Result<(u32, u32, bool), i64> {
    let v = sys::lx_obj(LX_OBJ_FD, cx.id, fd, 0)?;
    Ok((v as u32, (v >> 32) as u32 & 0xFFFF, v & (1 << 62) != 0))
}

/// The last descriptor of slot `slot` (an object of `kind`) went away.
pub fn closed(slot: u32, kind: u32) {
    if matches!(kind, LX_OBJ_KIND_BPF_MAP | LX_OBJ_KIND_BPF_PROG | LX_OBJ_KIND_BPF_LINK | LX_OBJ_KIND_BPF_BTF) {
        crate::bpf::closed(slot);
    }
    objs::free(slot);
}
