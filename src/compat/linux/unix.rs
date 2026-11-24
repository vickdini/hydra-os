//! # Unix domain sockets: the kernel's part
//!
//! Unix sockets are lx-ipc's (wave 5 step 4; wave 10 10-C deleted the in-kernel copy that
//! `lx=kernel`/`lx.ipc=kernel` used). What stays is the path-name half of `bind` and
//! `connect`, done in the caller's context (the socket node in the file system).

use alloc::sync::Arc;

const EINVAL: i64 = -22;
const EADDRINUSE: i64 = -98;
const AF_UNIX: u32 = 1;

/// A socket call (`bind`, `connect`, `sendmsg`, ...) on a socket of lx-ipc
/// (`ServerObject::socket_call`). `bind` and `connect` on a path name resolve the node here
/// first, in the caller's context (the temporary `vfs_resolve` of step 4, until the VFS
/// moves): `bind` makes the node (and removes it again if the server then refuses), and
/// `connect` checks it is a socket the caller may write to. The server gets the node's
/// inode in `LxCall::ino`; abstract names go as they are.
pub fn server_call(dev: &Arc<dyn super::chardev::CharDevice>, num: u64, a: [u64; 6]) -> i64 {
    if dev.as_server().map(|o| o.kind()) != Some(crate::ipc::protocol::LX_OBJ_KIND_UNIX) {
        return -88; // ENOTSOCK
    }
    if num != 49 && num != 42 {
        return crate::lx::call_obj(num, a, dev);
    }
    // sockaddr_un: family, then a path (NUL-terminated or not) or an abstract name
    if a[2] < 2 || a[2] > 110 {
        return EINVAL;
    }
    let b = match super::vfs::copy_in(a[1], a[2] as usize) {
        Ok(b) => b,
        Err(e) => return e,
    };
    if u16::from_le_bytes([b[0], b[1]]) as u32 != AF_UNIX || b.len() < 3 || b[2] == 0 {
        // (another family, autobind, an abstract name: the server decides)
        return crate::lx::call_obj(num, a, dev);
    }
    let name = &b[2..];
    let path = &name[..name.iter().position(|&c| c == 0).unwrap_or(name.len())];
    if num == 42 {
        return match super::vfs::socket_node_for_connect(path) {
            Ok(ino) => crate::lx::call_obj_ino(num, a, dev, ino),
            Err(e) => e,
        };
    }
    let ino = match super::vfs::make_socket_node(path) {
        Ok(i) => i,
        Err(e) => return if e == -17 { EADDRINUSE } else { e },
    };
    let r = crate::lx::call_obj_ino(num, a, dev, ino);
    if r < 0 {
        super::vfs::unlink_socket_node(path);
    }
    r
}
