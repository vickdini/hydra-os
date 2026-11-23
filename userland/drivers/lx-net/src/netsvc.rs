//! lx-net's calls (wave 8, Group X2): which forwarded calls are the network service's, and
//! what its main thread does. lx-net's `main.rs` and linux-server (which builds the same
//! files for `lx.net=linux`) both serve through these functions, so the two hosts cannot
//! drift apart.
//!
//! The service (`LXS_NET`) owns `AF_INET`, `AF_INET6` and `AF_NETLINK` sockets: `socket` of
//! those families, every call on their objects ([`crate::socket`] keeps blocked ones), the
//! kernel's netlink delivery for a message queue notification, and `/proc/net/{tcp,udp}[6]`.

use hydra_rt::protocol::*;

use crate::client::Cx;

/// Whether `kind` is an object kind of this service.
pub fn owns_kind(kind: u32) -> bool {
    matches!(kind, LX_OBJ_KIND_INET | LX_OBJ_KIND_NETLINK)
}

/// Serves forwarded call `cx` if it is one of this service's: `Some((result, flags))`.
pub fn dispatch(cx: &Cx) -> Option<(i64, u64)> {
    let c = &cx.c;
    let kind = if c.obj != LX_OBJ_NONE { crate::obj::kind_of(c.obj as u32) } else { 0 };
    Some(match c.nr {
        // `socket`/`socketpair` of the families routed here (never AF_UNIX: lx-ipc's)
        41 | 53 if cx.args[0] != 1 => crate::socket::by_family(cx),
        // socket calls, and read/write/readv/writev/ioctl and the kernel's own calls on one
        // (an in-kernel message queue's notification for one of our netlink sockets, or
        // lx-ipc's through the kernel's `LX_OBJ_NOTIFY`)
        LX_KCALL_NLDELIVER if kind == LX_OBJ_KIND_NETLINK => match cx.copy_in(cx.args[1], (cx.args[2] as usize).min(64)) {
            Ok(d) => (crate::netlink::deliver_slot(c.obj as u32, &d), 0),
            Err(e) => (e, 0),
        },
        42..=52 | 54 | 55 | 288 | 299 | 307 | 0 | 1 | 16 | 19 | 20 | 276 | LX_KCALL_REOPEN | LX_KCALL_FCNTL | LX_KCALL_PSEEK | LX_KCALL_PREAD if owns_kind(kind) => crate::socket::by_kind(cx),
        _ => return None,
    })
}

/// The last descriptor of slot `slot` (an object of `kind`) went: `true` if it was ours.
pub fn closed(slot: u32, kind: u32) -> bool {
    if !owns_kind(kind) {
        return false;
    }
    crate::socket::closed(slot);
    if kind == LX_OBJ_KIND_INET {
        crate::inet::closed(slot);
    } else {
        crate::netlink::closed(slot);
    }
    true
}

/// Process `tgid` ended.
pub fn on_exit(tgid: u64) {
    crate::socket::on_exit(tgid);
}

/// A signal for the caller of pending request `id`: `true` if it was one of ours.
pub fn interrupted(id: u64) -> bool {
    crate::socket::interrupted(id)
}

/// Blocked calls whose deadline passed are answered; the earliest deadline still waiting.
pub fn tick(now: u64) -> Option<u64> {
    crate::socket::tick(now)
}

/// The main thread, after waking with notification bits `bits` (net-server's doorbell, or
/// net-server gone): readiness relayed, blocked calls tried again.
pub fn main_work(bits: u64) {
    crate::socket::notified(bits);
    crate::socket::relay_check();
}
