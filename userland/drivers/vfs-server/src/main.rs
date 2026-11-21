//! # vfs-server: the file service (wave 7)
//!
//! The ring-3 service that owns names, mounts, permissions and the changes to files, next to
//! zfs-server, which stays the ZFS back end (`docs/vfs-design.md`, the user's decisions 9 and
//! 19-24). The kernel routes file calls here by number (service `LXS_VFS`, endpoint
//! [`ENDPOINT_VFS_SERVER`]); the descriptor table stays in the kernel as a table of handles.
//!
//! This is the core (Group 7-1): the service on `svcrt` (workers on the kernel's direct
//! switch), the path walk ([`walk`]), the name/attribute/link caches ([`cache`]), the
//! zfs-server client ([`zfs`], in vfs-server's own window), mount crossing and the redirect
//! answer for mounts other services serve ([`walk::Mounts`]; 7-3's `mount.rs` tables). Its own call, `LX_VFS_WALK_NR`, walks
//! a path and says what it found (the walk test compares it with the kernel's `stat`); the
//! file calls themselves come with Group 7-2 (`calls/`), the mount tables with 7-3.
//!
//! ## Restarts
//! The caches are refilled from zfs-server; nothing else is kept yet (7-6 adds the kept
//! state: mount tables, locks, the `tmpfs` tree). Calls made while it restarts wait for it.

#![no_std]
#![no_main]
// The walk, cache, mount and zfs-client interface is wider than the core uses: 7-2's calls
// and 7-3's mounts build on it (NOTES.md, wave 7)
#![allow(dead_code)]

extern crate alloc;

mod be;
// wave7 G7-2: the file calls (stat family, access, readlink, getdents, open, changes)
mod calls;
mod cache;
mod ctx;
mod lock;
// wave7 G7-3 begin: mount tables and tmpfs
mod mount;
mod mountcalls;
mod mtab;
mod tmpfs;
mod tmpfs_mem;
// wave7 G7-3 end
mod perm;
mod walk;
mod zfs;

/// The kernel's protocol (message codes, `LxCall`, service ids).
pub use hydra_rt::protocol as proto;

/// The ZFS request protocol, shared with the kernel and zfs-server.
pub mod fs {
    /// On-disk types (the protocol's attribute types use them).
    #[allow(dead_code)]
    #[path = "../../../../../src/fs/zfs/types.rs"]
    pub mod types;
    /// The requests and their encoding.
    #[allow(dead_code)]
    #[path = "../../../../../src/fs/zfs/fsproto.rs"]
    pub mod fsproto;
}

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use hydra_rt::svccall::DcallArgs;
use hydra_rt::svcrt::{self, Answer, Cx, Event};
use hydra_rt::{println, sys};
use proto::*;


use crate::be::ZfsBackend;
use crate::cache::CACHE;
use crate::ctx::{Ctx, Node};
use crate::walk::{Redirect, Start, Walked};

hydra_rt::entry!(main);

const EINVAL: i64 = -22;
const ENOENT: i64 = -2;
const ENOSYS: i64 = -38;
const EXDEV: i64 = -18;
const ENAMETOOLONG: i64 = -36;
/// `AT_FDCWD`.
const AT_FDCWD: i64 = -100;
/// What the kernel puts in `LxCall::root`/`cwd` when it cannot describe them (a root or
/// working directory in a mount: 7-3's tables) — `wave7 G7-1`'s temporary fill.
const CTX_UNKNOWN: u64 = u64::MAX;

/// The notification ring's "dropped" word (entries lost to a full ring) last seen; held
/// while the caches are forgotten, so no worker goes on before that is done.
static DROPPED_SEEN: lock::YLock<u64> = lock::YLock::new(0);
/// Where the ring's header is.
static RING: AtomicU64 = AtomicU64::new(0);

fn main(args: &[&str]) {
    if let Some(n) = args.iter().find_map(|a| a.strip_prefix("cache=")).and_then(|n| n.parse::<usize>().ok()) {
        CACHE.set_cap(n);
    }
    let cfg = svcrt::Config { name: "vfs-server", endpoint: ENDPOINT_VFS_SERVER, workers: svcrt::workers_arg(args, 4), subscribe: None };
    // wave7 G7-3: the initial namespace's mount table, before any worker or note can ask
    // (the pool root is set when zfs-server answers)
    mount::install_boot(0);
    let mut svc = match svcrt::start(&cfg, serve) {
        Ok(s) => s,
        Err(e) => {
            println!("[vfs-server] cannot start: {}", e);
            sys::exit_group(1);
        }
    };
    let win = svc.window().as_mut_ptr();
    zfs::init(win);
    RING.store(win as u64 + LX_NOTES_OFF as u64, Ordering::Release);
    svcrt::notes::init(win, on_note);
    svcrt::objs::init(svc.area, ENDPOINT_VFS_SERVER);
    // The first request of this instance has no parameters (`FS_ROOT`), and it is made before
    // any call can come: a request of a previous instance that zfs-server may still be
    // serving finishes first (it writes its reply into our part of the window), so no later
    // request's bytes are overwritten by that stale reply
    // (until it is answered: going online earlier would let a worker's request be
    // overwritten; zfs-server may still be starting at boot)
    let mut root = zfs::root();
    for _ in 0..120 {
        if root.is_ok() {
            break;
        }
        sys::sleep_ms(500);
        root = zfs::root();
    }
    if let Err(e) = svc.online() {
        println!("[vfs-server] cannot go online: {}", e);
        sys::exit_group(1);
    }
    // wave7 G7-3: the pool root of the boot table, once zfs-server answers (else again below)
    let mut root_known = root.map(mount::set_pool_root).unwrap_or(false);
    match root {
        Ok(r) => println!("[vfs-server] online: {} workers, caches of {} entries, pool root {}", cfg.workers, CACHE.cap(), r),
        Err(e) => println!("[vfs-server] online ({} workers); zfs-server not answering yet ({})", cfg.workers, e),
    }
    // wave7 G7-2: the calls go to vfs-server from now on (`calls=0`: none, `calls=4,6,..`: these)
    println!("[vfs-server] {} file calls claimed", calls::claim_all(args));
    // wave7 G7-3: the mount calls moved so far (`mcalls=0`: none)
    println!("[vfs-server] {} mount calls claimed", mountcalls::claim_all(args));
    loop {
        match svc.recv(100) {
            Event::Request(id, _req) => svc.reply(id, &hydra_rt::Message::new(MSG_LX_REPLY as u64, [ENOSYS as u64, 0, 0, 0])),
            Event::Notify(_) | Event::Idle => {}
        }
        take_notes(u64::MAX);
        // wave7 G7-3
        if !root_known {
            root_known = zfs::root().map(mount::set_pool_root).unwrap_or(false);
        }
    }
}

/// Takes the notifications posted before `seq` (`u64::MAX`: all), and forgets everything if
/// some were lost to a full ring.
fn take_notes(seq: u64) {
    let ring = RING.load(Ordering::Acquire);
    if ring != 0 {
        let mut seen = DROPPED_SEEN.lock();
        // SAFETY: the ring header in the mapped window (word 2: entries dropped, written by
        // the kernel under its ring lock; an aligned u64). Read under the lock: a worker
        // with an older count never sets it back
        let dropped = unsafe { (*((ring as *const u64).add(2) as *const AtomicU64)).load(Ordering::Acquire) };
        if dropped != *seen {
            CACHE.forget_all();
            // wave7 G7-3: lost namespace notes: only the initial table is sure now
            mount::forget_namespaces(&mut *tmpfs_mem::STORE.lock());
            *seen = dropped;
        }
    }
    if seq == u64::MAX {
        svcrt::notes::drain_all();
    } else {
        svcrt::notes::drain_to(seq);
    }
}

/// One notification: the kernel changed the file system (`LX_NOTE_FSCHANGE`).
fn on_note(kind: u64, a: u64, b: u64, _c: u64) {
    // wave7 G7-3: mount namespaces made and gone (the tables and tmpfs instances follow)
    if kind == LX_NOTE_MNTNS {
        mount::on_mntns(a, b, &mut *tmpfs_mem::STORE.lock());
        return;
    }
    if kind == LX_NOTE_FSCHANGE {
        if a == 0 {
            // wave7 G7-2: 0 = names and attributes anywhere (link counts change with names)
            CACHE.forget_all();
        } else {
            CACHE.forget_object(a);
        }
    }
}

/// Serves one forwarded call.
fn serve(c: &LxCall, page: *mut u8) -> Answer {
    take_notes(c.note_seq);
    let cx = Cx::from_call(c, page);
    // wave7 G7-2
    if let Some(a) = calls::serve(&cx) {
        return a;
    }
    // wave7 G7-3
    if let Some(a) = mountcalls::serve(&cx) {
        return a;
    }
    let r = match c.nr {
        LX_VFS_WALK_NR => return walk_call(&cx, page),
        LX_DCALL_NR => dcall(&cx),
        _ => ENOSYS,
    };
    (r, 0)
}

/// The pool-root-relative node of a kernel context word (`LxCall::root`/`cwd`: an object
/// number in the root's own tree, 0 for the pool root).
fn ctx_node(v: u64) -> Result<Node, i64> {
    match v {
        CTX_UNKNOWN => Err(EXDEV),
        0 => Ok(Node::new(0, zfs::root()?)),
        i => Ok(Node::new(0, i)),
    }
}

/// `LX_VFS_WALK_NR(dirfd, path, flags, out)`.
fn walk_call(cx: &Cx, page: *mut u8) -> Answer {
    let [dirfd, path, flags, out, _, _] = cx.args;
    let r = (|| -> Result<Answer, i64> {
        let path = cx.user_cstr(path)?;
        let root = ctx_node(cx.c.root)?;
        // (an absolute path needs no start)
        let cwd = if path.first() == Some(&b'/') {
            root
        } else if dirfd as i32 as i64 != AT_FDCWD {
            // (directory descriptors come with 7-2's `at_ino`)
            return Err(EINVAL);
        } else {
            ctx_node(cx.c.cwd)?
        };
        let who = Ctx::from_call(&cx.c, root);
        let mut o = LxVfsWalkOut::default();
        let before = zfs::REQUESTS.load(Ordering::Relaxed);
        let be = ZfsBackend { nocache: flags & LX_VFS_NOCACHE != 0, ns: who.ns };
        let w = walk::walk(&be, &who, Start::At(cwd), &path, if flags & LX_VFS_NOFOLLOW != 0 { walk::NOFOLLOW } else { 0 })?;
        o.zfs_requests = zfs::REQUESTS.load(Ordering::Relaxed) - before;
        match w {
            Walked::Found { node, attr } => {
                o.ino = attr.ino;
                o.mnt = node.mnt as u64;
                o.mode = attr.mode as u64;
                o.nlink = attr.nlink as u64;
                o.uid = attr.uid as u64;
                o.gid = attr.gid as u64;
                o.rdev = attr.rdev;
                o.size = attr.size;
            }
            Walked::Redirect(r) => {
                let (obj, tail) = redirect_words(&r);
                if flags & LX_VFS_NOREDIR == 0 {
                    return Ok(svcrt::redirect(page, r.svc, obj, tail));
                }
                o.redir_svc = r.svc as u64;
                o.redir_obj = obj;
                o.redir_tail = tail as u64;
            }
        }
        // SAFETY: a plain repr(C) struct of u64s
        let bytes = unsafe { core::slice::from_raw_parts(&o as *const LxVfsWalkOut as *const u8, core::mem::size_of::<LxVfsWalkOut>()) };
        cx.copy_out(out, bytes)?;
        Ok((0, 0))
    })();
    r.unwrap_or_else(|e| (e, 0))
}

// ----------------------------------------------------------------------
// Redirect texts
// ----------------------------------------------------------------------

/// The rest of redirected paths that are not suffixes of their argument: `(ticket, text)`,
/// the last [`TICKETS`] of them.
static TEXTS: lock::YLock<Vec<(u64, Vec<u8>)>> = lock::YLock::new(Vec::new());
static NEXT_TICKET: AtomicU64 = AtomicU64::new(1);
const TICKETS: usize = 256;

/// The redirect's `(obj, tail)` words (a text gets a ticket).
fn redirect_words(r: &Redirect) -> (u64, u32) {
    match r.tail {
        Some(t) => (r.obj & 0xFFFF_FFFF, t),
        None => {
            let ticket = NEXT_TICKET.fetch_add(1, Ordering::Relaxed) & 0xFFFF_FFFF;
            let mut t = TEXTS.lock();
            if t.len() >= TICKETS {
                t.remove(0);
            }
            t.push((ticket, r.text.clone()));
            ((r.obj & 0xFFFF_FFFF) | ticket << 32, LX_VFS_TAIL_TEXT)
        }
    }
}

/// A direct call from another service.
fn dcall(cx: &Cx) -> i64 {
    let a = DcallArgs::of(&cx.c);
    match a.op {
        LX_DCALL_OP_NULL => 0,
        LX_VFS_OP_REDIR_TEXT => {
            let Ok(b) = cx.copy_in(a.input, 8.min(a.input_len)) else { return EINVAL };
            if b.len() < 8 {
                return EINVAL;
            }
            let ticket = Cx::u64_at(&b, 0) >> 32;
            // (a ticket is good for one fetch: the target asks once per redirected call)
            let text = {
                let mut t = TEXTS.lock();
                t.iter().position(|e| e.0 == ticket).map(|i| t.remove(i).1)
            };
            match text {
                Some(t) => {
                    let n = t.len().min(a.output_cap);
                    cx.copy_out_any(a.output, &t[..n]).map_or_else(|e| e, |()| t.len() as i64)
                }
                None => ENOENT,
            }
        }
        LX_VFS_OP_WALK => dcall_walk(cx, &a),
        _ => ENOSYS,
    }
}

/// `LX_VFS_OP_WALK`: a walk for another service (linux-server's `execve`, socket files).
fn dcall_walk(cx: &Cx, a: &DcallArgs) -> i64 {
    let head = core::mem::size_of::<LxVfsWalkIn>();
    let r = (|| -> Result<i64, i64> {
        if a.input_len <= head {
            return Err(EINVAL);
        }
        if a.input_len > head + walk::PATH_MAX {
            return Err(ENAMETOOLONG);
        }
        let b = cx.copy_in(a.input, a.input_len)?;
        // SAFETY: at least `head` bytes, a plain repr(C) struct
        let w: LxVfsWalkIn = unsafe { core::ptr::read_unaligned(b.as_ptr() as *const LxVfsWalkIn) };
        let path = &b[head..];
        let path = &path[..path.iter().position(|&c| c == 0).unwrap_or(path.len())];
        if w.root_mnt != 0 {
            return Err(EXDEV);
        }
        let root = ctx_node(w.root)?;
        let base = if path.first() == Some(&b'/') {
            root
        } else if w.base_mnt != 0 {
            return Err(EXDEV);
        } else {
            ctx_node(w.base)?
        };
        let mut who = Ctx::new(w.uid, w.gid, w.caps, root);
        who.ns = w.mnt_ns as u32;
        // (more groups than fit: refused, never cut: a dropped group could turn an ACL's
        // denial into an allow)
        if w.ngroups as usize > LX_GROUPS {
            return Err(EINVAL);
        }
        for &g in &w.groups[..w.ngroups as usize] {
            who = who.with_group(g);
        }
        let be = ZfsBackend { nocache: w.flags & LX_VFS_NOCACHE != 0, ns: who.ns };
        let mut o = LxVfsWalkOut::default();
        match walk::walk(&be, &who, Start::At(base), path, if w.flags & LX_VFS_NOFOLLOW != 0 { walk::NOFOLLOW } else { 0 })? {
            Walked::Found { node, attr } => {
                o.ino = attr.ino;
                o.mnt = node.mnt as u64;
                o.mode = attr.mode as u64;
                o.nlink = attr.nlink as u64;
                o.uid = attr.uid as u64;
                o.gid = attr.gid as u64;
                o.rdev = attr.rdev;
                o.size = attr.size;
            }
            Walked::Redirect(r) => {
                let (obj, tail) = redirect_words(&r);
                o.redir_svc = r.svc as u64;
                o.redir_obj = obj;
                o.redir_tail = tail as u64;
            }
        }
        // SAFETY: a plain repr(C) struct of u64s
        let bytes = unsafe { core::slice::from_raw_parts(&o as *const LxVfsWalkOut as *const u8, core::mem::size_of::<LxVfsWalkOut>()) };
        if a.output_cap < bytes.len() {
            return Err(EINVAL);
        }
        cx.copy_out_any(a.output, bytes)?;
        Ok(0)
    })();
    r.unwrap_or_else(|e| e)
}
