//! # lx-ipc's Transparent restart (wave 9, Group X3)
//!
//! A new lx-ipc maps its two kept objects (the records, [`crate::kstore`]; the data arena,
//! [`crate::arena`]) and, when the kernel says this is a Transparent restart
//! (`LX_SVC_ADOPT`), takes back every object of the old instance from the kernel's list
//! (`LX_SVC_LIST`: slot, kind, key = record): each module rebuilds its tables from the
//! records and the arena chains they name ([`crate::pipe::restore`],
//! [`crate::unix::restore`], ...). What fails a check, or has no record (things made when
//! the records ran out), goes dead (`LX_SVC_DEAD`: its kind's error, as
//! FailObjects). Then the records nobody took back are cleared and lx-ipc goes online; the
//! calls that were waiting are sent again by the kernel.
//!
//! The first start (or a restart the ladder made FailObjects: the kernel dropped the kept
//! objects and made the old objects stale) finds nothing and starts empty.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use hydra_rt::mem::{MemObj, PROT_RW};
use hydra_rt::protocol::*;
use hydra_rt::{println, sys};

use crate::{arena, kstore};

/// Maps a kept object of `size` bytes: its address and whether it existed.
fn map_kept(key: u64, size: usize) -> Option<(*mut u8, bool)> {
    let (m, existed) = match MemObj::kept(key, size as u64) {
        Ok(v) => v,
        Err(e) => {
            println!("[lx-ipc] no kept object {} ({}): IPC objects will not survive a restart", key, e);
            return None;
        }
    };
    let p = m.map(0, size as u64, PROT_RW).ok()?;
    let _ = m.into_raw();
    Some((p, existed))
}

/// The kernel's list of this service's live objects: `(slot, kind, key)`.
fn list() -> Vec<(u32, u32, u64)> {
    let mut out = Vec::new();
    let mut buf = [LxSvcObj::default(); 64];
    let mut start = 0u32;
    while let Ok(n) = sys::lx_svc_list(&mut buf, start) {
        if n == 0 {
            break;
        }
        out.extend(buf[..n].iter().map(|o| (o.slot, o.kind, o.key)));
        start = buf[n - 1].slot + 1;
    }
    out
}

/// Opens the kept objects and takes back the previous instance's objects (see the module
/// comment): the objects taken back, for [`sweep`].
pub fn start() -> Vec<(u32, u32, u64)> {
    let Some((abase, _)) = map_kept(kstore::KEY_ARENA, arena::SIZE) else { return Vec::new() };
    // SAFETY: the kernel mapped the object for this process's life
    unsafe { arena::init(abase, arena::SIZE) };
    let Some((rbase, _)) = map_kept(kstore::KEY_REC, kstore::SIZE) else { return Vec::new() };
    // SAFETY: as above
    let (opened, found) = unsafe { kstore::open(rbase, kstore::SIZE) };
    if opened.bad_records > 0 {
        println!("[lx-ipc] kept records: {} damaged ones dropped", opened.bad_records);
    }
    if found.is_empty() || sys::lx_svc_adopt().is_err() {
        // A first start, or nothing to take back
        kstore::keep_only(&[]);
        return Vec::new();
    }
    let objs = list();
    let recs: BTreeMap<u64, &[u8]> = found.iter().map(|(id, d)| (*id, d.as_slice())).collect();
    let mut live: Vec<u64> = Vec::new();
    let mut dead: Vec<u32> = Vec::new();
    let mut adopted: Vec<(u32, u32, u64)> = Vec::new();
    // Pipes: each record with the ends the kernel still has
    let mut ends: BTreeMap<u64, Vec<(u32, u32)>> = BTreeMap::new();
    let mut unix_objs: Vec<(u32, u64)> = Vec::new();
    let mut mq_objs: Vec<(u32, u64)> = Vec::new();
    for &(slot, kind, key) in &objs {
        match kind {
            LX_OBJ_KIND_PIPE_R | LX_OBJ_KIND_PIPE_W | LX_OBJ_KIND_PIPE_RW if recs.get(&key).is_some_and(|d| d.first() == Some(&kstore::K_PIPE)) => ends.entry(key).or_default().push((slot, kind)),
            LX_OBJ_KIND_UNIX => unix_objs.push((slot, key)),
            LX_OBJ_KIND_MQ => mq_objs.push((slot, key)),
            LX_OBJ_KIND_EVENTFD | LX_OBJ_KIND_TIMERFD | LX_OBJ_KIND_SIGNALFD => {
                let ok = recs.get(&key).is_some_and(|d| match kind {
                    LX_OBJ_KIND_EVENTFD => crate::eventfd::restore(slot, key, d),
                    LX_OBJ_KIND_TIMERFD => crate::timerfd::restore(slot, key, d),
                    _ => crate::signalfd::restore(slot, key, d),
                });
                if ok {
                    live.push(key);
                    adopted.push((slot, kind, key));
                } else {
                    dead.push(slot);
                }
            }
            LX_OBJ_KIND_PIDFD if crate::pidfd::restore(slot, key) => adopted.push((slot, kind, key)),
            _ => dead.push(slot),
        }
    }
    for (&id, e) in &ends {
        let (alive, d) = crate::pipe::restore(id, recs[&id], e);
        if alive {
            live.push(id);
        }
        for &(slot, kind) in e {
            if d.contains(&slot) {
                dead.push(slot);
            } else if alive {
                adopted.push((slot, kind, id));
            }
        }
        if !alive {
            dead.extend(e.iter().map(|x| x.0).filter(|s| !d.contains(s)));
        }
    }
    let socks: Vec<(u64, &[u8])> = recs.iter().filter(|(_, d)| d.first() == Some(&kstore::K_USOCK)).map(|(&k, &d)| (k, d)).collect();
    let pairs: Vec<(u64, &[u8])> = recs.iter().filter(|(_, d)| d.first() == Some(&kstore::K_UPAIR)).map(|(&k, &d)| (k, d)).collect();
    let tokens: Vec<(u64, &[u8])> = recs.iter().filter(|(_, d)| d.first() == Some(&kstore::K_TOKENS)).map(|(&k, &d)| (k, d)).collect();
    let (ulive, udead) = crate::unix::restore(&socks, &pairs, &unix_objs, &tokens);
    live.extend(ulive);
    for &(slot, key) in &unix_objs {
        if udead.contains(&slot) {
            dead.push(slot);
        } else {
            adopted.push((slot, LX_OBJ_KIND_UNIX, key));
        }
    }
    let mqs: Vec<(u64, &[u8])> = recs.iter().filter(|(_, d)| d.first() == Some(&kstore::K_MQ)).map(|(&k, &d)| (k, d)).collect();
    let (mlive, mdead) = crate::mqueue::restore(&mqs, &mq_objs);
    live.extend(mlive);
    for &(slot, key) in &mq_objs {
        if mdead.contains(&slot) {
            dead.push(slot);
        } else {
            adopted.push((slot, LX_OBJ_KIND_MQ, key));
        }
    }
    // System V's tables (no objects: one record)
    if let Some((&id, &d)) = recs.iter().find(|(_, d)| d.first() == Some(&kstore::K_SYSV)) {
        if crate::sysv::restore(id, d) {
            live.push(id);
        }
    }
    for &slot in &dead {
        let _ = sys::lx_svc_dead(slot);
    }
    kstore::keep_only(&live);
    let (np, nb) = crate::pipe::count();
    let (ns, nc) = crate::unix::count();
    let a = arena::get();
    println!(
        "[lx-ipc] restarted: {} objects taken back, {} not; {} pipes ({} bytes waiting), {} Unix sockets, {} connections, {} System V objects; arena {} KiB in use",
        adopted.len(),
        dead.len(),
        np,
        nb,
        ns,
        nc,
        crate::sysv::objects(),
        a.used() * arena::UNIT / 1024
    );
    adopted
}

/// Just before going online: an object taken back whose last descriptor went since the
/// list was read is closed now (no notification will come for it).
pub fn sweep(adopted: &[(u32, u32, u64)]) {
    if adopted.is_empty() {
        return;
    }
    let now: BTreeMap<u32, u64> = list().into_iter().map(|(s, _, k)| (s, k)).collect();
    for &(slot, kind, key) in adopted {
        if now.get(&slot) != Some(&key) {
            crate::obj::closed(slot, kind);
        }
    }
}
