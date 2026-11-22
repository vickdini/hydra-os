//! # Device "remove" and "add" announcements around a device service's restart (wave 8, Group H)
//!
//! The input and sound services (`input-server`, `sound-server`) restart Transparently: the
//! first crash is invisible, programs keep their descriptors. When a crash makes their
//! objects fail instead (a second crash within 30 s: the ladder's FailObjects; or a new
//! instance that did not adopt them), the programs' descriptors are dead: kwin's input
//! devices, PipeWire's sound card. Linux programs recover from that the way they do from a
//! device pulled out and plugged in again, so the kernel tells them exactly that
//! (`docs/display-input-design.md`, sections 3.6 and 5):
//!
//! - objects failed ([`objects_failed`], from `lx::server_gone` or the new instance's
//!   `LX_CTL_ONLINE`): **"remove"** for the service's devices;
//! - the next instance online ([`online`]): **"add"** for them (the sound card also gets a
//!   "change", the event on which PipeWire's ALSA monitor takes a card).
//!
//! libinput then drops the dead devices and opens them again through logind (`TakeDevice`,
//! which reaches the new instance); WirePlumber drops the card and makes its sink again.
//! The display service (decision 28: its crash ends the session) and the terminal service
//! (Konsole's shells end) announce nothing.
//!
//! The messages (kernel and udev formats, from the same records as the udev database:
//! [`super::uevent`], `compat::linux::devices`) are delivered by a short-lived kernel task,
//! never from the caller's context: to the kernel's own uevent sockets
//! (`compat::linux::netlink`, `lx.net=kernel`) and to the network service that holds the
//! others (lx-net, or linux-server when co-located: [`MSG_LX_UEVENT`]), waiting up to 10 s
//! for it if it is restarting itself.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::svc;
use super::uevent::{self, Batch, DevRecord};
use crate::ipc::protocol::{SvcId, LXS_INPUT, LXS_NET, LXS_SOUND, LX_PROC_KEYS_TEXT_MAX, LX_PROC_KEYS_TEXT_OFF, MSG_LX_UEVENT};

/// The device groups that announce.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Devs {
    /// The input service's event devices.
    Input = 0,
    /// The sound service's card and its nodes.
    Sound = 1,
}

/// One announcement waiting for the task.
#[derive(Clone, Copy, Debug)]
pub struct Job {
    /// Whose devices.
    pub devs: Devs,
    /// "add" (else "remove").
    pub add: bool,
}

/// Per device group: "remove" was announced and "add" not yet.
static REMOVED: [AtomicBool; 2] = [const { AtomicBool::new(false) }; 2];
static JOBS: Mutex<VecDeque<Job>> = Mutex::new(VecDeque::new());
/// The delivering task runs.
static RUNNING: AtomicBool = AtomicBool::new(false);
/// The last sequence number used (`SEQNUM`).
static SEQNUM: AtomicU64 = AtomicU64::new(1000);
/// Announcements queued.
pub static ANNOUNCED: AtomicU64 = AtomicU64::new(0);
/// Messages handed to the network service.
pub static DELIVERED: AtomicU64 = AtomicU64::new(0);
/// Batches the network service did not take.
pub static DROPPED: AtomicU64 = AtomicU64::new(0);

/// The device group service host `h` serves (none: it serves no announced devices).
fn devs_of(h: SvcId) -> Option<Devs> {
    if h == 0 {
        None
    } else if svc::host_of(LXS_INPUT) == h {
        Some(Devs::Input)
    } else if svc::host_of(LXS_SOUND) == h {
        Some(Devs::Sound)
    } else {
        None
    }
}

/// Host `h`'s objects failed (its process died without a Transparent restart, or its new
/// instance did not adopt them): its devices are announced "removed" (once).
pub fn objects_failed(h: SvcId) {
    let Some(d) = devs_of(h) else { return };
    if !REMOVED[d as usize].swap(true, Ordering::AcqRel) {
        queue(Job { devs: d, add: false });
    }
}

/// Host `h` is online: devices announced "removed" are announced "added" again.
pub fn online(h: SvcId) {
    let Some(d) = devs_of(h) else { return };
    if REMOVED[d as usize].swap(false, Ordering::AcqRel) {
        queue(Job { devs: d, add: true });
    }
}

fn queue(j: Job) {
    x86_64::instructions::interrupts::without_interrupts(|| JOBS.lock().push_back(j));
    ANNOUNCED.fetch_add(1, Ordering::Relaxed);
    if !RUNNING.swap(true, Ordering::AcqRel) {
        crate::task::spawn("uevent", task, crate::task::TaskPriority::Normal);
    }
}

fn next_job() -> Option<Job> {
    x86_64::instructions::interrupts::without_interrupts(|| JOBS.lock().pop_front())
}

/// The device records of a group (`compat::linux::devices`, the udev database's source).
fn records(d: Devs) -> Vec<DevRecord> {
    use crate::compat::linux::devices;
    match d {
        Devs::Input => devices::input_records(devices::INIT_USEC),
        Devs::Sound => devices::sound_records(devices::INIT_USEC),
    }
}

/// The messages of one job: "remove" children first; "add" the parent first, and for the
/// sound card a final "change" (PipeWire's ALSA monitor ignores "add" and takes a card on
/// "change" with `SOUND_INITIALIZED`, as udev's rules send it on Linux).
pub fn messages(j: Job, mut recs: Vec<DevRecord>, seq: &mut u64) -> Vec<(u32, Vec<u8>)> {
    if j.add {
        let mut m = uevent::announce("add", &recs, seq);
        if j.devs == Devs::Sound && !recs.is_empty() {
            m.extend(uevent::announce("change", &recs[..1], seq));
        }
        m
    } else {
        recs.reverse();
        uevent::announce("remove", &recs, seq)
    }
}

/// The delivering task: every queued job, then it ends.
fn task() {
    loop {
        while let Some(j) = next_job() {
            let mut seq = SEQNUM.load(Ordering::Relaxed);
            let msgs = messages(j, records(j.devs), &mut seq);
            SEQNUM.store(seq, Ordering::Relaxed);
            let t0 = crate::arch::pit::ticks();
            let reached = deliver(&msgs);
            let ms = |t: u64| t * 1000 / crate::arch::pit::frequency_hz().max(1);
            crate::kprintln!(
                "[hotplug] {:?} devices: \"{}\" announced ({} messages, {} sockets) at {} ms, delivery took {} ms",
                j.devs,
                if j.add { "add" } else { "remove" },
                msgs.len(),
                reached,
                ms(t0),
                ms(crate::arch::pit::ticks() - t0)
            );
        }
        RUNNING.store(false, Ordering::Release);
        // (a job queued after the last look and before RUNNING was cleared)
        if x86_64::instructions::interrupts::without_interrupts(|| JOBS.lock().is_empty()) || RUNNING.swap(true, Ordering::AcqRel) {
            break;
        }
    }
    crate::task::exit();
}

/// Hands messages to every uevent socket: the kernel's own, and the network service's.
/// Returns how many sockets got one.
fn deliver(msgs: &[(u32, Vec<u8>)]) -> usize {
    let mut reached = crate::compat::linux::netlink::uevent_all(msgs);
    if super::family_svc(16) == 0 {
        return reached;
    }
    // The network service may itself be restarting: wait for it (bounded)
    let deadline = crate::arch::pit::ticks() + 10 * crate::arch::pit::frequency_hz();
    while !svc::online(LXS_NET) {
        if crate::arch::pit::ticks() >= deadline {
            DROPPED.fetch_add(1, Ordering::Relaxed);
            crate::kprintln!("[hotplug] the network service is not online: {} messages not announced", msgs.len());
            return reached;
        }
        crate::task::sleep_ms(50);
    }
    let ep = svc::endpoint_of(LXS_NET);
    let _window = crate::ipc::service::hold_window_queued(ep);
    let Some(win) = crate::ipc::service::window(ep) else { return reached };
    let mut i = 0;
    let mut buf = Vec::new();
    while i < msgs.len() {
        buf.clear();
        let n = Batch::encode(&msgs[i..], &mut buf, LX_PROC_KEYS_TEXT_MAX);
        if n == 0 {
            i += 1; // (a message larger than the window: never, they are < 2 KiB)
            continue;
        }
        win[LX_PROC_KEYS_TEXT_OFF..LX_PROC_KEYS_TEXT_OFF + buf.len()].copy_from_slice(&buf);
        let msg = crate::ipc::Message::with_args(MSG_LX_UEVENT, [buf.len() as u64, n as u64, 0, 0]);
        match crate::ipc::service::call_queued(ep, msg, crate::ipc::service::CALL_TIMEOUT_TICKS) {
            Ok(r) if (r.args[0] as i64) >= 0 => {
                DELIVERED.fetch_add(n as u64, Ordering::Relaxed);
                reached = reached.max(r.args[0] as usize);
            }
            r => {
                DROPPED.fetch_add(1, Ordering::Relaxed);
                crate::kprintln!("[hotplug] the network service did not take {} messages ({:?})", n, r.map(|m| m.args[0] as i64));
            }
        }
        i += n;
    }
    reached
}
