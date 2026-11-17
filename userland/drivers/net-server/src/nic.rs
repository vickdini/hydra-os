//! # net-server: the network card, through its driver
//!
//! net-server calls `e1000-driver` directly (server to server, [`ENDPOINT_NET_DEV`]) and
//! maps its window (the supervisor allows it): frames go into the window and come back
//! out of it, never through the kernel. Received frames come in batches
//! (`MSG_NET_RECEIVE`, after the driver's interrupt was forwarded here); frames to send are
//! queued and go in batches too (`MSG_NET_TRANSMIT_BATCH`, [`flush`]): the main loop
//! flushes after each request and each round of received frames, before answering.
//!
//! Single-threaded (the main loop): the statics need no locking beyond [`spin::Mutex`]'s
//! interior mutability.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use hydra_rt::protocol::{
    ENDPOINT_NET_DEV, MSG_NET_GET_MAC, MSG_NET_GET_STATUS, MSG_NET_RECEIVE, MSG_NET_REPLY, MSG_NET_TRANSMIT_BATCH,
};
use hydra_rt::{sys, Message, WINDOW_SIZE};

/// Largest frame the adapter moves.
const MAX_FRAME: usize = 2048;
/// Frames queued before [`send_frame`] flushes by itself.
const BATCH_FRAMES: usize = 96;

static PRESENT: AtomicBool = AtomicBool::new(false);
/// The driver's window, mapped here (0: none).
static WINDOW: AtomicU64 = AtomicU64::new(0);
static MAC: Mutex<[u8; 6]> = Mutex::new([0; 6]);
/// Frames waiting to be sent, laid out as the batch request wants them.
static TX: Mutex<(Vec<u8>, usize)> = Mutex::new((Vec::new(), 0));
/// Frames received and not yet handed to the stack ([`receive_one`], used while ARP waits).
static RX_QUEUE: Mutex<Vec<Vec<u8>>> = Mutex::new(Vec::new());

/// Traffic counters: packets received, bytes received, packets sent, bytes sent; receive
/// requests made and frames they returned.
pub static PACKETS_RX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_RX: AtomicU64 = AtomicU64::new(0);
pub static PACKETS_TX: AtomicU64 = AtomicU64::new(0);
pub static BYTES_TX: AtomicU64 = AtomicU64::new(0);
pub static RECV_CALLS: AtomicU64 = AtomicU64::new(0);
pub static RECV_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Calls the driver.
fn request(label: u32, args: [u64; 4]) -> Result<Message, &'static str> {
    match sys::svc_call(ENDPOINT_NET_DEV, Message::new(label as u64, args), 0) {
        Ok(r) if r.label == MSG_NET_REPLY as u64 && (r.args[0] as i64) >= 0 => Ok(r),
        Ok(_) => Err("the network driver reported an error"),
        Err(_) => Err("the network driver is not running"),
    }
}

/// The driver's window.
fn window() -> Option<&'static mut [u8]> {
    let w = WINDOW.load(Ordering::Acquire);
    (w != 0).then(|| unsafe { core::slice::from_raw_parts_mut(w as *mut u8, WINDOW_SIZE) })
}

/// Maps the driver's window and learns the MAC address.
///
/// # Errors
/// If the driver does not run or refuses.
pub fn init() -> Result<(), &'static str> {
    if WINDOW.load(Ordering::Acquire) == 0 {
        let w = sys::svc_attach(ENDPOINT_NET_DEV).map_err(|_| "cannot map the network driver's window")?;
        WINDOW.store(w, Ordering::Release);
    }
    let r = request(MSG_NET_GET_MAC, [0; 4])?;
    let lo = (r.args[1] as u32).to_le_bytes();
    let hi = (r.args[2] as u16).to_le_bytes();
    *MAC.lock() = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    PRESENT.store(true, Ordering::Release);
    Ok(())
}

/// Whether the card and its driver are up.
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// The card's MAC address (zeros without one).
pub fn mac_address() -> [u8; 6] {
    *MAC.lock()
}

/// Whether the card has a carrier link (asks the driver).
pub fn is_link_up() -> bool {
    is_present() && request(MSG_NET_GET_STATUS, [0; 4]).map_or(false, |r| r.args[1] != 0)
}

/// Queues a frame to send ([`flush`] sends the queue).
///
/// # Errors
/// If there is no card or the frame is too long.
pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    if !is_present() {
        return Err("no network card");
    }
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err("Packet exceeds max transmission buffer size (2048 bytes)");
    }
    let full = {
        let mut tx = TX.lock();
        tx.0.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        tx.0.extend_from_slice(frame);
        tx.1 += 1;
        tx.1 >= BATCH_FRAMES || tx.0.len() + 2 + MAX_FRAME > WINDOW_SIZE
    };
    if full {
        flush();
    }
    Ok(())
}

/// Sends the queued frames in one request to the driver.
pub fn flush() {
    let (bytes, count) = {
        let mut tx = TX.lock();
        if tx.1 == 0 {
            return;
        }
        let count = tx.1;
        tx.1 = 0;
        (core::mem::take(&mut tx.0), count)
    };
    let Some(w) = window() else { return };
    w[..bytes.len()].copy_from_slice(&bytes);
    let sent = match request(MSG_NET_TRANSMIT_BATCH, [count as u64, 0, 0, 0]) {
        Ok(r) => r.args[1] as usize,
        Err(_) => 0,
    };
    PACKETS_TX.fetch_add(sent as u64, Ordering::Relaxed);
    BYTES_TX.fetch_add((bytes.len() - 2 * count) as u64, Ordering::Relaxed);
    // Reuse the buffer
    let mut tx = TX.lock();
    if tx.0.is_empty() {
        tx.0 = bytes;
        tx.0.clear();
    }
}

/// Fetches a batch of received frames from the driver into [`RX_QUEUE`].
fn fetch() -> usize {
    flush(); // the window is about to be overwritten
    let Ok(r) = request(MSG_NET_RECEIVE, [0; 4]) else { return 0 };
    let count = r.args[1] as usize;
    RECV_CALLS.fetch_add(1, Ordering::Relaxed);
    RECV_FRAMES.fetch_add(count as u64, Ordering::Relaxed);
    let Some(w) = window() else { return 0 };
    let mut q = RX_QUEUE.lock();
    let mut at = 0;
    for _ in 0..count {
        let len = u16::from_le_bytes([w[at], w[at + 1]]) as usize;
        if at + 2 + len > WINDOW_SIZE {
            break;
        }
        q.push(w[at + 2..at + 2 + len].to_vec());
        at += 2 + len;
        PACKETS_RX.fetch_add(1, Ordering::Relaxed);
        BYTES_RX.fetch_add(len as u64, Ordering::Relaxed);
    }
    count
}

/// Hands every frame the driver has (one batch) to `handle`; returns how many. The frames
/// are copied out of the window first: `handle` may send (and so flush) meanwhile.
pub fn receive_frames(mut handle: impl FnMut(&[u8])) -> usize {
    if !is_present() {
        return 0;
    }
    if RX_QUEUE.lock().is_empty() {
        fetch();
    }
    let frames = core::mem::take(&mut *RX_QUEUE.lock());
    for f in &frames {
        handle(f);
    }
    frames.len()
}

/// Takes the next received frame into `out` (fetching a batch when none waits): for the
/// ARP wait, which polls.
pub fn receive_one(out: &mut [u8]) -> Option<usize> {
    if !is_present() {
        return None;
    }
    if RX_QUEUE.lock().is_empty() {
        fetch();
    }
    let mut q = RX_QUEUE.lock();
    if q.is_empty() {
        return None;
    }
    let f = q.remove(0);
    let len = f.len().min(out.len());
    out[..len].copy_from_slice(&f[..len]);
    Some(len)
}
