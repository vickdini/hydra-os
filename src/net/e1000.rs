//! # Network Subsystem: Intel 82540EM (E1000) Adapter Client
//!
//! The adapter is driven by `e1000-driver`, a Ring 3 program the supervisor starts with
//! the adapter's registers granted to it (`userland/drivers/e1000-driver`). This module is
//! the network stack's side of it: frames go to the driver and come back from it over
//! [`ENDPOINT_NET_DEV`] (see [`crate::ipc::service`]), through the service window.
//!
//! ## Key Interfaces
//!
//! - [`find_adapter`]: PCI enumeration for the supervisor (bus mastering enabled here).
//! - [`init`]: Learns the adapter's MAC address from the driver once it runs.
//! - [`send_frame`] / [`receive_frame`]: Raw Ethernet frames; received frames are fetched in
//!   batches and handed out one at a time.
//! - [`enable_interrupts`]: Wakes the network task ([`crate::net::stack::NET_WQ`]) when the
//!   adapter's interrupt arrives (the driver owns the line).
//!
//! ## Concurrency
//!
//! Calls to the driver run it in the caller's place ([`crate::ipc::service::call`]); the
//! received-frame queue is a [`spin::Mutex`] held only to push or pop.

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use crate::arch::pci;
use crate::ipc::protocol::{ENDPOINT_NET_DEV, MSG_NET_GET_MAC, MSG_NET_GET_STATUS, MSG_NET_RECEIVE, MSG_NET_REPLY, MSG_NET_TRANSMIT};
use crate::ipc::service::{self, CALL_TIMEOUT_TICKS};
use crate::ipc::Message;

/// PCI Vendor ID for Intel Corporation.
pub const E1000_VENDOR_ID: u16 = 0x8086;
/// PCI Device ID for the Intel 82540EM (VirtualBox / QEMU default).
pub const E1000_DEVICE_ID: u16 = 0x100E;

/// Largest frame the adapter moves.
const MAX_FRAME: usize = 2048;

static PRESENT: AtomicBool = AtomicBool::new(false);
static MAC: Mutex<[u8; 6]> = Mutex::new([0; 6]);
/// Frames fetched from the driver and not yet taken by the stack.
static RX_QUEUE: Mutex<VecDeque<Vec<u8>>> = Mutex::new(VecDeque::new());
static PACKETS_RX: AtomicU64 = AtomicU64::new(0);
static PACKETS_TX: AtomicU64 = AtomicU64::new(0);
static BYTES_RX: AtomicU64 = AtomicU64::new(0);
static BYTES_TX: AtomicU64 = AtomicU64::new(0);
/// Receive requests made and frames they returned (diagnostics).
static RECV_CALLS: AtomicU64 = AtomicU64::new(0);
static RECV_FRAMES: AtomicU64 = AtomicU64::new(0);

/// Finds the adapter on the PCI bus and lets it bus-master; returns its register window
/// (`BAR0`) and interrupt line, which the supervisor gives the driver.
///
/// # Returns
///
/// `Some((bar0_address, irq_line))` if found, or `None`.
pub fn find_adapter() -> Option<(u64, u8)> {
    let dev = pci::find_device(E1000_VENDOR_ID, E1000_DEVICE_ID)?;
    pci::enable_bus_mastering(&dev);
    let bar0 = dev.bar0_address();
    (bar0 != 0).then_some((bar0, dev.irq_line))
}

/// Sends a request to the driver; returns its reply.
///
/// # Arguments
/// * `label` - IPC message protocol label.
/// * `args` - Array of 4 argument words.
///
/// # Returns
///
/// The reply [`Message`] on success, or an error description string on failure.
fn request(label: u32, args: [u64; 4]) -> Result<Message, &'static str> {
    match service::call(ENDPOINT_NET_DEV, Message::with_args(label, args), CALL_TIMEOUT_TICKS) {
        Ok(r) if r.label == MSG_NET_REPLY && (r.args[0] as i64) >= 0 => Ok(r),
        Ok(_) => Err("the network driver reported an error"),
        Err(_) => Err("the network driver is not running"),
    }
}

/// Asks the driver (started at the hardware takeover) for the adapter's MAC address.
///
/// # Returns
///
/// `Ok(())` on success, or an error description string on failure.
pub fn init() -> Result<(), &'static str> {
    if !service::is_online(ENDPOINT_NET_DEV) {
        return Err("Intel E1000 (82540EM) network driver is not running");
    }
    let r = request(MSG_NET_GET_MAC, [0; 4])?;
    let lo = (r.args[1] as u32).to_le_bytes();
    let hi = (r.args[2] as u16).to_le_bytes();
    *MAC.lock() = [lo[0], lo[1], lo[2], lo[3], hi[0], hi[1]];
    PRESENT.store(true, Ordering::Release);
    Ok(())
}

/// Wakes the network task whenever the adapter interrupts. Returns whether the driver runs.
///
/// # Returns
///
/// `true` if the network driver is present and running, `false` otherwise.
pub fn enable_interrupts() -> bool {
    service::notify_on_irq(ENDPOINT_NET_DEV, &crate::net::stack::NET_WQ);
    is_present()
}

/// Whether the adapter and its driver are up.
///
/// # Returns
///
/// `true` if initialized and available, `false` otherwise.
pub fn is_present() -> bool {
    PRESENT.load(Ordering::Acquire)
}

/// Packets and bytes received and sent: `(packets_rx, packets_tx, bytes_rx, bytes_tx)`.
///
/// # Returns
///
/// A tuple `(packets_rx, packets_tx, bytes_rx, bytes_tx)`.
pub fn metrics() -> (u64, u64, u64, u64) {
    (
        PACKETS_RX.load(Ordering::Relaxed),
        PACKETS_TX.load(Ordering::Relaxed),
        BYTES_RX.load(Ordering::Relaxed),
        BYTES_TX.load(Ordering::Relaxed),
    )
}

/// Transmits a raw Ethernet frame.
///
/// # Arguments
/// * `frame` - Byte slice containing the raw Ethernet frame.
///
/// # Returns
///
/// `Ok(())` on success, or an error description string on failure.
///
/// # Errors
/// Returns `Err` if the driver is not running, the frame is too long, or the adapter fails.
pub fn send_frame(frame: &[u8]) -> Result<(), &'static str> {
    if !is_present() {
        return Err("E1000 NIC not initialized");
    }
    if frame.is_empty() || frame.len() > MAX_FRAME {
        return Err("Packet exceeds max transmission buffer size (2048 bytes)");
    }
    let window = service::window(ENDPOINT_NET_DEV).ok_or("the network driver is not running")?;
    window[..frame.len()].copy_from_slice(frame);
    request(MSG_NET_TRANSMIT, [frame.len() as u64, 0, 0, 0])?;
    PACKETS_TX.fetch_add(1, Ordering::Relaxed);
    BYTES_TX.fetch_add(frame.len() as u64, Ordering::Relaxed);
    Ok(())
}

/// Takes the next received frame into `out_buf`, fetching a batch from the driver when
/// none is waiting.
///
/// # Arguments
/// * `out_buf` - Destination buffer to store the received packet.
///
/// # Returns
/// `Some(bytes_read)` if a frame was received, or `None` if none arrived.
pub fn receive_frame(out_buf: &mut [u8]) -> Option<usize> {
    if !is_present() {
        return None;
    }
    if RX_QUEUE.lock().is_empty() {
        let count = request(MSG_NET_RECEIVE, [0; 4]).ok()?.args[1] as usize;
        RECV_CALLS.fetch_add(1, Ordering::Relaxed);
        RECV_FRAMES.fetch_add(count as u64, Ordering::Relaxed);
        let window = service::window(ENDPOINT_NET_DEV)?;
        let mut queue = RX_QUEUE.lock();
        let mut at = 0;
        for _ in 0..count {
            let len = u16::from_le_bytes([window[at], window[at + 1]]) as usize;
            queue.push_back(window[at + 2..at + 2 + len].to_vec());
            at += 2 + len;
        }
    }
    let frame = RX_QUEUE.lock().pop_front()?;
    let len = frame.len().min(out_buf.len());
    out_buf[..len].copy_from_slice(&frame[..len]);
    PACKETS_RX.fetch_add(1, Ordering::Relaxed);
    BYTES_RX.fetch_add(len as u64, Ordering::Relaxed);
    Some(len)
}

/// Returns the MAC address of the adapter, or all zeros if it is not up.
///
/// # Returns
///
/// The 6-byte Ethernet MAC address array.
pub fn mac_address() -> [u8; 6] {
    *MAC.lock()
}

/// Driver diagnostics: `(receive requests, frames they returned, adapter's receive head,
/// driver's receive position)`.
///
/// # Returns
///
/// A tuple `(receive_requests, frames_returned, hw_rx_head, driver_rx_pos)`.
pub fn rx_diagnostics() -> (u64, u64, u64, u64) {
    let r = request(MSG_NET_GET_STATUS, [0; 4]).map_or([0; 4], |r| r.args);
    (RECV_CALLS.load(Ordering::Relaxed), RECV_FRAMES.load(Ordering::Relaxed), r[2], r[3])
}

/// Returns `true` if the adapter has a carrier link.
///
/// # Returns
///
/// `true` if physical Ethernet link carrier is detected, `false` otherwise.
pub fn is_link_up() -> bool {
    is_present() && request(MSG_NET_GET_STATUS, [0; 4]).map_or(false, |r| r.args[1] != 0)
}
