//! USB hubs (class 9): USB 2.0 hubs (full or high speed, with their transaction
//! translator for low and full speed devices) and SuperSpeed hubs. A hub's ports are
//! powered, their status read and devices on them reset and set up like those on the
//! controller's own (root) ports; the hub's status change endpoint (an interrupt IN
//! endpoint reporting a bitmap of the ports that changed) tells when to look again.

use crate::{Dma, HidIf, HidKind, Ring, Xhci, DEV_CTL_BUF, DEV_IN_CTX, REPORTS_QUEUED, TRB_CONFIGURE_EP};
use crate::{println, sys, Deadline};

/// Port features (USB 2.0 table 11-17, USB 3.2 table 10-9).
const PORT_RESET: u16 = 4;
const PORT_POWER: u16 = 8;

/// Port status bits (`wPortStatus`).
const ST_CONNECTION: u32 = 1 << 0;
const ST_ENABLE: u32 = 1 << 1;
const ST_RESET: u32 = 1 << 4;
const ST_LOW_SPEED: u32 = 1 << 9;
const ST_HIGH_SPEED: u32 = 1 << 10;

/// Port change bits (`wPortChange`, in the upper half of the status word).
const CH_CONNECTION: u32 = 1 << 16;
const CH_RESET: u32 = 1 << 20;

/// Deepest tier a device may be at (the USB limit: five hubs below the root).
const MAX_DEPTH: u32 = 5;

/// What the driver keeps about a hub.
pub struct Hub {
    /// Downstream ports.
    pub ports: u32,
    /// Multiple transaction translators in use (not used: the hub runs with one).
    pub mtt: bool,
    /// TT think time (hub characteristics bits 5..6), for the slot context.
    pub think_time: u32,
    /// A SuperSpeed hub (its own descriptor, status bits and hub depth).
    pub superspeed: bool,
}

/// The first interrupt IN endpoint of a configuration: address, max packet size, interval.
fn interrupt_in(conf: &[u8]) -> Option<(u8, u16, u8)> {
    let mut at = 0;
    while at + 2 <= conf.len() {
        let (len, ty) = (conf[at] as usize, conf[at + 1]);
        if len < 2 || at + len > conf.len() {
            break;
        }
        let d = &conf[at..at + len];
        if ty == 5 && len >= 7 && d[2] & 0x80 != 0 && d[3] & 3 == 3 {
            return Some((d[2], u16::from_le_bytes([d[4], d[5]]), d[6]));
        }
        at += len;
    }
    None
}

impl Xhci {
    /// Sets up hub `di`: its configuration, descriptor and status change endpoint, then
    /// powers its ports and sets up the devices on them.
    pub(crate) fn setup_hub(&mut self, di: usize, dd: &[u8; 18], conf: &[u8], config_value: u8) -> Result<(), &'static str> {
        let (slot, speed, depth) = (self.devices[di].slot, self.devices[di].speed, self.devices[di].depth);
        if depth >= MAX_DEPTH {
            return Err("hubs nested too deeply");
        }
        let superspeed = speed >= 4 || dd[6] == 3;
        let (ep, mps, interval) = interrupt_in(conf).ok_or("a hub without a status endpoint")?;
        self.control(di, 0x00, 9, config_value as u16, 0, 0)?;
        let n = if superspeed {
            self.control(di, 0xA0, 6, 0x2A00, 0, 12)?
        } else {
            self.control(di, 0xA0, 6, 0x2900, 0, 71)?
        };
        if n < 7 {
            return Err("short hub descriptor");
        }
        let hd = self.devices[di].mem.bytes(DEV_CTL_BUF, n);
        let ports = (hd[2] as u32).min(15);
        let chars = u16::from_le_bytes([hd[3], hd[4]]) as u32;
        let power_on_ms = hd[5] as u32 * 2;
        self.devices[di].hub = Some(Hub {
            ports,
            mtt: false,
            think_time: if speed == 3 { (chars >> 5) & 3 } else { 0 },
            superspeed,
        });
        if superspeed {
            // SET_HUB_DEPTH: where it is, so it can find its tier in route strings
            self.control(di, 0x20, 12, depth as u16, 0, 0)?;
        }
        // The status change endpoint, and the slot context that says it is a hub
        unsafe { core::ptr::write_bytes(self.devices[di].mem.virt.add(DEV_IN_CTX), 0, crate::PAGE) };
        let dci = (ep as u32 & 0xF) * 2 + 1;
        let mem = Dma::alloc(2)?;
        let ring = Ring::new(mem);
        self.write_interrupt_ep(di, dci, interval, mps, ring.mem.phys);
        self.devices[di].hids.push(HidIf {
            kind: HidKind::HubStatus,
            dci,
            ring,
            bufs: mem.at(crate::PAGE),
            queued: [0; REPORTS_QUEUED],
            report_len: (mps as usize & 0x7FF).clamp(1, crate::REPORT_BUF),
            layout: None,
            prev_keys: [0; 8],
            failed: false,
        });
        self.in_ctx(di, 0).w32(4, 1 | 1 << dci);
        self.write_slot_ctx(di, self.max_dci(di));
        let input = self.devices[di].mem.phys + DEV_IN_CTX as u64;
        self.command(input, TRB_CONFIGURE_EP << 10 | slot << 24, 1000)?;
        println!(
            "[usb-driver] {}: {} hub, {} ports",
            self.loc(di),
            if superspeed {
                "SuperSpeed"
            } else if speed == 3 {
                "high speed"
            } else {
                "full speed"
            },
            ports
        );
        for p in 1..=ports {
            let _ = self.control(di, 0x23, 3, PORT_POWER, p as u16, 0);
        }
        sys::sleep_ms(power_on_ms.max(100) as u64);
        self.start_interrupt_eps(di);
        for p in 1..=ports {
            self.hub_port(slot, p);
        }
        Ok(())
    }

    /// Port `port`'s status of hub `di`: status in the low half, changes in the high half.
    fn hub_port_status(&mut self, di: usize, port: u32) -> Option<u32> {
        let n = self.control(di, 0xA3, 0, 0, port as u16, 4).ok()?;
        (n == 4).then(|| u32::from_le_bytes(self.devices[di].mem.bytes(DEV_CTL_BUF, 4).try_into().unwrap()))
    }

    /// Acknowledges the changes `st` reports on hub `di`'s port `port` (each change bit
    /// has a feature to clear it).
    fn hub_clear_changes(&mut self, di: usize, port: u32, st: u32) {
        // wPortChange bits 0..4: C_PORT_CONNECTION .. C_PORT_RESET (features 16..20);
        // SuperSpeed hubs: bit 5 C_BH_PORT_RESET (29), 6 C_PORT_LINK_STATE (25), 7
        // C_PORT_CONFIG_ERROR (26)
        const FEATURES: [u16; 8] = [16, 17, 18, 19, 20, 29, 25, 26];
        for (bit, &feature) in FEATURES.iter().enumerate() {
            if st & (1 << (16 + bit)) != 0 {
                let _ = self.control(di, 0x23, 1, feature, port as u16, 0);
            }
        }
    }

    /// Looks at port `port` of the hub in slot `hub_slot`: a device that left is
    /// forgotten, a new one reset and set up.
    pub(crate) fn hub_port(&mut self, hub_slot: u32, port: u32) {
        let Some(di) = self.dev_of_slot(hub_slot) else { return };
        let Some(st) = self.hub_port_status(di, port) else { return };
        self.hub_clear_changes(di, port, st);
        let connected = st & ST_CONNECTION != 0;
        let child = self.devices.iter().find(|d| d.parent == hub_slot && d.parent_port == port).map(|d| (d.port, d.route, d.depth));
        if let Some((root, route, depth)) = child {
            if !connected || st & CH_CONNECTION != 0 {
                self.detach_tree(root, route, depth);
            }
        }
        if !connected || self.devices.iter().any(|d| d.parent == hub_slot && d.parent_port == port) {
            return;
        }
        // Debounce, then reset the port
        sys::sleep_ms(100);
        let Some(di) = self.dev_of_slot(hub_slot) else { return };
        match self.hub_port_status(di, port) {
            Some(st) if st & ST_CONNECTION != 0 => {}
            _ => return,
        }
        if self.control(di, 0x23, 3, PORT_RESET, port as u16, 0).is_err() {
            return;
        }
        let d = Deadline::after_ms(800);
        let st = loop {
            sys::sleep_ms(10);
            match self.hub_port_status(di, port) {
                Some(st) if st & CH_RESET != 0 && st & ST_RESET == 0 => break Some(st),
                Some(st) if st & ST_CONNECTION == 0 => break None,
                None => break None,
                _ => {}
            }
            if d.expired() {
                break None;
            }
        };
        let Some(st) = st else {
            println!("[usb-driver] {}: hub port {}: reset failed", self.loc(di), port);
            return;
        };
        self.hub_clear_changes(di, port, st);
        if st & ST_ENABLE == 0 {
            println!("[usb-driver] {}: hub port {}: not enabled after a reset", self.loc(di), port);
            return;
        }
        // Reset recovery (USB 2.0 7.1.7.5)
        sys::sleep_ms(10);
        let hub = &self.devices[di];
        let superspeed = hub.hub.as_ref().is_some_and(|h| h.superspeed);
        let speed = if superspeed {
            4
        } else if st & ST_LOW_SPEED != 0 {
            2
        } else if st & ST_HIGH_SPEED != 0 {
            3
        } else {
            1
        };
        let route = hub.route | port.min(15) << (4 * hub.depth);
        // Low and full speed devices behind a high speed hub talk through its
        // transaction translator; behind a full speed hub, through the one above it
        let tt = if speed <= 2 && hub.speed == 3 {
            (hub.slot, port)
        } else if speed <= 2 {
            (hub.tt_slot, hub.tt_port)
        } else {
            (0, 0)
        };
        let (root, depth) = (hub.port, hub.depth + 1);
        if let Err(e) = self.attach_device(root, route, depth, speed, hub_slot, port, tt) {
            println!("[usb-driver] {}: hub port {}: {}", self.loc(di), port, e);
        }
    }

    /// A hub's status change endpoint reported something: looks at each of its ports.
    pub(crate) fn hub_service(&mut self, di: usize) {
        let slot = self.devices[di].slot;
        let ports = self.devices[di].hub.as_ref().map_or(0, |h| h.ports);
        for p in 1..=ports {
            self.hub_port(slot, p);
        }
    }
}
