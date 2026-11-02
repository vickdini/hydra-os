//! # Hydra e1000 network driver
//!
//! Drives an Intel 82540EM (e1000) network adapter from Ring 3, in an address space of its
//! own: its registers are the device memory the supervisor granted (PCI `BAR0`), its
//! descriptor rings and packet buffers DMA memory it allocates. The kernel enumerates PCI
//! (enabling bus mastering) and starts it with `bar0=<phys> irq=<line>`.
//!
//! The driver only answers requests. When the adapter interrupts, the kernel masks the line
//! and wakes its network task, which asks for the received frames; the driver acknowledges
//! the interrupt causes and unmasks the line then.
//!
//! Requests on [`ENDPOINT_NET_DEV`] (frames travel through the service window):
//! - `MSG_NET_TRANSMIT [len]`: send the frame at the start of the window;
//! - `MSG_NET_RECEIVE`: fill the window with received frames, each a 16-bit little-endian
//!   length then its bytes; reply `[0, frame count]`;
//! - `MSG_NET_GET_MAC`: reply `[0, MAC bytes 0..4, MAC bytes 4..6]`;
//! - `MSG_NET_GET_STATUS`: reply `[0, link up]`.

#![no_std]
#![no_main]

extern crate alloc;

use hydra_rt::protocol::{
    ENDPOINT_NET_DEV, MSG_NET_GET_MAC, MSG_NET_GET_STATUS, MSG_NET_RECEIVE, MSG_NET_REPLY, MSG_NET_TRANSMIT,
};
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

hydra_rt::entry!(main);

const REG_CTRL: usize = 0x0000;
const REG_STATUS: usize = 0x0008;
const REG_ICR: usize = 0x00C0;
const REG_IMS: usize = 0x00D0;
const REG_IMC: usize = 0x00D8;
const REG_RDTR: usize = 0x2820;
const REG_RCTL: usize = 0x0100;
const REG_TCTL: usize = 0x0400;
const REG_TIPG: usize = 0x0410;
const REG_RDBAL: usize = 0x2800;
const REG_RDBAH: usize = 0x2804;
const REG_RDLEN: usize = 0x2808;
const REG_RDH: usize = 0x2810;
const REG_RDT: usize = 0x2818;
const REG_TDBAL: usize = 0x3800;
const REG_TDBAH: usize = 0x3804;
const REG_TDLEN: usize = 0x3808;
const REG_TDH: usize = 0x3810;
const REG_TDT: usize = 0x3818;
const REG_RAL0: usize = 0x5400;
const REG_RAH0: usize = 0x5404;

const CTRL_SLU: u32 = 1 << 6;
const CTRL_RST: u32 = 1 << 26;
const STATUS_LU: u32 = 1 << 1;
const RCTL_EN: u32 = 1 << 1;
const RCTL_SBP: u32 = 1 << 2;
const RCTL_UPE: u32 = 1 << 3;
const RCTL_MPE: u32 = 1 << 4;
const RCTL_BAM: u32 = 1 << 15;
const RCTL_SECRC: u32 = 1 << 26;
const TCTL_EN: u32 = 1 << 1;
const TCTL_PSP: u32 = 1 << 3;

const INT_LSC: u32 = 1 << 2;
const INT_RXDMT0: u32 = 1 << 4;
const INT_RXO: u32 = 1 << 6;
const INT_RXT0: u32 = 1 << 7;

const NUM_TX: usize = 32;
const NUM_RX: usize = 256;
const BUF: usize = 2048;
/// Size of the register window mapped.
const MMIO_LEN: usize = 128 * 1024;

const EIO: i64 = -5;
const EINVAL: i64 = -22;

/// A legacy transmit or receive descriptor (16 bytes; the fields differ by direction).
#[repr(C)]
#[derive(Clone, Copy)]
struct Desc {
    addr: u64,
    length: u16,
    /// TX: checksum offset; RX: checksum.
    cso_or_csum_lo: u8,
    /// TX: command; RX: checksum high byte.
    cmd_or_csum_hi: u8,
    status: u8,
    /// TX: checksum start; RX: errors.
    css_or_errors: u8,
    special: u16,
}

struct Nic {
    regs: *mut u8,
    /// DMA memory: RX descriptors, TX descriptors, RX buffers, TX buffers.
    mem: *mut u8,
    mem_phys: u64,
    mac: [u8; 6],
    tx_cur: usize,
    rx_cur: usize,
    irq: Option<u8>,
}

const RX_DESC_OFF: usize = 0;
const TX_DESC_OFF: usize = NUM_RX * 16;
const RX_BUF_OFF: usize = 8192;
const TX_BUF_OFF: usize = RX_BUF_OFF + NUM_RX * BUF;
const DMA_LEN: usize = TX_BUF_OFF + NUM_TX * BUF;

impl Nic {
    fn read(&self, reg: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.regs.add(reg) as *const u32) }
    }

    fn write(&self, reg: usize, v: u32) {
        unsafe { core::ptr::write_volatile(self.regs.add(reg) as *mut u32, v) }
    }

    fn rx_desc(&self, i: usize) -> *mut Desc {
        unsafe { self.mem.add(RX_DESC_OFF + i * 16) as *mut Desc }
    }

    fn tx_desc(&self, i: usize) -> *mut Desc {
        unsafe { self.mem.add(TX_DESC_OFF + i * 16) as *mut Desc }
    }

    /// Resets the adapter and sets up both rings.
    fn init(&mut self) {
        self.write(REG_IMC, 0xFFFF_FFFF);
        self.write(REG_CTRL, self.read(REG_CTRL) | CTRL_RST);
        for _ in 0..100_000 {
            core::hint::spin_loop();
        }
        self.write(REG_IMC, 0xFFFF_FFFF);
        let (ral, rah) = (self.read(REG_RAL0), self.read(REG_RAH0));
        self.mac = [ral as u8, (ral >> 8) as u8, (ral >> 16) as u8, (ral >> 24) as u8, rah as u8, (rah >> 8) as u8];

        for i in 0..NUM_TX {
            unsafe {
                self.tx_desc(i).write_volatile(Desc {
                    addr: self.mem_phys + (TX_BUF_OFF + i * BUF) as u64,
                    length: 0,
                    cso_or_csum_lo: 0,
                    cmd_or_csum_hi: 0,
                    status: 1, // free
                    css_or_errors: 0,
                    special: 0,
                })
            };
        }
        for i in 0..NUM_RX {
            unsafe {
                self.rx_desc(i).write_volatile(Desc {
                    addr: self.mem_phys + (RX_BUF_OFF + i * BUF) as u64,
                    length: 0,
                    cso_or_csum_lo: 0,
                    cmd_or_csum_hi: 0,
                    status: 0,
                    css_or_errors: 0,
                    special: 0,
                })
            };
        }
        let tx = self.mem_phys + TX_DESC_OFF as u64;
        self.write(REG_TDBAL, tx as u32);
        self.write(REG_TDBAH, (tx >> 32) as u32);
        self.write(REG_TDLEN, (NUM_TX * 16) as u32);
        self.write(REG_TDH, 0);
        self.write(REG_TDT, 0);
        self.write(REG_TCTL, TCTL_EN | TCTL_PSP | (15 << 4) | (0x40 << 12));
        self.write(REG_TIPG, 0x0060_200A);

        let rx = self.mem_phys + RX_DESC_OFF as u64;
        self.write(REG_RDBAL, rx as u32);
        self.write(REG_RDBAH, (rx >> 32) as u32);
        self.write(REG_RDLEN, (NUM_RX * 16) as u32);
        self.write(REG_RDH, 0);
        self.write(REG_RDT, (NUM_RX - 1) as u32);
        self.write(REG_RCTL, RCTL_EN | RCTL_SBP | RCTL_UPE | RCTL_MPE | RCTL_BAM | RCTL_SECRC);

        self.write(REG_CTRL, self.read(REG_CTRL) | CTRL_SLU);
        for _ in 0..50 {
            if self.link_up() {
                break;
            }
            sys::sleep_ms(10);
        }
    }

    fn link_up(&self) -> bool {
        self.read(REG_STATUS) & STATUS_LU != 0
    }

    /// Routes the adapter's interrupt to this driver and enables the causes the kernel's
    /// network task waits for.
    fn enable_interrupts(&mut self, irq: u8) {
        if sys::irq_register(irq).is_err() {
            println!("[e1000-driver] interrupt line {} unavailable; the network is polled", irq);
            return;
        }
        self.irq = Some(irq);
        self.write(REG_RDTR, 0); // an interrupt per frame
        self.read(REG_ICR);
        self.write(REG_IMS, INT_RXT0 | INT_RXO | INT_RXDMT0 | INT_LSC);
    }

    fn transmit(&mut self, frame: &[u8]) -> Result<(), &'static str> {
        if frame.is_empty() || frame.len() > BUF {
            return Err("bad frame length");
        }
        let cur = self.tx_cur;
        unsafe {
            core::ptr::copy_nonoverlapping(frame.as_ptr(), self.mem.add(TX_BUF_OFF + cur * BUF), frame.len());
            let d = self.tx_desc(cur);
            let mut desc = d.read_volatile();
            desc.length = frame.len() as u16;
            desc.cmd_or_csum_hi = (1 << 0) | (1 << 1) | (1 << 3); // EOP | IFCS | RS
            desc.status = 0;
            d.write_volatile(desc);
        }
        self.tx_cur = (cur + 1) % NUM_TX;
        self.write(REG_TDT, self.tx_cur as u32);
        for _ in 0..1_000_000 {
            if unsafe { self.tx_desc(cur).read_volatile().status } & 1 != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        Err("transmit timed out")
    }

    /// Moves received frames into `out` (length-prefixed); returns how many. Acknowledges
    /// the interrupt and unmasks the line.
    fn receive(&mut self, out: &mut [u8]) -> usize {
        self.read(REG_ICR); // acknowledge: the adapter stops asserting the line
        let (mut count, mut at) = (0, 0);
        loop {
            let d = self.rx_desc(self.rx_cur);
            let mut desc = unsafe { d.read_volatile() };
            if desc.status & 1 == 0 {
                break;
            }
            let len = desc.length as usize;
            if at + 2 + len > out.len() {
                break; // the rest waits for the next request
            }
            out[at..at + 2].copy_from_slice(&(len as u16).to_le_bytes());
            unsafe { core::ptr::copy_nonoverlapping(self.mem.add(RX_BUF_OFF + self.rx_cur * BUF), out[at + 2..].as_mut_ptr(), len) };
            at += 2 + len;
            count += 1;
            desc.status = 0;
            unsafe { d.write_volatile(desc) };
            self.write(REG_RDT, self.rx_cur as u32);
            self.rx_cur = (self.rx_cur + 1) % NUM_RX;
        }
        if let Some(irq) = self.irq {
            let _ = sys::irq_ack(irq);
        }
        count
    }
}

fn reply(args: [u64; 4]) -> Message {
    Message::new(MSG_NET_REPLY as u64, args)
}

/// Value of a `key=<number>` argument (decimal or `0x` hex).
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

fn main(args: &[&str]) {
    let Some(bar0) = arg(args, "bar0") else {
        println!("[e1000-driver] no adapter given (bar0=...)");
        return;
    };
    let regs = match sys::physmap(bar0, MMIO_LEN) {
        Ok(r) => r,
        Err(e) => {
            println!("[e1000-driver] cannot map the registers at {:#x}: error {}", bar0, e);
            return;
        }
    };
    let (mem, mem_phys) = match sys::dma_alloc(DMA_LEN) {
        Ok(m) => m,
        Err(e) => {
            println!("[e1000-driver] no DMA memory: error {}", e);
            return;
        }
    };
    let mut nic = Nic { regs, mem, mem_phys, mac: [0; 6], tx_cur: 0, rx_cur: 0, irq: None };
    nic.init();
    if let Some(irq) = arg(args, "irq") {
        nic.enable_interrupts(irq as u8);
    }
    let mut server = match Server::register(ENDPOINT_NET_DEV) {
        Ok(s) => s,
        Err(e) => {
            println!("[e1000-driver] cannot register on endpoint {:#x}: error {}", ENDPOINT_NET_DEV, e);
            return;
        }
    };
    let m = nic.mac;
    println!(
        "[e1000-driver] MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}",
        m[0], m[1], m[2], m[3], m[4], m[5],
        if nic.link_up() { "up" } else { "down" }
    );
    server.serve(|srv, msg| match msg.label as u32 {
        MSG_NET_TRANSMIT => {
            let len = msg.args[0] as usize;
            if len == 0 || len > BUF.min(WINDOW_SIZE) {
                return reply([EINVAL as u64, 0, 0, 0]);
            }
            match nic.transmit(&srv.window()[..len]) {
                Ok(()) => reply([0, len as u64, 0, 0]),
                Err(_) => reply([EIO as u64, 0, 0, 0]),
            }
        }
        MSG_NET_RECEIVE => {
            let n = nic.receive(srv.window());
            reply([0, n as u64, 0, 0])
        }
        MSG_NET_GET_MAC => {
            let m = nic.mac;
            reply([0, u32::from_le_bytes([m[0], m[1], m[2], m[3]]) as u64, u16::from_le_bytes([m[4], m[5]]) as u64, 0])
        }
        MSG_NET_GET_STATUS => {
            let d = unsafe { nic.rx_desc(nic.rx_cur).read_volatile() };
            reply([0, nic.link_up() as u64, nic.read(REG_RDH) as u64 | (nic.read(REG_RDT) as u64) << 16, nic.rx_cur as u64 | (d.status as u64) << 16 | (d.length as u64) << 32 | (d.css_or_errors as u64) << 48])
        }
        _ => reply([(-38i64) as u64, 0, 0, 0]),
    })
}
