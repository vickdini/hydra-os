//! # Hydra e1000 network driver
//!
//! Drives an Intel gigabit network adapter of the e1000 families from Ring 3, in an
//! address space of its own: its registers are the device memory the supervisor granted
//! (PCI `BAR0`), its descriptor rings and packet buffers DMA memory it allocates. The
//! kernel enumerates PCI (enabling bus mastering) and starts it with
//! `bar0=<phys> irq=<line> model=<family>`, the family being
//! - `82540`: the 8254x (QEMU's `e1000`, an 82540EM);
//! - `82574`: the 82574L (QEMU's `e1000e`);
//! - `pch`: the PHYs built into Intel chipsets' MAC (I217, I218, I219: "PCH LAN"), such as
//!   the I218-V of a Haswell NUC.
//! All three take the legacy descriptor formats and the same queue registers; they differ
//! in reset and in how the link comes up (see [`Nic::init`]).
//!
//! The driver only answers requests; its client is net-server (`net-server`), which takes
//! the frames through this driver's window. When the adapter interrupts, the kernel masks
//! the line (or, for a message-signalled interrupt, just counts it) and notifies
//! net-server, which asks for the received frames; the driver acknowledges the interrupt
//! causes and unmasks the line then.
//!
//! Requests on [`ENDPOINT_NET_DEV`] (frames travel through the service window):
//! - `MSG_NET_TRANSMIT [len]`: send the frame at the start of the window;
//! - `MSG_NET_TRANSMIT_BATCH [count]`: send `count` frames, laid out in the window as
//!   `MSG_NET_RECEIVE` returns them; reply `[0, frames sent]`;
//! - `MSG_NET_RECEIVE`: fill the window with received frames, each a 16-bit little-endian
//!   length then its bytes; reply `[0, frame count]`;
//! - `MSG_NET_GET_MAC`: reply `[0, MAC bytes 0..4, MAC bytes 4..6]`;
//! - `MSG_NET_GET_STATUS`: reply `[0, link up]`;
//! - `MSG_NET_DMA_TEST [phys]` (test only, with the argument `dma_test=1`): the adapter
//!   reads 64 bytes at physical `phys` by DMA (a transmit descriptor pointing there), as
//!   a rogue driver would; the IOMMU should block it.

#![no_std]
#![no_main]

extern crate alloc;

use hydra_rt::protocol::{
    ENDPOINT_NET_DEV, MSG_NET_DMA_TEST, MSG_NET_GET_MAC, MSG_NET_GET_STATUS, MSG_NET_RECEIVE, MSG_NET_REPLY,
    MSG_NET_TRANSMIT, MSG_NET_TRANSMIT_BATCH,
};
use hydra_rt::{println, sys, Message, Server, WINDOW_SIZE};

hydra_rt::entry!(main);

const REG_CTRL: usize = 0x0000;
const REG_STATUS: usize = 0x0008;
const REG_CTRL_EXT: usize = 0x0018;
const REG_MDIC: usize = 0x0020;
const REG_FEXTNVM3: usize = 0x003C;
const REG_EXTCNF_CTRL: usize = 0x0F00;
/// wave11 GH: the management firmware's status (PCH): FW_VALID (bit 15) when the chipset's
/// firmware runs, RSPCIPHY (bit 6) clear when it blocks PHY resets.
const REG_FWSM: usize = 0x5B54;
const FWSM_FW_VALID: u32 = 1 << 15;
const FWSM_RSPCIPHY: u32 = 1 << 6;
/// CTRL_EXT: the MAC talks to the PHY over SMBus (its low-power path), not MDIO.
const CTRL_EXT_FORCE_SMBUS: u32 = 1 << 11;
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

const CTRL_FD: u32 = 1 << 0;
const CTRL_ASDE: u32 = 1 << 5;
const CTRL_SLU: u32 = 1 << 6;
const CTRL_SPEED_1000: u32 = 2 << 8;
const CTRL_FRCSPD: u32 = 1 << 11;
const CTRL_FRCDPX: u32 = 1 << 12;
const CTRL_RST: u32 = 1 << 26;
const CTRL_LANPHYPC_OVERRIDE: u32 = 1 << 16;
const CTRL_LANPHYPC_VALUE: u32 = 1 << 17;
const CTRL_PHY_RST: u32 = 1 << 31;
const CTRL_EXT_LPCD: u32 = 1 << 2;
const CTRL_EXT_DRV_LOAD: u32 = 1 << 28;
const STATUS_LU: u32 = 1 << 1;
const STATUS_LAN_INIT_DONE: u32 = 1 << 9;
const EXTCNF_SWFLAG: u32 = 1 << 5;
const MDIC_READ: u32 = 2 << 26;
const MDIC_WRITE: u32 = 1 << 26;
const MDIC_READY: u32 = 1 << 28;
const MDIC_ERROR: u32 = 1 << 30;
/// PHY control register (IEEE 802.3 clause 22 register 0) and its bits.
const PHY_BMCR: u32 = 0;
const BMCR_POWER_DOWN: u16 = 1 << 11;
const BMCR_ANEG_ENABLE: u16 = 1 << 12;
const BMCR_ANEG_RESTART: u16 = 1 << 9;
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
/// The causes the network task is woken for.
const INT_CAUSES: u32 = INT_RXT0 | INT_RXO | INT_RXDMT0 | INT_LSC;

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

/// Adapter family (see the module documentation).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Model {
    I82540,
    I82574,
    Pch,
}

impl Model {
    /// The PHY's address on the adapter's MDIO bus.
    fn phy_addr(self) -> u32 {
        match self {
            Model::Pch => 2,
            _ => 1,
        }
    }

    /// Name for the log.
    fn name(self) -> &'static str {
        match self {
            Model::I82540 => "82540EM",
            Model::I82574 => "82574L",
            Model::Pch => "PCH LAN (I217/I218/I219)",
        }
    }
}

struct Nic {
    model: Model,
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
    /// Reads a 32-bit MMIO register from the controller.
    ///
    /// # Arguments
    /// * `reg` - Register byte offset.
    ///
    /// # Returns
    /// 32-bit register value.
    fn read(&self, reg: usize) -> u32 {
        unsafe { core::ptr::read_volatile(self.regs.add(reg) as *const u32) }
    }

    /// Writes a 32-bit MMIO register on the controller.
    ///
    /// # Arguments
    /// * `reg` - Register byte offset.
    /// * `v` - Value to write.
    fn write(&self, reg: usize, v: u32) {
        unsafe { core::ptr::write_volatile(self.regs.add(reg) as *mut u32, v) }
    }

    /// Returns a pointer to the receive descriptor at index `i`.
    ///
    /// # Arguments
    /// * `i` - Descriptor ring index.
    ///
    /// # Returns
    /// Raw pointer to descriptor structure.
    fn rx_desc(&self, i: usize) -> *mut Desc {
        unsafe { self.mem.add(RX_DESC_OFF + i * 16) as *mut Desc }
    }

    /// Returns a pointer to the transmit descriptor at index `i`.
    ///
    /// # Arguments
    /// * `i` - Descriptor ring index.
    ///
    /// # Returns
    /// Raw pointer to descriptor structure.
    fn tx_desc(&self, i: usize) -> *mut Desc {
        unsafe { self.mem.add(TX_DESC_OFF + i * 16) as *mut Desc }
    }

    /// Waits up to `ms` milliseconds for `(read(reg) & mask) == want`.
    fn wait_reg(&self, reg: usize, mask: u32, want: u32, ms: u64) -> bool {
        let end = sys::uptime_ticks() + ms.div_ceil(10) + 1;
        loop {
            if self.read(reg) & mask == want {
                return true;
            }
            if sys::uptime_ticks() >= end {
                return false;
            }
            sys::sleep_ms(1);
        }
    }

    /// Takes the software semaphore that PCH adapters share with the chipset's management
    /// firmware for the PHY and the reset (up to 1 s, as Linux allows).
    fn acquire_swflag(&self) -> bool {
        if self.model != Model::Pch {
            return true;
        }
        if !self.wait_reg(REG_EXTCNF_CTRL, EXTCNF_SWFLAG, 0, 1000) {
            println!("[e1000-driver] the PHY semaphore stays taken by the firmware");
            return false;
        }
        self.write(REG_EXTCNF_CTRL, self.read(REG_EXTCNF_CTRL) | EXTCNF_SWFLAG);
        if !self.wait_reg(REG_EXTCNF_CTRL, EXTCNF_SWFLAG, EXTCNF_SWFLAG, 100) {
            println!("[e1000-driver] the PHY semaphore cannot be taken");
            return false;
        }
        true
    }

    /// Gives the semaphore of [`Nic::acquire_swflag`] back.
    fn release_swflag(&self) {
        if self.model == Model::Pch {
            self.write(REG_EXTCNF_CTRL, self.read(REG_EXTCNF_CTRL) & !EXTCNF_SWFLAG);
        }
    }

    /// One MDIO access to PHY register `reg` (a read when `write` is `None`).
    fn mdic(&self, reg: u32, write: Option<u16>) -> Option<u16> {
        if !self.acquire_swflag() {
            return None;
        }
        let op = match write {
            Some(v) => MDIC_WRITE | v as u32,
            None => MDIC_READ,
        };
        self.write(REG_MDIC, op | (reg & 0x1F) << 16 | self.model.phy_addr() << 21);
        let mut result = None;
        // MDIO runs at about 2.5 MHz: an access takes some 50 microseconds; allow 100 ms
        let end = sys::uptime_ticks() + 11;
        loop {
            let m = self.read(REG_MDIC);
            if m & MDIC_READY != 0 {
                if m & MDIC_ERROR == 0 {
                    result = Some(m as u16);
                }
                break;
            }
            if sys::uptime_ticks() >= end {
                break;
            }
            core::hint::spin_loop();
        }
        self.release_swflag();
        result
    }

    /// Wakes a PCH PHY that the firmware or a previous operating system left in its
    /// ultra-low-power state, where it does not answer on MDIO: toggles the LANPHYPC pin
    /// (as Linux's `e1000_toggle_lanphypc_pch_lpt`), which power-cycles the PHY.
    fn toggle_lanphypc(&self) {
        // The PHY configuration counter: 50 ms after the power cycle
        let f = self.read(REG_FEXTNVM3);
        self.write(REG_FEXTNVM3, (f & !7) | 0x1);
        let ctrl = self.read(REG_CTRL);
        self.write(REG_CTRL, (ctrl | CTRL_LANPHYPC_OVERRIDE) & !CTRL_LANPHYPC_VALUE);
        self.read(REG_STATUS);
        sys::sleep_ms(1);
        self.write(REG_CTRL, self.read(REG_CTRL) & !CTRL_LANPHYPC_OVERRIDE);
        self.read(REG_STATUS);
        // The adapter reports the PHY's configuration done
        if !self.wait_reg(REG_CTRL_EXT, CTRL_EXT_LPCD, CTRL_EXT_LPCD, 100) {
            println!("[e1000-driver] the PHY did not report its configuration done after a power cycle");
        }
        sys::sleep_ms(30);
    }

    // wave11 GH begin
    /// The PHY's identifier (registers 2 and 3), when the PHY answers on MDIO.
    fn phy_id(&self) -> Option<u32> {
        let hi = self.mdic(2, None)?;
        let lo = self.mdic(3, None)?;
        (hi != 0xFFFF && lo != 0xFFFF && (hi, lo) != (0, 0)).then_some((hi as u32) << 16 | lo as u32)
    }

    /// Makes a PCH PHY reachable on MDIO, as Linux's `e1000_init_phy_workarounds_pchlan`
    /// does for Lynx Point (I217/I218): a PHY left in its low-power (SMBus) mode by the
    /// firmware or another operating system answers only after the MAC is switched to
    /// SMBus and back, or after a LANPHYPC power cycle (not when the chipset's management
    /// firmware blocks PHY resets). Logs what it found: the NUC run's log tells.
    fn pch_phy_reachable(&self) -> bool {
        let fwsm = self.read(REG_FWSM);
        println!(
            "[e1000-driver] PCH: FWSM {:#x} (management firmware {}, PHY resets {}), STATUS {:#x}, CTRL_EXT {:#x}",
            fwsm,
            if fwsm & FWSM_FW_VALID != 0 { "running" } else { "off" },
            if fwsm & FWSM_RSPCIPHY == 0 { "blocked" } else { "allowed" },
            self.read(REG_STATUS),
            self.read(REG_CTRL_EXT)
        );
        if let Some(id) = self.phy_id() {
            println!("[e1000-driver] PHY {:#010x} answers", id);
            return true;
        }
        // The MAC through SMBus for a moment (50 ms for it to finish its retries)
        self.write(REG_CTRL_EXT, self.read(REG_CTRL_EXT) | CTRL_EXT_FORCE_SMBUS);
        sys::sleep_ms(50);
        if let Some(id) = self.phy_id() {
            println!("[e1000-driver] PHY {:#010x} answers after the SMBus switch", id);
            self.write(REG_CTRL_EXT, self.read(REG_CTRL_EXT) & !CTRL_EXT_FORCE_SMBUS);
            return true;
        }
        if fwsm & FWSM_RSPCIPHY == 0 {
            println!("[e1000-driver] the PHY does not answer and the management firmware blocks its power cycle");
            self.write(REG_CTRL_EXT, self.read(REG_CTRL_EXT) & !CTRL_EXT_FORCE_SMBUS);
            return false;
        }
        println!("[e1000-driver] the PHY does not answer; power-cycling it (LANPHYPC)");
        self.toggle_lanphypc();
        // The power cycle takes the PHY out of SMBus mode: the MAC too
        self.write(REG_CTRL_EXT, self.read(REG_CTRL_EXT) & !CTRL_EXT_FORCE_SMBUS);
        match self.phy_id() {
            Some(id) => {
                println!("[e1000-driver] PHY {:#010x} answers after the power cycle", id);
                true
            }
            None => {
                println!("[e1000-driver] the PHY still does not answer");
                false
            }
        }
    }
    // wave11 GH end

    /// Makes sure the PHY is powered and negotiating (82574 and PCH: the MAC follows the
    /// speed and duplex the PHY negotiated).
    fn phy_up(&self) {
        // wave11 GH: the PCH PHY reachable first (low-power mode, see pch_phy_reachable)
        if self.model == Model::Pch {
            self.pch_phy_reachable();
        }
        let bmcr = self.mdic(PHY_BMCR, None);
        match bmcr {
            Some(b) if b != 0xFFFF => {
                if b & BMCR_POWER_DOWN != 0 || b & BMCR_ANEG_ENABLE == 0 {
                    let v = (b & !BMCR_POWER_DOWN) | BMCR_ANEG_ENABLE | BMCR_ANEG_RESTART;
                    let _ = self.mdic(PHY_BMCR, Some(v));
                }
            }
            _ => println!("[e1000-driver] cannot reach the PHY; the link may stay down"),
        }
    }

    /// Resets the MAC. On 82574 and PCH adapters the receive and transmit units are
    /// stopped and drained first, and PCH ones reset under the firmware semaphore and
    /// then reload their configuration from the NVM.
    fn reset(&self) {
        self.write(REG_IMC, 0xFFFF_FFFF);
        if self.model != Model::I82540 {
            self.write(REG_RCTL, 0);
            self.write(REG_TCTL, TCTL_PSP);
            self.read(REG_STATUS);
            sys::sleep_ms(10);
        }
        let mut ctrl = self.read(REG_CTRL) | CTRL_RST;
        if self.model == Model::Pch {
            // The semaphore is released by the reset itself
            self.acquire_swflag();
            ctrl &= !CTRL_PHY_RST;
        }
        self.write(REG_CTRL, ctrl);
        if self.model != Model::I82540 {
            // Reading registers while the reset runs can hang PCH adapters
            sys::sleep_ms(20);
        }
        if !self.wait_reg(REG_CTRL, CTRL_RST, 0, 1000) {
            println!("[e1000-driver] the adapter did not finish its reset");
        }
        if self.model == Model::Pch && !self.wait_reg(REG_STATUS, STATUS_LAN_INIT_DONE, STATUS_LAN_INIT_DONE, 150) {
            println!("[e1000-driver] the adapter did not report its NVM configuration loaded");
        }
        self.write(REG_IMC, 0xFFFF_FFFF);
        self.read(REG_ICR);
        if self.model != Model::I82540 {
            // Tells the management firmware an operating system driver runs the adapter
            self.write(REG_CTRL_EXT, self.read(REG_CTRL_EXT) | CTRL_EXT_DRV_LOAD);
        }
    }

    /// Resets the adapter and sets up both rings.
    fn init(&mut self) {
        self.reset();
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

        let ctrl = self.read(REG_CTRL) & !CTRL_RST;
        let ctrl = if self.model == Model::I82540 {
            ctrl | CTRL_SLU | CTRL_ASDE | CTRL_FD | CTRL_SPEED_1000 | CTRL_FRCSPD | CTRL_FRCDPX
        } else {
            // The MAC takes speed and duplex from the PHY's negotiation
            (ctrl | CTRL_SLU) & !(CTRL_FRCSPD | CTRL_FRCDPX)
        };
        self.write(REG_CTRL, ctrl);
        if self.model != Model::I82540 {
            self.phy_up();
        }
        self.read(REG_ICR);

        // Negotiation on a real link takes 2 to 3 s; the network stack retries DHCP, so
        // only a short wait here

        for _ in 0..100 {
            if self.link_up() {
                break;
            }
            sys::sleep_ms(10);
        }
    }

    /// Checks whether link is established.
    ///
    /// # Returns
    /// `true` if link is up, `false` otherwise.
    fn link_up(&self) -> bool {
        self.read(REG_STATUS) & STATUS_LU != 0
    }

    /// Routes the adapter's interrupt to this driver and enables the causes the kernel's
    /// network task waits for.
    ///
    /// # Arguments
    /// * `irq` - Hardware IRQ line number.
    fn enable_interrupts(&mut self, irq: u8) {
        if sys::irq_register(irq).is_err() {
            println!("[e1000-driver] interrupt line {} unavailable; the network is polled", irq);
            return;
        }
        self.irq = Some(irq);
        self.write(REG_RDTR, 0); // an interrupt per frame
        self.read(REG_ICR);
        self.write(REG_IMS, INT_CAUSES);
    }

    /// Transmits an Ethernet frame via DMA.
    ///
    /// # Arguments
    /// * `frame` - Raw Ethernet frame bytes.
    ///
    /// # Returns
    /// `Ok(())` on success.
    ///
    /// # Errors
    /// Static error string if frame length is invalid or transmit times out.
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
        for _ in 0..100_000 {
            if unsafe { self.tx_desc(cur).read_volatile().status } & 1 != 0 {
                return Ok(());
            }
            core::hint::spin_loop();
        }
        for _ in 0..100 {
            if unsafe { self.tx_desc(cur).read_volatile().status } & 1 != 0 {
                return Ok(());
            }
            sys::sleep_ms(2);
        }
        Err("transmit timed out")
    }

    /// Test only: sends one 64-byte frame whose buffer is at physical `phys` (outside this
    /// driver's DMA memory), then puts the descriptor's own buffer address back.
    ///
    /// # Errors
    /// Static error string if the descriptor does not complete.
    fn rogue_dma(&mut self, phys: u64) -> Result<(), &'static str> {
        let cur = self.tx_cur;
        let own = self.mem_phys + (TX_BUF_OFF + cur * BUF) as u64;
        unsafe {
            let d = self.tx_desc(cur);
            let mut desc = d.read_volatile();
            desc.addr = phys;
            desc.length = 64;
            desc.cmd_or_csum_hi = (1 << 0) | (1 << 1) | (1 << 3); // EOP | IFCS | RS
            desc.status = 0;
            d.write_volatile(desc);
        }
        self.tx_cur = (cur + 1) % NUM_TX;
        self.write(REG_TDT, self.tx_cur as u32);
        let mut done = false;
        for _ in 0..200 {
            if unsafe { self.tx_desc(cur).read_volatile().status } & 1 != 0 {
                done = true;
                break;
            }
            sys::sleep_ms(2);
        }
        unsafe {
            let d = self.tx_desc(cur);
            let mut desc = d.read_volatile();
            desc.addr = own;
            d.write_volatile(desc);
        }
        if done { Ok(()) } else { Err("the test descriptor did not complete") }
    }

    /// Moves received frames into `out` (length-prefixed); returns how many. Acknowledges
    /// the interrupt and unmasks the line.
    ///
    /// # Arguments
    /// * `out` - Destination buffer to store received frames.
    ///
    /// # Returns
    /// Count of complete frames stored.
    fn receive(&mut self, out: &mut [u8]) -> usize {
        // Acknowledge: the adapter stops asserting the line. Reading clears the causes on
        // the 8254x; the 82574 and PCH adapters clear on read only in some interrupt
        // modes, so the causes read are also written back (write 1 to clear)
        let icr = self.read(REG_ICR);
        if self.model != Model::I82540 && icr != 0 {
            self.write(REG_ICR, icr);
        }
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

/// Constructs a network service reply message.
///
/// # Arguments
/// * `args` - Array of 4 argument words.
///
/// # Returns
/// Formatted reply [`Message`].
fn reply(args: [u64; 4]) -> Message {
    Message::new(MSG_NET_REPLY as u64, args)
}

/// Value of a `key=<number>` argument (decimal or `0x` hex).
///
/// # Arguments
/// * `args` - Argument string list.
/// * `key` - Key name to search for.
///
/// # Returns
/// Parsed integer value if found, or `None`.
fn arg(args: &[&str], key: &str) -> Option<u64> {
    let v = args.iter().find_map(|a| a.strip_prefix(key)?.strip_prefix('='))?;
    match v.strip_prefix("0x") {
        Some(h) => u64::from_str_radix(h, 16).ok(),
        None => v.parse().ok(),
    }
}

/// Driver entry point that configures the Intel 8254x NIC and services packet I/O requests.
///
/// # Arguments
/// * `args` - Command-line argument strings.
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
    let model = match args.iter().find_map(|a| a.strip_prefix("model=")) {
        Some("82574") => Model::I82574,
        Some("pch") => Model::Pch,
        _ => Model::I82540,
    };
    // Test only (QEMU opt/hydra/iommu=test): accept MSG_NET_DMA_TEST
    let dma_test = arg(args, "dma_test") == Some(1);
    let mut nic = Nic { model, regs, mem, mem_phys, mac: [0; 6], tx_cur: 0, rx_cur: 0, irq: None };
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
        "[e1000-driver] {}: MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}, link {}, {}",
        nic.model.name(),
        m[0], m[1], m[2], m[3], m[4], m[5],
        if nic.link_up() { "up" } else { "down" },
        match nic.irq {
            Some(i) if i >= 16 => "MSI interrupt",
            Some(_) => "interrupt line",
            None => "polled",
        }
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
        MSG_NET_TRANSMIT_BATCH => {
            // Frames as MSG_NET_RECEIVE returns them: a 16-bit length, then the frame
            let count = msg.args[0] as usize;
            let (mut at, mut sent) = (0usize, 0u64);
            for _ in 0..count {
                let w = srv.window();
                if at + 2 > WINDOW_SIZE {
                    return reply([EINVAL as u64, sent, 0, 0]);
                }
                let len = u16::from_le_bytes([w[at], w[at + 1]]) as usize;
                if len == 0 || len > BUF || at + 2 + len > WINDOW_SIZE {
                    return reply([EINVAL as u64, sent, 0, 0]);
                }
                if nic.transmit(&w[at + 2..at + 2 + len]).is_err() {
                    return reply([EIO as u64, sent, 0, 0]);
                }
                at += 2 + len;
                sent += 1;
            }
            reply([0, sent, 0, 0])
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
        MSG_NET_DMA_TEST if dma_test => {
            println!("[e1000-driver] DMA test: pointing a transmit descriptor at {:#x}", msg.args[0]);
            match nic.rogue_dma(msg.args[0]) {
                Ok(()) => reply([0, 0, 0, 0]),
                Err(_) => reply([EIO as u64, 0, 0, 0]),
            }
        }
        _ => reply([(-38i64) as u64, 0, 0, 0]),
    })
}
