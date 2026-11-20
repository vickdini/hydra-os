//! An Intel VT-d remapping unit's registers (the parts `arch/iommu.rs` uses), on the host
//! seam for MMIO (`host::MMIO`).

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use hydra_hosttests_t32::host;

pub const FRO: u64 = 0x200;
pub const IRO: u64 = 0x300;

pub struct Unit {
    pub base: u64,
    pub regs: BTreeMap<u64, u32>,
    /// Writes in order: (offset, value).
    pub log: Vec<(u64, u32)>,
    /// Status bits that never follow their command (a broken unit).
    pub stuck: u32,
    /// Invalidations never complete.
    pub hang_inval: bool,
}

/// CAP: 4-level tables (SAGAW bit 2), 256 domains, fault records at FRO, 4 of them.
pub const CAP4: u64 = 4 << 8 | 2 | (FRO / 16) << 24 | 3 << 40;
/// ECAP: coherent, IOTLB registers at IRO.
pub const ECAP: u64 = 1 | (IRO / 16) << 8;

impl Unit {
    pub fn new(base: u64, cap: u64, ecap: u64) -> Unit {
        let mut regs = BTreeMap::new();
        regs.insert(0x00, 0x10); // VT-d 1.0
        regs.insert(0x08, cap as u32);
        regs.insert(0x0C, (cap >> 32) as u32);
        regs.insert(0x10, ecap as u32);
        regs.insert(0x14, (ecap >> 32) as u32);
        Unit { base, regs, log: vec![], stuck: 0, hang_inval: false }
    }
    pub fn r(&self, off: u64) -> u32 {
        self.regs.get(&off).copied().unwrap_or(0)
    }
    pub fn gsts(&self) -> u32 {
        self.r(0x1C)
    }
    /// Queues a fault record `i`: (address, source id, reason, read).
    pub fn fault(&mut self, i: u64, addr: u64, source: u16, reason: u8, read: bool) {
        let off = FRO + i * 16;
        self.regs.insert(off, addr as u32);
        self.regs.insert(off + 4, (addr >> 32) as u32);
        self.regs.insert(off + 8, source as u32);
        self.regs.insert(off + 12, 1 << 31 | (read as u32) << 30 | reason as u32);
        let fsts = self.r(0x34) | 2;
        self.regs.insert(0x34, fsts);
    }
    fn write(&mut self, off: u64, v: u32) {
        self.log.push((off, v));
        match off {
            0x18 => {
                let mut g = self.gsts();
                for bit in [31u32, 26, 25] {
                    if self.stuck & (1 << bit) == 0 {
                        g = (g & !(1 << bit)) | (v & (1 << bit));
                    }
                }
                if v & (1 << 30) != 0 && self.stuck & (1 << 30) == 0 {
                    g |= 1 << 30;
                }
                self.regs.insert(0x1C, g);
            }
            0x2C if v & (1 << 31) != 0 && !self.hang_inval => {
                self.regs.insert(0x2C, v & !(1 << 31));
            }
            o if o == IRO + 12 && v & (1 << 31) != 0 && !self.hang_inval => {
                self.regs.insert(o, v & !(1 << 31));
            }
            0x34 => {
                // Write 1 to clear
                let f = self.r(0x34) & !(v & 0x7D);
                self.regs.insert(0x34, f);
            }
            0x64 => {
                self.regs.insert(0x64, v & !1);
            }
            o if o >= FRO && o < FRO + 0x40 && o % 16 == 12 && v & (1 << 31) != 0 => {
                let r = self.r(o) & !(1 << 31);
                self.regs.insert(o, r);
                // No more records pending: the status' pending bit goes
                if (0..4).all(|i| self.r(FRO + i * 16 + 12) >> 31 == 0) {
                    let f = self.r(0x34) & !2;
                    self.regs.insert(0x34, f);
                }
            }
            _ => {
                self.regs.insert(off, v);
            }
        }
    }
}

/// Puts `units` on the MMIO seam (4 KiB of registers each); other addresses are memory.
pub fn install(units: Vec<Unit>) -> Rc<RefCell<Vec<Unit>>> {
    let u = Rc::new(RefCell::new(units));
    let st = u.clone();
    host::MMIO.with_borrow_mut(|m| {
        *m = Some(Box::new(move |a, w| {
            let mut units = st.borrow_mut();
            match units.iter_mut().find(|u| a >= u.base && a < u.base + 0x1000) {
                Some(u) => match w {
                    Some(v) => {
                        u.write(a - u.base, v);
                        0
                    }
                    None => u.r(a - u.base),
                },
                None => match w {
                    Some(v) => {
                        unsafe { core::ptr::write_volatile(a as *mut u32, v) };
                        0
                    }
                    None => unsafe { core::ptr::read_volatile(a as *const u32) },
                },
            }
        }))
    });
    u
}
