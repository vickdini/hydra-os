//! A PCI configuration space (mechanism 1: ports 0xCF8/0xCFC) on the shim's port bus.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;

use x86_64::hw;

pub struct Func {
    pub regs: [u32; 64],
    /// BAR sizes (bytes) by BAR index (a 64-bit BAR's size is given at its low index).
    pub bar_sizes: BTreeMap<usize, u64>,
}

impl Default for Func {
    fn default() -> Func {
        Func { regs: [0; 64], bar_sizes: BTreeMap::new() }
    }
}

#[derive(Default)]
pub struct Pci {
    pub funcs: BTreeMap<(u8, u8, u8), Func>,
    /// Every config write: (bus, dev, fn, offset, value).
    pub writes: Vec<(u8, u8, u8, u8, u32)>,
}

impl Pci {
    /// Adds a function with vendor/device, class/subclass, header type.
    pub fn add(&mut self, b: u8, d: u8, f: u8, vendor: u16, device: u16, class: u8, sub: u8, header: u8) -> &mut Func {
        let func = self.funcs.entry((b, d, f)).or_default();
        func.regs[0] = vendor as u32 | (device as u32) << 16;
        func.regs[2] = (class as u32) << 24 | (sub as u32) << 16;
        func.regs[3] = (header as u32) << 16;
        func
    }
    pub fn reg(&self, b: u8, d: u8, f: u8, off: u8) -> u32 {
        self.funcs[&(b, d, f)].regs[off as usize / 4]
    }
}

impl Func {
    pub fn set16(&mut self, off: u8, v: u16) {
        let i = off as usize / 4;
        let sh = (off & 2) * 8;
        self.regs[i] = (self.regs[i] & !(0xFFFF << sh)) | (v as u32) << sh;
    }
    pub fn set8(&mut self, off: u8, v: u8) {
        let i = off as usize / 4;
        let sh = (off & 3) * 8;
        self.regs[i] = (self.regs[i] & !(0xFF << sh)) | (v as u32) << sh;
    }
    /// A capability list at 0x40, 0x60, ...: (id, control word).
    pub fn caps(&mut self, caps: &[(u8, u16)]) {
        self.regs[1] |= 0x10 << 16; // status: capability list
        self.set8(0x34, 0x40);
        for (i, &(id, ctrl)) in caps.iter().enumerate() {
            let at = 0x40 + i as u8 * 0x20;
            let next = if i + 1 < caps.len() { at + 0x20 } else { 0 };
            self.regs[at as usize / 4] = id as u32 | (next as u32) << 8 | (ctrl as u32) << 16;
        }
    }
}

/// Puts `pci` on the port bus; returns it shared.
pub fn install(pci: Pci) -> Rc<RefCell<Pci>> {
    let p = Rc::new(RefCell::new(pci));
    let st = p.clone();
    let mut addr = 0u32;
    hw::set_port_handler(move |op| match (op.port, op.write) {
        (0xCF8, Some(a)) => {
            addr = a;
            0
        }
        (0xCFC, w) => {
            let (b, d, f, off) = ((addr >> 16) as u8, ((addr >> 11) & 31) as u8, ((addr >> 8) & 7) as u8, (addr & 0xFC) as u8);
            let mut s = st.borrow_mut();
            if let Some(v) = w {
                s.writes.push((b, d, f, off, v));
            }
            let Some(func) = s.funcs.get_mut(&(b, d, f)) else { return 0xFFFF_FFFF };
            let i = off as usize / 4;
            match w {
                None => func.regs[i],
                Some(v) => {
                    if (4..10).contains(&i) && v == 0xFFFF_FFFF {
                        // BAR sizing: the writable bits read back
                        let bar = i - 4;
                        let low = func.regs[i] & 0xF;
                        func.regs[i] = match func.bar_sizes.get(&bar) {
                            Some(&size) => ((!(size - 1)) as u32 & !0xF) | low,
                            None => match bar.checked_sub(1).and_then(|b| func.bar_sizes.get(&b)) {
                                Some(&size) if (func.regs[i - 1] >> 1) & 3 == 2 => ((!(size - 1)) >> 32) as u32,
                                _ => 0,
                            },
                        };
                    } else {
                        func.regs[i] = v;
                    }
                    0
                }
            }
        }
        _ => 0,
    });
    p
}
