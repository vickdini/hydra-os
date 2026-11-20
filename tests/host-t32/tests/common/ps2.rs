//! An 8042 PS/2 controller with a keyboard and a mouse, on the shim's port bus.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use x86_64::hw;

/// An 8042 controller with a keyboard and a (wheel) mouse.
pub struct Ps2 {
    pub out: VecDeque<u8>,
    config: u8,
    next: Option<u8>, // pending controller command taking a data byte (0x60, 0xD4)
    pub rates: Vec<u8>,
    wheel: bool,
    mouse_ok: bool,
    pub log: Vec<String>,
    awaiting_rate: bool,
    /// Bytes the mouse sends after its next ACK to 0xF4 (late replies).
    pub after_f4: Vec<u8>,
}

pub fn ps2(config: u8, wheel: bool, mouse_ok: bool) -> Rc<RefCell<Ps2>> {
    let s = Rc::new(RefCell::new(Ps2 { out: VecDeque::new(), config, next: None, rates: vec![], wheel, mouse_ok, log: vec![], awaiting_rate: false, after_f4: vec![] }));
    let st = s.clone();
    hw::set_port_handler(move |op| {
        let mut s = st.borrow_mut();
        match (op.port, op.write) {
            (0x64, None) => (!s.out.is_empty()) as u32,
            (0x64, Some(c)) => {
                s.log.push(format!("cmd {c:#x}"));
                match c {
                    0x20 => {
                        let cfg = s.config;
                        s.out.push_back(cfg)
                    }
                    0x60 | 0xD4 => s.next = Some(c as u8),
                    _ => {}
                }
                0
            }
            (0x60, None) => s.out.pop_front().unwrap_or(0) as u32,
            (0x60, Some(d)) => {
                let d = d as u8;
                match s.next.take() {
                    Some(0x60) => {
                        s.config = d;
                        s.log.push(format!("config {d:#x}"));
                    }
                    Some(0xD4) => {
                        s.log.push(format!("mouse {d:#x}"));
                        if !s.mouse_ok {
                            s.out.push_back(0xFE);
                            return 0;
                        }
                        s.out.push_back(0xFA);
                        if s.awaiting_rate {
                            s.awaiting_rate = false;
                            s.rates.push(d);
                        } else if d == 0xF3 {
                            s.awaiting_rate = true;
                        } else if d == 0xF4 {
                            let extra = std::mem::take(&mut s.after_f4);
                            s.out.extend(extra);
                        } else if d == 0xF2 {
                            let n = s.rates.len();
                            let id = if s.wheel && n >= 3 && s.rates[n - 3..] == [200, 100, 80] { 3 } else { 0 };
                            s.out.push_back(id);
                        }
                    }
                    _ => {
                        s.log.push(format!("kbd {d:#x}"));
                        s.out.push_back(0xFA);
                    }
                }
                0
            }
            _ => 0,
        }
    });
    s
}

