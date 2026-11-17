//! # Shell Command: the IOMMU (`iommu`)
//!
//! - `iommu` / `iommu status`: whether DMA remapping is on, the units, and each DMA
//!   domain with its devices and mapped pages.
//! - `iommu faults`: reads the fault records now and lists the recent blocked accesses.
//! - `iommu dmatest`: the rogue-DMA test. The network driver points a transmit descriptor
//!   at a kernel page that is not in its domain; the adapter's read must be blocked and
//!   logged, and the driver must keep working. Needs QEMU's
//!   `-fw_cfg name=opt/hydra/iommu,string=test`. Prints `IOMMU-DMATEST: PASS` or `FAIL`.

use crate::shell::command::Command;
use crate::shell::state::ShellState;

/// The `iommu` command.
pub struct IommuCommand;

impl Command for IommuCommand {
    fn name(&self) -> &'static str {
        "iommu"
    }

    fn description(&self) -> &'static str {
        "Intel VT-d DMA remapping: status, blocked DMA faults, rogue-DMA test"
    }

    fn usage(&self) -> &'static str {
        "iommu [status|faults|dmatest]"
    }

    fn execute(&self, args: &[&str], _state: &mut ShellState) {
        match args.first().copied().unwrap_or("status") {
            "status" => {
                for l in crate::arch::iommu::status() {
                    crate::println!("{}", l);
                }
            }
            "faults" => {
                crate::arch::iommu::poll_faults();
                let faults = crate::arch::iommu::recent_faults();
                crate::println!("{} recent blocked DMA access(es):", faults.len());
                for f in faults {
                    let (b, d, func) = crate::arch::dmar::bdf_parts(f.fault.source);
                    crate::println!(
                        "  tick {}: {:02x}:{:02x}.{} {} {:#x}: {}",
                        f.tick,
                        b,
                        d,
                        func,
                        if f.fault.read { "read" } else { "write" },
                        f.fault.address,
                        crate::arch::dmar::reason_text(f.fault.reason)
                    );
                }
            }
            "dmatest" => dma_test(),
            _ => crate::println!("usage: {}", self.usage()),
        }
    }
}

/// The rogue-DMA test (see the module documentation).
fn dma_test() {
    use crate::ipc::protocol::{ENDPOINT_NET_DEV, MSG_NET_DMA_TEST, MSG_NET_REPLY};
    use crate::ipc::service;
    if !crate::arch::iommu::dma_test_enabled() {
        crate::println!("IOMMU-DMATEST: not enabled (QEMU -fw_cfg name=opt/hydra/iommu,string=test)");
        return;
    }
    if !service::is_online(ENDPOINT_NET_DEV) {
        crate::println!("IOMMU-DMATEST: FAIL (the network driver is not running)");
        return;
    }
    // A kernel page the driver was never given, filled with a pattern
    let Some(page) = service::ContiguousFrames::allocate(1) else {
        crate::println!("IOMMU-DMATEST: FAIL (no memory)");
        return;
    };
    unsafe { page.bytes().fill(0x5A) };
    let target = page.base;
    crate::arch::iommu::poll_faults();
    let before = crate::arch::iommu::recent_faults().len();
    let on = crate::arch::iommu::active();
    crate::println!("[iommu] DMA test: the network adapter will try to read kernel page {:#x} (IOMMU {})", target, if on { "on" } else { "off" });
    let r = service::call(ENDPOINT_NET_DEV, crate::ipc::Message::with_args(MSG_NET_DMA_TEST, [target, 0, 0, 0]), service::CALL_TIMEOUT_TICKS);
    let answered = matches!(r, Ok(m) if m.label == MSG_NET_REPLY);
    crate::task::sleep_ms(100);
    crate::arch::iommu::poll_faults();
    let dev = crate::arch::iommu::device_of(ENDPOINT_NET_DEV);
    let faults = crate::arch::iommu::recent_faults();
    let hit = faults.iter().skip(before.min(faults.len())).find(|f| Some(f.fault.source) == dev && f.fault.address == target && f.fault.read);
    let alive = service::is_online(ENDPOINT_NET_DEV);
    crate::println!(
        "[iommu] DMA test: driver answered: {}; fault logged for the adapter at that page: {}; driver still online: {}",
        answered,
        hit.is_some(),
        alive
    );
    if on && hit.is_some() && alive {
        crate::println!("IOMMU-DMATEST: PASS (the IOMMU blocked the rogue read and logged it)");
    } else if !on {
        crate::println!("IOMMU-DMATEST: FAIL (the IOMMU is off: nothing stopped the read)");
    } else {
        crate::println!("IOMMU-DMATEST: FAIL");
    }
}
