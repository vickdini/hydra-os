//! # Intel VT-d DMA remapping (the IOMMU)
//!
//! Hydra's hardware drivers are Ring 3 programs, but a device they program can read and
//! write any physical memory by DMA unless something stops it. The IOMMU does: with DMA
//! remapping on, every DMA request of a PCI device is translated through the page table
//! of the device's *domain*, and an address not mapped there is blocked and recorded as a
//! fault.
//!
//! ## Domains
//!
//! - Each driver service (endpoint) has a domain of its own; the supervisor attaches the
//!   PCI device it gives the driver ([`attach`]).
//! - A domain maps only the memory its driver got from `dma_alloc` ([`map_dma`], undone
//!   by [`unmap_dma`] when the buffer is freed, which also happens when the driver dies),
//!   memory the kernel lends the device (the sound ring buffers), and the reserved memory
//!   regions (RMRR) the firmware lists for that device.
//! - Addresses are identities: a buffer's I/O address is its physical address, so drivers
//!   program devices exactly as without an IOMMU.
//! - Devices no driver owns get no domain and cannot DMA at all, except those the firmware
//!   lists in an RMRR: they share a firmware domain mapping just those regions.
//! - A unit that covers only graphics devices (the integrated GPU's unit on Intel client
//!   chips) is left off: the firmware framebuffer keeps working and Hydra has no GPU driver
//!   that would DMA (Linux's `intel_iommu=igfx_off`).
//!
//! ## Start-up and fallback
//!
//! [`discover`] copies the ACPI DMAR table and reads the boot options while the firmware's
//! boot services still run; [`init`] parses it, builds the tables and turns translation on
//! after the hardware takeover, before the drivers start. Whatever goes wrong there (no
//! table, a broken table, a unit that does not answer) leaves the IOMMU off and Hydra
//! boots as without one, after one warning line. It can be turned off on purpose:
//!
//! - the boot entry's load option `iommu=off` (or `noiommu`);
//! - a file `\hydra\noiommu` on the EFI system partition;
//! - QEMU's `-fw_cfg name=opt/hydra/iommu,string=off`.
//!
//! `opt/hydra/iommu` = `test` additionally lets the network driver accept a test request
//! that makes the adapter read kernel memory (`iommu dmatest`).
//!
//! ## Faults
//!
//! The supervisor's watchdog reads the fault records every second ([`poll_faults`]) and
//! logs each blocked access in plain words: which device, which address, read or write,
//! and why.
//!
//! Invalidation is register based; interrupt remapping is not used (interrupts pass
//! through as before).

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

use super::dmar::{self, Resolved, TableMemory, PTE_R, PTE_W};
use crate::memory::frame_allocator::{phys_to_virt, FRAME_ALLOCATOR};

// Registers
const REG_VER: u64 = 0x00;
const REG_CAP: u64 = 0x08;
const REG_ECAP: u64 = 0x10;
const REG_GCMD: u64 = 0x18;
const REG_GSTS: u64 = 0x1C;
const REG_RTADDR: u64 = 0x20;
const REG_CCMD: u64 = 0x28;
const REG_FSTS: u64 = 0x34;
const REG_FECTL: u64 = 0x38;
const REG_PMEN: u64 = 0x64;

// Global command and status bits
const GCMD_TE: u32 = 1 << 31;
const GCMD_SRTP: u32 = 1 << 30;
const GCMD_WBF: u32 = 1 << 27;
const GCMD_QIE: u32 = 1 << 26;
const GCMD_IRE: u32 = 1 << 25;

/// Spins before a register handshake counts as failed.
const SPIN_LIMIT: u32 = 2_000_000;

/// The DMAR table, copied before the firmware's memory is reclaimed.
static TABLE: Mutex<Option<Vec<u8>>> = Mutex::new(None);
/// Why the IOMMU was turned off by a boot option, if it was.
static OFF_BY: Mutex<Option<&'static str>> = Mutex::new(None);
/// QEMU asked for the rogue-DMA test request.
static TEST: AtomicBool = AtomicBool::new(false);
/// DMA remapping is on.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// Faults recorded since boot.
static FAULTS: AtomicU64 = AtomicU64::new(0);
/// Everything else.
static STATE: Mutex<State> = Mutex::new(State::new());

/// One remapping unit.
struct Unit {
    /// Register base (physical).
    phys: u64,
    /// Register base (kernel address).
    regs: u64,
    cap: u64,
    ecap: u64,
    include_all: bool,
    /// The devices it lists.
    scopes: Vec<Resolved>,
    /// Translation is (to be) on.
    translate: bool,
    /// Why not, in plain words.
    skipped: Option<String>,
    /// Root table (physical).
    root: u64,
    /// Context table per bus (physical, 0: none yet).
    ctx: Vec<u64>,
    /// Translation was turned on (to undo it on failure).
    enabled: bool,
}

/// One DMA domain.
struct Domain {
    /// Service endpoint (0: the firmware's RMRR domain).
    endpoint: u32,
    did: u16,
    /// Top-level page table (physical).
    root: u64,
    /// Pages mapped.
    pages: u64,
    /// Devices in it: requester ID and the owning service's name.
    devices: Vec<(u16, &'static str)>,
}

/// A logged fault.
#[derive(Clone, Copy)]
pub struct FaultLog {
    /// The fault.
    pub fault: dmar::Fault,
    /// Timer tick it was read.
    pub tick: u64,
}

struct State {
    units: Vec<Unit>,
    domains: Vec<Domain>,
    /// Page-table levels (3 or 4).
    levels: u8,
    /// Every unit snoops processor caches when it walks tables.
    coherent: bool,
    rmrrs: Vec<(u64, u64, Vec<Resolved>)>,
    recent: VecDeque<FaultLog>,
    lost: u64,
    next_did: u16,
}

impl State {
    const fn new() -> Self {
        Self { units: Vec::new(), domains: Vec::new(), levels: 4, coherent: true, rmrrs: Vec::new(), recent: VecDeque::new(), lost: 0, next_did: 1 }
    }
}

/// Page tables in RAM, written through the kernel's direct map.
struct Mem {
    coherent: bool,
}

impl TableMemory for Mem {
    fn alloc_table(&mut self) -> Option<u64> {
        let f = FRAME_ALLOCATOR.lock().allocate_zeroed_frame()?;
        let p = f.start_address().as_u64();
        if !self.coherent {
            flush_range(p, 4096);
        }
        Some(p)
    }

    fn entry(&self, table: u64, index: usize) -> *mut u64 {
        unsafe { (phys_to_virt(table) as *mut u64).add(index) }
    }

    fn flushed(&self, e: *mut u64) {
        if !self.coherent {
            unsafe {
                core::arch::x86_64::_mm_clflush(e as *const u8);
                core::arch::x86_64::_mm_mfence();
            }
        }
    }
}

/// Writes back the cache lines of `[phys, phys + len)` (for units that do not snoop).
fn flush_range(phys: u64, len: u64) {
    let mut a = phys & !63;
    while a < phys + len {
        unsafe { core::arch::x86_64::_mm_clflush(phys_to_virt(a)) };
        a += 64;
    }
    unsafe { core::arch::x86_64::_mm_mfence() };
}

fn r32(u: &Unit, off: u64) -> u32 {
    unsafe { core::ptr::read_volatile((u.regs + off) as *const u32) }
}

fn w32(u: &Unit, off: u64, v: u32) {
    unsafe { core::ptr::write_volatile((u.regs + off) as *mut u32, v) }
}

fn r64(u: &Unit, off: u64) -> u64 {
    // Two halves, low first: every unit accepts 32-bit accesses
    r32(u, off) as u64 | (r32(u, off + 4) as u64) << 32
}

fn w64(u: &Unit, off: u64, v: u64) {
    w32(u, off, v as u32);
    w32(u, off + 4, (v >> 32) as u32);
}

/// Spins until `done` or the limit.
fn wait(mut done: impl FnMut() -> bool) -> bool {
    for _ in 0..SPIN_LIMIT {
        if done() {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

/// Sets or clears a persistent global command bit and waits for its status.
fn command(u: &Unit, bit: u32, on: bool) -> bool {
    let gsts = r32(u, REG_GSTS);
    w32(u, REG_GCMD, dmar::gcmd(gsts, bit, on));
    wait(|| (r32(u, REG_GSTS) & bit != 0) == on)
}

/// Write-buffer flush, for units that need it (CAP.RWBF).
fn write_buffer_flush(u: &Unit) {
    if u.cap & (1 << 4) != 0 {
        let gsts = r32(u, REG_GSTS);
        w32(u, REG_GCMD, dmar::gcmd(gsts, GCMD_WBF, true));
        wait(|| r32(u, REG_GSTS) & GCMD_WBF == 0);
    }
}

/// Invalidates the unit's whole context cache.
fn flush_context(u: &Unit) -> bool {
    w64(u, REG_CCMD, 1 << 63 | 1 << 61);
    wait(|| r64(u, REG_CCMD) >> 63 == 0)
}

/// Invalidates the unit's IOTLB: everything (`did` = None) or one domain.
fn flush_iotlb(u: &Unit, did: Option<u16>) -> bool {
    let off = ((u.ecap >> 8) & 0x3FF) * 16 + 8;
    // Drain reads and writes first where the unit can
    let drain = (u.cap >> 55 & 1) << 49 | (u.cap >> 54 & 1) << 48;
    let kind = match did {
        None => 1u64 << 60,
        Some(d) => 2u64 << 60 | (d as u64) << 32,
    };
    w64(u, off, 1 << 63 | kind | drain);
    wait(|| r64(u, off) >> 63 == 0)
}

/// Words of the boot entry's load options (lower case), without allocating much.
fn load_options_say(words: &[&[u8]]) -> bool {
    let Ok(img) = uefi::boot::open_protocol_exclusive::<uefi::proto::loaded_image::LoadedImage>(uefi::boot::image_handle()) else {
        return false;
    };
    let Some(opts) = img.load_options_as_bytes() else { return false };
    let text: Vec<u8> = opts.chunks_exact(2).take(512).map(|c| if c[1] == 0 { c[0].to_ascii_lowercase() } else { b'?' }).collect();
    words.iter().any(|w| text.windows(w.len()).any(|x| x == *w))
}

/// Reads the boot options and copies the DMAR table. Called while the firmware's boot
/// services still run (before `ExitBootServices`).
pub fn discover() {
    let mut cfg = [0u8; 16];
    let fw = crate::arch::fwcfg::read_file_into("opt/hydra/iommu", &mut cfg).map(|n| &cfg[..n]);
    if fw.is_some_and(|v| v.starts_with(b"off")) {
        *OFF_BY.lock() = Some("QEMU fw_cfg opt/hydra/iommu=off");
    } else if load_options_say(&[b"iommu=off", b"noiommu"]) {
        *OFF_BY.lock() = Some("boot option iommu=off");
    } else if crate::fs::bootfs::file_exists("\\hydra\\noiommu") {
        *OFF_BY.lock() = Some("file \\hydra\\noiommu on the EFI partition");
    }
    if fw.is_some_and(|v| v.starts_with(b"test")) {
        TEST.store(true, Ordering::Relaxed);
    }
    let rsdp = uefi::system::with_config_table(|t| {
        t.iter()
            .find(|e| e.guid == uefi::table::cfg::ConfigTableEntry::ACPI2_GUID)
            .or_else(|| t.iter().find(|e| e.guid == uefi::table::cfg::ConfigTableEntry::ACPI_GUID))
            .map(|e| e.address as u64)
    });
    let Some(rsdp) = rsdp else { return };
    unsafe {
        let rd32 = |p: u64| core::ptr::read_unaligned(p as *const u32);
        let rd64 = |p: u64| core::ptr::read_unaligned(p as *const u64);
        if core::slice::from_raw_parts(rsdp as *const u8, 8) != b"RSD PTR " {
            return;
        }
        let revision = *((rsdp + 15) as *const u8);
        let (sdt, entry) = if revision >= 2 && rd64(rsdp + 24) != 0 { (rd64(rsdp + 24), 8) } else { (rd32(rsdp + 16) as u64, 4) };
        if sdt == 0 {
            return;
        }
        let len = rd32(sdt + 4) as u64;
        let mut at = sdt + 36;
        while at + entry <= sdt + len {
            let t = if entry == 8 { rd64(at) } else { rd32(at) as u64 };
            at += entry;
            if t == 0 || core::slice::from_raw_parts(t as *const u8, 4) != b"DMAR" {
                continue;
            }
            let tlen = rd32(t + 4) as usize;
            if (48..=64 * 1024).contains(&tlen) {
                *TABLE.lock() = Some(core::slice::from_raw_parts(t as *const u8, tlen).to_vec());
            }
            break;
        }
    }
}

/// Whether DMA remapping is on.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

/// Whether the rogue-DMA test request is allowed (QEMU `opt/hydra/iommu=test`).
pub fn dma_test_enabled() -> bool {
    TEST.load(Ordering::Relaxed)
}

/// A bridge's secondary and subordinate bus numbers.
fn bridge_buses(bus: u8, dev: u8, func: u8) -> (u8, u8) {
    let hdr = crate::arch::pci::pci_read_u8(bus, dev, func, 0x0E) & 0x7F;
    if hdr != 1 {
        return (0, 0);
    }
    (crate::arch::pci::pci_read_u8(bus, dev, func, 0x19), crate::arch::pci::pci_read_u8(bus, dev, func, 0x1A))
}

/// The unit translating requests of device `id` (segment 0).
fn unit_for(units: &[Unit], id: u16) -> Option<usize> {
    units
        .iter()
        .position(|u| !u.include_all && u.scopes.iter().any(|s| dmar::covers(s, id)))
        .or_else(|| units.iter().position(|u| u.include_all))
}

fn bdf_text(id: u16) -> String {
    let (b, d, f) = dmar::bdf_parts(id);
    alloc::format!("{:02x}:{:02x}.{}", b, d, f)
}

/// Builds the tables and turns DMA remapping on. Called after the hardware takeover,
/// before the drivers start. Never fails the boot: on any problem the IOMMU stays off
/// and one warning says why.
pub fn init() {
    if let Some(why) = *OFF_BY.lock() {
        crate::kprintln!("[iommu] WARNING: DMA remapping turned off by {}: drivers' devices can reach all memory", why);
        return;
    }
    let Some(table) = TABLE.lock().take() else {
        crate::kprintln!("[iommu] no DMAR table (no Intel VT-d, or VT-d is off in the firmware setup): drivers' devices can reach all memory");
        return;
    };
    let parsed = match dmar::parse(&table) {
        Ok(p) => p,
        Err(e) => {
            crate::kprintln!("[iommu] WARNING: the firmware's DMAR table is broken ({}): booting without the IOMMU", e);
            return;
        }
    };
    for w in &parsed.warnings {
        crate::kprintln!("[iommu] firmware table: {}", w);
    }
    let mut lines: Vec<String> = Vec::new();
    let result = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut st = STATE.lock();
        let r = start(&mut st, &parsed, &mut lines);
        if r.is_err() {
            // Undo whatever was turned on
            for u in st.units.iter_mut().filter(|u| u.enabled) {
                command(u, GCMD_TE, false);
                u.enabled = false;
            }
            st.units.clear();
            st.domains.clear();
        }
        r
    });
    for l in &lines {
        crate::kprintln!("{}", l);
    }
    match result {
        Ok(()) => ACTIVE.store(true, Ordering::Release),
        Err(e) => crate::kprintln!("[iommu] WARNING: could not start the IOMMU ({}): booting without it, drivers' devices can reach all memory", e),
    }
}

/// [`init`]'s work, with the state locked.
fn start(st: &mut State, parsed: &dmar::Dmar, lines: &mut Vec<String>) -> Result<(), String> {
    let mut bb = bridge_buses;
    for d in &parsed.units {
        let mut u = Unit {
            phys: d.base,
            regs: 0,
            cap: 0,
            ecap: 0,
            include_all: d.include_all(),
            scopes: d.scopes.iter().filter_map(|s| dmar::resolve(s, &mut bb)).collect(),
            translate: false,
            skipped: None,
            root: 0,
            ctx: alloc::vec![0; 256],
            enabled: false,
        };
        if d.segment != 0 {
            u.skipped = Some(String::from("PCI segment other than 0"));
        } else if d.base >= 4 << 30 {
            u.skipped = Some(String::from("registers above 4 GiB"));
        } else {
            u.regs = phys_to_virt(d.base) as u64;
            let ver = r32(&u, REG_VER);
            if ver == 0 || ver == 0xFFFF_FFFF {
                return Err(alloc::format!("no remapping unit answers at {:#x}", d.base));
            }
            u.cap = r64(&u, REG_CAP);
            u.ecap = r64(&u, REG_ECAP);
            let gfx_only = !u.include_all
                && !u.scopes.is_empty()
                && u.scopes.iter().all(|s| match *s {
                    Resolved::Device(id) => {
                        let (b, dv, f) = dmar::bdf_parts(id);
                        crate::arch::pci::pci_read_u8(b, dv, f, 0x0B) == 0x03
                    }
                    Resolved::Bridge(..) => false,
                });
            if gfx_only {
                u.skipped = Some(String::from("graphics only; the firmware framebuffer stays untranslated"));
            } else if dmar::levels_from_cap(u.cap).is_none() {
                u.skipped = Some(String::from("no supported page-table format"));
            } else {
                u.translate = true;
            }
        }
        st.units.push(u);
    }
    if !st.units.iter().any(|u| u.translate) {
        return Err(String::from("no usable remapping unit"));
    }
    // 4-level tables if every unit takes them, else 3-level
    let all4 = st.units.iter().filter(|u| u.translate).all(|u| dmar::levels_from_cap(u.cap) == Some(4));
    st.levels = if all4 { 4 } else { 3 };
    let levels = st.levels;
    for u in st.units.iter_mut().filter(|u| u.translate) {
        if (u.cap >> 8) & 0x1F & (if levels == 4 { 4 } else { 2 }) == 0 {
            u.translate = false;
            u.skipped = Some(String::from("page-table format differs from the other units"));
        }
    }
    st.coherent = st.units.iter().filter(|u| u.translate).all(|u| u.ecap & 1 != 0);
    let reach = dmar::reach(levels);
    let ram_top = FRAME_ALLOCATOR.lock().total_usable_memory();
    if ram_top >= reach {
        lines.push(alloc::format!("[iommu] note: memory beyond {} GiB cannot be given to devices", reach >> 30));
    }
    // Reserved regions and the firmware domain for their devices
    let mut bb = bridge_buses;
    st.rmrrs = parsed
        .rmrrs
        .iter()
        .filter(|r| r.segment == 0)
        .map(|r| (r.base, r.limit, r.scopes.iter().filter_map(|s| dmar::resolve(s, &mut bb)).collect()))
        .collect();
    // Root tables
    let mut mem = Mem { coherent: st.coherent };
    for u in st.units.iter_mut().filter(|u| u.translate) {
        u.root = mem.alloc_table().ok_or("no memory for a root table")?;
    }
    if !st.rmrrs.is_empty() {
        let fw = new_domain(st, 0)?;
        let rmrrs = st.rmrrs.clone();
        for (base, limit, scopes) in &rmrrs {
            map_identity(st, fw, *base, *limit + 1 - *base)?;
            for s in scopes {
                let id = match *s {
                    Resolved::Device(id) => id,
                    Resolved::Bridge(id, ..) => id,
                };
                if let Some(ui) = unit_for(&st.units, id) {
                    if st.units[ui].translate && !st.domains[fw].devices.iter().any(|d| d.0 == id) {
                        set_context(st, ui, id, fw)?;
                        st.domains[fw].devices.push((id, "firmware"));
                    }
                }
            }
            lines.push(alloc::format!("[iommu] firmware region {:#x}-{:#x} kept reachable for {} device(s)", base, limit, scopes.len()));
        }
    }
    // Turn translation on, unit by unit
    let mut on = 0;
    for i in 0..st.units.len() {
        if !st.units[i].translate {
            continue;
        }
        let u = &mut st.units[i];
        let gsts = r32(u, REG_GSTS);
        // Whatever the firmware left on: translation, queued invalidation, interrupt
        // remapping, protected memory regions
        if gsts & GCMD_TE != 0 && !command(u, GCMD_TE, false) {
            return Err(alloc::format!("unit {:#x} did not stop the firmware's translation", u.phys));
        }
        if gsts & GCMD_IRE != 0 {
            command(u, GCMD_IRE, false);
        }
        if gsts & GCMD_QIE != 0 && !command(u, GCMD_QIE, false) {
            return Err(alloc::format!("unit {:#x} did not leave queued invalidation", u.phys));
        }
        if r32(u, REG_PMEN) & (1 << 31) != 0 {
            w32(u, REG_PMEN, 0);
            wait(|| r32(u, REG_PMEN) & 1 == 0);
        }
        // Clear old faults; fault interrupts stay masked (faults are polled)
        clear_faults(u);
        w32(u, REG_FECTL, 1 << 31);
        w64(u, REG_RTADDR, u.root);
        let gsts = r32(u, REG_GSTS);
        w32(u, REG_GCMD, dmar::gcmd(gsts, GCMD_SRTP, true));
        if !wait(|| r32(u, REG_GSTS) & GCMD_SRTP != 0) {
            return Err(alloc::format!("unit {:#x} did not take the root table", u.phys));
        }
        write_buffer_flush(u);
        if !flush_context(u) || !flush_iotlb(u, None) {
            return Err(alloc::format!("unit {:#x} did not finish an invalidation", u.phys));
        }
        if !command(u, GCMD_TE, true) {
            return Err(alloc::format!("unit {:#x} did not turn translation on", u.phys));
        }
        u.enabled = true;
        on += 1;
    }
    for u in &st.units {
        let (ver, nd) = (r32(u, REG_VER), 1u32 << (4 + 2 * (u.cap & 7) as u32));
        match &u.skipped {
            None if u.regs != 0 => lines.push(alloc::format!(
                "[iommu] unit {:#x} (VT-d {}.{}, {} domains{}{}): translating{}",
                u.phys,
                ver >> 4 & 0xF,
                ver & 0xF,
                nd,
                if u.cap >> 7 & 1 != 0 { ", caching mode" } else { "" },
                if u.ecap & 1 != 0 { "" } else { ", non-coherent" },
                if u.include_all { " all other devices" } else { " its listed devices" }
            )),
            Some(why) => lines.push(alloc::format!("[iommu] unit {:#x}: left off ({})", u.phys, why)),
            _ => {}
        }
    }
    lines.push(alloc::format!(
        "[iommu] DMA remapping on: {} unit(s), {}-level I/O page tables; each driver's device reaches only its own DMA memory",
        on, levels
    ));
    Ok(())
}

/// Clears a unit's fault records and overflow flags.
fn clear_faults(u: &Unit) {
    let fro = ((u.cap >> 24) & 0x3FF) * 16;
    let nfr = ((u.cap >> 40) & 0xFF) + 1;
    for i in 0..nfr {
        w32(u, fro + i * 16 + 12, 1 << 31);
    }
    let fsts = r32(u, REG_FSTS);
    w32(u, REG_FSTS, fsts & 0x7D);
}

/// A new domain for `endpoint`; its index.
fn new_domain(st: &mut State, endpoint: u32) -> Result<usize, String> {
    let max = st.units.iter().filter(|u| u.translate).map(|u| 1u32 << (4 + 2 * (u.cap & 7) as u32)).min().unwrap_or(16);
    if st.next_did as u32 >= max {
        return Err(String::from("out of domain IDs"));
    }
    let root = Mem { coherent: st.coherent }.alloc_table().ok_or("no memory for an I/O page table")?;
    let did = st.next_did;
    st.next_did += 1;
    st.domains.push(Domain { endpoint, did, root, pages: 0, devices: Vec::new() });
    Ok(st.domains.len() - 1)
}

/// The domain of `endpoint`, made if needed.
fn domain_of(st: &mut State, endpoint: u32) -> Result<usize, String> {
    match st.domains.iter().position(|d| d.endpoint == endpoint) {
        Some(i) => Ok(i),
        None => new_domain(st, endpoint),
    }
}

/// Maps `[phys, phys + len)` at the same I/O addresses into domain `di`.
fn map_identity(st: &mut State, di: usize, phys: u64, len: u64) -> Result<(), String> {
    let (root, levels) = (st.domains[di].root, st.levels);
    let mut mem = Mem { coherent: st.coherent };
    let first = phys & !0xFFF;
    let end = (phys + len + 0xFFF) & !0xFFF;
    let mut a = first;
    let mut new = 0;
    while a < end {
        match dmar::map_page(&mut mem, root, levels, a, a, PTE_R | PTE_W) {
            Ok(fresh) => new += fresh as u64,
            Err(e) => {
                let mut b = first;
                while b < a {
                    dmar::unmap_page(&mut mem, root, levels, b);
                    b += 4096;
                }
                return Err(String::from(e));
            }
        }
        a += 4096;
    }
    st.domains[di].pages += new;
    Ok(())
}

/// Points device `id`'s context entry on unit `ui` at domain `di`.
fn set_context(st: &mut State, ui: usize, id: u16, di: usize) -> Result<(), String> {
    let mut mem = Mem { coherent: st.coherent };
    let (bus, devfn) = ((id >> 8) as usize, (id & 0xFF) as usize);
    let (root, did, levels) = (st.domains[di].root, st.domains[di].did, st.levels);
    let u = &mut st.units[ui];
    if u.ctx[bus] == 0 {
        let t = mem.alloc_table().ok_or("no memory for a context table")?;
        u.ctx[bus] = t;
        let re = mem.entry(u.root, bus * 2);
        unsafe {
            mem.entry(u.root, bus * 2 + 1).write_volatile(0);
            re.write_volatile(dmar::root_entry(t));
        }
        mem.flushed(re);
    }
    let lo = mem.entry(u.ctx[bus], devfn * 2);
    let hi = mem.entry(u.ctx[bus], devfn * 2 + 1);
    let (new_lo, new_hi) = dmar::context_entry(root, levels, did);
    unsafe {
        if lo.read_volatile() & 1 != 0 {
            // Present already (another domain): take it away first
            lo.write_volatile(0);
            mem.flushed(lo);
            if u.enabled {
                flush_context(u);
                flush_iotlb(u, None);
            }
        }
        hi.write_volatile(new_hi);
        mem.flushed(hi);
        lo.write_volatile(new_lo);
        mem.flushed(lo);
    }
    if u.enabled {
        write_buffer_flush(u);
        flush_context(u);
        flush_iotlb(u, None);
    }
    Ok(())
}

/// Gives PCI function `dev`, driven by service `name` on `endpoint`, a DMA domain of its
/// own (the same one across driver restarts), with the firmware regions listed for it.
pub fn attach(endpoint: u32, name: &'static str, dev: &crate::arch::pci::PciDevice) {
    if !active() {
        return;
    }
    let id = dmar::bdf(dev.bus, dev.device, dev.function);
    let mut note: Option<String> = None;
    let r: Result<(), String> = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut st = STATE.lock();
        let Some(ui) = unit_for(&st.units, id) else {
            note = Some(alloc::format!("[iommu] {} ({}): no remapping unit covers it; its DMA is not restricted", bdf_text(id), name));
            return Ok(());
        };
        if !st.units[ui].translate {
            note = Some(alloc::format!("[iommu] {} ({}): its unit is off; its DMA is not restricted", bdf_text(id), name));
            return Ok(());
        }
        let di = domain_of(&mut st, endpoint)?;
        if st.domains[di].devices.iter().any(|d| d.0 == id) {
            return Ok(()); // a restart: already attached
        }
        // Out of the firmware domain, if it was there
        for d in st.domains.iter_mut() {
            d.devices.retain(|x| x.0 != id);
        }
        let regions: Vec<(u64, u64)> =
            st.rmrrs.iter().filter(|(_, _, s)| s.iter().any(|r| dmar::covers(r, id))).map(|(b, l, _)| (*b, *l + 1 - *b)).collect();
        for (b, len) in regions {
            map_identity(&mut st, di, b, len)?;
        }
        set_context(&mut st, ui, id, di)?;
        st.domains[di].devices.push((id, name));
        note = Some(alloc::format!("[iommu] {} ({}): DMA domain {}", bdf_text(id), name, st.domains[di].did));
        Ok(())
    });
    if let Some(n) = note {
        crate::kprintln!("{}", n);
    }
    if let Err(e) = r {
        crate::kprintln!("[iommu] {} ({}): no DMA domain ({}); the device cannot DMA", bdf_text(id), name, e);
    }
}

/// Invalidates domain `di`'s cached translations on every unit translating.
fn flush_domain(st: &State, di: usize) {
    let did = st.domains[di].did;
    for u in st.units.iter().filter(|u| u.enabled) {
        write_buffer_flush(u);
        if !flush_iotlb(u, Some(did)) {
            flush_iotlb(u, None);
        }
    }
}

/// Lets the device of `endpoint`'s driver reach `[phys, phys + len)` (at the same I/O
/// address). A no-op when the IOMMU is off.
///
/// # Errors
/// No memory for page tables, or the address is beyond the domain's reach.
pub fn map_dma(endpoint: u32, phys: u64, len: u64) -> Result<(), ()> {
    if !active() || len == 0 {
        return Ok(());
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut st = STATE.lock();
        let di = domain_of(&mut st, endpoint).map_err(|_| ())?;
        map_identity(&mut st, di, phys, len).map_err(|_| ())?;
        // Caching mode (an emulated unit) caches "not present" too
        if st.units.iter().any(|u| u.enabled && u.cap >> 7 & 1 != 0) {
            flush_domain(&st, di);
        } else {
            for u in st.units.iter().filter(|u| u.enabled) {
                write_buffer_flush(u);
            }
        }
        Ok(())
    })
}

/// Takes `[phys, phys + len)` away from `endpoint`'s device (the buffer is being freed).
pub fn unmap_dma(endpoint: u32, phys: u64, len: u64) {
    if !active() || len == 0 {
        return;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let mut st = STATE.lock();
        let Some(di) = st.domains.iter().position(|d| d.endpoint == endpoint) else { return };
        let (root, levels) = (st.domains[di].root, st.levels);
        let mut mem = Mem { coherent: st.coherent };
        let mut a = phys & !0xFFF;
        let mut n = 0;
        while a < phys + len {
            if dmar::unmap_page(&mut mem, root, levels, a) {
                n += 1;
            }
            a += 4096;
        }
        st.domains[di].pages = st.domains[di].pages.saturating_sub(n);
        flush_domain(&st, di);
    });
}

/// Name of the service owning device `id`, if any.
fn owner(st: &State, id: u16) -> &'static str {
    st.domains.iter().flat_map(|d| d.devices.iter()).find(|d| d.0 == id).map_or("no driver", |d| d.1)
}

/// Reads and clears the fault records of every unit and logs them. Called every second
/// by the supervisor's watchdog (and by `iommu faults`).
///
/// # Returns
/// The number of faults read.
pub fn poll_faults() -> usize {
    if !active() {
        return 0;
    }
    let mut lines: Vec<String> = Vec::new();
    let n = x86_64::instructions::interrupts::without_interrupts(|| {
        let mut st = STATE.lock();
        let mut found = Vec::new();
        let mut lost = 0;
        for u in st.units.iter().filter(|u| u.enabled) {
            let fsts = r32(u, REG_FSTS);
            if fsts & 2 != 0 {
                let fro = ((u.cap >> 24) & 0x3FF) * 16;
                let nfr = ((u.cap >> 40) & 0xFF) + 1;
                let mut i = ((fsts >> 8) & 0xFF) as u64 % nfr;
                for _ in 0..nfr {
                    let off = fro + i * 16;
                    let hi = r64(u, off + 8);
                    let Some(f) = dmar::decode_fault(r64(u, off), hi) else { break };
                    w32(u, off + 12, 1 << 31);
                    found.push(f);
                    i = (i + 1) % nfr;
                }
            }
            if fsts & 1 != 0 {
                lost += 1;
            }
            if fsts & 0x7D != 0 {
                w32(u, REG_FSTS, fsts & 0x7D);
            }
        }
        let tick = crate::arch::pit::ticks();
        st.lost += lost;
        for (k, f) in found.iter().enumerate() {
            if k < 8 {
                lines.push(alloc::format!(
                    "[iommu] blocked DMA: device {} ({}) tried to {} {:#x}: {} (fault reason {:#x})",
                    bdf_text(f.source),
                    owner(&st, f.source),
                    if f.read { "read" } else { "write" },
                    f.address,
                    dmar::reason_text(f.reason),
                    f.reason
                ));
            }
            if st.recent.len() == 64 {
                st.recent.pop_front();
            }
            st.recent.push_back(FaultLog { fault: *f, tick });
        }
        if found.len() > 8 {
            lines.push(alloc::format!("[iommu] ... and {} more blocked DMA accesses", found.len() - 8));
        }
        if lost > 0 {
            lines.push(String::from("[iommu] more faults came than the unit could record; some were not logged"));
        }
        FAULTS.fetch_add(found.len() as u64, Ordering::Relaxed);
        found.len()
    });
    for l in &lines {
        crate::kprintln!("{}", l);
    }
    n
}

/// The faults read since boot, newest last (at most 64).
pub fn recent_faults() -> Vec<FaultLog> {
    x86_64::instructions::interrupts::without_interrupts(|| STATE.lock().recent.iter().copied().collect())
}

/// The requester ID of the device attached for `endpoint`, if any.
pub fn device_of(endpoint: u32) -> Option<u16> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let st = STATE.lock();
        st.domains.iter().find(|d| d.endpoint == endpoint).and_then(|d| d.devices.first().map(|x| x.0))
    })
}

/// Whether domain of `endpoint` maps I/O address `iova`, and to what.
pub fn lookup(endpoint: u32, iova: u64) -> Option<(u64, u64)> {
    x86_64::instructions::interrupts::without_interrupts(|| {
        let st = STATE.lock();
        let d = st.domains.iter().find(|d| d.endpoint == endpoint)?;
        dmar::translate(&Mem { coherent: st.coherent }, d.root, st.levels, iova)
    })
}

/// A report for `iommu status`.
pub fn status() -> Vec<String> {
    let mut out = Vec::new();
    if !active() {
        out.push(String::from(match *OFF_BY.lock() {
            Some(_) => "DMA remapping: off (turned off by a boot option)",
            None => "DMA remapping: off (no usable Intel VT-d unit; see the boot log)",
        }));
        return out;
    }
    x86_64::instructions::interrupts::without_interrupts(|| {
        let st = STATE.lock();
        out.push(alloc::format!(
            "DMA remapping: on ({}-level tables, {} fault(s) since boot, {} lost)",
            st.levels,
            FAULTS.load(Ordering::Relaxed),
            st.lost
        ));
        for u in &st.units {
            out.push(alloc::format!(
                "  unit {:#x}: {}{}",
                u.phys,
                if u.enabled { "translating" } else { "off" },
                u.skipped.as_ref().map_or(String::new(), |s| alloc::format!(" ({})", s))
            ));
        }
        for d in &st.domains {
            let devs: Vec<String> = d.devices.iter().map(|(id, n)| alloc::format!("{} {}", bdf_text(*id), n)).collect();
            out.push(alloc::format!(
                "  domain {} ({}): {} page(s) mapped; devices: {}",
                d.did,
                if d.endpoint == 0 { String::from("firmware regions") } else { alloc::format!("endpoint {:#x}", d.endpoint) },
                d.pages,
                if devs.is_empty() { String::from("none") } else { devs.join(", ") }
            ));
        }
    });
    out
}
