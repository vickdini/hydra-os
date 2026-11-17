//! # Intel VT-d: the ACPI DMAR table and second-level page tables
//!
//! The hardware-independent half of the IOMMU support ([`super::iommu`] drives the
//! hardware). Kept free of kernel state so the host unit tests compile it as it is.
//!
//! - [`parse`] reads the firmware's DMAR table: the remapping units (DRHD), the memory
//!   the firmware still needs devices to reach (RMRR) and the PCI devices each covers.
//!   A broken table is refused as a whole ([`parse`] returns an error); a broken RMRR is
//!   skipped with a warning, as Linux does.
//! - [`map_page`], [`unmap_page`] and [`translate`] edit a second-level page table (the
//!   format of a DMA domain's I/O page table) through a [`TableMemory`].
//! - [`decode_fault`] and [`reason_text`] turn a fault record into plain words.

use alloc::vec::Vec;

/// A device scope entry: an endpoint, or a bridge and everything below it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceScope {
    /// 1: PCI endpoint, 2: PCI sub-hierarchy (a bridge), 3: I/O APIC, 4: HPET, 5: ACPI
    /// namespace device.
    pub kind: u8,
    /// Enumeration ID (the I/O APIC or HPET number).
    pub enum_id: u8,
    /// Bus the path starts on.
    pub start_bus: u8,
    /// `(device, function)` hops from `start_bus`: every hop but the last is a bridge.
    pub path: Vec<(u8, u8)>,
}

/// A DMA remapping hardware unit (DRHD).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Drhd {
    /// Bit 0: INCLUDE_PCI_ALL (the unit covers every device of its segment that no other
    /// unit lists).
    pub flags: u8,
    /// PCI segment.
    pub segment: u16,
    /// Physical address of its registers.
    pub base: u64,
    /// The devices it covers (unless INCLUDE_PCI_ALL).
    pub scopes: Vec<DeviceScope>,
}

impl Drhd {
    /// Whether the unit covers all devices no other unit lists.
    pub fn include_all(&self) -> bool {
        self.flags & 1 != 0
    }
}

/// A reserved memory region (RMRR): memory the listed devices may still use for DMA
/// after the operating system takes over (USB keyboard emulation, graphics stolen memory).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rmrr {
    /// PCI segment.
    pub segment: u16,
    /// First byte (4 KiB aligned).
    pub base: u64,
    /// Last byte (inclusive; the region ends on a 4 KiB boundary).
    pub limit: u64,
    /// The devices that use it.
    pub scopes: Vec<DeviceScope>,
}

/// The parsed DMAR table.
#[derive(Debug, Clone, Default)]
pub struct Dmar {
    /// Physical address width the platform supports (bits).
    pub host_address_width: u8,
    /// Bit 0: interrupt remapping supported; bit 1: x2APIC opt-out; bit 2: DMA control
    /// opt-in.
    pub flags: u8,
    /// Remapping units, in table order.
    pub units: Vec<Drhd>,
    /// Reserved memory regions (only the valid ones).
    pub rmrrs: Vec<Rmrr>,
    /// What was wrong but skipped, in plain words.
    pub warnings: Vec<&'static str>,
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

fn u64_at(b: &[u8], o: usize) -> u64 {
    u32_at(b, o) as u64 | (u32_at(b, o + 4) as u64) << 32
}

/// Parses the device scopes in `b` (the tail of a DRHD or RMRR structure).
fn parse_scopes(mut b: &[u8]) -> Result<Vec<DeviceScope>, &'static str> {
    let mut out = Vec::new();
    while !b.is_empty() {
        if b.len() < 6 {
            return Err("a device scope entry is cut short");
        }
        let len = b[1] as usize;
        if len < 6 || len > b.len() || (len - 6) % 2 != 0 {
            return Err("a device scope entry has a bad length");
        }
        let path = b[6..len].chunks_exact(2).map(|p| (p[0], p[1])).collect::<Vec<_>>();
        if path.is_empty() {
            return Err("a device scope entry has an empty path");
        }
        out.push(DeviceScope { kind: b[0], enum_id: b[4], start_bus: b[5], path });
        b = &b[len..];
    }
    Ok(out)
}

/// Parses an ACPI DMAR table (with its 36-byte header).
///
/// # Errors
/// A plain description of what is broken: a bad signature, length or checksum, a
/// structure running past the end, a unit without a register address, or no unit.
pub fn parse(table: &[u8]) -> Result<Dmar, &'static str> {
    if table.len() < 48 || &table[0..4] != b"DMAR" {
        return Err("not a DMAR table");
    }
    let len = u32_at(table, 4) as usize;
    if len < 48 || len > table.len() {
        return Err("the table's length is wrong");
    }
    let table = &table[..len];
    if table.iter().fold(0u8, |s, &b| s.wrapping_add(b)) != 0 {
        return Err("the table's checksum is wrong");
    }
    let mut d = Dmar { host_address_width: table[36].wrapping_add(1), flags: table[37], ..Default::default() };
    let mut at = 48;
    while at < len {
        if at + 4 > len {
            return Err("a structure is cut short");
        }
        let (ty, slen) = (u16_at(table, at), u16_at(table, at + 2) as usize);
        if slen < 4 || at + slen > len {
            return Err("a structure has a bad length");
        }
        let s = &table[at..at + slen];
        match ty {
            0 => {
                if slen < 16 {
                    return Err("a remapping unit (DRHD) is cut short");
                }
                let base = u64_at(s, 8);
                if base == 0 || base & 0xFFF != 0 {
                    return Err("a remapping unit has no valid register address");
                }
                d.units.push(Drhd { flags: s[4], segment: u16_at(s, 6), base, scopes: parse_scopes(&s[16..])? });
            }
            1 => {
                if slen < 24 {
                    return Err("a reserved memory region (RMRR) is cut short");
                }
                let (base, limit) = (u64_at(s, 8), u64_at(s, 16));
                match parse_scopes(&s[24..]) {
                    Ok(scopes) if base & 0xFFF == 0 && (limit + 1) & 0xFFF == 0 && base < limit => {
                        d.rmrrs.push(Rmrr { segment: u16_at(s, 6), base, limit, scopes });
                    }
                    Ok(_) => d.warnings.push("a reserved memory region (RMRR) has a bad address range; ignored"),
                    Err(_) => d.warnings.push("a reserved memory region (RMRR) has broken device entries; ignored"),
                }
            }
            // ATSR, RHSA, ANDD, SATC, SIDP: not needed here
            _ => {}
        }
        at += slen;
    }
    if d.units.is_empty() {
        return Err("the table lists no remapping unit");
    }
    Ok(d)
}

/// A PCI function as a 16-bit requester ID: `bus << 8 | device << 3 | function`.
pub fn bdf(bus: u8, device: u8, function: u8) -> u16 {
    (bus as u16) << 8 | (device as u16 & 0x1F) << 3 | (function as u16 & 7)
}

/// `bb:dd.f` of a requester ID.
pub fn bdf_parts(id: u16) -> (u8, u8, u8) {
    ((id >> 8) as u8, ((id >> 3) & 0x1F) as u8, (id & 7) as u8)
}

/// What a device scope resolves to on the PCI bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// One function (its requester ID).
    Device(u16),
    /// A bridge: the function itself and the buses `first..=last` below it.
    Bridge(u16, u8, u8),
}

/// Follows a PCI scope's path across bridges. `bridge_buses(bus, dev, fn)` returns a
/// bridge's secondary and subordinate bus numbers (configuration offsets 0x19, 0x1A).
///
/// # Returns
/// `None` for I/O APIC, HPET and namespace scopes, or when a bridge on the path has no
/// bus behind it.
pub fn resolve(scope: &DeviceScope, bridge_buses: &mut dyn FnMut(u8, u8, u8) -> (u8, u8)) -> Option<Resolved> {
    if scope.kind != 1 && scope.kind != 2 {
        return None;
    }
    let mut bus = scope.start_bus;
    let last = scope.path.len() - 1;
    for (i, &(dev, func)) in scope.path.iter().enumerate() {
        if i == last {
            let id = bdf(bus, dev, func);
            if scope.kind == 2 {
                let (sec, sub) = bridge_buses(bus, dev, func);
                return (sec != 0 && sub >= sec).then_some(Resolved::Bridge(id, sec, sub));
            }
            return Some(Resolved::Device(id));
        }
        let (sec, _) = bridge_buses(bus, dev, func);
        if sec == 0 || sec == 0xFF {
            return None;
        }
        bus = sec;
    }
    None
}

/// Whether `id` is `r` or below it.
pub fn covers(r: &Resolved, id: u16) -> bool {
    match *r {
        Resolved::Device(d) => d == id,
        Resolved::Bridge(b, first, last) => b == id || ((id >> 8) as u8 >= first && (id >> 8) as u8 <= last),
    }
}

// ------------------------------------------------------------------------------------
// Second-level page tables
// ------------------------------------------------------------------------------------

/// Read permission.
pub const PTE_R: u64 = 1;
/// Write permission.
pub const PTE_W: u64 = 2;
/// Address bits of an entry.
pub const PTE_ADDR: u64 = 0x000F_FFFF_FFFF_F000;

/// Memory holding page tables, known by physical address.
pub trait TableMemory {
    /// A zeroed 4 KiB table; its physical address.
    fn alloc_table(&mut self) -> Option<u64>;
    /// Entry `index` of the table at physical `table`.
    fn entry(&self, table: u64, index: usize) -> *mut u64;
    /// Called after an entry changed (the unit may read tables without snooping caches).
    fn flushed(&self, _entry: *mut u64) {}
}

/// The index into a level-`level` table (1: the last) for `iova`.
pub fn index(iova: u64, level: u8) -> usize {
    ((iova >> (12 + 9 * (level as u64 - 1))) & 511) as usize
}

/// The first address a `levels`-level table cannot translate.
pub fn reach(levels: u8) -> u64 {
    1u64 << (12 + 9 * levels as u32)
}

/// Maps the 4 KiB page at `iova` to `phys` with `perm` ([`PTE_R`] | [`PTE_W`]) in the table
/// rooted at `root`, adding tables as needed. Mapping a page that is already mapped to
/// the same `phys` counts one more reference (see [`unmap_page`]).
///
/// # Returns
/// Whether the page was newly mapped (false: one more reference to a mapped page).
///
/// # Errors
/// The address is outside the table's reach, or no memory for a table.
pub fn map_page(mem: &mut dyn TableMemory, root: u64, levels: u8, iova: u64, phys: u64, perm: u64) -> Result<bool, &'static str> {
    if iova >= reach(levels) {
        return Err("address beyond the domain's width");
    }
    let mut table = root;
    for level in (2..=levels).rev() {
        let e = mem.entry(table, index(iova, level));
        let v = unsafe { e.read_volatile() };
        table = if v & (PTE_R | PTE_W) != 0 {
            v & PTE_ADDR
        } else {
            let t = mem.alloc_table().ok_or("no memory for an I/O page table")?;
            unsafe { e.write_volatile(t | PTE_R | PTE_W) };
            mem.flushed(e);
            t
        };
    }
    let e = mem.entry(table, index(iova, 1));
    let old = unsafe { e.read_volatile() };
    if old & (PTE_R | PTE_W) != 0 && old & PTE_ADDR == phys & PTE_ADDR {
        // Mapped already (a page lent for two requests at once): one more reference
        let refs = ((old & PTE_REFS) >> PTE_REFS_SHIFT).saturating_add(1).min(PTE_REFS >> PTE_REFS_SHIFT);
        unsafe { e.write_volatile((old & !PTE_REFS) | refs << PTE_REFS_SHIFT | (perm & (PTE_R | PTE_W))) };
        mem.flushed(e);
        return Ok(false);
    }
    unsafe { e.write_volatile((phys & PTE_ADDR) | (perm & (PTE_R | PTE_W))) };
    mem.flushed(e);
    Ok(true)
}

/// Extra references to a mapped page, minus one, kept in bits the unit ignores (52..=61).
pub const PTE_REFS: u64 = 0x3FF << PTE_REFS_SHIFT;
/// First bit of [`PTE_REFS`].
pub const PTE_REFS_SHIFT: u64 = 52;

/// Drops one reference to the page at `iova`, unmapping it with the last one.
/// Intermediate tables stay (they are few).
///
/// # Returns
/// Whether a page was unmapped (false when it was not mapped or is still referenced).
pub fn unmap_page(mem: &mut dyn TableMemory, root: u64, levels: u8, iova: u64) -> bool {
    if iova >= reach(levels) {
        return false;
    }
    let mut table = root;
    for level in (2..=levels).rev() {
        let v = unsafe { mem.entry(table, index(iova, level)).read_volatile() };
        if v & (PTE_R | PTE_W) == 0 {
            return false;
        }
        table = v & PTE_ADDR;
    }
    let e = mem.entry(table, index(iova, 1));
    let v = unsafe { e.read_volatile() };
    let was = v & (PTE_R | PTE_W) != 0;
    if was && v & PTE_REFS != 0 {
        unsafe { e.write_volatile(v - (1 << PTE_REFS_SHIFT)) };
        mem.flushed(e);
        return false;
    }
    unsafe { e.write_volatile(0) };
    mem.flushed(e);
    was
}

/// The physical address `iova` maps to and its permissions, if mapped.
pub fn translate(mem: &dyn TableMemory, root: u64, levels: u8, iova: u64) -> Option<(u64, u64)> {
    if iova >= reach(levels) {
        return None;
    }
    let mut table = root;
    for level in (1..=levels).rev() {
        let v = unsafe { mem.entry(table, index(iova, level)).read_volatile() };
        if v & (PTE_R | PTE_W) == 0 {
            return None;
        }
        if level == 1 {
            return Some(((v & PTE_ADDR) | (iova & 0xFFF), v & (PTE_R | PTE_W)));
        }
        table = v & PTE_ADDR;
    }
    None
}

// ------------------------------------------------------------------------------------
// Root and context entries, registers, faults
// ------------------------------------------------------------------------------------

/// A root entry's low word: present, pointing at a context table.
pub fn root_entry(context_table: u64) -> u64 {
    (context_table & PTE_ADDR) | 1
}

/// A context entry `(low, high)`: present, translating untranslated requests through the
/// second-level table at `table` (`levels` levels) in domain `did`.
pub fn context_entry(table: u64, levels: u8, did: u16) -> (u64, u64) {
    // Address width: 1 = 39 bits (3 levels), 2 = 48 bits (4 levels)
    ((table & PTE_ADDR) | 1, (levels as u64 - 2) | (did as u64) << 8)
}

/// The levels to use given the capability register's SAGAW bits: 4 (48-bit) if
/// supported, else 3 (39-bit).
pub fn levels_from_cap(cap: u64) -> Option<u8> {
    let sagaw = (cap >> 8) & 0x1F;
    if sagaw & 4 != 0 {
        Some(4)
    } else if sagaw & 2 != 0 {
        Some(3)
    } else {
        None
    }
}

/// The global command register value that keeps the persistent enables of `gsts`
/// (translation, queued invalidation, interrupt remapping, ...) and sets (`on`) or
/// clears `bit`; the one-shot bits are never repeated.
pub fn gcmd(gsts: u32, bit: u32, on: bool) -> u32 {
    let keep = gsts & 0x96FF_FFFF;
    if on {
        keep | bit
    } else {
        keep & !bit
    }
}

/// One fault record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Fault {
    /// The device (requester ID).
    pub source: u16,
    /// The page it tried to reach.
    pub address: u64,
    /// The fault reason code.
    pub reason: u8,
    /// A read (else a write).
    pub read: bool,
}

/// Decodes a 128-bit fault recording register `(low, high)`; `None` if it holds no fault.
pub fn decode_fault(low: u64, high: u64) -> Option<Fault> {
    if high >> 63 == 0 {
        return None;
    }
    Some(Fault { source: high as u16, address: low & !0xFFF, reason: (high >> 32) as u8, read: (high >> 62) & 1 != 0 })
}

/// A fault reason in plain words.
pub fn reason_text(reason: u8) -> &'static str {
    match reason {
        1 => "the device's bus has no entry in the root table",
        2 => "the device has no DMA domain (no context entry)",
        3 => "the device's context entry is invalid",
        4 => "the address is beyond the domain's address width",
        5 => "write to memory not mapped writable for this device",
        6 => "read from memory not mapped for this device",
        7 => "the unit could not read an I/O page table",
        8 => "the unit could not read the root table",
        9 => "the unit could not read a context table",
        0xA => "reserved bits set in a root entry",
        0xB => "reserved bits set in a context entry",
        0xC => "reserved bits set in an I/O page table entry",
        0xD => "the translation type is blocked by the context entry",
        _ => "another remapping fault",
    }
}
