//! Tests for `src/arch/dmar.rs`: parsing a DMAR table built here the way firmware lays it
//! out, refusing broken ones, resolving device scopes across bridges, editing
//! second-level page tables, and decoding fault records.

use hydra_hosttests::arch::dmar::*;

/// A device scope entry of `kind` starting on `bus` with the given path.
fn scope(kind: u8, bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
    let mut s = vec![kind, (6 + 2 * path.len()) as u8, 0, 0, 0, bus];
    for &(d, f) in path {
        s.push(d);
        s.push(f);
    }
    s
}

fn drhd(flags: u8, base: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = scopes.concat();
    let mut s = vec![0u8; 16];
    s[0..2].copy_from_slice(&0u16.to_le_bytes());
    s[2..4].copy_from_slice(&((16 + body.len()) as u16).to_le_bytes());
    s[4] = flags;
    s[8..16].copy_from_slice(&base.to_le_bytes());
    s.extend(body);
    s
}

fn rmrr(base: u64, limit: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let body: Vec<u8> = scopes.concat();
    let mut s = vec![0u8; 24];
    s[0..2].copy_from_slice(&1u16.to_le_bytes());
    s[2..4].copy_from_slice(&((24 + body.len()) as u16).to_le_bytes());
    s[8..16].copy_from_slice(&base.to_le_bytes());
    s[16..24].copy_from_slice(&limit.to_le_bytes());
    s.extend(body);
    s
}

/// A full table with a correct length and checksum.
fn table(structs: &[Vec<u8>]) -> Vec<u8> {
    let mut t = vec![0u8; 48];
    t[0..4].copy_from_slice(b"DMAR");
    t[8] = 1;
    t[36] = 38; // host address width 39 bits
    t[37] = 1; // interrupt remapping supported
    for s in structs {
        t.extend_from_slice(s);
    }
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    let sum = t.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

/// A Haswell-like table: the graphics unit (00:02.0), the include-all unit, an RMRR for
/// USB (00:14.0, 00:1d.0) and one for graphics.
fn haswell() -> Vec<u8> {
    table(&[
        drhd(0, 0xFED9_0000, &[scope(1, 0, &[(2, 0)])]),
        drhd(1, 0xFED9_1000, &[scope(3, 0, &[(0x1F, 0)])]),
        rmrr(0xDA00_0000, 0xDA01_FFFF, &[scope(1, 0, &[(0x14, 0)]), scope(1, 0, &[(0x1D, 0)])]),
        rmrr(0xDB80_0000, 0xDF9F_FFFF, &[scope(1, 0, &[(2, 0)])]),
    ])
}

#[test]
fn parses_units_and_rmrrs() {
    let d = parse(&haswell()).unwrap();
    assert_eq!(d.host_address_width, 39);
    assert_eq!(d.flags, 1);
    assert_eq!(d.units.len(), 2);
    assert!(!d.units[0].include_all());
    assert_eq!(d.units[0].base, 0xFED9_0000);
    assert_eq!(d.units[0].scopes, vec![DeviceScope { kind: 1, enum_id: 0, start_bus: 0, path: vec![(2, 0)] }]);
    assert!(d.units[1].include_all());
    assert_eq!(d.units[1].scopes[0].kind, 3);
    assert_eq!(d.rmrrs.len(), 2);
    assert_eq!(d.rmrrs[0].base, 0xDA00_0000);
    assert_eq!(d.rmrrs[0].limit, 0xDA01_FFFF);
    assert_eq!(d.rmrrs[0].scopes.len(), 2);
    assert!(d.warnings.is_empty());
}

#[test]
fn refuses_broken_tables() {
    let good = haswell();
    let mut bad_sum = good.clone();
    bad_sum[40] ^= 1;
    assert_eq!(parse(&bad_sum).unwrap_err(), "the table's checksum is wrong");

    let mut bad_sig = good.clone();
    bad_sig[0] = b'X';
    assert_eq!(parse(&bad_sig).unwrap_err(), "not a DMAR table");

    // Length beyond the bytes given
    assert_eq!(parse(&good[..good.len() - 4]).unwrap_err(), "the table's length is wrong");

    // A structure whose length runs past the table
    let mut s = drhd(1, 0xFED9_1000, &[]);
    s[2..4].copy_from_slice(&200u16.to_le_bytes());
    assert_eq!(parse(&table(&[s])).unwrap_err(), "a structure has a bad length");

    // A unit without registers, and a table with no units
    assert_eq!(parse(&table(&[drhd(1, 0, &[])])).unwrap_err(), "a remapping unit has no valid register address");
    assert_eq!(parse(&table(&[rmrr(0x1000, 0x1FFF, &[])])).unwrap_err(), "the table lists no remapping unit");

    // A broken scope inside a unit
    let mut s = drhd(0, 0xFED9_0000, &[scope(1, 0, &[(2, 0)])]);
    s[17] = 7; // odd scope length
    assert_eq!(parse(&table(&[s])).unwrap_err(), "a device scope entry has a bad length");
}

#[test]
fn skips_a_broken_rmrr() {
    let t = table(&[drhd(1, 0xFED9_1000, &[]), rmrr(0x1000, 0x1800, &[]), rmrr(0x2000, 0x2FFF, &[scope(1, 0, &[(0x14, 0)])])]);
    let d = parse(&t).unwrap();
    assert_eq!(d.rmrrs.len(), 1);
    assert_eq!(d.rmrrs[0].base, 0x2000);
    assert_eq!(d.warnings.len(), 1);
}

#[test]
fn resolves_scopes_across_bridges() {
    // 00:1c.0 is a bridge to buses 2..=3; on bus 2, device 0 is the endpoint.
    let mut buses = |bus: u8, dev: u8, func: u8| if (bus, dev, func) == (0, 0x1C, 0) { (2, 3) } else { (0, 0) };
    let ep = DeviceScope { kind: 1, enum_id: 0, start_bus: 0, path: vec![(0x1C, 0), (0, 0)] };
    assert_eq!(resolve(&ep, &mut buses), Some(Resolved::Device(bdf(2, 0, 0))));
    let br = DeviceScope { kind: 2, enum_id: 0, start_bus: 0, path: vec![(0x1C, 0)] };
    let r = resolve(&br, &mut buses).unwrap();
    assert_eq!(r, Resolved::Bridge(bdf(0, 0x1C, 0), 2, 3));
    assert!(covers(&r, bdf(3, 0, 0)));
    assert!(covers(&r, bdf(0, 0x1C, 0)));
    assert!(!covers(&r, bdf(4, 0, 0)));
    // A path through something that is not a bridge goes nowhere
    let dead = DeviceScope { kind: 1, enum_id: 0, start_bus: 0, path: vec![(5, 0), (0, 0)] };
    assert_eq!(resolve(&dead, &mut buses), None);
    // I/O APIC scopes are not PCI devices
    let ioapic = DeviceScope { kind: 3, enum_id: 2, start_bus: 0xF0, path: vec![(0x1F, 0)] };
    assert_eq!(resolve(&ioapic, &mut buses), None);
    assert_eq!(bdf_parts(bdf(0, 0x1F, 2)), (0, 0x1F, 2));
}

/// Page tables in a Vec; "physical address" = (index + 1) * 4096.
struct Mem(Vec<Box<[u64; 512]>>);

impl TableMemory for Mem {
    fn alloc_table(&mut self) -> Option<u64> {
        if self.0.len() >= 64 {
            return None;
        }
        self.0.push(Box::new([0; 512]));
        Some(self.0.len() as u64 * 4096)
    }
    fn entry(&self, table: u64, index: usize) -> *mut u64 {
        let t = &self.0[(table / 4096 - 1) as usize];
        &t[index] as *const u64 as *mut u64
    }
}

#[test]
fn maps_and_unmaps_pages() {
    for levels in [3u8, 4] {
        let mut m = Mem(Vec::new());
        let root = m.alloc_table().unwrap();
        let iova = 0x1_2345_6000u64;
        assert_eq!(translate(&m, root, levels, iova), None);
        assert!(map_page(&mut m, root, levels, iova, iova, PTE_R | PTE_W).unwrap());
        assert_eq!(translate(&m, root, levels, iova + 0x10), Some((iova + 0x10, PTE_R | PTE_W)));
        assert_eq!(translate(&m, root, levels, iova + 0x1000), None);
        let tables = m.0.len();
        assert_eq!(tables, levels as usize);
        // A neighbour shares all tables
        assert!(map_page(&mut m, root, levels, iova + 0x1000, 0x7000, PTE_R).unwrap());
        assert_eq!(m.0.len(), tables);
        assert_eq!(translate(&m, root, levels, iova + 0x1000), Some((0x7000, PTE_R)));
        assert!(unmap_page(&mut m, root, levels, iova));
        assert!(!unmap_page(&mut m, root, levels, iova));
        assert_eq!(translate(&m, root, levels, iova), None);
        assert_eq!(translate(&m, root, levels, iova + 0x1000), Some((0x7000, PTE_R)));
        // Beyond the reach
        assert!(map_page(&mut m, root, levels, reach(levels), 0, PTE_R).is_err());
        assert!(!unmap_page(&mut m, root, levels, reach(levels)));
    }
    assert_eq!(reach(3), 1 << 39);
    assert_eq!(reach(4), 1 << 48);
}

#[test]
fn runs_out_of_table_memory_cleanly() {
    let mut m = Mem(Vec::new());
    let root = m.alloc_table().unwrap();
    let mut err = None;
    for i in 0..200u64 {
        // Each address needs its own last-level table
        if let Err(e) = map_page(&mut m, root, 4, i << 21, 0, PTE_R) {
            err = Some(e);
            break;
        }
    }
    assert_eq!(err, Some("no memory for an I/O page table"));
}

#[test]
fn entries_and_registers() {
    assert_eq!(root_entry(0x5000), 0x5001);
    assert_eq!(context_entry(0x9000, 4, 7), (0x9001, 2 | 7 << 8));
    assert_eq!(context_entry(0x9000, 3, 1), (0x9001, 1 | 1 << 8));
    assert_eq!(levels_from_cap(0b00100 << 8), Some(4));
    assert_eq!(levels_from_cap(0b00110 << 8), Some(4));
    assert_eq!(levels_from_cap(0b00010 << 8), Some(3));
    assert_eq!(levels_from_cap(0b00001 << 8), None);
    // Translation on (bit 31) keeps fault log / queued invalidation state, never repeats
    // the one-shot root-pointer (30) or write-buffer flush (27) bits.
    let gsts = 1 << 30 | 1 << 27;
    assert_eq!(gcmd(gsts, 1 << 31, true), 1 << 31);
    assert_eq!(gcmd(1 << 31 | 1 << 26, 1 << 31, false), 1 << 26);
    assert_eq!(gcmd(1 << 31, 1 << 30, true), 1 << 31 | 1 << 30);
}

#[test]
fn decodes_faults() {
    assert_eq!(decode_fault(0x1234_5678, 0), None);
    let high = 1u64 << 63 | 1 << 62 | 6u64 << 32 | bdf(0, 3, 0) as u64;
    let f = decode_fault(0x1234_5678, high).unwrap();
    assert_eq!(f, Fault { source: 0x18, address: 0x1234_5000, reason: 6, read: true });
    assert_eq!(reason_text(f.reason), "read from memory not mapped for this device");
    assert_eq!(reason_text(5), "write to memory not mapped writable for this device");
    assert_eq!(reason_text(0x77), "another remapping fault");
}

#[test]
fn counts_references_to_a_page_mapped_twice() {
    let mut m = Mem(Vec::new());
    let root = m.alloc_table().unwrap();
    let a = 0x40_0000u64;
    assert!(map_page(&mut m, root, 4, a, a, PTE_R | PTE_W).unwrap());
    // Lent again for a second request: still one page, two references
    assert!(!map_page(&mut m, root, 4, a, a, PTE_R | PTE_W).unwrap());
    assert!(!map_page(&mut m, root, 4, a, a, PTE_R).unwrap());
    assert_eq!(translate(&m, root, 4, a), Some((a, PTE_R | PTE_W)));
    assert!(!unmap_page(&mut m, root, 4, a));
    assert!(!unmap_page(&mut m, root, 4, a));
    assert_eq!(translate(&m, root, 4, a), Some((a, PTE_R | PTE_W)));
    assert!(unmap_page(&mut m, root, 4, a));
    assert_eq!(translate(&m, root, 4, a), None);
    assert!(!unmap_page(&mut m, root, 4, a));
    // Another physical page at the same address replaces the mapping
    assert!(map_page(&mut m, root, 4, a, a, PTE_R).unwrap());
    assert!(map_page(&mut m, root, 4, a, 0x9000, PTE_R).unwrap());
    assert_eq!(translate(&m, root, 4, a), Some((0x9000, PTE_R)));
    assert!(unmap_page(&mut m, root, 4, a));
}
