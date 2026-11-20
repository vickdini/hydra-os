//! ACPI tables in memory (leaked, so their addresses stay valid): an RSDP pointing at an
//! XSDT (or an RSDT) listing the given tables, each with a valid checksum.

/// A table: signature, then `body` after the 36-byte header.
pub fn table(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[0..4].copy_from_slice(sig);
    t[8] = 1; // revision
    t.extend_from_slice(body);
    let len = t.len() as u32;
    t[4..8].copy_from_slice(&len.to_le_bytes());
    let sum = t.iter().fold(0u8, |s, &b| s.wrapping_add(b));
    t[9] = 0u8.wrapping_sub(sum);
    t
}

/// Copies `v` into memory below 4 GiB (an RSDT holds 32-bit addresses) that lives for the
/// whole test binary; returns its address.
pub fn leak(v: Vec<u8>) -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    const BASE: u64 = 0x3800_0000;
    const SIZE: u64 = 4 << 20;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        std::mem::forget(super::Arena::at(BASE, SIZE));
        NEXT.store(BASE, Ordering::SeqCst);
    });
    let at = NEXT.fetch_add((v.len() as u64 + 15) & !15, Ordering::SeqCst);
    assert!(at + v.len() as u64 <= BASE + SIZE, "ACPI arena full");
    unsafe { core::ptr::copy_nonoverlapping(v.as_ptr(), at as *mut u8, v.len()) };
    at
}

/// An RSDP (revision 2 with an XSDT, or 0 with an RSDT) listing `tables`; returns its address.
pub fn rsdp(tables: Vec<Vec<u8>>, xsdt: bool) -> u64 {
    let addrs: Vec<u64> = tables.into_iter().map(leak).collect();
    let mut body = Vec::new();
    for a in &addrs {
        if xsdt {
            body.extend_from_slice(&a.to_le_bytes());
        } else {
            body.extend_from_slice(&(*a as u32).to_le_bytes());
        }
    }
    let sdt = leak(table(if xsdt { b"XSDT" } else { b"RSDT" }, &body));
    let mut r = vec![0u8; 36];
    r[0..8].copy_from_slice(b"RSD PTR ");
    r[15] = if xsdt { 2 } else { 0 };
    r[16..20].copy_from_slice(&(sdt as u32).to_le_bytes());
    if xsdt {
        r[24..32].copy_from_slice(&sdt.to_le_bytes());
    }
    leak(r)
}

/// A MADT: local APIC base, then entries (type, bytes after the 2-byte header).
pub fn madt(lapic: u32, entries: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut b = lapic.to_le_bytes().to_vec();
    b.extend_from_slice(&1u32.to_le_bytes()); // flags: PC-AT compatible
    for (ty, e) in entries {
        b.push(*ty);
        b.push(e.len() as u8 + 2);
        b.extend_from_slice(e);
    }
    table(b"APIC", &b)
}

/// MADT entry: processor local APIC (`flags` bit 0 enabled, bit 1 online capable).
pub fn lapic_entry(uid: u8, apic: u8, flags: u32) -> (u8, Vec<u8>) {
    let mut e = vec![uid, apic];
    e.extend_from_slice(&flags.to_le_bytes());
    (0, e)
}

/// MADT entry: processor local x2APIC.
pub fn x2apic_entry(apic: u32, flags: u32) -> (u8, Vec<u8>) {
    let mut e = vec![0, 0];
    e.extend_from_slice(&apic.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e.extend_from_slice(&0u32.to_le_bytes());
    (9, e)
}

/// MADT entry: local APIC address override.
pub fn lapic_override(addr: u64) -> (u8, Vec<u8>) {
    let mut e = vec![0, 0];
    e.extend_from_slice(&addr.to_le_bytes());
    (5, e)
}

/// A DMAR device scope: kind (1 endpoint, 2 bridge, 3 IOAPIC), start bus, path.
pub fn scope(kind: u8, bus: u8, path: &[(u8, u8)]) -> Vec<u8> {
    let mut s = vec![kind, 6 + 2 * path.len() as u8, 0, 0, 0, bus];
    for &(d, f) in path {
        s.push(d);
        s.push(f);
    }
    s
}

/// A DMAR remapping unit (DRHD).
pub fn drhd(flags: u8, segment: u16, base: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let sc: Vec<u8> = scopes.concat();
    let mut s = vec![0, 0];
    s.extend_from_slice(&(16 + sc.len() as u16).to_le_bytes());
    s.push(flags);
    s.push(0);
    s.extend_from_slice(&segment.to_le_bytes());
    s.extend_from_slice(&base.to_le_bytes());
    s.extend_from_slice(&sc);
    s
}

/// A DMAR reserved memory region (RMRR).
pub fn rmrr(base: u64, limit: u64, scopes: &[Vec<u8>]) -> Vec<u8> {
    let sc: Vec<u8> = scopes.concat();
    let mut s = vec![1, 0];
    s.extend_from_slice(&(24 + sc.len() as u16).to_le_bytes());
    s.extend_from_slice(&[0, 0, 0, 0]);
    s.extend_from_slice(&base.to_le_bytes());
    s.extend_from_slice(&limit.to_le_bytes());
    s.extend_from_slice(&sc);
    s
}

/// A DMAR table (host address width 39 bits).
pub fn dmar(structs: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![38, 1];
    b.extend_from_slice(&[0; 10]);
    b.extend_from_slice(&structs.concat());
    table(b"DMAR", &b)
}
