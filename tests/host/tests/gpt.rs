//! Tests for `src/fs/gpt.rs`: GUID text forms, and reading GPT and MBR tables from a
//! disk image built here the way sgdisk/sfdisk lay them out.

use hydra_hosttests::fs::gpt::{crc32, guid_string, parse_guid, read_table, Kind, ESP_TYPE, HYDRA_POOL_TYPE};

#[test]
fn guid_text_round_trip() {
    assert_eq!(guid_string(&ESP_TYPE), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    assert_eq!(guid_string(&HYDRA_POOL_TYPE), "7685a0b8-df41-47eb-af4f-02ce6fb01879");
    assert_eq!(parse_guid("7685A0B8-DF41-47EB-AF4F-02CE6FB01879"), Some(HYDRA_POOL_TYPE));
    assert_eq!(parse_guid("not-a-guid"), None);
    assert_eq!(&ESP_TYPE[..4], &[0x28, 0x73, 0x2A, 0xC1]); // first field little-endian on disk
}

/// A 64 MiB disk with a protective MBR, a GPT header and two entries.
fn gpt_disk() -> Vec<u8> {
    let mut d = vec![0u8; 64 << 20];
    d[446 + 4] = 0xEE;
    d[446 + 8..446 + 12].copy_from_slice(&1u32.to_le_bytes());
    d[446 + 12..446 + 16].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
    let mut ent = vec![0u8; 128 * 128];
    let mut put = |i: usize, ty: [u8; 16], uniq: u8, first: u64, last: u64, name: &str| {
        let e = &mut ent[i * 128..(i + 1) * 128];
        e[0..16].copy_from_slice(&ty);
        e[16..32].copy_from_slice(&[uniq; 16]);
        e[32..40].copy_from_slice(&first.to_le_bytes());
        e[40..48].copy_from_slice(&last.to_le_bytes());
        for (k, c) in name.encode_utf16().enumerate() {
            e[56 + 2 * k..58 + 2 * k].copy_from_slice(&c.to_le_bytes());
        }
    };
    put(0, ESP_TYPE, 0x11, 2048, 2048 + 16384 - 1, "EFI");
    put(1, HYDRA_POOL_TYPE, 0x22, 2048 + 16384, (64 << 11) - 34, "Hydra");
    d[1024..1024 + ent.len()].copy_from_slice(&ent);
    let h = &mut d[512..512 + 92];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    h[24..32].copy_from_slice(&1u64.to_le_bytes());
    h[56..72].copy_from_slice(&[0x33; 16]);
    h[72..80].copy_from_slice(&2u64.to_le_bytes());
    h[80..84].copy_from_slice(&128u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    h[88..92].copy_from_slice(&crc32(&ent).to_le_bytes());
    let c = crc32(h);
    h[16..20].copy_from_slice(&c.to_le_bytes());
    d
}

fn reader(d: &[u8]) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
    move |off, buf| {
        let o = off as usize;
        if o + buf.len() > d.len() {
            return false;
        }
        buf.copy_from_slice(&d[o..o + buf.len()]);
        true
    }
}

#[test]
fn reads_gpt() {
    let d = gpt_disk();
    let t = read_table(&mut reader(&d), d.len() as u64).expect("a table");
    assert_eq!(t.kind, Kind::Gpt);
    assert_eq!(t.parts.len(), 2);
    assert_eq!(t.parts[0].number, 1);
    assert_eq!(t.parts[0].start, 1 << 20);
    assert_eq!(t.parts[0].len, 8 << 20);
    assert_eq!(t.parts[0].name, "EFI");
    let pool = t.by_type(&HYDRA_POOL_TYPE).unwrap();
    assert_eq!(pool.number, 2);
    assert_eq!(pool.start, 9 << 20);
    assert!(t.by_guid(&[0x11; 16]).is_some());
    assert_eq!(t.disk_guid, [0x33; 16]);
}

#[test]
fn rejects_corrupt_gpt() {
    let mut d = gpt_disk();
    d[1024 + 40] ^= 1; // an entry changed: the entries' CRC no longer matches
    assert!(read_table(&mut reader(&d), d.len() as u64).is_none());
}

#[test]
fn reads_mbr_and_ignores_fat_boot_sector() {
    let mut d = vec![0u8; 16 << 20];
    d[446] = 0x80;
    d[446 + 4] = 0x0C;
    d[446 + 8..446 + 12].copy_from_slice(&2048u32.to_le_bytes());
    d[446 + 12..446 + 16].copy_from_slice(&4096u32.to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
    let t = read_table(&mut reader(&d), d.len() as u64).unwrap();
    assert_eq!(t.kind, Kind::Mbr);
    assert_eq!(t.parts.len(), 1);
    assert_eq!(t.parts[0].mbr_type, 0x0C);
    assert_eq!(t.parts[0].start, 1 << 20);
    // A FAT32 file system straight on the disk
    d[82..87].copy_from_slice(b"FAT32");
    assert!(read_table(&mut reader(&d), d.len() as u64).is_none());
    // Blank disk
    let blank = vec![0u8; 1 << 20];
    assert!(read_table(&mut reader(&blank), blank.len() as u64).is_none());
}
