use crate::acpi_s5::*;
use crate::bootwords::*;
use crate::fat32::*;
use crate::logring::*;

// ---------------------------------------------------------------------------------------
// The log ring

fn region() -> Vec<u8> {
    let mut r = vec![0u8; REGION];
    set_header(&mut r, &Header::new(7));
    r
}

#[test]
fn ring_starts_empty_and_valid() {
    let r = region();
    let h = header(&r);
    assert!(h.valid());
    assert_eq!(h.seq, 7);
    assert!(!h.unsaved(), "nothing written yet");
    assert!(render(&r).is_empty());
}

#[test]
fn garbage_is_not_a_header() {
    let mut r = vec![0x5Au8; REGION];
    assert!(!header(&r).valid());
    // The magic alone is not enough
    r[..8].copy_from_slice(b"HYDRALG1");
    assert!(!header(&r).valid());
    append(&mut r, b"x\n");
    assert_eq!(r[HEADER], 0x5A, "an invalid region is never written");
}

#[test]
fn append_makes_crlf_and_drops_cr_and_nul() {
    let mut r = region();
    append(&mut r, b"one\r\ntwo\0\nthree");
    assert_eq!(render(&r), b"one\r\ntwo\r\nthree");
    assert!(header(&r).unsaved());
}

#[test]
fn head_then_ring_then_wrap() {
    let mut r = region();
    let line = [b'a'; 1000];
    for _ in 0..HEAD / 1000 {
        append(&mut r, &line);
    }
    let h = header(&r);
    assert_eq!(h.head_len as usize, HEAD / 1000 * 1000);
    append(&mut r, &[b'b'; 1000]); // fills the head, the rest into the ring
    let h = header(&r);
    assert_eq!(h.head_len as usize, HEAD);
    assert!(h.ring_written > 0);
    assert!(!wrapped(&h));
    let t = render(&r);
    assert_eq!(t.len(), HEAD + h.ring_written as usize);
    // Wrap the ring: the head stays, the newest RING bytes follow a note
    for i in 0..(RING / 1000 + 5) {
        let c = b'0' + (i % 10) as u8;
        append(&mut r, &[c; 1000]);
    }
    let h = header(&r);
    assert!(wrapped(&h));
    let t = render(&r);
    assert!(t.len() <= FILE_SIZE);
    assert_eq!(&t[..HEAD - 1000], &[b'a'; HEAD - 1000][..]);
    let s = String::from_utf8_lossy(&t);
    assert!(s.contains("bytes of the log left out here"));
    // The newest text is at the end
    let last = b'0' + ((RING / 1000 + 4) % 10) as u8;
    assert_eq!(t[t.len() - 1], last);
    assert_eq!(t.len(), HEAD + RING + s.split("left out here ...]\r\n").next().unwrap().len() - HEAD + "left out here ...]\r\n".len());
}

#[test]
fn flags_mark_saved_logs() {
    let mut r = region();
    append(&mut r, b"x");
    let mut h = header(&r);
    h.flags |= F_WRITTEN;
    set_header(&mut r, &h);
    assert!(!header(&r).unsaved());
    h.flags = F_PANIC;
    set_header(&mut r, &h);
    assert!(header(&r).unsaved());
    // A boot without a file (seq 0) never needs saving
    let mut r0 = vec![0u8; REGION];
    set_header(&mut r0, &Header::new(0));
    append(&mut r0, b"x");
    assert!(!header(&r0).unsaved());
}

#[test]
fn filler_is_empty_lines() {
    assert_eq!(filler(6), b"\r\n\r\n\r\n");
}

#[test]
fn file_names_and_numbers() {
    assert_eq!(file_name(7), "boot007.txt");
    assert_eq!(file_number("BOOT007.TXT"), Some(7));
    assert_eq!(file_number("boot999.txt"), Some(999));
    assert_eq!(file_number("boot000.txt"), None);
    assert_eq!(file_number("boot07.txt"), None);
    assert_eq!(file_number("readme.txt"), None);
}

#[test]
fn next_number_counts_and_keeps_ten() {
    assert_eq!(next_number(&[], 10), (1, vec![]));
    assert_eq!(next_number(&[1, 2, 3], 10), (4, vec![]));
    let have: Vec<u32> = (1..=10).collect();
    let (n, mut del) = next_number(&have, 10);
    del.sort();
    assert_eq!((n, del), (11, vec![1]));
    let have: Vec<u32> = (5..=20).collect();
    let (n, mut del) = next_number(&have, 10);
    del.sort();
    assert_eq!(n, 21);
    assert_eq!(del, (5..=11).collect::<Vec<u32>>());
}

#[test]
fn next_number_wraps_after_999() {
    let (n, del) = next_number(&[997, 998, 999], 10);
    assert_eq!((n, del), (1, vec![]));
    // After the wrap the newest is just below the gap
    let (n, mut del) = next_number(&[1, 2, 995, 996, 997, 998, 999], 5);
    del.sort();
    assert_eq!(n, 3);
    assert_eq!(del, vec![995, 996, 997]);
    // A file with the next number already there is replaced
    let (n, del) = next_number(&[1, 2, 3, 900], 10);
    assert_eq!(n, 4);
    assert!(del.is_empty());
}

// ---------------------------------------------------------------------------------------
// FAT32

/// A small FAT32 volume in memory: 512-byte sectors, `per` sectors per cluster.
struct Fat {
    img: Vec<u8>,
    per: usize,
    reserved: usize,
    fat_sectors: usize,
}

impl Fat {
    fn new(per: usize) -> Fat {
        let reserved = 32;
        let fat_sectors = 16; // 2048 entries
        let total = reserved + 2 * fat_sectors + 1000 * per;
        let mut img = vec![0u8; total * 512];
        let b = &mut img[..512];
        b[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        b[3..11].copy_from_slice(b"MSWIN4.1");
        b[11..13].copy_from_slice(&512u16.to_le_bytes());
        b[13] = per as u8;
        b[14..16].copy_from_slice(&(reserved as u16).to_le_bytes());
        b[16] = 2;
        b[32..36].copy_from_slice(&(total as u32).to_le_bytes());
        b[36..40].copy_from_slice(&(fat_sectors as u32).to_le_bytes());
        b[44..48].copy_from_slice(&2u32.to_le_bytes());
        b[510] = 0x55;
        b[511] = 0xAA;
        let mut f = Fat { img, per, reserved, fat_sectors };
        f.set(0, 0x0FFF_FFF8);
        f.set(1, 0x0FFF_FFFF);
        f.set(2, 0x0FFF_FFFF); // the root directory
        f
    }
    fn set(&mut self, c: u32, v: u32) {
        let at = self.reserved * 512 + c as usize * 4;
        self.img[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn chain(&mut self, cs: &[u32]) {
        for w in cs.windows(2) {
            self.set(w[0], w[1]);
        }
        self.set(*cs.last().unwrap(), 0x0FFF_FFFF);
    }
    fn cluster_off(&self, c: u32) -> usize {
        (self.reserved + 2 * self.fat_sectors) * 512 + (c as usize - 2) * self.per * 512
    }
    fn entry(&mut self, dir_cluster: u32, slot: usize, name: &[u8; 11], attr: u8, first: u32, size: u32) {
        let at = self.cluster_off(dir_cluster) + slot * 32;
        let e = &mut self.img[at..at + 32];
        e[..11].copy_from_slice(name);
        e[11] = attr;
        e[20..22].copy_from_slice(&((first >> 16) as u16).to_le_bytes());
        e[26..28].copy_from_slice(&(first as u16).to_le_bytes());
        e[28..32].copy_from_slice(&size.to_le_bytes());
    }
    fn reader(&self) -> impl FnMut(u64, &mut [u8]) -> bool + '_ {
        move |off, buf| {
            let off = off as usize;
            if off + buf.len() > self.img.len() {
                return false;
            }
            buf.copy_from_slice(&self.img[off..off + buf.len()]);
            true
        }
    }
}

#[test]
fn short_names() {
    assert_eq!(&short_name("boot001.txt").unwrap(), b"BOOT001 TXT");
    assert_eq!(&short_name("logs").unwrap(), b"LOGS       ");
    assert!(short_name("hydra-logs-long").is_none());
    assert!(short_name("a.toolong").is_none());
    assert!(short_name("sp ace").is_none());
}

/// A volume with \LOGS\BOOT001.TXT in clusters 4,5,9,10,11 (fragmented), a long-name
/// piece, a deleted entry and the volume label in front of it.
fn sample(per: usize, size: u32) -> Fat {
    let mut f = Fat::new(per);
    f.entry(2, 0, b"HYDRA-LIVE ", 0x08, 0, 0);
    f.entry(2, 1, b"EFI        ", 0x10, 12, 0);
    f.chain(&[12]);
    f.entry(2, 2, b"LOGS       ", 0x10, 3, 0);
    f.chain(&[3]);
    f.entry(3, 0, b".          ", 0x10, 3, 0);
    f.entry(3, 1, b"..         ", 0x10, 0, 0);
    f.entry(3, 2, b"BOOT001 TXT", 0x20, 20, 10); // overwritten below
    let at = f.cluster_off(3) + 2 * 32;
    f.img[at] = 0xE5; // deleted
    f.entry(3, 3, b"Bxxxxxxxxxx", 0x0F, 0, 0); // a long-name piece
    f.entry(3, 4, b"BOOT001 TXT", 0x20, 4, size);
    f.chain(&[4, 5, 9, 10, 11]);
    f
}

#[test]
fn locate_follows_dirs_and_fragmented_chain() {
    let f = sample(1, 2500);
    let mut r = f.reader();
    let m = locate(&mut r, 1 << 40, &["logs", "BOOT001.TXT"]).unwrap();
    assert_eq!(m.size, 2500);
    let c = |n: u32| f.cluster_off(n) as u64;
    assert_eq!(
        m.extents,
        vec![Extent { file_off: 0, part_off: c(4), len: 1024 }, Extent { file_off: 1024, part_off: c(9), len: 1536 }]
    );
    // Pieces clip to the file and split at the gap
    assert_eq!(m.pieces(1000, 100), vec![(c(4) + 1000, 1000, 24), (c(9), 1024, 76)]);
    assert_eq!(m.pieces(2400, 1000), vec![(c(9) + 1376, 2400, 100)]);
    assert!(m.pieces(3000, 10).is_empty());
}

#[test]
fn locate_with_bigger_clusters() {
    let f = sample(8, 9000);
    let mut r = f.reader();
    let m = locate(&mut r, 1 << 40, &["LOGS", "boot001.txt"]).unwrap();
    assert_eq!(m.size, 9000);
    // 3 clusters of 4 KiB: 4, 5 (adjacent), then 9
    assert_eq!(m.extents.len(), 2);
    assert_eq!(m.extents[0].len, 8192);
    assert_eq!(m.extents[1].file_off, 8192);
}

#[test]
fn locate_errors() {
    let f = sample(1, 2500);
    let mut r = f.reader();
    assert_eq!(locate(&mut r, 1 << 40, &["logs", "boot002.txt"]), Err("not found"));
    assert_eq!(locate(&mut r, 1 << 40, &["efi", "boot001.txt"]), Err("not found"));
    assert_eq!(locate(&mut r, 1 << 40, &["logs"]), Err("a directory"));
    assert_eq!(locate(&mut r, 1 << 40, &["logs", "boot001.txt", "x"]), Err("not a directory"));
    // A chain shorter than the file
    let f = sample(1, 9000);
    let mut r = f.reader();
    assert_eq!(locate(&mut r, 1 << 40, &["logs", "boot001.txt"]), Err("the file's cluster chain is shorter than the file"));
    // A loop
    let mut f = sample(1, 5000);
    f.set(11, 4);
    let mut r = f.reader();
    assert!(locate(&mut r, 1 << 40, &["logs", "boot001.txt"]).is_ok(), "only the clusters the size needs are followed");
    let mut f = sample(1, 2500);
    f.set(3, 3); // the directory's chain loops
    let mut r = f.reader();
    assert!(locate(&mut r, 1 << 40, &["logs", "boot002.txt"]).is_err());
}

#[test]
fn locate_refuses_other_volumes() {
    let mut f = sample(1, 100);
    f.img[510] = 0;
    let mut r = f.reader();
    assert_eq!(locate(&mut r, 1 << 40, &["logs", "boot001.txt"]), Err("no FAT boot sector"));
    let mut f = sample(1, 100);
    f.img[22] = 9; // a FAT16 FAT size
    let mut r = f.reader();
    assert_eq!(locate(&mut r, 1 << 40, &["logs", "boot001.txt"]), Err("not FAT32"));
    let mut r = |_: u64, _: &mut [u8]| false;
    assert_eq!(locate(&mut r, 1 << 40, &["x"]), Err("cannot read the boot sector"));
}

// ---------------------------------------------------------------------------------------
// Boot words

fn ucs2(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|c| c.to_le_bytes()).collect()
}

#[test]
fn words_from_options_file_and_menu() {
    let mut w = Words::new();
    let mut opts = ucs2("Debug lx.vfs.restart=fast");
    opts.extend_from_slice(&[0, 0, b'x', 0]);
    w.add_ucs2(&opts);
    assert_eq!(w.text(), b"debug lx.vfs.restart=fast");
    w.add_file(b"\xEF\xBB\xBF# a comment\r\nIOMMU=off  # why\r\n\r\npcid=off\n");
    w.add_text(SAFE);
    let t = String::from_utf8(w.text().to_vec()).unwrap();
    assert_eq!(t, "debug lx.vfs.restart=fast iommu=off  pcid=off safe iommu=off pcid=off cpus=1 verbose");
    assert!(w.has(b"iommu=off"));
    assert!(!w.has(b"nodesktop"));
    assert!(!w.has(b""));
    assert_eq!(w.number(b"cpus="), Some(1));
    assert_eq!(w.number(b"mem="), None);
    assert_eq!(w.ucs2(), ucs2(&t));
}

#[test]
fn words_overflow_and_odd_characters() {
    let mut w = Words::new();
    w.add_ucs2(&ucs2("a\u{e9}b"));
    assert_eq!(w.text(), b"a?b");
    for _ in 0..200 {
        w.add_text("abcdefghij");
    }
    assert_eq!(w.len, MAX);
    let mut w = Words::new();
    w.add_text("cpus=x cpus=2");
    assert_eq!(w.number(b"cpus="), Some(2));
}

#[test]
fn menu_file_and_keys() {
    assert_eq!(menu_timeout(b"", 5), 5);
    assert_eq!(menu_timeout(b"# menu\r\n Timeout = 8 \r\n", 5), 8);
    assert_eq!(menu_timeout(b"timeout=600", 5), 60);
    assert_eq!(menu_timeout(b"timeout=x", 5), 5);
    assert_eq!(menu_choice('1'), Some(""));
    assert_eq!(menu_choice('\r'), Some(""));
    assert_eq!(menu_choice('2'), Some(SAFE));
    assert_eq!(menu_choice('3'), Some(SAFE_CONSOLE));
    assert_eq!(menu_choice('x'), None);
    assert!(SAFE_CONSOLE.contains("nodesktop") && SAFE.contains("cpus=1") && SAFE.contains("iommu=off") && SAFE.contains("pcid=off"));
}

// ---------------------------------------------------------------------------------------
// ACPI

fn fadt(len: usize) -> Vec<u8> {
    let mut t = vec![0u8; len];
    t[..4].copy_from_slice(b"FACP");
    t[4..8].copy_from_slice(&(len as u32).to_le_bytes());
    t[40..44].copy_from_slice(&0x7FE0_0000u32.to_le_bytes()); // DSDT
    t[48..52].copy_from_slice(&0xB2u32.to_le_bytes()); // SMI_CMD
    t[52] = 0xA0; // ACPI_ENABLE
    t[64..68].copy_from_slice(&0x1804u32.to_le_bytes()); // PM1a_CNT
    t
}

#[test]
fn fadt_v1_and_v5() {
    let f = parse_fadt(&fadt(116)).unwrap();
    assert_eq!(f, Fadt { pm1a_cnt: 0x1804, pm1b_cnt: 0, smi_cmd: 0xB2, acpi_enable: 0xA0, dsdt: 0x7FE0_0000, reset: None });
    let mut t = fadt(276);
    t[112..116].copy_from_slice(&(1u32 << 10).to_le_bytes());
    t[116] = 1; // I/O
    t[120..128].copy_from_slice(&0xCF9u64.to_le_bytes());
    t[128] = 6;
    t[140..148].copy_from_slice(&0x1_2345_0000u64.to_le_bytes()); // X_DSDT
    let f = parse_fadt(&t).unwrap();
    assert_eq!(f.reset, Some((1, 0xCF9, 6)));
    assert_eq!(f.dsdt, 0x1_2345_0000);
    // Only the extended PM1a block (I/O space)
    let mut t = fadt(276);
    t[64..68].copy_from_slice(&0u32.to_le_bytes());
    t[172] = 1;
    t[176..184].copy_from_slice(&0x404u64.to_le_bytes());
    assert_eq!(parse_fadt(&t).unwrap().pm1a_cnt, 0x404);
    // Reset register not supported: none
    let mut t = fadt(276);
    t[116] = 1;
    t[120..128].copy_from_slice(&0xCF9u64.to_le_bytes());
    assert_eq!(parse_fadt(&t).unwrap().reset, None);
    assert!(parse_fadt(b"APIC....").is_none());
}

fn dsdt(body: &[u8]) -> Vec<u8> {
    let mut t = vec![0u8; 36];
    t[..4].copy_from_slice(b"DSDT");
    t.extend_from_slice(body);
    t
}

#[test]
fn s5_package_forms() {
    // Name (_S5, Package (0x04) { 0x07, 0x07, 0, 0 }) with BytePrefix
    assert_eq!(s5_sleep_types(&dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x0A, 0x04, 0x0A, 0x07, 0x0A, 0x07, 0, 0])), Some((7, 7)));
    // QEMU's: ZeroOp elements
    assert_eq!(s5_sleep_types(&dsdt(&[0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x04, 0x00, 0x00, 0x00, 0x00])), Some((0, 0)));
    // A root-prefixed name and a two-byte package length
    assert_eq!(s5_sleep_types(&dsdt(&[0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x40, 0x00, 0x02, 0x0A, 0x05, 0x01])), Some((5, 1)));
    // A reference to _S5_ (not a NameOp) is skipped; the real one later is found
    assert_eq!(
        s5_sleep_types(&dsdt(&[0x70, b'_', b'S', b'5', b'_', 0x00, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02, 0x0A, 0x03, 0x0A, 0x03])),
        Some((3, 3))
    );
    assert_eq!(s5_sleep_types(&dsdt(b"no sleep states here")), None);
}

#[test]
fn pm1_value_keeps_other_bits() {
    assert_eq!(pm1_sleep_value(0x0001, 7), 0x0001 | 7 << 10 | 1 << 13);
    assert_eq!(pm1_sleep_value(0xFFFF, 0), 0xFFFF & !(7 << 10));
    assert_eq!(pm1_sleep_value(0x1C01, 5), 0x0001 | 5 << 10 | 1 << 13);
}

#[test]
fn locate_refuses_a_volume_bigger_than_its_partition_or_its_fat() {
    let f = sample(1, 2500);
    let len = f.img.len() as u64;
    let mut r = f.reader();
    assert!(locate(&mut r, len, &["logs", "boot001.txt"]).is_ok());
    assert_eq!(locate(&mut r, len - 512, &["logs", "boot001.txt"]), Err("the FAT volume is larger than its partition"));
    let mut f = sample(1, 2500);
    f.img[36..40].copy_from_slice(&1u32.to_le_bytes()); // a FAT of one sector (128 entries) for 1000 clusters
    let len = f.img.len() as u64;
    let mut r = f.reader();
    assert_eq!(locate(&mut r, len, &["logs", "boot001.txt"]), Err("the FAT is too small for the volume"));
}

#[test]
fn fingerprints_differ() {
    assert_eq!(fingerprint(b""), 0xcbf2_9ce4_8422_2325);
    assert_ne!(fingerprint(b"boot001"), fingerprint(b"boot002"));
}

// ---------------------------------------------------------------------------------------
// Start menu (review M1): it always starts something

fn run(m: &mut Menu, keys: &[Option<MenuKey>], max: usize) -> (Option<&'static str>, usize) {
    for i in 0..max {
        let k = keys.get(i).copied().flatten();
        if let Some(w) = m.step(k) {
            return (Some(w), i);
        }
    }
    (None, max)
}

#[test]
fn menu_counts_down_to_entry_1() {
    let mut m = Menu::new(5);
    assert_eq!(run(&mut m, &[], 1000), (Some(""), 50));
    let mut m = Menu::new(0);
    assert_eq!(m.step(None), Some(""));
}

#[test]
fn menu_keys_choose() {
    let mut m = Menu::new(5);
    assert_eq!(run(&mut m, &[None, None, Some(MenuKey::Char('2'))], 1000), (Some(SAFE), 2));
    let mut m = Menu::new(5);
    assert_eq!(m.step(Some(MenuKey::Char('3'))), Some(SAFE_CONSOLE));
    let mut m = Menu::new(5);
    assert_eq!(m.step(Some(MenuKey::Char('\r'))), Some(""));
}

#[test]
fn menu_special_keys_do_not_stop_the_countdown() {
    let keys: Vec<Option<MenuKey>> = (0..100).map(|_| Some(MenuKey::Special)).collect();
    let mut m = Menu::new(5);
    assert_eq!(run(&mut m, &keys, 1000), (Some(""), 50));
}

#[test]
fn menu_other_key_waits_30_s_then_starts_entry_1() {
    let mut m = Menu::new(5);
    let (w, i) = run(&mut m, &[None, Some(MenuKey::Char('x'))], 10_000);
    assert_eq!(w, Some(""));
    assert_eq!(i, 1 + MENU_IDLE_LIMIT as usize - 1);
    assert!(!m.counting);
    // Another key restarts the 30 s
    let mut m = Menu::new(5);
    let mut keys = vec![None; 400];
    keys[1] = Some(MenuKey::Char('x'));
    keys[200] = Some(MenuKey::Char('y'));
    let (_, i) = run(&mut m, &keys, 10_000);
    assert_eq!(i, 200 + MENU_IDLE_LIMIT as usize - 1);
}

