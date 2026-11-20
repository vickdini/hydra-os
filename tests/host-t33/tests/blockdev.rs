//! Disks as the kernel sees them (`src/fs/blockdev.rs`) against fake block drivers, and the
//! partition tables it reads with `src/fs/gpt.rs`: scanning, byte-granular reads and
//! writes split into blocks and window-sized requests, the pool guard, BLKPG edits, re-reads.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Mutex;

use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fakefs;
use hydra_hosttests_t33::fs::blockdev::{self, BLOCK};
use hydra_hosttests_t33::fs::gpt::{self, crc32, guid_string, parse_guid, Kind, ESP_TYPE, HYDRA_POOL_TYPE};
use hydra_hosttests_t33::ipc::protocol::{ENDPOINT_BLOCK_DEV, ENDPOINT_USB_DISK, MSG_BLOCK_FLUSH, MSG_BLOCK_GET_SIZE, MSG_BLOCK_READ, MSG_BLOCK_REPLY, MSG_BLOCK_WRITE};
use hydra_hosttests_t33::ipc::service::WINDOW_SIZE;
use hydra_hosttests_t33::ipc::Message;

/// The disk list is global: one test at a time.
fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

#[derive(Clone)]
struct FakeDisk {
    unit: u64,
    data: Vec<u8>,
    model: &'static str,
    removable: bool,
    pool: Option<(u64, u64)>,
}

/// Requests seen by the drivers: (endpoint, label, args).
type Log = Rc<RefCell<Vec<(u32, u32, [u64; 4])>>>;

/// Installs a block driver on `ep` serving `disks` (by unit); returns the shared disks and
/// the request log.
fn driver(ep: u32, disks: Vec<FakeDisk>) -> (Rc<RefCell<Vec<FakeDisk>>>, Log) {
    let disks = Rc::new(RefCell::new(disks));
    let log: Log = Rc::new(RefCell::new(Vec::new()));
    let (d2, l2) = (disks.clone(), log.clone());
    fakefs::set_handler(
        ep,
        Box::new(move |m: &Message, w: &mut [u8]| {
            l2.borrow_mut().push((ep, m.label, m.args));
            let unit = m.args[3];
            let mut disks = d2.borrow_mut();
            let Some(d) = disks.iter_mut().find(|d| d.unit == unit) else {
                return Ok(Message::with_args(MSG_BLOCK_REPLY, [(-19i64) as u64, 0, 0, 0]));
            };
            match m.label {
                MSG_BLOCK_GET_SIZE => {
                    w[..64].fill(0);
                    w[..d.model.len()].copy_from_slice(d.model.as_bytes());
                    w[40..44].copy_from_slice(&0u32.to_le_bytes());
                    let flags = d.removable as u32 | (d.pool.is_some() as u32) << 1;
                    w[44..48].copy_from_slice(&flags.to_le_bytes());
                    let (pb, pn) = d.pool.unwrap_or((0, 0));
                    w[48..56].copy_from_slice(&pb.to_le_bytes());
                    w[56..64].copy_from_slice(&pn.to_le_bytes());
                    Ok(Message::with_args(MSG_BLOCK_REPLY, [0, d.data.len() as u64 / BLOCK, 0, 0]))
                }
                MSG_BLOCK_READ | MSG_BLOCK_WRITE => {
                    let (at, n) = (m.args[0] as usize * BLOCK as usize, m.args[1] as usize * BLOCK as usize);
                    assert!(n <= WINDOW_SIZE, "one request fits the window");
                    if at + n > d.data.len() {
                        return Ok(Message::with_args(MSG_BLOCK_REPLY, [(-5i64) as u64, 0, 0, 0]));
                    }
                    if m.label == MSG_BLOCK_READ {
                        w[..n].copy_from_slice(&d.data[at..at + n]);
                    } else {
                        d.data[at..at + n].copy_from_slice(&w[..n]);
                    }
                    Ok(Message::with_args(MSG_BLOCK_REPLY, [0, m.args[1], 0, 0]))
                }
                MSG_BLOCK_FLUSH => Ok(Message::with_args(MSG_BLOCK_REPLY, [0; 4])),
                _ => Ok(Message::with_args(0x1, [0; 4])),
            }
        }),
    );
    (disks, log)
}

fn put_mbr(d: &mut [u8], slot: usize, ty: u8, start_lba: u32, sectors: u32) {
    let e = &mut d[446 + slot * 16..446 + slot * 16 + 16];
    e[4] = ty;
    e[8..12].copy_from_slice(&start_lba.to_le_bytes());
    e[12..16].copy_from_slice(&sectors.to_le_bytes());
    d[510] = 0x55;
    d[511] = 0xAA;
    d[440..444].copy_from_slice(&0xDEADBEEFu32.to_le_bytes());
}

/// A GPT (512-byte sectors) with an ESP and a pool partition.
fn put_gpt(d: &mut [u8]) {
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
    put(0, ESP_TYPE, 0x11, 2048, 4095, "EFI");
    put(1, HYDRA_POOL_TYPE, 0x22, 4096, 8191, "Hydra");
    put(2, HYDRA_POOL_TYPE, 0x33, 9000, 8999, "backwards"); // skipped: last < first
    d[1024..1024 + ent.len()].copy_from_slice(&ent);
    let ecrc = crc32(&ent);
    let h = &mut d[512..512 + 92];
    h[0..8].copy_from_slice(b"EFI PART");
    h[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    h[12..16].copy_from_slice(&92u32.to_le_bytes());
    h[56..72].copy_from_slice(&[0xAB; 16]);
    h[72..80].copy_from_slice(&2u64.to_le_bytes());
    h[80..84].copy_from_slice(&128u32.to_le_bytes());
    h[84..88].copy_from_slice(&128u32.to_le_bytes());
    h[88..92].copy_from_slice(&ecrc.to_le_bytes());
    let hc = crc32(&d[512..604]);
    d[528..532].copy_from_slice(&hc.to_le_bytes());
}

fn disk(unit: u64, mib: usize, model: &'static str) -> FakeDisk {
    FakeDisk { unit, data: vec![0u8; mib << 20], model, removable: false, pool: None }
}

#[test]
fn scan_finds_every_drivers_disks_and_their_tables() {
    let _g = serial();
    let mut a = disk(1, 8, "QEMU HARDDISK");
    put_gpt(&mut a.data);
    a.pool = Some((512, 512)); // the pool at 2..4 MiB
    let mut b = disk(2, 4, "SECOND");
    put_mbr(&mut b.data, 0, 0x83, 2048, 2048);
    put_mbr(&mut b.data, 1, 0x0C, 4096, 1024);
    let (_ata, _) = driver(ENDPOINT_BLOCK_DEV, vec![a, b]);
    // A USB stick as unit 3 (units 1 and 2 missing: gaps are looked past)
    let mut u = disk(3, 2, "USB STICK");
    u.removable = true;
    let (_usb, _) = driver(ENDPOINT_USB_DISK, vec![u]);
    blockdev::scan();
    let all = blockdev::disks();
    assert_eq!(all.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(), vec!["sda", "sdb", "sdc"]);
    let sda = &all[0];
    assert_eq!((sda.model.as_str(), sda.bytes, sda.sector_size, sda.removable), ("QEMU HARDDISK", 8 << 20, 512, false));
    assert_eq!(sda.pool, Some((2 << 20, 4 << 20)));
    assert_eq!(sda.table.map(|t| t.0), Some(Kind::Gpt));
    assert_eq!(sda.parts.len(), 2);
    assert_eq!(sda.part(1).unwrap().entry.as_ref().unwrap().name, "EFI");
    assert_eq!((sda.part(2).unwrap().start, sda.part(2).unwrap().len), (4096 * 512, 4096 * 512));
    assert!(sda.part(3).is_none());
    let sdb = &all[1];
    assert_eq!(sdb.table.map(|t| t.0), Some(Kind::Mbr));
    assert_eq!(sdb.table.unwrap().1[..4], 0xDEADBEEFu32.to_le_bytes());
    assert_eq!(sdb.parts.iter().map(|p| p.entry.as_ref().unwrap().mbr_type).collect::<Vec<_>>(), vec![0x83, 0x0C]);
    let sdc = &all[2];
    assert_eq!((sdc.endpoint, sdc.unit, sdc.removable, sdc.table.is_none()), (ENDPOINT_USB_DISK, 3, true, true));
    assert!(blockdev::disk(3).is_none());
    assert!(fake::klog_take().contains("[disks] sda: 'QEMU HARDDISK' 8 MiB on endpoint 0x21 unit 1, 2 partitions, the pool at 2..4 MiB"));
    // The table helpers
    let t = gpt::read_table(&mut |off, buf| blockdev::read_at(0, off, buf).map_or(false, |n| n == buf.len()), 8 << 20).unwrap();
    assert_eq!(t.by_type(&HYDRA_POOL_TYPE).unwrap().number, 2);
    assert_eq!(t.by_guid(&[0x11; 16]).unwrap().number, 1);
    assert!(t.by_guid(&[0x99; 16]).is_none());
}

#[test]
fn disk_names_go_past_z() {
    let _g = serial();
    // 28 small disks on one driver: sda..sdz, sdaa, sdab
    let disks: Vec<FakeDisk> = (1..=28).map(|u| disk(u, 0, "D")).map(|mut d| {
        d.data = vec![0u8; 16384];
        d
    }).collect();
    driver(ENDPOINT_BLOCK_DEV, disks);
    fakefs::set_offline(ENDPOINT_USB_DISK, true);
    blockdev::scan();
    let names: Vec<String> = blockdev::disks().into_iter().map(|d| d.name).collect();
    assert_eq!(names.len(), 28);
    assert_eq!((names[25].as_str(), names[26].as_str(), names[27].as_str()), ("sdz", "sdaa", "sdab"));
}

#[test]
fn unaligned_reads_and_writes_are_split_into_blocks() {
    let _g = serial();
    let mut a = disk(1, 4, "RW");
    for (i, b) in a.data.iter_mut().enumerate() {
        *b = (i % 253) as u8;
    }
    let (disks, log) = driver(ENDPOINT_BLOCK_DEV, vec![a]);
    fakefs::set_offline(ENDPOINT_USB_DISK, true);
    blockdev::scan();
    let size = 4u64 << 20;
    // An unaligned read across blocks and windows
    let mut buf = vec![0u8; 600_000];
    assert_eq!(blockdev::read_at(0, 1000, &mut buf), Ok(600_000));
    assert!(buf.iter().enumerate().all(|(i, &b)| b == ((i + 1000) % 253) as u8));
    // At the end: fewer bytes; past it: none
    let mut tail = vec![0u8; 100];
    assert_eq!(blockdev::read_at(0, size - 10, &mut tail), Ok(10));
    assert_eq!(blockdev::read_at(0, size, &mut tail), Ok(0));
    assert_eq!(blockdev::read_at(7, 0, &mut tail), Err(-19));
    // Writes: partial blocks are read, changed and written back
    log.borrow_mut().clear();
    let data = vec![0xEEu8; 9000];
    assert_eq!(blockdev::write_at(0, 4090, &data), Ok(9000));
    let d = disks.borrow()[0].data.clone();
    assert!(d[4090..13090].iter().all(|&b| b == 0xEE));
    assert_eq!(d[4089], (4089 % 253) as u8);
    assert_eq!(d[13090], (13090 % 253) as u8);
    let reads = log.borrow().iter().filter(|r| r.1 == MSG_BLOCK_READ).count();
    assert_eq!(reads, 2, "the first and the last block were partial");
    // A big aligned write goes a window at a time
    log.borrow_mut().clear();
    let big = vec![0x11u8; 600 * 1024];
    assert_eq!(blockdev::write_at(0, 0, &big), Ok(big.len()));
    let writes: Vec<u64> = log.borrow().iter().filter(|r| r.1 == MSG_BLOCK_WRITE).map(|r| r.2[1]).collect();
    assert_eq!(writes, vec![64, 64, 22]);
    // Past the end
    assert_eq!(blockdev::write_at(0, size, b"x"), Err(-28));
    assert_eq!(blockdev::write_at(0, size, b""), Ok(0));
    assert_eq!(blockdev::write_at(0, size - 2, b"abcd"), Ok(2));
    // zero_range
    blockdev::zero_range(0, 100, 5000).unwrap();
    assert!(disks.borrow()[0].data[100..5100].iter().all(|&b| b == 0));
    assert_eq!(disks.borrow()[0].data[5100], 0x11);
    // flush
    log.borrow_mut().clear();
    blockdev::flush(0).unwrap();
    assert_eq!(log.borrow()[0].1, MSG_BLOCK_FLUSH);
    assert_eq!(blockdev::flush(5), Err(-19));
}

#[test]
fn the_pool_is_never_written_and_its_disk_is_busy() {
    let _g = serial();
    let mut a = disk(1, 4, "POOL");
    a.pool = Some((256, 256)); // 1..2 MiB
    put_mbr(&mut a.data, 0, 0x83, 2048, 2048); // 1..2 MiB: the pool's partition
    let b = disk(2, 4, "OTHER");
    let (_d, log) = driver(ENDPOINT_BLOCK_DEV, vec![a, b]);
    fakefs::set_offline(ENDPOINT_USB_DISK, true);
    blockdev::scan();
    let d = blockdev::disk(0).unwrap();
    assert!(d.touches_pool(1 << 20, (1 << 20) + 1));
    assert!(!d.touches_pool(0, 1 << 20));
    assert_eq!(blockdev::write_at(0, (1 << 20) - 1, b"xx"), Err(-16));
    assert_eq!(blockdev::write_at(0, 0, b"ok"), Ok(2));
    assert_eq!(blockdev::reread(0), Err(-16));
    assert_eq!(blockdev::reread(9), Err(-19));
    assert_eq!(blockdev::blkpg(0, 2, 1, 0, 0), Err(-16), "the pool's partition stays");
    // flush_all skips the pool's disk
    log.borrow_mut().clear();
    blockdev::flush_all();
    let flushed: Vec<u64> = log.borrow().iter().filter(|r| r.1 == MSG_BLOCK_FLUSH).map(|r| r.2[3]).collect();
    assert_eq!(flushed, vec![2]);
}

#[test]
fn blkpg_edits_and_reread_restores_the_table() {
    let _g = serial();
    let mut a = disk(1, 4, "EDIT");
    put_mbr(&mut a.data, 0, 0x83, 2048, 1024);
    let (disks, _) = driver(ENDPOINT_BLOCK_DEV, vec![a]);
    fakefs::set_offline(ENDPOINT_USB_DISK, true);
    blockdev::scan();
    let gen = blockdev::disk(0).unwrap().generation;
    let mib = 1u64 << 20;
    assert_eq!(blockdev::blkpg(0, 1, 0, mib, mib), Err(-22), "number 0");
    assert_eq!(blockdev::blkpg(0, 1, 16, mib, mib), Err(-22), "number 16");
    assert_eq!(blockdev::blkpg(0, 1, 1, 2 * mib, mib), Err(-16), "1 exists");
    assert_eq!(blockdev::blkpg(0, 1, 2, mib + 4096, mib), Err(-22), "overlaps 1");
    assert_eq!(blockdev::blkpg(0, 1, 2, 2 * mib + 1, mib), Err(-22), "not sector aligned");
    assert_eq!(blockdev::blkpg(0, 1, 2, 3 * mib, 2 * mib), Err(-22), "past the end");
    assert_eq!(blockdev::blkpg(0, 1, 2, 2 * mib, 0), Err(-22), "empty");
    assert_eq!(blockdev::blkpg(0, 1, 3, 3 * mib, mib), Ok(()));
    assert_eq!(blockdev::blkpg(0, 1, 2, 2 * mib, mib), Ok(()));
    let d = blockdev::disk(0).unwrap();
    assert_eq!(d.parts.iter().map(|p| p.number).collect::<Vec<_>>(), vec![1, 2, 3], "kept in number order");
    assert!(d.part(2).unwrap().entry.is_none(), "not in the table");
    assert_eq!(d.generation, gen + 2);
    // resize
    assert_eq!(blockdev::blkpg(0, 3, 2, 2 * mib, mib / 2), Ok(()));
    assert_eq!(blockdev::disk(0).unwrap().part(2).unwrap().len, mib / 2);
    assert_eq!(blockdev::blkpg(0, 3, 2, 2 * mib + 512, mib), Err(-22), "the start may not move");
    assert_eq!(blockdev::blkpg(0, 3, 2, 2 * mib, 8 * mib), Err(-22));
    assert_eq!(blockdev::blkpg(0, 3, 9, 0, mib), Err(-6));
    // delete
    assert_eq!(blockdev::blkpg(0, 2, 3, 0, 0), Ok(()));
    assert_eq!(blockdev::blkpg(0, 2, 3, 0, 0), Err(-6));
    assert_eq!(blockdev::blkpg(0, 7, 1, 0, 0), Err(-22), "unknown operation");
    assert_eq!(blockdev::blkpg(4, 1, 1, 0, 0), Err(-19));
    // A new table on the disk, read again
    put_mbr(&mut disks.borrow_mut()[0].data, 1, 0x07, 4096, 2048);
    let g2 = blockdev::disk(0).unwrap().generation;
    blockdev::reread(0).unwrap();
    let d = blockdev::disk(0).unwrap();
    assert_eq!(d.parts.iter().map(|p| p.number).collect::<Vec<_>>(), vec![1, 2]);
    assert_eq!(d.generation, g2 + 1);
}

#[test]
fn driver_failures() {
    let _g = serial();
    let mut a = disk(1, 1, "FLAKY");
    a.data.truncate(8192 + 4096);
    driver(ENDPOINT_BLOCK_DEV, vec![a]);
    fakefs::set_offline(ENDPOINT_USB_DISK, true);
    blockdev::scan();
    assert_eq!(blockdev::disks().len(), 1);
    // The driver goes away
    fakefs::set_offline(ENDPOINT_BLOCK_DEV, true);
    let mut b = [0u8; 16];
    assert_eq!(blockdev::read_at(0, 0, &mut b), Err(-19));
    fakefs::set_offline(ENDPOINT_BLOCK_DEV, false);
    // A reply with another label; a reply with an error status
    fakefs::set_handler(ENDPOINT_BLOCK_DEV, Box::new(|_: &Message, _: &mut [u8]| Ok(Message::with_args(0x77, [0; 4]))));
    assert_eq!(blockdev::read_at(0, 0, &mut b), Err(-5));
    fakefs::set_handler(ENDPOINT_BLOCK_DEV, Box::new(|_: &Message, _: &mut [u8]| Ok(Message::with_args(MSG_BLOCK_REPLY, [(-30i64) as u64, 0, 0, 0]))));
    assert_eq!(blockdev::write_at(0, 0, &[1u8; 4096]), Err(-30));
    assert_eq!(blockdev::flush(0), Err(-30));
    // The window disappears
    fakefs::drop_window(ENDPOINT_BLOCK_DEV);
    assert_eq!(blockdev::read_at(0, 0, &mut b), Err(-19));
}

#[test]
fn guid_text_and_odd_tables() {
    assert_eq!(guid_string(&ESP_TYPE), "c12a7328-f81f-11d2-ba4b-00a0c93ec93b");
    assert_eq!(parse_guid(&guid_string(&HYDRA_POOL_TYPE)), Some(HYDRA_POOL_TYPE));
    assert_eq!(parse_guid("7685a0b8-df41-47eb-af4f-02ce6fb0187"), None);
    assert_eq!(parse_guid("zz85a0b8-df41-47eb-af4f-02ce6fb01879"), None);
    let mut rd = |img: &Vec<u8>| {
        let img = img.clone();
        let len = img.len() as u64;
        gpt::read_table(&mut |off, buf: &mut [u8]| {
            let o = off as usize;
            if o + buf.len() > img.len() {
                return false;
            }
            buf.copy_from_slice(&img[o..o + buf.len()]);
            true
        }, len)
    };
    // Too small, no signature, a FAT boot sector, a bad boot flag, a lone protective entry
    assert!(rd(&vec![0u8; 4096]).is_none());
    assert!(rd(&vec![0u8; 1 << 20]).is_none());
    let mut fat = vec![0u8; 1 << 20];
    put_mbr(&mut fat, 0, 0x0C, 1, 100);
    fat[82..87].copy_from_slice(b"FAT32");
    assert!(rd(&fat).is_none());
    let mut flag = vec![0u8; 1 << 20];
    put_mbr(&mut flag, 0, 0x83, 1, 100);
    flag[446] = 0x12;
    assert!(rd(&flag).is_none());
    let mut prot = vec![0u8; 1 << 20];
    put_mbr(&mut prot, 0, 0xEE, 1, 100);
    assert!(rd(&prot).is_none());
    // A GPT whose header checksum is wrong falls back to the MBR
    let mut g = vec![0u8; 8 << 20];
    put_gpt(&mut g);
    put_mbr(&mut g, 0, 0x83, 2048, 100);
    g[530] ^= 0xFF;
    assert_eq!(rd(&g).unwrap().kind, Kind::Mbr);
}
