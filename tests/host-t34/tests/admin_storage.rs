//! `src/admin/storage.rs`: the pool's operations and the USB disk tool.

mod common;
use common::*;
use k::admin::proto::*;
use k::admin::storage;
use k::admin::Failure;
use k::ipc::protocol::*;
use std::cell::RefCell;
use std::rc::Rc;

fn fail(f: Failure) -> (i64, String) {
    match f {
        Failure::Errno(e) => (e, String::new()),
        Failure::Message(e, m) => (e, m.to_string()),
        Failure::Text(e, m) => (e, m),
    }
}

trait Must<T> {
    fn must(self) -> T;
}
impl<T> Must<T> for Result<T, Failure> {
    fn must(self) -> T {
        match self {
            Ok(v) => v,
            Err(f) => panic!("failed: {:?}", fail(f)),
        }
    }
}

#[test]
fn pool_status_and_disk_info() {
    let _g = setup();
    let p = storage::pool_status();
    assert_eq!((p.on_disk, p.metrics_valid, p.total_mib), (0, 0, 0));
    fake::with(|s| {
        s.pool = Some((1024, 2048, 4096, 77));
        s.disk = Some((2_000_000, true, false, "QEMU HARDDISK".into()));
    });
    let p = storage::pool_status();
    assert_eq!((p.on_disk, p.metrics_valid, p.total_mib, p.alloc_kib, p.free_kib, p.txg), (1, 1, 1024, 2048, 4096, 77));
    let d = storage::disk_info();
    assert_eq!((d.present, d.sectors, d.lba48, d.dma), (1, 2_000_000, 1, 0));
    assert_eq!(name_str(&d.model), "QEMU HARDDISK");
    fake::with(|s| s.disk = None);
    assert_eq!(storage::disk_info().present, 0);
}

#[test]
fn directory_listings_have_a_record_per_slot() {
    let _g = setup();
    fake::file("/etc/hosts", b"127.0.0.1 localhost\n");
    fake::file("/etc/link.lnk", b"x");
    fake::file("/etc/~stale", b"");
    fake::dir("/etc/apt");
    let mut out = Vec::new();
    storage::dir_list("/etc", &mut out).must();
    let h: DirHeader = read_record(&out, 0).unwrap();
    assert_eq!(h.count, 4);
    assert_eq!(name_str(&h.dataset), "hydrapool/root");
    let n = core::mem::size_of::<DirRecord>();
    assert_eq!(out.len(), core::mem::size_of::<DirHeader>() + 4 * n);
    let mut kinds: Vec<(String, u8)> = (0..4)
        .map(|i| {
            let r: DirRecord = read_record(&out, core::mem::size_of::<DirHeader>() + i * n).unwrap();
            (name_str(&r.name).to_string(), r.kind)
        })
        .collect();
    kinds.sort();
    assert_eq!(
        kinds,
        vec![("apt".into(), KIND_DIR), ("hosts".into(), KIND_FILE), ("link.lnk".into(), KIND_OTHER), ("~stale".into(), KIND_INVALID)]
    );
    assert_eq!(fail(storage::dir_list("/nope", &mut out).unwrap_err()), (ENOENT, "not a directory".into()));
}

#[test]
fn lookup_and_stat() {
    let _g = setup();
    fake::file("/bin/ls", &[0u8; 1234]);
    let l = storage::lookup("/bin/ls").must();
    assert_eq!((l.kind, l.size), (KIND_FILE as u64, 1234));
    assert_eq!(storage::lookup("/bin").must().kind, KIND_DIR as u64);
    assert_eq!(fail(storage::lookup("/x").unwrap_err()), (ENOENT, "No such file or directory".into()));
    let s = storage::stat("/bin/ls").must();
    assert_eq!((s.kind, s.size, s.birth_txg, s.checksum), (KIND_FILE as u64, 1234, 9, [1, 2, 3, 4]));
    assert_ne!(s.obj, 0);
    assert_eq!(fail(storage::stat("/x").unwrap_err()).0, ENOENT);
}

#[test]
fn changes_in_the_pool() {
    let _g = setup();
    fake::file("/a.txt", b"one");
    assert_eq!(storage::fs_op(FS_COPY, b"/a.txt\0/b.txt").must(), 12);
    assert_eq!(fake::with(|s| s.files.get("/b.txt").cloned()), Some(b"one".to_vec()));
    assert_eq!(storage::fs_op(FS_RENAME, b"/b.txt\0/c.txt").must(), 0);
    assert!(fake::logged("rename /b.txt /c.txt"));
    assert_eq!(storage::fs_op(FS_TOUCH, b"/t").must(), 13);
    assert_eq!(storage::fs_op(FS_WRITE, b"/w.txt\0data\0with nul").must(), 77);
    assert_eq!(fake::with(|s| s.files.get("/w.txt").cloned()), Some(b"data\0with nul".to_vec()));
    // Append to an existing file, and to a new one
    storage::fs_op(FS_APPEND, b"/a.txt\0 two").must();
    assert_eq!(fake::with(|s| s.files.get("/a.txt").cloned()), Some(b"one two".to_vec()));
    storage::fs_op(FS_APPEND, b"/new.txt\0first").must();
    assert_eq!(fake::with(|s| s.files.get("/new.txt").cloned()), Some(b"first".to_vec()));
    assert_ne!(storage::fs_op(FS_MKDIR, b"/d").must(), 0);
    assert_ne!(storage::fs_op(FS_MKDIR_ALL, b"/d/e/f").must(), 0);
    assert_eq!(storage::fs_op(FS_RMDIR, b"/d/e/f").must(), 0);
    assert_eq!(storage::fs_op(FS_UNLINK, b"/a.txt").must(), 0);
    assert_eq!(storage::fs_op(FS_SYNC, b"").must(), 0);
    assert_eq!(storage::fs_op(FS_SNAPSHOT, b"").must(), 14);
    // Bad input
    assert_eq!(fail(storage::fs_op(FS_MKDIR, b"\xff").unwrap_err()).0, EINVAL);
    assert_eq!(fail(storage::fs_op(FS_COPY, b"/w.txt\0\xff").unwrap_err()).0, EINVAL);
    assert_eq!(fail(storage::fs_op(FS_RENAME, b"/w.txt\0\xfe").unwrap_err()).0, EINVAL);
    assert_eq!(fail(storage::fs_op(42, b"/x").unwrap_err()).0, EINVAL);
    // The file server's failures carry its message
    assert_eq!(fail(storage::fs_op(FS_UNLINK, b"/missing").unwrap_err()), (EIO, "not found".into()));
    fake::with(|s| s.fs_fail = Some("pool is read-only"));
    for code in [FS_MKDIR, FS_MKDIR_ALL, FS_RMDIR, FS_COPY, FS_RENAME, FS_TOUCH, FS_WRITE, FS_APPEND, FS_SYNC, FS_SNAPSHOT] {
        assert_eq!(fail(storage::fs_op(code, b"/w.txt\0/z").unwrap_err()), (EIO, "pool is read-only".into()), "code {}", code);
    }
}

#[test]
fn datasets_and_checks() {
    let _g = setup();
    let mut out = Vec::new();
    assert_eq!(fail(storage::datasets(&mut out).unwrap_err()), (EIO, "the file server did not answer".into()));
    // The pool answers but the dataset list does not
    fake::with(|s| s.pool = Some((100, 200, 300, 9)));
    assert_eq!(fail(storage::datasets(&mut out).unwrap_err()).0, EIO);
    assert!(out.is_empty());
}

#[test]
fn dataset_records() {
    let _g = setup();
    fake::with(|s| {
        s.pool = Some((100, 200, 300, 9));
        s.datasets = Some(vec![("hydrapool/root".into(), "/".into(), 4, false), ("hydrapool/root@boot".into(), "".into(), 8, true)]);
    });
    let mut out = Vec::new();
    storage::datasets(&mut out).must();
    let h: DatasetHeader = read_record(&out, 0).unwrap();
    assert_eq!((h.count, h.allocated, h.free), (2, 200, 300));
    let r: DatasetRecord = read_record(&out, 24 + core::mem::size_of::<DatasetRecord>()).unwrap();
    assert_eq!((r.txg, r.snapshot), (8, 1));
    assert_eq!((name_str(&r.name), name_str(&r.mount)), ("hydrapool/root@boot", ""));
}

#[test]
fn file_server_checks() {
    use k::fs::zfs::fsproto::*;
    let _g = setup();
    storage::zfs_diag(ZFSDIAG_SELFTEST, false, "ignored").must();
    storage::zfs_diag(ZFSDIAG_VERIFY, true, "").must();
    storage::zfs_diag(ZFSDIAG_FSCK, false, "").must();
    storage::zfs_diag(ZFSDIAG_FSCK, true, "/home").must();
    assert_eq!(
        fake::take_log(),
        vec![
            format!("diag {:#x}  false", FS_SELFTEST),
            format!("diag {:#x}  true", FS_VERIFY),
            format!("diag {:#x} / false", FS_FSCK),
            format!("diag {:#x} /home true", FS_FSCK),
        ]
    );
    assert_eq!(fail(storage::zfs_diag(9, false, "").unwrap_err()).0, EINVAL);
}

// ------------------------------------------------------------------------- USB disks

/// A fake block driver on `ep` with a disk of `blocks` 4 KiB blocks; returns the disk.
fn block_driver(ep: u32, blocks: usize) -> Rc<RefCell<Vec<u8>>> {
    let disk = Rc::new(RefCell::new((0..blocks * 4096).map(|i| (i % 251) as u8).collect::<Vec<u8>>()));
    let d = disk.clone();
    fake::with(|s| {
        s.servers.insert(ep, 50);
        s.online.insert(ep);
        s.handler = Some(Box::new(move |e, m, _| {
            assert_eq!(e, ep);
            let w = k::ipc::service::window(e).unwrap();
            let mut disk = d.borrow_mut();
            let (b, n) = (m.args[0] as usize, m.args[1] as usize);
            let reply = |a0: u64, a1: u64| Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [a0, a1, 0, 0]));
            match m.label {
                MSG_BLOCK_GET_SIZE => reply(0, (disk.len() / 4096) as u64),
                MSG_BLOCK_READ => {
                    w[..n * 4096].copy_from_slice(&disk[b * 4096..(b + n) * 4096]);
                    reply(0, n as u64)
                }
                MSG_BLOCK_WRITE => {
                    disk[b * 4096..(b + n) * 4096].copy_from_slice(&w[..n * 4096]);
                    reply(0, n as u64)
                }
                MSG_BLOCK_FLUSH => reply(0, 0),
                _ => reply(-38i64 as u64, 0),
            }
        }));
    });
    disk
}

#[test]
fn usb_disk_list() {
    let _g = setup();
    storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
    assert!(fake::take_out().contains("the USB driver is not running"));
    fake::with(|s| {
        s.online.insert(ENDPOINT_USB_DISK);
        s.servers.insert(ENDPOINT_USB_DISK, 9);
    });
    // No answer
    storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
    assert!(fake::take_out().contains("usbdisk: no answer from the USB driver (Err(-11))"));
    // An error status
    fake::with(|s| s.handler = Some(Box::new(|_, _, _| Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [-5i64 as u64, 0, 0, 0])))));
    storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
    assert!(fake::take_out().contains("(Ok(-5))"));
    // No disks
    fake::with(|s| s.handler = Some(Box::new(|_, _, _| Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [0, 0, 0, 0])))));
    storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
    assert_eq!(fake::take_out(), "No USB disks.\n");
    // Two disks
    let mut recs = vec![0u8; 2 * BLOCK_LIST_RECORD];
    {
        let r = &mut recs[..BLOCK_LIST_RECORD];
        r[0..4].copy_from_slice(&0u32.to_le_bytes());
        r[8..16].copy_from_slice(&(8192u64).to_le_bytes()); // 32 MiB
        r[16..20].copy_from_slice(&512u32.to_le_bytes());
        r[20] = 2; // port
        r[21] = 2; // depth
        r[22] = 3; // high speed
        r[23] = 1 | 4; // removable, medium present
        r[24..28].copy_from_slice(&0x31u32.to_le_bytes()); // route 1.3
        r[28..30].copy_from_slice(&0x0781u16.to_le_bytes());
        r[30..32].copy_from_slice(&0x5567u16.to_le_bytes());
        r[32..40].copy_from_slice(b"SanDisk ");
        r[72..76].copy_from_slice(b"1234");
    }
    {
        let r = &mut recs[BLOCK_LIST_RECORD..];
        r[0] = 1;
        r[8..16].copy_from_slice(&(256u64).to_le_bytes());
        r[16..20].copy_from_slice(&4096u32.to_le_bytes());
        r[20] = 1;
        r[22] = 7;
        r[23] = 2; // write-protected, no medium
        r[32] = 0xff; // a model that is not text
    }
    fake::with(|s| {
        s.handler = Some(Box::new(move |_, m, _| {
            assert_eq!(m.label, MSG_BLOCK_LIST);
            k::ipc::service::window(ENDPOINT_USB_DISK).unwrap()[..recs.len()].copy_from_slice(&recs);
            Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [0, 2, 0, 0]))
        }))
    });
    storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
    let out = fake::take_out();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "usb disk 0: 32 MiB, 512-byte sectors, port 2.1.3, high speed 3, 0781:5567 'SanDisk' serial '1234', removable");
    assert_eq!(lines[1], "usb disk 1: 1 MiB, 4096-byte sectors, port 1, super+ speed 7, 0000:0000 '?' serial '', write-protected, no medium");
    // The window was held for the call
    assert!(fake::logged(&format!("hold_window {}", ENDPOINT_USB_DISK)));
}

#[test]
fn usb_speed_names() {
    let _g = setup();
    fake::with(|s| {
        s.online.insert(ENDPOINT_USB_DISK);
        s.servers.insert(ENDPOINT_USB_DISK, 9);
    });
    for (speed, name) in [(1u8, "full"), (2, "low"), (4, "super")] {
        fake::with(|s| {
            s.handler = Some(Box::new(move |_, _, _| {
                let w = k::ipc::service::window(ENDPOINT_USB_DISK).unwrap();
                w[..BLOCK_LIST_RECORD].fill(0);
                w[22] = speed;
                w[23] = 4;
                Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [0, 1, 0, 0]))
            }))
        });
        storage::usbdisk(&[USBDISK_LIST, 0, 0, 0]).must();
        assert!(fake::take_out().contains(&format!("port 0, {} speed {}", name, speed)));
    }
}

#[test]
fn usb_write_test_restores_the_data() {
    let _g = setup();
    let disk = block_driver(ENDPOINT_USB_DISK, 300);
    let before = disk.borrow().clone();
    storage::usbdisk(&[USBDISK_TEST, 0, 10, 0]).must();
    let out = fake::take_out();
    assert!(out.contains("usbdisk test disk 0: 10 blocks x 3 places x 2 patterns written, read back and restored in 0.0 s: OK, all data matched"), "{}", out);
    assert!(*disk.borrow() == before, "the original data came back");
    // Writes went to the three places: start, middle, end
    let writes: Vec<u64> = fake::with(|s| s.calls.iter().filter(|c| c.1 == MSG_BLOCK_WRITE).map(|c| c.2[0]).collect());
    assert!(writes.contains(&0) && writes.contains(&150) && writes.contains(&290));
    // More blocks than a third of the disk: a third
    storage::usbdisk(&[USBDISK_TEST, 0, 1000, 0]).must();
    assert!(fake::take_out().contains("100 blocks x 3 places"));
}

#[test]
fn usb_write_test_reports_bad_disks() {
    let _g = setup();
    // A disk that loses writes: every byte of the pattern differs from what is read back
    block_driver(ENDPOINT_USB_DISK, 30);
    let inner = fake::with(|s| s.handler.take()).unwrap();
    let inner = RefCell::new(inner);
    fake::with(|s| {
        s.handler = Some(Box::new(move |e, m, k| {
            if m.label == MSG_BLOCK_WRITE {
                return Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [0, m.args[1], 0, 0]));
            }
            (inner.borrow_mut())(e, m, k)
        }))
    });
    storage::usbdisk(&[USBDISK_TEST, 0, 2, 0]).must();
    let out = fake::take_out();
    assert!(out.contains(": FAILED, "), "{}", out);
    assert!(!out.contains("did not come back"));
}

#[test]
fn usb_write_test_errors() {
    let _g = setup();
    // The running pool on USB: no writes
    k::fs::zfs::POOL_ON_USB.store(true, core::sync::atomic::Ordering::Release);
    storage::usbdisk(&[USBDISK_TEST, 0, 1, 0]).must();
    assert!(fake::take_out().contains("the running pool is on a USB disk"));
    storage::usbdisk(&[USBDISK_SPEED, 0, 1, 1]).must();
    assert!(fake::take_out().contains("not writing to the disk of the running pool"));
    k::fs::zfs::POOL_ON_USB.store(false, core::sync::atomic::Ordering::Release);
    // No window (no driver): -ENODEV
    storage::usbdisk(&[USBDISK_TEST, 3, 1, 0]).must();
    assert_eq!(fake::take_out(), "usbdisk: disk 3: error -19\n");
    // Errors at each step
    for (label, nth, what) in [(MSG_BLOCK_READ, 1, "read of 1 blocks at 0 failed: error -5"), (MSG_BLOCK_WRITE, 1, "write of 1 blocks at 0 failed: error -5"), (MSG_BLOCK_READ, 2, "read back of 1 blocks at 0 failed: error -5"), (MSG_BLOCK_WRITE, 3, "restoring 1 blocks at 0 failed: error -5")] {
        block_driver(ENDPOINT_USB_DISK, 30);
        let inner = RefCell::new(fake::with(|s| s.handler.take()).unwrap());
        let seen = RefCell::new(0);
        fake::with(|s| {
            s.handler = Some(Box::new(move |e, m, k| {
                if m.label == label {
                    *seen.borrow_mut() += 1;
                    if *seen.borrow() == nth {
                        return Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [-5i64 as u64, 0, 0, 0]));
                    }
                }
                (inner.borrow_mut())(e, m, k)
            }))
        });
        storage::usbdisk(&[USBDISK_TEST, 0, 1, 0]).must();
        let out = fake::take_out();
        assert!(out.contains(what), "{} / {}", what, out);
    }
}

#[test]
fn usb_write_test_on_a_tiny_disk() {
    let _g = setup();
    // Fewer than 3 blocks: no room for the three places
    block_driver(ENDPOINT_USB_DISK, 2);
    storage::usbdisk(&[USBDISK_TEST, 0, 1, 0]).must();
    assert_eq!(fake::take_out(), "usbdisk: disk 0: too small for the test (2 blocks)\n");
    assert!(fake::with(|s| s.calls.iter().all(|c| c.1 == MSG_BLOCK_GET_SIZE)));
}

#[test]
fn usb_speed_test() {
    let _g = setup();
    // The pool's own disk (ATA), read only: 1 MiB = 256 blocks in 4 requests of 64
    let disk = block_driver(ENDPOINT_BLOCK_DEV, 1000);
    let before = disk.borrow().clone();
    storage::usbdisk(&[USBDISK_SPEED, u64::MAX, 1, 0]).must();
    let out = fake::take_out();
    assert!(out.starts_with("usbdisk speed: read 1 MiB in 0.01 s: 100 MiB/s"), "{}", out);
    assert_eq!(fake::with(|s| s.calls.iter().filter(|c| c.1 == MSG_BLOCK_READ).count()), 4);
    // A USB disk with the write test (read and written back: unchanged), capped at its size
    let disk = block_driver(ENDPOINT_USB_DISK, 100);
    let usb_before = disk.borrow().clone();
    fake::with(|s| s.calls.clear());
    storage::usbdisk(&[USBDISK_SPEED, 0, 4, 1]).must();
    let out = fake::take_out();
    assert!(out.contains("usbdisk speed: read 0 MiB"), "{}", out);
    assert!(out.contains("read and wrote back 0 MiB"), "{}", out);
    assert_eq!(fake::with(|s| s.calls.iter().filter(|c| c.1 == MSG_BLOCK_WRITE).count()), 2);
    assert!(*disk.borrow() == usb_before);
    drop(before);
    // Errors
    let _ = block_driver(ENDPOINT_USB_DISK, 100);
    fake::with(|s| s.servers.remove(&ENDPOINT_USB_DISK));
    storage::usbdisk(&[USBDISK_SPEED, 0, 1, 0]).must();
    assert_eq!(fake::take_out(), "usbdisk: error -19\n");
}

#[test]
fn usb_speed_test_errors() {
    let _g = setup();
    for (label, nth, write, what) in [
        (MSG_BLOCK_READ, 1, false, "read failed at block 0: error -5"),
        (MSG_BLOCK_READ, 2, true, "read failed at block 0: error -5"),
        (MSG_BLOCK_WRITE, 1, true, "write failed at block 0: error -5"),
    ] {
        block_driver(ENDPOINT_USB_DISK, 64);
        let inner = RefCell::new(fake::with(|s| s.handler.take()).unwrap());
        let seen = RefCell::new(0);
        fake::with(|s| {
            s.handler = Some(Box::new(move |e, m, k| {
                if m.label == label {
                    *seen.borrow_mut() += 1;
                    if *seen.borrow() == nth {
                        return Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [-5i64 as u64, 0, 0, 0]));
                    }
                }
                (inner.borrow_mut())(e, m, k)
            }))
        });
        storage::usbdisk(&[USBDISK_SPEED, 0, 1, write as u64]).must();
        let out = fake::take_out();
        assert!(out.contains(what), "{} / {}", what, out);
    }
    // A reply that is not a block reply counts as a failure
    block_driver(ENDPOINT_USB_DISK, 64);
    fake::with(|s| s.handler = Some(Box::new(|_, _, _| Ok(k::ipc::Message::with_args(0x1234, [0, 64, 0, 0])))));
    storage::usbdisk(&[USBDISK_SPEED, 0, 1, 0]).must();
    assert_eq!(fake::take_out(), "usbdisk: error 0\n");
}

#[test]
fn usb_write_test_notices_data_that_does_not_come_back() {
    let _g = setup();
    // The disk drops the third write (the restore of the first place)
    block_driver(ENDPOINT_USB_DISK, 30);
    let inner = RefCell::new(fake::with(|s| s.handler.take()).unwrap());
    let writes = RefCell::new(0);
    fake::with(|s| {
        s.handler = Some(Box::new(move |e, m, k| {
            if m.label == MSG_BLOCK_WRITE {
                *writes.borrow_mut() += 1;
                if *writes.borrow() == 3 {
                    return Ok(k::ipc::Message::with_args(MSG_BLOCK_REPLY, [0, m.args[1], 0, 0]));
                }
            }
            (inner.borrow_mut())(e, m, k)
        }))
    });
    storage::usbdisk(&[USBDISK_TEST, 0, 1, 0]).must();
    let out = fake::take_out();
    assert!(out.contains("usbdisk: the original data at 0 did not come back"), "{}", out);
    assert!(out.contains("FAILED, 1 bytes differ"), "{}", out);
}
