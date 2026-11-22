//! The intent log end to end on the real ZFS code: requests as the main loop serves them
//! (`durable::before`, `serve`, `durable::after`), a simulated kill (the server's memory
//! goes, the RAM disk and the kept log stay), a re-import and the replay.

use crate::durable;
use crate::zfs::fsproto::*;
use crate::zfs::server::{ZfsServer, ZFS_SERVER};
use crate::zfs::spa::Vdev;
use crate::zil;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// The server's statics are global: one test at a time.
static SERIAL: Mutex<()> = Mutex::new(());

const POOL_BYTES: usize = 64 * 1024 * 1024;

/// Page-aligned zeroed memory that lives for the test run.
fn leak_zeroed(bytes: usize) -> *mut u8 {
    let l = std::alloc::Layout::from_size_align(bytes, 4096).unwrap();
    let p = unsafe { std::alloc::alloc_zeroed(l) };
    assert!(!p.is_null());
    p
}

/// A machine: the pool's RAM disk and the kept log object (both survive a kill).
struct Machine {
    disk: *mut u8,
    log: *mut u8,
    /// The kept object exists (an instance made it before).
    log_made: bool,
    /// With an intent log (false: the server as it was before wave 8).
    with_log: bool,
}

impl Machine {
    fn new() -> Self {
        Self { disk: leak_zeroed(POOL_BYTES), log: leak_zeroed(durable::LOG_BYTES), log_made: false, with_log: true }
    }

    /// Starts a server instance: import (or create), then the log's replay.
    fn start(&mut self) -> durable::Recovered {
        let vdev = unsafe { Vdev::ram_at(self.disk, (POOL_BYTES / 4096) as u64) };
        *ZFS_SERVER.lock() = Some(ZfsServer::on(vdev));
        if !self.with_log {
            return durable::Recovered::default();
        }
        let existed = self.log_made;
        self.log_made = true;
        let buf = unsafe { std::slice::from_raw_parts_mut(self.log, durable::LOG_BYTES) };
        durable::recover(buf, existed)
    }

    /// The process dies: everything in its memory goes.
    fn kill(&mut self) {
        durable::detach();
        *ZFS_SERVER.lock() = None;
    }

    fn log_bytes(&self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.log, durable::LOG_BYTES) }
    }

    fn disk_bytes(&self) -> &'static mut [u8] {
        unsafe { std::slice::from_raw_parts_mut(self.disk, POOL_BYTES) }
    }
}

/// One request as the main loop serves it; returns `(status, value, reply)`.
fn req(op: u32, params: impl FnOnce(&mut Writer)) -> (i64, u64, Vec<u8>) {
    let mut buf = vec![0u8; EVENT_OFFSET];
    let len = {
        let mut w = Writer::new(&mut buf);
        params(&mut w);
        w.len()
    };
    let r = buf[..len].to_vec();
    let mut out = vec![0u8; EVENT_OFFSET];
    crate::compat::linux::inotify::take();
    let before = durable::before(crate::arch::rtc::real());
    let (status, value, n) = crate::serve::serve(op, &r, &mut out);
    durable::after(before, op, &r, status, value);
    crate::compat::linux::inotify::take();
    (status, value, out[..n].to_vec())
}

fn root() -> u64 {
    req(FS_ROOT, |_| {}).1
}

fn ok(r: (i64, u64, Vec<u8>)) -> u64 {
    assert!(r.0 >= 0, "request failed: {}", r.0);
    r.1
}

fn mkdir(dir: u64, name: &str) -> u64 {
    ok(req(FS_MKDIR, |w| {
        w.u64(dir);
        w.bytes(name.as_bytes());
        w.u64(0o755);
        w.u64(1000);
        w.u64(1000);
    }))
}

fn create(dir: u64, name: &str) -> u64 {
    ok(req(FS_CREATE, |w| {
        w.u64(dir);
        w.bytes(name.as_bytes());
        w.u64(0o644);
        w.u64(1000);
        w.u64(1000);
    }))
}

fn write(ino: u64, off: u64, data: &[u8]) {
    // (as the kernel sends them: at most MAX_IO bytes per request)
    for (i, part) in data.chunks(MAX_IO).enumerate() {
        let n = ok(req(FS_WRITE, |w| {
            w.u64(ino);
            w.u64(off + (i * MAX_IO) as u64);
            w.bytes(part);
            w.u64(0);
        }));
        assert_eq!(n as usize, part.len());
    }
}

fn lookup(dir: u64, name: &str) -> Result<u64, i64> {
    let r = req(FS_LOOKUP, |w| {
        w.u64(dir);
        w.bytes(name.as_bytes());
    });
    if r.0 < 0 {
        Err(r.0)
    } else {
        Ok(r.1)
    }
}

fn unlink(dir: u64, name: &str) {
    ok(req(FS_UNLINK, |w| {
        w.u64(dir);
        w.bytes(name.as_bytes());
    }));
}

fn rename(sdir: u64, sname: &str, ddir: u64, dname: &str) {
    ok(req(FS_RENAME, |w| {
        w.u64(sdir);
        w.bytes(sname.as_bytes());
        w.u64(ddir);
        w.bytes(dname.as_bytes());
    }));
}

fn getattr(ino: u64) -> Option<Attr> {
    let r = req(FS_GETATTR, |w| {
        w.u64(ino);
    });
    (r.0 >= 0).then(|| Reader::new(&r.2).attr())
}

fn read_all(ino: u64) -> Vec<u8> {
    let size = getattr(ino).unwrap().size;
    let mut out = Vec::new();
    while (out.len() as u64) < size {
        let off = out.len() as u64;
        let r = req(FS_READ, |w| {
            w.u64(ino);
            w.u64(off);
            w.u64(MAX_IO as u64);
        });
        assert!(r.0 >= 0 && r.1 > 0);
        out.extend_from_slice(&r.2);
    }
    out
}

fn sync() {
    ok(req(FS_SYNC, |_| {}));
}

fn txg() -> u64 {
    ZFS_SERVER.lock().as_ref().unwrap().dmu.ub.txg
}

/// Every name under `dir`, recursively: path -> (ino, mode, nlink, size, data or link
/// target, mtime, ctime).
type Tree = BTreeMap<String, (u64, u32, u32, u64, Vec<u8>, (i64, u32), (i64, u32))>;

fn tree(dir: u64, prefix: &str, out: &mut Tree) {
    let mut cookie = 0;
    loop {
        let r = req(FS_READDIR, |w| {
            w.u64(dir);
            w.u64(cookie);
            w.u64(64);
        });
        assert!(r.0 >= 0);
        if r.1 == 0 {
            break;
        }
        let mut rd = Reader::new(&r.2);
        for _ in 0..r.1 {
            let e = rd.entry();
            cookie = e.next_cookie;
            let name = String::from_utf8(e.name.clone()).unwrap();
            if name == "." || name == ".." {
                continue;
            }
            let path = format!("{}/{}", prefix, name);
            let a = getattr(e.ino).unwrap();
            let content = if a.is_dir() {
                Vec::new()
            } else if a.mode & 0o170000 == 0o120000 {
                req(FS_READLINK, |w| {
                    w.u64(e.ino);
                })
                .2
            } else {
                read_all(e.ino)
            };
            out.insert(path.clone(), (e.ino, a.mode, a.nlink, a.size, content, a.mtime, a.ctime));
            if a.is_dir() {
                tree(e.ino, &path, out);
            }
        }
    }
}

fn whole_tree() -> Tree {
    let mut t = Tree::new();
    tree(root(), "", &mut t);
    t
}

/// The same tree without the times (for runs on different clocks).
fn shape(t: &Tree) -> BTreeMap<String, (u64, u32, u32, u64, Vec<u8>)> {
    t.iter().map(|(k, v)| (k.clone(), (v.0, v.1, v.2, v.3, v.4.clone()))).collect()
}

fn pattern(seed: u64, n: usize) -> Vec<u8> {
    (0..n).map(|i| (i as u64 * 31 + seed * 7 + (i as u64 >> 9)) as u8).collect()
}

/// A fresh machine with a pool (created and committed) and the log started.
fn fresh() -> Machine {
    let mut m = Machine::new();
    let r = m.start();
    assert!(!r.matched);
    m
}

/// A workload of every kind of change; returns the inode numbers it made.
fn workload(tag: u64) -> Vec<u64> {
    let r = root();
    let d = mkdir(r, &format!("w{}", tag));
    let sub = mkdir(d, "sub");
    let f = create(d, "file");
    write(f, 0, &pattern(tag, 10_000));
    write(f, 5_000, b"overwritten in the middle");
    let g = create(sub, "g");
    write(g, 0, &pattern(tag + 1, 200_000));
    ok(req(FS_SYMLINK, |w| {
        w.u64(d);
        w.bytes(b"link");
        w.bytes(b"file");
        w.u64(1000);
        w.u64(1000);
    }));
    ok(req(FS_LINK, |w| {
        w.u64(f);
        w.u64(sub);
        w.bytes(b"hard");
    }));
    let h = create(d, "gone");
    unlink(d, "gone");
    rename(sub, "g", d, "g2");
    ok(req(FS_SETATTR, |w| {
        w.u64(f);
        w.setattr(&SetAttr { mode: Some(0o600), ..SetAttr::default() });
    }));
    ok(req(FS_SETATTR, |w| {
        w.u64(g);
        w.setattr(&SetAttr { size: Some(70_000), ..SetAttr::default() });
    }));
    ok(req(FS_SETXATTR, |w| {
        w.u64(f);
        w.bytes(b"user.test");
        w.bytes(b"value");
        w.u64(0);
    }));
    let e = mkdir(d, "empty");
    ok(req(FS_RMDIR, |w| {
        w.u64(d);
        w.bytes(b"empty");
    }));
    // A request that fails changes nothing and is not logged
    assert_eq!(
        req(FS_MKDIR, |w| {
            w.u64(d);
            w.bytes(b"sub");
            w.u64(0o755);
            w.u64(0);
            w.u64(0);
        })
        .0,
        EEXIST
    );
    // Reuse of the freed object numbers
    let n1 = create(d, "new1");
    let n2 = mkdir(d, "new2");
    vec![d, sub, f, g, h, e, n1, n2]
}

#[test]
fn acknowledged_changes_survive_a_kill() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let base = txg();
    let inos = workload(1);
    // Nothing was committed: all of it is in the log only
    assert_eq!(txg(), base);
    let before = whole_tree();
    m.kill();
    let r = m.start();
    assert!(r.matched && !r.given_up && !r.torn);
    assert_eq!(r.replayed.mismatches, 0);
    assert!(r.replayed.applied >= 15, "{:?}", r);
    // Committed by the replay
    assert!(r.txg > base);
    // The same tree, object numbers, data and times
    assert_eq!(whole_tree(), before);
    assert_eq!(lookup(inos[0], "new1"), Ok(inos[6]));
    let xattr = req(FS_GETXATTR, |w| {
        w.u64(inos[2]);
        w.bytes(b"user.test");
    });
    assert_eq!(&xattr.2[..], b"value");
    m.kill();
}

#[test]
fn without_the_log_a_kill_loses_the_changes() {
    // The problem this log solves, shown on the same code
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = Machine::new();
    m.with_log = false;
    m.start();
    workload(2);
    let r = root();
    assert!(lookup(r, "w2").is_ok());
    m.kill();
    m.start();
    assert_eq!(lookup(root(), "w2"), Err(ENOENT));
    m.kill();
}

#[test]
fn object_numbers_match_a_run_without_a_kill() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // Run A: workload, commit, more work (with frees and reuse), kill, replay, more work
    let mut a = fresh();
    workload(3);
    sync();
    let r0 = root();
    let d = lookup(r0, "w3").unwrap();
    for i in 0..20 {
        create(d, &format!("f{}", i));
    }
    for i in (0..20).step_by(3) {
        unlink(d, &format!("f{}", i));
    }
    let after_kill_expected: Vec<u64>;
    a.kill();
    let r = a.start();
    assert_eq!(r.replayed.mismatches, 0);
    after_kill_expected = (0..5).map(|i| create(d, &format!("post{}", i))).collect();
    let tree_a = shape(&whole_tree());
    a.kill();
    // Run B: the same without the kill
    let mut b = fresh();
    workload(3);
    sync();
    let d = lookup(root(), "w3").unwrap();
    for i in 0..20 {
        create(d, &format!("f{}", i));
    }
    for i in (0..20).step_by(3) {
        unlink(d, &format!("f{}", i));
    }
    let post: Vec<u64> = (0..5).map(|i| create(d, &format!("post{}", i))).collect();
    assert_eq!(post, after_kill_expected);
    assert_eq!(shape(&whole_tree()), tree_a);
    b.kill();
}

#[test]
fn an_unlinked_open_file_lives_on_after_the_replay() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let r = root();
    let f = create(r, "held");
    write(f, 0, b"still here");
    ok(req(FS_OPEN_REF, |w| {
        w.u64(f);
    }));
    // A commit: the open count is now only in the log's state record
    sync();
    unlink(r, "held");
    assert!(getattr(f).is_some());
    m.kill();
    let rec = m.start();
    assert_eq!(rec.replayed.mismatches, 0);
    // Unlinked, still open: readable
    let a = getattr(f).expect("the open file was freed");
    assert_eq!(a.nlink, 0);
    assert_eq!(read_all(f), b"still here");
    // A second kill after the replay's commit: the state record carries it
    m.kill();
    let rec = m.start();
    assert!(rec.matched);
    assert_eq!(read_all(f), b"still here");
    // The last close frees it, and its number is reused
    ok(req(FS_RELEASE, |w| {
        w.u64(f);
    }));
    let g = create(root(), "reuse");
    assert_eq!(g, f);
    m.kill();
}

#[test]
fn a_torn_last_record_loses_only_that_change() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let r = root();
    let a = mkdir(r, "a");
    let used_before_b = durable::used();
    mkdir(r, "b");
    m.kill();
    // The kill came while "b" was being written into the log
    let start = {
        let log = zil::Log::attach(m.log_bytes());
        zil::HDR_SIZE + log.header().unwrap().area * log.area_size()
    };
    m.log_bytes()[start + used_before_b + zil::REC_HEAD + 3] ^= 0xFF;
    let rec = m.start();
    assert!(rec.matched && rec.torn);
    assert_eq!(rec.replayed.applied, 1);
    assert_eq!(lookup(root(), "a"), Ok(a));
    assert_eq!(lookup(root(), "b"), Err(ENOENT));
    m.kill();
}

#[test]
fn a_log_of_an_older_generation_is_ignored() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let r = root();
    mkdir(r, "x");
    create(r, "y");
    // An open file unlinked in this generation: only the log knows it is still open
    let held = create(r, "held");
    write(held, 0, b"open after unlink");
    ok(req(FS_OPEN_REF, |w| {
        w.u64(held);
    }));
    unlink(r, "held");
    let old_header = m.log_bytes()[..zil::HDR_SIZE].to_vec();
    let t0 = txg();
    // The txgd's commit; the kill came right after the commit and the new generation's
    // state record, before its header
    ok(req(FS_SYNC_IF_DIRTY, |_| {}));
    assert!(txg() > t0);
    let before = whole_tree();
    m.kill();
    m.log_bytes()[..zil::HDR_SIZE].copy_from_slice(&old_header);
    let rec = m.start();
    // Not replayed (the pool is past the log's generation): nothing done twice
    assert!(!rec.matched);
    assert!(rec.handles_from_older);
    assert_eq!(whole_tree(), before);
    // The handle counts came from the older generation: the unlinked file is still there
    assert_eq!(getattr(held).map(|a| a.nlink), Some(0));
    assert_eq!(read_all(held), b"open after unlink");
    ok(req(FS_RELEASE, |w| {
        w.u64(held);
    }));
    assert!(getattr(held).is_none() || getattr(held).unwrap().mode == 0);
    assert_eq!(create(root(), "reuse"), held);
    m.kill();
}

#[test]
fn repeated_commits_at_the_same_txg_never_bring_old_records_back() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let f = create(root(), "f");
    sync();
    // Handle requests change no block: the txgd's commits find nothing to write and keep
    // the txg, yet each starts a new generation (in alternating areas)
    ok(req(FS_OPEN_REF, |w| {
        w.u64(f);
    }));
    ok(req(FS_OPEN_REF, |w| {
        w.u64(f);
    }));
    let t = txg();
    for _ in 0..3 {
        ok(req(FS_SYNC_IF_DIRTY, |_| {}));
    }
    assert_eq!(txg(), t);
    m.kill();
    let r = m.start();
    assert!(r.matched);
    // The two open requests are in the state record now, not replayed again
    assert_eq!(r.replayed.applied, 0);
    let open = ZFS_SERVER.lock().as_ref().unwrap().durable_state();
    assert_eq!(crate::zil::decode_state(&open).unwrap().0.get(&f), Some(&2));
    m.kill();
}

#[test]
fn replaying_twice_gives_the_same_pool() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    workload(4);
    m.kill();
    // The state a second restart would find if the first died before its commit: the
    // disk and the log as they are now, with one attempt counted
    let disk = m.disk_bytes().to_vec();
    let mut log = m.log_bytes().to_vec();
    zil::Log::attach(&mut log).begin_replay();
    let r1 = m.start();
    assert_eq!(r1.replayed.mismatches, 0);
    let t1 = whole_tree();
    m.kill();
    m.disk_bytes().copy_from_slice(&disk);
    m.log_bytes().copy_from_slice(&log);
    let r2 = m.start();
    assert!(r2.matched && !r2.given_up);
    assert_eq!(r2.replayed, r1.replayed);
    assert_eq!(whole_tree(), t1);
    // And the restart after a finished replay replays nothing more
    m.kill();
    let r3 = m.start();
    assert!(r3.matched);
    assert_eq!(r3.replayed.applied, 0);
    assert_eq!(whole_tree(), t1);
    m.kill();
}

#[test]
fn a_log_that_keeps_failing_is_given_up() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    mkdir(root(), "doomed");
    m.kill();
    {
        let mut log = zil::Log::attach(m.log_bytes());
        for _ in 0..zil::MAX_ATTEMPTS {
            log.begin_replay();
        }
    }
    let r = m.start();
    assert!(r.matched && r.given_up);
    assert_eq!(lookup(root(), "doomed"), Err(ENOENT));
    // A fresh log was started: the next kill keeps the next changes
    mkdir(root(), "kept");
    m.kill();
    let r = m.start();
    assert!(r.matched && !r.given_up);
    assert!(lookup(root(), "kept").is_ok());
    m.kill();
}

#[test]
fn a_full_log_forces_a_commit() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let f = create(root(), "big");
    let t0 = txg();
    let chunk = pattern(9, MAX_IO);
    let total = durable::COMMIT_AT + 4 * MAX_IO;
    let mut off = 0;
    while off < total {
        write(f, off as u64, &chunk);
        off += MAX_IO;
        assert!(durable::used() <= durable::COMMIT_AT + MAX_IO + 4096);
    }
    assert!(txg() > t0, "no commit");
    m.kill();
    let r = m.start();
    assert_eq!(r.replayed.mismatches, 0);
    let data = read_all(lookup(root(), "big").unwrap());
    assert_eq!(data.len(), total);
    assert!(data.chunks(MAX_IO).all(|c| c == &chunk[..]));
    m.kill();
}

#[test]
fn the_txgd_commit_restarts_the_log() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    let empty = durable::used();
    mkdir(root(), "a");
    assert!(durable::used() > empty);
    ok(req(FS_SYNC_IF_DIRTY, |_| {}));
    assert_eq!(durable::used(), empty);
    // Requests that change nothing are not logged
    lookup(root(), "a").unwrap();
    getattr(root()).unwrap();
    assert_eq!(durable::used(), empty);
    m.kill();
}

#[test]
fn a_log_of_another_pool_is_ignored() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut m = fresh();
    mkdir(root(), "mine");
    m.kill();
    // Another disk under the same kept log
    let other = Machine::new();
    m.disk = other.disk;
    let r = m.start();
    assert!(!r.matched);
    assert_eq!(lookup(root(), "mine"), Err(ENOENT));
    m.kill();
}

/// Not a check: the log's cost on the host (`cargo test --release -- --ignored --nocapture
/// log_cost`): 64 KiB appends, 4 KiB creates and write+sync, with and without the log.
#[test]
#[ignore]
fn log_cost() {
    let _s = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    for with_log in [false, true, false, true] {
        let mut m = Machine::new();
        m.with_log = with_log;
        m.start();
        let r = root();
        let f = create(r, "big");
        let chunk = pattern(1, 65536);
        let t = std::time::Instant::now();
        for i in 0..512u64 {
            write(f, i * 65536, &chunk);
        }
        let append = t.elapsed().as_secs_f64() * 1e6 / 512.0;
        let t = std::time::Instant::now();
        for i in 0..2000 {
            let g = create(r, &format!("c{}", i));
            write(g, 0, &chunk[..4096]);
        }
        let creates = t.elapsed().as_secs_f64() * 1e6 / 2000.0;
        let t = std::time::Instant::now();
        for i in 0..200u64 {
            write(f, (i % 64) * 4096, &chunk[..4096]);
            sync();
        }
        let fsync = t.elapsed().as_secs_f64() * 1e6 / 200.0;
        std::println!("log={} append_64k={:.1}us create_4k={:.1}us write_sync_4k={:.1}us", with_log, append, creates, fsync);
        m.kill();
    }
}
