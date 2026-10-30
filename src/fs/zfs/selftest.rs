//! # ZFS Self-Test
//!
//! `zfs selftest` builds a test tree under `/zfstest`, verifies it, commits, drops every
//! cache and verifies again from disk. `zfs verify` re-checks the tree after a reboot.

use alloc::format;
use alloc::vec::Vec;

use super::server::{with_server, ZfsServer};
use super::types::*;
use super::zpl::{self, SetAttr};
use crate::fs::client::resolve_at;

const BIG_FILE_BYTES: usize = 5 * 1024 * 1024 + 1234;
const MANY_FILES: usize = 3000;

fn pattern(i: usize) -> u8 {
    (i.wrapping_mul(2_654_435_761) >> 13) as u8
}

fn check(name: &str, ok: bool, failures: &mut u32) {
    println!("[zfstest] {:<52} {}", name, if ok { "PASS" } else { "FAIL" });
    if !ok {
        *failures += 1;
    }
}

fn path(s: &mut ZfsServer, p: &str) -> Result<u64, i64> {
    let root = s.root_obj();
    resolve_at(s, root, p.as_bytes(), true)
}

/// Removes the directory tree `dir/name` recursively.
fn remove_tree(s: &mut ZfsServer, dir: u64, name: &[u8]) -> Result<(), i64> {
    let ino = s.lookup(dir, name)?;
    if s.getattr(ino)?.is_dir() {
        loop {
            let batch = s.readdir(ino, 2, 64)?;
            if batch.is_empty() {
                break;
            }
            for e in batch {
                remove_tree(s, ino, &e.name)?;
            }
        }
        s.rmdir(dir, name)
    } else {
        s.unlink(dir, name)
    }
}

fn build(s: &mut ZfsServer) -> Result<(), i64> {
    let root = s.root_obj();
    if s.lookup(root, b"zfstest").is_ok() {
        println!("[zfstest] removing /zfstest left by an earlier run");
        remove_tree(s, root, b"zfstest")?;
    }
    let top = s.mkdir(root, b"zfstest", 0o755, 0, 0)?;

    // Large file spanning several indirect levels
    let big = s.create(top, b"big.bin", 0o644, 1000, 1000)?;
    let chunk: Vec<u8> = (0..65536).map(pattern).collect();
    let mut off = 0;
    while off < BIG_FILE_BYTES {
        let n = (BIG_FILE_BYTES - off).min(chunk.len());
        let data: Vec<u8> = (off..off + n).map(pattern).collect();
        s.write(big, off as u64, &data)?;
        off += n;
    }

    // Sparse file: data far past the end leaves a hole
    let sparse = s.create(top, b"sparse.bin", 0o600, 0, 0)?;
    s.write(sparse, 300 * 1024 * 1024, b"tail")?;

    // Many directory entries with long names
    let many = s.mkdir(top, b"many", 0o755, 0, 0)?;
    for i in 0..MANY_FILES {
        let name = format!("entry-{:05}-{}", i, "x".repeat(i % 200));
        let ino = s.create(many, name.as_bytes(), 0o644, 0, 0)?;
        s.write(ino, 0, format!("file {}", i).as_bytes())?;
    }
    // Remove every third entry to exercise tombstones and slot reuse
    for i in (0..MANY_FILES).step_by(3) {
        let name = format!("entry-{:05}-{}", i, "x".repeat(i % 200));
        s.unlink(many, name.as_bytes())?;
    }

    // Symlinks (inline and long), hard links, rename, truncate
    s.symlink(top, b"link-short", b"big.bin", 0, 0)?;
    let long_target = format!("/zfstest{}/big.bin", "/sub/..".repeat(40));
    s.symlink(top, b"link-long", long_target.as_bytes(), 0, 0)?;
    s.link(big, top, b"big-hardlink")?;
    let tmp = s.create(top, b"rename-me", 0o644, 0, 0)?;
    s.write(tmp, 0, b"renamed contents")?;
    let sub = s.mkdir(top, b"sub", 0o750, 0, 0)?;
    s.rename(top, b"rename-me", sub, b"renamed")?;
    let trunc = s.create(top, b"truncated", 0o644, 0, 0)?;
    s.write(trunc, 0, &[0xAB; 10_000])?;
    s.setattr(trunc, SetAttr { size: Some(5000), ..SetAttr::default() })?;
    s.setattr(trunc, SetAttr { size: Some(8192), ..SetAttr::default() })?;
    Ok(())
}

fn verify(s: &mut ZfsServer, failures: &mut u32) -> Result<(), i64> {
    let big = path(s, "/zfstest/big.bin")?;
    let attr = s.getattr(big)?;
    check("big.bin size", attr.size == BIG_FILE_BYTES as u64, failures);
    check("big.bin nlink == 2 (hard link)", attr.nlink == 2, failures);
    let mut buf = alloc::vec![0u8; 65536];
    let mut ok = true;
    let mut off = 0;
    while off < BIG_FILE_BYTES {
        let n = s.read(big, off as u64, &mut buf)?;
        ok &= n > 0 && buf[..n].iter().enumerate().all(|(i, &b)| b == pattern(off + i));
        off += n.max(1);
    }
    check("big.bin contents (multi-level block tree)", ok, failures);

    let sparse = path(s, "/zfstest/sparse.bin")?;
    let mut hole = [1u8; 4096];
    s.read(sparse, 100 * 1024 * 1024, &mut hole)?;
    let mut tail = [0u8; 4];
    s.read(sparse, 300 * 1024 * 1024, &mut tail)?;
    check("sparse.bin hole reads zero, tail intact", hole.iter().all(|&b| b == 0) && &tail == b"tail", failures);

    let many = path(s, "/zfstest/many")?;
    let mut names = 0;
    let mut cookie = 0;
    let mut content_ok = true;
    loop {
        let batch = s.readdir(many, cookie, 128)?;
        if batch.is_empty() {
            break;
        }
        for e in batch {
            cookie = e.next_cookie;
            if e.name == b"." || e.name == b".." {
                continue;
            }
            names += 1;
            let idx: usize = core::str::from_utf8(&e.name[6..11]).ok().and_then(|n| n.parse().ok()).unwrap_or(usize::MAX);
            let mut b = [0u8; 16];
            let n = s.read(e.ino, 0, &mut b)?;
            content_ok &= idx % 3 != 0 && b[..n] == *format!("file {}", idx).as_bytes();
        }
    }
    check("directory with 3000 entries, 1000 removed", names == MANY_FILES - MANY_FILES / 3, failures);
    check("directory entries resolve to the right files", content_ok, failures);

    let short = path(s, "/zfstest/link-short")?;
    check("short symlink resolves", short == big, failures);
    let long = path(s, "/zfstest/link-long")?;
    check("long symlink (data blocks) resolves", long == big, failures);
    let root = s.root_obj();
    let link_ino = resolve_at(s, root, b"/zfstest/link-short", false)?;
    check("symlink lstat is S_IFLNK", s.getattr(link_ino)?.mode & S_IFMT == S_IFLNK, failures);

    let renamed = path(s, "/zfstest/sub/renamed")?;
    let mut r = [0u8; 32];
    let n = s.read(renamed, 0, &mut r)?;
    check("rename across directories", &r[..n] == b"renamed contents", failures);
    check("old name gone after rename", path(s, "/zfstest/rename-me") == Err(zpl::ENOENT), failures);
    let sub = path(s, "/zfstest/sub")?;
    check("subdir mode 0750", s.getattr(sub)?.mode & 0o7777 == 0o750, failures);
    let up = path(s, "/zfstest/sub/..")?;
    let top = path(s, "/zfstest")?;
    check(".. of subdir is parent", up == top, failures);

    let trunc = path(s, "/zfstest/truncated")?;
    let mut t = alloc::vec![0u8; 8192];
    let n = s.read(trunc, 0, &mut t)?;
    check(
        "truncate down then up zero-fills",
        n == 8192 && t[..5000].iter().all(|&b| b == 0xAB) && t[5000..].iter().all(|&b| b == 0),
        failures,
    );
    Ok(())
}

fn report(failures: u32) {
    println!("[zfstest] {} ({} failure{})", if failures == 0 { "ALL PASSED" } else { "FAILED" }, failures, if failures == 1 { "" } else { "s" });
}

/// Creates the test tree and verifies it before and after a commit with cold caches.
pub fn run_selftest() {
    let mut failures = 0;
    let res = with_server(|s| {
        build(s)?;
        verify(s, &mut failures)?;
        let txg = s.sync()?;
        println!("[zfstest] committed TXG #{}; dropping caches and re-reading from disk", txg);
        s.dmu.drop_caches();
        s.zap.clear();
        verify(s, &mut failures)
    });
    if let Err(e) = res {
        println!("[zfstest] aborted with errno {}", e);
        failures += 1;
    }
    report(failures);
}

/// Re-verifies a test tree created by an earlier boot.
pub fn run_verify() {
    let mut failures = 0;
    if let Err(e) = with_server(|s| verify(s, &mut failures)) {
        println!("[zfstest] aborted with errno {}", e);
        failures += 1;
    }
    report(failures);
}
