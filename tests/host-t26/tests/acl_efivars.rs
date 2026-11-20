//! acl.rs (POSIX ACLs), efivars.rs (UEFI variables) and live.rs.
mod common;
use common::*;
use hydra_hosttests_t26::fake::firmware;
use lx::{acl, efivars};

fn acl_bytes(e: &[(u16, u16, u32)]) -> Vec<u8> {
    let mut b = 2u32.to_le_bytes().to_vec();
    for &(t, p, i) in e {
        b.extend_from_slice(&t.to_le_bytes());
        b.extend_from_slice(&p.to_le_bytes());
        b.extend_from_slice(&i.to_le_bytes());
    }
    b
}

const UO: u16 = 1;
const U: u16 = 2;
const GO: u16 = 4;
const G: u16 = 8;
const M: u16 = 0x10;
const O: u16 = 0x20;

#[test]
fn validation() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    let a = memfs::attr(f);
    let set = |e: &[u8]| acl::set(&memfs::attr(f), false, e, 0);
    assert_eq!(set(&[1, 2, 3]), EINVAL); // not a whole header
    let mut v3 = acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]);
    v3[0] = 3;
    assert_eq!(set(&v3), EOPNOTSUPP);
    assert_eq!(set(&acl_bytes(&[(UO, 8, 0), (GO, 5, 0), (O, 5, 0)])), EINVAL); // perm bits
    assert_eq!(set(&acl_bytes(&[(GO, 5, 0), (UO, 7, 0), (O, 5, 0)])), EINVAL); // order
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (U, 7, 5), (GO, 5, 0), (O, 5, 0)])), EINVAL); // no mask
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (U, 7, 5), (U, 7, 5), (GO, 5, 0), (M, 7, 0), (O, 5, 0)])), EINVAL); // dup user
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (G, 7, 9), (G, 7, 3), (M, 7, 0), (O, 5, 0)])), EINVAL); // group order
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (GO, 5, 0)])), EINVAL); // no other
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0), (O, 5, 0)])), EINVAL);
    // Equivalent to the mode: only the mode is kept
    assert_eq!(set(&acl_bytes(&[(UO, 6, 0), (GO, 4, 0), (O, 0, 0)])), 0);
    assert_eq!(memfs::attr(f).mode, 0o100640);
    assert!(memfs::xattr(f, acl::ACCESS).is_none());
    // An extended one is kept and sets owner/mask/other bits
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (U, 6, 1000), (GO, 4, 0), (G, 6, 2000), (M, 6, 0), (O, 1, 0)])), 0);
    assert_eq!(memfs::attr(f).mode, 0o100761);
    assert!(memfs::xattr(f, acl::ACCESS).is_some());
    // An empty value removes it (twice is fine)
    assert_eq!(set(&[]), 0);
    assert_eq!(set(&[]), 0);
    // Default ACLs only on directories
    assert_eq!(acl::set(&a, true, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0), EACCES);
    // Only the owner (or CAP_FOWNER)
    become_user(1000);
    assert_eq!(set(&acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)])), EPERM);
    assert_eq!(acl::remove(&memfs::attr(f), false), EPERM);
    task::set_caps(1 << 3);
    assert_eq!(acl::remove(&memfs::attr(f), false), ENODATA);
}

#[test]
fn set_group_id_and_server_errors() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chown(f, 1000, 3000);
    memfs::chmod(f, 0o2755);
    become_user(1000);
    // Not in the group, no CAP_FSETID: set-group-ID goes
    assert_eq!(acl::set(&memfs::attr(f), false, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0), 0);
    assert_eq!(memfs::attr(f).mode & 0o7777, 0o755);
    memfs::chmod(f, 0o2755);
    task::set_caps(1 << 4);
    assert_eq!(acl::set(&memfs::attr(f), false, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0), 0);
    assert_eq!(memfs::attr(f).mode & 0o7777, 0o2755);
    task::set_ids(0, 0);
    memfs::fail("setxattr", -28);
    assert_eq!(acl::set(&memfs::attr(f), false, &acl_bytes(&[(UO, 7, 0), (U, 7, 1), (GO, 5, 0), (M, 7, 0), (O, 5, 0)]), 0), -28);
    memfs::fail("setxattr", 0);
    memfs::fail("removexattr", -5);
    assert_eq!(acl::set(&memfs::attr(f), false, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0), -5);
    memfs::fail("removexattr", 0);
    memfs::fail("setattr", -5);
    assert_eq!(acl::set(&memfs::attr(f), false, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0), -5);
}

#[test]
fn checks_follow_posix_acl_permission() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chown(f, 10, 20);
    // owner rw, user 1000 rwx (masked to r), group r, group 30 rw (masked to r), other none
    memfs::set_xattr(f, acl::ACCESS, &acl_bytes(&[(UO, 6, 0), (U, 7, 1000), (GO, 4, 0), (G, 6, 30), (M, 4, 0), (O, 0, 0)]));
    let a = memfs::attr(f);
    assert_eq!(acl::check(&a, 10, 99, 6), Some(true)); // owner
    assert_eq!(acl::check(&a, 10, 99, 1), Some(false));
    assert_eq!(acl::check(&a, 1000, 99, 4), Some(true)); // named user, masked
    assert_eq!(acl::check(&a, 1000, 99, 2), Some(false));
    assert_eq!(acl::check(&a, 2000, 20, 4), Some(true)); // owning group
    assert_eq!(acl::check(&a, 2000, 30, 2), Some(false)); // named group, matched but masked
    assert_eq!(acl::check(&a, 2000, 99, 4), Some(false)); // other
    // A supplementary group grants
    lx::proc::with(task::SELF_PID, |p| p.groups.push(30));
    assert_eq!(acl::check(&a, 2000, 99, 4), Some(true));
    // No ACL: the mode decides (None); an unreadable one too
    let g = memfs::mkfile("/g", b"");
    assert_eq!(acl::check(&memfs::attr(g), 1, 1, 4), None);
    memfs::set_xattr(g, b"user.x", b"y");
    assert_eq!(acl::check(&memfs::attr(g), 1, 1, 4), None);
    // The VFS uses it: user 1000 may read, not write
    become_user(1000);
    assert!(open("/f", O_RDONLY) >= 0);
    assert_eq!(open("/f", O_WRONLY), EACCES);
}

#[test]
fn chmod_rewrites_the_acl() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::set_xattr(f, acl::ACCESS, &acl_bytes(&[(UO, 6, 0), (U, 7, 1000), (GO, 4, 0), (M, 4, 0), (O, 0, 0)]));
    acl::on_chmod(&memfs::attr(f), 0o751);
    assert_eq!(memfs::xattr(f, acl::ACCESS).unwrap(), acl_bytes(&[(UO, 7, 0), (U, 7, 1000), (GO, 4, 0), (M, 5, 0), (O, 1, 0)]));
    // Without a mask the owning group takes the group bits
    let g = memfs::mkfile("/g", b"");
    memfs::set_xattr(g, acl::ACCESS, &acl_bytes(&[(UO, 6, 0), (GO, 4, 0), (O, 0, 0)]));
    acl::on_chmod(&memfs::attr(g), 0o777);
    assert_eq!(memfs::xattr(g, acl::ACCESS).unwrap(), acl_bytes(&[(UO, 7, 0), (GO, 7, 0), (O, 7, 0)]));
    // Nothing changes: not rewritten; no ACL: nothing
    acl::on_chmod(&memfs::attr(g), 0o777);
    let h = memfs::mkfile("/h", b"");
    acl::on_chmod(&memfs::attr(h), 0o600);
    assert!(memfs::xattr(h, acl::ACCESS).is_none());
}

#[test]
fn creation_inherits_default_acls() {
    let _e = setup();
    let d = memfs::mkdir_p("/shared");
    let def = acl_bytes(&[(UO, 7, 0), (U, 7, 1000), (GO, 5, 0), (M, 7, 0), (O, 0, 0)]);
    assert_eq!(acl::set(&memfs::attr(d), true, &def, 0), 0);
    // A file: no umask, limited by the requested mode
    let fd = openat(AT_FDCWD, "/shared/f", O_CREAT | O_WRONLY, 0o640);
    assert!(fd >= 0);
    let f = memfs::lookup("/shared/f").unwrap();
    assert_eq!(memfs::attr(f).mode, 0o100640);
    let acc = memfs::xattr(f, acl::ACCESS).unwrap();
    assert_eq!(acc, acl_bytes(&[(UO, 6, 0), (U, 7, 1000), (GO, 5, 0), (M, 4, 0), (O, 0, 0)]));
    assert!(memfs::xattr(f, acl::DEFAULT).is_none());
    // A directory also gets the default ACL
    assert_eq!(sys(83, &[cstr("/shared/sub"), 0o777]), 0);
    let s = memfs::lookup("/shared/sub").unwrap();
    assert_eq!(memfs::attr(s).mode, 0o040770);
    assert_eq!(memfs::xattr(s, acl::DEFAULT).unwrap(), def);
    // A default ACL equivalent to a mode: no access ACL on new files
    let e = memfs::mkdir_p("/plain");
    acl::set(&memfs::attr(e), true, &acl_bytes(&[(UO, 7, 0), (GO, 5, 0), (O, 5, 0)]), 0);
    let (mode, plan) = acl::create_mode(e, 0o666, 0o077, false);
    assert_eq!(mode, 0o644);
    acl::inherit(memfs::mkfile("/plain/x", b""), plan);
    assert!(memfs::xattr(memfs::lookup("/plain/x").unwrap(), acl::ACCESS).is_none());
    // Without a default ACL: the umask applies
    let n = memfs::mkdir_p("/none");
    let (mode, plan) = acl::create_mode(n, 0o666, 0o022, false);
    assert_eq!(mode, 0o644);
    assert!(plan.is_none());
    acl::inherit(5, None);
    // A missing directory
    assert_eq!(acl::create_mode(987654321, 0o666, 0o022, false).0, 0o644);
    // Access labels pass to new files and folders
    let l = memfs::mkdir_p("/labelled");
    memfs::set_xattr(l, lx::abac::LABELS, b"L1");
    let (_, plan) = acl::create_mode(l, 0o644, 0o022, false);
    let nf = memfs::mkfile("/labelled/n", b"");
    acl::inherit(nf, plan);
    assert_eq!(memfs::xattr(nf, lx::abac::LABELS).unwrap(), b"L1");
}

#[test]
fn the_cache_follows_changes() {
    let _e = setup();
    let f = memfs::mkfile("/f", b"");
    memfs::chown(f, 10, 10);
    memfs::set_xattr(f, acl::ACCESS, &acl_bytes(&[(UO, 6, 0), (U, 4, 5), (GO, 0, 0), (M, 4, 0), (O, 0, 0)]));
    assert_eq!(acl::check(&memfs::attr(f), 5, 5, 4), Some(true));
    memfs::set_xattr(f, acl::ACCESS, &acl_bytes(&[(UO, 6, 0), (U, 0, 5), (GO, 0, 0), (M, 4, 0), (O, 0, 0)]));
    assert_eq!(acl::check(&memfs::attr(f), 5, 5, 4), Some(false));
    // Many files fill the cache, which starts over
    for _ in 0..4100 {
        let g = memfs::mkfile(&format!("/many/{}", hydra_hosttests_t26::fake::buf(1)), b"");
        memfs::set_xattr(g, b"user.a", b"1");
        assert_eq!(acl::check(&memfs::attr(g), 1, 1, 4), None);
    }
}

// ---------------------------------------------------------------- efivars

const GLOBAL: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

fn guid() -> uefi::Guid {
    efivars::parse_name(&format!("X-{}", GLOBAL)).unwrap().1
}

#[test]
fn variable_names() {
    let _e = setup();
    let (n, g) = efivars::parse_name(&format!("Boot0001-{}", GLOBAL)).unwrap();
    assert_eq!(n, "Boot0001");
    assert_eq!(efivars::file_name(&n, &g), format!("Boot0001-{}", GLOBAL));
    assert!(efivars::parse_name("short").is_none());
    assert!(efivars::parse_name(&format!("-{}", GLOBAL)).is_none());
    assert!(efivars::parse_name(&format!("BootX{}", GLOBAL)).is_none());
    assert!(efivars::parse_name("Boot-zzzzzzzz-93ca-11d2-aa0d-00e098032b8c").is_none());
}

#[test]
fn get_set_list() {
    let _e = setup();
    let g = guid();
    firmware::add("BootOrder", g, 7, &[1, 0]);
    firmware::add("Big", g, 7, &vec![5u8; 3000]);
    assert_eq!(efivars::get("BootOrder", &g).unwrap(), (7, vec![1, 0]));
    assert_eq!(efivars::get("Big", &g).unwrap().1.len(), 3000); // grown buffer
    assert_eq!(efivars::get("Missing", &g).unwrap_err(), ENOENT);
    assert_eq!(efivars::set("New", &g, 7, b"x"), Ok(()));
    assert_eq!(firmware::get("New", g).unwrap(), (7, b"x".to_vec()));
    assert_eq!(efivars::set("New", &g, 0, &[]), Ok(()));
    assert!(firmware::get("New", g).is_none());
    // A name too long for the wide buffer
    assert_eq!(efivars::get(&"n".repeat(600), &g).unwrap_err(), EINVAL);
    assert_eq!(efivars::set(&"n".repeat(600), &g, 7, b"x").unwrap_err(), EINVAL);
    // Listing, with a retry for a longer name
    *firmware::FW.name_too_small.lock() = Some(1000);
    let l = efivars::list().unwrap();
    assert_eq!(l.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(), vec!["BootOrder", "Big"]);
    let snap = efivars::snapshot().unwrap();
    assert_eq!(snap[0].0, format!("BootOrder-{}", GLOBAL));
    assert_eq!(snap[0].1, vec![7, 0, 0, 0, 1, 0]);
    // Firmware statuses as errnos
    for (s, e) in [(uefi::Status::INVALID_PARAMETER, EINVAL), (uefi::Status::WRITE_PROTECTED, EPERM), (uefi::Status::SECURITY_VIOLATION, EPERM), (uefi::Status::OUT_OF_RESOURCES, -28), (uefi::Status::DEVICE_ERROR, -5)] {
        *firmware::FW.fail_set.lock() = Some(s);
        assert_eq!(efivars::set("X", &g, 7, b"1").unwrap_err(), e);
    }
    *firmware::FW.fail_set.lock() = None;
    // No variable services: list fails at once; after some names, stops there
    *firmware::FW.fail.lock() = Some(uefi::Status::UNSUPPORTED);
    assert!(efivars::list().is_none());
    assert!(efivars::snapshot().is_none());
    *firmware::FW.fail.lock() = None;
    efivars::refresh();
    assert_eq!(hydra_hosttests_t26::fake::counter("refresh_efivars"), 1);
}

#[test]
fn list_stops_at_errors_after_names() {
    let _e = setup();
    let g = guid();
    for i in 0..3 {
        firmware::add(&format!("V{}", i), g, 7, b"1");
    }
    // An error after the first names ends the list there
    struct After;
    let l = efivars::list().unwrap();
    assert_eq!(l.len(), 3);
    let _ = After;
    // Many variables: capped
    for i in 0..4100 {
        firmware::add(&format!("M{}", i), g, 7, b"");
    }
    assert_eq!(efivars::list().unwrap().len(), 4097);
}

#[test]
fn variable_files() {
    let _e = setup();
    let g = guid();
    firmware::add("Timeout", g, 7, &[5, 0]);
    let path = format!("{}/Timeout-{}", efivars::DIR, GLOBAL);
    // Not ours
    assert!(efivars::open("/etc/x", 0).is_none());
    assert!(efivars::open(&format!("{}/sub/Timeout-{}", efivars::DIR, GLOBAL), 0).is_none());
    assert!(efivars::open(&format!("{}/bad", efivars::DIR), 0).is_none());
    // Missing without O_CREAT
    assert_eq!(efivars::open(&format!("{}/None-{}", efivars::DIR, GLOBAL), 0).unwrap().err(), Some(ENOENT));
    let f = efivars::open(&path, 0).unwrap().unwrap();
    assert_eq!(f.path(), path);
    let mut b = [0u8; 3];
    assert_eq!(f.read(&mut b), 3);
    assert_eq!(b, [7, 0, 0]);
    assert_eq!(f.read(&mut b), 3);
    assert_eq!(&b[..3], &[0, 5, 0]);
    assert_eq!(f.read(&mut b), 0);
    assert_eq!(f.write(b"1234"), -9); // read-only
    assert_eq!(f.poll_events(), 5);
    assert_eq!(f.rdev(), 0);
    assert!(!f.nonblock());
    f.set_nonblock(true);
    let st = f.stat();
    assert_eq!((st.st_mode, st.st_size, st.st_dev), (0o100644, 6, 0x2d));
    let n = buf(4);
    assert_eq!(f.ioctl(0x8008_6601, n), 0);
    assert_eq!(f.ioctl(0x8008_6601, 16), EFAULT);
    assert_eq!(f.ioctl(0x4008_6602, 0), 0);
    assert_eq!(f.ioctl(1, 0), -25);
    // Writing needs CAP_SYS_ADMIN; attributes then data in one write
    let w = efivars::open(&format!("{}/New-{}", efivars::DIR, GLOBAL), 0o101).unwrap().unwrap();
    assert_eq!(w.read(&mut b), -9);
    assert_eq!(w.write(b"12"), EINVAL);
    assert_eq!(w.write(&[7, 0, 0, 0, 9, 9]), 6);
    assert_eq!(firmware::get("New", g).unwrap(), (7, vec![9, 9]));
    *firmware::FW.fail_set.lock() = Some(uefi::Status::WRITE_PROTECTED);
    assert_eq!(w.write(&[7, 0, 0, 0, 9]), EPERM);
    *firmware::FW.fail_set.lock() = None;
    // A file whose variable went away reads as the error
    let gone = efivars::open(&format!("{}/New-{}", efivars::DIR, GLOBAL), 0).unwrap().unwrap();
    firmware::FW.vars.lock().retain(|v| v.0 != "New");
    assert_eq!(gone.read(&mut b), ENOENT);
    assert_eq!(gone.stat().st_size, 0);
    become_user(1000);
    assert_eq!(efivars::open(&path, 1).unwrap().err(), Some(EACCES));
    assert!(efivars::open(&path, 0).unwrap().is_ok());
}

#[test]
fn unlinking_deletes_the_variable() {
    let _e = setup();
    let g = guid();
    firmware::add("Old", g, 7, b"x");
    let dir = memfs::mkdir_p("/sys/firmware/efi/efivars");
    memfs::mkfile(&format!("/sys/firmware/efi/efivars/Old-{}", GLOBAL), b"");
    let name = format!("Old-{}", GLOBAL);
    // Not the efivars directory (yet)
    assert!(efivars::unlink(dir, name.as_bytes()).is_none());
    efivars::DIR_INO.store(dir, core::sync::atomic::Ordering::Relaxed);
    assert!(efivars::unlink(0, name.as_bytes()).is_none());
    assert!(efivars::unlink(dir, b"not-a-variable").is_none());
    // Through unlink(2): the variable and the file go
    assert_eq!(sys(87, &[cstr(&format!("/sys/firmware/efi/efivars/{}", name))]), 0);
    assert!(firmware::get("Old", g).is_none());
    assert!(memfs::lookup(&format!("/sys/firmware/efi/efivars/{}", name)).is_none());
    // A variable already gone is fine; a firmware error is reported
    assert_eq!(efivars::unlink(dir, name.as_bytes()), Some(Ok(())));
    firmware::add("Old", g, 7, b"x");
    *firmware::FW.fail_set.lock() = Some(uefi::Status::DEVICE_ERROR);
    assert_eq!(efivars::unlink(dir, name.as_bytes()), Some(Err(-5)));
    memfs::mkfile(&format!("/sys/firmware/efi/efivars/{}", name), b"");
    assert_eq!(sys(87, &[cstr(&format!("/sys/firmware/efi/efivars/{}", name))]), -5);
    *firmware::FW.fail_set.lock() = None;
    become_user(1000);
    assert_eq!(efivars::unlink(dir, name.as_bytes()), Some(Err(EACCES)));
    efivars::DIR_INO.store(0, core::sync::atomic::Ordering::Relaxed);
}

#[test]
fn open_through_the_vfs() {
    let _e = setup();
    let g = guid();
    firmware::add("Lang", g, 7, b"en");
    let fd = open(&format!("/sys/firmware/efi/efivars/Lang-{}", GLOBAL), O_RDONLY);
    assert!(fd >= 0);
    assert!(matches!(desc(fd), Some(FileDescriptor::Device(_))));
}

#[test]
fn live_session_flag() {
    let _e = setup();
    assert!(!lx::live::is_live());
    hydra_hosttests_t26::fake::arch::LIVE.set(true);
    assert!(lx::live::is_live());
}
