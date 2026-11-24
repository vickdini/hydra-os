//! fuse.rs after wave 9's closing (Group 9-C): the kernel's own FUSE client is gone; what is
//! left is the inode numbering, the initial namespace's mount list, mount(2) of a vfs-server
//! connection and the forwarders (the host's `fuse_svc` stub answers ENOTCONN).
mod common;
use common::*;
use lx::fuse;

/// A FUSE inode of a vfs-server connection (`FUSE_SVC_CONN` 0x8000 and up).
const REMOTE: u64 = 1 << 62 | 0x8001 << 40 | 5;
/// A FUSE inode of a kernel connection number (none exists any more).
const LOCAL: u64 = 1 << 62 | 1 << 40 | 5;

#[test]
fn only_vfs_server_inodes_are_served() {
    let _e = setup();
    assert!(fuse::is_fuse(REMOTE) && fuse::is_fuse(LOCAL) && !fuse::is_fuse(5));
    // a kernel connection's inode: nobody serves it
    assert_eq!(fuse::getattr(LOCAL).unwrap_err(), -107);
    assert_eq!(fuse::lookup(LOCAL, b"x").unwrap_err(), -107);
    assert_eq!(fuse::readlink(LOCAL).unwrap_err(), -107);
    assert_eq!(fuse::read(LOCAL, 0, &mut [0u8; 4]).unwrap_err(), -107);
    assert_eq!(fuse::write(LOCAL, 0, b"x").unwrap_err(), -107);
    assert_eq!(fuse::readdir(LOCAL, 0, 8).err(), Some(-107));
    assert_eq!(fuse::create(LOCAL, b"x", 0o644).unwrap_err(), -107);
    assert_eq!(fuse::mkdir(LOCAL, b"x", 0o755).unwrap_err(), -107);
    assert_eq!(fuse::unlink(LOCAL, b"x").unwrap_err(), -107);
    assert_eq!(fuse::statfs(LOCAL).unwrap_err(), -107);
    assert_eq!(fuse::getxattr(LOCAL, b"user.x").unwrap_err(), -107);
    assert!(fuse::name_of(LOCAL).is_none());
    assert_eq!(fuse::user_ino(LOCAL), 5);
    // vfs-server's: forwarded (the stub answers ENOTCONN)
    assert_eq!(fuse::getattr(REMOTE).unwrap_err(), -107);
    assert_eq!(fuse::user_ino(REMOTE), 5);
    // links and renames stay within one of vfs-server's connections
    assert_eq!(fuse::link(LOCAL, REMOTE, b"x").unwrap_err(), -18);
    assert_eq!(fuse::rename(REMOTE, b"a", 7, b"b").unwrap_err(), -18);
    // open references of anything but vfs-server's are ignored
    fuse::open_ref(LOCAL);
    fuse::release(LOCAL);
}

#[test]
fn the_initial_namespaces_mount_list() {
    let _e = setup();
    let root = 1u64 << 62 | 0x8002 << 40 | 1;
    assert!(!fuse::ns0_any());
    fuse::ns0_add(fuse::Ns0Mount { mountpoint: 77, root, path: "/run/user/1000/doc".into(), fstype: "fuse.portal".into(), source: "portal".into(), opts: "rw,nosuid,nodev,relatime,user_id=1000,group_id=1000".into(), flags: 6 });
    assert!(fuse::ns0_any());
    assert_eq!(fuse::ns0_list(), vec![(77, root, 0)]);
    assert_eq!(fuse::ns0_mnt_of(root | 9), 1);
    assert_eq!(fuse::ns0_mnt_of(5), 0);
    assert_eq!(fuse::ns0_mountpoint(root), Some(77));
    assert!(fuse::ns0_mounts_text().starts_with("portal /run/user/1000/doc fuse.portal rw,nosuid"));
    assert!(fuse::ns0_mountinfo_text().contains(" /run/user/1000/doc rw,nosuid,nodev,relatime - fuse.portal portal "));
    assert!(fuse::ns0_remove(root));
    assert!(!fuse::ns0_remove(root));
    assert!(!fuse::ns0_any());
}

#[test]
fn mount_takes_only_vfs_servers_dev_fuse() {
    let _e = setup();
    // options missing
    assert_eq!(fuse::mount("/m", 7, "fuse.x", "x", 0, "fd=3", true).unwrap_err(), -22);
    // a descriptor that is not open
    assert_eq!(fuse::mount("/m", 7, "fuse.x", "x", 0, "fd=600,rootmode=40000,user_id=0,group_id=0", true).unwrap_err(), -9);
    // a device that is not vfs-server's /dev/fuse
    let d: std::sync::Arc<dyn lx::chardev::CharDevice> = std::sync::Arc::new(lx::chardev::TestDev::new("/dev/x", 0));
    let fd = install(FileDescriptor::Device(d));
    let opts = format!("fd={},rootmode=40000,user_id=0,group_id=0", fd);
    assert_eq!(fuse::mount("/m", 7, "fuse.x", "x", 0, &opts, true).unwrap_err(), -22);
    assert!(!fuse::ns0_any());
    assert!(fuse::is_fuse_type("fuse") && fuse::is_fuse_type("fuse.sshfs") && !fuse::is_fuse_type("fusectl"));
}
