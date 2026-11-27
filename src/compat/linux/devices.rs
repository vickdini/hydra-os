//! # Device nodes, sysfs and the udev database for a Linux root
//!
//! What devtmpfs, sysfs and udev provide on Linux, written into the Linux root as ordinary
//! files before its programs start ([`populate`]):
//!
//! - `/dev/dri/card0` and `/dev/input/event0`/`event1`: character device nodes whose
//!   numbers open the drivers in [`super::drm`] and [`super::evdev`].
//! - `/sys/devices/...`, `/sys/class/{drm,input}`, `/sys/bus/...` and `/sys/dev/char`: the
//!   device tree libudev and libdrm walk, with `uevent`, `dev`, identity and capability
//!   attributes and the `subsystem`/`device`/`driver` links.
//! - `/run/udev/data/c<major>:<minor>`: the udev database records that mark the devices
//!   initialized and classify them (`ID_INPUT_KEYBOARD`, `ID_INPUT_MOUSE`, seat tags).
//!
//! The devices are fixed at boot, so the files are a snapshot; they are rewritten only
//! when their content differs.

use alloc::string::String;
use alloc::vec::Vec;

use crate::fs::zfs::ZfsServer;

const ENOENT: i64 = -2;
const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFCHR: u32 = 0o020000;

/// PCI identity of the display adapter: (slot name, vendor, device, subsystem vendor,
/// subsystem device, revision, class).
struct Vga {
    slot: String,
    vendor: u16,
    device: u16,
    sub_vendor: u16,
    sub_device: u16,
    revision: u8,
}

/// Probes PCI bus for display adapter or returns fallback VGA controller details.
///
/// # Returns
///
/// Populated [`Vga`] descriptor.
fn vga() -> Vga {
    use crate::arch::pci;
    match pci::find_class(0x03, 0x00) {
        Some(d) => {
            let sub = pci::pci_read_u32(d.bus, d.device, d.function, 0x2C);
            Vga {
                slot: alloc::format!("0000:{:02x}:{:02x}.{}", d.bus, d.device, d.function),
                vendor: d.vendor_id,
                device: d.device_id,
                sub_vendor: sub as u16,
                sub_device: (sub >> 16) as u16,
                revision: pci::pci_read_u8(d.bus, d.device, d.function, pci::PCI_REG_REVISION),
            }
        }
        None => Vga { slot: String::from("0000:00:02.0"), vendor: 0x1234, device: 0x1111, sub_vendor: 0x1af4, sub_device: 0x1100, revision: 2 },
    }
}

/// PCI slot name of the display adapter (`DRM_IOCTL_GET_UNIQUE`).
///
/// # Returns
///
/// PCI slot identifier string (e.g. `"0000:00:02.0"`).
pub fn vga_slot() -> String {
    vga().slot
}

/// Writes files under one root, remembering whether anything changed.
struct Tree {
    root: u64,
    changed: bool,
    /// Path of the operation in progress (named when one fails).
    at: String,
}

/// Splits a path into its parent directory string and final filename component.
///
/// # Arguments
///
/// * `path` - Path string to split.
///
/// # Returns
///
/// `(parent_dir, file_name)` tuple.
fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

impl Tree {
    /// Ensures directory hierarchy exists under tree root, returning final directory inode.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Directory path relative to root.
    ///
    /// # Returns
    ///
    /// Directory inode number on success, or a negative Linux errno on error.
    fn dir(&mut self, s: &mut ZfsServer, path: &str) -> Result<u64, i64> {
        self.at = String::from(path);
        let mut ino = self.root;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            let next = match s.lookup(ino, comp.as_bytes()) {
                Ok(i) => i,
                Err(ENOENT) => {
                    self.changed = true;
                    s.mkdir(ino, comp.as_bytes(), 0o755, 0, 0)?
                }
                Err(e) => return Err(e),
            };
            if let Ok(attr) = s.getattr(next) {
                if attr.mode & S_IFMT == S_IFLNK {
                    if let Ok(target) = s.readlink(next) {
                        if let Ok(t_str) = core::str::from_utf8(&target) {
                            let base = if t_str.starts_with('/') { self.root } else { ino };
                            if let Some(resolved) = lookup_path(s, base, t_str) {
                                ino = resolved;
                                continue;
                            }
                        }
                    }
                }
            }
            ino = next;
        }
        Ok(ino)
    }

    /// The entry `name` in `dir` if it has file type `ty`; anything else there is removed.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `dir` - Parent directory inode number.
    /// * `name` - Child name to look up.
    /// * `ty` - Expected file type bits (`S_IFREG`, `S_IFLNK`, `S_IFCHR`).
    ///
    /// # Returns
    ///
    /// Inode number if matching entry exists, `None` if not found or unlinked, or negative errno on error.
    fn existing(&mut self, s: &mut ZfsServer, dir: u64, name: &str, ty: u32) -> Result<Option<u64>, i64> {
        match s.lookup(dir, name.as_bytes()) {
            Ok(i) if s.getattr(i)?.mode & S_IFMT == ty => Ok(Some(i)),
            Ok(_) => {
                self.changed = true;
                s.unlink(dir, name.as_bytes())?;
                Ok(None)
            }
            Err(ENOENT) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Creates or updates a UTF-8 text file with mode 0644.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Target file path.
    /// * `content` - String text content to write.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative Linux errno on error.
    fn file(&mut self, s: &mut ZfsServer, path: &str, content: &str) -> Result<(), i64> {
        self.file_bytes(s, path, content.as_bytes(), 0o644)
    }

    /// Creates or updates a binary file with specified permissions.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Target file path.
    /// * `content` - Raw bytes to write.
    /// * `perm` - File mode permission bits.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative Linux errno on error.
    fn file_bytes(&mut self, s: &mut ZfsServer, path: &str, content: &[u8], perm: u32) -> Result<(), i64> {
        self.at = String::from(path);
        let (parent, name) = split(path);
        let dir = self.dir(s, parent)?;
        let ino = match self.existing(s, dir, name, S_IFREG)? {
            Some(i) => {
                if s.getattr(i)?.size == content.len() as u64 {
                    let mut cur = alloc::vec![0u8; content.len()];
                    if s.read(i, 0, &mut cur)? == cur.len() && cur == content && s.getattr(i)?.mode & 0o7777 == perm {
                        return Ok(());
                    }
                }
                s.setattr(i, crate::fs::zfs::zpl::SetAttr { size: Some(0), mode: Some(perm), ..Default::default() })?;
                i
            }
            None => s.create(dir, name.as_bytes(), perm, 0, 0)?,
        };
        self.changed = true;
        s.write(ino, 0, content)?;
        Ok(())
    }

    /// Writes a default that administrators may edit (a file in /etc): only when it is missing
    /// or still exactly one of Hydra's earlier versions of it, so their own edits stay.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Target file path.
    /// * `content` - Hydra's current version.
    /// * `earlier` - Hydra's earlier versions, replaced by the current one.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative Linux errno on error.
    fn default_file(&mut self, s: &mut ZfsServer, path: &str, content: &str, earlier: &[&str]) -> Result<(), i64> {
        if let Some(ino) = lookup_path(s, self.root, path) {
            let size = s.getattr(ino)?.size as usize;
            if !earlier.iter().any(|e| e.len() == size) {
                return Ok(());
            }
            let mut cur = alloc::vec![0u8; size];
            let n = s.read(ino, 0, &mut cur)?;
            if !earlier.iter().any(|e| e.as_bytes() == &cur[..n]) {
                return Ok(());
            }
        }
        self.file(s, path, content)
    }

    /// Creates or updates a symbolic link pointing to `target`.
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Symlink location.
    /// * `target` - Symlink target path string.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative Linux errno on error.
    fn link(&mut self, s: &mut ZfsServer, path: &str, target: &str) -> Result<(), i64> {
        self.at = String::from(path);
        let (parent, name) = split(path);
        let dir = self.dir(s, parent)?;
        if let Some(i) = self.existing(s, dir, name, S_IFLNK)? {
            if s.readlink(i)? == target.as_bytes() {
                return Ok(());
            }
            s.unlink(dir, name.as_bytes())?;
        }
        self.changed = true;
        s.symlink(dir, name.as_bytes(), target.as_bytes(), 0, 0)?;
        Ok(())
    }

    /// Creates or updates a character device node (`S_IFCHR`).
    ///
    /// # Arguments
    ///
    /// * `s` - Active ZFS server reference.
    /// * `path` - Node path to create.
    /// * `rdev` - 64-bit device number.
    /// * `gid` - Group ownership ID.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a negative Linux errno on error.
    fn node(&mut self, s: &mut ZfsServer, path: &str, rdev: u64, gid: u32) -> Result<(), i64> {
        self.node_mode(s, path, rdev, gid, 0o660)
    }

    /// [`Self::node`] with permissions `perm`.
    fn node_mode(&mut self, s: &mut ZfsServer, path: &str, rdev: u64, gid: u32, perm: u32) -> Result<(), i64> {
        self.node_kind(s, path, rdev, gid, perm, S_IFCHR)
    }

    /// A block device node (`S_IFBLK`), mode 0660.
    fn block_node(&mut self, s: &mut ZfsServer, path: &str, rdev: u64, gid: u32) -> Result<(), i64> {
        self.node_kind(s, path, rdev, gid, 0o660, 0o060000)
    }

    /// A device node of type `kind` (`S_IFCHR` or `S_IFBLK`).
    fn node_kind(&mut self, s: &mut ZfsServer, path: &str, rdev: u64, gid: u32, perm: u32, kind: u32) -> Result<(), i64> {
        self.at = String::from(path);
        let (parent, name) = split(path);
        let dir = self.dir(s, parent)?;
        if let Some(i) = self.existing(s, dir, name, kind)? {
            let a = s.getattr(i)?;
            // A boot starts with root owning every node (the seat daemon hands some out)
            if a.rdev == rdev && a.uid == 0 && a.gid == gid && a.mode & 0o777 == perm {
                return Ok(());
            }
            s.unlink(dir, name.as_bytes())?;
        }
        self.changed = true;
        s.mknod(dir, name.as_bytes(), kind | perm, rdev, 0, gid)?;
        Ok(())
    }
}

/// Looks `path` up below directory `root`, following symbolic links up to 16 hops.
///
/// # Arguments
///
/// * `s` - Active ZFS server reference.
/// * `root` - Starting root inode number.
/// * `path` - Slash-separated path.
///
/// # Returns
///
/// `Some(inode)` if found, or `None`.
fn lookup_path(s: &mut ZfsServer, root: u64, path: &str) -> Option<u64> {
    lookup_path_hops(s, root, path, 0)
}

fn lookup_path_hops(s: &mut ZfsServer, root: u64, path: &str, hops: u32) -> Option<u64> {
    if hops > 16 {
        return None;
    }
    let mut ino = root;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let next = s.lookup(ino, comp.as_bytes()).ok()?;
        if let Ok(attr) = s.getattr(next) {
            if attr.mode & S_IFMT == S_IFLNK {
                if let Ok(target) = s.readlink(next) {
                    if let Ok(t_str) = core::str::from_utf8(&target) {
                        let base = if t_str.starts_with('/') { root } else { ino };
                        ino = lookup_path_hops(s, base, t_str, hops + 1)?;
                        continue;
                    }
                }
            }
        }
        ino = next;
    }
    Some(ino)
}

/// Group id of `name` in the root's `/etc/group` (`fallback` if absent).
///
/// # Arguments
///
/// * `s` - Active ZFS server reference.
/// * `root` - Root inode number.
/// * `name` - Group name to query.
/// * `fallback` - Default GID if not found.
///
/// # Returns
///
/// Discovered GID or `fallback`.
fn group_id(s: &mut ZfsServer, root: u64, name: &str, fallback: u32) -> u32 {
    let ino = match lookup_path(s, root, "/etc/group") {
        Some(i) => i,
        None => return fallback,
    };
    let size = s.getattr(ino).map(|a| a.size).unwrap_or(0) as usize;
    let mut buf = alloc::vec![0u8; size.min(64 * 1024)];
    let n = s.read(ino, 0, &mut buf).unwrap_or(0);
    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
    text.lines()
        .filter_map(|l| {
            let mut f = l.split(':');
            (f.next()? == name).then(|| f.nth(1)?.parse().ok()).flatten()
        })
        .next()
        .unwrap_or(fallback)
}

/// A capability bitmap as sysfs prints it: 64-bit words in hex, most significant first.
///
/// # Arguments
///
/// * `bytes` - Raw capability bitmap byte slice.
///
/// # Returns
///
/// Hex-formatted sysfs string representation.
fn bitmap_words(bytes: &[u8]) -> String {
    let words: Vec<u64> = bytes
        .chunks(8)
        .map(|c| {
            let mut w = [0u8; 8];
            w[..c.len()].copy_from_slice(c);
            u64::from_le_bytes(w)
        })
        .collect();
    let top = match words.iter().rposition(|&w| w != 0) {
        Some(t) => t,
        None => return String::from("0"),
    };
    let mut out = String::new();
    for (i, w) in words[..=top].iter().rev().enumerate() {
        if i > 0 {
            out.push(' ');
        }
        out.push_str(&alloc::format!("{:x}", w));
    }
    out
}

/// Event codes set in a bitmap, as `MODALIAS` lists them.
///
/// # Arguments
///
/// * `bytes` - Raw bitmap byte slice.
///
/// # Returns
///
/// Comma-separated hex list of set bit indexes.
fn bit_list(bytes: &[u8]) -> String {
    let mut out = String::new();
    for bit in 0..bytes.len() * 8 {
        if bytes[bit / 8] & (1 << (bit % 8)) != 0 {
            out.push_str(&alloc::format!("{:x},", bit));
        }
    }
    out
}

/// Populates all sysfs device directories, uevent files, and dev nodes.
///
/// # Arguments
///
/// * `t` - Active filesystem tree builder.
/// * `s` - Active ZFS server reference.
///
/// # Returns
///
/// `Ok(())` on success, or a negative Linux errno on error.
fn populate_tree(t: &mut Tree, s: &mut ZfsServer) -> Result<(), i64> {
    let video = group_id(s, t.root, "video", 44);
    let input = group_id(s, t.root, "input", 106);
    let usec = 1_000_000u64; // "initialized" one second after boot

    // ---- DRM: the display adapter and card0 ----
    let v = vga();
    let pci = alloc::format!("/sys/devices/pci0000:00/{}", v.slot);
    t.file(s, "/sys/devices/pci0000:00/uevent", "")?;
    t.file(
        s,
        &alloc::format!("{}/uevent", pci),
        &alloc::format!(
            "DRIVER=hydradrm\nPCI_CLASS=30000\nPCI_ID={:04X}:{:04X}\nPCI_SUBSYS_ID={:04X}:{:04X}\nPCI_SLOT_NAME={}\nMODALIAS=pci:v{:08X}d{:08X}sv{:08X}sd{:08X}bc03sc00i00\n",
            v.vendor, v.device, v.sub_vendor, v.sub_device, v.slot, v.vendor, v.device, v.sub_vendor, v.sub_device
        ),
    )?;
    for (name, value) in [
        ("vendor", alloc::format!("0x{:04x}\n", v.vendor)),
        ("device", alloc::format!("0x{:04x}\n", v.device)),
        ("subsystem_vendor", alloc::format!("0x{:04x}\n", v.sub_vendor)),
        ("subsystem_device", alloc::format!("0x{:04x}\n", v.sub_device)),
        ("revision", alloc::format!("0x{:02x}\n", v.revision)),
        ("class", String::from("0x030000\n")),
        ("boot_vga", String::from("1\n")),
        ("enable", String::from("1\n")),
    ] {
        t.file(s, &alloc::format!("{}/{}", pci, name), &value)?;
    }
    t.link(s, &alloc::format!("{}/subsystem", pci), "../../../bus/pci")?;
    t.link(s, &alloc::format!("{}/driver", pci), "../../../bus/pci/drivers/hydradrm")?;
    t.dir(s, "/sys/bus/pci/drivers/hydradrm")?;
    t.link(s, &alloc::format!("/sys/bus/pci/devices/{}", v.slot), &alloc::format!("../../../devices/pci0000:00/{}", v.slot))?;

    let card = alloc::format!("{}/drm/card0", pci);
    t.file(s, &alloc::format!("{}/uevent", card), "MAJOR=226\nMINOR=0\nDEVNAME=dri/card0\nDEVTYPE=drm_minor\n")?;
    t.file(s, &alloc::format!("{}/dev", card), "226:0\n")?;
    t.link(s, &alloc::format!("{}/subsystem", card), "../../../../../class/drm")?;
    t.link(s, &alloc::format!("{}/device", card), &alloc::format!("../../../{}", v.slot))?;
    t.file(s, "/sys/class/drm/version", "drm 1.1.0 20060810\n")?;
    // The cgroup v2 mount point (its cgroup.procs files are the kernel's)
    t.dir(s, super::fs::CGROUP_ROOT)?;
    t.link(s, "/sys/class/drm/card0", &alloc::format!("../../devices/pci0000:00/{}/drm/card0", v.slot))?;
    t.link(s, "/sys/dev/char/226:0", &alloc::format!("../../devices/pci0000:00/{}/drm/card0", v.slot))?;
    t.node(s, "/dev/dri/card0", super::chardev::makedev(226, 0), video)?;
    // FUSE: anyone may open it (fusermount3 mounts for users); fusermount3 reads the
    // mount table as /etc/mtab
    t.node_mode(s, "/dev/fuse", super::fuse::RDEV, 0, 0o666)?;
    // wave10 GV2 begin: the devices the kernel served by name are nodes like the others
    // (vfs-server walks /dev in the pool and opens a device by its number; Linux's modes and
    // owners); /dev/pts is the terminal service's (redirected at lookup), its directory is
    // here for listings
    let tty = group_id(s, t.root, "tty", 5);
    for (name, major, minor, gid, perm) in [
        ("null", 1, 3, 0, 0o666),
        ("zero", 1, 5, 0, 0o666),
        ("full", 1, 7, 0, 0o666),
        ("random", 1, 8, 0, 0o666),
        ("urandom", 1, 9, 0, 0o666),
        ("tty", 5, 0, tty, 0o666),
        ("console", 5, 1, 0, 0o600),
        ("ptmx", 5, 2, tty, 0o666),
    ] {
        t.node_mode(s, &alloc::format!("/dev/{}", name), super::chardev::makedev(major, minor), gid, perm)?;
    }
    for n in 0..64u64 {
        t.node_mode(s, &alloc::format!("/dev/tty{}", n), super::chardev::makedev(4, n), tty, 0o620)?;
    }
    t.dir(s, "/dev/pts")?;
    // (review 3: the cpu ranges as files too, so a walk relative to the cpu directory finds
    // them; an absolute path is still linux-server's, which shows the same text)
    let n = crate::arch::smp::online();
    let range = if n > 1 { alloc::format!("0-{}\n", n - 1) } else { String::from("0\n") };
    for f in ["online", "possible", "present"] {
        t.file(s, &alloc::format!("/sys/devices/system/cpu/{}", f), &range)?;
    }
    // wave10 GV2 end
    t.link(s, "/etc/mtab", "../proc/self/mounts")?;
    let path_tag: String = v.slot.chars().map(|c| if c == ':' || c == '.' { '_' } else { c }).collect();
    t.link(s, &alloc::format!("/dev/dri/by-path/pci-{}-card", v.slot), "../card0")?;
    t.file(
        s,
        "/run/udev/data/c226:0",
        &alloc::format!(
            "I:{}\nE:ID_PATH=pci-{}\nE:ID_PATH_TAG=pci-{}\nE:ID_FOR_SEAT=drm-pci-{}\nG:seat\nG:master-of-seat\nG:uaccess\nQ:seat\nQ:master-of-seat\nQ:uaccess\nV:1\n",
            usec, v.slot, path_tag, path_tag
        ),
    )?;

    // ---- Input: the i8042 keyboard (event0) and mouse (event1), and under QEMU the
    // absolute pointer behind the mouse (event2, on the mouse's port as on Linux) ----
    t.file(s, "/sys/devices/platform/uevent", "")?;
    t.file(s, "/sys/devices/platform/i8042/uevent", "DRIVER=i8042\nMODALIAS=platform:i8042\n")?;
    t.link(s, "/sys/devices/platform/i8042/subsystem", "../../../bus/platform")?;
    for dev in 0..super::evdev::device_count() {
        let (name, phys, id) = super::evdev::device_info(dev);
        let port = dev.min(1);
        let serio = alloc::format!("/sys/devices/platform/i8042/serio{}", port);
        let input_dir = alloc::format!("{}/input/input{}", serio, dev);
        let event_dir = alloc::format!("{}/event{}", input_dir, dev);
        let minor = 64 + dev as u64;
        t.file(
            s,
            &alloc::format!("{}/uevent", serio),
            &alloc::format!("DRIVER={}\nSERIO_TYPE=06\nSERIO_PROTO=00\nSERIO_ID=00\nSERIO_EXTRA=00\nMODALIAS=serio:ty06pr00id00ex00\n", if dev == 0 { "atkbd" } else { "psmouse" }),
        )?;
        t.link(s, &alloc::format!("{}/subsystem", serio), "../../../../bus/serio")?;

        let caps: Vec<(u16, &str)> = alloc::vec![(0, "ev"), (1, "key"), (2, "rel"), (3, "abs"), (4, "msc"), (5, "sw"), (0x11, "led"), (0x12, "snd"), (0x15, "ff")];
        let mut uevent = alloc::format!(
            "PRODUCT={:x}/{:x}/{:x}/{:x}\nNAME=\"{}\"\nPHYS=\"{}\"\nPROP=0\n",
            id[0], id[1], id[2], id[3], name, phys
        );
        let mut modalias = alloc::format!("input:b{:04X}v{:04X}p{:04X}e{:04X}-", id[0], id[1], id[2], id[3]);
        for (ty, letter) in [(0u16, 'e'), (1, 'k'), (2, 'r'), (3, 'a'), (4, 'm'), (0x11, 'l'), (0x12, 's'), (0x15, 'f'), (5, 'w')] {
            modalias.push(letter);
            modalias.push_str(&bit_list(&super::evdev::capabilities(dev, ty)).to_uppercase());
        }
        for (ty, file) in caps {
            let bytes = super::evdev::capabilities(dev, ty);
            let words = bitmap_words(&bytes);
            t.file(s, &alloc::format!("{}/capabilities/{}", input_dir, file), &alloc::format!("{}\n", words))?;
            if words != "0" {
                uevent.push_str(&alloc::format!("{}={}\n", file.to_uppercase(), words));
            }
        }
        uevent.push_str(&alloc::format!("MODALIAS={}\n", modalias));
        t.file(s, &alloc::format!("{}/uevent", input_dir), &uevent)?;
        t.file(s, &alloc::format!("{}/name", input_dir), &alloc::format!("{}\n", name))?;
        t.file(s, &alloc::format!("{}/phys", input_dir), &alloc::format!("{}\n", phys))?;
        t.file(s, &alloc::format!("{}/uniq", input_dir), "\n")?;
        t.file(s, &alloc::format!("{}/properties", input_dir), "0\n")?;
        t.file(s, &alloc::format!("{}/modalias", input_dir), &alloc::format!("{}\n", modalias))?;
        for (file, value) in [("bustype", id[0]), ("vendor", id[1]), ("product", id[2]), ("version", id[3])] {
            t.file(s, &alloc::format!("{}/id/{}", input_dir, file), &alloc::format!("{:04x}\n", value))?;
        }
        t.link(s, &alloc::format!("{}/subsystem", input_dir), "../../../../../../class/input")?;
        t.link(s, &alloc::format!("{}/device", input_dir), "../../../serio")?;

        t.file(s, &alloc::format!("{}/uevent", event_dir), &alloc::format!("MAJOR=13\nMINOR={}\nDEVNAME=input/event{}\n", minor, dev))?;
        t.file(s, &alloc::format!("{}/dev", event_dir), &alloc::format!("13:{}\n", minor))?;
        t.link(s, &alloc::format!("{}/subsystem", event_dir), "../../../../../../../class/input")?;
        t.link(s, &alloc::format!("{}/device", event_dir), &alloc::format!("../../input{}", dev))?;
        let rel = alloc::format!("../../devices/platform/i8042/serio{}/input/input{}", port, dev);
        t.link(s, &alloc::format!("/sys/class/input/input{}", dev), &rel)?;
        t.link(s, &alloc::format!("/sys/class/input/event{}", dev), &alloc::format!("{}/event{}", rel, dev))?;
        t.link(s, &alloc::format!("/sys/dev/char/13:{}", minor), &alloc::format!("{}/event{}", rel, dev))?;
        t.node(s, &alloc::format!("/dev/input/event{}", dev), super::chardev::makedev(13, minor), input)?;
        // wave8 GH: the same record announces the device again after an input service crash
        let rec = input_record(dev, usec);
        t.file(s, &alloc::format!("/run/udev/data/{}", rec.db_name()), &rec.db_text())?;
        if dev < 2 {
            t.link(s, &alloc::format!("/dev/input/by-path/platform-i8042-serio-{}-event-{}", dev, if dev == 0 { "kbd" } else { "mouse" }), &alloc::format!("../event{}", dev))?;
        }
    }
    t.dir(s, "/sys/bus/serio/devices")?;
    t.dir(s, "/sys/bus/platform/devices")?;
    // ---- Sound: the ALSA card (see sound_tree) ----
    sound_tree(t, s, usec)?;

    // udev is "running": libudev's monitor stays enabled when this exists
    t.file(s, "/run/udev/control", "")?;

    // ---- What systemd-tmpfiles creates at boot: sockets of X11 (Xwayland) and ICE ----
    let tmp_ino = t.dir(s, "/tmp")?;
    if s.getattr(tmp_ino)?.mode & 0o7777 != 0o1777 {
        s.setattr(tmp_ino, crate::fs::zfs::zpl::SetAttr { mode: Some(0o1777), ..Default::default() })?;
        t.changed = true;
    }
    // Clean up stale SDDM auth sockets and runtime files from previous unclean boots
    if let Ok(entries) = s.readdir(tmp_ino, 0, 128) {
        for entry in entries {
            if entry.name.starts_with(b"sddm-") || entry.name.starts_with(b".sddm-") {
                let _ = s.unlink(tmp_ino, &entry.name);
                t.changed = true;
            }
        }
    }

    // Clean up /run/sddm and ensure permissions
    let _ = t.dir(s, "/run/sddm");
    if let Some(run_sddm) = lookup_path(s, t.root, "/run/sddm") {
        let _ = s.setattr(run_sddm, crate::fs::zfs::zpl::SetAttr { mode: Some(0o755), uid: Some(101), gid: Some(101), ..Default::default() });
        if let Ok(entries) = s.readdir(run_sddm, 0, 128) {
            for entry in entries {
                let _ = s.unlink(run_sddm, &entry.name);
                t.changed = true;
            }
        }
    }

    // Ensure /var/lib/sddm has correct ownership (sddm:sddm, 101:101)
    let _ = t.dir(s, "/var/lib");
    let sddm_home = t.dir(s, "/var/lib/sddm")?;
    if s.getattr(sddm_home)?.uid != 101 {
        let _ = s.setattr(sddm_home, crate::fs::zfs::zpl::SetAttr { mode: Some(0o750), uid: Some(101), gid: Some(101), ..Default::default() });
        t.changed = true;
    }

    // Ensure /run/user/101 exists with correct mode and ownership
    let _ = t.dir(s, "/run/user");
    let u101 = t.dir(s, "/run/user/101")?;
    if s.getattr(u101)?.uid != 101 || s.getattr(u101)?.mode & 0o7777 != 0o700 {
        let _ = s.setattr(u101, crate::fs::zfs::zpl::SetAttr { mode: Some(0o700), uid: Some(101), gid: Some(101), ..Default::default() });
        t.changed = true;
    }

    for d in ["/tmp/.X11-unix", "/tmp/.ICE-unix"] {
        let ino = t.dir(s, d)?;
        if s.getattr(ino)?.mode & 0o7777 != 0o1777 {
            s.setattr(ino, crate::fs::zfs::zpl::SetAttr { mode: Some(0o1777), ..Default::default() })?;
            t.changed = true;
        }
    }
    // The audio/video server, started by systemd user units on a real system: autostart
    // entries start it with the session (TryExec skips them when PipeWire is missing)
    for (name, exec, phase) in [("pipewire", "pipewire", 0), ("wireplumber", "wireplumber", 1), ("pipewire-pulse", "pipewire-pulse", 1)] {
        t.file(
            s,
            &alloc::format!("/etc/xdg/autostart/hydra-{}.desktop", name),
            &alloc::format!(
                "[Desktop Entry]
# Written by Hydra: no systemd user manager starts this
Type=Application
Name={}
Exec={}
TryExec={}
NoDisplay=true
X-KDE-autostart-phase={}
",
                name, exec, exec, phase
            ),
        )?;
    }
    // Sessions start at the login screen, with a password: the screen locks on idle as on
    // Ubuntu. Remove the override older Hydra versions wrote (sessions had no password)
    if let (Some(dir), Some(ino)) = (lookup_path(s, t.root, "/etc/xdg"), lookup_path(s, t.root, "/etc/xdg/kscreenlockerrc")) {
        let mut head = [0u8; 18];
        let n = s.read(ino, 0, &mut head)?;
        if &head[..n] == b"# Written by Hydra" {
            s.unlink(dir, b"kscreenlockerrc")?;
            t.changed = true;
        }
    }
    // Plasma starts through systemd user units by default; there is no systemd here
    if lookup_path(s, t.root, "/etc/xdg/startkderc").is_none() {
        t.file(s, "/etc/xdg/startkderc", "# Written by Hydra: no systemd user manager, start Plasma directly
[General]
systemdBoot=false
")?;
    }

    // The display manager: a Wayland greeter on KWin (software rendering, as the sessions)
    if lookup_path(s, t.root, "/usr/bin/sddm").is_some() && lookup_path(s, t.root, "/etc/sddm.conf.d/hydra.conf").is_none() {
        t.dir(s, "/etc/sddm.conf.d")?;
        t.file(s, "/etc/sddm.conf.d/hydra.conf", "# Written by Hydra: the greeter runs on KWin under Wayland
[General]
DisplayServer=wayland

[Wayland]
CompositorCommand=kwin_wayland --drm --no-lockscreen --no-global-shortcuts --locale1

[Theme]
Current=breeze
CursorTheme=breeze_cursors

[Users]
MinimumUid=1000
MaximumUid=60000
")?;
    }
    // Every session (and the greeter) composites in software and uses the Breeze cursor
    if let Some(ino) = lookup_path(s, t.root, "/etc/environment") {
        let size = s.getattr(ino)?.size as usize;
        let mut env = alloc::vec![0u8; size];
        let n = s.read(ino, 0, &mut env)?;
        env.truncate(n);
        if !env.windows(12).any(|w| w == b"KWIN_COMPOSE") {
            if !env.is_empty() && !env.ends_with(b"\n") {
                env.push(b'\n');
            }
            env.extend_from_slice(b"# Added by Hydra: no GPU acceleration\nKWIN_COMPOSE=Q\nXCURSOR_THEME=breeze_cursors\n");
            t.file_bytes(s, "/etc/environment", &env, 0o644)?;
        }
    }

    // ---- The login manager and the script that starts a graphical session ----
    t.file(s, "/usr/share/dbus-1/system.d/org.freedesktop.login1.conf", include_str!("../../../userland/hydra-logind/org.freedesktop.login1.conf"))?;
    t.file_bytes(s, "/usr/libexec/hydra-session", include_bytes!("../../../userland/hydra-logind/hydra-session"), 0o755)?;
    if let Some(logind) = boot_binary(s, "/bin/hydra-logind.elf") {
        t.file_bytes(s, "/usr/libexec/hydra-logind", &logind, 0o755)?;
    }
    if let Some(sockact) = boot_binary(s, "/bin/hydra-socket-activate.elf") {
        t.file_bytes(s, "/usr/libexec/hydra-socket-activate", &sockact, 0o755)?;
    }

    t.file_bytes(
        s,
        "/usr/bin/hydra-power-check",
        b"#!/bin/sh\necho '=== SESSIONS ==='\ndbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.ListSessions\necho '=== CAN POWER OFF ==='\ndbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanPowerOff\necho '=== CAN REBOOT ==='\ndbus-send --system --print-reply --dest=org.freedesktop.login1 /org/freedesktop/login1 org.freedesktop.login1.Manager.CanReboot\n",
        0o755,
    )?;

    // Network configuration & test script
    let dns = crate::net::iface().dns;
    let dns_ip = if dns != [0, 0, 0, 0] {
        alloc::format!("{}.{}.{}.{}", dns[0], dns[1], dns[2], dns[3])
    } else {
        alloc::string::String::from("10.0.2.3")
    };
    let resolv_content = alloc::format!(
        "# Configured by Hydra\nnameserver {}\nnameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:2 attempts:2\n",
        dns_ip
    );
    t.file_bytes(s, "/etc/resolv.conf", resolv_content.as_bytes(), 0o644)?;
    // ---- Group G: the computer name chosen in the installer (/etc/hostname, written by
    // hydra-firstboot) names 127.0.1.1; "hydra" when there is none ----
    let mut host = String::from("hydra");
    if let Some(ino) = lookup_path(s, t.root, "/etc/hostname") {
        let mut buf = [0u8; 64];
        let n = s.read(ino, 0, &mut buf).unwrap_or(0);
        let name = core::str::from_utf8(&buf[..n]).unwrap_or("").trim();
        if !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.') {
            host = String::from(name);
        }
    }
    let hosts = alloc::format!("127.0.0.1\tlocalhost\n127.0.1.1\t{}\n::1\tlocalhost ip6-localhost ip6-loopback\n", host);
    t.file_bytes(s, "/etc/hosts", hosts.as_bytes(), 0o644)?;
    // ---- end Group G ----
    t.file_bytes(
        s,
        "/usr/bin/hydra-net-check",
        b"#!/bin/sh\necho '=== RESOLV.CONF ==='\ncat /etc/resolv.conf\necho '=== PYTHON NETWORK TEST ==='\npython3 -c \"\nimport socket, urllib.request\nprint('1. Creating AF_INET socket...')\ns = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\nprint('   Socket OK:', s)\ns.close()\nprint('2. Resolving google.com...')\ntry:\n    ip = socket.gethostbyname('google.com')\n    print('   Resolved google.com ->', ip)\nexcept Exception as e:\n    print('   DNS error:', e)\nprint('3. HTTP GET to google.com...')\ntry:\n    resp = urllib.request.urlopen('http://google.com', timeout=10)\n    print('   HTTP status:', resp.getcode())\n    head = resp.read(64)\n    print('   HTTP response snippet:', repr(head[:40]))\nexcept Exception as e:\n    print('   HTTP error:', e)\n\"\n",
        0o755,
    )?;

    // Reboot / poweroff helpers for environments without systemd
    t.file_bytes(
        s,
        "/usr/local/bin/reboot",
        b"#!/bin/sh\nexec /sbin/reboot -f \"$@\"\n",
        0o755,
    )?;
    t.file_bytes(
        s,
        "/usr/local/bin/poweroff",
        b"#!/bin/sh\nexec /sbin/poweroff -f \"$@\"\n",
        0o755,
    )?;
    t.file_bytes(
        s,
        "/usr/local/bin/shutdown",
        b"#!/bin/sh\nexec /sbin/poweroff -f \"$@\"\n",
        0o755,
    )?;
    t.file_bytes(
        s,
        "/usr/local/bin/restart",
        b"#!/bin/sh\nexec /sbin/reboot -f \"$@\"\n",
        0o755,
    )?;

    // Firefox (Mozilla's APT repo, /usr/lib/firefox): native Wayland and its own sandbox need
    // no wrapper. Policies turn off what a fresh profile shows first (an onboarding dialog
    // over a gray backdrop on the whole window, the default-browser question), the built-in
    // updater (apt updates it), sponsored shortcuts and stories on the new tab page, and the
    // "Open previous tabs?" bar of the second start (a message shown when this counter is 1:
    // locked at 2). Written when missing or still an earlier version of Hydra's: an
    // administrator's own edits stay
    if lookup_path(s, t.root, "/usr/lib/firefox/firefox").is_some() {
        const POLICIES: &str = r#"{
  "policies": {
    "DisableAppUpdate": true,
    "DisableTelemetry": true,
    "DontCheckDefaultBrowser": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "FirefoxHome": {
      "SponsoredTopSites": false,
      "SponsoredPocket": false,
      "SponsoredStories": false,
      "Pocket": false,
      "Stories": false
    },
    "Preferences": {
      "browser.startup.couldRestoreSession.count": { "Value": 2, "Status": "locked" }
    },
    "UserMessaging": {
      "SkipOnboarding": true,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "MoreFromMozilla": false,
      "FirefoxLabs": false
    }
  }
}
"#;
        // Hydra's earlier versions of the file
        const EARLIER: [&str; 1] = [r#"{
  "policies": {
    "DisableAppUpdate": true,
    "DisableTelemetry": true,
    "DontCheckDefaultBrowser": true,
    "OverrideFirstRunPage": "",
    "OverridePostUpdatePage": "",
    "UserMessaging": {
      "SkipOnboarding": true,
      "ExtensionRecommendations": false,
      "FeatureRecommendations": false,
      "UrlbarInterventions": false,
      "MoreFromMozilla": false,
      "FirefoxLabs": false
    }
  }
}
"#];
        let path = "/etc/firefox/policies/policies.json";
        let replace = match lookup_path(s, t.root, path) {
            None => true,
            Some(ino) => {
                let size = s.getattr(ino).map(|a| a.size).unwrap_or(0) as usize;
                let mut cur = alloc::vec![0u8; size.min(16384)];
                let n = s.read(ino, 0, &mut cur).unwrap_or(0);
                EARLIER.iter().any(|e| e.as_bytes() == &cur[..n])
            }
        };
        if replace {
            t.file(s, path, POLICIES)?;
        }
    }

    // Windows programs (Wine in /opt/wine, tools/build-wine.sh), with helpers that keep a
    // terminal out of it (userland/hydra-wine; each says what it does at its top):
    // - hydra-wine-setup prepares each user's Windows environment (the Wine prefix, ~4 minutes
    //   to create) in the background at their first login, with a notification when it starts
    //   and when it is ready, so the first double-clicked program does not wait for it. It
    //   runs without a display (an unset WAYLAND_DISPLAY means wayland-0, the desktop: a name
    //   that does not exist): Wine's own "configuration is being updated" window would sit on
    //   the desktop for minutes. Wine Mono (the .NET Framework, part of Hydra's Wine package in
    //   share/wine/mono) is added after the prefix is announced ready (~1 minute more), and to
    //   prefixes made before the package had it: without it a .NET program exits with no
    //   message at all. Gecko (Internet Explorer's engine) is not offered: a download dialog at
    //   a first login. It also turns off Wine's WM_TAKE_FOCUS focus model in each prefix (a
    //   program still starting lost what was typed into its window, see the script)
    // - hydra-wine-run opens a double-clicked .exe/.msi/.lnk and turns Wine's terminal
    //   messages about a failed start into notifications (a missing Visual C++ runtime comes
    //   with an Install button: hydra-wine-runtime)
    // - hydra-wine-uninstall is the "Uninstall" of a Windows program's right-click menu in
    //   the start menu (the run and setup helpers add it to the entries Wine writes)
    if lookup_path(s, t.root, "/opt/wine/bin/wine").is_some() {
        t.dir(s, "/usr/local/libexec")?;
        t.file(s, "/usr/local/libexec/hydra-wine-common", include_str!("../../../userland/hydra-wine/hydra-wine-common"))?;
        for (name, script) in [
            ("hydra-wine-setup", include_bytes!("../../../userland/hydra-wine/hydra-wine-setup").as_slice()),
            ("hydra-wine-run", include_bytes!("../../../userland/hydra-wine/hydra-wine-run").as_slice()),
            ("hydra-wine-uninstall", include_bytes!("../../../userland/hydra-wine/hydra-wine-uninstall").as_slice()),
            ("hydra-wine-runtime", include_bytes!("../../../userland/hydra-wine/hydra-wine-runtime").as_slice()),
        ] {
            t.file_bytes(s, &alloc::format!("/usr/local/libexec/{}", name), script, 0o755)?;
        }
        // Windows programs open with Wine from the file manager and the browser (Icon: KDE's
        // own, Wine's icon is not installed)
        t.file(
            s,
            "/usr/share/applications/wine.desktop",
            "[Desktop Entry]
# Written by Hydra: Windows programs open with Wine
Type=Application
Name=Windows Program Loader
Comment=Runs Windows programs
Exec=/usr/local/libexec/hydra-wine-run %f
MimeType=application/vnd.microsoft.portable-executable;application/x-ms-dos-executable;application/x-msdownload;application/x-msi;application/x-ms-shortcut;
Icon=application-x-ms-dos-executable
NoDisplay=true
Terminal=false
Categories=System;Emulator;
",
        )?;
        // Windows' "Add or remove programs" (Wine's list of installed Windows programs, each
        // removed with its own uninstaller), found in the start menu under the name Windows
        // users search for
        t.file(
            s,
            "/usr/share/applications/hydra-windows-programs.desktop",
            "[Desktop Entry]
# Written by Hydra: the list of installed Windows programs, to uninstall or change them
Type=Application
Name=Add or Remove Windows Programs
GenericName=Installed Windows programs
Comment=Uninstall or change programs installed for Windows
Keywords=uninstall;remove;programs;apps;features;windows;wine;
Exec=/opt/wine/bin/wine uninstaller
Icon=preferences-system
Terminal=false
Categories=Settings;System;
",
        )?;
        // Optional parts of Windows, one click each (downloaded from Microsoft on demand)
        t.file(
            s,
            "/usr/share/applications/hydra-wine-vcrun.desktop",
            "[Desktop Entry]
# Written by Hydra: installs Microsoft's Visual C++ runtime for Windows programs
Type=Application
Name=Install Visual C++ Runtime
GenericName=Windows component
Comment=Microsoft Visual C++ 2015-2022, needed by many Windows programs
Keywords=vcredist;vc_redist;msvcp140;vcruntime140;visual c++;runtime;windows;wine;
Exec=/usr/local/libexec/hydra-wine-runtime vcrun
Icon=application-x-ms-dos-executable
Terminal=false
Categories=Settings;System;
",
        )?;
        t.file(
            s,
            "/etc/xdg/autostart/hydra-wine-setup.desktop",
            "[Desktop Entry]
# Written by Hydra: prepares Windows support at a user's first login
Type=Application
Name=Windows support setup
Exec=/usr/local/libexec/hydra-wine-setup
TryExec=/opt/wine/bin/wine
NoDisplay=true
X-KDE-autostart-phase=2
",
        )?;
    }

    // The desktop as Windows users know it (userland/hydra-desktop): a global theme whose
    // layout puts the taskbar's start button and programs in the middle, made the default for
    // users who have not chosen one, plus Windows' shortcuts and File Explorer habits. Users
    // with a desktop of their own keep it: Plasma reads the layout only for a first login
    if lookup_path(s, t.root, "/usr/bin/plasmashell").is_some() {
        const LNF: &str = "/usr/share/plasma/look-and-feel/org.hydra.windows.desktop";
        t.file(s, &alloc::format!("{}/metadata.json", LNF), include_str!("../../../userland/hydra-desktop/look-and-feel/metadata.json"))?;
        t.file(s, &alloc::format!("{}/contents/defaults", LNF), include_str!("../../../userland/hydra-desktop/look-and-feel/contents/defaults"))?;
        t.file(
            s,
            &alloc::format!("{}/contents/layouts/org.kde.plasma.desktop-layout.js", LNF),
            include_str!("../../../userland/hydra-desktop/look-and-feel/contents/layouts/org.kde.plasma.desktop-layout.js"),
        )?;
        for (name, content) in [
            ("kdeglobals", include_str!("../../../userland/hydra-desktop/xdg/kdeglobals")),
            ("dolphinrc", include_str!("../../../userland/hydra-desktop/xdg/dolphinrc")),
        ] {
            t.default_file(s, &alloc::format!("/etc/xdg/{}", name), content, &[])?;
        }
        // The names Windows users search the start menu for, and Windows' Ctrl+Shift+Esc for
        // the Task Manager (Plasma already has Win+E files, Win+D desktop, Win+L lock, Win+I
        // settings, Win+Shift+S screenshot, Win+V clipboard, Win+arrows to snap): copies of
        // KDE's entries in /usr/local/share/applications, which comes first in XDG_DATA_DIRS,
        // made again from KDE's at every boot so updates reach them. The shortcut daemon reads
        // a launcher's shortcuts from share/kglobalaccel, not from /etc/xdg
        for (id, generic, keywords, shortcuts) in [
            ("org.kde.dolphin.desktop", Some("File Explorer"), "File Explorer;Explorer;This PC;My Computer;", None),
            ("org.kde.plasma-systemmonitor.desktop", Some("Task Manager"), "Task Manager;taskmgr;End Task;", Some("Meta+Esc,Ctrl+Shift+Esc")),
            ("systemsettings.desktop", None, "Control Panel;Settings;", None),
        ] {
            windows_alias(t, s, id, generic, keywords, shortcuts)?;
            if shortcuts.is_some() && lookup_path(s, t.root, &alloc::format!("/usr/local/share/applications/{}", id)).is_some() {
                t.link(s, &alloc::format!("/usr/local/share/kglobalaccel/{}", id), &alloc::format!("/usr/local/share/applications/{}", id))?;
            }
        }
        // ---- Group B: Windows' shortcuts ----
        // Win+Up maximize, Win+Down minimize, Win+R Run: written into each user's shortcuts
        // once, before the desktop starts (the shortcut daemon keeps no system-wide defaults
        // for them; the script explains)
        t.file(
            s,
            "/etc/xdg/plasma-workspace/env/hydra-windows-shortcuts.sh",
            include_str!("../../../userland/hydra-desktop/env/hydra-windows-shortcuts.sh"),
        )?;
        // Discover had Windows' "App Store" names; Hydra Apps has them now (Discover cannot
        // install Ubuntu's packages on Hydra): Hydra's copy of Discover's entry goes
        if let (Some(dir), Some(ino)) = (
            lookup_path(s, t.root, "/usr/local/share/applications"),
            lookup_path(s, t.root, "/usr/local/share/applications/org.kde.discover.desktop"),
        ) {
            let mut head = [0u8; 80];
            let n = s.read(ino, 0, &mut head)?;
            if head[..n].windows(ALIAS_MARK.len()).any(|w| w == ALIAS_MARK.as_bytes()) {
                s.unlink(dir, b"org.kde.discover.desktop")?;
                t.changed = true;
            }
        }
    }

    // ---- Group B: Hydra Apps and the welcome window ----
    // Hydra Apps (userland/hydra-apps), the place to get programs like the Microsoft Store:
    // Windows programs from their publishers (checked against a recorded SHA-256, installed
    // with Wine for the user) and Linux apps (installed for everyone by a root helper started
    // through polkit). Written in Python with PyQt6, which hydra-session installs at boot when
    // it is missing (hydra-apps-helper ensure-base). Also the welcome window for people coming
    // from Windows, shown once at a user's first login (hydra-welcome)
    if lookup_path(s, t.root, "/usr/bin/python3").is_some() {
        t.dir(s, "/usr/local/libexec")?;
        for (name, script) in [
            ("hydra-apps", include_bytes!("../../../userland/hydra-apps/hydra-apps").as_slice()),
            ("hydra-apps-helper", include_bytes!("../../../userland/hydra-apps/hydra-apps-helper").as_slice()),
            ("hydra-apps-wine", include_bytes!("../../../userland/hydra-apps/hydra-apps-wine").as_slice()),
            ("hydra-welcome", include_bytes!("../../../userland/hydra-apps/hydra-welcome").as_slice()),
        ] {
            t.file_bytes(s, &alloc::format!("/usr/local/libexec/{}", name), script, 0o755)?;
        }
        t.file(s, "/usr/local/share/hydra-apps/catalogue.json", include_str!("../../../userland/hydra-apps/catalogue.json"))?;
        t.file(s, "/usr/share/polkit-1/actions/org.hydra.apps.policy", include_str!("../../../userland/hydra-apps/org.hydra.apps.policy"))?;
        t.file(s, "/usr/share/applications/org.hydra.apps.desktop", include_str!("../../../userland/hydra-apps/org.hydra.apps.desktop"))?;
        t.file(s, "/usr/share/applications/org.hydra.welcome.desktop", include_str!("../../../userland/hydra-apps/org.hydra.welcome.desktop"))?;
        t.file(s, "/etc/xdg/autostart/hydra-welcome.desktop", include_str!("../../../userland/hydra-apps/hydra-welcome-autostart.desktop"))?;
    }

    // ---- Group G: the installer (userland/hydra-install) ----
    // hydra-install: the "Install Hydra" window (PyQt6) of the live system; its root helper
    // erases the chosen disk and writes Hydra to it (polkit action org.hydra.install.run; the
    // live user needs no password). hydra-firstboot: run by hydra-session at the first start
    // of an installed computer, applies /etc/hydra/setup.conf (src/fs/firstboot.rs). Both are
    // in every pool, so the clean image the live stick carries has them
    t.file_bytes(s, "/usr/libexec/hydra-firstboot", include_bytes!("../../../userland/hydra-install/hydra-firstboot"), 0o755)?;
    if lookup_path(s, t.root, "/usr/bin/python3").is_some() {
        t.file_bytes(s, "/usr/bin/hydra-install", include_bytes!("../../../userland/hydra-install/hydra-install"), 0o755)?;
        t.file_bytes(s, "/usr/libexec/hydra-install-helper", include_bytes!("../../../userland/hydra-install/hydra-install-helper"), 0o755)?;
        t.file_bytes(s, "/usr/share/hydra-install/hydra-logo.png", include_bytes!("../../../userland/hydra-install/hydra-logo.png"), 0o644)?;
        t.file(s, "/usr/share/applications/hydra-install.desktop", include_str!("../../../userland/hydra-install/hydra-install.desktop"))?;
        t.file(s, "/usr/share/polkit-1/actions/org.hydra.install.policy", include_str!("../../../userland/hydra-install/org.hydra.install.policy"))?;
        t.file(s, "/etc/polkit-1/rules.d/60-hydra-install.rules", include_str!("../../../userland/hydra-install/60-hydra-install.rules"))?;
    }
    // ---- end Group G ----

    // ---- Group B: system users ----
    // hydra-session runs systemd-sysusers at boot (as systemd does elsewhere), which creates
    // the system users and groups /usr/lib/sysusers.d and /etc/sysusers.d ask for. Some have
    // no entry there: libmalcontent-common ships D-Bus rules for the users of malcontent's
    // daemons, whose package (malcontent) is not installed, and the system bus warned at every
    // start that they are unknown
    if lookup_path(s, t.root, "/usr/share/dbus-1/system.d/org.freedesktop.MalcontentTimer1.conf").is_some() {
        t.file(
            s,
            "/etc/sysusers.d/hydra-malcontent.conf",
            "# Written by Hydra: the users of malcontent's daemons, named in the D-Bus rules of
# libmalcontent-common (the malcontent package would create them; existing users are kept)
u! malcontent-timerd - \"Parental controls screen time daemon\"
u! malcontent-timer-ext-agent - \"Parental controls screen time extension agent\"
u! malcontent-webd - \"Parental controls web filter daemon\"
",
        )?;
    }

    // Older Hydra versions started Brave through wrappers of their own in /usr/bin and
    // /usr/local/bin; once Brave is gone (apt purge leaves the ones that replaced its
    // links), remove those that are still Hydra's
    if lookup_path(s, t.root, "/opt/brave.com/brave/brave-browser").is_none() {
        for dir_path in ["/usr/bin", "/usr/local/bin"] {
            let Some(dir) = lookup_path(s, t.root, dir_path) else { continue };
            for name in ["brave-browser", "brave-browser-stable", "brave"] {
                let Ok(ino) = s.lookup(dir, name.as_bytes()) else { continue };
                let mut head = [0u8; 28];
                let n = s.read(ino, 0, &mut head).unwrap_or(0);
                if head[..n].windows(18).any(|w| w == b"# Written by Hydra") {
                    let _ = s.unlink(dir, name.as_bytes());
                    t.changed = true;
                }
            }
        }
    }

    // Ensure /dev/shm (POSIX shared memory) exists with mode 1777 (world-writable + sticky)
    let shm = t.dir(s, "/dev/shm")?;
    let _ = s.setattr(shm, crate::fs::zfs::zpl::SetAttr { mode: Some(0o1777), ..Default::default() });
    // wave9 GM begin: /dev/shm is a memory directory (`fs::tmem`): empty at boot as Linux's
    // tmpfs (the first time this root is prepared; later preparations must keep the files of
    // running programs), and its new files keep their data in memory
    if !crate::fs::tmem::shm_dir(shm) {
        crate::fs::tmem::add_shm_dir(shm);
        // (the names first, then the unlinks: a cookie need not survive a change)
        let mut names = Vec::new();
        let mut cookie = 0;
        while let Ok(batch) = s.readdir(shm, cookie, 64) {
            let Some(last) = batch.last() else { break };
            if last.next_cookie == cookie {
                break;
            }
            cookie = last.next_cookie;
            names.extend(batch.into_iter().filter(|e| e.name != b"." && e.name != b".." && e.dtype != 4).map(|e| e.name));
        }
        for n in names {
            if s.unlink(shm, &n).is_ok() {
                t.changed = true;
            }
        }
    }
    // wave9 GM end
    let _ = t.link(s, "/run/shm", "/dev/shm");
    // The links systemd creates in /dev for a process's own descriptors
    let _ = t.link(s, "/dev/fd", "/proc/self/fd");
    let _ = t.link(s, "/dev/stdin", "/proc/self/fd/0");
    let _ = t.link(s, "/dev/stdout", "/proc/self/fd/1");
    let _ = t.link(s, "/dev/stderr", "/proc/self/fd/2");

    // Older Hydra versions let the sudo group use sudo without a password: remove that
    // rule if it is still the one Hydra wrote
    if let Some(dir) = lookup_path(s, t.root, "/etc/sudoers.d") {
        if let Ok(ino) = s.lookup(dir, b"010_nopasswd") {
            let ours = b"%sudo ALL=(ALL) NOPASSWD: ALL\n";
            let mut cur = [0u8; 64];
            let n = s.read(ino, 0, &mut cur).unwrap_or(0);
            if s.getattr(ino).map(|a| a.size).unwrap_or(0) == ours.len() as u64 && &cur[..n] == ours {
                let _ = s.unlink(dir, b"010_nopasswd");
                t.changed = true;
            }
        }
    }
    access_control_files(t, s)?;
    live_session_files(t, s)?;
    Ok(())
}

// ---- Group F: the live session (Hydra from its USB stick, `super::live`) ----
/// Files of the live session that exist only while it runs (removed at a boot that is not
/// one, so an installed system or a stick booted without its flag never has them).
const LIVE_ONLY: [&str; 4] = [
    "/etc/sddm.conf.d/zz-hydra-live.conf",
    "/etc/sudoers.d/hydra-live",
    "/etc/polkit-1/rules.d/49-hydra-live.rules",
    "/etc/xdg/autostart/hydra-live-hint.desktop",
];

/// The live session (`/run/hydra/live`, written with the other boot flags, tells programs
/// that this is one): the login screen logs the user `live` in by itself (hydra-live-setup, run by
/// hydra-session before the login screen, creates that user and its desktop); `live` may
/// administer without a password (sudo, polkit: the installer); "Install Hydra" on the desktop
/// (hydra-live-setup copies the installer's start menu entry there) starts the installer
/// (`/usr/bin/hydra-install` and its entry are Group G's, written into every pool; placeholders
/// until a pool has them); a small window says that nothing is saved to the computer
/// (userland/hydra-live).
fn live_session_files(t: &mut Tree, s: &mut ZfsServer) -> Result<(), i64> {
    if !super::live::is_live() {
        for path in LIVE_ONLY {
            let (parent, name) = split(path);
            if let (Some(dir), Some(_)) = (lookup_path(s, t.root, parent), lookup_path(s, t.root, path)) {
                s.unlink(dir, name.as_bytes())?;
                t.changed = true;
            }
        }
        return Ok(());
    }
    t.dir(s, "/usr/local/libexec")?;
    t.file_bytes(s, "/usr/local/libexec/hydra-live-setup", include_bytes!("../../../userland/hydra-live/hydra-live-setup"), 0o755)?;
    t.file_bytes(s, "/usr/local/libexec/hydra-live-hint", include_bytes!("../../../userland/hydra-live/hydra-live-hint"), 0o755)?;
    t.file(s, "/etc/xdg/autostart/hydra-live-hint.desktop", include_str!("../../../userland/hydra-live/hydra-live-hint.desktop"))?;
    if lookup_path(s, t.root, "/usr/bin/hydra-install").is_none() {
        t.file_bytes(s, "/usr/bin/hydra-install", include_bytes!("../../../userland/hydra-live/hydra-install-placeholder"), 0o755)?;
    }
    if lookup_path(s, t.root, "/usr/share/applications/hydra-install.desktop").is_none() {
        t.file(s, "/usr/share/applications/hydra-install.desktop", include_str!("../../../userland/hydra-live/hydra-install-placeholder.desktop"))?;
    }
    t.dir(s, "/etc/sddm.conf.d")?;
    t.file(
        s,
        "/etc/sddm.conf.d/zz-hydra-live.conf",
        "# Written by Hydra: the live session logs in by itself (removed outside it)
[Autologin]
User=live
Session=plasma.desktop
Relogin=false
",
    )?;
    t.dir(s, "/etc/sudoers.d")?;
    t.file_bytes(s, "/etc/sudoers.d/hydra-live", b"# Written by Hydra: the live session's user administers without a password
live ALL=(ALL) NOPASSWD: ALL
", 0o440)?;
    t.dir(s, "/etc/polkit-1/rules.d")?;
    t.file(
        s,
        "/etc/polkit-1/rules.d/49-hydra-live.rules",
        "// Written by Hydra: the live session's user administers without a password (removed outside it)
polkit.addRule(function(action, subject) {
    if (subject.user == \"live\") {
        return polkit.Result.YES;
    }
});
",
    )?;
    Ok(())
}

// ---- Group D: access control (ABAC) apps and their system files ----

/// Files of Hydra's access control apps (userland/hydra-access): Family & accounts, Hydra
/// Access Center, their root helper and polkit action, the polkit rule that lets access
/// rules decide administrative tasks, the Dolphin menu, and the sign-in hours check in
/// SDDM's PAM stack (src/compat/linux/abac.rs is the kernel side).
fn access_control_files(t: &mut Tree, s: &mut ZfsServer) -> Result<(), i64> {
    const PY: [(&str, &str); 7] = [
        ("__init__.py", include_str!("../../../userland/hydra-access/hydra_access/__init__.py")),
        ("core.py", include_str!("../../../userland/hydra-access/hydra_access/core.py")),
        ("helper.py", include_str!("../../../userland/hydra-access/hydra_access/helper.py")),
        ("webfilter.py", include_str!("../../../userland/hydra-access/hydra_access/webfilter.py")),
        ("ui_common.py", include_str!("../../../userland/hydra-access/hydra_access/ui_common.py")),
        ("family.py", include_str!("../../../userland/hydra-access/hydra_access/family.py")),
        ("center.py", include_str!("../../../userland/hydra-access/hydra_access/center.py")),
    ];
    for (name, text) in PY {
        t.file(s, &alloc::format!("/usr/lib/hydra-access/hydra_access/{}", name), text)?;
    }
    t.file_bytes(s, "/usr/bin/hydra-family", include_bytes!("../../../userland/hydra-access/data/hydra-family"), 0o755)?;
    t.file_bytes(s, "/usr/bin/hydra-access-center", include_bytes!("../../../userland/hydra-access/data/hydra-access-center"), 0o755)?;
    t.file_bytes(s, "/usr/libexec/hydra-access-helper", include_bytes!("../../../userland/hydra-access/data/hydra-access-helper"), 0o755)?;
    t.file(s, "/usr/share/applications/hydra-family.desktop", include_str!("../../../userland/hydra-access/data/hydra-family.desktop"))?;
    t.file(s, "/usr/share/applications/hydra-access-center.desktop", include_str!("../../../userland/hydra-access/data/hydra-access-center.desktop"))?;
    t.file_bytes(s, "/usr/share/kio/servicemenus/hydra-access.desktop", include_bytes!("../../../userland/hydra-access/data/hydra-access-servicemenu.desktop"), 0o755)?;
    t.file(s, "/usr/share/polkit-1/actions/org.hydra.access.policy", include_str!("../../../userland/hydra-access/data/org.hydra.access.policy"))?;
    t.file(s, "/etc/polkit-1/rules.d/60-hydra-access.rules", include_str!("../../../userland/hydra-access/data/60-hydra-access.rules"))?;
    t.dir(s, "/etc/hydra/access/subjects")?;
    let have_check = match boot_binary(s, "/bin/hydra-access-check.elf") {
        Some(bin) => {
            t.file_bytes(s, "/usr/libexec/hydra-access-check", &bin, 0o755)?;
            true
        }
        None => lookup_path(s, t.root, "/usr/libexec/hydra-access-check").is_some(),
    };
    // Sign-in hours (Family screen time, Enterprise): SDDM asks the access policy before a
    // session starts (pam_exec; the check allows everything while no policy says otherwise)
    const PAM_LINE: &str = "account required pam_exec.so quiet /usr/libexec/hydra-access-check login";
    if have_check {
        if let Some(ino) = lookup_path(s, t.root, "/etc/pam.d/sddm") {
            let size = s.getattr(ino)?.size as usize;
            let mut cur = alloc::vec![0u8; size];
            let n = s.read(ino, 0, &mut cur)?;
            cur.truncate(n);
            if let Ok(text) = core::str::from_utf8(&cur) {
                if !text.contains("hydra-access-check") {
                    let mut out = String::new();
                    let mut done = false;
                    for line in text.lines() {
                        out.push_str(line);
                        out.push('\n');
                        if !done && line.trim_start().starts_with("@include common-account") {
                            out.push_str(PAM_LINE);
                            out.push('\n');
                            done = true;
                        }
                    }
                    if done {
                        t.file_bytes(s, "/etc/pam.d/sddm", out.as_bytes(), 0o644)?;
                    }
                }
            }
        }
    }
    Ok(())
}

/// The marker line of the menu entries [`windows_alias`] writes.
const ALIAS_MARK: &str = "# Written by Hydra from /usr/share/applications";

/// KDE's menu entry `orig` with Windows' names added: `generic` replaces its generic name (the
/// grey line under the name in the start menu), `keywords` are added to what search finds it
/// by, and `shortcuts` replaces its global shortcuts. Only the main group changes (actions
/// have their own names and shortcuts); localised names stay as they are.
fn alias_entry(orig: &str, generic: Option<&str>, keywords: &str, shortcuts: Option<&str>) -> String {
    let mut out = String::new();
    let (mut in_main, mut seen_kw, mut seen_sc) = (false, false, false);
    // What the main group still lacks, added where it ends
    let finish = |out: &mut String, seen_kw: bool, seen_sc: bool| {
        if !seen_kw {
            out.push_str(&alloc::format!("Keywords={}\n", keywords));
        }
        if let (false, Some(sc)) = (seen_sc, shortcuts) {
            out.push_str(&alloc::format!("X-KDE-Shortcuts={}\n", sc));
        }
    };
    for line in orig.lines() {
        if line.starts_with('[') {
            if in_main {
                finish(&mut out, seen_kw, seen_sc);
                out.push('\n');
            }
            in_main = line == "[Desktop Entry]";
            out.push_str(line);
            out.push('\n');
            if in_main {
                out.push_str(ALIAS_MARK);
                out.push_str(": Windows' names added\n");
            }
            continue;
        }
        if in_main && line.is_empty() {
            continue;
        }
        if in_main {
            if let (Some(g), true) = (generic, line.starts_with("GenericName=")) {
                out.push_str(&alloc::format!("GenericName={}\n", g));
                continue;
            }
            if let Some(kw) = line.strip_prefix("Keywords=") {
                seen_kw = true;
                let sep = if kw.is_empty() || kw.ends_with(';') { "" } else { ";" };
                out.push_str(&alloc::format!("Keywords={}{}{}\n", kw, sep, keywords));
                continue;
            }
            if let (Some(sc), true) = (shortcuts, line.starts_with("X-KDE-Shortcuts=")) {
                seen_sc = true;
                out.push_str(&alloc::format!("X-KDE-Shortcuts={}\n", sc));
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    if in_main {
        finish(&mut out, seen_kw, seen_sc);
    }
    out
}

/// Writes /usr/local/share/applications/`id`, KDE's menu entry `id` with Windows' names (see
/// [`alias_entry`]), unless an administrator replaced Hydra's copy with their own (no marker);
/// Hydra's copy goes when KDE's entry does.
///
/// # Returns
///
/// `Ok(())` on success, or a negative Linux errno on error.
fn windows_alias(t: &mut Tree, s: &mut ZfsServer, id: &str, generic: Option<&str>, keywords: &str, shortcuts: Option<&str>) -> Result<(), i64> {
    let path = alloc::format!("/usr/local/share/applications/{}", id);
    let ours = match lookup_path(s, t.root, &path) {
        None => true,
        Some(ino) => {
            let mut head = [0u8; 80];
            let n = s.read(ino, 0, &mut head)?;
            head[..n].windows(ALIAS_MARK.len()).any(|w| w == ALIAS_MARK.as_bytes())
        }
    };
    if !ours {
        return Ok(());
    }
    let orig = lookup_path(s, t.root, &alloc::format!("/usr/share/applications/{}", id)).and_then(|ino| {
        let size = s.getattr(ino).ok()?.size as usize;
        let mut buf = alloc::vec![0u8; size];
        let n = s.read(ino, 0, &mut buf).ok()?;
        buf.truncate(n);
        Some(buf)
    });
    let Some(orig) = orig else {
        if let (Some(dir), Some(_)) = (lookup_path(s, t.root, "/usr/local/share/applications"), lookup_path(s, t.root, &path)) {
            s.unlink(dir, id.as_bytes())?;
            t.changed = true;
        }
        return Ok(());
    };
    let Ok(orig) = core::str::from_utf8(&orig) else { return Ok(()) };
    t.file(s, &path, &alias_entry(orig, generic, keywords, shortcuts))
}

/// Contents of a file imported from the boot volume into the pool's `/bin`.
///
/// # Arguments
///
/// * `s` - Active ZFS server reference.
/// * `path` - Slash-separated path on root dataset.
///
/// # Returns
///
/// `Some(bytes)` if read successfully, or `None`.
fn boot_binary(s: &mut ZfsServer, path: &str) -> Option<Vec<u8>> {
    let root = s.root_obj();
    let ino = lookup_path(s, root, path)?;
    let size = s.getattr(ino).ok()?.size as usize;
    let mut buf = alloc::vec![0u8; size];
    let n = s.read(ino, 0, &mut buf).ok()?;
    buf.truncate(n);
    Some(buf)
}

/// Writes the device nodes, sysfs tree and udev records into the Linux root at `root`.
///
/// # Arguments
///
/// * `root` - Target root directory path string.
///
/// # Returns
///
/// `Ok(())` on success, or an error description string on failure.
pub fn populate(root: &str) -> Result<(), &'static str> {
    let root_ino = crate::fs::ZfsClient::resolve(0, root.as_bytes(), true).map_err(|_| "no such root directory")?;
    let mut tree = Tree { root: root_ino, changed: false, at: String::new() };
    *LINUX_ROOT.lock() = Some(String::from(root));
    let facts = block_facts();
    let efivars = super::efivars::snapshot();
    if let Err(e) = crate::fs::zfs::with_server(|s| {
        populate_tree(&mut tree, s)?;
        block_tree(&mut tree, s, 1_000_000, &facts)?;
        boot_flag_files(&mut tree, s, &facts)?;
        efivars_tree(&mut tree, s, efivars.as_deref())
    }) {
        crate::kprintln!("[devices] writing the device tree into {} failed at {}: errno {}", root, tree.at, -e);
        return Err("could not write the device tree");
    }
    // Access policies (Group D): the saved policy is enforced from the first setup on
    super::abac::boot_load(root);
    // No sync of its own: the changes are visible at once, and the background commit
    // writes them (most boots only give the device nodes back to root, which took a
    // second's sync before the login screen could start)
    Ok(())
}

// wave8 GH begin: one udev record per device, for the database files written above and
// for the announcements after a device service's crash (`crate::lx::hotplug`), so a device
// announced again has exactly the properties and tags it had at boot

/// When udev "initialized" the devices: one second after boot (`USEC_INITIALIZED`).
pub const INIT_USEC: u64 = 1_000_000;

/// The record of input device `dev` (its `event` node; the keyboard is 0, pointers 1..).
pub fn input_record(dev: usize, usec: u64) -> crate::lx::uevent::DevRecord {
    let port = dev.min(1);
    let p = |k: &str, v: &str| (String::from(k), String::from(v));
    let mut props = alloc::vec![p("ID_INPUT", "1")];
    if dev == 0 {
        props.extend([p("ID_INPUT_KEY", "1"), p("ID_INPUT_KEYBOARD", "1"), p("XKBMODEL", "pc105"), p("XKBLAYOUT", "us")]);
    } else {
        props.push(p("ID_INPUT_MOUSE", "1"));
    }
    let path = alloc::format!("platform-i8042-serio-{}", port);
    props.extend([p("ID_BUS", "i8042"), p("ID_SERIAL", "noserial"), p("ID_PATH", &path), p("ID_PATH_TAG", &path)]);
    crate::lx::uevent::DevRecord {
        devpath: alloc::format!("/devices/platform/i8042/serio{}/input/input{}/event{}", port, dev, dev),
        subsystem: "input",
        devtype: None,
        node: Some((alloc::format!("input/event{}", dev), 13, 64 + dev as u32)),
        props,
        tags: alloc::vec!["seat", "uaccess"],
        usec,
    }
}

/// Every input device's record.
pub fn input_records(usec: u64) -> Vec<crate::lx::uevent::DevRecord> {
    (0..super::evdev::device_count()).map(|d| input_record(d, usec)).collect()
}

/// The sound card's nodes: (name, minor).
fn sound_nodes(capture: bool) -> Vec<(&'static str, u64)> {
    let mut nodes = alloc::vec![("controlC0", 0u64), ("pcmC0D0p", 16)];
    if capture {
        nodes.push(("pcmC0D0c", 24));
    }
    nodes
}

/// The sound card's records: the card first, then its nodes (none without a card).
pub fn sound_records(usec: u64) -> Vec<crate::lx::uevent::DevRecord> {
    let Some((slot, vendor, device, _)) = super::snd::controller() else { return Vec::new() };
    let path_tag: String = slot.chars().map(|c| if c == ':' || c == '.' { '_' } else { c }).collect();
    let p = |k: &str, v: String| (String::from(k), v);
    let card_path = alloc::format!("/devices/pci0000:00/{}/sound/card0", slot);
    let mut v = alloc::vec![crate::lx::uevent::DevRecord {
        devpath: card_path.clone(),
        subsystem: "sound",
        devtype: None,
        node: None,
        props: alloc::vec![
            p("ID_PATH", alloc::format!("pci-{}", slot)),
            p("ID_PATH_TAG", alloc::format!("pci-{}", path_tag)),
            p("SOUND_INITIALIZED", String::from("1")),
            p("SOUND_FORM_FACTOR", String::from("internal")),
            p("ID_BUS", String::from("pci")),
            p("ID_VENDOR_ID", alloc::format!("0x{:04x}", vendor)),
            p("ID_MODEL_ID", alloc::format!("0x{:04x}", device)),
            p("ID_VENDOR_FROM_DATABASE", String::from("Intel Corporation")),
            p("ID_MODEL_FROM_DATABASE", String::from("High Definition Audio Controller")),
        ],
        tags: alloc::vec!["seat"],
        usec,
    }];
    for (name, minor) in sound_nodes(super::snd::has_dir(1)) {
        v.push(crate::lx::uevent::DevRecord {
            devpath: alloc::format!("{}/{}", card_path, name),
            subsystem: "sound",
            devtype: None,
            node: Some((alloc::format!("snd/{}", name), 116, minor as u32)),
            props: alloc::vec![p("ID_PATH", alloc::format!("pci-{}", slot)), p("ID_PATH_TAG", alloc::format!("pci-{}", path_tag))],
            tags: alloc::vec!["seat", "uaccess"],
            usec,
        });
    }
    v
}
// wave8 GH end

/// The sound card (`super::snd`): `/dev/snd` nodes, its sysfs devices (PipeWire finds cards
/// through libudev, subsystem "sound"), their udev records, and the `/proc/asound`
/// directories (the files are served by `super::snd::proc_text`; the ones here only make
/// them show in directory listings). Without a card, the records a previous boot wrote are
/// removed, so nothing looks for it.
fn sound_tree(t: &mut Tree, s: &mut ZfsServer, usec: u64) -> Result<(), i64> {
    let Some((slot, vendor, device, subsys)) = super::snd::controller() else {
        for path in ["/run/udev/data/+sound:card0", "/sys/class/sound/card0", "/sys/class/sound/controlC0", "/sys/class/sound/pcmC0D0p", "/sys/class/sound/pcmC0D0c"] {
            let (parent, name) = split(path);
            if let Some(dir) = lookup_path(s, t.root, parent) {
                if s.lookup(dir, name.as_bytes()).is_ok() {
                    let _ = s.unlink(dir, name.as_bytes());
                    t.changed = true;
                }
            }
        }
        return Ok(());
    };
    let capture = super::snd::has_dir(1);
    // PipeWire's settings for Hydra:
    // - no realtime module: it asks RTKit for realtime threads over D-Bus; Hydra has no
    //   working RTKit, and the call blocked the audio thread for D-Bus's 25 s timeout;
    // - cycles of at least 1024 frames (21 ms), for the server and for PulseAudio clients
    //   (Wine, Firefox): shorter ones underran under load (gaps of silence in Wine's sound)
    for (conf, extra) in [
        ("pipewire", "    default.clock.min-quantum = 1024
"),
        ("client", ""),
        ("pipewire-pulse", ""),
    ] {
        let mut text = alloc::format!("# Written by Hydra (see src/compat/linux/devices.rs, sound_tree)
context.properties = {{
    module.rt = false
{}}}
", extra);
        if conf == "pipewire-pulse" {
            text.push_str("pulse.properties = {
    pulse.min.req = 1024/48000
    pulse.min.frag = 1024/48000
    pulse.min.quantum = 1024/48000
}
");
        }
        t.file(s, &alloc::format!("/etc/pipewire/{}.conf.d/50-hydra-sound.conf", conf), &text)?;
        // The name of an earlier version of this file
        if let Some(dir) = lookup_path(s, t.root, &alloc::format!("/etc/pipewire/{}.conf.d", conf)) {
            if s.lookup(dir, b"50-hydra-no-rtkit.conf").is_ok() {
                let _ = s.unlink(dir, b"50-hydra-no-rtkit.conf");
                t.changed = true;
            }
        }
    }
    let pci = alloc::format!("/sys/devices/pci0000:00/{}", slot);
    let (sub_vendor, sub_device) = (subsys as u16, (subsys >> 16) as u16);
    t.file(
        s,
        &alloc::format!("{}/uevent", pci),
        &alloc::format!(
            "DRIVER=snd_hda_intel\nPCI_CLASS=40300\nPCI_ID={:04X}:{:04X}\nPCI_SUBSYS_ID={:04X}:{:04X}\nPCI_SLOT_NAME={}\nMODALIAS=pci:v{:08X}d{:08X}sv{:08X}sd{:08X}bc04sc03i00\n",
            vendor, device, sub_vendor, sub_device, slot, vendor, device, sub_vendor, sub_device
        ),
    )?;
    for (name, value) in [
        ("vendor", alloc::format!("0x{:04x}\n", vendor)),
        ("device", alloc::format!("0x{:04x}\n", device)),
        ("subsystem_vendor", alloc::format!("0x{:04x}\n", sub_vendor)),
        ("subsystem_device", alloc::format!("0x{:04x}\n", sub_device)),
        ("class", String::from("0x040300\n")),
        ("enable", String::from("1\n")),
    ] {
        t.file(s, &alloc::format!("{}/{}", pci, name), &value)?;
    }
    t.link(s, &alloc::format!("{}/subsystem", pci), "../../../bus/pci")?;
    t.link(s, &alloc::format!("{}/driver", pci), "../../../bus/pci/drivers/snd_hda_intel")?;
    t.dir(s, "/sys/bus/pci/drivers/snd_hda_intel")?;
    t.link(s, &alloc::format!("/sys/bus/pci/devices/{}", slot), &alloc::format!("../../../devices/pci0000:00/{}", slot))?;

    let card = alloc::format!("{}/sound/card0", pci);
    t.file(s, &alloc::format!("{}/uevent", card), "")?;
    t.file(s, &alloc::format!("{}/id", card), "Intel\n")?;
    t.file(s, &alloc::format!("{}/number", card), "0\n")?;
    t.link(s, &alloc::format!("{}/subsystem", card), "../../../../../class/sound")?;
    t.link(s, &alloc::format!("{}/device", card), &alloc::format!("../../../{}", slot))?;
    t.link(s, "/sys/class/sound/card0", &alloc::format!("../../devices/pci0000:00/{}/sound/card0", slot))?;
    // wave8 GH: the card's and its nodes' records (the same ones announce them again after a
    // sound service crash)
    let recs = sound_records(usec);
    for rec in &recs {
        t.file(s, &alloc::format!("/run/udev/data/{}", rec.db_name()), &rec.db_text())?;
    }
    for (name, minor) in sound_nodes(capture) {
        let dir = alloc::format!("{}/{}", card, name);
        t.file(s, &alloc::format!("{}/uevent", dir), &alloc::format!("MAJOR=116\nMINOR={}\nDEVNAME=snd/{}\n", minor, name))?;
        t.file(s, &alloc::format!("{}/dev", dir), &alloc::format!("116:{}\n", minor))?;
        if name.starts_with("pcm") {
            t.file(s, &alloc::format!("{}/pcm_class", dir), "generic\n")?;
        }
        t.link(s, &alloc::format!("{}/subsystem", dir), "../../../../../../class/sound")?;
        t.link(s, &alloc::format!("{}/device", dir), "../../card0")?;
        let rel = alloc::format!("../../devices/pci0000:00/{}/sound/card0/{}", slot, name);
        t.link(s, &alloc::format!("/sys/class/sound/{}", name), &rel)?;
        t.link(s, &alloc::format!("/sys/dev/char/116:{}", minor), &rel)?;
        // Anyone may play sound: a desktop's user owns the seat
        t.node_mode(s, &alloc::format!("/dev/snd/{}", name), super::chardev::makedev(116, minor), 29, 0o666)?;
    }
    t.link(s, &alloc::format!("/dev/snd/by-path/pci-{}", slot), "../controlC0")?;

    // /proc/asound: directories and placeholders (contents from super::snd)
    t.link(s, "/proc/asound/Intel", "card0")?;
    for f in ["cards", "devices", "pcm", "version", "card0/id", "card0/codec#0"] {
        t.file(s, &alloc::format!("/proc/asound/{}", f), "")?;
    }
    for d in if capture { &["p", "c"][..] } else { &["p"][..] } {
        for f in ["info", "sub0/info", "sub0/status", "sub0/hw_params", "sub0/sw_params"] {
            t.file(s, &alloc::format!("/proc/asound/card0/pcm0{}/{}", d, f), "")?;
        }
    }
    Ok(())
}

// ----------------------------------------------------------------------
// Block devices: /dev/sdX, their sysfs devices and udev records
// ----------------------------------------------------------------------

/// The root the device tree was last written into (for [`refresh_block_tree`]).
static LINUX_ROOT: spin::Mutex<Option<String>> = spin::Mutex::new(None);

/// A file system found at the start of a partition (what `blkid` would report).
#[derive(Clone)]
struct FsInfo {
    ty: &'static str,
    version: &'static str,
    uuid: String,
    label: String,
}

/// Recognizes a FAT file system from its boot sector.
fn probe_fs(sector: &[u8]) -> Option<FsInfo> {
    if sector.len() < 512 || sector[510] != 0x55 || sector[511] != 0xAA {
        return None;
    }
    let text = |a: usize, n: usize| String::from(core::str::from_utf8(&sector[a..a + n]).unwrap_or("").trim_end());
    let (version, id_at, label_at) = if &sector[82..87] == b"FAT32" {
        ("FAT32", 0x43, 0x47)
    } else if &sector[54..59] == b"FAT16" {
        ("FAT16", 0x27, 0x2B)
    } else if &sector[54..59] == b"FAT12" {
        ("FAT12", 0x27, 0x2B)
    } else {
        return None;
    };
    let id = u32::from_le_bytes(sector[id_at..id_at + 4].try_into().unwrap());
    let mut label = text(label_at, 11);
    if label == "NO NAME" {
        label.clear();
    }
    Some(FsInfo { ty: "vfat", version, uuid: alloc::format!("{:04X}-{:04X}", id >> 16, id & 0xFFFF), label })
}

/// The disks and what is on their partitions (read before the tree is written: the disk
/// reads must not happen inside a file server session).
fn block_facts() -> Vec<(crate::fs::blockdev::Disk, Vec<Option<FsInfo>>)> {
    let disks = crate::fs::blockdev::disks();
    disks
        .into_iter()
        .enumerate()
        .map(|(i, d)| {
            let fs = d
                .parts
                .iter()
                .map(|p| {
                    if d.touches_pool(p.start, p.start + p.len) {
                        return Some(FsInfo { ty: "zfs_member", version: "5000", uuid: String::new(), label: String::from("hydrapool") });
                    }
                    let mut sector = [0u8; 512];
                    match crate::fs::blockdev::read_at(i, p.start, &mut sector) {
                        Ok(512) => probe_fs(&sector),
                        _ => None,
                    }
                })
                .collect();
            (d, fs)
        })
        .collect()
}

/// PCI slot of the disk controller (the sysfs parent of the disks).
fn disk_controller_slot() -> String {
    use crate::arch::pci;
    pci::find_class(0x01, 0x06)
        .or_else(|| pci::find_class(0x01, 0x01))
        .map_or_else(|| String::from("0000:00:01.1"), |d| alloc::format!("0000:{:02x}:{:02x}.{}", d.bus, d.device, d.function))
}

/// `name` with characters udev does not keep in `ID_MODEL`/`ID_SERIAL` replaced by `_`.
fn udev_safe(name: &str) -> String {
    name.trim().chars().map(|c| if c.is_ascii_alphanumeric() || "-._".contains(c) { c } else { '_' }).collect()
}

/// Removes `name` in directory `dir`, a directory with everything below it included.
fn remove_all(t: &mut Tree, s: &mut ZfsServer, dir: u64, name: &str) -> Result<(), i64> {
    let ino = match s.lookup(dir, name.as_bytes()) {
        Ok(i) => i,
        Err(ENOENT) => return Ok(()),
        Err(e) => return Err(e),
    };
    t.changed = true;
    if s.getattr(ino)?.mode & S_IFMT != 0o040000 {
        return s.unlink(dir, name.as_bytes());
    }
    loop {
        let entries = s.readdir(ino, 0, 64)?;
        let names: Vec<Vec<u8>> = entries.into_iter().map(|e| e.name).filter(|n| n != b"." && n != b"..").collect();
        if names.is_empty() {
            break;
        }
        for n in names {
            remove_all(t, s, ino, core::str::from_utf8(&n).unwrap_or(""))?;
        }
    }
    s.rmdir(dir, name.as_bytes())
}

/// Removes the entries of directory `path` that `stale` picks.
fn remove_stale(t: &mut Tree, s: &mut ZfsServer, path: &str, stale: &dyn Fn(&str) -> bool) -> Result<(), i64> {
    let Some(dir) = lookup_path(s, t.root, path) else { return Ok(()) };
    let mut gone = Vec::new();
    let mut cookie = 0;
    loop {
        let entries = s.readdir(dir, cookie, 64)?;
        if entries.is_empty() {
            break;
        }
        for e in &entries {
            let n = String::from_utf8_lossy(&e.name).into_owned();
            if n != "." && n != ".." && stale(&n) {
                gone.push(n);
            }
        }
        cookie = entries.last().unwrap().next_cookie;
    }
    for n in gone {
        remove_all(t, s, dir, &n)?;
    }
    Ok(())
}

/// Writes the block devices: for disk `i` named `sdX` the SCSI device
/// `/sys/devices/pci0000:00/<controller>/ata<i+1>/host<i>/target<i>:0:0/<i>:0:0:0` with
/// `block/sdX` (and `block/sdX/sdXN` for its partitions) below it, the `/sys/block`,
/// `/sys/class/block` and `/sys/dev/block` links, the `/dev` nodes (group `disk`) and the
/// udev records `/run/udev/data/b8:<minor>`. What a previous boot or partition table
/// left that no longer exists is removed.
fn block_tree(t: &mut Tree, s: &mut ZfsServer, usec: u64, facts: &[(crate::fs::blockdev::Disk, Vec<Option<FsInfo>>)]) -> Result<(), i64> {
    let disk_gid = group_id(s, t.root, "disk", 6);
    let slot = disk_controller_slot();
    let ctrl = alloc::format!("/sys/devices/pci0000:00/{}", slot);
    let names: Vec<String> = facts.iter().map(|(d, _)| d.name.clone()).collect();
    let mut nodes: Vec<String> = Vec::new();
    for (d, _) in facts {
        nodes.push(d.name.clone());
        for p in &d.parts {
            nodes.push(alloc::format!("{}{}", d.name, p.number));
        }
    }
    let minors: Vec<String> = facts.iter().enumerate().flat_map(|(i, (d, _))| {
        core::iter::once(alloc::format!("8:{}", i * 16)).chain(d.parts.iter().map(move |p| alloc::format!("8:{}", i * 16 + p.number as usize)))
    }).collect();
    // What no longer exists
    let is_sd = |n: &str| n.len() >= 3 && n.starts_with("sd") && n.as_bytes()[2].is_ascii_lowercase();
    remove_stale(t, s, "/dev", &|n| is_sd(n) && !nodes.iter().any(|x| x == n))?;
    remove_stale(t, s, "/sys/block", &|n| !names.iter().any(|x| x == n))?;
    remove_stale(t, s, "/sys/class/block", &|n| !nodes.iter().any(|x| x == n))?;
    remove_stale(t, s, "/sys/dev/block", &|n| n.starts_with("8:") && !minors.iter().any(|x| x == n))?;
    remove_stale(t, s, "/run/udev/data", &|n| n.starts_with("b8:") && !minors.iter().any(|x| &x[..] == &n[1..]))?;
    remove_stale(t, s, &ctrl, &|n| n.starts_with("ata") && n[3..].parse::<usize>().map_or(false, |k| k == 0 || k > facts.len()))?;

    if !facts.is_empty() {
        t.file(s, &alloc::format!("{}/uevent", ctrl), "DRIVER=ahci\n")?;
        t.link(s, &alloc::format!("{}/subsystem", ctrl), "../../../bus/pci")?;
    }
    t.dir(s, "/sys/class/block")?;
    t.dir(s, "/sys/dev/block")?;
    for (i, (d, fs)) in facts.iter().enumerate() {
        let ata = alloc::format!("{}/ata{}", ctrl, i + 1);
        let host = alloc::format!("{}/host{}", ata, i);
        let target = alloc::format!("{}/target{}:0:0", host, i);
        let dev = alloc::format!("{}/{}:0:0:0", target, i);
        let blk = alloc::format!("{}/block/{}", dev, d.name);
        let rel = &blk["/sys/".len()..];
        t.file(s, &alloc::format!("{}/uevent", ata), "")?;
        t.file(s, &alloc::format!("{}/uevent", host), "DEVTYPE=scsi_host\n")?;
        t.file(s, &alloc::format!("{}/uevent", target), "DEVTYPE=scsi_target\n")?;
        t.file(s, &alloc::format!("{}/uevent", dev), "DEVTYPE=scsi_device\nDRIVER=sd\nMODALIAS=scsi:t-0x00\n")?;
        t.link(s, &alloc::format!("{}/subsystem", dev), "../../../../../../../bus/scsi")?;
        let model = if d.model.is_empty() { "Disk" } else { &d.model };
        for (f, v) in [
            ("model", alloc::format!("{}\n", model)),
            ("vendor", String::from("ATA     \n")),
            ("rev", String::from("1.0\n")),
            ("type", String::from("0\n")),
            ("state", String::from("running\n")),
            ("device_blocked", String::from("0\n")),
            ("queue_depth", String::from("32\n")),
        ] {
            t.file(s, &alloc::format!("{}/{}", dev, f), &v)?;
        }
        let minor = i * 16;
        let sectors = d.bytes / 512;
        let ssz = d.sector_size;
        t.file(s, &alloc::format!("{}/uevent", blk), &alloc::format!("MAJOR=8\nMINOR={}\nDEVNAME={}\nDEVTYPE=disk\nDISKSEQ={}\n", minor, d.name, i + 1))?;
        for (f, v) in [
            ("dev", alloc::format!("8:{}\n", minor)),
            ("size", alloc::format!("{}\n", sectors)),
            ("ro", String::from("0\n")),
            ("removable", alloc::format!("{}\n", d.removable as u8)),
            ("range", String::from("16\n")),
            ("ext_range", String::from("256\n")),
            ("capability", String::from("0\n")),
            ("hidden", String::from("0\n")),
            ("alignment_offset", String::from("0\n")),
            ("discard_alignment", String::from("0\n")),
            ("diskseq", alloc::format!("{}\n", i + 1)),
            ("events", String::from("\n")),
            ("events_async", String::from("\n")),
            ("events_poll_msecs", String::from("-1\n")),
            ("stat", String::from("       0        0        0        0        0        0        0        0        0        0        0        0        0        0        0        0        0\n")),
            ("inflight", String::from("       0        0\n")),
            ("queue/logical_block_size", alloc::format!("{}\n", ssz)),
            ("queue/physical_block_size", alloc::format!("{}\n", ssz.max(4096))),
            ("queue/hw_sector_size", alloc::format!("{}\n", ssz)),
            ("queue/minimum_io_size", alloc::format!("{}\n", ssz.max(4096))),
            ("queue/optimal_io_size", String::from("0\n")),
            ("queue/rotational", String::from("0\n")),
            ("queue/read_ahead_kb", String::from("128\n")),
            ("queue/max_sectors_kb", String::from("256\n")),
            ("queue/max_hw_sectors_kb", String::from("256\n")),
            ("queue/discard_granularity", String::from("0\n")),
            ("queue/discard_max_bytes", String::from("0\n")),
            ("queue/discard_zeroes_data", String::from("0\n")),
            ("queue/zoned", String::from("none\n")),
            ("queue/nr_requests", String::from("64\n")),
            ("queue/scheduler", String::from("[none]\n")),
            ("queue/add_random", String::from("0\n")),
            ("queue/dax", String::from("0\n")),
            ("queue/write_cache", String::from("write back\n")),
        ] {
            t.file(s, &alloc::format!("{}/{}", blk, f), &v)?;
        }
        let up = "../".repeat(rel.split('/').count());
        t.link(s, &alloc::format!("{}/subsystem", blk), &alloc::format!("{}class/block", up))?;
        t.link(s, &alloc::format!("{}/device", blk), &alloc::format!("../../../{}:0:0:0", i))?;
        t.link(s, &alloc::format!("/sys/block/{}", d.name), &alloc::format!("../{}", rel))?;
        t.link(s, &alloc::format!("/sys/class/block/{}", d.name), &alloc::format!("../../{}", rel))?;
        t.link(s, &alloc::format!("/sys/dev/block/8:{}", minor), &alloc::format!("../../{}", rel))?;
        t.block_node(s, &alloc::format!("/dev/{}", d.name), super::blockdev::rdev(i, 0), disk_gid)?;
        // Partitions of the table no longer there
        let parts: Vec<String> = d.parts.iter().map(|p| alloc::format!("{}{}", d.name, p.number)).collect();
        remove_stale(t, s, &blk, &|n| is_sd(n) && !parts.iter().any(|x| x == n))?;
        let ignore = if d.pool.is_some() { "E:UDISKS_IGNORE=1\nE:UDISKS_SYSTEM=1\n" } else { "" };
        let id_model = udev_safe(model);
        let path_id = alloc::format!("pci-{}-ata-{}", slot, i + 1);
        let mut rec = alloc::format!(
            "I:{}\nE:ID_ATA=1\nE:ID_TYPE=disk\nE:ID_BUS=ata\nE:ID_MODEL={}\nE:ID_SERIAL={}_HYDRA{}\nE:ID_SERIAL_SHORT=HYDRA{}\nE:ID_PATH={}\nE:ID_PATH_TAG={}\n{}",
            usec,
            id_model,
            id_model,
            i,
            i,
            path_id,
            path_id.replace([':', '.'], "_"),
            ignore
        );
        if let Some((kind, guid)) = d.table {
            match kind {
                crate::fs::gpt::Kind::Gpt => rec.push_str(&alloc::format!("E:ID_PART_TABLE_TYPE=gpt\nE:ID_PART_TABLE_UUID={}\n", crate::fs::gpt::guid_string(&guid))),
                crate::fs::gpt::Kind::Mbr => rec.push_str(&alloc::format!(
                    "E:ID_PART_TABLE_TYPE=dos\nE:ID_PART_TABLE_UUID={:08x}\n",
                    u32::from_le_bytes([guid[0], guid[1], guid[2], guid[3]])
                )),
            }
        }
        rec.push_str("G:systemd\nQ:systemd\nV:1\n");
        t.file(s, &alloc::format!("/run/udev/data/b8:{}", minor), &rec)?;

        for (p, fs) in d.parts.iter().zip(fs.iter()) {
            let pname = alloc::format!("{}{}", d.name, p.number);
            let pdir = alloc::format!("{}/{}", blk, pname);
            let prel = &pdir["/sys/".len()..];
            let pminor = minor + p.number as usize;
            let label = p.entry.as_ref().map_or(String::new(), |e| e.name.clone());
            let mut ue = alloc::format!("MAJOR=8\nMINOR={}\nDEVNAME={}\nDEVTYPE=partition\nDISKSEQ={}\nPARTN={}\n", pminor, pname, i + 1, p.number);
            if !label.is_empty() {
                ue.push_str(&alloc::format!("PARTNAME={}\n", label));
            }
            t.file(s, &alloc::format!("{}/uevent", pdir), &ue)?;
            for (f, v) in [
                ("dev", alloc::format!("8:{}\n", pminor)),
                ("partition", alloc::format!("{}\n", p.number)),
                ("start", alloc::format!("{}\n", p.start / 512)),
                ("size", alloc::format!("{}\n", p.len / 512)),
                ("ro", String::from("0\n")),
                ("alignment_offset", String::from("0\n")),
                ("discard_alignment", String::from("0\n")),
                ("stat", String::from("       0        0        0        0        0        0        0        0        0        0        0        0        0        0        0        0        0\n")),
                ("inflight", String::from("       0        0\n")),
            ] {
                t.file(s, &alloc::format!("{}/{}", pdir, f), &v)?;
            }
            t.link(s, &alloc::format!("{}/subsystem", pdir), &alloc::format!("../{}class/block", up))?;
            t.link(s, &alloc::format!("/sys/class/block/{}", pname), &alloc::format!("../../{}", prel))?;
            t.link(s, &alloc::format!("/sys/dev/block/8:{}", pminor), &alloc::format!("../../{}", prel))?;
            t.block_node(s, &alloc::format!("/dev/{}", pname), super::blockdev::rdev(i, p.number), disk_gid)?;
            let mut rec = alloc::format!("I:{}\nE:ID_PATH={}-part{}\n{}", usec, path_id, p.number, ignore);
            if let (Some(e), Some((kind, _))) = (&p.entry, d.table) {
                if kind == crate::fs::gpt::Kind::Gpt {
                    rec.push_str(&alloc::format!(
                        "E:ID_PART_ENTRY_SCHEME=gpt\nE:ID_PART_ENTRY_UUID={}\nE:ID_PART_ENTRY_TYPE={}\n",
                        crate::fs::gpt::guid_string(&e.part_guid),
                        crate::fs::gpt::guid_string(&e.type_guid)
                    ));
                    if !e.name.is_empty() {
                        rec.push_str(&alloc::format!("E:ID_PART_ENTRY_NAME={}\n", udev_safe(&e.name)));
                    }
                } else {
                    rec.push_str(&alloc::format!("E:ID_PART_ENTRY_SCHEME=dos\nE:ID_PART_ENTRY_TYPE=0x{:x}\n", e.mbr_type));
                }
            }
            rec.push_str(&alloc::format!(
                "E:ID_PART_ENTRY_NUMBER={}\nE:ID_PART_ENTRY_OFFSET={}\nE:ID_PART_ENTRY_SIZE={}\nE:ID_PART_ENTRY_DISK=8:{}\n",
                p.number,
                p.start / 512,
                p.len / 512,
                minor
            ));
            if let Some(f) = fs {
                rec.push_str(&alloc::format!("E:ID_FS_TYPE={}\nE:ID_FS_USAGE=filesystem\nE:ID_FS_VERSION={}\n", f.ty, f.version));
                if !f.uuid.is_empty() {
                    rec.push_str(&alloc::format!("E:ID_FS_UUID={}\nE:ID_FS_UUID_ENC={}\n", f.uuid, f.uuid));
                }
                if !f.label.is_empty() {
                    rec.push_str(&alloc::format!("E:ID_FS_LABEL={}\nE:ID_FS_LABEL_ENC={}\n", udev_safe(&f.label), f.label));
                }
            }
            rec.push_str("G:systemd\nQ:systemd\nV:1\n");
            t.file(s, &alloc::format!("/run/udev/data/b8:{}", pminor), &rec)?;
        }
    }
    Ok(())
}

/// `/run/hydra/live` (the live session), `/run/hydra/setup.conf` (first-boot settings,
/// readable by root only) and `/run/hydra/boot-disk` (the disk holding the pool, e.g.
/// `sda`): from the boot volume, see [`crate::arch::bootdisk`]. Absent when not so.
fn boot_flag_files(t: &mut Tree, s: &mut ZfsServer, facts: &[(crate::fs::blockdev::Disk, Vec<Option<FsInfo>>)]) -> Result<(), i64> {
    let info = crate::arch::bootdisk::info();
    let boot_disk = facts.iter().find(|(d, _)| d.pool.is_some()).map(|(d, _)| alloc::format!("{}
", d.name));
    // wave11 GH: /run/hydra/nettest with the boot word nettest (hydra-live-setup then runs
    // hydra-nettest a minute after the session starts)
    let nettest = crate::arch::bootopts::say(&[b"nettest"]).then(|| b"1\n".to_vec());
    let wanted: [(&str, Option<Vec<u8>>, u32); 4] = [
        ("nettest", nettest, 0o644),
        ("live", info.live.then(|| b"1
".to_vec()), 0o644),
        ("setup.conf", info.setup_conf.clone(), 0o600),
        ("boot-disk", boot_disk.map(|n| n.into_bytes()), 0o644),
    ];
    for (name, content, perm) in wanted {
        let path = alloc::format!("/run/hydra/{}", name);
        match content {
            Some(c) => t.file_bytes(s, &path, &c, perm)?,
            None => {
                if let Some(dir) = lookup_path(s, t.root, "/run/hydra") {
                    remove_all(t, s, dir, name)?;
                }
            }
        }
    }
    Ok(())
}

/// `/sys/firmware/efi`: the firmware's bitness and the variables as efivarfs files (see
/// [`super::efivars`]); stale variable files are removed.
fn efivars_tree(t: &mut Tree, s: &mut ZfsServer, vars: Option<&[(String, Vec<u8>)]>) -> Result<(), i64> {
    t.file(s, "/sys/firmware/efi/fw_platform_size", "64
")?;
    let Some(vars) = vars else { return Ok(()) };
    let dir = t.dir(s, super::efivars::DIR)?;
    super::efivars::DIR_INO.store(dir, core::sync::atomic::Ordering::Relaxed);
    remove_stale(t, s, super::efivars::DIR, &|n| !vars.iter().any(|(v, _)| v == n))?;
    for (name, content) in vars {
        t.file_bytes(s, &alloc::format!("{}/{}", super::efivars::DIR, name), content, 0o644)?;
    }
    Ok(())
}

/// Rewrites the UEFI variable files (after a variable changed).
pub fn refresh_efivars() {
    let Some(root) = LINUX_ROOT.lock().clone() else { return };
    let Ok(root_ino) = crate::fs::ZfsClient::resolve(0, root.as_bytes(), true) else { return };
    let vars = super::efivars::snapshot();
    let mut tree = Tree { root: root_ino, changed: false, at: String::new() };
    if let Err(e) = crate::fs::zfs::with_server(|s| efivars_tree(&mut tree, s, vars.as_deref())) {
        crate::kprintln!("[devices] rewriting the UEFI variables failed at {}: errno {}", tree.at, -e);
    }
}

/// Rewrites the block devices in the Linux root (after `BLKRRPART`/`BLKPG` changed a
/// partition list).
pub fn refresh_block_tree() {
    let Some(root) = LINUX_ROOT.lock().clone() else { return };
    let Ok(root_ino) = crate::fs::ZfsClient::resolve(0, root.as_bytes(), true) else { return };
    let facts = block_facts();
    let mut tree = Tree { root: root_ino, changed: false, at: String::new() };
    let usec = crate::arch::pit::ticks() * 10_000;
    if let Err(e) = crate::fs::zfs::with_server(|s| block_tree(&mut tree, s, usec, &facts)) {
        crate::kprintln!("[devices] rewriting the block devices failed at {}: errno {}", tree.at, -e);
    }
}
