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
        self.at = String::from(path);
        let (parent, name) = split(path);
        let dir = self.dir(s, parent)?;
        if let Some(i) = self.existing(s, dir, name, S_IFCHR)? {
            let a = s.getattr(i)?;
            // A boot starts with root owning every node (the seat daemon hands some out)
            if a.rdev == rdev && a.uid == 0 && a.gid == gid && a.mode & 0o777 == perm {
                return Ok(());
            }
            s.unlink(dir, name.as_bytes())?;
        }
        self.changed = true;
        s.mknod(dir, name.as_bytes(), S_IFCHR | perm, rdev, 0, gid)?;
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

    // ---- Input: the i8042 keyboard (event0) and mouse (event1) ----
    t.file(s, "/sys/devices/platform/uevent", "")?;
    t.file(s, "/sys/devices/platform/i8042/uevent", "DRIVER=i8042\nMODALIAS=platform:i8042\n")?;
    t.link(s, "/sys/devices/platform/i8042/subsystem", "../../../bus/platform")?;
    for dev in 0..2usize {
        let (name, phys, id) = super::evdev::device_info(dev);
        let serio = alloc::format!("/sys/devices/platform/i8042/serio{}", dev);
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
        let rel = alloc::format!("../../devices/platform/i8042/serio{}/input/input{}", dev, dev);
        t.link(s, &alloc::format!("/sys/class/input/input{}", dev), &rel)?;
        t.link(s, &alloc::format!("/sys/class/input/event{}", dev), &alloc::format!("{}/event{}", rel, dev))?;
        t.link(s, &alloc::format!("/sys/dev/char/13:{}", minor), &alloc::format!("{}/event{}", rel, dev))?;
        t.node(s, &alloc::format!("/dev/input/event{}", dev), super::chardev::makedev(13, minor), input)?;
        let class = if dev == 0 { "E:ID_INPUT_KEY=1\nE:ID_INPUT_KEYBOARD=1\nE:XKBMODEL=pc105\nE:XKBLAYOUT=us\n" } else { "E:ID_INPUT_MOUSE=1\n" };
        t.file(
            s,
            &alloc::format!("/run/udev/data/c13:{}", minor),
            &alloc::format!(
                "I:{}\nE:ID_INPUT=1\n{}E:ID_BUS=i8042\nE:ID_SERIAL=noserial\nE:ID_PATH=platform-i8042-serio-{}\nE:ID_PATH_TAG=platform-i8042-serio-{}\nG:seat\nG:uaccess\nQ:seat\nQ:uaccess\nV:1\n",
                usec, class, dev, dev
            ),
        )?;
        t.link(s, &alloc::format!("/dev/input/by-path/platform-i8042-serio-{}-event-{}", dev, if dev == 0 { "kbd" } else { "mouse" }), &alloc::format!("../event{}", dev))?;
    }
    t.dir(s, "/sys/bus/serio/devices")?;
    t.dir(s, "/sys/bus/platform/devices")?;
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
    let dns = crate::net::GLOBAL_INTERFACE.lock().dns_server();
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
    t.file_bytes(s, "/etc/hosts", b"127.0.0.1\tlocalhost\n127.0.1.1\thydra\n::1\tlocalhost ip6-localhost ip6-loopback\n", 0o644)?;
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

    // Brave: its own launcher (/opt/brave.com/brave/brave-browser), on Wayland, with
    // Chromium's sandbox (user, PID and network namespaces, seccomp-bpf). It uses Ubuntu's
    // NSS like on any Ubuntu system: no private copies, no LD_LIBRARY_PATH
    let brave_wrapper = b"#!/bin/sh\n# Written by Hydra\nexec /opt/brave.com/brave/brave-browser --ozone-platform=wayland \"$@\"\n";
    if lookup_path(s, t.root, "/opt/brave.com/brave/brave-browser").is_some() {
        for path in ["/usr/bin/brave-browser", "/usr/bin/brave-browser-stable", "/usr/bin/brave"] {
            let _ = t.file_bytes(s, path, brave_wrapper, 0o755);
        }
    }
    // Older Hydra versions put NSS copies (of mixed versions, which NSS rejects with
    // SEC_ERROR_PKCS11_GENERAL_ERROR) next to Brave and wrappers in /usr/local/bin
    if let Some(dir) = lookup_path(s, t.root, "/opt/brave.com/brave") {
        for name in [
            "libfreebl3.so", "libfreeblpriv3.so", "libfreebl3.chk", "libfreeblpriv3.chk", "libsoftokn3.so", "libsoftokn3.chk",
            "libnssdbm3.so", "libnssdbm3.chk", "libnssckbi.so", "libnss3.so", "libnssutil3.so", "libnspr4.so", "libplc4.so",
            "libplds4.so", "libsmime3.so", "libssl3.so",
        ] {
            if s.lookup(dir, name.as_bytes()).is_ok() {
                let _ = s.unlink(dir, name.as_bytes());
                t.changed = true;
            }
        }
    }
    if let Some(dir) = lookup_path(s, t.root, "/usr/local/bin") {
        for name in ["brave-browser", "brave"] {
            if s.lookup(dir, name.as_bytes()).is_ok() {
                let _ = s.unlink(dir, name.as_bytes());
            }
        }
    }

    // Ensure /dev/shm (POSIX shared memory) exists with mode 1777 (world-writable + sticky)
    let shm = t.dir(s, "/dev/shm")?;
    let _ = s.setattr(shm, crate::fs::zfs::zpl::SetAttr { mode: Some(0o1777), ..Default::default() });
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
    Ok(())
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
    if let Err(e) = crate::fs::zfs::with_server(|s| populate_tree(&mut tree, s)) {
        crate::kprintln!("[devices] writing the device tree into {} failed at {}: errno {}", root, tree.at, -e);
        return Err("could not write the device tree");
    }
    // No sync of its own: the changes are visible at once, and the background commit
    // writes them (most boots only give the device nodes back to root, which took a
    // second's sync before the login screen could start)
    Ok(())
}
