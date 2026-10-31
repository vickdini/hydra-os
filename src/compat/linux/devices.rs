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
pub fn vga_slot() -> String {
    vga().slot
}

/// Writes files under one root, remembering whether anything changed.
struct Tree {
    root: u64,
    changed: bool,
}

fn split(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(i) => (&path[..i], &path[i + 1..]),
        None => ("", path),
    }
}

impl Tree {
    fn dir(&mut self, s: &mut ZfsServer, path: &str) -> Result<u64, i64> {
        let mut ino = self.root;
        for comp in path.split('/').filter(|c| !c.is_empty()) {
            ino = match s.lookup(ino, comp.as_bytes()) {
                Ok(i) => i,
                Err(ENOENT) => {
                    self.changed = true;
                    s.mkdir(ino, comp.as_bytes(), 0o755, 0, 0)?
                }
                Err(e) => return Err(e),
            };
        }
        Ok(ino)
    }

    /// The entry `name` in `dir` if it has file type `ty`; anything else there is removed.
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

    fn file(&mut self, s: &mut ZfsServer, path: &str, content: &str) -> Result<(), i64> {
        self.file_bytes(s, path, content.as_bytes(), 0o644)
    }

    fn file_bytes(&mut self, s: &mut ZfsServer, path: &str, content: &[u8], perm: u32) -> Result<(), i64> {
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

    fn link(&mut self, s: &mut ZfsServer, path: &str, target: &str) -> Result<(), i64> {
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

    fn node(&mut self, s: &mut ZfsServer, path: &str, rdev: u64, gid: u32) -> Result<(), i64> {
        let (parent, name) = split(path);
        let dir = self.dir(s, parent)?;
        if let Some(i) = self.existing(s, dir, name, S_IFCHR)? {
            let a = s.getattr(i)?;
            if a.rdev == rdev && a.gid == gid && a.mode & 0o777 == 0o660 {
                return Ok(());
            }
            s.unlink(dir, name.as_bytes())?;
        }
        self.changed = true;
        s.mknod(dir, name.as_bytes(), S_IFCHR | 0o660, rdev, 0, gid)?;
        Ok(())
    }
}

/// Looks `path` up below directory `root` without following symbolic links (the caller
/// holds the file server, so `ZfsClient` cannot be used).
fn lookup_path(s: &mut ZfsServer, root: u64, path: &str) -> Option<u64> {
    let mut ino = root;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        ino = s.lookup(ino, comp.as_bytes()).ok()?;
    }
    Some(ino)
}

/// Group id of `name` in the root's `/etc/group` (`fallback` if absent).
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
fn bit_list(bytes: &[u8]) -> String {
    let mut out = String::new();
    for bit in 0..bytes.len() * 8 {
        if bytes[bit / 8] & (1 << (bit % 8)) != 0 {
            out.push_str(&alloc::format!("{:x},", bit));
        }
    }
    out
}

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
    t.link(s, "/sys/class/drm/card0", &alloc::format!("../../devices/pci0000:00/{}/drm/card0", v.slot))?;
    t.link(s, "/sys/dev/char/226:0", &alloc::format!("../../devices/pci0000:00/{}/drm/card0", v.slot))?;
    t.node(s, "/dev/dri/card0", super::chardev::makedev(226, 0), video)?;
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

    // ---- The login manager and the script that starts a graphical session ----
    t.file(s, "/usr/share/dbus-1/system.d/org.freedesktop.login1.conf", include_str!("../../../userland/hydra-logind/org.freedesktop.login1.conf"))?;
    t.file_bytes(s, "/usr/libexec/hydra-session", include_bytes!("../../../userland/hydra-logind/hydra-session"), 0o755)?;
    if let Some(logind) = boot_binary(s, "/bin/hydra-logind.elf") {
        t.file_bytes(s, "/usr/libexec/hydra-logind", &logind, 0o755)?;
    }
    Ok(())
}

/// Contents of a file imported from the boot volume into the pool's `/bin`.
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
pub fn populate(root: &str) -> Result<(), &'static str> {
    let root_ino = crate::fs::ZfsClient::resolve(0, root.as_bytes(), true).map_err(|_| "no such root directory")?;
    let mut tree = Tree { root: root_ino, changed: false };
    crate::fs::zfs::with_server(|s| populate_tree(&mut tree, s)).map_err(|_| "could not write the device tree")?;
    if tree.changed {
        let _ = crate::fs::ZfsClient::sync();
    }
    Ok(())
}
