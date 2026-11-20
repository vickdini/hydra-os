//! `devices.rs`: the device nodes, sysfs tree, udev records and system files written
//! into a Linux root, on an in-memory ZFS file server (`fake::FS`, per test thread):
//! what is written, that a second run rewrites nothing, that administrators' edits stay,
//! the clean-ups of older versions, the block devices and UEFI variables, and failures.
//! (No sound card in this binary: see `devices_sound.rs`.)

mod common;

use hydra_hosttests_t28::compat::linux::chardev::makedev;
use hydra_hosttests_t28::compat::linux::devices;
use hydra_hosttests_t28::fake::{self, fs_lookup, fs_node, fs_read, fs_readlink, fs_symlink, fs_text, fs_write, Partition, PciDevice};
use hydra_hosttests_t28::fs::gpt::{Kind, Part};

const R: &str = "/linux";

fn root() {
    fake::fs_mkdir_p(R);
}

fn populate() {
    devices::populate(R).expect("populate");
}

fn path(p: &str) -> String {
    format!("{R}{p}")
}
fn text(p: &str) -> String {
    fs_text(&path(p))
}
fn exists(p: &str) -> bool {
    fs_node(&path(p)).is_some()
}
fn link(p: &str) -> String {
    fs_readlink(&path(p)).unwrap_or_else(|| panic!("no link {p}"))
}

/// Populates again and checks that nothing was written: the modes of /run/sddm and
/// /dev/shm are set again each time (2 setattr), and the /run/sddm clean-up tries to
/// unlink "." and ".." of its listing (2 unlink, refused by the file server with EISDIR:
/// harmless, nothing changes).
fn second_run_writes_nothing() {
    let before = fake::with_fs(|fs| fs.ops.clone());
    populate();
    let after = fake::with_fs(|fs| fs.ops.clone());
    let d = |op: &str| after.get(op).copied().unwrap_or(0) - before.get(op).copied().unwrap_or(0);
    for op in ["write", "create", "mknod", "symlink", "mkdir", "rmdir"] {
        assert_eq!(d(op), 0, "the second run did {op}");
    }
    assert_eq!((d("setattr"), d("unlink")), (2, 2));
}

#[test]
fn a_bare_root_gets_the_device_tree() {
    root();
    fake::VMMOUSE.set(false);
    populate();
    // DRM: the fallback adapter (no PCI display found), card0 and its links
    let pci = "/sys/devices/pci0000:00/0000:00:02.0";
    let ue = text(&format!("{pci}/uevent"));
    assert!(ue.contains("DRIVER=hydradrm\n") && ue.contains("PCI_ID=1234:1111\n") && ue.contains("MODALIAS=pci:v00001234d00001111sv00001AF4sd00001100bc03sc00i00\n"), "{ue}");
    assert_eq!(text(&format!("{pci}/vendor")), "0x1234\n");
    assert_eq!(text(&format!("{pci}/revision")), "0x02\n");
    assert_eq!(text(&format!("{pci}/boot_vga")), "1\n");
    assert_eq!(link(&format!("{pci}/driver")), "../../../bus/pci/drivers/hydradrm");
    assert_eq!(text(&format!("{pci}/drm/card0/dev")), "226:0\n");
    assert_eq!(link("/sys/class/drm/card0"), "../../devices/pci0000:00/0000:00:02.0/drm/card0");
    assert_eq!(link("/sys/dev/char/226:0"), "../../devices/pci0000:00/0000:00:02.0/drm/card0");
    assert!(exists("/sys/fs/cgroup"));
    // The device nodes: numbers, groups (video 44 and input 106 without /etc/group), modes
    let card = fs_node(&path("/dev/dri/card0")).unwrap();
    assert_eq!((card.mode, card.rdev, card.gid, card.uid), (0o020660, makedev(226, 0), 44, 0));
    let fuse = fs_node(&path("/dev/fuse")).unwrap();
    assert_eq!((fuse.mode, fuse.rdev), (0o020666, makedev(10, 229)));
    assert_eq!(link("/etc/mtab"), "../proc/self/mounts");
    assert_eq!(link("/dev/dri/by-path/pci-0000:00:02.0-card"), "../card0");
    let rec = text("/run/udev/data/c226:0");
    assert!(rec.starts_with("I:1000000\n") && rec.contains("E:ID_PATH_TAG=pci-0000_00_02_0\n") && rec.contains("G:master-of-seat\n"), "{rec}");
    // Input: keyboard and mouse only (no absolute pointer)
    for (dev, minor) in [(0, 64), (1, 65)] {
        let n = fs_node(&path(&format!("/dev/input/event{dev}"))).unwrap();
        assert_eq!((n.rdev, n.gid), (makedev(13, minor), 106));
        assert!(text(&format!("/run/udev/data/c13:{minor}")).contains("E:ID_INPUT=1\n"));
    }
    assert!(!exists("/dev/input/event2"));
    let kbd = "/sys/devices/platform/i8042/serio0/input/input0";
    assert_eq!(text(&format!("{kbd}/name")), "AT Translated Set 2 keyboard\n");
    assert_eq!(text(&format!("{kbd}/id/version")), "ab41\n");
    let ue = text(&format!("{kbd}/uevent"));
    assert!(ue.contains("PRODUCT=11/1/1/ab41\n") && ue.contains("EV=120013\n") && ue.contains("MSC=10\n") && ue.contains("LED=7\n"), "{ue}");
    assert!(ue.contains("MODALIAS=input:b0011v0001p0001eAB41-e0,1,4,11,14,k1,2,"), "{ue}");
    assert_eq!(text(&format!("{kbd}/capabilities/rel")), "0\n");
    assert_eq!(text(&format!("{kbd}/capabilities/key")), "e000ffff01ffffff fffffffffffffffe
");
    assert!(text("/run/udev/data/c13:64").contains("E:ID_INPUT_KEYBOARD=1\n"));
    assert!(text("/run/udev/data/c13:65").contains("E:ID_INPUT_MOUSE=1\n"));
    assert_eq!(text("/sys/devices/platform/i8042/serio1/input/input1/capabilities/rel"), "903\n");
    assert_eq!(link("/dev/input/by-path/platform-i8042-serio-0-event-kbd"), "../event0");
    assert_eq!(link("/dev/input/by-path/platform-i8042-serio-1-event-mouse"), "../event1");
    assert_eq!(link("/sys/class/input/event1"), "../../devices/platform/i8042/serio1/input/input1/event1");
    // udev runs; tmpfiles' directories
    assert_eq!(text("/run/udev/control"), "");
    assert_eq!(fs_node(&path("/tmp")).unwrap().mode & 0o7777, 0o1777);
    assert_eq!(fs_node(&path("/tmp/.X11-unix")).unwrap().mode & 0o7777, 0o1777);
    assert_eq!(fs_node(&path("/tmp/.ICE-unix")).unwrap().mode & 0o7777, 0o1777);
    let u101 = fs_node(&path("/run/user/101")).unwrap();
    assert_eq!((u101.uid, u101.gid, u101.mode & 0o7777), (101, 101, 0o700));
    assert_eq!(fs_node(&path("/var/lib/sddm")).unwrap().uid, 101);
    assert_eq!(fs_node(&path("/run/sddm")).unwrap().mode & 0o7777, 0o755);
    // Session helpers, network files, power helpers
    assert!(text("/etc/xdg/autostart/hydra-pipewire.desktop").contains("Exec=pipewire\n"));
    assert!(text("/etc/xdg/autostart/hydra-wireplumber.desktop").contains("X-KDE-autostart-phase=1\n"));
    assert!(text("/etc/xdg/startkderc").contains("systemdBoot=false"));
    assert_eq!(fs_node(&path("/usr/libexec/hydra-session")).unwrap().mode & 0o777, 0o755);
    assert!(exists("/usr/share/dbus-1/system.d/org.freedesktop.login1.conf"));
    assert!(!exists("/usr/libexec/hydra-logind"), "no binary on the boot volume");
    assert!(text("/etc/resolv.conf").contains("nameserver 10.0.2.3\n"));
    assert!(text("/etc/hosts").contains("127.0.1.1\thydra\n"));
    assert_eq!(text("/usr/local/bin/reboot"), "#!/bin/sh\nexec /sbin/reboot -f \"$@\"\n");
    assert!(exists("/usr/bin/hydra-net-check") && exists("/usr/bin/hydra-power-check"));
    assert!(exists("/usr/libexec/hydra-firstboot"));
    assert_eq!(fs_node(&path("/dev/shm")).unwrap().mode & 0o7777, 0o1777);
    assert_eq!(link("/run/shm"), "/dev/shm");
    assert_eq!(link("/dev/stderr"), "/proc/self/fd/2");
    // Access control apps (always), no live session files
    assert!(exists("/usr/lib/hydra-access/hydra_access/core.py"));
    assert!(exists("/etc/hydra/access/subjects"));
    assert!(!exists("/etc/sudoers.d/hydra-live"));
    // Optional programs absent: none of their files
    for p in ["/etc/sddm.conf.d/hydra.conf", "/etc/firefox/policies/policies.json", "/usr/local/libexec/hydra-wine-run", "/usr/share/plasma/look-and-feel/org.hydra.windows.desktop/metadata.json", "/usr/local/libexec/hydra-apps", "/usr/bin/hydra-install", "/etc/sysusers.d/hydra-malcontent.conf"] {
        assert!(!exists(p), "{p}");
    }
    // No sound card: no PipeWire settings
    assert!(!exists("/etc/pipewire/pipewire.conf.d/50-hydra-sound.conf"));
    // UEFI: the bitness only, without variables
    assert_eq!(text("/sys/firmware/efi/fw_platform_size"), "64\n");
    assert!(!exists("/sys/firmware/efi/efivars"));
    // Access policies loaded for this root
    assert_eq!(fake::ABAC_LOADS.with_borrow(|v| v.clone()), vec![R.to_string()]);

    // A second run changes nothing
    second_run_writes_nothing();
}

#[test]
fn a_real_display_adapter_and_groups() {
    root();
    fake::PCI.with_borrow_mut(|m| m.insert((3, 0), PciDevice { bus: 0, device: 0x10, function: 1, vendor_id: 0x8086, device_id: 0x0412 }));
    fake::PCI_CONFIG.with_borrow_mut(|m| {
        m.insert((0, 0x10, 1, 0x2C), 0x2010_17aa);
        m.insert((0, 0x10, 1, 0x08), 0x0300_0006);
    });
    assert_eq!(devices::vga_slot(), "0000:00:10.1");
    fs_write(&path("/etc/group"), b"root:x:0:\nvideo:x:39:user\ninput:x:104:\nbroken\ndisk:x:not-a-number:\n");
    fake::VMMOUSE.set(true);
    populate();
    let pci = "/sys/devices/pci0000:00/0000:00:10.1";
    assert!(text(&format!("{pci}/uevent")).contains("PCI_SUBSYS_ID=17AA:2010\n"));
    assert_eq!(text(&format!("{pci}/subsystem_device")), "0x2010\n");
    assert_eq!(text(&format!("{pci}/revision")), "0x06\n");
    assert_eq!(fs_node(&path("/dev/dri/card0")).unwrap().gid, 39);
    // The absolute pointer is event2, on the mouse's port
    let n = fs_node(&path("/dev/input/event2")).unwrap();
    assert_eq!((n.rdev, n.gid), (makedev(13, 66), 104));
    assert_eq!(text("/sys/devices/platform/i8042/serio1/input/input2/name"), "VirtualPS/2 VMware VMMouse\n");
    assert!(!exists("/dev/input/by-path/platform-i8042-serio-2-event-mouse"));
}

#[test]
fn stale_and_wrongly_typed_entries_are_replaced() {
    root();
    // A link where a file goes, a file where a link goes, a node with the wrong
    // number and owner, a file with the wrong mode
    fs_symlink(&path("/sys/class/drm/version"), "elsewhere");
    fs_write(&path("/etc/mtab"), b"old mtab\n");
    let card = fake::fs_mkdir_p(&path("/dev/dri"));
    fake::with_fs(|fs| {
        let i = fs.next;
        fs.next += 1;
        fs.inodes.insert(i, fake::Inode { mode: 0o020600, uid: 1000, gid: 44, rdev: makedev(226, 5), data: vec![], entries: Default::default() });
        fs.inodes.get_mut(&card).unwrap().entries.insert(b"card0".to_vec(), i);
    });
    fs_symlink(&path("/dev/dri/by-path/pci-0000:00:02.0-card"), "../old");
    let ino = fs_write(&path("/usr/libexec/hydra-session"), b"#!/bin/sh\nold\n");
    // Stale SDDM files and an sddm home with the wrong owner
    fs_write(&path("/tmp/sddm-auth-123"), b"");
    fs_write(&path("/tmp/.sddm-old"), b"");
    fs_write(&path("/tmp/keep-me"), b"");
    fs_write(&path("/run/sddm/xauth_1"), b"");
    fake::fs_mkdir_p(&path("/var/lib/sddm"));
    // An older Hydra's screen locker override, brave wrappers, the sudo rule
    fs_write(&path("/etc/xdg/kscreenlockerrc"), b"# Written by Hydra\n[Daemon]\nAutolock=false\n");
    fs_write(&path("/usr/bin/brave-browser"), b"#!/bin/sh\n# Written by Hydra\nexec brave\n");
    fs_write(&path("/usr/local/bin/brave"), b"#!/bin/sh\nexec real-brave\n");
    fs_write(&path("/etc/sudoers.d/010_nopasswd"), b"%sudo ALL=(ALL) NOPASSWD: ALL\n");
    populate();
    assert_eq!(text("/sys/class/drm/version"), "drm 1.1.0 20060810\n");
    assert_eq!(link("/etc/mtab"), "../proc/self/mounts");
    let n = fs_node(&path("/dev/dri/card0")).unwrap();
    assert_eq!((n.rdev, n.uid, n.mode), (makedev(226, 0), 0, 0o020660));
    assert_eq!(link("/dev/dri/by-path/pci-0000:00:02.0-card"), "../card0");
    let s = fake::with_fs(|fs| fs.inodes[&ino].clone());
    assert_eq!(s.mode & 0o777, 0o755);
    assert!(String::from_utf8_lossy(&s.data).contains("hydra"));
    assert!(!exists("/tmp/sddm-auth-123") && !exists("/tmp/.sddm-old") && exists("/tmp/keep-me"));
    assert!(!exists("/run/sddm/xauth_1"));
    assert_eq!(fs_node(&path("/var/lib/sddm")).unwrap().mode & 0o777, 0o750);
    assert!(!exists("/etc/xdg/kscreenlockerrc"));
    assert!(!exists("/usr/bin/brave-browser"));
    assert!(exists("/usr/local/bin/brave"), "not Hydra's: kept");
    assert!(!exists("/etc/sudoers.d/010_nopasswd"));
}

#[test]
fn administrators_edits_stay() {
    root();
    fs_write(&path("/etc/xdg/kscreenlockerrc"), b"[Daemon]\nTimeout=5\n");
    fs_write(&path("/etc/xdg/startkderc"), b"[General]\nsystemdBoot=true\n");
    fs_write(&path("/etc/sudoers.d/010_nopasswd"), b"%admins ALL=(ALL) ALL\n");
    fs_write(&path("/usr/bin/brave"), b"short");
    populate();
    assert_eq!(text("/etc/xdg/kscreenlockerrc"), "[Daemon]\nTimeout=5\n");
    assert_eq!(text("/etc/xdg/startkderc"), "[General]\nsystemdBoot=true\n");
    assert!(exists("/etc/sudoers.d/010_nopasswd"));
    assert!(exists("/usr/bin/brave"));
}

#[test]
fn environment_hostname_and_dns() {
    root();
    fs_write(&path("/etc/environment"), b"PATH=/usr/bin");
    fs_write(&path("/etc/hostname"), b"  my-pc.lan \n");
    fake::DNS.set([192, 168, 1, 1]);
    populate();
    assert_eq!(text("/etc/environment"), "PATH=/usr/bin\n# Added by Hydra: no GPU acceleration\nKWIN_COMPOSE=Q\nXCURSOR_THEME=breeze_cursors\n");
    assert!(text("/etc/hosts").contains("127.0.1.1\tmy-pc.lan\n"));
    assert!(text("/etc/resolv.conf").starts_with("# Configured by Hydra\nnameserver 192.168.1.1\n"));
    // Already there: not added again; an empty environment gets no blank line
    populate();
    assert_eq!(text("/etc/environment").matches("KWIN_COMPOSE").count(), 1);
    fs_write(&path("/etc/environment"), b"");
    fs_write(&path("/etc/hostname"), b"bad name!");
    populate();
    assert!(text("/etc/environment").starts_with("# Added by Hydra"));
    assert!(text("/etc/hosts").contains("127.0.1.1\thydra\n"));
}

#[test]
fn optional_programs_get_their_files() {
    root();
    for p in ["/usr/bin/sddm", "/usr/lib/firefox/firefox", "/opt/wine/bin/wine", "/usr/bin/plasmashell", "/usr/bin/python3", "/usr/share/dbus-1/system.d/org.freedesktop.MalcontentTimer1.conf"] {
        fs_write(&path(p), b"x");
    }
    // KDE's menu entries the Windows names are added to (systemsettings is missing)
    fs_write(
        &path("/usr/share/applications/org.kde.dolphin.desktop"),
        b"[Desktop Entry]\nName=Dolphin\nGenericName=File Manager\nKeywords=files;folders\n\n[Desktop Action new]\nName=New Window\n",
    );
    fs_write(&path("/usr/share/applications/org.kde.plasma-systemmonitor.desktop"), b"[Desktop Entry]\nName=System Monitor\nX-KDE-Shortcuts=Meta+Esc\n");
    // Hydra's copy of an entry KDE no longer has goes; an admin's own copy stays
    fs_write(&path("/usr/local/share/applications/systemsettings.desktop"), b"[Desktop Entry]\n# Written by Hydra from /usr/share/applications: x\n");
    fs_write(&path("/usr/local/share/applications/org.kde.discover.desktop"), b"[Desktop Entry]\n# Written by Hydra from /usr/share/applications: Windows' names added\n");
    // Binaries on the boot volume (the pool root, not the Linux root)
    fs_write("/bin/hydra-logind.elf", b"\x7fELF-logind");
    fs_write("/bin/hydra-socket-activate.elf", b"\x7fELF-sock");
    fs_write("/bin/hydra-access-check.elf", b"\x7fELF-check");
    fs_write(&path("/etc/pam.d/sddm"), b"#%PAM-1.0\nauth include common-auth\n@include common-account\nsession required pam_env.so\n");
    populate();
    assert!(text("/etc/sddm.conf.d/hydra.conf").contains("DisplayServer=wayland"));
    assert!(text("/etc/firefox/policies/policies.json").contains("SponsoredTopSites"));
    assert_eq!(fs_node(&path("/usr/local/libexec/hydra-wine-run")).unwrap().mode & 0o777, 0o755);
    assert!(exists("/usr/local/libexec/hydra-wine-common"));
    assert!(text("/usr/share/applications/wine.desktop").contains("hydra-wine-run %f"));
    assert!(exists("/etc/xdg/autostart/hydra-wine-setup.desktop"));
    assert!(exists("/usr/share/plasma/look-and-feel/org.hydra.windows.desktop/contents/defaults"));
    assert!(exists("/etc/xdg/kdeglobals") && exists("/etc/xdg/dolphinrc"));
    assert!(exists("/etc/xdg/plasma-workspace/env/hydra-windows-shortcuts.sh"));
    let dolphin = text("/usr/local/share/applications/org.kde.dolphin.desktop");
    assert_eq!(
        dolphin,
        "[Desktop Entry]\n# Written by Hydra from /usr/share/applications: Windows' names added\nName=Dolphin\nGenericName=File Explorer\nKeywords=files;folders;File Explorer;Explorer;This PC;My Computer;\n\n[Desktop Action new]\nName=New Window\n"
    );
    let monitor = text("/usr/local/share/applications/org.kde.plasma-systemmonitor.desktop");
    assert!(monitor.contains("GenericName=") == false && monitor.contains("X-KDE-Shortcuts=Meta+Esc,Ctrl+Shift+Esc\n") && monitor.contains("Keywords=Task Manager;taskmgr;End Task;\n"), "{monitor}");
    assert_eq!(link("/usr/local/share/kglobalaccel/org.kde.plasma-systemmonitor.desktop"), "/usr/local/share/applications/org.kde.plasma-systemmonitor.desktop");
    assert!(!exists("/usr/local/share/applications/systemsettings.desktop"));
    assert!(!exists("/usr/local/share/applications/org.kde.discover.desktop"));
    assert!(exists("/usr/local/libexec/hydra-apps") && exists("/usr/local/share/hydra-apps/catalogue.json"));
    assert!(exists("/usr/bin/hydra-install") && exists("/etc/polkit-1/rules.d/60-hydra-install.rules"));
    assert!(text("/etc/sysusers.d/hydra-malcontent.conf").contains("malcontent-timerd"));
    assert_eq!(fs_read(&path("/usr/libexec/hydra-logind")).unwrap(), b"\x7fELF-logind");
    assert_eq!(fs_read(&path("/usr/libexec/hydra-socket-activate")).unwrap(), b"\x7fELF-sock");
    assert_eq!(fs_read(&path("/usr/libexec/hydra-access-check")).unwrap(), b"\x7fELF-check");
    assert_eq!(
        text("/etc/pam.d/sddm"),
        "#%PAM-1.0\nauth include common-auth\n@include common-account\naccount required pam_exec.so quiet /usr/libexec/hydra-access-check login\nsession required pam_env.so\n"
    );
    // Once is enough
    populate();
    assert_eq!(text("/etc/pam.d/sddm").matches("hydra-access-check").count(), 1);
    // An admin's own menu entry (no marker) is not replaced
    fs_write(&path("/usr/local/share/applications/org.kde.dolphin.desktop"), b"[Desktop Entry]\nName=Mine\n");
    populate();
    assert_eq!(text("/usr/local/share/applications/org.kde.dolphin.desktop"), "[Desktop Entry]\nName=Mine\n");
}

#[test]
fn firefox_policies_follow_hydras_versions_only() {
    root();
    fs_write(&path("/usr/lib/firefox/firefox"), b"x");
    // An earlier Hydra version: replaced
    let earlier = "{\n  \"policies\": {\n    \"DisableAppUpdate\": true,\n    \"DisableTelemetry\": true,\n    \"DontCheckDefaultBrowser\": true,\n    \"OverrideFirstRunPage\": \"\",\n    \"OverridePostUpdatePage\": \"\",\n    \"UserMessaging\": {\n      \"SkipOnboarding\": true,\n      \"ExtensionRecommendations\": false,\n      \"FeatureRecommendations\": false,\n      \"UrlbarInterventions\": false,\n      \"MoreFromMozilla\": false,\n      \"FirefoxLabs\": false\n    }\n  }\n}\n";
    fs_write(&path("/etc/firefox/policies/policies.json"), earlier.as_bytes());
    populate();
    assert!(text("/etc/firefox/policies/policies.json").contains("couldRestoreSession"));
    // An administrator's own: kept
    fs_write(&path("/etc/firefox/policies/policies.json"), b"{\"policies\":{}}\n");
    populate();
    assert_eq!(text("/etc/firefox/policies/policies.json"), "{\"policies\":{}}\n");
}

#[test]
fn pam_without_the_account_include_is_left_alone() {
    root();
    fs_write("/bin/hydra-access-check.elf", b"bin");
    fs_write(&path("/etc/pam.d/sddm"), b"auth required pam_unix.so\n");
    populate();
    assert_eq!(text("/etc/pam.d/sddm"), "auth required pam_unix.so\n");
    // No binary on the boot volume but one installed: still the check
    root();
    fake::with_fs(|fs| *fs = fake::Fs::new());
    root();
    fs_write(&path("/usr/libexec/hydra-access-check"), b"old");
    fs_write(&path("/etc/pam.d/sddm"), b"@include common-account\n");
    populate();
    assert!(text("/etc/pam.d/sddm").contains("hydra-access-check login"));
}

#[test]
fn the_live_session() {
    root();
    fake::LIVE.set(true);
    populate();
    assert!(exists("/usr/local/libexec/hydra-live-setup"));
    assert!(text("/etc/sddm.conf.d/zz-hydra-live.conf").contains("User=live"));
    let sudo = fs_node(&path("/etc/sudoers.d/hydra-live")).unwrap();
    assert_eq!(sudo.mode & 0o777, 0o440);
    assert!(exists("/etc/polkit-1/rules.d/49-hydra-live.rules"));
    assert!(exists("/etc/xdg/autostart/hydra-live-hint.desktop"));
    // Placeholders for the installer until the pool has it
    assert!(exists("/usr/bin/hydra-install"));
    assert!(exists("/usr/share/applications/hydra-install.desktop"));
    // A boot that is not live removes the live-only files
    fake::LIVE.set(false);
    populate();
    for p in ["/etc/sddm.conf.d/zz-hydra-live.conf", "/etc/sudoers.d/hydra-live", "/etc/polkit-1/rules.d/49-hydra-live.rules", "/etc/xdg/autostart/hydra-live-hint.desktop"] {
        assert!(!exists(p), "{p}");
    }
}

#[test]
fn symlinked_directories_are_followed() {
    root();
    // /var/lib -> ../varlib (relative), /usr/local/share -> /usr/share (absolute in the root)
    fake::fs_mkdir_p(&path("/varlib"));
    fs_symlink(&path("/var/lib"), "../varlib");
    fake::fs_mkdir_p(&path("/usr/share"));
    fs_symlink(&path("/usr/local/share"), "/usr/share");
    fs_write(&path("/usr/bin/python3"), b"x");
    // A loop is not followed for ever
    fs_symlink(&path("/etc/loop1"), "loop2");
    fs_symlink(&path("/etc/loop2"), "loop1");
    fs_symlink(&path("/etc/sudoers.d"), "loop1");
    populate();
    assert_eq!(fs_node(&path("/varlib/sddm")).unwrap().uid, 101);
    assert!(exists("/usr/share/hydra-apps/catalogue.json"));
}

#[test]
fn failures_are_reported() {
    // No such root
    assert_eq!(devices::populate("/nowhere"), Err("no such root directory"));
    // The file server is not there
    root();
    fake::SERVER_DOWN.set(Some(-5));
    assert_eq!(devices::populate(R), Err("could not write the device tree"));
    fake::SERVER_DOWN.set(None);
    // Each kind of operation failing
    for op in ["mkdir", "create", "write", "symlink", "mknod", "lookup", "getattr"] {
        fake::with_fs(|fs| *fs = fake::Fs::new());
        root();
        fake::with_fs(|fs| fs.fail.push((op, -28)));
        assert_eq!(devices::populate(R), Err("could not write the device tree"), "{op}");
    }
    // Rewriting a file whose truncation fails; unlinking a wrong-typed entry fails
    for (op, pre) in [("setattr", "/sys/devices/pci0000:00/uevent"), ("unlink", "/etc/mtab"), ("read", "/sys/devices/pci0000:00/uevent"), ("readlink", "/etc/mtab")] {
        fake::with_fs(|fs| *fs = fake::Fs::new());
        root();
        populate();
        if op == "setattr" || op == "read" {
            fs_write(&path(pre), b"something else");
        } else if op == "unlink" {
            fake::with_fs(|fs| *fs = fake::Fs::new());
            root();
            fs_write(&path(pre), b"a file");
        }
        fake::with_fs(|fs| fs.fail.push((op, -5)));
        assert_eq!(devices::populate(R), Err("could not write the device tree"), "{op}");
    }
}

// ------------------------------------------------------------ block devices

fn guid(b: u8) -> [u8; 16] {
    let mut g = [0u8; 16];
    for (i, x) in g.iter_mut().enumerate() {
        *x = b.wrapping_add(i as u8);
    }
    g
}

/// A FAT boot sector: FAT32 or FAT16/12 with id and label.
fn fat(version: &str, id: u32, label: &str) -> Vec<u8> {
    let mut s = vec![0u8; 512];
    let (at, idat, lat) = if version == "FAT32" { (82, 0x43, 0x47) } else { (54, 0x27, 0x2B) };
    s[at..at + 5].copy_from_slice(version.as_bytes());
    s[idat..idat + 4].copy_from_slice(&id.to_le_bytes());
    let mut l = [b' '; 11];
    l[..label.len()].copy_from_slice(label.as_bytes());
    s[lat..lat + 11].copy_from_slice(&l);
    s[510] = 0x55;
    s[511] = 0xAA;
    s
}

const MIB: u64 = 1 << 20;

/// sda: GPT, an ESP (FAT32 "EFI") and the pool; sdb: MBR, a FAT16 stick, removable.
fn two_disks() {
    let a = fake::add_disk("sda", 8 * MIB);
    fake::with_disk(a, |d| {
        d.disk.model = "Samsung SSD 860 (x)".into();
        d.disk.table = Some((Kind::Gpt, guid(0x10)));
        d.disk.pool = Some((4 * MIB, 4 * MIB));
        d.disk.parts.push(Partition {
            number: 1,
            start: MIB,
            len: 2 * MIB,
            entry: Some(Part { number: 1, start: MIB, len: 2 * MIB, type_guid: guid(0x20), part_guid: guid(0x30), name: "EFI system partition".into(), mbr_type: 0 }),
        });
        d.disk.parts.push(Partition { number: 2, start: 4 * MIB, len: 4 * MIB, entry: None });
        d.data[MIB as usize..MIB as usize + 512].copy_from_slice(&fat("FAT32", 0xABCD_1234, "EFI"));
    });
    let b = fake::add_disk("sdb", 4 * MIB);
    fake::with_disk(b, |d| {
        d.disk.removable = true;
        d.disk.sector_size = 4096;
        d.disk.table = Some((Kind::Mbr, guid(0x40)));
        d.disk.parts.push(Partition {
            number: 1,
            start: MIB,
            len: MIB,
            entry: Some(Part { number: 1, start: MIB, len: MIB, type_guid: [0; 16], part_guid: [0; 16], name: String::new(), mbr_type: 0x0c }),
        });
        d.data[MIB as usize..MIB as usize + 512].copy_from_slice(&fat("FAT16", 0x0102_0304, "NO NAME"));
    });
}

#[test]
fn block_devices_sysfs_and_udev() {
    root();
    fake::PCI.with_borrow_mut(|m| m.insert((1, 6), PciDevice { bus: 0, device: 0x1f, function: 2, vendor_id: 0x8086, device_id: 0x2922 }));
    fs_write(&path("/etc/group"), b"disk:x:66:\n");
    two_disks();
    populate();
    let ctrl = "/sys/devices/pci0000:00/0000:00:1f.2";
    assert_eq!(text(&format!("{ctrl}/uevent")), "DRIVER=ahci\n");
    let dev = format!("{ctrl}/ata1/host0/target0:0:0/0:0:0:0");
    assert_eq!(text(&format!("{dev}/model")), "Samsung SSD 860 (x)\n");
    let blk = format!("{dev}/block/sda");
    assert!(text(&format!("{blk}/uevent")).contains("DEVNAME=sda\nDEVTYPE=disk\nDISKSEQ=1\n"));
    assert_eq!(text(&format!("{blk}/size")), format!("{}\n", 8 * MIB / 512));
    assert_eq!(text(&format!("{blk}/queue/physical_block_size")), "4096\n");
    assert_eq!(text(&format!("{blk}/removable")), "0\n");
    assert_eq!(link("/sys/block/sda"), "../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda");
    assert_eq!(link(&format!("{blk}/subsystem")), "../../../../../../../../../class/block");
    assert_eq!(link("/sys/dev/block/8:1"), "../../devices/pci0000:00/0000:00:1f.2/ata1/host0/target0:0:0/0:0:0:0/block/sda/sda1");
    let n = fs_node(&path("/dev/sda1")).unwrap();
    assert_eq!((n.mode, n.rdev, n.gid), (0o060660, makedev(8, 1), 66));
    assert_eq!(fs_node(&path("/dev/sdb")).unwrap().rdev, makedev(8, 16));
    assert_eq!(text(&format!("{blk}/sda1/start")), format!("{}\n", MIB / 512));
    assert!(text(&format!("{blk}/sda1/uevent")).contains("PARTNAME=EFI system partition\n"));
    // udev: the disk with its GPT and the pool's ignore flags
    let rec = text("/run/udev/data/b8:0");
    assert!(rec.contains("E:ID_MODEL=Samsung_SSD_860__x_\n") && rec.contains("E:ID_SERIAL=Samsung_SSD_860__x__HYDRA0\n"), "{rec}");
    assert!(rec.contains("E:ID_PATH=pci-0000:00:1f.2-ata-1\nE:ID_PATH_TAG=pci-0000_00_1f_2-ata-1\n"), "{rec}");
    assert!(rec.contains("E:UDISKS_IGNORE=1\n") && rec.contains("E:ID_PART_TABLE_TYPE=gpt\nE:ID_PART_TABLE_UUID=13121110-1514-1716-1819-1a1b1c1d1e1f\n"), "{rec}");
    let esp = text("/run/udev/data/b8:1");
    assert!(esp.contains("E:ID_PART_ENTRY_SCHEME=gpt\n") && esp.contains("E:ID_PART_ENTRY_NAME=EFI_system_partition\n"), "{esp}");
    assert!(esp.contains("E:ID_FS_TYPE=vfat\n") && esp.contains("E:ID_FS_VERSION=FAT32\n") && esp.contains("E:ID_FS_UUID=ABCD-1234\n") && esp.contains("E:ID_FS_LABEL=EFI\nE:ID_FS_LABEL_ENC=EFI\n"), "{esp}");
    assert!(esp.contains("E:ID_PART_ENTRY_OFFSET=2048\nE:ID_PART_ENTRY_SIZE=4096\nE:ID_PART_ENTRY_DISK=8:0\n"), "{esp}");
    let pool = text("/run/udev/data/b8:2");
    assert!(pool.contains("E:ID_FS_TYPE=zfs_member\n") && pool.contains("E:ID_FS_LABEL=hydrapool\n") && !pool.contains("ID_FS_UUID"), "{pool}");
    assert!(!pool.contains("ID_PART_ENTRY_SCHEME"), "no table entry: {pool}");
    // sdb: MBR, removable, 4K sectors, an unlabelled FAT16 stick
    let sdb = text("/run/udev/data/b8:16");
    assert!(sdb.contains("E:ID_PART_TABLE_TYPE=dos\nE:ID_PART_TABLE_UUID=43424140\n") && sdb.contains("E:ID_MODEL=Disk\n") && !sdb.contains("UDISKS"), "{sdb}");
    let stick = text("/run/udev/data/b8:17");
    assert!(stick.contains("E:ID_PART_ENTRY_SCHEME=dos\nE:ID_PART_ENTRY_TYPE=0xc\n") && stick.contains("E:ID_FS_VERSION=FAT16\n") && !stick.contains("ID_FS_LABEL"), "{stick}");
    let sdb_blk = format!("{ctrl}/ata2/host1/target1:0:0/1:0:0:0/block/sdb");
    assert_eq!(text(&format!("{sdb_blk}/removable")), "1\n");
    assert_eq!(text(&format!("{sdb_blk}/queue/logical_block_size")), "4096\n");
    // The boot disk flag: the disk holding the pool
    assert_eq!(text("/run/hydra/boot-disk"), "sda\n");
    assert!(!exists("/run/hydra/live"));
    // A second run rewrites nothing
    second_run_writes_nothing();
}

#[test]
fn what_no_longer_exists_is_removed() {
    root();
    two_disks();
    populate();
    // Remember an old disk sdc with a partition and its records
    fake::with_fs(|_| ());
    fake::fs_mkdir_p(&path("/sys/block/sdc"));
    fs_write(&path("/sys/block/sdc/size"), b"1\n");
    fs_write(&path("/dev/sdc"), b"");
    fs_write(&path("/dev/sdc1"), b"");
    fs_write(&path("/dev/sda9"), b"");
    fs_write(&path("/dev/sd"), b"not a disk name");
    fs_write(&path("/dev/sdX"), b"not a disk name either");
    fs_write(&path("/run/udev/data/b8:32"), b"");
    fs_write(&path("/run/udev/data/c13:64.keep"), b"");
    fs_symlink(&path("/sys/dev/block/8:33"), "x");
    fs_symlink(&path("/sys/class/block/sdc"), "x");
    let ctrl = "/sys/devices/pci0000:00/0000:00:01.1";
    fake::fs_mkdir_p(&path(&format!("{ctrl}/ata3/host2")));
    fake::fs_mkdir_p(&path(&format!("{ctrl}/ata0")));
    fake::fs_mkdir_p(&path(&format!("{ctrl}/atax")));
    let blk = format!("{ctrl}/ata1/host0/target0:0:0/0:0:0:0/block/sda");
    fake::fs_mkdir_p(&path(&format!("{blk}/sda7")));
    // The disk lost its second partition
    fake::with_disk(0, |d| {
        d.disk.parts.truncate(1);
    });
    populate();
    for p in ["/sys/block/sdc", "/dev/sdc", "/dev/sdc1", "/dev/sda9", "/dev/sda2", "/run/udev/data/b8:32", "/run/udev/data/b8:2", "/sys/dev/block/8:33", "/sys/class/block/sdc", &format!("{ctrl}/ata3"), &format!("{ctrl}/ata0"), &format!("{blk}/sda7"), &format!("{blk}/sda2")] {
        assert!(!exists(p), "{p} still there");
    }
    for p in ["/dev/sd", "/dev/sdX", "/run/udev/data/c13:64.keep", &format!("{ctrl}/atax"), "/dev/sda1", "/sys/block/sdb"] {
        assert!(exists(p), "{p} removed");
    }
    // No disks at all: everything of theirs goes
    fake::DISKS.with_borrow_mut(|d| d.clear());
    populate();
    assert!(!exists("/dev/sda") && !exists("/sys/block/sda") && !exists("/run/hydra/boot-disk"));
}

#[test]
fn unreadable_partitions_have_no_file_system() {
    root();
    two_disks();
    fake::with_disk(1, |d| d.fail = Some(-5));
    populate();
    assert!(!text("/run/udev/data/b8:17").contains("ID_FS_TYPE"));
    // Not FAT: no file system either
    fake::with_disk(1, |d| {
        d.fail = None;
        d.data[MIB as usize + 54..MIB as usize + 59].copy_from_slice(b"NTFS ");
    });
    populate();
    assert!(!text("/run/udev/data/b8:17").contains("ID_FS_TYPE"));
    fake::with_disk(1, |d| d.data[MIB as usize + 510] = 0);
    populate();
    assert!(!text("/run/udev/data/b8:17").contains("ID_FS_TYPE"));
    // FAT12 with a label
    fake::with_disk(1, |d| d.data[MIB as usize..MIB as usize + 512].copy_from_slice(&fat("FAT12", 1, "FLOPPY")));
    populate();
    assert!(text("/run/udev/data/b8:17").contains("E:ID_FS_VERSION=FAT12\n"));
}

#[test]
fn refresh_after_partition_changes() {
    let _g = common::serial(); // LINUX_ROOT is shared by the binary
    root();
    two_disks();
    populate();
    fake::with_disk(1, |d| {
        d.disk.parts.push(Partition { number: 2, start: 2 * MIB, len: MIB, entry: None });
    });
    fake::TICKS.set(300);
    devices::refresh_block_tree();
    assert!(exists("/dev/sdb2"));
    assert!(text("/run/udev/data/b8:18").starts_with("I:3000000\n"));
    // A failing file server is only logged
    fake::SERVER_DOWN.set(Some(-5));
    devices::refresh_block_tree();
    devices::refresh_efivars();
    fake::SERVER_DOWN.set(None);
}

#[test]
fn boot_flags() {
    root();
    fake::BOOT_INFO.with_borrow_mut(|b| {
        b.live = true;
        b.setup_conf = Some(b"user=me\n".to_vec());
    });
    populate();
    assert_eq!(text("/run/hydra/live"), "1\n");
    let conf = fs_node(&path("/run/hydra/setup.conf")).unwrap();
    assert_eq!((conf.mode & 0o777, conf.data.as_slice()), (0o600, &b"user=me\n"[..]));
    assert!(!exists("/run/hydra/boot-disk"));
    // Gone at the next boot without them
    fake::BOOT_INFO.with_borrow_mut(|b| *b = Default::default());
    populate();
    assert!(!exists("/run/hydra/live") && !exists("/run/hydra/setup.conf"));
}

#[test]
fn uefi_variables() {
    let _g = common::serial(); // LINUX_ROOT and efivars' DIR_INO are shared by the binary
    root();
    fake::EFIVARS.with_borrow_mut(|e| {
        *e = Some(vec![("BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c".into(), vec![7, 0, 0, 0, 1, 0]), ("Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c".into(), vec![7, 0, 0, 0, 5, 0])])
    });
    fs_write(&path("/sys/firmware/efi/efivars/Stale-1234"), b"old");
    populate();
    let dir = "/sys/firmware/efi/efivars";
    assert_eq!(fs_read(&path(&format!("{dir}/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c"))).unwrap(), vec![7, 0, 0, 0, 1, 0]);
    assert!(!exists(&format!("{dir}/Stale-1234")));
    let ino = hydra_hosttests_t28::compat::linux::efivars::DIR_INO.load(std::sync::atomic::Ordering::Relaxed);
    assert_eq!(Some(ino), fs_lookup(&path(dir)));
    // A variable deleted: refresh_efivars removes its file
    fake::EFIVARS.with_borrow_mut(|e| e.as_mut().unwrap().truncate(1));
    devices::refresh_efivars();
    assert!(!exists(&format!("{dir}/Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c")));
    assert!(exists(&format!("{dir}/BootOrder-8be4df61-93ca-11d2-aa0d-00e098032b8c")));
}

#[test]
fn refresh_without_a_root_does_nothing() {
    // (LINUX_ROOT may be set by another test of this binary: the root then simply does
    // not exist in this thread's file system)
    let _g = common::serial();
    devices::refresh_block_tree();
    devices::refresh_efivars();
    assert!(fs_lookup("/linux/sys").is_none());
}

#[test]
fn a_former_sound_card_leaves_no_records() {
    root();
    fs_write(&path("/run/udev/data/+sound:card0"), b"I:1
");
    fs_symlink(&path("/sys/class/sound/card0"), "x");
    fs_symlink(&path("/sys/class/sound/pcmC0D0p"), "x");
    populate();
    assert!(!exists("/run/udev/data/+sound:card0"));
    assert!(!exists("/sys/class/sound/card0") && !exists("/sys/class/sound/pcmC0D0p"));
    assert!(exists("/sys/class/sound"));
}
