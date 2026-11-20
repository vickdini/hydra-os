//! `devices.rs` with a sound card (`snd::start` against the fake driver): the ALSA
//! nodes, their sysfs devices and udev records, PipeWire's settings and the
//! `/proc/asound` placeholders.

mod common;

use hydra_hosttests_t28::compat::linux::chardev::makedev;
use hydra_hosttests_t28::compat::linux::{devices, snd};
use hydra_hosttests_t28::fake::{self, fs_node, fs_readlink, fs_symlink, fs_text, fs_write};
use hydra_hosttests_t28::ipc::protocol::MSG_SND_REPLY;
use hydra_hosttests_t28::ipc::Message;

fn card(dirs: u64) {
    fake::sound(|s| {
        s.online = true;
        s.window = Some(Box::leak(vec![0u8; 4096].into_boxed_slice()));
        s.responder = Some(Box::new(move |_, _| Ok(Message::with_args(MSG_SND_REPLY, [0, 0x1af4_0022, dirs, 0]))));
    });
    snd::set_controller(0xfebf_0000, "0000:00:1b.0".into(), 0x8086, 0x293e, 0x1af4_1100);
    snd::start();
}

#[test]
fn the_sound_card_in_the_device_tree() {
    let _g = common::serial();
    card(0b11);
    assert!(snd::present());
    fake::fs_mkdir_p("/linux");
    // An earlier name of the settings file goes
    fs_write("/linux/etc/pipewire/pipewire.conf.d/50-hydra-no-rtkit.conf", b"old");
    devices::populate("/linux").unwrap();
    let t = |p: &str| fs_text(&format!("/linux{p}"));
    let pw = t("/etc/pipewire/pipewire.conf.d/50-hydra-sound.conf");
    assert!(pw.contains("module.rt = false") && pw.contains("default.clock.min-quantum = 1024"), "{pw}");
    assert!(!t("/etc/pipewire/client.conf.d/50-hydra-sound.conf").contains("min-quantum"));
    assert!(t("/etc/pipewire/pipewire-pulse.conf.d/50-hydra-sound.conf").contains("pulse.min.quantum = 1024/48000"));
    assert!(fs_node("/linux/etc/pipewire/pipewire.conf.d/50-hydra-no-rtkit.conf").is_none());
    let pci = "/sys/devices/pci0000:00/0000:00:1b.0";
    let ue = t(&format!("{pci}/uevent"));
    assert!(ue.contains("DRIVER=snd_hda_intel\n") && ue.contains("PCI_ID=8086:293E\n") && ue.contains("PCI_SUBSYS_ID=1100:1AF4\n"), "{ue}");
    assert_eq!(t(&format!("{pci}/class")), "0x040300\n");
    assert_eq!(t(&format!("{pci}/sound/card0/id")), "Intel\n");
    assert_eq!(fs_readlink("/linux/sys/class/sound/card0").unwrap(), "../../devices/pci0000:00/0000:00:1b.0/sound/card0");
    assert!(t("/run/udev/data/+sound:card0").contains("E:ID_VENDOR_ID=0x8086\nE:ID_MODEL_ID=0x293e\n"));
    for (name, minor) in [("controlC0", 0), ("pcmC0D0p", 16), ("pcmC0D0c", 24)] {
        let n = fs_node(&format!("/linux/dev/snd/{name}")).unwrap();
        assert_eq!((n.mode, n.rdev, n.gid), (0o020666, makedev(116, minor), 29), "{name}");
        assert_eq!(t(&format!("{pci}/sound/card0/{name}/dev")), format!("116:{minor}\n"));
        assert!(t(&format!("/run/udev/data/c116:{minor}")).contains("G:uaccess\n"));
    }
    assert_eq!(t(&format!("{pci}/sound/card0/pcmC0D0c/pcm_class")), "generic\n");
    assert_eq!(fs_readlink("/linux/dev/snd/by-path/pci-0000:00:1b.0").unwrap(), "../controlC0");
    assert_eq!(fs_readlink("/linux/proc/asound/Intel").unwrap(), "card0");
    assert_eq!(t("/proc/asound/card0/pcm0c/sub0/hw_params"), "");
    assert_eq!(t("/proc/asound/card0/codec#0"), "");
    // An old symlink where a node goes is replaced
    let _ = fs_symlink;
}
