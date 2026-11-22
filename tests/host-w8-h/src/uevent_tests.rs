//! The uevent message formats: kernel and libudev layouts, the udev database text, hashes,
//! batches.

use crate::uevent::*;

fn s(x: &str) -> String {
    x.to_string()
}

fn keyboard() -> DevRecord {
    DevRecord {
        devpath: s("/devices/platform/i8042/serio0/input/input0/event0"),
        subsystem: "input",
        devtype: None,
        node: Some((s("input/event0"), 13, 64)),
        props: vec![(s("ID_INPUT"), s("1")), (s("ID_INPUT_KEY"), s("1")), (s("ID_INPUT_KEYBOARD"), s("1")), (s("ID_PATH"), s("platform-i8042-serio-0"))],
        tags: vec!["seat", "uaccess"],
        usec: 1_000_000,
    }
}

fn card() -> DevRecord {
    DevRecord {
        devpath: s("/devices/pci0000:00/0000:00:1b.0/sound/card0"),
        subsystem: "sound",
        devtype: None,
        node: None,
        props: vec![(s("SOUND_INITIALIZED"), s("1"))],
        tags: vec!["seat"],
        usec: 1_000_000,
    }
}

#[test]
fn db_text_matches_the_boot_files() {
    // The text devices.rs wrote before the records existed (byte for byte)
    let mut k = keyboard();
    k.props = vec![
        (s("ID_INPUT"), s("1")),
        (s("ID_INPUT_KEY"), s("1")),
        (s("ID_INPUT_KEYBOARD"), s("1")),
        (s("XKBMODEL"), s("pc105")),
        (s("XKBLAYOUT"), s("us")),
        (s("ID_BUS"), s("i8042")),
        (s("ID_SERIAL"), s("noserial")),
        (s("ID_PATH"), s("platform-i8042-serio-0")),
        (s("ID_PATH_TAG"), s("platform-i8042-serio-0")),
    ];
    assert_eq!(
        k.db_text(),
        "I:1000000\nE:ID_INPUT=1\nE:ID_INPUT_KEY=1\nE:ID_INPUT_KEYBOARD=1\nE:XKBMODEL=pc105\nE:XKBLAYOUT=us\nE:ID_BUS=i8042\nE:ID_SERIAL=noserial\nE:ID_PATH=platform-i8042-serio-0\nE:ID_PATH_TAG=platform-i8042-serio-0\nG:seat\nG:uaccess\nQ:seat\nQ:uaccess\nV:1\n"
    );
    assert_eq!(card().db_text(), "I:1000000\nE:SOUND_INITIALIZED=1\nG:seat\nQ:seat\nV:1\n");
}

#[test]
fn db_names() {
    assert_eq!(keyboard().db_name(), "c13:64");
    assert_eq!(card().db_name(), "+sound:card0");
    assert_eq!(card().sysname(), "card0");
}

#[test]
fn kernel_format() {
    let m = kernel_message("remove", &keyboard(), 1001);
    let text = String::from_utf8(m.clone()).unwrap();
    assert!(text.starts_with("remove@/devices/platform/i8042/serio0/input/input0/event0\0ACTION=remove\0"));
    assert_eq!(*m.last().unwrap(), 0);
    let p = properties(&m);
    assert_eq!(
        p,
        vec![
            ("ACTION", "remove"),
            ("DEVPATH", "/devices/platform/i8042/serio0/input/input0/event0"),
            ("SUBSYSTEM", "input"),
            ("MAJOR", "13"),
            ("MINOR", "64"),
            ("DEVNAME", "input/event0"),
            ("SEQNUM", "1001")
        ]
    );
    // a device without a node: no MAJOR/MINOR/DEVNAME
    let cm = kernel_message("change", &card(), 7);
    let c = properties(&cm).into_iter().map(|(k, _)| k).collect::<Vec<_>>();
    assert_eq!(c, vec!["ACTION", "DEVPATH", "SUBSYSTEM", "SEQNUM"]);
}

#[test]
fn udev_format_header() {
    let m = udev_message("add", &keyboard(), 1004);
    assert_eq!(&m[..8], b"libudev\0");
    assert_eq!(&m[8..12], &[0xfe, 0xed, 0xca, 0xfe]); // big-endian magic
    let le = |o: usize| u32::from_le_bytes(m[o..o + 4].try_into().unwrap());
    let be = |o: usize| u32::from_be_bytes(m[o..o + 4].try_into().unwrap());
    assert_eq!(le(12), 40); // header_size
    assert_eq!(le(16), 40); // properties_off
    assert_eq!(le(20) as usize, m.len() - 40); // properties_len
    assert_eq!(be(24), murmur2(b"input", 0));
    assert_eq!(be(28), 0); // no devtype
    let bloom = string_bloom64("seat") | string_bloom64("uaccess");
    assert_eq!(be(32), (bloom >> 32) as u32);
    assert_eq!(be(36), bloom as u32);
    assert_eq!(*m.last().unwrap(), 0);
}

#[test]
fn udev_format_properties() {
    let um = udev_message("add", &keyboard(), 1004);
    let p = properties(&um);
    let get = |k: &str| p.iter().find(|(x, _)| *x == k).map(|(_, v)| *v);
    assert_eq!(get("ACTION"), Some("add"));
    assert_eq!(get("DEVNAME"), Some("/dev/input/event0")); // absolute, as udevd sends it
    assert_eq!(get("MAJOR"), Some("13"));
    assert_eq!(get("SEQNUM"), Some("1004"));
    assert_eq!(get("USEC_INITIALIZED"), Some("1000000"));
    assert_eq!(get("ID_INPUT"), Some("1"));
    assert_eq!(get("ID_INPUT_KEYBOARD"), Some("1"));
    assert_eq!(get("TAGS"), Some(":seat:uaccess:"));
    assert_eq!(get("CURRENT_TAGS"), Some(":seat:uaccess:"));
    // the card: no tags line without tags
    let mut c = card();
    c.tags.clear();
    let cm = udev_message("change", &c, 9);
    let pc = properties(&cm);
    assert!(pc.iter().all(|(k, _)| *k != "TAGS"));
    assert!(pc.contains(&("SOUND_INITIALIZED", "1")));
}

#[test]
fn devtype_hash() {
    let mut k = keyboard();
    k.devtype = Some("drm_minor");
    let m = udev_message("add", &k, 1);
    assert_eq!(u32::from_be_bytes(m[28..32].try_into().unwrap()), murmur2(b"drm_minor", 0));
    assert!(properties(&m).contains(&("DEVTYPE", "drm_minor")));
}

#[test]
fn murmur2_values() {
    assert_eq!(murmur2(b"", 0), 0);
    // every tail length (0..3 bytes after the 4-byte blocks) and the seed
    assert_eq!(murmur2(b"input", 0), 0xc1a2_8470);
    assert_eq!(murmur2(b"sound", 0), 0xd196_ab6e);
    assert_eq!(murmur2(b"seat", 0), 0x435b_3e40);
    assert_eq!(murmur2(b"uaccess", 0), 0xe88e_d0cc);
    assert_eq!(murmur2(b"abc", 0), 0x1357_7c9b);
    assert_ne!(murmur2(b"abc", 1), murmur2(b"abc", 0));
    assert_ne!(murmur2(b"ab", 0), murmur2(b"ba", 0));
}

#[test]
fn bloom_sets_at_most_four_bits() {
    for t in ["seat", "uaccess", "master-of-seat", "x"] {
        let b = string_bloom64(t);
        assert!(b != 0 && b.count_ones() <= 4, "{}", t);
    }
}

#[test]
fn announce_numbers_and_groups() {
    let mut seq = 1000;
    let devs = vec![keyboard(), card()];
    let m = announce("remove", &devs, &mut seq);
    assert_eq!(seq, 1002);
    assert_eq!(m.len(), 4);
    assert_eq!(m.iter().map(|(g, _)| *g).collect::<Vec<_>>(), vec![GROUP_KERNEL, GROUP_UDEV, GROUP_KERNEL, GROUP_UDEV]);
    // the kernel's and udev's message of one device share its number
    assert!(properties(&m[0].1).contains(&("SEQNUM", "1001")));
    assert!(properties(&m[1].1).contains(&("SEQNUM", "1001")));
    assert!(properties(&m[3].1).contains(&("SEQNUM", "1002")));
    assert!(announce("add", &[], &mut seq).is_empty());
}

#[test]
fn batch_round_trip_and_cap() {
    let msgs = vec![(1u32, vec![1u8, 2, 3]), (2, vec![4u8; 10]), (1, vec![])];
    let mut b = Vec::new();
    assert_eq!(Batch::encode(&msgs, &mut b, 1000), 3);
    assert_eq!(b.len(), 8 * 3 + 13);
    let d = Batch::decode(&b);
    assert_eq!(d, vec![(1, &[1u8, 2, 3][..]), (2, &[4u8; 10][..]), (1, &[][..])]);
    // a cap stops before a message that does not fit
    let mut c = Vec::new();
    assert_eq!(Batch::encode(&msgs, &mut c, 8 + 3 + 8 + 9), 1);
    // a truncated last message is dropped
    assert_eq!(Batch::decode(&b[..b.len() - 9]).len(), 1);
    assert!(Batch::decode(&[1, 2, 3]).is_empty());
}

#[test]
fn properties_of_garbage() {
    assert!(properties(b"").is_empty());
    assert!(properties(b"no header").is_empty());
    // a short "libudev" prefix is read as a kernel message
    assert!(properties(b"libudev\0X=1\0").contains(&("X", "1")));
}
