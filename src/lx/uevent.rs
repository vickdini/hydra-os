//! # Device announcements: the uevent message formats (wave 8, Group H)
//!
//! What Linux's kernel and udev send on the uevent netlink socket
//! (`NETLINK_KOBJECT_UEVENT`) when a device appears or goes, built from one record per
//! device ([`DevRecord`]). The same record writes the device's udev database file
//! (`/run/udev/data/...`, [`DevRecord::db_text`], used by `compat::linux::devices`), so a
//! device announced again carries exactly the properties and tags it had at boot.
//!
//! - **Group 1, the kernel's format** ([`kernel_message`]): `ACTION@DEVPATH\0` and then
//!   `KEY=value\0` lines (the device's sysfs `uevent` keys and `SEQNUM`).
//! - **Group 2, udev's format** ([`udev_message`]), what libudev's monitor reads (libinput,
//!   PipeWire's ALSA monitor, KWin): a 40-byte header (`libudev\0`, the magic 0xfeedcafe,
//!   the hashes and tag bloom libudev's socket filters test, all big-endian) and the
//!   properties, `KEY=value\0` each, including the udev database's (`ID_INPUT=1`, ...),
//!   `TAGS` and `USEC_INITIALIZED`.
//!
//! The kernel hands batches of messages to the network service ([`Batch`]: `[u32 group]
//! [u32 length][bytes]` each) which queues them on its uevent sockets (`lx::hotplug`).
//! Pure code: host-tested in `tests/host-w8-h`.

use alloc::string::String;
use alloc::vec::Vec;

/// The kernel's multicast group of uevent sockets.
pub const GROUP_KERNEL: u32 = 1;
/// udev's group (libudev's monitors bind here).
pub const GROUP_UDEV: u32 = 2;
/// libudev's header magic (stored big-endian).
pub const UDEV_MAGIC: u32 = 0xfeed_cafe;
/// Size of libudev's `struct monitor_netlink_header`.
pub const UDEV_HEADER: usize = 40;

/// One device as udev knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DevRecord {
    /// Below `/sys`, e.g. `/devices/platform/i8042/serio0/input/input0/event0`.
    pub devpath: String,
    /// `input`, `sound`, ...
    pub subsystem: &'static str,
    /// `DEVTYPE` (none for most).
    pub devtype: Option<&'static str>,
    /// The node below `/dev` (`input/event0`) and its number, for a character device.
    pub node: Option<(String, u32, u32)>,
    /// udev's properties, in the database's order (`ID_INPUT=1`, ...).
    pub props: Vec<(String, String)>,
    /// udev's tags (`seat`, `uaccess`).
    pub tags: Vec<&'static str>,
    /// When udev initialized it (µs since boot).
    pub usec: u64,
}

impl DevRecord {
    /// The udev database file's text (`/run/udev/data/c13:64`, `+sound:card0`): `I:`, the
    /// properties `E:`, tags `G:` and current tags `Q:`, `V:1`.
    pub fn db_text(&self) -> String {
        let mut t = alloc::format!("I:{}\n", self.usec);
        for (k, v) in &self.props {
            t.push_str(&alloc::format!("E:{}={}\n", k, v));
        }
        for g in &self.tags {
            t.push_str(&alloc::format!("G:{}\n", g));
        }
        for g in &self.tags {
            t.push_str(&alloc::format!("Q:{}\n", g));
        }
        t.push_str("V:1\n");
        t
    }

    /// The database file's name below `/run/udev/data`: `c<major>:<minor>` for a device
    /// node, `+<subsystem>:<sysname>` otherwise.
    pub fn db_name(&self) -> String {
        match &self.node {
            Some((_, major, minor)) => alloc::format!("c{}:{}", major, minor),
            None => alloc::format!("+{}:{}", self.subsystem, self.sysname()),
        }
    }

    /// The last part of the device path (`event0`, `card0`).
    pub fn sysname(&self) -> &str {
        self.devpath.rsplit('/').next().unwrap_or("")
    }

    /// The keys the kernel itself sends (before `SEQNUM`).
    fn kernel_keys(&self, action: &str) -> Vec<(String, String)> {
        let mut v = alloc::vec![(String::from("ACTION"), String::from(action)), (String::from("DEVPATH"), self.devpath.clone()), (String::from("SUBSYSTEM"), String::from(self.subsystem))];
        if let Some(t) = self.devtype {
            v.push((String::from("DEVTYPE"), String::from(t)));
        }
        if let Some((name, major, minor)) = &self.node {
            v.push((String::from("MAJOR"), alloc::format!("{}", major)));
            v.push((String::from("MINOR"), alloc::format!("{}", minor)));
            v.push((String::from("DEVNAME"), name.clone()));
        }
        v
    }
}

/// The kernel's message (group 1): `ACTION@DEVPATH\0KEY=value\0...`.
pub fn kernel_message(action: &str, d: &DevRecord, seqnum: u64) -> Vec<u8> {
    let mut m = Vec::new();
    m.extend_from_slice(action.as_bytes());
    m.push(b'@');
    m.extend_from_slice(d.devpath.as_bytes());
    m.push(0);
    for (k, v) in d.kernel_keys(action) {
        push_prop(&mut m, &k, &v);
    }
    push_prop(&mut m, "SEQNUM", &alloc::format!("{}", seqnum));
    m
}

/// udev's message (group 2), as systemd-udevd sends it after processing the kernel's.
pub fn udev_message(action: &str, d: &DevRecord, seqnum: u64) -> Vec<u8> {
    let mut props = Vec::new();
    for (k, v) in d.kernel_keys(action) {
        // udev sends the node's absolute path
        let v = if k == "DEVNAME" { alloc::format!("/dev/{}", v) } else { v };
        push_prop(&mut props, &k, &v);
    }
    push_prop(&mut props, "SEQNUM", &alloc::format!("{}", seqnum));
    push_prop(&mut props, "USEC_INITIALIZED", &alloc::format!("{}", d.usec));
    for (k, v) in &d.props {
        push_prop(&mut props, k, v);
    }
    if !d.tags.is_empty() {
        let mut tags = String::from(":");
        for t in &d.tags {
            tags.push_str(t);
            tags.push(':');
        }
        push_prop(&mut props, "TAGS", &tags);
        push_prop(&mut props, "CURRENT_TAGS", &tags);
    }
    let mut bloom = 0u64;
    for t in &d.tags {
        bloom |= string_bloom64(t);
    }
    let mut m = Vec::with_capacity(UDEV_HEADER + props.len());
    m.extend_from_slice(b"libudev\0");
    m.extend_from_slice(&UDEV_MAGIC.to_be_bytes());
    m.extend_from_slice(&(UDEV_HEADER as u32).to_le_bytes()); // header_size (host order)
    m.extend_from_slice(&(UDEV_HEADER as u32).to_le_bytes()); // properties_off
    m.extend_from_slice(&(props.len() as u32).to_le_bytes()); // properties_len
    m.extend_from_slice(&murmur2(d.subsystem.as_bytes(), 0).to_be_bytes());
    m.extend_from_slice(&d.devtype.map_or(0, |t| murmur2(t.as_bytes(), 0)).to_be_bytes());
    m.extend_from_slice(&((bloom >> 32) as u32).to_be_bytes());
    m.extend_from_slice(&(bloom as u32).to_be_bytes());
    m.extend_from_slice(&props);
    m
}

fn push_prop(m: &mut Vec<u8>, k: &str, v: &str) {
    m.extend_from_slice(k.as_bytes());
    m.push(b'=');
    m.extend_from_slice(v.as_bytes());
    m.push(0);
}

/// MurmurHash2 (32 bits, little-endian reads), as systemd's `string_hash32`.
pub fn murmur2(key: &[u8], seed: u32) -> u32 {
    const M: u32 = 0x5bd1_e995;
    let mut h = seed ^ key.len() as u32;
    let mut chunks = key.chunks_exact(4);
    for c in &mut chunks {
        let mut k = u32::from_le_bytes([c[0], c[1], c[2], c[3]]);
        k = k.wrapping_mul(M);
        k ^= k >> 24;
        k = k.wrapping_mul(M);
        h = h.wrapping_mul(M) ^ k;
    }
    let r = chunks.remainder();
    if !r.is_empty() {
        if r.len() >= 3 {
            h ^= (r[2] as u32) << 16;
        }
        if r.len() >= 2 {
            h ^= (r[1] as u32) << 8;
        }
        h ^= r[0] as u32;
        h = h.wrapping_mul(M);
    }
    h ^= h >> 13;
    h = h.wrapping_mul(M);
    h ^= h >> 15;
    h
}

/// The 4 bits one tag sets in libudev's 64-bit tag bloom filter.
pub fn string_bloom64(s: &str) -> u64 {
    let h = murmur2(s.as_bytes(), 0);
    (1u64 << (h & 63)) | (1u64 << ((h >> 6) & 63)) | (1u64 << ((h >> 12) & 63)) | (1u64 << ((h >> 18) & 63))
}

/// The messages of one announcement: kernel's then udev's for each device, sequence numbers
/// from `seqnum` up (one per device). `action` is `add`, `remove` or `change`.
pub fn announce(action: &str, devs: &[DevRecord], seqnum: &mut u64) -> Vec<(u32, Vec<u8>)> {
    let mut out = Vec::with_capacity(devs.len() * 2);
    for d in devs {
        *seqnum += 1;
        out.push((GROUP_KERNEL, kernel_message(action, d, *seqnum)));
        out.push((GROUP_UDEV, udev_message(action, d, *seqnum)));
    }
    out
}

/// A batch of messages as the kernel hands it to the network service: `[u32 group][u32
/// length][bytes]` each, little-endian, unpadded.
pub struct Batch;

impl Batch {
    /// Appends messages to `out` while the whole stays within `cap` bytes; returns how many
    /// were taken (at least one if the first fits at all).
    pub fn encode(msgs: &[(u32, Vec<u8>)], out: &mut Vec<u8>, cap: usize) -> usize {
        let mut n = 0;
        for (g, m) in msgs {
            if out.len() + 8 + m.len() > cap {
                break;
            }
            out.extend_from_slice(&g.to_le_bytes());
            out.extend_from_slice(&(m.len() as u32).to_le_bytes());
            out.extend_from_slice(m);
            n += 1;
        }
        n
    }

    /// The messages of a batch (a truncated last one is dropped).
    pub fn decode(mut b: &[u8]) -> Vec<(u32, &[u8])> {
        let mut v = Vec::new();
        while b.len() >= 8 {
            let g = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
            let n = u32::from_le_bytes([b[4], b[5], b[6], b[7]]) as usize;
            if b.len() < 8 + n {
                break;
            }
            v.push((g, &b[8..8 + n]));
            b = &b[8 + n..];
        }
        v
    }
}

/// The `KEY=value` properties of a message of either format (for tests and readers).
pub fn properties(m: &[u8]) -> Vec<(&str, &str)> {
    let body = if m.len() >= UDEV_HEADER && &m[..8] == b"libudev\0" {
        let off = u32::from_le_bytes([m[16], m[17], m[18], m[19]]) as usize;
        m.get(off..).unwrap_or(&[])
    } else {
        // after the `ACTION@DEVPATH` line
        match m.iter().position(|&c| c == 0) {
            Some(p) => &m[p + 1..],
            None => &[],
        }
    };
    body.split(|&c| c == 0)
        .filter_map(|kv| core::str::from_utf8(kv).ok())
        .filter_map(|kv| kv.split_once('='))
        .collect()
}
