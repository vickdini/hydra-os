//! wave11 GD: an interface's traffic counters in a link message (`RTM_NEWLINK`), as Linux
//! sends them: `IFLA_STATS` (`struct rtnl_link_stats`, 24 32-bit counters) and
//! `IFLA_STATS64` (`struct rtnl_link_stats64`, the same 24 as 64-bit ones). What libnl's
//! link cache reads, and with it KDE's System Monitor (ksystemstats' network plugin) for
//! the download and upload rates. Only packets and bytes are counted; the error and drop
//! counters stay 0.

use alloc::vec::Vec;

/// `IFLA_STATS`.
pub const IFLA_STATS: u16 = 7;
/// `IFLA_STATS64`.
pub const IFLA_STATS64: u16 = 23;

/// Traffic of one interface.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Traffic {
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub tx_packets: u64,
    pub tx_bytes: u64,
}

/// The 24 counters in Linux's order: rx_packets, tx_packets, rx_bytes, tx_bytes, then
/// the errors, drops and the rest (0).
pub fn counters(t: Traffic) -> [u64; 24] {
    let mut c = [0u64; 24];
    c[0] = t.rx_packets;
    c[1] = t.tx_packets;
    c[2] = t.rx_bytes;
    c[3] = t.tx_bytes;
    c
}

/// `IFLA_STATS`' payload (32-bit counters wrap as Linux's do).
pub fn stats32(t: Traffic) -> Vec<u8> {
    counters(t).iter().flat_map(|&v| (v as u32).to_le_bytes()).collect()
}

/// `IFLA_STATS64`' payload.
pub fn stats64(t: Traffic) -> Vec<u8> {
    counters(t).iter().flat_map(|&v| v.to_le_bytes()).collect()
}
