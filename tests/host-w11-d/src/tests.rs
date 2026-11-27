//! wave11 GD: the link messages' traffic counters.
use crate::linkstats::*;

fn word32(b: &[u8], i: usize) -> u32 {
    u32::from_le_bytes(b[i * 4..i * 4 + 4].try_into().unwrap())
}

fn word64(b: &[u8], i: usize) -> u64 {
    u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap())
}

#[test]
fn counters_are_in_linux_order_and_sizes() {
    let t = Traffic { rx_packets: 10, rx_bytes: 15_000, tx_packets: 7, tx_bytes: 900 };
    let c = counters(t);
    assert_eq!(&c[..4], &[10, 7, 15_000, 900], "rx_packets, tx_packets, rx_bytes, tx_bytes");
    assert!(c[4..].iter().all(|&v| v == 0));
    let s = stats32(t);
    assert_eq!(s.len(), 96, "struct rtnl_link_stats");
    assert_eq!((word32(&s, 0), word32(&s, 1), word32(&s, 2), word32(&s, 3)), (10, 7, 15_000, 900));
    let s = stats64(t);
    assert_eq!(s.len(), 192, "struct rtnl_link_stats64");
    assert_eq!((word64(&s, 0), word64(&s, 1), word64(&s, 2), word64(&s, 3)), (10, 7, 15_000, 900));
    assert_eq!((IFLA_STATS, IFLA_STATS64), (7, 23));
}

#[test]
fn the_32_bit_counters_wrap_and_the_64_bit_ones_do_not() {
    let t = Traffic { rx_bytes: (1 << 32) + 5, ..Default::default() };
    assert_eq!(word32(&stats32(t), 2), 5);
    assert_eq!(word64(&stats64(t), 2), (1 << 32) + 5);
    assert_eq!(stats64(Traffic::default()), vec![0u8; 192]);
}
