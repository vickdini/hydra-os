//! Socket options of `AF_INET` sockets (`setsockopt`, `getsockopt`).
//!
//! Every option Linux knows at `SOL_SOCKET`, `IPPROTO_IP`, `IPPROTO_TCP` (stream sockets)
//! and `IPPROTO_UDP` (datagram sockets) is validated and kept per socket, and reads back as
//! Linux reports it: booleans as 0 or 1, buffer sizes doubled and clamped, `IP_TTL` -1 as the
//! default, timeouts as `struct timeval`. Unknown options and levels give `ENOPROTOOPT`;
//! read-only ones (`SO_TYPE`, `SO_ERROR`, ...) too when set.
//!
//! In effect: `SO_RCVTIMEO` and `SO_SNDTIMEO` bound blocking receives, sends and connects
//! ([`Options::rcv_timeout`], [`Options::snd_timeout`]). The others are kept for programs
//! that read them back; Hydra's TCP/IP engine sends without Nagle delays (as with
//! `TCP_NODELAY`), uses TTL 64 and has no keepalive probes.
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const ENODEV: i64 = -19;
const EINVAL: i64 = -22;
const EDOM: i64 = -33;
const ENOPROTOOPT: i64 = -92;
const ENOTCONN: i64 = -107;

const SOL_SOCKET: u32 = 1;
const IPPROTO_IP: u32 = 0;
const IPPROTO_TCP: u32 = 6;
const IPPROTO_UDP: u32 = 17;

// SOL_SOCKET
const SO_TYPE: u32 = 3;
const SO_ERROR: u32 = 4;
const SO_SNDBUF: u32 = 7;
const SO_RCVBUF: u32 = 8;
const SO_PRIORITY: u32 = 12;
const SO_LINGER: u32 = 13;
const SO_PEERCRED: u32 = 17;
const SO_RCVLOWAT: u32 = 18;
const SO_SNDLOWAT: u32 = 19;
const SO_RCVTIMEO_OLD: u32 = 20;
const SO_SNDTIMEO_OLD: u32 = 21;
const SO_BINDTODEVICE: u32 = 25;
const SO_PEERNAME: u32 = 28;
const SO_ACCEPTCONN: u32 = 30;
const SO_PEERSEC: u32 = 31;
const SO_SNDBUFFORCE: u32 = 32;
const SO_RCVBUFFORCE: u32 = 33;
const SO_MARK: u32 = 36;
const SO_PROTOCOL: u32 = 38;
const SO_DOMAIN: u32 = 39;
const SO_RCVTIMEO_NEW: u32 = 66;
const SO_SNDTIMEO_NEW: u32 = 67;
/// Boolean `SOL_SOCKET` options: `SO_DEBUG`, `REUSEADDR`, `DONTROUTE`, `BROADCAST`,
/// `KEEPALIVE`, `OOBINLINE`, `NO_CHECK`, `REUSEPORT`, `PASSCRED`, `TIMESTAMP`, `PASSSEC`,
/// `TIMESTAMPNS`, `RXQ_OVFL`, `WIFI_STATUS`, `NOFCS`, `LOCK_FILTER`, `SELECT_ERR_QUEUE`,
/// `ZEROCOPY`, `PASSPIDFD`...
const SOCKET_BOOLS: &[u32] = &[1, 2, 5, 6, 9, 10, 11, 15, 16, 29, 34, 35, 40, 41, 43, 44, 45, 60, 76];

// IPPROTO_IP
const IP_TOS: u32 = 1;
const IP_TTL: u32 = 2;
const IP_MTU_DISCOVER: u32 = 10;
const IP_MTU: u32 = 14;
const IP_TRANSPARENT: u32 = 19;
const IP_MULTICAST_TTL: u32 = 33;
const IP_MULTICAST_LOOP: u32 = 34;
/// Boolean `IPPROTO_IP` options: `IP_HDRINCL`, `PKTINFO`, `RECVERR`, `RECVTTL`, `RECVTOS`,
/// `RECVOPTS`, `RETOPTS`, `FREEBIND`, `PASSSEC`, `MULTICAST_ALL`, `NODEFRAG`,
/// `BIND_ADDRESS_NO_PORT`, `RECVORIGDSTADDR`, `CHECKSUM`, `RECVFRAGSIZE`, `RECVERR_RFC4884`.
const IP_BOOLS: &[u32] = &[3, 6, 7, 8, 11, 12, 13, 15, 18, 20, 22, 24, 25, 49, 23, 26];

// IPPROTO_TCP
const TCP_MAXSEG: u32 = 2;
const TCP_KEEPIDLE: u32 = 4;
const TCP_KEEPINTVL: u32 = 5;
const TCP_KEEPCNT: u32 = 6;
const TCP_SYNCNT: u32 = 7;
const TCP_INFO: u32 = 11;
const TCP_CONGESTION: u32 = 13;
const TCP_USER_TIMEOUT: u32 = 18;
/// Boolean `IPPROTO_TCP` options: `TCP_NODELAY`, `CORK`, `QUICKACK`, `THIN_LINEAR_TIMEOUTS`,
/// `THIN_DUPACK`, `REPAIR`, `FASTOPEN_CONNECT`, `FASTOPEN_NO_COOKIE`, `INQ`, `TX_DELAY`.
const TCP_BOOLS: &[u32] = &[1, 3, 12, 16, 17, 19, 30, 34, 36, 37];

/// Socket buffer limits (`net.core.wmem_max`/`rmem_max`), minimums (`SOCK_MIN_SNDBUF`,
/// `SOCK_MIN_RCVBUF`) and defaults.
const BUF_MAX: u32 = 212_992;
const MIN_SNDBUF: u32 = 4608;
const MIN_RCVBUF: u32 = 2304;

/// The options of one socket.
#[derive(Default)]
pub struct Options {
    vals: BTreeMap<(u32, u32), Vec<u8>>,
    /// `SO_RCVTIMEO` / `SO_SNDTIMEO` in nanoseconds (0: none).
    rcvtimeo: u64,
    sndtimeo: u64,
}

/// What `getsockopt` needs to know about the socket itself.
pub struct SockInfo {
    /// A TCP socket (else UDP).
    pub stream: bool,
    /// Connected (TCP past the handshake, or UDP with a default peer).
    pub connected: bool,
    /// Pending error for `SO_ERROR` (taken), negative errno or 0.
    pub error: i64,
    /// Linux TCP state number (`TCP_ESTABLISHED` 1 ... `TCP_CLOSE` 7, `TCP_SYN_SENT` 2).
    pub tcp_state: u8,
}

fn cap_net_admin() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 12) != 0).unwrap_or(false)
}

fn cap_net_raw() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 13) != 0).unwrap_or(false)
}

fn int_of(v: &[u8]) -> Result<i32, i64> {
    // Linux reads an int; IPPROTO_IP options also take a single byte
    match v.len() {
        0 => Err(EINVAL),
        1..=3 => Ok(v[0] as i32),
        _ => Ok(i32::from_le_bytes(v[..4].try_into().unwrap())),
    }
}

fn timeval_ns(v: &[u8]) -> Result<u64, i64> {
    if v.len() < 16 {
        return Err(EINVAL);
    }
    let sec = i64::from_le_bytes(v[0..8].try_into().unwrap());
    let usec = i64::from_le_bytes(v[8..16].try_into().unwrap());
    if !(0..1_000_000).contains(&usec) {
        return Err(EDOM);
    }
    if sec < 0 {
        return Ok(0); // Linux: a negative timeout means none
    }
    Ok((sec as u64).saturating_mul(1_000_000_000).saturating_add(usec as u64 * 1000))
}

fn ns_timeval(ns: u64) -> Vec<u8> {
    let mut b = Vec::with_capacity(16);
    b.extend_from_slice(&((ns / 1_000_000_000) as i64).to_le_bytes());
    b.extend_from_slice(&(((ns % 1_000_000_000) / 1000) as i64).to_le_bytes());
    b
}

fn known(level: u32, name: u32, stream: bool) -> bool {
    match level {
        SOL_SOCKET => (1..=80).contains(&name),
        IPPROTO_IP => (1..=50).contains(&name),
        IPPROTO_TCP => stream && (1..=40).contains(&name),
        IPPROTO_UDP => !stream && matches!(name, 1 | 100..=105),
        _ => false,
    }
}

impl Options {
    /// Receive timeout in nanoseconds (`SO_RCVTIMEO`), if any.
    pub fn rcv_timeout(&self) -> Option<u64> {
        (self.rcvtimeo != 0).then_some(self.rcvtimeo)
    }

    /// Send (and connect) timeout in nanoseconds (`SO_SNDTIMEO`), if any.
    pub fn snd_timeout(&self) -> Option<u64> {
        (self.sndtimeo != 0).then_some(self.sndtimeo)
    }

    /// `setsockopt(level, name, val)`.
    pub fn set(&mut self, level: u32, name: u32, val: &[u8], stream: bool) -> i64 {
        if !known(level, name, stream) {
            return ENOPROTOOPT;
        }
        let int = || int_of(val);
        let stored: Vec<u8> = match (level, name) {
            (SOL_SOCKET, SO_TYPE | SO_ERROR | SO_PEERCRED | SO_PEERNAME | SO_ACCEPTCONN | SO_PEERSEC | SO_PROTOCOL | SO_DOMAIN | SO_SNDLOWAT) => {
                return ENOPROTOOPT
            }
            (SOL_SOCKET, SO_SNDBUF | SO_RCVBUF | SO_SNDBUFFORCE | SO_RCVBUFFORCE) => {
                if val.len() < 4 {
                    return EINVAL;
                }
                let v = int_of(val).unwrap_or(0).max(0) as u32;
                let force = matches!(name, SO_SNDBUFFORCE | SO_RCVBUFFORCE);
                if force && !cap_net_admin() {
                    return EPERM;
                }
                let snd = matches!(name, SO_SNDBUF | SO_SNDBUFFORCE);
                let v = if force { v } else { v.min(BUF_MAX) };
                let v = v.saturating_mul(2).max(if snd { MIN_SNDBUF } else { MIN_RCVBUF });
                self.vals.insert((SOL_SOCKET, if snd { SO_SNDBUF } else { SO_RCVBUF }), v.to_le_bytes().to_vec());
                return 0;
            }
            (SOL_SOCKET, SO_PRIORITY) => {
                let v = match int() {
                    Ok(v) if val.len() >= 4 => v,
                    _ => return EINVAL,
                };
                if !(0..=6).contains(&v) && !cap_net_admin() {
                    return EPERM;
                }
                v.to_le_bytes().to_vec()
            }
            (SOL_SOCKET, SO_MARK) => {
                if val.len() < 4 {
                    return EINVAL;
                }
                if !cap_net_admin() && !cap_net_raw() {
                    return EPERM;
                }
                val[..4].to_vec()
            }
            (SOL_SOCKET, SO_LINGER) => {
                if val.len() < 8 {
                    return EINVAL;
                }
                let on = (int_of(&val[0..4]).unwrap_or(0) != 0) as i32;
                let mut v = on.to_le_bytes().to_vec();
                v.extend_from_slice(&val[4..8]);
                v
            }
            (SOL_SOCKET, SO_RCVLOWAT) => {
                if val.len() < 4 {
                    return EINVAL;
                }
                let v = int_of(val).unwrap_or(1);
                let v = if v < 0 { i32::MAX } else { v.max(1) };
                v.to_le_bytes().to_vec()
            }
            (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_SNDTIMEO_OLD | SO_RCVTIMEO_NEW | SO_SNDTIMEO_NEW) => {
                let ns = match timeval_ns(val) {
                    Ok(n) => n,
                    Err(e) => return e,
                };
                if matches!(name, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) {
                    self.rcvtimeo = ns;
                } else {
                    self.sndtimeo = ns;
                }
                return 0;
            }
            (SOL_SOCKET, SO_BINDTODEVICE) => {
                if !cap_net_raw() {
                    return EPERM;
                }
                let name: Vec<u8> = val.iter().copied().take(16).take_while(|&b| b != 0).collect();
                if !name.is_empty() && name != b"eth0" && name != b"lo" {
                    return ENODEV;
                }
                name
            }
            (SOL_SOCKET, n) if SOCKET_BOOLS.contains(&n) => {
                if val.len() < 4 {
                    return EINVAL;
                }
                ((int_of(val).unwrap_or(0) != 0) as i32).to_le_bytes().to_vec()
            }
            (IPPROTO_IP, IP_TOS) => {
                let v = match int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                // TCP keeps its ECN bits
                let v = if stream { v & 0xfc } else { v & 0xff };
                v.to_le_bytes().to_vec()
            }
            (IPPROTO_IP, IP_TTL) => {
                let v = match int() {
                    Ok(v) => v,
                    Err(e) => return e,
                };
                if v == -1 {
                    self.vals.remove(&(level, name));
                    return 0;
                }
                if !(1..=255).contains(&v) {
                    return EINVAL;
                }
                v.to_le_bytes().to_vec()
            }
            (IPPROTO_IP, IP_MTU_DISCOVER) => match int() {
                Ok(v) if (0..=5).contains(&v) => v.to_le_bytes().to_vec(),
                Ok(_) => return EINVAL,
                Err(e) => return e,
            },
            (IPPROTO_IP, IP_MTU) => return ENOPROTOOPT,
            (IPPROTO_IP, IP_TRANSPARENT) => {
                if !cap_net_admin() && !cap_net_raw() {
                    return EPERM;
                }
                match int() {
                    Ok(v) => ((v != 0) as i32).to_le_bytes().to_vec(),
                    Err(e) => return e,
                }
            }
            (IPPROTO_IP, IP_MULTICAST_TTL) => match int() {
                Ok(-1) => 1i32.to_le_bytes().to_vec(),
                Ok(v) if (0..=255).contains(&v) => v.to_le_bytes().to_vec(),
                Ok(_) => return EINVAL,
                Err(e) => return e,
            },
            (IPPROTO_IP, n) if n == IP_MULTICAST_LOOP || IP_BOOLS.contains(&n) => match int() {
                Ok(v) => ((v != 0) as i32).to_le_bytes().to_vec(),
                Err(e) => return e,
            },
            (IPPROTO_TCP, TCP_MAXSEG) => match int() {
                Ok(v) if val.len() >= 4 && (v == 0 || (88..=65535).contains(&v)) => v.to_le_bytes().to_vec(),
                Ok(_) | Err(_) => return EINVAL,
            },
            (IPPROTO_TCP, TCP_KEEPIDLE | TCP_KEEPINTVL) => match int() {
                Ok(v) if val.len() >= 4 && (1..=32767).contains(&v) => v.to_le_bytes().to_vec(),
                _ => return EINVAL,
            },
            (IPPROTO_TCP, TCP_KEEPCNT | TCP_SYNCNT) => match int() {
                Ok(v) if val.len() >= 4 && (1..=127).contains(&v) => v.to_le_bytes().to_vec(),
                _ => return EINVAL,
            },
            (IPPROTO_TCP, TCP_USER_TIMEOUT) => match int() {
                Ok(v) if val.len() >= 4 && v >= 0 => v.to_le_bytes().to_vec(),
                _ => return EINVAL,
            },
            (IPPROTO_TCP, TCP_INFO) => return ENOPROTOOPT,
            (IPPROTO_TCP, TCP_CONGESTION) => {
                let name: Vec<u8> = val.iter().copied().take(16).take_while(|&b| b != 0).collect();
                if name != b"cubic" && name != b"reno" {
                    return ENOENT;
                }
                name
            }
            (IPPROTO_TCP, n) if TCP_BOOLS.contains(&n) => match int() {
                Ok(v) if val.len() >= 4 => ((v != 0) as i32).to_le_bytes().to_vec(),
                _ => return EINVAL,
            },
            // Other known options: integers, or structures kept as given
            _ => {
                if val.len() < 4 && level != IPPROTO_IP {
                    return EINVAL;
                }
                val.to_vec()
            }
        };
        self.vals.insert((level, name), stored);
        0
    }

    /// `getsockopt(level, name)`: the value's bytes (the caller copies at most `optlen`).
    pub fn get(&self, level: u32, name: u32, info: &SockInfo) -> Result<Vec<u8>, i64> {
        if !known(level, name, info.stream) {
            return Err(ENOPROTOOPT);
        }
        let i = |v: i32| v.to_le_bytes().to_vec();
        if let Some(v) = self.vals.get(&(level, name)) {
            return Ok(v.clone());
        }
        Ok(match (level, name) {
            (SOL_SOCKET, SO_TYPE) => i(if info.stream { 1 } else { 2 }),
            (SOL_SOCKET, SO_ERROR) => i(-info.error as i32),
            (SOL_SOCKET, SO_DOMAIN) => i(2),
            (SOL_SOCKET, SO_PROTOCOL) => i(if info.stream { 6 } else { 17 }),
            (SOL_SOCKET, SO_ACCEPTCONN) => i(0),
            (SOL_SOCKET, SO_SNDBUF) => i(if info.stream { 16_384 } else { BUF_MAX as i32 }),
            (SOL_SOCKET, SO_RCVBUF) => i(if info.stream { 131_072 } else { BUF_MAX as i32 }),
            (SOL_SOCKET, SO_RCVLOWAT | SO_SNDLOWAT) => i(1),
            (SOL_SOCKET, SO_LINGER) => alloc::vec![0; 8],
            (SOL_SOCKET, SO_RCVTIMEO_OLD | SO_RCVTIMEO_NEW) => ns_timeval(self.rcvtimeo),
            (SOL_SOCKET, SO_SNDTIMEO_OLD | SO_SNDTIMEO_NEW) => ns_timeval(self.sndtimeo),
            (SOL_SOCKET, SO_BINDTODEVICE) => Vec::new(),
            (SOL_SOCKET, SO_PEERCRED) => alloc::vec![0; 12],
            (SOL_SOCKET, SO_PEERNAME) => return Err(ENOTCONN),
            (IPPROTO_IP, IP_TTL) => i(64),
            (IPPROTO_IP, IP_MTU_DISCOVER) => i(1),
            (IPPROTO_IP, IP_MTU) => {
                if !info.connected {
                    return Err(ENOTCONN);
                }
                i(1500)
            }
            (IPPROTO_IP, IP_MULTICAST_TTL | IP_MULTICAST_LOOP) => i(1),
            (IPPROTO_TCP, TCP_MAXSEG) => i(if info.connected { 1460 } else { 536 }),
            (IPPROTO_TCP, TCP_KEEPIDLE) => i(7200),
            (IPPROTO_TCP, TCP_KEEPINTVL) => i(75),
            (IPPROTO_TCP, TCP_KEEPCNT) => i(9),
            (IPPROTO_TCP, TCP_SYNCNT) => i(6),
            (IPPROTO_TCP, TCP_CONGESTION) => b"cubic".to_vec(),
            (IPPROTO_TCP, TCP_INFO) => {
                // struct tcp_info: state, then the fields Hydra does not track (0), with the
                // MSS values and the default RTO (in microseconds)
                let mut v = alloc::vec![0u8; 232];
                v[0] = info.tcp_state;
                v[8..12].copy_from_slice(&1_000_000u32.to_le_bytes()); // tcpi_rto
                v[16..20].copy_from_slice(&1460u32.to_le_bytes()); // tcpi_snd_mss
                v[20..24].copy_from_slice(&1460u32.to_le_bytes()); // tcpi_rcv_mss
                v
            }
            _ => i(0),
        })
    }
}
