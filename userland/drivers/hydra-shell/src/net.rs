//! The network commands: `ifconfig`, `dhcp`, `dns`, `ping`, `wget`.
//!
//! The ONE module of hydra-shell that talks to the network. Today it calls the admin
//! interface's temporary network group (`ADMIN_NET`, op group 0x6_), which runs the kernel's
//! network stack. Wave 2 moves the protocols into the ring-3 net-server (group 2): then
//! [`request`] (the only function that reaches the network) sends the same commands to
//! net-server instead, and nothing else in hydra-shell changes.

use alloc::vec::Vec;

use crate::proto::*;
use crate::sys::*;
use crate::{report, Shell};

/// Runs network command `code` with its arguments (they print their own output).
fn request(code: u64, args: &[&str]) {
    let input: Vec<u8> = nul_join(args);
    if let Err(e) = admin(ADMIN_NET, [code, 0, 0, 0], &input) {
        report(&e, "network");
    }
}

pub fn ifconfig(_sh: &mut Shell, args: &[&str]) {
    request(NET_IFCONFIG, args)
}

pub fn dhcp(_sh: &mut Shell, args: &[&str]) {
    request(NET_DHCP, args)
}

pub fn dns(_sh: &mut Shell, args: &[&str]) {
    request(NET_DNS, args)
}

pub fn ping(_sh: &mut Shell, args: &[&str]) {
    request(NET_PING, args)
}

pub fn wget(sh: &mut Shell, args: &[&str]) {
    // The destination is a pool path: relative to the working directory, as for cp
    let mut a: Vec<alloc::string::String> = args.iter().map(|s| alloc::string::String::from(*s)).collect();
    if a.len() >= 4 {
        a[3] = crate::normalize_path(&sh.cwd, &a[3]);
    }
    let refs: Vec<&str> = a.iter().map(|s| s.as_str()).collect();
    request(NET_WGET, &refs)
}
