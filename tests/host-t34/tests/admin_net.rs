//! `src/admin/net.rs`: the console's network commands (ifconfig, dhcp, dns, ping, wget).

mod common;
use common::*;
use k::admin::net::run;
use k::admin::proto::*;
use k::admin::Failure;

fn ok(r: Result<(), Failure>) {
    assert!(r.is_ok(), "the command failed");
}

#[test]
fn unknown_network_commands() {
    let _g = setup();
    assert!(matches!(run(99, &[]), Err(Failure::Errno(EINVAL))));
}

#[test]
fn ifconfig_without_a_server_or_a_card() {
    let _g = setup();
    ok(run(NET_IFCONFIG, &[]));
    assert!(fake::take_out().contains("The network server (net_server) is not running."));
    net_server(5);
    ok(run(NET_IFCONFIG, &[]));
    let out = fake::take_out();
    assert!(out.contains("No Ethernet network interface controller detected on PCI bus."));
    assert!(out.contains("Tip: Enable Intel PRO/1000"));
}

#[test]
fn ifconfig_shows_the_interface() {
    use k::ipc::protocol::*;
    let _g = setup();
    fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    for (i, v) in [10u64, 2000, 20, 3000].iter().enumerate() {
        status(NETS_ST_ETH_COUNTERS + i, *v);
    }
    status(NETS_ST_RX_CALLS, 50);
    status(NETS_ST_RX_CALLS + 1, 12);
    ok(run(NET_IFCONFIG, &[]));
    let out = fake::take_out();
    for want in [
        "=== Hydra OS Network Interfaces ===",
        "  - Driver RX:         50 requests, 12 frames (net-server)",
        "Interface: eth0 (Intel 82540EM Gigabit Ethernet)",
        "  - Hardware MAC:      52:54:00:12:34:56",
        "  - Carrier Link:      UP (1000 Mbps Full-Duplex)",
        "  - IPv4 Address:      10.0.2.15",
        "  - Subnet Mask:       255.255.255.0",
        "  - Default Gateway:   10.0.2.2",
        "  - DNS Server:        10.0.2.3",
        "  - Telemetry RX:      10 packets (2000 bytes)",
        "  - Telemetry TX:      20 packets (3000 bytes)",
    ] {
        assert!(out.contains(want), "{:?} not in {}", want, out);
    }
    // No address yet but a link: a DHCP lease first
    let net = fake_net();
    iface_up([0, 0, 0, 0], [0, 0, 0, 0]);
    net.borrow_mut().dhcp = Some(Ok([192, 168, 1, 50]));
    ok(run(NET_IFCONFIG, &[]));
    let out = fake::take_out();
    assert!(out.contains("[*] Requesting dynamic DHCP lease for eth0..."));
    assert!(out.contains("  - IPv4 Address:      192.168.1.50"));
    // No link: no DHCP, and the link shows down
    status(NETS_ST_IP, 0);
    status(NETS_ST_FLAGS, NETS_F_NIC);
    ok(run(NET_IFCONFIG, &[]));
    let out = fake::take_out();
    assert!(!out.contains("Requesting"));
    assert!(out.contains("DOWN (No carrier detected)"));
    // The lease fails: the interface as it was
    status(NETS_ST_FLAGS, NETS_F_NIC | NETS_F_LINK);
    net.borrow_mut().dhcp = Some(Err(-110));
    ok(run(NET_IFCONFIG, &[]));
    assert!(fake::take_out().contains("  - IPv4 Address:      0.0.0.0"));
}

#[test]
fn dhcp_reports_the_lease() {
    let _g = setup();
    let net = fake_net();
    iface_up([0, 0, 0, 0], [10, 0, 2, 3]);
    net.borrow_mut().dhcp = Some(Ok([10, 0, 2, 16]));
    ok(run(NET_DHCP, &[]));
    let out = fake::take_out();
    assert!(out.contains("[+] DHCP Lease Successfully Acquired!"));
    assert!(out.contains("    - Assigned IP:     10.0.2.16"));
    assert!(out.contains("    - DNS Server:      10.0.2.3"));
    assert!(out.contains("    - DHCP Server:     0.0.0.2"));
    net.borrow_mut().dhcp = Some(Err(-19));
    ok(run(NET_DHCP, &[]));
    assert!(fake::take_out().contains("[!] DHCP configuration failed: no network card"));
}

#[test]
fn dns_lookups() {
    let _g = setup();
    ok(run(NET_DNS, &[]));
    assert!(fake::take_out().contains("Usage: dns <domain_or_url>"));
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    net.borrow_mut().names.push(("example.com".into(), [93, 184, 216, 34]));
    // A URL is cut to its host
    ok(run(NET_DNS, &["https://example.com/index.html"]));
    let out = fake::take_out();
    assert!(out.contains("[*] Querying DNS server 10.0.2.3 for 'example.com'..."), "{}", out);
    assert!(out.contains("Domain:  example.com\nAddress: 93.184.216.34\n"));
    ok(run(NET_DNS, &["nowhere.invalid"]));
    assert!(fake::take_out().contains("[!] DNS resolution error: no such name"));
}

#[test]
fn ping_reports_replies_and_statistics() {
    let _g = setup();
    ok(run(NET_PING, &[]));
    assert!(fake::take_out().contains("Usage: ping"));
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    net.borrow_mut().pingable.push([10, 0, 2, 2]);
    ok(run(NET_PING, &["10.0.2.2"]));
    let out = fake::take_out();
    assert!(!out.contains("Resolving"));
    assert!(out.contains("PING 10.0.2.2 (10.0.2.2) with 32 bytes of diagnostic data:"));
    for seq in 1..=4 {
        assert!(out.contains(&format!("Reply from 10.0.2.2: bytes=32 seq={} time=0ms TTL=64", seq)), "{}", out);
    }
    assert!(out.contains("4 packets transmitted, 4 received, 0% packet loss"));
    assert!(out.contains("rtt min/avg/max = 0/0/0 ms"));
}

#[test]
fn ping_by_name_and_timeouts() {
    let _g = setup();
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    net.borrow_mut().names.push(("router".into(), [10, 0, 2, 9]));
    ok(run(NET_PING, &["router"]));
    let out = fake::take_out();
    assert!(out.contains("[*] Resolving domain 'router' via DNS..."));
    assert!(out.contains("[+] Resolved 'router' -> 10.0.2.9"));
    assert!(out.contains("Request timed out (seq=1): Request timed out (no ICMP Echo Reply received)"));
    assert!(out.contains("4 packets transmitted, 0 received, 100% packet loss"));
    assert!(!out.contains("rtt"));
    // A name nobody knows
    ok(run(NET_PING, &["ghost"]));
    assert!(fake::take_out().contains("[!] DNS resolution failed for 'ghost': no such name"));
}

#[test]
fn ping_asks_for_a_lease_first() {
    let _g = setup();
    let net = fake_net();
    iface_up([0, 0, 0, 0], [10, 0, 2, 3]);
    net.borrow_mut().dhcp = Some(Ok([10, 0, 2, 15]));
    net.borrow_mut().pingable.push([10, 0, 2, 2]);
    ok(run(NET_PING, &["10.0.2.2"]));
    let out = fake::take_out();
    assert!(out.contains("[*] Interface has no IP address. Automatically acquiring DHCP lease..."));
    assert!(out.contains("4 received"));
}

#[test]
fn dotted_addresses_are_parsed_strictly() {
    let _g = setup();
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    net.borrow_mut().dns_err = Some(-2);
    // Not dotted quads: each goes to DNS
    for bad in ["1.2.3", "1.2.3.4.5", "256.1.1.1", "1.2.3.999", "1..2.3", ".1.2.3", "1.2.3.", "1.2.a.4", "1000.1.1.1"] {
        ok(run(NET_PING, &[bad]));
        let out = fake::take_out();
        assert!(out.contains("via DNS"), "{} was taken as an address: {}", bad, out);
    }
    // Dotted quads are not looked up
    for good in ["0.0.0.0", "255.255.255.255", "127.0.0.1"] {
        ok(run(NET_PING, &[good]));
        assert!(!fake::take_out().contains("via DNS"), "{}", good);
    }
}

#[test]
fn wget_downloads_into_the_pool() {
    let _g = setup();
    ok(run(NET_WGET, &["a", "b", "c"]));
    let out = fake::take_out();
    assert!(out.contains("Usage: wget <server_ip_or_url> <port> <remote_path> <dest_zfs_path>"));
    assert!(out.contains("Example: wget 10.0.2.2 80"));
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    net.borrow_mut().http_response = b"HTTP/1.0 200 OK\r\nContent-Length: 5\r\n\r\nhello".to_vec();
    net.borrow_mut().names.push(("files.local".into(), [10, 0, 2, 2]));
    ok(run(NET_WGET, &["files.local", "8080", "/pkg/app.elf", "/bin/app.elf"]));
    let out = fake::take_out();
    assert!(out.contains("[+] Resolved 'files.local' -> 10.0.2.2"));
    assert!(out.contains("[*] Connecting to http://10.0.2.2:8080/pkg/app.elf ..."));
    assert!(out.contains("[+] Successfully downloaded 5 bytes!"));
    assert!(out.contains("[+] Written to ZFS! Committed in TXG #77."));
    assert_eq!(fake::with(|s| s.files.get("/bin/app.elf").cloned()).unwrap(), b"hello".to_vec());
    let req = String::from_utf8(net.borrow().sent.clone()).unwrap();
    assert_eq!(req, "GET /pkg/app.elf HTTP/1.0\r\nHost: 10.0.2.2\r\nUser-Agent: HydraOS\r\nConnection: close\r\n\r\n");
}

#[test]
fn wget_errors() {
    let _g = setup();
    let net = fake_net();
    iface_up([10, 0, 2, 15], [10, 0, 2, 3]);
    ok(run(NET_WGET, &["nohost", "80", "/", "/x"]));
    assert!(fake::take_out().contains("[!] DNS resolution failed for 'nohost': no such name"));
    ok(run(NET_WGET, &["10.0.2.2", "http", "/", "/x"]));
    assert!(fake::take_out().contains("[!] Invalid port number: 'http'"));
    net.borrow_mut().refuse = true;
    ok(run(NET_WGET, &["10.0.2.2", "80", "/", "/x"]));
    assert!(fake::take_out().contains("[!] HTTP transfer failed: connection refused"));
    net.borrow_mut().refuse = false;
    net.borrow_mut().http_response = b"HTTP/1.0 200 OK\r\n\r\nbody".to_vec();
    fake::with(|s| s.fs_fail = Some("no space"));
    ok(run(NET_WGET, &["10.0.2.2", "80", "/", "/x"]));
    assert!(fake::take_out().contains("[!] Failed to commit to ZFS: no space"));
}
