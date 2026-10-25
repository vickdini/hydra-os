# Intel E1000 Gigabit Ethernet Driver & Microkernel Network Stack

## 1. Architectural Role & Design Rationale

Hydra OS implements a zero-dependency, `no_std` native network protocol stack running directly in Ring 0 / Ring 3 microkernel space. Rather than relying on monolithic Linux network subsystems or third-party crates with external POSIX requirements, Hydra OS provides a purpose-built networking architecture designed for microkernel efficiency, zero-copy packet processing, and direct integration with persistent OpenZFS storage.

```text
+--------------------------------------------------------------------------+
|                  Application & Shell Utilities Layer                     |
|     - `ifconfig` / `ip` (Interface diagnostics & TX/RX telemetry)        |
|     - `dhcp` (Automated DHCP dynamic lease acquisition)                  |
|     - `ping <ip>` (ICMP Echo Request/Reply latency tester)               |
|     - `wget <ip> <port> <path> <zfs_path>` (HTTP/1.0 File Downloader)    |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|                   Transport Layer Protocols (RFC 768 / 793)             |
|     - UDP (User Datagram Protocol: Checksum, ports, datagram mux)        |
|     - TCP (Transmission Control Protocol: 3-Way Handshake, SEQ/ACK, PSH) |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|                   Internetwork Layer Protocols (RFC 791 / 792 / 826)     |
|     - IPv4 (Internet Protocol v4: 20-byte header, RFC 1071 Checksum)     |
|     - ICMP (Internet Control Message Protocol: Echo Request / Reply)     |
|     - ARP (Address Resolution Protocol: Dynamic 16-entry MAC cache)      |
|     - DHCP Client (RFC 2131: Discover -> Offer -> Request -> Ack)       |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|                    Link Layer: Ethernet II Framing                       |
|     - Destination MAC (6B), Source MAC (6B), EtherType (2B)              |
|     - EtherType 0x0800 (IPv4), EtherType 0x0806 (ARP)                    |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|            Intel 82540EM (E1000) Gigabit NIC Controller Driver            |
|     - PCI Bus Enumeration (Vendor: 0x8086, Device: 0x100E)               |
|     - 32-Entry Circular Ring Transmit (TX) & Receive (RX) Descriptors    |
|     - Memory Mapped I/O (MMIO) Registers (CTRL, RCTL, TCTL, RAL/RAH)     |
|     - Direct Memory Access (DMA) Packet Buffers (2048 bytes per slot)    |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
       Physical / Virtualized Hardware (VirtualBox 82540EM / QEMU E1000)
```

---

## 2. PCI Subsystem & Intel 82540EM Hardware Controller

Hardware interaction begins with the x86 PCI Configuration Mechanism #1 ([`src/arch/pci.rs`](file:///d:/os/src/arch/pci.rs)):
- **Config Address Port (`0xCF8`)**: Formats 32-bit queries containing the Bus (0–255), Device (0–31), Function (0–7), and Register offset (aligned to 4 bytes).
- **Config Data Port (`0xCFC`)**: Reads and writes 32-bit register values.
- **Bus Mastering**: Bit 2 of the PCI Command Register (`0x04`) is explicitly enabled to allow the NIC's DMA engine to access host system memory.

### Intel 82540EM Architecture ([`src/net/e1000.rs`](file:///d:/os/src/net/e1000.rs))
The Intel 82540EM Gigabit Ethernet controller is initialized via standard MMIO registers:
1. **Device Reset**: The `CTRL_RST` bit is asserted, followed by hardware link setup (`CTRL_SLU`).
2. **MAC Address Extraction**: The hardware burned-in MAC address is read from registers `RAL0` (Receive Address Low) and `RAH0` (Receive Address High).
3. **Receive Engine (`RCTL`)**:
   - Programmed with 32 circular RX descriptors (`RxDesc`).
   - Configured with `RCTL_EN` (Receiver Enable), `RCTL_BAM` (Broadcast Accept Mode), and `RCTL_BSIZE_2048` (2048-byte DMA packet buffer per descriptor).
4. **Transmit Engine (`TCTL`)**:
   - Programmed with 32 circular TX descriptors (`TxDesc`).
   - Configured with `TCTL_EN` (Transmitter Enable), `TCTL_PSP` (Pad Short Packets), and standard IPG (Inter-Packet Gap) timings via `TIPG`.

---

## 3. Network Stack Implementation

### Ethernet II Framing ([`src/net/ethernet.rs`](file:///d:/os/src/net/ethernet.rs))
Packs 14-byte Ethernet headers containing 6-byte Destination MAC, 6-byte Source MAC, and 16-bit EtherType:
- `0x0806`: Address Resolution Protocol (ARP).
- `0x0800`: Internet Protocol version 4 (IPv4).

### Address Resolution Protocol & Cache ([`src/net/arp.rs`](file:///d:/os/src/net/arp.rs))
Maintains an internal dynamic `ArpCache` of up to 16 mappings between 4-byte IPv4 addresses and 6-byte Ethernet hardware addresses.
- **ARP Request**: Broadcasts `FF:FF:FF:FF:FF:FF` asking `"Who has IP X.X.X.X? Tell Hydra OS"`.
- **ARP Reply**: Dynamically updates the cache with target MAC addresses upon receipt.

### IPv4 Engine & Checksum Verification ([`src/net/ipv4.rs`](file:///d:/os/src/net/ipv4.rs))
Encapsulates 20-byte IPv4 headers with Type of Service (`0x00`), Total Length, Identification counter, Flags/Fragment Offset (`0x4000` Don't Fragment), TTL (`64`), Protocol (`1` ICMP, `6` TCP, `17` UDP), Source IP, and Destination IP.
- Implements RFC 1071 standard One's Complement 16-bit Internet Checksum computation.

### DHCP Dynamic Lease Acquisition ([`src/net/dhcp.rs`](file:///d:/os/src/net/dhcp.rs))
Automates network configuration via RFC 2131:
1. **DHCP Discover**: Broadcast packet sent from port 68 to port 67 (`255.255.255.255`).
2. **DHCP Offer**: Parses offered IP address, server identifier, subnet mask (Option 1), router gateway (Option 3), and DNS servers (Option 6).
3. **DHCP Request**: Broadcasts formal request for the offered lease.
4. **DHCP Ack**: Acknowledges lease and applies network parameters directly to the global `Interface` state.

### Domain Name System (DNS) Client ([`src/net/dns.rs`](file:///d:/os/src/net/dns.rs))
Implements standard RFC 1035 UDP-based name resolution over port 53:
- **URL & Hostname Sanitization**: Strips `http://`, `https://`, trailing paths (`/...`), and port numbers (`:80`).
- **Standard Query Formatting**: Emits 12-byte header with recursion desired (`0x0100`), single question, and length-prefixed domain labels (e.g. `\x06google\x03com\x00`).
- **Response Parsing**: Validates transaction IDs and response flags, handles DNS name pointer compression (`0xC0`), parses Answer records, and extracts 4-byte `A` (IPv4) addresses.

### Transport Layer & HTTP Downloader ([`src/net/tcp.rs`](file:///d:/os/src/net/tcp.rs) & [`src/net/http.rs`](file:///d:/os/src/net/http.rs))
- **TCP Handshake**: Performs SYN -> SYN-ACK -> ACK connection establishment with sequence and acknowledgment tracking.
- **HTTP/1.0 GET**: Transmits `GET <path> HTTP/1.0\r\nHost: <host>\r\nConnection: close\r\n\r\n`, receives streaming segments, strips HTTP response headers (`200 OK`), and returns binary file content.

---

## 4. OpenZFS Storage Integration

Hydra OS connects its network stack directly to persistent OpenZFS storage pools:
- The `wget` command downloads remote binaries, configuration files, and assets over TCP/HTTP using either IP addresses or domain names.
- Streamed payloads are committed into persistent OpenZFS storage via [`ZfsClient::write_file_by_path`](file:///d:/os/src/fs/zfs.rs).

---

## 5. Shell Command Reference

| Command | Arguments | Description |
| :--- | :--- | :--- |
| `ifconfig` / `ip` | None | Displays MAC address, link state, IP address, subnet mask, gateway, DNS, and TX/RX packet telemetry. |
| `dhcp` | None | Manually triggers the RFC 2131 DHCP state machine to refresh network parameters (auto-acquired at boot). |
| `dns` / `nslookup` | `<domain_or_url>` | Queries the configured DNS server to resolve a domain name into an IPv4 address. |
| `ping` | `<ip_or_url>` | Resolves domain names/URLs via DNS and transmits 4 ICMP Echo Request packets to verify connectivity. |
| `wget` | `<server_or_url> <port> <path> <dest>` | Fetches a remote file over HTTP and commits the payload directly into OpenZFS. |

