# ATA / IDE PIO Hard Disk Block Driver

## 1. Architectural Role & Design Rationale

Hydra OS requires autonomous persistent secondary storage that remains fully functional after UEFI boot services are terminated (`ExitBootServices`). The **ATA / IDE Programmed I/O (PIO)** driver provides direct bare-metal block access to virtual and physical hard disk controllers (e.g. Intel PIIX3/PIIX4 IDE controllers or SATA controllers operating in IDE legacy compatibility mode) without any runtime BIOS/UEFI firmware dependencies.

The driver acts as the physical block device backing the **OpenZFS Storage Pool Allocator (SPA)**, binding physical 512-byte sectors to ZFS 4096-byte virtual blocks (`vdev-ata-0`).

```text
+--------------------------------------------------------------------------+
|                        Hydra Shell / Userland Apps                       |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|                  Microkernel ZFS Client & DMU Subsystem                  |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|            OpenZFS Storage Pool Allocator (SPA - 32 MiB Pool)             |
+--------------------------------------------------------------------------+
                                     │
                                     ▼
+--------------------------------------------------------------------------+
|               ATA / IDE Block Driver (Polled PIO, Ring 0)                |
+--------------------------------------------------------------------------+
                  │                                     │
                  ▼                                     ▼
     Command Ports (0x1F0..0x1F7)              Control Port (0x3F6)
```

---

## 2. Port & Register Specifications

The ATA driver communicates over the legacy PC/AT standard I/O port assignments:

| Port | Register Name | Direction | Function |
|:---:|:---|:---:|:---|
| `0x1F0` | Data Register | Read/Write | 16-bit PIO sector data transfer |
| `0x1F1` | Error / Features | Read / Write | Pre-command features / Post-command error flags |
| `0x1F2` | Sector Count | Read/Write | Number of 512-byte sectors to transfer (0 = 256 sectors) |
| `0x1F3` | LBA Low | Read/Write | Bits 0..7 of starting Logical Block Address |
| `0x1F4` | LBA Mid | Read/Write | Bits 8..15 of starting Logical Block Address |
| `0x1F5` | LBA High | Read/Write | Bits 16..23 of starting Logical Block Address |
| `0x1F6` | Drive / Head | Read/Write | Bits 24..27 of LBA, Master/Slave select, and LBA flag (`0xE0`) |
| `0x1F7` | Status / Command | Read / Write | Drive status flags / Command dispatch register |
| `0x3F6` | Control / Alt Status | Write / Read | Device Control (`nIEN`, `SRST`) / Alternate Status |

---

## 3. Status Register & Bit Definitions

The driver verifies device status before and after every hardware transaction:

| Bit | Name | Description |
|:---:|:---|:---|
| **7** | `BSY` (Busy) | Drive is executing an internal command; other registers invalid. |
| **6** | `DRDY` (Device Ready)| Drive is spun up, locked on track, and ready for commands. |
| **5** | `DF` (Device Fault) | Drive fault condition detected. |
| **4** | `DSC` / `SRV` | Drive seek complete / Service request. |
| **3** | `DRQ` (Data Request)| Drive is ready to transmit/receive data through port `0x1F0`. |
| **0** | `ERR` (Error) | An error occurred during the last dispatched command. |

---

## 4. Polled PIO Operation & Interrupt Isolation

To maintain zero interrupt latency and absolute deterministic execution across CPU cores, the driver operates in **Polled Programmed I/O (PIO)** mode:

1. **Hardware Interrupt Masking (`nIEN = 1`)**:
   During initialization, bit 1 (`nIEN`) of the Device Control Register (`0x3F6`) is set to `1`. This disables device hardware interrupts on IRQ 14, preventing spontaneous interrupts from preempting microkernel threads.
2. **400ns Propagation Delays**:
   After writing to command or control registers, the driver performs four successive reads of the Alternate Status Register (`0x3F6`) to ensure the device logic has stabilized before polling the status register.
3. **Spin-Wait Polling with Bounded Timeouts**:
   The driver spins using `core::hint::spin_loop()` until the `BSY` bit clears and `DRQ` asserts. If the drive fails to respond within 1,000,000 poll cycles, a descriptive timeout error is returned.

---

## 5. ATA Commands Implemented

- **`ATA_CMD_IDENTIFY` (`0xEC`)**:
  Dispatched on boot to probe drive presence, extract the ASCII model name (40 bytes), total sectors (LBA28 / LBA48), and verify that the connected device is an ATA hard disk (and not an ATAPI optical drive).
- **`ATA_CMD_READ_SECTORS` (`0x20`) / `READ_SECTORS_EXT` (`0x24`)**:
  Reads contiguous 512-byte sectors into memory over the 16-bit data port `0x1F0`.
- **`ATA_CMD_WRITE_SECTORS` (`0x30`) / `WRITE_SECTORS_EXT` (`0x34`)**:
  Writes contiguous 512-byte sectors from memory to magnetic/solid-state media.
- **`ATA_CMD_CACHE_FLUSH` (`0xE7`) / `CACHE_FLUSH_EXT` (`0xEA`)**:
  Commands the on-disk volatile write cache to commit all modified sectors to non-volatile physical storage, providing strict ACID durability.

---

## 6. Shell & Diagnostic Integration

The block device subsystem is exposed to userland and systems administrators via the `disks` (alias `storage`, `lsblk`) shell command:

```text
hydra:/bin> disks
=== Hydra OS Storage Subsystem & Block Devices ===

Device: /dev/hda (Primary Master ATA/IDE)
  - Model:             QEMU HARDDISK
  - Controller Port:   I/O Base 0x1F0, Control 0x3F6
  - Capacity:          32 MiB (33554432 bytes)
  - Total Sectors:     65536 (512 bytes/sector)
  - Addressing:        LBA48 (48-bit Logical Block Addressing)
  - I/O Mode:          Programmed I/O (Polled PIO, nIEN=1)
  - Cache Flushing:    Hardware ATA CACHE FLUSH supported
  - Vdev Association:  vdev-ata-0 -> Backs OpenZFS pool 'hydrapool'
  - Persistence:       ENABLED (Durably saved across reboots)
```
