//! # Task Subsystem: Driver Supervisor (MINIX 3-Style Reincarnation Server)
//!
//! Starts the Ring 3 driver and server programs, watches them, and restarts them when they
//! crash or stop answering.
//!
//! ## Architectural Role & Design Rationale
//!
//! Drivers and system servers are separate programs: static native ELFs built from
//! `userland/drivers` and embedded in the kernel image as boot modules (the disk driver
//! cannot be loaded from the disk it drives). Each runs in Ring 3 in an address space of
//! its own and serves one endpoint ([`crate::ipc::service`]). The supervisor:
//!
//! 1. starts them when the kernel takes over the hardware (`start_all`), with the
//!    device memory each may map ([`crate::ipc::service::set_grants`]) and arguments
//!    describing its devices;
//! 2. checks every second that each is alive and answers a heartbeat
//!    ([`crate::ipc::protocol::MSG_SUPERVISOR_PING`]);
//! 3. restarts one that died or stopped answering, up to a limit, after which the service
//!    is marked faulted.
//!
//! A kernel caller whose driver died revives it on the spot (`revive`): the caller may
//! hold locks of its subsystem, so it cannot wait for the supervisor task to run.
//!
//! ## Concurrency & Safety
//!
//! The service table is a [`spin::Mutex`] held only for bookkeeping, never across a call to
//! a service or a wait.

use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

use crate::ipc::protocol::{ENDPOINT_BLOCK_DEV, ENDPOINT_NET_DEV, ENDPOINT_ZFS_SERVER, MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG};
use crate::ipc::service;
use crate::ipc::Message;
use crate::task::{is_task_alive, kill, TaskId};

/// The ATA disk driver program.
static ATA_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/ata-driver"));
/// The AHCI (SATA) disk driver program.
static AHCI_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/ahci-driver"));
/// The USB (xHCI and HID input) driver program.
static USB_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/usb-driver"));
/// The ZFS file server program.
static ZFS_SERVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/zfs-server"));
/// The e1000 network driver program.
static E1000_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/e1000-driver"));
/// The sound driver program (Intel High Definition Audio).
static HDA_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/hda-driver"));

/// Operational state of a supervised service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Its process is running (and registered, once it has started up).
    Running,
    /// Being started again after a failure.
    Restarting,
    /// Failed too often; no longer restarted.
    Faulted,
    /// Not started (no hardware for it, or stopped by hand).
    Stopped,
}

/// How to start a service.
pub struct ServiceDescriptor {
    /// Service name (`service` command, process name).
    pub name: &'static str,
    /// Endpoint it serves.
    pub endpoint_id: u32,
    /// Program image.
    image: &'static [u8],
    /// Arguments after the program path, describing its devices (`None`: no device, the
    /// service is not started).
    args: fn() -> Option<Vec<String>>,
    /// Physical ranges it may map.
    grants: fn() -> Vec<(u64, u64)>,
    /// Its process.
    pub task_id: Option<TaskId>,
    /// Current state.
    pub state: ServiceState,
    /// Restarts since boot.
    pub restart_count: u32,
    /// Restarts allowed before the service is marked faulted.
    pub max_restarts: u32,
    /// Heartbeats missed in a row.
    pub unanswered_pings: u32,
    /// Heartbeats that may be missed before the service is restarted.
    pub max_unanswered_pings: u32,
    /// Tick of the last answered heartbeat.
    pub last_heartbeat_tick: u64,
}

impl ServiceDescriptor {
    const fn new(
        name: &'static str,
        endpoint_id: u32,
        image: &'static [u8],
        args: fn() -> Option<Vec<String>>,
        grants: fn() -> Vec<(u64, u64)>,
    ) -> Self {
        Self {
            name,
            endpoint_id,
            image,
            args,
            grants,
            task_id: None,
            state: ServiceState::Stopped,
            restart_count: 0,
            max_restarts: 10,
            unanswered_pings: 0,
            max_unanswered_pings: 3,
            last_heartbeat_tick: 0,
        }
    }
}

/// The first AHCI SATA adapter (PCI class 01:06, programming interface 01) and its
/// register window (`ABAR`, BAR 5).
///
/// # Returns
///
/// `Some((device, abar))`, or `None` if there is no AHCI adapter with its window assigned.
fn ahci_adapter() -> Option<(crate::arch::pci::PciDevice, u64)> {
    use crate::arch::pci;
    pci::find_all_class(0x01, 0x06).into_iter().find_map(|dev| {
        if pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09) != 0x01 {
            return None; // a vendor-specific SATA interface, not AHCI
        }
        let abar = pci::bar_address(&dev, 5);
        (abar != 0).then_some((dev, abar))
    })
}

/// AHCI driver: the adapter's register window and, when the adapter can signal it as a
/// message, its interrupt line (bus mastering and MSI are set up here). Not started
/// without an adapter; the driver exits if no disk is attached to it, and the IDE driver
/// is started instead.
///
/// # Returns
///
/// `Some(Vec<String>)` with `abar=<phys>` and maybe `irq=<line>`, or `None`.
fn ahci_args() -> Option<Vec<String>> {
    let (dev, abar) = ahci_adapter()?;
    crate::arch::iommu::attach(ENDPOINT_BLOCK_DEV, "ahci_driver", &dev);
    crate::arch::pci::enable_bus_mastering(&dev);
    let mut args = alloc::vec![alloc::format!("abar={:#x}", abar)];
    args.extend(crate::arch::bootdisk::driver_arg());
    match service::msi_line(&dev) {
        Some(line) => args.push(alloc::format!("irq={}", line)),
        None => crate::kprintln!("[supervisor] AHCI adapter {:02x}:{:02x}.{}: no MSI; its driver polls", dev.bus, dev.device, dev.function),
    }
    Some(args)
}

/// AHCI driver: the pages holding its register window (on Intel adapters the window is
/// 2 KiB aligned, so it need not start a page).
///
/// # Returns
///
/// The granted `(base, length)` range, if there is an adapter.
fn ahci_grants() -> Vec<(u64, u64)> {
    ahci_adapter().map_or_else(Vec::new, |(_, abar)| {
        let start = abar & !0xFFF;
        let end = (abar + 0x1100 + 0xFFF) & !0xFFF;
        alloc::vec![(start, end - start)]
    })
}

/// ATA driver: the primary channel's ports and, if the PCI IDE controller can bus-master,
/// its DMA registers (bus mastering is enabled here). It exits if there is no disk. Not
/// started when the AHCI driver already serves the disk endpoint.
///
/// # Returns
///
/// `Some(Vec<String>)` containing configuration flags (`"io=..."`, `"bm=..."`), or `None` if device absent.
fn ata_args() -> Option<Vec<String>> {
    if service::is_online(ENDPOINT_BLOCK_DEV) {
        return None;
    }
    let mut args = alloc::vec![String::from("io=0x1f0"), String::from("ctrl=0x3f6")];
    args.extend(crate::arch::bootdisk::driver_arg());
    if let Some(dev) = crate::arch::pci::find_class(0x01, 0x01) {
        let prog_if = crate::arch::pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09);
        let bar4 = crate::arch::pci::pci_read_u32(dev.bus, dev.device, dev.function, 0x20);
        if prog_if & 0x80 != 0 && bar4 & 1 != 0 && bar4 & !3 != 0 {
            crate::arch::iommu::attach(ENDPOINT_BLOCK_DEV, "ata_driver", &dev);
            crate::arch::pci::enable_bus_mastering(&dev);
            args.push(alloc::format!("bm={:#x}", bar4 & 0xFFFC));
        }
    }
    Some(args)
}

/// e1000 driver: the adapter's register window, family and interrupt: a message-signalled
/// one (MSI) where the adapter has it (82574, PCH), else its legacy line as the firmware
/// routed it. Not started without an adapter.
///
/// # Returns
///
/// `Some(Vec<String>)` containing base address, model and IRQ flags, or `None` if no adapter found.
fn e1000_args() -> Option<Vec<String>> {
    let a = crate::net::e1000::find_adapter()?;
    crate::arch::iommu::attach(ENDPOINT_NET_DEV, "net_driver", &a.dev);
    let mut args = alloc::vec![alloc::format!("bar0={:#x}", a.bar0), alloc::format!("model={}", a.model)];
    if crate::arch::iommu::dma_test_enabled() {
        // QEMU's opt/hydra/iommu=test: the driver accepts the rogue-DMA test request
        args.push(String::from("dma_test=1"));
    }
    let msi = if a.model == "82540" { None } else { service::msi_line(&a.dev) };
    let irq = msi.unwrap_or(a.dev.irq_line);
    if msi.is_some() || (irq != 0 && irq < 16 && irq != 2) {
        args.push(alloc::format!("irq={}", irq));
    }
    Some(args)
}

/// e1000 driver: its 128 KiB register window.
///
/// # Returns
///
/// A vector of physical memory ranges `(base, length)` granted to the network driver.
fn e1000_grants() -> Vec<(u64, u64)> {
    crate::net::e1000::find_adapter().map_or_else(Vec::new, |a| alloc::vec![(a.bar0, 128 * 1024)])
}

/// The first xHCI USB host controller (PCI class 0C:03, programming interface 30) with
/// its register window (BAR 0, often 64-bit) and the window's size.
///
/// # Returns
///
/// `Some((device, base, length))`, or `None`.
fn xhci_controller() -> Option<(crate::arch::pci::PciDevice, u64, u64)> {
    use crate::arch::pci;
    pci::find_all_class(0x0C, 0x03).into_iter().find_map(|dev| {
        if pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09) != 0x30 {
            return None; // UHCI, OHCI or EHCI
        }
        let base = pci::bar_address(&dev, 0);
        let len = (pci::bar_size(&dev, 0) + 0xFFF) & !0xFFF;
        (base != 0 && len != 0).then_some((dev, base, len))
    })
}

/// The xHCI window's grant, computed once (sizing a BAR briefly turns off its decoding,
/// which must not happen while the driver runs).
static XHCI: spin::Once<Option<(crate::arch::pci::PciDevice, u64, u64)>> = spin::Once::new();

/// USB driver: the xHCI controller's register window and its MSI line. On Intel chipsets
/// of the 7 to 9 series (Panther Point, Lynx Point) the USB ports start out routed to the
/// EHCI controllers; they are switched to the xHCI one here, as Linux does
/// (`usb_enable_intel_xhci_ports`), or the keyboard and mouse would not appear on it.
///
/// # Returns
///
/// `Some(Vec<String>)` with `mmio=<phys> len=<bytes>` and maybe `irq=<line>`, or `None`.
fn usb_args() -> Option<Vec<String>> {
    use crate::arch::pci;
    let (dev, base, len) = (*XHCI.call_once(xhci_controller))?;
    crate::arch::iommu::attach(crate::ipc::protocol::ENDPOINT_INPUT_DEV, "usb_driver", &dev);
    pci::enable_bus_mastering(&dev);
    if dev.vendor_id == 0x8086 && matches!(dev.device_id, 0x1E31 | 0x8C31 | 0x9C31 | 0x8CB1 | 0x9CB1) {
        let (b, d, f) = (dev.bus, dev.device, dev.function);
        // USB 3 SuperSpeed enables (USB3_PSSEN) from their mask (USB3PRM), then the
        // USB 2 port routing (XUSB2PR) from its mask (XUSB2PRM)
        pci::pci_write_u32(b, d, f, 0xD8, pci::pci_read_u32(b, d, f, 0xDC));
        pci::pci_write_u32(b, d, f, 0xD0, pci::pci_read_u32(b, d, f, 0xD4));
        crate::kprintln!("[supervisor] Intel xHCI: USB ports switched from EHCI (routing {:#x})", pci::pci_read_u32(b, d, f, 0xD0));
    }
    let mut args = alloc::vec![alloc::format!("mmio={:#x}", base), alloc::format!("len={:#x}", len)];
    // Where the pool is: the boot partition when the kernel came from a disk (the USB
    // driver serves the pool view if that partition is on a USB disk); otherwise, with
    // no ATA or SATA disk, the first USB disk holding a pool
    match crate::arch::bootdisk::driver_arg() {
        Some(a) => args.push(a),
        None if !service::is_online(ENDPOINT_BLOCK_DEV) => args.push(String::from("pool=usb")),
        None => {}
    }
    if let Some(line) = service::msi_line(&dev) {
        args.push(alloc::format!("irq={}", line));
    } else if let Some((line, table, addr, data)) = service::msix_line(&dev) {
        args.push(alloc::format!("irq={}", line));
        args.push(alloc::format!("msix={:#x}:{:#x}:{:#x}", table, addr, data));
    } else {
        crate::kprintln!("[supervisor] xHCI controller: no MSI; its driver polls");
    }
    Some(args)
}

/// USB driver: the controller's register window.
///
/// # Returns
///
/// The granted `(base, length)` range, if there is a controller.
fn usb_grants() -> Vec<(u64, u64)> {
    XHCI.call_once(xhci_controller).map_or_else(Vec::new, |(_, base, len)| alloc::vec![(base, len)])
}

/// The first High Definition Audio controller (PCI class 04:03) with a codec that can
/// play analog sound, and its register window (BAR 0, 16 KiB). Intel's HDMI-only audio
/// controllers (on the processor, next to the chipset's) are skipped.
fn hda_controller() -> Option<(crate::arch::pci::PciDevice, u64)> {
    use crate::arch::pci;
    const HDMI_ONLY: [u16; 6] = [0x0A0C, 0x0C0C, 0x0D0C, 0x160C, 0x2807, 0x2808];
    pci::find_all_class(0x04, 0x03).into_iter().find_map(|dev| {
        if dev.vendor_id == 0x8086 && HDMI_ONLY.contains(&dev.device_id) {
            return None;
        }
        let base = pci::bar_address(&dev, 0);
        (base != 0).then_some((dev, base))
    })
}

/// The controller found once (sizing BARs must not happen while the driver runs).
static HDA: spin::Once<Option<(crate::arch::pci::PciDevice, u64)>> = spin::Once::new();

/// Sound driver: the controller's register window (bus mastering enabled here). On
/// Intel chipsets the controller's DMA must snoop the processor caches (Linux clears the
/// "no snoop" bit of the device control register 0x78 for the same reason): the ring
/// buffers are ordinary cached memory.
///
/// # Returns
///
/// `Some(Vec<String>)` with `mmio=<phys>`, or `None` without a controller.
fn hda_args() -> Option<Vec<String>> {
    use crate::arch::pci;
    let (dev, base) = (*HDA.call_once(hda_controller))?;
    crate::arch::iommu::attach(crate::ipc::protocol::ENDPOINT_SOUND_DEV, "sound_driver", &dev);
    pci::enable_bus_mastering(&dev);
    if dev.vendor_id == 0x8086 {
        let (b, d, f) = (dev.bus, dev.device, dev.function);
        let devc = pci::pci_read_u16(b, d, f, 0x78);
        if devc & (1 << 11) != 0 {
            pci::pci_write_u16(b, d, f, 0x78, devc & !(1 << 11));
        }
    }
    let sub = pci::pci_read_u32(dev.bus, dev.device, dev.function, 0x2C);
    crate::compat::linux::snd::set_controller(
        base,
        alloc::format!("0000:{:02x}:{:02x}.{}", dev.bus, dev.device, dev.function),
        dev.vendor_id,
        dev.device_id,
        sub,
    );
    Some(alloc::vec![alloc::format!("mmio={:#x}", base)])
}

/// Sound driver: the controller's 16 KiB register window.
fn hda_grants() -> Vec<(u64, u64)> {
    HDA.call_once(hda_controller).map_or_else(Vec::new, |(_, base)| alloc::vec![(base & !0xFFF, 0x4000)])
}

/// Whether the block driver on `endpoint` serves a pool view (unit 0 answers its size).
fn has_pool_view(endpoint: u32) -> bool {
    use crate::ipc::protocol::{MSG_BLOCK_GET_SIZE, MSG_BLOCK_REPLY};
    if !service::is_online(endpoint) {
        return false;
    }
    let _window = service::hold_window(endpoint);
    matches!(
        service::call(endpoint, Message::with_args(MSG_BLOCK_GET_SIZE, [0; 4]), service::CALL_TIMEOUT_TICKS),
        Ok(r) if r.label == MSG_BLOCK_REPLY && r.args[0] == 0 && r.args[1] > 0
    )
}

/// ZFS file server: no arguments; it finds the pool through the disk driver.
///
/// # Returns
///
/// An empty argument vector wrapped in `Some`.
fn zfs_args() -> Option<Vec<String>> {
    // The block cache: an eighth of the RAM, between 128 MiB and 512 MiB (the server's
    // heap is 1 GiB). 128 MiB held less than Firefox maps at every start
    let ram = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock().total_usable_memory();
    let blocks = (ram / 8 / 4096).clamp(32 * 1024, 128 * 1024);
    let mut args = alloc::vec![alloc::format!("cache_blocks={}", blocks)];
    if let Some(id) = crate::arch::bootdisk::new_guid_id() {
        args.push(alloc::format!("new_guid={:x}", id));
    }
    // The pool on a USB disk: the ATA/SATA driver has no pool view (no disk, or the boot
    // disk is a USB stick) and the USB driver has one
    if !has_pool_view(ENDPOINT_BLOCK_DEV) && has_pool_view(crate::ipc::protocol::ENDPOINT_USB_DISK) {
        args.push(String::from("disk=usb"));
        crate::fs::zfs::POOL_ON_USB.store(true, core::sync::atomic::Ordering::Release);
    }
    Some(args)
}

/// No device memory (port I/O and its own DMA buffers only).
///
/// # Returns
///
/// An empty vector of memory grants.
fn no_grants() -> Vec<(u64, u64)> {
    Vec::new()
}

/// Telemetry of one service (`service status`).
#[derive(Debug, Clone)]
pub struct ServiceSnapshot {
    /// Service name.
    pub name: &'static str,
    /// Endpoint it serves.
    pub endpoint_id: u32,
    /// Its process.
    pub task_id: Option<u64>,
    /// Current state.
    pub state: ServiceState,
    /// Restarts since boot.
    pub restart_count: u32,
    /// Heartbeats missed in a row.
    pub unanswered_pings: u32,
}

/// The supervised services.
pub struct Supervisor {
    services: Vec<ServiceDescriptor>,
}

impl Supervisor {
    /// An empty supervisor (services are added by [`supervisor_init`]).
    pub const fn new() -> Self {
        Self { services: Vec::new() }
    }

    /// Looks up the index of a service descriptor by name.
    ///
    /// # Arguments
    ///
    /// * `name` - Service name to search for.
    ///
    /// # Returns
    ///
    /// `Ok(usize)` index within `services`.
    ///
    /// # Errors
    ///
    /// Returns static string error if name is not found.
    fn index(&self, name: &str) -> Result<usize, &'static str> {
        self.services.iter().position(|s| s.name == name).ok_or("Service not found")
    }

    /// Starts service `idx`'s program (a previous instance must be gone).
    ///
    /// # Arguments
    ///
    /// * `idx` - Service index in `services`.
    ///
    /// # Returns
    ///
    /// The newly spawned [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns static string error if spawning or argument retrieval fails.
    fn launch(&mut self, idx: usize) -> Result<TaskId, &'static str> {
        let svc = &mut self.services[idx];
        let args = (svc.args)().ok_or("no device for this service")?;
        service::set_grants(svc.endpoint_id, (svc.grants)());
        let path = alloc::format!("/drivers/{}", svc.name);
        let mut argv: Vec<&str> = alloc::vec![path.as_str()];
        argv.extend(args.iter().map(|a| a.as_str()));
        let id = crate::task::spawn_service(svc.name, svc.image, &argv, svc.endpoint_id)?;
        svc.task_id = Some(id);
        svc.state = ServiceState::Running;
        svc.unanswered_pings = 0;
        svc.last_heartbeat_tick = crate::arch::pit::ticks();
        Ok(id)
    }

    /// Stops service `idx`'s process, if any, and forgets its registration.
    ///
    /// # Arguments
    ///
    /// * `idx` - Service index in `services`.
    fn retire(&mut self, idx: usize) {
        let svc = &mut self.services[idx];
        if let Some(old) = svc.task_id.take() {
            if is_task_alive(old) {
                let _ = kill(old);
            }
            service::release_irqs(old.0);
        }
        service::unregister(svc.endpoint_id);
    }

    /// Replaces service `idx`'s process with a new one, unless it failed too often.
    ///
    /// # Arguments
    ///
    /// * `idx` - Service index in `services`.
    ///
    /// # Returns
    ///
    /// The newly restarted [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns static string error if maximum restarts reached or launch fails.
    fn reincarnate(&mut self, idx: usize) -> Result<TaskId, &'static str> {
        self.retire(idx);
        let svc = &mut self.services[idx];
        if svc.restart_count >= svc.max_restarts {
            svc.state = ServiceState::Faulted;
            crate::kprintln!("[supervisor] '{}' failed {} times; not restarting it", svc.name, svc.restart_count);
            return Err("restart limit reached");
        }
        svc.restart_count += 1;
        svc.state = ServiceState::Restarting;
        let id = self.launch(idx)?;
        let svc = &self.services[idx];
        crate::kprintln!("[supervisor] restarted '{}' as process {} (restart {}/{})", svc.name, id.0, svc.restart_count, svc.max_restarts);
        Ok(id)
    }

    /// Telemetry of all services.
    ///
    /// # Returns
    ///
    /// Vector of [`ServiceSnapshot`] structures describing all services.
    pub fn snapshots(&self) -> Vec<ServiceSnapshot> {
        self.services
            .iter()
            .map(|s| ServiceSnapshot {
                name: s.name,
                endpoint_id: s.endpoint_id,
                task_id: s.task_id.map(|t| t.0),
                state: s.state,
                restart_count: s.restart_count,
                unanswered_pings: s.unanswered_pings,
            })
            .collect()
    }

    /// Starts a stopped service by name (`service start`).
    ///
    /// # Arguments
    ///
    /// * `name` - Service identifier string.
    ///
    /// # Returns
    ///
    /// The running [`TaskId`].
    ///
    /// # Errors
    ///
    /// Returns static string error if service is unknown or launch fails.
    pub fn start_service(&mut self, name: &str) -> Result<TaskId, &'static str> {
        let idx = self.index(name)?;
        if let Some(id) = self.services[idx].task_id {
            if is_task_alive(id) {
                return Ok(id);
            }
        }
        self.retire(idx);
        self.launch(idx)
    }
}

/// Global supervisor.
pub static SUPERVISOR: Mutex<Supervisor> = Mutex::new(Supervisor::new());

/// Registers the system's services (they start at [`start_all`]).
pub fn supervisor_init() {
    let mut sup = SUPERVISOR.lock();
    if sup.services.is_empty() {
        // The disk first: everything else may need files. An AHCI adapter with a disk
        // takes the disk endpoint; the IDE driver starts only if it did not
        sup.services.push(ServiceDescriptor::new("ahci_driver", ENDPOINT_BLOCK_DEV, AHCI_DRIVER_ELF, ahci_args, ahci_grants));
        sup.services.push(ServiceDescriptor::new("ata_driver", ENDPOINT_BLOCK_DEV, ATA_DRIVER_ELF, ata_args, no_grants));
        // The USB driver before the file server: the pool may be on a USB disk (the
        // driver serves the USB disks next to its input endpoint)
        sup.services.push(ServiceDescriptor::new(
            "usb_driver",
            crate::ipc::protocol::ENDPOINT_INPUT_DEV,
            USB_DRIVER_ELF,
            usb_args,
            usb_grants,
        ));
        // The file server imports the pool through the disk driver
        sup.services.push(ServiceDescriptor::new("zfs_server", ENDPOINT_ZFS_SERVER, ZFS_SERVER_ELF, zfs_args, no_grants));
        service::allow_client(ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER);
        service::allow_client(crate::ipc::protocol::ENDPOINT_USB_DISK, ENDPOINT_ZFS_SERVER);
        sup.services.push(ServiceDescriptor::new("net_driver", ENDPOINT_NET_DEV, E1000_DRIVER_ELF, e1000_args, e1000_grants));
        sup.services.push(ServiceDescriptor::new(
            "sound_driver",
            crate::ipc::protocol::ENDPOINT_SOUND_DEV,
            HDA_DRIVER_ELF,
            hda_args,
            hda_grants,
        ));
    }
}

/// Waits (letting only process `id` run) until it registers as a server of `endpoint` or
/// gives up; for kernel callers that may hold locks.
///
/// # Arguments
///
/// * `endpoint` - IPC endpoint ID to await registration on.
/// * `id` - Expected server [`TaskId`].
///
/// # Returns
///
/// `true` if service registered and is online before deadline, `false` otherwise.
fn await_registration(endpoint: u32, id: TaskId) -> bool {
    // Generous: the file server imports the pool before it registers
    let deadline = crate::arch::pit::ticks() + 6000;
    while !service::is_online(endpoint) && is_task_alive(id) && crate::arch::pit::ticks() < deadline {
        let handed = x86_64::instructions::interrupts::without_interrupts(|| crate::task::SCHEDULER.lock().begin_handoff(id.0, deadline));
        if !handed {
            return false;
        }
        crate::task::yield_now();
    }
    service::is_online(endpoint)
}

/// Starts every service that has a device, after the hardware takeover (system calls and
/// the timer work from then on), waits for each to register, and starts the watchdog.
pub fn start_all() {
    supervisor_init();
    let count = SUPERVISOR.lock().services.len();
    for idx in 0..count {
        let launched = {
            let mut sup = SUPERVISOR.lock();
            let name = sup.services[idx].name;
            let endpoint = sup.services[idx].endpoint_id;
            sup.launch(idx).map(|id| (name, endpoint, id)).map_err(|e| (name, e))
        };
        match launched {
            Ok((name, endpoint, id)) => {
                if await_registration(endpoint, id) {
                    crate::kprintln!("[supervisor] started '{}' (process {}, endpoint {:#x})", name, id.0, endpoint);
                } else if !is_task_alive(id) {
                    // It found no device (a disk adapter without a disk): not restarted,
                    // and another service may take the endpoint
                    let mut sup = SUPERVISOR.lock();
                    sup.retire(idx);
                    sup.services[idx].state = ServiceState::Stopped;
                    crate::kprintln!("[supervisor] '{}' (process {}) exited without registering: no device", name, id.0);
                } else {
                    crate::kprintln!("[supervisor] '{}' (process {}) did not register", name, id.0);
                }
            }
            Err((name, e)) => crate::kprintln!("[supervisor] not starting '{}': {}", name, e),
        }
    }
    crate::arch::usb_input::start();
    crate::compat::linux::snd::start();
    crate::task::spawn("supervisor", watchdog_task, crate::task::TaskPriority::Normal);
}

/// Called by a kernel client whose service has no live server: restarts it and waits for
/// it to register. Returns whether the service is back.
///
/// # Arguments
///
/// * `endpoint` - IPC endpoint identifier of the missing service.
///
/// # Returns
///
/// `true` if service was successfully revived and is online, `false` otherwise.
pub fn revive(endpoint: u32) -> bool {
    // An endpoint served by another service's process (the USB disks): that service
    let endpoint = service::primary_of(endpoint);
    let restarted = {
        let mut sup = match SUPERVISOR.try_lock() {
            Some(s) => s,
            None => return false, // the supervisor itself is restarting it
        };
        // Several services may offer an endpoint (the AHCI and IDE disk drivers): the one
        // that was started
        let Some(idx) = sup.services.iter().position(|s| s.endpoint_id == endpoint && s.state != ServiceState::Stopped) else { return false };
        if sup.services[idx].state == ServiceState::Faulted || sup.services[idx].state == ServiceState::Stopped {
            return false;
        }
        if let Some(id) = sup.services[idx].task_id {
            if is_task_alive(id) && service::server_of(endpoint) == id.0 {
                return true; // alive and registered: nothing to do
            }
        }
        sup.reincarnate(idx).ok()
    };
    restarted.map_or(false, |id| await_registration(endpoint, id))
}

/// Checks every service once: restarts dead ones, pings live ones.
pub fn supervisor_tick() {
    let services: Vec<(usize, u32, Option<TaskId>, ServiceState)> = SUPERVISOR
        .lock()
        .services
        .iter()
        .enumerate()
        .map(|(i, s)| (i, s.endpoint_id, s.task_id, s.state))
        .collect();
    for (idx, endpoint, task, state) in services {
        if state != ServiceState::Running {
            continue;
        }
        let Some(id) = task else { continue };
        if !is_task_alive(id) {
            crate::kprintln!("[supervisor] service on endpoint {:#x} (process {}) died", endpoint, id.0);
            let restarted = SUPERVISOR.lock().reincarnate(idx);
            if let Ok(id) = restarted {
                await_registration(endpoint, id);
            }
            continue;
        }
        if !service::is_online(endpoint) {
            continue; // still starting up
        }
        let seq = crate::arch::pit::ticks();
        // A queued call: the watchdog holds no locks, and a heartbeat waits behind the
        // requests the driver already has (a busy driver is not a hung one)
        let answered = match service::call_once_mode(endpoint, Message::with_args(MSG_SUPERVISOR_PING, [seq, 0, 0, 0]), 100, service::CallMode::Queued) {
            Ok(reply) => reply.label == MSG_SUPERVISOR_PONG && reply.args[0] == seq,
            Err(_) => false,
        };
        let hung = {
            let mut sup = SUPERVISOR.lock();
            let svc = &mut sup.services[idx];
            if answered {
                svc.unanswered_pings = 0;
                svc.last_heartbeat_tick = seq;
                false
            } else {
                svc.unanswered_pings += 1;
                svc.unanswered_pings >= svc.max_unanswered_pings
            }
        };
        if hung {
            crate::kprintln!("[supervisor] service on endpoint {:#x} (process {}) stopped answering", endpoint, id.0);
            let restarted = SUPERVISOR.lock().reincarnate(idx);
            if let Ok(id) = restarted {
                await_registration(endpoint, id);
            }
        }
    }
}

/// The watchdog: one sweep per second.
fn watchdog_task() {
    loop {
        crate::task::sleep_ms(1000);
        // Descriptors of processes that died without a system call to close them (a fault)
        crate::task::close_retired();
        supervisor_tick();
        // DMA the IOMMU blocked since the last look
        crate::arch::iommu::poll_faults();
    }
}

/// Telemetry of all services.
///
/// # Returns
///
/// A vector of [`ServiceSnapshot`] items for all registered services.
pub fn get_service_snapshots() -> Vec<ServiceSnapshot> {
    SUPERVISOR.lock().snapshots()
}

/// Restarts a service by name (`service restart`).
///
/// # Arguments
///
/// * `name` - Service name to restart.
///
/// # Returns
///
/// The new process [`TaskId`].
///
/// # Errors
///
/// Returns static string error if service is unknown or reincarnation fails.
pub fn restart_service_by_name(name: &str) -> Result<TaskId, &'static str> {
    let (idx, endpoint) = {
        let sup = SUPERVISOR.lock();
        let idx = sup.index(name)?;
        (idx, sup.services[idx].endpoint_id)
    };
    let id = {
        let mut sup = SUPERVISOR.lock();
        sup.services[idx].restart_count = 0; // a deliberate restart resets the failure count
        sup.reincarnate(idx)?
    };
    await_registration(endpoint, id);
    Ok(id)
}

/// Kills a service's process by name, as a crash would (`service kill`); the watchdog
/// restarts it.
///
/// # Arguments
///
/// * `name` - Service name to kill.
///
/// # Returns
///
/// The [`TaskId`] of the terminated process.
///
/// # Errors
///
/// Returns static string error if service is unknown or not currently running.
pub fn kill_service_by_name(name: &str) -> Result<TaskId, &'static str> {
    let sup = SUPERVISOR.lock();
    let svc = &sup.services[sup.index(name)?];
    let id = svc.task_id.ok_or("Service is not running")?;
    let _ = kill(id);
    Ok(id)
}
