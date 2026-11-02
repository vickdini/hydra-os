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

use crate::ipc::protocol::{ENDPOINT_BLOCK_DEV, ENDPOINT_DISPLAY_DEV, ENDPOINT_NET_DEV, ENDPOINT_ZFS_SERVER, MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG};
use crate::ipc::service;
use crate::ipc::Message;
use crate::task::{is_task_alive, kill, TaskId};

/// The ATA disk driver program.
static ATA_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/ata-driver"));
/// The ZFS file server program.
static ZFS_SERVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/zfs-server"));
/// The e1000 network driver program.
static E1000_DRIVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/e1000-driver"));
/// The display server program.
static DISPLAY_SERVER_ELF: &[u8] = include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/x86_64-unknown-none/release/display-server"));

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

/// ATA driver: the primary channel's ports and, if the PCI IDE controller can bus-master,
/// its DMA registers (bus mastering is enabled here). It exits if there is no disk.
fn ata_args() -> Option<Vec<String>> {
    let mut args = alloc::vec![String::from("io=0x1f0"), String::from("ctrl=0x3f6")];
    if let Some(dev) = crate::arch::pci::find_class(0x01, 0x01) {
        let prog_if = crate::arch::pci::pci_read_u8(dev.bus, dev.device, dev.function, 0x09);
        let bar4 = crate::arch::pci::pci_read_u32(dev.bus, dev.device, dev.function, 0x20);
        if prog_if & 0x80 != 0 && bar4 & 1 != 0 && bar4 & !3 != 0 {
            crate::arch::pci::enable_bus_mastering(&dev);
            args.push(alloc::format!("bm={:#x}", bar4 & 0xFFFC));
        }
    }
    Some(args)
}

/// e1000 driver: the adapter's register window and interrupt line. Not started without
/// an adapter.
fn e1000_args() -> Option<Vec<String>> {
    let (bar0, irq) = crate::net::e1000::find_adapter()?;
    let mut args = alloc::vec![alloc::format!("bar0={:#x}", bar0)];
    if irq != 0 && irq < 16 && irq != 2 {
        args.push(alloc::format!("irq={}", irq));
    }
    Some(args)
}

/// e1000 driver: its 128 KiB register window.
fn e1000_grants() -> Vec<(u64, u64)> {
    crate::net::e1000::find_adapter().map_or_else(Vec::new, |(bar0, _)| alloc::vec![(bar0, 128 * 1024)])
}

/// ZFS file server: no arguments; it finds the pool through the disk driver.
fn zfs_args() -> Option<Vec<String>> {
    Some(Vec::new())
}

/// No device memory (port I/O and its own DMA buffers only).
fn no_grants() -> Vec<(u64, u64)> {
    Vec::new()
}

/// Display server: the framebuffer, and whether there is a disk (for its widgets).
fn display_args() -> Option<Vec<String>> {
    let info = crate::video::get_video_info()?;
    let disk = if service::is_online(crate::ipc::protocol::ENDPOINT_BLOCK_DEV) { "disk=ata" } else { "disk=none" };
    Some(alloc::vec![
        alloc::format!("fb={:#x}:{}:{}:{}:{}", info.base_ptr as u64, info.width, info.height, info.stride, info.is_bgr as u8),
        String::from(disk),
    ])
}

fn display_grants() -> Vec<(u64, u64)> {
    crate::video::get_video_info().map_or_else(Vec::new, |info| alloc::vec![(info.base_ptr as u64, ((info.size as u64) + 4095) & !4095)])
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

    fn index(&self, name: &str) -> Result<usize, &'static str> {
        self.services.iter().position(|s| s.name == name).ok_or("Service not found")
    }

    /// Starts service `idx`'s program (a previous instance must be gone).
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
        // The disk first: everything else may need files
        sup.services.push(ServiceDescriptor::new("ata_driver", ENDPOINT_BLOCK_DEV, ATA_DRIVER_ELF, ata_args, no_grants));
        // The file server imports the pool through the disk driver
        sup.services.push(ServiceDescriptor::new("zfs_server", ENDPOINT_ZFS_SERVER, ZFS_SERVER_ELF, zfs_args, no_grants));
        service::allow_client(ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER);
        sup.services.push(ServiceDescriptor::new("net_driver", ENDPOINT_NET_DEV, E1000_DRIVER_ELF, e1000_args, e1000_grants));
        sup.services.push(ServiceDescriptor::new("display_server", ENDPOINT_DISPLAY_DEV, DISPLAY_SERVER_ELF, display_args, display_grants));
    }
}

/// Waits (letting only process `id` run) until it registers as a server of `endpoint` or
/// gives up; for kernel callers that may hold locks.
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
                } else {
                    crate::kprintln!("[supervisor] '{}' (process {}) did not register", name, id.0);
                }
            }
            Err((name, e)) => crate::kprintln!("[supervisor] not starting '{}': {}", name, e),
        }
    }
    crate::task::spawn("supervisor", watchdog_task, crate::task::TaskPriority::Normal);
}

/// Called by a kernel client whose service has no live server: restarts it and waits for
/// it to register. Returns whether the service is back.
pub fn revive(endpoint: u32) -> bool {
    let restarted = {
        let mut sup = match SUPERVISOR.try_lock() {
            Some(s) => s,
            None => return false, // the supervisor itself is restarting it
        };
        let Some(idx) = sup.services.iter().position(|s| s.endpoint_id == endpoint) else { return false };
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
        let answered = matches!(
            service::call_once(endpoint, Message::with_args(MSG_SUPERVISOR_PING, [seq, 0, 0, 0]), 100),
            Ok(reply) if reply.label == MSG_SUPERVISOR_PONG && reply.args[0] == seq
        );
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
    }
}

/// Telemetry of all services.
pub fn get_service_snapshots() -> Vec<ServiceSnapshot> {
    SUPERVISOR.lock().snapshots()
}

/// Restarts a service by name (`service restart`).
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
pub fn kill_service_by_name(name: &str) -> Result<TaskId, &'static str> {
    let sup = SUPERVISOR.lock();
    let svc = &sup.services[sup.index(name)?];
    let id = svc.task_id.ok_or("Service is not running")?;
    let _ = kill(id);
    Ok(id)
}
