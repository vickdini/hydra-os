//! # Task Subsystem: MINIX 3-Style Process Reincarnation Server
//!
//! Provides automated driver supervision, heartbeat monitoring, fault recovery,
//! and transparent restart of microkernel service daemons.
//!
//! ## Architectural Role & Design Rationale
//!
//! In standard monolithic kernels, a crash or deadlock inside any device driver or storage
//! stack inevitably triggers an unrecoverable kernel panic.
//!
//! Following the principles established by the MINIX 3 Reincarnation Server (RS), Hydra OS
//! isolates device drivers and system servers into unprivileged tasks communicating strictly
//! over IPC endpoints. The [`Supervisor`] acts as an autonomous watchdog that:
//! 1. Periodically sends heartbeat ping requests ([`crate::ipc::protocol::MSG_SUPERVISOR_PING`]) across registered driver endpoints.
//! 2. Checks task vitality via [`crate::task::is_task_alive`].
//! 3. If a driver crashes (due to a `#PF` or `#GP`) or fails to respond to pings within a configurable
//!    threshold, the supervisor terminates the faulted instance, flushes the endpoint channel,
//!    and transparently spawns a replacement instance with identical privileges.
//!
//! ## Key Types & Interfaces
//!
//! - [`ServiceState`]: Operational state (`Running`, `Restarting`, `Faulted`, `Stopped`).
//! - [`ServiceDescriptor`]: Metadata describing a supervised service (name, endpoint, PID, restart policy).
//! - [`ServiceSnapshot`]: Diagnostic telemetry capture for shell and status utilities.
//! - [`Supervisor`]: Central registry maintaining and monitoring all supervised driver tasks.
//! - [`SUPERVISOR`]: Global thread-safe supervisor singleton.
//! - [`supervisor_init`]: Registers and starts default microkernel drivers.
//! - [`supervisor_tick`]: Periodic health check and reincarnation sweep.
//!
//! ## Concurrency & Safety
//!
//! Driver state transitions are protected by a [`spin::Mutex`]. IPC communications rely on
//! bounded queues with automatic recovery to ensure stale messages cannot poison a reincarnated driver.

extern crate alloc;

use alloc::vec::Vec;
use spin::Mutex;

use crate::ipc::endpoint::get_system_endpoint;
use crate::ipc::protocol::{
    MSG_SUPERVISOR_PING, MSG_SUPERVISOR_PONG,
};
use crate::ipc::{
    Message, ENDPOINT_BLOCK_DEV, ENDPOINT_DISPLAY_DEV, ENDPOINT_NET_DEV, ENDPOINT_ZFS_SERVER,
};
use crate::task::{is_task_alive, kill, spawn_user, TaskId, TaskPriority};

/// Operational lifecycle state of a supervised microkernel service daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceState {
    /// Service is actively executing and responding to heartbeats.
    Running,
    /// Service encountered a fault or crash and is being reincarnated.
    Restarting,
    /// Service exceeded its restart limit or encountered an unrecoverable error.
    Faulted,
    /// Service was administratively stopped or disabled.
    Stopped,
}

/// Metadata, configuration, and monitoring telemetry for a supervised microkernel service.
pub struct ServiceDescriptor {
    /// Human-readable service identifier (e.g. `"ata_driver"`).
    pub name: &'static str,
    /// Numeric ID of the rendezvous IPC endpoint bound to this service.
    pub endpoint_id: u32,
    /// Active Task ID assigned by the scheduler, or `None` if stopped.
    pub task_id: Option<TaskId>,
    /// Current operational state of the service.
    pub state: ServiceState,
    /// Entry point function executed when spawning or reincarnating the service.
    pub spawn_fn: fn(),
    /// Scheduler priority assigned to the service task.
    pub priority: TaskPriority,
    /// Cumulative count of reincarnation restarts executed since system boot.
    pub restart_count: u32,
    /// Maximum allowable consecutive restarts before transitioning to [`ServiceState::Faulted`].
    pub max_restarts: u32,
    /// Number of consecutive unacknowledged heartbeat ping requests.
    pub unanswered_pings: u32,
    /// Maximum allowable unanswered pings before the service is declared hung.
    pub max_unanswered_pings: u32,
    /// Sequence number of the most recent heartbeat ping dispatched to this service.
    pub last_ping_seq: u64,
    /// System PIT tick timestamp of the last confirmed heartbeat pong response.
    pub last_heartbeat_tick: u64,
}

impl ServiceDescriptor {
    /// Constructs a new service descriptor with default restart policies.
    ///
    /// # Arguments
    ///
    /// * `name` - Service identifier name.
    /// * `endpoint_id` - IPC endpoint ID bound to the driver.
    /// * `spawn_fn` - Daemon entry point function.
    /// * `priority` - Scheduler priority.
    pub const fn new(
        name: &'static str,
        endpoint_id: u32,
        spawn_fn: fn(),
        priority: TaskPriority,
    ) -> Self {
        Self {
            name,
            endpoint_id,
            task_id: None,
            state: ServiceState::Stopped,
            spawn_fn,
            priority,
            restart_count: 0,
            max_restarts: 10,
            unanswered_pings: 0,
            max_unanswered_pings: 3,
            last_ping_seq: 0,
            last_heartbeat_tick: 0,
        }
    }
}

/// Immutable diagnostic telemetry snapshot of a supervised service.
#[derive(Debug, Clone)]
pub struct ServiceSnapshot {
    /// Human-readable service name.
    pub name: &'static str,
    /// Numeric IPC endpoint ID.
    pub endpoint_id: u32,
    /// Task ID (PID) if currently active.
    pub task_id: Option<u64>,
    /// Current service operational state.
    pub state: ServiceState,
    /// Total lifetime restart count.
    pub restart_count: u32,
    /// Number of consecutive missed heartbeats.
    pub unanswered_pings: u32,
}

/// Central supervisor and reincarnation server managing microkernel service lifecycles.
pub struct Supervisor {
    services: Vec<ServiceDescriptor>,
    next_ping_seq: u64,
}

impl Supervisor {
    /// Creates an empty supervisor registry.
    pub const fn new() -> Self {
        Self {
            services: Vec::new(),
            next_ping_seq: 1,
        }
    }

    /// Registers a new service descriptor in the supervisor table.
    ///
    /// # Arguments
    ///
    /// * `descriptor` - Configured service descriptor to track.
    pub fn register(&mut self, descriptor: ServiceDescriptor) {
        self.services.push(descriptor);
    }

    /// Initializes default Hydra microkernel system drivers and registers them.
    pub fn init_default_services(&mut self) {
        if !self.services.is_empty() {
            return;
        }

        self.register(ServiceDescriptor::new(
            "ata_driver",
            ENDPOINT_BLOCK_DEV,
            ata_driver_entry,
            TaskPriority::High,
        ));

        self.register(ServiceDescriptor::new(
            "net_driver",
            ENDPOINT_NET_DEV,
            net_driver_entry,
            TaskPriority::High,
        ));

        self.register(ServiceDescriptor::new(
            "display_server",
            ENDPOINT_DISPLAY_DEV,
            display_server_entry,
            TaskPriority::High,
        ));

        self.register(ServiceDescriptor::new(
            "zfs_server",
            ENDPOINT_ZFS_SERVER,
            zfs_server_entry,
            TaskPriority::High,
        ));
    }

    /// Starts a registered service by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - Service identifier to activate.
    ///
    /// # Returns
    ///
    /// * `Ok(TaskId)` - The newly spawned task ID.
    /// * `Err(&str)` - If the service is not found or already running.
    pub fn start_service(&mut self, name: &str) -> Result<TaskId, &'static str> {
        let idx = self
            .services
            .iter()
            .position(|s| s.name == name)
            .ok_or("Service not found")?;

        let service = &mut self.services[idx];
        if service.state == ServiceState::Running {
            if let Some(id) = service.task_id {
                if is_task_alive(id) {
                    return Ok(id);
                }
            }
        }

        let new_id = spawn_user(service.name, service.spawn_fn, service.priority);
        service.task_id = Some(new_id);
        service.state = ServiceState::Running;
        service.unanswered_pings = 0;
        service.last_heartbeat_tick = crate::arch::pit::ticks();

        Ok(new_id)
    }

    /// Stops a running service by its name.
    ///
    /// # Arguments
    ///
    /// * `name` - Service identifier to stop.
    ///
    /// # Returns
    ///
    /// * `Ok(())` on successful termination.
    /// * `Err(&str)` if the service is not found.
    pub fn stop_service(&mut self, name: &str) -> Result<(), &'static str> {
        let idx = self
            .services
            .iter()
            .position(|s| s.name == name)
            .ok_or("Service not found")?;

        let service = &mut self.services[idx];
        if let Some(id) = service.task_id.take() {
            let _ = kill(id);
        }
        service.state = ServiceState::Stopped;
        Ok(())
    }

    /// Reincarnates a faulted or hung service by terminating it, purging the IPC endpoint,
    /// and spawning a fresh instance with identical privilege and configuration.
    ///
    /// # Arguments
    ///
    /// * `idx` - Index into the `services` registry.
    ///
    /// # Returns
    ///
    /// * `Ok(TaskId)` - The newly spawned task ID.
    /// * `Err(&str)` - If restart limits are exceeded.
    pub fn reincarnate_service(&mut self, idx: usize) -> Result<TaskId, &'static str> {
        if idx >= self.services.len() {
            return Err("Invalid service index");
        }

        let service = &mut self.services[idx];
        let name = service.name;
        let endpoint_id = service.endpoint_id;

        if service.restart_count >= service.max_restarts {
            service.state = ServiceState::Faulted;
            crate::println!(
                "[!] Supervisor: Service '{}' reached max restarts ({}/{}). Marked FAULTED.",
                name,
                service.restart_count,
                service.max_restarts
            );
            return Err("Maximum restart limit exceeded");
        }

        service.state = ServiceState::Restarting;
        service.restart_count += 1;
        let attempt = service.restart_count;
        let max_attempts = service.max_restarts;

        // 1. Terminate old task if still lingering
        if let Some(old_id) = service.task_id.take() {
            if is_task_alive(old_id) {
                let _ = kill(old_id);
            }
        }

        // 2. Flush and reset the rendezvous endpoint queue to eliminate stale messages
        if let Some(ep) = get_system_endpoint(endpoint_id) {
            ep.reset();
        }

        // 3. Spawn a clean new instance in user space
        let new_id = spawn_user(service.name, service.spawn_fn, service.priority);
        service.task_id = Some(new_id);
        service.state = ServiceState::Running;
        service.unanswered_pings = 0;
        service.last_heartbeat_tick = crate::arch::pit::ticks();

        crate::println!(
            "[+] Supervisor: Reincarnated '{}' as PID {} (restart {}/{}) on endpoint {:#x}.",
            name,
            new_id.0,
            attempt,
            max_attempts,
            endpoint_id
        );

        Ok(new_id)
    }

    /// Performs a periodic health inspection across all registered services.
    ///
    /// Detects crashed tasks, evaluates missed heartbeats, and triggers automated reincarnation.
    pub fn tick(&mut self) {
        let current_tick = crate::arch::pit::ticks();
        let service_count = self.services.len();

        for i in 0..service_count {
            let service = &self.services[i];
            if service.state != ServiceState::Running {
                continue;
            }

            let task_id = match service.task_id {
                Some(id) => id,
                None => continue,
            };

            // 1. Check if the task crashed or was terminated in the scheduler
            if !is_task_alive(task_id) {
                crate::println!(
                    "[!] Supervisor: Detected CRASH in service '{}' (PID {} died). Initiating reincarnation...",
                    service.name,
                    task_id.0
                );
                let _ = self.reincarnate_service(i);
                continue;
            }

            // 2. Inspect endpoint for heartbeat pong replies
            if let Some(ep) = get_system_endpoint(service.endpoint_id) {
                while let Some(msg) = ep.receive() {
                    if msg.label == MSG_SUPERVISOR_PONG {
                        let service_mut = &mut self.services[i];
                        service_mut.unanswered_pings = 0;
                        service_mut.last_heartbeat_tick = current_tick;
                    }
                }
            }

            // 3. Evaluate unacknowledged ping threshold
            let service_mut = &mut self.services[i];
            if service_mut.unanswered_pings >= service_mut.max_unanswered_pings {
                crate::println!(
                    "[!] Supervisor: Service '{}' (PID {}) is UNRESPONSIVE ({} missed heartbeats). Forcing reincarnation...",
                    service_mut.name,
                    task_id.0,
                    service_mut.unanswered_pings
                );
                let _ = self.reincarnate_service(i);
                continue;
            }

            // 4. Dispatch heartbeat ping
            if let Some(ep) = get_system_endpoint(service_mut.endpoint_id) {
                let seq = self.next_ping_seq;
                self.next_ping_seq = self.next_ping_seq.wrapping_add(1);
                service_mut.last_ping_seq = seq;
                service_mut.unanswered_pings += 1;

                let ping_msg = Message::with_args(MSG_SUPERVISOR_PING, [seq, current_tick, 0, 0]);
                let _ = ep.send(ping_msg);
            }
        }
    }

    /// Captures a diagnostic snapshot list of all registered services.
    ///
    /// # Returns
    ///
    /// A [`Vec`] of [`ServiceSnapshot`] structures describing the current service states.
    pub fn snapshots(&self) -> Vec<ServiceSnapshot> {
        self.services
            .iter()
            .map(|s| ServiceSnapshot {
                name: s.name,
                endpoint_id: s.endpoint_id,
                task_id: s.task_id.map(|id| id.0),
                state: s.state,
                restart_count: s.restart_count,
                unanswered_pings: s.unanswered_pings,
            })
            .collect()
    }
}

/// Global thread-safe instance of the Process Reincarnation Supervisor.
pub static SUPERVISOR: Mutex<Supervisor> = Mutex::new(Supervisor::new());

/// Initializes the supervisor and registers standard microkernel driver services.
pub fn supervisor_init() {
    let mut sup = SUPERVISOR.lock();
    sup.init_default_services();
}

/// Performs a periodic health inspection and reincarnation sweep across all microkernel services.
pub fn supervisor_tick() {
    let mut sup = SUPERVISOR.lock();
    sup.tick();
}

/// Returns a telemetry snapshot list of all supervised services.
pub fn get_service_snapshots() -> Vec<ServiceSnapshot> {
    SUPERVISOR.lock().snapshots()
}

/// Reincarnates a specific service by name.
///
/// # Arguments
///
/// * `name` - Service identifier to restart.
///
/// # Returns
///
/// * `Ok(TaskId)` - The newly spawned process ID.
/// * `Err(&str)` - If the service was not found.
pub fn restart_service_by_name(name: &str) -> Result<TaskId, &'static str> {
    let mut sup = SUPERVISOR.lock();
    let idx = sup
        .services
        .iter()
        .position(|s| s.name == name)
        .ok_or("Service not found")?;
    sup.reincarnate_service(idx)
}

/// Kills a service task by name to simulate a driver crash and test self-healing reincarnation.
///
/// # Arguments
///
/// * `name` - Service identifier to terminate.
///
/// # Returns
///
/// * `Ok(TaskId)` - The terminated Task ID.
/// * `Err(&str)` - If the service was not found or has no active task.
pub fn kill_service_by_name(name: &str) -> Result<TaskId, &'static str> {
    let sup = SUPERVISOR.lock();
    let service = sup
        .services
        .iter()
        .find(|s| s.name == name)
        .ok_or("Service not found")?;

    let task_id = service.task_id.ok_or("Service is not running")?;
    let _ = kill(task_id);
    Ok(task_id)
}

// Trampoline entry points for user-space driver daemons

fn ata_driver_entry() {
    crate::arch::ata::run_user_block_daemon(ENDPOINT_BLOCK_DEV);
}

fn net_driver_entry() {
    crate::net::e1000::run_user_e1000_daemon(ENDPOINT_NET_DEV);
}

fn display_server_entry() {
    crate::video::run_user_display_daemon(ENDPOINT_DISPLAY_DEV);
}

fn zfs_server_entry() {
    crate::fs::zfs::server::run_zfs_server_daemon(ENDPOINT_ZFS_SERVER);
}