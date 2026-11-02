# Task Subsystem: Driver Supervisor (MINIX 3-Style Reincarnation Server)

- **Source File**: [`src/task/supervisor.rs`](file:///d:/os/src/task/supervisor.rs)
- **Subsystem**: Microkernel Fault Tolerance & Service Lifecycle
- **Endpoint**: `0x24` (`ENDPOINT_SUPERVISOR`)

---

## 1. Architectural Role & Design Rationale

In monolithic operating systems (such as Linux), device drivers and filesystems execute directly in Ring 0. A single null-pointer dereference, kernel panics, or memory corruption in any third-party driver instantly crashes the entire operating system (kernel panic / Blue Screen of Death).

Hydra eliminates this failure mode by adhering strictly to a **MINIX 3-style Reincarnation Architecture**:
1. **Ring 3 Isolation**: Device drivers (`ata-driver`, `e1000-driver`, `display-server`) and storage servers (`zfs-server`) are decoupled from Ring 0 and compiled as static, standalone ELF64 userland daemons. Each runs in an isolated address space with separate page tables (PML4) and capability spaces.
2. **On-the-Spot Revival**: When a driver process terminates unexpectedly, faults, or misses its deadline, the calling kernel thread revives the server *on the spot* using cached service parameters and capability grants. The subsystem does not dead-lock waiting for an asynchronous supervisor thread.
3. **Transparent State Handoff**: Each service maintains a shared data window (`SharedWindow`) and state snapshot. Upon revival, the newly spawned daemon re-attaches to the existing physical memory window, restoring communication without client-side data loss.
4. **Heartbeat Health Monitoring**: A background supervisor thread periodically sends ping probes (`MSG_SUPERVISOR_PING`) every second to ensure non-blocking liveness.

```text
+--------------------------------------------------------------------------+
|                            RING 0 MICROKERNEL                            |
|                                                                          |
|   +---------------------+        Revives        +--------------------+   |
|   |  Subsystem Caller   | --------------------> | Process Supervisor |   |
|   | (ZFS client / VFS)  | <-------------------- |  (Reincarnation)   |   |
|   +---------------------+     Snapshot Handoff  +--------------------+   |
|              |                                             |             |
+--------------|---------------------------------------------|-------------+
               | Shared Data Window (256 KiB)                | Spawns &
               | Direct CPU Handoff IPC                      | Monitors
               v                                             v
+--------------------------------------------------------------------------+
|                            RING 3 USERLAND                               |
|                                                                          |
|   +--------------------+  Crash Detected  +--------------------------+   |
|   | ATA / Disk Driver  | ---------------> | Dead Process Terminated  |   |
|   +--------------------+                  +--------------------------+   |
|                                                        |                 |
|                                            Replaced by Fresh Daemon      |
|                                                        v                 |
|                                           +--------------------------+   |
|                                           | Reincarnated ATA Driver  |   |
|                                           +--------------------------+   |
+--------------------------------------------------------------------------+
```

---

## 2. Key Types & Interfaces

### 1. `Supervisor`
The central registry tracking all supervised services, their target ELF binaries, device grants, process identifiers, and restart history.

- `start_all()`: Invoked during hardware takeover (`ExitBootServices`) to launch userland drivers (`ata-driver`, `e1000-driver`, `zfs-server`, `display-server`) in their respective address spaces.
- `revive(endpoint)`: Synchronously restarts a failed service upon demand from an active kernel caller.
- `tick()`: Periodic heartbeat check verifying that running services are alive and responsive to ping requests.

### 2. `ServiceState`
Tracks the lifecycle status of each driver:
- `Running`: The driver process is active, registered, and accepting IPC requests.
- `Restarting`: The driver encountered a failure and is currently being respawned.
- `Faulted`: The driver exceeded maximum restart limits (`MAX_RESTARTS = 5`) within the cooldown window, preventing restart loops.
- `Stopped`: Service is intentionally disabled or absent due to missing physical hardware.

### 3. `ServiceSnapshot`
Stores the configuration required to cleanly resurrect a dead driver:
- Target endpoint identifier (`ENDPOINT_BLOCK_DEV`, `ENDPOINT_NET_DEV`, etc.).
- Embedded ELF binary slice.
- Device grants (I/O port ranges, MMIO memory mappings, DMA allowances).
- Command-line arguments passed to the driver's `main()`.

---

## 3. Hardware & Concurrency Context

- **Privilege Level**: Supervisor coordination logic resides in Ring 0; driver targets execute exclusively in Ring 3.
- **Concurrency**: The global supervisor state is protected by a `spin::Mutex`. To prevent inversion deadlocks, the lock is held strictly for table inspection and task spawning, never held across IPC transmissions or wait loops.
- **Failure Boundaries**: Hardware exceptions (`#PF`, `#GP`, `#UD`) occurring inside a driver daemon are trapped by the kernel IDT and converted into a graceful process termination, triggering the revival mechanism.

