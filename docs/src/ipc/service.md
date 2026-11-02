# IPC Subsystem: Driver Services & Shared Windows

- **Source File**: [`src/ipc/service.rs`](file:///d:/os/src/ipc/service.rs)
- **Subsystem**: Microkernel IPC Service Infrastructure
- **Core Interfaces**: `call()`, `register()`, `recv()`, `reply()`, `attach()`

---

## 1. Architectural Role & Design Rationale

Hydra's microkernel design requires that client subsystems (such as the VFS or file server) communicate frequently with Ring 3 device drivers without incurring the performance penalty of traditional context switching or multi-copy socket buffers.

The `service` module solves this through three primary innovations:
1. **Shared Data Windows (`SharedWindow`)**: Each registered service is allocated a physically contiguous, 256 KiB (64 pages) memory window. The window is identity-mapped in Ring 0 and mapped into the driver's Ring 3 address space. Large payloads (such as disk sectors or network frames) are written directly into this buffer, eliminating intermediate copies.
2. **Direct CPU Handoff**: When a client issues a synchronous `call()` to a driver, the kernel scheduler performs a direct CPU handoff (`Scheduler::begin_handoff`). The target driver process is scheduled immediately to consume the request, and no other unprivileged tasks can interleave or contend for subsystem locks.
3. **Hardware Isolation via Least Privilege Grants**: Drivers cannot arbitrarily touch system memory. Instead, the supervisor provisions explicit grants:
   - **MMIO Grants**: Specific physical address ranges the driver is permitted to map (e.g., GOP video framebuffer, NIC registers).
   - **DMA Buffers**: Contiguous physical frames allocated via `dma_alloc` for hardware bus-mastering.
   - **IRQ Notification**: Hardware interrupts are acknowledged and masked in the kernel ISR; the driver is woken asynchronously via wait queues without executing untrusted code in interrupt context.

```text
+-------------------+                           +--------------------+
|   Kernel Caller   |                           |    Ring 3 Driver   |
| (e.g. ZFS Client) |                           |  (e.g. ATA Server) |
+-------------------+                           +--------------------+
          |                                               |
          | 1. Write payload into Shared Window (256 KiB) |
          |---------------------------------------------->|
          |                                               |
          | 2. svc_call(ENDPOINT, label, args)            |
          |---------------------------------------------->|
          |    (Direct CPU Handoff: driver runs now)      |
          |                                               |
          |                                               | 3. Process I/O
          |                                               |    (Ports / DMA)
          |                                               |
          | 4. svc_reply(status, args)                    |
          |<----------------------------------------------|
          |                                               |
          | 5. Read results from Shared Window            |
          v                                               v
```

---

## 2. Key Types & Interfaces

### 1. `SharedWindow`
Manages the life cycle of the contiguous 256 KiB physical memory buffer backing bulk IPC:
- `WINDOW_PAGES`: 64 frames (262,144 bytes).
- `attach()`: Maps the window into the client or server's page tables.
- `as_slice_mut()`: Provides safe typed mutable access to the underlying bytes.

### 2. Service Protocol Call Envelopes
- `call(endpoint, request, timeout_ticks)`: Issues a request, performs CPU handoff, and blocks the calling thread until a reply arrives or the timeout expires.
- `register(endpoint)`: Enrolls the calling Ring 3 process as the authoritative daemon for a designated service endpoint.
- `recv(endpoint)`: Called by the server daemon to wait for incoming client requests.
- `reply(endpoint, response)`: Delivers the result back to the waiting client and unblocks it.

### 3. Driver Capability Grants
- `set_grants(endpoint, mmio_ranges, port_ranges)`: Restricts which physical memory pages and hardware I/O ports the driver is permitted to access.
- `irq_register(irq_num)`: Associates an interrupt vector with the service.
- `irq_wait(irq_num)`: Puts the driver thread to sleep until the hardware line triggers.

---

## 3. Hardware & Concurrency Context

- **Privilege Boundary**: Clients may reside in Ring 0 or Ring 3; services reside in Ring 3.
- **Deadlock Avoidance**: Service locks are never held across blocking rendezvous points. Dead drivers are detected via call timeouts (`CALL_TIMEOUT_TICKS = 500` / 5 seconds) and trigger automatic resuscitation via the process supervisor.

