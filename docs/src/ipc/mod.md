# IPC Subsystem Overview

- **Source File**: [`src/ipc/mod.rs`](file:///d:/os/src/ipc/mod.rs)
- **Subsystem**: Microkernel IPC (Inter-Process Communication)

---

## 1. Role in Hydra OS

The `ipc` module binds together the fundamental primitives for Inter-Process Communication in the Hydra microkernel.

Because Hydra isolates all system services (network stack, file systems, device drivers, cloud node daemons) into separate userland processes, fast and secure message passing is the backbone of the entire operating system.

---

## 2. Module Organization

- [`endpoint.rs`](file:///d:/os/docs/src/ipc/endpoint.md): Provides the [`Endpoint`](file:///d:/os/docs/src/ipc/endpoint.md#endpoint) and [`SharedEndpoint`](file:///d:/os/docs/src/ipc/endpoint.md#sharedendpoint) message queues.
- [`message.rs`](file:///d:/os/docs/src/ipc/message.md): Defines the structure of an IPC [`Message`](file:///d:/os/docs/src/ipc/message.md#the-message-struct), including inline arguments and security capability tokens.
- [`service.rs`](file:///d:/os/docs/src/ipc/service.md): Driver service registry, shared data window IPC (256 KiB zero-copy memory frames), and direct CPU handoffs.
- `protocol.rs`: Well-known microkernel service endpoints (`0x20` ZFS, `0x21` Block Device, `0x22` Network, `0x23` Display, `0x24` Supervisor) and standard operation codes.

---

## 3. Re-exported Types

```rust
pub use endpoint::Endpoint;
pub use message::Message;
pub use service::{call, register, recv, reply, SharedWindow};
```

These re-exports allow any other module in the kernel to conveniently import IPC types directly via `use crate::ipc::{Endpoint, Message};`.
