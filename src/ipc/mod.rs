//! # Inter-Process Communication (IPC) Subsystem
//!
//! Provides microkernel message passing primitives, fixed-size inline message buffers,
//! capability delegation, and wait-queue backed rendezvous communication endpoints.
//!
//! ## Architectural Role & Design Rationale
//!
//! In a microkernel architecture, services (such as filesystems, device drivers, and display servers)
//! reside in isolated protection domains. The IPC subsystem enables these decoupled tasks to communicate
//! via structured message passing. Hydra OS provides both synchronous blocking and non-blocking
//! message passing through `SharedEndpoint` queues, transmitting compact 4-word inline register
//! arguments and delegating object-capability tokens ([`crate::capability::Capability`]).
//!
//! ## Key Types & Interfaces
//!
//! - [`Message`]: 32-byte structured message payload with 4 inline arguments and optional capability.
//! - [`Endpoint`]: Single-threaded bounded circular FIFO ring-buffer communication port.
//! - `SharedEndpoint`: Thread-safe wrapper around [`Endpoint`] protected by a spinlock.
//! - `endpoint::SYSTEM_ENDPOINTS`: Global pool of system-wide shared rendezvous endpoints (0..15).
//!
//! ## Hardware & Dependency Context
//!
//! - Concurrency: Thread-safe via [`spin::Mutex`] and scheduler wait queues ([`crate::sync::WaitQueue`]).
//! - Performance: Zero-allocation message passing with register-sized arrays.

/// Endpoint ring-buffer queues and thread-safe shared endpoints.
pub mod endpoint;
/// Inline register message definitions and capability delegation containers.
pub mod message;

pub use endpoint::{Endpoint, SharedEndpoint};
pub use message::Message;
