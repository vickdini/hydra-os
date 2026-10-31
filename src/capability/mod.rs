//! # Security Subsystem: Object-Capability Security Model
//!
//! Provides the core object-capability security primitives, resource tokens, and access rights
//! bitmasks for Hydra Microkernel.
//!
//! ## Architectural Role & Design Rationale
//!
//! Rather than relying on ambient authority or coarse-grained discretionary access controls (DAC),
//! Hydra OS enforces a fine-grained object-capability model inspired by seL4 and KeyKOS.
//! A [`Capability`] pairs an unforgeable typed kernel resource reference ([`CapType`]) with a
//! set of permitted operations ([`Rights`]). A task can only access hardware or kernel resources
//! (such as endpoints, page tables, or physical memory) if it holds a valid capability token
//! in its capability space (`table::CapabilityTable`).
//!
//! ## Key Types & Interfaces
//!
//! - [`Rights`]: Bitflags representing permitted actions (`READ`, `WRITE`, `EXECUTE`, `GRANT`, `CALL`).
//! - [`CapType`]: Enumeration of protected kernel object references.
//! - [`Capability`]: Discrete capability token held in a task's CSpace table.
//! - `table`: Per-task capability table storage and rights verification.
//!
//! ## Hardware & Dependency Context
//!
//! - Privilege Level: Evaluated exclusively in Ring 0 during system call and IPC dispatch.
//! - Security Model: Principle of Least Privilege (PoLP); authority is explicitly delegated via IPC.

/// Capability space table implementation and slot management.
pub mod table;

/// Access rights bitmask governing permitted operations on a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rights(pub u32);

impl Rights {
    /// Permission to read or inspect the referenced kernel resource.
    pub const READ: Rights = Rights(1 << 0);
    /// Permission to modify or write to the referenced kernel resource.
    pub const WRITE: Rights = Rights(1 << 1);
    /// Permission to execute instructions from the referenced memory region.
    pub const EXECUTE: Rights = Rights(1 << 2);
    /// Permission to delegate or transfer this capability token to another task via IPC.
    pub const GRANT: Rights = Rights(1 << 3);
    /// Permission to invoke or call an IPC endpoint or system gate.
    pub const CALL: Rights = Rights(1 << 4);
    /// Composite mask granting all standard access permissions.
    pub const ALL: Rights = Rights(0x1F);

    /// Checks if this rights set includes all permissions specified in `other`.
    pub fn contains(&self, other: Rights) -> bool {
        (self.0 & other.0) == other.0
    }
}

/// Identifies the underlying kernel object or hardware resource referenced by a capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapType {
    /// Raw unallocated physical memory region that can be retyped.
    UntypedMemory {
        /// Size of the unallocated physical chunk in bytes.
        size_bytes: usize,
    },
    /// A single 4 KiB physical memory frame.
    MemoryFrame {
        /// Physical base address of the frame.
        physical_addr: u64,
    },
    /// A 4-level x86_64 virtual address space represented by its root PML4 page table.
    AddressSpace {
        /// Physical address of the root PML4 table (loaded into CR3).
        root_cr3: u64,
    },
    /// A synchronous or asynchronous microkernel IPC message-passing endpoint.
    Endpoint {
        /// Identifier of the communication endpoint.
        endpoint_id: u32,
    },
    /// An execution thread / task control block.
    Thread {
        /// Identifier of the thread.
        thread_id: u32,
    },
    /// Direct memory-mapped or I/O port hardware peripheral device.
    HardwareDevice {
        /// Device identifier or PCI bus address.
        device_id: u32,
    },
}

/// An unforgeable security token representing authority to perform operations on a kernel resource.
#[derive(Debug, Clone, Copy)]
pub struct Capability {
    /// The specific kernel resource referenced by this token.
    pub cap_type: CapType,
    /// The bitmask of permitted access rights.
    pub rights: Rights,
}

impl Capability {
    /// Constructs a new capability token with the specified resource type and rights.
    pub fn new(cap_type: CapType, rights: Rights) -> Self {
        Self { cap_type, rights }
    }
}
