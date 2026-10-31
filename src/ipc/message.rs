//! # IPC Subsystem: Fast Inline Message Buffers & Delegation
//!
//! Provides the structured [`Message`] payload for microkernel inter-process communication,
//! containing operation codes, inline fast register arguments, and optional capability tokens.
//!
//! ## Architectural Role & Design Rationale
//!
//! To eliminate memory allocation and paging overhead during high-frequency IPC interactions,
//! Hydra OS transmits messages with up to 4 inline 64-bit words (`args: [u64; 4]`).
//! This size matches standard AMD64 ABI register passing and accommodates remote procedure call
//! (RPC) arguments, file offsets, buffer pointers, or status codes directly in cache without heap traffic.
//!
//! ## Key Types & Interfaces
//!
//! - `MAX_INLINE_WORDS`: Maximum number of 64-bit inline arguments per message (4 words / 32 bytes).
//! - [`Message`]: Fixed-size message payload passed between endpoints.

use crate::capability::Capability;

/// Maximum number of inline 64-bit register words stored in a single [`Message`] payload (4 words).
pub const MAX_INLINE_WORDS: usize = 4;

/// Structured message payload passed between threads via IPC endpoints.
#[derive(Debug, Clone, Copy)]
pub struct Message {
    /// Operation code or protocol identifier label (e.g. syscall / RPC function ID).
    pub label: u32,
    /// Fast inline register arguments passed without heap allocation.
    pub args: [u64; MAX_INLINE_WORDS],
    /// Optional capability token delegated or transferred with this message.
    pub capability: Option<Capability>,
}

impl Message {
    /// Constructs a new empty message with the given protocol label and zeroed arguments.
    pub const fn new(label: u32) -> Self {
        Self {
            label,
            args: [0; MAX_INLINE_WORDS],
            capability: None,
        }
    }

    /// Constructs a message with the specified protocol label and inline argument array.
    pub fn with_args(label: u32, args: [u64; MAX_INLINE_WORDS]) -> Self {
        Self {
            label,
            args,
            capability: None,
        }
    }

    /// Attaches an object-capability token to be delegated alongside this message.
    pub fn with_cap(mut self, cap: Capability) -> Self {
        self.capability = Some(cap);
        self
    }
}
