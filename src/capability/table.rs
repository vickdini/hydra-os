//! # Security Subsystem: Capability Space (CSpace) Table Management
//!
//! Provides the per-task capability table (`CapabilityTable`) storing discrete access tokens,
//! slot allocation, rights verification, and capability revocation.
//!
//! ## Architectural Role & Design Rationale
//!
//! In Hydra OS, each task control block ([`crate::task::Task`]) contains a capability table (its CSpace).
//! When a task attempts to invoke a system resource (such as sending an IPC message or mapping memory),
//! the kernel indexes into the caller's capability table to verify that a capability exists with the
//! required [`Rights`]. This prevents confused deputy attacks and enforces strict compartmentalization.
//!
//! ## Key Types & Interfaces
//!
//! - `MAX_CAPABILITIES`: Maximum capability slots per task (256 slots).
//! - `CapabilityTable`: Fixed-size array of capability slots with linear probing.
//! - `CapabilityTable::insert`: Allocates a slot and inserts a new capability.
//! - `CapabilityTable::revoke`: Removes and invalidates a capability from a slot.
//! - `CapabilityTable::check_rights`: Validates that a slot contains required access rights.
//!
//! ## Concurrency & Thread Safety
//!
//! Capability tables are typically accessed under the task or scheduler lock during system calls.

use super::{Capability, Rights};

/// Maximum number of capability tokens that can be held by a single task's CSpace (256 slots).
pub const MAX_CAPABILITIES: usize = 256;

/// Per-task capability space table storing up to `MAX_CAPABILITIES` access tokens.
pub struct CapabilityTable {
    slots: [Option<Capability>; MAX_CAPABILITIES],
    next_free_slot: usize,
}

impl CapabilityTable {
    /// Constructs a new, empty capability table with all slots initialized to `None`.
    pub const fn new() -> Self {
        Self {
            slots: [None; MAX_CAPABILITIES],
            next_free_slot: 0,
        }
    }

    /// Inserts a new capability token into the first available free slot.
    ///
    /// # Arguments
    ///
    /// * `cap` - The capability token to store.
    ///
    /// # Returns
    ///
    /// * `Ok(slot)` - The assigned slot index (0..`MAX_CAPABILITIES`).
    /// * `Err("Capability table full")` - If all 256 slots are currently occupied.
    pub fn insert(&mut self, cap: Capability) -> Result<usize, &'static str> {
        for idx in 0..MAX_CAPABILITIES {
            let slot = (self.next_free_slot + idx) % MAX_CAPABILITIES;
            if self.slots[slot].is_none() {
                self.slots[slot] = Some(cap);
                self.next_free_slot = (slot + 1) % MAX_CAPABILITIES;
                return Ok(slot);
            }
        }
        Err("Capability table full")
    }

    /// Retrieves an immutable reference to the capability residing at `slot`.
    pub fn get(&self, slot: usize) -> Option<&Capability> {
        if slot < MAX_CAPABILITIES {
            self.slots[slot].as_ref()
        } else {
            None
        }
    }

    /// Revokes and removes the capability at `slot`, returning the removed token if present.
    pub fn revoke(&mut self, slot: usize) -> Option<Capability> {
        if slot < MAX_CAPABILITIES {
            self.slots[slot].take()
        } else {
            None
        }
    }

    /// Verifies whether the capability at `slot` exists and satisfies `required_rights`.
    pub fn check_rights(&self, slot: usize, required_rights: Rights) -> bool {
        if let Some(cap) = self.get(slot) {
            cap.rights.contains(required_rights)
        } else {
            false
        }
    }

    /// Returns the total number of occupied capability slots in this table.
    pub fn len(&self) -> usize {
        let mut count = 0;
        for slot in self.slots.iter() {
            if slot.is_some() {
                count += 1;
            }
        }
        count
    }

    /// Returns true if the capability table contains zero active capabilities.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
