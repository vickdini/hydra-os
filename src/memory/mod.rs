//! # Memory Subsystem: Physical and Virtual Memory Management
//!
//! Provides physical page frame allocation, dynamic kernel heap management, 4-level x86_64
//! hardware page table manipulation, and per-process copy-on-write virtual address spaces.
//!
//! ## Architectural Role & Design Rationale
//!
//! The memory subsystem forms the foundation of isolation and resource management in Hydra OS.
//! It transitions the system from the UEFI boot environment into an autonomous kernel memory
//! model by reclaiming conventional RAM, establishing a reference-counted physical frame
//! allocator, initializing the global `alloc` heap, and managing both the shared higher-half
//! kernel mappings and isolated user-space virtual memory areas (VMAs).
//!
//! ## Key Types & Interfaces
//!
//! - `frame_allocator::PhysicalMemoryManager`: Reference-counted physical 4 KiB frame allocator.
//! - `heap::HEAP_ALLOCATOR`: Global dynamic kernel heap allocator (`LockedHeap`).
//! - `paging::AddressSpace`: Low-level 4-level x86_64 page table (`PML4`) abstraction.
//! - `vm::Mm`: Per-process virtual memory manager supporting demand paging, `fork`, and `mmap`.
//!
//! ## Hardware & Dependency Context
//!
//! - **Architecture**: x86_64 4-level paging (`PML4` -> `PDPT` -> `PD` -> `PT`) with 4 KiB pages and `NX` protection.
//! - **Firmware**: Consumes the UEFI memory map (`CONVENTIONAL` regions) during early boot.
//! - **Synchronization**: Protected by `spin::Mutex` locks and lock-free atomic pointers (`CURRENT_MM`).

/// Physical 4 KiB page frame allocator and per-frame reference counting.
pub mod frame_allocator;
/// Global dynamic kernel heap allocator (`extern crate alloc`) and diagnostics.
pub mod heap;
/// Low-level x86_64 4-level page table manipulation and address space switching.
pub mod paging;
/// Per-process virtual memory areas (VMAs), demand paging, and copy-on-write management.
pub mod vm;


