//! # Synchronization Subsystem: Blocking Concurrency Primitives
//!
//! Provides scheduler-integrated synchronization primitives (`Mutex`, `CondVar`, `Semaphore`,
//! `Channel`, and `WaitQueue`) that suspend contended tasks into `TaskState::Blocked` instead
//! of burning CPU cycles spinning.
//!
//! ## Architectural Role & Design Rationale
//!
//! While short critical sections inside interrupt handlers and core kernel structures use
//! `spin::Mutex`, longer-held locks or inter-task communication benefit from cooperative
//! blocking so the CPU can execute other ready tasks. Each primitive in this module pairs
//! atomic fast-path state with an internal spinlock-protected `WaitQueue` that integrates
//! with [`crate::task::block_current`] and [`crate::task::unblock_task`].
//!
//! ## Key Types & Interfaces
//!
//! - `WaitQueue`: FIFO wait-queue tracking blocked [`crate::task::TaskId`]s.
//! - `Mutex` & `MutexGuard`: Sleep-mutex with RAII lock guard and owner PID tracking.
//! - `CondVar`: Condition variable atomically releasing a `MutexGuard` and blocking until notified.
//! - `Semaphore`: Counting semaphore for resource pool throttling and signaling.
//! - `Channel`: Bounded, synchronized MPMC message queue with blocking and non-blocking operations.
//!
//! ## Hardware & Dependency Context
//!
//! - **Atomics**: Relies on hardware `LOCK CMPXCHG` / `XADD` (`core::sync::atomic`) for lock-free fast paths.
//! - **Scheduler Integration**: Depends on [`crate::task::SCHEDULER`] to transition tasks between
//!   `Running`, `Blocked`, and `Ready`.

/// Bounded multi-producer, multi-consumer blocking message channel.
pub mod channel;
/// Condition variable for waiting on state changes protected by a `Mutex`.
pub mod condvar;
/// Sleep-based mutual exclusion lock and RAII guard.
pub mod mutex;
/// Counting semaphore with blocking permit acquisition.
pub mod semaphore;
/// FIFO task wait-queue for suspending and waking blocked threads.
pub mod wait_queue;

pub use channel::Channel;
pub use condvar::CondVar;
pub use mutex::{Mutex, MutexGuard};
pub use semaphore::Semaphore;
pub use wait_queue::WaitQueue;
