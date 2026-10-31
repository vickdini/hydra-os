//! # Shell Subsystem: Fixed-Capacity Session Command History
//!
//! Implements a stack-allocated circular ring buffer (`History`) that records interactive
//! shell commands for recall via arrow-key navigation, `history` inspection, and `!!` expansion.
//!
//! ## Architectural Role & Design Rationale
//! Interactive shells must retain command history even before heap allocators or persistent
//! filesystems are mounted. By storing up to `MAX_HISTORY` entries of `MAX_CMD_LEN` bytes
//! in a fixed-size ring buffer inside [`crate::shell::state::ShellState`], history tracking
//! requires zero dynamic memory allocation and cannot fragment the kernel heap.
//!
//! ## Key Types & Interfaces
//! - `History`: Circular buffer storing recent command strings and total session command count.
//! - `MAX_HISTORY`: Maximum number of historical commands retained simultaneously (32).
//! - `MAX_CMD_LEN`: Maximum byte length of a single stored command line (1024).
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: None (pure in-memory ring buffer)
//! - Concurrency: Owned exclusively by the active [`crate::shell::state::ShellState`] instance

/// Maximum number of recent commands retained in the `History` ring buffer.
pub const MAX_HISTORY: usize = 32;
/// Maximum byte length of a single command stored in `History`.
pub const MAX_CMD_LEN: usize = 1024;

/// Fixed-size command history ring buffer for the Hydra interactive shell.
///
/// # Concurrency & Thread Safety
/// Embedded directly within [`crate::shell::state::ShellState`] and accessed exclusively by
/// the interactive shell REPL thread without locking overhead.
///
/// # Lifetime & Cleanup
/// Statically sized on the stack/struct; oldest entries are overwritten modulo `MAX_HISTORY`
/// once more than `MAX_HISTORY` commands have been recorded.
pub struct History {
    /// Fixed-size byte arrays storing the UTF-8 payload of each historical command.
    entries: [[u8; MAX_CMD_LEN]; MAX_HISTORY],
    /// Valid UTF-8 byte length of each corresponding slot in `entries`.
    lengths: [usize; MAX_HISTORY],
    /// Monotonically increasing count of total non-empty, non-duplicate commands added in this session.
    count: usize,
}

impl History {
    /// Constructs a new empty `History` ring buffer at compile time or runtime.
    ///
    /// # Returns
    ///
    /// A zero-initialized `History` instance with `count == 0`.
    pub const fn new() -> Self {
        Self {
            entries: [[0u8; MAX_CMD_LEN]; MAX_HISTORY],
            lengths: [0usize; MAX_HISTORY],
            count: 0,
        }
    }

    /// Appends a command string to the history ring buffer.
    ///
    /// Automatically ignores empty lines, the `!!` repeat shortcut, and commands that are
    /// identical to the most recently recorded entry.
    ///
    /// # Arguments
    ///
    /// * `cmd` - Raw UTF-8 command string to record.
    pub fn add(&mut self, cmd: &str) {
        let trimmed = cmd.trim();
        if trimmed.is_empty() || trimmed == "!!" {
            return;
        }

        // Avoid adding duplicate of the most recent command
        if let Some(last) = self.get_from_latest(0) {
            if last == trimmed {
                return;
            }
        }

        let idx = self.count % MAX_HISTORY;
        let bytes = trimmed.as_bytes();
        let len = bytes.len().min(MAX_CMD_LEN);

        self.entries[idx][..len].copy_from_slice(&bytes[..len]);
        self.lengths[idx] = len;
        self.count += 1;
    }

    /// Returns the number of commands currently stored in the ring buffer (capped at `MAX_HISTORY`).
    pub fn len(&self) -> usize {
        self.count.min(MAX_HISTORY)
    }

    /// Returns `true` if no commands have been recorded in the history buffer.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns the total number of commands entered during the entire shell session.
    pub fn total_count(&self) -> usize {
        self.count
    }

    /// Retrieves a historical command indexed backward from the most recent entry.
    ///
    /// # Arguments
    ///
    /// * `offset` - Reverse offset where `0` is the latest command, `1` is the previous command, etc.
    ///
    /// # Returns
    ///
    /// * `Some(&str)` - The stored command slice if `offset < self.len()`.
    /// * `None` - If `offset` is out of bounds.
    pub fn get_from_latest(&self, offset: usize) -> Option<&str> {
        let len = self.len();
        if offset >= len {
            return None;
        }

        let idx = (self.count - 1 - offset) % MAX_HISTORY;
        let entry_len = self.lengths[idx];
        core::str::from_utf8(&self.entries[idx][..entry_len]).ok()
    }

    /// Retrieves a historical command by its 1-based chronological session index.
    ///
    /// # Arguments
    ///
    /// * `session_idx` - 1-based chronological command number (`1..=self.total_count()`).
    ///
    /// # Returns
    ///
    /// * `Some(&str)` - The command string if it is still resident in the ring buffer.
    /// * `None` - If `session_idx` is `0`, exceeds `total_count()`, or has been evicted.
    pub fn get_by_index(&self, session_idx: usize) -> Option<&str> {
        if session_idx == 0 || session_idx > self.count {
            return None;
        }

        let start_idx = if self.count > MAX_HISTORY {
            self.count - MAX_HISTORY + 1
        } else {
            1
        };

        if session_idx < start_idx {
            return None; // Evicted
        }

        let ring_idx = (session_idx - 1) % MAX_HISTORY;
        let entry_len = self.lengths[ring_idx];
        core::str::from_utf8(&self.entries[ring_idx][..entry_len]).ok()
    }

    /// Returns the lowest 1-based chronological session index currently resident in the buffer.
    ///
    /// Returns `0` if the history buffer is empty.
    pub fn start_session_index(&self) -> usize {
        if self.count > MAX_HISTORY {
            self.count - MAX_HISTORY + 1
        } else if self.count > 0 {
            1
        } else {
            0
        }
    }
}
