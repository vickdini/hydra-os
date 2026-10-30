pub const MAX_HISTORY: usize = 32;
pub const MAX_CMD_LEN: usize = 1024;

/// Fixed-size command history ring buffer for Hydra shell.
pub struct History {
    entries: [[u8; MAX_CMD_LEN]; MAX_HISTORY],
    lengths: [usize; MAX_HISTORY],
    count: usize,
}

impl History {
    pub const fn new() -> Self {
        Self {
            entries: [[0u8; MAX_CMD_LEN]; MAX_HISTORY],
            lengths: [0usize; MAX_HISTORY],
            count: 0,
        }
    }

    /// Adds a command to history. Skips empty lines and duplicate consecutive commands.
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

    /// Number of items stored in history (capped at MAX_HISTORY).
    pub fn len(&self) -> usize {
        self.count.min(MAX_HISTORY)
    }

    /// Total number of commands entered during the session.
    pub fn total_count(&self) -> usize {
        self.count
    }

    /// Retrieves an entry indexed backwards from the most recent (0 = latest, 1 = previous, etc.).
    pub fn get_from_latest(&self, offset: usize) -> Option<&str> {
        let len = self.len();
        if offset >= len {
            return None;
        }

        let idx = (self.count - 1 - offset) % MAX_HISTORY;
        let entry_len = self.lengths[idx];
        core::str::from_utf8(&self.entries[idx][..entry_len]).ok()
    }

    /// Retrieves an entry by 1-based chronological session number.
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

    /// Returns the starting 1-based session index currently in the buffer.
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
