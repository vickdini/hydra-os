//! wave10 GN: which readiness slots a publishing round saw live.
//!
//! [`crate::publish`] runs after every request and every round of the loop. It used to make
//! and clear a 4 KiB array per run to mark the live slots; the marks are now round numbers
//! kept from run to run: a slot is live in this round when its mark is this round's number.

/// Per slot, the last round that marked it (0: never).
pub struct Marks {
    marks: alloc::vec::Vec<u32>,
    round: u32,
}

impl Marks {
    /// Marks for `slots` slots, none marked.
    pub fn new(slots: usize) -> Self {
        Self { marks: alloc::vec![0; slots], round: 0 }
    }

    /// Marks whose round counter stands at `round` (the host tests: wrapping).
    #[cfg(test)]
    pub fn at_round(slots: usize, round: u32) -> Self {
        Self { marks: alloc::vec![0; slots], round }
    }

    /// Starts a round: no slot is marked in it yet. Round numbers skip 0 when they wrap,
    /// and every mark is cleared then (a mark from 2^32 rounds ago must not count).
    pub fn next_round(&mut self) {
        self.round = self.round.wrapping_add(1);
        if self.round == 0 {
            self.marks.iter_mut().for_each(|m| *m = 0);
            self.round = 1;
        }
    }

    /// Marks `slot` live in this round.
    pub fn mark(&mut self, slot: usize) {
        self.marks[slot] = self.round;
    }

    /// Whether `slot` was marked in this round.
    pub fn live(&self, slot: usize) -> bool {
        self.round != 0 && self.marks[slot] == self.round
    }
}

