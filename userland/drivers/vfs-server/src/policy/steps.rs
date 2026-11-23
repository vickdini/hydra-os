//! The last step of each call's walk (wave 9, Group 6b-3 review): a file's parent for
//! Landlock comes from the call's own walk, never from another call's (with hard links in an
//! allowed and a denied folder, a shared hint could lend a denied path the allowed chain).
//! Pure: unit-tested on the host (`tests/host-w9-6b3`).

use alloc::collections::BTreeMap;

/// Per call (request id): the last object its walk found and the directory it was in.
#[derive(Default)]
pub struct LastSteps {
    m: BTreeMap<u64, (u64, u64)>,
    cap: usize,
}

impl LastSteps {
    /// An empty table holding at most `cap` calls (all go when full).
    pub const fn new(cap: usize) -> Self {
        Self { m: BTreeMap::new(), cap }
    }

    /// Call `req`'s walk found `child` in `dir`.
    pub fn record(&mut self, req: u64, child: u64, dir: u64) {
        if self.m.len() >= self.cap && !self.m.contains_key(&req) {
            self.m.clear();
        }
        self.m.insert(req, (child, dir));
    }

    /// The directory call `req`'s walk found `ino` in, if `ino` is what it found last (the
    /// entry goes either way).
    pub fn take(&mut self, req: u64, ino: u64) -> Option<u64> {
        match self.m.remove(&req) {
            Some((child, dir)) if child == ino => Some(dir),
            _ => None,
        }
    }

    /// Forgets call `req`'s entry.
    pub fn forget(&mut self, req: u64) {
        self.m.remove(&req);
    }

    /// Forgets everything.
    pub fn clear(&mut self) {
        self.m.clear();
    }

    /// Calls remembered.
    pub fn len(&self) -> usize {
        self.m.len()
    }
}
