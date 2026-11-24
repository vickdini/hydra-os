//! Group 8-1's host build (wave 10): the ptrace access rule and the decisions of the
//! tracing calls (`src/lx/ptrace_rules.rs`, built into lx-proc's `trace.rs` with `#[path]`,
//! exactly as in the service) and lx-proc's half of each decision
//! (`userland/drivers/lx-proc/src/trace.rs`) against [`K`], a model of the kernel's op-75
//! sub-ops `LXP_TRACE_FACTS` and `LXP_APPROVE`, and [`M`], a model of the caller's memory.
//! The tests are in `tests.rs`.

#![allow(dead_code)]

extern crate alloc;

/// The kernel's protocol (`LxProcIo`, the `LXP_*` sub-ops), as lx-proc sees it.
#[path = "../../../src/ipc/protocol.rs"]
#[allow(unused)]
pub mod protocol;

/// lx-proc's `proto` (in the service: `hydra_rt::protocol`).
pub mod proto {
    pub use crate::protocol::*;
}

/// lx-proc's policy (for its `Call`, `Kernel`, `Mem`, `Out`).
#[path = "../../../userland/drivers/lx-proc/src/policy.rs"]
pub mod policy;

/// The code under test (with the rule inside it: `trace::rules`).
#[path = "../../../userland/drivers/lx-proc/src/trace.rs"]
pub mod trace;

pub use trace::rules;

use std::cell::RefCell;

use proto::*;

/// The kernel model: what `LXP_TRACE_FACTS` answers, what `LXP_APPROVE` answers, and the
/// sub-ops seen.
pub struct K {
    pub facts: Result<[u64; 16], i64>,
    pub approve: i64,
    pub calls: RefCell<Vec<(u64, [u64; 16])>>,
}

impl K {
    pub fn with(facts: Result<rules::Facts, i64>) -> K {
        K { facts: facts.map(|f| f.encode()), approve: 0, calls: RefCell::new(Vec::new()) }
    }
}

impl policy::Kernel for K {
    fn op(&self, sub: u64, io: &mut LxProcIo) -> i64 {
        self.calls.borrow_mut().push((sub, io.a));
        match sub {
            LXP_TRACE_FACTS => match self.facts {
                Ok(w) => {
                    io.a = w;
                    0
                }
                Err(e) => e,
            },
            LXP_APPROVE => self.approve,
            _ => -22,
        }
    }
}

/// The caller's memory: one block at `addr`, or nothing.
pub struct M {
    pub addr: u64,
    pub data: Vec<u8>,
}

impl policy::Mem for M {
    fn copy_in(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if ptr == self.addr && len <= self.data.len() {
            Ok(self.data[..len].to_vec())
        } else {
            Err(-14)
        }
    }
    fn copy_out(&self, _ptr: u64, _data: &[u8]) -> Result<(), i64> {
        Err(-14)
    }
    fn cstr(&self, _ptr: u64) -> Result<Vec<u8>, i64> {
        Err(-14)
    }
}

#[cfg(test)]
mod tests;
