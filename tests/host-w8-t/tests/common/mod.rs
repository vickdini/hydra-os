//! Fakes for tty-server's `Io` (client memory, answers, signals, readiness, the console)
//! and `ldisc::Mem` (a caller's memory).

#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use hydra_hosttests_w8_t::ldisc::Mem;
use hydra_hosttests_w8_t::ttys::{Io, Iov};

/// A caller's memory: bytes by address (each `put` keeps its bytes at its address).
#[derive(Default)]
pub struct FakeMem {
    pub cells: RefCell<BTreeMap<u64, Vec<u8>>>,
}

impl FakeMem {
    pub fn with(addr: u64, data: &[u8]) -> Self {
        let m = Self::default();
        m.cells.borrow_mut().insert(addr, data.to_vec());
        m
    }
    pub fn put_i32(&self, addr: u64, v: i32) {
        self.cells.borrow_mut().insert(addr, v.to_le_bytes().to_vec());
    }
    pub fn at(&self, addr: u64) -> Vec<u8> {
        self.cells.borrow().get(&addr).cloned().unwrap_or_default()
    }
}

impl Mem for FakeMem {
    fn get(&self, ptr: u64, len: usize) -> Result<Vec<u8>, i64> {
        if ptr == 0 {
            return Err(-14);
        }
        let c = self.cells.borrow();
        let v = c.get(&ptr).ok_or(-14)?;
        if v.len() < len {
            return Err(-14);
        }
        Ok(v[..len].to_vec())
    }
    fn put(&self, ptr: u64, data: &[u8]) -> Result<(), i64> {
        if ptr == 0 {
            return Err(-14);
        }
        self.cells.borrow_mut().insert(ptr, data.to_vec());
        Ok(())
    }
}

/// Everything the state asked for, in order.
#[derive(Default)]
pub struct FakeIo {
    /// (request, bytes written into its buffers)
    pub puts: Vec<(u64, Vec<u8>)>,
    pub completes: Vec<(u64, i64)>,
    /// (group?, who, signal)
    pub signals: Vec<(bool, u64, u32)>,
    /// The session named with each group signal.
    pub group_sids: Vec<u64>,
    pub ready: BTreeMap<u32, u32>,
    /// (slot, bits, arrived) in order
    pub ready_log: Vec<(u32, u32, bool)>,
    pub cons: Vec<u8>,
    pub cons_ready: Vec<(u64, bool)>,
    /// Requests whose memory is gone (their `put` fails).
    pub dead: Vec<u64>,
    /// `pgrp_in` answers by (pgid, sid); default 0 (in the session).
    pub pgrps: BTreeMap<(u64, u64), i64>,
}

impl Io for FakeIo {
    fn put(&mut self, id: u64, _iov: &Iov, data: &[u8]) -> Result<(), i64> {
        if self.dead.contains(&id) {
            return Err(-14);
        }
        self.puts.push((id, data.to_vec()));
        Ok(())
    }
    fn complete(&mut self, id: u64, result: i64) {
        self.completes.push((id, result));
    }
    fn signal_group(&mut self, pgid: u64, sid: u64, sig: u32) {
        self.signals.push((true, pgid, sig));
        self.group_sids.push(sid);
    }
    fn signal_proc(&mut self, pid: u64, sig: u32) {
        self.signals.push((false, pid, sig));
    }
    fn ready(&mut self, slot: u32, bits: u32, arrived: bool) {
        self.ready.insert(slot, bits);
        self.ready_log.push((slot, bits, arrived));
    }
    fn cons_out(&mut self, data: &[u8]) {
        self.cons.extend_from_slice(data);
    }
    fn cons_ready(&mut self, gen: u64, readable: bool) {
        self.cons_ready.push((gen, readable));
    }
    fn pgrp_in(&mut self, pgid: u64, sid: u64) -> i64 {
        *self.pgrps.get(&(pgid, sid)).unwrap_or(&0)
    }
}

impl FakeIo {
    /// The bytes last written for request `id`.
    pub fn got(&self, id: u64) -> Option<Vec<u8>> {
        self.puts.iter().rev().find(|(i, _)| *i == id).map(|(_, d)| d.clone())
    }
    /// The answer given to pending request `id`.
    pub fn answer(&self, id: u64) -> Option<i64> {
        self.completes.iter().rev().find(|(i, _)| *i == id).map(|(_, r)| *r)
    }
}
