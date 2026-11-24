//! bpf: maps, programs, cgroup attachment, links, pinning, and an eBPF interpreter.
//!
//! - **Maps**: hash, array, per-CPU hash and array (one CPU), LRU hash; lookup, update
//!   (`BPF_ANY`/`NOEXIST`/`EXIST`), delete, next key, lookup-and-delete, freeze.
//! - **Programs** (socket filter, cgroup skb/sock/device/sock_addr/sysctl) are checked
//!   structurally at load (known instructions and helpers, registers, jump targets, map
//!   references) and run by an interpreter that checks every memory access against the
//!   context, its stack frames, packet data and map values, and stops after 1M steps; a
//!   program that breaks a rule is stopped and its result taken as "deny".
//! - **Device control** (`BPF_PROG_TYPE_CGROUP_DEVICE`, what systemd's `DeviceAllow=` loads):
//!   programs attached to a process's cgroup or its ancestors decide device opens and
//!   `mknod`s; any one returning 0 refuses (`EPERM`). Other cgroup programs are attached and
//!   listed but not run: Hydra's network stack has no hook for them yet.
//! - `BPF_PROG_TEST_RUN` runs socket filter and cgroup skb programs on a packet.
//! - Links (`BPF_LINK_CREATE`, detached when closed or by `BPF_LINK_DETACH`), pins
//!   (`BPF_OBJ_PIN`/`GET` by path under the bpf file system), IDs and `OBJ_GET_INFO_BY_FD`.
//!   BTF is accepted and kept, not checked.
//! - Root only (`CAP_BPF` or `CAP_SYS_ADMIN`): `unprivileged_bpf_disabled` is 2, as on
//!   Ubuntu.
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use spin::Mutex;


const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const E2BIG: i64 = -7;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;

// Map types
const MAP_ARRAY: u32 = 2;
const MAP_PERCPU_ARRAY: u32 = 6;
const MAP_LRU_HASH: u32 = 9;
const MAP_LRU_PERCPU_HASH: u32 = 10;

// Program types
const PROG_CGROUP_DEVICE: u32 = 15;

// Attach types
const ATTACH_CGROUP_DEVICE: u32 = 6;

const MAX_INSNS: usize = 65536;
const MAX_STEPS: u64 = 1_000_000;
const STACK: usize = 512;

/// The helpers programs may call (by number).
const HELPERS: &[i32] = &[1, 2, 3, 5, 6, 7, 8, 14, 15, 16, 125];

// ----------------------------------------------------------------------
// Objects
// ----------------------------------------------------------------------

/// A map.
#[allow(dead_code)] // (wave10 G10-C: fields the deleted bpf()/ALSA copy read; kept as the records' shape)
pub struct Map {
    id: u32,
    kind: u32,
    key_size: u32,
    value_size: u32,
    max: u32,
    flags: u32,
    name: [u8; 16],
    entries: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    frozen: AtomicBool,
}

impl Map {
    fn is_array(&self) -> bool {
        matches!(self.kind, MAP_ARRAY | MAP_PERCPU_ARRAY)
    }
}

#[derive(Clone, Copy)]
struct Insn {
    code: u8,
    dst: u8,
    src: u8,
    off: i16,
    imm: i32,
}

/// A loaded program.
#[allow(dead_code)] // (wave10 G10-C: fields the deleted bpf()/ALSA copy read; kept as the records' shape)
pub struct Prog {
    id: u32,
    kind: u32,
    insns: Vec<Insn>,
    /// Maps it references (LD_IMM64 map loads index this).
    maps: Vec<Arc<Map>>,
    name: [u8; 16],
    tag: [u8; 8],
}


/// A program attached to a cgroup.
#[allow(dead_code)] // (wave10 G10-C: fields the deleted bpf()/ALSA copy read; kept as the records' shape)
struct Attached {
    cgroup: String,
    attach_type: u32,
    prog: Arc<Prog>,
    /// The link that holds it (0: `BPF_PROG_ATTACH`).
    link: u32,
}

static ATTACHED: Mutex<Vec<Attached>> = Mutex::new(Vec::new());
static ANY_DEVICE: AtomicBool = AtomicBool::new(false);

/// (wave10 G10-C: the kernel holds no bpf maps any more: lx-sec's device programs come
/// without them, so a map reference in a program is refused.)
fn map_of(_fd: u32) -> Result<Arc<Map>, i64> {
    Err(EINVAL)
}

// ----------------------------------------------------------------------
// Maps
// ----------------------------------------------------------------------

impl Map {

    /// Update with `BPF_ANY` (0), `BPF_NOEXIST` (1) or `BPF_EXIST` (2).
    fn update(&self, key: &[u8], value: &[u8], flags: u64) -> i64 {
        if flags > 2 {
            return EINVAL;
        }
        let mut e = self.entries.lock();
        if self.is_array() {
            if !e.contains_key(key) {
                return E2BIG;
            }
            if flags == 1 {
                return EEXIST;
            }
        } else {
            let present = e.contains_key(key);
            if flags == 1 && present {
                return EEXIST;
            }
            if flags == 2 && !present {
                return ENOENT;
            }
            if !present && e.len() >= self.max as usize {
                if matches!(self.kind, MAP_LRU_HASH | MAP_LRU_PERCPU_HASH) {
                    let first = e.keys().next().cloned();
                    if let Some(k) = first {
                        e.remove(&k);
                    }
                } else {
                    return E2BIG;
                }
            }
        }
        e.insert(key.to_vec(), value[..self.value_size as usize].to_vec());
        0
    }

    fn delete(&self, key: &[u8]) -> i64 {
        if self.is_array() {
            return EINVAL;
        }
        if self.entries.lock().remove(key).is_some() { 0 } else { ENOENT }
    }
}

// ----------------------------------------------------------------------
// Programs: loading
// ----------------------------------------------------------------------

fn decode(raw: &[u8]) -> Vec<Insn> {
    raw.chunks_exact(8)
        .map(|c| Insn { code: c[0], dst: c[1] & 0xf, src: c[1] >> 4, off: i16::from_le_bytes([c[2], c[3]]), imm: i32::from_le_bytes([c[4], c[5], c[6], c[7]]) })
        .collect()
}

/// Checks a program's shape and resolves its map references (into `maps`).
fn check(insns: &mut [Insn], maps: &mut Vec<Arc<Map>>) -> Result<(), &'static str> {
    let n = insns.len();
    let mut second_half = alloc::vec![false; n];
    let mut i = 0;
    while i < n {
        let ins = insns[i];
        if ins.dst > 10 || ins.src > 10 {
            return Err("invalid register");
        }
        let class = ins.code & 7;
        let writes_dst = matches!(class, 1 | 4 | 7) || (class == 0 && ins.code == 0x18);
        if writes_dst && ins.dst == 10 {
            return Err("frame pointer is read only");
        }
        match class {
            0 => {
                // Only LD_IMM64 (legacy packet loads are not supported)
                if ins.code != 0x18 || i + 1 >= n || insns[i + 1].code != 0 {
                    return Err("invalid BPF_LD");
                }
                match ins.src {
                    0 => {}
                    1 | 2 => {
                        // BPF_PSEUDO_MAP_FD / MAP_VALUE: the map (and an offset into its value)
                        let m = map_of(ins.imm as u32).map_err(|_| "fd is not a map")?;
                        if ins.src == 2 && (!m.is_array() || insns[i + 1].imm as u32 >= m.value_size) {
                            return Err("invalid map value reference");
                        }
                        let idx = maps.iter().position(|x| Arc::ptr_eq(x, &m)).unwrap_or_else(|| {
                            maps.push(m);
                            maps.len() - 1
                        });
                        insns[i].imm = idx as i32;
                    }
                    _ => return Err("unsupported pseudo load"),
                }
                second_half[i + 1] = true;
                i += 2;
                continue;
            }
            1 | 2 | 3 => {
                let mode = ins.code & 0xe0;
                if mode != 0x60 && !(class == 3 && mode == 0xc0) {
                    return Err("unsupported load/store mode");
                }
                if mode == 0xc0 && !matches!(ins.imm, 0x00 | 0x01 | 0x40 | 0x41 | 0x50 | 0x51 | 0xa0 | 0xa1 | 0xe1 | 0xf1) {
                    return Err("unsupported atomic operation");
                }
            }
            4 | 7 => {
                let op = ins.code & 0xf0;
                if op > 0xd0 {
                    return Err("invalid ALU operation");
                }
                if op == 0xd0 && !matches!(ins.imm, 16 | 32 | 64) {
                    return Err("invalid byte swap");
                }
            }
            5 | 6 => {
                let op = ins.code & 0xf0;
                match op {
                    0x80 => {
                        if class == 6 {
                            return Err("invalid call");
                        }
                        if ins.src == 1 {
                            // bpf-to-bpf call
                            let t = i as i64 + 1 + ins.imm as i64;
                            if t < 0 || t as usize >= n {
                                return Err("call out of range");
                            }
                        } else if !HELPERS.contains(&ins.imm) {
                            return Err("unknown helper");
                        }
                    }
                    0x90 => {
                        if class == 6 {
                            return Err("invalid exit");
                        }
                    }
                    0xe0 | 0xf0 => return Err("invalid jump"),
                    _ => {
                        let t = i as i64 + 1 + ins.off as i64;
                        if t < 0 || t as usize >= n {
                            return Err("jump out of range");
                        }
                    }
                }
            }
            _ => unreachable!(),
        }
        i += 1;
    }
    // No jump lands inside an LD_IMM64; the program cannot run off its end
    for (k, ins) in insns.iter().enumerate() {
        if matches!(ins.code & 7, 5 | 6) && !matches!(ins.code & 0xf0, 0x80 | 0x90) {
            let t = (k as i64 + 1 + ins.off as i64) as usize;
            if second_half[t] {
                return Err("jump into the middle of an instruction");
            }
        }
    }
    let last = insns[n - 1];
    if !(last.code == 0x95 || last.code == 0x05) {
        return Err("last instruction is not an exit or jump");
    }
    Ok(())
}

// ----------------------------------------------------------------------
// The interpreter
// ----------------------------------------------------------------------

// Pointer encoding: region tag << 48 | index << 32 | offset
const R_CTX: u64 = 1;
const R_STACK: u64 = 2;
const R_VALUE: u64 = 3;
const R_MAP: u64 = 4;
const R_PACKET: u64 = 5;

fn ptr(region: u64, index: u64, off: u64) -> u64 {
    (region << 48) | (index << 32) | off
}

struct Run<'a> {
    prog: &'a Prog,
    ctx: Vec<u8>,
    /// Context offsets that hold packet pointers (`__sk_buff` data, data_end).
    ctx_ptrs: &'a [(usize, u64)],
    packet: Vec<u8>,
    stacks: Vec<[u8; STACK]>,
    /// Map values handed to the program: (map, key).
    values: Vec<(Arc<Map>, Vec<u8>)>,
}

impl<'a> Run<'a> {
    /// Reads `n` bytes at encoded address `addr`.
    fn load(&mut self, addr: u64, n: usize) -> Result<u64, ()> {
        let mut b = [0u8; 8];
        self.access(addr, n, |m| b[..n].copy_from_slice(m))?;
        Ok(u64::from_le_bytes(b))
    }

    fn store(&mut self, addr: u64, n: usize, v: u64) -> Result<(), ()> {
        let b = v.to_le_bytes();
        self.access(addr, n, |m| m.copy_from_slice(&b[..n]))
    }

    fn access(&mut self, addr: u64, n: usize, f: impl FnOnce(&mut [u8])) -> Result<(), ()> {
        let (region, index, off) = (addr >> 48, (addr >> 32) & 0xffff, (addr & 0xffff_ffff) as usize);
        let end = off.checked_add(n).ok_or(())?;
        match region {
            R_CTX if index == 0 && end <= self.ctx.len() => f(&mut self.ctx[off..end]),
            R_STACK if (index as usize) < self.stacks.len() && end <= STACK => f(&mut self.stacks[index as usize][off..end]),
            R_PACKET if index == 0 && end <= self.packet.len() => f(&mut self.packet[off..end]),
            R_VALUE if (index as usize) < self.values.len() => {
                let (m, k) = &self.values[index as usize];
                let mut e = m.entries.lock();
                let v = e.get_mut(k).ok_or(())?;
                if end > v.len() {
                    return Err(());
                }
                f(&mut v[off..end]);
            }
            _ => return Err(()),
        }
        Ok(())
    }

    fn bytes(&mut self, addr: u64, n: usize) -> Result<Vec<u8>, ()> {
        let mut out = alloc::vec![0u8; n];
        self.access(addr, n, |m| out.copy_from_slice(m))?;
        Ok(out)
    }

    fn map_arg(&self, v: u64) -> Result<Arc<Map>, ()> {
        if v >> 48 != R_MAP {
            return Err(());
        }
        self.prog.maps.get((v & 0xffff_ffff) as usize).cloned().ok_or(())
    }

    fn helper(&mut self, id: i32, r: &[u64; 11]) -> Result<u64, ()> {
        Ok(match id {
            // map_lookup_elem(map, key) -> value pointer or NULL
            1 => {
                let m = self.map_arg(r[1])?;
                let key = self.bytes(r[2], m.key_size as usize)?;
                if m.entries.lock().contains_key(&key) {
                    self.values.push((m, key));
                    ptr(R_VALUE, (self.values.len() - 1) as u64, 0)
                } else {
                    0
                }
            }
            // map_update_elem(map, key, value, flags)
            2 => {
                let m = self.map_arg(r[1])?;
                let key = self.bytes(r[2], m.key_size as usize)?;
                let value = self.bytes(r[3], m.value_size as usize)?;
                m.update(&key, &value, r[4]) as u64
            }
            // map_delete_elem(map, key)
            3 => {
                let m = self.map_arg(r[1])?;
                let key = self.bytes(r[2], m.key_size as usize)?;
                m.delete(&key) as u64
            }
            // ktime_get_ns, ktime_get_boot_ns
            5 | 125 => crate::arch::pit::now_ns(),
            // trace_printk: nowhere to print
            6 => 0,
            7 => {
                let mut b = [0u8; 4];
                crate::arch::random::fill(&mut b);
                u32::from_le_bytes(b) as u64
            }
            8 => 0, // get_smp_processor_id
            14 => {
                let (tid, pid) = super::proc::current_ids();
                (pid << 32) | tid
            }
            15 => {
                let (uid, gid) = crate::task::with_current_task_mut(|t| (t.uid, t.gid)).unwrap_or((0, 0));
                ((gid as u64) << 32) | uid as u64
            }
            // get_current_comm(buf, size)
            16 => {
                let size = r[2] as usize;
                if size == 0 || size > 256 {
                    return Err(());
                }
                let comm = super::fs::proc_pid_file_text("self/comm").unwrap_or_default();
                let mut b = alloc::vec![0u8; size];
                for (i, c) in comm.iter().take(size - 1).enumerate() {
                    if *c != b'\n' {
                        b[i] = *c;
                    }
                }
                self.access(r[1], size, |m| m.copy_from_slice(&b))?;
                0
            }
            _ => return Err(()),
        })
    }

    /// Runs the program; `None` if it broke a rule (an invalid access, too many steps).
    fn exec(&mut self) -> Option<u64> {
        let insns = &self.prog.insns;
        let mut r = [0u64; 11];
        r[1] = ptr(R_CTX, 0, 0);
        self.stacks.push([0u8; STACK]);
        r[10] = ptr(R_STACK, 0, STACK as u64);
        // Calls: (return pc, saved r6..r9)
        let mut frames: Vec<(usize, [u64; 4])> = Vec::new();
        let mut pc = 0usize;
        let mut steps = 0u64;
        loop {
            steps += 1;
            if steps > MAX_STEPS || pc >= insns.len() {
                return None;
            }
            let ins = insns[pc];
            let (d, s) = (ins.dst as usize, ins.src as usize);
            let class = ins.code & 7;
            pc += 1;
            match class {
                0 => {
                    let hi = insns[pc].imm as u32 as u64;
                    r[d] = match ins.src {
                        1 => ptr(R_MAP, 0, ins.imm as u32 as u64),
                        2 => {
                            let m = self.prog.maps[ins.imm as usize].clone();
                            self.values.push((m, 0u32.to_le_bytes().to_vec()));
                            ptr(R_VALUE, (self.values.len() - 1) as u64, hi)
                        }
                        _ => (ins.imm as u32 as u64) | (hi << 32),
                    };
                    pc += 1;
                }
                1 | 2 | 3 => {
                    let n = match ins.code & 0x18 {
                        0x00 => 4,
                        0x08 => 2,
                        0x10 => 1,
                        _ => 8,
                    };
                    match class {
                        1 => {
                            let addr = r[s].wrapping_add(ins.off as i64 as u64);
                            // __sk_buff data / data_end: packet pointers
                            if addr >> 48 == R_CTX {
                                if let Some(&(_, p)) = self.ctx_ptrs.iter().find(|(o, _)| *o as u64 == (addr & 0xffff_ffff)) {
                                    r[d] = p;
                                    continue;
                                }
                            }
                            r[d] = self.load(addr, n).ok()?;
                        }
                        2 => {
                            let addr = r[d].wrapping_add(ins.off as i64 as u64);
                            self.store(addr, n, ins.imm as i64 as u64).ok()?;
                        }
                        _ => {
                            let addr = r[d].wrapping_add(ins.off as i64 as u64);
                            if ins.code & 0xe0 == 0xc0 {
                                // Atomics (one CPU: plain read-modify-write)
                                let old = self.load(addr, n).ok()?;
                                let mask = if n == 8 { u64::MAX } else { 0xffff_ffff };
                                let v = r[s] & mask;
                                let new = match ins.imm & 0xf0 {
                                    0x00 => old.wrapping_add(v),
                                    0x40 => old | v,
                                    0x50 => old & v,
                                    0xa0 => old ^ v,
                                    0xe0 => v,
                                    _ => {
                                        // CMPXCHG: r0 is compared and gets the old value
                                        let n2 = if old == r[0] & mask { v } else { old };
                                        r[0] = old;
                                        self.store(addr, n, n2 & mask).ok()?;
                                        continue;
                                    }
                                };
                                self.store(addr, n, new & mask).ok()?;
                                if ins.imm & 1 != 0 {
                                    r[s] = old;
                                }
                            } else {
                                self.store(addr, n, r[s]).ok()?;
                            }
                        }
                    }
                }
                4 | 7 => {
                    let is64 = class == 7;
                    let src = if ins.code & 8 != 0 { r[s] } else { ins.imm as i64 as u64 };
                    let dst = r[d];
                    let (a, b) = if is64 { (dst, src) } else { (dst as u32 as u64, src as u32 as u64) };
                    let sh = if is64 { 63 } else { 31 };
                    let v = match ins.code & 0xf0 {
                        0x00 => a.wrapping_add(b),
                        0x10 => a.wrapping_sub(b),
                        0x20 => a.wrapping_mul(b),
                        0x30 => {
                            if b == 0 { 0 } else if is64 { a / b } else { (a as u32 / b as u32) as u64 }
                        }
                        0x40 => a | b,
                        0x50 => a & b,
                        0x60 => a.wrapping_shl((b & sh) as u32),
                        0x70 => {
                            if is64 { a >> (b & 63) } else { ((a as u32) >> (b & 31)) as u64 }
                        }
                        0x80 => (a as i64).wrapping_neg() as u64,
                        0x90 => {
                            if b == 0 { a } else if is64 { a % b } else { (a as u32 % b as u32) as u64 }
                        }
                        0xa0 => a ^ b,
                        0xb0 => b,
                        0xc0 => {
                            if is64 { ((a as i64) >> (b & 63)) as u64 } else { ((a as u32 as i32) >> (b & 31)) as u32 as u64 }
                        }
                        _ => {
                            // END: to little (no-op on x86 beyond truncation) or big endian
                            let width = ins.imm;
                            let be = ins.code & 8 != 0;
                            match (width, be) {
                                (16, false) => dst & 0xffff,
                                (32, false) => dst & 0xffff_ffff,
                                (64, false) => dst,
                                (16, true) => (dst as u16).swap_bytes() as u64,
                                (32, true) => (dst as u32).swap_bytes() as u64,
                                _ => dst.swap_bytes(),
                            }
                        }
                    };
                    r[d] = if is64 || ins.code & 0xf0 == 0xd0 { v } else { v as u32 as u64 };
                }
                _ => {
                    let op = ins.code & 0xf0;
                    if op == 0x80 {
                        if ins.src == 1 {
                            if frames.len() >= 8 {
                                return None;
                            }
                            frames.push((pc, [r[6], r[7], r[8], r[9]]));
                            self.stacks.push([0u8; STACK]);
                            r[10] = ptr(R_STACK, (self.stacks.len() - 1) as u64, STACK as u64);
                            pc = (pc as i64 + ins.imm as i64) as usize;
                        } else {
                            r[0] = self.helper(ins.imm, &r).ok()?;
                            // r1-r5 are clobbered by calls
                            for x in &mut r[1..6] {
                                *x = 0;
                            }
                        }
                        continue;
                    }
                    if op == 0x90 {
                        match frames.pop() {
                            Some((ret, saved)) => {
                                r[6..10].copy_from_slice(&saved);
                                pc = ret;
                                // The callee's stack goes with it: stacks and frames pair
                                // up, so the caller's own stack is at its depth again
                                self.stacks.pop();
                                let depth = frames.len() as u64;
                                r[10] = ptr(R_STACK, depth, STACK as u64);
                                continue;
                            }
                            None => return Some(r[0]),
                        }
                    }
                    let (a, b) = {
                        let src = if ins.code & 8 != 0 { r[s] } else { ins.imm as i64 as u64 };
                        if class == 6 { (r[d] as u32 as u64, src as u32 as u64) } else { (r[d], src) }
                    };
                    let (sa, sb) = if class == 6 { (a as u32 as i32 as i64, b as u32 as i32 as i64) } else { (a as i64, b as i64) };
                    let taken = match op {
                        0x00 => true,
                        0x10 => a == b,
                        0x20 => a > b,
                        0x30 => a >= b,
                        0x40 => a & b != 0,
                        0x50 => a != b,
                        0x60 => sa > sb,
                        0x70 => sa >= sb,
                        0xa0 => a < b,
                        0xb0 => a <= b,
                        0xc0 => sa < sb,
                        _ => sa <= sb,
                    };
                    if taken {
                        pc = (pc as i64 + ins.off as i64) as usize;
                    }
                }
            }
        }
    }
}

/// Runs `prog` on context `ctx` (and packet data for skb programs).
fn run(prog: &Prog, ctx: Vec<u8>, ctx_ptrs: &[(usize, u64)], packet: Vec<u8>) -> (Option<u64>, Vec<u8>) {
    let mut r = Run { prog, ctx, ctx_ptrs, packet, stacks: Vec::new(), values: Vec::new() };
    let res = r.exec();
    (res, r.packet)
}

// ----------------------------------------------------------------------
// Device control
// ----------------------------------------------------------------------

/// Device access types and kinds (`BPF_DEVCG_*`).
pub const DEV_MKNOD: u32 = 1;
/// Reading.
pub const DEV_READ: u32 = 2;
/// Writing.
pub const DEV_WRITE: u32 = 4;
/// A block device.
pub const DEV_BLOCK: u32 = 1;
/// A character device.
pub const DEV_CHAR: u32 = 2;

// wave10 GV1 begin
/// Whether any device program is attached (vfs-server's `mknod` of a device node then
/// leaves it to [`device_check`] here: `LX_FS_DEVCG`).
pub fn any_device_programs() -> bool {
    ANY_DEVICE.load(Ordering::Relaxed) || SERVER_ANY_DEVICE.load(Ordering::Relaxed)
}
// wave10 GV1 end

/// Whether the calling process's cgroup programs allow `access` to device `kind`
/// `major:minor` (`EPERM` if one refuses).
pub fn device_check(kind: u32, major: u32, minor: u32, access: u32) -> Result<(), i64> {
    if !ANY_DEVICE.load(Ordering::Relaxed) && !SERVER_ANY_DEVICE.load(Ordering::Relaxed) {
        return Ok(());
    }
    let group = super::proc::PROCS.lock().get(&super::proc::current_ids().1).and_then(|p| p.cgroup.clone());
    let group = String::from(group.as_deref().unwrap_or(""));
    let applies = |cg: &str| cg.is_empty() || group == cg || group.starts_with(&alloc::format!("{}/", cg));
    let mut progs: Vec<Arc<Prog>> =
        ATTACHED.lock().iter().filter(|a| a.attach_type == ATTACH_CGROUP_DEVICE && applies(&a.cgroup)).map(|a| a.prog.clone()).collect();
    progs.extend(SERVER_DEVICE.lock().iter().filter(|(cg, _)| applies(cg)).map(|(_, p)| p.clone()));
    for p in progs {
        let mut ctx = Vec::with_capacity(12);
        ctx.extend_from_slice(&((access << 16) | kind).to_le_bytes());
        ctx.extend_from_slice(&major.to_le_bytes());
        ctx.extend_from_slice(&minor.to_le_bytes());
        if run(&p, ctx, &[], Vec::new()).0.unwrap_or(0) == 0 {
            return Err(EPERM);
        }
    }
    Ok(())
}

/// The device programs linux-server attached (wave 4, step 2: bpf lives in the server, but
/// device opens and `mknod`s are decided here, inside the kernel's open path, where it
/// cannot ask the server): the server hands over the whole list whenever it changes.
static SERVER_DEVICE: Mutex<Vec<(String, Arc<Prog>)>> = Mutex::new(Vec::new());
static SERVER_ANY_DEVICE: AtomicBool = AtomicBool::new(false);

/// Replaces the server's device programs with the list in `raw` (`LX_OBJ_BPF_DEVICE`:
/// entries of `[u32 cgroup length, cgroup, u32 instruction count, instructions]`). Each
/// program is checked again here; one that uses maps (they live in the server) or fails the
/// checks refuses the whole list (`EINVAL`) and the previous list stays.
pub fn set_server_device_programs(raw: &[u8]) -> i64 {
    let mut list = Vec::new();
    let mut at = 0usize;
    let take = |at: &mut usize, n: usize| -> Option<&[u8]> {
        let s = raw.get(*at..*at + n)?;
        *at += n;
        Some(s)
    };
    while at < raw.len() {
        let Some(l) = take(&mut at, 4) else { return EINVAL };
        let l = u32::from_le_bytes(l.try_into().unwrap()) as usize;
        let Some(cg) = take(&mut at, l) else { return EINVAL };
        let cg = String::from_utf8_lossy(cg).into_owned();
        let Some(n) = take(&mut at, 4) else { return EINVAL };
        let n = u32::from_le_bytes(n.try_into().unwrap()) as usize;
        if n == 0 || n > MAX_INSNS {
            return EINVAL;
        }
        let Some(code) = take(&mut at, n * 8) else { return EINVAL };
        let mut insns = decode(code);
        // A map reference makes the check fail: the server's maps are not the kernel's
        if insns.iter().any(|i| i.code == 0x18 && i.src != 0) {
            return EINVAL;
        }
        let mut maps = Vec::new();
        if check(&mut insns, &mut maps).is_err() {
            return EINVAL;
        }
        list.push((cg, Arc::new(Prog { id: 0, kind: PROG_CGROUP_DEVICE, insns, maps, name: [0; 16], tag: [0; 8] })));
    }
    SERVER_ANY_DEVICE.store(!list.is_empty(), Ordering::Relaxed);
    *SERVER_DEVICE.lock() = list;
    0
}

// ----------------------------------------------------------------------
// Attaching
// ----------------------------------------------------------------------

// ----------------------------------------------------------------------
// The system call
// ----------------------------------------------------------------------
