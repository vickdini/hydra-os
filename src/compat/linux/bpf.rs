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
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use spin::Mutex;

use super::chardev::CharDevice;
use super::vfs::{copy_in, copy_out};
use crate::task::wait::WaitSet;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EBADF: i64 = -9;
const E2BIG: i64 = -7;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;
const ENOSPC: i64 = -28;
const ENOTSUPP: i64 = -524;

// Map types
const MAP_HASH: u32 = 1;
const MAP_ARRAY: u32 = 2;
const MAP_PERCPU_HASH: u32 = 5;
const MAP_PERCPU_ARRAY: u32 = 6;
const MAP_LRU_HASH: u32 = 9;
const MAP_LRU_PERCPU_HASH: u32 = 10;

// Program types
const PROG_SOCKET_FILTER: u32 = 1;
const PROG_CGROUP_SKB: u32 = 8;
const PROG_CGROUP_SOCK: u32 = 9;
const PROG_CGROUP_DEVICE: u32 = 15;
const PROG_CGROUP_SOCK_ADDR: u32 = 18;
const PROG_CGROUP_SYSCTL: u32 = 23;

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
    /// The value size user space sees (per-CPU maps: one 8-byte aligned value per CPU).
    fn user_value_size(&self) -> usize {
        if matches!(self.kind, MAP_PERCPU_HASH | MAP_PERCPU_ARRAY | MAP_LRU_PERCPU_HASH) {
            (self.value_size as usize + 7) & !7
        } else {
            self.value_size as usize
        }
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
pub struct Prog {
    id: u32,
    kind: u32,
    insns: Vec<Insn>,
    /// Maps it references (LD_IMM64 map loads index this).
    maps: Vec<Arc<Map>>,
    name: [u8; 16],
    tag: [u8; 8],
}

/// A link: a program attached to a cgroup until the link goes.
pub struct Link {
    id: u32,
    prog: Arc<Prog>,
    cgroup: String,
    attach_type: u32,
    detached: AtomicBool,
}

/// BTF data, kept as given.
pub struct Btf {
    id: u32,
}

/// The object behind a bpf descriptor.
#[derive(Clone)]
pub enum Obj {
    /// A map.
    Map(Arc<Map>),
    /// A program.
    Prog(Arc<Prog>),
    /// A link.
    Link(Arc<Link>),
    /// BTF.
    Btf(Arc<Btf>),
}

struct BpfDev(Obj);

impl Drop for BpfDev {
    fn drop(&mut self) {
        if let Obj::Link(l) = &self.0 {
            // The last descriptor of a link (a pin holds its own reference) detaches it
            if Arc::strong_count(l) == 1 {
                detach_link(l);
            }
        }
    }
}

impl CharDevice for BpfDev {
    fn read(&self, _buf: &mut [u8]) -> i64 {
        EINVAL
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _waits: &mut WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        String::from(match &self.0 {
            Obj::Map(_) => "anon_inode:bpf-map",
            Obj::Prog(_) => "anon_inode:bpf-prog",
            Obj::Link(_) => "anon_inode:bpf_link",
            Obj::Btf(_) => "anon_inode:btf",
        })
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn as_bpf(&self) -> Option<Obj> {
        Some(self.0.clone())
    }
}

static NEXT_ID: AtomicU32 = AtomicU32::new(1);
static MAPS: Mutex<BTreeMap<u32, Weak<Map>>> = Mutex::new(BTreeMap::new());
static PROGS: Mutex<BTreeMap<u32, Weak<Prog>>> = Mutex::new(BTreeMap::new());
static LINKS: Mutex<BTreeMap<u32, Weak<Link>>> = Mutex::new(BTreeMap::new());
/// Pinned objects by path.
static PINS: Mutex<BTreeMap<String, Obj>> = Mutex::new(BTreeMap::new());

/// A program attached to a cgroup.
struct Attached {
    cgroup: String,
    attach_type: u32,
    prog: Arc<Prog>,
    /// The link that holds it (0: `BPF_PROG_ATTACH`).
    link: u32,
}

static ATTACHED: Mutex<Vec<Attached>> = Mutex::new(Vec::new());
static ANY_DEVICE: AtomicBool = AtomicBool::new(false);

fn new_id() -> u32 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn install(obj: Obj) -> i64 {
    let dev: Arc<dyn CharDevice> = Arc::new(BpfDev(obj));
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::Device(dev)) {
        Ok(fd) => {
            fds.set_cloexec(fd, true);
            fd as i64
        }
        Err(_) => EMFILE,
    })
}

fn obj_of(fd: u32) -> Result<Obj, i64> {
    let d = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    match d {
        Some(crate::fs::FileDescriptor::Device(d)) => d.as_bpf().ok_or(EINVAL),
        Some(_) => Err(EINVAL),
        None => Err(EBADF),
    }
}

fn map_of(fd: u32) -> Result<Arc<Map>, i64> {
    match obj_of(fd)? {
        Obj::Map(m) => Ok(m),
        _ => Err(EINVAL),
    }
}

fn prog_of(fd: u32) -> Result<Arc<Prog>, i64> {
    match obj_of(fd)? {
        Obj::Prog(p) => Ok(p),
        _ => Err(EINVAL),
    }
}

fn detach_link(l: &Link) {
    if !l.detached.swap(true, Ordering::Relaxed) {
        ATTACHED.lock().retain(|a| a.link != l.id);
    }
}

// ----------------------------------------------------------------------
// Maps
// ----------------------------------------------------------------------

fn map_create(a: &[u8]) -> i64 {
    let u = |o: usize| u32::from_le_bytes(a[o..o + 4].try_into().unwrap());
    let (kind, key_size, value_size, max, flags) = (u(0), u(4), u(8), u(12), u(16));
    let mut name = [0u8; 16];
    name.copy_from_slice(&a[28..44]);
    if !matches!(kind, MAP_HASH | MAP_ARRAY | MAP_PERCPU_HASH | MAP_PERCPU_ARRAY | MAP_LRU_HASH | MAP_LRU_PERCPU_HASH) {
        return EINVAL;
    }
    if value_size == 0 || max == 0 || key_size == 0 || value_size > 65536 || key_size > 512 {
        return EINVAL;
    }
    // Arrays: 4-byte keys, every index present (zeroed)
    let array = matches!(kind, MAP_ARRAY | MAP_PERCPU_ARRAY);
    if array && key_size != 4 {
        return EINVAL;
    }
    if (max as u64) * (value_size as u64) > 64 << 20 {
        return -12; // ENOMEM
    }
    let mut entries = BTreeMap::new();
    if array {
        for i in 0..max {
            entries.insert(i.to_le_bytes().to_vec(), alloc::vec![0u8; value_size as usize]);
        }
    }
    let m = Arc::new(Map { id: new_id(), kind, key_size, value_size, max, flags, name, entries: Mutex::new(entries), frozen: AtomicBool::new(false) });
    MAPS.lock().insert(m.id, Arc::downgrade(&m));
    install(Obj::Map(m))
}

impl Map {
    fn lookup(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.entries.lock().get(key).cloned()
    }

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

fn map_elem(cmd: u32, a: &[u8]) -> i64 {
    let fd = u32::from_le_bytes(a[0..4].try_into().unwrap());
    let key_ptr = u64::from_le_bytes(a[8..16].try_into().unwrap());
    let val_ptr = u64::from_le_bytes(a[16..24].try_into().unwrap());
    let flags = u64::from_le_bytes(a[24..32].try_into().unwrap());
    let m = match map_of(fd) {
        Ok(m) => m,
        Err(e) => return e,
    };
    let key = if key_ptr == 0 && cmd == 4 { None } else {
        match copy_in(key_ptr, m.key_size as usize) {
            Ok(k) => Some(k),
            Err(e) => return e,
        }
    };
    let uvs = m.user_value_size();
    match cmd {
        // LOOKUP_ELEM, LOOKUP_AND_DELETE_ELEM
        1 | 21 => {
            let Some(v) = m.lookup(key.as_ref().unwrap()) else { return ENOENT };
            let mut out = v;
            out.resize(uvs, 0);
            if copy_out(val_ptr, &out).is_err() {
                return EFAULT;
            }
            if cmd == 21 {
                if m.is_array() {
                    return EINVAL;
                }
                m.entries.lock().remove(key.as_ref().unwrap());
            }
            0
        }
        2 => {
            if m.frozen.load(Ordering::Relaxed) {
                return EPERM;
            }
            let v = match copy_in(val_ptr, uvs) {
                Ok(v) => v,
                Err(e) => return e,
            };
            m.update(key.as_ref().unwrap(), &v, flags)
        }
        3 => {
            if m.frozen.load(Ordering::Relaxed) {
                return EPERM;
            }
            m.delete(key.as_ref().unwrap())
        }
        // GET_NEXT_KEY: after `key` (the first key when absent or unknown)
        _ => {
            let e = m.entries.lock();
            let next = match &key {
                Some(k) if e.contains_key(k) => e.range::<Vec<u8>, _>((core::ops::Bound::Excluded(k.clone()), core::ops::Bound::Unbounded)).next().map(|(k, _)| k.clone()),
                _ => e.keys().next().cloned(),
            };
            drop(e);
            match next {
                Some(n) => copy_out(val_ptr, &n).map_or(EFAULT, |_| 0),
                None => ENOENT,
            }
        }
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

fn prog_load(a: &[u8]) -> i64 {
    let u = |o: usize| u32::from_le_bytes(a[o..o + 4].try_into().unwrap());
    let q = |o: usize| u64::from_le_bytes(a[o..o + 8].try_into().unwrap());
    let (kind, cnt, insns_ptr, log_level, log_size, log_buf) = (u(0), u(4) as usize, q(8), u(24), u(28), q(32));
    if !matches!(kind, PROG_SOCKET_FILTER | PROG_CGROUP_SKB | PROG_CGROUP_SOCK | PROG_CGROUP_DEVICE | PROG_CGROUP_SOCK_ADDR | PROG_CGROUP_SYSCTL) {
        return EINVAL;
    }
    if cnt == 0 || cnt > MAX_INSNS {
        return E2BIG;
    }
    let raw = match copy_in(insns_ptr, cnt * 8) {
        Ok(r) => r,
        Err(e) => return e,
    };
    let mut insns = decode(&raw);
    let mut maps = Vec::new();
    if let Err(why) = check(&mut insns, &mut maps) {
        // The reason, in the log buffer (as the verifier writes its log)
        if log_level != 0 && log_buf != 0 && log_size > 1 {
            let mut msg = alloc::format!("{}\n", why).into_bytes();
            msg.truncate(log_size as usize - 1);
            msg.push(0);
            let _ = copy_out(log_buf, &msg);
        }
        return if log_level != 0 && log_size == 0 { EINVAL } else { -13 }; // EACCES, as a verifier refusal
    }
    let mut name = [0u8; 16];
    name.copy_from_slice(&a[48..64]);
    // A tag from the instructions (Linux: the first 8 bytes of their SHA-1)
    let mut tag = [0u8; 8];
    for (i, b) in raw.iter().enumerate() {
        tag[i % 8] = tag[i % 8].rotate_left(3) ^ *b;
    }
    let p = Arc::new(Prog { id: new_id(), kind, insns, maps, name, tag });
    PROGS.lock().insert(p.id, Arc::downgrade(&p));
    install(Obj::Prog(p))
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
            5 | 125 => crate::arch::pit::ticks() * 10_000_000,
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

/// Whether the calling process's cgroup programs allow `access` to device `kind`
/// `major:minor` (`EPERM` if one refuses).
pub fn device_check(kind: u32, major: u32, minor: u32, access: u32) -> Result<(), i64> {
    if !ANY_DEVICE.load(Ordering::Relaxed) {
        return Ok(());
    }
    let group = super::proc::PROCS.lock().get(&super::proc::current_ids().1).and_then(|p| p.cgroup.clone());
    let group = String::from(group.as_deref().unwrap_or(""));
    let progs: Vec<Arc<Prog>> = ATTACHED
        .lock()
        .iter()
        .filter(|a| a.attach_type == ATTACH_CGROUP_DEVICE && (a.cgroup.is_empty() || group == a.cgroup || group.starts_with(&alloc::format!("{}/", a.cgroup))))
        .map(|a| a.prog.clone())
        .collect();
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

// ----------------------------------------------------------------------
// Attaching
// ----------------------------------------------------------------------

/// The cgroup a descriptor names (its path below `/sys/fs/cgroup`; "" is the root).
fn cgroup_of(fd: u32) -> Result<String, i64> {
    let d = crate::task::with_current_fds_mut(|fds| fds.get(fd as i32 as usize).cloned());
    let path = match d {
        Some(crate::fs::FileDescriptor::Vnode(f)) => f.lock().path.clone(),
        Some(crate::fs::FileDescriptor::File { path, .. }) => path,
        Some(_) => return Err(EINVAL),
        None => return Err(EBADF),
    };
    let rest = path.strip_prefix(super::fs::CGROUP_ROOT).ok_or(EINVAL)?;
    Ok(String::from(rest.trim_end_matches('/')))
}

/// Which program types attach with which attach types.
fn attach_ok(kind: u32, attach_type: u32) -> bool {
    match kind {
        PROG_CGROUP_SKB => matches!(attach_type, 0 | 1),
        PROG_CGROUP_SOCK => matches!(attach_type, 2 | 12 | 13 | 25 | 26),
        PROG_CGROUP_DEVICE => attach_type == ATTACH_CGROUP_DEVICE,
        PROG_CGROUP_SOCK_ADDR => matches!(attach_type, 8..=11 | 14..=17 | 18 | 19 | 28..=31),
        PROG_CGROUP_SYSCTL => attach_type == 18,
        _ => false,
    }
}

fn attach(cgroup: String, attach_type: u32, prog: Arc<Prog>, link: u32) {
    if attach_type == ATTACH_CGROUP_DEVICE {
        ANY_DEVICE.store(true, Ordering::Relaxed);
    }
    ATTACHED.lock().push(Attached { cgroup, attach_type, prog, link });
}

// ----------------------------------------------------------------------
// The system call
// ----------------------------------------------------------------------

fn info(obj: &Obj, ptr: u64, len: u32) -> i64 {
    let mut out = alloc::vec![0u8; 256];
    let p32 = |o: &mut [u8], at: usize, v: u32| o[at..at + 4].copy_from_slice(&v.to_le_bytes());
    let size = match obj {
        Obj::Prog(p) => {
            p32(&mut out, 0, p.kind);
            p32(&mut out, 4, p.id);
            out[8..16].copy_from_slice(&p.tag);
            p32(&mut out, 20, (p.insns.len() * 8) as u32);
            p32(&mut out, 52, p.maps.len() as u32);
            out[64..80].copy_from_slice(&p.name);
            228
        }
        Obj::Map(m) => {
            p32(&mut out, 0, m.kind);
            p32(&mut out, 4, m.id);
            p32(&mut out, 8, m.key_size);
            p32(&mut out, 12, m.value_size);
            p32(&mut out, 16, m.max);
            p32(&mut out, 20, m.flags);
            out[24..40].copy_from_slice(&m.name);
            88
        }
        Obj::Link(l) => {
            p32(&mut out, 0, 3); // BPF_LINK_TYPE_CGROUP
            p32(&mut out, 4, l.id);
            p32(&mut out, 8, l.prog.id);
            // cgroup_id: a number for the cgroup's path
            let cg = l.cgroup.bytes().fold(1469598103934665603u64, |h, b| (h ^ b as u64).wrapping_mul(1099511628211));
            out[16..24].copy_from_slice(&cg.to_le_bytes());
            p32(&mut out, 24, l.attach_type);
            32
        }
        Obj::Btf(b) => {
            p32(&mut out, 16, b.id);
            32
        }
    };
    let n = (len as usize).min(size);
    if copy_out(ptr, &out[..n]).is_err() {
        return EFAULT;
    }
    n as i64
}

/// `bpf(cmd, attr, size)`.
pub fn sys_bpf(cmd: u64, attr: u64, size: u64) -> i64 {
    if !crate::task::with_current_task_mut(|t| (t.caps.effective & ((1 << 39) | (1 << 21))) != 0 && !t.caps.in_userns).unwrap_or(false) {
        return EPERM;
    }
    if size > 4096 {
        return E2BIG;
    }
    let mut a = match copy_in(attr, size as usize) {
        Ok(a) => a,
        Err(e) => return e,
    };
    a.resize(256, 0);
    let u = |o: usize| u32::from_le_bytes(a[o..o + 4].try_into().unwrap());
    let q = |o: usize| u64::from_le_bytes(a[o..o + 8].try_into().unwrap());
    match cmd {
        0 => map_create(&a),
        1..=4 | 21 => map_elem(cmd as u32, &a),
        5 => prog_load(&a),
        // OBJ_PIN, OBJ_GET
        6 | 7 => {
            let path = match super::vfs::user_path(q(0)) {
                Ok(p) => String::from_utf8_lossy(&p).into_owned(),
                Err(e) => return e,
            };
            if cmd == 6 {
                let obj = match obj_of(u(8)) {
                    Ok(o) => o,
                    Err(e) => return e,
                };
                let mut pins = PINS.lock();
                if pins.contains_key(&path) {
                    return EEXIST;
                }
                pins.insert(path, obj);
                0
            } else {
                match PINS.lock().get(&path).cloned() {
                    Some(o) => install(o),
                    None => ENOENT,
                }
            }
        }
        // PROG_ATTACH, PROG_DETACH
        8 | 9 => {
            let cg = match cgroup_of(u(0)) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let attach_type = u(8);
            if cmd == 8 {
                let p = match prog_of(u(4)) {
                    Ok(p) => p,
                    Err(e) => return e,
                };
                if !attach_ok(p.kind, attach_type) {
                    return EINVAL;
                }
                // Without BPF_F_ALLOW_MULTI the new program replaces the cgroup's one
                if u(12) & 2 == 0 {
                    ATTACHED.lock().retain(|x| !(x.cgroup == cg && x.attach_type == attach_type && x.link == 0));
                }
                attach(cg, attach_type, p, 0);
                0
            } else {
                let want = prog_of(u(4)).ok();
                let mut list = ATTACHED.lock();
                let before = list.len();
                let mut done = false;
                list.retain(|x| {
                    let hit = !done && x.cgroup == cg && x.attach_type == attach_type && x.link == 0 && want.as_ref().map_or(true, |w| Arc::ptr_eq(w, &x.prog));
                    if hit {
                        done = true;
                    }
                    !hit
                });
                if list.len() == before { ENOENT } else { 0 }
            }
        }
        // PROG_TEST_RUN
        10 => {
            let p = match prog_of(u(0)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            if !matches!(p.kind, PROG_SOCKET_FILTER | PROG_CGROUP_SKB) {
                return ENOTSUPP;
            }
            let (size_in, data_in, data_out) = (u(8) as usize, q(16), q(24));
            if size_in < 14 || size_in > 65536 {
                return EINVAL;
            }
            let data = match copy_in(data_in, size_in) {
                Ok(d) => d,
                Err(e) => return e,
            };
            // The program sees the packet from its network header, as cgroup hooks show it
            // (after the 14-byte Ethernet header): struct __sk_buff len and protocol
            // (network order), and data/data_end as packet pointers. (Linux's test runs
            // leave data/data_end unset for these program types.)
            let net = data[14..].to_vec();
            let mut ctx = alloc::vec![0u8; 192];
            ctx[0..4].copy_from_slice(&(net.len() as u32).to_le_bytes());
            ctx[16] = data[12];
            ctx[17] = data[13];
            let ptrs = [(76usize, ptr(R_PACKET, 0, 0)), (80usize, ptr(R_PACKET, 0, net.len() as u64))];
            let (res, net_out) = run(&p, ctx, &ptrs, net);
            let mut pkt = data[..14].to_vec();
            pkt.extend_from_slice(&net_out);
            let Some(ret) = res else { return EINVAL };
            let mut out = a.clone();
            out[4..8].copy_from_slice(&(ret as u32).to_le_bytes());
            out[12..16].copy_from_slice(&(pkt.len() as u32).to_le_bytes());
            out[36..40].copy_from_slice(&1u32.to_le_bytes()); // duration (ns)
            if data_out != 0 && copy_out(data_out, &pkt[..pkt.len().min(u(12).max(pkt.len() as u32) as usize)]).is_err() {
                return EFAULT;
            }
            if copy_out(attr, &out[..size as usize]).is_err() {
                return EFAULT;
            }
            0
        }
        // PROG_GET_NEXT_ID, MAP_GET_NEXT_ID, LINK_GET_NEXT_ID
        11 | 12 | 31 => {
            let start = u(0);
            let next = match cmd {
                11 => PROGS.lock().iter().filter(|(&k, w)| k > start && w.strong_count() > 0).map(|(&k, _)| k).next(),
                12 => MAPS.lock().iter().filter(|(&k, w)| k > start && w.strong_count() > 0).map(|(&k, _)| k).next(),
                _ => LINKS.lock().iter().filter(|(&k, w)| k > start && w.strong_count() > 0).map(|(&k, _)| k).next(),
            };
            match next {
                Some(n) => copy_out(attr + 4, &n.to_le_bytes()).map_or(EFAULT, |_| 0),
                None => ENOENT,
            }
        }
        // PROG_GET_FD_BY_ID, MAP_GET_FD_BY_ID, LINK_GET_FD_BY_ID
        13 | 14 | 30 => {
            let id = u(0);
            let obj = match cmd {
                13 => PROGS.lock().get(&id).and_then(|w| w.upgrade()).map(Obj::Prog),
                14 => MAPS.lock().get(&id).and_then(|w| w.upgrade()).map(Obj::Map),
                _ => LINKS.lock().get(&id).and_then(|w| w.upgrade()).map(Obj::Link),
            };
            match obj {
                Some(o) => install(o),
                None => ENOENT,
            }
        }
        // OBJ_GET_INFO_BY_FD
        15 => match obj_of(u(0)) {
            Ok(o) => {
                let n = info(&o, q(8), u(4));
                if n < 0 {
                    return n;
                }
                copy_out(attr + 4, &(n as u32).to_le_bytes()).map_or(EFAULT, |_| 0)
            }
            Err(e) => e,
        },
        // PROG_QUERY
        16 => {
            let cg = match cgroup_of(u(0)) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let attach_type = u(4);
            let ids: Vec<u32> = ATTACHED.lock().iter().filter(|x| x.cgroup == cg && x.attach_type == attach_type).map(|x| x.prog.id).collect();
            let room = u(24) as usize;
            let mut out = a.clone();
            out[24..28].copy_from_slice(&(ids.len() as u32).to_le_bytes());
            if q(16) != 0 {
                let bytes: Vec<u8> = ids.iter().take(room).flat_map(|v| v.to_le_bytes()).collect();
                if copy_out(q(16), &bytes).is_err() {
                    return EFAULT;
                }
            }
            if copy_out(attr, &out[..size as usize]).is_err() {
                return EFAULT;
            }
            if room < ids.len() && q(16) != 0 { ENOSPC } else { 0 }
        }
        // BTF_LOAD: kept, not checked
        18 => {
            let b = Arc::new(Btf { id: new_id() });
            install(Obj::Btf(b))
        }
        // MAP_FREEZE
        22 => match map_of(u(0)) {
            Ok(m) => {
                m.frozen.store(true, Ordering::Relaxed);
                0
            }
            Err(e) => e,
        },
        // LINK_CREATE
        28 => {
            let p = match prog_of(u(0)) {
                Ok(p) => p,
                Err(e) => return e,
            };
            let cg = match cgroup_of(u(4)) {
                Ok(c) => c,
                Err(e) => return e,
            };
            let attach_type = u(8);
            if !attach_ok(p.kind, attach_type) {
                return EINVAL;
            }
            let l = Arc::new(Link { id: new_id(), prog: p.clone(), cgroup: cg.clone(), attach_type, detached: AtomicBool::new(false) });
            LINKS.lock().insert(l.id, Arc::downgrade(&l));
            attach(cg, attach_type, p, l.id);
            install(Obj::Link(l))
        }
        // LINK_DETACH
        34 => match obj_of(u(0)) {
            Ok(Obj::Link(l)) => {
                detach_link(&l);
                0
            }
            Ok(_) => EINVAL,
            Err(e) => e,
        },
        _ => EINVAL,
    }
}
