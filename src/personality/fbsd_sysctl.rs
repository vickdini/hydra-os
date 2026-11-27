//! # FreeBSD personality: the temporary `sysctl` minimum (wave 12, Group FK)
//!
//! `__sysctl` (202) and `__sysctlbyname` (570) for the few names FreeBSD's C library,
//! libthr and rtld ask for before anything else works (the table in
//! [`super::fbsd_tmp::NODES`]: `kern.osreldate`, `kern.arandom`, `kern.usrstack`,
//! `hw.pagesize(s)`, `hw.ncpu`, `kern.smp.cpus`, `vm.overcommit`, `uname`'s five names, the
//! cpuset sizes), plus the name-to-OID meta node `{0, 3}` (`sysctlnametomib`). Every other
//! name answers `ENOENT`.
//!
//! // wave12 FK temporary: moves to lx-proc in stage 2

use super::fbsd_tmp::{self as tmp, Node};
use super::linux_call;
use crate::arch::syscall::SyscallFrame;
use crate::compat::linux::vfs::{copy_in, copy_out};

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOMEM: i64 = -12;

/// `__sysctl(name, namelen, old, oldlenp, new, newlen)`.
// wave12 FK temporary: moves to lx-proc in stage 2
pub fn sysctl(f: &SyscallFrame, a: [u64; 6]) -> Result<i64, i64> {
    let [name, namelen, old, oldlenp, new, newlen] = a;
    if !(2..=24).contains(&namelen) {
        return Err(EINVAL);
    }
    let b = copy_in(name, namelen as usize * 4).map_err(|_| EFAULT)?;
    let oid: alloc::vec::Vec<u32> = b.chunks_exact(4).map(|c| u32::from_le_bytes(c.try_into().unwrap())).collect();
    if oid[0] == 0 {
        // Meta nodes: {0, 3} name to OID (the name is the "new" value)
        if oid[1] == 3 && namelen == 2 && new != 0 {
            let n = copy_in(new, (newlen as usize).min(256)).map_err(|_| EFAULT)?;
            let Some((o, _)) = tmp::sysctl_name(&n) else { return Err(ENOENT) };
            let bytes: alloc::vec::Vec<u8> = o.iter().flat_map(|v| v.to_le_bytes()).collect();
            return answer(&bytes, old, oldlenp);
        }
        return Err(ENOENT);
    }
    let node = tmp::sysctl_oid(&oid).ok_or(ENOENT)?;
    node_value(f, node, old, oldlenp, new, newlen)
}

/// `__sysctlbyname(name, namelen, old, oldlenp, new, newlen)`.
// wave12 FK temporary: moves to lx-proc in stage 2
pub fn sysctlbyname(f: &SyscallFrame, a: [u64; 6]) -> Result<i64, i64> {
    let [name, namelen, old, oldlenp, new, newlen] = a;
    if namelen == 0 || namelen > 256 {
        return Err(EINVAL);
    }
    let n = copy_in(name, namelen as usize).map_err(|_| EFAULT)?;
    let (_, node) = tmp::sysctl_name(&n).ok_or(ENOENT)?;
    node_value(f, node, old, oldlenp, new, newlen)
}

/// Answers `value` the `sysctl` way: no buffer, only the size; a too small one, what fits
/// and `ENOMEM`.
fn answer(value: &[u8], old: u64, oldlenp: u64) -> Result<i64, i64> {
    if oldlenp == 0 {
        return Ok(0);
    }
    let cap = if old != 0 { Some(u64::from_le_bytes(copy_in(oldlenp, 8).map_err(|_| EFAULT)?[0..8].try_into().unwrap()) as usize) } else { None };
    let (n, short) = tmp::sysctl_fit(value.len(), cap);
    if n > 0 {
        copy_out(old, &value[..n]).map_err(|_| EFAULT)?;
    }
    let len = if cap.is_some() { n } else { value.len() };
    copy_out(oldlenp, &(len as u64).to_le_bytes()).map_err(|_| EFAULT)?;
    if short {
        Err(ENOMEM)
    } else {
        Ok(0)
    }
}

/// The value of `node` (a write is refused, except `kern.proc.osrel`'s, which is ignored).
fn node_value(f: &SyscallFrame, node: Node, old: u64, oldlenp: u64, new: u64, newlen: u64) -> Result<i64, i64> {
    if new != 0 && newlen != 0 && node != Node::ProcOsrel {
        return Err(EPERM);
    }
    if let Some(v) = tmp::sysctl_const(node) {
        return answer(v, old, oldlenp);
    }
    let int = |v: i32| v.to_le_bytes().to_vec();
    let ncpu = crate::arch::smp::online().max(1) as i32;
    let v: alloc::vec::Vec<u8> = match node {
        Node::Osrevision => int(199_506),
        Node::Osreldate | Node::ProcOsrel => int(super::abi::FREEBSD_OSRELDATE as i32),
        Node::Usrstack => crate::memory::vm::STACK_TOP.to_le_bytes().to_vec(),
        Node::Argmax => int(262_144),
        Node::Ngroups => int(1023),
        Node::Ncpu => int(ncpu),
        Node::Maxid => int(ncpu - 1),
        Node::Pagesize => int(4096),
        Node::Pagesizes => [4096u64, 0x20_0000, 0x4000_0000].iter().flat_map(|v| v.to_le_bytes()).collect(),
        Node::Overcommit => int(0),
        Node::Cpusetsize => int(128),
        Node::Cpusetsizemin => int(8),
        Node::Hostname => {
            // Linux uname's node name, through the caller's stack
            let s = (f.rsp.wrapping_sub(512 + 400)) & !0xF;
            if linux_call(63, [s, 0, 0, 0, 0, 0]) != 0 {
                return Err(EFAULT);
            }
            let u = copy_in(s + 65, 65).map_err(|_| EFAULT)?;
            let n = u.iter().position(|&c| c == 0).unwrap_or(64);
            let mut h = u[..n].to_vec();
            h.push(0);
            h
        }
        Node::Physmem => {
            let s = (f.rsp.wrapping_sub(512 + 128)) & !0xF;
            if linux_call(99, [s, 0, 0, 0, 0, 0]) != 0 {
                return Err(EFAULT);
            }
            let i = copy_in(s, 112).map_err(|_| EFAULT)?;
            let total = u64::from_le_bytes(i[32..40].try_into().unwrap());
            let unit = u32::from_le_bytes(i[104..108].try_into().unwrap()).max(1) as u64;
            (total * unit).to_le_bytes().to_vec()
        }
        Node::Arandom => {
            // Up to 256 random bytes straight into the caller's buffer
            if old == 0 || oldlenp == 0 {
                return answer(&[0u8; 256], 0, oldlenp);
            }
            let cap = u64::from_le_bytes(copy_in(oldlenp, 8).map_err(|_| EFAULT)?[0..8].try_into().unwrap()).min(256);
            let r = linux_call(318, [old, cap, 0, 0, 0, 0]);
            if r < 0 {
                return Err(r);
            }
            copy_out(oldlenp, &(r as u64).to_le_bytes()).map_err(|_| EFAULT)?;
            return Ok(0);
        }
        Node::Ostype | Node::Osrelease | Node::Version | Node::Machine => return Err(ENOENT),
    };
    answer(&v, old, oldlenp)
}
