//! # The tracing calls' decisions (wave 10, Group 8-1)
//!
//! lx-proc decides who may trace and observe whom: `ptrace`'s attach family (`ATTACH`,
//! `SEIZE`, `TRACEME`, and options asking to suspend seccomp), `perf_event_open`,
//! `process_vm_readv`/`writev`, `kcmp` and `pidfd_getfd`. The mechanism stays in the kernel
//! (stopping and resuming, registers, memory, single-step, breakpoints, the counters), and
//! so do the requests on a tracee already attached: the kernel never sends them here.
//!
//! For each call: the kernel's facts (`LXP_TRACE_FACTS`: the targets resolved as the kernel
//! will run the call), the rule ([`rules::decide`], the kernel's `src/lx/ptrace_rules.rs`:
//! one copy for both), and a redirect to the kernel carrying the verdict's key, bound to
//! every fact ([`rules::key`]; the kernel keeps it as the call's approval mark), whose code reports the
//! verdict at the point where it checks permission (its own argument errors first). Facts
//! the kernel cannot gather (no such target, not a pidfd, an attribute that cannot be read)
//! are left to the kernel's code, which gives the same error.
//!
//! lx-proc changes nothing here, so a call cut by a crash is simply decided again.

use crate::policy::{Call, Kernel, Mem};
use crate::proto::*;

/// The kernel's rule, shared with the kernel.
#[allow(dead_code)]
#[path = "../../../../src/lx/ptrace_rules.rs"]
pub mod rules;

/// Whether lx-proc decides call `nr` here.
pub fn handles(nr: u64) -> bool {
    matches!(nr, rules::NR_PTRACE | rules::NR_PERF_EVENT_OPEN | rules::NR_PROCESS_VM_READV | rules::NR_PROCESS_VM_WRITEV | rules::NR_KCMP | rules::NR_PIDFD_GETFD)
}

/// `perf_event_attr`: bits word at byte 40, `exclude_kernel` bit 5.
const ATTR_BITS: usize = 40;
const EXCLUDE_KERNEL: u64 = 1 << 5;

/// What lx-proc answers a tracing call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// A redirect to the kernel carrying the verdict's key (0: none, the kernel decides).
    Kernel(u64),
}

/// Decides call `c` (one of [`handles`]'): always a redirect to the kernel, with the key of
/// the verdict when the facts could be had (the kernel keeps it as the call's approval mark;
/// no `LXP_APPROVE` round trip).
pub fn serve<K: Kernel, M: Mem>(k: &K, m: &M, c: &Call) -> Answer {
    let mut io = LxProcIo::EMPTY;
    io.a[0] = c.nr;
    io.a[1..7].copy_from_slice(&c.args);
    if c.nr == rules::NR_PERF_EVENT_OPEN {
        // (an attribute that cannot be read: the kernel's code gives EFAULT)
        let Ok(raw) = m.copy_in(c.args[0], ATTR_BITS + 8) else { return Answer::Kernel(0) };
        let bits = u64::from_le_bytes(raw[ATTR_BITS..ATTR_BITS + 8].try_into().unwrap());
        io.a[7] = if bits & EXCLUDE_KERNEL == 0 { rules::PERF_KERNEL as u64 } else { 0 };
    }
    if k.op(LXP_TRACE_FACTS, &mut io) < 0 {
        // The call fails before its permission check: the kernel's code says how
        return Answer::Kernel(0);
    }
    let facts = rules::Facts::decode(&io.a);
    Answer::Kernel(rules::key(&io.a, rules::verdict(rules::decide(&facts))))
}
