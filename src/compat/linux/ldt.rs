//! # Segment system calls: `set_thread_area`, `get_thread_area`, `modify_ldt`, `arch_prctl`
//!
//! The Linux calls through which a 64-bit process sets up segments for its 32-bit code
//! (Wine's WoW64 mode: the 32-bit Windows thread block is reached through `fs`), and the
//! FS/GS base calls of `arch_prctl`. Semantics follow Linux's `arch/x86/kernel/tls.c`,
//! `ldt.c` and `process_64.c`; the CPU side is in [`crate::arch::segments`].
//!
//! Differences from Linux: only 32-bit data segments are accepted in the LDT (Linux also
//! takes code and 16-bit segments), and a changed LDT reaches other CPUs running the
//! process's threads at their next context switch rather than by an interrupt at once.

use alloc::sync::Arc;
use alloc::vec;
use spin::Mutex;

use super::types::{EINVAL, ENOSYS, EPERM, ESRCH};
use super::vfs::{copy_in, copy_out};
use crate::arch::gdt::{TLS_ENTRIES, TLS_ENTRY_MIN};
use crate::arch::segments::{self, Ldt, SharedLdt, UserDesc, LDT_ENTRIES};

/// `arch_prctl` codes.
const ARCH_SET_GS: u64 = 0x1001;
const ARCH_SET_FS: u64 = 0x1002;
const ARCH_GET_FS: u64 = 0x1003;
const ARCH_GET_GS: u64 = 0x1004;

/// Serializes LDT writers (Linux's `mm->context.lock`).
static LDT_WRITE: Mutex<()> = Mutex::new(());

/// `set_thread_area(2)`: sets one of the thread's three TLS descriptors (GDT entries
/// 12-14); entry -1 picks a free one and writes its number back.
///
/// # Arguments
/// * `uptr` - User pointer to a `struct user_desc`.
///
/// # Returns
/// 0, or `-EFAULT`, `-EINVAL` (bad entry or descriptor), `-ESRCH` (no free entry).
pub fn sys_set_thread_area(uptr: u64) -> i64 {
    let raw = match copy_in(uptr, 16) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let info = UserDesc::parse(&raw);
    let clear = info.is_empty() || info.is_zero();
    // Linux's tls_desc_okay: 32-bit, data, present
    if !clear && (!info.seg_32bit || info.contents > 1 || info.seg_not_present) {
        return -EINVAL;
    }
    let mut idx = info.entry_number as i32 as i64;
    if idx == -1 {
        let free = crate::task::with_current_task_mut(|t| t.segs.tls.iter().position(|d| *d == 0)).flatten();
        let Some(i) = free else { return -ESRCH };
        idx = (TLS_ENTRY_MIN + i) as i64;
        if let Err(e) = copy_out(uptr, &(idx as u32).to_le_bytes()) {
            return e;
        }
    }
    if idx < TLS_ENTRY_MIN as i64 || idx >= (TLS_ENTRY_MIN + TLS_ENTRIES) as i64 {
        return -EINVAL;
    }
    let desc = if clear { 0 } else { info.descriptor() };
    x86_64::instructions::interrupts::without_interrupts(|| {
        crate::task::with_current_task_mut(|t| segments::set_current_tls(&mut t.segs, idx as usize, desc));
    });
    0
}

/// `get_thread_area(2)`: reads one of the thread's TLS descriptors.
///
/// # Arguments
/// * `uptr` - User pointer to a `struct user_desc` whose `entry_number` names the entry.
///
/// # Returns
/// 0, or `-EFAULT`, `-EINVAL` (entry not 12-14).
pub fn sys_get_thread_area(uptr: u64) -> i64 {
    let raw = match copy_in(uptr, 4) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let idx = i32::from_le_bytes(raw[..4].try_into().unwrap()) as i64;
    if idx < TLS_ENTRY_MIN as i64 || idx >= (TLS_ENTRY_MIN + TLS_ENTRIES) as i64 {
        return -EINVAL;
    }
    let desc = crate::task::with_current_task_mut(|t| t.segs.tls[idx as usize - TLS_ENTRY_MIN]).unwrap_or(0);
    match copy_out(uptr, &UserDesc::from_descriptor(idx as u32, desc).bytes()) {
        Ok(()) => 0,
        Err(e) => e,
    }
}

/// `modify_ldt(2)`: reads (0), writes (1: old mode, 0x11: new mode) or reads the default
/// (2) Local Descriptor Table of the process.
///
/// # Arguments
/// * `func` - 0, 1, 2 or 0x11.
/// * `ptr` - User buffer (read) or `struct user_desc` (write).
/// * `bytecount` - Buffer size; 16 for a write.
///
/// # Returns
/// Bytes read, 0 after a write, or a negative errno, as an `int` in the low 32 bits of
/// the result like Linux (errors come back as 0x00000000ffffffea and so on).
pub fn sys_modify_ldt(func: u64, ptr: u64, bytecount: u64) -> i64 {
    let r = match func as i32 {
        0 => read_ldt(ptr, bytecount),
        1 => write_ldt(ptr, bytecount, true),
        2 => read_default_ldt(ptr, bytecount),
        0x11 => write_ldt(ptr, bytecount, false),
        _ => -ENOSYS,
    };
    r as i32 as u32 as i64
}

/// The current process's LDT holder, made (and given to every thread sharing the address
/// space) on first use.
fn ldt_holder() -> Option<SharedLdt> {
    let fresh: SharedLdt = Arc::new(Mutex::new(None));
    let mut sched = crate::task::SCHEDULER.lock();
    let (have, mm) = sched.current_task_mut(|t| (t.ldt.clone(), t.mm.as_ref().map(|m| Arc::as_ptr(m) as usize)))?;
    if let Some(h) = have {
        return Some(h);
    }
    let mm = mm?;
    sched.for_each_task_mut(|t| {
        if t.ldt.is_none() && t.mm.as_ref().map(|m| Arc::as_ptr(m) as usize) == Some(mm) {
            t.ldt = Some(fresh.clone());
        }
    });
    Some(fresh)
}

/// The current process's LDT, if it has one.
fn current_ldt() -> Option<Arc<Ldt>> {
    let holder = crate::task::with_current_task_mut(|t| t.ldt.clone()).flatten()?;
    let cur = x86_64::instructions::interrupts::without_interrupts(|| holder.lock().clone());
    cur
}

/// `modify_ldt` function 0: copies the LDT out, zero-filled to `bytecount`.
fn read_ldt(ptr: u64, bytecount: u64) -> i64 {
    let Some(ldt) = current_ldt() else { return 0 };
    let n = (bytecount as usize).min(LDT_ENTRIES * 8);
    let mut out = vec![0u8; n];
    for (i, d) in ldt.entries().iter().enumerate() {
        let off = i * 8;
        if off >= n {
            break;
        }
        let b = d.to_le_bytes();
        let k = (n - off).min(8);
        out[off..off + k].copy_from_slice(&b[..k]);
    }
    match copy_out(ptr, &out) {
        Ok(()) => n as i64,
        Err(e) => e,
    }
}

/// `modify_ldt` function 2: the default LDT, which is empty (128 zero bytes at most).
fn read_default_ldt(ptr: u64, bytecount: u64) -> i64 {
    let n = (bytecount as usize).min(128);
    match copy_out(ptr, &vec![0u8; n]) {
        Ok(()) => n as i64,
        Err(e) => e,
    }
}

/// `modify_ldt` functions 1 and 0x11: sets one LDT entry (Linux's `write_ldt`).
fn write_ldt(ptr: u64, bytecount: u64, oldmode: bool) -> i64 {
    if bytecount != 16 {
        return -EINVAL;
    }
    let raw = match copy_in(ptr, 16) {
        Ok(b) => b,
        Err(e) => return e,
    };
    let info = UserDesc::parse(&raw);
    let idx = info.entry_number as usize;
    if idx >= LDT_ENTRIES {
        return -EINVAL;
    }
    if info.contents == 3 && (oldmode || !info.seg_not_present) {
        return -EINVAL;
    }
    let clear = (oldmode && info.base_addr == 0 && info.limit == 0) || info.is_empty();
    let desc = if clear {
        0
    } else {
        if !info.supported() {
            return -EINVAL;
        }
        let d = info.descriptor();
        if oldmode {
            d & !(1 << 52)
        } else {
            d
        }
    };
    let Some(holder) = ldt_holder() else { return -EINVAL };
    let _w = LDT_WRITE.lock();
    let old = x86_64::instructions::interrupts::without_interrupts(|| holder.lock().clone());
    let old_entries = old.as_ref().map_or(&[][..], |l| l.entries());
    let mut entries = vec![0u64; old_entries.len().max(idx + 1)];
    entries[..old_entries.len()].copy_from_slice(old_entries);
    entries[idx] = desc;
    drop(old);
    segments::publish_ldt(&holder, Arc::new(Ldt::new(entries.into_boxed_slice())), idx);
    0
}

/// `int $0x80` from a 64-bit program: Linux (with `IA32_EMULATION`) runs it through the
/// 32-bit system call table, with the number in `eax` and arguments in `ebx`... Hydra
/// serves the two calls Wine makes this way, `set_thread_area` (243) and
/// `get_thread_area` (244), which the 64-bit table lacks; everything else is `-ENOSYS`.
/// A task with a seccomp filter gets `-ENOSYS` for all of them: its filter only judges
/// 64-bit calls, and `int $0x80` must not be a way around it.
///
/// # Arguments
/// * `eax` - 32-bit system call number.
/// * `ebx` - First argument (32 bits).
///
/// # Returns
/// The result for `rax`.
pub fn int80(eax: u64, ebx: u64) -> i64 {
    if crate::task::with_current_task_mut(|t| t.seccomp.mode != 0).unwrap_or(true) {
        return -ENOSYS;
    }
    match eax as u32 {
        243 => sys_set_thread_area(ebx as u32 as u64),
        244 => sys_get_thread_area(ebx as u32 as u64),
        _ => -ENOSYS,
    }
}

/// `arch_prctl(2)`: the FS and GS bases.
///
/// # Arguments
/// * `code` - `ARCH_SET_FS`, `ARCH_GET_FS`, `ARCH_SET_GS` or `ARCH_GET_GS`.
/// * `addr` - The new base, or a user pointer receiving the current one.
///
/// # Returns
/// 0, or `-EPERM` (base outside user space), `-EFAULT`, `-EINVAL` (other codes).
pub fn sys_arch_prctl(code: u64, addr: u64) -> i64 {
    match code {
        ARCH_SET_FS | ARCH_SET_GS => {
            // A non-canonical base would fault the kernel's wrmsr
            if addr >= crate::memory::vm::USER_SPACE_END {
                return -EPERM;
            }
            x86_64::instructions::interrupts::without_interrupts(|| {
                crate::task::with_current_task_mut(|t| {
                    if code == ARCH_SET_FS {
                        t.fs_base = addr;
                        segments::set_fs_base(&mut t.segs, addr);
                    } else {
                        segments::set_gs_base(&mut t.segs, addr);
                    }
                });
            });
            0
        }
        ARCH_GET_FS | ARCH_GET_GS => {
            let (fs, gs) = segments::current_bases();
            let v = if code == ARCH_GET_FS { fs } else { gs };
            match copy_out(addr, &v.to_le_bytes()) {
                Ok(()) => 0,
                Err(e) => e,
            }
        }
        _ => -EINVAL,
    }
}
