//! # `signalfd`
//!
//! A descriptor that receives signals as data: reading it takes pending signals from its
//! mask (normally blocked with `sigprocmask`, so they are not delivered to handlers) and
//! returns one 128-byte `struct signalfd_siginfo` per signal. It is readable in
//! `poll`/`select`/`epoll` while such a signal is pending. Posting a signal wakes the
//! process's waits, so no wait queue of its own is needed.
//!
//! `ssi_signo` is filled in, plus `ssi_code`, `ssi_pid` and `ssi_status` for `SIGCHLD`
//! (derived from the children's state: the process table does not record senders).

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

const EAGAIN: i64 = -11;
const EBADF: i64 = -9;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const EMFILE: i64 = -24;

const SFD_NONBLOCK: u64 = 0o4000;
const SFD_CLOEXEC: u64 = 0o2000000;
const SIGINFO_SIZE: usize = 128;

/// Represents an active Linux signal file descriptor (`signalfd`).
pub struct SignalFd {
    mask: AtomicU64,
    nonblock: AtomicBool,
    /// Process that created it (used by `poll`, which may not look up the caller).
    owner: u64,
}

impl SignalFd {
    /// Polls readiness of queued pending signals matching the descriptor's signal mask.
    pub fn poll_events(&self) -> u32 {
        if super::proc::pending_for(self.owner, self.mask.load(Ordering::Relaxed)) {
            0x0001
        } else {
            0
        }
    }

    /// Sets or clears non-blocking I/O mode on this signal descriptor.
    pub fn set_nonblock(&self, on: bool) {
        self.nonblock.store(on, Ordering::Relaxed);
    }

    /// Queries whether non-blocking mode is currently enabled on this descriptor.
    pub fn get_nonblock(&self) -> bool {
        self.nonblock.load(Ordering::Relaxed)
    }

    /// Reads structured `signalfd_siginfo` records for pending delivered signals.
    pub fn read(&self, buf: &mut [u8]) -> i64 {
        if buf.len() < SIGINFO_SIZE {
            return EINVAL;
        }
        loop {
            let mut n = 0;
            while n + SIGINFO_SIZE <= buf.len() {
                match super::proc::take_signal(self.mask.load(Ordering::Relaxed)) {
                    Some(sig) => {
                        let rec = &mut buf[n..n + SIGINFO_SIZE];
                        rec.fill(0);
                        rec[0..4].copy_from_slice(&sig.to_le_bytes()); // ssi_signo
                        if sig == super::proc::SIGCHLD {
                            // Programs check ssi_code before reaping (util-linux script)
                            let (code, pid, status) = super::proc::sigchld_details(self.owner);
                            rec[8..12].copy_from_slice(&code.to_le_bytes()); // ssi_code
                            rec[12..16].copy_from_slice(&(pid as u32).to_le_bytes()); // ssi_pid
                            rec[40..44].copy_from_slice(&status.to_le_bytes()); // ssi_status
                        }
                        n += SIGINFO_SIZE;
                    }
                    None => break,
                }
            }
            if n > 0 {
                return n as i64;
            }
            if self.get_nonblock() {
                return EAGAIN;
            }
            if super::proc::signal_pending() {
                return super::proc::ERESTARTSYS;
            }
            crate::task::wait::wait(None);
        }
    }
}

/// `signalfd4(fd, mask, sizemask, flags)` (and `signalfd` with no flags).
pub fn sys_signalfd4(fd: i64, mask_ptr: u64, size: u64, flags: u64) -> i64 {
    if size != 8 || flags & !(SFD_NONBLOCK | SFD_CLOEXEC) != 0 {
        return EINVAL;
    }
    if !crate::memory::vm::prefault_current(mask_ptr, 8, false) {
        return EFAULT;
    }
    // SIGKILL and SIGSTOP cannot be received through a signalfd
    let mask = unsafe { core::ptr::read_unaligned(mask_ptr as *const u64) } & !((1 << 8) | (1 << 18));
    if fd >= 0 {
        return crate::task::with_current_fds_mut(|fds| match fds.get(fd as usize) {
            Some(crate::fs::FileDescriptor::SignalFd(s)) => {
                s.mask.store(mask, Ordering::Relaxed);
                fd
            }
            _ => EINVAL,
        });
    }
    if fd != -1 {
        return EBADF;
    }
    let (_, pid) = super::proc::current_ids();
    let sfd = Arc::new(SignalFd { mask: AtomicU64::new(mask), nonblock: AtomicBool::new(flags & SFD_NONBLOCK != 0), owner: pid });
    crate::task::with_current_fds_mut(|fds| match fds.alloc_fd(crate::fs::FileDescriptor::SignalFd(sfd)) {
        Ok(n) => {
            fds.set_cloexec(n, flags & SFD_CLOEXEC != 0);
            n as i64
        }
        Err(_) => EMFILE,
    })
}
