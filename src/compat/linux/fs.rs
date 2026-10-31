//! # Linux Compatibility: Pseudo-Filesystem Emulation (`/dev` & `/proc`)
//!
//! Provides synthetic in-memory emulation for essential Linux virtual filesystems
//! (`/dev/null`, `/dev/zero`, `/dev/urandom`, and `/proc/*` informational nodes).
//!
//! ## Architectural Role & Design Rationale
//! Standard C libraries (`musl`, `glibc`), dynamic linkers, and system utilities query
//! `/dev` and `/proc` during startup to seed random number generators, discover memory
//! and CPU topology, and inspect the current process's executable path or auxiliary vector.
//! This module synthesizes these files on-the-fly from live kernel state without requiring
//! backing storage on the ZFS pool.
//!
//! ## Key Types & Interfaces
//! - [`PseudoFile`]: Enumeration of supported virtual device and `/proc` nodes.
//! - [`match_pseudo_path()`]: Resolves a canonical path string to a [`PseudoFile`] variant.
//! - [`proc_link()`]: Resolves dynamic `/proc/self/cwd` and `/proc/self/exe` symbolic links.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Reads PIT tick counter ([`crate::arch::pit::ticks`]) to seed PRNG
//!   for `/dev/urandom`.
//! - Concurrency: Stateless enum variants reading atomic/spinlock-guarded kernel metrics.

use crate::compat::linux::types::*;

/// Identifies an emulated Linux virtual file under `/dev` or `/proc`.
pub enum PseudoFile {
    /// `/dev/null`: discards all writes and immediately returns EOF (`0` bytes) on read.
    DevNull,
    /// `/dev/zero`: discards all writes and fills read buffers with zero bytes (`0x00`).
    DevZero,
    /// `/dev/urandom` and `/dev/random`: generates pseudo-random bytes on read.
    DevUrandom,
    /// `/proc/version`: reports the kernel release and compiler version banner.
    ProcVersion,
    /// `/proc/meminfo`: reports total and free kernel heap memory in `kB`.
    ProcMeminfo,
    /// `/proc/cpuinfo`: reports `x86_64` processor identification and feature flags.
    ProcCpuinfo,
    /// `/proc/self/maps`: reports the virtual memory regions of the calling process.
    ProcSelfMaps,
    /// `/proc/self/auxv`: exposes the raw ELF auxiliary vector of the calling process.
    ProcSelfAuxv,
}

/// Matches a normalized filesystem path against known `/dev` and `/proc` pseudo-files.
///
/// # Arguments
/// * `path` - Absolute path string to inspect.
///
/// # Returns
/// * `Some(PseudoFile)` if `path` names a recognized virtual device or `/proc` entry.
/// * `None` if `path` should be resolved against the real ZFS filesystem.
pub fn match_pseudo_path(path: &str) -> Option<PseudoFile> {
    match path {
        "/dev/null" => Some(PseudoFile::DevNull),
        "/dev/zero" => Some(PseudoFile::DevZero),
        "/dev/urandom" | "/dev/random" => Some(PseudoFile::DevUrandom),
        "/proc/version" => Some(PseudoFile::ProcVersion),
        "/proc/meminfo" => Some(PseudoFile::ProcMeminfo),
        "/proc/cpuinfo" => Some(PseudoFile::ProcCpuinfo),
        "/proc/self/maps" => Some(PseudoFile::ProcSelfMaps),
        "/proc/self/auxv" => Some(PseudoFile::ProcSelfAuxv),
        _ => None,
    }
}

impl PseudoFile {
    /// Synthesizes data for a read operation on this pseudo-file starting at `cursor`.
    ///
    /// # Arguments
    /// * `cursor` - Current byte offset within the open file description.
    /// * `buf` - Destination slice to fill with synthesized bytes.
    ///
    /// # Returns
    /// Number of bytes written into `buf` (`0` indicates end-of-file).
    pub fn read(&self, cursor: usize, buf: &mut [u8]) -> usize {
        match self {
            PseudoFile::DevNull => 0,
            PseudoFile::DevZero => {
                buf.fill(0);
                buf.len()
            }
            PseudoFile::DevUrandom => {
                // Generate pseudo-random bytes using PIT ticks and linear-feedback PRNG
                let mut seed = crate::arch::pit::ticks().wrapping_mul(0x5DEECE66D).wrapping_add(11);
                for byte in buf.iter_mut() {
                    seed = seed.wrapping_mul(0x5DEECE66D).wrapping_add(11);
                    *byte = (seed >> 16) as u8;
                }
                buf.len()
            }
            PseudoFile::ProcVersion => {
                let content = b"Linux version 6.8.0-hydra (gcc-13 / rustc-1.80) #1 SMP PREEMPT Hydra Microkernel\n";
                read_slice(content, cursor, buf)
            }
            PseudoFile::ProcMeminfo => {
                let st = crate::memory::heap::stats();
                let text = alloc::format!(
                    "MemTotal:       {:8} kB\nMemFree:        {:8} kB\nMemAvailable:   {:8} kB\nBuffers:               0 kB\nCached:                0 kB\n",
                    st.total_bytes / 1024,
                    st.free_bytes / 1024,
                    st.free_bytes / 1024
                );
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcCpuinfo => {
                let text = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 1\nmodel name\t: x86_64 Hydra Virtual CPU\nflags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss syscall nx lm\n\n";
                read_slice(text.as_bytes(), cursor, buf)
            }
            PseudoFile::ProcSelfAuxv => {
                let auxv = super::process::current_auxv();
                read_slice(&auxv, cursor, buf)
            }
            PseudoFile::ProcSelfMaps => {
                let text = "00400000-00452000 r-xp 00000000 00:00 0 /bin/app\n00652000-00653000 rw-p 00052000 00:00 0 /bin/app\n7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n";
                read_slice(text.as_bytes(), cursor, buf)
            }
        }
    }

    /// Handles a write operation on this pseudo-file.
    ///
    /// Character devices (`/dev/null`, `/dev/zero`, `/dev/urandom`) absorb all bytes;
    /// `/proc` entries are read-only and return `0`.
    ///
    /// # Arguments
    /// * `buf` - Slice of bytes written by the caller.
    ///
    /// # Returns
    /// Number of bytes consumed (`buf.len()` for `/dev/*`, `0` for `/proc/*`).
    pub fn write(&self, buf: &[u8]) -> usize {
        match self {
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevUrandom => buf.len(),
            _ => 0, // /proc is read-only
        }
    }

    /// Populates a [`LinuxStat`] buffer with synthetic inode metadata for this pseudo-file.
    ///
    /// # Arguments
    /// * `statbuf` - Mutable [`LinuxStat`] structure to fill.
    pub fn stat(&self, statbuf: &mut LinuxStat) {
        statbuf.st_dev = 1;
        statbuf.st_ino = 1;
        statbuf.st_nlink = 1;
        statbuf.st_uid = 0;
        statbuf.st_gid = 0;
        statbuf.st_blksize = 4096;

        match self {
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevUrandom => {
                statbuf.st_mode = S_IFCHR | 0o666;
                statbuf.st_size = 0;
            }
            _ => {
                statbuf.st_mode = S_IFREG | 0o444;
                statbuf.st_size = 512;
            }
        }
    }
}

/// Copies a window of `data` starting at `cursor` into `buf`.
fn read_slice(data: &[u8], cursor: usize, buf: &mut [u8]) -> usize {
    if cursor >= data.len() {
        return 0;
    }
    let available = &data[cursor..];
    let to_copy = available.len().min(buf.len());
    buf[..to_copy].copy_from_slice(&available[..to_copy]);
    to_copy
}

/// Resolves the target of a `/proc/self/*` symbolic link (`/proc/self/exe`, `/proc/self/cwd`).
///
/// # Arguments
/// * `path` - Absolute `/proc` path to inspect.
///
/// # Returns
/// * `Some(String)` containing the target path if `path` is a known `/proc/self` symlink.
/// * `None` if `path` is not a dynamic `/proc` symlink.
pub fn proc_link(path: &str) -> Option<alloc::string::String> {
    match path {
        "/proc/self/cwd" => Some(crate::task::with_current_fds_mut(|fds| fds.cwd_path.clone())),
        "/proc/self/exe" => crate::task::with_current_task_mut(|t| alloc::string::String::from(t.exe_path())),
        _ => None,
    }
}

