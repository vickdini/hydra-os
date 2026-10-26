//! # Linux Pseudo-Filesystem Emulation
//!
//! Provides in-memory emulation for essential Linux virtual filesystems:
//! - `/dev/null`, `/dev/zero`, `/dev/urandom`
//! - `/proc/version`, `/proc/meminfo`, `/proc/cpuinfo`, `/proc/self/maps`

use crate::compat::linux::types::*;

pub enum PseudoFile {
    DevNull,
    DevZero,
    DevUrandom,
    ProcVersion,
    ProcMeminfo,
    ProcCpuinfo,
    ProcSelfMaps,
}

pub fn match_pseudo_path(path: &str) -> Option<PseudoFile> {
    match path {
        "/dev/null" => Some(PseudoFile::DevNull),
        "/dev/zero" => Some(PseudoFile::DevZero),
        "/dev/urandom" | "/dev/random" => Some(PseudoFile::DevUrandom),
        "/proc/version" => Some(PseudoFile::ProcVersion),
        "/proc/meminfo" => Some(PseudoFile::ProcMeminfo),
        "/proc/cpuinfo" => Some(PseudoFile::ProcCpuinfo),
        "/proc/self/maps" => Some(PseudoFile::ProcSelfMaps),
        _ => None,
    }
}

impl PseudoFile {
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
            PseudoFile::ProcSelfMaps => {
                let text = "00400000-00452000 r-xp 00000000 00:00 0 /bin/app\n00652000-00653000 rw-p 00052000 00:00 0 /bin/app\n7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0 [stack]\n";
                read_slice(text.as_bytes(), cursor, buf)
            }
        }
    }

    pub fn write(&self, buf: &[u8]) -> usize {
        match self {
            PseudoFile::DevNull | PseudoFile::DevZero | PseudoFile::DevUrandom => buf.len(),
            _ => 0, // /proc is read-only
        }
    }

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

fn read_slice(data: &[u8], cursor: usize, buf: &mut [u8]) -> usize {
    if cursor >= data.len() {
        return 0;
    }
    let available = &data[cursor..];
    let to_copy = available.len().min(buf.len());
    buf[..to_copy].copy_from_slice(&available[..to_copy]);
    to_copy
}
