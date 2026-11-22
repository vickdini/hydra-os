//! # The sound status page, read by the kernel (wave 8, Group S)
//!
//! The sound service writes each stream's state into a page the kernel keeps
//! ([`SndStatus`], `ipc/sound.rs`); `/proc/asound` (kept in the kernel) reads it. Plain Rust
//! over the protocol's types: the host tests (`tests/host-w8-s`) compile this file.

use alloc::string::String;

use crate::ipc::protocol::SndStatus;

/// `SNDRV_PCM_ACCESS_MMAP_INTERLEAVED`.
const ACCESS_MMAP_INTERLEAVED: u32 = 0;

/// A consistent copy of the record at `p` (the writer makes `seq` odd while it writes):
/// `None` if it kept changing.
///
/// # Safety
/// `p` points at a readable `SndStatus` for the whole call.
pub unsafe fn read_record(p: *const SndStatus) -> Option<SndStatus> {
    use core::sync::atomic::{fence, Ordering};
    for _ in 0..64 {
        // A seqlock reader: the sequence, then the record, then the sequence again
        let first = core::ptr::read_volatile(core::ptr::addr_of!((*p).seq));
        fence(Ordering::Acquire);
        let a = core::ptr::read_volatile(p);
        fence(Ordering::Acquire);
        let again = core::ptr::read_volatile(core::ptr::addr_of!((*p).seq));
        if first & 1 == 0 && first == again {
            return Some(SndStatus { seq: first, ..a });
        }
        core::hint::spin_loop();
    }
    None
}

/// The text of `/proc/asound/card0/pcm0{p,c}<file>` for a stream the sound service serves
/// (its record `st` in the status page).
pub fn proc_stream_text(file: &str, dir: usize, chip: &str, st: &SndStatus) -> Option<String> {
    let open = st.open != 0;
    match file {
        "/info" | "/sub0/info" => Some(alloc::format!(
            "card: 0\ndevice: 0\nsubdevice: 0\nstream: {}\nid: {} Analog\nname: {} Analog\nsubname: subdevice #0\nclass: 0\nsubclass: 0\nsubdevices_count: 1\nsubdevices_avail: {}\n",
            if dir == 0 { "PLAYBACK" } else { "CAPTURE" },
            chip,
            chip,
            !open as u32
        )),
        "/sub0/status" => Some(if !open {
            String::from("closed\n")
        } else {
            let name = ["OPEN", "SETUP", "PREPARED", "RUNNING", "XRUN", "DRAINING", "PAUSED"].get(st.state as usize).copied().unwrap_or("?");
            alloc::format!("state: {}\nowner_pid   : {}\nhw_ptr      : {}\nappl_ptr    : {}\n", name, st.owner, st.hw_ptr, st.appl_ptr)
        }),
        "/sub0/hw_params" => Some(if open && st.has_hw != 0 {
            alloc::format!(
                "access: {}\nformat: S16_LE\nsubformat: STD\nchannels: 2\nrate: {} ({}/1)\nperiod_size: {}\nbuffer_size: {}\n",
                if st.access == ACCESS_MMAP_INTERLEAVED { "MMAP_INTERLEAVED" } else { "RW_INTERLEAVED" },
                st.rate,
                st.rate,
                st.period_size,
                st.buffer_size
            )
        } else {
            String::from("closed\n")
        }),
        "/sub0/sw_params" => Some(if open && st.has_hw != 0 {
            alloc::format!(
                "tstamp_mode: {}\nperiod_step: 1\navail_min: {}\nstart_threshold: {}\nstop_threshold: {}\nsilence_threshold: {}\nsilence_size: {}\nboundary: {}\n",
                if st.tstamp_mode == 1 { "ENABLE" } else { "NONE" },
                st.avail_min,
                st.start_threshold,
                st.stop_threshold,
                st.silence_threshold,
                st.silence_size,
                st.boundary
            )
        } else {
            String::from("closed\n")
        }),
        _ => None,
    }
}
