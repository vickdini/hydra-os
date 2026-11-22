//! The kernel's `ipc/sound_page.rs`: the status page the sound service writes and
//! `/proc/asound` reads.

use hydra_hosttests_w8_s::ipc::protocol::{LxSndInfo, SndStatus, SND_STATUS_STRIDE};
use hydra_hosttests_w8_s::ipc::sound_page::{proc_stream_text, read_record};

#[test]
fn records_fit_their_stride() {
    assert!(core::mem::size_of::<SndStatus>() <= SND_STATUS_STRIDE);
    assert!(2 * SND_STATUS_STRIDE <= 4096);
    assert!(core::mem::size_of::<LxSndInfo>() < 4096);
}

#[test]
fn a_closed_stream() {
    let st = SndStatus::default();
    assert_eq!(proc_stream_text("/sub0/status", 0, "QEMU HDA", &st).unwrap(), "closed\n");
    assert_eq!(proc_stream_text("/sub0/hw_params", 0, "QEMU HDA", &st).unwrap(), "closed\n");
    let info = proc_stream_text("/info", 1, "QEMU HDA", &st).unwrap();
    assert!(info.contains("stream: CAPTURE\n"));
    assert!(info.contains("subdevices_avail: 1\n"));
    assert!(proc_stream_text("/sub0/nothing", 0, "x", &st).is_none());
}

#[test]
fn a_running_stream() {
    let st = SndStatus { open: 1, state: 3, has_hw: 1, access: 0, rate: 48000, owner: 1234, period_size: 512, buffer_size: 16384, hw_ptr: 100, appl_ptr: 4196, avail_min: 512, boundary: 1 << 62, ..Default::default() };
    let s = proc_stream_text("/sub0/status", 0, "QEMU HDA", &st).unwrap();
    assert!(s.starts_with("state: RUNNING\n"));
    assert!(s.contains("owner_pid   : 1234\n"));
    assert!(s.contains("hw_ptr      : 100\n"));
    let h = proc_stream_text("/sub0/hw_params", 0, "QEMU HDA", &st).unwrap();
    assert!(h.contains("access: MMAP_INTERLEAVED\n"));
    assert!(h.contains("rate: 48000 (48000/1)\n"));
    assert!(h.contains("buffer_size: 16384\n"));
    let w = proc_stream_text("/sub0/sw_params", 0, "QEMU HDA", &st).unwrap();
    assert!(w.contains("avail_min: 512\n"));
    assert!(proc_stream_text("/sub0/info", 0, "QEMU HDA", &st).unwrap().contains("subdevices_avail: 0\n"));
    let rw = SndStatus { access: 3, ..st };
    assert!(proc_stream_text("/sub0/hw_params", 0, "x", &rw).unwrap().contains("RW_INTERLEAVED"));
}

#[test]
fn a_record_being_written_is_not_read() {
    let mut st = SndStatus { open: 1, seq: 4, ..Default::default() };
    // SAFETY: a live local record
    assert_eq!(unsafe { read_record(&st) }, Some(st));
    st.seq = 5;
    // SAFETY: as above
    assert_eq!(unsafe { read_record(&st) }, None);
}
