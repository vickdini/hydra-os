//! POSIX message queues (`src/compat/linux/mqueue.rs`), the paths `tests/host` leaves: the
//! descriptor's answers, SIGEV_THREAD notification state in the status line, oversized
//! messages, descriptor exhaustion, missing queues, unknown numbers.

use std::ffi::CString;
use std::sync::{Arc, Mutex};

use hydra_hosttests_t33::compat::linux::{chardev::CharDevice, mqueue, NOFILE};
use hydra_hosttests_t33::fake;
use hydra_hosttests_t33::fs::FileDescriptor;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

fn call(n: u64, a: [u64; 6]) -> i64 {
    mqueue::dispatch(n, a).unwrap()
}

fn open(name: &str, flags: u64, attr: Option<[i64; 4]>) -> i64 {
    let c = CString::new(name).unwrap();
    let a = attr.map(|v| {
        let mut b = [0u8; 64];
        for (i, x) in v.iter().enumerate() {
            b[i * 8..i * 8 + 8].copy_from_slice(&x.to_le_bytes());
        }
        b
    });
    call(240, [c.as_ptr() as u64, flags, 0o600, a.as_ref().map_or(0, |b| b.as_ptr() as u64), 0, 0])
}

fn dev(fd: i64) -> Arc<dyn CharDevice> {
    match fake::fds(|t| t.get(fd as usize).cloned()) {
        Some(FileDescriptor::Device(d)) => d,
        _ => panic!("not a device"),
    }
}

/// A sink for SIGEV_THREAD notifications (glibc's netlink socket).
struct Sink(Mutex<Vec<Vec<u8>>>);
impl CharDevice for Sink {
    fn read(&self, _b: &mut [u8]) -> i64 {
        0
    }
    fn poll_events(&self) -> u32 {
        0
    }
    fn add_wait_queues(&self, _w: &mut hydra_hosttests_t33::task::wait::WaitSet) {}
    fn rdev(&self) -> u64 {
        0
    }
    fn path(&self) -> String {
        "socket:[netlink]".into()
    }
    fn set_nonblock(&self, _on: bool) {}
    fn nonblock(&self) -> bool {
        false
    }
    fn deliver_notification(&self, data: &[u8]) -> bool {
        self.0.lock().unwrap().push(data.to_vec());
        true
    }
}

#[test]
fn the_descriptor_and_its_status_line() {
    let _g = serial();
    fake::IPC_NS.set(33_001);
    let fd = open("t33-status", 0o100 | 2, Some([0, 4, 16, 0])); // O_CREAT | O_RDWR
    assert!(fd >= 3, "{fd}");
    let d = dev(fd);
    assert_eq!(d.write(b"x"), -22);
    assert_eq!(d.rdev(), 0);
    assert_eq!(d.path(), "/t33-status");
    let mut w = hydra_hosttests_t33::task::wait::WaitSet::new();
    d.add_wait_queues(&mut w);
    assert_eq!(w.queues.len(), 1);
    // SIGEV_THREAD: the sink is a descriptor, the cookie 32 bytes
    let sink = Arc::new(Sink(Mutex::new(Vec::new())));
    let sfd = fake::fds_mut(|t| t.alloc_fd(FileDescriptor::Device(sink.clone())).unwrap());
    let cookie = [7u8; 32];
    let mut sev = [0u8; 64];
    sev[0..8].copy_from_slice(&(cookie.as_ptr() as u64).to_le_bytes());
    sev[8..12].copy_from_slice(&(sfd as i32).to_le_bytes());
    sev[12..16].copy_from_slice(&2i32.to_le_bytes()); // SIGEV_THREAD
    assert_eq!(call(244, [fd as u64, sev.as_ptr() as u64, 0, 0, 0, 0]), 0);
    let mut buf = [0u8; 128];
    let n = d.read(&mut buf) as usize;
    let line = String::from_utf8_lossy(&buf[..n]).into_owned();
    assert!(line.contains("NOTIFY:2 ") && line.contains("NOTIFY_PID:1 "), "{line}");
    // A message to the empty queue fires it: the cookie goes to the sink
    let msg = b"hi";
    assert_eq!(call(242, [fd as u64, msg.as_ptr() as u64, 2, 0, 0, 0]), 0);
    assert_eq!(sink.0.lock().unwrap().len(), 1);
    let got = sink.0.lock().unwrap()[0].clone();
    assert_eq!(&got[..31], &cookie[..31]);
    assert_eq!(got[31], 1, "NOTIFY_WOKENUP in the last byte, as Linux");
    // SIGEV_THREAD with a descriptor that is not a device
    sev[8..12].copy_from_slice(&1i32.to_le_bytes());
    assert_eq!(call(244, [fd as u64, sev.as_ptr() as u64, 0, 0, 0, 0]), -9);
    // A message larger than the queue's message size, before anything is copied
    let big = vec![0u8; 64];
    assert_eq!(call(242, [fd as u64, big.as_ptr() as u64, 17, 0, 0, 0]), -90);
    let c = CString::new("t33-status").unwrap();
    assert_eq!(call(241, [c.as_ptr() as u64, 0, 0, 0, 0, 0]), 0);
}

#[test]
fn missing_queues_full_tables_and_other_numbers() {
    let _g = serial();
    fake::IPC_NS.set(33_002);
    let c = CString::new("t33-none").unwrap();
    assert_eq!(call(241, [c.as_ptr() as u64, 0, 0, 0, 0, 0]), -2);
    assert_eq!(open("t33-none", 2, None), -2);
    assert_eq!(call(241, [0, 0, 0, 0, 0, 0]), -14);
    // No descriptor left
    NOFILE.set(fake::fds(|t| (0..1024).find(|&i| t.get(i).is_none()).unwrap()));
    assert_eq!(open("t33-full", 0o100 | 2, None), -24);
    NOFILE.set(1024);
    // Operations on descriptors that are not queues
    let mut buf = [0u8; 16];
    assert_eq!(call(243, [1, buf.as_mut_ptr() as u64, 16, 0, 0, 0]), -9);
    assert_eq!(call(244, [500, 0, 0, 0, 0, 0]), -9);
    assert_eq!(call(245, [500, 0, 0, 0, 0, 0]), -9);
    assert!(mqueue::dispatch(39, [0; 6]).is_none());
    // getsetattr with bad pointers
    let fd = open("t33-attr", 0o100 | 2, None);
    let mut attr = [0u8; 64];
    assert_eq!(call(245, [fd as u64, 0, attr.as_mut_ptr() as u64, 0, 0, 0]), 0);
    assert_eq!(i64::from_le_bytes(attr[8..16].try_into().unwrap()) > 0, true, "maxmsg");
    let c = CString::new("t33-attr").unwrap();
    call(241, [c.as_ptr() as u64, 0, 0, 0, 0, 0]);
}
