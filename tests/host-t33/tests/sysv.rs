//! System V IPC (`src/compat/linux/sysv.rs`), the paths `tests/host` leaves: the INFO and
//! STAT commands of semaphores and message queues, permission refusals for other users,
//! bad indexes and sizes, unknown commands and numbers.

use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::sysv;
use hydra_hosttests_t33::fake;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

fn call(n: u64, a: [u64; 6]) -> i64 {
    sysv::dispatch(n, a).unwrap()
}

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const MSG_STAT: u64 = 11;
const MSG_INFO: u64 = 12;
const SEM_STAT: u64 = 18;
const SEM_INFO: u64 = 19;
const GETVAL: u64 = 12;
const SETVAL: u64 = 16;

fn other_user() {
    fake::CREDS.set((1000, 1000));
    fake::UID.set(1000);
    fake::CAPS.set(Some(0));
}

fn root() {
    fake::CREDS.set((0, 0));
    fake::UID.set(0);
    fake::CAPS.set(Some(u64::MAX >> 1));
}

#[test]
fn semaphore_info_stat_and_refusals() {
    let _g = serial();
    fake::IPC_NS.set(33_100);
    root();
    let id = call(64, [IPC_PRIVATE, 3, IPC_CREAT | 0o600, 0, 0, 0]);
    assert!(id >= 0, "{id}");
    let mut info = [0u8; 40];
    let max = call(66, [0, 0, SEM_INFO, info.as_mut_ptr() as u64, 0, 0]);
    assert!(max >= 0);
    let ints: Vec<i32> = info.chunks(4).map(|c| i32::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!((ints[0], ints[2]), (1, 3), "one set of three in this namespace");
    assert!(call(66, [0, 0, IPC_INFO, info.as_mut_ptr() as u64, 0, 0]) >= 0);
    assert_eq!(i32::from_le_bytes(info[8..12].try_into().unwrap()), i32::MAX);
    assert_eq!(call(66, [0, 0, SEM_INFO, 0, 0, 0]), -14);
    // SEM_STAT by index
    let mut ds = [0u8; 128];
    let idx = (id as u64) & 0x7fff;
    assert_eq!(call(66, [idx, 0, SEM_STAT, ds.as_mut_ptr() as u64, 0, 0]), id);
    assert_eq!(call(66, [0x7ffe, 0, SEM_STAT, ds.as_mut_ptr() as u64, 0, 0]), -22);
    // Another namespace does not see it
    fake::IPC_NS.set(33_101);
    assert_eq!(call(66, [id as u64, 0, GETVAL, 0, 0, 0]), -22);
    fake::IPC_NS.set(33_100);
    // Bad semaphore number
    assert_eq!(call(66, [id as u64, 9, GETVAL, 0, 0, 0]), -22);
    assert_eq!(call(66, [id as u64, 0, 77, 0, 0, 0]), -22, "unknown command");
    // Another user: no read, no write, not the owner
    other_user();
    assert_eq!(call(66, [id as u64, 0, GETVAL, 0, 0, 0]), -13);
    assert_eq!(call(66, [id as u64, 0, SETVAL, 1, 0, 0]), -13);
    assert_eq!(call(66, [id as u64, 0, IPC_STAT, ds.as_mut_ptr() as u64, 0, 0]), -13);
    assert_eq!(call(66, [id as u64, 0, IPC_RMID, 0, 0, 0]), -1);
    assert_eq!(call(66, [id as u64, 0, IPC_SET, ds.as_ptr() as u64, 0, 0]), -1);
    let sop = [0u8; 6];
    assert_eq!(call(65, [id as u64, sop.as_ptr() as u64, 1, 0, 0, 0]), -13);
    root();
    assert_eq!(call(66, [id as u64, 0, IPC_RMID, 0, 0, 0]), 0);
    assert_eq!(call(66, [id as u64, 0, IPC_RMID, 0, 0, 0]), -22);
}

#[test]
fn message_queue_info_stat_and_refusals() {
    let _g = serial();
    fake::IPC_NS.set(33_200);
    root();
    let q = call(68, [IPC_PRIVATE, IPC_CREAT | 0o600, 0, 0, 0, 0]);
    assert!(q >= 0);
    let mut m = vec![0u8; 8 + 5];
    m[..8].copy_from_slice(&3i64.to_le_bytes());
    m[8..].copy_from_slice(b"hello");
    assert_eq!(call(69, [q as u64, m.as_ptr() as u64, 5, 0, 0, 0]), 0);
    let mut info = [0u8; 32];
    assert!(call(71, [0, MSG_INFO, info.as_mut_ptr() as u64, 0, 0, 0]) >= 0);
    let ints: Vec<i32> = info.chunks(4).map(|c| i32::from_le_bytes(c.try_into().unwrap())).collect();
    assert_eq!((ints[0], ints[1], ints[6]), (1, 1, 5), "queues, messages, bytes");
    assert!(call(71, [0, IPC_INFO, info.as_mut_ptr() as u64, 0, 0, 0]) >= 0);
    assert_eq!(call(71, [0, MSG_INFO, 0, 0, 0, 0]), -14);
    let mut ds = [0u8; 120];
    assert_eq!(call(71, [(q as u64) & 0x7fff, MSG_STAT, ds.as_mut_ptr() as u64, 0, 0, 0]), q);
    assert_eq!(call(71, [0x7ffe, MSG_STAT, ds.as_mut_ptr() as u64, 0, 0, 0]), -22);
    assert_eq!(call(71, [q as u64, 77, 0, 0, 0, 0]), -22, "unknown command");
    assert_eq!(call(71, [q as u64, IPC_STAT, 0, 0, 0, 0]), -14);
    // Receiving: a negative size, a too small buffer
    let mut buf = vec![0u8; 64];
    assert_eq!(call(70, [q as u64, buf.as_mut_ptr() as u64, (-1i64) as u64, 0, 0, 0]), -22);
    assert_eq!(call(70, [q as u64, buf.as_mut_ptr() as u64, 2, 0, 0, 0]), -7, "E2BIG without MSG_NOERROR");
    // Another user
    other_user();
    assert_eq!(call(70, [q as u64, buf.as_mut_ptr() as u64, 64, 0, 0, 0]), -13);
    assert_eq!(call(69, [q as u64, m.as_ptr() as u64, 5, 0, 0, 0]), -13);
    assert_eq!(call(71, [q as u64, IPC_STAT, ds.as_mut_ptr() as u64, 0, 0, 0]), -13);
    assert_eq!(call(71, [q as u64, IPC_RMID, 0, 0, 0, 0]), -1);
    root();
    // Received by type (the lowest type up to |-5|)
    assert_eq!(call(70, [q as u64, buf.as_mut_ptr() as u64, 64, (-5i64) as u64, 0, 0]), 5);
    assert_eq!(&buf[8..13], b"hello");
    assert_eq!(call(71, [q as u64, IPC_RMID, 0, 0, 0, 0]), 0);
    assert_eq!(call(71, [q as u64, IPC_RMID, 0, 0, 0, 0]), -22);
    assert!(sysv::dispatch(39, [0; 6]).is_none());
}

#[test]
fn shared_memory_refusals() {
    let _g = serial();
    fake::IPC_NS.set(33_300);
    root();
    let id = call(29, [IPC_PRIVATE, 4096, IPC_CREAT | 0o600, 0, 0, 0]);
    assert!(id >= 0);
    let mut ds = [0u8; 112];
    other_user();
    assert_eq!(call(31, [id as u64, IPC_STAT, ds.as_mut_ptr() as u64, 0, 0, 0]), -13);
    assert_eq!(call(31, [id as u64, IPC_RMID, 0, 0, 0, 0]), -1);
    assert_eq!(call(31, [id as u64, IPC_SET, ds.as_ptr() as u64, 0, 0, 0]), -1);
    root();
    assert_eq!(call(31, [id as u64, 77, 0, 0, 0, 0]), -22);
    assert_eq!(call(31, [0x7fff_fff0, IPC_STAT, ds.as_mut_ptr() as u64, 0, 0, 0]), -22);
    assert_eq!(call(31, [id as u64, IPC_RMID, 0, 0, 0, 0]), 0);
    // shmdt of an address nothing is attached at
    assert_eq!(call(67, [0x1000_0000, 0, 0, 0, 0, 0]), -22);
}
