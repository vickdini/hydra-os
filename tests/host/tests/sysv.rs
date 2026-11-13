//! Tests for System V IPC (`src/compat/linux/sysv.rs`): shared memory,
//! semaphore sets and message queues, driven through `sysv::dispatch` with
//! the x86-64 syscall numbers, exactly as `syscall(2)` reaches them.
//!
//! The kernel keeps one global IPC table; each test runs in its own IPC
//! namespace and pid (see `setup`), so tests stay independent in parallel.
//! User pointers are host pointers: with no current `Mm`, `copy_in` and
//! `copy_out` copy directly, as in the kernel.

mod common;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use hydra_hosttests::compat::linux::sysv::{dispatch, forget_process, on_fork};
use hydra_hosttests::fake;
use hydra_hosttests::memory::frame_allocator::FRAME_ALLOCATOR;
use hydra_hosttests::memory::vm::{Mm, PROT_READ, PROT_WRITE, USER_SPACE_START};
use spin::Mutex;

const SHMGET: u64 = 29;
const SHMAT: u64 = 30;
const SHMCTL: u64 = 31;
const SEMGET: u64 = 64;
const SEMOP: u64 = 65;
const SEMCTL: u64 = 66;
const SHMDT: u64 = 67;
const MSGGET: u64 = 68;
const MSGSND: u64 = 69;
const MSGRCV: u64 = 70;
const MSGCTL: u64 = 71;
const SEMTIMEDOP: u64 = 220;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EINTR: i64 = -4;
const E2BIG: i64 = -7;
const EAGAIN: i64 = -11;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EFBIG: i64 = -27;
const ERANGE: i64 = -34;
const ENOMSG: i64 = -42;

const IPC_PRIVATE: u64 = 0;
const IPC_CREAT: u64 = 0o1000;
const IPC_EXCL: u64 = 0o2000;
const IPC_NOWAIT: u64 = 0o4000;
const IPC_RMID: u64 = 0;
const IPC_SET: u64 = 1;
const IPC_STAT: u64 = 2;
const IPC_INFO: u64 = 3;
const SHM_RDONLY: u64 = 0o10000;
const SHM_RND: u64 = 0o20000;
const SHM_REMAP: u64 = 0o40000;
const SHM_STAT: u64 = 13;
const SHM_INFO: u64 = 14;
const GETPID: u64 = 11;
const GETVAL: u64 = 12;
const GETALL: u64 = 13;
const GETNCNT: u64 = 14;
const GETZCNT: u64 = 15;
const SETVAL: u64 = 16;
const SETALL: u64 = 17;
const SEM_UNDO: i16 = 0x1000;
const MSG_NOERROR: u64 = 0o10000;
const MSG_EXCEPT: u64 = 0o20000;
const MSG_COPY: u64 = 0o40000;
const CAP_IPC_OWNER: u64 = 1 << 15;
const CAP_SYS_RESOURCE: u64 = 1 << 24;

const P: u64 = 4096;
const A: u64 = USER_SPACE_START + 0x3000_0000;

static NEXT: AtomicU64 = AtomicU64::new(1000);

/// Fresh fakes, a private IPC namespace and pid; returns the pid.
fn setup() -> u64 {
    fake::reset();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    fake::IPC_NS.set(n);
    fake::IDS.set((n, n));
    fake::CREDS.set((1000, 1000));
    n
}

fn sys(num: u64, a: [u64; 6]) -> i64 {
    dispatch(num, a).expect("a SysV syscall number")
}

fn ptr<T>(v: &mut [T]) -> u64 {
    v.as_mut_ptr() as u64
}

// --------------------------------------------------------------- helpers

fn shmget(key: u64, size: u64, flags: u64) -> i64 {
    sys(SHMGET, [key, size, flags, 0, 0, 0])
}
fn shmat(id: i64, addr: u64, flags: u64) -> i64 {
    sys(SHMAT, [id as u64, addr, flags, 0, 0, 0])
}
fn shmdt(addr: u64) -> i64 {
    sys(SHMDT, [addr, 0, 0, 0, 0, 0])
}
fn shmctl(id: i64, cmd: u64, buf: u64) -> i64 {
    sys(SHMCTL, [id as u64, cmd, buf, 0, 0, 0])
}
fn semget(key: u64, n: u64, flags: u64) -> i64 {
    sys(SEMGET, [key, n, flags, 0, 0, 0])
}
fn semctl(id: i64, num: u64, cmd: u64, arg: u64) -> i64 {
    sys(SEMCTL, [id as u64, num, cmd, arg, 0, 0])
}
/// `struct sembuf` array.
fn sembufs(ops: &[(u16, i16, i16)]) -> Vec<u8> {
    ops.iter().flat_map(|&(n, op, f)| [n.to_le_bytes(), op.to_le_bytes(), f.to_le_bytes()].concat()).collect()
}
fn semop(id: i64, ops: &[(u16, i16, i16)]) -> i64 {
    let mut b = sembufs(ops);
    sys(SEMOP, [id as u64, ptr(&mut b), ops.len() as u64, 0, 0, 0])
}
fn msgget(key: u64, flags: u64) -> i64 {
    sys(MSGGET, [key, flags, 0, 0, 0, 0])
}
fn msgsnd(id: i64, mtype: i64, data: &[u8], flags: u64) -> i64 {
    let mut b = [&mtype.to_le_bytes()[..], data].concat();
    sys(MSGSND, [id as u64, ptr(&mut b), data.len() as u64, flags, 0, 0])
}
/// Returns (result, mtype, data).
fn msgrcv(id: i64, size: usize, msgtyp: i64, flags: u64) -> (i64, i64, Vec<u8>) {
    let mut b = vec![0u8; 8 + size];
    let r = sys(MSGRCV, [id as u64, ptr(&mut b), size as u64, msgtyp as u64, flags, 0]);
    let mtype = i64::from_le_bytes(b[..8].try_into().unwrap());
    let n = r.max(0) as usize;
    (r, mtype, b[8..8 + n].to_vec())
}
fn msgctl(id: i64, cmd: u64, buf: u64) -> i64 {
    sys(MSGCTL, [id as u64, cmd, buf, 0, 0, 0])
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}

/// Shared-memory tests: exclusive frame pool, an address space for the
/// caller, and a leak check at the end (every segment must be removed).
fn with_shm(f: impl FnOnce(u64, &Arc<Mutex<Mm>>)) {
    let _g = common::serial();
    common::global_frames();
    let pid = setup();
    let before = FRAME_ALLOCATOR.lock().allocated_memory();
    {
        let mm = Arc::new(Mutex::new(Mm::new().unwrap()));
        fake::TASK_MM.with_borrow_mut(|m| *m = Some(mm.clone()));
        f(pid, &mm);
        fake::TASK_MM.with_borrow_mut(|m| *m = None);
    }
    assert_eq!(FRAME_ALLOCATOR.lock().allocated_memory(), before, "frames leaked (segment not removed?)");
}

// ================================================================ shm

#[test]
fn shmget_creates_and_finds_by_key() {
    setup();
    let a = shmget(IPC_PRIVATE, P, 0o600);
    let b = shmget(IPC_PRIVATE, P, 0o600);
    assert!(a > 0 && b > 0 && a != b, "IPC_PRIVATE always creates");
    let k = shmget(0x1234, 2 * P, IPC_CREAT | 0o600);
    assert!(k > 0);
    assert_eq!(shmget(0x1234, 0, 0), k, "found by key");
    assert_eq!(shmget(0x1234, P, 0o600), k, "smaller size is fine");
    assert_eq!(shmget(0x1234, 3 * P, 0), EINVAL, "larger than the segment");
    assert_eq!(shmget(0x1234, P, IPC_CREAT | IPC_EXCL | 0o600), EEXIST);
    assert_eq!(shmget(0x9999, P, 0), ENOENT);
    for id in [a, b, k] {
        assert_eq!(shmctl(id, IPC_RMID, 0), 0);
    }
}

#[test]
fn shmget_size_limits() {
    setup();
    assert_eq!(shmget(IPC_PRIVATE, 0, 0o600), EINVAL);
    assert_eq!(shmget(IPC_PRIVATE, (1 << 40) + 1, 0o600), EINVAL, "above SHMMAX");
}

#[test]
fn namespaces_are_isolated() {
    setup();
    let id = shmget(0x77, P, IPC_CREAT | 0o600);
    let mut buf = [0u8; 112];
    let home = fake::IPC_NS.get();
    fake::IPC_NS.set(NEXT.fetch_add(1, Ordering::Relaxed));
    assert_eq!(shmget(0x77, P, 0), ENOENT, "key not visible from another namespace");
    assert_eq!(shmctl(id, IPC_STAT, ptr(&mut buf)), EINVAL, "nor the id");
    assert_eq!(shmctl(id, IPC_RMID, 0), EINVAL, "nor removable from there");
    fake::IPC_NS.set(home);
    assert_eq!(shmctl(id, IPC_RMID, 0), 0);
}

#[test]
fn key_lookup_checks_permissions() {
    setup();
    let id = shmget(0x55, P, IPC_CREAT | 0o640);
    fake::CREDS.set((2000, 2000)); // stranger
    assert_eq!(shmget(0x55, P, 0o400), EACCES, "asks for read: other bits are ---");
    assert_eq!(shmget(0x55, P, 0), id, "asking for nothing always works");
    fake::CREDS.set((2000, 1000)); // same group
    assert_eq!(shmget(0x55, P, 0o400), id, "group may read");
    assert_eq!(shmget(0x55, P, 0o600), EACCES, "but not write");
    fake::CAPS.set(Some(CAP_IPC_OWNER));
    assert_eq!(shmget(0x55, P, 0o600), id, "CAP_IPC_OWNER bypasses permissions");
    fake::CREDS.set((1000, 1000));
    fake::CAPS.set(Some(0));
    assert_eq!(shmctl(id, IPC_RMID, 0), 0);
}

#[test]
fn supplementary_groups_count() {
    let pid = setup();
    let id = shmget(0x56, P, IPC_CREAT | 0o640);
    fake::CREDS.set((2000, 2000));
    fake::PROCS.lock().insert(pid, fake::Process { groups: vec![5, 1000], ..Default::default() });
    assert_eq!(shmget(0x56, P, 0o400), id);
    fake::PROCS.lock().remove(&pid);
    fake::CREDS.set((1000, 1000));
    shmctl(id, IPC_RMID, 0);
}

#[test]
fn shmat_maps_shared_memory_and_counts_attachments() {
    with_shm(|pid, mm| {
        let id = shmget(IPC_PRIVATE, P + 100, 0o600);
        let a = shmat(id, 0, 0) as u64;
        let b = shmat(id, 0, 0) as u64;
        assert!(a != b && a % P == 0 && b % P == 0);
        {
            let m = mm.lock();
            let v = m.find_vma(a).unwrap();
            assert_eq!((v.end - v.start, v.prot, v.shared), (2 * P, PROT_READ | PROT_WRITE, true), "rounded up to pages");
        }
        mm.lock().write_bytes(a + P + 5, b"shared!").unwrap();
        let mut m = mm.lock();
        m.handle_fault(b + P, false, false).unwrap();
        let seen = unsafe { std::slice::from_raw_parts((m.translate(b + P + 5).unwrap().as_u64()) as *const u8, 7) };
        assert_eq!(seen, b"shared!", "both attachments see the same pages");
        drop(m);

        let mut st = [0u8; 112];
        assert_eq!(shmctl(id, IPC_STAT, ptr(&mut st)), 0);
        assert_eq!(u64_at(&st, 48), P + 100, "shm_segsz keeps the requested size");
        assert_eq!(u64_at(&st, 88), 2, "shm_nattch");
        assert_eq!((u32_at(&st, 80), u32_at(&st, 84)), (pid as u32, pid as u32), "cpid, lpid");
        assert_eq!(u64_at(&st, 72), 1_767_225_600, "shm_ctime from the RTC");

        assert_eq!(shmdt(a), 0);
        assert!(mm.lock().find_vma(a).is_none(), "detach unmaps");
        assert_eq!(shmdt(a), EINVAL, "already detached");
        assert_eq!(shmdt(b + 1), EINVAL, "not an attach address");
        shmctl(id, IPC_STAT, ptr(&mut st));
        assert_eq!(u64_at(&st, 88), 1);
        shmdt(b);
        shmctl(id, IPC_RMID, 0);
    });
}

#[test]
fn shmat_flags_and_addresses() {
    with_shm(|_, mm| {
        let id = shmget(IPC_PRIVATE, P, 0o600);
        let ro = shmat(id, 0, SHM_RDONLY) as u64;
        assert_eq!(mm.lock().find_vma(ro).unwrap().prot, PROT_READ);
        assert_eq!(shmat(id, A + 1, 0), EINVAL, "unaligned without SHM_RND");
        assert_eq!(shmat(id, A + 1, SHM_RND), A as i64, "SHM_RND rounds down to SHMLBA");
        assert_eq!(shmat(id, A, 0), EINVAL, "address in use");
        assert_eq!(shmat(id, A, SHM_REMAP), A as i64, "SHM_REMAP replaces it");
        assert_eq!(shmat(0x7fff_0000, 0, 0), EINVAL, "no such segment");
        for addr in [ro, A, A] {
            let _ = shmdt(addr);
        }
        // The first attach at A was replaced, not detached: release its count too.
        forget_process(fake::IDS.get().1, false);
        shmctl(id, IPC_RMID, 0);
    });
}

#[test]
fn shmat_checks_permissions_and_needs_an_address_space() {
    with_shm(|_, _| {
        let id = shmget(IPC_PRIVATE, P, 0o400);
        assert_eq!(shmat(id, 0, 0), EACCES, "read-only segment, read-write attach");
        let ro = shmat(id, 0, SHM_RDONLY);
        assert!(ro > 0);
        shmdt(ro as u64);
        fake::TASK_MM.with_borrow_mut(|m| *m = None);
        assert_eq!(shmat(id, 0, SHM_RDONLY), EINVAL, "kernel threads cannot attach");
        shmctl(id, IPC_RMID, 0);
    });
}

#[test]
fn read_only_attach_cannot_be_made_writable() {
    with_shm(|_, mm| {
        let id = shmget(IPC_PRIVATE, P, 0o400);
        let ro = shmat(id, 0, SHM_RDONLY);
        assert!(ro > 0);
        let r = mm.lock().mprotect(ro as u64, P, PROT_READ | PROT_WRITE);
        assert_eq!(r, Err(EACCES), "a segment the caller may only read became writable");
        shmdt(ro as u64);
        shmctl(id, IPC_RMID, 0);
    });
}

#[test]
fn rmid_waits_for_the_last_detach() {
    with_shm(|_, _| {
        let id = shmget(0x88, P, IPC_CREAT | 0o600);
        let a = shmat(id, 0, 0) as u64;
        assert_eq!(shmctl(id, IPC_RMID, 0), 0);
        assert_eq!(shmget(0x88, P, 0), ENOENT, "key is gone at once");
        let mut st = [0u8; 112];
        assert_eq!(shmctl(id, IPC_STAT, ptr(&mut st)), 0, "segment still exists");
        assert_ne!(u32_at(&st, 20) & 0o1000, 0, "SHM_DEST set in mode");
        assert_eq!(u32_at(&st, 0), 0, "key shown as IPC_PRIVATE");
        assert_eq!(shmdt(a), 0);
        assert_eq!(shmctl(id, IPC_STAT, ptr(&mut st)), EINVAL, "destroyed with the last detach");
    });
}

#[test]
fn only_the_owner_may_change_or_remove() {
    setup();
    let id = shmget(IPC_PRIVATE, P, 0o666);
    fake::CREDS.set((2000, 2000));
    assert_eq!(shmctl(id, IPC_RMID, 0), EPERM);
    let mut perm = [0u8; 112];
    assert_eq!(shmctl(id, IPC_SET, ptr(&mut perm)), EPERM);
    fake::CREDS.set((1000, 1000));
    shmctl(id, IPC_STAT, ptr(&mut perm));
    perm[4..8].copy_from_slice(&2000u32.to_le_bytes()); // uid
    perm[20..22].copy_from_slice(&0o4640u16.to_le_bytes()); // mode: only the 0o777 bits apply
    assert_eq!(shmctl(id, IPC_SET, ptr(&mut perm)), 0);
    let mut st = [0u8; 112];
    shmctl(id, IPC_STAT, ptr(&mut st));
    assert_eq!((u32_at(&st, 4), u32_at(&st, 20) & 0xFFFF), (2000, 0o640));
    assert_eq!(u32_at(&st, 12), 1000, "creator unchanged");
    assert_eq!(shmctl(id, IPC_RMID, 0), 0, "the creator still owns it");
}

#[test]
fn shmctl_info_and_stat_by_index() {
    setup();
    let id = shmget(IPC_PRIVATE, 3 * P, 0o600);
    let mut info = [0u8; 48];
    assert_eq!(shmctl(0, IPC_INFO, ptr(&mut info)), 4095);
    assert_eq!(u64_at(&info, 0), 1 << 40, "shmmax");
    let r = shmctl(0, SHM_INFO, ptr(&mut info));
    assert!(r >= 0);
    assert_eq!(u32_at(&info, 0), 1, "one segment in this namespace");
    assert_eq!(u64_at(&info, 8), 3, "shm_tot in pages");
    let mut st = [0u8; 112];
    assert_eq!(shmctl(id & 0x7fff, SHM_STAT, ptr(&mut st)), id, "SHM_STAT takes the slot, returns the id");
    assert_eq!(shmctl(id, IPC_STAT, 0), EFAULT);
    shmctl(id, IPC_RMID, 0);
}

#[test]
fn fork_and_exit_track_attachments() {
    with_shm(|pid, _| {
        let id = shmget(IPC_PRIVATE, P, 0o600);
        shmat(id, 0, 0);
        let child = pid + 500_000;
        on_fork(pid, child);
        let mut st = [0u8; 112];
        shmctl(id, IPC_STAT, ptr(&mut st));
        assert_eq!(u64_at(&st, 88), 2, "the child shares the attachment");
        forget_process(child, true);
        forget_process(pid, false); // exec: detaches too
        shmctl(id, IPC_STAT, ptr(&mut st));
        assert_eq!(u64_at(&st, 88), 0);
        shmctl(id, IPC_RMID, 0);
    });
}

// ========================================================== semaphores

#[test]
fn semget_rules() {
    setup();
    assert_eq!(semget(IPC_PRIVATE, 0, 0o600), EINVAL);
    assert_eq!(semget(IPC_PRIVATE, 32001, 0o600), EINVAL, "SEMMSL");
    let id = semget(0x10, 3, IPC_CREAT | 0o600);
    assert_eq!(semget(0x10, 2, 0), id);
    assert_eq!(semget(0x10, 4, 0), EINVAL, "more semaphores than the set has");
    let mut st = [0u8; 104];
    assert_eq!(semctl(id, 0, IPC_STAT, ptr(&mut st)), 0);
    assert_eq!(u64_at(&st, 80), 3, "sem_nsems");
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn semop_takes_and_gives() {
    let pid = setup();
    let id = semget(IPC_PRIVATE, 2, 0o600);
    assert_eq!(semctl(id, 0, SETVAL, 2), 0);
    assert_eq!(semop(id, &[(0, -1, 0)]), 0);
    assert_eq!(semctl(id, 0, GETVAL, 0), 1);
    assert_eq!(semctl(id, 0, GETPID, 0), pid as i64);
    assert_eq!(semop(id, &[(0, -2, IPC_NOWAIT as i16)]), EAGAIN);
    assert_eq!(semctl(id, 0, GETVAL, 0), 1, "unchanged after EAGAIN");
    assert_eq!(semop(id, &[(1, 0, 0)]), 0, "wait-for-zero on a zero semaphore");
    assert_eq!(semop(id, &[(0, 0, IPC_NOWAIT as i16)]), EAGAIN);
    let mut st = [0u8; 104];
    semctl(id, 0, IPC_STAT, ptr(&mut st));
    assert_eq!(u64_at(&st, 48), 1_767_225_600, "sem_otime");
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn semop_is_all_or_nothing() {
    setup();
    let id = semget(IPC_PRIVATE, 2, 0o600);
    assert_eq!(semop(id, &[(0, 5, 0), (1, -1, IPC_NOWAIT as i16)]), EAGAIN);
    assert_eq!(semctl(id, 0, GETVAL, 0), 0, "the +5 was not applied");
    assert_eq!(semop(id, &[(0, 5, 0), (0, -3, 0)]), 0, "ops apply in order");
    assert_eq!(semctl(id, 0, GETVAL, 0), 2);
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn semop_argument_errors() {
    setup();
    let id = semget(IPC_PRIVATE, 1, 0o600);
    assert_eq!(semop(id, &[]), EINVAL, "nsops 0");
    let many = vec![(0u16, 0i16, 0i16); 501];
    assert_eq!(semop(id, &many), E2BIG, "SEMOPM");
    assert_eq!(semop(id, &[(1, 1, 0)]), EFBIG, "sem_num out of range");
    assert_eq!(sys(SEMOP, [id as u64, 0, 1, 0, 0, 0]), EFAULT);
    semctl(id, 0, SETVAL, 32767);
    assert_eq!(semop(id, &[(0, 1, 0)]), ERANGE, "above SEMVMX");
    fake::CREDS.set((2000, 2000));
    assert_eq!(semop(id, &[(0, -1, 0)]), EACCES);
    fake::CREDS.set((1000, 1000));
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn blocked_semop_is_interrupted_by_signals() {
    setup();
    let id = semget(IPC_PRIVATE, 1, 0o600);
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(semop(id, &[(0, -1, 0)]), EINTR);
    assert_eq!(semctl(id, 0, GETNCNT, 0), 0, "no longer counted as a waiter");
    assert_eq!(semop(id, &[(0, 0, 0)]), 0);
    semctl(id, 0, SETVAL, 1);
    assert_eq!(semop(id, &[(0, 0, 0)]), EINTR);
    assert_eq!(semctl(id, 0, GETZCNT, 0), 0);
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn blocked_semop_sleeps() {
    setup();
    let id = semget(IPC_PRIVATE, 1, 0o600);
    let r = std::panic::catch_unwind(|| semop(id, &[(0, -1, 0)]));
    let msg = r.unwrap_err().downcast_ref::<String>().cloned().unwrap_or_default();
    assert_eq!(msg, fake::wait::WOULD_BLOCK);
}

#[test]
fn semtimedop_timeouts() {
    setup();
    let id = semget(IPC_PRIVATE, 1, 0o600);
    let mut ops = sembufs(&[(0, -1, 0)]);
    let mut ts = [0u8; 16];
    assert_eq!(sys(SEMTIMEDOP, [id as u64, ptr(&mut ops), 1, ptr(&mut ts), 0, 0]), EAGAIN, "zero timeout expires at once");
    ts[8..16].copy_from_slice(&1_000_000_000i64.to_le_bytes());
    assert_eq!(sys(SEMTIMEDOP, [id as u64, ptr(&mut ops), 1, ptr(&mut ts), 0, 0]), EINVAL, "tv_nsec out of range");
    ts[..8].copy_from_slice(&(-1i64).to_le_bytes());
    ts[8..16].copy_from_slice(&0i64.to_le_bytes());
    assert_eq!(sys(SEMTIMEDOP, [id as u64, ptr(&mut ops), 1, ptr(&mut ts), 0, 0]), EINVAL, "negative");
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn sem_undo_is_applied_on_exit_only() {
    let pid = setup();
    let id = semget(IPC_PRIVATE, 1, 0o600);
    assert_eq!(semop(id, &[(0, 3, SEM_UNDO)]), 0);
    forget_process(pid, false); // exec keeps adjustments
    assert_eq!(semctl(id, 0, GETVAL, 0), 3);
    forget_process(pid, true); // exit applies them
    assert_eq!(semctl(id, 0, GETVAL, 0), 0);

    assert_eq!(semop(id, &[(0, 2, SEM_UNDO)]), 0);
    semctl(id, 0, SETVAL, 7); // SETVAL cancels the adjustment
    forget_process(pid, true);
    assert_eq!(semctl(id, 0, GETVAL, 0), 7);
    semctl(id, 0, IPC_RMID, 0);
}

#[test]
fn getall_setall_and_permissions() {
    setup();
    let id = semget(IPC_PRIVATE, 3, 0o640);
    let mut vals = [1u16, 2, 3].map(u16::to_le_bytes).concat();
    assert_eq!(semctl(id, 0, SETALL, ptr(&mut vals)), 0);
    let mut out = [0u8; 6];
    assert_eq!(semctl(id, 0, GETALL, ptr(&mut out)), 0);
    assert_eq!(out, [1, 0, 2, 0, 3, 0]);
    let mut big = [1u16, 40000, 3].map(u16::to_le_bytes).concat();
    assert_eq!(semctl(id, 0, SETALL, ptr(&mut big)), ERANGE);
    assert_eq!(semctl(id, 3, GETVAL, 0), EINVAL, "semnum out of range");
    assert_eq!(semctl(id, 0, SETVAL, 32768), ERANGE);
    fake::CREDS.set((2000, 1000)); // group: read only
    assert_eq!(semctl(id, 1, GETVAL, 0), 2);
    assert_eq!(semctl(id, 1, SETVAL, 5), EACCES);
    assert_eq!(semctl(id, 0, IPC_RMID, 0), EPERM);
    fake::CREDS.set((1000, 1000));
    assert_eq!(semctl(id, 0, IPC_RMID, 0), 0);
    assert_eq!(semctl(id, 0, GETVAL, 0), EINVAL);
}

#[test]
fn unknown_ids_are_einval() {
    setup();
    assert_eq!(semop(0x7ff0_1234, &[(0, 1, 0)]), EINVAL);
    assert_eq!(msgsnd(0x7ff0_1234, 1, b"x", IPC_NOWAIT), EINVAL);
    assert_eq!(msgrcv(0x7ff0_1234, 8, 0, IPC_NOWAIT).0, EINVAL);
}

// ======================================================= message queues

#[test]
fn messages_are_fifo() {
    let pid = setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    assert_eq!(msgsnd(id, 1, b"first", 0), 0);
    assert_eq!(msgsnd(id, 1, b"second", 0), 0);
    assert_eq!(msgrcv(id, 64, 0, 0), (5, 1, b"first".to_vec()));
    assert_eq!(msgrcv(id, 64, 0, 0), (6, 1, b"second".to_vec()));
    assert_eq!(msgrcv(id, 64, 0, IPC_NOWAIT).0, ENOMSG);
    let mut st = [0u8; 120];
    msgctl(id, IPC_STAT, ptr(&mut st));
    assert_eq!((u64_at(&st, 72), u64_at(&st, 80), u64_at(&st, 88)), (0, 0, 16384), "cbytes, qnum, qbytes");
    assert_eq!((u32_at(&st, 96), u32_at(&st, 100)), (pid as u32, pid as u32), "lspid, lrpid");
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn message_type_selection() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    for (t, d) in [(5, "five"), (2, "two"), (9, "nine"), (2, "two-b")] {
        msgsnd(id, t, d.as_bytes(), 0);
    }
    assert_eq!(msgrcv(id, 64, 9, 0).2, b"nine", "exact type");
    assert_eq!(msgrcv(id, 64, 5, MSG_EXCEPT).2, b"two", "first not of type 5");
    assert_eq!(msgrcv(id, 64, -6, 0).2, b"two-b", "lowest type <= 6");
    assert_eq!(msgrcv(id, 64, -4, IPC_NOWAIT).0, ENOMSG, "nothing <= 4 left");
    assert_eq!(msgrcv(id, 64, 0, 0).2, b"five");
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn receive_buffer_too_small() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    msgsnd(id, 1, b"0123456789", 0);
    assert_eq!(msgrcv(id, 4, 0, 0).0, E2BIG);
    assert_eq!(msgrcv(id, 4, 0, MSG_NOERROR), (4, 1, b"0123".to_vec()), "truncated and consumed");
    assert_eq!(msgrcv(id, 64, 0, IPC_NOWAIT).0, ENOMSG);
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn send_validation_and_full_queue() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    assert_eq!(msgsnd(id, 0, b"x", 0), EINVAL, "mtype must be positive");
    assert_eq!(msgsnd(id, 1, &vec![0; 8193], 0), EINVAL, "MSGMAX");
    assert_eq!(msgsnd(id, 1, &vec![0; 8192], 0), 0);
    assert_eq!(msgsnd(id, 1, &vec![0; 8192], 0), 0);
    assert_eq!(msgsnd(id, 1, b"x", IPC_NOWAIT), EAGAIN, "16384 bytes queued");
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(msgsnd(id, 1, b"x", 0), EINTR);
    fake::SIGNAL_PENDING.set(false);
    assert_eq!(sys(MSGSND, [id as u64, 0, 1, 0, 0, 0]), EFAULT);
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn zero_length_messages_are_limited() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    let mut accepted = 0;
    for _ in 0..20_000 {
        if msgsnd(id, 1, b"", IPC_NOWAIT) != 0 {
            break;
        }
        accepted += 1;
    }
    msgctl(id, IPC_RMID, 0);
    assert!(accepted <= 16384, "{accepted} empty messages queued");
}

#[test]
fn msg_copy_peeks_by_index() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    msgsnd(id, 3, b"a", 0);
    msgsnd(id, 4, b"b", 0);
    assert_eq!(msgrcv(id, 8, 1, MSG_COPY).0, EINVAL, "MSG_COPY needs IPC_NOWAIT");
    assert_eq!(msgrcv(id, 8, 1, MSG_COPY | IPC_NOWAIT), (1, 4, b"b".to_vec()));
    assert_eq!(msgrcv(id, 8, 5, MSG_COPY | IPC_NOWAIT).0, ENOMSG);
    assert_eq!(msgrcv(id, 8, 0, 0).2, b"a", "copy did not remove anything");
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn blocked_receive_sleeps_or_is_interrupted() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    let r = std::panic::catch_unwind(|| msgrcv(id, 8, 0, 0));
    assert!(r.is_err(), "empty queue: the receiver sleeps");
    fake::SIGNAL_PENDING.set(true);
    assert_eq!(msgrcv(id, 8, 0, 0).0, EINTR);
    fake::SIGNAL_PENDING.set(false);
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn queue_limit_changes_need_privilege_to_grow() {
    setup();
    let id = msgget(IPC_PRIVATE, 0o600);
    let mut ds = [0u8; 120];
    msgctl(id, IPC_STAT, ptr(&mut ds));
    ds[88..96].copy_from_slice(&65536u64.to_le_bytes());
    assert_eq!(msgctl(id, IPC_SET, ptr(&mut ds)), EPERM, "above MSGMNB needs CAP_SYS_RESOURCE");
    ds[88..96].copy_from_slice(&100u64.to_le_bytes());
    assert_eq!(msgctl(id, IPC_SET, ptr(&mut ds)), 0, "lowering is fine");
    assert_eq!(msgsnd(id, 1, &[0; 101], IPC_NOWAIT), EAGAIN, "new limit applies");
    fake::CAPS.set(Some(CAP_SYS_RESOURCE));
    ds[88..96].copy_from_slice(&65536u64.to_le_bytes());
    assert_eq!(msgctl(id, IPC_SET, ptr(&mut ds)), 0);
    fake::CAPS.set(Some(0));
    msgctl(id, IPC_RMID, 0);
}

#[test]
fn msgget_and_msgctl_rules() {
    setup();
    let id = msgget(0x42, IPC_CREAT | 0o600);
    assert_eq!(msgget(0x42, 0), id);
    assert_eq!(msgget(0x42, IPC_CREAT | IPC_EXCL), EEXIST);
    assert_eq!(msgget(0x43, 0), ENOENT);
    let mut info = [0u8; 32];
    assert!(msgctl(0, IPC_INFO, ptr(&mut info)) >= 0);
    assert_eq!(u32_at(&info, 8), 8192, "msgmax");
    fake::CREDS.set((2000, 2000));
    assert_eq!(msgctl(id, IPC_RMID, 0), EPERM);
    assert_eq!(msgsnd(id, 1, b"x", 0), EACCES);
    fake::CREDS.set((1000, 1000));
    assert_eq!(msgctl(id, IPC_RMID, 0), 0);
    assert_eq!(msgget(0x42, 0), ENOENT);
}

#[test]
fn other_syscall_numbers_are_not_sysv() {
    assert_eq!(dispatch(0, [0; 6]), None);
    assert_eq!(dispatch(221, [0; 6]), None);
}
