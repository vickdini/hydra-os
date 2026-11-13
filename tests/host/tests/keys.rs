//! Tests for the kernel key retention service (`src/compat/linux/keys.rs`):
//! `add_key`, `request_key` and `keyctl`, through `keys::dispatch` with the
//! x86-64 syscall numbers. Used by Kerberos, NFS, eCryptfs, systemd and
//! `keyutils`.
//!
//! The key table is global. Each test runs as its own user and process
//! (unique uid, tid and tgid, registered in the fake process table so the
//! keyring garbage collector keeps its keyrings alive).

use std::ffi::CString;
use std::sync::atomic::{AtomicU64, Ordering};

use hydra_hosttests::compat::linux::keys::{dispatch, on_exec, on_fork, proc_keys};
use hydra_hosttests::fake;

const ADD_KEY: u64 = 248;
const REQUEST_KEY: u64 = 249;
const KEYCTL: u64 = 250;

const THREAD: i32 = -1;
const PROCESS: i32 = -2;
const SESSION: i32 = -3;
const USER: i32 = -4;
const USER_SESSION: i32 = -5;
const GROUP: i32 = -6;

const GET_KEYRING_ID: u64 = 0;
const JOIN_SESSION: u64 = 1;
const UPDATE: u64 = 2;
const REVOKE: u64 = 3;
const CHOWN: u64 = 4;
const SETPERM: u64 = 5;
const DESCRIBE: u64 = 6;
const CLEAR: u64 = 7;
const LINK: u64 = 8;
const UNLINK: u64 = 9;
const SEARCH: u64 = 10;
const READ: u64 = 11;
const INSTANTIATE: u64 = 12;
const SET_REQKEY_KEYRING: u64 = 14;
const SET_TIMEOUT: u64 = 15;
const INVALIDATE: u64 = 21;
const GET_PERSISTENT: u64 = 22;
const MOVE: u64 = 30;
const CAPABILITIES: u64 = 31;

const EPERM: i64 = -1;
const ENOENT: i64 = -2;
const EACCES: i64 = -13;
const EFAULT: i64 = -14;
const ENODEV: i64 = -19;
const ENOTDIR: i64 = -20;
const EEXIST: i64 = -17;
const EINVAL: i64 = -22;
const EDEADLK: i64 = -35;
const EOPNOTSUPP: i64 = -95;
const EDQUOT: i64 = -122;
const ENOKEY: i64 = -126;
const EKEYEXPIRED: i64 = -127;
const EKEYREVOKED: i64 = -128;

const CAP_SYS_ADMIN: u64 = 1 << 21;

static NEXT: AtomicU64 = AtomicU64::new(20_000);

/// A process registered in the fake process table for the test's duration.
struct Proc(u64);

impl Drop for Proc {
    fn drop(&mut self) {
        fake::PROCS.lock().remove(&self.0);
    }
}

/// Fresh fakes; run as a new user (uid = gid = returned value) and process.
fn setup() -> (u32, Proc) {
    fake::reset();
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    become_process(n, n as u32, 1)
}

/// Switch to process `pid` (tid = tgid) running as `uid`.
fn become_process(pid: u64, uid: u32, ppid: u64) -> (u32, Proc) {
    fake::IDS.set((pid, pid));
    fake::CREDS.set((uid, uid));
    fake::PROCS.lock().insert(pid, fake::Process { ppid, ..Default::default() });
    (uid, Proc(pid))
}

fn cs(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn add(ktype: &str, desc: &str, payload: &[u8], ring: i32) -> i64 {
    let (t, d) = (cs(ktype), cs(desc));
    let p = if payload.is_empty() { 0 } else { payload.as_ptr() as u64 };
    dispatch(ADD_KEY, [t.as_ptr() as u64, d.as_ptr() as u64, p, payload.len() as u64, ring as u32 as u64, 0]).unwrap()
}

fn request(ktype: &str, desc: &str, dest: i32) -> i64 {
    let (t, d) = (cs(ktype), cs(desc));
    dispatch(REQUEST_KEY, [t.as_ptr() as u64, d.as_ptr() as u64, 0, dest as u32 as u64, 0, 0]).unwrap()
}

fn keyctl(op: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    dispatch(KEYCTL, [op, a2, a3, a4, a5, 0]).unwrap()
}

fn id(k: i32) -> u64 {
    k as u32 as u64
}

fn ring_id(spec: i32, create: bool) -> i64 {
    keyctl(GET_KEYRING_ID, id(spec), create as u64, 0, 0)
}

/// KEYCTL_READ into a buffer; returns (result, bytes).
fn read(key: i64) -> (i64, Vec<u8>) {
    let mut buf = vec![0u8; 64 * 1024];
    let r = keyctl(READ, key as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
    buf.truncate(r.max(0) as usize);
    (r, buf)
}

fn describe(key: i64) -> Result<String, i64> {
    let mut buf = vec![0u8; 512];
    let r = keyctl(DESCRIBE, key as u64, buf.as_mut_ptr() as u64, buf.len() as u64, 0);
    if r < 0 {
        return Err(r);
    }
    Ok(String::from_utf8_lossy(&buf[..r as usize - 1]).into_owned())
}

fn ring_contents(ring: i64) -> Vec<i32> {
    read(ring).1.chunks(4).map(|c| i32::from_ne_bytes(c.try_into().unwrap())).collect()
}

// -------------------------------------------------------------- add_key

#[test]
fn add_and_read_a_user_key() {
    let (uid, _p) = setup();
    let k = add("user", "api-token", b"s3cret", PROCESS);
    assert!(k > 0);
    assert_eq!(read(k), (6, b"s3cret".to_vec()));
    assert_eq!(describe(k).unwrap(), format!("user;{uid};{uid};3f010000;api-token"), "possessor: all, owner: view");
    let r = ring_id(PROCESS, false);
    assert_eq!(ring_contents(r), vec![k as i32], "linked into the process keyring");
}

#[test]
fn add_key_validation() {
    let (_, _p) = setup();
    assert_eq!(add("", "d", b"x", PROCESS), EINVAL);
    assert_eq!(add(".request_key_auth", "d", b"x", PROCESS), EPERM, "internal types");
    assert_eq!(add("asymmetric", "d", b"x", PROCESS), ENODEV, "unsupported type");
    assert_eq!(add("user", "", b"x", PROCESS), EINVAL, "empty description");
    assert!(add("user", &"d".repeat(4095), b"x", PROCESS) > 0, "4095 bytes is the limit");
    assert!(add("user", &"d".repeat(4096), b"x", PROCESS) < 0, "too long (ENAMETOOLONG here, EINVAL on Linux)");
    assert_eq!(add("logon", "nocolon", b"x", PROCESS), EINVAL, "logon needs a prefix:");
    assert_eq!(add("logon", ":x", b"x", PROCESS), EINVAL, "and the prefix may not be empty");
    assert_eq!(add("logon", "cifs:x", b"", PROCESS), EINVAL, "logon keys need a payload");
    assert_eq!(add("user", "big", &vec![0; 32768], PROCESS), EINVAL, "user payload limit 32767");
    assert_eq!(add("keyring", "r", b"x", PROCESS), EINVAL, "keyrings take no payload");
    assert!(add("user", "empty", b"", PROCESS) > 0, "an empty user key is fine");
    let me = fake::CREDS.get();
    fake::CREDS.set((0, 0)); // root's quota is 25 MB; a normal user's 20 KB would refuse this
    assert!(add("big_key", "b", &vec![1; 100_000], USER_SESSION) > 0, "big_key payloads may exceed 32 KiB");
    fake::CREDS.set(me);
    let (t, d) = (cs("user"), cs("nullp"));
    assert_eq!(dispatch(ADD_KEY, [t.as_ptr() as u64, d.as_ptr() as u64, 0, 5, id(PROCESS), 0]), Some(EFAULT));
    assert_eq!(add("user", "d", b"x", 0), EINVAL, "keyring id 0");
    assert_eq!(add("user", "d", b"x", GROUP), EINVAL, "group keyrings do not exist");
}

#[test]
fn same_type_and_description_updates_in_place() {
    let (_, _p) = setup();
    let a = add("user", "cfg", b"v1", PROCESS);
    let b = add("user", "cfg", b"version-2", PROCESS);
    assert_eq!(a, b);
    assert_eq!(read(a).1, b"version-2");
    let c = add("logon", "cfg:x", b"v1", PROCESS);
    assert_ne!(c, a, "a different type is a different key");
}

#[test]
fn add_key_needs_a_keyring_with_write_access() {
    let (_, _p) = setup();
    let k = add("user", "leaf", b"x", PROCESS);
    assert_eq!(add("user", "child", b"x", k as i32), ENOTDIR);
    assert_eq!(add("user", "x", b"x", 0x7fff_fff0), ENOKEY, "no such keyring");
}

#[test]
fn logon_keys_are_write_only() {
    let (_, _p) = setup();
    let k = add("logon", "ceph:client", b"password", PROCESS);
    assert_eq!(read(k).0, EOPNOTSUPP);
    assert!(describe(k).is_ok());
}

// ----------------------------------------------------- special keyrings

#[test]
fn special_keyrings() {
    let (_, _p) = setup();
    assert_eq!(ring_id(THREAD, false), ENOKEY, "not created until asked");
    let t = ring_id(THREAD, true);
    assert!(t > 0);
    assert_eq!(ring_id(THREAD, false), t);
    let p = ring_id(PROCESS, true);
    assert!(p > 0 && p != t);
    let u = ring_id(USER, false);
    let us = ring_id(USER_SESSION, false);
    assert!(u > 0 && us > 0 && u != us);
    assert_eq!(ring_id(SESSION, false), us, "no session keyring: the user-session one stands in");
    assert_eq!(ring_contents(us), vec![u as i32], "user-session links the user keyring");
    assert_eq!(ring_id(GROUP, false), EINVAL);
    assert_eq!(ring_id(-7, false), ENOKEY, "REQKEY_AUTH");
    assert_eq!(ring_id(-9, false), EINVAL);
    assert_eq!(ring_id(0x7fff_fff0, false), ENOKEY);
}

#[test]
fn join_session_keyrings() {
    let (_, _p) = setup();
    let anon = keyctl(JOIN_SESSION, 0, 0, 0, 0);
    assert!(anon > 0);
    assert_eq!(ring_id(SESSION, false), anon);
    let name = cs(&format!("team-{}", fake::IDS.get().0));
    let named = keyctl(JOIN_SESSION, name.as_ptr() as u64, 0, 0, 0);
    assert!(named > 0 && named != anon);
    let me = fake::IDS.get().0;
    {
        let (_, _q) = become_process(me + 1_000_000, fake::CREDS.get().0, me);
        assert_eq!(keyctl(JOIN_SESSION, name.as_ptr() as u64, 0, 0, 0), EACCES, "as on Linux: no user SEARCH by default");
    }
    fake::IDS.set((me, me));
    assert_eq!(keyctl(SETPERM, named as u64, 0x3f0b_0000, 0, 0), 0, "owner may view, read, search");
    let (_, _q) = become_process(me + 1_000_001, fake::CREDS.get().0, me);
    assert_eq!(keyctl(JOIN_SESSION, name.as_ptr() as u64, 0, 0, 0), named, "another process joins by name");
}

#[test]
fn fork_shares_the_session_and_exec_drops_private_rings() {
    let (uid, _p) = setup();
    let me = fake::IDS.get().0;
    let ses = keyctl(JOIN_SESSION, 0, 0, 0, 0);
    let t = ring_id(THREAD, true);
    let child = me + 2_000_000;
    on_fork(me, child);
    {
        let (_, _c) = become_process(child, uid, me);
        assert_eq!(ring_id(SESSION, false), ses);
        assert_ne!(ring_id(THREAD, true), t, "threads have their own keyring");
    }
    fake::IDS.set((me, me));
    on_exec(me, me);
    assert_eq!(ring_id(THREAD, false), ENOKEY, "execve drops the thread keyring");
    assert_eq!(ring_id(PROCESS, false), ENOKEY, "and the process keyring");
    assert_eq!(ring_id(SESSION, false), ses, "but keeps the session");
}

// ----------------------------------------------------------- searching

#[test]
fn request_key_searches_the_callers_keyrings() {
    let (_, _p) = setup();
    let ses = keyctl(JOIN_SESSION, 0, 0, 0, 0);
    let inner = add("keyring", "inner", b"", SESSION);
    let k = add("user", "deep", b"found", inner as i32);
    assert_eq!(request("user", "deep", 0), k, "found through a nested keyring");
    assert_eq!(request("user", "missing", 0), ENOKEY, "no upcall to construct keys");
    assert_eq!(request("logon", "deep", 0), ENOKEY, "type must match");
    let p = ring_id(PROCESS, true);
    assert_eq!(request("user", "deep", PROCESS), k);
    assert!(ring_contents(p).contains(&(k as i32)), "linked into the destination");
    let _ = ses;
}

#[test]
fn keyctl_search_in_one_keyring() {
    let (_, _p) = setup();
    let ring = add("keyring", "box", b"", PROCESS);
    let k = add("user", "item", b"x", ring as i32);
    let (t, d) = (cs("user"), cs("item"));
    assert_eq!(keyctl(SEARCH, ring as u64, t.as_ptr() as u64, d.as_ptr() as u64, 0), k);
    let d2 = cs("nope");
    assert_eq!(keyctl(SEARCH, ring as u64, t.as_ptr() as u64, d2.as_ptr() as u64, 0), ENOKEY);
    assert_eq!(keyctl(SEARCH, k as u64, t.as_ptr() as u64, d.as_ptr() as u64, 0), ENOTDIR);
}

// ---------------------------------------------------------- permissions

#[test]
fn other_users_cannot_see_or_read_keys() {
    let (_, _p) = setup();
    let k = add("user", "private", b"x", PROCESS);
    let me = fake::IDS.get().0;
    let (_, _q) = become_process(me + 3_000_000, 4_000_000_000, 1);
    assert_eq!(read(k).0, EACCES);
    assert_eq!(describe(k), Err(EACCES));
    assert_eq!(keyctl(REVOKE, k as u64, 0, 0, 0), EACCES);
}

#[test]
fn same_user_without_possession_can_only_view() {
    let (uid, _p) = setup();
    let k = add("user", "mine", b"x", PROCESS);
    let me = fake::IDS.get().0;
    let (_, _q) = become_process(me + 3_000_000, uid, 1);
    assert!(describe(k).is_ok(), "owner VIEW");
    assert_eq!(read(k).0, EACCES, "no owner READ by default");
}

#[test]
fn setperm_and_chown() {
    let (uid, _p) = setup();
    let k = add("user", "perm", b"x", PROCESS);
    assert_eq!(keyctl(SETPERM, k as u64, 0x4000_0000, 0, 0), EINVAL, "undefined bits");
    assert_eq!(keyctl(SETPERM, k as u64, 0x3f3f_0000, 0, 0), 0, "owner: everything");
    let me = fake::IDS.get().0;
    {
        let (_, _q) = become_process(me + 3_000_000, uid, 1);
        assert_eq!(read(k).1, b"x", "owner READ now granted");
    }
    fake::IDS.set((me, me));
    assert_eq!(keyctl(CHOWN, k as u64, 0, u32::MAX as u64, 0), EACCES, "changing uid needs CAP_SYS_ADMIN");
    assert_eq!(keyctl(CHOWN, k as u64, u32::MAX as u64, uid as u64, 0), 0, "own group");
    assert_eq!(keyctl(CHOWN, k as u64, u32::MAX as u64, 12345, 0), EACCES, "a group we are not in");
    fake::CAPS.set(Some(CAP_SYS_ADMIN));
    assert_eq!(keyctl(CHOWN, k as u64, 77, u32::MAX as u64, 0), 0);
    assert!(describe(k).unwrap().contains(";77;"));
}

// --------------------------------------------------------- key lifetime

#[test]
fn revoke_timeout_and_invalidate() {
    let (_, _p) = setup();
    let r = add("user", "r", b"x", PROCESS);
    assert_eq!(keyctl(REVOKE, r as u64, 0, 0, 0), 0);
    assert_eq!(read(r).0, EKEYREVOKED);

    let t = add("user", "t", b"x", PROCESS);
    assert_eq!(keyctl(SET_TIMEOUT, t as u64, 5, 0, 0), 0);
    assert_eq!(read(t).1, b"x");
    fake::TICKS.set(fake::TICKS.get() + 5_000);
    assert_eq!(read(t).0, EKEYEXPIRED);
    assert_eq!(request("user", "t", 0), EKEYEXPIRED, "search reports why the key is unusable");

    let i = add("user", "i", b"x", PROCESS);
    assert_eq!(keyctl(INVALIDATE, i as u64, 0, 0, 0), 0);
    assert_eq!(read(i).0, ENOKEY, "invalidated keys are collected at once");
    assert!(!ring_contents(ring_id(PROCESS, false)).contains(&(i as i32)));
}

#[test]
fn link_unlink_and_garbage_collection() {
    let (_, _p) = setup();
    let a = add("keyring", "a", b"", PROCESS);
    let b = add("keyring", "b", b"", a as i32);
    assert_eq!(keyctl(LINK, a as u64, b as u64, 0, 0), EDEADLK, "no cycles");
    assert_eq!(keyctl(LINK, a as u64, a as u64, 0, 0), EDEADLK, "not into itself");
    let k = add("user", "k", b"x", b as i32);
    assert_eq!(keyctl(LINK, k as u64, k as u64, 0, 0), ENOTDIR, "destination must be a keyring");
    let leaf = add("user", "leaf", b"x", PROCESS);
    assert_eq!(keyctl(LINK, k as u64, leaf as u64, 0, 0), ENOTDIR);
    assert_eq!(keyctl(LINK, k as u64, a as u64, 0, 0), 0);
    assert_eq!(ring_contents(a), vec![b as i32, k as i32]);
    assert_eq!(keyctl(UNLINK, k as u64, a as u64, 0, 0), 0);
    assert_eq!(keyctl(UNLINK, k as u64, a as u64, 0, 0), ENOENT);
    assert_eq!(keyctl(UNLINK, b as u64, a as u64, 0, 0), 0);
    assert_eq!(read(k).0, ENOKEY, "no longer reachable: collected");
    assert_eq!(keyctl(CLEAR, ring_id(PROCESS, false) as u64, 0, 0, 0), 0);
    assert_eq!(read(a).0, ENOKEY);
}

#[test]
fn linking_replaces_a_key_of_the_same_name() {
    let (_, _p) = setup();
    let ring = add("keyring", "r", b"", PROCESS);
    let other = add("keyring", "o", b"", PROCESS);
    let old = add("user", "same", b"old", ring as i32);
    let new = add("user", "same", b"new", other as i32);
    assert_eq!(keyctl(LINK, new as u64, ring as u64, 0, 0), 0);
    assert_eq!(ring_contents(ring), vec![new as i32], "displaced");
    let _ = old;
}

#[test]
fn move_between_keyrings() {
    let (_, _p) = setup();
    let from = add("keyring", "from", b"", PROCESS);
    let to = add("keyring", "to", b"", PROCESS);
    let k = add("user", "m", b"x", from as i32);
    add("user", "m", b"y", to as i32);
    assert_eq!(keyctl(MOVE, k as u64, from as u64, to as u64, 2), EINVAL, "unknown flag");
    assert_eq!(keyctl(MOVE, k as u64, from as u64, to as u64, 1), EEXIST, "KEYCTL_MOVE_EXCL");
    assert_eq!(keyctl(MOVE, k as u64, from as u64, to as u64, 0), 0);
    assert_eq!(ring_contents(to), vec![k as i32]);
    assert!(ring_contents(from).is_empty());
    assert_eq!(keyctl(MOVE, k as u64, from as u64, to as u64, 0), ENOENT, "not in the source");
}

// ----------------------------------------------------------- update/quota

#[test]
fn keyctl_update() {
    let (_, _p) = setup();
    let k = add("user", "u", b"v1", PROCESS);
    let v2 = b"v2-longer";
    assert_eq!(keyctl(UPDATE, k as u64, v2.as_ptr() as u64, v2.len() as u64, 0), 0);
    assert_eq!(read(k).1, v2);
    let ring = ring_id(PROCESS, false);
    assert_eq!(keyctl(UPDATE, ring as u64, v2.as_ptr() as u64, v2.len() as u64, 0), EOPNOTSUPP);
    let l = add("logon", "a:b", b"x", PROCESS);
    assert_eq!(keyctl(UPDATE, l as u64, 0, 0, 0), EINVAL, "logon keys cannot be emptied");
}

#[test]
fn per_user_quota() {
    let (_, _p) = setup();
    let ring = add("keyring", "q", b"", PROCESS);
    let mut made = 1; // the keyring counts too (thread/process rings are not charged)
    loop {
        let r = add("user", &format!("k{made}"), b"x", ring as i32);
        if r < 0 {
            assert_eq!(r, EDQUOT);
            break;
        }
        made += 1;
        assert!(made < 1000, "quota never hit");
    }
    assert!(made <= 200, "200 keys per user; got {made}");
}

#[test]
fn updates_count_against_the_quota() {
    let (_, _p) = setup();
    let ring = add("keyring", "q", b"", PROCESS);
    let mut over = 0usize;
    for i in 0..10 {
        let k = add("user", &format!("k{i}"), b"x", ring as i32);
        let big = vec![b'z'; 30_000];
        if add("user", &format!("k{i}"), &big, ring as i32) == k {
            over += 30_000;
        }
    }
    assert!(over <= 20_000, "{over} bytes of payload accepted against a 20000-byte quota");
}

// ---------------------------------------------------------------- misc

#[test]
fn proc_keys_lists_visible_keys() {
    let (uid, _p) = setup();
    let k = add("user", "listed", b"abc", PROCESS);
    let text = proc_keys();
    let line = text.lines().find(|l| l.starts_with(&format!("{k:08x} "))).expect("key listed");
    assert!(line.contains(" perm "), "{line}");
    assert!(line.contains(&format!(" {uid:5} ")) || line.contains(&format!(" {uid} ")), "{line}");
    assert!(line.ends_with("user      listed: 3"), "{line}");
}

#[test]
fn capability_and_unsupported_operations() {
    let (_, _p) = setup();
    let mut caps = [0u8; 2];
    assert_eq!(keyctl(CAPABILITIES, caps.as_mut_ptr() as u64, 2, 0, 0), 2);
    assert_eq!(caps, [0x22, 0x05]);
    assert_eq!(keyctl(INSTANTIATE, 0, 0, 0, 0), EPERM, "no request-key upcalls");
    assert_eq!(keyctl(24, 0, 0, 0, 0), EOPNOTSUPP, "public-key operations");
    assert_eq!(keyctl(999, 0, 0, 0, 0), EOPNOTSUPP);
    assert_eq!(keyctl(SET_REQKEY_KEYRING, 3, 0, 0, 0), 0, "returns the old default (0)");
    assert_eq!(keyctl(SET_REQKEY_KEYRING, id(-1), 0, 0, 0), 3, "-1 only queries");
    assert_eq!(keyctl(SET_REQKEY_KEYRING, 8, 0, 0, 0), EINVAL);
}

#[test]
fn persistent_keyrings() {
    let (uid, _p) = setup();
    let p1 = keyctl(GET_PERSISTENT, u64::MAX, id(PROCESS), 0, 0);
    assert!(p1 > 0);
    assert_eq!(keyctl(GET_PERSISTENT, uid as u64, id(PROCESS), 0, 0), p1, "one per user");
    assert!(describe(p1).unwrap().ends_with(&format!("_persistent.{uid}")));
    assert_eq!(keyctl(GET_PERSISTENT, 0, id(PROCESS), 0, 0), EPERM, "another user's needs privilege");
}

#[test]
fn session_to_parent_needs_a_real_parent() {
    let (_, _p) = setup();
    keyctl(JOIN_SESSION, 0, 0, 0, 0);
    assert_eq!(keyctl(18, 0, 0, 0, 0), EPERM, "parent is init (ppid 1)");
}
