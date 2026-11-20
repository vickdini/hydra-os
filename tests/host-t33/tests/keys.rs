//! Kernel keyrings (`src/compat/linux/keys.rs`), the paths `tests/host` leaves: key types
//! by name, expiry in `/proc/keys`, logon keys, the unknown operations and numbers,
//! timeouts, quotas, keyrings across fork and exec.

use std::ffi::CString;
use std::sync::Mutex;

use hydra_hosttests_t33::compat::linux::keys;
use hydra_hosttests_t33::fake;

fn serial() -> std::sync::MutexGuard<'static, ()> {
    static L: Mutex<()> = Mutex::new(());
    let g = L.lock().unwrap_or_else(|e| e.into_inner());
    fake::reset();
    g
}

const SESSION: i32 = -3;
const PROCESS: i32 = -2;

fn c(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn add(kind: &str, desc: &str, payload: &[u8], ring: i32) -> i64 {
    let (k, d) = (c(kind), c(desc));
    keys::dispatch(248, [k.as_ptr() as u64, d.as_ptr() as u64, payload.as_ptr() as u64, payload.len() as u64, ring as i64 as u64, 0]).unwrap()
}

fn keyctl(op: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> i64 {
    keys::dispatch(250, [op, a2, a3, a4, a5, 0]).unwrap()
}

/// Each test its own process (keyrings are per process).
fn proc(tgid: u64) {
    fake::IDS.set((tgid, tgid));
    fake::PROCS.lock().entry(tgid).or_default();
}

#[test]
fn key_types_payloads_and_descriptions() {
    let _g = serial();
    proc(7100);
    let k = add("user", "plain", b"secret", PROCESS);
    assert!(k > 0, "{k}");
    let mut buf = [0u8; 64];
    assert_eq!(keyctl(11, k as u64, buf.as_mut_ptr() as u64, 64, 0), 6);
    assert_eq!(&buf[..6], b"secret");
    // A logon key cannot be read back
    let l = add("logon", "svc:pw", b"pw", PROCESS);
    assert!(l > 0);
    assert_eq!(keyctl(11, l as u64, buf.as_mut_ptr() as u64, 64, 0), -95);
    // Unknown types and bad strings
    assert_eq!(add("nosuchtype", "x", b"", PROCESS), -19);
    assert_eq!(keys::dispatch(248, [0, 0, 0, 0, PROCESS as i64 as u64, 0]).unwrap(), -14);
    // Describe a key and a keyring
    let n = keyctl(6, k as u64, buf.as_mut_ptr() as u64, 64, 0);
    let d = String::from_utf8_lossy(&buf[..n as usize - 1]).into_owned();
    assert!(d.starts_with("user;") && d.ends_with(";plain"), "{d}");
    // Operations this kernel does not do
    for op in [23, 29, 32, 99] {
        assert_eq!(keyctl(op, 0, 0, 0, 0), -95, "op {op}");
    }
    for op in [12, 13, 19, 20] {
        assert_eq!(keyctl(op, 0, 0, 0, 0), -1, "op {op}");
    }
    // Not a key system call
    assert!(keys::dispatch(39, [0; 6]).is_none());
}

#[test]
fn expired_keys_show_in_proc_keys() {
    let _g = serial();
    proc(7200);
    let k = add("user", "short-lived", b"x", PROCESS);
    assert_eq!(keyctl(15, k as u64, 1, 0, 0), 0, "a one-second timeout");
    let listing = keys::proc_keys();
    assert!(listing.lines().any(|l| l.contains("short-lived") && !l.contains("expd")), "{listing}");
    fake::TICKS.set(fake::TICKS.get() + 5_000);
    let listing = keys::proc_keys();
    assert!(listing.lines().any(|l| l.contains("short-lived") && l.contains("expd")), "{listing}");
    // An expired key can no longer be read
    let mut buf = [0u8; 8];
    assert!(keyctl(11, k as u64, buf.as_mut_ptr() as u64, 8, 0) < 0);
    // Clearing the timeout of a missing key
    assert!(keyctl(15, 0x7fff_0000, 0, 0, 0) < 0);
}

#[test]
fn keyrings_follow_fork_and_exec() {
    let _g = serial();
    proc(7300);
    let k = add("user", "inherited", b"v", SESSION);
    assert!(k > 0);
    keys::on_fork(7300, 7301);
    proc(7301);
    let d = c("inherited");
    let t = c("user");
    let found = keys::dispatch(250, [10, SESSION as i64 as u64, t.as_ptr() as u64, d.as_ptr() as u64, 0, 0]).unwrap();
    assert_eq!(found, k, "the child shares the session keyring");
    // exec drops the thread keyring only; the session one stays
    keys::on_exec(7301, 7301);
    let found = keys::dispatch(250, [10, SESSION as i64 as u64, t.as_ptr() as u64, d.as_ptr() as u64, 0, 0]).unwrap();
    assert_eq!(found, k);
    // request_key finds it too; a missing one is ENOKEY
    let r = keys::dispatch(249, [t.as_ptr() as u64, d.as_ptr() as u64, 0, 0, 0, 0]).unwrap();
    assert_eq!(r, k);
    let m = c("missing");
    assert_eq!(keys::dispatch(249, [t.as_ptr() as u64, m.as_ptr() as u64, 0, 0, 0, 0]).unwrap(), -126);
}

#[test]
fn unlink_invalidate_and_bad_ids() {
    let _g = serial();
    proc(7400);
    let k = add("user", "gone", b"v", PROCESS);
    let ring = keyctl(0, PROCESS as i64 as u64, 1, 0, 0);
    assert!(ring > 0);
    assert_eq!(keyctl(9, k as u64, ring as u64, 0, 0), 0, "unlinked");
    assert!(keyctl(9, k as u64, ring as u64, 0, 0) < 0, "twice");
    let k2 = add("user", "inval", b"v", PROCESS);
    assert_eq!(keyctl(21, k2 as u64, 0, 0, 0), 0);
    let mut buf = [0u8; 8];
    assert!(keyctl(11, k2 as u64, buf.as_mut_ptr() as u64, 8, 0) < 0, "invalidated");
    assert!(keyctl(11, 0x7fff_1234, buf.as_mut_ptr() as u64, 8, 0) < 0);
    // A key read into a bad buffer
    let k3 = add("user", "badbuf", b"value", PROCESS);
    assert_eq!(keyctl(11, k3 as u64, 0, 8, 0), 5, "a NULL buffer asks for the size, as on Linux");
    // Size 0: the length only
    assert_eq!(keyctl(11, k3 as u64, 0, 0, 0), 5);
}
