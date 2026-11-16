//! Attribute-based access control (ABAC) in the kernel: where the pure engine
//! ([`super::abac_core`]) meets processes, files and system calls.
//!
//! - **Subjects**: a login session's attributes (`department=Finance`, `clearance=Secret`,
//!   `account=child`, ...). Root sets them for a process (hydra-logind at login, the console
//!   login for the kernel shell); every child inherits them, `execve` keeps them. Identical
//!   sets share one ID ([`Process::abac`](super::proc::Process)).
//! - **Labels**: a file's or folder's attributes, in the `security.hydra.labels` extended
//!   attribute (`key=value` lines). Anyone may read them; only `CAP_SYS_ADMIN` may set or
//!   remove them (the `security.` namespace rule in vfs.rs). New files and folders get their
//!   folder's labels ([`inherited_labels`], called from acl.rs's creation plan). The label
//!   `policy=<name>` applies a policy to the file (and, inherited, to a folder's contents).
//! - **Enforcement** ([`check`], [`check_delete`]): after the mode bits and ACLs allowed an
//!   access, the policy may only take rights away (as Windows central access policies do).
//!   Root is not restricted. A file without extended attributes, a process without a
//!   subject, or no loaded policy skip it after one or two loads.
//! - **Caches**: labels by `(inode, generation)` (emptied when labels are set or removed),
//!   decisions by `(policy generation, subject, label set, local minute
//!   when a rule reads the time)` in a fixed table: a repeated decision takes no allocation
//!   and no evaluation.
//! - **Audit** ([`audit`]): denials, and where staged (proposed) rules would decide
//!   differently, go to a fixed ring that root drains with `PR_HYDRA_ACCESS`
//!   `READ_AUDIT` (hydra-accessd writes them to `/var/log/hydra/access.log`).
//! - **App control** ([`exec_check`]): `execve` asks the app rules whether the subject may
//!   run the program.
//!
//! Interface: `prctl(PR_HYDRA_ACCESS, command, ...)`, see [`prctl`].
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::Mutex;

use super::abac_core::{AttrSet, Compiled, Decision, Interner, Sha256};
use crate::fs::zfs::zpl::Attr;
use crate::fs::ZfsClient;

const EPERM: i64 = -1;
const ESRCH: i64 = -3;
const EFAULT: i64 = -14;
const EINVAL: i64 = -22;
const ENOSPC: i64 = -28;
const ERANGE: i64 = -34;

/// `prctl` option: `PR_HYDRA_ACCESS` ("HYD" 1).
pub const PR_HYDRA_ACCESS: u64 = 0x4859_4401;
/// The labels attribute.
pub const LABELS: &[u8] = b"security.hydra.labels";

/// Commands (`prctl(PR_HYDRA_ACCESS, cmd, ...)`).
pub mod cmd {
    /// `(ptr, len)`: loads a compiled policy (root); `len` 0 unloads.
    pub const LOAD: u64 = 1;
    /// `(pid, ptr, len)`: sets a process's subject attributes (root); `len` 0 clears.
    pub const SET_SUBJECT: u64 = 2;
    /// `(pid, buf, size)`: a process's subject attributes (another's: root).
    pub const GET_SUBJECT: u64 = 3;
    /// `(0, buf, size)`: takes the audit records that fit (root).
    pub const READ_AUDIT: u64 = 4;
    /// `(query, len | size << 32, buf)`: evaluates a query (anyone), see
    /// [`super::evaluate`]. (glibc's `prctl` passes four arguments after the option.)
    pub const EVALUATE: u64 = 5;
    /// `(0, buf, size)`: counters.
    pub const STATUS: u64 = 6;
}

/// A policy with rules is loaded.
static ACTIVE: AtomicBool = AtomicBool::new(false);
/// A policy with app rules is loaded.
static APPS: AtomicBool = AtomicBool::new(false);
/// Policy generation (decision cache tag).
static GEN: AtomicU32 = AtomicU32::new(1);
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static CHECKS: AtomicU64 = AtomicU64::new(0);
/// Label reads from the file server (label cache misses).
static LABEL_READS: AtomicU64 = AtomicU64::new(0);
/// Bumped by every label change (see [`labels_of`]).
static LABEL_EPOCH: AtomicU64 = AtomicU64::new(0);
/// The console login's subject (processes the kernel shell starts).
static CONSOLE: AtomicU32 = AtomicU32::new(0);

struct State {
    it: Interner,
    policy: Option<Arc<Compiled>>,
    /// Subject `i + 1`.
    subjects: Vec<AttrSet>,
    /// Label set `i + 1` and its raw text.
    labelsets: Vec<(AttrSet, Arc<[u8]>)>,
    /// Label set of `(inode, generation)`; 0 none. Every label change goes through
    /// [`labels_changed`] (the xattr calls) or makes a new inode (inheritance).
    label_cache: BTreeMap<(u64, u64), u32>,
}

static STATE: Mutex<Option<State>> = Mutex::new(None);

fn with_state<R>(f: impl FnOnce(&mut State) -> R) -> R {
    let mut g = STATE.lock();
    let s = g.get_or_insert_with(|| State {
        it: Interner::new(),
        policy: None,
        subjects: Vec::new(),
        labelsets: Vec::new(),
        label_cache: BTreeMap::new(),
    });
    f(s)
}

/// Most distinct subjects and label sets.
const MAX_SETS: usize = 4096;
/// Label cache entries before it is emptied.
const MAX_LABEL_CACHE: usize = 8192;

// ----------------------------------------------------------------------
// Decision cache
// ----------------------------------------------------------------------

const SLOTS: usize = 1024;

#[derive(Clone, Copy)]
struct Slot {
    gen: u32,
    subject: u32,
    labels: u32,
    env: u32,
    d: Decision,
}

static DECISIONS: Mutex<[Slot; SLOTS]> = Mutex::new([Slot { gen: 0, subject: 0, labels: 0, env: 0, d: Decision::OPEN }; SLOTS]);

fn slot_of(gen: u32, subject: u32, labels: u32, env: u32) -> usize {
    let h = (gen as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ ((subject as u64) << 32 | labels as u64).wrapping_mul(0xC2B2_AE3D_27D4_EB4F) ^ env as u64;
    (h ^ (h >> 29)) as usize % SLOTS
}

/// Seconds since the epoch, UTC.
fn now() -> i64 {
    crate::arch::rtc::now().0 as i64
}

/// The environment key of a decision: the local minute of the week when some rule reads
/// the time (decisions change with it), else 0.
fn env_key(p: &Compiled) -> u32 {
    if !p.uses_time {
        return 0;
    }
    let l = now() + p.tz as i64;
    (l.div_euclid(60).rem_euclid(7 * 24 * 60)) as u32 + 1
}

/// The decision for subject `subject` on label set `labels`.
fn decision(subject: u32, labels: u32) -> Decision {
    let gen = GEN.load(Ordering::Acquire);
    // Policy and the two sets (copied out: the evaluation runs without the state lock)
    let Some((p, user, res)) = with_state(|s| {
        let p = s.policy.clone()?;
        let user = *s.subjects.get(subject as usize - 1)?;
        let res = s.labelsets.get(labels as usize - 1)?.0;
        Some((p, user, res))
    }) else {
        return Decision::OPEN;
    };
    let env = env_key(&p);
    let i = slot_of(gen, subject, labels, env);
    {
        let t = DECISIONS.lock();
        let s = &t[i];
        if s.gen == gen && s.subject == subject && s.labels == labels && s.env == env {
            HITS.fetch_add(1, Ordering::Relaxed);
            return s.d;
        }
    }
    MISSES.fetch_add(1, Ordering::Relaxed);
    let d = p.decide(&user, &res, &p.env_at(now()));
    DECISIONS.lock()[i] = Slot { gen, subject, labels, env, d };
    d
}

// ----------------------------------------------------------------------
// Labels and subjects
// ----------------------------------------------------------------------

/// Interns an attribute set (identical sets share an ID); 0 for an empty one.
fn intern_set(list: &mut Vec<AttrSet>, set: AttrSet) -> Result<u32, i64> {
    if set.is_empty() {
        return Ok(0);
    }
    if let Some(i) = list.iter().position(|s| *s == set) {
        return Ok(i as u32 + 1);
    }
    if list.len() >= MAX_SETS {
        return Err(ENOSPC);
    }
    list.push(set);
    Ok(list.len() as u32)
}

/// The label set of a file (0: no labels).
fn labels_of(attr: &Attr) -> u32 {
    if !attr.has_xattr {
        return 0;
    }
    // Not keyed by change time: a folder's changes with every file made in it, and a
    // labelled folder would be read again for each
    let key = (attr.ino, attr.generation);
    if let Some(id) = with_state(|s| s.label_cache.get(&key).copied()) {
        return id;
    }
    // Read outside the lock (a file server call); a label change meanwhile (epoch moved)
    // means the answer is not cached
    let epoch = LABEL_EPOCH.load(Ordering::Acquire);
    LABEL_READS.fetch_add(1, Ordering::Relaxed);
    let raw = ZfsClient::getxattr(attr.ino, LABELS).ok();
    with_state(|s| {
        let id = match raw.as_deref().and_then(|r| core::str::from_utf8(r).ok()) {
            Some(text) => match AttrSet::parse(&mut s.it, text, true) {
                Ok(set) if !set.is_empty() => match s.labelsets.iter().position(|(x, _)| *x == set) {
                    Some(i) => i as u32 + 1,
                    None if s.labelsets.len() < MAX_SETS => {
                        s.labelsets.push((set, Arc::from(raw.as_deref().unwrap_or(&[]))));
                        s.labelsets.len() as u32
                    }
                    None => 0,
                },
                _ => 0,
            },
            None => 0,
        };
        if s.label_cache.len() >= MAX_LABEL_CACHE {
            s.label_cache.clear();
        }
        if LABEL_EPOCH.load(Ordering::Acquire) == epoch {
            s.label_cache.insert(key, id);
        }
        id
    })
}

/// The labels a new file or folder in directory `dir` gets (its folder's).
pub fn inherited_labels(dir: &Attr) -> Option<Vec<u8>> {
    let id = labels_of(dir);
    if id == 0 {
        return None;
    }
    with_state(|s| s.labelsets.get(id as usize - 1).map(|(_, raw)| raw.to_vec()))
}

/// A label attribute changed on some file: forget the cached labels.
pub fn labels_changed() {
    with_state(|s| {
        LABEL_EPOCH.fetch_add(1, Ordering::AcqRel);
        s.label_cache.clear()
    });
}

/// The calling process's subject (0: none).
fn current_subject() -> u32 {
    super::proc::abac_subject(super::proc::current_ids().1)
}

/// The console login's subject, for processes the kernel shell starts.
pub fn console_subject() -> u32 {
    CONSOLE.load(Ordering::Relaxed)
}

/// The console login: attaches `/etc/hydra/access/subjects/<user>` (read by the caller
/// from the Ubuntu root) to the processes the shell starts from now on; `None` logs out.
pub fn console_login(attrs: Option<&str>) {
    let id = match attrs {
        Some(text) => with_state(|s| AttrSet::parse(&mut s.it, text, true).ok().and_then(|set| intern_set(&mut s.subjects, set).ok())).unwrap_or(0),
        None => 0,
    };
    CONSOLE.store(id, Ordering::Relaxed);
}

/// Whether a policy is loaded (callers skip path bookkeeping otherwise).
#[inline]
pub fn active() -> bool {
    ACTIVE.load(Ordering::Relaxed)
}

// ----------------------------------------------------------------------
// Enforcement
// ----------------------------------------------------------------------

/// Whether the caller (not root: may_access returns earlier for root) may access a file
/// for `want` (`r` 4, `w` 2, `x` 1) under the access policies. Called after the mode bits
/// and ACLs allowed it.
#[inline]
pub fn check(attr: &Attr, want: u32) -> bool {
    if !ACTIVE.load(Ordering::Relaxed) || !attr.has_xattr {
        return true;
    }
    // A folder's x (enter it, reach what is inside) goes with its read right, as Windows'
    // "read" includes listing and traversing
    let mut want = want as u8 & 7;
    if attr.is_dir() && want & super::abac_core::X != 0 {
        want = (want & !super::abac_core::X) | super::abac_core::R;
    }
    check_slow(attr, want)
}

/// Whether the caller may delete (unlink, rmdir, move away) a file.
pub fn check_delete(attr: &Attr) -> bool {
    if !ACTIVE.load(Ordering::Relaxed) || !attr.has_xattr || super::vfs::creds().euid == 0 {
        return true;
    }
    check_slow(attr, super::abac_core::D)
}

#[inline(never)]
fn check_slow(attr: &Attr, want: u8) -> bool {
    CHECKS.fetch_add(1, Ordering::Relaxed);
    let subject = current_subject();
    if subject == 0 {
        return true;
    }
    let labels = labels_of(attr);
    if labels == 0 {
        return true;
    }
    let d = decision(subject, labels);
    if !d.covered {
        return true;
    }
    let ok = d.enforced & want == want;
    let would = d.proposed & want == want;
    if !ok || ok != would {
        let kind = match (ok, would) {
            (false, false) => Kind::Deny,
            (true, false) => Kind::WouldDeny,
            _ => Kind::DenyStagedAllows,
        };
        let rule = d.deciding_rule(want, ok).or_else(|| d.deciding_rule(want, !ok));
        audit(kind, attr.ino, want, rule, None);
    }
    ok
}

/// App control at `execve`: whether the caller may run `path` (inode `attr`). `parent`
/// gives the attributes of the program's folder (for the "installed by the
/// administrator" rule).
pub fn exec_check(path: &str, attr: &Attr, parent: &mut dyn FnMut() -> Option<Attr>) -> bool {
    if !APPS.load(Ordering::Relaxed) {
        return true;
    }
    let subject = current_subject();
    if subject == 0 || super::vfs::creds().euid == 0 {
        return true;
    }
    let Some((p, user)) = with_state(|s| Some((s.policy.clone()?, *s.subjects.get(subject as usize - 1)?))) else { return true };
    let env = p.env_at(now());
    let ino = attr.ino;
    let size = attr.size;
    let mut hash = || file_hash(ino, size);
    let (uid, mode) = (attr.uid, attr.mode);
    let mut trusted = || uid == 0 && mode & 0o022 == 0 && parent().is_some_and(|d| d.uid == 0 && d.mode & 0o022 == 0);
    let d = p.app_decide(&user, &env, path, &mut hash, &mut trusted);
    if !d.allowed || d.allowed != d.would_allow {
        let kind = match (d.allowed, d.would_allow) {
            (false, false) => Kind::AppDeny,
            (true, false) => Kind::AppWouldDeny,
            _ => Kind::AppDenyStagedAllows,
        };
        let rule = if !d.allowed { d.rule } else { d.would_rule };
        audit(kind, ino, super::abac_core::X, rule.checked_sub(1).map(|r| r as usize), Some(path));
    }
    d.allowed
}

/// SHA-256 of a program (cached by inode, generation and size).
fn file_hash(ino: u64, size: u64) -> Option<[u8; 32]> {
    static CACHE: Mutex<BTreeMap<(u64, u64), [u8; 32]>> = Mutex::new(BTreeMap::new());
    if let Some(h) = CACHE.lock().get(&(ino, size)) {
        return Some(*h);
    }
    if size > 512 << 20 {
        return None;
    }
    let mut h = Sha256::new();
    let mut buf = alloc::vec![0u8; 64 * 1024];
    let mut off = 0u64;
    while off < size {
        let n = crate::fs::zfs::with_server(|s| s.read(ino, off, &mut buf)).ok()?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        off += n as u64;
    }
    let out = h.finish();
    let mut c = CACHE.lock();
    if c.len() > 1024 {
        c.clear();
    }
    c.insert((ino, size), out);
    Some(out)
}

// ----------------------------------------------------------------------
// Audit
// ----------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Deny,
    WouldDeny,
    DenyStagedAllows,
    AppDeny,
    AppWouldDeny,
    AppDenyStagedAllows,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Deny => "deny",
            Kind::WouldDeny => "staged-would-deny",
            Kind::DenyStagedAllows => "deny-staged-would-allow",
            Kind::AppDeny => "app-deny",
            Kind::AppWouldDeny => "app-staged-would-deny",
            Kind::AppDenyStagedAllows => "app-deny-staged-would-allow",
        }
    }
    fn is_app(self) -> bool {
        matches!(self, Kind::AppDeny | Kind::AppWouldDeny | Kind::AppDenyStagedAllows)
    }
}

const PATH_MAX: usize = 160;

#[derive(Clone, Copy)]
struct Record {
    time: i64,
    kind: Kind,
    pid: u64,
    uid: u32,
    ino: u64,
    want: u8,
    gen: u32,
    rule: u16,
    count: u32,
    exe: [u8; 32],
    exe_len: u8,
    path: [u8; PATH_MAX],
    path_len: u8,
}

const RING: usize = 256;

struct Audit {
    r: [Option<Record>; RING],
    head: usize,
    len: usize,
    dropped: u64,
}

static AUDIT: Mutex<Audit> = Mutex::new(Audit { r: [None; RING], head: 0, len: 0, dropped: 0 });
/// A record waits for its path ([`note_path`]).
static UNPATHED: AtomicBool = AtomicBool::new(false);

fn copy_trunc<const N: usize>(dst: &mut [u8; N], src: &[u8]) -> u8 {
    // The end of a long path says more than its start
    let s = if src.len() > N { &src[src.len() - N..] } else { src };
    dst[..s.len()].copy_from_slice(s);
    s.len() as u8
}

fn audit(kind: Kind, ino: u64, want: u8, rule: Option<usize>, path: Option<&str>) {
    let pid = super::proc::current_ids().1;
    let uid = super::vfs::creds().uid;
    let gen = GEN.load(Ordering::Relaxed);
    let exe = crate::task::with_current_task_mut(|t| t.exe.clone()).flatten();
    let mut rec = Record {
        time: now(),
        kind,
        pid,
        uid,
        ino,
        want,
        gen,
        rule: rule.map_or(0, |r| r as u16 + 1),
        count: 1,
        exe: [0; 32],
        exe_len: 0,
        path: [0; PATH_MAX],
        path_len: 0,
    };
    if let Some(e) = exe.as_deref() {
        let base = e.rsplit('/').next().unwrap_or(e);
        rec.exe_len = copy_trunc(&mut rec.exe, base.as_bytes());
    }
    if let Some(p) = path {
        rec.path_len = copy_trunc(&mut rec.path, p.as_bytes());
    }
    let mut a = AUDIT.lock();
    // The same event again (a program retrying, a folder listed twice): count it
    if a.len > 0 {
        let last = (a.head + a.len - 1) % RING;
        if let Some(l) = a.r[last].as_mut() {
            if l.kind == kind && l.pid == pid && l.ino == ino && l.want == want && l.gen == gen && l.time + 60 > rec.time {
                l.count = l.count.saturating_add(1);
                return;
            }
        }
    }
    if a.len == RING {
        a.head = (a.head + 1) % RING;
        a.len -= 1;
        a.dropped += 1;
    }
    let at = (a.head + a.len) % RING;
    a.r[at] = Some(rec);
    a.len += 1;
    if path.is_none() {
        UNPATHED.store(true, Ordering::Relaxed);
    }
}

/// Gives the latest audit record about inode `ino` from this process its path (the open
/// or exec path that caused it). Cheap when nothing waits for a path.
pub fn note_path(ino: u64, path: &str) {
    if !UNPATHED.load(Ordering::Relaxed) {
        return;
    }
    let pid = super::proc::current_ids().1;
    let mut a = AUDIT.lock();
    if a.len > 0 {
        let last = (a.head + a.len - 1) % RING;
        if let Some(l) = a.r[last].as_mut() {
            if l.pid == pid && l.ino == ino && l.path_len == 0 {
                l.path_len = copy_trunc(&mut l.path, path.as_bytes());
            }
        }
    }
    UNPATHED.store(false, Ordering::Relaxed);
}

/// Escapes a token for the text formats (space, `%`, `=`, `,`, control characters).
fn esc(out: &mut String, s: &[u8]) {
    for &b in s {
        if b <= b' ' || b == b'%' || b == b'=' || b == b',' || b >= 0x7f {
            out.push_str(&alloc::format!("%{:02X}", b));
        } else {
            out.push(b as char);
        }
    }
}

fn format_record(r: &Record, p: Option<&Compiled>) -> String {
    let mut s = alloc::format!(
        "{} {} pid={} uid={} want={} ino={} count={}",
        r.time,
        r.kind.name(),
        r.pid,
        r.uid,
        super::abac_core::format_actions(r.want),
        r.ino,
        r.count
    );
    let (rule, policy) = match (p, r.rule.checked_sub(1)) {
        (Some(p), Some(i)) if r.gen == GEN.load(Ordering::Relaxed) => {
            if r.kind.is_app() {
                (p.apps.get(i as usize).map(|a| a.name.clone()), Some(String::from("app-control")))
            } else {
                let rule = p.rules.get(i as usize);
                (rule.map(|x| x.name.clone()), rule.and_then(|x| p.policies.get(x.policy)).map(|x| x.name.clone()))
            }
        }
        _ => (None, None),
    };
    if let Some(rule) = rule {
        s.push_str(" rule=");
        esc(&mut s, rule.as_bytes());
    }
    if let Some(policy) = policy {
        s.push_str(" policy=");
        esc(&mut s, policy.as_bytes());
    }
    s.push_str(" exe=");
    esc(&mut s, &r.exe[..r.exe_len as usize]);
    if r.path_len > 0 {
        s.push_str(" path=");
        esc(&mut s, &r.path[..r.path_len as usize]);
    }
    s.push('\n');
    s
}

// ----------------------------------------------------------------------
// Interface
// ----------------------------------------------------------------------

fn is_admin() -> bool {
    crate::task::with_current_task_mut(|t| t.euid == 0 && t.caps.has(1 << 21)).unwrap_or(false)
}

fn read_user(ptr: u64, len: u64) -> Result<String, i64> {
    if len > 1 << 20 {
        return Err(EINVAL);
    }
    let b = super::vfs::copy_in(ptr, len as usize).map_err(|_| EFAULT)?;
    String::from_utf8(b).map_err(|_| EINVAL)
}

fn write_user(ptr: u64, size: u64, data: &[u8]) -> i64 {
    if size == 0 {
        return data.len() as i64;
    }
    if (size as usize) < data.len() {
        return ERANGE;
    }
    match super::vfs::copy_out(ptr, data) {
        Ok(()) => data.len() as i64,
        Err(e) => e,
    }
}

/// Parses and loads a compiled policy.
fn install(text: &str) -> Result<(), ()> {
    let r = with_state(|s| match Compiled::parse(&mut s.it, text) {
        Ok(c) => {
            let (rules, apps) = (!c.rules.is_empty(), c.has_apps());
            s.policy = Some(Arc::new(c));
            GEN.fetch_add(1, Ordering::AcqRel);
            ACTIVE.store(rules, Ordering::Release);
            APPS.store(apps, Ordering::Release);
            Ok(())
        }
        Err(e) => Err(e),
    });
    r.map_err(|(line, why)| crate::kprintln!("[access] policy rejected: line {}: {}", line, why))
}

/// The compiled policy hydra-access writes (relative to the system root).
pub const POLICY_FILE: &str = "/etc/hydra/access/policy.compiled";

/// Loads the system's saved policy the first time the Ubuntu root is set up (before any
/// login), so it is enforced from boot; hydra-access reloads it after every change.
pub fn boot_load(root: &str) {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::AcqRel) {
        return;
    }
    let path = alloc::format!("{}{}", root.trim_end_matches('/'), POLICY_FILE);
    let Ok(st) = ZfsClient::file_stat(&path) else { return };
    let mut buf = alloc::vec![0u8; st.size as usize];
    let Ok(n) = ZfsClient::read_file_by_path(&path, &mut buf) else { return };
    buf.truncate(n);
    if let Ok(text) = core::str::from_utf8(&buf) {
        if install(text).is_ok() {
            crate::kprintln!("[access] policy loaded from {}", path);
        }
    }
}

/// `prctl(PR_HYDRA_ACCESS, cmd, a2, a3, a4, a5)`.
pub fn prctl(a: [u64; 6]) -> i64 {
    match a[1] {
        cmd::LOAD => {
            if !is_admin() {
                return EPERM;
            }
            if a[3] == 0 {
                with_state(|s| s.policy = None);
                ACTIVE.store(false, Ordering::Release);
                APPS.store(false, Ordering::Release);
                GEN.fetch_add(1, Ordering::AcqRel);
                return 0;
            }
            let text = match read_user(a[2], a[3]) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match install(&text) {
                Ok(()) => 0,
                Err(_) => EINVAL,
            }
        }
        cmd::SET_SUBJECT => {
            if !is_admin() {
                return EPERM;
            }
            let pid = if a[2] == 0 { super::proc::current_ids().1 } else { super::ns::pid_from_caller(a[2]) };
            let text = match read_user(a[3], a[4]) {
                Ok(t) => t,
                Err(e) => return e,
            };
            let id = with_state(|s| match AttrSet::parse(&mut s.it, &text, true) {
                Ok(set) => intern_set(&mut s.subjects, set),
                Err(_) => Err(EINVAL),
            });
            match id {
                Ok(id) => {
                    if super::proc::set_abac_subject(pid, id) {
                        0
                    } else {
                        ESRCH
                    }
                }
                Err(e) => e,
            }
        }
        cmd::GET_SUBJECT => {
            let me = super::proc::current_ids().1;
            let pid = if a[2] == 0 { me } else { super::ns::pid_from_caller(a[2]) };
            if pid != me && !is_admin() {
                return EPERM;
            }
            if !super::proc::process_exists(pid) {
                return ESRCH;
            }
            let id = super::proc::abac_subject(pid);
            let text = with_state(|s| if id == 0 { String::new() } else { s.subjects[id as usize - 1].format(&s.it) });
            write_user(a[3], a[4], text.as_bytes())
        }
        cmd::READ_AUDIT => {
            if !is_admin() {
                return EPERM;
            }
            let p = with_state(|s| s.policy.clone());
            let mut out = String::new();
            {
                let mut au = AUDIT.lock();
                while au.len > 0 {
                    let h = au.head;
                    let Some(rec) = au.r[h] else { break };
                    let line = format_record(&rec, p.as_deref());
                    if out.len() + line.len() > a[4] as usize {
                        break;
                    }
                    out.push_str(&line);
                    au.r[h] = None;
                    au.head = (h + 1) % RING;
                    au.len -= 1;
                }
            }
            match super::vfs::copy_out(a[3], out.as_bytes()) {
                Ok(()) => out.len() as i64,
                Err(e) => e,
            }
        }
        cmd::EVALUATE => {
            let q = match read_user(a[2], a[3] & 0xFFFF_FFFF) {
                Ok(t) => t,
                Err(e) => return e,
            };
            match evaluate(&q) {
                Ok(text) => write_user(a[4], a[3] >> 32, text.as_bytes()),
                Err(e) => e,
            }
        }
        cmd::STATUS => {
            let (policies, rules, apps, subjects, labelsets, strings) = with_state(|s| {
                let (p, r, ap) = s.policy.as_ref().map_or((0, 0, 0), |p| (p.policies.len(), p.rules.len(), p.apps.len()));
                (p, r, ap, s.subjects.len(), s.labelsets.len(), s.it.len())
            });
            let (pending, dropped) = {
                let au = AUDIT.lock();
                (au.len, au.dropped)
            };
            let text = alloc::format!(
                "active={} apps={} generation={} policies={} rules={} app_rules={} subjects={} label_sets={} strings={} checks={} hits={} misses={} label_reads={} audit_pending={} audit_dropped={}\n",
                ACTIVE.load(Ordering::Relaxed) as u8,
                APPS.load(Ordering::Relaxed) as u8,
                GEN.load(Ordering::Relaxed),
                policies,
                rules,
                apps,
                subjects,
                labelsets,
                strings,
                CHECKS.load(Ordering::Relaxed),
                HITS.load(Ordering::Relaxed),
                MISSES.load(Ordering::Relaxed),
                LABEL_READS.load(Ordering::Relaxed),
                pending,
                dropped
            );
            write_user(a[3], a[4], text.as_bytes())
        }
        _ => EINVAL,
    }
}

/// An unprivileged "what if" query, the Effective Access tool's: sections separated by
/// lines `--`: the subject's attributes, the resource's labels, and optionally environment
/// overrides (`time=930`, `weekday=1`, ...) plus `exec=<path>` for an app-control
/// question. Unknown names and values match nothing (the tables do not grow).
///
/// Answer: `enforced=<actions> proposed=<actions> covered=<0|1> rule=<name>
/// would_rule=<name> policy=<name>` and, with `exec=`, `app=<allow|deny>
/// app_staged=<allow|deny> app_rule=<name>`.
pub fn evaluate(q: &str) -> Result<String, i64> {
    let mut parts = q.split("\n--\n");
    let (user_t, res_t, env_t) = (parts.next().unwrap_or(""), parts.next().unwrap_or(""), parts.next().unwrap_or(""));
    let p = with_state(|s| s.policy.clone()).ok_or(-61i64)?; // ENODATA: no policy
    let (user, res, env, exec) = with_state(|s| -> Result<_, i64> {
        let user = AttrSet::parse(&mut s.it, user_t, false).map_err(|_| EINVAL)?;
        let res = AttrSet::parse(&mut s.it, res_t, false).map_err(|_| EINVAL)?;
        let mut env = p.env_at(now());
        let mut exec = None;
        for line in env_t.lines() {
            if let Some(path) = line.strip_prefix("exec=") {
                exec = Some(String::from(path.trim()));
                continue;
            }
            let o = AttrSet::parse(&mut s.it, line, false).map_err(|_| EINVAL)?;
            for &(a, _) in o.entries() {
                env.remove(a);
            }
            for &(a, v) in o.entries() {
                env.push(a, v);
            }
        }
        Ok((user, res, env, exec))
    })?;
    let d = p.decide(&user, &res, &env);
    let name = |r: Option<usize>| r.and_then(|i| p.rules.get(i)).map_or(String::from("-"), |r| r.name.clone());
    // The rule that refused the first missing action, of all four
    let rule = d.deciding_rule(super::abac_core::ALL, false);
    let would = d.deciding_rule(super::abac_core::ALL, true);
    let policy = rule.and_then(|i| p.rules.get(i)).and_then(|r| p.policies.get(r.policy)).map_or(String::from("-"), |x| x.name.clone());
    let mut out = String::new();
    out.push_str(&alloc::format!(
        "enforced={} proposed={} covered={} rule=",
        super::abac_core::format_actions(d.enforced),
        super::abac_core::format_actions(d.proposed),
        d.covered as u8
    ));
    esc(&mut out, name(rule).as_bytes());
    out.push_str(" would_rule=");
    esc(&mut out, name(would).as_bytes());
    out.push_str(" policy=");
    esc(&mut out, policy.as_bytes());
    if let Some(path) = exec {
        let ad = p.app_decide(&user, &env, &path, &mut || None, &mut || path.starts_with("/usr/") || path.starts_with("/bin/") || path.starts_with("/sbin/") || path.starts_with("/opt/"));
        let an = |r: u16| r.checked_sub(1).and_then(|i| p.apps.get(i as usize)).map_or(String::from("-"), |a| a.name.clone());
        out.push_str(&alloc::format!(" app={} app_staged={} app_rule=", if ad.allowed { "allow" } else { "deny" }, if ad.would_allow { "allow" } else { "deny" }));
        esc(&mut out, an(if ad.allowed { ad.would_rule } else { ad.rule }).as_bytes());
    }
    out.push('\n');
    Ok(out)
}
