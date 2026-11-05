//! Namespaces for the Linux personality, as far as Chromium's and Brave's sandbox uses them.
//!
//! - **User namespaces**: `clone`/`unshare` with `CLONE_NEWUSER` give the process a new
//!   namespace with every capability *inside* it ([`crate::task::tcb::Caps::in_userns`]):
//!   those capabilities pass only namespace-scoped checks (`chroot`, creating further
//!   namespaces, writing its own ID maps), never the system-wide ones. `/proc/<pid>/uid_map`,
//!   `gid_map` and `setgroups` work as on Linux for an unprivileged writer: one line
//!   mapping the creator's own ID, written once (`gid_map` only after `setgroups` is
//!   `deny`). `getuid` and friends report IDs as the namespace sees them (unmapped: 65534).
//! - **Network namespaces**: a process in a new one has no network: IPv4 addresses are
//!   unreachable (`connect`, `sendto`, `bind` fail with `ENETUNREACH`).
//! - **PID namespaces**: the first process in a new one (its init) sees itself, and is
//!   seen by the processes in the namespace, as PID 1 (`getpid`, `gettid` of its main
//!   thread, `kill`/`tgkill`/`wait4` targets), its parent as 0, and its namespace dies
//!   with it (every other member gets `SIGKILL`). Other processes keep their system-wide
//!   IDs, and processes outside the namespace are not hidden from it: Chromium's
//!   sandboxed processes cannot see them anyway (an empty root, seccomp filters on
//!   `kill`).
//! - **Mount, IPC, UTS and cgroup namespaces**: accepted and tracked, but they do not
//!   isolate anything yet.
//!
//! Namespace state is per process ([`super::proc::Process::ns`]).

use alloc::string::String;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;

/// New mount namespace.
pub const CLONE_NEWNS: u64 = 0x0002_0000;
/// New cgroup namespace.
pub const CLONE_NEWCGROUP: u64 = 0x0200_0000;
/// New UTS (host name) namespace.
pub const CLONE_NEWUTS: u64 = 0x0400_0000;
/// New IPC namespace.
pub const CLONE_NEWIPC: u64 = 0x0800_0000;
/// New user namespace.
pub const CLONE_NEWUSER: u64 = 0x1000_0000;
/// New PID namespace.
pub const CLONE_NEWPID: u64 = 0x2000_0000;
/// New network namespace.
pub const CLONE_NEWNET: u64 = 0x4000_0000;
/// Every namespace flag `clone` accepts.
pub const CLONE_NEW_ALL: u64 = CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNET;
const CLONE_FS: u64 = 0x200;
const CLONE_FILES: u64 = 0x400;
const CLONE_SIGHAND: u64 = 0x800;
const CLONE_VM: u64 = 0x100;
const CLONE_THREAD: u64 = 0x0001_0000;
const CLONE_SYSVSEM: u64 = 0x0004_0000;

const EINVAL: i64 = -22;
const EPERM: i64 = -1;
const EUSERS: i64 = -87;

/// `CAP_SYS_ADMIN`, needed (in the caller's user namespace) for every other namespace type.
const CAP_SYS_ADMIN: u64 = 1 << 21;
/// User ID reported for a system ID with no mapping in the caller's namespace.
const OVERFLOW_ID: u32 = 65534;
/// Deepest nesting of user namespaces Linux allows.
const MAX_USER_DEPTH: u32 = 32;

/// Namespace inode numbers of the initial namespaces, as a Linux system shows them.
const INIT_IDS: [(&str, u64); 8] = [
    ("cgroup", 4026531835),
    ("ipc", 4026531839),
    ("mnt", 4026531841),
    ("net", 4026531840),
    ("pid", 4026531836),
    ("pid_for_children", 4026531836),
    ("user", 4026531837),
    ("uts", 4026531838),
];

/// Init process of each PID namespace created by `unshare` (namespace id -> system PID).
static PID_NS_INIT: Mutex<alloc::collections::BTreeMap<u64, u64>> = Mutex::new(alloc::collections::BTreeMap::new());

/// Next namespace inode number handed out.
static NEXT_ID: AtomicU64 = AtomicU64::new(4026532200);

fn new_id() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

/// One line of an ID map: `count` IDs from `inner` (in the namespace) map to `outer` (in
/// its parent).
#[derive(Clone, Copy)]
pub struct IdMap {
    inner: u32,
    outer: u32,
    count: u32,
}

/// A user namespace.
pub struct UserNs {
    /// Namespace inode number (`/proc/<pid>/ns/user`).
    id: u64,
    /// Effective user ID of the process that created it (in the system).
    owner_uid: u32,
    /// Effective group ID of the process that created it (in the system).
    owner_gid: u32,
    /// Nesting depth (1 for a child of the initial namespace).
    depth: u32,
    uid_map: Mutex<Option<IdMap>>,
    gid_map: Mutex<Option<IdMap>>,
    /// `setgroups` was set to `deny`.
    setgroups_deny: AtomicBool,
    parent: Option<Arc<UserNs>>,
}

/// A process's namespaces. `None`/0 means the initial namespace.
#[derive(Clone, Default)]
pub struct Ns {
    /// User namespace.
    pub user: Option<Arc<UserNs>>,
    /// PID namespace.
    pub pid: u64,
    /// System-wide PIDs of the init process of each PID namespace the process is in,
    /// outermost first (empty: the initial namespace only).
    pub pid_inits: alloc::vec::Vec<u64>,
    /// The PID namespace children are created in, after `unshare(CLONE_NEWPID)`.
    pub pid_for_children: Option<u64>,
    /// Network namespace.
    pub net: u64,
    /// Mount namespace.
    pub mnt: u64,
    /// IPC namespace.
    pub ipc: u64,
    /// UTS namespace.
    pub uts: u64,
    /// Cgroup namespace.
    pub cgroup: u64,
}

impl Ns {
    /// The namespaces a forked child starts in.
    ///
    /// # Arguments
    /// * `child` - The child's system-wide PID (the init of a PID namespace the parent
    ///   unshared, if it is the first child created in it).
    pub fn for_child(&self, child: u64) -> Ns {
        let mut ns = self.clone();
        if let Some(id) = self.pid_for_children {
            ns.pid = id;
            let init = *PID_NS_INIT.lock().entry(id).or_insert(child);
            ns.pid_inits.push(init);
        }
        ns.pid_for_children = None;
        ns
    }

    /// Inode number of namespace `kind` (`user`, `pid`, ...), for `/proc/<pid>/ns/<kind>`.
    fn id_of(&self, kind: &str) -> Option<u64> {
        let own = match kind {
            "user" => self.user.as_ref().map_or(0, |u| u.id),
            "pid" => self.pid,
            "pid_for_children" => self.pid_for_children.unwrap_or(self.pid),
            "net" => self.net,
            "mnt" => self.mnt,
            "ipc" => self.ipc,
            "uts" => self.uts,
            "cgroup" => self.cgroup,
            _ => return None,
        };
        let init = INIT_IDS.iter().find(|(k, _)| *k == kind)?.1;
        Some(if own == 0 { init } else { own })
    }
}

/// Namespaces of process `pid`.
fn ns_of(pid: u64) -> Option<Ns> {
    super::proc::PROCS.lock().get(&pid).map(|p| p.ns.clone())
}

/// Namespaces of the calling process.
fn current_ns() -> Ns {
    ns_of(super::proc::current_ids().1).unwrap_or_default()
}

/// Whether the caller holds `CAP_SYS_ADMIN` in its own user namespace.
fn has_ns_admin() -> bool {
    crate::task::with_current_task_mut(|t| t.caps.effective & CAP_SYS_ADMIN != 0).unwrap_or(false)
}

/// Creates a user namespace under `parent` owned by the caller.
fn new_user_ns(parent: Option<Arc<UserNs>>) -> Result<Arc<UserNs>, i64> {
    let depth = parent.as_ref().map_or(0, |p| p.depth) + 1;
    if depth > MAX_USER_DEPTH {
        return Err(EUSERS);
    }
    let (euid, egid) = crate::task::with_current_task_mut(|t| (t.euid, t.egid)).unwrap_or((0, 0));
    Ok(Arc::new(UserNs {
        id: new_id(),
        owner_uid: euid,
        owner_gid: egid,
        depth,
        uid_map: Mutex::new(None),
        gid_map: Mutex::new(None),
        setgroups_deny: AtomicBool::new(false),
        parent,
    }))
}

/// Checks the namespace flags of a `clone` before the child is created.
///
/// # Arguments
/// * `flags` - `clone` flags.
///
/// # Returns
/// `Ok(())`, or the errno `clone` fails with.
pub fn check_clone(flags: u64) -> Result<(), i64> {
    let ns = flags & CLONE_NEW_ALL;
    if ns == 0 {
        return Ok(());
    }
    if flags & CLONE_NEWUSER != 0 && flags & (CLONE_THREAD | CLONE_FS) != 0 {
        return Err(EINVAL);
    }
    if flags & CLONE_NEWPID != 0 && flags & CLONE_THREAD != 0 {
        return Err(EINVAL);
    }
    // Other namespace types need CAP_SYS_ADMIN, which a new user namespace provides
    if ns & !CLONE_NEWUSER != 0 && flags & CLONE_NEWUSER == 0 && !has_ns_admin() {
        return Err(EPERM);
    }
    Ok(())
}

/// Puts a new child process into the namespaces its `clone` flags ask for. The child has
/// already inherited the parent's ([`Ns::for_child`]).
///
/// # Arguments
/// * `child` - Child process (thread group) ID.
/// * `flags` - `clone` flags.
pub fn after_clone(child: u64, flags: u64) {
    if flags & CLONE_NEW_ALL == 0 || flags & CLONE_THREAD != 0 {
        return;
    }
    let parent_user = current_ns().user;
    let user = if flags & CLONE_NEWUSER != 0 {
        match new_user_ns(parent_user) {
            Ok(u) => Some(u),
            Err(_) => return,
        }
    } else {
        None
    };
    if let Some(p) = super::proc::PROCS.lock().get_mut(&child) {
        if let Some(u) = user.clone() {
            p.ns.user = Some(u);
        }
        apply_new(&mut p.ns, flags, false);
        if flags & CLONE_NEWPID != 0 {
            p.ns.pid_inits.push(child);
        }
    }
    if user.is_some() {
        let id = crate::task::TaskId(child);
        crate::task::SCHEDULER.lock().with_task_mut(id, |t| t.caps.enter_userns());
    }
}

/// Gives `ns` fresh namespaces of the non-user types in `flags`. With `unshare`, a new
/// PID namespace is for the caller's children only.
fn apply_new(ns: &mut Ns, flags: u64, unshare: bool) {
    if flags & CLONE_NEWPID != 0 {
        if unshare {
            ns.pid_for_children = Some(new_id());
        } else {
            ns.pid = new_id();
        }
    }
    for (flag, slot) in [
        (CLONE_NEWNET, &mut ns.net),
        (CLONE_NEWNS, &mut ns.mnt),
        (CLONE_NEWIPC, &mut ns.ipc),
        (CLONE_NEWUTS, &mut ns.uts),
        (CLONE_NEWCGROUP, &mut ns.cgroup),
    ] {
        if flags & flag != 0 {
            *slot = new_id();
        }
    }
}

/// `unshare(2)`.
///
/// # Arguments
/// * `flags` - What to unshare (`CLONE_NEW*`, `CLONE_FS`, `CLONE_FILES`, ...).
///
/// # Returns
/// 0 on success, or a negative errno.
pub fn sys_unshare(flags: u64) -> i64 {
    const ALLOWED: u64 = CLONE_NEW_ALL | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM | CLONE_THREAD | CLONE_SYSVSEM;
    if flags & !ALLOWED != 0 {
        return EINVAL;
    }
    let (_, pid) = super::proc::current_ids();
    let threads = super::proc::thread_ids_of(pid).len();
    // A new user namespace (and unsharing threads, signal handlers or memory) needs a
    // single-threaded process
    if threads > 1 && flags & (CLONE_NEWUSER | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 {
        return EINVAL;
    }
    let ns_flags = flags & CLONE_NEW_ALL;
    if ns_flags == 0 {
        return 0;
    }
    if ns_flags & !CLONE_NEWUSER != 0 && ns_flags & CLONE_NEWUSER == 0 && !has_ns_admin() {
        return EPERM;
    }
    let user = if ns_flags & CLONE_NEWUSER != 0 {
        match new_user_ns(current_ns().user) {
            Ok(u) => Some(u),
            Err(e) => return e,
        }
    } else {
        None
    };
    if let Some(p) = super::proc::PROCS.lock().get_mut(&pid) {
        if let Some(u) = user.clone() {
            p.ns.user = Some(u);
        }
        apply_new(&mut p.ns, ns_flags, true);
    }
    if user.is_some() {
        crate::task::with_current_task_mut(|t| t.caps.enter_userns());
    }
    0
}

/// System PID of the init process of the caller's PID namespace (`None`: the initial one).
fn caller_pid_init() -> Option<u64> {
    let (_, pid) = super::proc::current_ids();
    super::proc::PROCS.lock().get(&pid).and_then(|p| p.ns.pid_inits.last().copied())
}

/// A system-wide process or thread ID as the caller's PID namespace shows it.
///
/// # Arguments
/// * `id` - System-wide ID.
///
/// # Returns
/// 1 for the init of the caller's namespace, otherwise `id`.
pub fn pid_to_caller(id: u64) -> u64 {
    match caller_pid_init() {
        Some(init) if init == id => 1,
        _ => id,
    }
}

/// A process or thread ID given by the caller, as a system-wide ID.
///
/// # Arguments
/// * `id` - ID in the caller's PID namespace.
///
/// # Returns
/// The init's system PID for 1 inside a namespace, otherwise `id`.
pub fn pid_from_caller(id: u64) -> u64 {
    match caller_pid_init() {
        Some(init) if id == 1 => init,
        _ => id,
    }
}

/// Maps a system ID into user namespace `ns` (through every namespace above it).
fn map_down(ns: &UserNs, id: u32, gid: bool) -> Option<u32> {
    let above = match &ns.parent {
        Some(p) => map_down(p, id, gid)?,
        None => id,
    };
    let map = (if gid { &ns.gid_map } else { &ns.uid_map }).lock().as_ref().copied()?;
    let offset = above.checked_sub(map.outer)?;
    (offset < map.count).then(|| map.inner + offset)
}

/// A system user (`gid == false`) or group ID as the calling process's user namespace sees
/// it: unmapped IDs read as 65534.
///
/// # Arguments
/// * `id` - System-wide ID.
/// * `gid` - Whether `id` is a group ID.
///
/// # Returns
/// The ID inside the caller's namespace.
pub fn id_for_caller(id: u32, gid: bool) -> u32 {
    match current_ns().user {
        Some(ns) => map_down(&ns, id, gid).unwrap_or(OVERFLOW_ID),
        None => id,
    }
}

/// Whether the calling process may not change its supplementary groups (`setgroups` is
/// `deny` in its user namespace).
pub fn setgroups_denied() -> bool {
    current_ns().user.is_some_and(|u| u.setgroups_deny.load(Ordering::Relaxed))
}

/// Whether the calling process is in a network namespace of its own (which has no
/// network).
pub fn net_isolated() -> bool {
    current_ns().net != 0
}

/// Whether `rest` (a path after `/proc/`) is one of the namespace files of a process:
/// `<pid>/uid_map`, `gid_map`, `setgroups`, or `ns/<kind>`.
pub fn is_ns_file(rest: &str) -> bool {
    let Some((who, file)) = rest.split_once('/') else { return false };
    let numeric = !who.is_empty() && who.bytes().all(|b| b.is_ascii_digit());
    (who == "self" || who == "thread-self" || numeric)
        && (matches!(file, "uid_map" | "gid_map" | "setgroups")
            || file.strip_prefix("ns/").is_some_and(|k| INIT_IDS.iter().any(|(n, _)| *n == k)))
}

/// Process ID and file name of a namespace file path (after `/proc/`).
fn split(rest: &str) -> Option<(u64, &str)> {
    let (who, file) = rest.split_once('/')?;
    let pid = match who {
        "self" | "thread-self" => super::proc::current_ids().1,
        n => n.parse().ok()?,
    };
    Some((pid, file))
}

/// Target of `/proc/<pid>/ns/<kind>` (`user:[4026531837]`).
///
/// # Arguments
/// * `rest` - Path after `/proc/`.
///
/// # Returns
/// The link text, or `None` if the path is not a namespace link of a live process.
pub fn ns_link(rest: &str) -> Option<String> {
    let (pid, file) = split(rest)?;
    let kind = file.strip_prefix("ns/")?;
    let id = ns_of(pid)?.id_of(kind)?;
    let shown = if kind == "pid_for_children" { "pid" } else { kind };
    Some(alloc::format!("{}:[{}]", shown, id))
}

/// Contents of `/proc/<pid>/uid_map`, `gid_map` or `setgroups`.
///
/// # Arguments
/// * `rest` - Path after `/proc/`.
///
/// # Returns
/// The file text (empty for a process that no longer exists).
pub fn read_file(rest: &str) -> String {
    let Some((pid, file)) = split(rest) else { return String::new() };
    let Some(ns) = ns_of(pid) else { return String::new() };
    let line = |m: IdMap| alloc::format!("{:>10} {:>10} {:>10}\n", m.inner, m.outer, m.count);
    match (file, ns.user) {
        ("setgroups", Some(u)) if u.setgroups_deny.load(Ordering::Relaxed) => String::from("deny\n"),
        ("setgroups", _) => String::from("allow\n"),
        (_, None) => line(IdMap { inner: 0, outer: 0, count: u32::MAX }),
        ("uid_map", Some(u)) => u.uid_map.lock().map(line).unwrap_or_default(),
        (_, Some(u)) => u.gid_map.lock().map(line).unwrap_or_default(),
    }
}

/// Writes `/proc/<pid>/uid_map`, `gid_map` or `setgroups`.
///
/// # Arguments
/// * `rest` - Path after `/proc/`.
/// * `buf` - Bytes written.
///
/// # Returns
/// Bytes accepted, or a negative errno.
pub fn write_file(rest: &str, buf: &[u8]) -> i64 {
    let Some((pid, file)) = split(rest) else { return EINVAL };
    let Some(user) = ns_of(pid).and_then(|n| n.user) else { return EPERM };
    let text = core::str::from_utf8(buf).unwrap_or("").trim();
    let (euid, egid, privileged) = crate::task::with_current_task_mut(|t| {
        (t.euid, t.egid, t.caps.has(crate::task::tcb::Caps::SETUID) && t.caps.has(crate::task::tcb::Caps::SETGID))
    })
    .unwrap_or((u32::MAX, u32::MAX, false));
    if file == "setgroups" {
        let deny = match text {
            "deny" => true,
            "allow" => false,
            _ => return EINVAL,
        };
        // Fixed once the group map is written
        if user.gid_map.lock().is_some() || (!privileged && euid != user.owner_uid) {
            return EPERM;
        }
        user.setgroups_deny.store(deny, Ordering::Relaxed);
        return buf.len() as i64;
    }
    let gid = file == "gid_map";
    let mut fields = text.split_ascii_whitespace().map(|f| f.parse::<u32>());
    let (Some(Ok(inner)), Some(Ok(outer)), Some(Ok(count)), None) = (fields.next(), fields.next(), fields.next(), fields.next()) else {
        return EINVAL;
    };
    if count == 0 || inner.checked_add(count - 1).is_none() || outer.checked_add(count - 1).is_none() {
        return EINVAL;
    }
    // Unprivileged: one ID, the creator's own (groups only once setgroups is denied)
    let own = if gid { outer == user.owner_gid && euid == user.owner_uid && egid == user.owner_gid } else { outer == user.owner_uid && euid == user.owner_uid };
    let unprivileged_ok = count == 1 && own && (!gid || user.setgroups_deny.load(Ordering::Relaxed));
    if !unprivileged_ok && !privileged {
        return EPERM;
    }
    let mut slot = if gid { user.gid_map.lock() } else { user.uid_map.lock() };
    if slot.is_some() {
        return EPERM;
    }
    *slot = Some(IdMap { inner, outer, count });
    buf.len() as i64
}
