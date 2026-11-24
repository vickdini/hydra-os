//! Namespaces for the Linux personality, as far as the Chromium and Firefox sandboxes use them.
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

use crate::lx::proc::{self as mech, NsChange, NsKind};

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
const EBADF: i64 = -9;
const ESRCH: i64 = -3;
const EUSERS: i64 = -87;

/// `CAP_SYS_ADMIN`, needed (in the caller's user namespace) for every other namespace type.
const CAP_SYS_ADMIN: u64 = 1 << 21;
/// User ID reported for a system ID with no mapping in the caller's namespace.
const OVERFLOW_ID: u32 = 65534;
/// Default `max_user_namespaces`.
const MAX_USER_NAMESPACES: u64 = 63621;
/// Limit of user namespaces reached.
const ENOSPC: i64 = -28;
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

/// The init processes of each PID namespace that has one, outermost first (namespace id ->
/// system PIDs; the last is the namespace's own init).
static PID_NS_INIT: Mutex<alloc::collections::BTreeMap<u64, alloc::vec::Vec<u64>>> = Mutex::new(alloc::collections::BTreeMap::new());

/// Next namespace inode number handed out.
static NEXT_ID: AtomicU64 = AtomicU64::new(4026532200);

pub(crate) fn new_id() -> u64 {
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
    pub(crate) id: u64,
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
    /// `/proc/sys/user/max_user_namespaces` here: how many user namespaces may exist below.
    max_children: AtomicU64,
    /// User namespaces created below (at any depth).
    children: AtomicU64,
    parent: Option<Arc<UserNs>>,
}

impl Drop for UserNs {
    /// A namespace that is gone no longer counts against the limits above it (Linux's
    /// `dec_user_namespaces` when a namespace is freed).
    fn drop(&mut self) {
        let mut up = self.parent.clone();
        while let Some(a) = up {
            a.children.fetch_sub(1, Ordering::Relaxed);
            up = a.parent.clone();
        }
    }
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
            // The first child is the namespace's init; later ones join it (also after setns)
            let chain = PID_NS_INIT
                .lock()
                .entry(id)
                .or_insert_with(|| {
                    let mut c = self.pid_inits.clone();
                    c.push(child);
                    c
                })
                .clone();
            ns.pid_inits = chain;
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
    // Every namespace above has a limit on how many may exist below it
    let mut up = parent.clone();
    while let Some(a) = up {
        if a.children.load(Ordering::Relaxed) >= a.max_children.load(Ordering::Relaxed) {
            return Err(ENOSPC);
        }
        up = a.parent.clone();
    }
    let mut up = parent.clone();
    while let Some(a) = up {
        a.children.fetch_add(1, Ordering::Relaxed);
        up = a.parent.clone();
    }
    let (euid, egid) = crate::task::with_current_task_mut(|t| (t.euid, t.egid)).unwrap_or((0, 0));
    Ok(Arc::new(UserNs {
        id: new_id(),
        owner_uid: euid,
        owner_gid: egid,
        depth,
        uid_map: Mutex::new(None),
        gid_map: Mutex::new(None),
        // Inherited, as on Linux: a denied parent denies its children too
        setgroups_deny: AtomicBool::new(parent.as_ref().is_some_and(|p| p.setgroups_deny.load(Ordering::Relaxed))),
        max_children: AtomicU64::new(parent.as_ref().map_or(MAX_USER_NAMESPACES, |p| p.max_children.load(Ordering::Relaxed))),
        children: AtomicU64::new(0),
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
    let parent = current_ns();
    let parent_mnt = parent.mnt;
    let mut child_mnt = 0;
    // (the child starts with the parent's namespaces: the plan is made from those)
    let mut plan = plan_new(&parent, flags, false);
    if let Some(u) = user.clone() {
        plan.insert(0, NsChange::User(Some(u)));
    }
    if let Some(p) = super::proc::PROCS.lock().get_mut(&child) {
        mech::ns_apply(&mut p.ns, &plan);
        if flags & CLONE_NEWPID != 0 {
            p.ns.pid_inits.push(child);
            PID_NS_INIT.lock().insert(p.ns.pid, p.ns.pid_inits.clone());
        }
        child_mnt = p.ns.mnt;
        // wave7 G7-3: posted with the process table held, so it is ordered with every
        // "gone" note (all are posted under this lock)
        if flags & CLONE_NEWNS != 0 {
            note_mntns(child_mnt, parent_mnt);
        }
    }
    if flags & CLONE_NEWNS != 0 {
        // The child's own copy of the mount table
        let fds = crate::task::SCHEDULER.lock().with_process(child, |t| t.fds.clone());
        if let Some(fds) = fds {
            super::mount::copy_ns(parent_mnt, child_mnt, &fds);
        }
    }
    if user.is_some() {
        let id = crate::task::TaskId(child);
        crate::task::SCHEDULER.lock().with_task_mut(id, |t| t.caps.enter_userns());
    }
}

/// Gives `ns` fresh namespaces of the non-user types in `flags`. With `unshare`, a new
/// PID namespace is for the caller's children only.
///
/// wave9 G7a: as changes for `lx::proc::ns_apply` (fresh ids from `lx::proc::ns_new_id`).
fn plan_new(ns: &Ns, flags: u64, unshare: bool) -> alloc::vec::Vec<NsChange> {
    let mut out = alloc::vec::Vec::new();
    if flags & CLONE_NEWPID != 0 {
        out.push(NsChange::Id(if unshare { NsKind::PidForChildren } else { NsKind::Pid }, mech::ns_new_id()));
    }
    for (flag, kind, old) in [
        (CLONE_NEWNET, NsKind::Net, ns.net),
        (CLONE_NEWNS, NsKind::Mnt, ns.mnt),
        (CLONE_NEWIPC, NsKind::Ipc, ns.ipc),
        (CLONE_NEWUTS, NsKind::Uts, ns.uts),
        (CLONE_NEWCGROUP, NsKind::Cgroup, ns.cgroup),
    ] {
        if flags & flag != 0 {
            let id = mech::ns_new_id();
            if flag == CLONE_NEWUTS {
                // A new UTS namespace starts with the old one's names
                super::extra::uts_copy(old, id);
            }
            out.push(NsChange::Id(kind, id));
        }
    }
    out
}

/// `unshare(2)`.
///
/// # Arguments
/// * `flags` - What to unshare (`CLONE_NEW*`, `CLONE_FS`, `CLONE_FILES`, ...).
///
/// # Returns
/// 0 on success, or a negative errno.
pub fn sys_unshare(flags: u64) -> i64 {
    let (tid, pid) = super::proc::current_ids();
    // wave10 G7b-1: lx-proc decided these very flags (it ran the permission check below,
    // then answered with a redirect to the kernel): that check is skipped. The mark is
    // taken first, so no early return leaves it behind.
    let approved = mech::take_approval_mark(tid, 272) == Some(flags);
    const ALLOWED: u64 = CLONE_NEW_ALL | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_VM | CLONE_THREAD | CLONE_SYSVSEM;
    if flags & !ALLOWED != 0 {
        return EINVAL;
    }
    let threads = super::proc::thread_ids_of(pid).len();
    // A new user namespace (and unsharing threads, signal handlers or memory) needs a
    // single-threaded process (wave10 G7b-1: checked here also when approved: a thread
    // may have been made since lx-proc looked)
    if threads > 1 && flags & (CLONE_NEWUSER | CLONE_THREAD | CLONE_SIGHAND | CLONE_VM) != 0 {
        return EINVAL;
    }
    let ns_flags = flags & CLONE_NEW_ALL;
    if ns_flags == 0 {
        return 0;
    }
    if !approved && ns_flags & !CLONE_NEWUSER != 0 && ns_flags & CLONE_NEWUSER == 0 && !has_ns_admin() {
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
    let mine = current_ns();
    let old_mnt = mine.mnt;
    let mut plan = plan_new(&mine, ns_flags, true);
    if let Some(u) = user.clone() {
        plan.insert(0, NsChange::User(Some(u)));
    }
    let new_mnt = mech::ns_set(pid, &plan).map_or(0, |ids| ids.mnt);
    // wave7 G7-3: vfs-server copies the table; the old namespace may be empty now (both
    // posted with the process table held: ordered with every other namespace note)
    if ns_flags & CLONE_NEWNS != 0 {
        let procs = super::proc::PROCS.lock();
        note_mntns(new_mnt, old_mnt);
        gone_if_empty(&procs, old_mnt);
    }
    if ns_flags & CLONE_NEWNS != 0 {
        let fds = crate::task::SCHEDULER.lock().with_process(pid, |t| t.fds.clone());
        if let Some(fds) = fds {
            super::mount::copy_ns(old_mnt, new_mnt, &fds);
        }
    }
    if user.is_some() {
        crate::task::with_current_task_mut(|t| t.caps.enter_userns());
    }
    0
}

/// System PID of the init process of the caller's PID namespace (`None`: the initial one).
fn caller_pid_init() -> Option<u64> {
    mech::pid_ns_init(super::proc::current_ids().1)
}

/// A system-wide process or thread ID as the caller's PID namespace shows it.
///
/// # Arguments
/// * `id` - System-wide ID.
///
/// # Returns
/// 1 for the init of the caller's namespace, otherwise `id`.
pub fn pid_to_caller(id: u64) -> u64 {
    mech::pid_to_view(id, caller_pid_init())
}

/// A process or thread ID given by the caller, as a system-wide ID.
///
/// # Arguments
/// * `id` - ID in the caller's PID namespace.
///
/// # Returns
/// The init's system PID for 1 inside a namespace, otherwise `id`.
pub fn pid_from_caller(id: u64) -> u64 {
    mech::pid_from_view(id, caller_pid_init())
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

/// `/proc/sys/user/max_user_namespaces` of the caller's user namespace, as text.
pub fn max_user_namespaces_text() -> String {
    let v = current_ns().user.map_or(MAX_USER_NAMESPACES, |u| u.max_children.load(Ordering::Relaxed));
    alloc::format!("{}\n", v)
}

/// Writes `/proc/sys/user/max_user_namespaces` of the caller's user namespace
/// (`CAP_SYS_RESOURCE` there).
///
/// # Returns
/// Bytes accepted, or a negative errno.
pub fn set_max_user_namespaces(buf: &[u8]) -> i64 {
    let Ok(v) = core::str::from_utf8(buf).unwrap_or("").trim().parse::<u64>() else { return EINVAL };
    if !crate::task::with_current_task_mut(|t| t.caps.effective & (1 << 24) != 0).unwrap_or(false) {
        return EPERM;
    }
    match current_ns().user {
        Some(u) => u.max_children.store(v, Ordering::Relaxed),
        None => return EPERM, // the initial namespace's limit is fixed
    }
    buf.len() as i64
}

/// Whether the calling process may not change its supplementary groups (`setgroups` is
/// `deny` in its user namespace).
pub fn setgroups_denied() -> bool {
    current_ns().user.is_some_and(|u| u.setgroups_deny.load(Ordering::Relaxed))
}

/// The calling process's IPC namespace (0: the initial one), which scopes System V IPC.
pub fn ipc_ns() -> u64 {
    current_ns().ipc
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
        n => super::ns::pid_from_caller(n.parse().ok()?),
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
    let ns = ns_of(pid)?;
    // A PID namespace for children has no name until its init exists (as on Linux)
    if kind == "pid_for_children" {
        if let Some(id) = ns.pid_for_children {
            PID_NS_INIT.lock().get(&id)?;
        }
    }
    let id = ns.id_of(kind)?;
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
    // Unprivileged: one ID, the creator's own (groups only once setgroups is denied). The
    // outer IDs are the parent namespace's: the creator's, as that namespace sees them
    let in_parent = |id: u32, g: bool| match &user.parent {
        Some(p) => map_down(p, id, g),
        None => Some(id),
    };
    let own = if gid {
        in_parent(user.owner_gid, true) == Some(outer) && euid == user.owner_uid && egid == user.owner_gid
    } else {
        in_parent(user.owner_uid, false) == Some(outer) && euid == user.owner_uid
    };
    let unprivileged_ok = count == 1 && own && (!gid || user.setgroups_deny.load(Ordering::Relaxed));
    if !unprivileged_ok && !privileged {
        return EPERM;
    }
    let mut slot = if gid { user.gid_map.lock() } else { user.uid_map.lock() };
    if slot.is_some() {
        return EPERM;
    }
    *slot = Some(IdMap { inner, outer, count });
    // getuid and the others answer through the map now (their cached answers are stale)
    super::ident_changed();
    buf.len() as i64
}

/// The `CLONE_NEW*` flag of a namespace file kind.
fn flag_of(kind: &str) -> Option<u64> {
    Some(match kind {
        "mnt" => CLONE_NEWNS,
        "cgroup" => CLONE_NEWCGROUP,
        "uts" => CLONE_NEWUTS,
        "ipc" => CLONE_NEWIPC,
        "user" => CLONE_NEWUSER,
        "pid" | "pid_for_children" => CLONE_NEWPID,
        "net" => CLONE_NEWNET,
        _ => return None,
    })
}

/// Whether user namespace `inner` lies inside `outer` (`None`: the initial namespace).
fn user_ns_within(inner: &Option<Arc<UserNs>>, outer: &Option<Arc<UserNs>>) -> bool {
    let mut cur = inner.clone();
    loop {
        match (&cur, outer) {
            (None, None) => return true,
            (Some(a), Some(b)) if Arc::ptr_eq(a, b) => return true,
            (None, Some(_)) => return false,
            (Some(a), _) => cur = a.parent.clone(),
        }
    }
}

// wave10 G8-1 begin: the ptrace rule's "capabilities count over the target"
/// Whether process `target`'s user namespace is process `caller`'s or lies below it
/// (`false` when `target` is gone).
pub fn user_within(target: u64, caller: u64) -> bool {
    let procs = super::proc::PROCS.lock();
    let Some(t) = procs.get(&target) else { return false };
    let mine = procs.get(&caller).and_then(|p| p.ns.user.clone());
    user_ns_within(&t.ns.user, &mine)
}
// wave10 G8-1 end

// wave10 G7b-1 begin: what lx-proc's setns/unshare rules need (`LXP_NS_FD`, `LXP_NS_GET`)
/// The process and the namespace kinds `setns(fd, nstype)` names in descriptor table `fds`:
/// a pidfd's process (`nstype` the kinds), or a `/proc/<pid>/ns/*` file's.
pub fn ns_fd_target(fds: &crate::fs::FdTable, fd: u64, nstype: u64) -> Result<(u64, u64), i64> {
    if let Some(pid) = super::pidfd::pid_in(fds, fd) {
        if nstype == 0 || nstype & !CLONE_NEW_ALL != 0 {
            return Err(EINVAL);
        }
        return Ok((pid, nstype));
    }
    let path = match fds.get(fd as usize) {
        Some(crate::fs::FileDescriptor::File { path, .. }) => path.clone(),
        Some(_) => return Err(EINVAL),
        None => return Err(EBADF),
    };
    let Some((pid, file)) = path.strip_prefix("/proc/").and_then(split) else { return Err(EINVAL) };
    let Some(flag) = file.strip_prefix("ns/").and_then(flag_of) else { return Err(EINVAL) };
    if nstype != 0 && nstype != flag {
        return Err(EINVAL);
    }
    Ok((pid, flag))
}

/// What `setns`/`unshare`'s rules ask about process `target` against process `caller`
/// (`LXP_NS_GET`'s words): its ids (user, pid, pid_for_children, net, mnt, ipc, uts,
/// cgroup), its user namespace's owner (0: the initial one), bit 0 "its user namespace lies
/// within the caller's" | bit 1 "it is the caller's", its PID namespace against the
/// caller's (0 the same, 1 below, 2 neither), its live threads, `setgroups` denied.
pub fn ns_facts(target: u64, caller: u64) -> Option<[u64; 13]> {
    let theirs = ns_of(target)?;
    let mine = ns_of(caller).unwrap_or_default();
    let ids = mech::NsIds::of(&theirs);
    let same = match (&theirs.user, &mine.user) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    };
    let within = user_ns_within(&theirs.user, &mine.user);
    let pid_rel = if theirs.pid == mine.pid {
        0
    } else if theirs.pid_inits.len() > mine.pid_inits.len() && theirs.pid_inits.starts_with(&mine.pid_inits) {
        1
    } else {
        2
    };
    let deny = theirs.user.as_ref().is_some_and(|u| u.setgroups_deny.load(Ordering::Relaxed));
    Some([
        ids.user,
        ids.pid,
        ids.pid_for_children,
        ids.net,
        ids.mnt,
        ids.ipc,
        ids.uts,
        ids.cgroup,
        theirs.user.as_ref().map_or(0, |u| u.owner_uid as u64),
        within as u64 | (same as u64) << 1,
        pid_rel,
        super::proc::thread_ids_of(target).len() as u64,
        deny as u64,
    ])
}
// wave10 G7b-1 end

/// `setns(2)`: joins the namespaces of a `/proc/<pid>/ns/*` file or of a pidfd's process.
///
/// # Arguments
/// * `fd` - Namespace file or pidfd.
/// * `nstype` - For a namespace file: 0 or its `CLONE_NEW*` flag; for a pidfd: the
///   namespaces to join.
///
/// # Returns
/// 0 on success, or a negative errno.
pub fn sys_setns(fd: u64, nstype: u64) -> i64 {
    // wave10 G7b-1: lx-proc's approval, taken first (no early return leaves it behind)
    let (tid, me) = super::proc::current_ids();
    let mark = mech::take_approval_mark(tid, 308);
    // wave10 G7b-1: the descriptor's target, shared with lx-proc's `LXP_NS_FD`
    let (target, kinds) = match crate::task::with_current_fds_mut(|fds| ns_fd_target(fds, fd, nstype)) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let Some(theirs) = ns_of(target) else { return ESRCH };
    let mine = current_ns();
    // wave10 G7b-1: lx-proc decided the checks below up to the PID rule for exactly this
    // target, these kinds and the target's namespaces as they were (the key): only then are
    // they skipped. A descriptor changed meanwhile (another thread's dup2) names something
    // else, and the kernel's own checks run.
    let ids = mech::NsIds::of(&theirs);
    let key = mech::rules::setns_key(target, kinds, &[ids.user, ids.pid, ids.pid_for_children, ids.net, ids.mnt, ids.ipc, ids.uts, ids.cgroup]);
    let approved = mark == Some(key);
    // (the single-thread rule of a user namespace change is checked again: a thread may
    // have been made since lx-proc looked)
    let user_differs = !match (&theirs.user, &mine.user) {
        (None, None) => true,
        (Some(a), Some(b)) => Arc::ptr_eq(a, b),
        _ => false,
    };
    if approved && kinds & CLONE_NEWUSER != 0 && user_differs && super::proc::thread_ids_of(me).len() > 1 {
        return EINVAL;
    }
    if kinds & CLONE_NEWUSER != 0 && !approved {
        let same = match (&theirs.user, &mine.user) {
            (None, None) => true,
            (Some(a), Some(b)) => Arc::ptr_eq(a, b),
            _ => false,
        };
        if same {
            // Joining the namespace one is already in is refused (only for user namespaces)
            if kinds == CLONE_NEWUSER {
                return EINVAL;
            }
        } else {
            if super::proc::thread_ids_of(me).len() > 1 {
                return EINVAL;
            }
            // CAP_SYS_ADMIN in the target: it lies below ours and we own it or are privileged
            let euid = crate::task::with_current_task_mut(|t| t.euid).unwrap_or(u32::MAX);
            let owner = theirs.user.as_ref().map_or(0, |u| u.owner_uid);
            if !user_ns_within(&theirs.user, &mine.user) || !(owner == euid || has_ns_admin()) {
                return EPERM;
            }
        }
    }
    if !approved && kinds & !CLONE_NEWUSER != 0 && !has_ns_admin() && kinds & CLONE_NEWUSER == 0 {
        return EPERM;
    }
    // A PID namespace is joined for children only, and only one at or below the caller's
    let pid_for_children = if kinds & CLONE_NEWPID != 0 {
        if theirs.pid == mine.pid {
            Some(None)
        } else if theirs.pid_inits.len() > mine.pid_inits.len() && theirs.pid_inits.starts_with(&mine.pid_inits) {
            PID_NS_INIT.lock().entry(theirs.pid).or_insert_with(|| theirs.pid_inits.clone());
            Some(Some(theirs.pid))
        } else {
            return EINVAL;
        }
    } else {
        None
    };
    let target_fds = if kinds & CLONE_NEWNS != 0 && theirs.mnt != mine.mnt {
        match crate::task::SCHEDULER.lock().with_process(target, |t| t.fds.clone()) {
            Some(f) => Some(f),
            None => return ESRCH,
        }
    } else {
        None
    };
    let user_changed = kinds & CLONE_NEWUSER != 0
        && !matches!((&theirs.user, &mine.user), (Some(a), Some(b)) if Arc::ptr_eq(a, b))
        && !(theirs.user.is_none() && mine.user.is_none());
    let mut plan = alloc::vec::Vec::new();
    if user_changed {
        plan.push(NsChange::User(theirs.user.clone()));
    }
    if let Some(target) = pid_for_children {
        plan.push(NsChange::Id(NsKind::PidForChildren, target.unwrap_or(0)));
    }
    for (flag, kind, value) in [
        (CLONE_NEWNET, NsKind::Net, theirs.net),
        (CLONE_NEWNS, NsKind::Mnt, theirs.mnt),
        (CLONE_NEWIPC, NsKind::Ipc, theirs.ipc),
        (CLONE_NEWUTS, NsKind::Uts, theirs.uts),
        (CLONE_NEWCGROUP, NsKind::Cgroup, theirs.cgroup),
    ] {
        if kinds & flag != 0 {
            plan.push(NsChange::Id(kind, value));
        }
    }
    mech::ns_set(me, &plan);
    // wave7 G7-3: the namespace left may be empty now
    if kinds & CLONE_NEWNS != 0 && theirs.mnt != mine.mnt {
        mntns_left(mine.mnt);
    }
    // A new mount namespace puts the root and working directory at its root
    if let Some(src) = target_fds {
        let (root_ino, root_mnt) = {
            let f = src.lock();
            (f.root_ino, f.root_mnt)
        };
        crate::task::with_current_fds_mut(|f| {
            f.root_ino = root_ino;
            f.root_mnt = root_mnt;
            f.cwd_ino = root_ino;
            f.cwd_mnt = root_mnt;
            f.cwd_path = String::from("/");
        });
    }
    if user_changed {
        crate::task::with_current_task_mut(|t| t.caps.enter_userns());
    }
    0
}

/// Whether the caller may create a process: not once the PID namespace the child would
/// live in has lost its init (`ENOMEM`, as on Linux).
pub fn check_fork() -> Result<(), i64> {
    const ENOMEM: i64 = -12;
    let ns = current_ns();
    let init = match ns.pid_for_children {
        Some(id) => match PID_NS_INIT.lock().get(&id) {
            Some(chain) => chain.last().copied(),
            // The child will be the init
            None => return Ok(()),
        },
        None => ns.pid_inits.last().copied(),
    };
    let Some(init) = init else { return Ok(()) };
    let gone = super::proc::PROCS.lock().get(&init).map_or(true, |p| p.zombie);
    if gone {
        Err(ENOMEM)
    } else {
        Ok(())
    }
}

// wave7 G7-3 begin: vfs-server keeps the mount tables (wave 7) and hears of namespaces
/// Tells vfs-server that mount namespace `new` was made from `from`, or (`from` =
/// [`LX_MNTNS_GONE`]) that `new` has no live process left. Nothing when vfs-server is not
/// the host of the file service.
///
/// [`LX_MNTNS_GONE`]: crate::ipc::protocol::LX_MNTNS_GONE
pub fn note_mntns(new: u64, from: u64) {
    use crate::ipc::protocol::{ENDPOINT_VFS_SERVER, LXS_VFS, LX_NOTE_MNTNS};
    if new == 0 {
        return;
    }
    let h = crate::lx::svc::host_of(LXS_VFS);
    if h != 0 && crate::lx::svc::endpoint_of(LXS_VFS) == ENDPOINT_VFS_SERVER {
        crate::lx::note_to(h, LX_NOTE_MNTNS, new, from, 0);
    }
}

/// A process left mount namespace `ns` (`setns`, `unshare`): when no live process is left
/// in it, vfs-server drops its table. (Exits: `proc::thread_exited`, which holds the
/// process table.)
pub fn mntns_left(ns: u64) {
    let procs = super::proc::PROCS.lock();
    gone_if_empty(&procs, ns);
}

/// With the process table `procs` held (so the note is ordered with every other namespace
/// note): when no live process is left in mount namespace `ns`, tells vfs-server.
pub fn gone_if_empty(procs: &alloc::collections::BTreeMap<u64, alloc::boxed::Box<super::proc::Process>>, ns: u64) {
    if ns != 0 && !procs.values().any(|p| !p.zombie && p.ns.mnt == ns) {
        note_mntns(ns, crate::ipc::protocol::LX_MNTNS_GONE);
    }
}
// wave7 G7-3 end

// wave7 G7-6 begin: a restarted vfs-server resyncs its kept mount tables
/// The mount namespaces with a live process (sorted, each once; 0 is the initial one), for
/// `LX_FH_NSLIST`.
pub fn live_mntns() -> alloc::vec::Vec<u64> {
    let set: alloc::collections::BTreeSet<u64> = super::proc::PROCS.lock().values().filter(|p| !p.zombie).map(|p| p.ns.mnt).collect();
    set.into_iter().collect()
}
// wave7 G7-6 end
