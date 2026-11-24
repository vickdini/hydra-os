//! # Restart support: the decisions (wave 6, Group 21)
//!
//! The parts of restart support that are pure decisions, kept apart from the kernel's state
//! so the host tests run them (`tests/host`): the restart classes, the ladder, the
//! idempotent marks and the error a stale object gives. [`super::restart`] holds the state
//! and does the waiting (`docs/linux-services-design.md`, section 5).

/// What happens to a Linux service's callers and objects when it dies (design 5.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RestartClass {
    /// Callers wait for the new instance; calls that were queued, pending, or safe to
    /// repeat are sent again; objects the new instance adopts keep working.
    Transparent = 0,
    /// The old instance's objects fail with a per-kind error; calls in flight fail with
    /// `EIO`; new calls wait for the new instance. Programs live.
    FailObjects = 1,
    /// The user's decision 6 (today's linux-server): every Linux program ends and the login
    /// screen returns.
    EndLinux = 2,
}

impl RestartClass {
    /// The class from its number (`LX_SVC_INFO`, boot words); anything else is `None`.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Transparent),
            1 => Some(Self::FailObjects),
            2 => Some(Self::EndLinux),
            _ => None,
        }
    }

    /// The class one step down the ladder: Transparent becomes FailObjects; the others stay
    /// (EndLinux is never reached by the ladder alone, and never left by it).
    pub fn lowered(self) -> Self {
        match self {
            Self::Transparent => Self::FailObjects,
            c => c,
        }
    }

    /// The boot word's spelling (`lx.<name>.restart=...`) and the log's.
    pub fn name(self) -> &'static str {
        match self {
            Self::Transparent => "transparent",
            Self::FailObjects => "failobjects",
            Self::EndLinux => "endlinux",
        }
    }

    /// Parses a boot word's value.
    pub fn parse(s: &[u8]) -> Option<Self> {
        match s {
            b"transparent" => Some(Self::Transparent),
            b"failobjects" => Some(Self::FailObjects),
            b"endlinux" => Some(Self::EndLinux),
            _ => None,
        }
    }
}

/// How long after a restart a crash counts as "again" (design 5.2): 30 s.
pub const LADDER_WINDOW_MS: u64 = 30_000;
/// How long callers wait for a restarting service before they fail with `EIO`: 30 s.
pub const WAIT_MS: u64 = 30_000;

/// What to do about one crash.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decision {
    /// How this crash is handled.
    pub class: RestartClass,
    /// The kept state is suspect: drop it (the next instance starts with a zeroed one).
    pub reset_kept: bool,
    /// Start a new instance (false: the service stays down, its calls fail with `EIO`).
    pub restart: bool,
}

/// One service's ladder (design 5.2): its configured class, and how many crashes came
/// within [`LADDER_WINDOW_MS`] of the restart before them.
#[derive(Clone, Copy, Debug)]
pub struct Ladder {
    /// The class the supervisor (or a boot word) gave the service.
    pub configured: RestartClass,
    /// When the last restart happened (ms since boot), if any.
    last_restart_ms: Option<u64>,
    /// Crashes in a row, each within the window of the restart before it.
    quick: u32,
    /// The class after the last crash (shown by `LX_SVC_INFO` and the diagnostics).
    pub current: RestartClass,
    /// Crashes seen since boot.
    pub crashes: u32,
}

impl Ladder {
    /// A service of class `configured` that never crashed.
    pub const fn new(configured: RestartClass) -> Self {
        Self { configured, last_restart_ms: None, quick: 0, current: configured, crashes: 0 }
    }

    /// The service crashed at `now_ms`: how to handle it.
    ///
    /// - A crash longer than the window after the last restart (or the first one) is
    ///   handled in the configured class.
    /// - The second crash within the window: one class lower, and the kept state is reset.
    /// - The third crash within the window: one class lower, and no restart, except for an
    ///   EndLinux service (decision 6 keeps its restarts: the supervisor's own limit
    ///   applies to it, as before wave 6).
    pub fn crash(&mut self, now_ms: u64) -> Decision {
        self.crashes = self.crashes.saturating_add(1);
        let quick = self.last_restart_ms.is_some_and(|t| now_ms.saturating_sub(t) < LADDER_WINDOW_MS);
        self.quick = if quick { self.quick + 1 } else { 0 };
        let d = match self.quick {
            0 => Decision { class: self.configured, reset_kept: false, restart: true },
            1 => Decision { class: self.configured.lowered(), reset_kept: true, restart: true },
            _ => Decision { class: self.configured.lowered(), reset_kept: true, restart: self.configured == RestartClass::EndLinux },
        };
        self.current = d.class;
        d
    }

    /// A deliberate restart (`service restart`): handled in the configured class, not
    /// counted as a crash, and it starts a new window.
    pub fn deliberate(&mut self, now_ms: u64) -> Decision {
        self.quick = 0;
        self.last_restart_ms = Some(now_ms);
        self.current = self.configured;
        Decision { class: self.configured, reset_kept: false, restart: true }
    }

    /// wave10 G7b-1: when the window of the next crash counts from (`None`: never
    /// restarted), for the log line of each decision.
    pub fn last_restart_ms(&self) -> Option<u64> {
        self.last_restart_ms
    }

    /// The new instance started at `now_ms` (the window counts from here).
    pub fn restarted(&mut self, now_ms: u64) {
        self.last_restart_ms = Some(now_ms);
    }

    /// The service was started by hand after it was given up (`service start`): a fresh
    /// ladder.
    pub fn reset(&mut self) {
        *self = Self::new(self.configured);
    }
}

// Linux errno values (negated where returned).
const EBADF: i64 = 9;
const EPIPE: i64 = 32;
const ENODEV: i64 = 19;
const ECONNRESET: i64 = 104;

/// The error (negative) a call on an object of a dead instance gives (design 5.2,
/// FailObjects), by its `LX_OBJ_KIND_*`: pipes `EPIPE`, sockets `ECONNRESET`, device
/// objects (kinds 64 and up, wave 8's device services) `ENODEV`, everything else `EBADF`.
pub fn stale_errno(kind: u32) -> i64 {
    -match kind {
        // LX_OBJ_KIND_PIPE_R, PIPE_W, PIPE_RW
        16 | 17 | 23 => EPIPE,
        // LX_OBJ_KIND_INET, NETLINK, UNIX
        7 | 8 | 18 => ECONNRESET,
        64.. => ENODEV,
        _ => EBADF,
    }
}

/// Hydra's test call (`LX_NULL_NR`).
const LX_NULL_NR: u64 = 0x6710;
/// The test service's call (`LX_TEST_NR`).
const LX_TEST_NR: u64 = 0x6711;

/// Whether call `nr` with arguments `args` may be sent again to a restarted service after
/// the old instance died **while serving it** (design 5.1, point 3): only calls that change
/// nothing a second sending could notice. Calls that were still queued, or answered
/// "pending", are sent again whatever this says (they had no effect yet).
///
/// **Review this list as carefully as the copy table** (design section 10): a call marked
/// here that changes state could be done twice. When in doubt, a call is not listed: it then
/// fails with `EIO`, which a program can handle.
///
/// The marks are by number and argument, for the calls moved so far and the ones the next
/// waves move (path lookups, /proc, process queries); calls that create descriptors are
/// listed only where the kernel undoes a lost one ([`super::restart`] closes descriptors
/// installed for the failed request before sending it again).
pub fn idempotent(nr: u64, args: &[u64; 6]) -> bool {
    match nr {
        // Hydra's test call: 0 return, 1 pending, 4 count closes. (2 changes the caller's
        // buffer through the client memory primitives; 3 makes an object)
        LX_NULL_NR => matches!(args[0], 0 | 1 | 4),
        // The test service's call (wave 6): 0 null, 2 pending, 4 who, 7 closes, 21 kept
        // counter (1 makes an object, 3/6 redirect, 5 changes the caller's buffer, 20 adds 1)
        LX_TEST_NR => matches!(args[0], 0 | 2 | 4 | 7 | 21),
        // keyctl: the commands that only read, and the two that create only when asked to
        // (Group 24: lx-sec commits every change to its kept state before it answers, so a
        // GET_KEYRING_ID that created a keyring finds it the second time)
        250 => match args[0] {
            // GET_KEYRING_ID (with or without "create"), DESCRIBE, READ, GET_SECURITY,
            // DH_COMPUTE, PKEY_QUERY, PKEY_ENCRYPT, PKEY_DECRYPT, PKEY_SIGN, PKEY_VERIFY,
            // CAPABILITIES (not 29 RESTRICT_KEYRING, 30 MOVE, 32 WATCH_KEY)
            0 | 6 | 11 | 17 | 23..=28 | 31 => true,
            // SEARCH without a destination keyring to link the key into
            10 => args[4] == 0,
            _ => false,
        },
        // request_key without a destination keyring (Group 24)
        249 => args[3] == 0,
        // mq_getsetattr without a new attribute
        245 => args[1] == 0,
        // semget(key, n, flags) / msgget(key, flags): a lookup, or create-if-missing of a
        // named set; not IPC_PRIVATE (key 0, always new) and not IPC_EXCL (EEXIST the 2nd time)
        64 => args[0] != 0 && args[2] & 0o2000 == 0,
        68 => args[0] != 0 && args[1] & 0o2000 == 0,
        // semctl: IPC_STAT, IPC_INFO, GETPID, GETVAL, GETALL, GETNCNT, GETZCNT, SEM_STAT,
        // SEM_INFO, SEM_STAT_ANY (IPC_64 masked off)
        66 => matches!(args[2] & !0x100, 2 | 3 | 11 | 12 | 13 | 14 | 15 | 18 | 19 | 20),
        // msgctl: IPC_STAT, IPC_INFO, MSG_STAT, MSG_INFO, MSG_STAT_ANY
        71 => matches!(args[1] & !0x100, 2 | 3 | 11 | 12 | 13),
        // wave10 G8-2 begin: System V shared memory in lx-ipc. shmget as semget (a named
        // segment made but not yet kept is made again; kept, it is found by its key); shmat
        // (lx-ipc only checks and names the segment: the kernel maps and counts); shmctl
        // IPC_STAT, IPC_INFO, SHM_STAT, SHM_INFO, SHM_STAT_ANY
        29 => args[0] != 0 && args[2] & 0o2000 == 0,
        30 => true,
        31 => matches!(args[1] & !0x100, 2 | 3 | 13 | 14 | 15),
        // wave10 G8-2 end
        // bpf: MAP_LOOKUP_ELEM, MAP_GET_NEXT_KEY, PROG/MAP_GET_NEXT_ID, OBJ_GET_INFO_BY_FD,
        // PROG_QUERY, BTF_GET_NEXT_ID, LINK_GET_NEXT_ID
        321 => matches!(args[0], 1 | 4 | 11 | 12 | 15 | 16 | 23 | 31),
        // getsockname, getpeername, getsockopt
        51 | 52 | 55 => true,
        // recvfrom / recvmsg with MSG_PEEK (nothing is taken from the socket)
        45 => args[3] & 2 != 0,
        47 => args[2] & 2 != 0,
        // ioctl requests that only read: TCGETS, TIOCGPGRP, TIOCGWINSZ, FIONREAD,
        // SIOCGIFNAME, SIOCGIFCONF, SIOCGIFFLAGS, SIOCGIFADDR, SIOCGIFMTU, SIOCGIFHWADDR,
        // SIOCGIFINDEX
        16 => matches!(args[1], 0x5401 | 0x540F | 0x5413 | 0x541B | 0x8910 | 0x8912 | 0x8913 | 0x8915 | 0x8921 | 0x8927 | 0x8933) || alsa_resendable(args[1]),
        // Path and attribute queries (wave 7's file service): stat, fstat, lstat, access,
        // readlink, getcwd, statfs, fstatfs, the getxattr and listxattr families,
        // readlinkat, newfstatat, faccessat, statx, faccessat2
        4 | 5 | 6 | 21 | 89 | 79 | 137 | 138 | 191..=196 | 267 | 262 | 269 | 332 | 439 => true,
        // pread64, preadv, preadv2: no file offset moves (a pipe answers ESPIPE both times)
        17 | 295 | 327 => true,
        // open / openat without O_CREAT, O_TRUNC, O_TMPFILE (the descriptor of a lost answer
        // is closed before the call is sent again)
        // wave10 GV1: and O_CREAT without O_EXCL / O_TRUNC / O_TMPFILE (made by vfs-server now): sent
        // again it opens the file the first try made, as Linux's create-if-missing
        2 => open_resendable(args[1]),
        257 => open_resendable(args[2]),
        // wave10 GV1: changes to an absolute value, the same done twice: chmod, fchmod,
        // fchmodat(2), chown family, the times calls, setxattr without XATTR_CREATE (args[4]
        // bit 0). Not truncate/ftruncate: a second cut could destroy data written meanwhile
        // (review 6)
        90 | 91 | 268 | 452 | 92 | 93 | 94 | 260 | 280 | 132 | 235 | 261 => true,
        188..=190 => args[4] & 1 == 0,
        // Process queries (lx-proc, wave 10): uname, getrlimit, getrusage, sysinfo,
        // getgroups, getresuid, getresgid, getpgid, getsid, capget, getpriority,
        // sched_getaffinity, prlimit64 without a new limit
        63 | 97 | 98 | 99 | 115 | 118 | 120 | 121 | 124 | 125 | 140 | 204 => true,
        302 => args[2] == 0,
        // wave10 G7b-1 begin: lx-proc's changes that come out the same when made twice (it
        // keeps nothing: the kernel's state is the truth): the setuid family and setgroups
        // (absolute values: once made, they pass the unprivileged rule again), setpgid,
        // setfsuid/setfsgid, setrlimit, sethostname/setdomainname, acct; prctl's sets and gets
        // of names, dumpable, parent-death signal, keepcaps, no_new_privs, subreaper; syslog's
        // reads that take nothing (3 READ_ALL, 9 SIZE_UNREAD, 10 SIZE_BUFFER, 0/1, 5 CLEAR).
        // Not setsid (a leader the second time), unshare (new namespaces again), setns.
        105 | 106 | 113 | 114 | 117 | 119 | 116 | 109 | 122 | 123 | 160 | 170 | 171 | 163 => true,
        157 => matches!(args[0], 1 | 2 | 3 | 4 | 7 | 8 | 15 | 16 | 36 | 37 | 38 | 39),
        103 => matches!(args[0], 0 | 1 | 3 | 5 | 9 | 10),
        // wave10 G7b-1 end
        // wave10 G8-1: the tracing calls: lx-proc only decides them (the kernel acts after its
        // redirect), so a cut decision is simply made again
        // (ptrace: only the requests lx-proc decides, as `ptrace_rules::ptrace_routed`: TRACEME,
        // ATTACH, SEIZE, SETOPTIONS with O_SUSPEND_SECCOMP)
        101 => matches!(args[0], 0 | 16 | 0x4206) || (args[0] == 0x4200 && args[3] & (1 << 21) != 0),
        298 | 310 | 311 | 312 | 438 => true,
        _ => false,
    }
}

// wave8 GS begin
/// ALSA `ioctl`s (the sound service, wave 8) that a restarted sound service may be sent
/// again: the queries, and `SYNC_PTR`, which sets the application pointer and minimum to the
/// values in its record (the same the second time) and reads the status. The request is
/// compared as 32 bits: libasound passes it as an `int`, which may arrive sign-extended.
pub fn alsa_resendable(req: u64) -> bool {
    matches!(
        req as u32,
        // PCM: PVERSION, INFO, STATUS, DELAY, HWSYNC, SYNC_PTR, STATUS_EXT
        0x8004_4100 | 0x8120_4101 | 0x8098_4120 | 0x8008_4121 | 0x0000_4122 | 0xC088_4123 | 0xC098_4124
        // control: PVERSION, CARD_INFO, ELEM_LIST, ELEM_INFO, ELEM_READ, TLV_READ, PCM_INFO,
        // POWER_STATE (not PCM_NEXT_DEVICE: it overwrites its argument with the answer)
        | 0x8004_5500 | 0x8178_5501 | 0xC050_5510 | 0xC110_5511 | 0xC4C8_5512 | 0xC008_551A | 0xC120_5531 | 0x8004_55D1
    )
}
// wave8 GS end

// wave7 GB begin
/// `add_key`.
pub const NR_ADD_KEY: u64 = 248;

/// Whether an `add_key` of key type `ty`, served by a lx-sec that died before answering, may
/// be sent again: lx-sec commits every change before it answers, and `add_key` of a key
/// type that exists in the keyring with the same description updates it in place (same
/// serial, same payload the second time). Not for `keyring` (a new one would be made, and
/// the first one's serial was never learned) nor an unknown type.
pub fn add_key_resendable(ty: &[u8]) -> bool {
    matches!(ty, b"user" | b"logon" | b"big_key")
}
// wave7 GB end

/// `O_CREAT | O_TRUNC | O_TMPFILE` (`__O_TMPFILE` 0o20000000 plus `O_DIRECTORY`): the open
/// flags that change the file system.
const OPEN_CHANGES: u64 = 0o100 | 0o1000 | 0o20000000;

// wave10 GV1 begin
/// Whether an open with `flags` may be sent again after the file service died serving it:
/// one that changes nothing, or a create-if-missing (`O_CREAT` without `O_EXCL`: the second
/// try opens what the first made); never `O_EXCL`, `O_TMPFILE` or `O_TRUNC` (a second cut
/// could destroy data another process wrote meanwhile: EIO is safer, review 6).
pub fn open_resendable(flags: u64) -> bool {
    const O_CREAT: u64 = 0o100;
    const O_EXCL: u64 = 0o200;
    const O_TRUNC: u64 = 0o1000;
    flags & OPEN_CHANGES == 0 || (flags & (O_EXCL | O_TRUNC | 0o20000000) == 0 && flags & O_CREAT != 0)
}
// wave10 GV1 end

/// The results a dead Transparent service's calls get from the kernel (never seen by a
/// program: the caller sends the call again or fails it). Next to Group 12's `LX_RETRY`
/// (-4097).
pub const LX_RESEND: i64 = -4098;
/// See [`LX_RESEND`]: the call was being served when the service died; it is sent again
/// only if [`idempotent`].
pub const LX_RESEND_MAYBE: i64 = -4099;

/// What a caller does with a dead Transparent service's answer `r` to call `nr`(`args`):
/// `Ok(())` send it again (after the service is back), `Err(errno)` fail it.
pub fn after_crash(r: i64, nr: u64, args: &[u64; 6]) -> Result<(), i64> {
    const EIO: i64 = -5;
    match r {
        LX_RESEND => Ok(()),
        LX_RESEND_MAYBE if idempotent(nr, args) => Ok(()),
        _ => Err(EIO),
    }
}
