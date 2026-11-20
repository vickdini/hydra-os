//! `src/admin/mod.rs`: the `SYS_ADMIN` system call: authorization, copying the call block
//! and the answer, the login gate, failure messages, and every operation's dispatch.

mod common;
use common::*;
use k::admin::proto::*;

#[test]
fn only_the_authorized_console_may_call() {
    let _g = setup();
    // Nobody authorized yet
    assert_eq!(k::admin::console_task(), None);
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, -EPERM);
    let id = authorize();
    assert_eq!(k::admin::console_task(), Some(id));
    assert!(fake::logged("spawn_native hydra-shell hydra-shell [\"hydra-shell\"] 1000 1000"));
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, 4);
    // Another task
    fake::with(|s| s.current_tid = id.0 + 1);
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, -EPERM);
    // The console's task id, but a Linux process (its call 40 is sendfile, never this)
    fake::with(|s| {
        s.current_tid = id.0;
        s.personality = Some(k::task::TaskPersonality::Linux);
    });
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, -EPERM);
    fake::with(|s| s.personality = Some(k::task::TaskPersonality::Hydra));
    // Revoking another id changes nothing; revoking the console's withdraws it
    k::admin::revoke_console(k::task::TaskId(id.0 + 5));
    assert_eq!(k::admin::console_task(), Some(id));
    k::admin::revoke_console(id);
    assert_eq!(k::admin::console_task(), None);
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, -EPERM);
}

#[test]
fn launching_the_shell_sets_it_up_as_a_native_program() {
    let _g = setup();
    let id = authorize();
    // A native Hydra program, not a Linux one
    assert_eq!(k::task::with_task(id.0, |t| t.personality), k::task::TaskPersonality::Hydra);
    assert!(fake::logged("load_image hydra-shell"));
    // A program that is not loadable, or a process that cannot be made
    fake::with(|s| s.not_loadable = true);
    assert_eq!(k::admin::launch_shell(&["hydra-shell"], 0, 0).unwrap_err(), "not a loadable static ELF executable");
    fake::with(|s| {
        s.not_loadable = false;
        s.spawn_fail = Some("out of memory");
    });
    assert_eq!(k::admin::spawn_native("x", b"\x7fELF", &[], 0, 0, false).unwrap_err(), "out of memory");
    // A non-console program does not take the console's authorization
    fake::with(|s| s.spawn_fail = None);
    let other = k::admin::spawn_native("tool", b"\x7fELF", &[], 5, 5, false).unwrap();
    assert_ne!(other, id);
    assert_eq!(k::admin::console_task(), Some(id));
    assert!(fake::logged("spawn_native tool tool [] 5 5"));
}

#[test]
fn version_answers_the_abi_version() {
    let _g = setup();
    authorize();
    let a = admin(ADMIN_VERSION, [0; 4], b"");
    assert_eq!(a.rc, 4);
    assert_eq!(u32::from_le_bytes(a.out[..4].try_into().unwrap()), ADMIN_ABI_VERSION);
    // No answer buffer: only the size
    assert_eq!(admin_cap(ADMIN_VERSION, [0; 4], b"", 0).rc, 4);
    // A buffer too small: the size of the whole answer, the part that fits written
    let a = admin_cap(ADMIN_VERSION, [0; 4], b"", 2);
    assert_eq!(a.rc, 4);
    assert_eq!(a.out, ADMIN_ABI_VERSION.to_le_bytes()[..2].to_vec());
}

#[test]
fn bad_pointers_and_sizes_are_refused() {
    let _g = setup();
    authorize();
    // The call block itself
    assert_eq!(k::admin::syscall(0), -EFAULT);
    assert_eq!(k::admin::syscall(u64::MAX - 8), -EFAULT);
    assert_eq!(k::admin::syscall(0x0000_8000_0000_0000), -EFAULT);
    // Input too large
    let call = AdminCall { op: ADMIN_LOOKUP, in_ptr: 0x1000, in_len: 4 * 1024 * 1024 + 1, ..Default::default() };
    assert_eq!(k::admin::syscall(&call as *const _ as u64), -EINVAL);
    // Input at address 0
    let call = AdminCall { op: ADMIN_LOOKUP, in_ptr: 0, in_len: 4, ..Default::default() };
    assert_eq!(k::admin::syscall(&call as *const _ as u64), -EFAULT);
    // An answer buffer at address 0 with a capacity
    let call = AdminCall { op: ADMIN_VERSION, out_ptr: 0, out_cap: 16, ..Default::default() };
    assert_eq!(k::admin::syscall(&call as *const _ as u64), -EFAULT);
    // Memory the address space cannot provide
    fake::with(|s| s.prefault_fails = true);
    let mut buf = [0u8; 8];
    let call = AdminCall { op: ADMIN_VERSION, out_ptr: buf.as_mut_ptr() as u64, out_cap: 8, ..Default::default() };
    assert_eq!(k::admin::syscall(&call as *const _ as u64), -EFAULT);
}

#[test]
fn unknown_operations_and_bad_text() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    assert!(k::admin::session::logged_in());
    assert_eq!(admin(0x7F, [0; 4], b"").rc, -ENOSYS);
    // Operations that take text refuse bytes that are not UTF-8
    assert_eq!(admin(ADMIN_LOOKUP, [0; 4], b"\xff\xfe").rc, -EINVAL);
    assert_eq!(admin(ADMIN_SESSION_LOGIN, [LOGIN_LOGIN, 0, 0, 0], b"\xff").rc, -EINVAL);
}

#[test]
fn a_protected_console_answers_only_its_own_operations_before_login() {
    let _g = setup();
    accounts();
    authorize();
    k::admin::session::begin();
    assert!(!k::admin::session::logged_in());
    let a = admin(ADMIN_MEM_INFO, [0; 4], b"");
    assert_eq!(a.rc, -EACCES);
    assert_eq!(a.msg, "not logged in");
    // The message is cut to the buffer; no buffer: no message
    let a = admin_cap(ADMIN_MEM_INFO, [0; 4], b"", 3);
    assert_eq!((a.rc, a.msg.as_str()), (-EACCES, "not"));
    let a = admin_cap(ADMIN_MEM_INFO, [0; 4], b"", 0);
    assert_eq!((a.rc, a.msg.as_str()), (-EACCES, ""));
    // The console's own operations, the session's and the version still answer
    assert_eq!(admin(ADMIN_VERSION, [0; 4], b"").rc, 4);
    assert!(admin(ADMIN_SESSION_INFO, [0; 4], b"").rc > 0);
    assert_eq!(admin(ADMIN_CONSOLE_CTL, [CTL_SIZE, 0, 0, 0], b"").rc, 16);
    assert_eq!(admin(ADMIN_CONSOLE_COLOR, [15, 0, 0, 0], b"").rc, 0);
    assert!(admin(ADMIN_CONSOLE_READ, [0, u64::MAX, 0, 0], b"").rc > 0);
    // The login answers a LoginResult
    let a = admin(ADMIN_SESSION_LOGIN, [LOGIN_LOGIN, 0, 0, 0], b"bob\0pw");
    assert_eq!(a.rc as usize, core::mem::size_of::<LoginResult>());
}

#[test]
fn console_and_session_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    // Colours: numbers 0-15 only
    assert_eq!(admin(ADMIN_CONSOLE_COLOR, [14, 1, 0, 0], b"").rc, 0);
    assert_eq!(k::console::CONSOLE.lock().current_attr, 0x1E);
    assert_eq!(admin(ADMIN_CONSOLE_COLOR, [16, 0, 0, 0], b"").rc, -EINVAL);
    assert_eq!(admin(ADMIN_CONSOLE_COLOR, [1, 99, 0, 0], b"").rc, -EINVAL);
    // A key
    fake::with(|s| s.uefi_keys.push_back(fake::key('x')));
    let a = admin(ADMIN_CONSOLE_READ, [0, u64::MAX, 0, 0], b"");
    let ev: KeyEvent = a.rec(0);
    assert_eq!((ev.kind, ev.code), (KEY_CHAR, 'x' as u32));
    // Console control: two u64s, unknown codes refused
    let a = admin(ADMIN_CONSOLE_CTL, [CTL_SIZE, 0, 0, 0], b"");
    assert_eq!((a.u64(0), a.u64(8)), (80, 25));
    assert_eq!(admin(ADMIN_CONSOLE_CTL, [99, 0, 0, 0], b"").rc, -EINVAL);
    // Session info
    let info: SessionInfo = admin(ADMIN_SESSION_INFO, [0; 4], b"").rec(0);
    assert_eq!((info.uid, info.logged_in, info.protected), (1000, 1, 0));
    assert_eq!(name_str(&info.name), "hydra");
    // A login without a NUL: the whole input is the name
    let r: LoginResult = admin(ADMIN_SESSION_LOGIN, [LOGIN_LOGIN, 0, 0, 0], b"someone").rec(0);
    assert_eq!(r.status, LOGIN_UNPROTECTED);
}

#[test]
fn task_operations_dispatch() {
    use k::task::*;
    let _g = setup();
    authorize();
    k::admin::session::begin();
    fake::with(|s| {
        s.snapshots = vec![TaskSnapshot { id: TaskId(0), uid: 0, mode: PrivilegeMode::Kernel, state: TaskState::Running, priority: TaskPriority::High, ticks_run: 5, rsp: 0x1000, name: "shell" }]
    });
    let a = admin(ADMIN_TASK_LIST, [0; 4], b"");
    let h: TaskListHeader = a.rec(0);
    assert_eq!(h.count, 1);
    let t: TaskRecord = a.rec(core::mem::size_of::<TaskListHeader>());
    assert_eq!(name_str(&t.name), "shell");
    // Kill
    fake::task(55, 1, None);
    assert_eq!(admin(ADMIN_TASK_KILL, [55, 0, 0, 0], b"").rc, 0);
    let a = admin(ADMIN_TASK_KILL, [55, 0, 0, 0], b"");
    assert_eq!((a.rc, a.msg.as_str()), (-ENOENT, "not found or already dead"));
    // Exec runs as the console's user
    let mut elf = vec![0x7f, b'E', b'L', b'F'];
    elf.resize(100, 0);
    fake::file("/bin/tool", &elf);
    let r: ExecResult = admin(ADMIN_TASK_EXEC, [EXEC_BACKGROUND, 0, 0, 0], b"/bin/tool\0-v").rec(0);
    assert_eq!((r.size, r.linux, r.finished), (100, 0, 0));
    assert!(fake::logged("spawn_native /bin/tool /bin/tool [\"/bin/tool\", \"-v\"] 1000 1000"));
    // Statistics
    fake::with(|s| s.msrs.insert(0xC000_0080, 0xD01));
    let st: SyscallStats = admin(ADMIN_SYSCALL_STATS, [0; 4], b"").rec(0);
    assert_eq!(st.efer, 0xD01);
    let a = admin(ADMIN_ENDPOINT_LIST, [0; 4], b"");
    assert_eq!(a.rc as usize, 3 * core::mem::size_of::<EndpointRecord>());
    let a = admin(ADMIN_REQUEST_LIST, [0; 4], b"");
    assert_eq!(a.rec::<RequestHeader>(0).count, 0);
}

#[test]
fn memory_cpu_and_clock_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    let m: MemInfo = admin(ADMIN_MEM_INFO, [0; 4], b"").rec(0);
    assert_eq!((m.total, m.page_size), (512 << 20, 4096));
    let c: CpuState = admin(ADMIN_CPU_STATE, [0; 4], b"").rec(0);
    assert_eq!(c.cr3, 0x1234_5000);
    let r: RtcTime = admin(ADMIN_RTC_TIME, [0; 4], b"").rec(0);
    assert_eq!(r.valid, 0);
    // Not mapped: ENOENT (the report goes to fd 1)
    assert_eq!(admin(ADMIN_TRANSLATE, [0x4000, 0, 0, 0], b"").rc, -ENOENT);
    assert_eq!(admin(ADMIN_TRANSLATE, [0x8000_0000_0000, 0, 0, 0], b"").msg, "not a canonical address");
    // The heap test
    assert_eq!(admin(ADMIN_HEAP_TEST, [0; 4], b"").rc, 0);
    fake::with(|s| s.heap_test_fail = Some("Vec mismatch"));
    let a = admin(ADMIN_HEAP_TEST, [0; 4], b"");
    assert_eq!((a.rc, a.msg.as_str()), (-EIO, "Vec mismatch"));
}

#[test]
fn service_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    assert_eq!(admin(ADMIN_SERVICE_LIST, [0; 4], b"").rc, 0);
    assert_eq!(admin(ADMIN_IRQ_LIST, [0; 4], b"").rc, 0);
    let a = admin(ADMIN_SERVICE_CTL, [SVCCTL_RESTART, 0, 0, 0], b"net-server");
    assert_eq!((a.rc, a.u64(0)), (8, 41));
    assert!(fake::logged("restart net-server"));
    assert_eq!(admin(ADMIN_SERVICE_CTL, [9, 0, 0, 0], b"x").rc, -EINVAL);
    assert_eq!(admin(ADMIN_IOMMU, [0, 0, 0, 0], b"").rc, 0);
    assert_eq!(admin(ADMIN_IOMMU, [7, 0, 0, 0], b"").rc, -EINVAL);
}

#[test]
fn storage_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    fake::file("/etc/motd", b"hello");
    let p: PoolStatus = admin(ADMIN_POOL_STATUS, [0; 4], b"").rec(0);
    assert_eq!(p.metrics_valid, 0);
    let a = admin(ADMIN_DIR_LIST, [0; 4], b"/etc");
    assert_eq!(a.rec::<DirHeader>(0).count, 1);
    let l: LookupRecord = admin(ADMIN_LOOKUP, [0; 4], b"/etc/motd").rec(0);
    assert_eq!((l.kind, l.size), (KIND_FILE as u64, 5));
    let a = admin(ADMIN_FS_OP, [FS_MKDIR, 0, 0, 0], b"/tmp");
    assert_eq!(a.rc, 8);
    let s: StatRecord = admin(ADMIN_FILE_STAT, [0; 4], b"/etc/motd").rec(0);
    assert_eq!(s.size, 5);
    let a = admin(ADMIN_DATASET_LIST, [0; 4], b"");
    assert_eq!((a.rc, a.msg.as_str()), (-EIO, "the file server did not answer"));
    assert_eq!(admin(ADMIN_ZFS_DIAG, [ZFSDIAG_FSCK, 1, 0, 0], b"/home").rc, 0);
    assert!(fake::logged("diag 0x32 /home true"));
    let d: DiskInfo = admin(ADMIN_DISK_INFO, [0; 4], b"").rec(0);
    assert_eq!(d.present, 0);
    assert_eq!(admin(ADMIN_USBDISK, [9, 0, 0, 0], b"").rc, -EINVAL);
}

#[test]
fn network_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    // No input: no words; the report goes to fd 1
    assert_eq!(admin(ADMIN_NET, [NET_DNS, 0, 0, 0], b"").rc, 0);
    assert!(fake::take_out().contains("Usage: dns"));
    assert_eq!(admin(ADMIN_NET, [NET_PING, 0, 0, 0], b"").rc, 0);
    assert!(fake::take_out().contains("Usage: ping"));
    // Words are NUL separated
    assert_eq!(admin(ADMIN_NET, [NET_WGET, 0, 0, 0], b"10.0.2.2\080").rc, 0);
    assert!(fake::take_out().contains("Usage: wget"));
    assert_eq!(admin(ADMIN_NET, [99, 0, 0, 0], b"").rc, -EINVAL);
}

#[test]
fn power_and_fault_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    expect_panic("power_off", || {
        admin(ADMIN_POWER, [POWER_OFF, 0, 0, 0], b"");
    });
    expect_panic("reboot", || {
        admin(ADMIN_POWER, [POWER_REBOOT, 0, 0, 0], b"");
    });
    assert_eq!(admin(ADMIN_POWER, [9, 0, 0, 0], b"").rc, -EINVAL);
    assert_eq!(admin(ADMIN_FAULT_TEST, [FAULT_TRAP, 0, 0, 0], b"").rc, 0);
    assert_eq!(admin(ADMIN_FAULT_TEST, [5, 0, 0, 0], b"").rc, -EINVAL);
}

#[test]
fn linux_operations_dispatch() {
    let _g = setup();
    authorize();
    k::admin::session::begin();
    k::compat::linux::LINUX_STATS.lock().total_calls = 77;
    let s: LinuxStats = admin(ADMIN_LINUX_STATUS, [0; 4], b"").rec(0);
    assert_eq!(s.calls[0], 77);
    // A program of the pool, as the console's user
    let mut elf = vec![0x7f, b'E', b'L', b'F'];
    elf.resize(80, 1);
    fake::file("/bin/hello", &elf);
    let r: RunResult = admin(ADMIN_LINUX_RUN, [RUN_FILE | RUN_FOREGROUND, 0, 0, 0], b"hello").rec(0);
    assert_eq!((r.uid, r.size), (1000, 80));
    assert_eq!(name_str(&r.path), "/bin/hello");
    // Its wait; a second wait is not for the console's foreground process any more
    let w: WaitResult = admin(ADMIN_LINUX_WAIT, [r.pid, 0, 0, 0], b"").rec(0);
    assert_eq!((w.known, w.status), (1, 0));
    let a = admin(ADMIN_LINUX_WAIT, [r.pid, 0, 0, 0], b"");
    assert_eq!((a.rc, a.msg.as_str()), (-EINVAL, "not the console's foreground process"));
    // A failed start carries the reason
    let a = admin(ADMIN_LINUX_RUN, [RUN_FILE, 0, 0, 0], b"missing");
    assert_eq!((a.rc, a.msg.as_str()), (-EIO, "cannot read the program from the pool"));
    assert_eq!(admin(ADMIN_LINUX_TEST, [0; 4], b"").rc, 0);
    assert_eq!(admin(ADMIN_LINUX_TRACE, [1, 0, 0, 0], b"bash").rc, 0);
    assert_eq!(k::compat::linux::TRACE_FILTER.lock().as_str(), "bash");
    assert_eq!(admin(ADMIN_LINUX_PROF, [PROF_RESET, 0, 0, 0], b"").rc, 0);
    assert_eq!(admin(ADMIN_LINUX_PROF, [99, 0, 0, 0], b"").rc, -EINVAL);
    // The desktop: the default root is /ubuntu
    assert_eq!(admin(ADMIN_LINUX_PLASMA, [0; 4], b"").rc, 0);
    assert!(fake::take_out().contains("no KDE in /ubuntu"));
    assert_eq!(admin(ADMIN_LINUX_PLASMA, [1, 0, 0, 0], b"/debian").rc, 0);
    assert!(fake::take_out().contains("no KDE in /debian"));
}
