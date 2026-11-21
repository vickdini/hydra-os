//! Tests of the info primitives' pure part and of linux-server's pseudo file logic.

use alloc::vec::Vec;

use crate::lx::info::*;
use crate::proto::*;
use crate::pseudo::path::{self, classify, File, PidFile, Target, Who};
use crate::pseudo::text;

// ---------------------------------------------------------------- info.rs

#[test]
fn resolve_pid_names_the_caller_and_the_namespace_init() {
    assert_eq!(resolve_pid(0, 42, None), 42);
    assert_eq!(resolve_pid(7, 42, None), 7);
    assert_eq!(resolve_pid(1, 42, None), 1);
    assert_eq!(resolve_pid(1, 42, Some(300)), 300);
    assert_eq!(resolve_pid(0, 42, Some(300)), 42);
    assert_eq!(resolve_pid(5, 42, Some(300)), 5);
}

#[test]
fn to_caller_renumbers_only_the_init() {
    assert_eq!(to_caller(300, Some(300)), 1);
    assert_eq!(to_caller(301, Some(300)), 301);
    assert_eq!(to_caller(300, None), 300);
}

#[test]
fn may_see_follows_the_ptrace_read_rule() {
    let all = |x: u32| (x, x, x);
    // itself, always (even a service)
    assert!(may_see(true, true, (1000, 1000), 0, all(0), all(0)));
    // a service's process: never
    assert!(!may_see(false, true, (0, 0), CAP_SYS_PTRACE, all(0), all(0)));
    // same user and group in all three ids
    assert!(may_see(false, false, (1000, 100), 0, all(1000), all(100)));
    // a set-user-ID target (euid or suid differs): no
    assert!(!may_see(false, false, (1000, 100), 0, (1000, 0, 1000), all(100)));
    assert!(!may_see(false, false, (1000, 100), 0, (1000, 1000, 0), all(100)));
    // a set-group-ID target (egid or sgid differs): no (Linux checks the groups too)
    assert!(!may_see(false, false, (1000, 100), 0, all(1000), (100, 42, 100)));
    assert!(!may_see(false, false, (1000, 100), 0, all(1000), (100, 100, 42)));
    // a caller of another group: no
    assert!(!may_see(false, false, (1000, 7), 0, all(1000), all(100)));
    // CAP_SYS_PTRACE: yes
    assert!(may_see(false, false, (1000, 100), CAP_SYS_PTRACE, all(0), all(0)));
    // other capabilities do not count
    assert!(!may_see(false, false, (1000, 100), !CAP_SYS_PTRACE, all(0), all(0)));
}

#[test]
fn may_query_answers_only_first_namespace_callers_about_linux_processes() {
    assert_eq!(may_query(None, false, false), Ok(()));
    // a caller in a PID namespace of its own, or a user namespace: refused
    assert_eq!(may_query(Some(300), false, false), Err(err::EPERM));
    assert_eq!(may_query(None, true, false), Err(err::EPERM));
    assert_eq!(may_query(Some(300), true, true), Err(err::EPERM));
    // a service's process is no Linux process
    assert_eq!(may_query(None, false, true), Err(err::ESRCH));
}

#[test]
fn comm_is_the_file_name_cut_to_15_bytes() {
    let c = comm_of("/usr/bin/bash");
    assert_eq!(&c[..5], b"bash\0");
    let c = comm_of("/opt/x/a-very-long-program-name");
    assert_eq!(&c[..15], b"a-very-long-pro");
    assert_eq!(c[15], 0);
    assert_eq!(comm_of(""), [0u8; 16]);
    assert_eq!(&comm_of("noslash")[..8], b"noslash\0");
    // multi-byte characters are never cut in the middle
    let c = comm_of("/x/ääääääää"); // 8 x 2 bytes
    let n = c.iter().position(|&b| b == 0).unwrap();
    assert_eq!(n, 14);
    assert!(core::str::from_utf8(&c[..n]).is_ok());
}

#[test]
fn cmdline_rule_keeps_a_terminated_area_and_follows_setproctitle() {
    assert_eq!(cmdline_rule(b"ls\0-l\0".to_vec(), b"HOME=/\0"), b"ls\0-l\0");
    // the final NUL overwritten: runs on into the environment up to the first NUL
    assert_eq!(cmdline_rule(b"kworker: busy".to_vec(), b" more\0HOME=/\0"), b"kworker: busy more\0");
    // a NUL inside the overwritten area stops there
    assert_eq!(cmdline_rule(b"a\0bc".to_vec(), b"x"), b"a\0");
    // no NUL at all
    assert_eq!(cmdline_rule(b"abc".to_vec(), b"def"), b"abcdef");
    assert_eq!(cmdline_rule(Vec::new(), b""), b"");
    // an empty area never shows the environment
    assert_eq!(cmdline_rule(Vec::new(), b"HOME=/\0"), b"");
}

fn areas() -> Vec<Area<'static>> {
    alloc::vec![
        Area { start: 0x400000, end: 0x401000, offset: 0, prot: 5, shared: false, name: Some("/usr/bin/cat") },
        Area { start: 0x7f0000000000, end: 0x7f0000002000, offset: 0x2000, prot: 3, shared: true, name: Some("/dev/shm/x") },
        Area { start: 0x7ffd00000000, end: 0x7ffd00021000, offset: 0, prot: 3, shared: false, name: Some("[stack]") },
        Area { start: 0x10000, end: 0x11000, offset: 0, prot: 0, shared: false, name: None },
    ]
}

#[test]
fn encode_maps_writes_padded_records_and_the_full_length() {
    let a = areas();
    let (data, total) = encode_maps(&a, 1 << 20);
    assert_eq!(data.len(), total);
    assert_eq!(total, record_len(12) + record_len(10) + record_len(7) + record_len(0));
    assert_eq!(data.len() % 8, 0);
    let hdr: LxMapEntry = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const LxMapEntry) };
    assert_eq!(hdr.start, 0x400000);
    assert_eq!(hdr.flags, LX_MAP_R | LX_MAP_X);
    assert_eq!(hdr.name_len, 12);
    assert_eq!(&data[32..44], b"/usr/bin/cat");
    let second: LxMapEntry = unsafe { core::ptr::read_unaligned(data[record_len(12)..].as_ptr() as *const LxMapEntry) };
    assert_eq!(second.flags, LX_MAP_R | LX_MAP_W | LX_MAP_SHARED);
    assert_eq!(second.offset, 0x2000);
}

#[test]
fn encode_maps_leaves_out_whole_records_that_do_not_fit() {
    let a = areas();
    let first = record_len(12);
    let (data, total) = encode_maps(&a, first + 10);
    assert_eq!(data.len(), first);
    assert!(total > first + 10);
    let (data, total2) = encode_maps(&a, 0);
    assert!(data.is_empty());
    assert_eq!(total, total2);
    // once one did not fit, later smaller ones are not written either (order kept)
    let (data, _) = encode_maps(&a, first + record_len(10) + record_len(7) - 1);
    assert_eq!(data.len(), first + record_len(10));
}

#[test]
fn encode_maps_cuts_very_long_names() {
    let long: alloc::string::String = core::iter::repeat('a').take(5000).collect();
    let a = [Area { start: 0, end: 4096, offset: 0, prot: 1, shared: false, name: Some(&long) }];
    let (data, total) = encode_maps(&a, 1 << 20);
    assert_eq!(total, record_len(4095));
    let e: LxMapEntry = unsafe { core::ptr::read_unaligned(data.as_ptr() as *const LxMapEntry) };
    assert_eq!(e.name_len, 4095);
}

#[test]
fn split_who_and_check_len() {
    assert_eq!(split_who(5 | 9 << 32), (5, 9));
    assert_eq!(split_who(5), (5, 0));
    assert_eq!(check_len(16 << 20), Ok(16 << 20));
    assert_eq!(check_len((16 << 20) + 1), Err(err::EINVAL));
}

#[test]
fn info_structs_have_stable_layouts() {
    assert_eq!(core::mem::size_of::<LxMapEntry>(), 32);
    assert_eq!(core::mem::size_of::<LxTaskInfo>(), 18 * 8 + 6 * 4 + 8 + 8 + LX_INFO_NS * 8 + 16);
    assert_eq!(core::mem::size_of::<LxSysInfo>(), 8 * (2 + 3 * LX_INFO_CPUS + 3 + 11));
}

#[test]
fn pseudo_types_cover_every_served_fs_type_once() {
    let mut objs: Vec<u64> = LX_VFS_PSEUDO_TYPES.iter().map(|t| t.2).collect();
    assert!(LX_VFS_PSEUDO_TYPES.iter().any(|t| t.0 == "proc" && t.1 == LXS_PROC && t.2 == LX_VFS_PSEUDO_PROC));
    assert!(LX_VFS_PSEUDO_TYPES.iter().filter(|t| t.0 != "proc").all(|t| t.1 == LXS_LINUX));
    objs.sort();
    objs.dedup();
    // cgroup and cgroup2 share one object
    assert_eq!(objs.len(), LX_VFS_PSEUDO_TYPES.len() - 1);
    assert_eq!(objs, (1..=15).collect::<Vec<u64>>());
}

// ---------------------------------------------------------------- path.rs

fn p(tail: &str) -> Target {
    classify(LX_VFS_PSEUDO_PROC, tail.as_bytes())
}

#[test]
fn classify_global_proc_files() {
    assert_eq!(p("uptime"), Target::File(File::Uptime));
    assert_eq!(p("version"), Target::File(File::Version));
    assert_eq!(p("loadavg"), Target::File(File::Loadavg));
    assert_eq!(p("stat"), Target::File(File::Stat));
    assert_eq!(p("meminfo"), Target::File(File::Meminfo));
    assert_eq!(p("cpuinfo"), Target::File(File::Cpuinfo));
    assert_eq!(p("./uptime"), Target::File(File::Uptime));
    assert_eq!(p("//uptime"), Target::File(File::Uptime));
    assert_eq!(p("sys/kernel/shmmni"), Target::File(File::Static(b"4096\n")));
    assert_eq!(p("sys/fs/inotify/max_user_watches"), Target::File(File::Static(b"1048576\n")));
}

#[test]
fn classify_pid_files() {
    let f = |who, tid, file| Target::File(File::Pid { who, tid, file });
    assert_eq!(p("self/stat"), f(Who::Caller, 0, PidFile::Stat));
    assert_eq!(p("thread-self/status"), f(Who::Caller, 0, PidFile::Status));
    assert_eq!(p("123/statm"), f(Who::Pid(123), 0, PidFile::Statm));
    assert_eq!(p("123/cmdline"), f(Who::Pid(123), 0, PidFile::Cmdline));
    assert_eq!(p("123/comm"), f(Who::Pid(123), 0, PidFile::Comm));
    assert_eq!(p("self/maps"), f(Who::Caller, 0, PidFile::Maps));
    assert_eq!(p("123/task/124/stat"), f(Who::Pid(123), 124, PidFile::Stat));
    assert_eq!(p("self/task/9/comm"), f(Who::Caller, 9, PidFile::Comm));
    // per-thread directories have no statm, cmdline or maps here
    assert_eq!(p("123/task/124/statm"), Target::Kernel);
    assert_eq!(p("123/task/124/cmdline"), Target::Kernel);
}

#[test]
fn classify_sends_the_rest_to_the_kernel() {
    for t in [
        "", "self", "self/", "123", "123/", "self/fd", "self/fd/3", "self/exe", "self/cwd", "self/root", "self/mountinfo", "mounts", "net/tcp", "self/fdinfo/1",
        "self/limits", "self/auxv", "self/cgroup", "self/oom_score_adj", "self/ns/mnt", "self/uid_map", "keys", "swaps", "locks", "filesystems",
        "sys/kernel/random/boot_id", "sys/kernel/random/uuid", "sys/user/max_user_namespaces", "asound/cards", "0/stat", "-1/stat", "12345678901/stat",
        "12a/stat", "123/task/0/stat", "123/task/x/stat", "self/../uptime", "../etc/passwd", "uptime/", "self/stat/", "sys/kernel/nothing", "nothing",
    ] {
        assert_eq!(p(t), if t == "self" { Target::SelfLink(false) } else { Target::Kernel }, "{:?}", t);
    }
    assert_eq!(p("thread-self"), Target::SelfLink(true));
    // not UTF-8
    assert_eq!(classify(LX_VFS_PSEUDO_PROC, b"\xff/stat"), Target::Kernel);
}

#[test]
fn classify_sys_and_other_mounts() {
    let s = |t: &str| classify(LX_VFS_PSEUDO_SYS, t.as_bytes());
    assert_eq!(s("devices/system/cpu/online"), Target::File(File::CpuRange));
    assert_eq!(s("devices/system/cpu/possible"), Target::File(File::CpuRange));
    assert_eq!(s("devices/system/cpu/present"), Target::File(File::CpuRange));
    assert!(File::CpuRange.in_sys());
    assert!(!File::Uptime.in_sys());
    assert_eq!(s("devices/system/cpu"), Target::Kernel);
    assert_eq!(s("class/drm/card0/uevent"), Target::Kernel);
    assert_eq!(s("fs/cgroup/cgroup.procs"), Target::Kernel);
    assert_eq!(s("firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c"), Target::File(File::Efivar));
    // /dev and anything else: the kernel
    assert_eq!(classify(LX_VFS_PSEUDO_DEV, b"null"), Target::Kernel);
    assert_eq!(classify(LX_VFS_PSEUDO_DEVPTS, b"0"), Target::Kernel);
    assert_eq!(classify(99, b"uptime"), Target::Kernel);
    // the high half of the object (a ticket) does not matter
    assert_eq!(classify(LX_VFS_PSEUDO_PROC | 7 << 32, b"uptime"), Target::File(File::Uptime));
}

#[test]
fn components_reject_dotdot() {
    assert_eq!(path::components(b"a/./b//c"), Some(alloc::vec!["a", "b", "c"]));
    assert_eq!(path::components(b"a/../b"), None);
    assert_eq!(path::components(b""), Some(Vec::new()));
}

#[test]
fn inode_numbers_are_stable_and_distinct() {
    let a = path::ino_of(1, b"uptime");
    assert_eq!(a, path::ino_of(1, b"uptime"));
    assert_ne!(a, path::ino_of(1, b"loadavg"));
    assert_ne!(a, path::ino_of(2, b"uptime"));
    for t in [&b""[..], b"x", b"self/stat"] {
        assert!(path::ino_of(1, t) >= 2);
    }
}

#[test]
fn static_table_has_unique_paths() {
    let mut v: Vec<&str> = path::STATIC.iter().map(|s| s.0).collect();
    let n = v.len();
    v.sort();
    v.dedup();
    assert_eq!(v.len(), n);
    for (path_, text) in path::STATIC {
        assert!(path_.starts_with("sys/"));
        assert!(text.ends_with(b"\n"));
        assert_eq!(p(path_), Target::File(File::Static(text)));
    }
}

// ---------------------------------------------------------------- text.rs

fn task() -> LxTaskInfo {
    let mut i = LxTaskInfo {
        pid: 1234,
        tid: 1236,
        ppid: 1,
        pgid: 1234,
        sid: 1000,
        tracer: 0,
        state: b'S' as u64,
        threads: 3,
        start: 4567,
        utime: 11,
        stime: 22,
        cutime: 33,
        cstime: 44,
        nice: -5,
        vsize: 8 << 20,
        rss_anon: 100,
        rss_file: 50,
        locked_kib: 12,
        ids: [1000, 1001, 1002, 100, 101, 102],
        nnp: 1,
        seccomp: 2,
        ..Default::default()
    };
    i.comm[..4].copy_from_slice(b"bash");
    i
}

#[test]
fn pid_stat_has_52_fields_in_proc5_order() {
    let t = alloc::string::String::from_utf8(text::stat(&task())).unwrap();
    assert!(t.ends_with('\n'));
    let f: Vec<&str> = t.trim_end().split(' ').collect();
    assert_eq!(f.len(), 52);
    assert_eq!(f[0], "1234");
    assert_eq!(f[1], "(bash)");
    assert_eq!(f[2], "S");
    assert_eq!(&f[3..6], ["1", "1234", "1000"]);
    assert_eq!(&f[13..17], ["11", "22", "33", "44"]);
    assert_eq!(f[17], "15"); // 20 + nice
    assert_eq!(f[18], "-5");
    assert_eq!(f[19], "3");
    assert_eq!(f[21], "4567");
    assert_eq!(f[22], (8u64 << 20).to_string());
    assert_eq!(f[23], "150");
    assert!(f[24..].iter().all(|x| *x == "0"));
}

#[test]
fn pid_status_lines() {
    let t = alloc::string::String::from_utf8(text::status(&task())).unwrap();
    let get = |k: &str| t.lines().find(|l| l.starts_with(&alloc::format!("{}:", k))).map(|l| l.split_once(":\t").unwrap().1.to_string());
    assert_eq!(get("Name").unwrap(), "bash");
    assert_eq!(get("Tgid").unwrap(), "1234");
    assert_eq!(get("Pid").unwrap(), "1236");
    assert_eq!(get("PPid").unwrap(), "1");
    assert_eq!(get("Uid").unwrap(), "1000\t1001\t1002\t1001");
    assert_eq!(get("Gid").unwrap(), "100\t101\t102\t101");
    assert_eq!(get("NStgid").unwrap(), "1234");
    assert_eq!(get("VmLck").unwrap(), "12 kB");
    assert_eq!(get("VmSize").unwrap(), "8192 kB");
    assert_eq!(get("VmRSS").unwrap(), "600 kB");
    assert_eq!(get("RssAnon").unwrap(), "400 kB");
    assert_eq!(get("RssFile").unwrap(), "200 kB");
    assert_eq!(get("NoNewPrivs").unwrap(), "1");
    assert_eq!(get("Seccomp").unwrap(), "2");
    assert!(t.ends_with("Seccomp:\t2\n"));
}

#[test]
fn pid_status_namespace_ids() {
    let mut i = task();
    i.ns_depth = 2;
    i.ns_inits = [1234, 99, 0, 0];
    let t = alloc::string::String::from_utf8(text::status(&i)).unwrap();
    assert!(t.contains("NStgid:\t1234\t1\t1234\n"));
    assert!(t.contains("NSpid:\t1236\t1236\t1236\n"));
    // a depth above the array is clamped
    i.ns_depth = 99;
    let _ = text::status(&i);
}

#[test]
fn statm_comm_and_zombie_state() {
    assert_eq!(text::statm(&task()), b"2048 150 50 0 0 100 0\n");
    assert_eq!(text::comm_file(&task()), b"bash\n");
    let mut z = task();
    z.state = b'Z' as u64;
    assert!(alloc::string::String::from_utf8(text::stat(&z)).unwrap().starts_with("1234 (bash) Z "));
    // a full 16-byte comm (no NUL) is taken whole
    z.comm = *b"abcdefghijklmnop";
    assert_eq!(text::comm(&z), b"abcdefghijklmnop");
}

fn sys() -> LxSysInfo {
    let mut s = LxSysInfo { now_ns: 123_456_789_000, ncpu: 2, running: 3, tasks: 90, last_pid: 4321, procs: 70, boot_time: 1_700_000_000, ..Default::default() };
    s.cpu[0] = [10, 20, 1000];
    s.cpu[1] = [1, 2, 2005];
    s.cpu[5] = [99, 99, 99]; // past ncpu: not shown
    s.load = [2048, 1024 + 2048 * 3, 0];
    s.mem_total = 4_000_000;
    s.mem_free = 1_000_000;
    s.cached = 500_000;
    s.reclaimable = 3_500_000;
    s.swap_total = 100;
    s.swap_free = 40;
    s
}

#[test]
fn proc_stat_text() {
    let t = alloc::string::String::from_utf8(text::proc_stat(&sys())).unwrap();
    let l: Vec<&str> = t.lines().collect();
    assert_eq!(l[0], "cpu  11 0 22 3005 0 0 0 0 0 0");
    assert_eq!(l[1], "cpu0 10 0 20 1000 0 0 0 0 0 0");
    assert_eq!(l[2], "cpu1 1 0 2 2005 0 0 0 0 0 0");
    assert_eq!(l[3], "intr 0");
    assert!(t.contains("btime 1700000000\nprocesses 70\nprocs_running 3\nprocs_blocked 0\n"));
    // no CPUs reported: one line for cpu0, running at least 1
    let mut s = sys();
    s.ncpu = 0;
    s.running = 0;
    let t = alloc::string::String::from_utf8(text::proc_stat(&s)).unwrap();
    assert!(t.contains("cpu0 10 0 20 1000"));
    assert!(!t.contains("cpu1"));
    assert!(t.contains("procs_running 1\n"));
}

#[test]
fn uptime_loadavg_meminfo() {
    assert_eq!(text::uptime(&sys()), b"123.45 30.05\n");
    assert_eq!(text::loadavg(&sys()), b"1.00 3.50 0.00 3/90 4321\n");
    let m = alloc::string::String::from_utf8(text::meminfo(&sys())).unwrap();
    assert!(m.starts_with("MemTotal:        4000000 kB\nMemFree:         1000000 kB\nMemAvailable:    4000000 kB\n"));
    assert!(m.contains("Cached:           500000 kB\n"));
    assert!(m.contains("SwapTotal:           100 kB\nSwapFree:             40 kB\n"));
    assert_eq!(m.lines().count(), 11);
}

#[test]
fn cpuinfo_and_cpu_range() {
    let t = alloc::string::String::from_utf8(text::cpuinfo(4)).unwrap();
    assert_eq!(t.matches("processor\t:").count(), 4);
    assert!(t.contains("processor\t: 3\n"));
    assert!(t.contains("siblings\t: 4\n"));
    assert_eq!(text::cpu_range(1), b"0\n");
    assert_eq!(text::cpu_range(4), b"0-3\n");
}

#[test]
fn maps_text_matches_the_kernels_layout() {
    let (data, _) = encode_maps(&areas(), 1 << 20);
    let t = alloc::string::String::from_utf8(text::maps(&data)).unwrap();
    let l: Vec<&str> = t.lines().collect();
    assert_eq!(l.len(), 4);
    assert!(l[0].starts_with("00400000-00401000 r-xp 00000000 00:00 0"));
    assert_eq!(l[0].len(), 73 + "/usr/bin/cat".len());
    assert!(l[0].ends_with(" /usr/bin/cat"));
    assert!(l[1].starts_with("7f0000000000-7f0000002000 rw-s 00002000 00:00 0"));
    assert!(l[2].ends_with("[stack]"));
    assert_eq!(l[3], "00010000-00011000 ---p 00000000 00:00 0");
    // a cut record at the end is ignored, never read past the data
    assert_eq!(text::maps(&data[..10]), b"");
    // a record cut in its name, or with a name longer than the kernel writes, ends the list
    let first = record_len(12);
    assert_eq!(alloc::string::String::from_utf8(text::maps(&data[..first + 40])).unwrap().lines().count(), 1);
    let mut bad = data.clone();
    bad[first + 28..first + 32].copy_from_slice(&5000u32.to_le_bytes());
    assert_eq!(alloc::string::String::from_utf8(text::maps(&bad)).unwrap().lines().count(), 1);
}

#[test]
fn classify_efivars_files() {
    let s = |t: &str| classify(LX_VFS_PSEUDO_SYS, t.as_bytes());
    assert_eq!(s("firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c"), Target::File(File::Efivar));
    assert!(File::Efivar.in_sys());
    // the directory, a bad GUID, a short name, a trailing slash: the kernel
    for t in [
        "firmware/efi/efivars",
        "firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8",
        "firmware/efi/efivars/Boot0000-8be4df61x93ca-11d2-aa0d-00e098032b8c",
        "firmware/efi/efivars/Boot0000_8be4df61-93ca-11d2-aa0d-00e098032b8c",
        "firmware/efi/efivars/-8be4df61-93ca-11d2-aa0d-00e098032b8c",
        "firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c/",
        "firmware/efi/efivars/Boot0000-8be4df61-93ca-11d2-aa0d-00e098032g8c",
    ] {
        assert_eq!(s(t), Target::Kernel, "{}", t);
    }
    assert!(path::efivar_name("X-00000000-0000-0000-0000-000000000000"));
    assert!(!path::efivar_name("00000000-0000-0000-0000-000000000000"));
}

#[test]
fn classify_rejects_big_ids_and_dot_endings() {
    // IDs above 31 bits never reach the info primitives (they would spill into the other half)
    assert_eq!(p("2147483647/stat"), Target::File(File::Pid { who: Who::Pid(2147483647), tid: 0, file: PidFile::Stat }));
    assert_eq!(p("2147483648/stat"), Target::Kernel);
    assert_eq!(p("9999999999/stat"), Target::Kernel);
    assert_eq!(p("1/task/4294967296/stat"), Target::Kernel);
    // `/.` at the end: must be a directory (ENOTDIR for a file, the kernel's rules)
    assert_eq!(p("version/."), Target::Kernel);
    assert_eq!(p("self/."), Target::Kernel);
    assert_eq!(p("self/stat/."), Target::Kernel);
    assert_eq!(p("."), Target::Kernel);
    // `.` in the middle is fine
    assert_eq!(p("./self/./stat"), Target::File(File::Pid { who: Who::Caller, tid: 0, file: PidFile::Stat }));
}

#[test]
fn classify_rejects_leading_zeros() {
    assert_eq!(p("01/stat"), Target::Missing);
    assert_eq!(p("00/stat"), Target::Missing);
    assert_eq!(p("1/task/01/stat"), Target::Missing);
    assert_eq!(p("01/fd"), Target::Missing);
    assert_eq!(p("10/stat"), Target::File(File::Pid { who: Who::Pid(10), tid: 0, file: PidFile::Stat }));
}

#[test]
fn access_rule_for_read_only_files_and_the_self_link() {
    use crate::pseudo::path::access_rule;
    // F_OK, R_OK: anyone
    assert_eq!(access_rule(0, 0, 1000, false), Ok(()));
    assert_eq!(access_rule(4, 0, 1000, false), Ok(()));
    // W_OK: root only (it overrides the mode bits)
    assert_eq!(access_rule(2, 0, 1000, false), Err(-13));
    assert_eq!(access_rule(2, 0, 0, false), Ok(()));
    // X_OK: never on a file (no x bit; root too), fine on the directory
    assert_eq!(access_rule(1, 0, 0, false), Err(-13));
    assert_eq!(access_rule(1, 0, 1000, true), Ok(()));
    assert_eq!(access_rule(5, 0, 1000, true), Ok(()));
    // bad mode bits and faccessat2 flags
    assert_eq!(access_rule(8, 0, 0, false), Err(-22));
    assert_eq!(access_rule(4, 0x200 | 0x100 | 0x1000, 0, false), Ok(()));
    assert_eq!(access_rule(4, 0x400, 0, false), Err(-22));
}
