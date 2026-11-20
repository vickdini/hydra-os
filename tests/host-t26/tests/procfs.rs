//! fs.rs: the pseudo files of /dev and /proc (matching, contents, writes, stat, links).
mod common;
use common::*;
use lx::fs::{self as pfs, PseudoFile};

fn text(p: &str) -> String {
    let f = pfs::match_pseudo_path(p).unwrap_or_else(|| panic!("{} not served", p));
    let mut out = Vec::new();
    let mut b = [0u8; 97];
    loop {
        let n = f.read(out.len(), &mut b);
        if n == 0 {
            break;
        }
        out.extend_from_slice(&b[..n]);
        if out.len() > 200_000 {
            break;
        }
    }
    String::from_utf8(out).unwrap()
}

fn pid_text(rest: &str) -> Option<String> {
    pfs::proc_pid_file_text(rest).map(|v| String::from_utf8_lossy(&v).into_owned())
}

#[test]
fn devices() {
    let _e = setup();
    let mut b = [7u8; 8];
    assert_eq!(pfs::match_pseudo_path("/dev/null").unwrap().read(0, &mut b), 0);
    assert_eq!(pfs::match_pseudo_path("/dev/zero").unwrap().read(0, &mut b), 8);
    assert_eq!(b, [0; 8]);
    b = [7; 8];
    assert_eq!(pfs::match_pseudo_path("/dev/full").unwrap().read(0, &mut b), 8);
    assert_eq!(b, [0; 8]);
    assert_eq!(pfs::match_pseudo_path("/dev/random").unwrap().read(0, &mut b), 8);
    assert_eq!(pfs::match_pseudo_path("/dev/urandom").unwrap().write(b"x"), 1);
    assert_eq!(pfs::match_pseudo_path("/dev/null").unwrap().write(b"abc"), 3);
    assert_eq!(pfs::match_pseudo_path("/dev/full").unwrap().write(b"abc"), 0);
    assert_eq!(pfs::match_pseudo_path("/proc/version").unwrap().write(b"abc"), 0);
    assert!(pfs::match_pseudo_path("/dev/sda").is_none());
    assert!(pfs::match_pseudo_path("/etc/passwd").is_none());
}

#[test]
fn static_and_system_files() {
    let _e = setup();
    assert!(text("/proc/version").starts_with("Linux version 6.8.0-hydra"));
    let m = text("/proc/meminfo");
    assert!(m.starts_with("MemTotal:        8388608 kB\nMemFree:         6291456 kB\nMemAvailable:    6291472 kB\n"));
    assert!(m.contains("Cached:               40 kB\n"));
    assert!(m.contains("SwapTotal:          2048 kB\n") && m.contains("SwapFree:           1024 kB\n"));
    assert!(text("/proc/swaps").starts_with("Filename"));
    assert_eq!(text("/proc/filesystems"), "nodev\tproc\n\tzfs\n");
    assert_eq!(text("/proc/sys/kernel/dmesg_restrict"), "1\n");
    assert_eq!(text("/proc/sys/net/ipv4/ip_forward"), "0\n");
    assert_eq!(text("/proc/sys/net/ipv6/conf/default/hop_limit"), "64\n");
    assert_eq!(text("/proc/sys/fs/inotify/max_user_watches"), "1048576\n");
    assert_eq!(text("/proc/sys/fs/inotify/max_user_instances"), "1024\n");
    assert_eq!(text("/proc/sys/fs/inotify/max_queued_events"), "16384\n");
    assert_eq!(text("/proc/sys/kernel/overflowuid"), "65534\n");
    assert_eq!(text("/proc/sys/kernel/random/entropy_avail"), "256\n");
    assert_eq!(text("/proc/sys/fs/mqueue/msg_max"), "10\n");
    assert_eq!(text("/proc/sys/fs/mqueue/msgsize_max"), "8192\n");
    assert_eq!(text("/proc/sys/fs/mqueue/queues_max"), "256\n");
    assert_eq!(text("/proc/sys/kernel/shmmax"), "1099511627776\n");
    assert_eq!(text("/proc/sys/kernel/shmall"), "268435456\n");
    assert_eq!(text("/proc/sys/kernel/shmmni"), "4096\n");
    assert_eq!(text("/proc/sys/kernel/sem"), "32000\t1024000000\t500\t32000\n");
    assert_eq!(text("/proc/sys/kernel/msgmax"), "8192\n");
    assert_eq!(text("/proc/sys/kernel/msgmnb"), "16384\n");
    assert_eq!(text("/proc/sys/kernel/msgmni"), "32000\n");
    assert_eq!(text("/proc/sys/kernel/yama/ptrace_scope"), "3\n");
    assert_eq!(text("/proc/sys/kernel/perf_event_paranoid"), "2\n");
    assert_eq!(text("/proc/sys/user/max_user_namespaces"), "15000\n");
    assert_eq!(pfs::match_pseudo_path("/proc/sys/user/max_user_namespaces").unwrap().write(b"5\n"), 2);
    // CPUs
    let c = text("/proc/cpuinfo");
    assert_eq!(c.matches("processor\t:").count(), 2);
    assert_eq!(text("/sys/devices/system/cpu/online"), "0-1\n");
    hydra_hosttests_t26::fake::arch::CPUS.set(1);
    assert_eq!(text("/sys/devices/system/cpu/possible"), "0\n");
    // stat, uptime, loadavg
    hydra_hosttests_t26::fake::arch::CPUS.set(2);
    lx::proc::add(150, 1);
    let st = text("/proc/stat");
    assert!(st.starts_with("cpu "));
    assert!(st.contains("cpu0 ") && st.contains("cpu1 "));
    assert!(st.contains("btime 1767225599\n"));
    assert!(st.contains("processes 2\n"));
    hydra_hosttests_t26::fake::arch::TICKS.set(12_340);
    assert!(text("/proc/uptime").starts_with("12.34 "));
    assert_eq!(text("/proc/loadavg"), "0.00 0.00 0.00 1/1 150\n");
    // Keys, network tables, locks, sound
    assert!(text("/proc/keys").contains("keyring"));
    hydra_hosttests_t26::fake::lx::KEYS_TEXT.with_borrow_mut(|k| *k = Some("from server\n".into()));
    assert_eq!(text("/proc/keys"), "from server\n");
    assert!(text("/proc/net/tcp").contains("local_address"));
    assert!(text("/proc/self/net/unix").starts_with("Num"));
    assert!(text("/proc/100/net/route").starts_with("Iface"));
    assert_eq!(text("/proc/net/snmp"), "");
    hydra_hosttests_t26::fake::lx::NET_TEXT.with_borrow_mut(|k| *k = Some("srv\n".into()));
    hydra_hosttests_t26::fake::lx::UNIX_TEXT.with_borrow_mut(|k| *k = Some("srvunix\n".into()));
    assert_eq!(text("/proc/net/tcp6"), "srv\n");
    assert_eq!(text("/proc/net/unix"), "srvunix\n");
    assert!(pfs::match_pseudo_path("/proc/abc/net/tcp").is_none());
    assert!(pfs::match_pseudo_path("/proc/net/nothing").is_none());
    assert_eq!(text("/proc/locks"), "");
    assert!(text("/proc/asound/cards").contains("HDA"));
    assert!(pfs::match_pseudo_path("/proc/asound/none").is_none());
}

#[test]
fn uuids() {
    let _e = setup();
    let a = text("/proc/sys/kernel/random/boot_id");
    let b = text("/proc/sys/kernel/random/boot_id");
    assert_eq!(a, b);
    assert_eq!(a.len(), 37);
    assert_eq!(&a[14..15], "4");
    let u1 = text("/proc/sys/kernel/random/uuid");
    let u2 = text("/proc/sys/kernel/random/uuid");
    assert_ne!(u1, u2);
}

#[test]
fn self_files() {
    let _e = setup();
    let mm = std::sync::Arc::new(spin::Mutex::new(hydra_hosttests_t26::memory::vm::Mm { maps: "00400000-00401000 r-xp\n".into(), auxv: vec![9, 9], usage: (8 << 20, 10, 5), ..Default::default() }));
    task::current(|t| t.mm = Some(mm.clone()));
    assert_eq!(text("/proc/self/maps"), "00400000-00401000 r-xp\n");
    assert_eq!(text("/proc/self/auxv").as_bytes(), &(1..=16).collect::<Vec<u8>>()[..]);
    task::current(|t| t.mm = None);
    assert_eq!(text("/proc/self/maps"), "");
    // Mount tables: Hydra's fixed layout in the initial namespace
    assert!(text("/proc/self/mountinfo").starts_with("2069 1 8:1 / / rw,relatime shared:1 - zfs hydrapool/root rw,xattr\n"));
    assert!(text("/proc/mounts").starts_with("hydrapool/root / zfs"));
    assert!(text("/proc/self/mounts").contains("devpts /dev/pts"));
    assert!(pfs::match_pseudo_path("/proc/123/mountinfo").is_some());
    assert!(pfs::mountinfo_text().contains("/sys/fs/cgroup"));
    // Per-process files are captured at open: through the path they read empty
    assert_eq!(text("/proc/self/comm"), "");
}

#[test]
fn proc_directories() {
    let _e = setup();
    for p in ["/proc/self", "/proc/thread-self", "/proc/12", "/proc/self/task", "/proc/12/fd/", "/proc/self/ns"] {
        assert!(pfs::is_proc_dir(p), "{}", p);
    }
    for p in ["/proc", "/proc/x", "/proc/self/maps", "/etc/self", "/proc/12/fdinfo"] {
        assert!(!pfs::is_proc_dir(p), "{}", p);
    }
    let mut st = lx::types::LinuxStat::default();
    lx::proc::with(task::SELF_PID, |p| p.threads = vec![100, 101, 102]);
    PseudoFile::ProcDir("/proc/self/task".into()).stat(&mut st);
    assert_eq!((st.st_mode, st.st_nlink), (0o040555, 5));
    PseudoFile::ProcDir("/proc/100/task/".into()).stat(&mut st);
    assert_eq!(st.st_nlink, 5);
    PseudoFile::ProcDir("/proc/self".into()).stat(&mut st);
    assert_eq!(st.st_nlink, 2);
    assert_eq!(text("/proc/self/fd"), "");
}

#[test]
fn stat_of_pseudo_files() {
    let _e = setup();
    let st = |p: &str| {
        let mut s = lx::types::LinuxStat::default();
        pfs::match_pseudo_path(p).unwrap().stat(&mut s);
        s
    };
    assert_eq!(st("/dev/zero").st_mode, 0o020666);
    assert_eq!(st("/sys/fs/cgroup/cgroup.procs").st_mode, 0o100644);
    assert_eq!(st("/proc/self/oom_score_adj").st_mode, 0o100644);
    assert_eq!(st("/proc/self/oom_score").st_mode, 0o100444);
    assert_eq!(st("/proc/self/uid_map").st_mode, 0o100644);
    assert_eq!(st("/proc/self/ns/mnt").st_mode, 0o100444);
    let s = st("/proc/sys/kernel/msgmax");
    assert_eq!((s.st_mode, s.st_size), (0o100444, 5));
    assert_eq!(st("/proc/version").st_size, 512);
}

#[test]
fn cgroups() {
    let _e = setup();
    lx::proc::add(200, 1);
    lx::proc::add(201, 1);
    lx::proc::with(201, |p| p.cgroup = Some("/app.slice".into()));
    lx::proc::add(202, 1);
    lx::proc::with(202, |p| {
        p.cgroup = Some("/app.slice".into());
        p.zombie = true;
    });
    assert_eq!(text("/sys/fs/cgroup/app.slice/cgroup.procs"), "201\n");
    let root = text("/sys/fs/cgroup/cgroup.procs");
    assert!(root.contains("200\n") && root.contains("100\n") && !root.contains("201"));
    assert!(pfs::match_pseudo_path("/sys/fs/cgroupx/cgroup.procs").is_none());
    assert!(pfs::match_pseudo_path("/sys/fs/cgroup/a/other").is_none());
    // Writing a pid moves the process; 0 is the writer; garbage and missing pids fail
    let f = pfs::match_pseudo_path("/sys/fs/cgroup/app.slice/cgroup.procs").unwrap();
    assert_eq!(f.write(b"200\n"), 4);
    assert_eq!(lx::proc::with(200, |p| p.cgroup.clone()).as_deref(), Some("/app.slice"));
    assert_eq!(f.write(b"0"), 1);
    assert_eq!(lx::proc::with(100, |p| p.cgroup.clone()).as_deref(), Some("/app.slice"));
    assert_eq!(f.write(b"x"), 0);
    assert_eq!(f.write(b"999"), 0);
    let r = pfs::match_pseudo_path("/sys/fs/cgroup/cgroup.procs").unwrap();
    assert_eq!(r.write(b"200"), 3);
    assert!(lx::proc::with(200, |p| p.cgroup.is_none()));
    // /proc/<pid>/cgroup
    assert_eq!(pid_text("201/cgroup").unwrap(), "0::/app.slice\n");
    assert_eq!(pid_text("200/cgroup").unwrap(), "0::/\n");
    assert_eq!(pid_text("1/cgroup").unwrap(), "0::/init.scope\n");
    lx::proc::PROCS.lock().remove(&1);
    assert_eq!(pid_text("1/cgroup").unwrap(), "0::/init.scope\n");
    assert!(pid_text("999/cgroup").is_none());
}

#[test]
fn oom_and_namespace_files() {
    let _e = setup();
    assert_eq!(text("/proc/self/oom_score_adj"), "0\n");
    assert_eq!(text("/proc/100/oom_score"), "666\n");
    let f = pfs::match_pseudo_path("/proc/self/oom_score_adj").unwrap();
    assert_eq!(f.write(b"-500\n"), 5);
    assert_eq!(text("/proc/self/oom_score_adj"), "-500\n");
    assert_eq!(f.write(b"abc"), 0);
    assert_eq!(pfs::match_pseudo_path("/proc/self/oom_score").unwrap().write(b"1"), 0);
    assert_eq!(pfs::match_pseudo_path("/proc/999/oom_score_adj").unwrap().write(b"1"), 0);
    assert_eq!(text("/proc/999/oom_score_adj"), "");
    assert!(pfs::match_pseudo_path("/proc/x/oom_score").is_none());
    // uid_map and friends go to ns
    assert!(text("/proc/self/uid_map").contains("4294967295"));
    assert_eq!(pfs::match_pseudo_path("/proc/self/gid_map").unwrap().write(b"0 0 1\n"), 6);
    assert_eq!(text("/proc/self/ns/net"), "");
}

#[test]
fn pid_files() {
    let _e = setup();
    lx::proc::with(task::SELF_PID, |p| {
        p.ppid = 1;
        p.threads = vec![100, 104];
        p.ns.pid_inits = vec![100];
    });
    task::current(|t| {
        t.exe = "/usr/bin/a-very-long-program-name".into();
        t.cmdline = Some(b"prog\0arg\0".to_vec());
        t.uid = 5;
        t.euid = 6;
    });
    lx::ptrace::TRACER.set(42);
    assert_eq!(pid_text("self/comm").unwrap(), "a-very-long-pro\n");
    let st = pid_text("self/status").unwrap();
    assert!(st.starts_with("Name:\ta-very-long-pro\nState:\tR (running)\nTgid:\t100\nPid:\t100\nPPid:\t1\nTracerPid:\t42\n"));
    assert!(st.contains("Uid:\t5\t6\t0\t6\n"));
    assert!(st.contains("NStgid:\t100\t1\n"));
    assert!(st.contains("VmLck:\t12 kB\n"));
    assert!(st.contains("NoNewPrivs:\t1\nSeccomp:\t2\n"));
    // A thread's own status
    let t = pid_text("100/task/104/status").unwrap();
    assert!(t.contains("Pid:\t104\n") && t.contains("NSpid:\t104\t104\n"));
    assert!(pid_text("100/task/105/status").is_none());
    assert!(pid_text("100/task/x/status").is_none());
    assert!(pid_text("100/task/104").is_none());
    // stat: 52 fields
    let s = pid_text("self/stat").unwrap();
    let fields: Vec<&str> = s.trim_end().split(' ').collect();
    assert_eq!(fields.len(), 52);
    assert_eq!(fields[0], "100");
    assert_eq!(fields[1], "(a-very-long-pro)");
    assert_eq!(fields[2], "R");
    assert_eq!(fields[13], "10"); // utime in clock ticks
    assert_eq!(fields[18], "5"); // nice
    task::current(|t| t.runnable = false);
    assert_eq!(pid_text("self/stat").unwrap().split(' ').nth(2), Some("S"));
    lx::proc::with(task::SELF_PID, |p| p.zombie = true);
    assert_eq!(pid_text("self/stat").unwrap().split(' ').nth(2), Some("Z"));
    lx::proc::with(task::SELF_PID, |p| p.zombie = false);
    // statm, with memory
    let mm = std::sync::Arc::new(spin::Mutex::new(hydra_hosttests_t26::memory::vm::Mm { usage: (8192 * 4096, 7, 3), ..Default::default() }));
    task::current(|t| t.mm = Some(mm.clone()));
    assert_eq!(pid_text("self/statm").unwrap(), "8192 10 3 0 0 7 0\n");
    assert!(pid_text("self/status").unwrap().contains("VmRSS:\t40 kB\n"));
    // cmdline: the recorded one when the memory has no argument area
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"prog\0arg\0");
    // maps, limits, auxv; another process the caller may not inspect
    assert_eq!(pid_text("self/maps").unwrap(), "");
    assert_eq!(pid_text("self/limits").unwrap(), "Limit for 100\n");
    assert_eq!(pfs::proc_pid_file_text("self/auxv").unwrap(), Vec::<u8>::new());
    task::add_process(300, 0);
    lx::extra::deny(300);
    assert!(pid_text("300/maps").is_none());
    assert!(pid_text("300/auxv").is_none());
    // Missing process, malformed paths
    assert!(pid_text("999/comm").is_none());
    assert!(pid_text("abc/comm").is_none());
    assert!(pid_text("self").is_none());
    assert!(pid_text("self/fdinfo/x").is_none());
    assert!(pid_text("self/unknown").is_none());
}

#[test]
fn live_cmdline_from_memory() {
    let _e = setup();
    // The argument area in (host) memory: "a\0bb\0" then the environment
    let area = hydra_hosttests_t26::fake::leak(b"a\0bb\0ENV=1\0".to_vec());
    let mm = std::sync::Arc::new(spin::Mutex::new(hydra_hosttests_t26::memory::vm::Mm { args: (area, area + 5, area + 11), ..Default::default() }));
    task::current(|t| t.mm = Some(mm.clone()));
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"a\0bb\0");
    // setproctitle overwrote the final NUL: the text up to the first NUL, into the environment
    let area2 = hydra_hosttests_t26::fake::leak(b"title-long-ENV\0rest".to_vec());
    mm.lock().args = (area2, area2 + 5, area2 + 19);
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"title-long-ENV\0");
    // No environment after it
    mm.lock().args = (area2, area2 + 5, area2 + 5);
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"title");
    // Unreadable memory: the recorded command line
    mm.lock().args = (16, 32, 32);
    task::current(|t| t.cmdline = Some(b"rec\0".to_vec()));
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"rec\0");
    mm.lock().args = (0, 0, 0);
    assert_eq!(pfs::proc_pid_file_text("self/cmdline").unwrap(), b"rec\0");
}

#[test]
fn fdinfo() {
    let _e = setup();
    let f = install(FileDescriptor::File { path: "/dev/zero".into(), cursor: 77, readable: true, writable: true, append: false, shown: None });
    task::with_current_fds_mut(|t| t.set_cloexec(f as usize, true));
    assert_eq!(pid_text(&format!("self/fdinfo/{}", f)).unwrap(), "pos:\t77\nflags:\t02000002\nmnt_id:\t2069\n");
    // A pidfd of a live process, then of a gone one
    task::add_process(320, 0);
    let p = install(FileDescriptor::PidFd(std::sync::Arc::new(lx::pidfd::PidFd { pid: 320 })));
    assert!(pid_text(&format!("self/fdinfo/{}", p)).unwrap().ends_with("Pid:\t320\nNSpid:\t320\n"));
    let g = install(FileDescriptor::PidFd(std::sync::Arc::new(lx::pidfd::PidFd { pid: 9999 })));
    assert!(pid_text(&format!("self/fdinfo/{}", g)).unwrap().ends_with("Pid:\t-1\nNSpid:\t-1\n"));
    // A linux-server pidfd (its tag is the pid)
    let d: std::sync::Arc<dyn lx::chardev::CharDevice> = std::sync::Arc::new(lx::chardev::TestDev::server(22, None));
    let s = install(FileDescriptor::Device(d));
    assert!(pid_text(&format!("self/fdinfo/{}", s)).unwrap().contains("Pid:\t-1\n"));
    assert!(pid_text("self/fdinfo/500").is_none());
    // Another process's descriptor
    let fds = task::add_process(321, 0);
    fds.lock().alloc_fd(FileDescriptor::ConsoleIn).unwrap();
    assert!(pid_text("321/fdinfo/0").unwrap().starts_with("pos:\t0\n"));
}

#[test]
fn proc_links() {
    let _e = setup();
    assert_eq!(pfs::proc_link("/proc/self").unwrap(), "100");
    assert_eq!(pfs::proc_link("/proc/thread-self").unwrap(), "100/task/100");
    task::with_current_fds_mut(|t| t.cwd_path = "/home/u".into());
    assert_eq!(pfs::proc_link("/proc/self/cwd").unwrap(), "/home/u");
    assert_eq!(pfs::proc_link("/proc/self/exe").unwrap(), "/usr/bin/test-program");
    assert_eq!(pfs::proc_link("/proc/self/root").unwrap(), "/");
    assert_eq!(pfs::proc_link("/proc/self/ns/mnt").unwrap(), "mnt:[4026531840]");
    task::add_process(330, 0);
    task::with_other(330, |t| t.exe = "/bin/kwin".into());
    assert_eq!(pfs::proc_link("/proc/330/exe").unwrap(), "/bin/kwin");
    assert!(pfs::proc_link("/proc/330/root").is_none());
    assert!(pfs::proc_link("/proc/330/cwd").is_none());
    assert!(pfs::proc_link("/proc/abc/exe").is_none());
    assert!(pfs::proc_link("/etc").is_none());
    assert!(pfs::proc_link("/proc/version").is_none());
}
