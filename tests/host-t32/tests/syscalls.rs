//! `arch/syscall.rs`: the MSR set-up and the dispatcher: the personality hook, the
//! lock-free paths (identity calls, forwarded Linux calls), the kernel lock around the
//! rest, the Linux path with tracing and ptrace stops, and every native system call's
//! routing (to the stubbed services, fd table and Linux server).
//!
//! The kernel lock is global: every test holds [`serial`].

use std::sync::atomic::Ordering::SeqCst;
use std::sync::{Arc, Mutex, MutexGuard};

use hydra_hosttests_t32::arch::idt::FpuState;
use hydra_hosttests_t32::arch::smp;
use hydra_hosttests_t32::arch::syscall::{self, SyscallFrame};
use hydra_hosttests_t32::fs::FileDescriptor;
use hydra_hosttests_t32::ipc::service::WireMessage;
use hydra_hosttests_t32::stubs::task::{self, TaskPersonality};
use hydra_hosttests_t32::{host, stubs};
use x86_64::hw;

fn serial() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    let g = LOCK.lock().unwrap_or_else(|e| e.into_inner());
    host::reset();
    stubs::reset();
    host::set_cpu(0);
    g
}

fn frame(nr: u64, a: [u64; 3]) -> SyscallFrame {
    SyscallFrame { r9: 0, r8: 0, r10: 0, rdx: a[2], rsi: a[1], rdi: a[0], rax: nr, r15: 0, r14: 0, r13: 0, r12: 0, rbp: 0, rbx: 0, rip: 0x40_1000, rflags: 0x202, rsp: 0x7FFF_0000 }
}

/// A native call: returns rax.
fn native(nr: u64, a: [u64; 3]) -> i64 {
    task::PERSONALITY.set(TaskPersonality::Hydra);
    let mut f = frame(nr, a);
    let mut fpu = FpuState::new();
    syscall::syscall_dispatch(&mut f, &mut fpu);
    assert_eq!(smp::bkl_owner(), usize::MAX, "the lock is let go at the end");
    assert!(!hw::if_flag(), "interrupts off for the return to user mode");
    hw::set_if(true);
    f.rax as i64
}

fn calls() -> Vec<String> {
    stubs::take_calls()
}

fn has(v: &[String], s: &str) -> bool {
    v.iter().any(|l| l.contains(s))
}

#[test]
fn msr_setup() {
    let _g = serial();
    host::wrmsr(syscall::IA32_EFER, 0xD00);
    host::MSR_WRITES.with_borrow_mut(|w| w.clear());
    syscall::init();
    let w = host::MSR_WRITES.with_borrow(|w| w.clone());
    assert_eq!(w[0], (syscall::IA32_EFER, 0xD01), "SCE on, the rest kept");
    assert_eq!(w[1], (syscall::IA32_STAR, 0x23u64 << 48 | 0x08u64 << 32));
    assert_eq!(w[2].0, syscall::IA32_LSTAR);
    assert!(w[2].1 != 0);
    assert_eq!(w[3].0, syscall::IA32_CSTAR);
    assert_ne!(w[3].1, w[2].1);
    assert_eq!(w[4], (syscall::IA32_SYSENTER_CS, 0));
    assert_eq!(w[5], (syscall::IA32_FMASK, 0x0004_4700));
    // The kernel stack for the next entry, in the per-CPU block
    syscall::set_kernel_rsp(0xFFFF_8000_0000_8000);
    assert_eq!(hydra_hosttests_t32::arch::percpu::kernel_rsp_of(0), 0xFFFF_8000_0000_8000);
}

#[test]
fn personality_table_takes_over() {
    let _g = serial();
    static TABLE: hydra_hosttests_t32::personality::Table = hydra_hosttests_t32::personality::Table(9);
    hydra_hosttests_t32::personality::CURRENT_TABLE.store(&TABLE as *const _ as *mut _, SeqCst);
    let mut f = frame(1, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    hydra_hosttests_t32::personality::CURRENT_TABLE.store(core::ptr::null_mut(), SeqCst);
    assert_eq!(calls(), vec!["personality::syscall 1 table 9"]);
    assert_eq!(smp::bkl_owner(), usize::MAX);
}

#[test]
fn fast_identity_calls_skip_the_lock() {
    let _g = serial();
    stubs::answer("linux::fast_syscall", 1000);
    let mut f = frame(102, [0; 3]);
    hw::set_if(false);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax, 1000);
    assert!(!hw::if_flag());
    assert_eq!(calls(), vec!["linux::fast_syscall 102"]);
}

#[test]
fn forwarded_calls_and_replies() {
    let _g = serial();
    // A forwarded Linux call that came back: its result, no lock
    stubs::answer("lx::fast", 1);
    stubs::answer("lx::fast_r", -11);
    let mut f = frame(0, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax as i64, -11);
    assert_eq!(smp::bkl_owner(), usize::MAX);
    // ...with a signal to deliver: under the lock
    stubs::answer("lx::delivery_maybe", 1);
    let mut f = frame(0, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(has(&calls(), "proc::deliver_on_syscall_return 0"));
    // A server's reply never delivers signals; a retired caller leaves
    stubs::answer("lx::fast", 2);
    task::RETIRED.set(1);
    let mut f = frame(52, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    let k = calls();
    assert!(has(&k, "lx::fast_entry reply 52") && has(&k, "task::leave_retired") && !has(&k, "deliver"), "{k:?}");
    smp::bkl_exit();
    // Retired before the call even started
    stubs::answer("lx::fast", 0);
    task::RETIRED.set(1);
    native(syscall::SYS_UPTIME, [0; 3]);
    assert!(has(&calls(), "task::leave_retired"));
}

#[test]
fn linux_calls_go_to_the_linux_layer() {
    let _g = serial();
    task::PERSONALITY.set(TaskPersonality::Linux);
    stubs::answer("linux::dispatch", 77);
    let mut f = frame(39, [1, 2, 3]);
    let before = syscall::SYSCALL_ENTRIES.load(SeqCst);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax, 77);
    assert_eq!(syscall::SYSCALL_ENTRIES.load(SeqCst), before + 1);
    let k = calls();
    assert_eq!(&k[..4], &["sched::wait_out_handoff", "task::close_retired", "linux::admin::flush", "sched::reap_dead_tasks"], "retired tasks reaped first");
    assert!(has(&k, "linux::dispatch 39 0x1 0x2") && has(&k, "task::tick_on_return") && has(&k, "proc::deliver_on_syscall_return 39 rax=77"), "{k:?}");
    assert_eq!(task::CURRENT_SYSCALL.load(SeqCst), u64::MAX, "not in a call any more");
    // An identity change refreshes the fast paths' caches
    let mut f = frame(105, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(has(&calls(), "linux::ident_changed"));
    // Retired during the call
    task::RETIRED.set(2); // (the entry check consumes one)
    let mut f = frame(1, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    smp::bkl_exit();
    assert!(has(&calls(), "task::leave_retired"));
    // In a driver process, retired tasks are not reaped
    task::SERVICE.set(Some(3));
    let mut f = frame(1, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(!has(&calls(), "close_retired"));
    task::SERVICE.set(None);
}

#[test]
fn ptrace_stops_around_linux_calls() {
    let _g = serial();
    task::PERSONALITY.set(TaskPersonality::Linux);
    stubs::answer("ptrace::active", 1);
    stubs::answer("ptrace::traced", 1);
    stubs::answer("linux::dispatch", 5);
    let mut f = frame(0, [3, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    let k = calls();
    assert!(has(&k, "ptrace::syscall_entry 0") && has(&k, "linux::dispatch") && has(&k, "ptrace::syscall_exit 0 5"), "{k:?}");
    // The tracer cancelled the call with -1: not dispatched, the exit stop sees -1
    stubs::answer("ptrace::entry", -1);
    let mut f = frame(0, [3, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    let k = calls();
    assert!(!has(&k, "linux::dispatch") && has(&k, "ptrace::syscall_exit 0 -1"), "{k:?}");
    assert_eq!(f.rax as i64, -1);
    // ...or changed the number
    stubs::answer("ptrace::entry", 60);
    let mut f = frame(0, [3, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(has(&calls(), "ptrace::syscall_exit 60 5"));
}

#[test]
fn syscall_tracing() {
    let _g = serial();
    task::PERSONALITY.set(TaskPersonality::Linux);
    hydra_hosttests_t32::compat::linux::TRACE_SYSCALLS.store(true, SeqCst);
    stubs::answer("linux::dispatch", -2);
    let path = b"/etc/passwd\0".to_vec();
    let mut f = frame(2, [path.as_ptr() as u64, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    let log = stubs::take_log();
    assert!(has(&log, "> 2(") && has(&log, "path \"/etc/passwd\"") && has(&log, "= -2"), "{log:#?}");
    // openat: the path is the second argument
    let mut f = frame(257, [0, path.as_ptr() as u64, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(has(&stubs::take_log(), "path \"/etc/passwd\""));
    // ppoll: the timeout and the descriptors
    let ts: [i64; 2] = [0, 500];
    let fds: [[i16; 4]; 2] = [[3, 0, 1, 0], [4, 0, 4, 0]];
    let mut f = frame(271, [fds.as_ptr() as u64, 2, ts.as_ptr() as u64]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    let log = stubs::take_log();
    assert!(has(&log, "timeout 0s 500ns") && has(&log, "pollfd fd3 events 0x1") && has(&log, "pollfd fd4 events 0x4"), "{log:#?}");
    // sendmsg: the control length after the call
    let hdr: [u64; 7] = [0, 0, 0, 0, 0, 24, 0x40];
    let mut f = frame(46, [3, hdr.as_ptr() as u64, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(has(&stubs::take_log(), "controllen 24 flags 0x40"));
    // clock_gettime, mprotect and sigprocmask are never traced; other processes neither
    let mut f = frame(228, [0; 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(stubs::take_log().is_empty());
    stubs::answer("linux::trace_matches_current", 0);
    let mut f = frame(2, [path.as_ptr() as u64, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert!(stubs::take_log().is_empty());
    hydra_hosttests_t32::compat::linux::TRACE_SYSCALLS.store(false, SeqCst);
}

#[test]
fn native_files_and_pipes() {
    let _g = serial();
    // write: to a descriptor, the short form (fd 1), errors
    let out = Arc::new(spin::Mutex::new(Vec::new()));
    task::FDS.with_borrow_mut(|f| {
        f.alloc_fd(FileDescriptor::Buf { data: Arc::new(spin::Mutex::new(Vec::new())), fail: false }).unwrap();
        f.alloc_fd(FileDescriptor::Buf { data: out.clone(), fail: false }).unwrap();
        f.alloc_fd(FileDescriptor::Buf { data: Arc::new(spin::Mutex::new(b"input".to_vec())), fail: false }).unwrap();
        f.alloc_fd(FileDescriptor::Buf { data: Arc::new(spin::Mutex::new(Vec::new())), fail: true }).unwrap();
    });
    let msg = b"hello";
    assert_eq!(native(syscall::SYS_WRITE, [1, msg.as_ptr() as u64, 5]), 5);
    assert_eq!(native(syscall::SYS_WRITE, [msg.as_ptr() as u64, 3, 0]), 3, "pointer first: fd 1");
    assert_eq!(&*out.lock(), b"hellohel");
    assert_eq!(native(syscall::SYS_WRITE, [1, 0, 5]), -14);
    assert_eq!(native(syscall::SYS_WRITE, [1, msg.as_ptr() as u64, 0]), 0);
    assert_eq!(native(syscall::SYS_WRITE, [9, msg.as_ptr() as u64, 5]), -9);
    assert_eq!(native(syscall::SYS_WRITE, [3, msg.as_ptr() as u64, 5]), -5);
    // read
    let mut buf = [0u8; 8];
    assert_eq!(native(syscall::SYS_READ, [2, buf.as_mut_ptr() as u64, 8]), 5);
    assert_eq!(&buf[..5], b"input");
    assert_eq!(native(syscall::SYS_READ, [2, 0, 8]), -14);
    assert_eq!(native(syscall::SYS_READ, [2, buf.as_mut_ptr() as u64, 0]), 0);
    assert_eq!(native(syscall::SYS_READ, [9, buf.as_mut_ptr() as u64, 1]), -9);
    assert_eq!(native(syscall::SYS_READ, [3, buf.as_mut_ptr() as u64, 1]), -5);
    // open: by flags; writing touches the file first
    let p = b"/tmp/x";
    let fd = native(syscall::SYS_OPEN, [p.as_ptr() as u64, 6, 3]);
    assert_eq!(fd, 4);
    assert!(has(&calls(), "zfs::touch /tmp/x"));
    task::FDS.with_borrow(|f| match f.slots[4].as_ref().unwrap() {
        FileDescriptor::File { path, readable, writable, append, .. } => assert_eq!((path.as_str(), *readable, *writable, *append), ("/tmp/x", false, true, true)),
        _ => panic!(),
    });
    assert_eq!(native(syscall::SYS_OPEN, [p.as_ptr() as u64, 6, 0]), 5);
    assert!(!has(&calls(), "zfs::touch"), "read-only: no touch");
    assert_eq!(native(syscall::SYS_OPEN, [0, 6, 0]), -14);
    assert_eq!(native(syscall::SYS_OPEN, [p.as_ptr() as u64, 0, 0]), -14);
    let bad = [0xFFu8, 0xFE];
    assert_eq!(native(syscall::SYS_OPEN, [bad.as_ptr() as u64, 2, 0]), -22);
    task::FDS.with_borrow_mut(|f| f.limit = Some(6));
    assert_eq!(native(syscall::SYS_OPEN, [p.as_ptr() as u64, 6, 2]), -24);
    // close, dup2
    assert_eq!(native(syscall::SYS_CLOSE, [5, 0, 0]), 0);
    assert_eq!(native(syscall::SYS_CLOSE, [5, 0, 0]), -9);
    task::FDS.with_borrow_mut(|f| f.limit = None);
    assert_eq!(native(syscall::SYS_DUP2, [1, 7, 0]), 7);
    assert_eq!(native(syscall::SYS_DUP2, [99, 7, 0]), -9);
    // pipe: two descriptors stored at the pointer; out of slots after the first
    let mut pair = [0u64; 2];
    assert_eq!(native(syscall::SYS_PIPE, [pair.as_mut_ptr() as u64, 0, 0]), 0);
    assert_eq!(pair, [5, 6]);
    assert_eq!(native(syscall::SYS_PIPE, [0, 0, 0]), -14);
    task::FDS.with_borrow_mut(|f| f.limit = Some(9));
    assert_eq!(native(syscall::SYS_PIPE, [pair.as_mut_ptr() as u64, 0, 0]), -24, "only one slot left");
    assert!(task::FDS.with_borrow(|f| f.slots.get(8).map_or(true, |s| s.is_none())), "the read end closed again");
    task::FDS.with_borrow_mut(|f| f.limit = Some(8));
    assert_eq!(native(syscall::SYS_PIPE, [pair.as_mut_ptr() as u64, 0, 0]), -24);
    let s = *syscall::SYSCALL_STATS.lock();
    assert!(s.write_calls >= 6 && s.read_calls >= 5 && s.open_calls >= 6 && s.pipe_calls >= 4 && s.dup2_calls >= 2 && s.close_calls >= 2);
}

#[test]
fn native_process_and_time_calls() {
    let _g = serial();
    assert_eq!(native(syscall::SYS_YIELD, [0; 3]), 0);
    assert_eq!(native(syscall::SYS_SLEEP, [25, 0, 0]), 0);
    let k = calls();
    assert!(has(&k, "task::yield_now") && has(&k, "task::sleep_ms 25"), "{k:?}");
    assert_eq!(native(syscall::SYS_GETPID, [0; 3]), 42);
    assert!(native(syscall::SYS_UPTIME, [0; 3]) >= 0);
    let mut t = [0u64; 2];
    assert_eq!(native(syscall::SYS_CLOCK, [t.as_mut_ptr() as u64, 0, 0]), 0);
    assert_eq!(native(syscall::SYS_CLOCK, [0, 0, 0]), -14);
    // exit and exit_group never return (the stubs unwind)
    let r = std::panic::catch_unwind(|| native(syscall::SYS_EXIT, [0, 0, 0]));
    assert!(r.is_err());
    assert!(has(&calls(), "task::exit"));
    smp::bkl_exit();
    let r = std::panic::catch_unwind(|| native(syscall::SYS_EXIT, [0, 1, 0]));
    assert!(r.is_err());
    assert!(has(&calls(), "task::exit_group"));
    smp::bkl_exit();
    hw::set_if(true);
    // Unknown numbers
    let before = syscall::SYSCALL_STATS.lock().unknown_calls;
    assert_eq!(native(999, [0; 3]), -38);
    assert_eq!(syscall::SYSCALL_STATS.lock().unknown_calls, before + 1);
    // A thread of a native program
    assert_eq!(native(syscall::SYS_THREAD_CREATE, [0x40_2000, 0x7000_0000, 5]), 77);
    assert!(has(&calls(), "sched::spawn_native_thread 0x402000 0x70000000 5"));
    stubs::answer("sched::spawn_fails", 1);
    assert_eq!(native(syscall::SYS_THREAD_CREATE, [0; 3]), -12);
    // Anonymous memory needs an address space of its own
    assert_eq!(native(syscall::SYS_MAP_ANON, [4096, 0, 0]), -14);
}

#[test]
fn native_ipc_endpoints() {
    let _g = serial();
    use hydra_hosttests_t32::ipc::Message;
    let m = Message::with_args(3, [1, 2, 3, 4]);
    assert_eq!(native(syscall::SYS_IPC_SEND, [1, &m as *const Message as u64, 0]), 0);
    assert_eq!(native(syscall::SYS_IPC_SEND, [1, &m as *const Message as u64, 1]), 0);
    assert_eq!(native(syscall::SYS_IPC_SEND, [1, &m as *const Message as u64, 0]), -11, "queue full");
    assert_eq!(native(syscall::SYS_IPC_SEND, [5, &m as *const Message as u64, 0]), -22);
    assert_eq!(native(syscall::SYS_IPC_SEND, [1, 0, 0]), -14);
    let mut got = Message::with_args(0, [0; 4]);
    assert_eq!(native(syscall::SYS_IPC_RECV, [1, &mut got as *mut Message as u64, 0]), 0);
    assert_eq!(got.label, 3);
    assert_eq!(native(syscall::SYS_IPC_RECV, [1, &mut got as *mut Message as u64, 1]), 0);
    assert_eq!(native(syscall::SYS_IPC_RECV, [1, &mut got as *mut Message as u64, 0]), -11);
    assert_eq!(native(syscall::SYS_IPC_RECV, [1, &mut got as *mut Message as u64, 1]), 0, "blocking: waits (stub: a message 9)");
    assert_eq!(got.label, 9);
    assert_eq!(native(syscall::SYS_IPC_RECV, [7, &mut got as *mut Message as u64, 0]), -22);
    assert_eq!(native(syscall::SYS_IPC_RECV, [1, 0, 0]), -14);
}

#[test]
fn native_driver_services() {
    let _g = serial();
    // iopl: only for drivers; sets IOPL 3 or 0 in the saved flags
    task::PERSONALITY.set(TaskPersonality::Hydra);
    let mut f = frame(syscall::SYS_IOPL, [3, 0, 0]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax, 0);
    assert_eq!(f.rflags & 0x3000, 0x3000);
    let mut f = frame(syscall::SYS_IOPL, [0, 0, 0]);
    f.rflags = 0x3202;
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rflags & 0x3000, 0);
    stubs::answer("svc::iopl", -1);
    assert_eq!(native(syscall::SYS_IOPL, [3, 0, 0]), -1);
    hw::set_if(true);
    // physmap, dma, irqs: the service layer's answer
    stubs::answer("svc::physmap", 0x5000_0000);
    assert_eq!(native(syscall::SYS_PHYSMAP, [0xFEB0_0000, 0x1000, 0]), 0x5000_0000);
    let mut phys = 0u64;
    stubs::answer("svc::dma_alloc", 0x6000_0000);
    assert_eq!(native(syscall::SYS_DMA_ALLOC, [8192, &mut phys as *mut u64 as u64, 0]), 0x6000_0000);
    assert_eq!(phys, 0x1234_5000);
    assert_eq!(native(syscall::SYS_DMA_ALLOC, [8192, 0, 0]), -14, "nowhere to store the address");
    stubs::answer("svc::dma_alloc", -12);
    assert_eq!(native(syscall::SYS_DMA_ALLOC, [8192, &mut phys as *mut u64 as u64, 0]), -12);
    assert_eq!(native(syscall::SYS_IRQ_REGISTER, [11, 0, 0]), 0);
    stubs::answer("svc::irq_wait", 3);
    assert_eq!(native(syscall::SYS_IRQ_WAIT, [11, 50, 0]), 3);
    stubs::answer("svc::irq_ack", 1);
    assert_eq!(native(syscall::SYS_IRQ_ACK, [11, 0, 0]), 1);
    stubs::answer("svc::attach", 0x7000_0000);
    assert_eq!(native(syscall::SYS_SVC_ATTACH, [4, 0, 0]), 0x7000_0000);
    stubs::answer("svc::register", 0x7100_0000);
    assert_eq!(native(syscall::SYS_SVC_REGISTER, [4, 0, 0]), 0x7100_0000);
    assert_eq!(native(syscall::SYS_SVC_SIGNAL, [4, 0x10, 0]), 0);
    let k = calls();
    for want in ["svc::physmap 0xfeb00000 4096", "svc::dma_alloc 8192", "svc::irq_register 11", "svc::irq_wait 11 50", "svc::irq_ack 11", "svc::attach 4", "svc::register 4", "svc::signal 4 0x10"] {
        assert!(has(&k, want), "{want}: {k:?}");
    }
    // recv: the request comes back as a wire message, its ID as the result
    let mut w = WireMessage::default();
    stubs::answer("svc::recv", 17);
    assert_eq!(native(syscall::SYS_SVC_RECV, [4, &mut w as *mut WireMessage as u64, 0]), 17);
    assert_eq!((w.label, w.args), (5, [1, 2, 3, 4]));
    assert_eq!(native(syscall::SYS_SVC_RECV, [4, 0, 0]), -14, "nowhere to store it");
    // ...with a reply first (RECV_REPLY, the request ID in r10)
    let mut f = frame(syscall::SYS_SVC_RECV, [4, &mut w as *mut WireMessage as u64, hydra_hosttests_t32::ipc::protocol::RECV_REPLY]);
    f.r10 = 16;
    w.label = 8;
    task::PERSONALITY.set(TaskPersonality::Hydra);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax, 17);
    assert!(has(&calls(), "svc::reply_recv 4 16 8"));
    assert_eq!(w.label, 6);
    stubs::answer("svc::recv", -4);
    assert_eq!(native(syscall::SYS_SVC_RECV, [4, &mut w as *mut WireMessage as u64, 0]), -4);
    // reply
    assert_eq!(native(syscall::SYS_SVC_REPLY, [4, &w as *const WireMessage as u64, 17]), 0);
    assert_eq!(native(syscall::SYS_SVC_REPLY, [4, 0, 17]), -14);
}

#[test]
fn native_driver_calls() {
    let _g = serial();
    use hydra_hosttests_t32::ipc::protocol::{ENDPOINT_LINUX_SERVER, ENDPOINT_NET_SERVER, SVC_CALL_HANDOFF};
    let mut w = WireMessage { label: 10, args: [1, 2, 3, 4] };
    // Only driver processes may call
    assert_eq!(native(syscall::SYS_SVC_CALL, [4, &mut w as *mut WireMessage as u64, 0]), -1);
    task::SERVICE.set(Some(9));
    assert_eq!(native(syscall::SYS_SVC_CALL, [4, &mut w as *mut WireMessage as u64, 0]), 0);
    assert_eq!(w.label, 11, "the reply in place");
    assert!(has(&calls(), "svc::call_mode 4 10 500 Queued"));
    // A hand-off: only linux-server calling net-server gets it
    assert_eq!(native(syscall::SYS_SVC_CALL, [ENDPOINT_NET_SERVER as u64, &mut w as *mut WireMessage as u64, SVC_CALL_HANDOFF | 30]), 0);
    assert!(has(&calls(), "500 Queued") == false && true);
    task::SERVICE.set(Some(ENDPOINT_LINUX_SERVER));
    assert_eq!(native(syscall::SYS_SVC_CALL, [ENDPOINT_NET_SERVER as u64, &mut w as *mut WireMessage as u64, SVC_CALL_HANDOFF | 30]), 0);
    assert!(has(&calls(), "30 Handoff"));
    stubs::answer("svc::call", -110);
    assert_eq!(native(syscall::SYS_SVC_CALL, [4, &mut w as *mut WireMessage as u64, 0]), -110);
    stubs::answer("svc::call", 0);
    // With grants: the ranges and flags from the caller's GrantCall
    #[repr(C)]
    struct GrantCall {
        msg: WireMessage,
        timeout: u64,
        n: u64,
        flags: u64,
        ranges: [[u64; 2]; 4],
    }
    let mut g = GrantCall { msg: WireMessage { label: 20, args: [0; 4] }, timeout: 0, n: 2, flags: 1, ranges: [[0x1000, 64], [0x2000, 16], [0, 0], [0, 0]] };
    assert_eq!(native(syscall::SYS_SVC_CALL_GRANT, [4, &mut g as *mut GrantCall as u64, 0]), 0);
    assert!(has(&calls(), "svc::call_with 4 20 500 Queued 2 [(4096, 64), (8192, 16)] true"));
    assert_eq!(g.msg.label, 21);
    g.timeout = 7;
    native(syscall::SYS_SVC_CALL_GRANT, [4, &mut g as *mut GrantCall as u64, 0]);
    assert!(has(&calls(), " 7 Queued"));
    assert_eq!(native(syscall::SYS_SVC_CALL_GRANT, [4, 0, 0]), -14);
    task::SERVICE.set(None);
    assert_eq!(native(syscall::SYS_SVC_CALL_GRANT, [4, &mut g as *mut GrantCall as u64, 0]), -1);
    // Grant segments: [address, length] pairs
    let mut segs = [0u64; 4];
    assert_eq!(native(syscall::SYS_SVC_GRANT, [4, 17, segs.as_mut_ptr() as u64]), 2);
    assert_eq!(segs, [0x1000, 0x200, 0x5000, 0x10]);
    stubs::answer("svc::grant", -2);
    assert_eq!(native(syscall::SYS_SVC_GRANT, [4, 17, segs.as_mut_ptr() as u64]), -2);
}

#[test]
fn native_linux_server_primitives() {
    let _g = serial();
    let cases: [(u64, i64, &str); 13] = [
        (syscall::SYS_LX_CTL, 11, "lx::ctl 1"),
        (syscall::SYS_LX_REPLY_RECV, 12, "lx::reply_recv 1 2"),
        (syscall::SYS_LX_COMPLETE, 13, "lx::complete 1 2"),
        (syscall::SYS_LX_READ, 14, "lx::client_mem Read 1 2 3 9"),
        (syscall::SYS_LX_WRITE, 14, "lx::client_mem Write 1 2 3 9"),
        (syscall::SYS_LX_READ_STR, 14, "lx::client_mem ReadStr 1 2 3 9"),
        (syscall::SYS_LX_PROC_INFO, 15, "lx::proc_info 1 2"),
        (syscall::SYS_LX_OBJ, 16, "lx::obj_ctl 1 2 3 9"),
        (syscall::SYS_LX_SIG, 17, "lx::sig_post 1 2 3 9 8"),
        (syscall::SYS_LX_TIMER, 19, "lx::sys_timer 1 2 3"),
        (syscall::SYS_LX_SIGTAKE, 18, "lx::sig_take 1 2 3 9"),
        (syscall::SYS_LX_MEM, 22, "lx::sys_mem 1 2 3 9 8"),
        (syscall::SYS_LX_SVC, 23, "lx::svc_ctl 1 2 3 9"),
    ];
    for (nr, r, call) in cases {
        task::PERSONALITY.set(TaskPersonality::Hydra);
        let mut f = frame(nr, [1, 2, 3]);
        f.r10 = 9;
        f.r8 = 8;
        syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
        assert_eq!(f.rax as i64, r, "{call}");
        assert!(has(&calls(), call), "{call}");
    }
    assert_eq!(native(hydra_hosttests_t32::admin::proto::SYS_ADMIN, [0xA0, 0, 0]), 24);
    assert!(has(&calls(), "admin::syscall 0xa0"));
    // Calls between services: the wait runs without the kernel lock, taken again after
    let mut f = frame(syscall::SYS_SVC_DCALL, [1, 2, 3]);
    syscall::syscall_dispatch(&mut f, core::ptr::null_mut());
    assert_eq!(f.rax, 20);
    assert!(has(&calls(), "lx::dcall 42 3 [1, 2, 3, 0, 0, 0] true"));
    assert_eq!(native(syscall::SYS_SVC_POST, [1, 2, 3]), 21);
}
