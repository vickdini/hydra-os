//! `src/admin/system.rs`: tasks, memory, the CPU, services, power, fault tests, the IOMMU.

mod common;
use common::*;
use k::admin::proto::*;
use k::admin::system;
use k::admin::Failure;
use k::task::supervisor::{ServiceSnapshot, ServiceState};
use k::task::*;

/// The errno and message of a failure.
fn fail(f: Failure) -> (i64, String) {
    match f {
        Failure::Errno(e) => (e, String::new()),
        Failure::Message(e, m) => (e, m.to_string()),
        Failure::Text(e, m) => (e, m),
    }
}

/// `unwrap` for results whose error is a `Failure` (it has no `Debug`).
trait Must<T> {
    fn must(self) -> T;
}
impl<T> Must<T> for Result<T, Failure> {
    fn must(self) -> T {
        match self {
            Ok(v) => v,
            Err(f) => panic!("failed: {:?}", fail(f)),
        }
    }
}
impl<T> Must<T> for Option<T> {
    fn must(self) -> T {
        self.expect("a value")
    }
}

fn snap(id: u64, state: TaskState, prio: TaskPriority, mode: PrivilegeMode, name: &'static str) -> TaskSnapshot {
    TaskSnapshot { id: TaskId(id), uid: id as u32 * 10, mode, state, priority: prio, ticks_run: id * 3, rsp: 0x1000 + id, name }
}

#[test]
fn the_task_list_has_a_record_per_task() {
    let _g = setup();
    fake::with(|s| s.scheduler_inactive = true);
    let mut out = Vec::new();
    assert_eq!(fail(system::task_list(&mut out).unwrap_err()), (EIO, "Multitasking scheduler is not yet active.".into()));
    fake::with(|s| {
        s.scheduler_inactive = false;
        s.snapshots = vec![
            snap(0, TaskState::Running, TaskPriority::Normal, PrivilegeMode::Kernel, "shell"),
            snap(1, TaskState::Ready, TaskPriority::Idle, PrivilegeMode::Kernel, "idle"),
            snap(2, TaskState::Blocked, TaskPriority::Low, PrivilegeMode::User, "net-server"),
            snap(3, TaskState::Sleeping { until: 9 }, TaskPriority::High, PrivilegeMode::User, "a-name-that-is-longer-than-thirty-two-bytes"),
            snap(4, TaskState::Dead, TaskPriority::Realtime, PrivilegeMode::User, "zombie"),
        ]
    });
    system::task_list(&mut out).must();
    let h: TaskListHeader = read_record(&out, 0).unwrap();
    assert_eq!((h.count, h.timeslice_ms, h.worker_counter), (5, 20, 0));
    let hs = core::mem::size_of::<TaskListHeader>();
    let rs = core::mem::size_of::<TaskRecord>();
    assert_eq!(out.len(), hs + 5 * rs);
    let rec = |i: usize| read_record::<TaskRecord>(&out, hs + i * rs).must();
    let want = [
        (MODE_KERNEL, STATE_RUNNING, 2),
        (MODE_KERNEL, STATE_READY, 0),
        (MODE_USER, STATE_BLOCKED, 1),
        (MODE_USER, STATE_SLEEPING, 3),
        (MODE_USER, STATE_DEAD, 4),
    ];
    for (i, (mode, state, prio)) in want.iter().enumerate() {
        let r = rec(i);
        assert_eq!((r.pid, r.uid, r.mode, r.state, r.priority, r.ticks, r.rsp), (i as u64, i as u32 * 10, *mode, *state, *prio, i as u64 * 3, 0x1000 + i as u64));
    }
    assert_eq!(name_str(&rec(2).name), "net-server");
    assert_eq!(name_str(&rec(3).name), "a-name-that-is-longer-than-thir");
}

#[test]
fn kill_protects_the_kernel_and_the_console() {
    let _g = setup();
    assert_eq!(fail(system::kill(0).unwrap_err()).1, "Cannot kill PID 0 (the kernel's main thread)");
    assert_eq!(fail(system::kill(1).unwrap_err()).1, "Cannot kill PID 1 (Kernel idle thread)");
    let console = authorize();
    assert_eq!(fail(system::kill(console.0).unwrap_err()), (EINVAL, "Cannot kill the console shell itself (use 'exit')".into()));
    fake::task(9, 1, None);
    system::kill(9).must();
    assert!(fake::logged("kill 9"));
    assert_eq!(fail(system::kill(9).unwrap_err()), (ENOENT, "not found or already dead".into()));
}

fn elf(len: usize, interp: bool) -> Vec<u8> {
    let mut v = vec![0x7f, b'E', b'L', b'F'];
    if interp {
        v.extend_from_slice(b"/lib64/ld-linux-x86-64.so.2");
    }
    v.resize(len, 0);
    v
}

#[test]
fn exec_starts_native_and_linux_programs() {
    let _g = setup();
    // No path, a missing file, a file that is not ELF, a truncated ELF
    assert_eq!(fail(system::exec(0, b"", 0, 0).unwrap_err()).0, EINVAL);
    assert_eq!(fail(system::exec(0, b"/bin/none", 0, 0).unwrap_err()), (ENOENT, "No such file or directory".into()));
    fake::file("/bin/script", b"#!/bin/sh\necho hi\n");
    assert_eq!(fail(system::exec(0, b"/bin/script", 0, 0).unwrap_err()), (EINVAL, "not an ELF program".into()));
    fake::file("/bin/tiny", b"\x7fELF");
    assert_eq!(fail(system::exec(0, b"/bin/tiny", 0, 0).unwrap_err()), (EINVAL, "truncated ELF header".into()));
    fake::file("/bin/short", b"\x7fE");
    assert_eq!(fail(system::exec(0, b"/bin/short", 0, 0).unwrap_err()).1, "not an ELF program");
    // A native program in the background
    fake::file("/bin/native", &elf(200, false));
    let r = system::exec(EXEC_BACKGROUND, b"/bin/native\0a\0b", 1000, 1001).must();
    assert_eq!((r.size, r.linux, r.finished), (200, 0, 0));
    assert!(fake::logged("spawn_native /bin/native /bin/native [\"/bin/native\", \"a\", \"b\"] 1000 1001"));
    // A Linux program (it has an interpreter), waited for
    fake::file("/bin/dyn", &elf(300, true));
    let r = system::exec(0, b"/bin/dyn", 0, 0).must();
    assert_eq!((r.linux, r.finished), (1, 1));
    assert!(fake::logged("spawn_linux_elf /bin/dyn 300 [\"/bin/dyn\"] 0 0"));
    // A static Linux program, by its name
    fake::file("/bin/thread_test", &elf(64, false));
    assert_eq!(system::exec(EXEC_BACKGROUND, b"/bin/thread_test", 0, 0).must().linux, 1);
    // A read failure and a failed start
    fake::with(|s| s.fs_fail = Some("checksum error"));
    assert_eq!(fail(system::exec(0, b"/bin/native", 0, 0).unwrap_err()), (EIO, "checksum error".into()));
    fake::with(|s| {
        s.fs_fail = None;
        s.spawn_fail = Some("no memory");
    });
    assert_eq!(fail(system::exec(0, b"/bin/native", 0, 0).unwrap_err()), (EIO, "no memory".into()));
}

#[test]
fn a_waited_program_is_polled_until_it_ends() {
    let _g = setup();
    fake::file("/bin/native", &elf(100, false));
    // The stub task lives for 5 checks: the kernel sleeps 20 ms between them
    fake::with(|s| s.next_tid = 300);
    fake::task(300, 5, Some(0));
    let t0 = fake::with(|s| s.clock_ns);
    let r = system::exec(0, b"/bin/native", 0, 0).must();
    assert_eq!((r.pid, r.finished), (300, 1));
    assert_eq!(fake::with(|s| s.clock_ns) - t0, 5 * 20_000_000);
}

#[test]
fn statistics_records() {
    use k::arch::syscall::*;
    let _g = setup();
    fake::with(|s| {
        s.msrs.insert(IA32_EFER, 0xd01);
        s.msrs.insert(IA32_STAR, 0x23_0008_0000_0000);
        s.msrs.insert(IA32_LSTAR, 0xffff_8000_0010_0000);
        s.msrs.insert(IA32_FMASK, 0x4_7700);
    });
    {
        let mut st = SYSCALL_STATS.lock();
        st.yield_calls = 1;
        st.sleep_calls = 2;
        st.write_calls = 3;
        st.exit_calls = 4;
        st.getpid_calls = 5;
        st.uptime_calls = 6;
        st.ipc_calls = 7;
        st.total_calls = 28;
    }
    let s = system::syscall_stats();
    assert_eq!((s.efer, s.star, s.lstar, s.fmask), (0xd01, 0x23_0008_0000_0000, 0xffff_8000_0010_0000, 0x4_7700));
    assert_eq!(s.counts, [1, 2, 3, 4, 5, 6, 7, 28]);
    // Endpoints 1, 3, 5 exist in the stub
    let mut out = Vec::new();
    system::endpoints(&mut out);
    let n = core::mem::size_of::<EndpointRecord>();
    assert_eq!(out.len(), 3 * n);
    let e: EndpointRecord = read_record(&out, n).must();
    assert_eq!((e.id, e.pending, e.receivers, e.senders), (3, 31, 32, 33));
    // Requests in flight
    use k::ipc::service::CallMode;
    k::ipc::service::GRANTS_MADE.store(17, core::sync::atomic::Ordering::Relaxed);
    fake::with(|s| s.requests = vec![(5, 2, 100, "waiting", CallMode::Handoff), (6, 9, 101, "replied", CallMode::Queued)]);
    let mut out = Vec::new();
    system::requests(&mut out);
    let h: RequestHeader = read_record(&out, 0).unwrap();
    assert_eq!((h.count, h.grants_made), (2, 17));
    let r: RequestRecord = read_record(&out, 16 + core::mem::size_of::<RequestRecord>()).must();
    assert_eq!((r.id, r.endpoint, r.caller), (6, 9, 101));
    assert_eq!((name_str(&r.state), name_str(&r.mode)), ("replied", "Queued"));
}

#[test]
fn memory_cpu_and_clock() {
    let _g = setup();
    let m = system::mem_info();
    assert_eq!((m.total, m.allocated, m.free, m.page_size), (512 << 20, 64 << 20, 448 << 20, 4096));
    assert_eq!((m.heap_initialized, m.heap_start, m.heap_total, m.heap_used, m.heap_free), (1, 0xFFFF_9000_0000_0000, 8 << 20, 1 << 20, 7 << 20));
    let c = system::cpu_state();
    assert_eq!((c.cr0 & 0x8000_0001, c.cr2, c.cr3, c.cr4), (0x8000_0001, 0xdead_b000, 0x1234_5000, 0x20));
    // The clock does not answer: only the ticks
    fake::advance(1_230_000_000);
    let r = system::rtc_time();
    assert_eq!((r.valid, r.year, r.ticks), (0, 0, 123));
    fake::with(|s| s.rtc = Some((2026, 11, 20, 13, 45, 7)));
    let r = system::rtc_time();
    assert_eq!((r.valid, r.year, r.month, r.day, r.hour, r.minute, r.second), (1, 2026, 11, 20, 13, 45, 7));
}

#[test]
fn translate_reports_the_page_walk() {
    use x86_64::structures::paging::PageTableFlags as F;
    let _g = setup();
    // 0x7fff_1234_5678: L4 255, L3 508, L2 145, L1 325, offset 0x678
    fake::with(|s| s.translate = Some((0x9000, 0x9000, F::PRESENT | F::WRITABLE | F::USER_ACCESSIBLE | F::NO_EXECUTE)));
    system::translate(0x7fff_1234_5678).must();
    let out = fake::take_out();
    assert!(out.contains("Page Table Walk for 0x7fff12345678"));
    assert!(out.contains("PML4 Index (L4):    255"));
    assert!(out.contains("PDPT Index (L3):    508"));
    assert!(out.contains("PD Index   (L2):    145"));
    assert!(out.contains("PT Index   (L1):    325"));
    assert!(out.contains("Page Offset:        0x678"));
    assert!(out.contains("Status:             MAPPED"));
    assert!(out.contains("Physical Target:    0x9678"));
    assert!(out.contains("Base Frame:         0x9000"));
    assert!(out.contains("[PRESENT] [WRITABLE] [USER/RING-3] [NO-EXECUTE]"));
    // The other flag texts
    fake::with(|s| s.translate = Some((0x9000, 0x9000, F::empty())));
    system::translate(0x1000).must();
    assert!(fake::take_out().contains("Protection Flags:   [READ-ONLY] [SUPERVISOR/RING-0] [EXECUTABLE]"));
    // Not mapped
    fake::with(|s| s.translate = None);
    assert_eq!(fail(system::translate(0x1000).unwrap_err()).0, ENOENT);
    assert!(fake::take_out().contains("NOT MAPPED"));
    assert_eq!(fail(system::translate(0x0000_8000_0000_0000).unwrap_err()), (EINVAL, "not a canonical address".into()));
}

#[test]
fn services_and_interrupt_lines() {
    let _g = setup();
    let svc = |pid, state, name| ServiceSnapshot { task_id: pid, endpoint_id: 4, state, restart_count: 2, unanswered_pings: 1, name };
    fake::with(|s| {
        s.services = vec![
            svc(Some(12), ServiceState::Running, "net-server"),
            svc(None, ServiceState::Restarting, "ata"),
            svc(None, ServiceState::Faulted, "usb"),
            svc(None, ServiceState::Stopped, "audio"),
        ];
        s.irqs = vec![(11, 12, 100, 90, 2, true), (14, 13, 5, 5, 0, false)];
    });
    let mut out = Vec::new();
    system::services(&mut out);
    let n = core::mem::size_of::<ServiceRecord>();
    assert_eq!(out.len(), 4 * n);
    let r: ServiceRecord = read_record(&out, 0).unwrap();
    assert_eq!((r.pid, r.endpoint, r.state, r.restarts, r.unanswered_pings), (12, 4, SVC_RUNNING, 2, 1));
    assert_eq!(name_str(&r.name), "net-server");
    let states: Vec<u8> = (0..4).map(|i| read_record::<ServiceRecord>(&out, i * n).must().state).collect();
    assert_eq!(states, vec![SVC_RUNNING, SVC_RESTARTING, SVC_FAULTED, SVC_STOPPED]);
    assert_eq!(read_record::<ServiceRecord>(&out, n).must().pid, u64::MAX);
    let mut out = Vec::new();
    system::irqs(&mut out);
    let i: IrqRecord = read_record(&out, 0).unwrap();
    assert_eq!((i.irq, i.owner, i.count, i.notified, i.pending, i.masked), (11, 12, 100, 90, 2, 1));
    let i: IrqRecord = read_record(&out, core::mem::size_of::<IrqRecord>()).must();
    assert_eq!((i.irq, i.masked), (14, 0));
}

#[test]
fn service_control() {
    let _g = setup();
    assert_eq!(system::service_ctl(SVCCTL_RESTART, "ata").ok(), Some(41));
    assert_eq!(system::service_ctl(SVCCTL_START, "audio").ok(), Some(43));
    // A kill runs a supervisor sweep at once (the automatic restart)
    fake::take_log();
    assert_eq!(system::service_ctl(SVCCTL_KILL, "usb").ok(), Some(42));
    assert_eq!(fake::take_log(), vec!["kill_service usb".to_string(), "supervisor_tick".to_string()]);
    assert_eq!(system::service_ctl(SVCCTL_TICK, "").ok(), Some(0));
    assert!(fake::logged("supervisor_tick"));
    assert_eq!(fail(system::service_ctl(77, "x").unwrap_err()).0, EINVAL);
    fake::with(|s| s.service_fail = Some("no such service"));
    for code in [SVCCTL_RESTART, SVCCTL_KILL, SVCCTL_START] {
        assert_eq!(fail(system::service_ctl(code, "x").unwrap_err()), (EIO, "no such service".into()));
    }
}

#[test]
fn power() {
    let _g = setup();
    expect_panic("power_off", || {
        let _ = system::power(POWER_OFF);
    });
    expect_panic("reboot", || {
        let _ = system::power(POWER_REBOOT);
    });
    // Halt: interrupts off, then hlt for good
    expect_panic("hlt", || {
        let _ = system::power(POWER_HALT);
    });
    assert!(!x86_64::instructions::interrupts::are_enabled());
    x86_64::instructions::interrupts::enable();
    assert_eq!(fail(system::power(3).unwrap_err()).0, EINVAL);
}

#[test]
fn fault_tests() {
    let _g = setup();
    expect_panic("Manual kernel panic triggered by user from shell.", || {
        let _ = system::fault_test(FAULT_PANIC, 0);
    });
    // panic N: a kernel task that waits N seconds, then panics
    system::fault_test(FAULT_PANIC, 3).must();
    let (name, f) = fake::with(|s| s.kernel_fns.pop()).must();
    assert_eq!(name, "panictest");
    let t0 = fake::with(|s| s.clock_ns);
    expect_panic("Test kernel panic (panic N from the shell)", f);
    assert_eq!(fake::with(|s| s.clock_ns) - t0, 3_000_000_000);
    // A breakpoint resumes
    system::fault_test(FAULT_TRAP, 0).must();
    assert_eq!(fail(system::fault_test(9, 0).unwrap_err()).0, EINVAL);
}

#[test]
fn iommu_status_and_faults() {
    use k::arch::iommu::{Fault, FaultRecord};
    let _g = setup();
    system::iommu(0).must();
    assert_eq!(fake::take_out(), "IOMMU: 1 unit\ntranslation on\n");
    fake::with(|s| {
        s.iommu_faults = vec![FaultRecord { tick: 50, fault: Fault { source: 0x0018, read: true, address: 0x1000, reason: 6 } }];
        s.iommu_new_faults = vec![FaultRecord { tick: 60, fault: Fault { source: 0x0109, read: false, address: 0x2000, reason: 1 } }];
    });
    system::iommu(1).must();
    let out = fake::take_out();
    assert!(out.starts_with("2 recent blocked DMA access(es):\n"), "{}", out);
    assert!(out.contains("  tick 50: 00:03.0 read 0x1000: not present\n"));
    assert!(out.contains("  tick 60: 01:01.1 write 0x2000: other\n"));
    assert_eq!(fail(system::iommu(3).unwrap_err()).0, EINVAL);
}

/// The DMA test with the network driver answering, and the IOMMU logging a fault for the
/// adapter at the page it was asked to read when `blocked`.
fn dma_test(on: bool, blocked: bool, stays_online: bool) -> String {
    use k::arch::iommu::{Fault, FaultRecord};
    use k::ipc::protocol::{ENDPOINT_NET_DEV, MSG_NET_DMA_TEST, MSG_NET_REPLY};
    fake::with(|s| {
        s.iommu_test = true;
        s.iommu_on = on;
        s.iommu_dev = Some(0x0018);
        s.online.insert(ENDPOINT_NET_DEV);
        s.handler = Some(Box::new(move |ep, m, _| {
            assert_eq!((ep, m.label), (ENDPOINT_NET_DEV, MSG_NET_DMA_TEST));
            let target = m.args[0];
            fake::with(|s| {
                if blocked {
                    s.iommu_new_faults.push(FaultRecord { tick: 1, fault: Fault { source: 0x0018, read: true, address: target, reason: 6 } });
                }
                if !stays_online {
                    s.online.clear();
                }
            });
            Ok(k::ipc::Message::with_args(MSG_NET_REPLY, [0; 4]))
        }));
    });
    system::iommu(2).must();
    fake::take_out()
}

#[test]
fn the_rogue_dma_test() {
    let _g = setup();
    // Not enabled, driver missing, no memory
    system::iommu(2).must();
    assert!(fake::take_out().contains("IOMMU-DMATEST: not enabled"));
    fake::with(|s| s.iommu_test = true);
    system::iommu(2).must();
    assert!(fake::take_out().contains("IOMMU-DMATEST: FAIL (the network driver is not running)"));
    fake::with(|s| {
        s.online.insert(k::ipc::protocol::ENDPOINT_NET_DEV);
        s.no_frames = true;
    });
    system::iommu(2).must();
    assert!(fake::take_out().contains("IOMMU-DMATEST: FAIL (no memory)"));
    fake::with(|s| s.no_frames = false);
    // Blocked and logged, driver alive: PASS
    let out = dma_test(true, true, true);
    assert!(out.contains("(IOMMU on)"));
    assert!(out.contains("driver answered: true; fault logged for the adapter at that page: true; driver still online: true"));
    assert!(out.contains("IOMMU-DMATEST: PASS"), "{}", out);
    // The IOMMU off
    assert!(dma_test(false, false, true).contains("IOMMU-DMATEST: FAIL (the IOMMU is off: nothing stopped the read)"));
    // On, but nothing logged, or the driver died
    assert!(dma_test(true, false, true).ends_with("IOMMU-DMATEST: FAIL\n"));
    assert!(dma_test(true, true, false).ends_with("IOMMU-DMATEST: FAIL\n"));
}
