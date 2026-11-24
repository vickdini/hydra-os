//! # Admin operations: tasks, memory, the CPU, services, power
//!
//! The parts of the admin interface that stay in the kernel for good (the scheduler, the
//! frame allocator, the supervisor, power). Most answer records; the shell formats them.

use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use uefi::proto::console::text::Color;

use super::proto::*;
use super::{Failure, Failure::*};
use crate::console::set_color;

/// `ADMIN_TASK_LIST`.
pub fn task_list(out: &mut Vec<u8>) -> Result<(), Failure> {
    use crate::task::{PrivilegeMode, TaskPriority, TaskState};
    if !crate::task::is_active() {
        return Err(Message(EIO, "Multitasking scheduler is not yet active."));
    }
    let snaps = crate::task::get_task_snapshots();
    let header = TaskListHeader {
        count: snaps.len() as u32,
        timeslice_ms: crate::task::scheduler::DEFAULT_TIMESLICE_TICKS * 10,
        worker_counter: 0,
    };
    out.extend_from_slice(as_bytes(&header));
    for s in &snaps {
        let rec = TaskRecord {
            pid: s.id.0,
            uid: s.uid,
            mode: match s.mode {
                PrivilegeMode::Kernel => MODE_KERNEL,
                PrivilegeMode::User => MODE_USER,
            },
            state: match s.state {
                TaskState::Ready => STATE_READY,
                TaskState::Running => STATE_RUNNING,
                TaskState::Blocked => STATE_BLOCKED,
                TaskState::Sleeping { .. } => STATE_SLEEPING,
                TaskState::Dead => STATE_DEAD,
            },
            priority: match s.priority {
                TaskPriority::Idle => 0,
                TaskPriority::Low => 1,
                TaskPriority::Normal => 2,
                TaskPriority::High => 3,
                TaskPriority::Realtime => 4,
            },
            _pad: 0,
            ticks: s.ticks_run,
            rsp: s.rsp,
            name: name_field(s.name),
        };
        out.extend_from_slice(as_bytes(&rec));
    }
    Ok(())
}

/// `ADMIN_TASK_KILL`.
pub fn kill(pid: u64) -> Result<(), Failure> {
    match pid {
        0 => return Err(Message(EINVAL, "Cannot kill PID 0 (the kernel's main thread)")),
        1 => return Err(Message(EINVAL, "Cannot kill PID 1 (Kernel idle thread)")),
        _ => {}
    }
    if super::console_task().is_some_and(|c| c.0 == pid) {
        return Err(Message(EINVAL, "Cannot kill the console shell itself (use 'exit')"));
    }
    if crate::task::kill(crate::task::TaskId(pid)) {
        Ok(())
    } else {
        Err(Message(ENOENT, "not found or already dead"))
    }
}

/// `ADMIN_TASK_EXEC`: an ELF program of the pool, native or Linux (a program with an
/// interpreter, or one whose name says so, as the kernel shell decided).
pub fn exec(flags: u64, input: &[u8], uid: u32, gid: u32) -> Result<ExecResult, Failure> {
    let w = super::linux::words(input);
    let path = *w.first().filter(|p| !p.is_empty()).ok_or(Errno(EINVAL))?;
    let st = crate::fs::ZfsClient::file_stat(path).map_err(|e| Message(ENOENT, e))?;
    let mut data = alloc::vec![0u8; st.size as usize];
    let n = crate::fs::ZfsClient::read_file_by_path(path, &mut data).map_err(|e| Message(EIO, e))?;
    data.truncate(n);
    if n < 4 || data[..4] != crate::task::elf::ELF_MAGIC {
        return Err(Message(EINVAL, "not an ELF program"));
    }
    let elf = crate::task::elf::ElfBinary::parse(&data).map_err(|e| Message(EINVAL, e.as_str()))?;
    let linux = elf.interp_path().is_some()
        || ["linux", "dynclient", "thread", "sock", "epoll", "shm", "role"].iter().any(|k| path.contains(k));
    let name: &'static str = alloc::boxed::Box::leak(alloc::string::String::from(path).into_boxed_str());
    let pid = if linux {
        let mut argv: Vec<&str> = alloc::vec![name];
        argv.extend_from_slice(&w[1..]);
        crate::task::spawn_linux_elf(name, &data, &argv, crate::task::TaskPriority::Normal, uid, gid)
    } else {
        // In an address space of its own (the old loader used the caller's)
        let mut argv: Vec<&str> = alloc::vec![name];
        argv.extend_from_slice(&w[1..]);
        super::spawn_native(name, &data, &argv, uid, gid, false)
    }
    .map_err(|e| Message(EIO, e))?;
    let mut res = ExecResult { pid: pid.0, size: n as u64, linux: linux as u32, finished: 0 };
    if flags & EXEC_BACKGROUND == 0 {
        while crate::task::is_task_alive(pid) {
            crate::task::sleep_ms(20);
        }
        res.finished = 1;
    }
    Ok(res)
}

/// `ADMIN_SYSCALL_STATS`.
pub fn syscall_stats() -> SyscallStats {
    use crate::arch::syscall as sc;
    let (efer, star, lstar, fmask) = unsafe { (sc::rdmsr(sc::IA32_EFER), sc::rdmsr(sc::IA32_STAR), sc::rdmsr(sc::IA32_LSTAR), sc::rdmsr(sc::IA32_FMASK)) };
    let s = sc::SYSCALL_STATS.lock();
    SyscallStats {
        efer,
        star,
        lstar,
        fmask,
        counts: [s.yield_calls, s.sleep_calls, s.write_calls, s.exit_calls, s.getpid_calls, s.uptime_calls, s.ipc_calls, s.total_calls],
    }
}

/// `ADMIN_ENDPOINT_LIST`.
pub fn endpoints(out: &mut Vec<u8>) {
    for i in 0..8 {
        if let Some(ep) = crate::ipc::endpoint::get_system_endpoint(i) {
            let rec = EndpointRecord {
                id: i as u64,
                pending: ep.pending_count() as u64,
                receivers: ep.waiting_receivers() as u64,
                senders: ep.waiting_senders() as u64,
            };
            out.extend_from_slice(as_bytes(&rec));
        }
    }
}

/// `ADMIN_REQUEST_LIST`.
pub fn requests(out: &mut Vec<u8>) {
    let reqs = crate::ipc::service::request_list();
    let header = RequestHeader { count: reqs.len() as u64, grants_made: crate::ipc::service::GRANTS_MADE.load(Ordering::Relaxed) };
    out.extend_from_slice(as_bytes(&header));
    for (id, ep, caller, state, mode) in reqs {
        let rec = RequestRecord {
            id,
            endpoint: ep as u64,
            caller,
            state: name_field(state),
            mode: name_field(&alloc::format!("{:?}", mode)),
        };
        out.extend_from_slice(as_bytes(&rec));
    }
}

/// `ADMIN_MEM_INFO`.
pub fn mem_info() -> MemInfo {
    let (total, allocated, free) = {
        let a = crate::memory::frame_allocator::FRAME_ALLOCATOR.lock();
        (a.total_usable_memory(), a.allocated_memory(), a.free_memory())
    };
    let h = crate::memory::heap::stats();
    MemInfo {
        total,
        allocated,
        free,
        page_size: crate::memory::frame_allocator::PAGE_SIZE,
        heap_initialized: h.is_initialized as u64,
        heap_start: h.start_address,
        heap_total: h.total_bytes as u64,
        heap_used: h.used_bytes as u64,
        heap_free: h.free_bytes as u64,
    }
}

/// `ADMIN_CPU_STATE`.
pub fn cpu_state() -> CpuState {
    let c = crate::arch::cpu::read_state();
    CpuState { cr0: c.cr0.bits(), cr2: c.cr2, cr3: c.cr3_frame.as_u64(), cr4: c.cr4.bits() }
}

/// `ADMIN_RTC_TIME`.
pub fn rtc_time() -> RtcTime {
    let mut r = RtcTime { ticks: crate::arch::pit::ticks(), ..Default::default() };
    if let Ok(t) = crate::memory::paging::with_kernel_tables(uefi::runtime::get_time) {
        r.valid = 1;
        r.year = t.year();
        r.month = t.month();
        r.day = t.day();
        r.hour = t.hour();
        r.minute = t.minute();
        r.second = t.second();
    }
    r
}

/// `ADMIN_TRANSLATE` (report): the page table walk of `addr` in the caller's address space.
pub fn translate(addr: u64) -> Result<(), Failure> {
    use x86_64::structures::paging::{Page, PageTableFlags};
    let virt = x86_64::VirtAddr::try_new(addr).map_err(|_| Message(EINVAL, "not a canonical address"))?;
    let space = crate::memory::paging::AddressSpace::active();
    let page = Page::containing_address(virt);
    let page_info = unsafe { space.translate_page(page) };
    let phys = unsafe { space.translate_addr(virt) };
    set_color(Color::LightCyan, Color::Black);
    crate::println!("\n4-Level PML4 Page Table Walk for {:#x}:", virt.as_u64());
    set_color(Color::White, Color::Black);
    crate::println!("  PML4 Index (L4):    {}", u16::from(virt.p4_index()));
    crate::println!("  PDPT Index (L3):    {}", u16::from(virt.p3_index()));
    crate::println!("  PD Index   (L2):    {}", u16::from(virt.p2_index()));
    crate::println!("  PT Index   (L1):    {}", u16::from(virt.p1_index()));
    crate::println!("  Page Offset:        {:#x}", virt.as_u64() & 0xFFF);
    match phys {
        Some(phys) => {
            set_color(Color::LightGreen, Color::Black);
            crate::println!("  Status:             MAPPED");
            crate::println!("  Physical Target:    {:#x}", phys.as_u64());
            if let Some((frame, flags)) = page_info {
                crate::println!("  Base Frame:         {:#x}", frame.start_address().as_u64());
                crate::println!(
                    "  Protection Flags:   {}{}{}{}",
                    if flags.contains(PageTableFlags::PRESENT) { "[PRESENT] " } else { "" },
                    if flags.contains(PageTableFlags::WRITABLE) { "[WRITABLE] " } else { "[READ-ONLY] " },
                    if flags.contains(PageTableFlags::USER_ACCESSIBLE) { "[USER/RING-3] " } else { "[SUPERVISOR/RING-0] " },
                    if flags.contains(PageTableFlags::NO_EXECUTE) { "[NO-EXECUTE] " } else { "[EXECUTABLE] " },
                );
            }
            crate::println!();
            Ok(())
        }
        None => {
            set_color(Color::Yellow, Color::Black);
            crate::println!("  Status:             NOT MAPPED (Page Fault on access)\n");
            Err(Errno(ENOENT))
        }
    }
}

/// `ADMIN_SERVICE_LIST`.
pub fn services(out: &mut Vec<u8>) {
    use crate::task::supervisor::ServiceState;
    for s in crate::task::supervisor::get_service_snapshots() {
        let rec = ServiceRecord {
            pid: s.task_id.unwrap_or(u64::MAX),
            endpoint: s.endpoint_id,
            state: match s.state {
                ServiceState::Running => SVC_RUNNING,
                ServiceState::Restarting => SVC_RESTARTING,
                ServiceState::Faulted => SVC_FAULTED,
                ServiceState::Stopped => SVC_STOPPED,
            },
            _pad: [0; 3],
            restarts: s.restart_count,
            unanswered_pings: s.unanswered_pings,
            name: name_field(s.name),
        };
        out.extend_from_slice(as_bytes(&rec));
    }
}

/// `ADMIN_IRQ_LIST`.
pub fn irqs(out: &mut Vec<u8>) {
    for (irq, owner, count, notified, pending, masked) in crate::ipc::service::irq_stats() {
        let rec = IrqRecord { irq: irq as u64, owner, count, notified, pending: pending as u64, masked: masked as u64 };
        out.extend_from_slice(as_bytes(&rec));
    }
}

// wave11 GR begin
/// Service kills asked for later (`service kill NAME after S`): name, when (ms since boot).
static DELAYED_KILLS: spin::Mutex<Vec<(alloc::string::String, u64)>> = spin::Mutex::new(Vec::new());
/// Whether the task doing them runs.
static KILLER: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The kernel task doing the delayed service kills; it ends when none is left.
fn delayed_killer() {
    loop {
        let now = crate::arch::pit::uptime_ms();
        let due: Vec<alloc::string::String> = {
            let mut l = DELAYED_KILLS.lock();
            let due = l.iter().filter(|(_, at)| *at <= now).map(|(n, _)| n.clone()).collect();
            l.retain(|(_, at)| *at > now);
            if l.is_empty() && Vec::<alloc::string::String>::is_empty(&due) {
                KILLER.store(false, core::sync::atomic::Ordering::Release);
                return;
            }
            due
        };
        for n in due {
            match crate::task::supervisor::kill_service_by_name(&n) {
                Ok(pid) => crate::kprintln!("[admin] delayed kill of service '{}' (process {})", n, pid.0),
                Err(e) => crate::kprintln!("[admin] delayed kill of service '{}' failed: {}", n, e),
            }
            crate::task::supervisor::supervisor_tick();
        }
        crate::task::sleep_ms(100);
    }
}
// wave11 GR end

/// `ADMIN_SERVICE_CTL`.
///
/// # Returns
/// The process id started (restart, start) or ended (kill); 0 for a sweep.
pub fn service_ctl(code: u64, name: &str, delay_s: u64) -> Result<u64, Failure> {
    use crate::task::supervisor as sv;
    match code {
        SVCCTL_RESTART => sv::restart_service_by_name(name).map(|t| t.0).map_err(|e| Message(EIO, e)),
        // wave11 GR: `service kill NAME after S`: the kill comes S seconds later, from a
        // kernel task, so the console can run a program meanwhile (kill tests of a call in
        // flight, e.g. a console read at a tty-server crash)
        SVCCTL_KILL if delay_s > 0 => {
            let at = crate::arch::pit::uptime_ms() + delay_s.min(3600) * 1000;
            DELAYED_KILLS.lock().push((alloc::string::String::from(name), at));
            if !KILLER.swap(true, core::sync::atomic::Ordering::AcqRel) {
                crate::task::spawn("svc-killer", delayed_killer, crate::task::TaskPriority::Normal);
            }
            Ok(0)
        }
        SVCCTL_KILL => {
            let pid = sv::kill_service_by_name(name).map_err(|e| Message(EIO, e))?;
            // A watchdog sweep at once, to show the automatic restart
            sv::supervisor_tick();
            Ok(pid.0)
        }
        SVCCTL_START => sv::SUPERVISOR.lock().start_service(name).map(|t| t.0).map_err(|e| Message(EIO, e)),
        SVCCTL_TICK => {
            sv::supervisor_tick();
            Ok(0)
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `ADMIN_POWER`.
pub fn power(what: u64) -> Result<(), Failure> {
    match what {
        POWER_OFF => crate::arch::power::power_off(),
        POWER_REBOOT => crate::arch::power::reboot(),
        POWER_HALT => {
            x86_64::instructions::interrupts::disable();
            loop {
                x86_64::instructions::hlt();
            }
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// Delay of `panic N`, in milliseconds.
static PANIC_DELAY_MS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The kernel task of `panic N`: waits, then panics.
fn delayed_panic() {
    crate::task::sleep_ms(PANIC_DELAY_MS.load(Ordering::Relaxed));
    panic!("Test kernel panic (panic N from the shell)");
}

/// `ADMIN_FAULT_TEST`.
pub fn fault_test(what: u64, secs: u64) -> Result<(), Failure> {
    match what {
        // panic N: a kernel task panics N seconds later, so that a panic can be tested while
        // the desktop shows (switch to it with Ctrl+Alt+F2 meanwhile)
        FAULT_PANIC if secs > 0 => {
            PANIC_DELAY_MS.store(secs * 1000, Ordering::Relaxed);
            crate::task::spawn("panictest", delayed_panic, crate::task::TaskPriority::High);
            Ok(())
        }
        FAULT_PANIC => panic!("Manual kernel panic triggered by user from shell."),
        FAULT_TRAP => {
            x86_64::instructions::interrupts::int3();
            Ok(())
        }
        _ => Err(Errno(EINVAL)),
    }
}

/// `ADMIN_IOMMU` (report).
pub fn iommu(what: u64) -> Result<(), Failure> {
    match what {
        0 => {
            for l in crate::arch::iommu::status() {
                crate::println!("{}", l);
            }
        }
        1 => {
            crate::arch::iommu::poll_faults();
            let faults = crate::arch::iommu::recent_faults();
            crate::println!("{} recent blocked DMA access(es):", faults.len());
            for f in faults {
                let (b, d, func) = crate::arch::dmar::bdf_parts(f.fault.source);
                crate::println!(
                    "  tick {}: {:02x}:{:02x}.{} {} {:#x}: {}",
                    f.tick,
                    b,
                    d,
                    func,
                    if f.fault.read { "read" } else { "write" },
                    f.fault.address,
                    crate::arch::dmar::reason_text(f.fault.reason)
                );
            }
        }
        2 => iommu_dma_test(),
        _ => return Err(Errno(EINVAL)),
    }
    Ok(())
}

/// The rogue-DMA test: the network adapter (driver argument `dma_test=1`) is asked to read
/// a kernel page it was never given; with the IOMMU on, the read must be blocked and
/// logged, and the driver must stay up. Needs QEMU's `-fw_cfg name=opt/hydra/iommu,string=test`.
fn iommu_dma_test() {
    use crate::ipc::protocol::{ENDPOINT_NET_DEV, MSG_NET_DMA_TEST, MSG_NET_REPLY};
    use crate::ipc::service;
    if !crate::arch::iommu::dma_test_enabled() {
        crate::println!("IOMMU-DMATEST: not enabled (QEMU -fw_cfg name=opt/hydra/iommu,string=test)");
        return;
    }
    if !service::is_online(ENDPOINT_NET_DEV) {
        crate::println!("IOMMU-DMATEST: FAIL (the network driver is not running)");
        return;
    }
    // A kernel page the driver was never given, filled with a pattern
    let Some(page) = service::ContiguousFrames::allocate(1) else {
        crate::println!("IOMMU-DMATEST: FAIL (no memory)");
        return;
    };
    unsafe { page.bytes().fill(0x5A) };
    let target = page.base;
    crate::arch::iommu::poll_faults();
    let before = crate::arch::iommu::recent_faults().len();
    let on = crate::arch::iommu::active();
    crate::println!("[iommu] DMA test: the network adapter will try to read kernel page {:#x} (IOMMU {})", target, if on { "on" } else { "off" });
    let r = service::call(ENDPOINT_NET_DEV, crate::ipc::Message::with_args(MSG_NET_DMA_TEST, [target, 0, 0, 0]), service::CALL_TIMEOUT_TICKS);
    let answered = matches!(r, Ok(m) if m.label == MSG_NET_REPLY);
    crate::task::sleep_ms(100);
    crate::arch::iommu::poll_faults();
    let dev = crate::arch::iommu::device_of(ENDPOINT_NET_DEV);
    let faults = crate::arch::iommu::recent_faults();
    let hit = faults.iter().skip(before.min(faults.len())).find(|f| Some(f.fault.source) == dev && f.fault.address == target && f.fault.read);
    let alive = service::is_online(ENDPOINT_NET_DEV);
    crate::println!(
        "[iommu] DMA test: driver answered: {}; fault logged for the adapter at that page: {}; driver still online: {}",
        answered,
        hit.is_some(),
        alive
    );
    if on && hit.is_some() && alive {
        crate::println!("IOMMU-DMATEST: PASS (the IOMMU blocked the rogue read and logged it)");
    } else if !on {
        crate::println!("IOMMU-DMATEST: FAIL (the IOMMU is off: nothing stopped the read)");
    } else {
        crate::println!("IOMMU-DMATEST: FAIL");
    }
}
