//! The driver supervisor (`src/task/supervisor.rs`): the service table, launching
//! drivers with their device arguments, waiting for them to register, restarting crashed
//! or hung ones (the restart limit and the Linux services' ladder), and the heartbeat.
//!
//! Drivers are the stand-in programs `build.rs` writes; they "register" when the caller
//! yields, through the yield hook below (as the real server's registration ends the
//! caller's hand-off).

mod common;
use common::*;

use hydra_hosttests_t31::ipc::protocol::*;
use hydra_hosttests_t31::ipc::Message;
use hydra_hosttests_t31::task::supervisor::{self, ServiceState, SUPERVISOR};
use hydra_hosttests_t31::task::{self, TaskId};
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Mutex;

/// Endpoints whose server does not register; tasks that die before registering.
static SILENT: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());
static DIE: Mutex<BTreeSet<u32>> = Mutex::new(BTreeSet::new());

/// The yield of a caller waiting for a driver: every driver process registers its
/// endpoint (unless SILENT; or dies, if DIE) and ends the hand-off.
fn drivers_register() {
    let list: Vec<(u32, u64)> = {
        let mut s = task::SCHEDULER.lock();
        let mut v = Vec::new();
        s.for_each_task_mut(|t| {
            if let Some(ep) = t.service {
                v.push((ep, t.id.0));
            }
        });
        v
    };
    for (ep, id) in list {
        if DIE.lock().unwrap().contains(&ep) {
            task::SCHEDULER.lock().kill_task(TaskId(id));
        } else if !SILENT.lock().unwrap().contains(&ep) {
            fake::SERVERS.lock().unwrap().insert(ep, id);
        }
        task::SCHEDULER.lock().end_handoffs_to(id);
    }
    // Time passes while the caller waits
    fake::set_ticks(fake::ticks() + 100);
}

fn setup() -> World {
    let w = booted();
    common::global_frames();
    SILENT.lock().unwrap().clear();
    DIE.lock().unwrap().clear();
    *fake::YIELD_MODE.lock().unwrap() = fake::YieldMode::Hook;
    *fake::YIELD_HOOK.lock().unwrap() = Some(drivers_register);
    w
}

fn snap(name: &str) -> supervisor::ServiceSnapshot {
    supervisor::get_service_snapshots().into_iter().find(|s| s.name == name).unwrap()
}

fn pong(_ep: u32, req: Message) -> Result<Message, i64> {
    Ok(Message::with_args(MSG_SUPERVISOR_PONG, [req.args[0], 0, 0, 0]))
}

fn wrong_pong(_ep: u32, _req: Message) -> Result<Message, i64> {
    Ok(Message::with_args(MSG_SUPERVISOR_PONG, [0, 0, 0, 0]))
}

#[test]
fn init_lists_every_service_once_and_wires_their_endpoints() {
    let _w = setup();
    supervisor::supervisor_init();
    supervisor::supervisor_init();
    let names: Vec<&str> = supervisor::get_service_snapshots().iter().map(|s| s.name).collect();
    assert_eq!(
        names,
        ["ahci_driver", "ata_driver", "usb_driver", "zfs_server", "net_driver", "net_server", "linux_server", "lx_sec", "svc_test", "sound_driver"]
    );
    assert!(supervisor::get_service_snapshots().iter().all(|s| s.state == ServiceState::Stopped && s.task_id.is_none()));
    let log = fake::SVC_LOG.lock().unwrap().clone();
    assert!(log.contains(&("allow_client", ENDPOINT_BLOCK_DEV, ENDPOINT_ZFS_SERVER as u64, 0)));
    assert!(log.contains(&("forward_irq", ENDPOINT_NET_DEV, ENDPOINT_NET_SERVER as u64, 0)));
    assert!(log.contains(&("set_signal_hook", ENDPOINT_LX_SEC, 0, 0)));
    assert!(log.contains(&("allow_client", ENDPOINT_NET_SERVER, ENDPOINT_LINUX_SERVER as u64, 0)));
    let lx = fake::LX_LOG.lock().unwrap().clone();
    for svc in [1u8, LXS_SEC, LXS_TEST] {
        assert!(lx.contains(&("configure", svc)) && lx.contains(&("fw_cfg", svc)), "Linux service {}", svc);
    }
    assert_eq!(*fake::LX_CALLS.lock().unwrap(), vec!["init"]);
}

#[test]
fn start_service_launches_a_driver_with_its_arguments_and_grants() {
    let _w = setup();
    supervisor::supervisor_init();
    let id = SUPERVISOR.lock().start_service("linux_server").unwrap();
    with(id.0, |t| {
        assert_eq!(t.service, Some(ENDPOINT_LINUX_SERVER));
        assert_eq!(t.exe_path(), "/drivers/linux_server");
        assert_eq!(&t.cmdline.as_ref().unwrap()[..], b"/drivers/linux_server\0workers=4\0");
    });
    let s = snap("linux_server");
    assert_eq!((s.state, s.task_id, s.restart_count), (ServiceState::Running, Some(id.0), 0));
    assert!(fake::LX_LOG.lock().unwrap().contains(&("started_by_hand", 1)));
    assert!(fake::SVC_LOG.lock().unwrap().iter().any(|e| e.0 == "set_grants" && e.1 == ENDPOINT_LINUX_SERVER));
    // Already running: the same process
    assert_eq!(SUPERVISOR.lock().start_service("linux_server").unwrap(), id);
    assert_eq!(SUPERVISOR.lock().start_service("nope").err(), Some("Service not found"));
    // No device: not started
    assert_eq!(SUPERVISOR.lock().start_service("net_driver").err(), Some("no device for this service"));
    assert_eq!(SUPERVISOR.lock().start_service("ahci_driver").err(), Some("no device for this service"));
    // The IDE driver stands back when another disk driver serves the endpoint, and
    // asking for it leaves that driver's registration alone
    let ahci = task::spawn("ahci-driver", noop, task::TaskPriority::High).0;
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_BLOCK_DEV, ahci);
    assert!(SUPERVISOR.lock().start_service("ata_driver").is_err());
    assert_eq!(fake::SERVERS.lock().unwrap().get(&ENDPOINT_BLOCK_DEV), Some(&ahci), "the AHCI driver's registration was dropped");
    // net-server is told whether the card's driver is there
    let ns = SUPERVISOR.lock().start_service("net_server").unwrap();
    assert_eq!(&with(ns.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/net_server\0");
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_NET_DEV, 98);
    task::kill(ns);
    let ns = SUPERVISOR.lock().start_service("net_server").unwrap();
    assert_eq!(&with(ns.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/net_server\0nic=1\0");
}

#[test]
fn ata_driver_gets_bus_master_dma_on_a_native_ide_controller() {
    let _w = setup();
    supervisor::supervisor_init();
    *fake::BOOTDISK_ARG.lock().unwrap() = Some("boot=disk0p2".into());
    let ide = fake::pci_add(0, 1, 1, 0x8086, 0x7010, 0x01, 0x01, 0x80);
    fake::pci_poke32(ide, 0x20, 0xC001); // BAR4: I/O at 0xC000
    let id = SUPERVISOR.lock().start_service("ata_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/ata_driver\0io=0x1f0\0ctrl=0x3f6\0boot=disk0p2\0bm=0xc000\0");
    assert_eq!(*fake::IOMMU_ATTACH.lock().unwrap(), vec![(ENDPOINT_BLOCK_DEV, "ata_driver")]);
    assert_eq!(*fake::BUS_MASTERS.lock().unwrap(), vec![(0, 1, 1)]);
    // Without bus mastering (prog-if bit 7 clear): plain PIO
    task::kill(id);
    fake::PCI.lock().unwrap()[ide].config[0x09] = 0;
    let id = SUPERVISOR.lock().start_service("ata_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/ata_driver\0io=0x1f0\0ctrl=0x3f6\0boot=disk0p2\0");
}

#[test]
fn ahci_driver_gets_its_register_window_and_msi_line() {
    let _w = setup();
    supervisor::supervisor_init();
    // A vendor-specific SATA function first (prog-if 0): skipped
    let raid = fake::pci_add(0, 2, 0, 0x8086, 0x2822, 0x01, 0x06, 0x00);
    fake::pci_set_bar(raid, 5, 0xF000_0000, 0x1000);
    let ahci = fake::pci_add(0, 3, 0, 0x8086, 0x2922, 0x01, 0x06, 0x01);
    fake::pci_set_bar(ahci, 5, 0xFEBF_1000, 0x1000);
    let id = SUPERVISOR.lock().start_service("ahci_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/ahci_driver\0abar=0xfebf1000\0");
    assert!(fake::klog_has("no MSI; its driver polls"));
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("set_grants", ENDPOINT_BLOCK_DEV, 0xFEBF_1000, 0x2000)));
    task::kill(id);
    fake::MSI.lock().unwrap().insert((0, 3, 0), 42);
    let id = SUPERVISOR.lock().start_service("ahci_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/ahci_driver\0abar=0xfebf1000\0irq=42\0");
}

#[test]
fn net_driver_gets_the_adapters_window_model_and_interrupt() {
    let _w = setup();
    supervisor::supervisor_init();
    let dev = hydra_hosttests_t31::arch::pci::PciDevice { bus: 0, device: 4, function: 0, vendor_id: 0x8086, device_id: 0x100E, class_id: 2, subclass_id: 0, bar0: 0, irq_line: 11 };
    *fake::E1000.lock().unwrap() = Some((dev, 0xFEB8_0000, "82540"));
    fake::MSI.lock().unwrap().insert((0, 4, 0), 50);
    fake::IOMMU_DMA_TEST.store(true, Ordering::SeqCst);
    let id = SUPERVISOR.lock().start_service("net_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/net_driver\0bar0=0xfeb80000\0model=82540\0dma_test=1\0irq=11\0", "the 82540 gets no MSI");
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("set_grants", ENDPOINT_NET_DEV, 0xFEB8_0000, 128 * 1024)));
    task::kill(id);
    fake::IOMMU_DMA_TEST.store(false, Ordering::SeqCst);
    let dev2 = hydra_hosttests_t31::arch::pci::PciDevice { irq_line: 2, ..dev };
    *fake::E1000.lock().unwrap() = Some((dev2, 0xFEB8_0000, "82574"));
    let id = SUPERVISOR.lock().start_service("net_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/net_driver\0bar0=0xfeb80000\0model=82574\0irq=50\0");
    task::kill(id);
    fake::MSI.lock().unwrap().clear();
    let id = SUPERVISOR.lock().start_service("net_driver").unwrap();
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/net_driver\0bar0=0xfeb80000\0model=82574\0", "IRQ 2 (the cascade) is not usable");
}

fn block_size(ep: u32, req: Message) -> Result<Message, i64> {
    assert_eq!(req.label, MSG_BLOCK_GET_SIZE);
    if ep == ENDPOINT_USB_DISK {
        Ok(Message::with_args(MSG_BLOCK_REPLY, [0, 1 << 20, 0, 0]))
    } else {
        Ok(Message::with_args(MSG_BLOCK_REPLY, [0, 0, 0, 0]))
    }
}

#[test]
fn zfs_server_sizes_its_cache_and_finds_a_pool_on_a_usb_disk() {
    let _w = setup();
    supervisor::supervisor_init();
    *fake::NEW_GUID.lock().unwrap() = Some(0xABC);
    let id = SUPERVISOR.lock().start_service("zfs_server").unwrap();
    // 64 MiB of test RAM: an eighth is below the 128 MiB floor (32768 blocks)
    assert_eq!(&with(id.0, |t| t.cmdline.clone()).unwrap()[..], b"/drivers/zfs_server\0cache_blocks=32768\0new_guid=abc\0");
    assert!(!hydra_hosttests_t31::fs::zfs::POOL_ON_USB.load(Ordering::SeqCst));
    task::kill(id);
    // The disk driver sees no pool; the USB driver does
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_BLOCK_DEV, 90);
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_USB_DISK, 91);
    *fake::CALL_HOOK.lock().unwrap() = Some(block_size);
    let id = SUPERVISOR.lock().start_service("zfs_server").unwrap();
    assert!(with(id.0, |t| t.cmdline.clone()).unwrap().ends_with(b"disk=usb\0"));
    assert!(hydra_hosttests_t31::fs::zfs::POOL_ON_USB.load(Ordering::SeqCst));
    assert!(fake::SVC_LOG.lock().unwrap().iter().any(|e| e.0 == "hold_window" && e.1 == ENDPOINT_USB_DISK));
}

#[test]
fn a_dead_driver_is_restarted_and_a_hung_one_after_three_missed_pings() {
    let _w = setup();
    supervisor::supervisor_init();
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    drivers_register();
    assert!(fake::SERVERS.lock().unwrap().contains_key(&ENDPOINT_NET_SERVER));
    // Answering pings: all well
    *fake::CALL_HOOK.lock().unwrap() = Some(pong);
    supervisor::supervisor_tick();
    assert!(fake::LX_CALLS.lock().unwrap().contains(&"watch"));
    assert_eq!(snap("net_server").unanswered_pings, 0);
    assert_eq!(SUPERVISOR.lock().snapshots().iter().find(|s| s.name == "net_server").unwrap().task_id, Some(id.0));
    // A wrong answer counts as none; three in a row restart it
    *fake::CALL_HOOK.lock().unwrap() = Some(wrong_pong);
    supervisor::supervisor_tick();
    supervisor::supervisor_tick();
    assert_eq!(snap("net_server").unanswered_pings, 2);
    *fake::CALL_HOOK.lock().unwrap() = None; // timeouts
    supervisor::supervisor_tick();
    assert!(fake::klog_has("stopped answering"));
    let s = snap("net_server");
    assert_eq!((s.restart_count, s.unanswered_pings, s.state), (1, 0, ServiceState::Running));
    assert_ne!(s.task_id, Some(id.0));
    assert!(!task::is_task_alive(id), "the hung process was killed");
    let log = fake::SVC_LOG.lock().unwrap().clone();
    assert!(log.contains(&("release_irqs", 0, id.0, 0)) && log.contains(&("unregister", ENDPOINT_NET_SERVER, 0, 0)));
    assert!(fake::klog_has("restarted 'net_server' as process"));
    // It dies: restarted at the next tick
    let id2 = TaskId(s.task_id.unwrap());
    task::kill(id2);
    supervisor::supervisor_tick();
    assert!(fake::klog_has("died"));
    assert_eq!(snap("net_server").restart_count, 2);
    // Still starting up (not registered): no ping
    SILENT.lock().unwrap().insert(ENDPOINT_NET_SERVER);
    let id3 = TaskId(snap("net_server").task_id.unwrap());
    fake::SERVERS.lock().unwrap().remove(&ENDPOINT_NET_SERVER);
    supervisor::supervisor_tick();
    assert_eq!(snap("net_server").task_id, Some(id3.0));
    assert_eq!(snap("net_server").unanswered_pings, 0);
}

#[test]
fn restarts_stop_at_the_limit_and_when_the_linux_ladder_gives_up() {
    let _w = setup();
    supervisor::supervisor_init();
    SUPERVISOR.lock().start_service("net_server").unwrap();
    for i in 1..=10 {
        let r = supervisor::revive(ENDPOINT_NET_SERVER);
        assert!(r || i > 0);
        // make it look dead so revive restarts it again
        let id = snap("net_server").task_id.unwrap();
        task::kill(TaskId(id));
    }
    assert_eq!(snap("net_server").restart_count, 10);
    assert!(!supervisor::revive(ENDPOINT_NET_SERVER), "the limit");
    assert_eq!(snap("net_server").state, ServiceState::Faulted);
    assert!(fake::klog_has("failed 10 times; not restarting it"));
    assert!(!supervisor::revive(ENDPOINT_NET_SERVER), "faulted: left alone");
    // A deliberate restart resets the count
    let id = supervisor::restart_service_by_name("net_server").unwrap();
    assert_eq!(snap("net_server").restart_count, 1);
    assert_eq!(snap("net_server").task_id, Some(id.0));
    // A Linux service whose ladder gave up
    SUPERVISOR.lock().start_service("lx_sec").unwrap();
    fake::LX_MAY_RESTART.store(false, Ordering::SeqCst);
    let id = snap("lx_sec").task_id.unwrap();
    task::kill(TaskId(id));
    supervisor::supervisor_tick();
    assert_eq!(snap("lx_sec").state, ServiceState::Faulted);
    assert!(fake::klog_has("crashed three times within 30 s"));
    assert!(supervisor::restart_service_by_name("lx_sec").is_err());
    assert!(fake::LX_LOG.lock().unwrap().contains(&("deliberate", LXS_SEC)));
    assert!(supervisor::restart_service_by_name("nope").is_err());
}

#[test]
fn revive_restarts_only_what_needs_it() {
    let _w = setup();
    supervisor::supervisor_init();
    assert!(!supervisor::revive(0x99), "nobody offers it");
    assert!(!supervisor::revive(ENDPOINT_NET_SERVER), "never started (Stopped)");
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    drivers_register();
    assert!(supervisor::revive(ENDPOINT_NET_SERVER), "alive and registered: nothing to do");
    assert_eq!(snap("net_server").task_id, Some(id.0));
    // An alias endpoint goes to the service serving it
    fake::PRIMARY.lock().unwrap().insert(0x55, ENDPOINT_NET_SERVER);
    task::kill(id);
    assert!(supervisor::revive(0x55));
    assert_ne!(snap("net_server").task_id, Some(id.0));
    // The supervisor itself busy: the caller does not wait for it
    let g = SUPERVISOR.lock();
    assert!(!supervisor::revive(ENDPOINT_NET_SERVER));
    drop(g);
    // A restarted server that never registers
    SILENT.lock().unwrap().insert(ENDPOINT_NET_SERVER);
    let cur = snap("net_server").task_id.unwrap();
    task::kill(TaskId(cur));
    fake::SERVERS.lock().unwrap().remove(&ENDPOINT_NET_SERVER);
    assert!(!supervisor::revive(ENDPOINT_NET_SERVER));
    let ids: Vec<TaskId> = task::SCHEDULER.lock().snapshots().iter().map(|s| s.id).collect();
    for id in ids {
        task::SCHEDULER.lock().end_handoffs_to(id.0);
    }
}

#[test]
fn a_restart_unregisters_the_endpoint_whichever_thread_of_the_old_process_registered_it() {
    let _w = setup();
    supervisor::supervisor_init();
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    // A worker thread of the driver's process registered the endpoint
    let worker = task::spawn("net-worker", noop, task::TaskPriority::Normal).0;
    with(worker, |t| t.tgid = id.0);
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_NET_SERVER, worker);
    supervisor::restart_service_by_name("net_server").unwrap();
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("unregister", ENDPOINT_NET_SERVER, 0, 0)));
    // A dead server's stale registration goes too
    let cur = TaskId(snap("net_server").task_id.unwrap());
    let ghost = task::spawn("ghost", noop, task::TaskPriority::Normal).0;
    task::kill(TaskId(ghost));
    fake::SVC_LOG.lock().unwrap().clear();
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_NET_SERVER, ghost);
    supervisor::restart_service_by_name("net_server").unwrap();
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("unregister", ENDPOINT_NET_SERVER, 0, 0)));
    assert!(!task::is_task_alive(cur));
}

// wave7 GB begin: Gemini's three concerns about `retire` (Group 31's 6d6419b)
#[test]
fn a_restart_never_unregisters_a_driver_that_registered_after_the_supervisor_looked() {
    let _w = setup();
    supervisor::supervisor_init();
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    drivers_register();
    // Another (live) driver's process registers the endpoint between the supervisor's look
    // and its clearing: its registration stays
    let other = task::spawn("other-driver", noop, task::TaskPriority::Normal).0;
    *fake::REGISTER_AFTER_LOOK.lock().unwrap() = Some((ENDPOINT_NET_SERVER, other));
    fake::SVC_LOG.lock().unwrap().clear();
    *fake::YIELD_HOOK.lock().unwrap() = None; // (the new instance does not register)
    supervisor::restart_service_by_name("net_server").unwrap();
    assert_eq!(fake::SERVERS.lock().unwrap().get(&ENDPOINT_NET_SERVER), Some(&other));
    assert!(!fake::SVC_LOG.lock().unwrap().iter().any(|e| e.0 == "unregister"));
    assert!(!task::is_task_alive(id));
    // Nobody registered at all: nothing to unregister (requests queued meanwhile are left
    // for the new instance)
    fake::SERVERS.lock().unwrap().clear();
    fake::SVC_LOG.lock().unwrap().clear();
    supervisor::restart_service_by_name("net_server").unwrap();
    assert!(!fake::SVC_LOG.lock().unwrap().iter().any(|e| e.0 == "unregister"));
}

#[test]
fn a_restart_ends_the_whole_old_process_even_when_its_first_thread_is_gone() {
    let _w = setup();
    supervisor::supervisor_init();
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    // Two more threads of the driver's process: one registered the endpoint
    let worker = task::spawn("net-worker", noop, task::TaskPriority::Normal).0;
    let irq = task::spawn("net-irq", noop, task::TaskPriority::Normal).0;
    with(worker, |t| t.tgid = id.0);
    with(irq, |t| t.tgid = id.0);
    fake::SERVERS.lock().unwrap().insert(ENDPOINT_NET_SERVER, worker);
    // The first thread exits and is reaped (gone from the table)
    task::kill(id);
    *fake::YIELD_HOOK.lock().unwrap() = None;
    yield_on(0); // (the scheduler moves dead tasks out of the table)
    task::scheduler::reap_dead_tasks();
    *fake::YIELD_HOOK.lock().unwrap() = Some(drivers_register);
    assert!(task::SCHEDULER.lock().with_task_mut(id, |_| ()).is_none(), "reaped");
    fake::SVC_LOG.lock().unwrap().clear();
    supervisor::restart_service_by_name("net_server").unwrap();
    // Its own thread's registration is no foreign one: unregistered
    assert!(fake::SVC_LOG.lock().unwrap().contains(&("unregister", ENDPOINT_NET_SERVER, 0, 0)));
    // The other threads ended, and the interrupt lines of the whole process were let go
    // (retired: one running on another CPU dies when it leaves the kernel)
    for t in [worker, irq] {
        assert!(with(t, |t| t.retired || t.state == task::TaskState::Dead), "thread {t} ended");
    }
    let log = fake::SVC_LOG.lock().unwrap().clone();
    assert!(log.contains(&("release_irqs", 0, id.0, 0)));
    assert!(log.contains(&("release_irqs_of_process", 0, id.0, 0)), "{log:?}");
}
// wave7 GB end

#[test]
fn kill_service_by_name_kills_the_running_process() {
    let _w = setup();
    supervisor::supervisor_init();
    assert_eq!(supervisor::kill_service_by_name("net_server").err(), Some("Service is not running"));
    assert!(supervisor::kill_service_by_name("nope").is_err());
    let id = SUPERVISOR.lock().start_service("net_server").unwrap();
    assert_eq!(supervisor::kill_service_by_name("net_server").unwrap(), id);
    assert!(!task::is_task_alive(id));
}

#[test]
fn start_all_launches_what_has_a_device_and_reports_the_rest() {
    let _w = setup();
    SILENT.lock().unwrap().insert(ENDPOINT_SVC_TEST);
    DIE.lock().unwrap().insert(ENDPOINT_LX_SEC);
    supervisor::start_all();
    assert!(fake::klog_has("[supervisor] started 'linux_server'"));
    assert!(fake::klog_has("[supervisor] started 'zfs_server'"));
    assert!(fake::klog_has("[supervisor] started 'ata_driver'"));
    assert!(fake::klog_has("not starting 'ahci_driver': no device for this service"));
    assert!(fake::klog_has("not starting 'net_driver'"));
    assert!(fake::klog_has("'svc_test' (process"), "{:?}", fake::KLOG.lock().unwrap());
    assert!(fake::klog_has("did not register"));
    assert!(fake::klog_has("exited without registering: no device"));
    assert_eq!(snap("lx_sec").state, ServiceState::Stopped);
    assert_eq!(snap("linux_server").state, ServiceState::Running);
    assert_eq!(*fake::STARTS.lock().unwrap(), vec!["usb_input", "snd"]);
    assert!(task::SCHEDULER.lock().task_named("supervisor").is_some(), "the watchdog task");
}
