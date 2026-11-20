//! The native system call wrappers (`src/syscall/user.rs`, through the host's stand-in for
//! the `syscall` instruction), capabilities (`src/capability`) and the task control block
//! (`src/task/tcb.rs`).

mod common;
use common::*;

use hydra_hosttests_t31::arch::idt::ExceptionContext;
use hydra_hosttests_t31::capability::table::{CapabilityTable, MAX_CAPABILITIES};
use hydra_hosttests_t31::capability::{CapType, Capability, Rights};
use hydra_hosttests_t31::ipc::Message;
use hydra_hosttests_t31::syscall::{self, *};
use hydra_hosttests_t31::arch::syscall::{SYS_OPEN, SYS_PIPE};
use hydra_hosttests_t31::task::tcb::{Caps, PrivilegeMode, Task, TaskId, TaskPersonality, TaskPriority, TaskRegisters, TaskState};

fn calls() -> Vec<(u64, [u64; 3])> {
    fake::SYSCALLS.lock().unwrap().clone()
}

fn returns(v: &[i64]) {
    *fake::SYSCALL_RETURNS.lock().unwrap() = v.to_vec();
}

// ------------------------------------------------------------------ system calls

#[test]
fn the_raw_calls_pass_number_and_arguments_in_order() {
    let _w = world();
    returns(&[10, 11, 12, 13]);
    unsafe {
        assert_eq!(syscall0(1), 10);
        assert_eq!(syscall1(2, 5), 11);
        assert_eq!(syscall2(3, 5, 6), 12);
        assert_eq!(syscall3(4, 5, 6, 7), 13);
    }
    assert_eq!(calls(), vec![(1, [0, 0, 0]), (2, [5, 0, 0]), (3, [5, 6, 0]), (4, [5, 6, 7])]);
}

#[test]
fn wrappers_turn_negative_returns_into_errors() {
    let _w = world();
    let buf = *b"hello";
    returns(&[5, -9]);
    assert_eq!(sys_write(1, &buf), Ok(5));
    assert_eq!(sys_write(1, &buf), Err(-9));
    assert_eq!(calls()[0], (SYS_WRITE, [1, buf.as_ptr() as u64, 5]));
    let mut rb = [0u8; 8];
    returns(&[3, -11]);
    assert_eq!(sys_read(0, &mut rb), Ok(3));
    assert_eq!(sys_read(0, &mut rb), Err(-11));
    let path = "/etc/motd";
    returns(&[4, -2]);
    assert_eq!(sys_open(path, 0), Ok(4));
    assert_eq!(sys_open(path, 2), Err(-2));
    assert_eq!(calls()[4], (SYS_OPEN, [path.as_ptr() as u64, 9, 0]));
    returns(&[0, -9]);
    assert_eq!(sys_close(4), Ok(()));
    assert_eq!(sys_close(4), Err(-9));
    returns(&[7, -9]);
    assert_eq!(sys_dup2(1, 7), Ok(7));
    assert_eq!(sys_dup2(1, 99), Err(-9));
    returns(&[1234, 99]);
    assert_eq!(sys_getpid(), 1234);
    assert_eq!(sys_uptime(), 99);
    sys_yield();
    sys_sleep(250);
    sys_print("hi");
    let n = calls().len();
    let c = calls();
    assert_eq!(c[n - 3], (SYS_YIELD, [0, 0, 0]));
    assert_eq!(c[n - 2], (SYS_SLEEP, [250, 0, 0]));
    assert_eq!(c[n - 1].0, SYS_WRITE);
    assert_eq!(c[n - 1].1[2], 2);
}

#[test]
fn pipe_returns_the_two_descriptors_the_kernel_wrote() {
    let _w = world();
    fn kernel(num: u64, args: [u64; 3]) {
        if num == SYS_PIPE {
            unsafe { *(args[0] as *mut [u64; 2]) = [3, 4] };
        }
    }
    *fake::SYSCALL_HOOK.lock().unwrap() = Some(kernel);
    assert_eq!(sys_pipe(), Ok((3, 4)));
    returns(&[-24]);
    assert_eq!(sys_pipe(), Err(-24));
}

#[test]
fn ipc_wrappers_pass_the_message_and_the_blocking_flag() {
    let _w = world();
    let msg = Message::with_args(0x77, [1, 2, 3, 4]);
    let mut out = Message::new(0);
    returns(&[0, -11, 0, -11, 0, 0, -5, -5]);
    assert_eq!(sys_ipc_send(3, &msg), Ok(()));
    assert_eq!(sys_ipc_send(3, &msg), Err(-11));
    assert_eq!(sys_ipc_recv(3, &mut out), Ok(()));
    assert_eq!(sys_ipc_recv(3, &mut out), Err(-11));
    assert_eq!(sys_ipc_send_blocking(3, &msg), Ok(()));
    assert_eq!(sys_ipc_recv_blocking(3, &mut out), Ok(()));
    assert_eq!(sys_ipc_send_blocking(3, &msg), Err(-5));
    assert_eq!(sys_ipc_recv_blocking(3, &mut out), Err(-5));
    let c = calls();
    assert_eq!(c[0], (SYS_IPC_SEND, [3, &msg as *const Message as u64, 0]));
    assert_eq!(c[4], (SYS_IPC_SEND, [3, &msg as *const Message as u64, 1]));
    assert_eq!(c[5], (SYS_IPC_RECV, [3, &out as *const Message as u64, 1]));
    assert_eq!(syscall::SYS_EXIT, 4);
}

#[test]
fn sys_exit_does_not_return() {
    let _w = world();
    let h = std::thread::spawn(|| {
        // The kernel never returns from SYS_EXIT; the host's stand-in does, and the wrapper
        // then spins: run it on a thread nobody waits for.
        fake::set_cpu(5);
        sys_exit();
    });
    while !calls().iter().any(|c| c.0 == SYS_EXIT) {
        std::thread::yield_now();
    }
    assert!(!h.is_finished());
}

// ------------------------------------------------------------------ capabilities

#[test]
fn rights_contain_subsets_only() {
    assert!(Rights::ALL.contains(Rights::READ));
    assert!(Rights(Rights::READ.0 | Rights::WRITE.0).contains(Rights::WRITE));
    assert!(!Rights::READ.contains(Rights::WRITE));
    assert!(Rights::READ.contains(Rights(0)));
}

#[test]
fn the_capability_table_fills_revokes_and_checks_rights() {
    let mut t = Box::new(CapabilityTable::new());
    assert!(t.is_empty());
    let ep = Capability::new(CapType::Endpoint { endpoint_id: 7 }, Rights::CALL);
    let a = t.insert(ep).unwrap();
    let b = t.insert(Capability::new(CapType::MemoryFrame { physical_addr: 0x1000 }, Rights::ALL)).unwrap();
    assert_eq!((a, b, t.len()), (0, 1, 2));
    assert!(t.check_rights(a, Rights::CALL));
    assert!(!t.check_rights(a, Rights::WRITE));
    assert!(!t.check_rights(99, Rights::READ));
    assert_eq!(t.get(a).unwrap().cap_type, CapType::Endpoint { endpoint_id: 7 });
    assert!(t.get(MAX_CAPABILITIES).is_none());
    assert_eq!(t.revoke(a).unwrap().rights, Rights::CALL);
    assert!(t.revoke(a).is_none());
    assert!(t.revoke(MAX_CAPABILITIES + 1).is_none());
    for _ in 0..MAX_CAPABILITIES - 1 {
        t.insert(ep).unwrap();
    }
    assert_eq!(t.len(), MAX_CAPABILITIES);
    assert!(t.insert(ep).is_err(), "full");
    t.revoke(5);
    assert_eq!(t.insert(ep).unwrap(), 5, "a freed slot is reused");
    let c = Message::new(1).with_cap(Capability::new(CapType::Thread { thread_id: 3 }, Rights::GRANT));
    let _ = c;
    for ty in [CapType::UntypedMemory { size_bytes: 1 }, CapType::AddressSpace { root_cr3: 0x1000 }, CapType::HardwareDevice { device_id: 2 }] {
        assert_eq!(Capability::new(ty, Rights::READ).cap_type, ty);
    }
}

// ------------------------------------------------------------------ task control block

#[test]
fn registers_round_trip_through_a_trap_frame() {
    let ctx;
    let vals: Vec<u64> = (1..=20).collect();
    let [r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax, rip, cs, rflags, rsp, ss]: [u64; 20] = vals.try_into().unwrap();
    ctx = ExceptionContext { r15, r14, r13, r12, rbp, rbx, r11, r10, r9, r8, rdi, rsi, rdx, rcx, rax, rip, cs, rflags, rsp, ss, vector: 99, error_code: 98 };
    let mut regs = TaskRegisters::empty();
    assert_eq!((regs.cs, regs.ss, regs.rflags, regs.cr3), (0x08, 0x10, 0x202, 0));
    regs.save_from_context(&ctx, 0x5000);
    assert_eq!(regs.cr3, 0x5000);
    let mut back = ExceptionContext::default();
    regs.restore_to_context(&mut back);
    back.vector = 99;
    back.error_code = 98;
    assert_eq!(back, ctx);
}

#[test]
fn names_of_states_priorities_modes_and_personalities() {
    assert_eq!(TaskState::Ready.as_str(), "Ready");
    assert_eq!(TaskState::Running.as_str(), "Running");
    assert_eq!(TaskState::Blocked.as_str(), "Blocked");
    assert_eq!(TaskState::Sleeping { wake_tick: 1 }.as_str(), "Sleeping");
    assert_eq!(TaskState::Dead.as_str(), "Dead");
    let p: Vec<&str> = [TaskPriority::Idle, TaskPriority::Low, TaskPriority::Normal, TaskPriority::High, TaskPriority::Realtime].iter().map(|p| p.as_str()).collect();
    assert_eq!(p, ["Idle", "Low", "Normal", "High", "Realtime"]);
    assert!(TaskPriority::Idle < TaskPriority::Low && TaskPriority::High < TaskPriority::Realtime);
    assert_eq!((PrivilegeMode::Kernel.as_str(), PrivilegeMode::User.as_str()), ("Kernel", "User"));
    let n: Vec<&str> = [TaskPersonality::Hydra, TaskPersonality::Linux, TaskPersonality::FreeBsd, TaskPersonality::MacOs].iter().map(|p| p.as_str()).collect();
    assert_eq!(n, ["Hydra", "Linux", "FreeBSD", "macOS"]);
    assert!(!TaskPersonality::Hydra.is_posix());
    assert!(TaskPersonality::Linux.is_posix() && TaskPersonality::FreeBsd.is_posix() && TaskPersonality::MacOs.is_posix());
}

#[test]
fn the_main_task_runs_on_the_boot_stack() {
    let _w = world();
    let mut t = Task::new_main(TaskId(0), "shell", 0x3000);
    assert_eq!((t.state, t.priority, t.mode, t.regs.cr3), (TaskState::Running, TaskPriority::Normal, PrivilegeMode::Kernel, 0x3000));
    assert!(t.stack.is_none());
    t.regs.rsp = 0xABCD0;
    assert_eq!(t.kernel_stack_top(), 0xABCD0, "no stack of its own: the saved rsp");
    assert_eq!(t.exe_path(), "shell");
    t.exe = Some(std::sync::Arc::from("/bin/sh"));
    assert_eq!(t.exe_path(), "/bin/sh");
    let c = Task::join_cmdline([&b"ls"[..], b"-l"]);
    assert_eq!(&c[..], b"ls\0-l\0");
    assert_eq!(&Task::join_cmdline(std::iter::empty())[..], b"");
}

#[test]
fn capabilities_follow_uid_changes_and_exec() {
    let mut root = Caps::for_euid(0);
    assert!(root.has(Caps::SETUID) && root.has(Caps::SYS_BOOT));
    let user = Caps::for_euid(1000);
    assert!(!user.has(Caps::SETUID));
    // Dropping every root id clears all capabilities
    root.on_uid_change((0, 0, 0), (1000, 1000, 1000));
    assert_eq!((root.effective, root.permitted), (0, 0));
    // With keep: permitted stay, effective goes when euid leaves 0 and comes back
    let mut k = Caps::for_euid(0);
    k.keep = true;
    k.on_uid_change((0, 0, 0), (1000, 1000, 1000));
    assert_eq!((k.effective, k.permitted), (0, Caps::FULL));
    k.on_uid_change((1000, 1000, 1000), (1000, 0, 1000));
    assert_eq!(k.effective, Caps::FULL);
    // euid 0 -> non-zero with a root id kept: effective cleared, permitted kept
    let mut s = Caps::for_euid(0);
    s.on_uid_change((0, 0, 0), (0, 1000, 0));
    assert_eq!((s.effective, s.permitted), (0, Caps::FULL));
    // exec
    let mut e = Caps::for_euid(1000);
    e.keep = true;
    e.on_exec(1000, 0);
    assert_eq!((e.effective, e.permitted, e.keep), (Caps::FULL, Caps::FULL, false));
    e.on_exec(0, 1000);
    assert_eq!((e.effective, e.permitted), (0, Caps::FULL));
    e.on_exec(1000, 1000);
    assert_eq!((e.effective, e.permitted), (0, 0));
    // In a user namespace: all capabilities, none of them count outside
    let mut n = Caps::for_euid(1000);
    n.enter_userns();
    assert_eq!(n.effective, Caps::FULL);
    assert!(!n.has(Caps::SETUID));
}
