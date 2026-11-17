//! # admin-probe: the admin interface refuses everyone but the console
//!
//! A test program (wave 2, group 4). Started from the console (`adminprobe` or
//! `elf /bin/adminprobe.elf`, after copying the build output to `esp/bin/adminprobe.elf`),
//! it is a native Hydra process like the console but not the console itself: every
//! `SYS_ADMIN` call it makes must fail with `-EPERM`, the version query and a power-off
//! request alike.

#![no_std]
#![no_main]

extern crate alloc;

#[path = "../../../../src/admin/proto.rs"]
#[allow(dead_code)]
mod proto;

use hydra_rt::println;
use proto::*;

hydra_rt::entry!(main);

/// `SYS_ADMIN` with operation `op`: the raw result.
fn admin(op: u32, args: [u64; 4]) -> i64 {
    let mut out = [0u8; 64];
    let mut call = AdminCall { op, flags: 0, args, in_ptr: 0, in_len: 0, out_ptr: out.as_mut_ptr() as u64, out_cap: 64, err_len: 0 };
    let ret: i64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") SYS_ADMIN as i64 => ret,
            in("rdi") &mut call as *mut AdminCall as u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            out("rcx") _,
            out("r11") _,
            options(nostack)
        );
    }
    ret
}

fn main(_args: &[&str]) {
    let version = admin(ADMIN_VERSION, [0; 4]);
    let tasks = admin(ADMIN_TASK_LIST, [0; 4]);
    let power = admin(ADMIN_POWER, [POWER_OFF, 0, 0, 0]);
    let ok = [version, tasks, power].iter().all(|&r| r == -EPERM);
    println!("ADMIN-PROBE: pid {}: SYS_ADMIN version {}, task list {}, power off {} (expected -{} EPERM each): {}", hydra_rt::sys::getpid(), version, tasks, power, EPERM, if ok { "PASS" } else { "FAIL" });
}
