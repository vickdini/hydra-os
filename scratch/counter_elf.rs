#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let header = b"[ELF Counter] Starting Ring 3 counting process...\n";
    sys_write(1, header);

    for i in 1..=3 {
        let msg = b"[ELF Counter] Ring 3 countdown step ";
        sys_write(1, msg);
        let digit = [b'0' + (i as u8), b'\n'];
        sys_write(1, &digit);
        sys_sleep(200);
    }

    let footer = "[ELF Counter] Finished! Exiting unprivileged Ring 3.\n";
    sys_write(1, footer.as_bytes());
    sys_exit();
}

#[inline(always)]
fn sys_write(fd: u64, buf: &[u8]) {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 3u64,
            in("rdi") fd,
            in("rsi") buf.as_ptr() as u64,
            in("rdx") buf.len() as u64,
            out("rcx") _,
            out("r11") _,
        );
    }
}

#[inline(always)]
fn sys_sleep(ms: u64) {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 2u64,
            in("rdi") ms,
            out("rcx") _,
            out("r11") _,
        );
    }
}

#[inline(always)]
fn sys_exit() -> ! {
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") 4u64,
            out("rcx") _,
            out("r11") _,
        );
    }
    loop {}
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
