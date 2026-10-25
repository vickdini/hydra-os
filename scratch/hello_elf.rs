#![no_std]
#![no_main]

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let msg = b"\n[ELF64 Userland] Greetings from standalone ELF64 binary in Ring 3!\n";
    unsafe {
        // SYS_WRITE (rax = 3, rdi = 1, rsi = ptr, rdx = len)
        core::arch::asm!(
            "syscall",
            in("rax") 3u64,
            in("rdi") 1u64,
            in("rsi") msg.as_ptr() as u64,
            in("rdx") msg.len() as u64,
            out("rcx") _,
            out("r11") _,
        );
        // SYS_EXIT (rax = 4)
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
