//! # hydra-rt: runtime for Hydra's Ring 3 driver and server programs
//!
//! Driver programs are static native ELFs (no libc) that the supervisor starts in an
//! address space of their own. This crate gives them what a C runtime would:
//!
//! - the process entry point (`_start`), arguments, a heap and a panic handler;
//! - `print!`/`println!` to the console;
//! - the native system calls ([`sys`]), I/O port access ([`port`]);
//! - the server side of a driver service ([`Server`]): register, receive, reply, and the
//!   shared data window.
//!
//! A program defines `fn main(args: &[&str])` and invokes [`entry!`] with it.

#![no_std]

extern crate alloc;

pub mod port;
pub mod sys;

/// Message codes shared with the kernel (one source: the kernel's `ipc/protocol.rs`).
#[path = "../../../../src/ipc/protocol.rs"]
pub mod protocol;

use alloc::vec::Vec;
use core::fmt::Write;

pub use sys::Message;

#[doc(hidden)]
pub mod __private {
    pub use alloc::format;
}

/// Virtual size of the heap. It is reserved, not committed: pages are allocated on
/// first use.
const HEAP_SIZE: usize = 1024 * 1024 * 1024;

#[global_allocator]
static ALLOCATOR: linked_list_allocator::LockedHeap = linked_list_allocator::LockedHeap::empty();

// The kernel enters with the stack holding argc, argv[] and envp[] (Linux layout)
core::arch::global_asm!(
    ".globl _start",
    "_start:",
    "mov rdi, rsp",
    "and rsp, -16",
    "call {start}",
    "ud2",
    start = sym rt_start,
);

extern "Rust" {
    /// The program's `main`, exported by [`entry!`].
    fn hydra_main(args: &[&'static str]);
}

/// Sets up the heap and the arguments, runs `main`, and exits.
///
/// # Arguments
/// * `stack` - Pointer to initial stack frame containing argument count and pointers.
///
/// # Returns
/// Does not return (`!`).
extern "C" fn rt_start(stack: *const u64) -> ! {
    let heap = sys::map_anon(HEAP_SIZE).unwrap_or_else(|_| sys::exit(127));
    unsafe { ALLOCATOR.lock().init(heap as *mut u8, HEAP_SIZE) };
    let argc = unsafe { *stack } as usize;
    let mut args: Vec<&'static str> = Vec::with_capacity(argc);
    for i in 0..argc {
        let p = unsafe { *stack.add(1 + i) } as *const u8;
        let mut len = 0;
        while unsafe { *p.add(len) } != 0 {
            len += 1;
        }
        let bytes = unsafe { core::slice::from_raw_parts(p, len) };
        args.push(core::str::from_utf8(bytes).unwrap_or(""));
    }
    unsafe { hydra_main(&args) };
    sys::exit(0)
}

/// Exports `main` (a `fn(&[&str])`) as the program's entry point.
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[no_mangle]
        /// Program entry point dispatched by the runtime.
        ///
        /// # Arguments
        /// * `args` - Program command line arguments.
        fn hydra_main(args: &[&'static str]) {
            $main(args)
        }
    };
}

/// Heap bytes `(used, free)`.
///
/// # Returns
/// Tuple of `(used_bytes, free_bytes)`.
pub fn heap_usage() -> (usize, usize) {
    let heap = ALLOCATOR.lock();
    (heap.used(), heap.free())
}

/// Console output (standard output of the process, which the kernel prints).
pub struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        sys::write(1, s.as_bytes());
        Ok(())
    }
}

/// Prints to the console.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        let _ = core::fmt::Write::write_fmt(&mut $crate::Console, format_args!($($arg)*));
    }};
}

/// Prints a line to the console.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        // One write per line, so lines of different programs do not interleave
        let line = alloc::format!("{}\n", format_args!($($arg)*));
        $crate::sys::write(1, line.as_bytes());
    }};
}

/// Driver panic handler that prints the panic info and terminates the driver process.
///
/// # Arguments
/// * `info` - Panic information payload.
///
/// # Returns
/// Does not return (`!`).
#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    let mut line = alloc::string::String::new();
    let _ = write!(line, "[driver] panic: {}\n", info);
    sys::write(2, line.as_bytes());
    sys::exit(101)
}

/// The server of a driver service: receives requests and answers them; bulk data is in
/// the service window shared with the kernel.
pub struct Server {
    /// Endpoint served.
    pub endpoint: u32,
    window: *mut u8,
    window_len: usize,
}

/// Size of a service window (as the kernel's `ipc::service::WINDOW_SIZE`).
pub const WINDOW_SIZE: usize = 64 * 4096;

impl Server {
    /// Registers the calling process as the server of `endpoint` (the supervisor started
    /// it for that service) and maps the service window.
    ///
    /// # Arguments
    /// * `endpoint` - Service endpoint ID.
    ///
    /// # Returns
    /// New [`Server`] instance on success.
    ///
    /// # Errors
    /// Returns negative error code if registration fails.
    pub fn register(endpoint: u32) -> Result<Self, i64> {
        let window = sys::svc_register(endpoint)?;
        Ok(Self { endpoint, window: window as *mut u8, window_len: WINDOW_SIZE })
    }

    /// The data window shared with clients.
    ///
    /// # Returns
    /// Mutable byte slice referencing the shared service window.
    pub fn window(&mut self) -> &mut [u8] {
        unsafe { core::slice::from_raw_parts_mut(self.window, self.window_len) }
    }

    /// Serves requests forever: each request goes to `handle`, whose result is the reply.
    /// Supervisor heartbeats are answered here.
    ///
    /// # Arguments
    /// * `handle` - Request handler closure.
    ///
    /// # Returns
    /// Does not return (`!`).
    pub fn serve(&mut self, mut handle: impl FnMut(&mut Self, &Message) -> Message) -> ! {
        loop {
            let req = match sys::svc_recv(self.endpoint) {
                Ok(m) => m,
                Err(_) => continue,
            };
            let reply = if req.label == protocol::MSG_SUPERVISOR_PING as u64 {
                Message::new(protocol::MSG_SUPERVISOR_PONG as u64, [req.args[0], 1, 0, 0])
            } else {
                handle(self, &req)
            };
            let _ = sys::svc_reply(self.endpoint, &reply);
        }
    }
}
