//! Host build of the Linux process files (test wave, Group 29).
//!
//! Each module below compiles the kernel's own source file through `#[path]`, laid out
//! under the same module path the kernel uses, so `crate::` and `super::` references inside
//! those files resolve unchanged. Where a kernel file calls into another part of the kernel
//! that is not compiled here, the callee is a stub (marked *stub*) from this file or
//! [`fake`]. Stubs record their calls in `fake::CALLS` and return `fake::ret(name)`, so
//! tests can check what the code under test asked for.
//!
//! Paths inside an inline `mod` block are resolved relative to a directory named after
//! that module, hence the extra `../` per nesting level.

#![allow(dead_code, unused_imports, unused_variables, unused_mut, clippy::all)]

extern crate alloc;

pub mod fake;

/// *stub* Kernel console output; discarded on the host.
#[macro_export]
macro_rules! println {
    ($($arg:tt)*) => {{
        let _ = format_args!($($arg)*);
    }};
}

/// *stub* Kernel log output: kept in `fake::CALLS` as "log:<text>".
#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => {{
        $crate::fake::rec(format!("log:{}", format_args!($($arg)*)));
    }};
}

/// A stub that records its call (name and arguments) and returns `fake::ret(name)`.
macro_rules! stub {
    ($(#[$m:meta])* $v:vis fn $name:ident($($a:ident: $t:ty),* $(,)?) -> i64 as $key:literal) => {
        $(#[$m])* $v fn $name($($a: $t),*) -> i64 {
            let mut s = alloc::string::String::from($key);
            s.push('(');
            $( s.push_str(&alloc::format!("{:?},", $a)); )*
            s.push(')');
            $crate::fake::rec(s);
            $crate::fake::ret($key)
        }
    };
    ($(#[$m:meta])* $v:vis fn $name:ident($($a:ident: $t:ty),* $(,)?) as $key:literal) => {
        $(#[$m])* $v fn $name($($a: $t),*) {
            let mut s = alloc::string::String::from($key);
            s.push('(');
            $( s.push_str(&alloc::format!("{:?},", $a)); )*
            s.push(')');
            $crate::fake::rec(s);
        }
    };
}
pub(crate) use stub;

pub mod arch;
pub mod compat;
pub mod fs;
pub mod lx;
pub mod memory;
pub mod personality;
pub mod task;

pub mod ipc {
    #[path = "../../../../src/ipc/protocol.rs"]
    pub mod protocol;
}
