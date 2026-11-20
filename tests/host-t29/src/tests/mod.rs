//! Group 29's tests, compiled into the library's test build so they reach `pub(crate)`
//! kernel items. One module per kernel file.

pub mod common;

mod execve;
mod extra;
mod ldt;
mod limits;
mod ns;
mod proc;
mod process;
mod ptrace;
