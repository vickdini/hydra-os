//! # Build Script: Ring 3 Driver Programs
//!
//! Builds the driver and server programs in `userland/drivers` (static native ELFs for
//! `x86_64-unknown-none`) into `target/drivers`, from where the kernel embeds them as boot
//! modules with `include_bytes!` (see `src/task/supervisor.rs`).
//!
//! (`build.rs` assembles the legacy Multiboot2 entry and is not used by UEFI builds.)

use std::env;
use std::process::Command;

/// Builds `userland/drivers` into `target/drivers`.
fn build_drivers()
{
    let root = env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    println!("cargo:rerun-if-changed=userland/drivers");
    // Kernel sources the drivers share
    println!("cargo:rerun-if-changed=src/ipc/protocol.rs");
    println!("cargo:rerun-if-changed=src/video/font.rs");

    let mut cmd = Command::new(env::var("CARGO").unwrap_or_else(|_| "cargo".into()));
    cmd.current_dir(format!("{}/userland/drivers", root)).args(["build", "--release"]);
    // The kernel build's settings (target, flags, jobserver) are not the drivers'
    for (key, _) in env::vars()
    {
        if (key.starts_with("CARGO_") && key != "CARGO_HOME") || key == "RUSTFLAGS" || key == "RUSTC"
        {
            cmd.env_remove(key);
        }
    }
    cmd.env("CARGO_TARGET_DIR", format!("{}/target/drivers", root));
    let status = cmd.status().expect("couldn't run cargo for userland/drivers");
    if !status.success()
    {
        panic!("building userland/drivers failed with {}", status);
    }
}

fn main()
{
    build_drivers();
}
