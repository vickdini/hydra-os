//! # Build Script: Ring 3 Driver Programs
//!
//! Builds the driver and server programs in `userland/drivers` (static native ELFs for
//! `x86_64-unknown-none`) into `target/drivers`, from where the kernel embeds them as boot
//! modules with `include_bytes!` (see `src/task/supervisor.rs`).

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
    // The kernel image's preferred load address. UEFI firmware (EDK2/OVMF) loads an image at
    // its preferred base when that memory is free, else anywhere. The kernel runs at its
    // physical address, so the 1 GiB slot it lands in is the kernel's in every address space
    // (`memory::vm::init_low_layout`). The linker's default for 64-bit images, 0x1_4000_0000,
    // is the base of 64-bit Windows programs, which Wine needs: on machines with RAM there
    // (QEMU q35 with 4 GiB, real machines with more than about 5 GiB) programs lost that
    // slot. 0x1_0000_0000 (slot 4) is used by neither Wine nor Linux programs.
    println!("cargo:rustc-link-arg-bins=/BASE:0x100000000");
}
