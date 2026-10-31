//! # Build Script: Legacy x86_64 Assembly Trampoline Compiler
//!
//! Compiles Multiboot2 and 32-to-64-bit long mode assembly files (`src/arch/x86_64/boot/*.asm`)
//! into ELF64 object files using `nasm` when targeting `x86_64` non-UEFI builds.
//!
//! ## Architectural Role & Design Rationale
//!
//! While Hydra OS primarily boots directly as a 64-bit UEFI application (`x86_64-unknown-uefi`),
//! the repository retains legacy Multiboot2 assembly bootstrap files for bare-metal ELF builds.
//! This Cargo build script invokes `nasm` with DWARF debug symbols and emits `cargo:rustc-link-object`
//! directives for the resulting object files.
//!
//! ## Key Types & Interfaces
//!
//! - [`assemble_file()`]: Compiles a single `.asm` file into an `.o` object file via `nasm`.
//! - [`assemble_all()`]: Iterates over all boot assembly sources and compiles each one.
//! - [`main()`]: Cargo build script entry point.
//!
//! ## Hardware & Dependency Context
//!
//! - Host Tooling: Requires `nasm` installed on the build host when targeting legacy ELF `x86_64`.

use std::env;
use std::process::Command;

/// Relative directory path containing `x86_64` assembly bootstrap sources.
const ASM_DIR: &str = "src/arch/x86_64";

/// No-op stub for assembling a single file on non-`x86_64` host targets.
#[cfg(not(target_arch = "x86_64"))]
fn assemble_file(_file: &str, _output_dir: &str) {}

/// No-op stub for assembling all boot files on non-`x86_64` host targets.
#[cfg(not(target_arch = "x86_64"))]
fn assemble_all(_output_dir: &str) {}

/// Compiles a single NASM assembly source file into a 64-bit ELF object file with DWARF symbols.
///
/// # Arguments
///
/// * `file` - Relative path under [`ASM_DIR`] of the `.asm` source file.
/// * `output_dir` - Directory where the compiled `.o` object file is written.
///
/// # Panics
///
/// Panics if the `nasm` binary cannot be spawned or returns a non-zero exit status.
#[cfg(target_arch = "x86_64")]
fn assemble_file(file: &str, output_dir: &str)
{
    let mut out_file = file.replace(".asm", ".o");
    out_file = format!("{}/{}", output_dir, out_file);
    let file = format!("{}/{}", ASM_DIR, file);
    println!("cargo:rerun-if-changed={}", file);

    let status = if env::var_os("DEBUG").is_some() && env::var("DEBUG").unwrap() == "true"
    {
        Command::new("nasm")
            .arg(file)
            .arg("-o")
            .arg(&out_file)
            .arg("-g")
            .arg("-f")
            .arg("elf64")
            .arg("-F")
            .arg("Dwarf")
            .status()
            .expect("couldn't run nasm")
    }
    else
    {
        Command::new("nasm")
            .arg(file)
            .arg("-o")
            .arg(&out_file)
            .arg("-f")
            .arg("elf64")
            .arg("-F")
            .arg("Dwarf")
            .status()
            .expect("couldn't run nasm")
    };

    if !status.success()
    {
        panic!("nasm failed with {}", status);
    }

    println!("cargo:rustc-link-object={}", env::current_dir().unwrap().display().to_string() + "/" + &out_file);
}

/// Compiles all `x86_64` bootstrap assembly files (`header.asm`, `main.asm`, `main64.asm`).
///
/// # Arguments
///
/// * `output_dir` - Directory where compiled object files are placed.
#[cfg(target_arch = "x86_64")]
fn assemble_all(output_dir: &str)
{
    let files = vec!
    [
        "boot/header.asm",
        "boot/main.asm",
        "boot/main64.asm",
    ];

    for f in files.iter()
    {
        assemble_file(f, output_dir);
    }
}

/// Cargo build script entry point configuring object search paths and assembling boot code.
fn main()
{
    let output_dir = "objects/x86_64";

    println!("cargo:rustc-link-search={}", output_dir);

    assemble_all(&output_dir);
}
