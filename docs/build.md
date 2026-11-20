# Build Script Documentation

- **Source File**: [`build_drivers.rs`](file:///d:/os/build_drivers.rs) (the `build` script named in [`Cargo.toml`](file:///d:/os/Cargo.toml))
- **Subsystem**: Toolchain & Build Automation

---

## 1. Purpose & Context

The kernel is built by Cargo for `x86_64-unknown-uefi` and is written entirely in Rust; the
few CPU-level sequences that need assembly (trap and `syscall` entry, application-processor
start-up, the user-copy fix-ups) are inline `asm!`/`global_asm!` blocks inside Rust source files.
No external assembler is used.

The build script builds the ring-3 driver and server programs in `userland/drivers` (static
native ELFs for `x86_64-unknown-none`) into `target/drivers`, from where the kernel embeds them
as boot modules with `include_bytes!` (see `src/task/supervisor.rs`).

(Until 2026-11-20 the tree also carried a legacy Multiboot2/BIOS entry: `build.rs`,
`src/arch/x86_64/boot/*.asm`, prebuilt `objects/*.o` and `linker.ld`. None of it was built or
linked by the UEFI kernel, and it was removed.)

---

## 2. What it does

1. Asks Cargo to rerun it when `userland/drivers`, `src/ipc/protocol.rs` or `src/video/font.rs`
   (kernel sources the drivers share) change.
2. Runs `cargo build --release` in `userland/drivers`, with the kernel build's Cargo settings
   (target, flags, jobserver) removed from the environment, so the drivers build with their own.
