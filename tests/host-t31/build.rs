//! `src/task/supervisor.rs` embeds the driver programs with `include_bytes!` from
//! `$CARGO_MANIFEST_DIR/target/drivers/x86_64-unknown-none/release/`. The host build
//! has none, so this writes a stand-in for each: a minimal static PIE (one R+X
//! segment, entry at 0x100) that the kernel's ELF loader accepts, so the
//! supervisor's launch path can run in the tests.

use std::path::PathBuf;

const DRIVERS: &[&str] = &[
    "ata-driver",
    "ahci-driver",
    "usb-driver",
    "zfs-server",
    "e1000-driver",
    "net-server",
    "linux-server",
    "lx-sec",
    "vfs-server",
    "display-server", // wave8 GD
    "svc-test",
    "hda-driver",
];

fn stand_in() -> Vec<u8> {
    let mut b = vec![0u8; 0x1000];
    b[..4].copy_from_slice(b"\x7fELF");
    b[4] = 2; // ELFCLASS64
    b[5] = 1; // little-endian
    b[6] = 1; // EV_CURRENT
    b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
    b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x100u64.to_le_bytes()); // e_entry
    b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
    b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
    b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
    b[56..58].copy_from_slice(&1u16.to_le_bytes()); // e_phnum
    let o = 64;
    b[o..o + 4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
    b[o + 4..o + 8].copy_from_slice(&5u32.to_le_bytes()); // R+X
    // offset 0, vaddr 0, paddr 0
    b[o + 32..o + 40].copy_from_slice(&0x1000u64.to_le_bytes()); // filesz
    b[o + 40..o + 48].copy_from_slice(&0x1000u64.to_le_bytes()); // memsz
    b[o + 48..o + 56].copy_from_slice(&0x1000u64.to_le_bytes()); // align
    b[0x100..0x104].copy_from_slice(b"DRVR");
    b
}

fn main() {
    let dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap()).join("target/drivers/x86_64-unknown-none/release");
    std::fs::create_dir_all(&dir).unwrap();
    let image = stand_in();
    for d in DRIVERS {
        let p = dir.join(d);
        if std::fs::read(&p).ok().as_deref() != Some(&image[..]) {
            std::fs::write(&p, &image).unwrap();
        }
    }
    println!("cargo:rerun-if-changed=build.rs");
}
