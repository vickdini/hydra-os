//! `src/admin/mod.rs` embeds the ring-3 `hydra-shell` with
//! `include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/target/drivers/.../hydra-shell"))`.
//! On the host that resolves inside this crate, where no driver build exists: put a
//! placeholder there (under `target/`, never committed). The host stubs of the program
//! loader never look at its bytes.
use std::path::PathBuf;

fn main() {
    let dir: PathBuf = [env!("CARGO_MANIFEST_DIR"), "target", "drivers", "x86_64-unknown-none", "release"].iter().collect();
    std::fs::create_dir_all(&dir).expect("placeholder directory");
    let file = dir.join("hydra-shell");
    if !file.exists() {
        std::fs::write(&file, b"\x7fELF hydra-shell placeholder (host tests)").expect("placeholder hydra-shell");
    }
    println!("cargo:rerun-if-changed=build.rs");
}
