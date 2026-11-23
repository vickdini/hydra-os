// wave9 GM: *stub* of `src/fs/tmem.rs` (in-memory tmpfs files) for the host crates that fake
// `crate::fs`: no file is an in-memory one here (the real file is tested in tests/host-w9-m).
use std::sync::Arc;
use core::sync::atomic::AtomicBool;

pub static ENABLED: AtomicBool = AtomicBool::new(false);
pub const SHM_INST: u32 = 0;

pub struct TmemFile;
impl TmemFile {
    pub fn read(&self, _offset: u64, _buf: &mut [u8]) -> usize {
        0
    }
}
pub fn get(_ino: u64) -> Option<Arc<TmemFile>> {
    None
}
pub fn created(_dir: u64, _ino: u64, _tmpfs: Option<u32>) {}
pub fn shm_dir(_dir: u64) -> bool {
    false
}
pub fn add_shm_dir(_dir: u64) {}
pub fn drop_instance(_id: u32) {}
pub fn set_limit(_id: u32, _bytes: u64) {}
pub fn parse_size(_data: &str) -> Option<u64> {
    None
}
pub fn ctl(_sub: u64, _a: u64, _b: u64, _out: &dyn Fn(&[u8]) -> i64) -> i64 {
    -22
}
pub fn usage(_id: u32) -> Option<(u64, u64, u64)> {
    None
}
