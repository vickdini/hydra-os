// wave9 GM: the stub's mapping side (crates that compile mm.rs)
impl crate::memory::vm::MappedObject for TmemFile {
    fn get_page(&self, _pgoff: u64) -> Option<x86_64::structures::paging::PhysFrame<x86_64::structures::paging::Size4KiB>> {
        None
    }
}
