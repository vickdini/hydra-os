//! Group H's host build (wave 11): the plain-logic files of the boot log
//! (`arch/logring.rs`, `fs/fat32.rs`), the boot words (`arch/bootwords.rs`) and the ACPI
//! power-off values (`arch/acpi_s5.rs`), compiled from their own sources. Tests in
//! `tests.rs`.
#![allow(dead_code)]

extern crate alloc;

#[path = "../../../src/arch/logring.rs"]
pub mod logring;
#[path = "../../../src/fs/fat32.rs"]
pub mod fat32;
#[path = "../../../src/arch/bootwords.rs"]
pub mod bootwords;
#[path = "../../../src/arch/acpi_s5.rs"]
pub mod acpi_s5;

#[cfg(test)]
mod tests;
