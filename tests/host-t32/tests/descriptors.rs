//! Descriptor tables and segment state: `arch/gdt.rs`, `arch/segments.rs`, plus the small
//! register files `arch/cpu.rs` and `arch/debugregs.rs`.
//!
//! The per-CPU GDTs are global (as in the kernel), so each test plays its own CPU number.

use std::sync::Arc;

use hydra_hosttests_t32::arch::{cpu, debugregs, gdt, segments};
use hydra_hosttests_t32::host;
use segments::{Ldt, UserDesc, UserSegs};

/// Plays CPU `c` with a fresh GDT of its own (as an application processor gets).
fn on_cpu(c: usize) {
    host::reset();
    host::set_cpu(c);
    gdt::load_for_ap(c);
}

fn tls_desc(base: u32, limit: u32) -> UserDesc {
    UserDesc { entry_number: 12, base_addr: base, limit, seg_32bit: true, limit_in_pages: true, useable: true, ..Default::default() }
}

#[test]
fn gdt_layout_follows_linux() {
    on_cpu(2);
    let g = gdt::CPU_GDT[2].load(std::sync::atomic::Ordering::Acquire);
    assert!(!g.is_null());
    let t = unsafe { &(*g).0 };
    use x86_64::structures::gdt::DescriptorFlags as F;
    assert_eq!(t[1], F::KERNEL_CODE64.bits());
    assert_eq!(t[2], F::KERNEL_DATA.bits());
    assert_eq!(t[4], F::USER_CODE32.bits());
    assert_eq!(t[5], F::USER_DATA.bits());
    assert_eq!(t[6], F::USER_CODE64.bits());
    // The TSS: a 16-byte system descriptor at 0x40, type 9 (available 64-bit TSS), present
    assert_eq!((t[8] >> 40) & 0xF, 9);
    assert_eq!((t[8] >> 47) & 1, 1);
    // SYSRET's order: user 32-bit code, data, 64-bit code from STAR's base 0x23
    assert_eq!((gdt::USER32_CS + 8, gdt::USER32_CS + 16), (gdt::USER_DS, gdt::USER_CS));
    // The CPU loaded it: lgdt of the table, then the selectors, then TR
    let tables = x86_64::hw::TABLES.with_borrow(|t| t.clone());
    assert_eq!(tables[0], ("lgdt", g as u64, 16 * 8 - 1));
    assert_eq!(tables[1], ("ltr", gdt::TSS_SEL as u64, 0));
    assert_eq!(host::read_seg("cs"), gdt::KERNEL_CS);
    assert_eq!(host::read_seg("ss"), gdt::KERNEL_DS);
    for r in ["ds", "es", "fs", "gs"] {
        assert_eq!(host::read_seg(r), 0, "{r} holds null");
    }
    // ...and its per-CPU block through GS
    let w = host::MSR_WRITES.with_borrow(|w| w.clone());
    assert!(w.iter().any(|&(m, v)| m == 0xC000_0101 && v != 0), "GS base set: {w:x?}");
    assert!(w.contains(&(0xC000_0102, 0)));
}

#[test]
fn ap_tss_has_its_own_stacks() {
    on_cpu(3);
    let tss = gdt::AP_TSS[3].load(std::sync::atomic::Ordering::Acquire);
    assert!(!tss.is_null());
    let (df, ps) = unsafe { ((*tss).interrupt_stack_table[0].as_u64(), (*tss).privilege_stack_table[0].as_u64()) };
    assert!(df != 0 && ps != 0 && df != ps);
    assert_eq!(gdt::privilege_stack(), ps);
    gdt::set_privilege_stack(x86_64::VirtAddr::new(0x1234_5000));
    assert_eq!(gdt::privilege_stack(), 0x1234_5000);
    // The TSS descriptor in this CPU's GDT points at this TSS
    let g = unsafe { &(*gdt::CPU_GDT[3].load(std::sync::atomic::Ordering::Acquire)).0 };
    let base = ((g[8] >> 16) & 0xFF_FFFF) | ((g[8] >> 56) << 24) | (g[9] << 32);
    assert_eq!(base, tss as u64);
}

#[test]
fn boot_processor_tss_and_gdt() {
    host::reset();
    host::set_cpu(0);
    gdt::init();
    let ps = gdt::privilege_stack();
    assert!(ps != 0);
    gdt::set_privilege_stack(x86_64::VirtAddr::new(0xABC000));
    assert_eq!(gdt::privilege_stack(), 0xABC000);
    gdt::set_privilege_stack(x86_64::VirtAddr::new(ps));
    gdt::load_and_switch();
    assert!(!gdt::CPU_GDT[0].load(std::sync::atomic::Ordering::Acquire).is_null());
    let s = gdt::get_selectors();
    assert_eq!(s.kernel_code_selector.0, gdt::KERNEL_CS);
    assert_eq!(s.user_code_selector.0, gdt::USER_CS | 3);
    assert_eq!(s.user_data_selector.0, gdt::USER_DS | 3);
    assert_eq!(s.user32_code_selector.0, gdt::USER32_CS | 3);
    assert_eq!(s.tss_selector.0, gdt::TSS_SEL);
}

#[test]
fn user_desc_round_trips() {
    let mut raw = [0u8; 16];
    raw[0..4].copy_from_slice(&13u32.to_le_bytes());
    raw[4..8].copy_from_slice(&0xDEAD_B000u32.to_le_bytes());
    raw[8..12].copy_from_slice(&0xFFFFFu32.to_le_bytes());
    raw[12..16].copy_from_slice(&0b0101_0011u32.to_le_bytes()); // 32-bit, contents 1, pages, useable
    let d = UserDesc::parse(&raw);
    assert_eq!(d.entry_number, 13);
    assert_eq!(d.base_addr, 0xDEAD_B000);
    assert!(d.seg_32bit && d.limit_in_pages && d.useable && !d.read_exec_only && !d.seg_not_present && !d.lm);
    assert_eq!(d.contents, 1);
    assert_eq!(d.bytes(), raw);
    assert!(d.supported() && !d.is_empty() && !d.is_zero());

    // The descriptor encoding and back
    let desc = d.descriptor();
    assert_eq!(desc >> 44 & 1, 1, "code/data segment");
    assert_eq!((desc >> 45) & 3, 3, "DPL 3");
    assert_eq!(desc >> 47 & 1, 1, "present");
    let back = UserDesc::from_descriptor(13, desc);
    assert_eq!(back, d);

    // Linux's "empty" and "zero" forms
    let empty = UserDesc { read_exec_only: true, seg_not_present: true, ..Default::default() };
    assert!(empty.is_empty() && !empty.is_zero());
    assert!(UserDesc::default().is_zero() && !UserDesc::default().is_empty());
    // 16-bit or code segments with contents 2+ are not supported
    assert!(!UserDesc { seg_32bit: false, ..d }.supported());
    assert!(!UserDesc { contents: 2, ..d }.supported());
}

#[test]
fn loadable_checks_the_descriptor() {
    on_cpu(4);
    assert!(segments::loadable(0), "null");
    assert!(segments::loadable(3), "null with RPL 3");
    assert!(!segments::loadable(gdt::KERNEL_DS), "RPL 0");
    assert!(segments::loadable(gdt::USER_DS));
    assert!(segments::loadable(gdt::USER_CS), "readable code");
    assert!(!segments::loadable(gdt::KERNEL_CS | 3), "DPL 0 descriptor");
    assert!(!segments::loadable(0x78 | 3), "past the table");
    // A TLS entry once set
    let mut s = UserSegs::default();
    let sel = (13u16 << 3) | 3;
    assert!(!segments::loadable(sel), "empty TLS slot");
    segments::set_current_tls(&mut s, 13, tls_desc(0x1000, 0xFFFFF).descriptor());
    assert!(segments::loadable(sel));
    assert_eq!(s.tls[1], tls_desc(0x1000, 0xFFFFF).descriptor());
    // LDT selectors need an LDT
    assert!(!segments::loadable(0x7), "no LDT");
}

#[test]
fn no_gdt_means_nothing_loadable() {
    host::reset();
    host::set_cpu(15); // never given a GDT
    assert!(!segments::loadable(gdt::USER_DS));
    let (mut cs, mut ss, mut rip) = (gdt::USER32_CS as u64, (13 << 3 | 3) as u64, 0x400000);
    segments::sanitize_frame(&mut cs, &mut ss, &mut rip);
    assert_eq!((cs, ss, rip), (gdt::USER_CS as u64, gdt::USER_DS as u64, 0xFFFF_8000_0000_0000));
}

#[test]
fn sanitize_frame_rejects_bad_returns() {
    on_cpu(5);
    let check = |cs: u16, ss: u16, rip: u64| {
        let (mut c, mut s, mut r) = (cs as u64, ss as u64, rip);
        segments::sanitize_frame(&mut c, &mut s, &mut r);
        (c as u16, s as u16, r)
    };
    // Fine as they are
    assert_eq!(check(gdt::USER_CS, gdt::USER_DS, 0x7000_0000_0000), (gdt::USER_CS, gdt::USER_DS, 0x7000_0000_0000));
    assert_eq!(check(gdt::USER32_CS, gdt::USER_DS, 0xFFFF_FFFF), (gdt::USER32_CS, gdt::USER_DS, 0xFFFF_FFFF));
    // 32-bit code past 4 GiB, a kernel selector, a stack in a code segment: a faulting return
    let bad = (gdt::USER_CS, gdt::USER_DS, 0xFFFF_8000_0000_0000);
    assert_eq!(check(gdt::USER32_CS, gdt::USER_DS, 0x1_0000_0000), bad);
    assert_eq!(check(gdt::KERNEL_CS, gdt::USER_DS, 0x1000), bad);
    assert_eq!(check(gdt::USER_CS, gdt::USER_CS, 0x1000), bad, "code segment as stack");
    assert_eq!(check(gdt::USER_CS, gdt::KERNEL_DS, 0x1000), bad, "RPL 0 stack");
    // A writable data TLS descriptor is a good stack; a read-only one is not
    let mut s = UserSegs::default();
    segments::set_current_tls(&mut s, 12, tls_desc(0, 0xFFFFF).descriptor());
    assert_eq!(check(gdt::USER_CS, 12 << 3 | 3, 0x1000), (gdt::USER_CS, 12 << 3 | 3, 0x1000));
    let ro = UserDesc { read_exec_only: true, ..tls_desc(0, 0xFFFFF) };
    segments::set_current_tls(&mut s, 12, ro.descriptor());
    assert_eq!(check(gdt::USER_CS, 12 << 3 | 3, 0x1000), bad);
}

#[test]
fn context_switch_saves_and_loads_user_segments() {
    on_cpu(6);
    host::load_seg("ds", gdt::USER_DS);
    host::load_seg("fs", 0);
    host::wrmsr(0xC000_0102, 0x7777_0000);
    let mut a = UserSegs::default();
    segments::save(&mut a);
    assert_eq!((a.ds, a.es, a.fs, a.gs, a.gs_base), (gdt::USER_DS, 0, 0, 0, 0x7777_0000));

    // Thread B: a TLS selector in fs (its base comes from the descriptor), gs by MSR
    let mut b = UserSegs { fs: 13 << 3 | 3, gs_base: 0x5555_0000, ..Default::default() };
    b.tls[1] = tls_desc(0x8000, 0xFFFFF).descriptor();
    host::SEG_LOADS.with_borrow_mut(|l| l.clear());
    host::MSR_WRITES.with_borrow_mut(|l| l.clear());
    segments::load(&b, 0xF5, None);
    let g = unsafe { &(*gdt::CPU_GDT[6].load(std::sync::atomic::Ordering::Acquire)).0 };
    assert_eq!(&g[12..15], &b.tls, "TLS descriptors in the GDT");
    assert_eq!(host::read_seg("fs"), 13 << 3 | 3);
    assert_eq!(host::read_seg("ds"), 0, "ds 0 for B");
    let w = host::MSR_WRITES.with_borrow(|w| w.clone());
    assert!(!w.iter().any(|&(m, _)| m == 0xC000_0100), "fs base comes from the selector: {w:x?}");
    assert!(w.contains(&(0xC000_0102, 0x5555_0000)));

    // Back to A: fs null, so FS_BASE is written; an unloadable selector becomes null
    let a2 = UserSegs { es: 0x78 | 3, ..a };
    segments::load(&a2, 0x1234, None);
    assert_eq!(host::read_seg("fs"), 0);
    assert_eq!(host::read_seg("es"), 0, "bad selector dropped");
    assert_eq!(host::read_seg("ds"), gdt::USER_DS);
    assert_eq!(segments::current_bases(), (0x1234, 0x7777_0000));

    // Setting bases directly clears the selectors
    let mut s = UserSegs { fs: 13 << 3 | 3, gs: 13 << 3 | 3, ..Default::default() };
    host::load_seg("fs", 13 << 3 | 3);
    host::load_seg("gs", 13 << 3 | 3);
    segments::set_fs_base(&mut s, 0xAAAA);
    segments::set_gs_base(&mut s, 0xBBBB);
    assert_eq!((s.fs, s.gs, s.gs_base), (0, 0, 0xBBBB));
    assert_eq!((host::read_seg("fs"), host::read_seg("gs")), (0, 0));
    assert_eq!(segments::current_bases(), (0xAAAA, 0xBBBB));

    // A gs selector is loaded as is
    let c = UserSegs { gs: 13 << 3 | 3, tls: b.tls, ..Default::default() };
    segments::load(&c, 0, None);
    assert_eq!(host::read_seg("gs"), 13 << 3 | 3);

    segments::reset_current();
    assert_eq!(segments::current_bases(), (0, 0));
    assert_eq!(&g[12..15], &[0; 3]);
}

#[test]
fn ldt_install_and_refresh() {
    on_cpu(7);
    let holder: segments::SharedLdt = Arc::new(spin::Mutex::new(None));
    let mut entries = vec![0u64; 4].into_boxed_slice();
    let d = UserDesc { entry_number: 2, ..tls_desc(0x9000, 0xFFF) };
    entries[2] = d.descriptor();
    let ldt = Arc::new(Ldt::new(entries));
    let p = ldt.entries().as_ptr();
    // A thread holding the LDT selector of entry 2 in ds
    host::load_seg("ds", 2 << 3 | 4 | 3);
    segments::publish_ldt(&holder, ldt.clone(), 2);
    assert_eq!(host::read_seg("ldtr"), 10 << 3, "LDT selector loaded");
    let g = unsafe { &(*gdt::CPU_GDT[7].load(std::sync::atomic::Ordering::Acquire)).0 };
    let base = ((g[10] >> 16) & 0xFF_FFFF) | (((g[10] >> 56) & 0xFF) << 24) | (g[11] << 32);
    assert_eq!(base, p as u64, "system descriptor at entry 10 points at the table");
    assert_eq!(g[10] & 0xFFFF, 4 * 8 - 1, "limit");
    assert!(segments::loadable(2 << 3 | 4 | 3));
    assert!(!segments::loadable(5 << 3 | 4 | 3), "past the LDT");
    assert!(!segments::loadable(1 << 3 | 4 | 3), "empty entry");
    // ds was reloaded with the (now loadable) selector
    assert_eq!(host::read_seg("ds"), 2 << 3 | 4 | 3);

    // The same table again: nothing reloaded
    let loads = host::SEG_LOADS.with_borrow(|l| l.len());
    segments::load(&UserSegs { ds: 2 << 3 | 4 | 3, ..Default::default() }, 0, Some(&holder));
    assert_eq!(host::SEG_LOADS.with_borrow(|l| l.iter().skip(loads).filter(|e| e.0 == "ldtr").count()), 0);

    // Removing the entry: ds holding it falls back to null
    let ldt2 = Arc::new(Ldt::new(vec![0u64; 4].into_boxed_slice()));
    segments::publish_ldt(&holder, ldt2, 2);
    assert_eq!(host::read_seg("ds"), 0, "selector of a removed entry unloaded");
    // An empty table unloads the LDT
    segments::publish_ldt(&holder, Arc::new(Ldt::new(Vec::new().into_boxed_slice())), 0);
    assert_eq!(host::read_seg("ldtr"), 0);
    drop(ldt);
}

#[test]
fn ldt_memory_outlives_its_last_cpu() {
    // A table still loaded on a CPU is kept (RETIRED) when dropped, and freed only once no
    // CPU has it loaded: otherwise that CPU would read freed memory (a use after free of the
    // kind the wave 7 hang is about)
    on_cpu(8);
    let holder: segments::SharedLdt = Arc::new(spin::Mutex::new(None));
    let mut e = vec![0u64; 2].into_boxed_slice();
    e[1] = UserDesc { entry_number: 1, ..tls_desc(0, 0xFFF) }.descriptor();
    let ldt = Arc::new(Ldt::new(e));
    let p = ldt.entries().as_ptr();
    segments::publish_ldt(&holder, ldt, 1);
    // CPU 9 switches to a thread of the same process: it loads the same table
    host::set_cpu(9);
    gdt::load_for_ap(9);
    segments::load(&UserSegs::default(), 0, Some(&holder));
    assert!(segments::loadable(1 << 3 | 4 | 3));
    // CPU 8 replaces the table (modify_ldt): the old one is dropped while CPU 9 has it
    host::set_cpu(8);
    let fresh = Arc::new(Ldt::new(vec![0u64; 2].into_boxed_slice()));
    segments::publish_ldt(&holder, fresh, 1);
    // CPU 9 still reads the old memory, which must still hold the descriptor
    host::set_cpu(9);
    assert!(segments::loadable(1 << 3 | 4 | 3), "CPU 9's LDT memory still valid");
    assert_eq!(unsafe { *p.add(1) } >> 47 & 1, 1);
    // CPU 9 moves on; the retired table is then freed
    segments::reset_current();
    segments::collect_retired();
    assert!(!segments::loadable(1 << 3 | 4 | 3));
}

#[test]
fn cpu_state_reads_control_registers() {
    x86_64::hw::set_cr(0, 0x8001_0033);
    x86_64::hw::set_cr(2, 0xDEAD_BEEF);
    x86_64::hw::set_cr(3, 0x12_3000 | 0x5);
    x86_64::hw::set_cr(4, 0x6A0 | (1 << 17));
    let s = cpu::read_state();
    use x86_64::registers::control::{Cr0Flags, Cr4Flags};
    assert!(s.cr0.contains(Cr0Flags::PAGING | Cr0Flags::WRITE_PROTECT | Cr0Flags::PROTECTED_MODE_ENABLE));
    assert_eq!(s.cr2, 0xDEAD_BEEF);
    assert_eq!(s.cr3_frame.as_u64(), 0x12_3000);
    assert!(s.cr4.contains(Cr4Flags::PCID | Cr4Flags::PHYSICAL_ADDRESS_EXTENSION));
}

#[test]
fn debug_registers_follow_the_task() {
    host::reset();
    host::set_cpu(1);
    // A task without breakpoints after one without: nothing written
    debugregs::switch_to(&[0; 8]);
    assert_eq!(host::DR7_WRITES.get(), 0);
    // One with a breakpoint: DR7 off, addresses, DR7 on
    let dr = [0x1000, 0x2000, 0x3000, 0x4000, 0, 0, 0, 0x55];
    debugregs::switch_to(&dr);
    assert_eq!(host::DR.with_borrow(|d| *d), [0x1000, 0x2000, 0x3000, 0x4000, 0, 0, 0, 0x55]);
    assert_eq!(host::DR7_WRITES.get(), 2);
    // Then one without: DR7 cleared once, and only once
    debugregs::switch_to(&[0; 8]);
    assert_eq!(host::read_dr(7), 0);
    assert_eq!(host::DR7_WRITES.get(), 3);
    debugregs::switch_to(&[0; 8]);
    assert_eq!(host::DR7_WRITES.get(), 3);
    // A DR7 with only the high (condition) bits set enables nothing
    debugregs::switch_to(&[0, 0, 0, 0, 0, 0, 0, 0xF0000]);
    assert_eq!(host::DR7_WRITES.get(), 3);
    // DR6: read and cleared
    host::write_dr(6, 0x4001);
    assert_eq!(debugregs::take_dr6(), 0x4001);
    assert_eq!(debugregs::take_dr6(), 0);
}
