//! Regression test for the two-load whole-system hang (waves 5-6, fixed in wave 7, Group H).
//!
//! The invariant: **every way into the kernel's Rust code clears the direction flag.** Rust
//! (like the SysV and Win64 ABIs) assumes RFLAGS.DF = 0 at every call; the kernel's own
//! `memmove` copies overlapping data backwards with `std; rep movs; cld`, and user code may
//! set DF too. An interrupt keeps the interrupted DF, so an entry stub that does not `cld`
//! runs the whole handler and the scheduler with DF = 1: every `memcpy`/`memset` there copies
//! backwards, writing below its destination (freed heap data turned up in another thread's
//! kernel stack, both CPUs froze). The 2026-11-21 dump showed CPU 1 spinning in kernel mode
//! with RFLAGS = 0x486 (DF set).
//!
//! The entry stubs are assembly that cannot run on the host, so this test reads them: in
//! `src/arch/idt.rs` each label that calls into Rust must execute `cld` before the call, every
//! gate macro must go through the common handler, and `SYSCALL` must mask DF (IA32_FMASK).

const IDT: &str = include_str!("../../../src/arch/idt.rs");
const SYSCALL: &str = include_str!("../../../src/arch/syscall.rs");

/// The instruction lines of the assembly after the line `first` (trimmed) up to the first
/// line containing `until` (comments stripped, trimmed).
fn insns_between<'a>(src: &'a str, first: &str, until: &str) -> Vec<&'a str> {
    let start = src
        .lines()
        .position(|l| l.trim() == first)
        .unwrap_or_else(|| panic!("line {first} not found in the assembly"));
    let mut out = Vec::new();
    for line in src.lines().skip(start + 1) {
        let insn = line.split("//").next().unwrap().trim();
        if insn.contains(until) {
            return out;
        }
        if !insn.is_empty() {
            out.push(insn);
        }
    }
    panic!("{until} not found after {first}");
}

/// The first instruction after `label:` (so `cld` runs on every path, before any branch).
fn first_insn<'a>(src: &'a str, label: &str) -> &'a str {
    insns_between(src, &format!("{label}:"), "iretq")[0]
}

#[test]
fn common_trap_handler_clears_df_first() {
    assert_eq!(first_insn(IDT, "common_trap_handler"), "cld");
}

#[test]
fn direct_switch_clears_df_first() {
    assert_eq!(first_insn(IDT, "asm_direct_switch"), "cld");
}

#[test]
fn every_gate_macro_goes_through_the_common_handler() {
    for mac in ["TRAP_NO_ERRCODE", "TRAP_ERRCODE"] {
        let body = insns_between(IDT, &format!(".macro {mac} name, vec"), ".endm");
        assert_eq!(body.last(), Some(&"jmp common_trap_handler"), "{mac}: {body:?}");
    }
    // Every call in the file's assembly (any operand form: symbol, `{sym}`, register) is one of
    // the two checked above; a new entry stub must be added to these tests.
    let calls: Vec<&str> = IDT
        .lines()
        .map(|l| l.split("//").next().unwrap().trim())
        .filter(|l| l.starts_with("call ") || l.starts_with("callq "))
        .collect();
    assert_eq!(calls, ["call hydra_direct_switch_handler", "call hydra_exception_handler"]);
}

/// The files with assembly entry or copy code; a new one must be checked for `cld` and added.
#[test]
fn no_new_assembly_files() {
    fn walk(dir: &std::path::Path, out: &mut Vec<String>) {
        for e in std::fs::read_dir(dir).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                walk(&p, out);
            } else if p.extension().is_some_and(|x| x == "rs") {
                let t = std::fs::read_to_string(&p).unwrap();
                if t.contains("global_asm!") || t.contains("#[unsafe(naked)]") || t.contains("#[naked]") {
                    let root = concat!(env!("CARGO_MANIFEST_DIR"), "/../../src/");
                    let rel = p.strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/");
                    out.push(rel);
                }
            }
        }
    }
    let mut files = Vec::new();
    walk(std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../../src")), &mut files);
    files.sort();
    // smp.rs: the AP start code begins with `cld`; lx/copy.rs: user copies, called from Rust
    assert_eq!(files, ["arch/idt.rs", "arch/smp.rs", "arch/syscall.rs", "lx/copy.rs"]);
}

#[test]
fn syscall_entry_masks_df() {
    // init() writes IA32_FMASK from this literal (tests/syscalls.rs checks the write); both
    // lines must be live code, not comments
    let live: Vec<&str> = SYSCALL.lines().map(|l| l.split("//").next().unwrap().trim()).collect();
    assert!(live.contains(&"let fmask: u64 = 0x0004_4700;"));
    assert!(live.contains(&"wrmsr(IA32_FMASK, fmask);"));
    const DF: u64 = 1 << 10;
    assert_ne!(0x0004_4700u64 & DF, 0, "SYSCALL must clear DF");
}
