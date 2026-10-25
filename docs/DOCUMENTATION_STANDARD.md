# Hydra OS — Source Code Documentation Standard

- **Document Version**: 1.0.0
- **Scope**: All Rust source files (`src/**/*.rs`) across the entire Hydra OS codebase.
- **Engine Compatibility**: `rustdoc` (Rust 2021 Edition), Markdown (CommonMark), GitHub Flavored Markdown (GFM).
- **Primary Goal**: Ensure every module, type, function, and unsafe block is maximally understandable, self-explanatory, and accessible to both systems engineers and learners.

---

## 1. Core Philosophy: "Code Tells How, Docs Tell Why"

1. **Self-Explanatory Architecture**: Source code expresses the raw algorithmic logic; documentation articulates the **architectural intent**, **hardware constraints**, **invariants**, and **safety prerequisites**.
2. **Accessible Rigor**: Use clear, accessible English accompanied by intuitive systems analogies (e.g., capability tokens as security keycards, frame allocator as parking lot attendant), while maintaining absolute technical precision regarding bit masks, memory layouts, and register states.
3. **Rustdoc First**: All public items must compile cleanly into formatted HTML via `cargo doc` without broken links, unescaped HTML, or missing sections.
4. **No Trivial Comments**: Comments like `// sets the value` or `/// returns the id` are forbidden. Every doc comment must provide genuine insight beyond what the type signature already conveys.

---

## 2. Doc Comment Types & Scope

| Syntax | Target | Required Scope |
|---|---|---|
| `//!` | **Module / Crate Root** | Top of every file: subsystem role, architectural dependencies, dataflow. |
| `///` | **Types, Functions, Constants** | All `struct`, `enum`, `trait`, `fn`, `const`, `static`, and type aliases. |
| `//` | **Implementation Logic** | Complex internal algorithms, hardware errata workarounds, assembly rationale. |

---

## 3. Module-Level Documentation Standard (`//!`)

Every single `.rs` file **must begin** with an outer module-level documentation block (`//!`) structured as follows:

```rust
//! # Subsystem Name: High-Level Title
//!
//! Concise summary of the module's core responsibility in 1–2 sentences.
//!
//! ## Architectural Role & Design Rationale
//! Explanation of why this module exists, how it fits into the microkernel design,
//! and the problems it solves. Include real-world analogies where helpful.
//!
//! ## Key Types & Interfaces
//! - [`TypeName`](TypeName): Summary of primary structure.
//! - [`function_name()`]: Core public entry point.
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel) / Ring 3 (Userland)
//! - Hardware Interaction: I/O Ports, MSRs, MMIO, or Page Tables
//! - Concurrency: Lock-free atomics / `spin::Mutex` / Interrupt-safe
//!
//! ## Dataflow & Architectural Diagram (Optional but Strongly Encouraged)
//! ```text
//! +-------------+         +-------------+         +-------------+
//! | Input Stream | ------> | Pipe Buffer | ------> | File Output |
//! +-------------+         +-------------+         +-------------+
//! ```
```

---

## 4. Function & Method Documentation Standard

Every function (both `pub` and non-trivial `pub(crate)`/private functions) must adhere to the **Standard Section Pattern**:

```rust
/// Single-sentence summary written in the third-person imperative mood.
///
/// Multi-paragraph detailed explanation of the function's internal mechanism,
/// edge-case handling, and architectural side effects (e.g., changes to task state,
/// hardware interrupt flags, or memory page mappings).
///
/// # Arguments
///
/// * `param1` - Purpose, units (bytes, ticks, ms), valid range, and constraints.
/// * `param2` - Expected invariant or state requirement.
///
/// # Returns
///
/// Description of the return value. For `Option<T>` or `Result<T, E>`, explain
/// what `Some` / `None` or `Ok` / `Err` specifically signify in this context.
///
/// # Errors
///
/// Explicitly list all error conditions, negative errno values, and recovery steps:
/// - `-EBADF`: The provided file descriptor index was out of bounds or unopened.
/// - `-EMFILE`: The per-process file descriptor table is completely saturated.
///
/// # Panics
///
/// Explicitly state conditions that cause a panic, or guarantee:
/// - *Guaranteed to never panic under normal execution.*
///
/// # Safety
///
/// **MANDATORY FOR ALL `unsafe fn`!** State caller invariants:
/// 1. Pointer validity: Alignment, dereference bounds, and lifetime requirements.
/// 2. Interrupt context: Must interrupts be disabled (`CLI`) before invocation?
/// 3. Hardware state: Required CPU mode (e.g., 64-bit Long Mode, CR0.WP active).
///
/// # Examples
///
/// ```rust,no_run
/// let (read_fd, write_fd) = sys_pipe().expect("Failed to create pipe");
/// sys_write(write_fd, b"Hydra OS").unwrap();
/// ```
```

---

## 5. Struct, Enum, and Field Documentation Standard

### Structs
Every struct must explain its **lifecycle**, **ownership**, and **threading guarantees**:

```rust
/// Circular ring buffer implementing an anonymous unidirectional streaming pipe.
///
/// # Concurrency & Thread Safety
/// This structure is protected by a [`spin::Mutex`] and is safe to share
/// across threads via an [`Arc<Mutex<PipeBuffer>>`]. Read and write operations
/// acquire the lock briefly to copy bytes into or out of the internal array.
///
/// # Lifetime & Cleanup
/// When all reader file descriptors drop (`readers == 0`), subsequent write calls
/// return a Broken Pipe error (`-EPIPE`). When all writers drop (`writers == 0`),
/// subsequent reads return `0` bytes (EOF) once the internal buffer is drained.
pub struct PipeBuffer {
    /// Internal 4096-byte ring storage for unread stream payload.
    buffer: [u8; PIPE_BUFFER_SIZE],
    /// Ring index where next incoming byte will be written (head pointer).
    head: usize,
    /// Ring index where next available byte will be read (tail pointer).
    tail: usize,
    /// Total count of valid, unconsumed bytes currently residing in the ring.
    count: usize,
    /// Number of active reader file descriptors holding a reference to this pipe.
    readers: usize,
    /// Number of active writer file descriptors holding a reference to this pipe.
    writers: usize,
}
```

### Enums
Every enum and each individual variant must be documented:

```rust
/// Execution privilege level of an architectural thread/task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegeMode {
    /// Ring 0: Full hardware privilege with supervisor segment selectors (CS=0x08, SS=0x10).
    Kernel,
    /// Ring 3: Unprivileged userland execution with user segment selectors (CS=0x23, SS=0x1B).
    /// All hardware I/O and privileged instructions cause a General Protection Fault (#GP).
    User,
}
```

---

## 6. Rustdoc Formatting Rules & Intra-Doc Links

1. **Intra-Doc Links**: Always link to types using Rustdoc bracket syntax rather than raw markdown URLs:
   - `[`Task`](crate::task::Task)`
   - `[`PipeBuffer`](crate::fs::pipe::PipeBuffer)`
   - `[`SCHEDULER`](crate::task::scheduler::SCHEDULER)`
2. **Code Blocks**: Always provide a language specifier on triple-backtick blocks:
   - ````rust,no_run```` for Rust examples
   - ````text```` for ASCII diagrams
   - ````bash```` for shell commands
3. **Section Headings**: Use Markdown Level 1 (`# Section`) inside doc comments for standard sections (`# Arguments`, `# Returns`, `# Errors`, `# Safety`).

---

## 7. Concrete Examples: Good vs. Bad Documentation

### Example 1: Function Documentation

#### ❌ Bad Documentation (Lazy / Inadequate)
```rust
// duplicates a descriptor
pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
    // ...
}
```

#### ✅ Good Documentation (Standard-Compliant)
```rust
/// Duplicates an open file descriptor onto another index, closing the target if active.
///
/// Conforms to POSIX `dup2` semantics. If `oldfd == newfd` and `oldfd` is a valid open
/// descriptor, the function returns `Ok(newfd)` without closing. Otherwise, if `newfd`
/// is already open, it is closed before the clone of `oldfd` is installed.
///
/// If `oldfd` references an anonymous pipe, the associated pipe buffer's reader or writer
/// reference count is incremented accordingly.
///
/// # Arguments
///
/// * `oldfd` - The source file descriptor index (must be in `0..MAX_FDS` and open).
/// * `newfd` - The target file descriptor index to overwrite (must be in `0..MAX_FDS`).
///
/// # Returns
///
/// * `Ok(newfd)` - The new file descriptor index on successful duplication.
/// * `Err("Bad file descriptor (EBADF)")` - If either index is out of bounds or `oldfd` is closed.
///
/// # Errors
///
/// Returns an error if `oldfd >= 16`, `newfd >= 16`, or `fds[oldfd]` is `None`.
pub fn dup2(&mut self, oldfd: usize, newfd: usize) -> Result<usize, &'static str> {
    // ...
}
```

---

### Example 2: Unsafe Hardware Architecture Function

#### ❌ Bad Documentation
```rust
// switches cr3 page table
pub unsafe fn switch_cr3(phys_addr: u64) {
    // ...
}
```

#### ✅ Good Documentation (Standard-Compliant)
```rust
/// Loads a new physical base address into the CPU Control Register 3 (`CR3`).
///
/// Flushes the architectural Translation Lookaside Buffer (TLB) for all non-global
/// page mappings and immediately switches the active 4-level paging root to the
/// specified PML4 table.
///
/// # Arguments
///
/// * `phys_addr` - Physical address of the root PML4 table. Must be strictly 4 KiB aligned
///   (bits 0..11 must be zero).
///
/// # Safety
///
/// This function is inherently unsafe because writing an invalid address to `CR3`
/// causes an immediate Triple Fault and hardware CPU reboot. The caller must guarantee:
/// 1. `phys_addr` points to a valid, identity-mapped or kernel-accessible PML4 frame.
/// 2. The new page table identity-maps the executing code and stack frames.
/// 3. The address satisfies 4096-byte alignment (`phys_addr & 0xFFF == 0`).
///
/// # Hardware Registers
///
/// - Modifies: `CR3` (PDBR — Page Directory Base Register).
/// - Side Effects: Complete invalidation of CPU TLB entries (except those marked Global in PTE).
pub unsafe fn switch_cr3(phys_addr: u64) {
    // ...
}
```

---

## 8. Verification & Tooling Workflow

Documentation completeness is verified automatically as part of the continuous build:

1. **Local Documentation Generation**:
   ```bash
   cargo doc --no-deps --target x86_64-unknown-uefi
   ```
2. **Enforcing Warnings as Errors**:
   Add to crate root (`src/main.rs`):
   ```rust
   #![warn(missing_docs)]
   #![warn(rustdoc::broken_intra_doc_links)]
   ```
3. **PDF Generation Synchronization**:
   Whenever a new module is documented, ensure it is added to `DOCS_ORDER` in [`scripts/generate_docs_pdf.py`](file:///d:/os/scripts/generate_docs_pdf.py) so it renders into the publication PDF:
   ```bash
   python scripts/generate_docs_pdf.py
   ```
