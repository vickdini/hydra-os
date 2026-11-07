# Hydra: Design and Implementation

> *A Modern Microkernel Operating System in Rust*  
> Inspired by the classic textbook **Operating Systems: Design and Implementation** by Andrew S. Tanenbaum.

---

## Overview

This repository holds the complete LaTeX source for the textbook **"Hydra: Design and Implementation"**. It follows the pedagogical structure of Tanenbaum's MINIX book, modernized for the 2020s with:

1. **Memory-Safe Systems Programming in Rust:** Eliminating buffer overflows, use-after-free, and data races in Ring 0.
2. **64-bit Microkernel Architecture (x86_64 Long Mode & UEFI):** Preemptive scheduling, task control blocks, and high-performance synchronous rendezvous IPC.
3. **Enterprise OpenZFS Storage Engine:** Pool-based storage (`hydrapool`), 32-slot Uberblock Ring, Merkle-tree integrity checks (Fletcher-4), and crash-consistent Copy-on-Write (CoW) transactions.
4. **Ring 3 Isolated Driver Architecture:** Hardware drivers (ATA DMA, Intel 82540EM Gigabit NIC, DRM/KMS Display Server) running as unprivileged user-space processes.
5. **Full Linux Binary Compatibility Subsystem:** Hardware `SYSCALL`/`SYSRET` dispatching, POSIX credentials, virtual filesystems (`/proc`, `/sys`, `/dev`), and the ability to run **SDDM, KWin Wayland, KDE Plasma 6, and the Brave Web Browser** unmodified on bare metal.

---

## Directory Structure

```
book/
├── Makefile                          # Build targets: all, pdf, clean, watch
├── main.tex                          # Master document
├── preamble.tex                      # Typography, packages, TikZ styles, Rust listings
├── references.bib                    # Academic and technical bibliography
├── frontmatter/
│   ├── titlepage.tex                 # Title page with microkernel diagram
│   ├── dedication.tex                # Dedication to Andrew S. Tanenbaum
│   └── preface.tex                   # Motivation, history, and scope
├── chapters/
│   ├── 01_introduction.tex           # Ch 1: OS Concepts, Microkernel vs Monolithic
│   ├── 02_processes_and_threads.tex  # Ch 2: Process Model, Context Switching, IPC
│   ├── 03_memory_management.tex      # Ch 3: 4-Level Paging, Frame Allocator, CoW
│   ├── 04_file_systems_zfs.tex       # Ch 4: OpenZFS Deep Dive, TXGs, Dnodes
│   ├── 05_io_and_device_drivers.tex  # Ch 5: Bus-Master DMA, Driver Isolation
│   ├── 06_network_subsystem.tex      # Ch 6: Intel E1000, Protocol Pipeline, TCP/IP
│   ├── 07_linux_compatibility.tex    # Ch 7: Linux ABI, Wayland, KDE Plasma 6
│   ├── 08_security_and_capabilities.tex # Ch 8: Capabilities, Least Privilege, Rust
│   └── 09_source_code_tour.tex       # Ch 9: Annotated Walkthrough of Hydra Code
└── appendices/
    ├── app_a_building_and_running.tex    # App A: Toolchains, ISO Packaging, VM Setup
    ├── app_b_syscall_reference.tex       # App B: Linux Syscall Table in Hydra
    └── app_c_hardware_cheatsheet.tex     # App C: x86_64 Registers, MSRs, and CRs
```

---

## Compiling the Book

### Using `make` (Linux / macOS / WSL)
```bash
cd book
make pdf
```

### Using `latexmk`
```bash
latexmk -pdf -synctex=1 main.tex
```

### Using Overleaf / TeX Live / MiKTeX
Simply open or upload the `book/` directory to Overleaf or open `main.tex` in TeXstudio / VS Code with LaTeX Workshop. Set `main.tex` as the root document.
