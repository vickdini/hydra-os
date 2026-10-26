#!/usr/bin/env python3
"""
Hydra OS - Documentation PDF Generator
=======================================
Generates a comprehensive, professional PDF containing all documentation files,
ordered logically according to the system and kernel boot sequence.

Requirements:
- Python 3.8+
- markdown, pygments (auto-installed or fallback)
- Microsoft Edge, Google Chrome, or Chromium (headless PDF engine)
"""

import sys
import os
import re
import shutil
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

# Try importing markdown and pygments
try:
    import markdown
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "markdown"], check=True)
    import markdown

try:
    from pygments.formatters import HtmlFormatter
except ImportError:
    subprocess.run([sys.executable, "-m", "pip", "install", "pygments"], check=True)
    from pygments.formatters import HtmlFormatter

# Base Directory of the repository
REPO_ROOT = Path(__file__).resolve().parent.parent

# Boot sequence topic ordering
DOCS_ORDER = [
    {
        "stage": "System Overview",
        "title": "Architecture Overview & Codebase Index",
        "file": "docs/README.md",
        "anchor": "doc-overview-index",
        "subtitle": "Microkernel architecture overview, directory map, and concept analogies.",
    },
    {
        "stage": "System Overview",
        "title": "Source Code Documentation Standard",
        "file": "docs/src/doc_standard.md",
        "anchor": "doc-standards",
        "subtitle": "Rustdoc specification, section headers (Safety, Panics, Errors), intra-doc links, and code comment conventions.",
    },
    {
        "stage": "Build & Toolchain",
        "title": "Build Automation & Toolchain Configuration",
        "file": "docs/build.md",
        "anchor": "doc-build-toolchain",
        "subtitle": "NASM assembly compiler script, DWARF debug symbols, and UEFI build settings.",
    },
    {
        "stage": "Stage 0: Firmware Handoff",
        "title": "Legacy BIOS Boot Trampoline & Long Mode Switch",
        "file": "docs/src/arch/x86_64/boot.md",
        "anchor": "doc-boot-stage0",
        "subtitle": "Multiboot2 header, CPUID validation, PAE identity paging, and 32-to-64-bit transition.",
    },
    {
        "stage": "Stage 1: Kernel Entry Point",
        "title": "UEFI Entry Point & Bootstrap Orchestrator",
        "file": "docs/src/main.md",
        "anchor": "doc-boot-stage1",
        "subtitle": "Native UEFI application entry point, system table access, panic handler, and main sequence.",
    },
    {
        "stage": "Stage 2: Early Diagnostics",
        "title": "UEFI Console & Thread-Safe Output",
        "file": "docs/src/console.md",
        "anchor": "doc-boot-stage2",
        "subtitle": "Bare-metal formatting macros, spinlock mutex synchronization, and UEFI SimpleTextOutput.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "Architecture Abstraction Layer",
        "file": "docs/src/arch/mod.md",
        "anchor": "doc-boot-stage3-mod",
        "subtitle": "Hardware isolation layer separating processor specifics from microkernel core.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "Global Descriptor Table (GDT) & TSS",
        "file": "docs/src/arch/gdt.md",
        "anchor": "doc-boot-stage3-gdt",
        "subtitle": "Privilege levels (Ring 0 / Ring 3), Task State Segment, and Double Fault IST stack.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "Interrupt Descriptor Table (IDT) & Hardware Exceptions",
        "file": "docs/src/arch/idt.md",
        "anchor": "doc-boot-stage3-idt",
        "subtitle": "256-gate IDT, assembly exception trampolines, IST double fault isolation, and #BP/#PF dispatchers.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "8259 Programmable Interrupt Controller (PIC)",
        "file": "docs/src/arch/pic.md",
        "anchor": "doc-boot-stage3-pic",
        "subtitle": "Dual-PIC architecture, IRQ remapping (vectors 32..47), cascade configuration, and EOI handling.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "8254 Programmable Interval Timer (PIT)",
        "file": "docs/src/arch/pit.md",
        "anchor": "doc-boot-stage3-pit",
        "subtitle": "Hardware timer clock, Mode 3 square wave generator at 100 Hz, tick counter, and low-power CPU halts.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "8042 PS/2 Keyboard Controller & Input Buffer",
        "file": "docs/src/arch/keyboard.md",
        "anchor": "doc-boot-stage3-keyboard",
        "subtitle": "Scancode Set 1 decoder, interrupt-driven circular ring buffer, modifier tracking, and sleep waits.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "Hardware Takeover & ExitBootServices",
        "file": "docs/src/arch/boot_services.md",
        "anchor": "doc-boot-stage3-takeover",
        "subtitle": "Terminating firmware control, reloading GDT/TSS, autonomous CR3 PML4, and 8042 PS/2 keyboard.",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "CPU Control Registers & Diagnostics",
        "file": "docs/src/arch/cpu.md",
        "anchor": "doc-boot-stage3-cpu",
        "subtitle": "Control register inspection (CR0 protection, CR2 fault address, CR3 PML4 root, CR4).",
    },
    {
        "stage": "Stage 3: CPU Architecture",
        "title": "Hardware System Calls & Ring 3 User Mode",
        "file": "docs/src/arch/syscall.md",
        "anchor": "doc-boot-stage3-syscall",
        "subtitle": "Fast syscall/sysretq MSRs, asm_syscall_entry trampoline, TSS RSP0, and fault isolation.",
    },
    {
        "stage": "Stage 4: Memory Subsystem",
        "title": "Memory Subsystem Coordinator",
        "file": "docs/src/memory/mod.md",
        "anchor": "doc-boot-stage4-mod",
        "subtitle": "Coordinator binding physical frame management and virtual memory translation.",
    },
    {
        "stage": "Stage 4: Memory Subsystem",
        "title": "Physical Memory Discovery & Frame Allocator",
        "file": "docs/src/memory/frame_allocator.md",
        "anchor": "doc-boot-stage4-frame",
        "subtitle": "UEFI memory map parser, 1 MiB low memory reservation, and 4 KiB frame allocator.",
    },
    {
        "stage": "Stage 4: Memory Subsystem",
        "title": "Dynamic Kernel Heap & Global Allocator",
        "file": "docs/src/memory/heap.md",
        "anchor": "doc-boot-stage4-heap",
        "subtitle": "8 MiB dynamic heap allocator, #[global_allocator] implementation, and Rust alloc integration.",
    },
    {
        "stage": "Stage 5: Virtual Memory",
        "title": "4-Level Paging & Address Translation",
        "file": "docs/src/memory/paging.md",
        "anchor": "doc-boot-stage5-paging",
        "subtitle": "4-level x86_64 PML4 hierarchy, virtual address translation, and 2 MiB / 1 GiB huge pages.",
    },
    {
        "stage": "Stage 6: Security & Capabilities",
        "title": "Capability Security Model & Rights",
        "file": "docs/src/capability/mod.md",
        "anchor": "doc-boot-stage6-cap-mod",
        "subtitle": "Object-capability security tokens, Rights bitflags, and CapType kernel resource identifiers.",
    },
    {
        "stage": "Stage 6: Security & Capabilities",
        "title": "Task Capability Space & Table Management",
        "file": "docs/src/capability/table.md",
        "anchor": "doc-boot-stage6-cap-table",
        "subtitle": "Per-task CSpace table, 256-slot fixed array storage, rights verification, and revocation.",
    },
    {
        "stage": "Stage 7: IPC Subsystem",
        "title": "Inter-Process Communication Overview",
        "file": "docs/src/ipc/mod.md",
        "anchor": "doc-boot-stage7-ipc-mod",
        "subtitle": "Microkernel message passing coordinating isolated userland services.",
    },
    {
        "stage": "Stage 7: IPC Subsystem",
        "title": "Fast Register Messages & Delegation",
        "file": "docs/src/ipc/message.md",
        "anchor": "doc-boot-stage7-ipc-msg",
        "subtitle": "Fast 4-word inline register payload, protocol labels, and transferred capability tokens.",
    },
    {
        "stage": "Stage 7: IPC Subsystem",
        "title": "Rendezvous Channels & Endpoints",
        "file": "docs/src/ipc/endpoint.md",
        "anchor": "doc-boot-stage7-ipc-ep",
        "subtitle": "Circular FIFO ring buffers, rendezvous mailboxes, and thread-safe SharedEndpoint.",
    },
    {
        "stage": "Stage 8: File Server & Storage",
        "title": "ATA / IDE PIO Hard Disk Block Driver",
        "file": "docs/src/arch/ata.md",
        "anchor": "doc-boot-stage8-ata",
        "subtitle": "Legacy PC/AT I/O port command blocks (0x1F0/0x3F6), polled PIO transfers, and hardware persistent vdev.",
    },
    {
        "stage": "Stage 8: File Server & Storage",
        "title": "ZFS Microkernel File Server Architecture",
        "file": "docs/src/zfs.md",
        "anchor": "doc-boot-stage8-zfs",
        "subtitle": "Microkernel ZFS File Server (Endpoint 0x20), CoW Merkle tree, Fletcher-4 checksums, and datasets.",
    },

    {
        "stage": "Stage 8: File Server & Storage",
        "title": "Unix File Descriptor Table & Shell Pipelines",
        "file": "docs/src/vfs.md",
        "anchor": "doc-boot-stage8-vfs",
        "subtitle": "POSIX file descriptors (0..15), anonymous pipes (PipeBuffer), I/O redirection, and shell pipeline chains.",
    },
    {
        "stage": "Stage 8b: Hardware Video & Framebuffer",
        "title": "Hardware Video Driver & Framebuffer Console",
        "file": "docs/src/video.md",
        "anchor": "doc-boot-stage8b-video",
        "subtitle": "UEFI GOP linear framebuffer discovery, 8x16 bitmap font, and autonomous pixel console.",
    },
    {
        "stage": "Stage 8c: Graphical Desktop & Wayland",
        "title": "Wayland Compositor & KDE Plasma Desktop Shell",
        "file": "docs/src/video/wayland_plasma.md",
        "anchor": "doc-boot-stage8c-plasma",
        "subtitle": "Double-buffered 32-bit compositor, PS/2 mouse driver, Breeze theme engine, Konsole, and KSysGuard.",
    },
    {
        "stage": "Stage 8d: Network Subsystem",
        "title": "Intel E1000 Gigabit NIC Driver & Network Stack",
        "file": "docs/src/net/mod.md",
        "anchor": "doc-boot-stage8d-net",
        "subtitle": "Intel 82540EM DMA controller, Ethernet II, ARP cache, IPv4, ICMP ping, DHCP client, and HTTP/1.0 downloader.",
    },
    {
        "stage": "Stage 9: Multitasking & Scheduler",
        "title": "Task Control Block (TCB) & Thread State",
        "file": "docs/src/task/tcb.md",
        "anchor": "doc-boot-stage9-tcb",
        "subtitle": "TCB architecture, register frame (TaskRegisters), lifecycle state machine, and heap stacks.",
    },
    {
        "stage": "Stage 9: Multitasking & Scheduler",
        "title": "Preemptive Multitasking & Context Switching",
        "file": "docs/src/task/scheduler.md",
        "anchor": "doc-boot-stage9-scheduler",
        "subtitle": "Round-robin timeslicing at 100 Hz, iretq context switching, idle task, and task commands (ps, spawn, kill).",
    },
    {
        "stage": "Stage 9: Multitasking & Scheduler",
        "title": "Synchronization Primitives & Wait Queues",
        "file": "docs/src/sync.md",
        "anchor": "doc-boot-stage9-sync",
        "subtitle": "TaskState::Blocked wait queues, sleep Mutex, Semaphore, CondVar, and blocking rendezvous IPC.",
    },
    {
        "stage": "Stage 9: Multitasking & Scheduler",
        "title": "Userspace ELF64 Binary Loader & Execution",
        "file": "docs/src/task/elf.md",
        "anchor": "doc-boot-stage9-elf",
        "subtitle": "Parsing standalone ELF64 binaries from ZFS, PIE relocation, Ring 3 memory mapping, and syscall execution.",
    },
    {
        "stage": "Stage 10: Interactive Shell",
        "title": "Interactive Microkernel Shell & Command REPL",
        "file": "docs/src/shell.md",
        "anchor": "doc-boot-stage10-shell",
        "subtitle": "Command REPL, real-time memory/CPU inspection, CSpace manipulation, ZFS commands, and IPC testing.",
    },
    {
        "stage": "Stage 11: Linux Compatibility (ABI Layer)",
        "title": "Linux Binary Compatibility Subsystem",
        "file": "docs/src/compat/linux.md",
        "anchor": "doc-boot-stage11-linux",
        "subtitle": "Direct x86_64 Linux system call emulation, MSR IA32_FS_BASE TLS management, Auxv stack setup, and POSIX pseudo-files.",
    },
]


# Map of relative file paths to their anchor IDs for internal links
FILE_TO_ANCHOR = {item["file"]: item["anchor"] for item in DOCS_ORDER}

def rewrite_internal_links(content: str, current_file: str) -> str:
    """Rewrite links to other docs to internal anchor links."""
    def replace_link(match):
        text = match.group(1)
        url = match.group(2)
        
        # Remove file:/// prefix or Windows drive letters if present
        cleaned_url = re.sub(r"^file:///[a-zA-Z]:[\\/]", "", url)
        cleaned_url = cleaned_url.replace("\\", "/")

        for doc_file, anchor in FILE_TO_ANCHOR.items():
            if cleaned_url.endswith(doc_file) or cleaned_url == doc_file:
                return f"[{text}](#{anchor})"
            # Also handle relative paths like ../arch/gdt.md
            if Path(doc_file).name in cleaned_url and cleaned_url.endswith(".md"):
                return f"[{text}](#{anchor})"
                
        return match.group(0)

    return re.sub(r"\[([^\]]+)\]\(([^)]+)\)", replace_link, content)

def render_markdown(md_content: str) -> str:
    """Render markdown with extensions for tables, code highlighting, and TOC."""
    extensions = [
        "markdown.extensions.tables",
        "markdown.extensions.fenced_code",
        "markdown.extensions.codehilite",
        "markdown.extensions.sane_lists",
    ]
    extension_configs = {
        "markdown.extensions.codehilite": {
            "css_class": "codehilite",
            "linenums": False,
            "guess_lang": True,
        }
    }
    return markdown.markdown(md_content, extensions=extensions, extension_configs=extension_configs)

def find_browser_executable() -> str:
    """Find a headless Chromium-based browser (Edge, Chrome, Chromium) for printing to PDF."""
    candidates = [
        # Windows Edge
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        # Windows Chrome
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        # Windows Brave
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        # Linux / WSL
        shutil.which("msedge"),
        shutil.which("google-chrome"),
        shutil.which("google-chrome-stable"),
        shutil.which("chromium"),
        shutil.which("chromium-browser"),
    ]
    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK if os.name != 'nt' else os.F_OK):
            return candidate
    return None

def build_html_document(sections_html: list) -> str:
    """Combine rendered sections into a single styled HTML document."""
    pygments_css = HtmlFormatter(style="friendly").get_style_defs(".codehilite")

    # Generate Table of Contents HTML
    toc_items = []
    current_stage = None
    for item in DOCS_ORDER:
        if item["stage"] != current_stage:
            current_stage = item["stage"]
            toc_items.append(f'<li class="toc-stage-header">{current_stage}</li>')
        toc_items.append(
            f'<li class="toc-item"><a href="#{item["anchor"]}" class="toc-link">'
            f'<span class="toc-title">{item["title"]}</span>'
            f'<span class="toc-sub">{item["subtitle"]}</span>'
            f'</a></li>'
        )
    toc_html = "\n".join(toc_items)

    sections_combined = "\n\n".join(sections_html)

    now_str = datetime.now().strftime("%B %d, %Y")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Hydra OS - Technical Architecture & Documentation Manual</title>
<style>
/* Page & Print Setup */
@page {{
    size: A4;
    margin: 20mm 15mm 20mm 15mm;
    @top-right {{
        content: "Hydra Microkernel OS";
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 8pt;
        color: #718096;
    }}
    @bottom-center {{
        content: counter(page);
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
        font-size: 9pt;
        color: #4a5568;
    }}
}}

body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    color: #1a202c;
    background-color: #ffffff;
    line-height: 1.6;
    font-size: 10.5pt;
    margin: 0;
    padding: 0;
}}

/* Cover Page */
.cover-page {{
    page-break-after: always;
    height: 90vh;
    display: flex;
    flex-direction: column;
    justify-content: center;
    align-items: center;
    text-align: center;
    padding: 40px 20px;
    border: 2px solid #2b6cb0;
    border-radius: 12px;
    background: linear-gradient(135deg, #f7fafc 0%, #edf2f7 100%);
    box-sizing: border-box;
}}

.cover-badge {{
    display: inline-block;
    background: #2b6cb0;
    color: white;
    font-size: 9pt;
    font-weight: 700;
    padding: 6px 16px;
    border-radius: 20px;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    margin-bottom: 24px;
}}

.cover-title {{
    font-size: 34pt;
    font-weight: 800;
    color: #1a365d;
    margin: 0 0 12px 0;
    letter-spacing: -1px;
}}

.cover-subtitle {{
    font-size: 15pt;
    color: #4a5568;
    max-width: 650px;
    margin: 0 auto 30px auto;
    font-weight: 400;
}}

.cover-meta {{
    font-size: 10pt;
    color: #718096;
    margin-top: 40px;
    line-height: 1.8;
}}

.cover-meta strong {{
    color: #2d3748;
}}

.cover-flow {{
    margin-top: 35px;
    padding: 15px 25px;
    background: white;
    border-radius: 8px;
    border: 1px solid #e2e8f0;
    font-size: 9pt;
    color: #2b6cb0;
    font-family: monospace;
}}

/* Table of Contents */
.toc-section {{
    page-break-before: always;
    page-break-after: always;
    padding: 20px 0;
}}

.toc-heading {{
    font-size: 22pt;
    font-weight: 700;
    color: #1a365d;
    border-bottom: 2px solid #2b6cb0;
    padding-bottom: 8px;
    margin-bottom: 20px;
}}

.toc-list {{
    list-style: none;
    padding-left: 0;
    margin: 0;
}}

.toc-stage-header {{
    font-weight: 700;
    font-size: 11pt;
    color: #2b6cb0;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    margin-top: 18px;
    margin-bottom: 6px;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 4px;
}}

.toc-item {{
    margin: 6px 0;
    padding-left: 12px;
}}

.toc-link {{
    text-decoration: none;
    color: #2d3748;
    display: flex;
    justify-content: space-between;
    align-items: baseline;
}}

.toc-link:hover {{
    color: #2b6cb0;
}}

.toc-title {{
    font-weight: 600;
    font-size: 10.5pt;
}}

.toc-sub {{
    font-size: 9pt;
    color: #718096;
    font-style: italic;
    margin-left: 15px;
}}

/* Document Sections */
.doc-section {{
    page-break-before: always;
    margin-top: 20px;
}}

.section-stage-badge {{
    display: inline-block;
    background: #edf2f7;
    color: #2b6cb0;
    font-size: 8.5pt;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 8px;
    border: 1px solid #cbd5e0;
}}

/* Typography */
h1, h2, h3, h4, h5, h6 {{
    color: #1a365d;
    font-weight: 700;
    page-break-after: avoid;
    margin-top: 1.2em;
    margin-bottom: 0.5em;
}}

h1 {{
    font-size: 20pt;
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 6px;
}}

h2 {{
    font-size: 14pt;
    border-bottom: 1px solid #edf2f7;
    padding-bottom: 4px;
}}

h3 {{
    font-size: 12pt;
}}

p {{
    margin-top: 0;
    margin-bottom: 1em;
    text-align: justify;
}}

a {{
    color: #2b6cb0;
    text-decoration: none;
}}

a:hover {{
    text-decoration: underline;
}}

/* Code Blocks */
pre, code {{
    font-family: "Cascadia Code", "Fira Code", "Source Code Pro", Consolas, "Courier New", monospace;
}}

code {{
    background-color: #f7fafc;
    color: #b83280;
    padding: 2px 6px;
    border-radius: 4px;
    font-size: 9pt;
    border: 1px solid #e2e8f0;
}}

pre {{
    background-color: #f7fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 16px;
    overflow-x: auto;
    font-size: 8.5pt;
    line-height: 1.45;
    page-break-inside: avoid;
}}

pre code {{
    background-color: transparent;
    padding: 0;
    border: none;
    color: inherit;
}}

/* Tables */
table {{
    width: 100%;
    border-collapse: collapse;
    margin: 16px 0;
    font-size: 9.5pt;
    page-break-inside: avoid;
}}

th, td {{
    padding: 8px 12px;
    border: 1px solid #e2e8f0;
    text-align: left;
}}

th {{
    background-color: #f7fafc;
    font-weight: 700;
    color: #2d3748;
}}

tr:nth-child(even) {{
    background-color: #fafaf9;
}}

/* Blockquotes / Alerts */
blockquote {{
    border-left: 4px solid #2b6cb0;
    margin: 16px 0;
    padding: 10px 16px;
    background-color: #ebf8ff;
    color: #2d3748;
    border-radius: 0 6px 6px 0;
}}

blockquote p:last-child {{
    margin-bottom: 0;
}}

/* Diagrams and Preformatted ASCII */
pre.ascii-diagram {{
    background: #2d3748;
    color: #e2e8f0;
    font-weight: bold;
    border: 1px solid #1a202c;
}}

/* Pygments Syntax Highlighting */
{pygments_css}
</style>
</head>
<body>

<!-- Cover Page -->
<div class="cover-page">
    <div class="cover-badge">Microkernel Architecture Manual</div>
    <div class="cover-title">HYDRA OS</div>
    <div class="cover-subtitle">UNIX-like Distributed Microkernel for Modern UEFI Hardware</div>
    
    <div class="cover-flow">
        BOOT SEQUENCE PIPELINE<br>
        UEFI POST &rarr; GDT/TSS &rarr; CPU Diagnostics &rarr; Frame Allocator &rarr; PML4 Paging &rarr; Capability Space &rarr; IPC Rendezvous
    </div>

    <div class="cover-meta">
        <strong>Edition:</strong> v0.1.0 Architecture Specification<br>
        <strong>Target Architecture:</strong> x86_64-unknown-uefi (Native 64-bit Long Mode)<br>
        <strong>Security Model:</strong> Capability-Based Access Control (seL4-style)<br>
        <strong>IPC Subsystem:</strong> Synchronous &amp; Asynchronous Message Rendezvous<br>
        <strong>Generated:</strong> {now_str}
    </div>
</div>

<!-- Table of Contents -->
<div class="toc-section">
    <div class="toc-heading">Table of Contents &mdash; Boot Sequence Topics</div>
    <ul class="toc-list">
        {toc_html}
    </ul>
</div>

<!-- Body Sections -->
{sections_combined}

</body>
</html>
"""
    return html

def main():
    import argparse
    parser = argparse.ArgumentParser(description="Generate Hydra OS Documentation PDF ordered by boot sequence.")
    parser.add_argument("--output", "-o", default=str(REPO_ROOT / "docs" / "Hydra_OS_Documentation.pdf"),
                        help="Path to output PDF file")
    parser.add_argument("--html-only", action="store_true",
                        help="Only generate HTML document, do not invoke browser for PDF")
    parser.add_argument("--browser", default=None,
                        help="Path to headless Chromium/Edge browser executable")
    args = parser.parse_args()

    output_pdf = Path(args.output).resolve()
    output_html = output_pdf.with_suffix(".html")
    output_pdf.parent.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print(" Hydra OS - Boot Sequence Documentation PDF Generator")
    print("=" * 60)
    print(f"[*] Repository root: {REPO_ROOT}")
    print(f"[*] Processing {len(DOCS_ORDER)} documentation modules...")

    sections_html = []

    for idx, item in enumerate(DOCS_ORDER, 1):
        rel_path = item["file"]
        file_path = REPO_ROOT / rel_path

        if not file_path.is_file():
            print(f"[!] Warning: File not found: {file_path}")
            continue

        print(f"    [{idx:02d}/{len(DOCS_ORDER):02d}] Including: {rel_path} ({item['stage']})")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Rewrite internal links
        content = rewrite_internal_links(content, rel_path)

        # Render markdown to HTML
        rendered = render_markdown(content)

        # Wrap in section div
        section_wrapped = f"""
<div id="{item['anchor']}" class="doc-section">
    <div class="section-stage-badge">{item['stage']} &bull; Boot Sequence Order #{idx:02d}</div>
    {rendered}
</div>
"""
        sections_html.append(section_wrapped)

    print("[*] Assembling unified HTML document with print styling...")
    html_doc = build_html_document(sections_html)

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html_doc)
    print(f"[+] HTML written to: {output_html}")

    if args.html_only:
        print("[+] HTML-only mode specified. Done.")
        return 0

    browser_bin = args.browser or find_browser_executable()
    if not browser_bin:
        print("[!] Headless browser not found (Edge/Chrome/Chromium).")
        print(f"[!] The HTML document was successfully created at {output_html}.")
        print("[!] You can open it in any browser and use 'Print to PDF'.")
        return 1

    print(f"[*] Headless browser found: {browser_bin}")
    print(f"[*] Rendering PDF via headless browser...")

    with tempfile.TemporaryDirectory() as temp_dir:
        cmd = [
            browser_bin,
            "--headless",
            "--disable-gpu",
            f"--user-data-dir={temp_dir}",
            "--no-pdf-header-footer",
            f"--print-to-pdf={str(output_pdf)}",
            str(output_html.as_uri()),
        ]

        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if output_pdf.is_file() and output_pdf.stat().st_size > 0:
        pdf_size_kb = output_pdf.stat().st_size / 1024
        print("=" * 60)
        print(f"[+] SUCCESS! Documentation PDF successfully generated:")
        print(f"    Path: {output_pdf}")
        print(f"    Size: {pdf_size_kb:.1f} KiB")
        print("=" * 60)

        # Also copy to dist directory if dist exists
        dist_dir = REPO_ROOT / "dist"
        if dist_dir.is_dir():
            dist_pdf = dist_dir / "Hydra_OS_Documentation.pdf"
            shutil.copyfile(output_pdf, dist_pdf)
            print(f"[+] Also mirrored to: {dist_pdf}")

        return 0
    else:
        print(f"[!] PDF generation failed. Error code: {result.returncode}")
        print(f"Stderr: {result.stderr}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
