# Interactive Microkernel Shell Documentation

- **Source Directory**: [`src/shell/`](file:///d:/os/src/shell/)
- **Subsystem**: Microkernel User Interface & Command REPL

---

## 1. Conceptual Overview

Operating system development often starts with non-interactive boot routines that print diagnostic logs and halt. To enable active exploration, debugging, and experimentation with kernel primitives on live hardware or virtual machines, Hydra provides an **Interactive Microkernel Shell**.

The shell is architected as a modular, extensible command registry where every command or tool lives in its own dedicated source file:

```
src/shell/
├── mod.rs                  # REPL loop, banner, prompt formatting, and command dispatcher
├── state.rs                # ShellState (CSpace, IPC endpoint, prompt color, cwd, history)
├── command.rs              # The `Command` trait and argument parsing helpers
├── editor.rs               # Interactive line editor (history cycling, tab completion, arrow keys)
├── history.rs              # Command history ring buffer (32 entries)
└── commands/               # Modular Command Implementations
    ├── mod.rs              # Static command registry (`COMMANDS`)
    ├── gnu_fs.rs           # GNU Filesystem utils (`pwd`, `cd`, `mkdir`, `rmdir`, `rm`, `cp`, `mv`, `touch`, `stat`, `df`, `du`)
    ├── gnu_text.rs         # GNU Text inspection (`head`, `tail`, `wc`, `grep`, `basename`, `dirname`)
    ├── gnu_sys.rs          # GNU System & scripting (`uname`, `whoami`, `sleep`, `seq`, `yes`, `true`, `false`)
    ├── fs_cmds.rs          # File operations (`ls`, `cat`, `write`)
    ├── history_cmd.rs      # Session history viewer (`history`)
    ├── script.rs           # Bash / POSIX script runner (`sh`, `source`, `.`)
    ├── help.rs             # Help command & usage manual generator
    ├── info.rs             # OS version & architecture overview (`info`, `version`)
    ├── status.rs           # Subsystem health inspection
    ├── cpu.rs              # CPU control registers (`cpu`)
    ├── mem.rs              # Memory statistics & allocation (`mem`, `alloc`)
    ├── translate.rs        # Virtual-to-physical paging translation (`translate`)
    ├── caps.rs             # CSpace inspection & revocation (`caps`, `cap_insert`, `cap_revoke`)
    ├── ipc.rs              # Microkernel message rendezvous (`ipc`)
    ├── time.rs             # Real-Time Clock (`time`, `date`)
    ├── power.rs            # ACPI/UEFI power management (`shutdown`, `reboot`, `halt`)
    ├── zfs_cmds.rs         # OpenZFS administration (`zpool`, `zfs`)
    ├── efifs.rs            # Low-level UEFI FAT boot volume diagnostics (`efifs`)
    └── misc.rs             # Utilities (`color`, `echo`, `clear`, `panic`)
```

### Zsh-Style Interactive Line Editor & History
The shell includes an interactive line editor (`editor.rs`):
- **Up / Down Arrow History Navigation**: Traverses the command history buffer (`history.rs`). Pressing <kbd>&uarr;</kbd> recalls previously entered commands, while <kbd>&darr;</kbd> cycles forward or restores the typed draft line.
- **Tab Auto-Completion (Zsh Style)**: Pressing <kbd>Tab</kbd> auto-completes built-in command names, aliases, and filesystem paths in the current directory. When multiple matches exist, a color-coded column listing is displayed, and the prompt and current editing line are cleanly reprinted.
- **In-Line Cursor Navigation**: <kbd>&larr;</kbd> and <kbd>&rarr;</kbd> move the cursor anywhere within the line; <kbd>Home</kbd> jumps to the start, <kbd>End</kbd> jumps to the end.
- **In-Line Editing**: Character insertion, <kbd>Backspace</kbd>, and <kbd>Delete</kbd> work anywhere in the line with automatic redraw.
- **History Expansion `!!`**: Typing `!!` echoes and immediately re-executes the most recent command.

### Standard Terminal Key Combinations

The interactive line editor and execution runtime implement standard POSIX / Readline / Zsh control key bindings:

| Key Combination | Action / Function | Behavior |
| :--- | :--- | :--- |
| <kbd>Ctrl+C</kbd> | **Interrupt / Cancel** | While editing: cancels current input, prints `^C`, and restarts prompt on a new line.<br>While running a program (`yes`, `sleep`, `seq`, `sh`, `cat`, `grep`, `head`, `tail`): halts execution immediately with status `130`. |
| <kbd>Ctrl+D</kbd> | **EOF / Forward Delete** | If the line buffer is empty: signals EOF (`logout` / clean shutdown).<br>If the line is non-empty: deletes character under cursor (same as <kbd>Delete</kbd>). |
| <kbd>Ctrl+L</kbd> | **Clear Screen** | Clears the UEFI display and redraws the shell prompt and current line buffer at row 0. |
| <kbd>Ctrl+A</kbd> | **Line Start** | Jumps cursor to the beginning of the line (equivalent to <kbd>Home</kbd>). |
| <kbd>Ctrl+E</kbd> | **Line End** | Jumps cursor to the end of the line (equivalent to <kbd>End</kbd>). |
| <kbd>Ctrl+U</kbd> | **Kill Line Before** | Deletes all text from the start of the line up to the cursor. |
| <kbd>Ctrl+K</kbd> | **Kill Line After** | Deletes all text from the cursor to the end of the line. |
| <kbd>Ctrl+W</kbd> | **Kill Word Backward** | Erases the previous whitespace-delimited word before the cursor. |
| <kbd>Ctrl+P</kbd> | **Previous History** | Cycles backward in command history (equivalent to <kbd>&uarr;</kbd>). |
| <kbd>Ctrl+N</kbd> | **Next History** | Cycles forward in command history (equivalent to <kbd>&darr;</kbd>). |
| <kbd>Ctrl+B</kbd> | **Move Backward** | Moves cursor left by one character (equivalent to <kbd>&larr;</kbd>). |
| <kbd>Ctrl+F</kbd> | **Move Forward** | Moves cursor right by one character (equivalent to <kbd>&rarr;</kbd>). |
| <kbd>Ctrl+H</kbd> | **Backspace** | Deletes character to the left of the cursor. |
| <kbd>Ctrl+Z</kbd> | **Suspend** | Displays `^Z` notification. |

### Shell Script Runner (Bash Compatible)
The shell provides a built-in script interpreter (`sh`, `source`, `.`) capable of executing `.sh` files stored in ZFS or EFI boot volumes:
- Supports `#` comment lines and shebangs (`#!/bin/sh`, `#!/bin/bash`).
- Supports command chaining with `;` (e.g. `mkdir /tmp/test; cd /tmp/test; touch a.txt; ls`).
- Supports script arguments (`$1`, `$2`, `$0`) and last exit status (`$?`).
- Pre-loaded with `/bin/demo.sh` demonstrating automated multi-command execution.

### Terminal Scrolling via Scroll Lock & Arrows

Hydra implements classic PC terminal scrolling using the **Scroll Lock** mode and arrow keys:

1. **When Scroll Lock is Active (`[SCROLL]` Prompt)**:
   - The shell freezes command execution and converts navigation keys into terminal viewport navigation:
     - <kbd>&uarr;</kbd> (Up Arrow): Scrolls the terminal screen **UP** line-by-line into the 512-line kernel scrollback buffer.
     - <kbd>&darr;</kbd> (Down Arrow): Scrolls the terminal screen **DOWN** line-by-line toward the active command prompt.
     - <kbd>Page Up</kbd>: Scrolls up by an entire screen page (`rows - 2` lines).
     - <kbd>Page Down</kbd>: Scrolls down by an entire screen page.
   - **Full Color & Attribute Preservation**: The scrollback buffer tracks both character bytes and formatting attributes (`(fg & 0xF) | ((bg & 0x7) << 4)`). All syntax highlighting, prompt colors (`LightCyan`), section headers (`Yellow`), directory names (`Green`), and error messages (`LightRed`) are preserved verbatim when scrolling up and down.
   - When scrolled up into history, a cyan status banner displays the visible line range: `-- SCROLL LOCK (up N lines, lines X-Y of Z) [UP/DOWN or PgUp/PgDn, ESC to exit] --`.
   - Allows naturally reviewing long command outputs (like `help`, `cat`, `ls -l`, `history`, or kernel boot diagnostics) that scrolled off the top of the screen without losing any visual hierarchy.

2. **When Scroll Lock is Inactive (Normal Mode)**:
   - <kbd>&uarr;</kbd> (Up Arrow) cycles backward through the command history ring buffer.
   - <kbd>&darr;</kbd> (Down Arrow) cycles forward through the command history ring buffer.
   - Typing any printable character, pressing <kbd>Enter</kbd>, or hitting <kbd>Backspace</kbd> automatically snaps the viewport back to the active prompt.

3. **Activating & Toggling Scroll Lock**:
   - **Keyboard Shortcut**: Press <kbd>Ctrl+S</kbd> or <kbd>F12</kbd> in the shell to immediately toggle Scroll Lock on/off. The prompt dynamically reflects the mode (`hydra:/bin [SCROLL]> ` vs `hydra:/bin> `).
   - **Direct Page Up**: Pressing <kbd>Page Up</kbd> at the prompt automatically enables scrolling mode and pages up through previous screen contents.
   - **Shell Command**: Run `scroll` (or `scroll on` / `scroll off`) from the command line.
   - **Exiting Scroll Mode**: Press <kbd>Escape</kbd>, <kbd>Ctrl+S</kbd>, or <kbd>Ctrl+C</kbd> to return to normal prompt mode.
   - **VirtualBox Note**: In VirtualBox with UEFI enabled, the firmware's `EFI_SIMPLE_TEXT_INPUT_PROTOCOL` does not generate key events for the physical <kbd>Scroll Lock</kbd> key (and host OS keyboard hooks often intercept or discard it). Use <kbd>Ctrl+S</kbd>, <kbd>F12</kbd>, or `scroll on` inside the VM for instant, reliable scrolling.

### Dynamic Working Directory Prompt
The shell tracks the current working directory dynamically in `ShellState` (initialized to `/bin`), displaying a standard Unix prompt:
```text
hydra:/bin> pwd
/bin
hydra:/bin> cd /
hydra:/> ls
NAME                     TYPE         CHECKSUM     STATUS
------------------------------------------------------------
bin                      <DIR>        Fletcher4     ONLINE
root                     <DIR>        Fletcher4     ONLINE
tmp                      <DIR>        Fletcher4     ONLINE
------------------------------------------------------------
hydra:/> cd /bin
hydra:/bin>
```

---

## 2. Command Reference

### GNU Core Utilities (POSIX / Linux Compatible)

| Command | Syntax | Description | Supported Options & Flags |
| :--- | :--- | :--- | :--- |
| `pwd` | `pwd` | Prints current working directory. | |
| `cd`, `chdir` | `cd [dir]` | Changes current working directory. Default: `/root`. | Relative paths, `..`, `.`, `/` |
| `ls`, `dir` | `ls [path]` | Lists files and directories in ZFS. Default: `cwd`. | `-l` (long format), `-a` (show all) |
| `cat`, `type` | `cat <file>` | Displays file contents verified with Fletcher-4. | Path resolution relative to `cwd` |
| `more`, `less` | `more <file>` | Paginates file with interactive Up/Down and PageUp/PageDown scrolling. | `less`, `page` aliases |
| `write` | `write <file> [text]` | Writes/appends data to a file via CoW transaction. | Path resolution relative to `cwd` |
| `touch` | `touch <file...>` | Creates empty file or updates birth TXG / timestamp. | Path resolution relative to `cwd` |
| `mkdir` | `mkdir <dir...>` | Creates one or more directories in ZFS. | `-p` (create parents without error) |
| `rmdir` | `rmdir <dir...>` | Removes empty directories from ZFS. | Verifies directory empty count |
| `rm`, `unlink` | `rm <file...>` | Removes files or directories from ZFS. | `-r`/`-R` (recursive), `-f` (force) |
| `cp`, `copy` | `cp <src> <dst>` | Copies files within ZFS pool via CoW. | Directory destination resolution |
| `mv`, `rename` | `mv <src> <dst>` | Moves or renames files or directories in ZFS. | Cross-directory and in-place moves |
| `stat` | `stat <file>` | Displays detailed file or directory metadata. | Size, blocks, birth TXG, checksum |
| `df` | `df` | Reports filesystem and storage pool capacity. | `-h` (human-readable: MiB/KiB) |
| `du` | `du [path]` | Estimates file and directory disk space usage. | `-h` (human-readable), `-s` (summary), `-a` |
| `head` | `head <file...>` | Displays first N lines of files. Default: 10 lines. | `-n <num>` or `-<num>` |
| `tail` | `tail <file...>` | Displays last N lines of files. Default: 10 lines. | `-n <num>` or `-<num>` |
| `wc` | `wc <file...>` | Counts newlines, words, and bytes in files. | `-l` (lines), `-w` (words), `-c` (bytes) |
| `grep` | `grep <pattern> <file>` | Searches for patterns in files. | `-i` (ignore case), `-n` (line numbers), `-v` (invert), `-c` (count) |
| `basename` | `basename <path> [suf]` | Strips directory and suffix from filenames. | Optional suffix removal |
| `dirname` | `dirname <path>` | Strips last component from filename path. | |
| `uname` | `uname` | Prints operating system and architecture info. | `-a` (all), `-s` (kernel), `-n` (node), `-r` (release), `-v` (version), `-m` (arch) |
| `whoami`, `id` | `whoami` | Prints current user identity and capabilities. | `-u`, `-g`, `-a` (full capability context) |
| `sleep` | `sleep <secs>` | Delays execution for specified duration (up to 60s). | Non-blocking firmware stall |
| `seq` | `seq [FIRST [INC]] LAST`| Prints sequences of integers. | Customizable start, step, and end |
| `history`, `hist`| `history` | Displays numbered session command history list. | Up/down arrow key cycling |
| `sh`, `source`, `.` | `sh <script.sh>` | Executes Bash-compatible script files line by line. | `#` comments, `;` chaining, `$1..$9`, `$?` |
| `!!` | `!!` | Repeats and re-executes the last command. | Shell history expansion |
| `true` | `true` | Returns success status (exit status 0). | |
| `false` | `false` | Returns failure status (exit status 1). | |

---

### Microkernel & Hardware Diagnostics

| Command | Syntax | Description |
| :--- | :--- | :--- |
| `help`, `?` | `help [cmd]` | Displays the interactive command manual and specific usage. |
| `info`, `version` | `info` | Prints Hydra Microkernel OS version, build target, and architecture overview. |
| `status` | `status` | Reports operational health across GDT, CPU, Frame Allocator, Paging, CSpace, and IPC. |
| `cpu` | `cpu` | Displays CPU control registers (`CR0`, `CR2`, `CR3` PML4 root, `CR4`). |
| `mem`, `memory` | `mem` | Displays physical memory manager statistics (Total Usable RAM, Allocated, Free). |
| `alloc` | `alloc` | Allocates a 4 KiB physical memory frame from the bump allocator and returns its physical address. |
| `translate` | `translate <hex_virt_addr>` | Walks the active 4-level PML4 page table hierarchy to resolve virtual to physical addresses. |
| `caps`, `cspace` | `caps` | Inspects the active task's capability table (slot numbers, resource types, and rights bitflags). |
| `cap_insert` | `cap_insert <ep_id>` | Inserts a new Endpoint capability into the task's CSpace. |
| `cap_revoke` | `cap_revoke <slot>` | Revokes an existing capability from the specified CSpace slot. |
| `ipc` | `ipc <label> [a0] [a1]` | Sends and receives a fast register IPC message through rendezvous Endpoint #1. |
| `time`, `date` | `time` | Queries the hardware Real-Time Clock (RTC) via UEFI runtime services. |
| `zpool` | `zpool <status\|list>` | Inspects and manages ZFS storage pools (`hydrapool`, vdevs, CoW Merkle tree). |
| `zfs` | `zfs <list\|snap\|cat\|write>` | Manages ZFS datasets (`hydrapool/root`, `hydrapool/bin`, `hydrapool/tmp`) and CoW snapshots. |
| `apt`, `pkg` | `apt <update\|install\|download\|search\|list\|show\|sources>` | Debian APT package manager: synchronizes indexes, decompresses Gzip, demuxes `ar`/`tar`, and installs packages to ZFS. |
| `efifs` | `efifs <ls\|cat\|run>` | Low-level firmware diagnostic tool inspecting raw UEFI FAT bootloader media. |
| `color` | `color <name>` | Customizes shell prompt and text color (`cyan`, `green`, `yellow`, `red`, `white`, `magenta`, `blue`). |
| `scroll` | `scroll [on\|off]` | Toggles or sets Scroll Lock mode for Up/Down arrow terminal scrolling. |
| `echo` | `echo <text...>` | Echoes input arguments back to the screen. |
| `clear`, `cls` | `clear` | Clears the active screen buffer and resets the cursor. |
| `panic` | `panic` | Manually triggers the kernel panic handler to verify diagnostic output. |
| `reboot` | `reboot` | Reboots the computer via 8042 keyboard pulse, PCI reset, and UEFI cold reset. |
| `shutdown` | `shutdown` | Powers down the computer via VirtualBox/QEMU ACPI I/O and UEFI shutdown. |
| `halt` | `halt` | Disables CPU interrupts and enters a low-power `hlt` loop. |

---

## 3. Integrating New Commands & Standalone Programs

Hydra supports two complementary paradigms for adding commands and applications:

### Approach A: Dynamic Filesystem Search ($PATH Discovery — No Code Changes!)
This is the recommended approach for integrating standalone applications, external utilities, and third-party binaries.

1. **How It Works**:
   When a command is entered (e.g. `hydra> matrix` or `hydra> test_app arg1 arg2`), the shell first checks built-in commands. If not found, it dynamically searches the `$PATH` directories on the boot volume:
   - `\bin\`
   - `\apps\`
   - `\EFI\BOOT\`
   - `\` (root directory)

   For each directory, it probes for:
   - `<dir>\<cmd>.efi`
   - `<dir>\<cmd>`

2. **Loading & Execution**:
   - The file is located on the UEFI boot volume via `SimpleFileSystem`.
   - The binary's PE32+ header (`MZ` signature) is verified.
   - Memory pages are dynamically allocated and the executable is loaded via `uefi::boot::load_image`.
   - Arguments are passed through the UEFI `LoadedImage` protocol.
   - The process is executed via `uefi::boot::start_image`.
   - Upon termination, control returns immediately to the Hydra interactive shell prompt!

3. **Zero Kernel Modifications**:
   You can drop any compiled UEFI PE32+ `.efi` executable into `\bin\` or `\apps\` on your boot USB or disk image at any time. **You do NOT need to modify `commands/mod.rs` or recompile the kernel!**

---

### Approach B: Static Built-in Command Integration
Used for core microkernel primitives that require direct access to kernel internals, `CapabilityTable`, or `ShellState`.

#### Step 1: Create a New Command File
Create a new file in `src/shell/commands/`, e.g. `src/shell/commands/my_tool.rs`:

```rust
use crate::console::set_color;
use uefi::proto::console::text::Color;
use crate::shell::command::Command;
use crate::shell::state::ShellState;

pub struct MyToolCommand;

impl Command for MyToolCommand {
    fn name(&self) -> &'static str {
        "mytool"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["mt"]
    }

    fn description(&self) -> &'static str {
        "Demonstrates custom command integration"
    }

    fn usage(&self) -> &'static str {
        "mytool <argument>"
    }

    fn execute(&self, args: &[&str], state: &mut ShellState) {
        set_color(Color::LightGreen, Color::Black);
        println!("[+] MyTool executed with args: {:?}", args);
    }
}
```

#### Step 2: Register in `src/shell/commands/mod.rs`
In [`src/shell/commands/mod.rs`](file:///d:/os/src/shell/commands/mod.rs):
1. Add the module: `pub mod my_tool;`
2. Export the struct: `pub use my_tool::MyToolCommand;`
3. Add `&MyToolCommand` to the `COMMANDS` slice:
   ```rust
   pub static COMMANDS: &[&dyn Command] = &[
       ...
       &MyToolCommand,
   ];
   ```

---

## 4. Architecture & Key Features

### Automatic 3-Second Bare-Metal Transition Countdown
Upon shell startup, Hydra automatically initiates a 3-second countdown before transitioning to bare-metal hardware ownership (`exitboot`):
- **Hands-Free Boot**: Users no longer need to manually type `exitboot` to unlock Ring 3 user mode, autonomous framebuffer rendering, and preemptive multitasking.
- **Countdown Display**: An interactive timer counts down (`3... 2... 1... NOW`), after which `ExitBootServices` is called, hardware ownership is established, and the bare-metal prompt `hydra:/bin>` appears.
- **User Control**:
  - Pressing <kbd>Enter</kbd> during the countdown immediately bypasses the remaining delay and transitions to bare metal instantly.
  - Pressing any other key (e.g. <kbd>Space</kbd> or <kbd>Esc</kbd>) cancels the countdown, keeping the shell in UEFI Boot Services mode.

### Thread-Safe Interactive Input & Automatic Prompt Refresh
Interactive input is handled by `src/shell/editor.rs` (`read_line`):
- **Automatic Prompt Appearance**: When a command finishes execution, the shell REPL loop immediately formats and renders the `hydra:/>` prompt on screen without requiring the user to press <kbd>Enter</kbd>.
- **Foreground vs. Background Task Synchronization**: Commands like `spawn user`, `spawn rogue`, `spawn mutex`, and `spawn producer` execute in the foreground by default using `task::wait_task(id)`, returning CPU control and rendering the prompt precisely when task execution finishes. Passing `--bg`, `-b`, or `&` launches the task asynchronously in the background.
- **Asynchronous Prompt Auto-Refresh**: If a concurrent background task (e.g. `consumer` receiving IPC messages) writes output to the console while the shell is waiting for input, `get_key_or_refresh()` monitors the global console generation counter (`CONSOLE_OUTPUT_GENERATION`). Once background output completes, the shell automatically moves to a new line and re-renders the prompt (and preserves any partially typed input) without requiring user intervention.
- Real-time backspace support erases characters from screen and buffer seamlessly via cursor positioning.
- Enter (`\r` or `\n`) submits the command line.

### Multi-Tier Power Management (`shutdown` & `reboot`)
Virtual machine firmware (such as VirtualBox's EFI and QEMU/EDK2) frequently stubs or hangs on generic UEFI runtime `ResetSystem(EfiResetShutdown)` prior to ACPI table activation. Hydra solves this by implementing direct hardware I/O power transitions:
1. **VirtualBox ACPI**: Writes sleep state S5 bits to PIIX3/4 ACPI `PM1a_CNT` (I/O Port `0x4004`).
2. **QEMU ACPI**: Writes to standard PIIX4 ACPI `PM1a_CNT` (I/O Port `0x604`) and debug exit (`0x501`).
3. **Cloud / Bochs ACPI**: Writes to I/O Port `0xb004` and APM (`0xb2`).
4. **Reboot Sequencing**: Pulses the 8042 keyboard controller reset line (`0x64`, `0xFE`) and the PCI reset control register (`0xCF9`, `0x06`) before falling back to UEFI cold reset.


### Virtual Address Translation Inspection
The `translate` command allows live debugging of paging:
```
hydra> translate 0x400000
[*] Translating Virtual Address 0x400000 via PML4 tree: Mapped -> Physical Address 0x400000
```

### On-Demand Memory Allocation
The `alloc` command demonstrates the physical memory frame allocator in real-time:
```
hydra> alloc
[+] Successfully allocated 4 KiB frame at physical address: 0x101000
hydra> mem
Physical Memory Manager Statistics:
  Total Usable RAM:   ...
  Allocated Frames:   ...
```

### Live Microkernel IPC
The `ipc` command sends a message through a rendezvous endpoint and reads the delivered payload:
```
hydra> ipc 0x2001 100 200 300
[+] Message queued to Endpoint #1: label=0x2001, args=[100, 200, 300, 0]
[+] Rendezvous complete! Received message from Endpoint #1:
    - Label: 0x2001
    - Args:  [100, 200, 300, 0]
```

### Visual Text Insertion Cursor & `cursor` Command
The shell provides real-time cursor tracking and blinking in both UEFI firmware mode and bare-metal video mode:
- **Exact Insertion Feedback**: As characters are typed, deleted, or traversed with <kbd>&larr;</kbd> / <kbd>&rarr;</kbd> / <kbd>Home</kbd> / <kbd>End</kbd>, the visual cursor instantly indicates the next character's insertion point.
- **Dynamic Cursor Shapes**: Supports `underline` (default 3px baseline), `block` (8x16 inverted cell), and `bar` (2px vertical).
- **Interactive Configuration**: The `cursor` command allows inspecting and toggling cursor parameters:
```text
hydra:/bin> cursor
[*] Terminal Cursor Status:
    Enabled:  yes
    Shape:    underline
    Position: col 0, row 9
    Blink:    ~1 Hz (500ms interval)
Usage: cursor [on|off|underline|block|bar]

hydra:/bin> cursor block
[+] Terminal cursor shape set to Block (8x16 inverted box).
```

