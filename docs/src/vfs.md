# Unix File Descriptor Table & Shell Pipelines

- **Source Files**: [`src/fs/fd.rs`](file:///d:/os/src/fs/fd.rs), [`src/fs/pipe.rs`](file:///d:/os/src/fs/pipe.rs), [`src/shell/pipeline.rs`](file:///d:/os/src/shell/pipeline.rs)
- **Subsystem**: Virtual File System (VFS), POSIX File Descriptors, IPC Pipes, Shell Streams
- **Privilege Levels**: Ring 0 (Kernel Subsystem) & Ring 3 (Userland Syscalls)

---

## 1. Architectural Overview

Hydra OS implements a complete Unix-like File Descriptor model that decouples input/output operations from underlying hardware devices or filesystem implementations. Every process in Hydra maintains its own **File Descriptor Table (`FdTable`)**, allowing standard streams to be seamlessly redirected across processes, anonymous pipes, and ZFS files.

```
+-------------------------------------------------------------------------+
|                              PROCESS (TCB)                              |
|                                                                         |
|   +-----------------------------------------------------------------+   |
|   |                   FILE DESCRIPTOR TABLE (0..15)                 |   |
|   |                                                                 |   |
|   |   fd 0: Stdin  ---------> [ ConsoleIn / PipeRead ]              |   |
|   |   fd 1: Stdout ---------> [ ConsoleOut / PipeWrite / File ]     |   |
|   |   fd 2: Stderr ---------> [ ConsoleErr / PipeWrite / File ]     |   |
|   |   fd 3..15: Open Files, Pipes, or Network Sockets               |   |
|   +-----------------------------------------------------------------+   |
+-------------------------------------------------------------------------+
                    |                                 |
         Pipes (Streaming IPC)               ZFS Storage (CoW)
                    v                                 v
        +-----------------------+         +-----------------------+
        |   4 KiB Ring Buffer   |         |    ZFS File Server    |
        |      PipeBuffer       |         |   (CoW Transaction)   |
        +-----------------------+         +-----------------------+
```

---

## 2. Standard Streams & Descriptors

Every newly spawned task automatically inherits a standard Unix descriptor table:

| FD Index | POSIX Name | Default Target | Capability & Access |
|---|---|---|---|
| `0` | `STDIN_FILENO` | `FileDescriptor::ConsoleIn` | PS/2 Keyboard Input Buffer (Non-blocking) |
| `1` | `STDOUT_FILENO` | `FileDescriptor::ConsoleOut` | Physical Framebuffer / Terminal Screen |
| `2` | `STDERR_FILENO` | `FileDescriptor::ConsoleErr` | Physical Framebuffer / Error Channel |
| `3..15` | Available FDs | `None` | Allocated dynamically via `open()` or `pipe()` |

### File Descriptor Types (`FileDescriptor`)

1. **`ConsoleIn`**: Reads characters from the hardware PS/2 keyboard ring buffer.
2. **`ConsoleOut` / `ConsoleErr`**: Writes formatted ASCII/UTF-8 directly to the screen console.
3. **`PipeRead(Arc<Mutex<PipeBuffer>>)`**: Reads streamed bytes from an anonymous pipe ring buffer.
4. **`PipeWrite(Arc<Mutex<PipeBuffer>>)`**: Writes streamed bytes into an anonymous pipe ring buffer.
5. **`File`**: Represents a stateful cursor into a file stored on the ZFS storage pool.

---

## 3. Anonymous Pipe Subsystem

The **`PipeBuffer`** primitive ([`src/fs/pipe.rs`](file:///d:/os/src/fs/pipe.rs)) provides high-throughput, lock-free/spinlock-protected unidirectional byte streaming between processes:

- **Buffer Size**: 4096 bytes circular ring buffer.
- **Reference Counting**: Tracks active reader and writer file descriptors.
- **EOF Semantics**: When all writers close their end (`writers == 0`), subsequent reads on an empty buffer return `0` bytes (standard POSIX EOF).
- **Broken Pipe (EPIPE)**: Attempting to write to a pipe with `readers == 0` immediately fails with `-EPIPE` (or broken pipe error).

---

## 4. Unix System Calls

Hydra OS exposes the full complement of POSIX I/O system calls to Ring 3 processes:

| Syscall | Number | Arguments | Description |
|---|---|---|---|
| `SYS_WRITE` | `3` | `arg0: fd`, `arg1: ptr`, `arg2: count` | Writes bytes to the specified file descriptor |
| `SYS_OPEN` | `9` | `arg0: path_ptr`, `arg1: len`, `arg2: flags` | Opens or creates a file in ZFS (`O_RDONLY`, `O_WRONLY`, `O_RDWR`, `O_APPEND`) |
| `SYS_CLOSE` | `10` | `arg0: fd` | Closes the file descriptor and decrements pipe refcounts |
| `SYS_READ` | `11` | `arg0: fd`, `arg1: buf_ptr`, `arg2: count` | Reads bytes from a descriptor (Console, Pipe, or File) |
| `SYS_PIPE` | `12` | `arg0: *mut [u64; 2]` | Allocates a new pipe and returns `[read_fd, write_fd]` |
| `SYS_DUP2` | `13` | `arg0: oldfd`, `arg1: newfd` | Duplicates `oldfd` onto `newfd`, redirecting streams |

---

## 5. Shell Pipelines & Redirection

The Hydra Interactive Shell ([`src/shell/pipeline.rs`](file:///d:/os/src/shell/pipeline.rs)) supports arbitrary pipeline chaining and file redirection:

### 1. Pipelines (`|`)
Chains the standard output (`fd 1`) of command $N$ to the standard input (`fd 0`) of command $N+1$:
```bash
cat /test.txt | grep Pipeline
ps | grep idle
help | grep fs
```

### 2. Output Redirection (`>` and `>>`)
Redirects command standard output to a file in ZFS:
- `>` (Overwrite / Truncate):
  ```bash
  echo Hello Hydra > /test.txt
  ```
- `>>` (Append):
  ```bash
  echo Pipeline Verified >> /test.txt
  ```

### 3. Combined Pipeline & Redirection
Pipelines can seamlessly terminate in a file redirection target:
```bash
ps | grep idle > /idle_process.txt
```
Output is buffered in memory during pipeline execution and committed atomically to the ZFS filesystem via Copy-on-Write (CoW).
