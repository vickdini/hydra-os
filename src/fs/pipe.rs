//! # Filesystem Subsystem: Anonymous Streaming Pipes
//!
//! Implements a fixed-capacity circular ring buffer (`64 KiB`) backing unidirectional
//! inter-process communication (IPC) pipes (`pipe(2)` / `pipe2(2)`).
//!
//! ## Architectural Role & Design Rationale
//! Pipes act as an in-memory conveyor belt between a producer task and a consumer task.
//! By decoupling read and write file descriptors around a shared [`PipeBuffer`], parent
//! and child processes can stream standard output into standard input (e.g., shell
//! pipelines like `ls | grep elf`) without touching disk storage.
//!
//! ## Key Types & Interfaces
//! - [`PipeBuffer`]: Lock-protected circular byte buffer tracking active reader/writer counts and wait queues.
//! - [`PIPE_BUFFER_SIZE`]: Default capacity (`65,536` bytes, matching Linux's 16-page pipe buffer).
//!
//! ## Hardware & Dependency Context
//! - CPU Privilege Level: Ring 0 (Kernel)
//! - Hardware Interaction: Purely memory-backed heap allocation (`alloc::vec::Vec`).
//! - Concurrency: Protected by [`spin::Mutex`] and coordinated via [`crate::task::wait::WaitQueue`].

use alloc::sync::Arc;
use spin::Mutex;

/// Capacity of an anonymous pipe ring buffer in bytes (`64 KiB`, matching Linux's 16-page default).
pub const PIPE_BUFFER_SIZE: usize = 65536;

/// Circular ring buffer implementing an anonymous unidirectional streaming pipe.
///
/// # Concurrency & Thread Safety
/// This structure is protected by a [`spin::Mutex`] and shared across file descriptors
/// via `Arc<Mutex<PipeBuffer>>`. Read and write operations acquire the lock briefly to
/// copy bytes into or out of the internal ring array and wake blocked tasks on [`PipeBuffer::wq`].
///
/// # Lifetime & Cleanup
/// When all reader file descriptors drop (`readers == 0`), subsequent write calls fail with
/// a broken pipe error (`EPIPE`). When all writer file descriptors drop (`writers == 0`),
/// subsequent reads return `0` bytes (EOF) once the buffered payload is drained.
pub struct PipeBuffer {
    /// Internal `64 KiB` ring storage for unread stream payload.
    buffer: alloc::vec::Vec<u8>,
    /// Ring index where the next incoming byte will be written (producer head pointer).
    head: usize,
    /// Ring index where the next available byte will be read (consumer tail pointer).
    tail: usize,
    /// Total count of valid, unconsumed bytes currently residing in the ring.
    count: usize,
    /// Number of active reader file descriptors (`FileDescriptor::PipeRead`) referencing this pipe.
    readers: usize,
    /// Number of active writer file descriptors (`FileDescriptor::PipeWrite`) referencing this pipe.
    writers: usize,
    /// Whether the read end was opened or configured with `O_NONBLOCK`.
    pub read_nonblock: bool,
    /// Whether the write end was opened or configured with `O_NONBLOCK`.
    pub write_nonblock: bool,
    /// Wait queue notifying blocked readers and writers when data arrives, space frees, or an end closes.
    pub wq: Arc<crate::task::wait::WaitQueue>,
}

impl PipeBuffer {
    /// Allocates and initializes a new [`PipeBuffer`] with 1 active reader and 1 active writer.
    ///
    /// # Returns
    ///
    /// An `Arc<Mutex<PipeBuffer>>` ready to be wrapped in a `PipeRead` and `PipeWrite` descriptor pair.
    ///
    /// # Panics
    ///
    /// Panics only if the kernel heap is exhausted when allocating the `64 KiB` backing vector.
    pub fn new() -> Arc<Mutex<Self>> {
        Arc::new(Mutex::new(Self {
            buffer: alloc::vec![0u8; PIPE_BUFFER_SIZE],
            head: 0,
            tail: 0,
            count: 0,
            readers: 1,
            writers: 1,
            read_nonblock: false,
            write_nonblock: false,
            wq: crate::task::wait::WaitQueue::new_shared(),
        }))
    }

    /// Checks whether the pipe ring buffer currently holds zero unread bytes.
    ///
    /// # Returns
    ///
    /// `true` if `count == 0`, otherwise `false`.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Checks whether the pipe ring buffer has reached its maximum capacity ([`PIPE_BUFFER_SIZE`]).
    ///
    /// # Returns
    ///
    /// `true` if no further bytes can be written without a consumer draining the buffer.
    pub fn is_full(&self) -> bool {
        self.count >= PIPE_BUFFER_SIZE
    }

    /// Returns the number of unread bytes currently buffered and available for reading.
    ///
    /// # Returns
    ///
    /// Byte count in the range `0..=PIPE_BUFFER_SIZE`.
    pub fn available_read(&self) -> usize {
        self.count
    }

    /// Returns the remaining free capacity in bytes before the ring buffer becomes full.
    ///
    /// # Returns
    ///
    /// Free byte count in the range `0..=PIPE_BUFFER_SIZE`.
    pub fn available_write(&self) -> usize {
        PIPE_BUFFER_SIZE - self.count
    }

    /// Returns the number of open reader file descriptors referencing this pipe.
    ///
    /// # Returns
    ///
    /// Active reader reference count.
    pub fn readers_count(&self) -> usize {
        self.readers
    }

    /// Returns the number of open writer file descriptors referencing this pipe.
    ///
    /// # Returns
    ///
    /// Active writer reference count.
    pub fn writers_count(&self) -> usize {
        self.writers
    }

    /// Increments the active reader reference count when a read descriptor is duplicated or forked.
    pub fn add_reader(&mut self) {
        self.readers += 1;
    }

    /// Decrements the active reader reference count and wakes all blocked writers if the last reader closed.
    pub fn drop_reader(&mut self) {
        self.readers = self.readers.saturating_sub(1);
        if self.readers == 0 {
            self.wq.wake_all();
        }
    }

    /// Increments the active writer reference count when a write descriptor is duplicated or forked.
    pub fn add_writer(&mut self) {
        self.writers += 1;
    }

    /// Decrements the active writer reference count and wakes all blocked readers (to observe EOF) if the last writer closed.
    pub fn drop_writer(&mut self) {
        self.writers = self.writers.saturating_sub(1);
        if self.writers == 0 {
            self.wq.wake_all();
        }
    }

    /// Drains up to `out.len()` bytes from the pipe ring buffer into `out`.
    ///
    /// Advances the consumer tail pointer modulo [`PIPE_BUFFER_SIZE`] and wakes any tasks
    /// waiting on [`PipeBuffer::wq`] if at least one byte was consumed.
    ///
    /// # Arguments
    ///
    /// * `out` - Destination slice to receive the de-queued bytes.
    ///
    /// # Returns
    ///
    /// The number of bytes copied into `out`. Returns `0` immediately if the buffer is empty.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        if self.count == 0 {
            return 0;
        }

        let to_read = out.len().min(self.count);
        for i in 0..to_read {
            out[i] = self.buffer[self.tail];
            self.tail = (self.tail + 1) % PIPE_BUFFER_SIZE;
        }
        self.count -= to_read;
        if to_read > 0 {
            self.wq.wake_all();
        }
        to_read
    }

    /// Enqueues as many bytes from `data` as fit into the remaining space of the pipe ring buffer.
    ///
    /// Advances the producer head pointer modulo [`PIPE_BUFFER_SIZE`] and wakes any tasks
    /// waiting on [`PipeBuffer::wq`] if at least one byte was written.
    ///
    /// # Arguments
    ///
    /// * `data` - Source slice of bytes to write into the pipe.
    ///
    /// # Returns
    ///
    /// * `Ok(n)` - Number of bytes written into the buffer (`0` if the buffer is currently full).
    ///
    /// # Errors
    ///
    /// * `Err("Broken pipe: no readers")` - All read descriptors have been closed (`readers == 0`, POSIX `EPIPE`).
    pub fn write(&mut self, data: &[u8]) -> Result<usize, &'static str> {
        if self.readers == 0 {
            return Err("Broken pipe: no readers");
        }

        let space = PIPE_BUFFER_SIZE - self.count;
        let to_write = data.len().min(space);
        for i in 0..to_write {
            self.buffer[self.head] = data[i];
            self.head = (self.head + 1) % PIPE_BUFFER_SIZE;
        }
        self.count += to_write;
        if to_write > 0 {
            self.wq.wake_all();
        }
        Ok(to_write)
    }
}
