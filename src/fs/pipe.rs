use alloc::sync::Arc;
use spin::Mutex;

/// Pipe capacity (Linux default: 16 pages).
pub const PIPE_BUFFER_SIZE: usize = 65536;

/// Circular ring buffer implementing an anonymous unidirectional pipe.
pub struct PipeBuffer {
    buffer: alloc::vec::Vec<u8>,
    head: usize,
    tail: usize,
    count: usize,
    readers: usize,
    writers: usize,
    /// `O_NONBLOCK` of the read and write ends (their open file descriptions).
    pub read_nonblock: bool,
    pub write_nonblock: bool,
}

impl PipeBuffer {
    /// Creates a new PipeBuffer with 1 reader and 1 writer reference.
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
        }))
    }

    /// Returns true if the pipe contains no readable bytes.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Returns true if the pipe's internal buffer is full.
    pub fn is_full(&self) -> bool {
        self.count >= PIPE_BUFFER_SIZE
    }

    /// Returns the number of readable bytes currently buffered.
    pub fn available_read(&self) -> usize {
        self.count
    }

    /// Returns the remaining write capacity before filling the buffer.
    pub fn available_write(&self) -> usize {
        PIPE_BUFFER_SIZE - self.count
    }

    /// Returns the count of active reader file descriptors.
    pub fn readers_count(&self) -> usize {
        self.readers
    }

    /// Returns the count of active writer file descriptors.
    pub fn writers_count(&self) -> usize {
        self.writers
    }

    pub fn add_reader(&mut self) {
        self.readers += 1;
    }

    pub fn drop_reader(&mut self) {
        self.readers = self.readers.saturating_sub(1);
    }

    pub fn add_writer(&mut self) {
        self.writers += 1;
    }

    pub fn drop_writer(&mut self) {
        self.writers = self.writers.saturating_sub(1);
    }

    /// Reads up to `out.len()` bytes from the pipe ring buffer.
    ///
    /// Returns:
    /// - `Ok(n)`: Number of bytes successfully read. If `n == 0` and writers == 0, indicates EOF.
    /// - `Err("No active writers")`: If empty and no writers remain.
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
        to_read
    }

    /// Writes data to the pipe ring buffer.
    ///
    /// Returns:
    /// - `Ok(n)`: Number of bytes written into the buffer.
    /// - `Err("Broken pipe")`: If all readers have closed their end (EPIPE).
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
        Ok(to_write)
    }
}
