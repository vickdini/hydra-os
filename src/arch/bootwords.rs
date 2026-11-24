//! # Boot words: the plain logic of [`crate::arch::bootopts`]
//!
//! No firmware and no heap here (the boot words are read before the kernel's heap exists):
//! a fixed buffer of lower-case ASCII words, filled from the boot entry's load options
//! (UCS-2), the `\hydra\options.txt` file and the start menu's choice. The host unit tests
//! use it as it is.

/// Longest text of boot words kept.
pub const MAX: usize = 1024;

/// The words of a safe start (start menu entry 2): one processor, no DMA remapping, no
/// tagged TLB entries, the boot messages on screen instead of the logo.
pub const SAFE: &str = "safe iommu=off pcid=off cpus=1 verbose";
/// Start menu entry 3: a safe start that stays on the text console (no desktop).
pub const SAFE_CONSOLE: &str = "safe iommu=off pcid=off cpus=1 verbose nodesktop";

/// The boot words: lower-case ASCII, separated by spaces.
#[derive(Clone, Copy)]
pub struct Words {
    /// The text.
    pub buf: [u8; MAX],
    /// Its length.
    pub len: usize,
}

impl Default for Words {
    fn default() -> Self {
        Self::new()
    }
}

impl Words {
    /// No words.
    pub const fn new() -> Self {
        Words { buf: [0; MAX], len: 0 }
    }

    /// The text.
    pub fn text(&self) -> &[u8] {
        &self.buf[..self.len]
    }

    /// Adds one character (lower case; anything but printable ASCII becomes `?`, line
    /// ends and tabs a space). Text beyond [`MAX`] is dropped.
    fn push(&mut self, c: u8) {
        if self.len == MAX {
            return;
        }
        let c = match c {
            b'\r' | b'\n' | b'\t' => b' ',
            0x20..=0x7E => c.to_ascii_lowercase(),
            _ => b'?',
        };
        self.buf[self.len] = c;
        self.len += 1;
    }

    /// Adds a space unless the text is empty or ends in one.
    fn space(&mut self) {
        if self.len > 0 && self.buf[self.len - 1] != b' ' {
            self.push(b' ');
        }
    }

    /// Adds the boot entry's load options (UCS-2, ending at a NUL if there is one).
    pub fn add_ucs2(&mut self, opts: &[u8]) {
        self.space();
        for c in opts.chunks_exact(2) {
            match (c[0], c[1]) {
                (0, 0) => break,
                (b, 0) => self.push(b),
                _ => self.push(b'?'),
            }
        }
    }

    /// Adds plain text (ASCII words).
    pub fn add_text(&mut self, text: &str) {
        self.space();
        for b in text.bytes() {
            self.push(b);
        }
    }

    /// Adds the words of an options file: each line's words, without comments (from `#`
    /// to the line's end). A byte-order mark and CR LF line ends (Notepad's) are fine.
    pub fn add_file(&mut self, file: &[u8]) {
        let file = file.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(file);
        for line in file.split(|&b| b == b'\n') {
            let line = match line.iter().position(|&b| b == b'#') {
                Some(i) => &line[..i],
                None => line,
            };
            if line.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            self.space();
            for &b in line {
                self.push(b);
            }
        }
    }

    /// Whether the text contains `word` (lower case) as a substring, as the kernel's other
    /// option checks always did (`iommu=off` matches inside `xiommu=off` too).
    pub fn has(&self, word: &[u8]) -> bool {
        !word.is_empty() && self.text().windows(word.len()).any(|w| w == word)
    }

    /// The value of the word `key=value` (`key` with its `=`), as a number.
    pub fn number(&self, key: &[u8]) -> Option<u64> {
        for w in self.text().split(|&b| b == b' ') {
            if let Some(v) = w.strip_prefix(key) {
                if !v.is_empty() && v.iter().all(|b| b.is_ascii_digit()) {
                    return core::str::from_utf8(v).ok()?.parse().ok();
                }
            }
        }
        None
    }

    /// The text as UCS-2 bytes (the form the load options have).
    pub fn ucs2(&self) -> alloc::vec::Vec<u8> {
        self.text().iter().flat_map(|&b| [b, 0]).collect()
    }
}

/// The start menu's wait (seconds) from the `\hydra\menu` file: a line `timeout=N`
/// (0..=60); `default` (5 s) without one.
pub fn menu_timeout(file: &[u8], default: u32) -> u32 {
    for line in file.split(|&b| b == b'\n') {
        let mut buf = [0u8; 32];
        let mut n = 0;
        for &b in line.iter().filter(|b| !b.is_ascii_whitespace()) {
            if n == buf.len() {
                break;
            }
            buf[n] = b.to_ascii_lowercase();
            n += 1;
        }
        if let Some(v) = buf[..n].strip_prefix(b"timeout=") {
            if let Some(n) = core::str::from_utf8(v).ok().and_then(|s| s.parse::<u32>().ok()) {
                return n.min(60);
            }
        }
    }
    default
}

/// The words a start menu key adds: `1`/Enter none, `2` [`SAFE`], `3` [`SAFE_CONSOLE`];
/// `None` for other keys.
pub fn menu_choice(key: char) -> Option<&'static str> {
    match key {
        '1' | '\r' | '\n' => Some(""),
        '2' => Some(SAFE),
        '3' => Some(SAFE_CONSOLE),
        _ => None,
    }
}
