//! # RFC 1951 DEFLATE Decompressor
//!
//! A pure-Rust, `no_std` zero-dependency implementation of the DEFLATE decompression algorithm.
//! Supports Stored (Type 0), Fixed Huffman (Type 1), and Dynamic Huffman (Type 2) compressed blocks.

extern crate alloc;

use alloc::vec::Vec;

/// Bitwise stream reader for DEFLATE bit-streams (LSB-first).
pub struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    bit_buf: u32,
    bits_in_buf: u8,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            bit_buf: 0,
            bits_in_buf: 0,
        }
    }

    /// Reads up to 24 bits from the stream.
    pub fn read_bits(&mut self, n: u8) -> Result<u32, &'static str> {
        while self.bits_in_buf < n {
            if self.pos >= self.data.len() {
                return Err("Unexpected end of compressed bitstream");
            }
            self.bit_buf |= (self.data[self.pos] as u32) << self.bits_in_buf;
            self.pos += 1;
            self.bits_in_buf += 8;
        }
        let mask = (1u32 << n) - 1;
        let result = self.bit_buf & mask;
        self.bit_buf >>= n;
        self.bits_in_buf -= n;
        Ok(result)
    }

    /// Discards remaining bits until the next byte boundary.
    pub fn align_to_byte(&mut self) {
        let discard = self.bits_in_buf % 8;
        if discard > 0 {
            self.bit_buf >>= discard;
            self.bits_in_buf -= discard;
        }
    }

    /// Reads an exact byte slice directly (must be byte-aligned).
    pub fn read_bytes(&mut self, count: usize) -> Result<&'a [u8], &'static str> {
        self.align_to_byte();
        // Drain any bytes cached in bit_buf first
        if self.bits_in_buf > 0 {
            let cached_bytes = (self.bits_in_buf / 8) as usize;
            self.pos -= cached_bytes;
            self.bit_buf = 0;
            self.bits_in_buf = 0;
        }
        if self.pos + count > self.data.len() {
            return Err("Unexpected end of stream during uncompressed block read");
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }
}

/// A node in the Huffman decoding tree.
#[derive(Clone, Copy)]
enum HuffmanNode {
    Branch { left: u16, right: u16 },
    Leaf(u16),
}

/// A Canonical Huffman Tree.
struct HuffmanTree {
    nodes: Vec<HuffmanNode>,
}

impl HuffmanTree {
    /// Builds a canonical Huffman tree from an array of code lengths (RFC 1951 section 3.2.2).
    pub fn from_code_lengths(lengths: &[u8]) -> Result<Self, &'static str> {
        let mut max_len = 0;
        for &len in lengths {
            if len > max_len {
                max_len = len;
            }
        }
        if max_len == 0 {
            return Ok(Self { nodes: Vec::new() });
        }

        let mut bl_count = [0u16; 16];
        for &len in lengths {
            if len > 0 && (len as usize) < bl_count.len() {
                bl_count[len as usize] += 1;
            }
        }

        let mut next_code = [0u16; 16];
        let mut code = 0u16;
        for bits in 1..=max_len as usize {
            code = (code + bl_count[bits - 1]) << 1;
            next_code[bits] = code;
        }

        let mut nodes = Vec::with_capacity(lengths.len() * 2);
        // Root node at index 0
        nodes.push(HuffmanNode::Branch { left: 0, right: 0 });

        for (symbol, &len) in lengths.iter().enumerate() {
            if len == 0 {
                continue;
            }
            let sym_code = next_code[len as usize];
            next_code[len as usize] += 1;

            let mut cur_idx = 0;
            for bit_pos in (0..len).rev() {
                let bit = (sym_code >> bit_pos) & 1;
                let (left, right) = match nodes[cur_idx] {
                    HuffmanNode::Branch { left, right } => (left, right),
                    HuffmanNode::Leaf(_) => return Err("Invalid Huffman prefix tree structure"),
                };

                let target = if bit == 0 { left } else { right };
                if target == 0 {
                    let next_idx = nodes.len() as u16;
                    if bit_pos == 0 {
                        nodes.push(HuffmanNode::Leaf(symbol as u16));
                    } else {
                        nodes.push(HuffmanNode::Branch { left: 0, right: 0 });
                    }
                    match &mut nodes[cur_idx] {
                        HuffmanNode::Branch { left, right } => {
                            if bit == 0 {
                                *left = next_idx;
                            } else {
                                *right = next_idx;
                            }
                        }
                        _ => unreachable!(),
                    }
                    cur_idx = next_idx as usize;
                } else {
                    cur_idx = target as usize;
                }
            }
        }

        Ok(Self { nodes })
    }

    /// Decodes the next symbol from the bitstream.
    pub fn decode(&self, reader: &mut BitReader) -> Result<u16, &'static str> {
        if self.nodes.is_empty() {
            return Err("Attempted to decode from empty Huffman tree");
        }
        let mut cur_idx = 0;
        loop {
            match self.nodes[cur_idx] {
                HuffmanNode::Leaf(val) => return Ok(val),
                HuffmanNode::Branch { left, right } => {
                    let bit = reader.read_bits(1)?;
                    let next = if bit == 0 { left } else { right };
                    if next == 0 {
                        return Err("Invalid Huffman bit sequence");
                    }
                    cur_idx = next as usize;
                }
            }
        }
    }
}

// RFC 1951 Table 3.2.5: Literal/Length extra bits & base lengths
const LENGTH_BASE: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115, 131,
    163, 195, 227, 258,
];
const LENGTH_EXTRA_BITS: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];

// RFC 1951 Table 3.2.5: Distance extra bits & base distances
const DISTANCE_BASE: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const DISTANCE_EXTRA_BITS: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

// RFC 1951 Section 3.2.7: Order of code length alphabet
const CODE_LENGTH_ORDER: [usize; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

/// Decompresses raw DEFLATE bytes into a dynamically allocated byte buffer.
pub fn inflate(compressed_data: &[u8]) -> Result<Vec<u8>, &'static str> {
    inflate_with_capacity(compressed_data, compressed_data.len().saturating_mul(3))
}

/// Decompresses raw DEFLATE bytes with an initial capacity hint for the output vector.
pub fn inflate_with_capacity(compressed_data: &[u8], initial_capacity: usize) -> Result<Vec<u8>, &'static str> {
    let mut reader = BitReader::new(compressed_data);
    let mut out = Vec::with_capacity(initial_capacity);

    loop {
        let bfinal = reader.read_bits(1)?;
        let btype = reader.read_bits(2)?;

        match btype {
            0 => {
                // Type 00: Stored (Uncompressed) - RFC 1951 Section 3.2.4
                reader.align_to_byte();
                let len_bytes = reader.read_bytes(4)?;
                let len = (len_bytes[0] as u16) | ((len_bytes[1] as u16) << 8);
                let nlen = (len_bytes[2] as u16) | ((len_bytes[3] as u16) << 8);
                if len != !nlen {
                    return Err("Stored block LEN and NLEN mismatch");
                }
                let bytes = reader.read_bytes(len as usize)?;
                out.extend_from_slice(bytes);
            }
            1 => {
                // Type 01: Compressed with Fixed Huffman Codes (RFC 1951 Section 3.2.6)
                let mut lit_lens = [0u8; 288];
                for i in 0..=143 {
                    lit_lens[i] = 8;
                }
                for i in 144..=255 {
                    lit_lens[i] = 9;
                }
                for i in 256..=279 {
                    lit_lens[i] = 7;
                }
                for i in 280..=287 {
                    lit_lens[i] = 8;
                }
                let lit_tree = HuffmanTree::from_code_lengths(&lit_lens)?;

                let dist_lens = [5u8; 32];
                let dist_tree = HuffmanTree::from_code_lengths(&dist_lens)?;

                decode_block(&mut reader, &lit_tree, &dist_tree, &mut out)?;
            }
            2 => {
                // Type 10: Compressed with Dynamic Huffman Codes (RFC 1951 Section 3.2.7)
                let hlit = (reader.read_bits(5)? + 257) as usize;
                let hdist = (reader.read_bits(5)? + 1) as usize;
                let hclen = (reader.read_bits(4)? + 4) as usize;

                let mut cl_lengths = [0u8; 19];
                for i in 0..hclen {
                    cl_lengths[CODE_LENGTH_ORDER[i]] = reader.read_bits(3)? as u8;
                }
                let cl_tree = HuffmanTree::from_code_lengths(&cl_lengths)?;

                let mut all_lengths = Vec::with_capacity(hlit + hdist);
                while all_lengths.len() < hlit + hdist {
                    let sym = cl_tree.decode(&mut reader)?;
                    match sym {
                        0..=15 => {
                            all_lengths.push(sym as u8);
                        }
                        16 => {
                            let repeat = (reader.read_bits(2)? + 3) as usize;
                            let prev = *all_lengths.last().ok_or("Invalid repeat code length")?;
                            for _ in 0..repeat {
                                all_lengths.push(prev);
                            }
                        }
                        17 => {
                            let repeat = (reader.read_bits(3)? + 3) as usize;
                            for _ in 0..repeat {
                                all_lengths.push(0);
                            }
                        }
                        18 => {
                            let repeat = (reader.read_bits(7)? + 11) as usize;
                            for _ in 0..repeat {
                                all_lengths.push(0);
                            }
                        }
                        _ => return Err("Illegal code length symbol"),
                    }
                }

                let lit_tree = HuffmanTree::from_code_lengths(&all_lengths[..hlit])?;
                let dist_tree = HuffmanTree::from_code_lengths(&all_lengths[hlit..hlit + hdist])?;

                decode_block(&mut reader, &lit_tree, &dist_tree, &mut out)?;
            }
            _ => return Err("Reserved or invalid DEFLATE block type (3)"),
        }

        if bfinal != 0 {
            break;
        }
    }

    Ok(out)
}

/// Decodes compressed symbols using the provided Literal/Length and Distance Huffman trees.
fn decode_block(
    reader: &mut BitReader,
    lit_tree: &HuffmanTree,
    dist_tree: &HuffmanTree,
    out: &mut Vec<u8>,
) -> Result<(), &'static str> {
    loop {
        let sym = lit_tree.decode(reader)?;
        match sym {
            0..=255 => {
                out.push(sym as u8);
            }
            256 => {
                // End of block
                break;
            }
            257..=285 => {
                let len_idx = (sym - 257) as usize;
                let extra_bits = LENGTH_EXTRA_BITS[len_idx];
                let extra = if extra_bits > 0 {
                    reader.read_bits(extra_bits)?
                } else {
                    0
                };
                let length = (LENGTH_BASE[len_idx] as u32 + extra) as usize;

                let dist_sym = dist_tree.decode(reader)? as usize;
                if dist_sym >= DISTANCE_BASE.len() {
                    return Err("Distance code out of range");
                }
                let dist_extra_bits = DISTANCE_EXTRA_BITS[dist_sym];
                let dist_extra = if dist_extra_bits > 0 {
                    reader.read_bits(dist_extra_bits)?
                } else {
                    0
                };
                let distance = (DISTANCE_BASE[dist_sym] as u32 + dist_extra) as usize;

                if distance > out.len() {
                    return Err("Backward distance references data before start of buffer");
                }

                let start_idx = out.len() - distance;
                for i in 0..length {
                    let b = out[start_idx + i];
                    out.push(b);
                }
            }
            _ => return Err("Invalid literal/length symbol decoded"),
        }
    }
    Ok(())
}
