//! The linear framebuffer: device memory the supervisor granted this server, mapped into
//! its address space.

/// A mapped linear 32-bit framebuffer.
pub struct Framebuffer {
    base: *mut u8,
    width: usize,
    height: usize,
    stride: usize,
    bgr: bool,
}

impl Framebuffer {
    /// Maps the framebuffer at physical address `phys` (`stride` pixels per row).
    pub fn map(phys: u64, width: usize, height: usize, stride: usize, bgr: bool) -> Result<Self, i64> {
        let len = (stride * height * 4 + 4095) & !4095;
        let base = hydra_rt::sys::physmap(phys, len)?;
        Ok(Self { base, width, height, stride, bgr })
    }

    /// First byte of the first row.
    pub fn base_ptr(&self) -> *mut u8 {
        self.base
    }

    /// Visible width in pixels.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Visible height in pixels.
    pub fn height(&self) -> usize {
        self.height
    }

    /// Pixels per row in memory.
    pub fn stride(&self) -> usize {
        self.stride
    }

    /// Whether pixels are stored blue-green-red.
    pub fn is_bgr(&self) -> bool {
        self.bgr
    }
}
