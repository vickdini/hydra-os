//! # ACPI power-off and reset values from the firmware's tables (plain logic)
//!
//! Real firmware powers the machine off when the operating system writes the "soft off"
//! sleep type (`\_S5`, from the DSDT) with the sleep-enable bit into the PM1 control
//! registers the FADT names, and resets it through the FADT's reset register. QEMU's
//! ports, which Hydra used to poke, mean nothing (or something else) on a real chipset:
//! port 0xB2 is the chipset's SMI command port. [`crate::arch::power`] reads the tables
//! before `ExitBootServices`; the parsing is here so the host unit tests run it.

/// What power-off and reset need from the FADT and DSDT.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fadt {
    /// I/O port of PM1a control (0: none).
    pub pm1a_cnt: u16,
    /// I/O port of PM1b control (0: none).
    pub pm1b_cnt: u16,
    /// SMI command port and the value that switches the firmware to ACPI mode (0: none).
    pub smi_cmd: u16,
    /// The ACPI-enable value for `smi_cmd`.
    pub acpi_enable: u8,
    /// Physical address of the DSDT.
    pub dsdt: u64,
    /// Reset register: (address space 0 memory / 1 I/O / 2 PCI config, address, value),
    /// when the FADT says it is supported.
    pub reset: Option<(u8, u64, u8)>,
}

fn le32(b: &[u8], at: usize) -> u64 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]]) as u64
}

fn le64(b: &[u8], at: usize) -> u64 {
    le32(b, at) | le32(b, at + 4) << 32
}

/// Reads the FADT (`t`: the whole table, its "FACP" header included).
pub fn parse_fadt(t: &[u8]) -> Option<Fadt> {
    if t.len() < 116 || &t[..4] != b"FACP" {
        return None;
    }
    let len = (le32(t, 4) as usize).min(t.len());
    let t = &t[..len];
    let mut f = Fadt {
        dsdt: le32(t, 40),
        smi_cmd: le32(t, 48) as u16,
        acpi_enable: t[52],
        pm1a_cnt: le32(t, 64) as u16,
        pm1b_cnt: le32(t, 68) as u16,
        reset: None,
    };
    // ACPI 2.0+: the 64-bit DSDT address and the extended PM1 control blocks (I/O space)
    if len >= 148 && le64(t, 140) != 0 {
        f.dsdt = le64(t, 140);
    }
    if len >= 184 && f.pm1a_cnt == 0 && t[172] == 1 {
        f.pm1a_cnt = le64(t, 176) as u16;
    }
    if len >= 196 && f.pm1b_cnt == 0 && t[184] == 1 {
        f.pm1b_cnt = le64(t, 188) as u16;
    }
    // The reset register (flags bit 10: RESET_REG_SUP), ACPI 2.0+
    if len >= 129 && le32(t, 112) & (1 << 10) != 0 {
        let space = t[116];
        let addr = le64(t, 120);
        if addr != 0 && space <= 2 {
            f.reset = Some((space, addr, t[128]));
        }
    }
    Some(f)
}

/// The `\_S5` sleep types (SLP_TYPa, SLP_TYPb) from the DSDT's code (`aml`: the whole
/// table): the package after the name `_S5_`, its first two integers.
pub fn s5_sleep_types(aml: &[u8]) -> Option<(u8, u8)> {
    let mut i = 36.min(aml.len());
    while i + 4 <= aml.len() {
        if &aml[i..i + 4] != b"_S5_" {
            i += 1;
            continue;
        }
        // A name, not a reference: NameOp (0x08) before it, possibly with a root `\`
        let named = i >= 1 && (aml[i - 1] == 0x08 || (i >= 2 && aml[i - 1] == b'\\' && aml[i - 2] == 0x08));
        let mut p = i + 4;
        if !named || p >= aml.len() || aml[p] != 0x12 {
            i += 1;
            continue;
        }
        // PackageOp, PkgLength (1 to 4 bytes), NumElements
        p += 1;
        let lead = *aml.get(p)?;
        p += 1 + (lead >> 6) as usize;
        p += 1;
        let int = |p: &mut usize| -> Option<u8> {
            let op = *aml.get(*p)?;
            *p += 1;
            match op {
                0x00 => Some(0),
                0x01 => Some(1),
                0xFF => Some(0xFF),
                0x0A => {
                    let v = *aml.get(*p)?;
                    *p += 1;
                    Some(v)
                }
                0x0B => {
                    let v = *aml.get(*p)?;
                    *p += 2;
                    Some(v)
                }
                0x0C => {
                    let v = *aml.get(*p)?;
                    *p += 4;
                    Some(v)
                }
                _ => None,
            }
        };
        let a = int(&mut p)?;
        let b = int(&mut p).unwrap_or(a);
        return Some((a & 7, b & 7));
    }
    None
}

/// The PM1 control value that enters the sleep type `typ` (SLP_TYP in bits 10..12,
/// SLP_EN bit 13), keeping `cur`'s other bits (SCI_EN among them).
pub fn pm1_sleep_value(cur: u16, typ: u8) -> u16 {
    (cur & !(7 << 10 | 1 << 13)) | (typ as u16 & 7) << 10 | 1 << 13
}
