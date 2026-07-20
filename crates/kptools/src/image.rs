//! Arm64 kernel image header decode.
//!
//! Port of upstream `tools/image.{c,h}`. Reads the fixed layout
//! Linux keeps at `arch/arm64/kernel/head.S`:
//! `[MZ|b stext] … kernel_offset (LE u64) … magic="ARM\x64" …`.
//!
//! We need three things from here:
//! - the `is_be` flag (0/1 — drives every endian-sensitive access
//!   further down the pipeline),
//! - the `kernel_size` + `load_offset` + `page_shift` (layout math),
//! - the offset of the `b stext` instruction we patch to redirect
//!   entry through kpimg.
//!
//! The UEFI `MZ` branch uses a different initial instruction location
//! — upstream detects it by checking the first two bytes. Mirror that.

use bytemuck::{Pod, Zeroable};

use kptools_base::{Error, Result};

pub const EFI_MAGIC: &[u8; 2] = b"MZ";
pub const KERNEL_MAGIC: &[u8; 4] = b"ARM\x64";

/// Mirrors upstream `kernel_info_t`.
#[derive(Clone, Copy, Debug, Default)]
pub struct KernelInfo {
    /// 0 little-endian, 1 big-endian. Matches the C `int8_t` field.
    pub is_be: i8,
    pub uefi: i8,
    pub load_offset: i32,
    pub kernel_size: i32,
    pub page_shift: i32,
    /// Offset within the image of the `b stext` instruction we
    /// overwrite to redirect entry through kpimg.
    pub b_stext_insn_offset: i32,
    /// Offset the original `b stext` jumped to, decoded from the
    /// instruction's immediate field.
    pub primary_entry_offset: i32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Arm64HdrEfi {
    mz: [u8; 4],
    b_insn: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Arm64HdrNefi {
    b_insn: u32,
    reserved0: u32,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Arm64Hdr {
    /// The C code uses a union of `efi` / `nefi` for the first 8
    /// bytes. Both alternatives are 8 bytes so we just read the raw
    /// bytes and decode after sniffing the `MZ` prefix.
    hdr_raw: [u8; 8],
    kernel_offset: u64,
    kernel_size_le: u64,
    kernel_flag_le: u64,
    reserved0: u64,
    reserved1: u64,
    reserved2: u64,
    magic: [u8; 4],
    /// `pe_offset` when UEFI, unused otherwise.
    pe_offset: u64,
}

impl Arm64Hdr {
    fn as_efi(&self) -> Arm64HdrEfi {
        let mut efi = Arm64HdrEfi::zeroed();
        efi.mz.copy_from_slice(&self.hdr_raw[..4]);
        efi.b_insn = u32::from_le_bytes(self.hdr_raw[4..8].try_into().unwrap());
        efi
    }
    fn as_nefi(&self) -> Arm64HdrNefi {
        Arm64HdrNefi {
            b_insn: u32::from_le_bytes(self.hdr_raw[0..4].try_into().unwrap()),
            reserved0: u32::from_le_bytes(self.hdr_raw[4..8].try_into().unwrap()),
        }
    }
}

/// Decode the arm64 header at the start of `img`.
///
/// `page_shift` is recovered from the low nibble of
/// `kernel_flag_le` the same way upstream `get_kernel_info` does:
/// bits [2:1] encode 4K/16K/64K page size (defaults to 4K).
pub fn get_kernel_info(img: &[u8]) -> Result<KernelInfo> {
    if img.len() < core::mem::size_of::<Arm64Hdr>() {
        return Err(Error::bad_kernel(format!(
            "kernel image truncated: {} bytes",
            img.len()
        )));
    }
    let hdr: &Arm64Hdr = bytemuck::from_bytes(&img[..core::mem::size_of::<Arm64Hdr>()]);

    if hdr.magic != *KERNEL_MAGIC {
        return Err(Error::bad_kernel(format!(
            "kernel magic mismatch: {:02x?}",
            hdr.magic
        )));
    }

    let mut info = KernelInfo {
        is_be: 0,
        ..Default::default()
    };

    let uefi = &hdr.hdr_raw[..2] == EFI_MAGIC;
    info.uefi = if uefi { 1 } else { 0 };

    let (b_primary_entry_insn, b_stext_insn_offset) = if uefi {
        let efi = hdr.as_efi();
        (efi.b_insn, 4_i32)
    } else {
        let nefi = hdr.as_nefi();
        (nefi.b_insn, 0_i32)
    };
    info.b_stext_insn_offset = b_stext_insn_offset;

    // `b` instruction decode — upstream mirrors the `(insn &
    // 0xFC000000) == 0x14000000` check. The immediate is
    // left-shifted by 2 (byte offset) and added to the instruction
    // offset.
    let b_insn = u32::from_le(b_primary_entry_insn);
    if (b_insn & 0xFC00_0000) != 0x1400_0000 {
        return Err(Error::bad_kernel(format!(
            "expected `b` at stext, got insn 0x{b_insn:08x}",
        )));
    }
    let imm = ((b_insn & 0x03FF_FFFF) << 2) as i32;
    info.primary_entry_offset = imm + b_stext_insn_offset;

    info.load_offset = u64::from_le(hdr.kernel_offset) as i32;
    info.kernel_size = u64::from_le(hdr.kernel_size_le) as i32;

    let flag = (u64::from_le(hdr.kernel_flag_le) & 0x0f) as u8;
    info.is_be = (flag & 0x01) as i8;
    if info.is_be != 0 {
        return Err(Error::bad_kernel("kernel unexpected arm64 big endian img"));
    }
    info.page_shift = match (flag & 0b0110) >> 1 {
        2 => 14, // 16k
        3 => 16, // 64k
        _ => 12, // 4k (case 1 + default)
    };

    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fabricate a minimal arm64 header (non-UEFI variant) and
    /// confirm the decoded fields match.
    #[test]
    fn decode_non_uefi_header() {
        let mut buf = vec![0u8; 128];
        // `b +0x100` (0x14000040) at offset 0
        buf[0..4].copy_from_slice(&0x1400_0040_u32.to_le_bytes());
        buf[8..16].copy_from_slice(&0x80000_u64.to_le_bytes()); // load offset
        buf[16..24].copy_from_slice(&0x800000_u64.to_le_bytes()); // kernel size
        buf[56..60].copy_from_slice(KERNEL_MAGIC);
        let info = get_kernel_info(&buf).unwrap();
        assert_eq!(info.is_be, 0);
        assert_eq!(info.uefi, 0);
        assert_eq!(info.b_stext_insn_offset, 0);
        assert_eq!(info.primary_entry_offset, 0x100);
        assert_eq!(info.load_offset, 0x80000);
        assert_eq!(info.kernel_size, 0x800000);
        assert_eq!(info.page_shift, 12);
    }

    #[test]
    fn decode_uefi_header() {
        let mut buf = vec![0u8; 128];
        buf[0..2].copy_from_slice(EFI_MAGIC);
        // `b +0x40` at offset 4
        buf[4..8].copy_from_slice(&0x1400_0010_u32.to_le_bytes());
        buf[56..60].copy_from_slice(KERNEL_MAGIC);
        let info = get_kernel_info(&buf).unwrap();
        assert_eq!(info.uefi, 1);
        assert_eq!(info.b_stext_insn_offset, 4);
        assert_eq!(info.primary_entry_offset, 0x44);
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0u8; 128];
        let err = get_kernel_info(&buf).unwrap_err();
        assert!(matches!(err, Error::BadKernel(_)));
    }

    #[test]
    fn rejects_truncated() {
        let err = get_kernel_info(&[0; 8]).unwrap_err();
        assert!(matches!(err, Error::BadKernel(_)));
    }
}
