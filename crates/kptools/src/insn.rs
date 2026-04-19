//! Arm64 A64 instruction helpers.
//!
//! This is the *subset* of upstream `tools/insn.c` + `tools/insn.h`
//! that the `patch.c` + `kallsym.c` call graph actually touches.
//! The upstream file is a 1 400-line copy of the Linux kernel's
//! `arch/arm64/include/asm/insn.h` covering every A64 encoder, but
//! kptools only exercises a handful:
//!
//! - `b_imm` / `b` — emit an unconditional branch.
//! - `INSN_IS_B` — opcode-mask test on a decoded instruction.
//! - `relo_branch_func` — follow a `b` instruction one hop and
//!   return its target.
//!
//! Everything else is left for later phases to bring in on demand.
//! Keeping the surface narrow prevents a 30 KB encoder table from
//! compiling against every test target.

use kptools_base::{Error, Result};

pub const AARCH64_INSN_SIZE: usize = 4;

/// Mask + prefix of the unconditional `b` (not `bl`) instruction.
const B_OPCODE_MASK: u32 = 0xFC00_0000;
const B_OPCODE: u32 = 0x1400_0000;

/// True iff `insn` encodes an unconditional `b` (not `bl`).
#[inline]
pub const fn is_b(insn: u32) -> bool {
    (insn & B_OPCODE_MASK) == B_OPCODE
}

/// Extract bits `[high:low]` inclusive from a 32-bit instruction.
#[inline]
pub const fn bits32(insn: u32, high: u32, low: u32) -> u32 {
    let width = high - low + 1;
    let mask = if width == 32 { u32::MAX } else { (1u32 << width) - 1 };
    (insn >> low) & mask
}

/// Sign-extend a `bits`-wide value to `i64`.
#[inline]
pub const fn sign64_extend(value: u64, bits: u32) -> i64 {
    let shift = 64 - bits;
    ((value << shift) as i64) >> shift
}

/// Encode a `b from → to` instruction. `from` / `to` are absolute
/// byte offsets; only the 26-bit `imm26` field is encoded, so the
/// displacement must fit within ±128 MiB (inclusive). Returns 4 on
/// success (instruction size), 0 when the displacement is out of
/// range — matches upstream's contract.
pub fn b(from: u64, to: u64) -> Result<u32> {
    if !can_b_imm(from, to) {
        return Err(Error::insn(format!(
            "b displacement out of range: 0x{from:x} -> 0x{to:x}"
        )));
    }
    let imm: i64 = (to as i64) - (from as i64);
    let imm26 = ((imm as u64) >> 2) & 0x03FF_FFFF;
    Ok(B_OPCODE | imm26 as u32)
}

/// Write `b from → to` into the 4 bytes starting at `buf[offset..]`.
/// Convenience wrapper — upstream uses `uint32_t *buf` pointer
/// arithmetic, we take an `&mut [u8]` slice instead.
pub fn write_b(buf: &mut [u8], offset: usize, from: u64, to: u64) -> Result<()> {
    if offset.saturating_add(4) > buf.len() {
        return Err(Error::insn(format!(
            "write_b OOB: offset 0x{offset:x} buflen 0x{:x}",
            buf.len()
        )));
    }
    let insn = b(from, to)?;
    buf[offset..offset + 4].copy_from_slice(&insn.to_le_bytes());
    Ok(())
}

/// Branch-displacement sanity check — imm26 encodes ±128 MiB.
/// Mirrors upstream's `can_b_imm` helper.
#[inline]
pub fn can_b_imm(from: u64, to: u64) -> bool {
    let limit: u64 = 128 * 1024 * 1024;
    if to >= from {
        to - from <= limit
    } else {
        from - to <= limit
    }
}

// ---------------------------------------------------------------------------
// Decoder subset required by `kallsym::arm64_verify_pid_vnr`. Ports the
// three helpers upstream's `kallsym.c` calls while walking the first six
// instructions of `pid_vnr`: `aarch64_get_insn_class`,
// `aarch64_insn_extract_system_reg`, and `aarch64_insn_decode_register`
// (RN only — that's the only register the caller asks for).

/// ARMv8 A64 main encoding class. Mirrors
/// `enum aarch64_insn_encoding_class` from upstream `insn.h`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InsnClass {
    Unknown,
    DpImm,
    DpReg,
    DpFpsimd,
    Ldst,
    BrSys,
}

/// Upstream `aarch64_insn_encoding_class[]` — indexed by bits `[28:25]`
/// of the instruction word. See ARM ARM v8 Profile-A, section C3.1.
const INSN_CLASS_TABLE: [InsnClass; 16] = [
    InsnClass::Unknown, InsnClass::Unknown, InsnClass::Unknown, InsnClass::Unknown,
    InsnClass::Ldst,    InsnClass::DpReg,   InsnClass::Ldst,    InsnClass::DpFpsimd,
    InsnClass::DpImm,   InsnClass::DpImm,   InsnClass::BrSys,   InsnClass::BrSys,
    InsnClass::Ldst,    InsnClass::DpReg,   InsnClass::Ldst,    InsnClass::DpFpsimd,
];

/// Upstream `aarch64_get_insn_class(insn)`.
#[inline]
pub const fn aarch64_get_insn_class(insn: u32) -> InsnClass {
    INSN_CLASS_TABLE[((insn >> 25) & 0xf) as usize]
}

/// A64 register type (subset — only RN is used by kallsym).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegType {
    Rt,
    Rn,
    Rt2,
    Rm,
    Rd,
    Ra,
}

/// Stack pointer register encoding (shared with ZR at 31).
pub const AARCH64_INSN_REG_SP: u32 = 31;

/// Special-purpose register encoding for `SP_EL0` in MSR/MRS.
pub const AARCH64_INSN_SPCLREG_SP_EL0: u32 = 0xC208;

/// Upstream `aarch64_insn_decode_register(type, insn)`.
#[inline]
pub const fn aarch64_insn_decode_register(ty: RegType, insn: u32) -> u32 {
    let shift = match ty {
        RegType::Rt | RegType::Rd => 0,
        RegType::Rn => 5,
        RegType::Rt2 | RegType::Ra => 10,
        RegType::Rm => 16,
    };
    (insn >> shift) & 0x1f
}

/// Upstream `aarch64_insn_extract_system_reg(insn)` — bits `[19:5]`.
#[inline]
pub const fn aarch64_insn_extract_system_reg(insn: u32) -> u32 {
    (insn & 0x001F_FFE0) >> 5
}

/// Follow the `b` instruction at `offset` one hop and return its
/// target offset. Returns the original offset when the instruction
/// isn't a `b` (matches upstream `relo_branch_func`).
pub fn relo_branch_func(img: &[u8], func_offset: i32) -> i32 {
    if func_offset < 0 {
        return func_offset;
    }
    let off = func_offset as usize;
    if off + 4 > img.len() {
        return func_offset;
    }
    let insn = u32::from_le_bytes(img[off..off + 4].try_into().unwrap());
    if !is_b(insn) {
        return func_offset;
    }
    let imm26 = bits32(insn, 25, 0) as u64;
    let imm64 = sign64_extend(imm26 << 2, 28);
    func_offset.saturating_add(imm64 as i32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_decode_roundtrip() {
        // b +256 from offset 0.
        let insn = b(0, 256).unwrap();
        assert_eq!(insn, 0x1400_0040);
        assert!(is_b(insn));
        assert_eq!(relo_branch_func(&insn.to_le_bytes(), 0), 256);
    }

    #[test]
    fn encode_negative_displacement() {
        let insn = b(0x1000, 0x0F00).unwrap();
        assert!(is_b(insn));
        // Decoded target must round-trip.
        let bytes = insn.to_le_bytes();
        // relo_branch_func expects the instruction at offset 0x1000
        // inside an image; fabricate a tiny buffer.
        let mut buf = vec![0u8; 0x2000];
        buf[0x1000..0x1004].copy_from_slice(&bytes);
        assert_eq!(relo_branch_func(&buf, 0x1000), 0x0F00);
    }

    #[test]
    fn b_out_of_range_errors() {
        let far = 129 * 1024 * 1024;
        assert!(b(0, far).is_err());
    }

    #[test]
    fn write_b_patches_in_place() {
        let mut buf = vec![0u8; 16];
        write_b(&mut buf, 0, 0, 0x40).unwrap();
        let insn = u32::from_le_bytes(buf[..4].try_into().unwrap());
        assert_eq!(insn, 0x1400_0010);
    }

    #[test]
    fn is_b_rejects_bl() {
        // BL = 0x94000000
        assert!(!is_b(0x9400_0000));
    }

    #[test]
    fn insn_class_mrs_sp_el0() {
        // `mrs x1, sp_el0` = 0xD5384101.
        let insn = 0xD538_4101u32;
        assert_eq!(aarch64_get_insn_class(insn), InsnClass::BrSys);
        assert_eq!(aarch64_insn_extract_system_reg(insn), AARCH64_INSN_SPCLREG_SP_EL0);
    }

    #[test]
    fn insn_class_ldr_sp_base() {
        // `ldr x0, [sp, #16]` = 0xF9400BE0  (class = LDST).
        let insn = 0xF940_0BE0u32;
        assert_eq!(aarch64_get_insn_class(insn), InsnClass::Ldst);
        assert_eq!(
            aarch64_insn_decode_register(RegType::Rn, insn),
            AARCH64_INSN_REG_SP,
        );
    }

    #[test]
    fn insn_class_add_imm_sp() {
        // `add x29, sp, #0x10` = 0x910043FD  (class = DP_IMM, RN=SP).
        let insn = 0x9100_43FDu32;
        assert_eq!(aarch64_get_insn_class(insn), InsnClass::DpImm);
        assert_eq!(
            aarch64_insn_decode_register(RegType::Rn, insn),
            AARCH64_INSN_REG_SP,
        );
    }
}
