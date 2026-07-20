//! Kallsyms table parser.
//!
//! Port of upstream `tools/kallsym.{c,h}` — walks a compiled kernel
//! image, finds the kallsyms compressed-symbol table, reconstructs
//! each symbol name, and answers symbol-to-offset queries.
//!
//! The parser is a multi-pass heuristic: locate the token table by
//! sniffing the compressed tokens for single digits, derive every
//! other section offset by chaining through the table's fixed
//! layout, apply arm64 RELA relocations when present, then walk
//! `kallsyms_names` to verify the layout against the well-known
//! `linux_banner` symbol. Everything here mirrors the C source one
//! step at a time so future upstream rebases stay mechanical.

use kptools_base::{logi, logw, Error, Result};

use crate::preset::VersionT;

pub const KSYM_TOKEN_NUMS: usize = 256;
pub const KSYM_SYMBOL_LEN: usize = 512;
pub const KSYM_MAX_SYMS: usize = 1_000_000;
pub const KSYM_MIN_NEQ_SYMS: usize = 25_600;
pub const KSYM_MIN_MARKER: usize = KSYM_MIN_NEQ_SYMS / 256;
pub const KSYM_FIND_NAMES_USED_MARKER: i32 = 5;
pub const ARM64_RELO_MIN_NUM: usize = 4_000;

pub const ELF64_KERNEL_MIN_VA: u64 = 0xffff_ff80_0808_0000;
pub const ELF64_KERNEL_MAX_VA: u64 = u64::MAX;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchType {
    Arm64,
    X86_64,
    ArmBe,
    ArmLe,
    X86,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CurrentType {
    SpEl0,
    Sp,
}

impl Default for CurrentType {
    fn default() -> Self {
        Self::SpEl0
    }
}

/// Upstream `kallsym_t`. The parser fills this in over several
/// passes — each pass reads earlier fields + writes later ones.
#[derive(Clone, Debug)]
pub struct Kallsym {
    pub arch: ArchType,
    pub is_64: bool,
    pub is_be: bool,
    pub version: VersionT,

    pub banner_num: i32,
    pub linux_banner_offset: [i32; 4],
    pub symbol_banner_idx: i32,

    /// Offset into the kernel image of each entry in the 256-slot
    /// token table. Populated by `find_token_table`.
    pub kallsyms_token_table: [i32; KSYM_TOKEN_NUMS],
    pub asm_long_size: i32,
    pub asm_ptr_size: i32,
    pub kallsyms_markers_elem_size: i32,
    pub kallsyms_num_syms: i32,

    pub has_relative_base: bool,
    pub kallsyms_addresses_offset: i32,
    pub kallsyms_offsets_offset: i32,
    pub kallsyms_num_syms_offset: i32,
    pub kallsyms_names_offset: i32,
    pub kallsyms_markers_offset: i32,
    pub kallsyms_token_table_offset: i32,
    pub kallsyms_token_index_offset: i32,

    pub approx_addresses_or_offsets_offset: i32,
    pub approx_addresses_or_offsets_end: i32,
    pub approx_addresses_or_offsets_num: i32,
    pub marker_num: i32,

    pub try_relo: bool,
    pub relo_applied: bool,
    pub kernel_base: u64,

    pub elf64_rela_num: i32,
    pub elf64_rela_offset: i32,

    pub is_kallsyms_all_yes: bool,
    pub current_type: CurrentType,
}

impl Default for Kallsym {
    fn default() -> Self {
        Self {
            arch: ArchType::Arm64,
            is_64: true,
            is_be: false,
            version: VersionT {
                reserved: 0,
                patch: 0,
                minor: 0,
                major: 0,
            },
            banner_num: 0,
            linux_banner_offset: [0; 4],
            symbol_banner_idx: 0,
            kallsyms_token_table: [0; KSYM_TOKEN_NUMS],
            asm_long_size: 0,
            asm_ptr_size: 0,
            kallsyms_markers_elem_size: 0,
            kallsyms_num_syms: 0,
            has_relative_base: false,
            kallsyms_addresses_offset: 0,
            kallsyms_offsets_offset: 0,
            kallsyms_num_syms_offset: 0,
            kallsyms_names_offset: 0,
            kallsyms_markers_offset: 0,
            kallsyms_token_table_offset: 0,
            kallsyms_token_index_offset: 0,
            approx_addresses_or_offsets_offset: 0,
            approx_addresses_or_offsets_end: 0,
            approx_addresses_or_offsets_num: 0,
            marker_num: 0,
            try_relo: false,
            relo_applied: false,
            kernel_base: 0,
            elf64_rela_num: 0,
            elf64_rela_offset: 0,
            is_kallsyms_all_yes: false,
            current_type: CurrentType::SpEl0,
        }
    }
}

// ---------------------------------------------------------------------------
// Unsigned / signed integer unpack (upstream `uint_unpack` / `int_unpack`).
// ---------------------------------------------------------------------------

fn uint_unpack(buf: &[u8], size: usize, is_be: bool) -> u64 {
    let mut v: u64 = 0;
    if is_be {
        for &b in buf.iter().take(size) {
            v = (v << 8) | b as u64;
        }
    } else {
        for (i, &b) in buf.iter().enumerate().take(size) {
            v |= (b as u64) << (8 * i);
        }
    }
    v
}

fn int_unpack(buf: &[u8], size: usize, is_be: bool) -> i64 {
    let u = uint_unpack(buf, size, is_be);
    // sign-extend from `size` bytes
    let bits = (size as u32) * 8;
    if bits >= 64 {
        u as i64
    } else {
        let shift = 64 - bits;
        ((u << shift) as i64) >> shift
    }
}

fn align_ceil(v: i32, a: i32) -> i32 {
    if a == 0 {
        v
    } else {
        ((v + a - 1) / a) * a
    }
}

// ---------------------------------------------------------------------------
// Banner detection (already the standalone probe in the previous slice,
// now integrated into the analyzer pipeline).
// ---------------------------------------------------------------------------

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

pub fn find_linux_banner(info: &mut Kallsym, img: &[u8]) -> Result<u32> {
    const PREFIX: &[u8] = b"Linux version ";
    info.banner_num = 0;
    info.linux_banner_offset = [0; 4];

    let mut pos = 0usize;
    while let Some(rel) = find_substr(&img[pos..], PREFIX) {
        let banner_start = pos + rel;
        let after = banner_start + PREFIX.len();
        if after + 1 >= img.len() {
            break;
        }
        let digit = img[after];
        let dot = img[after + 1];
        if digit.is_ascii_digit() && dot == b'.' {
            if info.banner_num < info.linux_banner_offset.len() as i32 {
                info.linux_banner_offset[info.banner_num as usize] = banner_start as i32;
            }
            info.banner_num += 1;
        }
        pos = banner_start + 1;
    }

    if info.banner_num == 0 {
        return Err(Error::kallsym("no `Linux version ` banner found"));
    }

    let last_idx = (info.banner_num as usize).min(info.linux_banner_offset.len()) - 1;
    let last_off = info.linux_banner_offset[last_idx] as usize;
    let uts_start = last_off + PREFIX.len();
    let (major, minor, patch) = parse_version_at(&img[uts_start..])?;
    info.version.major = major;
    info.version.minor = minor;
    info.version.patch = patch;

    Ok(info.version.as_u32())
}

fn parse_version_at(bytes: &[u8]) -> Result<(u8, u8, u8)> {
    let (major, rest) = read_u32_until(bytes, b'.')?;
    let (minor, rest) = read_u32_until(rest, b'.')?;
    let (patch, _) = read_u32_until_nondigit(rest);
    Ok((major as u8, minor as u8, patch as u8))
}

fn read_u32_until(bytes: &[u8], term: u8) -> Result<(u32, &[u8])> {
    let mut v: u32 = 0;
    let mut i = 0;
    let mut any = false;
    while i < bytes.len() && bytes[i] != term {
        let c = bytes[i];
        if !c.is_ascii_digit() {
            return Err(Error::kallsym(format!(
                "unexpected byte 0x{c:02x} in version field",
            )));
        }
        v = v
            .checked_mul(10)
            .and_then(|x| x.checked_add((c - b'0') as u32))
            .ok_or_else(|| Error::kallsym("version number overflow"))?;
        any = true;
        i += 1;
    }
    if !any || i >= bytes.len() {
        return Err(Error::kallsym("truncated version field"));
    }
    Ok((v, &bytes[i + 1..]))
}

fn read_u32_until_nondigit(bytes: &[u8]) -> (u32, &[u8]) {
    let mut v: u32 = 0;
    let mut i = 0;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        v = v
            .saturating_mul(10)
            .saturating_add((bytes[i] - b'0') as u32);
        i += 1;
    }
    (v, &bytes[i..])
}

// ---------------------------------------------------------------------------
// find_token_table: scan the image for the 256-entry token table.
//
// The table starts with the 256 single-byte tokens in a fixed
// order; upstream uses the strings "0\01\02\03\04\05\06\07\08\09"
// (ten digits, each null-terminated) as an anchor, then scans back
// to the start of the table.
// ---------------------------------------------------------------------------

fn find_token_table(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let nums_syms: [u8; 20] = {
        let mut a = [0u8; 20];
        for i in 0..10 {
            a[i * 2] = b'0' + i as u8;
        }
        a
    };
    let letters_syms: [u8; 20] = {
        let mut a = [0u8; 20];
        for i in 0..10 {
            a[i * 2] = b'a' + i as u8;
        }
        a
    };

    let mut pos = 0usize;
    let num_start: usize;
    loop {
        let Some(rel) = find_substr(&img[pos..], &nums_syms) else {
            return Err(Error::kallsym("find token_table error"));
        };
        let n = pos + rel;
        let num_end = n + nums_syms.len();
        if num_end + 1 >= img.len() || img[num_end] == 0 || img[num_end + 1] == 0 {
            pos = n + 1;
            continue;
        }

        // Walk forward past the upper-case letters + symbols until
        // we hit the lower-case 'a' anchor. Upstream uses
        // `'a' - '9' - 1 == 0x27` as the null-run count.
        let mut letter = num_end;
        let mut i = 0;
        while letter < img.len() && i < (b'a' - b'9' - 1) as usize {
            if img[letter] == 0 {
                i += 1;
            }
            letter += 1;
        }
        if letter + letters_syms.len() > img.len()
            || &img[letter..letter + letters_syms.len()] != letters_syms.as_slice()
        {
            pos = n + 1;
            continue;
        }

        num_start = n;
        break;
    }

    // Walk backward through the '0'..='9' digit tokens + their null
    // separators to find the first token ('\0') at the table head.
    let mut p = num_start as isize;
    let mut i = 0_i32;
    while p > 0 && i < (b'0' + 1) as i32 {
        if img[p as usize] == 0 {
            i += 1;
        }
        p -= 1;
    }
    let start_offset = (p + 2) as i32; // upstream: `pos + 2 - img`
    let offset = align_ceil(start_offset, 4);
    info.kallsyms_token_table_offset = offset;
    logi!("kallsyms_token_table offset: 0x{offset:08x}");

    // Rebuild the 256-slot offset array.
    let mut p = offset as usize;
    for slot in &mut info.kallsyms_token_table[..] {
        *slot = p as i32;
        while p < img.len() && img[p] != 0 {
            p += 1;
        }
        p += 1; // skip the null terminator
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// find_token_index: the kallsyms_token_index is a 256-entry u16
// array of per-token offsets into the token table. Scan for either
// the LE or BE encoding — the one that matches tells us the target
// endianness.
// ---------------------------------------------------------------------------

fn find_token_index(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let start = info.kallsyms_token_table_offset as usize;
    let mut offset = start;
    let mut le_index = [0u8; KSYM_TOKEN_NUMS * 2];
    let mut be_index = [0u8; KSYM_TOKEN_NUMS * 2];
    for i in 0..KSYM_TOKEN_NUMS {
        let token_index = (offset - start) as u16;
        le_index[i * 2..i * 2 + 2].copy_from_slice(&token_index.to_le_bytes());
        be_index[i * 2..i * 2 + 2].copy_from_slice(&token_index.to_be_bytes());
        while offset < img.len() && img[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }

    let le_pos = find_substr(img, &le_index);
    let be_pos = find_substr(img, &be_index);
    let (pos, is_be) = match (le_pos, be_pos) {
        (Some(p), _) => (p, false),
        (None, Some(p)) => (p, true),
        _ => return Err(Error::kallsym("kallsyms_token_index error")),
    };
    info.is_be = is_be;
    info.kallsyms_token_index_offset = pos as i32;
    logi!(
        "endian: {}, kallsyms_token_index offset: 0x{:08x}",
        if is_be { "big" } else { "little" },
        info.kallsyms_token_index_offset,
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Element-size helpers (asm_long_size / asm_ptr_size variants).
// ---------------------------------------------------------------------------

fn markers_elem_size(info: &Kallsym) -> i32 {
    if info.kallsyms_markers_elem_size != 0 {
        return info.kallsyms_markers_elem_size;
    }
    let mut elem_size = info.asm_long_size;
    if info.version.major < 4 || (info.version.major == 4 && info.version.minor < 20) {
        elem_size = info.asm_ptr_size;
    }
    elem_size
}

fn addresses_elem_size(info: &Kallsym) -> i32 {
    info.asm_ptr_size
}

fn offsets_elem_size(info: &Kallsym) -> i32 {
    info.asm_long_size
}

// ---------------------------------------------------------------------------
// try_find_arm64_relo_table + apply relocations.
//
// Modern android kernels ship a post-link RELA table with absolute-
// address fixups. kptools needs to apply those in-place before
// scanning for the addresses/offsets section, else the uint probes
// see raw relative offsets.
// ---------------------------------------------------------------------------

fn try_find_arm64_relo_table(info: &mut Kallsym, img: &mut [u8]) -> Result<()> {
    if !info.try_relo {
        return Ok(());
    }
    let imglen = img.len() as i32;
    let min_va = ELF64_KERNEL_MIN_VA;
    let max_va = ELF64_KERNEL_MAX_VA;
    let mut kernel_va = max_va;
    let mut cand: i32 = 0;
    let mut rela_num = 0;

    while cand < imglen - 24 {
        let i = cand as usize;
        let r_offset = u64::from_le_bytes(img[i..i + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(img[i + 8..i + 16].try_into().unwrap());
        let r_addend = u64::from_le_bytes(img[i + 16..i + 24].try_into().unwrap());
        let r_type = (r_info & 0xffff_ffff) as u32;
        if (r_offset & 0xffff_0000_0000_0000) == 0xffff_0000_0000_0000
            && (r_type == 0x101 || r_type == 0x403)
        {
            if (r_addend & 0xfff) == 0 && r_addend >= min_va && r_addend < kernel_va {
                kernel_va = r_addend;
            }
            cand += 24;
            rela_num += 1;
        } else if rela_num > 0 && r_offset == 0 && r_info == 0 && r_addend == 0 {
            cand += 24;
            rela_num += 1;
        } else {
            if rela_num >= ARM64_RELO_MIN_NUM as i32 {
                break;
            }
            cand += 8;
            rela_num = 0;
            kernel_va = max_va;
        }
    }

    if info.kernel_base != 0 {
        logi!(
            "arm64 relocation kernel_va: 0x{kernel_va:x}, try: 0x{:x}",
            info.kernel_base
        );
        kernel_va = info.kernel_base;
    } else {
        info.kernel_base = kernel_va;
        logi!("arm64 relocation kernel_va: 0x{kernel_va:x}");
    }

    let cand_start = cand - 24 * rela_num;
    let mut cand_end = cand - 24;
    while cand_end >= 0 {
        let i = cand_end as usize;
        let a = u64::from_le_bytes(img[i..i + 8].try_into().unwrap());
        let b = u64::from_le_bytes(img[i + 8..i + 16].try_into().unwrap());
        let c = u64::from_le_bytes(img[i + 16..i + 24].try_into().unwrap());
        if a != 0 && b != 0 && c != 0 {
            break;
        }
        cand_end -= 24;
    }
    cand_end += 24;

    let rela_num = (cand_end - cand_start) / 24;
    if rela_num < ARM64_RELO_MIN_NUM as i32 {
        logw!("can't find arm64 relocation table");
        return Ok(());
    }
    logi!(
        "arm64 relocation table range: [0x{cand_start:08x}, 0x{cand_end:08x}), count: 0x{rela_num:08x}"
    );

    // apply
    let max_offset = imglen - 8;
    let mut apply_num = 0_i32;
    let mut bad_offset_num = 0_i32;
    let mut c = cand_start;
    while c < cand_end {
        let i = c as usize;
        let r_offset = u64::from_le_bytes(img[i..i + 8].try_into().unwrap());
        let r_info = u64::from_le_bytes(img[i + 8..i + 16].try_into().unwrap());
        let mut r_addend = u64::from_le_bytes(img[i + 16..i + 24].try_into().unwrap());
        c += 24;
        if r_offset == 0 && r_info == 0 && r_addend == 0 {
            continue;
        }
        if r_offset <= kernel_va || r_offset >= max_va - imglen as u64 {
            continue;
        }
        let offset_i64 = r_offset as i64 - kernel_va as i64;
        if offset_i64 < 0 || offset_i64 >= max_offset as i64 {
            bad_offset_num += 1;
            continue;
        }
        let offset = offset_i64 as usize;
        let r_type = (r_info & 0xffff_ffff) as u32;
        if r_type == 0x101 {
            r_addend = r_addend.wrapping_add(kernel_va);
        }
        let value = u64::from_le_bytes(img[offset..offset + 8].try_into().unwrap());
        if value == r_addend {
            continue;
        }
        let new_val = value.wrapping_add(r_addend);
        img[offset..offset + 8].copy_from_slice(&new_val.to_le_bytes());
        apply_num += 1;
    }
    if apply_num > 0 {
        apply_num -= 1;
    }
    logi!("apply 0x{apply_num:08x} relocation entries");
    if bad_offset_num > 0 {
        logw!("ignore 0x{bad_offset_num:08x} out-of-range relocation entries");
    }
    if apply_num > 0 {
        info.relo_applied = true;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// find_approx_addresses / find_approx_offsets.
// ---------------------------------------------------------------------------

fn find_approx_addresses(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem_size = info.asm_ptr_size as usize;
    let imglen = img.len() as i32;
    let mut sym_num = 0_i32;
    let mut prev_offset: u64 = 0;
    let mut cand: i32 = 0;

    while cand < imglen - (KSYM_MIN_NEQ_SYMS as i32) * elem_size as i32 {
        let i = cand as usize;
        let address = uint_unpack(&img[i..], elem_size, info.is_be);
        if sym_num == 0 {
            if address & 0xff != 0 {
                cand += elem_size as i32;
                continue;
            }
            if elem_size == 4 && (address & 0xff80_0000) != 0xff80_0000 {
                cand += elem_size as i32;
                continue;
            }
            if elem_size == 8 && (address & 0xffff_0000_0000_0000) != 0xffff_0000_0000_0000 {
                cand += elem_size as i32;
                continue;
            }
            prev_offset = address;
            sym_num += 1;
            cand += elem_size as i32;
            continue;
        }
        if address >= prev_offset {
            prev_offset = address;
            sym_num += 1;
            if sym_num >= KSYM_MIN_NEQ_SYMS as i32 {
                break;
            }
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
        cand += elem_size as i32;
    }
    if sym_num < KSYM_MIN_NEQ_SYMS as i32 {
        return Err(Error::kallsym("find approximate kallsyms_addresses error"));
    }

    cand -= (KSYM_MIN_NEQ_SYMS as i32) * elem_size as i32;
    let approx_offset = cand;
    info.approx_addresses_or_offsets_offset = approx_offset;

    prev_offset = 0;
    while (cand as usize) + elem_size <= img.len() {
        let offset = uint_unpack(&img[cand as usize..], elem_size, info.is_be);
        if offset < prev_offset {
            break;
        }
        prev_offset = offset;
        cand += elem_size as i32;
    }
    info.approx_addresses_or_offsets_end = cand;
    info.has_relative_base = false;
    let approx_num = (cand - approx_offset) / elem_size as i32;
    info.approx_addresses_or_offsets_num = approx_num;
    logi!(
        "approximate kallsyms_addresses range: [0x{approx_offset:08x}, 0x{cand:08x}) count: 0x{approx_num:08x}"
    );
    if info.relo_applied {
        logw!("mismatch relo applied, subsequent operations may be undefined");
    }
    Ok(())
}

fn find_approx_offsets(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem_size = info.asm_long_size as usize;
    let imglen = img.len() as i32;
    let max_zero_offset_num = 10;
    let mut zero_offset_num = 0;
    let mut sym_num = 0_i32;
    let mut prev_offset: i64 = 0;
    let mut cand: i32 = 0;

    while cand < imglen - (KSYM_MIN_NEQ_SYMS as i32) * elem_size as i32 {
        let off = int_unpack(&img[cand as usize..], elem_size, info.is_be);
        if sym_num == 0 {
            // 0.13.2: skip leading zeros until the first non-zero offset.
            if off == 0 {
                cand += elem_size as i32;
                continue;
            }
            prev_offset = off;
            sym_num += 1;
            cand += elem_size as i32;
            continue;
        }
        if off == prev_offset {
            cand += elem_size as i32;
            continue;
        } else if off > prev_offset {
            prev_offset = off;
            sym_num += 1;
            if sym_num >= KSYM_MIN_NEQ_SYMS as i32 {
                break;
            }
        } else {
            prev_offset = 0;
            sym_num = 0;
        }
        cand += elem_size as i32;
    }
    if sym_num < KSYM_MIN_NEQ_SYMS as i32 {
        logw!("find approximate kallsyms_offsets error");
        return Err(Error::kallsym("find approximate kallsyms_offsets error"));
    }

    cand -= (KSYM_MIN_NEQ_SYMS as i32) * elem_size as i32;
    while cand >= 0 && int_unpack(&img[cand as usize..], elem_size, info.is_be) != 0 {
        cand -= elem_size as i32;
    }
    loop {
        if cand < 0 {
            break;
        }
        if int_unpack(&img[cand as usize..], elem_size, info.is_be) != 0 {
            break;
        }
        zero_offset_num += 1;
        if zero_offset_num >= max_zero_offset_num {
            break;
        }
        cand -= elem_size as i32;
    }
    cand += elem_size as i32;

    let approx_offset = cand;
    info.approx_addresses_or_offsets_offset = approx_offset;

    prev_offset = 0;
    while (cand as usize) + elem_size <= img.len() {
        let off = int_unpack(&img[cand as usize..], elem_size, info.is_be);
        if off < prev_offset {
            break;
        }
        prev_offset = off;
        cand += elem_size as i32;
    }
    let end = cand;
    info.approx_addresses_or_offsets_end = end;
    info.has_relative_base = true;
    let approx_num = (end - approx_offset) / elem_size as i32;
    info.approx_addresses_or_offsets_num = approx_num;
    logi!(
        "approximate kallsyms_offsets range: [0x{approx_offset:08x}, 0x{end:08x}) count: 0x{approx_num:08x}"
    );
    Ok(())
}

fn find_approx_addresses_or_offset(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    // 0.13.2: vendor arm64 kernels can carry kallsyms_offsets even
    // on older version strings such as 4.4, so don't gate the
    // relative-base path purely on the reported kernel version.
    if info.arch == ArchType::Arm64 && info.is_64 {
        logi!("try kallsyms_offsets first for arm64");
        if find_approx_offsets(info, img).is_ok() {
            return Ok(());
        }
    } else if (info.version.major > 4 || (info.version.major == 4 && info.version.minor >= 6))
        && find_approx_offsets(info, img).is_ok()
    {
        return Ok(());
    }
    logi!("fallback to kallsyms_addresses scan");
    find_approx_addresses(info, img)
}

// ---------------------------------------------------------------------------
// find_markers — walks backwards from the token-table offset to
// locate the kallsyms_markers array. Marker entries are monotonic-
// increasing offsets, so the last non-zero marker is followed by
// zero padding then the token table.
// ---------------------------------------------------------------------------

fn find_markers_internal(info: &mut Kallsym, img: &[u8], elem_size: i32) -> Result<()> {
    let mut cand = info.kallsyms_token_table_offset;
    let imglen = img.len() as i64;
    let mut last_marker: i64 = imglen;
    let mut count = 0_i32;

    while cand > 0x10000 {
        let marker = int_unpack(&img[cand as usize..], elem_size as usize, info.is_be);
        if last_marker > marker {
            count += 1;
            if marker == 0 && count > KSYM_MIN_MARKER as i32 {
                break;
            }
        } else {
            count = 0;
        }
        last_marker = marker;
        cand -= elem_size;
    }
    if count < KSYM_MIN_MARKER as i32 {
        logw!("find kallsyms_markers error");
        return Err(Error::kallsym("find kallsyms_markers error"));
    }

    let marker_end = cand + count * elem_size + elem_size;
    info.kallsyms_markers_offset = cand;
    info.marker_num = count;
    info.kallsyms_markers_elem_size = elem_size;
    logi!("kallsyms_markers range: [0x{cand:08x}, 0x{marker_end:08x}), count: 0x{count:08x}");
    Ok(())
}

fn find_markers(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem_size = markers_elem_size(info);
    match find_markers_internal(info, img, elem_size) {
        Ok(()) => Ok(()),
        Err(_) if elem_size == 8 => find_markers_internal(info, img, 4),
        Err(e) => Err(e),
    }
}

// ---------------------------------------------------------------------------
// decompress_symbol_name (used by find_names + get_symbol_offset).
// ---------------------------------------------------------------------------

fn decompress_symbol_name(
    info: &Kallsym,
    img: &[u8],
    pos_to_next: &mut i32,
    mut out_symbol: Option<&mut Vec<u8>>,
) -> Result<u8> {
    let mut pos = *pos_to_next as usize;
    if pos >= img.len() {
        return Err(Error::kallsym("decompress_symbol_name OOB"));
    }
    let mut len = img[pos] as usize;
    pos += 1;
    if len > 0x7F {
        if pos >= img.len() {
            return Err(Error::kallsym("decompress_symbol_name truncated length"));
        }
        len = (len & 0x7F) + ((img[pos] as usize) << 7);
        pos += 1;
    }
    if len == 0 || len >= KSYM_SYMBOL_LEN {
        return Err(Error::kallsym("decompress_symbol_name bad length"));
    }
    if pos + len > img.len() {
        return Err(Error::kallsym("decompress_symbol_name OOB"));
    }

    *pos_to_next = (pos + len) as i32;
    let mut ty = 0_u8;
    for i in 0..len {
        let tokidx = img[pos + i] as usize;
        let mut tok_start = info.kallsyms_token_table[tokidx] as usize;
        let tok_end = token_end(img, tok_start);
        let token = &img[tok_start..tok_end];
        if i == 0 {
            ty = token[0];
            tok_start += 1;
        }
        if let Some(out) = out_symbol.as_deref_mut() {
            out.extend_from_slice(&img[tok_start.min(tok_end)..tok_end]);
        }
        let _ = tok_start;
    }
    Ok(ty)
}

fn token_end(img: &[u8], mut pos: usize) -> usize {
    while pos < img.len() && img[pos] != 0 {
        pos += 1;
    }
    pos
}

// ---------------------------------------------------------------------------
// find_names — locate kallsyms_names by walking the compressed
// stream forward from every candidate start and checking that each
// 256-symbol boundary matches the marker table.
// ---------------------------------------------------------------------------

fn verify_names_candidate(info: &Kallsym, img: &[u8], marker_elem_size: usize, cand: i32) -> bool {
    let marker_off = info.kallsyms_markers_offset as usize;
    let mut pos = cand as usize;
    let mut test_marker_num = KSYM_FIND_NAMES_USED_MARKER;
    let mut i = 0_i32;
    loop {
        if pos >= marker_off || pos >= img.len() {
            return false;
        }
        let mut len = img[pos] as usize;
        pos += 1;
        if len > 0x7F {
            if pos >= marker_off || pos >= img.len() {
                return false;
            }
            len = (len & 0x7F) + ((img[pos] as usize) << 7);
            pos += 1;
        }
        if len == 0 || len >= KSYM_SYMBOL_LEN {
            return false;
        }
        if pos + len > marker_off {
            return false;
        }
        pos += len;
        if pos >= marker_off {
            return false;
        }

        if i > 0 && (i & 0xFF) == 0xFF {
            let marker_index = (i >> 8) + 1;
            let marker_offset = marker_index as usize * marker_elem_size;
            let marker_table_size = info.marker_num as usize * marker_elem_size;
            if marker_index >= info.marker_num {
                return false;
            }
            if marker_offset > marker_table_size.saturating_sub(marker_elem_size) {
                return false;
            }
            let marker_pos = marker_off + marker_offset;
            if marker_pos + marker_elem_size > img.len() {
                return false;
            }
            let mark_len = int_unpack(&img[marker_pos..], marker_elem_size, info.is_be) as i32;
            if pos as i32 - cand != mark_len {
                return false;
            }
            test_marker_num -= 1;
            if test_marker_num == 0 {
                return true;
            }
        }
        i += 1;
    }
}

fn find_names(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let marker_elem_size = markers_elem_size(info) as usize;
    let marker_off = info.kallsyms_markers_offset;

    // 0.13.2: when we have enough markers, guess the names start
    // from the last marker length before falling back to a full scan.
    if info.marker_num > KSYM_FIND_NAMES_USED_MARKER {
        let last_marker = int_unpack(
            &img[marker_off as usize + (info.marker_num as usize - 1) * marker_elem_size..],
            marker_elem_size,
            info.is_be,
        ) as i32;
        let guess = marker_off - last_marker;
        let mut guess_start = guess - 0x10000;
        let mut guess_end = guess + 0x1000;
        if guess_start < 0x4000 {
            guess_start = 0x4000;
        }
        if guess_end > marker_off {
            guess_end = marker_off;
        }
        let mut cand = guess_start;
        while cand < guess_end {
            if verify_names_candidate(info, img, marker_elem_size, cand) {
                info.kallsyms_names_offset = cand;
                logi!("kallsyms_names offset: 0x{cand:08x}");
                return Ok(());
            }
            cand += 1;
        }
    }

    let mut cand = 0x4000_i32;
    while cand < marker_off {
        if verify_names_candidate(info, img, marker_elem_size, cand) {
            info.kallsyms_names_offset = cand;
            logi!("kallsyms_names offset: 0x{cand:08x}");
            return Ok(());
        }
        cand += 1;
    }
    Err(Error::kallsym("find kallsyms_names error"))
}

// ---------------------------------------------------------------------------
// find_num_syms: the num_syms field is a 4-byte integer that sits
// just before kallsyms_names. Scan backward from the names offset
// checking each slot's value is close to the approximated sym count.
// ---------------------------------------------------------------------------

fn find_num_syms(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    const NSYMS_MAX_GAP: i32 = 10;
    let approx_end = info.kallsyms_names_offset;
    let num_syms_elem_size = 4_i32;
    let approx_num = info.approx_addresses_or_offsets_num;

    let mut found = false;
    let mut cand = approx_end;
    while cand > approx_end - 4096 {
        if cand < 0 || (cand as usize) + num_syms_elem_size as usize > img.len() {
            cand -= num_syms_elem_size;
            continue;
        }
        let nsyms = int_unpack(
            &img[cand as usize..],
            num_syms_elem_size as usize,
            info.is_be,
        ) as i32;
        if nsyms == 0 {
            cand -= num_syms_elem_size;
            continue;
        }
        let gap = (nsyms - approx_num).abs();
        if gap <= NSYMS_MAX_GAP {
            info.kallsyms_num_syms = nsyms;
            info.kallsyms_num_syms_offset = cand;
            found = true;
            break;
        }
        cand -= num_syms_elem_size;
    }
    if !found {
        info.kallsyms_num_syms = approx_num - NSYMS_MAX_GAP;
        logw!(
            "can't find kallsyms_num_syms, try: 0x{:08x}",
            info.kallsyms_num_syms
        );
    } else {
        logi!(
            "kallsyms_num_syms offset: 0x{:08x}, value: 0x{:08x}",
            info.kallsyms_num_syms_offset,
            info.kallsyms_num_syms
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// correct_addresses_or_offsets_by_banner — use the well-known
// `linux_banner` symbol to pin the addresses / offsets start.
// ---------------------------------------------------------------------------

fn correct_addresses_or_offsets_by_banner(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let mut pos = info.kallsyms_names_offset;
    let mut index = 0_i32;
    let mut found_banner = false;
    while (pos as usize) < info.kallsyms_markers_offset as usize {
        let mut sym = Vec::with_capacity(KSYM_SYMBOL_LEN);
        if decompress_symbol_name(info, img, &mut pos, Some(&mut sym)).is_err() {
            break;
        }
        if sym == b"linux_banner" {
            logi!("names table linux_banner index: 0x{index:08x}");
            found_banner = true;
            break;
        }
        index += 1;
    }
    if !found_banner {
        return Err(Error::kallsym("no linux_banner in names table"));
    }
    info.symbol_banner_idx = -1;

    let elem_size = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    } as usize;

    let mut found_pos: Option<i32> = None;
    for i in 0..info.banner_num {
        let target = info.linux_banner_offset[i as usize];
        let mut pos = info.approx_addresses_or_offsets_offset;
        let end = pos + 4096 + elem_size as i32;
        while pos < end {
            let base = uint_unpack(&img[pos as usize..], elem_size, info.is_be);
            let idx_slot = uint_unpack(
                &img[pos as usize + index as usize * elem_size..],
                elem_size,
                info.is_be,
            );
            let offset = idx_slot.wrapping_sub(base) as i32;
            if offset == target {
                break;
            }
            pos += elem_size as i32;
        }
        if pos < end {
            info.symbol_banner_idx = i;
            found_pos = Some(pos);
            logi!("linux_banner index: {i}");
            break;
        }
    }

    let Some(pos) = found_pos else {
        return Err(Error::kallsym("correct address or offsets error"));
    };

    if info.has_relative_base {
        info.kallsyms_offsets_offset = pos;
        logi!("kallsyms_offsets offset: 0x{pos:08x}");
    } else {
        info.kallsyms_addresses_offset = pos;
        logi!("kallsyms_addresses offset: 0x{pos:08x}");
        info.kernel_base = uint_unpack(&img[pos as usize..], elem_size, info.is_be);
        logi!("kernel base address: 0x{:x}", info.kernel_base);
    }
    // Walk the first 6 insns of `pid_vnr` and classify how the
    // kernel reads `current` — `mrs xN, sp_el0` ⇒ SP_EL0, otherwise
    // a stack-relative load (LDR/STR with RN == SP) ⇒ SP.
    let pid_vnr_offset = get_symbol_offset_zero(info, img, "pid_vnr");
    if arm64_verify_pid_vnr(info, img, pid_vnr_offset).is_err() {
        logw!("pid_vnr verification failed");
    }
    Ok(())
}

/// Port of upstream `arm64_verify_pid_vnr` — set `info.current_type`
/// by sniffing how `pid_vnr` reads the current task pointer. Returns
/// `Err` when no matching instruction is found in the first 6 words.
fn arm64_verify_pid_vnr(info: &mut Kallsym, img: &[u8], offset: i32) -> Result<()> {
    use crate::insn::{
        aarch64_get_insn_class, aarch64_insn_decode_register, aarch64_insn_extract_system_reg,
        InsnClass, RegType, AARCH64_INSN_REG_SP, AARCH64_INSN_SPCLREG_SP_EL0,
    };
    if offset <= 0 {
        return Err(Error::kallsym("pid_vnr offset invalid"));
    }
    for i in 0..6i32 {
        let insn_off = offset as usize + (i as usize) * 4;
        if insn_off + 4 > img.len() {
            break;
        }
        let insn = uint_unpack(&img[insn_off..], 4, false) as u32;
        match aarch64_get_insn_class(insn) {
            InsnClass::BrSys => {
                if aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0 {
                    logi!("pid_vnr verified sp_el0, insn: 0x{insn:x}");
                    info.current_type = CurrentType::SpEl0;
                    return Ok(());
                }
            }
            InsnClass::DpImm => {
                let rn = aarch64_insn_decode_register(RegType::Rn, insn);
                if rn == AARCH64_INSN_REG_SP {
                    logi!("pid_vnr verified sp, insn: 0x{insn:x}");
                    info.current_type = CurrentType::Sp;
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    Err(Error::kallsym("pid_vnr current-type classification failed"))
}

/// Port of upstream `correct_addresses_or_offsets_by_vectors`.
///
/// Used when `linux_banner` is absent (`CONFIG_KALLSYMS_ALL=n`).
/// Locates the `vectors` + `pid_vnr` name-table indices, then scans
/// the approximate addresses/offsets window for a candidate base
/// where:
/// - consecutive `vectors` entries are ≥ 0x600 apart,
/// - the first is 2KiB-aligned (`.align 11`),
/// - `pid_vnr` at that base verifies via `arm64_verify_pid_vnr`.
///
/// 0.13.2 bounds the scan with `max_shift` and a `pid_vnr_limit`
/// derived from the approximate table end.
fn correct_addresses_or_offsets_by_vectors(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let mut pos = info.kallsyms_names_offset;
    let mut index = 0_i32;
    let mut vector_index = 0_i32;
    let mut pid_vnr_index = 0_i32;

    while pos < info.kallsyms_markers_offset {
        let mut sym = Vec::with_capacity(KSYM_SYMBOL_LEN);
        decompress_symbol_name(info, img, &mut pos, Some(&mut sym))?;
        if vector_index == 0 && sym == b"vectors" {
            vector_index = index;
        } else if pid_vnr_index == 0 && sym == b"pid_vnr" {
            pid_vnr_index = index;
        }
        if vector_index != 0 && pid_vnr_index != 0 {
            logi!(
                "names table vector index: 0x{vector_index:08x}, pid_vnr index: 0x{pid_vnr_index:08x}"
            );
            break;
        }
        index += 1;
    }

    if pos >= info.kallsyms_markers_offset || vector_index == 0 || pid_vnr_index == 0 {
        return Err(Error::kallsym("no verify symbol in names table"));
    }

    let elem_size = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    } as usize;
    if elem_size == 0 {
        return Err(Error::kallsym("invalid addresses/offsets element size"));
    }

    let mut base_cands: [u64; 3] = [0; 3];
    let mut base_cand_num = 1_i32;
    if !info.has_relative_base {
        let approx = info.approx_addresses_or_offsets_offset as usize;
        if approx + elem_size > img.len() {
            return Err(Error::kallsym("approx addresses OOB"));
        }
        base_cands[0] = uint_unpack(&img[approx..], elem_size, info.is_be);
        if info.kernel_base != 0 {
            base_cands[base_cand_num as usize] = info.kernel_base;
            base_cand_num += 1;
        }
        if info.kernel_base != ELF64_KERNEL_MIN_VA {
            base_cands[base_cand_num as usize] = ELF64_KERNEL_MIN_VA;
            base_cand_num += 1;
        }
    }

    let search_start = info.approx_addresses_or_offsets_offset;
    let mut max_shift = info.approx_addresses_or_offsets_num - info.kallsyms_num_syms;
    if max_shift < 0 {
        max_shift = 0;
    }
    let mut search_end = search_start + (max_shift + 1) * elem_size as i32;
    let pid_vnr_limit = info.approx_addresses_or_offsets_end - pid_vnr_index * elem_size as i32;
    if search_end > pid_vnr_limit {
        search_end = pid_vnr_limit;
    }
    if search_end < search_start {
        return Err(Error::kallsym("can't locate vectors"));
    }

    let mut found_pos: Option<i32> = None;
    'bases: for i in 0..base_cand_num {
        let base = base_cands[i as usize];
        let mut cand = search_start;
        while cand < search_end {
            let vec_slot = cand as usize + vector_index as usize * elem_size;
            let vec_next_slot = vec_slot + elem_size;
            let pid_slot = cand as usize + pid_vnr_index as usize * elem_size;
            if pid_slot + elem_size > img.len() || vec_next_slot + elem_size > img.len() {
                break;
            }
            let vector_offset =
                (uint_unpack(&img[vec_slot..], elem_size, info.is_be).wrapping_sub(base)) as i32;
            let vector_next_offset = (uint_unpack(&img[vec_next_slot..], elem_size, info.is_be)
                .wrapping_sub(base)) as i32;
            if vector_next_offset - vector_offset >= 0x600
                && (vector_offset as u32 & ((1 << 11) - 1)) == 0
            {
                let pid_vnr_offset = (uint_unpack(&img[pid_slot..], elem_size, info.is_be)
                    .wrapping_sub(base)) as i32;
                if arm64_verify_pid_vnr(info, img, pid_vnr_offset).is_ok() {
                    logi!("vectors index: {vector_index}, offset: 0x{vector_offset:08x}");
                    logi!("pid_vnr offset: 0x{pid_vnr_offset:08x}");
                    info.kernel_base = base;
                    found_pos = Some(cand);
                    break 'bases;
                }
            }
            cand += elem_size as i32;
        }
    }

    let Some(pos) = found_pos else {
        return Err(Error::kallsym("can't locate vectors"));
    };

    if info.has_relative_base {
        info.kallsyms_offsets_offset = pos;
        logi!("kallsyms_offsets offset: 0x{pos:08x}");
    } else {
        info.kallsyms_addresses_offset = pos;
        logi!("kallsyms_addresses offset: 0x{pos:08x}");
        logi!("kernel base address: 0x{:x}", info.kernel_base);
    }
    Ok(())
}

fn correct_addresses_or_offsets(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    // Upstream order (0.13.2):
    //   1. try banner path; set is_kallsyms_all_yes=1 on entry
    //   2. on failure clear the flag, log CONFIG_KALLSYMS_ALL=n
    //   3. fall back to vectors path
    //   4. coverage check against approx table end
    let mut rc = correct_addresses_or_offsets_by_banner(info, img);
    info.is_kallsyms_all_yes = true;
    if rc.is_err() {
        info.is_kallsyms_all_yes = false;
        logw!("no linux_banner, CONFIG_KALLSYMS_ALL=n");
        rc = correct_addresses_or_offsets_by_vectors(info, img);
    }
    rc?;

    let elem_size = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    };
    if elem_size == 0 {
        return Err(Error::kallsym("invalid addresses/offsets element size"));
    }
    let start = if info.has_relative_base {
        info.kallsyms_offsets_offset
    } else {
        info.kallsyms_addresses_offset
    };
    let coverage = (info.approx_addresses_or_offsets_end - start) / elem_size;
    if coverage < info.kallsyms_num_syms {
        logw!(
            "resolved symbol table only covers 0x{coverage:08x} entries, but names table has 0x{:08x} entries",
            info.kallsyms_num_syms
        );
        return Err(Error::kallsym("symbol table coverage too small"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// analyze_kallsym_info — the public entry point.
// ---------------------------------------------------------------------------

fn retry_relo(info: &mut Kallsym, img: &mut [u8]) -> Result<()> {
    try_find_arm64_relo_table(info, img)?;
    find_markers(info, img)?;
    find_approx_addresses_or_offset(info, img)?;
    find_names(info, img)?;
    find_num_syms(info, img)?;
    correct_addresses_or_offsets(info, img)?;
    Ok(())
}

pub fn analyze_kallsym_info(
    info: &mut Kallsym,
    img: &mut [u8],
    arch: ArchType,
    is_64: bool,
) -> Result<()> {
    *info = Kallsym::default();
    info.arch = arch;
    info.is_64 = is_64;
    info.asm_long_size = 4;
    info.asm_ptr_size = if is_64 { 8 } else { 4 };
    info.try_relo = arch == ArchType::Arm64;

    find_linux_banner(info, img)?;
    find_token_table(info, img)?;
    find_token_index(info, img)?;

    // 0.13.2: capture a raw (pre-relocation) markers+names layout so
    // we can restore names/token tables if applying relocations
    // corrupts them, then re-scan addresses/offsets on the relocated
    // image.
    let mut raw_layout = info.clone();
    let raw_layout_ready =
        find_markers(&mut raw_layout, img).is_ok() && find_names(&mut raw_layout, img).is_ok();

    let saved = img.to_vec();
    let mut work = saved.clone();

    // 1st
    if retry_relo(info, &mut work).is_ok() {
        img.copy_from_slice(&work);
        return Ok(());
    }

    if raw_layout_ready {
        work.copy_from_slice(&saved);
        *info = raw_layout.clone();
        if try_find_arm64_relo_table(info, &mut work).is_ok() {
            let restore_start = info.kallsyms_names_offset.max(0) as usize;
            let restore_end = (info.kallsyms_token_index_offset + KSYM_TOKEN_NUMS as i32 * 2)
                .min(img.len() as i32)
                .max(0) as usize;
            if restore_start < restore_end && restore_end <= work.len() {
                work[restore_start..restore_end]
                    .copy_from_slice(&saved[restore_start..restore_end]);
            }
            if find_approx_addresses_or_offset(info, &work).is_ok()
                && find_num_syms(info, &work).is_ok()
                && correct_addresses_or_offsets(info, &work).is_ok()
            {
                img.copy_from_slice(&work);
                return Ok(());
            }
        }
    }

    // 2nd — bypass relocations if the 1st pass failed and try_relo
    // was set (already applied + not helping).
    if !info.try_relo {
        work.copy_from_slice(&saved);
        if retry_relo(info, &mut work).is_ok() {
            img.copy_from_slice(&work);
            return Ok(());
        }
    }

    // 3rd — pin kernel_base to ELF64_KERNEL_MIN_VA and retry.
    if info.kernel_base != ELF64_KERNEL_MIN_VA {
        info.kernel_base = ELF64_KERNEL_MIN_VA;
        work.copy_from_slice(&saved);
        if retry_relo(info, &mut work).is_ok() {
            img.copy_from_slice(&work);
            return Ok(());
        }
    }
    Err(Error::kallsym("analyze_kallsym_info exhausted retries"))
}

// ---------------------------------------------------------------------------
// Symbol lookup + iteration
// ---------------------------------------------------------------------------

pub fn get_symbol_index_offset(info: &Kallsym, img: &[u8], index: i32) -> i32 {
    let (elem_size, pos) = if info.has_relative_base {
        (offsets_elem_size(info), info.kallsyms_offsets_offset)
    } else {
        (addresses_elem_size(info), info.kallsyms_addresses_offset)
    };
    let elem_size = elem_size as usize;
    let target = uint_unpack(
        &img[pos as usize + index as usize * elem_size..],
        elem_size,
        info.is_be,
    );
    if info.has_relative_base {
        target as i32
    } else {
        (target.wrapping_sub(info.kernel_base)) as i32
    }
}

pub fn get_symbol_offset(info: &Kallsym, img: &[u8], symbol: &str) -> Option<i32> {
    let mut pos = info.kallsyms_names_offset;
    for i in 0..info.kallsyms_num_syms {
        let mut decomp = Vec::with_capacity(KSYM_SYMBOL_LEN);
        if decompress_symbol_name(info, img, &mut pos, Some(&mut decomp)).is_err() {
            return None;
        }
        if decomp == symbol.as_bytes() {
            return Some(get_symbol_index_offset(info, img, i));
        }
    }
    None
}

pub fn get_symbol_offset_zero(info: &Kallsym, img: &[u8], symbol: &str) -> i32 {
    get_symbol_offset(info, img, symbol)
        .filter(|o| *o > 0)
        .unwrap_or(0)
}

/// Upstream `is_symbol_exists` — true when `symbol` appears in the
/// names table, regardless of whether its address resolves.
pub fn is_symbol_exists(info: &Kallsym, img: &[u8], symbol: &str) -> bool {
    let mut pos = info.kallsyms_names_offset;
    for _ in 0..info.kallsyms_num_syms {
        let mut decomp = Vec::with_capacity(KSYM_SYMBOL_LEN);
        if decompress_symbol_name(info, img, &mut pos, Some(&mut decomp)).is_err() {
            return false;
        }
        if decomp == symbol.as_bytes() {
            return true;
        }
    }
    false
}

pub fn get_symbol_offset_exit(info: &Kallsym, img: &[u8], symbol: &str) -> Result<i32> {
    get_symbol_offset(info, img, symbol)
        .ok_or_else(|| Error::kallsym(format!("symbol `{symbol}` not found")))
}

pub fn on_each_symbol<F>(info: &Kallsym, img: &[u8], mut f: F) -> Result<()>
where
    F: FnMut(i32, u8, &[u8], i32) -> i32,
{
    let mut pos = info.kallsyms_names_offset;
    for i in 0..info.kallsyms_num_syms {
        let mut sym = Vec::with_capacity(KSYM_SYMBOL_LEN);
        let ty = decompress_symbol_name(info, img, &mut pos, Some(&mut sym))?;
        let off = get_symbol_index_offset(info, img, i);
        let rc = f(i, ty, &sym, off);
        if rc != 0 {
            return Ok(());
        }
    }
    Ok(())
}

/// Locate the embedded IKCONFIG gzip blob between `IKCFG_ST` and
/// `IKCFG_ED`. Returns `(start, size)` of the gzip payload, or an
/// integer reason code matching upstream `find_ikconfig_blob`
/// (`1` no start, `2` no end, `3` empty).
pub fn find_ikconfig_blob(img: &[u8]) -> std::result::Result<(usize, usize), i32> {
    const IKCFG_ST: &[u8] = b"IKCFG_ST";
    const IKCFG_ED: &[u8] = b"IKCFG_ED";

    let start_marker = img
        .windows(IKCFG_ST.len())
        .position(|w| w == IKCFG_ST)
        .ok_or(1)?;
    let mut kcfg_start = start_marker + IKCFG_ST.len();
    let end_rel = img[kcfg_start..]
        .windows(IKCFG_ED.len())
        .position(|w| w == IKCFG_ED)
        .ok_or(2)?;
    let pos_end = kcfg_start + end_rel;
    while kcfg_start < img.len() && (img[kcfg_start] == 0 || img[kcfg_start] == b'\n') {
        kcfg_start += 1;
    }
    if pos_end < kcfg_start {
        return Err(3);
    }
    let kcfg_bytes = pos_end - kcfg_start;
    if kcfg_bytes == 0 {
        return Err(3);
    }
    Ok((kcfg_start, kcfg_bytes))
}

/// Port of upstream `dump_all_ikconfig`. Finds the `IKCFG_ST` /
/// `IKCFG_ED` markers in the kernel image, gunzips the embedded
/// `.config`, writes it to stdout.
pub fn dump_all_ikconfig(img: &[u8]) -> Result<()> {
    use std::io::Read;

    let (kcfg_start, kcfg_bytes) = find_ikconfig_blob(img)
        .map_err(|rc| Error::kallsym(format!("Cannot find kernel config blob, rc={rc}")))?;
    logi!("Kernel config start: {kcfg_start}, bytes: {kcfg_bytes}");
    let cfg = &img[kcfg_start..kcfg_start + kcfg_bytes];

    let mut dec = flate2::read::GzDecoder::new(cfg);
    let mut out = String::new();
    dec.read_to_string(&mut out)
        .map_err(|e| Error::kallsym(format!("ikconfig gunzip failed: {e}")))?;
    print!("{out}");
    Ok(())
}

/// Port of upstream `extract_ikconfig` — inflate the IKCONFIG blob
/// into an owned buffer. Used by library callers that need the
/// decompressed config rather than a stdout dump.
pub fn extract_ikconfig(img: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;

    let (kcfg_start, kcfg_bytes) = find_ikconfig_blob(img)
        .map_err(|rc| Error::kallsym(format!("Cannot find kernel config blob, rc={rc}")))?;
    let cfg = &img[kcfg_start..kcfg_start + kcfg_bytes];
    let mut dec = flate2::read::GzDecoder::new(cfg);
    let mut out = Vec::new();
    dec.read_to_end(&mut out)
        .map_err(|e| Error::kallsym(format!("ikconfig gunzip failed: {e}")))?;
    Ok(out)
}

pub fn dump_all_symbols(info: &Kallsym, img: &[u8]) {
    let _ = on_each_symbol(info, img, |_i, ty, sym, off| {
        println!(
            "0x{off:08x} {} {}",
            ty as char,
            std::str::from_utf8(sym).unwrap_or("<non-utf8>")
        );
        0
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_kernel_with_banner(banner: &str) -> Vec<u8> {
        let mut v = vec![0u8; 4096];
        v.extend_from_slice(banner.as_bytes());
        v.resize(v.len() + 4096, 0);
        v
    }

    #[test]
    fn find_ikconfig_blob_roundtrip() {
        let mut img = vec![0u8; 64];
        img.extend_from_slice(b"IKCFG_ST");
        img.extend_from_slice(&[0, b'\n']);
        let payload = [0x1f, 0x8b, b'h', b'e', b'l', b'l', b'o'];
        img.extend_from_slice(&payload);
        img.extend_from_slice(b"IKCFG_ED");
        let (start, size) = find_ikconfig_blob(&img).unwrap();
        assert_eq!(&img[start..start + size], &payload);
    }

    #[test]
    fn find_ikconfig_blob_missing_start() {
        assert_eq!(find_ikconfig_blob(b"nope"), Err(1));
    }

    #[test]
    fn banner_detects_single_version() {
        let kernel =
            fake_kernel_with_banner("Linux version 6.6.118-android15-8-gabcdef (user@host)\n");
        let mut info = Kallsym::default();
        let ver = find_linux_banner(&mut info, &kernel).unwrap();
        assert_eq!(info.banner_num, 1);
        assert_eq!(info.version.major, 6);
        assert_eq!(info.version.minor, 6);
        assert_eq!(info.version.patch, 118);
        assert_eq!(ver, (6 << 16) | (6 << 8) | 118);
    }

    #[test]
    fn banner_uses_last_hit() {
        let a = "Linux version 4.9.1 dummy\n";
        let b = "Linux version 6.1.75-android14 (ci@host)\n";
        let mut buf = vec![0u8; 1024];
        buf.extend_from_slice(a.as_bytes());
        buf.resize(buf.len() + 1024, 0);
        buf.extend_from_slice(b.as_bytes());
        buf.resize(buf.len() + 1024, 0);
        let mut info = Kallsym::default();
        find_linux_banner(&mut info, &buf).unwrap();
        assert_eq!(info.banner_num, 2);
        assert_eq!(info.version.major, 6);
        assert_eq!(info.version.minor, 1);
        assert_eq!(info.version.patch, 75);
    }

    #[test]
    fn banner_rejects_when_missing() {
        let buf = vec![0u8; 8192];
        let mut info = Kallsym::default();
        assert!(find_linux_banner(&mut info, &buf).is_err());
    }

    #[test]
    fn banner_ignores_false_positive() {
        let kernel = fake_kernel_with_banner("Linux version XYZ not real\n");
        let mut info = Kallsym::default();
        assert!(find_linux_banner(&mut info, &kernel).is_err());
    }

    #[test]
    fn uint_unpack_le_be_match() {
        let b = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(uint_unpack(&b, 4, false), 0x0403_0201);
        assert_eq!(uint_unpack(&b, 4, true), 0x0102_0304);
    }

    #[test]
    fn int_unpack_sign_extends() {
        let b = [0xff, 0xff, 0xff, 0xff];
        assert_eq!(int_unpack(&b, 4, false), -1);
    }
}
