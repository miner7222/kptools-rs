//! Kallsyms table parser.
//!
//! Port of upstream `tools/kallsym.{c,h}` at KernelPatch 0.13.8.

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CurrentType {
    #[default]
    SpEl0,
    Sp,
}

#[derive(Clone, Debug)]
pub struct Kallsym {
    pub arch: ArchType,
    pub is_64: bool,
    pub is_be: bool,
    pub version: VersionT,
    pub banner_num: i32,
    pub linux_banner_offset: [i32; 4],
    pub symbol_banner_idx: i32,
    pub kallsyms_token_table: [i32; KSYM_TOKEN_NUMS],
    pub asm_long_size: i32,
    pub asm_ptr_size: i32,
    pub kallsyms_markers_elem_size: i32,
    pub kallsyms_num_syms: i32,
    pub has_relative_base: bool,
    pub has_absolute_percpu: bool,
    pub kallsyms_relative_base: u64,
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
            version: VersionT::new(0, 0, 0),
            banner_num: 0,
            linux_banner_offset: [0; 4],
            symbol_banner_idx: 0,
            kallsyms_token_table: [0; KSYM_TOKEN_NUMS],
            asm_long_size: 0,
            asm_ptr_size: 0,
            kallsyms_markers_elem_size: 0,
            kallsyms_num_syms: 0,
            has_relative_base: false,
            has_absolute_percpu: false,
            kallsyms_relative_base: 0,
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

fn uint_unpack(buf: &[u8], size: usize, is_be: bool) -> u64 {
    let mut v = 0u64;
    if is_be {
        for &b in buf.iter().take(size) {
            v = (v << 8) | b as u64;
        }
    } else {
        for (i, &b) in buf.iter().enumerate().take(size) {
            v |= (b as u64) << (i * 8);
        }
    }
    v
}

fn int_unpack(buf: &[u8], size: usize, is_be: bool) -> i64 {
    let u = uint_unpack(buf, size, is_be);
    let bits = (size * 8) as u32;
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

fn find_substr(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        None
    } else {
        haystack.windows(needle.len()).position(|w| w == needle)
    }
}

pub fn find_linux_banner(info: &mut Kallsym, img: &[u8]) -> Result<u32> {
    const PREFIX: &[u8] = b"Linux version ";
    info.banner_num = 0;
    info.linux_banner_offset = [0; 4];
    let mut pos = 0usize;
    while let Some(rel) = find_substr(&img[pos..], PREFIX) {
        let start = pos + rel;
        let after = start + PREFIX.len();
        if after + 1 < img.len()
            && img[after].is_ascii_digit()
            && img[after + 1] == b'.'
            && (info.banner_num as usize) < info.linux_banner_offset.len()
        {
            info.linux_banner_offset[info.banner_num as usize] = start as i32;
            info.banner_num += 1;
        }
        pos = start + 1;
    }
    if info.banner_num == 0 {
        return Err(Error::kallsym("no `Linux version ` banner found"));
    }
    let off = info.linux_banner_offset[(info.banner_num - 1) as usize] as usize + PREFIX.len();
    let (major, rest) = read_u32_until(&img[off..], b'.')?;
    let (minor, rest) = read_u32_until(rest, b'.')?;
    let (patch, _) = read_u32_until_nondigit(rest);
    info.version.major = major as u8;
    info.version.minor = minor as u8;
    info.version.patch = if patch <= 256 { patch as u8 } else { 255 };
    Ok(info.version.as_u32())
}

fn read_u32_until(bytes: &[u8], term: u8) -> Result<(u32, &[u8])> {
    let mut value = 0u32;
    let mut i = 0usize;
    while i < bytes.len() && bytes[i] != term {
        if !bytes[i].is_ascii_digit() {
            return Err(Error::kallsym("invalid kernel version"));
        }
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add((bytes[i] - b'0') as u32))
            .ok_or_else(|| Error::kallsym("kernel version overflow"))?;
        i += 1;
    }
    if i == 0 || i >= bytes.len() {
        return Err(Error::kallsym("truncated kernel version"));
    }
    Ok((value, &bytes[i + 1..]))
}

fn read_u32_until_nondigit(bytes: &[u8]) -> (u32, &[u8]) {
    let mut value = 0u32;
    let mut i = 0usize;
    while i < bytes.len() && bytes[i].is_ascii_digit() {
        value = value
            .saturating_mul(10)
            .saturating_add((bytes[i] - b'0') as u32);
        i += 1;
    }
    (value, &bytes[i..])
}

fn find_token_table(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let mut nums = [0u8; 20];
    let mut letters = [0u8; 20];
    for i in 0..10 {
        nums[i * 2] = b'0' + i as u8;
        letters[i * 2] = b'a' + i as u8;
    }
    let mut pos = 0usize;
    let num_start = loop {
        let Some(rel) = find_substr(&img[pos..], &nums) else {
            return Err(Error::kallsym("find token_table error"));
        };
        let n = pos + rel;
        let num_end = n + nums.len();
        if num_end + 1 >= img.len() || img[num_end] == 0 || img[num_end + 1] == 0 {
            pos = n + 1;
            continue;
        }
        let mut letter = num_end;
        let mut zeros = 0usize;
        while letter < img.len() && zeros < (b'a' - b'9' - 1) as usize {
            if img[letter] == 0 {
                zeros += 1;
            }
            letter += 1;
        }
        if letter + letters.len() <= img.len()
            && &img[letter..letter + letters.len()] == letters.as_slice()
        {
            break n;
        }
        pos = n + 1;
    };

    let mut p = num_start as isize;
    let mut zeros = 0i32;
    while p > 0 && zeros < (b'0' + 1) as i32 {
        if img[p as usize] == 0 {
            zeros += 1;
        }
        p -= 1;
    }
    let offset = align_ceil((p + 2) as i32, 4);
    info.kallsyms_token_table_offset = offset;
    logi!("kallsyms_token_table offset: 0x{offset:08x}");
    let mut p = offset as usize;
    for slot in &mut info.kallsyms_token_table {
        if p >= img.len() {
            return Err(Error::kallsym("token table OOB"));
        }
        *slot = p as i32;
        while p < img.len() && img[p] != 0 {
            p += 1;
        }
        p += 1;
    }
    Ok(())
}

fn find_token_index(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let start = info.kallsyms_token_table_offset as usize;
    let mut offset = start;
    let mut le = [0u8; KSYM_TOKEN_NUMS * 2];
    let mut be = [0u8; KSYM_TOKEN_NUMS * 2];
    for i in 0..KSYM_TOKEN_NUMS {
        let idx = (offset - start) as u16;
        le[i * 2..i * 2 + 2].copy_from_slice(&idx.to_le_bytes());
        be[i * 2..i * 2 + 2].copy_from_slice(&idx.to_be_bytes());
        while offset < img.len() && img[offset] != 0 {
            offset += 1;
        }
        offset += 1;
    }
    if let Some(p) = find_substr(img, &le) {
        info.is_be = false;
        info.kallsyms_token_index_offset = p as i32;
    } else if let Some(p) = find_substr(img, &be) {
        info.is_be = true;
        info.kallsyms_token_index_offset = p as i32;
    } else {
        return Err(Error::kallsym("kallsyms_token_index error"));
    }
    logi!("endian: {}", if info.is_be { "big" } else { "little" });
    logi!(
        "kallsyms_token_index offset: 0x{:08x}",
        info.kallsyms_token_index_offset
    );
    Ok(())
}

fn markers_elem_size(info: &Kallsym) -> i32 {
    if info.kallsyms_markers_elem_size != 0 {
        return info.kallsyms_markers_elem_size;
    }
    if info.version.major < 4 || (info.version.major == 4 && info.version.minor < 20) {
        info.asm_ptr_size
    } else {
        info.asm_long_size
    }
}

fn addresses_elem_size(info: &Kallsym) -> i32 {
    info.asm_ptr_size
}
fn offsets_elem_size(info: &Kallsym) -> i32 {
    info.asm_long_size
}

fn decode_relative_symbol_offset(info: &Kallsym, entry: &[u8]) -> i32 {
    let raw = int_unpack(entry, offsets_elem_size(info) as usize, info.is_be) as i32;
    if info.arch == ArchType::X86_64 && info.has_absolute_percpu {
        if raw >= 0 {
            raw
        } else {
            -1 - raw
        }
    } else {
        raw as u32 as i32
    }
}

fn try_find_arm64_relo_table(info: &mut Kallsym, img: &mut [u8]) -> Result<()> {
    if !info.try_relo {
        return Ok(());
    }
    let imglen = img.len() as i32;
    let mut kernel_va = ELF64_KERNEL_MAX_VA;
    let mut cand = 0i32;
    let mut rela_num = 0i32;
    while cand < imglen - 24 {
        let i = cand as usize;
        let r_offset = uint_unpack(&img[i..], 8, info.is_be);
        let r_info = uint_unpack(&img[i + 8..], 8, info.is_be);
        let r_addend = uint_unpack(&img[i + 16..], 8, info.is_be);
        let r_type = (r_info & 0xffff_ffff) as u32;
        if r_offset & 0xffff_0000_0000_0000 == 0xffff_0000_0000_0000
            && (r_type == 0x101 || r_type == 0x403)
        {
            if r_addend & 0xfff == 0 && r_addend >= ELF64_KERNEL_MIN_VA && r_addend < kernel_va {
                kernel_va = r_addend;
            }
            cand += 24;
            rela_num += 1;
        } else if rela_num != 0 && r_offset == 0 && r_info == 0 && r_addend == 0 {
            cand += 24;
            rela_num += 1;
        } else {
            if rela_num >= ARM64_RELO_MIN_NUM as i32 {
                break;
            }
            cand += 8;
            rela_num = 0;
            kernel_va = ELF64_KERNEL_MAX_VA;
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
        if i + 24 > img.len() {
            cand_end -= 24;
            continue;
        }
        if uint_unpack(&img[i..], 8, info.is_be) != 0
            && uint_unpack(&img[i + 8..], 8, info.is_be) != 0
            && uint_unpack(&img[i + 16..], 8, info.is_be) != 0
        {
            break;
        }
        cand_end -= 24;
    }
    cand_end += 24;
    rela_num = (cand_end - cand_start) / 24;
    if rela_num < ARM64_RELO_MIN_NUM as i32 {
        logw!("can't find arm64 relocation table");
        return Ok(());
    }
    logi!("arm64 relocation table range: [0x{cand_start:08x}, 0x{cand_end:08x}), count: 0x{rela_num:08x}");
    let max_offset = imglen - 8;
    let mut apply_num = 0i32;
    let mut c = cand_start;
    while c < cand_end {
        let i = c as usize;
        let r_offset = uint_unpack(&img[i..], 8, info.is_be);
        let r_info = uint_unpack(&img[i + 8..], 8, info.is_be);
        let mut r_addend = uint_unpack(&img[i + 16..], 8, info.is_be);
        c += 24;
        if r_offset == 0 && r_info == 0 && r_addend == 0 {
            continue;
        }
        if r_offset <= kernel_va || r_offset >= ELF64_KERNEL_MAX_VA - imglen as u64 {
            continue;
        }
        let offset = r_offset.wrapping_sub(kernel_va) as i64;
        if offset < 0 || offset >= max_offset as i64 {
            info.try_relo = false;
            return Err(Error::kallsym("arm64 relocation target outside image"));
        }
        let offset = offset as usize;
        if (r_info & 0xffff_ffff) as u32 == 0x101 {
            r_addend = r_addend.wrapping_add(kernel_va);
        }
        let value = uint_unpack(&img[offset..], 8, info.is_be);
        if value == r_addend {
            continue;
        }
        let new_value = value.wrapping_add(r_addend);
        let bytes = if info.is_be {
            new_value.to_be_bytes()
        } else {
            new_value.to_le_bytes()
        };
        img[offset..offset + 8].copy_from_slice(&bytes);
        apply_num += 1;
    }
    if apply_num != 0 {
        apply_num -= 1;
    }
    logi!("apply 0x{apply_num:08x} relocation entries");
    if apply_num != 0 {
        info.relo_applied = true;
    }
    Ok(())
}

fn find_approx_addresses(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem = info.asm_ptr_size as usize;
    let mut sym_num = 0i32;
    let mut prev = 0u64;
    let mut cand = 0i32;
    let limit = img.len() as i32 - KSYM_MIN_NEQ_SYMS as i32 * elem as i32;
    while cand < limit {
        let address = uint_unpack(&img[cand as usize..], elem, info.is_be);
        if sym_num == 0 {
            if address & 0xff != 0
                || (elem == 4 && address & 0xff80_0000 != 0xff80_0000)
                || (elem == 8 && address & 0xffff_0000_0000_0000 != 0xffff_0000_0000_0000)
            {
                cand += elem as i32;
                continue;
            }
            prev = address;
            sym_num += 1;
        } else if address >= prev {
            prev = address;
            sym_num += 1;
            if sym_num >= KSYM_MIN_NEQ_SYMS as i32 {
                break;
            }
        } else {
            prev = 0;
            sym_num = 0;
        }
        cand += elem as i32;
    }
    if sym_num < KSYM_MIN_NEQ_SYMS as i32 {
        return Err(Error::kallsym("find approximate kallsyms_addresses error"));
    }
    cand -= KSYM_MIN_NEQ_SYMS as i32 * elem as i32;
    let start = cand;
    info.approx_addresses_or_offsets_offset = start;
    prev = 0;
    while cand >= 0 && (cand as usize) + elem <= img.len() {
        let value = uint_unpack(&img[cand as usize..], elem, info.is_be);
        if value < prev {
            break;
        }
        prev = value;
        cand += elem as i32;
    }
    info.approx_addresses_or_offsets_end = cand;
    info.approx_addresses_or_offsets_num = (cand - start) / elem as i32;
    info.has_relative_base = false;
    logi!(
        "approximate kallsyms_addresses range: [0x{start:08x}, 0x{cand:08x}) count: 0x{:08x}",
        info.approx_addresses_or_offsets_num
    );
    if info.relo_applied {
        logw!("mismatch relo applied, subsequent operations may be undefined");
    }
    Ok(())
}

fn transformed_relative(raw: i64) -> u64 {
    if raw < 0 {
        (1u64 << 32).wrapping_add((-raw) as u32 as u64)
    } else {
        raw as u32 as u64
    }
}

fn find_approx_offsets(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem = info.asm_long_size as usize;
    let mut sym_num = 0i32;
    let mut prev = 0u64;
    let mut cand = 0i32;
    let limit = img.len() as i32 - KSYM_MIN_NEQ_SYMS as i32 * elem as i32;
    while cand < limit {
        let raw = int_unpack(&img[cand as usize..], elem, info.is_be);
        let offset = transformed_relative(raw);
        if sym_num == 0 {
            if raw == 0 {
                cand += elem as i32;
                continue;
            }
            prev = offset;
            sym_num += 1;
        } else if offset == prev {
        } else if offset > prev {
            prev = offset;
            sym_num += 1;
            if sym_num >= KSYM_MIN_NEQ_SYMS as i32 {
                break;
            }
        } else {
            prev = 0;
            sym_num = 0;
        }
        cand += elem as i32;
    }
    if sym_num < KSYM_MIN_NEQ_SYMS as i32 {
        logw!("find approximate kallsyms_offsets error");
        return Err(Error::kallsym("find approximate kallsyms_offsets error"));
    }
    cand -= KSYM_MIN_NEQ_SYMS as i32 * elem as i32;
    while cand >= 0 && int_unpack(&img[cand as usize..], elem, info.is_be) != 0 {
        cand -= elem as i32;
    }
    let mut zeros = 0;
    while cand >= 0 {
        if int_unpack(&img[cand as usize..], elem, info.is_be) != 0 {
            break;
        }
        if zeros >= 10 {
            break;
        }
        zeros += 1;
        cand -= elem as i32;
    }
    cand += elem as i32;
    let start = cand;
    info.approx_addresses_or_offsets_offset = start;
    prev = 0;
    while cand >= 0 && (cand as usize) + elem <= img.len() {
        let raw = int_unpack(&img[cand as usize..], elem, info.is_be);
        let offset = transformed_relative(raw);
        if offset < prev {
            break;
        }
        prev = offset;
        cand += elem as i32;
    }
    info.approx_addresses_or_offsets_end = cand;
    info.approx_addresses_or_offsets_num = (cand - start) / elem as i32;
    info.has_relative_base = true;
    logi!(
        "approximate kallsyms_offsets range: [0x{start:08x}, 0x{cand:08x}) count: 0x{:08x}",
        info.approx_addresses_or_offsets_num
    );
    Ok(())
}

fn find_approx_addresses_or_offset(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    if (info.arch == ArchType::Arm64 || info.arch == ArchType::X86_64) && info.is_64 {
        logi!("try kallsyms_offsets first for 64-bit relative-base kernel");
        if find_approx_offsets(info, img).is_ok() {
            return Ok(());
        }
    }
    logi!("fallback to kallsyms_addresses scan");
    find_approx_addresses(info, img)
}

fn find_markers_internal(info: &mut Kallsym, img: &[u8], elem: i32) -> Result<()> {
    let mut cand = info.kallsyms_token_table_offset;
    let mut last = img.len() as i64;
    let mut count = 0i32;
    while cand > 0x10000 {
        if cand < 0 || cand as usize + elem as usize > img.len() {
            cand -= elem;
            continue;
        }
        let marker = int_unpack(&img[cand as usize..], elem as usize, info.is_be);
        if last > marker {
            count += 1;
            if marker == 0 && count > KSYM_MIN_MARKER as i32 {
                break;
            }
        } else {
            count = 0;
        }
        last = marker;
        cand -= elem;
    }
    if count < KSYM_MIN_MARKER as i32 {
        return Err(Error::kallsym("find kallsyms_markers error"));
    }
    let end = cand + count * elem + elem;
    let mut prev = -1i64;
    for i in 0..count {
        let at = cand + i * elem;
        if at < 0 || at as usize + elem as usize > img.len() {
            return Err(Error::kallsym("kallsyms_markers OOB"));
        }
        let value = int_unpack(&img[at as usize..], elem as usize, info.is_be);
        if value < 0 || value >= cand as i64 || value < prev {
            logw!("kallsyms_markers elem_size {elem} rejected at [{i}] (val 0x{value:x})");
            return Err(Error::kallsym("invalid kallsyms_markers element size"));
        }
        prev = value;
    }
    info.kallsyms_markers_offset = cand;
    info.marker_num = count;
    info.kallsyms_markers_elem_size = elem;
    logi!("kallsyms_markers range: [0x{cand:08x}, 0x{end:08x}), count: 0x{count:08x}");
    Ok(())
}

fn find_markers(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem = markers_elem_size(info);
    match find_markers_internal(info, img, elem) {
        Ok(()) => Ok(()),
        Err(_) if elem == 8 => find_markers_internal(info, img, 4),
        Err(e) => Err(e),
    }
}

fn token_end(img: &[u8], mut p: usize) -> usize {
    while p < img.len() && img[p] != 0 {
        p += 1;
    }
    p
}

fn decompress_symbol_name(
    info: &Kallsym,
    img: &[u8],
    pos_to_next: &mut i32,
    mut out: Option<&mut Vec<u8>>,
) -> Result<u8> {
    let mut pos = *pos_to_next as usize;
    if pos >= img.len() {
        return Err(Error::kallsym("decompress symbol OOB"));
    }
    let mut len = img[pos] as usize;
    pos += 1;
    if len > 0x7f {
        if pos >= img.len() {
            return Err(Error::kallsym("truncated symbol length"));
        }
        len = (len & 0x7f) + ((img[pos] as usize) << 7);
        pos += 1;
    }
    if len == 0 || len >= KSYM_SYMBOL_LEN || pos + len > img.len() {
        return Err(Error::kallsym("bad compressed symbol"));
    }
    *pos_to_next = (pos + len) as i32;
    let mut ty = 0u8;
    for i in 0..len {
        let idx = img[pos + i] as usize;
        let mut start = info.kallsyms_token_table[idx] as usize;
        let end = token_end(img, start);
        if start >= end {
            return Err(Error::kallsym("empty kallsyms token"));
        }
        if i == 0 {
            ty = img[start];
            start += 1;
        }
        if let Some(buf) = out.as_deref_mut() {
            buf.extend_from_slice(&img[start.min(end)..end]);
        }
    }
    Ok(ty)
}

fn verify_names_candidate(info: &Kallsym, img: &[u8], marker_elem: usize, cand: i32) -> bool {
    let mut pos = cand as usize;
    let marker_off = info.kallsyms_markers_offset as usize;
    let mut remaining = KSYM_FIND_NAMES_USED_MARKER;
    let mut i = 0i32;
    loop {
        if pos >= marker_off || pos >= img.len() {
            return false;
        }
        let mut len = img[pos] as usize;
        pos += 1;
        if len > 0x7f {
            if pos >= marker_off {
                return false;
            }
            len = (len & 0x7f) + ((img[pos] as usize) << 7);
            pos += 1;
        }
        if len == 0 || len >= KSYM_SYMBOL_LEN || pos + len > marker_off {
            return false;
        }
        pos += len;
        if pos >= marker_off {
            return false;
        }
        if i > 0 && (i & 0xff) == 0xff {
            let marker_index = (i >> 8) + 1;
            if marker_index >= info.marker_num {
                return false;
            }
            let at = marker_off + marker_index as usize * marker_elem;
            if at + marker_elem > img.len() {
                return false;
            }
            let mark_len = int_unpack(&img[at..], marker_elem, info.is_be) as i32;
            if pos as i32 - cand != mark_len {
                return false;
            }
            remaining -= 1;
            if remaining == 0 {
                return true;
            }
        }
        i += 1;
    }
}

fn find_names(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let elem = markers_elem_size(info) as usize;
    if info.marker_num > KSYM_FIND_NAMES_USED_MARKER {
        let at = info.kallsyms_markers_offset as usize + (info.marker_num as usize - 1) * elem;
        let last = int_unpack(&img[at..], elem, info.is_be) as i32;
        let guess = info.kallsyms_markers_offset - last;
        let start = (guess - 0x10000).max(0x4000);
        let end = (guess + 0x1000).min(info.kallsyms_markers_offset);
        for cand in start..end {
            if verify_names_candidate(info, img, elem, cand) {
                info.kallsyms_names_offset = cand;
                logi!("kallsyms_names offset: 0x{cand:08x}");
                return Ok(());
            }
        }
    }
    for cand in 0x4000..info.kallsyms_markers_offset {
        if verify_names_candidate(info, img, elem, cand) {
            info.kallsyms_names_offset = cand;
            logi!("kallsyms_names offset: 0x{cand:08x}");
            return Ok(());
        }
    }
    Err(Error::kallsym("find kallsyms_names error"))
}

fn find_num_syms(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    const GAP: i32 = 10;
    let approx = info.approx_addresses_or_offsets_num;
    let mut cand = info.kallsyms_names_offset;
    while cand > info.kallsyms_names_offset - 4096 {
        if cand >= 0 && cand as usize + 4 <= img.len() {
            let n = int_unpack(&img[cand as usize..], 4, info.is_be) as i32;
            if n != 0 && (n - approx).abs() <= GAP {
                info.kallsyms_num_syms = n;
                info.kallsyms_num_syms_offset = cand;
                break;
            }
        }
        cand -= 4;
    }
    if info.kallsyms_num_syms_offset == 0 || info.kallsyms_num_syms == 0 {
        info.kallsyms_num_syms = approx - GAP;
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
    if info.arch == ArchType::X86_64 && info.has_relative_base && info.kallsyms_num_syms_offset > 0
    {
        let begin = (info.kallsyms_num_syms_offset - 32).max(0);
        let mut pos = info.kallsyms_num_syms_offset - 8;
        while pos >= begin {
            if pos as usize + 8 <= img.len() {
                let value = uint_unpack(&img[pos as usize..], 8, info.is_be);
                if value & 0xffff_0000_0000_0000 == 0xffff_0000_0000_0000 {
                    info.kallsyms_relative_base = value;
                    info.kernel_base = value;
                    logi!("kallsyms_relative_base offset: 0x{pos:08x}, value: 0x{value:x}");
                    break;
                }
            }
            if pos < 8 {
                break;
            }
            pos -= 8;
        }
    }
    Ok(())
}

fn arm64_verify_pid_vnr_window(
    info: &mut Kallsym,
    img: &[u8],
    offset: i32,
    back: i32,
    fwd: i32,
    generic_sp: bool,
) -> Result<()> {
    use crate::insn::{
        aarch64_get_insn_class, aarch64_insn_decode_register, aarch64_insn_extract_system_reg,
        InsnClass, RegType, AARCH64_INSN_REG_SP, AARCH64_INSN_SPCLREG_SP_EL0,
    };
    let mut i = -back;
    while i < fwd {
        let insn_offset = offset + i * 4;
        if insn_offset < 0 || insn_offset as usize + 4 > img.len() {
            i += 1;
            continue;
        }
        let at = insn_offset as usize;
        let insn = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        let enc = aarch64_get_insn_class(insn);
        if matches!(enc, InsnClass::BrSys)
            && aarch64_insn_extract_system_reg(insn) == AARCH64_INSN_SPCLREG_SP_EL0
        {
            info.current_type = CurrentType::SpEl0;
            logi!("pid_vnr verfied sp_el0, insn: 0x{insn:x} (off {i:+})");
            return Ok(());
        }
        if generic_sp
            && i >= 0
            && matches!(enc, InsnClass::DpImm)
            && aarch64_insn_decode_register(RegType::Rn, insn) == AARCH64_INSN_REG_SP
        {
            info.current_type = CurrentType::Sp;
            logi!("pid_vnr verfied sp, insn: 0x{insn:x}");
            return Ok(());
        }
        i += 1;
    }
    Err(Error::kallsym("pid_vnr verification failed"))
}

fn arm64_verify_pid_vnr(info: &mut Kallsym, img: &[u8], offset: i32, wide: bool) -> Result<()> {
    if !wide {
        // strict pass: 'current' loaded in the first instructions of the entry
        arm64_verify_pid_vnr_window(info, img, offset, 0, 6, true)
    } else {
        // wide pass: LTO/ICF folded kernels may point the kallsyms entry into
        // the middle of the surviving function, so only the strong sp_el0
        // system register read is scanned across a wider window.
        arm64_verify_pid_vnr_window(info, img, offset, 4, 12, false)
    }
}

fn correct_addresses_or_offsets_by_banner(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let mut pos = info.kallsyms_names_offset;
    let mut index = 0i32;
    let mut found = false;
    while pos < info.kallsyms_markers_offset {
        let mut sym = Vec::new();
        decompress_symbol_name(info, img, &mut pos, Some(&mut sym))?;
        if sym == b"linux_banner" {
            found = true;
            break;
        }
        index += 1;
    }
    if !found {
        return Err(Error::kallsym("no linux_banner in names table"));
    }
    logi!("names table linux_banner index: 0x{index:08x}");
    info.symbol_banner_idx = -1;
    let elem = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    } as usize;
    let mut resolved_pos = None;
    for i in 0..info.banner_num {
        let target = info.linux_banner_offset[i as usize];
        let mut p = info.approx_addresses_or_offsets_offset;
        let end = p + 4096 + elem as i32;
        while p < end {
            if p < 0 {
                p = end;
                break;
            }
            let entry = p as usize + index as usize * elem;
            if entry + elem > img.len() {
                p = end;
                break;
            }
            if info.arch == ArchType::X86_64 && info.has_relative_base {
                let raw = int_unpack(&img[entry..], elem, info.is_be) as i32;
                if raw as u32 == target as u32 {
                    info.has_absolute_percpu = false;
                    break;
                }
                if raw < 0 && -1 - raw == target {
                    info.has_absolute_percpu = true;
                    logi!("x86 kallsyms uses absolute percpu offsets");
                    break;
                }
                p += elem as i32;
                continue;
            }
            let base = uint_unpack(&img[p as usize..], elem, info.is_be);
            let value = uint_unpack(&img[entry..], elem, info.is_be);
            if value.wrapping_sub(base) as i32 == target {
                break;
            }
            p += elem as i32;
        }
        if p < end {
            info.symbol_banner_idx = i;
            resolved_pos = Some(p);
            logi!("linux_banner index: {i}");
            break;
        }
    }
    let p = resolved_pos.ok_or_else(|| Error::kallsym("correct address or offsets error"))?;
    if info.has_relative_base {
        info.kallsyms_offsets_offset = p;
        logi!("kallsyms_offsets offset: 0x{p:08x}");
    } else {
        info.kallsyms_addresses_offset = p;
        info.kernel_base = uint_unpack(&img[p as usize..], elem, info.is_be);
        logi!("kallsyms_addresses offset: 0x{p:08x}");
        logi!("kernel base address: 0x{:x}", info.kernel_base);
    }
    if info.arch == ArchType::Arm64 {
        let pid = get_symbol_offset_zero(info, img, "pid_vnr");
        if arm64_verify_pid_vnr(info, img, pid, false).is_err() {
            logw!("pid_vnr verification failed");
        }
    }
    Ok(())
}

fn correct_addresses_or_offsets_by_vectors(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    if info.arch != ArchType::Arm64 {
        return Err(Error::kallsym("vectors fallback is arm64-only"));
    }
    let mut pos = info.kallsyms_names_offset;
    let mut index = 0i32;
    let mut vector_index = 0i32;
    let mut pid_index = 0i32;
    while pos < info.kallsyms_markers_offset {
        let mut sym = Vec::new();
        decompress_symbol_name(info, img, &mut pos, Some(&mut sym))?;
        if vector_index == 0 && sym == b"vectors" {
            vector_index = index;
        } else if pid_index == 0 && sym == b"pid_vnr" {
            pid_index = index;
        }
        if vector_index != 0 && pid_index != 0 {
            break;
        }
        index += 1;
    }
    if vector_index == 0 || pid_index == 0 {
        return Err(Error::kallsym("no verify symbol in names table"));
    }
    let elem = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    } as usize;
    let mut bases = vec![0u64];
    if !info.has_relative_base {
        bases[0] = uint_unpack(
            &img[info.approx_addresses_or_offsets_offset as usize..],
            elem,
            info.is_be,
        );
        if info.kernel_base != 0 {
            bases.push(info.kernel_base);
        }
        if info.kernel_base != ELF64_KERNEL_MIN_VA {
            bases.push(ELF64_KERNEL_MIN_VA);
        }
    }
    let start = info.approx_addresses_or_offsets_offset;
    let max_shift = (info.approx_addresses_or_offsets_num - info.kallsyms_num_syms).max(0);
    let mut end = start + (max_shift + 1) * elem as i32;
    end = end.min(info.approx_addresses_or_offsets_end - pid_index * elem as i32);
    let mut found = None;
    // pass 0 verifies pid_vnr strictly within its first instructions; pass 1
    // widens the window for LTO/ICF folded kernels whose pid_vnr entry is
    // mid-function, only matching the strong sp_el0 system register read.
    'outer: for pass in 0..2 {
        let wide = pass != 0;
        for base in bases.iter().copied() {
            let mut p = start;
            while p < end {
                let vo = p as usize + vector_index as usize * elem;
                let po = p as usize + pid_index as usize * elem;
                if po + elem > img.len() || vo + elem * 2 > img.len() {
                    break;
                }
                let vector = uint_unpack(&img[vo..], elem, info.is_be).wrapping_sub(base) as i32;
                let next =
                    uint_unpack(&img[vo + elem..], elem, info.is_be).wrapping_sub(base) as i32;
                if next - vector >= 0x600 && vector & ((1 << 11) - 1) == 0 {
                    let pid = uint_unpack(&img[po..], elem, info.is_be).wrapping_sub(base) as i32;
                    let mut probe = info.clone();
                    if arm64_verify_pid_vnr(&mut probe, img, pid, wide).is_ok() {
                        info.current_type = probe.current_type;
                        info.kernel_base = base;
                        found = Some(p);
                        break 'outer;
                    }
                }
                p += elem as i32;
            }
        }
    }
    let p = found.ok_or_else(|| Error::kallsym("can't locate vectors"))?;
    if info.has_relative_base {
        info.kallsyms_offsets_offset = p;
    } else {
        info.kallsyms_addresses_offset = p;
    }
    Ok(())
}

fn correct_addresses_or_offsets(info: &mut Kallsym, img: &[u8]) -> Result<()> {
    let mut result = correct_addresses_or_offsets_by_banner(info, img);
    info.is_kallsyms_all_yes = true;
    if result.is_err() {
        info.is_kallsyms_all_yes = false;
        logw!("no linux_banner, CONFIG_KALLSYMS_ALL=n");
        result = correct_addresses_or_offsets_by_vectors(info, img);
    }
    result?;
    let elem = if info.has_relative_base {
        offsets_elem_size(info)
    } else {
        addresses_elem_size(info)
    };
    let start = if info.has_relative_base {
        info.kallsyms_offsets_offset
    } else {
        info.kallsyms_addresses_offset
    };
    let coverage = (info.approx_addresses_or_offsets_end - start) / elem;
    if coverage < info.kallsyms_num_syms {
        return Err(Error::kallsym("symbol table coverage too small"));
    }
    Ok(())
}

fn retry_relo(info: &mut Kallsym, img: &mut [u8]) -> Result<()> {
    try_find_arm64_relo_table(info, img)?;
    find_markers(info, img)?;
    find_approx_addresses_or_offset(info, img)?;
    find_names(info, img)?;
    find_num_syms(info, img)?;
    correct_addresses_or_offsets(info, img)
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

    let mut raw_layout = info.clone();
    let raw_ready =
        find_markers(&mut raw_layout, img).is_ok() && find_names(&mut raw_layout, img).is_ok();
    let saved = img.to_vec();
    let mut work = saved.clone();
    if retry_relo(info, &mut work).is_ok() {
        img.copy_from_slice(&work);
        return Ok(());
    }
    if raw_ready {
        work.copy_from_slice(&saved);
        *info = raw_layout;
        if try_find_arm64_relo_table(info, &mut work).is_ok() {
            let start = info.kallsyms_names_offset.max(0) as usize;
            let end = (info.kallsyms_token_index_offset + KSYM_TOKEN_NUMS as i32 * 2)
                .clamp(0, img.len() as i32) as usize;
            if start < end {
                work[start..end].copy_from_slice(&saved[start..end]);
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
    if !info.try_relo {
        work.copy_from_slice(&saved);
        if retry_relo(info, &mut work).is_ok() {
            img.copy_from_slice(&work);
            return Ok(());
        }
    }
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

pub fn get_symbol_index_offset(info: &Kallsym, img: &[u8], index: i32) -> i32 {
    let (elem, pos) = if info.has_relative_base {
        (offsets_elem_size(info), info.kallsyms_offsets_offset)
    } else {
        (addresses_elem_size(info), info.kallsyms_addresses_offset)
    };
    let at = pos as usize + index as usize * elem as usize;
    if info.has_relative_base {
        decode_relative_symbol_offset(info, &img[at..])
    } else {
        uint_unpack(&img[at..], elem as usize, info.is_be).wrapping_sub(info.kernel_base) as i32
    }
}

pub fn get_symbol_offset(info: &Kallsym, img: &[u8], symbol: &str) -> Option<i32> {
    let mut pos = info.kallsyms_names_offset;
    for i in 0..info.kallsyms_num_syms {
        let mut name = Vec::with_capacity(KSYM_SYMBOL_LEN);
        if decompress_symbol_name(info, img, &mut pos, Some(&mut name)).is_err() {
            return None;
        }
        if name == symbol.as_bytes() {
            return Some(get_symbol_index_offset(info, img, i));
        }
    }
    None
}

pub fn get_symbol_offset_zero(info: &Kallsym, img: &[u8], symbol: &str) -> i32 {
    get_symbol_offset(info, img, symbol)
        .filter(|v| *v > 0)
        .unwrap_or(0)
}

pub fn is_symbol_exists(info: &Kallsym, img: &[u8], symbol: &str) -> bool {
    let mut pos = info.kallsyms_names_offset;
    for _ in 0..info.kallsyms_num_syms {
        let mut name = Vec::with_capacity(KSYM_SYMBOL_LEN);
        if decompress_symbol_name(info, img, &mut pos, Some(&mut name)).is_err() {
            return false;
        }
        if name == symbol.as_bytes() {
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
        if f(i, ty, &sym, off) != 0 {
            return Ok(());
        }
    }
    Ok(())
}

pub fn find_ikconfig_blob(img: &[u8]) -> std::result::Result<(usize, usize), i32> {
    const START: &[u8] = b"IKCFG_ST";
    const END: &[u8] = b"IKCFG_ED";
    let marker = find_substr(img, START).ok_or(1)?;
    let mut start = marker + START.len();
    let end = start + find_substr(&img[start..], END).ok_or(2)?;
    while start < img.len() && (img[start] == 0 || img[start] == b'\n') {
        start += 1;
    }
    if end <= start {
        return Err(3);
    }
    Ok((start, end - start))
}

pub fn dump_all_ikconfig(img: &[u8]) -> Result<()> {
    use std::io::Read;
    let (start, size) = find_ikconfig_blob(img)
        .map_err(|rc| Error::kallsym(format!("Cannot find kernel config blob, rc={rc}")))?;
    logi!("Kernel config start: {start}, bytes: {size}");
    let mut decoder = flate2::read::GzDecoder::new(&img[start..start + size]);
    let mut out = String::new();
    decoder
        .read_to_string(&mut out)
        .map_err(|e| Error::decompress(format!("ikconfig gunzip failed: {e}")))?;
    print!("{out}");
    Ok(())
}

pub fn extract_ikconfig(img: &[u8]) -> Result<Vec<u8>> {
    use std::io::Read;
    let (start, size) = find_ikconfig_blob(img)
        .map_err(|rc| Error::kallsym(format!("Cannot find kernel config blob, rc={rc}")))?;
    let mut decoder = flate2::read::GzDecoder::new(&img[start..start + size]);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::decompress(format!("ikconfig gunzip failed: {e}")))?;
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

    #[test]
    fn x86_absolute_percpu_decode() {
        let mut info = Kallsym {
            arch: ArchType::X86_64,
            asm_long_size: 4,
            has_absolute_percpu: true,
            ..Default::default()
        };
        let raw = (-0x101i32).to_le_bytes();
        assert_eq!(decode_relative_symbol_offset(&info, &raw), 0x100);
        info.has_absolute_percpu = false;
        assert_eq!(decode_relative_symbol_offset(&info, &raw), -0x101);
    }

    #[test]
    fn transformed_negative_offsets_are_monotonic_space() {
        assert_eq!(transformed_relative(-1), 0x1_0000_0001);
        assert_eq!(transformed_relative(1), 1);
    }

    #[test]
    fn banner_correction_rejects_oob_candidate() {
        let mut img = vec![0u8; 80];
        img[16] = 1;
        img[17] = 0;
        img[64..78].copy_from_slice(b"Tlinux_banner\0");
        let mut info = Kallsym {
            arch: ArchType::Arm64,
            asm_long_size: 4,
            asm_ptr_size: 8,
            banner_num: 1,
            linux_banner_offset: [0x100, 0, 0, 0],
            kallsyms_names_offset: 16,
            kallsyms_markers_offset: 32,
            approx_addresses_or_offsets_offset: 76,
            ..Default::default()
        };
        info.kallsyms_token_table[0] = 64;
        assert!(correct_addresses_or_offsets_by_banner(&mut info, &img).is_err());
        assert_eq!(info.symbol_banner_idx, -1);
    }
}
