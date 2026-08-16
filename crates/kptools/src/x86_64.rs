//! x86_64 bzImage loader/repacker and KernelPatch payload injector.
//!
//! Port of upstream `tools/x86_64.{c,h}` at KernelPatch 0.13.4.
//! Compression stays in-process through `flate2`; unlike upstream we
//! never shell out to a system `gzip` binary.

use std::io::{Read, Write};
use std::path::Path;

use flate2::{Compression, GzBuilder};
use kptools_base::{
    io::{read_file, write_file},
    logi, Error, Result,
};

use crate::kallsym::{analyze_kallsym_info, get_symbol_offset, ArchType, Kallsym};
use crate::preset::{
    Preset, CONFIG_FLAG_X86_64, HDR_BACKUP_SIZE, KP_MAGIC, KP_X86_ENTRY_OFFSET, MAGIC_LEN,
};

const X86_BOOT_FLAG_OFFSET: usize = 0x1fe;
const X86_SETUP_SECTS_OFFSET: usize = 0x1f1;
const X86_HEADER_MAGIC_OFFSET: usize = 0x202;
const X86_PAYLOAD_OFFSET_OFFSET: usize = 0x248;
const X86_PAYLOAD_LENGTH_OFFSET: usize = 0x24c;
const X86_SYSSIZE_OFFSET: usize = 0x1f4;
const CALL_PATCH_SIZE: usize = 5;
const TRAMPOLINE_SIZE: usize = 16;

const PT_LOAD: u32 = 1;
const PF_X: u32 = 1;
const EM_X86_64: u16 = 62;
const ELFCLASS64: u8 = 2;
const ELFDATA2LSB: u8 = 1;
const ELF64_EHDR_SIZE: usize = 64;
const ELF64_PHDR_SIZE: usize = 56;

#[derive(Default, Debug)]
pub struct X86Bzimage {
    pub bzimage: Vec<u8>,
    pub payload_start: usize,
    pub payload_size: usize,
    pub elf: Vec<u8>,
    pub flat: Vec<u8>,
    pub phys_base: u64,
    pub virt_base: u64,
    pub suffix_payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug)]
struct ProgramHeader {
    index: usize,
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
}

fn get_le16(data: &[u8], off: usize) -> Result<u16> {
    let bytes = data
        .get(off..off + 2)
        .ok_or_else(|| Error::bad_kernel("truncated x86 image"))?;
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}

fn get_le32(data: &[u8], off: usize) -> Result<u32> {
    let bytes = data
        .get(off..off + 4)
        .ok_or_else(|| Error::bad_kernel("truncated x86 image"))?;
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn get_le64(data: &[u8], off: usize) -> Result<u64> {
    let bytes = data
        .get(off..off + 8)
        .ok_or_else(|| Error::bad_kernel("truncated ELF"))?;
    Ok(u64::from_le_bytes(bytes.try_into().unwrap()))
}

fn put_le32(data: &mut [u8], off: usize, value: u32) -> Result<()> {
    let dst = data
        .get_mut(off..off + 4)
        .ok_or_else(|| Error::bad_kernel("truncated x86 image"))?;
    dst.copy_from_slice(&value.to_le_bytes());
    Ok(())
}

fn put_rel32(dst: &mut [u8], opcode: u8, source: u64, target: u64) -> Result<()> {
    if dst.len() < 5 {
        return Err(Error::bad_kernel("short rel32 patch site"));
    }
    let displacement = target as i128 - (source as i128 + 5);
    if displacement < i32::MIN as i128 || displacement > i32::MAX as i128 {
        return Err(Error::bad_kernel("x86 trampoline is outside rel32 range"));
    }
    dst[0] = opcode;
    dst[1..5].copy_from_slice(&(displacement as i32).to_le_bytes());
    Ok(())
}

pub fn is_x86_bzimage(data: &[u8]) -> bool {
    data.len() > X86_PAYLOAD_LENGTH_OFFSET + 4
        && get_le16(data, X86_BOOT_FLAG_OFFSET).ok() == Some(0xaa55)
        && data.get(X86_HEADER_MAGIC_OFFSET..X86_HEADER_MAGIC_OFFSET + 4) == Some(b"HdrS")
}

fn gzip_decompress(src: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::read::GzDecoder::new(src);
    let mut out = Vec::new();
    decoder
        .read_to_end(&mut out)
        .map_err(|e| Error::decompress(format!("decompress x86 payload failed: {e}")))?;
    Ok(out)
}

fn gzip_compress(src: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzBuilder::new()
        .mtime(0)
        .write(Vec::new(), Compression::best());
    encoder
        .write_all(src)
        .map_err(|e| Error::compress(format!("compress x86 payload failed: {e}")))?;
    encoder
        .finish()
        .map_err(|e| Error::compress(format!("finish x86 gzip failed: {e}")))
}

fn parse_program_headers(elf: &[u8]) -> Result<Vec<ProgramHeader>> {
    if elf.len() < ELF64_EHDR_SIZE
        || &elf[..4] != b"\x7fELF"
        || elf[4] != ELFCLASS64
        || elf[5] != ELFDATA2LSB
    {
        return Err(Error::bad_kernel(
            "x86 payload is not a little-endian ELF64 image",
        ));
    }
    if get_le16(elf, 18)? != EM_X86_64 {
        return Err(Error::bad_kernel(
            "x86 payload ELF machine is not EM_X86_64",
        ));
    }
    let phoff = get_le64(elf, 32)? as usize;
    let phentsize = get_le16(elf, 54)? as usize;
    let phnum = get_le16(elf, 56)? as usize;
    if phentsize != ELF64_PHDR_SIZE
        || phoff > elf.len()
        || phnum
            .checked_mul(phentsize)
            .and_then(|n| phoff.checked_add(n))
            .is_none_or(|end| end > elf.len())
    {
        return Err(Error::bad_kernel("invalid ELF64 program header table"));
    }
    let mut out = Vec::with_capacity(phnum);
    for index in 0..phnum {
        let p = phoff + index * phentsize;
        out.push(ProgramHeader {
            index,
            p_type: get_le32(elf, p)?,
            p_flags: get_le32(elf, p + 4)?,
            p_offset: get_le64(elf, p + 8)?,
            p_vaddr: get_le64(elf, p + 16)?,
            p_paddr: get_le64(elf, p + 24)?,
            p_filesz: get_le64(elf, p + 32)?,
            p_memsz: get_le64(elf, p + 40)?,
        });
    }
    Ok(out)
}

fn map_elf_load_segments(image: &mut X86Bzimage) -> Result<()> {
    let phdrs = parse_program_headers(&image.elf)?;
    let mut phys_base = u64::MAX;
    let mut phys_end = 0u64;
    let mut virt_base = 0u64;
    for ph in &phdrs {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let file_end = ph
            .p_offset
            .checked_add(ph.p_filesz)
            .ok_or_else(|| Error::overflow("ELF segment file range"))?;
        if file_end > image.elf.len() as u64 {
            return Err(Error::bad_kernel("ELF PT_LOAD exceeds payload"));
        }
        if ph.p_paddr < phys_base {
            phys_base = ph.p_paddr;
            virt_base = ph.p_vaddr;
        }
        let span = ph.p_memsz.max(ph.p_filesz);
        phys_end = phys_end.max(
            ph.p_paddr
                .checked_add(span)
                .ok_or_else(|| Error::overflow("ELF physical range"))?,
        );
    }
    if phys_base == u64::MAX || phys_end <= phys_base || phys_end - phys_base > usize::MAX as u64 {
        return Err(Error::bad_kernel("invalid x86 ELF load span"));
    }
    let mut flat = vec![0u8; (phys_end - phys_base) as usize];
    for ph in &phdrs {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        let dst = (ph.p_paddr - phys_base) as usize;
        let len = ph.p_filesz as usize;
        let src = ph.p_offset as usize;
        if dst.checked_add(len).is_none_or(|end| end > flat.len()) {
            return Err(Error::bad_kernel("ELF flat copy exceeds image"));
        }
        flat[dst..dst + len].copy_from_slice(&image.elf[src..src + len]);
    }
    image.flat = flat;
    image.phys_base = phys_base;
    image.virt_base = virt_base;
    logi!(
        "x86 bzImage payload: 0x{:x}+0x{:x}, ELF: 0x{:x}, flat: 0x{:x}, phys: 0x{:x}, virt: 0x{:x}",
        image.payload_start,
        image.payload_size,
        image.elf.len(),
        image.flat.len(),
        image.phys_base,
        image.virt_base
    );
    Ok(())
}

pub fn load_x86_bzimage(path: &Path) -> Result<X86Bzimage> {
    let bzimage = read_file(path)?;
    if !is_x86_bzimage(&bzimage) {
        return Err(Error::bad_kernel("not an x86 bzImage"));
    }
    let setup_sects = match bzimage[X86_SETUP_SECTS_OFFSET] {
        0 => 4usize,
        n => n as usize,
    };
    let protected_start = (setup_sects + 1) * 512;
    let payload_offset = get_le32(&bzimage, X86_PAYLOAD_OFFSET_OFFSET)? as usize;
    let payload_size = get_le32(&bzimage, X86_PAYLOAD_LENGTH_OFFSET)? as usize;
    let payload_start = protected_start
        .checked_add(payload_offset)
        .ok_or_else(|| Error::overflow("x86 payload offset"))?;
    if payload_start
        .checked_add(payload_size)
        .is_none_or(|end| end > bzimage.len())
    {
        return Err(Error::bad_kernel("x86 payload exceeds bzImage"));
    }
    let elf = gzip_decompress(&bzimage[payload_start..payload_start + payload_size])?;
    let mut image = X86Bzimage {
        bzimage,
        payload_start,
        payload_size,
        elf,
        ..Default::default()
    };
    map_elf_load_segments(&mut image)?;
    Ok(image)
}

pub fn sync_x86_flat_to_elf(image: &mut X86Bzimage) -> Result<()> {
    for ph in parse_program_headers(&image.elf)? {
        if ph.p_type != PT_LOAD || ph.p_filesz == 0 {
            continue;
        }
        if ph.p_paddr < image.phys_base {
            return Err(Error::bad_kernel("ELF segment precedes physical base"));
        }
        let src = (ph.p_paddr - image.phys_base) as usize;
        let dst = ph.p_offset as usize;
        let len = ph.p_filesz as usize;
        if src
            .checked_add(len)
            .is_none_or(|end| end > image.flat.len())
            || dst.checked_add(len).is_none_or(|end| end > image.elf.len())
        {
            return Err(Error::bad_kernel("x86 sync range exceeds image"));
        }
        image.elf[dst..dst + len].copy_from_slice(&image.flat[src..src + len]);
    }
    Ok(())
}

fn flat_offset_to_va(image: &X86Bzimage, flat_offset: u64) -> Result<u64> {
    for ph in parse_program_headers(&image.elf)? {
        if ph.p_type != PT_LOAD || ph.p_memsz == 0 || ph.p_paddr < image.phys_base {
            continue;
        }
        let segment_offset = ph.p_paddr - image.phys_base;
        if flat_offset >= segment_offset && flat_offset - segment_offset < ph.p_memsz {
            return Ok(ph.p_vaddr + (flat_offset - segment_offset));
        }
    }
    Err(Error::bad_kernel(
        "cannot map x86 flat offset to virtual address",
    ))
}

fn flat_range_ok(image: &X86Bzimage, offset: u64, size: u64) -> bool {
    offset <= image.flat.len() as u64 && size <= image.flat.len() as u64 - offset
}

pub fn inject_x86_kpimg(image: &mut X86Bzimage, kpimg: &mut [u8]) -> Result<()> {
    if kpimg.len() <= KP_X86_ENTRY_OFFSET || kpimg.len() < core::mem::size_of::<Preset>() {
        return Err(Error::bad_kpimg("x86 kpimg is too small"));
    }
    let mut preset: Preset = *bytemuck::from_bytes(&kpimg[..core::mem::size_of::<Preset>()]);
    let flags = preset.header.config_flags;
    if preset.header.magic != *KP_MAGIC || flags & CONFIG_FLAG_X86_64 == 0 {
        return Err(Error::bad_kpimg("kpimg is not an x86_64 payload"));
    }

    let mut kallsym = Kallsym::default();
    analyze_kallsym_info(&mut kallsym, &mut image.flat, ArchType::X86_64, true)?;
    let start_kernel = get_symbol_offset(&kallsym, &image.flat, "start_kernel")
        .ok_or_else(|| Error::kallsym("x86 start_kernel is unavailable"))?;
    if start_kernel < 0 || !flat_range_ok(image, start_kernel as u64, HDR_BACKUP_SIZE as u64) {
        return Err(Error::bad_kernel("x86 start_kernel is out of range"));
    }
    let call_site_offset = start_kernel as usize;
    let ftrace_nop = [0x0f, 0x1f, 0x44, 0x00, 0x00];
    if image.flat[call_site_offset..call_site_offset + CALL_PATCH_SIZE] != ftrace_nop {
        return Err(Error::bad_kernel(
            "unsupported x86 start_kernel prologue; expected five-byte ftrace NOP",
        ));
    }

    let runtime_size = kpimg.len() as u64;
    let phdrs = parse_program_headers(&image.elf)?;
    let mut best: Option<(ProgramHeader, u64, u64, u64)> = None;
    for ph in phdrs.iter().copied() {
        if ph.p_type != PT_LOAD || ph.p_flags & PF_X == 0 || ph.p_paddr < image.phys_base {
            continue;
        }
        let segment_flat = ph.p_paddr - image.phys_base;
        if !flat_range_ok(image, segment_flat, ph.p_filesz) {
            continue;
        }
        let segment = &image.flat[segment_flat as usize..(segment_flat + ph.p_filesz) as usize];
        let mut run_start = 0u64;
        for (pos, byte) in segment.iter().enumerate() {
            if *byte != 0 {
                continue;
            }
            let pos = pos as u64;
            if pos == 0 || segment[pos as usize - 1] != 0 {
                run_start = pos;
            }
            let payload_offset = (run_start + 15) & !15u64;
            let trampoline_offset = (payload_offset + runtime_size + 15) & !15u64;
            if trampoline_offset > pos || TRAMPOLINE_SIZE as u64 > pos - trampoline_offset + 1 {
                continue;
            }
            let run_size = pos - run_start + 1;
            if best.is_some_and(|(_, _, _, best_size)| run_size >= best_size) {
                continue;
            }
            best = Some((ph, payload_offset, trampoline_offset, run_size));
        }
    }
    let (segment, kpimg_segment_offset, trampoline_segment_offset, _) =
        best.ok_or_else(|| Error::bad_kernel("x86 executable segment has no room for kpimg"))?;
    let payload_phys = segment.p_paddr + kpimg_segment_offset;
    let trampoline_phys = segment.p_paddr + trampoline_segment_offset;
    let payload_flat = payload_phys - image.phys_base;
    let trampoline_flat = trampoline_phys - image.phys_base;
    if !flat_range_ok(image, payload_flat, runtime_size)
        || !flat_range_ok(image, trampoline_flat, TRAMPOLINE_SIZE as u64)
    {
        return Err(Error::bad_kernel(
            "x86 injection range is outside flat image",
        ));
    }
    let call_site_va = flat_offset_to_va(image, start_kernel as u64)?;
    let trampoline_va = flat_offset_to_va(image, trampoline_flat)?;
    let payload_entry = flat_offset_to_va(image, payload_flat + KP_X86_ENTRY_OFFSET as u64)?;

    preset.setup.kimg_size = segment.p_filesz as i64;
    preset.setup.kpimg_size = kpimg.len() as i64;
    preset.setup.kernel_size = segment.p_memsz as i64;
    preset.setup.page_shift = 12;
    preset.setup.setup_offset = payload_flat as i64;
    preset.setup.start_offset = start_kernel as i64;
    preset.setup.extra_size = image.payload_size as i64;
    preset.setup.map_offset = start_kernel as i64;
    preset.setup.map_max_size = segment.index as i64;
    preset.setup.paging_init_offset = trampoline_flat as i64;
    preset
        .setup
        .header_backup
        .copy_from_slice(&image.flat[call_site_offset..call_site_offset + HDR_BACKUP_SIZE]);

    let tramp = trampoline_flat as usize;
    let trampoline = &mut image.flat[tramp..tramp + TRAMPOLINE_SIZE];
    trampoline.fill(0);
    trampoline[0] = 0x50;
    trampoline[1] = 0x48;
    trampoline[2] = 0xb8;
    trampoline[3..11].copy_from_slice(&payload_entry.to_le_bytes());
    trampoline[11] = 0xff;
    trampoline[12] = 0xd0;
    trampoline[13] = 0x58;
    trampoline[14] = 0xc3;
    trampoline[15] = 0x90;
    put_rel32(
        &mut image.flat[call_site_offset..call_site_offset + CALL_PATCH_SIZE],
        0xe8,
        call_site_va,
        trampoline_va,
    )?;

    kpimg[..core::mem::size_of::<Preset>()].copy_from_slice(bytemuck::bytes_of(&preset));
    let payload_at = payload_flat as usize;
    image.flat[payload_at..payload_at + kpimg.len()].copy_from_slice(kpimg);
    logi!("x86 kpimg injected: segment {}, start_kernel 0x{:x}, trampoline 0x{:x}, payload 0x{:x}+0x{:x}, entry 0x{:x}",
        segment.index, call_site_va, trampoline_phys, payload_phys, kpimg.len(), payload_entry);
    Ok(())
}

pub fn remove_x86_kpimg(image: &mut X86Bzimage) -> Result<()> {
    let preset_size = core::mem::size_of::<Preset>();
    let mut found = None;
    for offset in 0..=image.flat.len().saturating_sub(preset_size) {
        if image.flat.get(offset..offset + MAGIC_LEN) != Some(KP_MAGIC.as_slice()) {
            continue;
        }
        let candidate: Preset = *bytemuck::from_bytes(&image.flat[offset..offset + preset_size]);
        let flags = candidate.header.config_flags;
        let setup_offset = candidate.setup.setup_offset;
        if flags & CONFIG_FLAG_X86_64 != 0 && setup_offset == offset as i64 {
            found = Some((offset, candidate));
            break;
        }
    }
    let (preset_offset, preset) =
        found.ok_or_else(|| Error::bad_preset("x86 kpimg preset not found"))?;
    let blob_size = preset.setup.kpimg_size;
    let trampoline_offset = preset.setup.paging_init_offset;
    let entry_offset = preset.setup.map_offset;
    let payload_slot_size = preset.setup.extra_size;
    if blob_size <= 0
        || trampoline_offset < 0
        || entry_offset < 0
        || !flat_range_ok(image, preset_offset as u64, blob_size as u64)
        || !flat_range_ok(image, trampoline_offset as u64, TRAMPOLINE_SIZE as u64)
        || !flat_range_ok(image, entry_offset as u64, HDR_BACKUP_SIZE as u64)
    {
        return Err(Error::bad_preset(
            "x86 kpimg preset describes an out-of-range region",
        ));
    }
    let backup = preset.setup.header_backup;
    image.flat[preset_offset..preset_offset + blob_size as usize].fill(0);
    image.flat[trampoline_offset as usize..trampoline_offset as usize + TRAMPOLINE_SIZE].fill(0);
    image.flat[entry_offset as usize..entry_offset as usize + HDR_BACKUP_SIZE]
        .copy_from_slice(&backup);
    if payload_slot_size > 0
        && image.payload_start + payload_slot_size as usize <= image.bzimage.len()
    {
        image.payload_size = payload_slot_size as usize;
    }
    logi!("x86 kpimg removed: blob 0x{preset_offset:x}+0x{blob_size:x}, trampoline 0x{trampoline_offset:x}, restored call site 0x{:x}", image.phys_base + entry_offset as u64);
    Ok(())
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn write_x86_bzimage(image: &mut X86Bzimage, path: &Path) -> Result<()> {
    sync_x86_flat_to_elf(image)?;
    let mut payload = gzip_compress(&image.elf)?;
    logi!(
        "x86 payload compressed with flate2: 0x{:x} (slot 0x{:x})",
        payload.len(),
        image.payload_size
    );
    if payload.len() > image.payload_size {
        return Err(Error::compress(format!(
            "x86 payload does not fit the fixed bzImage slot: 0x{:x} > 0x{:x}",
            payload.len(),
            image.payload_size
        )));
    }
    payload.resize(image.payload_size, 0);

    let suffix_start = image
        .payload_start
        .checked_add(image.payload_size)
        .ok_or_else(|| Error::overflow("x86 suffix offset"))?;
    if suffix_start > image.bzimage.len() || image.bzimage.len() - suffix_start < 4 {
        return Err(Error::bad_kernel(
            "x86 bzImage suffix/checksum is truncated",
        ));
    }
    let suffix_data_size = image.bzimage.len() - suffix_start - 4;
    let suffix_padding = if image.suffix_payload.is_empty() {
        0
    } else {
        (16 - (suffix_data_size & 15)) & 15
    };
    let output_size = image.payload_start
        + payload.len()
        + suffix_data_size
        + suffix_padding
        + image.suffix_payload.len()
        + 4;
    let mut output = vec![0u8; output_size];
    output[..image.payload_start].copy_from_slice(&image.bzimage[..image.payload_start]);
    let mut cursor = image.payload_start;
    output[cursor..cursor + payload.len()].copy_from_slice(&payload);
    cursor += payload.len();
    output[cursor..cursor + suffix_data_size]
        .copy_from_slice(&image.bzimage[suffix_start..suffix_start + suffix_data_size]);
    cursor += suffix_data_size + suffix_padding;
    if !image.suffix_payload.is_empty() {
        output[cursor..cursor + image.suffix_payload.len()].copy_from_slice(&image.suffix_payload);
    }
    put_le32(&mut output, X86_PAYLOAD_LENGTH_OFFSET, payload.len() as u32)?;
    let setup_sects = match output[X86_SETUP_SECTS_OFFSET] {
        0 => 4usize,
        n => n as usize,
    };
    let protected_size = output_size - (setup_sects + 1) * 512;
    put_le32(
        &mut output,
        X86_SYSSIZE_OFFSET,
        protected_size.div_ceil(16) as u32,
    )?;
    let checksum = !crc32(&output[..output_size - 4]);
    put_le32(&mut output, output_size - 4, checksum)?;
    write_file(path, &output)?;
    logi!(
        "x86 bzImage repacked: payload 0x{:x}, image 0x{:x} -> 0x{:x}",
        image.payload_size,
        image.bzimage.len(),
        output_size
    );
    Ok(())
}

pub fn free_x86_bzimage(image: &mut X86Bzimage) {
    *image = X86Bzimage::default();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_bzimage_header() {
        let mut image = vec![0u8; 0x300];
        image[X86_BOOT_FLAG_OFFSET..X86_BOOT_FLAG_OFFSET + 2]
            .copy_from_slice(&0xaa55u16.to_le_bytes());
        image[X86_HEADER_MAGIC_OFFSET..X86_HEADER_MAGIC_OFFSET + 4].copy_from_slice(b"HdrS");
        assert!(is_x86_bzimage(&image));
        image[X86_HEADER_MAGIC_OFFSET] = b'X';
        assert!(!is_x86_bzimage(&image));
    }

    #[test]
    fn rel32_encoding() {
        let mut buf = [0u8; 5];
        put_rel32(&mut buf, 0xe8, 0x1000, 0x1100).unwrap();
        assert_eq!(buf[0], 0xe8);
        assert_eq!(i32::from_le_bytes(buf[1..5].try_into().unwrap()), 0xfb);
    }

    #[test]
    fn flate2_gzip_roundtrip() {
        let src = b"kernelpatch x86 payload".repeat(128);
        let gz = gzip_compress(&src).unwrap();
        assert_eq!(gzip_decompress(&gz).unwrap(), src);
    }

    #[test]
    fn crc32_matches_known_vector() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
    }
}
