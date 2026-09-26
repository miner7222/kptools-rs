//! AOSP boot image unpacking and repacking.
//!
//! Port of upstream `tools/bootimg.{c,h}`, including compression matching,
//! appended DTB preservation, ID digests, and AVB footer updates.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use bytemuck::{Pod, Zeroable};
use kptools_base::{io::write_file, logi, Error, Result};

pub const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
pub const PAGE_SIZE_DEFAULT: u32 = 4096;
pub const LZ4_MAGIC: u32 = 0x184c_2102;
pub const LZ4_BLOCK_SIZE: usize = 0x0080_0000;
pub const AVB_FOOTER_SIZE: usize = 64;
const AVB_VBMETA_MIN_SIZE: usize = 256;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct BootImgHdr {
    pub magic: [u8; 8], // "ANDROID!"
    pub kernel_size: u32,
    pub kernel_addr: u32, // v3: this field is ramdisk_size
    pub ramdisk_size: u32,
    pub ramdisk_addr: u32,
    pub second_size: u32,
    pub second_addr: u32,
    pub tags_addr: u32,
    pub page_size: u32,
    pub unused: [u32; 2], // unused[0] = header version
    pub name: [u8; 16],
    pub cmdline: [u8; 512],
    pub id: [u32; 8],
    pub extra_cmdline: [u8; 1024],
    // v2 extension
    pub recovery_dtbo_size: u32,
    pub recovery_dtbo_offset: u64,
    // v3 extension
    pub dtb_size: u32,
    pub dtb_addr: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct AvbFooter {
    pub magic: [u8; 4],
    pub version: [u8; 4],
    pub reserved0: [u8; 4],
    pub image_size: [u8; 8],
    pub vbmeta_offset: [u8; 8],
    pub vbmeta_size: [u8; 8],
    pub reserved1: [u8; 28],
}

/// 1 = SHA-256, 0 = SHA-1, 2 = ambiguous.
pub fn is_sha256(id: &[u32; 8]) -> i32 {
    if (id[0] | id[1] | id[2] | id[3] | id[4] | id[5]) == 0 {
        return 1;
    }
    if id[6] != 0 || id[7] != 0 {
        return 2;
    }
    0
}

pub fn detect_compress_method(magic: &[u8]) -> i32 {
    if magic.len() < 4 {
        return 0;
    }
    // gzip / zopfli
    if magic[0] == 0x1F && (magic[1] == 0x8B || magic[1] == 0x9E) {
        return 1;
    }
    // lz4 frame
    if magic[0] == 0x04 && magic[1] == 0x22 && magic[2] == 0x4D && magic[3] == 0x18 {
        return 2;
    }
    // the alt lz4 frame variant upstream also accepts
    if magic[0] == 0x03 && magic[1] == 0x21 && magic[2] == 0x4C && magic[3] == 0x18 {
        return 2;
    }
    // lz4 legacy
    if magic[0] == 0x02 && magic[1] == 0x21 && magic[2] == 0x4C && magic[3] == 0x18 {
        return 3;
    }
    // zstd
    if magic[0] == 0x28 && magic[1] == 0xB5 && magic[2] == 0x2F && magic[3] == 0xFD {
        return 4;
    }
    // bzip2
    if magic[0] == 0x42 && magic[1] == 0x5A && magic[2] == 0x68 {
        return 5;
    }
    // xz
    if magic[0] == 0xFD && magic[1] == 0x37 && magic[2] == 0x7A && magic[3] == 0x58 {
        return 6;
    }
    // lzma
    if magic.len() >= 3 && magic[0] == 0x5D && magic[1] == 0x00 && magic[2] == 0x00 {
        return 7;
    }
    0
}

fn decompress_gzip_to(data: &[u8], out_path: &Path) -> Result<()> {
    use flate2::read::MultiGzDecoder;
    let mut dec = MultiGzDecoder::new(data);
    let mut out = File::create(out_path).map_err(Error::Io)?;
    std::io::copy(&mut dec, &mut out).map_err(|e| Error::decompress(e.to_string()))?;
    Ok(())
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::GzEncoder;
    use flate2::Compression;
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

/// Raw DEFLATE helper retained for parity with upstream tools.
#[allow(dead_code)]
fn compress_raw_deflate(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::write::DeflateEncoder;
    use flate2::Compression;
    let mut enc = DeflateEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_lz4_frame_to(data: &[u8], out_path: &Path) -> Result<()> {
    let mut dec = lz4::Decoder::new(data).map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf)
        .map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_lz4_frame(data: &[u8]) -> Result<Vec<u8>> {
    use lz4::EncoderBuilder;
    let mut enc = EncoderBuilder::new()
        .level(12)
        .build(Vec::new())
        .map_err(|e| Error::compress(e.to_string()))?;
    enc.write_all(data).map_err(Error::Io)?;
    let (out, res) = enc.finish();
    res.map_err(|e| Error::compress(e.to_string()))?;
    Ok(out)
}

/// LZ4 legacy block format: `MAGIC u32 | (block_size u32 | compressed…)*`
/// terminated by a zero-length block or EOF.
fn decompress_lz4_legacy_to(data: &[u8], out_path: &Path) -> Result<()> {
    if data.len() < 4 {
        return Err(Error::decompress("lz4 legacy: too small"));
    }
    let magic = u32::from_le_bytes(data[..4].try_into().unwrap());
    if magic != LZ4_MAGIC {
        return Err(Error::decompress("lz4 legacy: bad magic"));
    }
    let mut pos = 4usize;
    let mut out = Vec::with_capacity(64 * 1024 * 1024);
    let _block_out = vec![0u8; LZ4_BLOCK_SIZE];
    loop {
        if pos + 4 > data.len() {
            break;
        }
        let block_size = u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
        pos += 4;
        if block_size == 0 {
            break;
        }
        if pos + block_size > data.len() {
            return Err(Error::decompress("lz4 legacy: truncated block"));
        }
        let decoded = lz4_flex::block::decompress(&data[pos..pos + block_size], LZ4_BLOCK_SIZE)
            .map_err(|e| Error::decompress(format!("lz4 block: {e}")))?;
        out.extend_from_slice(&decoded);
        pos += block_size;
    }
    write_file(out_path, &out)
}

/// Compresses to upstream's LZ4 legacy block format.
fn compress_lz4_legacy(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&LZ4_MAGIC.to_le_bytes());
    for chunk in data.chunks(LZ4_BLOCK_SIZE) {
        // `lz4` exposes high-compression blocks and lets this format write its
        // own length prefix.
        let mut compressed = lz4::block::compress(
            chunk,
            Some(lz4::block::CompressionMode::HIGHCOMPRESSION(12)),
            false,
        )
        .map_err(|e| Error::compress(e.to_string()))?;
        let bs = compressed.len() as u32;
        out.extend_from_slice(&bs.to_le_bytes());
        out.append(&mut compressed);
    }
    Ok(out)
}

fn decompress_bzip2_to(data: &[u8], out_path: &Path) -> Result<()> {
    use bzip2::read::BzDecoder;
    let mut dec = BzDecoder::new(data);
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf)
        .map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_bzip2(data: &[u8]) -> Result<Vec<u8>> {
    use bzip2::write::BzEncoder;
    use bzip2::Compression;
    let mut enc = BzEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_xz_to(data: &[u8], out_path: &Path) -> Result<()> {
    use lzma_rust2::XzReader;
    let mut dec = XzReader::new(data, true);
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf)
        .map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn decompress_lzma_to(data: &[u8], out_path: &Path) -> Result<()> {
    use lzma_rust2::LzmaReader;
    let mut dec = LzmaReader::new_mem_limit(data, u32::MAX, None)
        .map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf)
        .map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn decompress_zstd_to(data: &[u8], out_path: &Path) -> Result<()> {
    let mut dec =
        zstd::stream::read::Decoder::new(data).map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf)
        .map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

pub fn auto_depress(data: &[u8], out_path: &Path) -> Result<()> {
    if data.len() < 4 {
        return Err(Error::decompress("auto_depress: data too small"));
    }
    let method = detect_compress_method(&data[..4.min(data.len())]);
    logi!("Auto-detect compression method: {method}");
    match method {
        1 => {
            logi!("Detected GZIP compressed kernel.");
            decompress_gzip_to(data, out_path)?;
            logi!("Decompressed to {}", out_path.display());
        }
        2 => {
            logi!("Detected LZ4 Frame. Decompressing...");
            decompress_lz4_frame_to(data, out_path)?;
        }
        3 => {
            logi!("Detected LZ4 Legacy. Decompressing...");
            decompress_lz4_legacy_to(data, out_path)?;
        }
        4 => {
            logi!("Detected ZSTD. Decompressing...");
            decompress_zstd_to(data, out_path)?;
        }
        5 => {
            logi!("Detected BZIP2. Decompressing...");
            decompress_bzip2_to(data, out_path)?;
        }
        6 => {
            logi!("Detected XZ. Decompressing...");
            decompress_xz_to(data, out_path)?;
        }
        7 => {
            logi!("Detected Legacy LZMA. Decompressing...");
            decompress_lzma_to(data, out_path)?;
        }
        _ => {
            logi!("Treating as Raw Kernel (or unknown format).");
            write_file(out_path, data)?;
        }
    }
    Ok(())
}

/// Decompresses a kernel into memory using its detected format.
pub fn auto_depress_to_mem(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        return Err(Error::decompress("auto_depress_to_mem: data too small"));
    }
    let method = detect_compress_method(&data[..4]);
    logi!("Auto-detect compression method: {method}");
    let mut out = Vec::with_capacity(64 * 1024 * 1024);
    match method {
        1 => {
            use flate2::read::GzDecoder;
            logi!("Detected GZIP compressed kernel.");
            GzDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| Error::decompress(e.to_string()))?;
            logi!("Decompressed: {} bytes", out.len());
        }
        2 => {
            logi!("Detected LZ4 Frame. Decompressing with lz4frame...");
            lz4::Decoder::new(data)
                .map_err(|e| Error::decompress(e.to_string()))?
                .read_to_end(&mut out)
                .map_err(|e| Error::decompress(e.to_string()))?;
            logi!("Decompressed: {} bytes", out.len());
        }
        3 => {
            logi!("Probing LZ4 Legacy (block-based)...");
            if u32::from_le_bytes(data[..4].try_into().unwrap()) != LZ4_MAGIC {
                return Err(Error::decompress("lz4 legacy: bad magic"));
            }
            let mut pos = 4usize;
            while pos + 4 <= data.len() {
                let block_size =
                    u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap()) as usize;
                pos += 4;
                if block_size == 0 {
                    break;
                }
                if pos + block_size > data.len() {
                    return Err(Error::decompress("lz4 legacy: truncated block"));
                }
                let decoded =
                    lz4_flex::block::decompress(&data[pos..pos + block_size], LZ4_BLOCK_SIZE)
                        .map_err(|e| Error::decompress(format!("lz4 block: {e}")))?;
                out.extend_from_slice(&decoded);
                pos += block_size;
            }
            if out.is_empty() {
                logi!("Not LZ4 block format, fallback.");
                out.extend_from_slice(data);
            } else {
                logi!("LZ4 block decompressed: {} bytes", out.len());
            }
        }
        5 => {
            use bzip2::read::BzDecoder;
            logi!("Detected BZIP2. Decompressing...");
            BzDecoder::new(data)
                .read_to_end(&mut out)
                .map_err(|e| Error::decompress(e.to_string()))?;
            logi!("BZIP2 Decompressed: {} bytes", out.len());
        }
        6 => {
            use lzma_rust2::XzReader;
            logi!("Detected XZ format. Decompressing...");
            XzReader::new(data, true)
                .read_to_end(&mut out)
                .map_err(|e| Error::decompress(e.to_string()))?;
            logi!("XZ Decompressed: {} bytes", out.len());
        }
        7 => {
            use lzma_rust2::LzmaReader;
            logi!("Detected Legacy LZMA format. Decompressing...");
            LzmaReader::new_mem_limit(data, u32::MAX, None)
                .map_err(|e| Error::decompress(e.to_string()))?
                .read_to_end(&mut out)
                .map_err(|e| Error::decompress(e.to_string()))?;
            logi!("LZMA Decompressed: {} bytes", out.len());
        }
        _ => {
            // Upstream's in-memory path treats zstd (currently unsupported
            // there) and all unknown formats as a raw kernel.
            logi!("Treating as Raw Kernel (or unknown format).");
            out.extend_from_slice(data);
        }
    }
    Ok(out)
}

/// Extracts and decompresses the kernel from an AOSP boot image.
pub fn extract_kernel(bootimg_path: &Path, out_path: &Path) -> Result<()> {
    let data = kptools_base::io::read_file(bootimg_path)?;
    if data.len() < core::mem::size_of::<BootImgHdr>() {
        return Err(Error::bad_bootimg("truncated boot image"));
    }
    let hdr: &BootImgHdr = bytemuck::from_bytes(&data[..core::mem::size_of::<BootImgHdr>()]);
    if hdr.magic != *BOOT_MAGIC {
        return Err(Error::bad_bootimg("not an ANDROID! boot image"));
    }

    let page_size = hdr.page_size;
    let header_ver = hdr.unused[0];
    let kernel_size = hdr.kernel_size as usize;
    // Values above 10 encode `extracted_size` in `unused[0]`, so upstream
    // deliberately treats them as a sentinel rather than a header version.
    let mut kernel_offset = page_size;
    if header_ver >= 3 {
        kernel_offset = 4096;
    }
    if header_ver > 10 {
        kernel_offset = page_size;
    }
    logi!("Kernel size: {kernel_size}, Header Version: {header_ver}, Offset: {kernel_offset}");

    let start = kernel_offset as usize;
    let end = start
        .checked_add(kernel_size)
        .ok_or_else(|| Error::bad_bootimg("kernel offset + size overflow"))?;
    if end > data.len() {
        return Err(Error::bad_bootimg("kernel section past file end"));
    }
    let kernel_data = &data[start..end];
    auto_depress(kernel_data, out_path)?;
    Ok(())
}

pub fn is_bootimg(path: &Path) -> bool {
    let Ok(mut file) = File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).is_ok() && magic == *BOOT_MAGIC
}

/// Append-DTB detection scan: look for the flattened device tree
/// magic `0xd00dfeed` followed by a sane `totalsize` + a
/// `FDT_BEGIN_NODE` tag at `off_dt_struct`.
fn find_dtb_offset(buf: &[u8]) -> Option<usize> {
    const FDT_HEADER: usize = 40;
    const DTB_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];
    let mut pos = 0usize;
    while pos + FDT_HEADER < buf.len() {
        let rel = buf[pos..].windows(4).position(|w| w == DTB_MAGIC)?;
        let cand = pos + rel;
        if cand + FDT_HEADER > buf.len() {
            return None;
        }
        let total = u32::from_be_bytes(buf[cand + 4..cand + 8].try_into().unwrap()) as usize;
        let off_dt_struct =
            u32::from_be_bytes(buf[cand + 8..cand + 12].try_into().unwrap()) as usize;
        if total > buf.len() - cand || total <= 0x48 {
            pos = cand + 4;
            continue;
        }
        if cand + off_dt_struct + 4 <= buf.len() {
            let tag = u32::from_be_bytes(
                buf[cand + off_dt_struct..cand + off_dt_struct + 4]
                    .try_into()
                    .unwrap(),
            );
            if tag == 0x0000_0001 {
                return Some(cand);
            }
        }
        pos = cand + 4;
    }
    None
}

fn align_up(v: u32, a: u32) -> u32 {
    if a == 0 {
        v
    } else {
        v.div_ceil(a) * a
    }
}

fn shifted_offset(value: usize, old_start: usize, new_start: usize) -> Result<usize> {
    if new_start >= old_start {
        value.checked_add(new_start - old_start)
    } else {
        value.checked_sub(old_start - new_start)
    }
    .ok_or_else(|| Error::bad_bootimg("AVB offset shift overflow"))
}

pub fn repack_bootimg(
    orig_boot_path: &Path,
    new_kernel_path: &Path,
    out_boot_path: &Path,
) -> Result<()> {
    let raw_k = kptools_base::io::read_file(new_kernel_path)?;
    repack_bootimg_mem(orig_boot_path, &raw_k, out_boot_path)
}

/// Repacks an in-memory kernel using the source boot image's compression.
pub fn repack_bootimg_mem(
    orig_boot_path: &Path,
    new_kernel: &[u8],
    out_boot_path: &Path,
) -> Result<()> {
    logi!("Starting automatic repack...");

    let data = kptools_base::io::read_file(orig_boot_path)?;
    if data.len() < core::mem::size_of::<BootImgHdr>() {
        return Err(Error::bad_bootimg("boot image truncated"));
    }
    let hdr_size = core::mem::size_of::<BootImgHdr>();
    let mut hdr: BootImgHdr = *bytemuck::from_bytes(&data[..hdr_size]);
    if hdr.magic != *BOOT_MAGIC {
        return Err(Error::bad_bootimg("not an ANDROID! boot image"));
    }
    let total_size = data.len();
    let avb_size_of = core::mem::size_of::<AvbFooter>();
    let avb = (total_size >= avb_size_of)
        .then(|| *bytemuck::from_bytes::<AvbFooter>(&data[total_size - avb_size_of..]))
        .filter(|footer| footer.magic == *b"AVBf");

    let mut header_ver = hdr.unused[0];
    let mut extracted_size: u32 = 0;
    if header_ver > 10 {
        extracted_size = header_ver;
        header_ver = 0;
    }
    let page_size = if header_ver >= 3 { 4096 } else { hdr.page_size };
    if (page_size as usize) < hdr_size {
        return Err(Error::bad_bootimg("invalid boot image page size"));
    }
    let fmt_size = if header_ver >= 3 {
        hdr.kernel_addr
    } else {
        hdr.ramdisk_size
    };
    logi!("Header Version: {header_ver}, Page Size: {page_size}, fmt_size: {fmt_size}");

    let old_k_start = page_size as usize;
    let old_k_end = old_k_start
        .checked_add(hdr.kernel_size as usize)
        .ok_or_else(|| Error::bad_bootimg("kernel section overflow"))?;
    if old_k_end > data.len() {
        return Err(Error::bad_bootimg("kernel section past file end"));
    }
    let old_k = &data[old_k_start..old_k_end];
    let method = detect_compress_method(&old_k[..4.min(old_k.len())]);

    let mut extracted_dtb: Vec<u8> = Vec::new();
    if header_ver < 3 {
        if let Some(dtb_off) = find_dtb_offset(old_k) {
            extracted_dtb.extend_from_slice(&old_k[dtb_off..]);
            logi!(
                "Detected DTB appended to kernel. Size: {}",
                extracted_dtb.len()
            );
        }
    }

    let raw_k = new_kernel;

    // Upstream falls back to GZIP when the source uses XZ or LZMA.
    let (final_k, final_method) = match method {
        1 => {
            logi!("Compressing new kernel with GZIP...");
            (compress_gzip(raw_k)?, 1)
        }
        2 => {
            logi!("Compressing new kernel with LZ4...");
            (compress_lz4_frame(raw_k)?, 2)
        }
        3 => {
            logi!("Compressing new kernel with LZ4 Legacy...");
            (compress_lz4_legacy(raw_k)?, 3)
        }
        4 => {
            return Err(Error::compress(
                "kernel uses zstd, repacking is not supported",
            ));
        }
        5 => {
            logi!("Compressing new kernel with BZIP2 level 9...");
            (compress_bzip2(raw_k)?, 5)
        }
        6 | 7 => {
            logi!("Original was XZ/LZMA. Repacking as GZIP for compatibility...");
            (compress_gzip(raw_k)?, 1)
        }
        _ => (raw_k.to_vec(), 0),
    };
    let _ = final_method;
    let final_k_size = u32::try_from(final_k.len())
        .map_err(|_| Error::bad_bootimg("repacked kernel exceeds u32"))?;
    logi!("Final kernel size after compression (if applied): {final_k_size} bytes");

    let dtb_size = u32::try_from(extracted_dtb.len())
        .map_err(|_| Error::bad_bootimg("appended DTB exceeds u32"))?;
    let old_k_aligned = (hdr.kernel_size as usize)
        .div_ceil(page_size as usize)
        .checked_mul(page_size as usize)
        .ok_or_else(|| Error::bad_bootimg("kernel padding overflow"))?;
    let rest_data_offset = (page_size as usize)
        .checked_add(old_k_aligned)
        .ok_or_else(|| Error::bad_bootimg("rest data offset overflow"))?;
    if rest_data_offset > total_size {
        return Err(Error::bad_bootimg("padded kernel past file end"));
    }
    hdr.kernel_size = final_k_size
        .checked_add(dtb_size)
        .ok_or_else(|| Error::bad_bootimg("repacked kernel size overflow"))?;
    let new_k_total_aligned = (hdr.kernel_size as usize)
        .div_ceil(page_size as usize)
        .checked_mul(page_size as usize)
        .ok_or_else(|| Error::bad_bootimg("repacked kernel padding overflow"))?;
    let new_rest_offset = (page_size as usize)
        .checked_add(new_k_total_aligned)
        .ok_or_else(|| Error::bad_bootimg("repacked rest offset overflow"))?;
    let avb_metadata = if let Some(footer) = avb {
        let old_image_size = usize::try_from(u64::from_be_bytes(footer.image_size))
            .map_err(|_| Error::bad_bootimg("AVB image_size overflow"))?;
        let old_vbmeta_offset = usize::try_from(u64::from_be_bytes(footer.vbmeta_offset))
            .map_err(|_| Error::bad_bootimg("AVB vbmeta_offset overflow"))?;
        let vbmeta_size = usize::try_from(u64::from_be_bytes(footer.vbmeta_size))
            .map_err(|_| Error::bad_bootimg("AVB vbmeta_size overflow"))?;
        let footer_offset = total_size - avb_size_of;
        let metadata_end = old_vbmeta_offset
            .checked_add(vbmeta_size)
            .ok_or_else(|| Error::bad_bootimg("AVB metadata bounds overflow"))?;
        if footer_offset < rest_data_offset
            || u32::from_be_bytes(footer.version) != 1
            || old_image_size < rest_data_offset
            || old_vbmeta_offset < old_image_size
            || old_vbmeta_offset < rest_data_offset
            || vbmeta_size < AVB_VBMETA_MIN_SIZE
            || metadata_end > footer_offset
            || &data[old_vbmeta_offset..old_vbmeta_offset + 4] != b"AVB0"
        {
            return Err(Error::bad_bootimg("invalid AVB footer or metadata"));
        }
        let new_image_size = shifted_offset(old_image_size, rest_data_offset, new_rest_offset)?;
        let new_vbmeta_offset =
            shifted_offset(old_vbmeta_offset, rest_data_offset, new_rest_offset)?;
        if new_image_size < new_rest_offset || new_vbmeta_offset < new_image_size {
            return Err(Error::bad_bootimg("shifted AVB bounds invalid"));
        }
        Some((
            footer,
            old_vbmeta_offset,
            vbmeta_size,
            new_image_size,
            new_vbmeta_offset,
        ))
    } else {
        None
    };
    let mut checksum_aligned = align_up(fmt_size, page_size);

    // Every byte following the padded kernel is opaque except a recognized AVB footer.
    let tail_end = if avb.is_some() {
        total_size - avb_size_of
    } else {
        total_size
    };
    let rest_buf = &data[rest_data_offset..tail_end];

    // Upstream skips the hash rewrite for modern signed images that rely on
    // AVB alone. A dynamic digest keeps the update order identical for SHA-1
    // and SHA-256.
    let id_copy = hdr.id;
    let use_sha256 = is_sha256(&id_copy);
    if use_sha256 != 1 || header_ver <= 3 {
        let mut dyn_ctx: Box<dyn digest::DynDigest> = if use_sha256 != 0 {
            Box::new(sha2::Sha256::default())
        } else {
            Box::new(sha1::Sha1::default())
        };
        dyn_ctx.update(&final_k);
        dyn_ctx.update(&hdr.kernel_size.to_le_bytes());
        update_with_rest_dyn(&mut *dyn_ctx, rest_buf, fmt_size as usize);
        dyn_ctx.update(&fmt_size.to_le_bytes());
        update_with_rest_dyn(
            &mut *dyn_ctx,
            sec_slice(rest_buf, checksum_aligned, hdr.second_size),
            hdr.second_size as usize,
        );
        dyn_ctx.update(&hdr.second_size.to_le_bytes());
        if hdr.second_size > 0 {
            checksum_aligned += align_up(hdr.second_size, page_size);
        }
        if extracted_size != 0 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(rest_buf, checksum_aligned, page_size),
                page_size as usize,
            );
            dyn_ctx.update(&extracted_size.to_le_bytes());
            checksum_aligned += align_up(extracted_size, page_size);
        }
        if header_ver == 1 || header_ver == 2 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(rest_buf, checksum_aligned, hdr.recovery_dtbo_size),
                hdr.recovery_dtbo_size as usize,
            );
            dyn_ctx.update(&hdr.recovery_dtbo_size.to_le_bytes());
            checksum_aligned += align_up(hdr.recovery_dtbo_size, page_size);
        }
        if header_ver == 2 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(rest_buf, checksum_aligned, hdr.dtb_size),
                hdr.dtb_size as usize,
            );
            dyn_ctx.update(&hdr.dtb_size.to_le_bytes());
        }
        let out_len = dyn_ctx.output_size();
        let mut id_bytes = [0u8; 32];
        let digest = dyn_ctx.finalize();
        id_bytes[..out_len].copy_from_slice(&digest[..out_len]);
        for (i, chunk) in id_bytes.chunks(4).enumerate() {
            hdr.id[i] = u32::from_le_bytes(chunk.try_into().unwrap());
        }
    }

    let mut out = Vec::with_capacity(total_size);
    out.extend_from_slice(bytemuck::bytes_of(&hdr));
    out.resize(page_size as usize, 0);
    out.extend_from_slice(&final_k);
    if !extracted_dtb.is_empty() {
        out.extend_from_slice(&extracted_dtb);
    }
    let k_end = new_rest_offset;
    if out.len() < k_end {
        out.resize(k_end, 0);
    } else {
        out.truncate(k_end);
    }

    // AVB images commonly reserve zero slack before the footer. Reuse it when
    // the padded kernel grows, but never trim any part of the metadata blob.
    let copied_tail = if let Some((_, old_offset, size, _, _)) = avb_metadata {
        let metadata_end = old_offset + size - rest_data_offset;
        let last_nonzero = rest_buf.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
        &rest_buf[..metadata_end.max(last_nonzero)]
    } else {
        rest_buf
    };
    out.extend_from_slice(copied_tail);
    if let Some((mut footer, old_offset, size, new_image_size, new_offset)) = avb_metadata {
        let new_end = new_offset
            .checked_add(size)
            .ok_or_else(|| Error::bad_bootimg("shifted AVB metadata overflow"))?;
        let original_end = old_offset + size;
        if new_end > out.len() || out[new_offset..new_end] != data[old_offset..original_end] {
            return Err(Error::bad_bootimg("AVB metadata was not preserved"));
        }
        let required_size = out
            .len()
            .checked_add(avb_size_of)
            .ok_or_else(|| Error::bad_bootimg("repacked AVB image size overflow"))?;
        let footer_start = if required_size <= total_size {
            total_size - avb_size_of
        } else {
            required_size
                .div_ceil(page_size as usize)
                .checked_mul(page_size as usize)
                .and_then(|size| size.checked_sub(avb_size_of))
                .ok_or_else(|| Error::bad_bootimg("repacked AVB image padding overflow"))?
        };
        if new_end > footer_start {
            return Err(Error::bad_bootimg("AVB metadata overlaps footer"));
        }
        out.resize(footer_start, 0);
        footer.image_size = (new_image_size as u64).to_be_bytes();
        footer.vbmeta_offset = (new_offset as u64).to_be_bytes();
        out.extend_from_slice(bytemuck::bytes_of(&footer));
    }

    write_file(out_boot_path, &out)?;
    logi!("Repack completed: {}", out_boot_path.display());
    Ok(())
}

pub fn patch_bootimg(
    bootimg_path: &Path,
    kpimg_path: &Path,
    out_boot_path: &Path,
    superkey: &str,
    root_key: bool,
    additional: &[String],
    extras: Vec<crate::patch::ExtraConfig>,
) -> Result<()> {
    kptools_base::log::set_log_enable(true);
    logi!("patch boot image: {}", bootimg_path.display());
    if superkey.is_empty() && !root_key {
        return Err(Error::invalid_arg("empty superkey"));
    }

    let bootimg = kptools_base::io::read_file(bootimg_path)?;
    let hdr_size = core::mem::size_of::<BootImgHdr>();
    if bootimg.len() < hdr_size {
        return Err(Error::bad_bootimg("truncated boot image"));
    }
    let hdr: BootImgHdr = *bytemuck::from_bytes(&bootimg[..hdr_size]);
    if hdr.magic != *BOOT_MAGIC {
        return Err(Error::bad_bootimg("invalid boot image magic"));
    }

    let page_size = hdr.page_size;
    let header_ver = hdr.unused[0];
    let kernel_offset = if (3..=10).contains(&header_ver) {
        PAGE_SIZE_DEFAULT
    } else {
        page_size
    };
    let kernel_size = hdr.kernel_size as usize;
    logi!("Kernel size: {kernel_size}, Header Version: {header_ver}, Offset: {kernel_offset}");
    let start = kernel_offset as usize;
    let end = start
        .checked_add(kernel_size)
        .ok_or_else(|| Error::bad_bootimg("kernel offset + size overflow"))?;
    if end > bootimg.len() {
        return Err(Error::bad_bootimg("kernel section past file end"));
    }

    let raw = auto_depress_to_mem(&bootimg[start..end])?;
    let patched = crate::patch::patch_update_img_buf(
        &raw, kpimg_path, superkey, root_key, additional, extras,
    )?;
    repack_bootimg_mem(bootimg_path, &patched, out_boot_path)
}

fn sec_slice(buf: &[u8], off: u32, size: u32) -> &[u8] {
    let off = off as usize;
    let size = size as usize;
    if off >= buf.len() {
        return &[];
    }
    let end = (off + size).min(buf.len());
    &buf[off..end]
}

/// Feed `size` bytes of `slice` into the digest, zero-padding when
/// `slice` is short. Matches upstream's "slice pointer + declared
/// size, trust the declared size" semantics when hashing sections
/// that straddle the trimmed tail of `rest_buf`.
fn update_with_rest_dyn(d: &mut dyn digest::DynDigest, slice: &[u8], size: usize) {
    if slice.len() >= size {
        d.update(&slice[..size]);
    } else {
        d.update(slice);
        let pad = vec![0u8; size - slice.len()];
        d.update(&pad);
    }
}

pub fn calculate_sha1(path: &Path) -> Result<[u8; 20]> {
    use sha1::{Digest, Sha1};
    let mut f = File::open(path).map_err(Error::Io)?;
    let mut ctx = Sha1::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(Error::Io)?;
        if n == 0 {
            break;
        }
        ctx.update(&buf[..n]);
    }
    let out = ctx.finalize();
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&out);
    Ok(arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn raw_boot_image(kernel_size: usize, tail: &[u8]) -> Vec<u8> {
        let mut hdr = BootImgHdr::zeroed();
        hdr.magic = *BOOT_MAGIC;
        hdr.kernel_size = kernel_size as u32;
        hdr.page_size = PAGE_SIZE_DEFAULT;
        let rest_start = PAGE_SIZE_DEFAULT as usize
            + kernel_size.div_ceil(PAGE_SIZE_DEFAULT as usize) * PAGE_SIZE_DEFAULT as usize;
        let mut image = vec![0u8; rest_start];
        image[..core::mem::size_of::<BootImgHdr>()].copy_from_slice(bytemuck::bytes_of(&hdr));
        image[PAGE_SIZE_DEFAULT as usize..PAGE_SIZE_DEFAULT as usize + kernel_size].fill(b'K');
        image.extend_from_slice(tail);
        image
    }

    fn avb_boot_image(kernel_size: usize) -> (Vec<u8>, usize) {
        let rest_start = PAGE_SIZE_DEFAULT as usize
            + kernel_size.div_ceil(PAGE_SIZE_DEFAULT as usize) * PAGE_SIZE_DEFAULT as usize;
        let mut tail = vec![0x5a; 512];
        tail[8..12].copy_from_slice(b"AVB0"); // Decoy before the footer-selected blob.
        tail[128..132].copy_from_slice(b"AVB0");
        tail[400..404].copy_from_slice(b"AVB0"); // Decoy after it, which a last-match scan would choose.
        let mut footer = AvbFooter::zeroed();
        footer.magic = *b"AVBf";
        footer.version = 1u32.to_be_bytes();
        footer.reserved0 = [0xa5; 4];
        footer.reserved1 = [0x5a; 28];
        footer.image_size = (rest_start as u64).to_be_bytes();
        footer.vbmeta_offset = ((rest_start + 128) as u64).to_be_bytes();
        footer.vbmeta_size = 256u64.to_be_bytes();
        tail.extend_from_slice(bytemuck::bytes_of(&footer));
        (raw_boot_image(kernel_size, &tail), rest_start)
    }

    fn repack_fixture(image: &[u8], kernel: &[u8]) -> Result<Vec<u8>> {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("in.img");
        let output = dir.path().join("out.img");
        std::fs::write(&input, image).unwrap();
        repack_bootimg_mem(&input, kernel, &output)?;
        Ok(std::fs::read(output).unwrap())
    }

    #[test]
    fn avb_footer_tracks_padded_kernel_delta_and_selected_blob() {
        for (old_size, new_size) in [(4usize, 5000usize), (5000, 4), (4, 4)] {
            let (image, old_rest) = avb_boot_image(old_size);
            let new_rest = PAGE_SIZE_DEFAULT as usize
                + new_size.div_ceil(PAGE_SIZE_DEFAULT as usize) * PAGE_SIZE_DEFAULT as usize;
            let output = repack_fixture(&image, &vec![b'N'; new_size]).unwrap();
            let footer: AvbFooter =
                *bytemuck::from_bytes(&output[output.len() - AVB_FOOTER_SIZE..]);
            assert_eq!(footer.magic, *b"AVBf");
            assert_eq!(u64::from_be_bytes(footer.image_size), new_rest as u64);
            assert_eq!(
                u64::from_be_bytes(footer.vbmeta_offset),
                (new_rest + 128) as u64
            );
            assert_eq!(u64::from_be_bytes(footer.vbmeta_size), 256);
            assert_eq!(footer.reserved0, [0xa5; 4]);
            assert_eq!(footer.reserved1, [0x5a; 28]);
            assert_eq!(
                &output[new_rest..new_rest + 512],
                &image[old_rest..old_rest + 512]
            );
            assert_eq!(
                &output[new_rest + 128..new_rest + 384],
                &image[old_rest + 128..old_rest + 384]
            );
        }
    }

    #[test]
    fn avb_zero_slack_absorbs_growth_without_trimming_zero_metadata() {
        let (mut image, old_rest) = avb_boot_image(4);
        image[old_rest + 132..old_rest + 384].fill(0);
        image[old_rest + 384..old_rest + 512].fill(0);
        let old_footer = image.len() - AVB_FOOTER_SIZE;
        image.splice(old_footer..old_footer, vec![0; 8192]);
        let output = repack_fixture(&image, &vec![b'N'; 5000]).unwrap();
        let new_rest = old_rest + PAGE_SIZE_DEFAULT as usize;
        assert_eq!(output.len(), image.len());
        assert_eq!(
            &output[new_rest + 128..new_rest + 384],
            &image[old_rest + 128..old_rest + 384]
        );
        let footer: AvbFooter = *bytemuck::from_bytes(&output[output.len() - AVB_FOOTER_SIZE..]);
        assert_eq!(
            u64::from_be_bytes(footer.vbmeta_offset),
            (new_rest + 128) as u64
        );

        let large = repack_fixture(&image, &vec![b'N'; 20000]).unwrap();
        assert!(large.len() > image.len());
        assert_eq!(large.len() % PAGE_SIZE_DEFAULT as usize, 0);
    }

    #[test]
    fn malformed_avb_keeps_existing_output_untouched() {
        let (image, rest) = avb_boot_image(4);
        let footer = image.len() - AVB_FOOTER_SIZE;
        type Mutation = Box<dyn Fn(&mut Vec<u8>)>;
        let mutations: Vec<Mutation> = vec![
            Box::new(move |v| v[footer + 4..footer + 8].copy_from_slice(&2u32.to_be_bytes())),
            Box::new(move |v| {
                v[footer + 12..footer + 20].copy_from_slice(&((rest - 1) as u64).to_be_bytes())
            }),
            Box::new(move |v| v[footer + 20..footer + 28].copy_from_slice(&u64::MAX.to_be_bytes())),
            Box::new(move |v| v[footer + 28..footer + 36].copy_from_slice(&u64::MAX.to_be_bytes())),
            Box::new(move |v| v[footer + 28..footer + 36].copy_from_slice(&255u64.to_be_bytes())),
            Box::new(move |v| v[rest + 128..rest + 132].copy_from_slice(b"NOPE")),
        ];
        for mutate in mutations {
            let dir = tempfile::tempdir().unwrap();
            let input = dir.path().join("in.img");
            let output = dir.path().join("out.img");
            let mut bad = image.clone();
            mutate(&mut bad);
            std::fs::write(&input, bad).unwrap();
            std::fs::write(&output, b"unchanged").unwrap();
            assert!(repack_bootimg_mem(&input, b"NEWS", &output).is_err());
            assert_eq!(std::fs::read(&output).unwrap(), b"unchanged");
        }
    }

    #[test]
    fn non_avb_short_and_long_tails_remain_opaque() {
        for tail in [b"abc".as_slice(), &[0x7f; 80]] {
            let image = raw_boot_image(4, tail);
            let output = repack_fixture(&image, b"NEWS").unwrap();
            assert_eq!(&output[PAGE_SIZE_DEFAULT as usize * 2..], tail);
        }
    }

    #[test]
    fn detect_compress_method_covers_known_magics() {
        assert_eq!(detect_compress_method(&[0x1f, 0x8b, 0x08, 0x00]), 1);
        assert_eq!(detect_compress_method(&[0x04, 0x22, 0x4d, 0x18]), 2);
        assert_eq!(detect_compress_method(&[0x02, 0x21, 0x4c, 0x18]), 3);
        assert_eq!(detect_compress_method(&[0x28, 0xb5, 0x2f, 0xfd]), 4);
        assert_eq!(detect_compress_method(&[0x42, 0x5a, 0x68, 0x39]), 5);
        assert_eq!(detect_compress_method(&[0xfd, 0x37, 0x7a, 0x58]), 6);
        assert_eq!(detect_compress_method(&[0x5d, 0x00, 0x00, 0x00]), 7);
        assert_eq!(detect_compress_method(&[0xde, 0xad, 0xbe, 0xef]), 0);
    }

    #[test]
    fn gzip_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = b"hello kptools-rs";
        let gz = compress_gzip(plain).unwrap();
        assert_eq!(detect_compress_method(&gz[..4]), 1);
        let out = dir.path().join("out.bin");
        decompress_gzip_to(&gz, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
        assert_eq!(auto_depress_to_mem(&gz).unwrap(), plain);
    }

    #[test]
    fn is_bootimg_checks_android_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boot.img");
        std::fs::write(&path, b"ANDROID!tail").unwrap();
        assert!(is_bootimg(&path));
        std::fs::write(&path, b"NOTBOOT!").unwrap();
        assert!(!is_bootimg(&path));
    }

    #[test]
    fn repack_mem_writes_footer_when_kernel_fills_output() {
        let dir = tempfile::tempdir().unwrap();
        let input = dir.path().join("boot.img");
        let output = dir.path().join("new-boot.img");
        let mut hdr = BootImgHdr::zeroed();
        hdr.magic = *BOOT_MAGIC;
        hdr.kernel_size = 4;
        hdr.page_size = PAGE_SIZE_DEFAULT;
        let footer = AvbFooter::zeroed();
        let footer_size = core::mem::size_of::<AvbFooter>();
        let mut image = vec![0u8; PAGE_SIZE_DEFAULT as usize * 2 + footer_size];
        image[..core::mem::size_of::<BootImgHdr>()].copy_from_slice(bytemuck::bytes_of(&hdr));
        image[PAGE_SIZE_DEFAULT as usize..PAGE_SIZE_DEFAULT as usize + 4].copy_from_slice(b"KERN");
        let footer_offset = image.len() - footer_size;
        image[footer_offset..].copy_from_slice(bytemuck::bytes_of(&footer));
        std::fs::write(&input, image).unwrap();

        repack_bootimg_mem(&input, b"NEWS", &output).unwrap();
        let repacked = std::fs::read(output).unwrap();
        assert_eq!(repacked.len(), PAGE_SIZE_DEFAULT as usize * 2 + footer_size);
        assert_eq!(
            &repacked[PAGE_SIZE_DEFAULT as usize..PAGE_SIZE_DEFAULT as usize + 4],
            b"NEWS"
        );
        assert_eq!(
            &repacked[repacked.len() - footer_size..],
            bytemuck::bytes_of(&footer)
        );
    }

    #[test]
    fn compress_raw_deflate_produces_output() {
        let plain = b"raw deflate payload for kptools";
        let out = compress_raw_deflate(plain).unwrap();
        assert!(!out.is_empty());
        assert_ne!(&out[..2.min(out.len())], &[0x1f, 0x8b]);
    }

    #[test]
    fn lz4_frame_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = vec![0xABu8; 8192];
        let c = compress_lz4_frame(&plain).unwrap();
        assert_eq!(detect_compress_method(&c[..4]), 2);
        let out = dir.path().join("o.bin");
        decompress_lz4_frame_to(&c, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
    }

    #[test]
    fn lz4_legacy_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = vec![0xCDu8; 65_536];
        let c = compress_lz4_legacy(&plain).unwrap();
        assert_eq!(detect_compress_method(&c[..4]), 3);
        let out = dir.path().join("o.bin");
        decompress_lz4_legacy_to(&c, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
    }

    #[test]
    fn bzip2_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let plain = b"kptools-rs bz2 test";
        let c = compress_bzip2(plain).unwrap();
        assert_eq!(detect_compress_method(&c[..4]), 5);
        let out = dir.path().join("o.bin");
        decompress_bzip2_to(&c, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
    }

    #[test]
    fn sha1_matches_known_vector() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("e");
        std::fs::write(&p, b"").unwrap();
        let h = calculate_sha1(&p).unwrap();
        let expect = [
            0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55, 0xbf, 0xef, 0x95, 0x60,
            0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09,
        ];
        assert_eq!(h, expect);
    }

    #[test]
    fn is_sha256_picks_format() {
        // Upstream deliberately lets an all-zero first six words override the
        // final two words.
        let id = [0u32; 8];
        assert_eq!(is_sha256(&id), 1);
        let mut id_tail = [0u32; 8];
        id_tail[7] = 1;
        assert_eq!(is_sha256(&id_tail), 1);
        let mut id = [0u32; 8];
        id[0] = 1;
        assert_eq!(is_sha256(&id), 0);
        let mut id = [0u32; 8];
        id[0] = 1;
        id[7] = 1;
        assert_eq!(is_sha256(&id), 2);
    }
}
