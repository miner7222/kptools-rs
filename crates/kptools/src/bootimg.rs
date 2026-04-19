//! AOSP boot image unpack / repack.
//!
//! Port of upstream `tools/bootimg.{c,h}`. The upstream kptools
//! binary ships its own boot-image handler because the patch
//! pipeline needs to slot a recompressed kernel back in place
//! with the same compression the original used, preserve any
//! appended DTB, rebuild the SHA-1 / SHA-256 id, and touch up
//! the AVB footer `data_size` field.
//!
//! Scope:
//!
//! - [`extract_kernel`] — upstream `extract_kernel`. Reads
//!   `boot.img`, slices the kernel section at `page_size`, auto-
//!   decompresses to `./kernel`.
//! - [`repack_bootimg`] — upstream `repack_bootimg`. Re-compresses
//!   the provided kernel to match the source's compression, writes
//!   a new boot image with updated sizes + id digest + AVB footer.
//! - [`calculate_sha1`] — upstream `cacluate_sha1` (typo intentional
//!   to match the CLI subcommand name).
//! - [`detect_compress_method`] — magic-byte sniffer. `0 raw,
//!   1 gzip, 2 lz4-frame, 3 lz4-legacy, 4 zstd (unsupported),
//!   5 bzip2, 6 xz, 7 lzma`.
//! - [`auto_depress`] — dispatch on the sniffed method.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use bytemuck::{Pod, Zeroable};
use kptools_base::{Error, Result, io::write_file, logi, logw};

pub const BOOT_MAGIC: &[u8; 8] = b"ANDROID!";
pub const PAGE_SIZE_DEFAULT: u32 = 4096;
pub const LZ4_MAGIC: u32 = 0x184c_2102;
pub const LZ4_BLOCK_SIZE: usize = 0x0080_0000;
pub const AVB_FOOTER_SIZE: usize = 64;

// ---------------------------------------------------------------------------
// Struct mirrors
// ---------------------------------------------------------------------------

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
    pub reverse: [u32; 16],
    pub magic: u32,       // "AVBf"
    pub version: u32,     // 0x00000001
    pub reserved1: u64,   // 0
    pub data_size1: u32,  // little-endian host view of the be64 avbtool writes
    pub data_size_1: u32, // spare copy
    pub data_size2: u32,
    pub data_size_2: u32,
    pub unknown_field: u64, // 0x940
    pub padding: [u8; 24],
}

// ---------------------------------------------------------------------------
// SHA selection heuristic (upstream `is_sha256`)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Compression method detect
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Codec helpers
// ---------------------------------------------------------------------------

fn decompress_gzip_to(data: &[u8], out_path: &Path) -> Result<()> {
    use flate2::read::MultiGzDecoder;
    let mut dec = MultiGzDecoder::new(data);
    let mut out = File::create(out_path).map_err(Error::Io)?;
    std::io::copy(&mut dec, &mut out).map_err(|e| Error::decompress(e.to_string()))?;
    Ok(())
}

fn compress_gzip(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::Compression;
    use flate2::write::GzEncoder;
    let mut enc = GzEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_lz4_frame_to(data: &[u8], out_path: &Path) -> Result<()> {
    let mut dec = lz4::Decoder::new(data).map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf).map_err(|e| Error::decompress(e.to_string()))?;
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
    let mut block_out = vec![0u8; LZ4_BLOCK_SIZE];
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

/// Compress to LZ4 legacy block format — matches upstream
/// `compress_lz4_le`.
fn compress_lz4_legacy(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(&LZ4_MAGIC.to_le_bytes());
    for chunk in data.chunks(LZ4_BLOCK_SIZE) {
        // High-compression block encode. lz4_flex's high-compression
        // block path is not directly exposed as `compress_hc`, so we
        // use the `lz4` crate's block API which supports HC level.
        let mut compressed =
            lz4::block::compress(chunk, Some(lz4::block::CompressionMode::HIGHCOMPRESSION(12)), false)
                .map_err(|e| Error::compress(e.to_string()))?;
        // `lz4::block::compress` with `prepend_size=false` returns
        // raw bytes. We prepend our own length.
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
    dec.read_to_end(&mut buf).map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_bzip2(data: &[u8]) -> Result<Vec<u8>> {
    use bzip2::Compression;
    use bzip2::write::BzEncoder;
    let mut enc = BzEncoder::new(Vec::new(), Compression::new(9));
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_xz_to(data: &[u8], out_path: &Path) -> Result<()> {
    use lzma_rust2::XzReader;
    let mut dec = XzReader::new(data, true);
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf).map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_xz(data: &[u8]) -> Result<Vec<u8>> {
    use lzma_rust2::{CheckType, XzOptions, XzWriter};
    let mut opt = XzOptions::with_preset(9);
    opt.set_check_sum_type(CheckType::Crc32);
    let mut enc = XzWriter::new(Vec::new(), opt)
        .map_err(|e| Error::compress(e.to_string()))?;
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_lzma_to(data: &[u8], out_path: &Path) -> Result<()> {
    use lzma_rust2::LzmaReader;
    let mut dec = LzmaReader::new_mem_limit(data, u32::MAX, None)
        .map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf).map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_lzma(data: &[u8]) -> Result<Vec<u8>> {
    use lzma_rust2::{LzmaOptions, LzmaWriter};
    let opt = LzmaOptions::with_preset(9);
    let mut enc = LzmaWriter::new_use_header(Vec::new(), &opt, None)
        .map_err(|e| Error::compress(e.to_string()))?;
    enc.write_all(data).map_err(Error::Io)?;
    enc.finish().map_err(|e| Error::compress(e.to_string()))
}

fn decompress_zstd_to(data: &[u8], out_path: &Path) -> Result<()> {
    let mut dec = zstd::stream::read::Decoder::new(data)
        .map_err(|e| Error::decompress(e.to_string()))?;
    let mut buf = Vec::with_capacity(64 * 1024 * 1024);
    dec.read_to_end(&mut buf).map_err(|e| Error::decompress(e.to_string()))?;
    write_file(out_path, &buf)
}

fn compress_zstd(data: &[u8]) -> Result<Vec<u8>> {
    zstd::stream::encode_all(data, 22).map_err(|e| Error::compress(e.to_string()))
}

// ---------------------------------------------------------------------------
// auto_depress
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// extract_kernel
// ---------------------------------------------------------------------------

/// Extract the kernel section from an AOSP boot image, auto-
/// decompressing it, and write the result to `out_path`. Library-
/// friendly replacement for upstream `extract_kernel(bootimg_path)`
/// which hardcoded the output path to `./kernel`.
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
    // Upstream's offset-selection mirror:
    //   kernel_offset = page_size
    //   if header_ver >= 3 → 4096
    //   if header_ver > 10 → page_size (again; it's a sentinel for
    //   "extracted_size encoded in unused[0]", not a real version)
    let mut kernel_offset = page_size;
    if header_ver >= 3 {
        kernel_offset = 4096;
    }
    if header_ver > 10 {
        kernel_offset = page_size;
    }
    logi!(
        "Kernel size: {kernel_size}, Header Version: {header_ver}, Offset: {kernel_offset}"
    );

    let start = kernel_offset as usize;
    let end = start.checked_add(kernel_size).ok_or_else(|| {
        Error::bad_bootimg("kernel offset + size overflow")
    })?;
    if end > data.len() {
        return Err(Error::bad_bootimg("kernel section past file end"));
    }
    let kernel_data = &data[start..end];
    auto_depress(kernel_data, out_path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// repack_bootimg
// ---------------------------------------------------------------------------

/// Append-DTB detection scan: look for the flattened device tree
/// magic `0xd00dfeed` followed by a sane `totalsize` + a
/// `FDT_BEGIN_NODE` tag at `off_dt_struct`.
fn find_dtb_offset(buf: &[u8]) -> Option<usize> {
    const FDT_HEADER: usize = 40;
    const DTB_MAGIC: [u8; 4] = [0xd0, 0x0d, 0xfe, 0xed];
    let mut pos = 0usize;
    while pos + FDT_HEADER < buf.len() {
        let Some(rel) = buf[pos..].windows(4).position(|w| w == DTB_MAGIC) else {
            return None;
        };
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
            let tag =
                u32::from_be_bytes(buf[cand + off_dt_struct..cand + off_dt_struct + 4].try_into().unwrap());
            if tag == 0x0000_0001 {
                return Some(cand);
            }
        }
        pos = cand + 4;
    }
    None
}

fn align_up(v: u32, a: u32) -> u32 {
    if a == 0 { v } else { ((v + a - 1) / a) * a }
}

/// Port of upstream `repack_bootimg`. Pulls the new kernel from
/// disk, recompresses it in the same format as the original (or
/// GZIP when the original was XZ / LZMA — upstream's fallback),
/// rebuilds the header's `kernel_size`, refreshes the id digest,
/// and patches the AVB footer `data_size` field.
pub fn repack_bootimg(
    orig_boot_path: &Path,
    new_kernel_path: &Path,
    out_boot_path: &Path,
) -> Result<()> {
    logi!("Starting automatic repack...");

    let data = kptools_base::io::read_file(orig_boot_path)?;
    if data.len() < core::mem::size_of::<BootImgHdr>() + AVB_FOOTER_SIZE {
        return Err(Error::bad_bootimg("boot image truncated"));
    }
    let hdr_size = core::mem::size_of::<BootImgHdr>();
    let mut hdr: BootImgHdr = *bytemuck::from_bytes(&data[..hdr_size]);
    if hdr.magic != *BOOT_MAGIC {
        return Err(Error::bad_bootimg("not an ANDROID! boot image"));
    }
    let total_size = data.len();
    let avb_size_of = core::mem::size_of::<AvbFooter>();
    let mut avb: AvbFooter = *bytemuck::from_bytes(&data[total_size - avb_size_of..]);

    let mut header_ver = hdr.unused[0];
    let mut extracted_size: u32 = 0;
    if header_ver > 10 {
        extracted_size = header_ver;
        header_ver = 0;
    }
    let page_size = if header_ver >= 3 { 4096 } else { hdr.page_size };
    let fmt_size = if header_ver >= 3 {
        hdr.kernel_addr
    } else {
        hdr.ramdisk_size
    };
    logi!(
        "Header Version: {header_ver}, Page Size: {page_size}, fmt_size: {fmt_size}"
    );

    let old_k_start = page_size as usize;
    let old_k_end = old_k_start + hdr.kernel_size as usize;
    if old_k_end > data.len() {
        return Err(Error::bad_bootimg("kernel section past file end"));
    }
    let old_k = &data[old_k_start..old_k_end];
    let method = detect_compress_method(&old_k[..4.min(old_k.len())]);

    // Appended DTB (v1 / v2 only).
    let mut extracted_dtb: Vec<u8> = Vec::new();
    if header_ver < 3 {
        if let Some(dtb_off) = find_dtb_offset(old_k) {
            extracted_dtb.extend_from_slice(&old_k[dtb_off..]);
            logi!("Detected DTB appended to kernel. Size: {}", extracted_dtb.len());
        }
    }

    let raw_k = kptools_base::io::read_file(new_kernel_path)?;
    let raw_k_size = raw_k.len();

    // Recompress to match the source method. XZ / LZMA fall back
    // to GZIP (upstream behaviour).
    let (final_k, final_method) = match method {
        1 => {
            logi!("Compressing new kernel with GZIP...");
            (compress_gzip(&raw_k)?, 1)
        }
        2 => {
            logi!("Compressing new kernel with LZ4...");
            (compress_lz4_frame(&raw_k)?, 2)
        }
        3 => {
            logi!("Compressing new kernel with LZ4 Legacy...");
            (compress_lz4_legacy(&raw_k)?, 3)
        }
        4 => {
            logi!("Compressing new kernel with ZSTD level 22...");
            (compress_zstd(&raw_k)?, 4)
        }
        5 => {
            logi!("Compressing new kernel with BZIP2 level 9...");
            (compress_bzip2(&raw_k)?, 5)
        }
        6 => {
            logi!("Compressing new kernel with XZ level 9 (CRC32)...");
            (compress_xz(&raw_k)?, 6)
        }
        7 => {
            logi!("Compressing new kernel with Legacy LZMA level 9...");
            (compress_lzma(&raw_k)?, 7)
        }
        _ => (raw_k.clone(), 0),
    };
    let _ = final_method;
    let final_k_size = final_k.len() as u32;
    logi!("Final kernel size after compression (if applied): {final_k_size} bytes");

    let dtb_size = extracted_dtb.len() as u32;
    let old_k_aligned = align_up(hdr.kernel_size, page_size);
    let rest_data_offset = page_size as usize + old_k_aligned as usize;
    let mut rest_data_size = total_size.saturating_sub(rest_data_offset);
    hdr.kernel_size = final_k_size + dtb_size;
    let mut checksum_aligned = align_up(fmt_size, page_size);

    // Upstream copies `rest_data_size - sizeof(avb)` bytes from the
    // source right after the kernel, then trims trailing zeros. The
    // AVB footer is written separately at the end.
    let mut rest_buf: Vec<u8> = Vec::new();
    if rest_data_size > 0 {
        let end_minus_avb = total_size - avb_size_of;
        let raw_rest = &data[rest_data_offset..end_minus_avb];
        let rest_data_size_no_avb = raw_rest.len();
        let mut tail_off = rest_data_size_no_avb;
        while tail_off > 0 && raw_rest[tail_off - 1] == 0 {
            tail_off -= 1;
        }
        // The "overload" heuristic upstream flips to emit the whole
        // block when the significant region covers more than 2/3 of
        // the space. Mirror that.
        if tail_off > rest_data_size_no_avb / 3 * 2 {
            logi!(
                "warning: rest data large. Rest size: {rest_data_size_no_avb}, significant: {tail_off}"
            );
            rest_buf = raw_rest.to_vec();
            rest_data_size = tail_off + avb_size_of;
        } else {
            rest_buf = raw_rest[..tail_off].to_vec();
            logi!(
                "Rest data size: {rest_data_size_no_avb}, significant: {tail_off}"
            );
            rest_data_size = tail_off;
        }
    }

    // Recompute the id digest. Upstream gates on
    // `use_sha256 != 1 || header_ver <= 3` — the "1" case skips the
    // hash rewrite for modern signed images where the bootloader
    // trusts AVB alone. We drive both digests through `digest::DynDigest`
    // so the update sequence stays identical between SHA-1 and SHA-256.
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
        update_with_rest_dyn(&mut *dyn_ctx, &rest_buf, fmt_size as usize);
        dyn_ctx.update(&fmt_size.to_le_bytes());
        update_with_rest_dyn(
            &mut *dyn_ctx,
            sec_slice(&rest_buf, checksum_aligned, hdr.second_size),
            hdr.second_size as usize,
        );
        dyn_ctx.update(&hdr.second_size.to_le_bytes());
        if hdr.second_size > 0 {
            checksum_aligned += align_up(hdr.second_size, page_size);
        }
        if extracted_size != 0 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(&rest_buf, checksum_aligned, page_size),
                page_size as usize,
            );
            dyn_ctx.update(&extracted_size.to_le_bytes());
            checksum_aligned += align_up(extracted_size, page_size);
        }
        if header_ver == 1 || header_ver == 2 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(&rest_buf, checksum_aligned, hdr.recovery_dtbo_size),
                hdr.recovery_dtbo_size as usize,
            );
            dyn_ctx.update(&hdr.recovery_dtbo_size.to_le_bytes());
            checksum_aligned += align_up(hdr.recovery_dtbo_size, page_size);
        }
        if header_ver == 2 {
            update_with_rest_dyn(
                &mut *dyn_ctx,
                sec_slice(&rest_buf, checksum_aligned, hdr.dtb_size),
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

    // -- Assemble output file ---------------------------------------
    let mut out = Vec::with_capacity(total_size);
    // 1) Header + zero-pad to page boundary.
    out.extend_from_slice(bytemuck::bytes_of(&hdr));
    out.resize(page_size as usize, 0);
    // 2) Kernel + optional DTB tail.
    out.extend_from_slice(&final_k);
    if !extracted_dtb.is_empty() {
        out.extend_from_slice(&extracted_dtb);
    }
    // 3) Pad kernel block to page.
    let new_k_total_aligned = align_up(hdr.kernel_size, page_size) as usize;
    let k_end = page_size as usize + new_k_total_aligned;
    if out.len() < k_end {
        out.resize(k_end, 0);
    } else {
        out.truncate(k_end);
    }

    // 4) Walk `rest_buf` for the AVB0 signature so we can patch the
    //    AVB footer's `data_size{,_1,_2}` fields with the new size.
    let mut avb_sig: [u8; 19] = [
        0x41, 0x56, 0x42, 0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ];
    let mut rest_buf_local = rest_buf.clone();
    if !rest_buf_local.is_empty() {
        let mut last_avb: Option<usize> = None;
        for ver in [0x00u8, 0x01, 0x02] {
            avb_sig[18] = ver;
            let mut search = 0usize;
            while search + avb_sig.len() <= rest_buf_local.len() {
                let Some(rel) = rest_buf_local[search..]
                    .windows(avb_sig.len())
                    .position(|w| w == avb_sig)
                else {
                    break;
                };
                last_avb = Some(search + rel);
                search += rel + avb_sig.len();
            }
            if last_avb.is_some() {
                break;
            }
        }
        if let Some(avb_offset) = last_avb {
            let new_avb_size =
                page_size + avb_offset as u32 + new_k_total_aligned as u32;
            avb.data_size1 = new_avb_size.swap_bytes();
            avb.data_size2 = new_avb_size.swap_bytes();
        }
        // Write rest + footer, resizing the total length when the
        // significant region overflows the original frame.
        if rest_data_size > total_size.saturating_sub(page_size as usize + new_k_total_aligned) {
            let new_total = align_up(
                (page_size as usize + new_k_total_aligned + rest_data_size) as u32,
                page_size,
            ) as usize;
            let pad_len =
                new_total - page_size as usize - new_k_total_aligned - avb_size_of;
            out.extend_from_slice(&rest_buf_local[..pad_len.min(rest_buf_local.len())]);
            out.resize(page_size as usize + new_k_total_aligned + pad_len, 0);
            out.extend_from_slice(bytemuck::bytes_of(&avb));
        } else {
            out.extend_from_slice(&rest_buf_local);
        }
    }

    // 5) Final zero pad + append footer when we didn't already.
    if out.len() < total_size - avb_size_of {
        out.resize(total_size - avb_size_of, 0);
        out.extend_from_slice(bytemuck::bytes_of(&avb));
    }
    // 6) Truncate / extend to match the original file length.
    if out.len() < total_size {
        out.resize(total_size, 0);
    }

    write_file(out_boot_path, &out)?;
    logi!("Repack completed: {}", out_boot_path.display());
    Ok(())
}

fn sec_slice<'a>(buf: &'a [u8], off: u32, size: u32) -> &'a [u8] {
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

// ---------------------------------------------------------------------------
// cacluate_sha1 (upstream typo preserved on the CLI side; the API
// fn here uses the corrected spelling).
// ---------------------------------------------------------------------------

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
        // LZ4_MAGIC 0x184c2102 = bytes 02 21 4c 18 = legacy-detect.
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
        // detect_compress_method requires at least 4 bytes.
        assert_eq!(detect_compress_method(&c[..4]), 5);
        let out = dir.path().join("o.bin");
        decompress_bzip2_to(&c, &out).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), plain);
    }

    #[test]
    fn sha1_matches_known_vector() {
        // sha1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709
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
        // Upstream's first check short-circuits on `id[0..6] == 0`
        // regardless of id[6..8], so these two produce 1.
        let id = [0u32; 8];
        assert_eq!(is_sha256(&id), 1);
        let mut id_tail = [0u32; 8];
        id_tail[7] = 1;
        assert_eq!(is_sha256(&id_tail), 1);
        // id[0..6] any nonzero with id[6..8] == 0 → SHA-1.
        let mut id = [0u32; 8];
        id[0] = 1;
        assert_eq!(is_sha256(&id), 0);
        // id[0..6] any nonzero with id[6..8] nonzero → ambiguous (2).
        let mut id = [0u32; 8];
        id[0] = 1;
        id[7] = 1;
        assert_eq!(is_sha256(&id), 2);
    }
}
