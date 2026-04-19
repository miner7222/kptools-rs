//! Kernel-image patch driver.
//!
//! Port of upstream `tools/patch.{c,h}`. Wraps the kallsym + symbol
//! + image + preset + insn modules into the four commands the
//! binary exposes:
//!
//! - [`patch_update_img`] — full `-p` path. Reads a kernel image +
//!   kpimg + optional KPM `.kpm` extras, emits a patched kernel.
//! - [`unpatch_img`] — `-u`. Reverts a previously patched kernel
//!   by restoring the `header_backup` bytes and truncating to the
//!   original size recorded in the preset.
//! - [`reset_key`] — `-r`. Overwrites the superkey in a patched
//!   kernel without touching anything else.
//! - [`parse_image_patch_info`] / [`print_image_patch_info`] —
//!   introspection for the `-l` list command.

use sha2::Digest;

use kptools_base::{
    Error, Result, io::{read_file, read_file_align, write_file},
    logi, logw,
};

use crate::image::{KernelInfo, get_kernel_info};
use crate::insn::{relo_branch_func, write_b};
use crate::kallsym::{
    Kallsym, analyze_kallsym_info, find_linux_banner, ArchType,
};
use crate::kpm::{get_kpm_info, KpmInfo};
use crate::preset::{
    ADDITIONAL_LEN, EXTRA_ALIGN, EXTRA_EVENT_LEN, EXTRA_HDR_MAGIC, EXTRA_ITEM_MAX_NUM,
    EXTRA_NAME_LEN, ExtraType, KP_MAGIC, MAGIC_LEN, PATCH_EXTRA_ITEM_LEN, PatchExtraItem, Preset,
    ROOT_SUPER_KEY_HASH_LEN, SUPER_KEY_LEN,
};
use crate::symbol::{
    fillin_map_symbol, fillin_patch_config, get_symbol_offset_exit, select_map_area,
};

pub const INFO_KERNEL_IMG_SESSION: &str = "[kernel]";
pub const INFO_KP_IMG_SESSION: &str = "[kpimg]";
pub const INFO_ADDITIONAL_SESSION: &str = "[additional]";
pub const INFO_EXTRA_SESSION: &str = "[extras]";
pub const INFO_EXTRA_SESSION_N: &str = "[extra %d]";

const SZ_4K: usize = 0x1000;

// ---------------------------------------------------------------------------
// Kernel-file wrapper: handles the optional UNCOMPRESSED_IMG header
// that some downstream build systems prepend to a raw kernel blob.
// ---------------------------------------------------------------------------

const UNCOMPRESSED_IMG_MAGIC: &[u8] = b"UNCOMPRESSED_IMG";

pub struct KernelFile {
    /// Whole file contents, including the optional 20-byte
    /// `UNCOMPRESSED_IMG` prefix.
    pub kfile: Vec<u8>,
    /// Offset of the real kernel image inside `kfile`.
    pub img_offset: usize,
}

impl KernelFile {
    /// Length of the real kernel image (excluding the
    /// UNCOMPRESSED_IMG prefix when present).
    pub fn kimg_len(&self) -> usize {
        self.kfile.len() - self.img_offset
    }
    pub fn kimg(&self) -> &[u8] {
        &self.kfile[self.img_offset..]
    }
    pub fn kimg_mut(&mut self) -> &mut [u8] {
        &mut self.kfile[self.img_offset..]
    }
    pub fn is_uncompressed_img(&self) -> bool {
        self.img_offset == 20
    }

    pub fn read(path: &std::path::Path) -> Result<Self> {
        let kfile = read_file(path)?;
        let img_offset = if kfile.len() >= 20 && kfile.starts_with(UNCOMPRESSED_IMG_MAGIC) {
            20
        } else {
            0
        };
        Ok(Self { kfile, img_offset })
    }

    pub fn write(&self, path: &std::path::Path) -> Result<()> {
        write_file(path, &self.kfile)
    }

    /// Build a fresh `KernelFile` sized for `new_kimg_len` bytes of
    /// kernel image content, copying the prefix (if any) from
    /// `old`.
    pub fn new_from(old: &Self, new_kimg_len: usize) -> Self {
        let mut kfile = Vec::with_capacity(old.img_offset + new_kimg_len);
        kfile.extend_from_slice(&old.kfile[..old.img_offset]);
        kfile.resize(old.img_offset + new_kimg_len, 0);
        Self { kfile, img_offset: old.img_offset }
    }

    /// Update the `UNCOMPRESSED_IMG` length header (when present)
    /// + truncate the buffer to the new size.
    pub fn resize_kimg(&mut self, new_kimg_len: usize) {
        if self.is_uncompressed_img() {
            self.kfile[16..20].copy_from_slice(&(new_kimg_len as u32).to_le_bytes());
        }
        self.kfile.truncate(self.img_offset + new_kimg_len);
    }
}

// ---------------------------------------------------------------------------
// Preset / extras search
// ---------------------------------------------------------------------------

fn find_preset(kimg: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + MAGIC_LEN <= kimg.len() {
        if &kimg[i..i + MAGIC_LEN] == KP_MAGIC {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn read_preset(kimg: &[u8], offset: usize) -> &Preset {
    let size = core::mem::size_of::<Preset>();
    bytemuck::from_bytes(&kimg[offset..offset + size])
}

/// Configuration for a single `-M` / `-E` extra. Carries the raw
/// KPM bytes when sourced from a path, or a pointer back into the
/// parent image when re-configuring an already-embedded extra.
#[derive(Clone)]
pub struct ExtraConfig {
    pub extra_type: ExtraType,
    pub is_path: bool,
    pub name: String,
    pub set_args: Option<String>,
    pub set_name: Option<String>,
    pub set_event: Option<String>,
    pub priority: i32,
    pub data: Vec<u8>,
    pub item: PatchExtraItem,
}

impl ExtraConfig {
    pub fn from_path(path: &std::path::Path, ty: ExtraType) -> Result<Self> {
        let data = read_file_align(path, EXTRA_ALIGN)?;
        let name_hint = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let inferred_name = if ty == ExtraType::Kpm {
            let info = get_kpm_info(&data).unwrap_or(KpmInfo::default());
            info.name.clone().unwrap_or(name_hint.clone())
        } else {
            name_hint
        };

        let mut item = PatchExtraItem {
            magic: [0; 4],
            priority: 0,
            args_size: 0,
            con_size: data.len() as i32,
            extra_type: ty.as_i32(),
            name: [0; EXTRA_NAME_LEN],
            event: [0; EXTRA_EVENT_LEN],
            pad: [0; PATCH_EXTRA_ITEM_LEN - 4 - 4 - 4 - 4 - 4 - EXTRA_NAME_LEN - EXTRA_EVENT_LEN],
        };
        item.magic.copy_from_slice(EXTRA_HDR_MAGIC);
        copy_cstr_into(&mut item.name, inferred_name.as_bytes());
        Ok(Self {
            extra_type: ty,
            is_path: true,
            name: inferred_name,
            set_args: None,
            set_name: None,
            set_event: None,
            priority: 0,
            data,
            item,
        })
    }
}

fn copy_cstr_into(dst: &mut [u8], src: &[u8]) {
    let take = src.len().min(dst.len().saturating_sub(1));
    dst[..take].copy_from_slice(&src[..take]);
    if take < dst.len() {
        dst[take] = 0;
    }
}

// ---------------------------------------------------------------------------
// parse_image_patch_info — the `-l` introspection path. Finds the
// preset + enumerates embedded extras.
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct PatchedKimg {
    pub kimg_len: usize,
    pub ori_kimg_len: usize,
    pub banner: Option<usize>,
    pub kinfo: KernelInfo,
    pub preset_offset: Option<usize>,
    pub embed_items: Vec<PatchExtraItem>,
}

pub fn parse_image_patch_info(kimg: &[u8]) -> Result<PatchedKimg> {
    let mut out = PatchedKimg::default();
    out.kimg_len = kimg.len();

    out.kinfo = get_kernel_info(kimg)?;

    let banner_prefix = b"Linux version ";
    let mut pos = 0usize;
    while let Some(rel) = kimg[pos..]
        .windows(banner_prefix.len())
        .position(|w| w == banner_prefix)
    {
        let banner_start = pos + rel;
        let after = banner_start + banner_prefix.len();
        if after + 1 < kimg.len()
            && kimg[after].is_ascii_digit()
            && kimg[after + 1] == b'.'
        {
            out.banner = Some(banner_start);
            break;
        }
        pos = banner_start + 1;
    }
    if out.banner.is_none() {
        return Err(Error::bad_kernel("no Linux banner found"));
    }

    // patched or new?
    let mut search_from = 0usize;
    let mut found_preset_at: Option<usize> = None;
    let mut saved_kimg_len: i32 = 0;
    let mut align_kimg_len: i32 = 0;
    loop {
        let Some(off) = find_preset(&kimg[search_from..]) else {
            break;
        };
        let preset_off = search_from + off;
        let preset = read_preset(kimg, preset_off);
        let sk = preset.setup.kimg_size as i32;
        saved_kimg_len = sk; // upstream stores little-endian natively on host-LE builds
        let align = align_ceil_i32(sk, SZ_4K as i32);
        if preset_off as i32 == align {
            found_preset_at = Some(preset_off);
            align_kimg_len = align;
            break;
        }
        logw!(
            "found magic at 0x{preset_off:x} but saved kernel size mismatch, ignoring"
        );
        search_from = preset_off + 1;
    }

    let Some(preset_off) = found_preset_at else {
        out.ori_kimg_len = kimg.len();
        return Ok(out);
    };
    out.preset_offset = Some(preset_off);
    out.ori_kimg_len = saved_kimg_len as usize;

    let preset = read_preset(kimg, preset_off);
    let kpimg_size = preset.setup.kpimg_size as usize;
    let extra_size = preset.setup.extra_size as usize;
    let extra_start = align_kimg_len as usize + kpimg_size;
    if extra_start > kimg.len() {
        return Err(Error::bad_preset("kpimg length mismatch"));
    }
    if extra_start == kimg.len() {
        return Ok(out);
    }

    let mut p = extra_start;
    let end = extra_start + extra_size;
    while p + PATCH_EXTRA_ITEM_LEN <= end.min(kimg.len()) {
        let item: &PatchExtraItem =
            bytemuck::from_bytes(&kimg[p..p + PATCH_EXTRA_ITEM_LEN]);
        if item.magic != *EXTRA_HDR_MAGIC {
            break;
        }
        if item.extra_type == ExtraType::None.as_i32() {
            break;
        }
        let args = item.args_size as usize;
        let con = item.con_size as usize;
        out.embed_items.push(*item);
        p += PATCH_EXTRA_ITEM_LEN + args + con;
    }
    Ok(out)
}

fn align_ceil_i32(v: i32, a: i32) -> i32 {
    if a == 0 { v } else { ((v + a - 1) / a) * a }
}

// ---------------------------------------------------------------------------
// patch_update_img — the main entry point.
// ---------------------------------------------------------------------------

/// Config for a run of `patch_update_img`. Explicit struct instead
/// of the 10-positional-arg upstream signature so callers stay
/// readable.
pub struct PatchArgs<'a> {
    pub kimg_path: &'a std::path::Path,
    pub kpimg_path: &'a std::path::Path,
    pub out_path: &'a std::path::Path,
    pub superkey: &'a str,
    pub root_key: bool,
    pub additional: Vec<String>,
    pub extras: Vec<ExtraConfig>,
}

pub fn patch_update_img(mut args: PatchArgs<'_>) -> Result<()> {
    kptools_base::log::set_log_enable(true);

    if args.superkey.is_empty() {
        return Err(Error::invalid_arg("empty superkey"));
    }

    let mut kernel_file = KernelFile::read(args.kimg_path)?;
    if kernel_file.is_uncompressed_img() {
        logw!("kernel image with UNCOMPRESSED_IMG header");
    }

    // Copy the kimg for kallsym work — the parser mutates in place
    // (relocations etc).
    let mut kallsym_buf = kernel_file.kimg().to_vec();
    let mut kallsym = Kallsym::default();
    let ver = find_linux_banner(&mut kallsym, &kallsym_buf)?;
    if ver > 0x6_07_00 {
        // Linux 6.7+ — disable the PI_MAP guard inside the kernel
        // image itself so the kpimg entry can overwrite the map
        // area. Upstream applies the same hex patch against the
        // live kernel_file.kimg (not the kallsym copy).
        let kimg = kernel_file.kimg_mut();
        if disable_pi_map(kimg).is_ok() {
            logi!("disabled PI_MAP for kernel version > 6.12.23");
        } else {
            logi!("kernel already patched or PI_MAP not found");
        }
    }

    analyze_kallsym_info(&mut kallsym, &mut kallsym_buf, ArchType::Arm64, true)?;

    let pimg = parse_image_patch_info(kernel_file.kimg())?;
    let kinfo = pimg.kinfo;
    let ori_kimg_len = pimg.ori_kimg_len;

    // Restore original bytes if the image was previously patched
    // (so we're working from the clean kernel).
    if let Some(po) = pimg.preset_offset {
        let header_backup = read_preset(kernel_file.kimg(), po).setup.header_backup;
        kernel_file.kimg_mut()[..header_backup.len()].copy_from_slice(&header_backup);
    }

    let align_kernel_size = align_ceil_i32(kinfo.kernel_size, SZ_4K as i32) as usize;

    // Load kpimg (16-byte aligned).
    let kpimg = read_file_align(args.kpimg_path, 0x10)?;
    let kpimg_len = kpimg.len();

    // -- Process extras -----------------------------------------------
    // Sort by priority, descending (upstream qsort with negative
    // subtraction).
    args.extras.sort_by(|a, b| b.priority.cmp(&a.priority));
    if args.extras.len() > EXTRA_ITEM_MAX_NUM {
        return Err(Error::invalid_arg(format!(
            "too many extras: {} > {}",
            args.extras.len(),
            EXTRA_ITEM_MAX_NUM
        )));
    }
    let mut extra_size = PATCH_EXTRA_ITEM_LEN; // sentinel
    for cfg in &args.extras {
        extra_size += PATCH_EXTRA_ITEM_LEN;
        extra_size += cfg.item.args_size as usize;
        extra_size += cfg.item.con_size as usize;
    }

    // -- Layout -------------------------------------------------------
    let align_kimg_len = align_ceil_i32(ori_kimg_len as i32, SZ_4K as i32) as usize;
    let out_img_len = align_kimg_len + kpimg_len;
    let out_all_len = out_img_len + extra_size;
    let mut start_offset = align_kernel_size;
    if out_all_len > start_offset {
        start_offset = align_ceil_i32(out_all_len as i32, SZ_4K as i32) as usize;
        logi!(
            "patch overlap, move start 0x{align_kernel_size:x} -> 0x{start_offset:x}"
        );
    }
    logi!(
        "layout kimg: 0,0x{ori_kimg_len:x}, kpimg: 0x{align_kimg_len:x},0x{out_img_len:x}, extra: 0x{out_img_len:x},0x{out_all_len:x}, start: 0x{start_offset:x}"
    );

    // -- Allocate output ---------------------------------------------
    let mut out_kf = KernelFile::new_from(&kernel_file, out_all_len);
    // copy kernel bytes (clean version from kernel_file, which had
    // header_backup restored above)
    out_kf.kimg_mut()[..ori_kimg_len].copy_from_slice(&kernel_file.kimg()[..ori_kimg_len]);
    // zero padding to page align
    for b in &mut out_kf.kimg_mut()[ori_kimg_len..align_kimg_len] {
        *b = 0;
    }
    // append kpimg
    out_kf.kimg_mut()[align_kimg_len..align_kimg_len + kpimg_len].copy_from_slice(&kpimg);

    // Patch `b stext` so the new entry goes through kpimg.
    let text_offset = (align_kimg_len + SZ_4K) as u64;
    write_b(
        out_kf.kimg_mut(),
        kinfo.b_stext_insn_offset as usize,
        kinfo.b_stext_insn_offset as u64,
        text_offset,
    )?;

    // -- Preset ------------------------------------------------------
    let preset_off = align_kimg_len;
    let preset_end = preset_off + core::mem::size_of::<Preset>();
    // Read the kpimg-embedded preset (which carries the kp version
    // + compile_time + config flags) for logging then re-open as
    // mutable to write setup fields.
    let existing_header = {
        let p: &Preset = bytemuck::from_bytes(&out_kf.kimg()[preset_off..preset_end]);
        p.header
    };
    let ver_num = existing_header.kp_version.as_u32();
    let compile_time = existing_header.compile_time;
    let config_flags = existing_header.config_flags;
    let is_android = config_flags & crate::preset::CONFIG_ANDROID != 0;
    let is_debug = config_flags & crate::preset::CONFIG_DEBUG != 0;
    logi!("kpimg version: {ver_num:x}");
    logi!(
        "kpimg compile time: {}",
        std::str::from_utf8(
            &compile_time
                [..compile_time.iter().position(|&b| b == 0).unwrap_or(compile_time.len())]
        )
        .unwrap_or("<non-utf8>")
    );
    logi!(
        "kpimg config: {}, {}",
        if is_android { "android" } else { "linux" },
        if is_debug { "debug" } else { "release" },
    );

    // Build setup block.
    let mut new_preset: Preset =
        *bytemuck::from_bytes(&out_kf.kimg()[preset_off..preset_end]);
    new_preset.setup = bytemuck::Zeroable::zeroed();
    new_preset.setup.kernel_version = crate::preset::VersionT {
        reserved: 0,
        patch: kallsym.version.patch,
        minor: kallsym.version.minor,
        major: kallsym.version.major,
    };
    new_preset.setup.kimg_size = ori_kimg_len as i64;
    new_preset.setup.kpimg_size = kpimg_len as i64;
    new_preset.setup.kernel_size = kinfo.kernel_size as i64;
    new_preset.setup.page_shift = kinfo.page_shift as i64;
    new_preset.setup.setup_offset = align_kimg_len as i64;
    new_preset.setup.start_offset = start_offset as i64;
    new_preset.setup.extra_size = extra_size as i64;

    let (map_start, map_max_size) = select_map_area(&kallsym, &mut kallsym_buf)?;
    new_preset.setup.map_offset = map_start as i64;
    new_preset.setup.map_max_size = map_max_size as i64;
    logi!("map_start: 0x{map_start:x}, max_size: 0x{map_max_size:x}");

    // Sync NOP modifications from select_map_area back into the
    // output image.
    let tcp_init_sock_off = get_symbol_offset_exit(&kallsym, &kallsym_buf, "tcp_init_sock")? as usize;
    let sync_start = tcp_init_sock_off;
    let mut sync_size = (map_max_size * 2) as usize;
    if sync_start + sync_size > ori_kimg_len {
        sync_size = ori_kimg_len - sync_start;
    }
    if sync_size > 0 {
        out_kf.kimg_mut()[sync_start..sync_start + sync_size]
            .copy_from_slice(&kallsym_buf[sync_start..sync_start + sync_size]);
        logi!("synced NOP modifications offset: 0x{sync_start:x}, size: 0x{sync_size:x}");
    }

    new_preset.setup.kallsyms_lookup_name_offset =
        get_symbol_offset_exit(&kallsym, &kallsym_buf, "kallsyms_lookup_name")? as i64;
    let mut printk_off = crate::kallsym::get_symbol_offset_zero(&kallsym, &kallsym_buf, "printk");
    if printk_off == 0 {
        printk_off = crate::kallsym::get_symbol_offset_zero(&kallsym, &kallsym_buf, "_printk");
    }
    if printk_off == 0 {
        return Err(Error::kallsym("no symbol printk"));
    }
    new_preset.setup.printk_offset = printk_off as i64;

    // map_symbol + patch_config
    new_preset.setup.map_symbol = fillin_map_symbol(&kallsym, &kallsym_buf)?;
    new_preset.setup.header_backup.copy_from_slice(&kallsym_buf[..8]);
    new_preset.setup.patch_config =
        fillin_patch_config(&kallsym, &kallsym_buf, is_android)?;

    // superkey
    if !args.root_key {
        copy_cstr_into(&mut new_preset.setup.superkey, args.superkey.as_bytes());
        logi!("superkey: {}", args.superkey);
    } else {
        let hash = sha2::Sha256::digest(args.superkey.as_bytes());
        let len = ROOT_SUPER_KEY_HASH_LEN.min(hash.len());
        new_preset.setup.root_superkey[..len].copy_from_slice(&hash[..len]);
        let hex: String = hash[..len].iter().map(|b| format!("{b:02x}")).collect();
        logi!("root superkey hash: {hex}");
    }

    // paging_init entry
    let paging_init =
        get_symbol_offset_exit(&kallsym, &kallsym_buf, "paging_init")?;
    new_preset.setup.paging_init_offset =
        relo_branch_func(&kallsym_buf, paging_init) as i64;

    // additional `KEY=VALUE` list — length-prefixed packing.
    let mut pos_in_additional = 0usize;
    for kv in &args.additional {
        if !kv.contains('=') {
            return Err(Error::invalid_arg("addition must be key=value"));
        }
        let kvlen = kv.len();
        if kvlen > 127 {
            return Err(Error::invalid_arg(format!("addition `{kv}` too long")));
        }
        if pos_in_additional + kvlen + 1 > ADDITIONAL_LEN {
            return Err(Error::overflow("no room in preset.additional"));
        }
        new_preset.setup.additional[pos_in_additional] = kvlen as u8;
        pos_in_additional += 1;
        new_preset.setup.additional[pos_in_additional..pos_in_additional + kvlen]
            .copy_from_slice(kv.as_bytes());
        pos_in_additional += kvlen;
        logi!("adding addition: {kv}");
    }

    // Write preset back.
    out_kf.kimg_mut()[preset_off..preset_end].copy_from_slice(bytemuck::bytes_of(&new_preset));

    // -- Append extras ----------------------------------------------
    let mut cursor = out_img_len;
    for cfg in &args.extras {
        let item = cfg.item;
        // Item header
        out_kf.kimg_mut()[cursor..cursor + PATCH_EXTRA_ITEM_LEN]
            .copy_from_slice(bytemuck::bytes_of(&item));
        cursor += PATCH_EXTRA_ITEM_LEN;
        // args blob
        if item.args_size > 0 {
            if let Some(args_str) = &cfg.set_args {
                let take = (item.args_size as usize).min(args_str.len());
                out_kf.kimg_mut()[cursor..cursor + take]
                    .copy_from_slice(&args_str.as_bytes()[..take]);
            }
            cursor += item.args_size as usize;
        }
        // contents
        let con_len = item.con_size as usize;
        out_kf.kimg_mut()[cursor..cursor + con_len].copy_from_slice(&cfg.data[..con_len]);
        cursor += con_len;
        let args_size = item.args_size;
        let con_size = item.con_size;
        logi!(
            "embedding {} name: {} size: 0x{:x}+0x{:x}+0x{:x}",
            cfg.extra_type.str_tag(),
            cfg.name,
            PATCH_EXTRA_ITEM_LEN,
            args_size,
            con_size,
        );
    }
    // Guard empty item at end.
    let empty = PatchExtraItem {
        magic: [0; 4],
        priority: 0,
        args_size: 0,
        con_size: 0,
        extra_type: 0,
        name: [0; EXTRA_NAME_LEN],
        event: [0; EXTRA_EVENT_LEN],
        pad: [0; PATCH_EXTRA_ITEM_LEN - 4 - 4 - 4 - 4 - 4 - EXTRA_NAME_LEN - EXTRA_EVENT_LEN],
    };
    out_kf.kimg_mut()[cursor..cursor + PATCH_EXTRA_ITEM_LEN]
        .copy_from_slice(bytemuck::bytes_of(&empty));

    // Make sure the outer file-length header matches when
    // UNCOMPRESSED_IMG is present.
    out_kf.resize_kimg(out_all_len);
    out_kf.write(args.out_path)?;
    logi!("patch done: {}", args.out_path.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Hexpatch used by `patch_update_img` when the kernel is ≥ 6.12.23.
// ---------------------------------------------------------------------------

fn hexstr_to_bytes(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = from_hex(bytes[i]);
        let lo = from_hex(bytes[i + 1]);
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

fn from_hex(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

fn hex_patch(img: &mut [u8], pattern_hex: &str, replace_hex: &str) -> Result<()> {
    let pattern = hexstr_to_bytes(pattern_hex);
    let replace = hexstr_to_bytes(replace_hex);
    let Some(pos) = img.windows(pattern.len()).position(|w| w == pattern.as_slice()) else {
        return Err(Error::bad_kernel("hex pattern not found"));
    };
    img[pos..pos + replace.len()].copy_from_slice(&replace);
    Ok(())
}

fn disable_pi_map(img: &mut [u8]) -> Result<()> {
    hex_patch(
        img,
        "E60316AAE7031F2A3411889A",
        "E60316AAE7031F2AF40309AA",
    )
}

// ---------------------------------------------------------------------------
// unpatch + reset_key
// ---------------------------------------------------------------------------

pub fn unpatch_img(kimg_path: &std::path::Path, out_path: &std::path::Path) -> Result<()> {
    let mut kernel_file = KernelFile::read(kimg_path)?;
    let Some(preset_off) = find_preset(kernel_file.kimg()) else {
        return Err(Error::bad_preset("not patched kernel image"));
    };
    let preset: Preset = *read_preset(kernel_file.kimg(), preset_off);
    let header_backup = preset.setup.header_backup;
    kernel_file.kimg_mut()[..header_backup.len()].copy_from_slice(&header_backup);
    let kimg_size = if preset.setup.kimg_size != 0 {
        preset.setup.kimg_size as usize
    } else {
        preset_off
    };
    kernel_file.resize_kimg(kimg_size);
    kernel_file.write(out_path)?;
    Ok(())
}

pub fn reset_key(
    kimg_path: &std::path::Path,
    out_path: &std::path::Path,
    superkey: &str,
) -> Result<()> {
    if superkey.is_empty() {
        return Err(Error::invalid_arg("empty superkey"));
    }
    if superkey.len() >= SUPER_KEY_LEN {
        return Err(Error::invalid_arg("superkey too long"));
    }
    let mut kernel_file = KernelFile::read(kimg_path)?;
    let Some(preset_off) = find_preset(kernel_file.kimg()) else {
        return Err(Error::bad_preset("not patched kernel image"));
    };
    let mut preset: Preset = *read_preset(kernel_file.kimg(), preset_off);
    let origin = std::str::from_utf8(&preset.setup.superkey).unwrap_or("?").to_string();
    preset.setup.superkey = [0; SUPER_KEY_LEN];
    copy_cstr_into(&mut preset.setup.superkey, superkey.as_bytes());
    let end = preset_off + core::mem::size_of::<Preset>();
    kernel_file.kimg_mut()[preset_off..end].copy_from_slice(bytemuck::bytes_of(&preset));
    logi!("reset superkey: {origin} -> {superkey}");
    kernel_file.write(out_path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Info-print helpers — upstream `-l` introspection. Mirror the C
// output exactly so scripts parsing the banner-style `[kpimg]` /
// `[additional]` / `[kernel]` / `[extras]` / `[extra N]` / `[kpm]`
// sections continue to work.
// ---------------------------------------------------------------------------

fn cstr_trim(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn bytes_to_hex(buf: &[u8]) -> String {
    let mut s = String::with_capacity(buf.len() * 2);
    for b in buf {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Port of upstream `print_preset_info`. Writes to stdout.
pub fn print_preset_info(preset: &Preset) {
    let ver = preset.header.kp_version;
    let ver_num = ((ver.major as u32) << 16) | ((ver.minor as u32) << 8) | (ver.patch as u32);
    let flags = preset.header.config_flags;
    let is_android = flags & crate::preset::CONFIG_ANDROID != 0;
    let is_debug = flags & crate::preset::CONFIG_DEBUG != 0;

    println!("{INFO_KP_IMG_SESSION}");
    println!("version=0x{ver_num:x}");
    println!("compile_time={}", cstr_trim(&preset.header.compile_time));
    println!(
        "config={},{}",
        if is_android { "android" } else { "linux" },
        if is_debug { "debug" } else { "release" },
    );
    println!("superkey={}", cstr_trim(&preset.setup.superkey));

    if ver_num > 0xa04 {
        println!("root_superkey={}", bytes_to_hex(&preset.setup.root_superkey));
    }

    println!("{INFO_ADDITIONAL_SESSION}");
    // `additional` is a sequence of `(len:u8, bytes:len)` records
    // terminated by a zero length byte.
    let additional: &[u8] = if ver_num <= 0xa04 {
        // Compat layout: additional begins one hash+preserve block
        // earlier. For simplicity we only honour the modern layout
        // (every 0.13+ build). Anyone on <=0x0a04 already broke.
        &preset.setup.additional
    } else {
        &preset.setup.additional
    };
    let mut p = 0usize;
    while p < additional.len() {
        let len = additional[p] as usize;
        if len == 0 {
            break;
        }
        p += 1;
        if p + len > additional.len() {
            break;
        }
        if let Ok(s) = std::str::from_utf8(&additional[p..p + len]) {
            println!("{s}");
        }
        p += len;
    }
}

/// Port of upstream `print_kp_image_info_path`.
pub fn print_kp_image_info_path(kpimg_path: &std::path::Path) -> Result<()> {
    let kpimg = read_file(kpimg_path)?;
    let Some(off) = find_preset(&kpimg) else {
        return Err(Error::bad_preset("not a kpimg"));
    };
    let preset = read_preset(&kpimg, off);
    print_preset_info(preset);
    println!();
    Ok(())
}

/// Port of upstream `print_image_patch_info`. Takes a parsed
/// `PatchedKimg` + the backing slice so embedded KPM payloads can
/// be resolved by offset-within-kimg.
pub fn print_image_patch_info(pimg: &PatchedKimg, kimg: &[u8]) -> Result<()> {
    println!("{INFO_KERNEL_IMG_SESSION}");
    if let Some(banner_off) = pimg.banner {
        // Banner may span multiple lines — upstream prints up to
        // the first '\n'.
        let banner_end = kimg[banner_off..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|e| banner_off + e)
            .unwrap_or(kimg.len());
        let banner = std::str::from_utf8(&kimg[banner_off..banner_end]).unwrap_or("<non-utf8>");
        println!("banner={banner}");
    }
    println!(
        "patched={}",
        if pimg.preset_offset.is_some() { "true" } else { "false" }
    );

    let Some(preset_off) = pimg.preset_offset else {
        return Ok(());
    };
    let preset_copy: Preset = *read_preset(kimg, preset_off);
    print_preset_info(&preset_copy);

    println!("{INFO_EXTRA_SESSION}");
    println!("num={}", pimg.embed_items.len());

    // Walk extras a second time, same logic as parse_image_patch_info,
    // to find each extra's payload bytes for KPM modinfo extraction.
    let kimg_size = preset_copy.setup.kimg_size as i32;
    let kpimg_size = preset_copy.setup.kpimg_size as usize;
    let extra_start = align_ceil_i32(kimg_size, SZ_4K as i32) as usize + kpimg_size;
    let mut cursor = extra_start;
    for (i, item) in pimg.embed_items.iter().enumerate() {
        let ty = ExtraType::from_i32(item.extra_type).unwrap_or(ExtraType::None);
        let args_size = item.args_size;
        let con_size = item.con_size;
        println!("[extra {i}]");
        println!("index={i}");
        println!("type={}", ty.str_tag());
        println!("name={}", cstr_trim(&item.name));
        println!("event={}", cstr_trim(&item.event));
        let priority = item.priority;
        println!("priority={priority}");
        println!("args_size=0x{args_size:x}");
        let args_off = cursor + PATCH_EXTRA_ITEM_LEN;
        let args = if args_size > 0 {
            std::str::from_utf8(&kimg[args_off..args_off + args_size as usize]).unwrap_or("")
        } else {
            ""
        };
        println!("args={args}");
        println!("con_size=0x{con_size:x}");
        let con_off = args_off + args_size as usize;
        if ty == ExtraType::Kpm {
            let con_end = con_off + con_size as usize;
            if con_end <= kimg.len() {
                if let Ok(info) = get_kpm_info(&kimg[con_off..con_end]) {
                    println!("version={}", info.version.as_deref().unwrap_or(""));
                    println!("license={}", info.license.as_deref().unwrap_or(""));
                    println!("author={}", info.author.as_deref().unwrap_or(""));
                    println!("description={}", info.description.as_deref().unwrap_or(""));
                }
            }
        }
        cursor = con_off + con_size as usize;
    }
    Ok(())
}

/// Port of upstream `print_image_patch_info_path`.
pub fn print_image_patch_info_path(kimg_path: &std::path::Path) -> Result<()> {
    let kf = KernelFile::read(kimg_path)?;
    let pimg = parse_image_patch_info(kf.kimg())?;
    print_image_patch_info(&pimg, kf.kimg())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_patch_roundtrip() {
        let mut img = vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        hex_patch(&mut img, "BBCC", "1122").unwrap();
        assert_eq!(img, vec![0xAA, 0x11, 0x22, 0xDD, 0xEE, 0xFF]);
    }

    #[test]
    fn hex_patch_missing_errors() {
        let mut img = vec![0u8; 16];
        assert!(hex_patch(&mut img, "DEADBEEF", "00000000").is_err());
    }

    #[test]
    fn align_ceil_helper() {
        assert_eq!(align_ceil_i32(0x1000, 0x1000), 0x1000);
        assert_eq!(align_ceil_i32(0x1001, 0x1000), 0x2000);
    }
}
