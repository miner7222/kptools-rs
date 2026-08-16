//! Kernel-image patch driver for KernelPatch 0.13.4.

use sha2::Digest;

use kptools_base::{
    io::{read_file, read_file_align, write_file},
    logi, logw, Error, Result,
};

use crate::image::{get_kernel_info, KernelInfo};
use crate::insn::{relo_branch_func, write_b};
use crate::kallsym::{
    analyze_kallsym_info, dump_all_ikconfig, dump_all_symbols, find_ikconfig_blob,
    find_linux_banner, ArchType, Kallsym,
};
use crate::kpm::get_kpm_info;
use crate::preset::{
    extra_flags_get_header_version, ExtraType, PatchExtraItem, Preset, ADDITIONAL_LEN,
    CONFIG_ANDROID, CONFIG_DEBUG, CONFIG_FLAG_X86_64, EXTRA_ALIGN, EXTRA_EVENT_LEN,
    EXTRA_HDR_MAGIC, EXTRA_ITEM_MAX_NUM, EXTRA_NAME_LEN, HDR_BACKUP_SIZE, KP_MAGIC, KP_VERSION_U32,
    MAGIC_LEN, PATCH_EXTRA_HEADER_VERSION_LEGACY, PATCH_EXTRA_ITEM_LEN, ROOT_SUPER_KEY_HASH_LEN,
    SUPER_KEY_LEN,
};
use crate::symbol::{
    fillin_map_symbol, fillin_patch_config, get_symbol_offset_exit, get_usable_symbol_offset_try,
    select_map_area, select_symbol_lookup_anchor_offset,
};
use crate::x86_64::{
    inject_x86_kpimg, is_x86_bzimage, load_x86_bzimage, remove_x86_kpimg, write_x86_bzimage,
};

pub const INFO_KERNEL_IMG_SESSION: &str = "[kernel]";
pub const INFO_KP_IMG_SESSION: &str = "[kpimg]";
pub const INFO_ADDITIONAL_SESSION: &str = "[additional]";
pub const INFO_EXTRA_SESSION: &str = "[extras]";
pub const INFO_EXTRA_SESSION_N: &str = "[extra %d]";

const SZ_4K: usize = 0x1000;
const UNCOMPRESSED_IMG_MAGIC: &[u8] = b"UNCOMPRESSED_IMG";

pub struct KernelFile {
    pub kfile: Vec<u8>,
    pub img_offset: usize,
}

impl KernelFile {
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

    pub fn new_from(old: &Self, new_kimg_len: usize) -> Self {
        let mut kfile = Vec::with_capacity(old.img_offset + new_kimg_len);
        kfile.extend_from_slice(&old.kfile[..old.img_offset]);
        kfile.resize(old.img_offset + new_kimg_len, 0);
        Self {
            kfile,
            img_offset: old.img_offset,
        }
    }

    pub fn resize_kimg(&mut self, new_kimg_len: usize) {
        if self.is_uncompressed_img() {
            self.kfile[16..20].copy_from_slice(&(new_kimg_len as u32).to_le_bytes());
        }
        self.kfile.truncate(self.img_offset + new_kimg_len);
    }
}

fn find_preset(kimg: &[u8]) -> Option<usize> {
    kimg.windows(MAGIC_LEN).position(|w| w == KP_MAGIC)
}

fn read_preset(kimg: &[u8], offset: usize) -> &Preset {
    let size = core::mem::size_of::<Preset>();
    bytemuck::from_bytes(&kimg[offset..offset + size])
}

fn header_backup_has_valid_primary_entry(header_backup: &[u8]) -> bool {
    if header_backup.len() < HDR_BACKUP_SIZE {
        return false;
    }
    let primary = u32::from_le_bytes(header_backup[..4].try_into().unwrap());
    if primary & 0xfc00_0000 == 0x1400_0000 {
        return true;
    }
    if &header_backup[..2] == b"MZ" {
        let primary = u32::from_le_bytes(header_backup[4..8].try_into().unwrap());
        if primary & 0xfc00_0000 == 0x1400_0000 {
            return true;
        }
    }
    false
}

fn push_unique(candidates: &mut Vec<usize>, value: usize) {
    if !candidates.contains(&value) {
        candidates.push(value);
    }
}

fn preset_header_backup(preset: &Preset) -> [u8; HDR_BACKUP_SIZE] {
    let setup = bytemuck::bytes_of(&preset.setup);
    let current = core::mem::offset_of!(crate::preset::SetupPreset, header_backup);
    let ver = preset.header.kp_version.as_u32();
    let mut candidates = Vec::with_capacity(3);
    if ver <= crate::preset::pack_version(0, 13, 1) {
        if current >= 16 {
            push_unique(&mut candidates, current - 16);
        }
        push_unique(&mut candidates, current);
    } else {
        push_unique(&mut candidates, current);
        if current >= 16 {
            push_unique(&mut candidates, current - 16);
        }
    }
    if current >= 8 {
        push_unique(&mut candidates, current - 8);
    }
    for &off in &candidates {
        if off + HDR_BACKUP_SIZE <= setup.len()
            && header_backup_has_valid_primary_entry(&setup[off..off + HDR_BACKUP_SIZE])
        {
            return setup[off..off + HDR_BACKUP_SIZE].try_into().unwrap();
        }
    }
    let off = candidates[0];
    setup[off..off + HDR_BACKUP_SIZE].try_into().unwrap()
}

fn find_patched_preset(kimg: &[u8]) -> Option<(usize, i32)> {
    let mut search_from = 0usize;
    while search_from < kimg.len() {
        let rel = find_preset(&kimg[search_from..])?;
        let offset = search_from + rel;
        if offset + core::mem::size_of::<Preset>() > kimg.len() {
            return None;
        }
        let preset = read_preset(kimg, offset);
        let saved = preset.setup.kimg_size as i32;
        let expected = align_ceil_i32(saved, SZ_4K as i32);
        let backup = preset_header_backup(preset);
        if offset as i32 == expected && header_backup_has_valid_primary_entry(&backup) {
            return Some((offset, saved));
        }
        logw!("found magic string at 0x{offset:x} but saved kernel image size/header backup mismatch, ignoring");
        search_from = offset + 1;
    }
    None
}

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
            get_kpm_info(&data)
                .unwrap_or_default()
                .name
                .clone()
                .unwrap_or(name_hint.clone())
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
            flags: 0,
            pad: [0; PATCH_EXTRA_ITEM_LEN
                - 4
                - 4
                - 4
                - 4
                - 4
                - EXTRA_NAME_LEN
                - EXTRA_EVENT_LEN
                - 4],
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

fn cstr_trim(buf: &[u8]) -> &str {
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    std::str::from_utf8(&buf[..end]).unwrap_or("")
}

fn sanitize_legacy_extra_item(mut item: PatchExtraItem) -> PatchExtraItem {
    let flags = item.flags;
    if extra_flags_get_header_version(flags) == PATCH_EXTRA_HEADER_VERSION_LEGACY && flags != 0 {
        let name = cstr_trim(&item.name).to_string();
        logw!(
            "legacy extra item {name} has dirty flags 0x{:x}, clearing for compatibility",
            flags as u32
        );
        item.flags = 0;
    }
    item
}

fn is_legacy_kconfig_extra(item: &PatchExtraItem) -> bool {
    extra_flags_get_header_version(item.flags) == PATCH_EXTRA_HEADER_VERSION_LEGACY
        && item.extra_type == ExtraType::KconfigLegacy.as_i32()
        && cstr_trim(&item.name) == "kconfig"
}

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
    let found = find_patched_preset(kimg);
    let mut restored = kimg.to_vec();
    if let Some((preset_off, _)) = found {
        let backup = preset_header_backup(read_preset(kimg, preset_off));
        logi!("restore header backup before parsing patched kernel image");
        restored[..HDR_BACKUP_SIZE].copy_from_slice(&backup);
    }
    let kinfo = get_kernel_info(&restored)?;
    let mut out = PatchedKimg {
        kimg_len: kimg.len(),
        kinfo,
        ..Default::default()
    };

    let banner_prefix = b"Linux version ";
    let mut pos = 0usize;
    while pos < restored.len() {
        let Some(rel) = restored[pos..]
            .windows(banner_prefix.len())
            .position(|w| w == banner_prefix)
        else {
            break;
        };
        let start = pos + rel;
        let after = start + banner_prefix.len();
        if after + 1 < restored.len()
            && restored[after].is_ascii_digit()
            && restored[after + 1] == b'.'
        {
            out.banner = Some(start);
            break;
        }
        pos = start + 1;
    }
    if out.banner.is_none() {
        return Err(Error::bad_kernel("no Linux banner found"));
    }

    let Some((preset_off, saved_kimg_len)) = found else {
        logi!("new kernel image ...");
        out.ori_kimg_len = kimg.len();
        return Ok(out);
    };
    logi!("patched kernel image ...");
    out.preset_offset = Some(preset_off);
    out.ori_kimg_len = saved_kimg_len as usize;
    let preset = read_preset(kimg, preset_off);
    let kpimg_size = preset.setup.kpimg_size as usize;
    let extra_size = preset.setup.extra_size as usize;
    let extra_start = preset_off + kpimg_size;
    if extra_start > kimg.len() {
        return Err(Error::bad_preset("kpimg length mismatch"));
    }
    if extra_start == kimg.len() {
        return Ok(out);
    }
    let end = extra_start.saturating_add(extra_size).min(kimg.len());
    let mut p = extra_start;
    while p + PATCH_EXTRA_ITEM_LEN <= end {
        let raw: &PatchExtraItem = bytemuck::from_bytes(&kimg[p..p + PATCH_EXTRA_ITEM_LEN]);
        if raw.magic != *EXTRA_HDR_MAGIC || raw.extra_type == ExtraType::None.as_i32() {
            break;
        }
        let item = sanitize_legacy_extra_item(*raw);
        let args = item.args_size.max(0) as usize;
        let con = item.con_size.max(0) as usize;
        if is_legacy_kconfig_extra(&item) {
            logw!("skip legacy embedded kconfig extra item during upgrade compatibility scan");
            p = p.saturating_add(PATCH_EXTRA_ITEM_LEN + args + con);
            continue;
        }
        if out.embed_items.len() >= EXTRA_ITEM_MAX_NUM {
            return Err(Error::bad_preset("too many embedded extra items"));
        }
        out.embed_items.push(item);
        p = p.saturating_add(PATCH_EXTRA_ITEM_LEN + args + con);
    }
    Ok(out)
}

fn align_ceil_i32(v: i32, a: i32) -> i32 {
    if a == 0 {
        v
    } else {
        ((v + a - 1) / a) * a
    }
}

pub fn ensure_supported_kpimg_version(ver_num: u32) -> Result<()> {
    if ver_num != KP_VERSION_U32 {
        return Err(Error::bad_kpimg(format!("unsupported kpimg version 0x{ver_num:x}; this tools port only supports 0x{KP_VERSION_U32:x}")));
    }
    Ok(())
}

pub struct PatchArgs<'a> {
    pub kimg_path: &'a std::path::Path,
    pub kpimg_path: &'a std::path::Path,
    pub out_path: &'a std::path::Path,
    pub superkey: &'a str,
    pub root_key: bool,
    pub additional: Vec<String>,
    pub extras: Vec<ExtraConfig>,
}

fn patch_update_x86(args: &PatchArgs<'_>) -> Result<()> {
    if !args.extras.is_empty() {
        return Err(Error::invalid_arg("x86 kpimg extras are not supported yet"));
    }
    if !args.additional.is_empty() {
        return Err(Error::invalid_arg(
            "x86 kpimg additional properties are not supported yet",
        ));
    }
    let mut image = load_x86_bzimage(args.kimg_path)?;
    let mut kpimg = read_file(args.kpimg_path)?;
    if kpimg.len() < core::mem::size_of::<Preset>() {
        return Err(Error::bad_kpimg("x86 kpimg is too small"));
    }
    let mut preset: Preset = *bytemuck::from_bytes(&kpimg[..core::mem::size_of::<Preset>()]);
    ensure_supported_kpimg_version(preset.header.kp_version.as_u32())?;
    let flags = preset.header.config_flags;
    if preset.header.magic != *KP_MAGIC || flags & CONFIG_FLAG_X86_64 == 0 {
        return Err(Error::bad_kpimg("kpimg is not an x86_64 payload"));
    }
    preset.setup = bytemuck::Zeroable::zeroed();
    let mut info = Kallsym::default();
    if find_linux_banner(&mut info, &image.flat).is_ok() {
        preset.setup.kernel_version = info.version;
    }
    if !args.root_key {
        copy_cstr_into(&mut preset.setup.superkey, args.superkey.as_bytes());
    } else if !args.superkey.is_empty() {
        let hash = sha2::Sha256::digest(args.superkey.as_bytes());
        preset
            .setup
            .root_superkey
            .copy_from_slice(&hash[..ROOT_SUPER_KEY_HASH_LEN]);
    }
    kpimg[..core::mem::size_of::<Preset>()].copy_from_slice(bytemuck::bytes_of(&preset));
    inject_x86_kpimg(&mut image, &mut kpimg)?;
    write_x86_bzimage(&mut image, args.out_path)?;
    logi!("x86 patch done: {}", args.out_path.display());
    Ok(())
}

pub fn patch_update_img(mut args: PatchArgs<'_>) -> Result<()> {
    kptools_base::log::set_log_enable(true);
    if args.superkey.is_empty() && !args.root_key {
        return Err(Error::invalid_arg("empty superkey"));
    }
    let probe = read_file(args.kimg_path)?;
    if is_x86_bzimage(&probe) {
        return patch_update_x86(&args);
    }

    let mut kernel_file = KernelFile::read(args.kimg_path)?;
    if kernel_file.is_uncompressed_img() {
        logw!("kernel image with UNCOMPRESSED_IMG header");
    }
    let pimg = parse_image_patch_info(kernel_file.kimg())?;
    let kinfo = pimg.kinfo;
    let ori_kimg_len = pimg.ori_kimg_len;
    if let Some(po) = pimg.preset_offset {
        let backup = preset_header_backup(read_preset(kernel_file.kimg(), po));
        kernel_file.kimg_mut()[..HDR_BACKUP_SIZE].copy_from_slice(&backup);
    }

    let mut kallsym_buf = kernel_file.kimg()[..ori_kimg_len].to_vec();
    let mut kallsym = Kallsym::default();
    let ver = find_linux_banner(&mut kallsym, &kallsym_buf)?;
    let is_gki = ver >= 330_240;
    logi!("is_gki: {}", if is_gki { "true" } else { "false" });
    if ver > 395_008 {
        if disable_pi_map(kernel_file.kimg_mut()).is_err() {
            logi!("kernel have patched or not found");
        } else {
            logi!("disabled PI_MAP for kernel version > 6.12.23");
        }
    }
    analyze_kallsym_info(&mut kallsym, &mut kallsym_buf, ArchType::Arm64, true)?;

    let (kcfg_start, kcfg_bytes, kcfg_ok) = match find_ikconfig_blob(&kallsym_buf) {
        Ok((start, size)) => {
            logi!("ikconfig gzip blob at 0x{start:x}, size 0x{size:x} (runtime puff)");
            (start as i64, size as i64, true)
        }
        Err(rc) => {
            logw!("kernel IKCONFIG blob not found (rc={rc}), kconfig unavailable at runtime");
            (0, 0, false)
        }
    };
    let align_kernel_size = align_ceil_i32(kinfo.kernel_size, SZ_4K as i32) as usize;
    let kpimg = read_file_align(args.kpimg_path, 0x10)?;
    let kpimg_len = kpimg.len();

    args.extras
        .sort_by_key(|item| std::cmp::Reverse(item.priority));
    if args.extras.len() > EXTRA_ITEM_MAX_NUM {
        return Err(Error::invalid_arg("too many extras"));
    }
    let mut extra_size = PATCH_EXTRA_ITEM_LEN;
    for cfg in &mut args.extras {
        if let Some(name) = &cfg.set_name {
            if name.len() >= EXTRA_NAME_LEN {
                return Err(Error::invalid_arg("extra name too long"));
            }
            cfg.item.name = [0; EXTRA_NAME_LEN];
            copy_cstr_into(&mut cfg.item.name, name.as_bytes());
        }
        if let Some(event) = &cfg.set_event {
            if event.len() >= EXTRA_EVENT_LEN {
                return Err(Error::invalid_arg("extra event too long"));
            }
            cfg.item.event = [0; EXTRA_EVENT_LEN];
            copy_cstr_into(&mut cfg.item.event, event.as_bytes());
        }
        cfg.item.extra_type = cfg.extra_type.as_i32();
        cfg.item.priority = cfg.priority;
        if let Some(arguments) = &cfg.set_args {
            cfg.item.args_size = align_ceil_i32(arguments.len() as i32, EXTRA_ALIGN as i32);
        }
        extra_size += PATCH_EXTRA_ITEM_LEN
            + cfg.item.args_size.max(0) as usize
            + cfg.item.con_size.max(0) as usize;
    }

    let align_kimg_len = align_ceil_i32(ori_kimg_len as i32, SZ_4K as i32) as usize;
    let out_img_len = align_kimg_len + kpimg_len;
    let out_all_len = out_img_len + extra_size;
    let mut start_offset = align_kernel_size;
    if out_all_len > start_offset {
        start_offset = align_ceil_i32(out_all_len as i32, SZ_4K as i32) as usize;
        logi!("patch overlap, move start 0x{align_kernel_size:x} -> 0x{start_offset:x}");
    }
    logi!("layout kimg: 0x0,0x{ori_kimg_len:x}, kpimg: 0x{align_kimg_len:x},0x{kpimg_len:x}, extra: 0x{out_img_len:x},0x{extra_size:x}, end: 0x{out_all_len:x}, start: 0x{start_offset:x}");

    let mut out_kf = KernelFile::new_from(&kernel_file, out_all_len);
    out_kf.kimg_mut()[..ori_kimg_len].copy_from_slice(&kernel_file.kimg()[..ori_kimg_len]);
    out_kf.kimg_mut()[ori_kimg_len..align_kimg_len].fill(0);
    out_kf.kimg_mut()[align_kimg_len..align_kimg_len + kpimg_len].copy_from_slice(&kpimg);

    let preset_off = align_kimg_len;
    let preset_end = preset_off + core::mem::size_of::<Preset>();
    if preset_end > out_kf.kimg_len() {
        return Err(Error::bad_kpimg("kpimg preset is truncated"));
    }
    let mut new_preset: Preset = *bytemuck::from_bytes(&out_kf.kimg()[preset_off..preset_end]);
    let ver_num = new_preset.header.kp_version.as_u32();
    ensure_supported_kpimg_version(ver_num)?;
    let compile_time = new_preset.header.compile_time;
    let flags = new_preset.header.config_flags;
    let is_android = flags & CONFIG_ANDROID != 0;
    let is_debug = flags & CONFIG_DEBUG != 0;
    let is_x86 = flags & CONFIG_FLAG_X86_64 != 0;
    logi!("kpimg version: {ver_num:x}");
    logi!("kpimg compile time: {}", cstr_trim(&compile_time));
    logi!(
        "kpimg config: {}, {}, {}",
        if is_android { "android" } else { "linux" },
        if is_debug { "debug" } else { "release" },
        if is_x86 { "x86_64" } else { "arm64" }
    );
    if is_x86 {
        return Err(Error::bad_kpimg("x86_64 kpimg requires an x86 bzImage"));
    }

    new_preset.setup = bytemuck::Zeroable::zeroed();
    new_preset.setup.kernel_version = kallsym.version;
    new_preset.setup.kimg_size = ori_kimg_len as i64;
    new_preset.setup.kpimg_size = kpimg_len as i64;
    new_preset.setup.kernel_size = kinfo.kernel_size as i64;
    new_preset.setup.page_shift = kinfo.page_shift as i64;
    new_preset.setup.setup_offset = align_kimg_len as i64;
    new_preset.setup.start_offset = start_offset as i64;
    new_preset.setup.extra_size = extra_size as i64;

    let (map_start, map_max_size) =
        select_map_area(&kallsym, &mut kallsym_buf, ori_kimg_len as i32, is_gki)?;
    new_preset.setup.map_offset = map_start as i64;
    new_preset.setup.map_max_size = map_max_size as i64;
    logi!("map_start: 0x{map_start:x}, max_size: 0x{map_max_size:x}");
    let sync_start = map_start as usize;
    let sync_size = ((map_max_size * 2) as usize).min(ori_kimg_len.saturating_sub(sync_start));
    if sync_size > 0 {
        out_kf.kimg_mut()[sync_start..sync_start + sync_size]
            .copy_from_slice(&kallsym_buf[sync_start..sync_start + sync_size]);
    }

    let imglen = ori_kimg_len as i32;
    new_preset.setup.sprintf_offset =
        get_usable_symbol_offset_try(&kallsym, &kallsym_buf, imglen, "sprintf") as i64;
    let (anchor_off, anchor_name) =
        select_symbol_lookup_anchor_offset(&kallsym, &kallsym_buf, imglen);
    new_preset.setup.symbol_lookup_anchor_offset = anchor_off as i64;
    new_preset.setup.kallsyms_lookup_name_offset =
        get_usable_symbol_offset_try(&kallsym, &kallsym_buf, imglen, "kallsyms_lookup_name") as i64;
    if new_preset.setup.symbol_lookup_anchor_offset != 0 && new_preset.setup.sprintf_offset != 0 {
        logi!("prefer runtime forward scan anchor for kallsyms_lookup_name: {}, offset: 0x{anchor_off:08x}", anchor_name.unwrap_or("<unknown>"));
    } else if new_preset.setup.kallsyms_lookup_name_offset != 0 {
        logi!("fallback to direct kallsyms_lookup_name symbol");
    } else {
        return Err(Error::kallsym(
            "no usable symbol scan anchor/sprintf chain and no kallsyms_lookup_name symbol",
        ));
    }

    let mut printk = crate::kallsym::get_symbol_offset_zero(&kallsym, &kallsym_buf, "printk");
    if printk == 0 {
        printk = crate::kallsym::get_symbol_offset_zero(&kallsym, &kallsym_buf, "_printk");
    }
    if printk == 0 {
        return Err(Error::kallsym("no symbol printk"));
    }
    new_preset.setup.printk_offset = printk as i64;
    new_preset.setup.map_symbol = fillin_map_symbol(&kallsym, &kallsym_buf)?;
    new_preset
        .setup
        .header_backup
        .copy_from_slice(&kallsym_buf[..HDR_BACKUP_SIZE]);
    new_preset.setup.patch_config =
        fillin_patch_config(&kallsym, &kallsym_buf, imglen, is_android)?;

    if !args.root_key {
        copy_cstr_into(&mut new_preset.setup.superkey, args.superkey.as_bytes());
    } else if !args.superkey.is_empty() {
        let hash = sha2::Sha256::digest(args.superkey.as_bytes());
        new_preset
            .setup
            .root_superkey
            .copy_from_slice(&hash[..ROOT_SUPER_KEY_HASH_LEN]);
    }
    if kcfg_ok {
        new_preset.setup.kconfig_offset = kcfg_start;
        new_preset.setup.kconfig_size = kcfg_bytes;
    }
    let paging_init = get_symbol_offset_exit(&kallsym, &kallsym_buf, "paging_init")?;
    new_preset.setup.paging_init_offset = relo_branch_func(&kallsym_buf, paging_init) as i64;

    let text_offset = (align_kimg_len + SZ_4K) as u64;
    write_b(
        out_kf.kimg_mut(),
        kinfo.b_stext_insn_offset as usize,
        kinfo.b_stext_insn_offset as u64,
        text_offset,
    )?;

    let mut add_pos = 0usize;
    for kv in &args.additional {
        if !kv.contains('=') {
            return Err(Error::invalid_arg("addition must be key=value"));
        }
        if kv.len() > 127 || add_pos + kv.len() + 1 > ADDITIONAL_LEN {
            return Err(Error::overflow(
                "additional properties exceed preset capacity",
            ));
        }
        new_preset.setup.additional[add_pos] = kv.len() as u8;
        add_pos += 1;
        new_preset.setup.additional[add_pos..add_pos + kv.len()].copy_from_slice(kv.as_bytes());
        add_pos += kv.len();
    }
    out_kf.kimg_mut()[preset_off..preset_end].copy_from_slice(bytemuck::bytes_of(&new_preset));

    let mut cursor = out_img_len;
    for cfg in &args.extras {
        let item = sanitize_legacy_extra_item(cfg.item);
        out_kf.kimg_mut()[cursor..cursor + PATCH_EXTRA_ITEM_LEN]
            .copy_from_slice(bytemuck::bytes_of(&item));
        cursor += PATCH_EXTRA_ITEM_LEN;
        if item.args_size > 0 {
            let args_len = item.args_size as usize;
            if let Some(s) = &cfg.set_args {
                let take = s.len().min(args_len);
                out_kf.kimg_mut()[cursor..cursor + take].copy_from_slice(&s.as_bytes()[..take]);
            }
            cursor += args_len;
        }
        let con = item.con_size.max(0) as usize;
        out_kf.kimg_mut()[cursor..cursor + con].copy_from_slice(&cfg.data[..con]);
        cursor += con;
    }
    out_kf.kimg_mut()[cursor..cursor + PATCH_EXTRA_ITEM_LEN].fill(0);
    out_kf.resize_kimg(out_all_len);
    out_kf.write(args.out_path)?;
    logi!("patch done: {}", args.out_path.display());
    Ok(())
}

fn hexstr_to_bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks_exact(2)
        .map(|p| (from_hex(p[0]) << 4) | from_hex(p[1]))
        .collect()
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
    let pos = img
        .windows(pattern.len())
        .position(|w| w == pattern)
        .ok_or_else(|| Error::bad_kernel("hex pattern not found"))?;
    img[pos..pos + replace.len()].copy_from_slice(&replace);
    Ok(())
}
fn disable_pi_map(img: &mut [u8]) -> Result<()> {
    hex_patch(img, "E60316AAE7031F2A3411889A", "E60316AAE7031F2AF40309AA")
}

pub fn unpatch_img(kimg_path: &std::path::Path, out_path: &std::path::Path) -> Result<()> {
    let probe = read_file(kimg_path)?;
    if is_x86_bzimage(&probe) {
        let mut image = load_x86_bzimage(kimg_path)?;
        remove_x86_kpimg(&mut image)?;
        return write_x86_bzimage(&mut image, out_path);
    }
    let mut kernel_file = KernelFile::read(kimg_path)?;
    let (preset_off, saved) = find_patched_preset(kernel_file.kimg())
        .ok_or_else(|| Error::bad_preset("not patched kernel image"))?;
    let preset: Preset = *read_preset(kernel_file.kimg(), preset_off);
    let backup = preset_header_backup(&preset);
    kernel_file.kimg_mut()[..HDR_BACKUP_SIZE].copy_from_slice(&backup);
    let kimg_size = if saved > 0 {
        saved as usize
    } else {
        preset_off
    };
    kernel_file.resize_kimg(kimg_size);
    kernel_file.write(out_path)
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
    let preset_off = find_preset(kernel_file.kimg())
        .ok_or_else(|| Error::bad_preset("not patched kernel image"))?;
    let mut preset: Preset = *read_preset(kernel_file.kimg(), preset_off);
    preset.setup.superkey = [0; SUPER_KEY_LEN];
    copy_cstr_into(&mut preset.setup.superkey, superkey.as_bytes());
    let end = preset_off + core::mem::size_of::<Preset>();
    kernel_file.kimg_mut()[preset_off..end].copy_from_slice(bytemuck::bytes_of(&preset));
    kernel_file.write(out_path)
}

pub fn dump_kallsym_path(kimg_path: &std::path::Path) -> Result<()> {
    kptools_base::log::set_log_enable(true);
    let probe = read_file(kimg_path)?;
    if is_x86_bzimage(&probe) {
        let mut image = load_x86_bzimage(kimg_path)?;
        let mut info = Kallsym::default();
        analyze_kallsym_info(&mut info, &mut image.flat, ArchType::X86_64, true)?;
        dump_all_symbols(&info, &image.flat);
        return Ok(());
    }
    let kf = KernelFile::read(kimg_path)?;
    let pimg = parse_image_patch_info(kf.kimg())?;
    let mut buf = kf.kimg()[..pimg.ori_kimg_len].to_vec();
    if let Some(po) = pimg.preset_offset {
        let backup = preset_header_backup(read_preset(kf.kimg(), po));
        buf[..HDR_BACKUP_SIZE].copy_from_slice(&backup);
    }
    let mut info = Kallsym::default();
    analyze_kallsym_info(&mut info, &mut buf, ArchType::Arm64, true)?;
    dump_all_symbols(&info, &buf);
    Ok(())
}

pub fn dump_ikconfig_path(kimg_path: &std::path::Path) -> Result<()> {
    kptools_base::log::set_log_enable(true);
    let probe = read_file(kimg_path)?;
    if is_x86_bzimage(&probe) {
        let image = load_x86_bzimage(kimg_path)?;
        return dump_all_ikconfig(&image.flat);
    }
    let kf = KernelFile::read(kimg_path)?;
    dump_all_ikconfig(kf.kimg())
}

fn bytes_to_hex(buf: &[u8]) -> String {
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn print_preset_info(preset: &Preset) {
    let ver_num = preset.header.kp_version.as_u32();
    let flags = preset.header.config_flags;
    let is_android = flags & CONFIG_ANDROID != 0;
    let is_debug = flags & CONFIG_DEBUG != 0;
    let is_x86 = flags & CONFIG_FLAG_X86_64 != 0;
    println!("{INFO_KP_IMG_SESSION}");
    println!("version=0x{ver_num:x}");
    println!("compile_time={}", cstr_trim(&preset.header.compile_time));
    println!(
        "config={},{}",
        if is_android { "android" } else { "linux" },
        if is_debug { "debug" } else { "release" }
    );
    println!("arch={}", if is_x86 { "x86_64" } else { "arm64" });
    println!("superkey={}", cstr_trim(&preset.setup.superkey));
    if ver_num > 0xa04 {
        println!(
            "root_superkey={}",
            bytes_to_hex(&preset.setup.root_superkey)
        );
    }
    println!("{INFO_ADDITIONAL_SESSION}");
    let additional = &preset.setup.additional;
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

pub fn print_kp_image_info_path(kpimg_path: &std::path::Path) -> Result<()> {
    let kpimg = read_file(kpimg_path)?;
    if kpimg.len() < core::mem::size_of::<Preset>() {
        return Err(Error::bad_preset("not a kpimg"));
    }
    let preset: &Preset = bytemuck::from_bytes(&kpimg[..core::mem::size_of::<Preset>()]);
    if preset.header.magic != *KP_MAGIC {
        return Err(Error::bad_preset("not a kpimg"));
    }
    print_preset_info(preset);
    println!();
    Ok(())
}

pub fn print_image_patch_info(pimg: &PatchedKimg, kimg: &[u8]) -> Result<()> {
    println!("{INFO_KERNEL_IMG_SESSION}");
    if let Some(off) = pimg.banner {
        let end = kimg[off..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|x| off + x)
            .unwrap_or(kimg.len());
        println!(
            "banner={}",
            std::str::from_utf8(&kimg[off..end]).unwrap_or("<non-utf8>")
        );
    }
    println!(
        "patched={}",
        if pimg.preset_offset.is_some() {
            "true"
        } else {
            "false"
        }
    );
    let Some(preset_off) = pimg.preset_offset else {
        return Ok(());
    };
    let preset: Preset = *read_preset(kimg, preset_off);
    print_preset_info(&preset);
    println!("{INFO_EXTRA_SESSION}");
    println!("num={}", pimg.embed_items.len());
    let mut cursor = preset_off + preset.setup.kpimg_size as usize;
    for (i, item) in pimg.embed_items.iter().enumerate() {
        let ty = ExtraType::from_i32(item.extra_type).unwrap_or(ExtraType::None);
        let args_size = item.args_size.max(0) as usize;
        let con_size = item.con_size.max(0) as usize;
        println!("[extra {i}]");
        println!("index={i}");
        println!("type={}", ty.str_tag());
        println!("name={}", cstr_trim(&item.name));
        println!("event={}", cstr_trim(&item.event));
        let priority = item.priority;
        println!("priority={priority}");
        println!("args_size=0x{args_size:x}");
        let args_off = cursor + PATCH_EXTRA_ITEM_LEN;
        let args = if args_size > 0 && args_off + args_size <= kimg.len() {
            std::str::from_utf8(&kimg[args_off..args_off + args_size]).unwrap_or("")
        } else {
            ""
        };
        println!("args={args}");
        println!("con_size=0x{con_size:x}");
        let flags = item.flags;
        println!("flags=0x{flags:x}");
        let con_off = args_off + args_size;
        if ty == ExtraType::Kpm && con_off + con_size <= kimg.len() {
            if let Ok(info) = get_kpm_info(&kimg[con_off..con_off + con_size]) {
                println!("version={}", info.version.as_deref().unwrap_or(""));
                println!("license={}", info.license.as_deref().unwrap_or(""));
                println!("author={}", info.author.as_deref().unwrap_or(""));
                println!("description={}", info.description.as_deref().unwrap_or(""));
            }
        }
        cursor = con_off + con_size;
    }
    Ok(())
}

pub fn print_image_patch_info_path(kimg_path: &std::path::Path) -> Result<()> {
    let probe = read_file(kimg_path)?;
    if is_x86_bzimage(&probe) {
        let image = load_x86_bzimage(kimg_path)?;
        let Some(off) = image.flat.windows(MAGIC_LEN).position(|w| w == KP_MAGIC) else {
            println!("{INFO_KERNEL_IMG_SESSION}");
            println!("patched=false");
            return Ok(());
        };
        if off + core::mem::size_of::<Preset>() <= image.flat.len() {
            println!("{INFO_KERNEL_IMG_SESSION}");
            println!("patched=true");
            print_preset_info(bytemuck::from_bytes(
                &image.flat[off..off + core::mem::size_of::<Preset>()],
            ));
            return Ok(());
        }
        return Err(Error::bad_preset("truncated x86 preset"));
    }
    let kf = KernelFile::read(kimg_path)?;
    let pimg = parse_image_patch_info(kf.kimg())?;
    print_image_patch_info(&pimg, kf.kimg())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_backup_primary_entry_validation() {
        let mut backup = [0u8; 8];
        backup[..4].copy_from_slice(&0x1400_0000u32.to_le_bytes());
        assert!(header_backup_has_valid_primary_entry(&backup));
        backup = [0; 8];
        backup[..2].copy_from_slice(b"MZ");
        backup[4..8].copy_from_slice(&0x1400_0001u32.to_le_bytes());
        assert!(header_backup_has_valid_primary_entry(&backup));
        assert!(!header_backup_has_valid_primary_entry(&[0; 8]));
    }

    #[test]
    fn supported_version_is_0134() {
        assert_eq!(KP_VERSION_U32, 0x0d04);
        ensure_supported_kpimg_version(0x0d04).unwrap();
        assert!(ensure_supported_kpimg_version(0x0d02).is_err());
    }

    #[test]
    fn legacy_extra_header_version_compatibility() {
        let mut item = PatchExtraItem {
            magic: *EXTRA_HDR_MAGIC,
            priority: 0,
            args_size: 0,
            con_size: 0,
            extra_type: ExtraType::KconfigLegacy.as_i32(),
            name: [0; EXTRA_NAME_LEN],
            event: [0; EXTRA_EVENT_LEN],
            flags: 0x1234,
            pad: [0; PATCH_EXTRA_ITEM_LEN
                - 4
                - 4
                - 4
                - 4
                - 4
                - EXTRA_NAME_LEN
                - EXTRA_EVENT_LEN
                - 4],
        };
        copy_cstr_into(&mut item.name, b"kconfig");
        assert!(is_legacy_kconfig_extra(&item));
        let sanitized_flags = sanitize_legacy_extra_item(item).flags;
        assert_eq!(sanitized_flags, 0);
    }

    #[test]
    fn hex_patch_roundtrip() {
        let mut img = vec![0xaa, 0xbb, 0xcc, 0xdd];
        hex_patch(&mut img, "BBCC", "1122").unwrap();
        assert_eq!(img, vec![0xaa, 0x11, 0x22, 0xdd]);
    }
}
