//! On-disk preset structures + constants.
//!
//! Direct port of upstream `kernel/include/preset.h`, pinned to
//! tag 0.13.8. Field order, packing, and embedded size constants
//! match the C build byte-for-byte so a patched kernel produced by
//! this crate is interchangeable with the reference `kptools` binary.

use bytemuck::{Pod, Zeroable};

pub const KP_MAGIC: &[u8; MAGIC_LEN] = b"KP1158\0\0";
pub const MAGIC_LEN: usize = 0x8;
pub const KP_HEADER_SIZE: usize = 0x40;
pub const SUPER_KEY_LEN: usize = 0x40;
pub const ROOT_SUPER_KEY_HASH_LEN: usize = 0x20;
pub const SETUP_PRESERVE_LEN: usize = 0x40;
pub const HDR_BACKUP_SIZE: usize = 0x8;
pub const COMPILE_TIME_LEN: usize = 0x18;
pub const MAP_MAX_SIZE: usize = 0x1000;
pub const HOOK_ALLOC_SIZE: usize = 1 << 20;
pub const MEMORY_ROX_SIZE: usize = 4 << 20;
pub const MEMORY_RW_SIZE: usize = 2 << 20;
pub const MAP_ALIGN: usize = 0x10;

pub const CONFIG_DEBUG: u64 = 1 << 0;
pub const CONFIG_ANDROID: u64 = 1 << 1;
pub const CONFIG_FLAG_X86_64: u64 = 1 << 2;
pub const KP_X86_ENTRY_OFFSET: usize = 0x600;

pub const KP_VERSION_MAJOR: u8 = 0;
pub const KP_VERSION_MINOR: u8 = 13;
pub const KP_VERSION_PATCH: u8 = 8;
pub const KP_VERSION_U32: u32 = pack_version(KP_VERSION_MAJOR, KP_VERSION_MINOR, KP_VERSION_PATCH);

pub const MAP_SYMBOL_NUM: usize = 7;
pub const MAP_SYMBOL_SIZE: usize = MAP_SYMBOL_NUM * 8;
pub const MAP_SYM_NONE: u64 = 0;
pub const MAP_SYM_RESOLVE: u64 = 1;
pub const MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID: u64 = 1;
pub const MAP_SYM_MEMBLOCK_ALLOC_TRY_NID: u64 = 2;
pub const MAP_SYM_MEMBLOCK_FIND_IN_RANGE: u64 = 3;
pub const MAP_SYM_MEMBLOCK_VIRT_ALLOC_TRY_NID: u64 = 1;
pub const MAP_SYM_MEMBLOCK_VIRT_ALLOC_FROM_ALLOC_TRY_NID: u64 = 2;

pub const PATCH_CONFIG_LEN: usize = 512;
pub const ADDITIONAL_LEN: usize = 512;
pub const PATCH_EXTRA_ITEM_LEN: usize = 128;
pub const EXTRA_ITEM_MAX_NUM: usize = 32;
pub const EXTRA_ALIGN: usize = 0x10;
pub const EXTRA_NAME_LEN: usize = 0x20;
pub const EXTRA_EVENT_LEN: usize = 0x20;
pub const EXTRA_HDR_MAGIC: &[u8; 4] = b"kpe\0";

pub const PATCH_EXTRA_HEADER_VERSION_LEGACY: u32 = 0;
pub const PATCH_EXTRA_HEADER_VERSION_MAGIC: u32 = 0x4b50_0000;
pub const PATCH_EXTRA_HEADER_VERSION_MASK: u32 = 0xffff_0000;
pub const PATCH_EXTRA_HEADER_VERSION_VALUE_MASK: u32 = 0x0000_ffff;

/// Rust equivalent of upstream `PATCH_EXTRA_FLAGS_GET_HEADER_VERSION`.
pub const fn extra_flags_get_header_version(flags: i32) -> u32 {
    let flags = flags as u32;
    if flags & PATCH_EXTRA_HEADER_VERSION_MASK == PATCH_EXTRA_HEADER_VERSION_MAGIC {
        flags & PATCH_EXTRA_HEADER_VERSION_VALUE_MASK
    } else {
        PATCH_EXTRA_HEADER_VERSION_LEGACY
    }
}

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraType {
    None = 0,
    Kpm = 1,
    Shell = 2,
    Exec = 3,
    Raw = 4,
    AndroidRc = 5,
    KconfigLegacy = 6,
}

impl ExtraType {
    pub fn as_i32(self) -> i32 {
        self as i32
    }

    pub fn from_i32(v: i32) -> Option<Self> {
        match v {
            0 => Some(Self::None),
            1 => Some(Self::Kpm),
            2 => Some(Self::Shell),
            3 => Some(Self::Exec),
            4 => Some(Self::Raw),
            5 => Some(Self::AndroidRc),
            6 => Some(Self::KconfigLegacy),
            _ => None,
        }
    }

    pub fn from_str_tag(s: &str) -> Option<Self> {
        Some(match s {
            "none" => Self::None,
            "kpm" => Self::Kpm,
            "shell" => Self::Shell,
            "exec" => Self::Exec,
            "raw" => Self::Raw,
            "android_rc" => Self::AndroidRc,
            "kconfig" => Self::KconfigLegacy,
            _ => return None,
        })
    }

    pub fn str_tag(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Kpm => "kpm",
            Self::Shell => "shell",
            Self::Exec => "exec",
            Self::Raw => "raw",
            Self::AndroidRc => "android_rc",
            Self::KconfigLegacy => "kconfig",
        }
    }
}

pub const EXTRA_EVENT_PAGING_INIT: &str = "paging-init";
pub const EXTRA_EVENT_PRE_KERNEL_INIT: &str = "pre-kernel-init";
pub const EXTRA_EVENT_KPM_DEFAULT: &str = EXTRA_EVENT_PRE_KERNEL_INIT;
pub const EXTRA_EVENT_POST_KERNEL_INIT: &str = "post-kernel-init";
pub const EXTRA_EVENT_PRE_FIRST_STAGE: &str = "pre-init-first-stage";
pub const EXTRA_EVENT_POST_FIRST_STAGE: &str = "post-init-first-stage";
pub const EXTRA_EVENT_PRE_EXEC_INIT: &str = "pre-exec-init";
pub const EXTRA_EVENT_POST_EXEC_INIT: &str = "post-exec-init";
pub const EXTRA_EVENT_PRE_SECOND_STAGE: &str = "pre-init-second-stage";
pub const EXTRA_EVENT_POST_SECOND_STAGE: &str = "post-init-second-stage";
pub const EXTRA_EVENT_EARLY_INIT: &str = "early-init";
pub const EXTRA_EVENT_INIT: &str = "init";
pub const EXTRA_EVENT_LATE_INIT: &str = "late-init";
pub const EXTRA_EVENT_POST_FS_DATA: &str = "post-fs-data";
pub const EXTRA_EVENT_BOOT_COMPLETED: &str = "boot-completed";

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable, Debug)]
pub struct VersionT {
    pub reserved: u8,
    pub patch: u8,
    pub minor: u8,
    pub major: u8,
}

impl VersionT {
    pub fn as_u32(self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | self.patch as u32
    }

    pub const fn new(major: u8, minor: u8, patch: u8) -> Self {
        Self {
            reserved: 0,
            patch,
            minor,
            major,
        }
    }
}

pub const fn pack_version(major: u8, minor: u8, patch: u8) -> u32 {
    ((major as u32) << 16) | ((minor as u32) << 8) | patch as u32
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct SetupHeader {
    pub magic: [u8; MAGIC_LEN],
    pub kp_version: VersionT,
    pub reserved: u32,
    pub config_flags: u64,
    pub compile_time: [u8; COMPILE_TIME_LEN],
    pub pad: [u8; KP_HEADER_SIZE
        - MAGIC_LEN
        - core::mem::size_of::<VersionT>()
        - 4
        - 8
        - COMPILE_TIME_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MapSymbol {
    pub memblock_reserve_relo: u64,
    pub memblock_free_relo: u64,
    pub memblock_phys_alloc_relo: u64,
    pub memblock_virt_alloc_relo: u64,
    pub memblock_mark_nomap_relo: u64,
    pub memblock_phys_alloc_type: u64,
    pub memblock_virt_alloc_type: u64,
}

pub const PATCH_CONFIG_SU_ENABLE: u8 = 0x1;
pub const PATCH_CONFIG_SU_HOOK_NO_WRAP: u8 = 0x2;
pub const PATCH_CONFIG_SU_ENABLE32: u8 = 0x2;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct PatchConfig {
    pub kallsyms_lookup_name: u64,
    pub printk: u64,
    pub panic: u64,
    pub rest_init: u64,
    pub cgroup_init: u64,
    pub kernel_init: u64,
    pub report_cfi_failure: u64,
    pub __cfi_slowpath_diag: u64,
    pub __cfi_slowpath: u64,
    pub copy_process: u64,
    pub cgroup_post_fork: u64,
    pub avc_denied: u64,
    pub slow_avc_audit: u64,
    pub input_handle_event: u64,
    pub patch_su_config: u8,
    pub pad: [u8; PATCH_CONFIG_LEN - 14 * 8 - 1],
}

const EXTRA_ITEM_FIXED: usize = 4 + 4 + 4 + 4 + 4 + EXTRA_NAME_LEN + EXTRA_EVENT_LEN + 4;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct PatchExtraItem {
    pub magic: [u8; 4],
    pub priority: i32,
    pub args_size: i32,
    pub con_size: i32,
    pub extra_type: i32,
    pub name: [u8; EXTRA_NAME_LEN],
    pub event: [u8; EXTRA_EVENT_LEN],
    pub flags: i32,
    pub pad: [u8; PATCH_EXTRA_ITEM_LEN - EXTRA_ITEM_FIXED],
}

pub const SETUP_PRESERVE_REMAINING: usize = SETUP_PRESERVE_LEN - 32;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct SetupPreset {
    pub kernel_version: VersionT,
    pub reserved: i32,
    pub kimg_size: i64,
    pub kpimg_size: i64,
    pub kernel_size: i64,
    pub page_shift: i64,
    pub setup_offset: i64,
    pub start_offset: i64,
    pub extra_size: i64,
    pub map_offset: i64,
    pub map_max_size: i64,
    pub kallsyms_lookup_name_offset: i64,
    pub paging_init_offset: i64,
    pub printk_offset: i64,
    pub map_symbol: MapSymbol,
    pub header_backup: [u8; HDR_BACKUP_SIZE],
    pub superkey: [u8; SUPER_KEY_LEN],
    pub root_superkey: [u8; ROOT_SUPER_KEY_HASH_LEN],
    pub sprintf_offset: i64,
    pub symbol_lookup_anchor_offset: i64,
    pub kconfig_offset: i64,
    pub kconfig_size: i64,
    pub preserve: [u8; SETUP_PRESERVE_REMAINING],
    pub patch_config: PatchConfig,
    pub additional: [u8; ADDITIONAL_LEN],
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Preset {
    pub header: SetupHeader,
    pub setup: SetupPreset,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::{offset_of, size_of};

    #[test]
    fn abi_sizes_match_upstream() {
        assert_eq!(size_of::<VersionT>(), 4);
        assert_eq!(size_of::<SetupHeader>(), KP_HEADER_SIZE);
        assert_eq!(size_of::<MapSymbol>(), MAP_SYMBOL_SIZE);
        assert_eq!(size_of::<PatchConfig>(), PATCH_CONFIG_LEN);
        assert_eq!(size_of::<PatchExtraItem>(), PATCH_EXTRA_ITEM_LEN);
        let expected = 4 + 4 + 12 * 8 + 56 + 8 + 64 + 32 + 32 + 32 + 512 + 512;
        assert_eq!(size_of::<SetupPreset>(), expected);
        assert_eq!(
            size_of::<Preset>(),
            size_of::<SetupHeader>() + size_of::<SetupPreset>()
        );
    }

    #[test]
    fn setup_field_offsets_match_upstream_macros() {
        assert_eq!(offset_of!(SetupPreset, kernel_version), 0);
        assert_eq!(offset_of!(SetupPreset, kimg_size), 8);
        assert_eq!(offset_of!(SetupPreset, kpimg_size), 16);
        assert_eq!(offset_of!(SetupPreset, kernel_size), 24);
        assert_eq!(offset_of!(SetupPreset, page_shift), 32);
        assert_eq!(offset_of!(SetupPreset, setup_offset), 40);
        assert_eq!(offset_of!(SetupPreset, start_offset), 48);
        assert_eq!(offset_of!(SetupPreset, extra_size), 56);
        assert_eq!(offset_of!(SetupPreset, map_offset), 64);
        assert_eq!(offset_of!(SetupPreset, map_max_size), 72);
        assert_eq!(offset_of!(SetupPreset, kallsyms_lookup_name_offset), 80);
        assert_eq!(offset_of!(SetupPreset, paging_init_offset), 88);
        assert_eq!(offset_of!(SetupPreset, printk_offset), 96);
        assert_eq!(offset_of!(SetupPreset, map_symbol), 104);
        assert_eq!(
            offset_of!(SetupPreset, header_backup),
            104 + MAP_SYMBOL_SIZE
        );
        assert_eq!(
            offset_of!(SetupPreset, superkey),
            104 + MAP_SYMBOL_SIZE + HDR_BACKUP_SIZE
        );
        assert_eq!(
            offset_of!(SetupPreset, root_superkey),
            104 + MAP_SYMBOL_SIZE + HDR_BACKUP_SIZE + SUPER_KEY_LEN
        );
        assert_eq!(
            offset_of!(SetupPreset, map_symbol) + offset_of!(MapSymbol, memblock_phys_alloc_type),
            104 + 5 * 8
        );
        assert_eq!(
            offset_of!(SetupPreset, map_symbol) + offset_of!(MapSymbol, memblock_virt_alloc_type),
            104 + 6 * 8
        );
        let root_off = offset_of!(SetupPreset, root_superkey);
        assert_eq!(
            offset_of!(SetupPreset, sprintf_offset),
            root_off + ROOT_SUPER_KEY_HASH_LEN
        );
        assert_eq!(
            offset_of!(SetupPreset, symbol_lookup_anchor_offset),
            root_off + ROOT_SUPER_KEY_HASH_LEN + 8
        );
        assert_eq!(
            offset_of!(SetupPreset, kconfig_offset),
            root_off + ROOT_SUPER_KEY_HASH_LEN + 16
        );
        assert_eq!(
            offset_of!(SetupPreset, kconfig_size),
            root_off + ROOT_SUPER_KEY_HASH_LEN + 24
        );
        assert_eq!(
            offset_of!(SetupPreset, patch_config),
            root_off + ROOT_SUPER_KEY_HASH_LEN + SETUP_PRESERVE_LEN
        );
    }

    #[test]
    fn extra_types_and_header_version() {
        for t in [
            ExtraType::None,
            ExtraType::Kpm,
            ExtraType::Shell,
            ExtraType::Exec,
            ExtraType::Raw,
            ExtraType::AndroidRc,
            ExtraType::KconfigLegacy,
        ] {
            assert_eq!(ExtraType::from_i32(t.as_i32()), Some(t));
            assert_eq!(ExtraType::from_str_tag(t.str_tag()), Some(t));
        }
        assert_eq!(extra_flags_get_header_version(0), 0);
        assert_eq!(extra_flags_get_header_version(0x4b50_0002), 2);
        assert_eq!(extra_flags_get_header_version(0x1234_0002), 0);
    }

    #[test]
    fn magic_is_kp1158() {
        assert_eq!(&KP_MAGIC[..6], b"KP1158");
        assert_eq!(KP_MAGIC[6], 0);
        assert_eq!(KP_MAGIC[7], 0);
    }

    #[test]
    fn version_pack_matches_0138() {
        assert_eq!(KP_VERSION_U32, 0x0d08);
        assert_eq!(VersionT::new(0, 13, 8).as_u32(), 0x0d08);
    }

    #[test]
    fn x86_constants_match_upstream() {
        assert_eq!(CONFIG_FLAG_X86_64, 1 << 2);
        assert_eq!(KP_X86_ENTRY_OFFSET, 0x600);
        assert_eq!(MAP_MAX_SIZE, 0x1000);
    }
}
