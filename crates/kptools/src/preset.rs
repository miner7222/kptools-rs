//! On-disk preset structures + constants.
//!
//! Direct port of upstream `kernel/include/preset.h`, pinned to
//! tag 0.13.1. Field order, packing, and embedded size constants
//! match the C build byte-for-byte so a patched kernel produced by
//! this crate is interchangeable with the one produced by the
//! reference `kptools` binary.
//!
//! Every struct derives `bytemuck::{Pod, Zeroable}` so callers can
//! reinterpret an mmap slice straight into `&preset_t` with zero
//! copying. Size tests at the bottom pin every `_Static_assert` the
//! C header carries — if one of those trips, the layout has drifted
//! and downstream offsets would silently corrupt a patched kernel.

use bytemuck::{Pod, Zeroable};

// ---------------------------------------------------------------------------
// Magic + size constants
// ---------------------------------------------------------------------------

/// `KP_MAGIC` — the 6-char tag that marks a patched kernel image.
/// The trailing `\0\0` rounds it out to `MAGIC_LEN = 8` so upstream
/// can search for an 8-byte literal inside the mmap. We keep the
/// full 8-byte padded form here.
pub const KP_MAGIC: &[u8; MAGIC_LEN] = b"KP1158\0\0";
pub const MAGIC_LEN: usize = 0x8;

pub const KP_HEADER_SIZE: usize = 0x40;
pub const SUPER_KEY_LEN: usize = 0x40;
pub const ROOT_SUPER_KEY_HASH_LEN: usize = 0x20;
pub const SETUP_PRESERVE_LEN: usize = 0x40;
pub const HDR_BACKUP_SIZE: usize = 0x8;
pub const COMPILE_TIME_LEN: usize = 0x18;
pub const MAP_MAX_SIZE: usize = 0xa00;
pub const HOOK_ALLOC_SIZE: usize = 1 << 20;
pub const MEMORY_ROX_SIZE: usize = 4 << 20;
pub const MEMORY_RW_SIZE: usize = 2 << 20;
pub const MAP_ALIGN: usize = 0x10;

pub const CONFIG_DEBUG: u64 = 1 << 0;
pub const CONFIG_ANDROID: u64 = 1 << 1;

pub const MAP_SYMBOL_NUM: usize = 5;
pub const MAP_SYMBOL_SIZE: usize = MAP_SYMBOL_NUM * 8;

pub const PATCH_CONFIG_LEN: usize = 512;
pub const ADDITIONAL_LEN: usize = 512;
pub const PATCH_EXTRA_ITEM_LEN: usize = 128;

pub const EXTRA_ITEM_MAX_NUM: usize = 32;
pub const EXTRA_ALIGN: usize = 0x10;
pub const EXTRA_NAME_LEN: usize = 0x20;
pub const EXTRA_EVENT_LEN: usize = 0x20;
pub const EXTRA_HDR_MAGIC: &[u8; 4] = b"kpe\0";

// ---------------------------------------------------------------------------
// Extra item types (upstream `EXTRA_TYPE_*`)
// ---------------------------------------------------------------------------

#[repr(i32)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExtraType {
    None = 0,
    Kpm = 1,
    Shell = 2,
    Exec = 3,
    Raw = 4,
    AndroidRc = 5,
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
        }
    }
}

// Event-name constants — surfaced as str so callers can write them
// into `patch_extra_item_t.event` without stringifying ints.
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

// ---------------------------------------------------------------------------
// Version header
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable, Debug)]
pub struct VersionT {
    /// Reserved byte the C union keeps at offset 0.
    pub reserved: u8,
    pub patch: u8,
    pub minor: u8,
    pub major: u8,
}

impl VersionT {
    pub fn as_u32(self) -> u32 {
        ((self.major as u32) << 16) | ((self.minor as u32) << 8) | self.patch as u32
    }
}

/// `version(major, minor, patch)` upstream macro.
pub const fn pack_version(major: u8, minor: u8, patch: u8) -> u32 {
    ((major as u32) << 16) | ((minor as u32) << 8) | (patch as u32)
}

// ---------------------------------------------------------------------------
// setup_header_t (64 bytes)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct SetupHeader {
    pub magic: [u8; MAGIC_LEN],
    pub kp_version: VersionT,
    pub reserved: u32,
    /// `config_t` alias for `u64` in the C source.
    pub config_flags: u64,
    pub compile_time: [u8; COMPILE_TIME_LEN],
    /// Tail of the 64-byte header union. Zero-filled.
    pub pad: [u8; KP_HEADER_SIZE
        - MAGIC_LEN
        - core::mem::size_of::<VersionT>()
        - 4
        - 8
        - COMPILE_TIME_LEN],
}

// ---------------------------------------------------------------------------
// map_symbol_t (40 bytes = 5 × u64)
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct MapSymbol {
    pub memblock_reserve_relo: u64,
    pub memblock_free_relo: u64,
    pub memblock_phys_alloc_relo: u64,
    pub memblock_virt_alloc_relo: u64,
    pub memblock_mark_nomap_relo: u64,
}

// ---------------------------------------------------------------------------
// patch_config_t (512 bytes — fixed cap on the C union)
// ---------------------------------------------------------------------------

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
    /// Zero-filled tail up to the 512-byte cap the C union enforces.
    pub pad: [u8; PATCH_CONFIG_LEN - 14 * 8 - 1],
}

// ---------------------------------------------------------------------------
// _patch_extra_item (128 bytes)
// ---------------------------------------------------------------------------

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
    pub pad: [u8; PATCH_EXTRA_ITEM_LEN - 4 - 4 - 4 - 4 - 4 - EXTRA_NAME_LEN - EXTRA_EVENT_LEN],
}

// ---------------------------------------------------------------------------
// setup_preset_t (current layout — version > 0xa04)
// ---------------------------------------------------------------------------

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
    /// `uint8_t __[SETUP_PRESERVE_LEN]` in the C header.
    pub preserve: [u8; SETUP_PRESERVE_LEN],
    pub patch_config: PatchConfig,
    pub additional: [u8; ADDITIONAL_LEN],
}

// ---------------------------------------------------------------------------
// preset_t = setup_header_t + setup_preset_t
// ---------------------------------------------------------------------------

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
pub struct Preset {
    pub header: SetupHeader,
    pub setup: SetupPreset,
}

// ---------------------------------------------------------------------------
// Layout sanity checks — must match upstream `_Static_assert` lines.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn size_version_t() {
        assert_eq!(size_of::<VersionT>(), 4);
    }

    #[test]
    fn size_setup_header() {
        // Upstream `_Static_assert(sizeof(setup_header_t) == KP_HEADER_SIZE)`.
        assert_eq!(size_of::<SetupHeader>(), KP_HEADER_SIZE);
    }

    #[test]
    fn size_map_symbol() {
        assert_eq!(size_of::<MapSymbol>(), MAP_SYMBOL_SIZE);
    }

    #[test]
    fn size_patch_config() {
        assert_eq!(size_of::<PatchConfig>(), PATCH_CONFIG_LEN);
    }

    #[test]
    fn size_patch_extra_item() {
        assert_eq!(size_of::<PatchExtraItem>(), PATCH_EXTRA_ITEM_LEN);
    }

    #[test]
    fn size_setup_preset_current() {
        // Size isn't called out by a `_Static_assert` upstream, but
        // the field sequence is tight. Recompute the expected tally
        // to catch drift:
        //   4  version_t
        //   4  reserved
        //  12 × 8 = 96 i64 fields (kimg_size, kpimg_size,
        //          kernel_size, page_shift, setup_offset,
        //          start_offset, extra_size, map_offset,
        //          map_max_size, kallsyms_lookup_name_offset,
        //          paging_init_offset, printk_offset)
        //  40 map_symbol
        //   8 header_backup
        //  64 superkey
        //  32 root_superkey
        //  64 preserve
        // 512 patch_config
        // 512 additional
        let expected = 4 + 4 + 12 * 8 + 40 + 8 + 64 + 32 + 64 + 512 + 512;
        assert_eq!(size_of::<SetupPreset>(), expected);
    }

    #[test]
    fn size_preset() {
        assert_eq!(
            size_of::<Preset>(),
            size_of::<SetupHeader>() + size_of::<SetupPreset>()
        );
    }

    #[test]
    fn magic_is_kp1158() {
        assert_eq!(&KP_MAGIC[..6], b"KP1158");
        assert_eq!(KP_MAGIC[6], 0);
        assert_eq!(KP_MAGIC[7], 0);
    }

    #[test]
    fn extra_type_roundtrip() {
        for t in [
            ExtraType::None,
            ExtraType::Kpm,
            ExtraType::Shell,
            ExtraType::Exec,
            ExtraType::Raw,
            ExtraType::AndroidRc,
        ] {
            assert_eq!(ExtraType::from_i32(t.as_i32()), Some(t));
            assert_eq!(ExtraType::from_str_tag(t.str_tag()), Some(t));
        }
        assert_eq!(ExtraType::from_str_tag("bogus"), None);
    }

    #[test]
    fn version_pack_matches_u32() {
        assert_eq!(pack_version(0, 13, 1), 0x0d01);
        let v = VersionT {
            reserved: 0,
            patch: 1,
            minor: 13,
            major: 0,
        };
        assert_eq!(v.as_u32(), 0x0d01);
    }
}
