//! Symbol lookup helpers + map-area / patch-config fillers.
//!
//! Port of upstream `tools/symbol.{c,h}` at KernelPatch 0.13.2. Sits
//! on top of the kallsym parser and handles the couple of real-world
//! quirks: suffixed symbols (IPA-SRA produces `avc_denied.isra.5`),
//! pair-wise `PAC` / `AUT` instruction NOP-out inside the reserved
//! map area, GKI-aware map selection, usable-offset filtering, and
//! the fallback ladder when upstream renames symbols across kernel
//! revisions (`memblock_alloc_try_nid` taking over for
//! `memblock_{phys,virt}_alloc_try_nid`, `cgroup_init` for
//! `rest_init`, etc).

use kptools_base::{logi, Error, Result};

use crate::kallsym::{get_symbol_offset, get_symbol_offset_zero, on_each_symbol, Kallsym};
use crate::preset::{
    MapSymbol, PatchConfig, MAP_SYM_MEMBLOCK_ALLOC_TRY_NID, MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID,
    MAP_SYM_MEMBLOCK_VIRT_ALLOC_FROM_ALLOC_TRY_NID, MAP_SYM_MEMBLOCK_VIRT_ALLOC_TRY_NID,
};

/// Find a symbol whose full name starts with `prefix.` or `prefix$`
/// — gcc IPA-SRA / LTO tail variants. Upstream uses
/// `strstr(symbol, prefix) == symbol`; we mirror that exactly.
pub fn find_suffixed_symbol(info: &Kallsym, img: &[u8], prefix: &str) -> i32 {
    let prefix_bytes = prefix.as_bytes();
    let mut found: i32 = 0;
    let _ = on_each_symbol(info, img, |_i, _ty, sym, offset| {
        if sym.len() <= prefix_bytes.len() {
            return 0;
        }
        if !sym.starts_with(prefix_bytes) {
            return 0;
        }
        let next = sym[prefix_bytes.len()];
        if next != b'.' && next != b'$' {
            return 0;
        }
        // skip CFI jump-table shims
        if sym.windows(7).any(|w| w == b".cfi_jt") {
            return 0;
        }
        found = offset;
        1
    });
    found
}

/// `get_symbol_offset_exit` — return an offset or propagate an
/// error. The upstream version calls `exit()`; library callers want
/// the failure to surface through `Result`.
pub fn get_symbol_offset_exit(info: &Kallsym, img: &[u8], symbol: &str) -> Result<i32> {
    let off = get_symbol_offset(info, img, symbol);
    off.filter(|o| *o >= 0)
        .ok_or_else(|| Error::kallsym(format!("no symbol `{symbol}`")))
}

/// `try_get_symbol_offset_zero` — try the exact name first, fall
/// back to a suffixed match, return 0 when neither resolves.
pub fn try_get_symbol_offset_zero(info: &Kallsym, img: &[u8], symbol: &str) -> i32 {
    let off = get_symbol_offset_zero(info, img, symbol);
    if off > 0 {
        return off;
    }
    find_suffixed_symbol(info, img, symbol)
}

fn align_floor(v: i32, a: i32) -> i32 {
    (v / a) * a
}

fn align_ceil(v: i32, a: i32) -> i32 {
    if a == 0 {
        v
    } else {
        ((v + a - 1) / a) * a
    }
}

const NOP_INSN: u32 = 0xD503_201F;
/// `(insn & PAC_MASK) == PAC_PATTERN` — PACIBSP / PACIASP / PACDBSP /
/// PACDASP family.
const PAC_MASK: u32 = 0xFFFF_FD1F;
const PAC_PATTERN: u32 = 0xD503_211F;
const PAC_INSN: u32 = 0xD503_233F;

/// Upstream `is_usable_symbol_offset` — reject offsets that land in
/// the first/last page of the image (often relocation noise).
pub fn is_usable_symbol_offset(offset: i32, imglen: i32) -> bool {
    imglen >= 0x1000 && offset > 0 && offset <= imglen - 0x1000
}

/// Upstream `get_usable_symbol_offset_try` — exact name, then
/// suffixed, only accepting usable offsets.
pub fn get_usable_symbol_offset_try(info: &Kallsym, img: &[u8], imglen: i32, symbol: &str) -> i32 {
    let offset = get_symbol_offset_zero(info, img, symbol);
    if is_usable_symbol_offset(offset, imglen) {
        return offset;
    }
    let offset = find_suffixed_symbol(info, img, symbol);
    if is_usable_symbol_offset(offset, imglen) {
        return offset;
    }
    0
}

/// Candidates used by the runtime forward-scan path when
/// `kallsyms_lookup_name` is not directly usable.
const LOOKUP_ANCHOR_CANDIDATES: &[&str] = &[
    "show_stack",
    "dump_backtrace",
    "nmi_panic",
    "panic",
    "show_freq_kernel_log",
    "input_handle_event",
    "slow_avc_audit",
    "avc_denied",
    "tcp_init_sock",
    "udp_init_sock",
    "inet_create",
    "inet_release",
    "sock_init_data",
    "sk_alloc",
];

/// Candidates for the reserved map area anchor.
const MAP_ANCHOR_CANDIDATES: &[&str] = &[
    "tcp_init_sock",
    "udp_init_sock",
    "inet_create",
    "inet_release",
    "sock_init_data",
    "sk_alloc",
    "input_handle_event",
    "slow_avc_audit",
    "avc_denied",
    "nmi_panic",
    "panic",
    "kern_addr_valid",
    "set_memory_rw",
    "set_memory_ro",
    "free_initmem",
];

/// Upstream `select_symbol_lookup_anchor_offset`.
pub fn select_symbol_lookup_anchor_offset(
    info: &Kallsym,
    img: &[u8],
    imglen: i32,
) -> (i32, Option<&'static str>) {
    for name in LOOKUP_ANCHOR_CANDIDATES {
        let offset = get_usable_symbol_offset_try(info, img, imglen, name);
        if offset != 0 {
            return (offset, Some(*name));
        }
    }
    (0, None)
}

fn get_map_anchor_offset(info: &Kallsym, img: &[u8], imglen: i32) -> Result<(i32, &'static str)> {
    for name in MAP_ANCHOR_CANDIDATES {
        let offset = get_usable_symbol_offset_try(info, img, imglen, name);
        if offset != 0 {
            return Ok((offset, *name));
        }
    }
    Err(Error::kallsym("no usable map anchor symbol"))
}

/// `select_map_area` — pick the reserved slab we overwrite with
/// kpimg jumps.
///
/// 0.13.2 behaviour:
/// - choose the first usable map-anchor candidate (not just
///   `tcp_init_sock`);
/// - non-GKI kernels take the cold-text range starting at the
///   aligned-up anchor and skip the PAC-NOP pass;
/// - GKI kernels keep the previous PAC-pair NOP path, aligning the
///   anchor down to 16 bytes.
///
/// Returns `(map_start, max_size)`.
pub fn select_map_area(
    info: &Kallsym,
    img: &mut [u8],
    imglen: i32,
    is_gki: bool,
) -> Result<(i32, i32)> {
    let (addr, selected) = get_map_anchor_offset(info, img, imglen)?;
    logi!("select map anchor: {selected}, offset: 0x{addr:08x}");

    if !is_gki {
        // For non-GKI kernels, use the area starting from a cold
        // text symbol for mapping without PAC-pair surgery.
        let map_start = align_ceil(addr, 16);
        let max_size = 0x800;
        return Ok((map_start, max_size));
    }

    let map_start = align_floor(addr, 16);
    let max_size: i32 = 0x800;

    let mut count = 0_u32;
    let mut first_pac_seen = false;
    let mut last_pos = 0_u32;
    let asmbit = 4_i32;
    let mut i = 0_i32;
    while i < max_size {
        let at = (addr + i) as usize;
        if at + 4 > img.len() {
            break;
        }
        let insn = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
        if !first_pac_seen && insn == PAC_INSN && i < asmbit * 5 {
            first_pac_seen = true;
        }
        if (insn & PAC_MASK) == PAC_PATTERN {
            last_pos = i as u32;
            count += 1;
            img[at..at + 4].copy_from_slice(&NOP_INSN.to_le_bytes());
        }
        i += asmbit;
    }
    if !first_pac_seen {
        logi!("no first pac instruction found");
    }
    if !count.is_multiple_of(2) {
        logi!("pac verify not pair pos: {last_pos:x} count: {count}");
        let mut second_pos: i32 = 0;
        let mut j = max_size;
        while j < max_size * 2 {
            let at = (addr + j) as usize;
            if at + 4 > img.len() {
                break;
            }
            let insn = u32::from_le_bytes(img[at..at + 4].try_into().unwrap());
            if (insn & PAC_MASK) == PAC_PATTERN {
                second_pos = j;
                break;
            }
            j += asmbit;
        }
        logi!("second_pos: {second_pos:x}");
        if second_pos != 0 {
            let at = (addr + second_pos) as usize;
            if at + 4 <= img.len() {
                img[at..at + 4].copy_from_slice(&NOP_INSN.to_le_bytes());
            }
        }
    }
    Ok((map_start, max_size))
}

/// Port of upstream `fillin_map_symbol`. Resolves the five memblock
/// relocation symbols + records which phys/virt alloc fallback was
/// selected via the two type fields added in 0.13.2.
///
/// Host/target endianness swap lives in the caller (patch.rs); we
/// write native-endian values here. The whole struct is zeroed
/// first so unused type fields stay at `MAP_SYM_NONE`.
pub fn fillin_map_symbol(info: &Kallsym, img: &[u8]) -> Result<MapSymbol> {
    let mut symbol = MapSymbol {
        memblock_reserve_relo: 0,
        memblock_free_relo: 0,
        memblock_phys_alloc_relo: 0,
        memblock_virt_alloc_relo: 0,
        memblock_mark_nomap_relo: 0,
        memblock_phys_alloc_type: 0,
        memblock_virt_alloc_type: 0,
    };

    symbol.memblock_reserve_relo = get_symbol_offset_exit(info, img, "memblock_reserve")? as u64;
    symbol.memblock_free_relo = get_symbol_offset_exit(info, img, "memblock_free")? as u64;
    symbol.memblock_mark_nomap_relo =
        get_symbol_offset_zero(info, img, "memblock_mark_nomap") as u64;

    symbol.memblock_phys_alloc_relo =
        get_symbol_offset_zero(info, img, "memblock_phys_alloc_try_nid") as u64;
    if symbol.memblock_phys_alloc_relo != 0 {
        symbol.memblock_phys_alloc_type = MAP_SYM_MEMBLOCK_PHYS_ALLOC_TRY_NID;
    }

    symbol.memblock_virt_alloc_relo =
        get_symbol_offset_zero(info, img, "memblock_virt_alloc_try_nid") as u64;
    if symbol.memblock_virt_alloc_relo != 0 {
        symbol.memblock_virt_alloc_type = MAP_SYM_MEMBLOCK_VIRT_ALLOC_TRY_NID;
    }

    let memblock_alloc_try_nid = get_symbol_offset_zero(info, img, "memblock_alloc_try_nid") as u64;
    if symbol.memblock_phys_alloc_relo == 0 && memblock_alloc_try_nid != 0 {
        symbol.memblock_phys_alloc_relo = memblock_alloc_try_nid;
        symbol.memblock_phys_alloc_type = MAP_SYM_MEMBLOCK_ALLOC_TRY_NID;
    }
    if symbol.memblock_virt_alloc_relo == 0 && memblock_alloc_try_nid != 0 {
        symbol.memblock_virt_alloc_relo = memblock_alloc_try_nid;
        symbol.memblock_virt_alloc_type = MAP_SYM_MEMBLOCK_VIRT_ALLOC_FROM_ALLOC_TRY_NID;
    }

    if symbol.memblock_phys_alloc_relo == 0 {
        return Err(Error::kallsym(
            "no symbol memblock_phys_alloc_try_nid or memblock_alloc_try_nid",
        ));
    }
    if symbol.memblock_virt_alloc_relo == 0 {
        return Err(Error::kallsym(
            "no symbol memblock_virt_alloc_try_nid or memblock_alloc_try_nid",
        ));
    }
    if symbol.memblock_phys_alloc_type == MAP_SYM_MEMBLOCK_ALLOC_TRY_NID {
        logi!("use memblock_alloc_try_nid as map phys alloc");
    }

    Ok(symbol)
}

/// Port of upstream `fillin_patch_config`. Resolves every kernel
/// symbol the kpimg patch hook wraps. `is_android = true` makes the
/// missing-`avc_denied` case fatal (upstream behaviour).
pub fn fillin_patch_config(
    info: &Kallsym,
    img: &[u8],
    imglen: i32,
    is_android: bool,
) -> Result<PatchConfig> {
    let mut cfg = PatchConfig {
        kallsyms_lookup_name: 0,
        printk: 0,
        panic: 0,
        rest_init: 0,
        cgroup_init: 0,
        kernel_init: 0,
        report_cfi_failure: 0,
        __cfi_slowpath_diag: 0,
        __cfi_slowpath: 0,
        copy_process: 0,
        cgroup_post_fork: 0,
        avc_denied: 0,
        slow_avc_audit: 0,
        input_handle_event: 0,
        patch_su_config: 0,
        pad: [0; crate::preset::PATCH_CONFIG_LEN - 14 * 8 - 1],
    };

    cfg.kallsyms_lookup_name =
        get_usable_symbol_offset_try(info, img, imglen, "kallsyms_lookup_name") as u64;
    cfg.printk = get_symbol_offset_zero(info, img, "printk") as u64;
    if cfg.printk == 0 {
        cfg.printk = get_symbol_offset_zero(info, img, "_printk") as u64;
    }
    if cfg.printk == 0 {
        return Err(Error::kallsym("no symbol printk"));
    }

    cfg.panic = get_symbol_offset_zero(info, img, "panic") as u64;
    cfg.rest_init = try_get_symbol_offset_zero(info, img, "rest_init") as u64;
    if cfg.rest_init == 0 {
        cfg.cgroup_init = try_get_symbol_offset_zero(info, img, "cgroup_init") as u64;
    }
    if cfg.rest_init == 0 && cfg.cgroup_init == 0 {
        return Err(Error::kallsym("no symbol rest_init"));
    }

    cfg.kernel_init = try_get_symbol_offset_zero(info, img, "kernel_init") as u64;
    cfg.report_cfi_failure = get_symbol_offset_zero(info, img, "report_cfi_failure") as u64;
    cfg.__cfi_slowpath_diag = get_symbol_offset_zero(info, img, "__cfi_slowpath_diag") as u64;
    cfg.__cfi_slowpath = get_symbol_offset_zero(info, img, "__cfi_slowpath") as u64;

    cfg.copy_process = try_get_symbol_offset_zero(info, img, "copy_process") as u64;
    if cfg.copy_process == 0 {
        cfg.cgroup_post_fork = get_symbol_offset_zero(info, img, "cgroup_post_fork") as u64;
    }
    if cfg.copy_process == 0 && cfg.cgroup_post_fork == 0 {
        return Err(Error::kallsym("no symbol copy_process"));
    }

    cfg.avc_denied = try_get_symbol_offset_zero(info, img, "avc_denied") as u64;
    if cfg.avc_denied == 0 && is_android {
        return Err(Error::kallsym("no symbol avc_denied"));
    }
    cfg.slow_avc_audit = try_get_symbol_offset_zero(info, img, "slow_avc_audit") as u64;
    cfg.input_handle_event = get_symbol_offset_zero(info, img, "input_handle_event") as u64;

    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn usable_offset_bounds() {
        assert!(!is_usable_symbol_offset(0, 0x2000));
        assert!(!is_usable_symbol_offset(0x100, 0x800));
        assert!(is_usable_symbol_offset(0x1000, 0x3000));
        assert!(!is_usable_symbol_offset(0x2800, 0x3000));
        assert!(is_usable_symbol_offset(0x2000, 0x3000));
    }

    #[test]
    fn align_helpers() {
        assert_eq!(align_floor(0x1234, 16), 0x1230);
        assert_eq!(align_ceil(0x1231, 16), 0x1240);
        assert_eq!(align_ceil(0x1230, 16), 0x1230);
    }
}
