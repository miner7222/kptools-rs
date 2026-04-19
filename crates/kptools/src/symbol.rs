//! Symbol lookup helpers + map-area / patch-config fillers.
//!
//! Port of upstream `tools/symbol.{c,h}`. Sits on top of the kallsym
//! parser and handles the couple of real-world quirks: suffixed
//! symbols (IPA-SRA produces `avc_denied.isra.5`), pair-wise `PAC` /
//! `AUT` instruction NOP-out inside the reserved map area, and the
//! fallback ladder when upstream renames symbols across kernel
//! revisions (`memblock_alloc_try_nid` taking over for
//! `memblock_{phys,virt}_alloc_try_nid`, `cgroup_init` for
//! `rest_init`, etc).

use kptools_base::{Error, Result, logi};

use crate::kallsym::{Kallsym, get_symbol_offset, get_symbol_offset_zero, on_each_symbol};
use crate::preset::{MapSymbol, PatchConfig};

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

const NOP_INSN: u32 = 0xD503_201F;
/// `(insn & PAC_MASK) == PAC_PATTERN` — PACIBSP / PACIASP / PACDBSP /
/// PACDASP family.
const PAC_MASK: u32 = 0xFFFF_FD1F;
const PAC_PATTERN: u32 = 0xD503_211F;
const PAC_INSN: u32 = 0xD503_233F;

/// `select_map_area` — pick the reserved slab we overwrite with
/// kpimg jumps. Upstream anchors on `tcp_init_sock`, aligns down to
/// 16 bytes, reserves 0x800 bytes, then NOPs out every PAC-family
/// instruction inside that window. Returns `(map_start, max_size)`.
pub fn select_map_area(info: &Kallsym, img: &mut [u8]) -> Result<(i32, i32)> {
    let addr = get_symbol_offset_exit(info, img, "tcp_init_sock")?;
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
    if count % 2 != 0 {
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
/// relocation symbols + folds the `memblock_alloc_try_nid` fallback
/// when the `_phys` / `_virt` variants aren't exported.
///
/// Host/target endianness swap lives in the caller (patch.rs); we
/// write native-endian values here.
pub fn fillin_map_symbol(info: &Kallsym, img: &[u8]) -> Result<MapSymbol> {
    let memblock_reserve = get_symbol_offset_exit(info, img, "memblock_reserve")? as u64;
    let memblock_free = get_symbol_offset_exit(info, img, "memblock_free")? as u64;
    let memblock_mark_nomap = get_symbol_offset_zero(info, img, "memblock_mark_nomap") as u64;

    let mut memblock_phys_alloc =
        get_symbol_offset_zero(info, img, "memblock_phys_alloc_try_nid") as u64;
    let mut memblock_virt_alloc =
        get_symbol_offset_zero(info, img, "memblock_virt_alloc_try_nid") as u64;
    if memblock_phys_alloc == 0 && memblock_virt_alloc == 0 {
        // Explicit message matches upstream's first check.
        // (The C code re-checks after the `memblock_alloc_try_nid`
        // fallback, but returning early here is the same result.)
    }
    let memblock_alloc_try_nid =
        get_symbol_offset_zero(info, img, "memblock_alloc_try_nid") as u64;
    if memblock_phys_alloc == 0 {
        memblock_phys_alloc = memblock_alloc_try_nid;
    }
    if memblock_virt_alloc == 0 {
        memblock_virt_alloc = memblock_alloc_try_nid;
    }
    if memblock_phys_alloc == 0 && memblock_virt_alloc == 0 {
        return Err(Error::kallsym("no symbol memblock_alloc"));
    }

    Ok(MapSymbol {
        memblock_reserve_relo: memblock_reserve,
        memblock_free_relo: memblock_free,
        memblock_phys_alloc_relo: memblock_phys_alloc,
        memblock_virt_alloc_relo: memblock_virt_alloc,
        memblock_mark_nomap_relo: memblock_mark_nomap,
    })
}

/// Port of upstream `fillin_patch_config`. Resolves every kernel
/// symbol the kpimg patch hook wraps. `is_android = true` makes the
/// missing-`avc_denied` case fatal (upstream behaviour).
pub fn fillin_patch_config(
    info: &Kallsym,
    img: &[u8],
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
