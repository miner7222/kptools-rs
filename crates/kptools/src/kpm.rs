//! KPM (Kernel Patch Module) ELF inspection.
//!
//! Port of upstream `tools/kpm.{c,h}`. A KPM is a small relocatable
//! ELF64 object that carries a `.kpm.info` section stuffed with
//! `key=value\0` strings describing the module. We only need the
//! read-side: given a `.kpm` file's bytes, pull out `name`,
//! `version`, `license`, `author`, `description`.
//!
//! The upstream port rolls its own ELF walker to avoid a libelf
//! dependency. The Rust side leans on the `object` crate but
//! deliberately keeps the path small — the rest of the patch
//! pipeline still ships pure-data structs, so we do the ELF parse
//! by hand too (zero external deps here, matches base crate
//! philosophy).

use bytemuck::{Pod, Zeroable};

use kptools_base::{Error, Result};

pub const INFO_EXTRA_KPM_SESSION: &str = "[kpm]";

pub const EI_NIDENT: usize = 16;
pub const ELFMAG: &[u8; 4] = b"\x7fELF";
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_AARCH64: u16 = 183;
pub const ET_REL: u16 = 1;

pub const SHT_NOBITS: u32 = 8;
pub const SHF_ALLOC: u64 = 1 << 1;

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Elf64Ehdr {
    e_ident: [u8; EI_NIDENT],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

#[repr(C, packed)]
#[derive(Clone, Copy, Pod, Zeroable)]
struct Elf64Shdr {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// Mirrors upstream `kpm_info_t`. All fields are `Option<String>`
/// because a KPM may omit any tag — upstream's `get_modinfo`
/// returns `NULL` there.
#[derive(Default, Debug, Clone)]
pub struct KpmInfo {
    pub name: Option<String>,
    pub version: Option<String>,
    pub license: Option<String>,
    pub author: Option<String>,
    pub description: Option<String>,
}

/// Parse `kpm` (full ELF bytes) and extract the `.kpm.info`
/// section's `key=value` pairs. Returns an error when the ELF
/// header or the `.kpm.info` section is malformed.
pub fn get_kpm_info(kpm: &[u8]) -> Result<KpmInfo> {
    if kpm.len() < core::mem::size_of::<Elf64Ehdr>() {
        return Err(Error::bad_kpm("file too small for ELF header"));
    }
    let hdr: &Elf64Ehdr = bytemuck::from_bytes(&kpm[..core::mem::size_of::<Elf64Ehdr>()]);

    // Header sanity.
    if &hdr.e_ident[..4] != ELFMAG {
        return Err(Error::bad_kpm("bad ELF magic"));
    }
    if hdr.e_ident[4] != ELFCLASS64 {
        return Err(Error::bad_kpm("not ELFCLASS64"));
    }
    if hdr.e_ident[5] != ELFDATA2LSB {
        return Err(Error::bad_kpm("not little-endian ELF"));
    }
    let e_type = hdr.e_type;
    let e_machine = hdr.e_machine;
    let e_shentsize = hdr.e_shentsize;
    if e_type != ET_REL {
        return Err(Error::bad_kpm(format!("not ET_REL (got {e_type})")));
    }
    if e_machine != EM_AARCH64 {
        return Err(Error::bad_kpm(format!("not EM_AARCH64 (got {e_machine})")));
    }
    if e_shentsize as usize != core::mem::size_of::<Elf64Shdr>() {
        return Err(Error::bad_kpm(format!(
            "e_shentsize mismatch: got {e_shentsize}, want {}",
            core::mem::size_of::<Elf64Shdr>()
        )));
    }

    let shoff = hdr.e_shoff as usize;
    let shnum = hdr.e_shnum as usize;
    let shentsize = hdr.e_shentsize as usize;
    if shoff >= kpm.len() || shoff + shnum * shentsize > kpm.len() {
        return Err(Error::bad_kpm("section header table out of range"));
    }

    let sechdrs = parse_shdrs(kpm, shoff, shnum)?;

    // Resolve the section name string table via `e_shstrndx`.
    let shstrndx = hdr.e_shstrndx as usize;
    if shstrndx >= sechdrs.len() {
        return Err(Error::bad_kpm("bad e_shstrndx"));
    }
    let secstrings_hdr = &sechdrs[shstrndx];
    let secstrings_off = secstrings_hdr.sh_offset as usize;
    let secstrings_size = secstrings_hdr.sh_size as usize;
    if secstrings_off + secstrings_size > kpm.len() {
        return Err(Error::bad_kpm("secstrings section out of range"));
    }
    let secstrings = &kpm[secstrings_off..secstrings_off + secstrings_size];

    let info_sec = find_sec(&sechdrs, secstrings, ".kpm.info")
        .ok_or_else(|| Error::bad_kpm("no .kpm.info section"))?;
    let info_off = info_sec.sh_offset as usize;
    let info_size = info_sec.sh_size as usize;
    if info_sec.sh_type != SHT_NOBITS && info_off + info_size > kpm.len() {
        return Err(Error::bad_kpm(".kpm.info out of range"));
    }
    let info_bytes = &kpm[info_off..info_off + info_size];

    let mut out = KpmInfo::default();
    out.name = modinfo_lookup(info_bytes, "name");
    out.version = modinfo_lookup(info_bytes, "version");
    out.license = modinfo_lookup(info_bytes, "license");
    out.author = modinfo_lookup(info_bytes, "author");
    out.description = modinfo_lookup(info_bytes, "description");
    Ok(out)
}

/// Port of upstream `print_kpm_info_path`. Reads `kpm_path`, prints
/// `[kpm]` + `name/version/license/author/description` to stdout.
pub fn print_kpm_info_path(kpm_path: &std::path::Path) -> Result<()> {
    let bytes = kptools_base::io::read_file(kpm_path)?;
    let info = get_kpm_info(&bytes)?;
    println!("{INFO_EXTRA_KPM_SESSION}");
    println!("name={}", info.name.as_deref().unwrap_or(""));
    println!("version={}", info.version.as_deref().unwrap_or(""));
    println!("license={}", info.license.as_deref().unwrap_or(""));
    println!("author={}", info.author.as_deref().unwrap_or(""));
    println!("description={}", info.description.as_deref().unwrap_or(""));
    Ok(())
}

fn parse_shdrs(kpm: &[u8], shoff: usize, shnum: usize) -> Result<Vec<Elf64Shdr>> {
    let mut out = Vec::with_capacity(shnum);
    let stride = core::mem::size_of::<Elf64Shdr>();
    for i in 0..shnum {
        let start = shoff + i * stride;
        out.push(*bytemuck::from_bytes::<Elf64Shdr>(&kpm[start..start + stride]));
    }
    Ok(out)
}

fn find_sec<'a>(
    sechdrs: &'a [Elf64Shdr],
    secstrings: &[u8],
    name: &str,
) -> Option<&'a Elf64Shdr> {
    for shdr in sechdrs.iter().skip(1) {
        if shdr.sh_flags & SHF_ALLOC == 0 {
            continue;
        }
        let n = shdr.sh_name as usize;
        if n >= secstrings.len() {
            continue;
        }
        let end = secstrings[n..].iter().position(|&b| b == 0).unwrap_or(0);
        if &secstrings[n..n + end] == name.as_bytes() {
            return Some(shdr);
        }
    }
    None
}

/// Walk the `.kpm.info` section's `\0`-delimited `key=value` string
/// list and return the value for `tag`. Mirrors upstream
/// `get_modinfo`.
fn modinfo_lookup(info: &[u8], tag: &str) -> Option<String> {
    let needle = format!("{tag}=");
    let mut i = 0usize;
    while i < info.len() {
        let Some(end) = info[i..].iter().position(|&b| b == 0) else {
            break;
        };
        let slice = &info[i..i + end];
        if slice.starts_with(needle.as_bytes()) {
            let value = &slice[needle.len()..];
            return Some(String::from_utf8_lossy(value).into_owned());
        }
        i += end;
        // Skip the null terminator + any run of subsequent nulls
        // (upstream's `next_string` walks the same shape).
        while i < info.len() && info[i] == 0 {
            i += 1;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_elf_with_modinfo(info_bytes: &[u8]) -> Vec<u8> {
        let ehdr_size = core::mem::size_of::<Elf64Ehdr>();
        let shdr_size = core::mem::size_of::<Elf64Shdr>();

        let mut buf = vec![0u8; ehdr_size];
        // Place `.kpm.info` contents right after the ehdr.
        let info_off = buf.len();
        buf.extend_from_slice(info_bytes);
        while buf.len() % 8 != 0 {
            buf.push(0);
        }

        // Section name strings: "" (index 0), ".kpm.info" (index 1).
        let strtab_off = buf.len();
        buf.push(0); // index 0: empty
        let kpm_info_name_idx = buf.len() - strtab_off;
        buf.extend_from_slice(b".kpm.info\0");
        let shstr_name_idx = buf.len() - strtab_off;
        buf.extend_from_slice(b".shstrtab\0");
        while buf.len() % 8 != 0 {
            buf.push(0);
        }
        let strtab_size = buf.len() - strtab_off;

        // Three section headers:
        //   0: SHN_UNDEF (zeroed)
        //   1: .kpm.info
        //   2: .shstrtab
        let shoff = buf.len();
        buf.extend_from_slice(&vec![0u8; 3 * shdr_size]);

        let mut shdrs: [Elf64Shdr; 3] = [Elf64Shdr::zeroed(); 3];
        shdrs[1] = Elf64Shdr {
            sh_name: kpm_info_name_idx as u32,
            sh_type: 1, // SHT_PROGBITS
            sh_flags: SHF_ALLOC,
            sh_addr: 0,
            sh_offset: info_off as u64,
            sh_size: info_bytes.len() as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        };
        shdrs[2] = Elf64Shdr {
            sh_name: shstr_name_idx as u32,
            sh_type: 3, // SHT_STRTAB
            sh_flags: 0,
            sh_addr: 0,
            sh_offset: strtab_off as u64,
            sh_size: strtab_size as u64,
            sh_link: 0,
            sh_info: 0,
            sh_addralign: 1,
            sh_entsize: 0,
        };
        for (i, shdr) in shdrs.iter().enumerate() {
            let off = shoff + i * shdr_size;
            buf[off..off + shdr_size].copy_from_slice(bytemuck::bytes_of(shdr));
        }

        // Write ehdr last so offsets point at the final positions.
        let ehdr = Elf64Ehdr {
            e_ident: {
                let mut id = [0u8; EI_NIDENT];
                id[..4].copy_from_slice(ELFMAG);
                id[4] = ELFCLASS64;
                id[5] = ELFDATA2LSB;
                id[6] = 1; // EV_CURRENT
                id
            },
            e_type: ET_REL,
            e_machine: EM_AARCH64,
            e_version: 1,
            e_entry: 0,
            e_phoff: 0,
            e_shoff: shoff as u64,
            e_flags: 0,
            e_ehsize: ehdr_size as u16,
            e_phentsize: 0,
            e_phnum: 0,
            e_shentsize: shdr_size as u16,
            e_shnum: 3,
            e_shstrndx: 2,
        };
        buf[..ehdr_size].copy_from_slice(bytemuck::bytes_of(&ehdr));
        buf
    }

    #[test]
    fn extracts_modinfo_tags() {
        let info = b"name=nohello\0version=1.8.2\0license=GPL\0author=user\0description=demo\0";
        let elf = mk_elf_with_modinfo(info);
        let got = get_kpm_info(&elf).unwrap();
        assert_eq!(got.name.as_deref(), Some("nohello"));
        assert_eq!(got.version.as_deref(), Some("1.8.2"));
        assert_eq!(got.license.as_deref(), Some("GPL"));
        assert_eq!(got.author.as_deref(), Some("user"));
        assert_eq!(got.description.as_deref(), Some("demo"));
    }

    #[test]
    fn missing_tags_are_none() {
        let info = b"name=only\0";
        let elf = mk_elf_with_modinfo(info);
        let got = get_kpm_info(&elf).unwrap();
        assert_eq!(got.name.as_deref(), Some("only"));
        assert!(got.version.is_none());
        assert!(got.license.is_none());
    }

    #[test]
    fn rejects_bad_magic() {
        let buf = vec![0u8; 128];
        assert!(get_kpm_info(&buf).is_err());
    }

    #[test]
    fn rejects_not_aarch64() {
        let info = b"name=x\0";
        let mut elf = mk_elf_with_modinfo(info);
        // Patch e_machine to something else.
        elf[0x12..0x14].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        assert!(get_kpm_info(&elf).is_err());
    }
}
