//! CLI dispatcher compatible with KernelPatch kptools 0.13.8.

use std::path::PathBuf;

use kptools_base::{Error, Result};

use crate::patch::{self, ExtraConfig, PatchArgs};
use crate::preset::ExtraType;

pub fn version_u32() -> u32 {
    crate::preset::KP_VERSION_U32
}

pub fn main(argv: Vec<String>) -> Result<i32> {
    if argv.len() < 2 {
        print_usage(&argv);
        return Ok(1);
    }

    if argv.len() > 3 {
        match argv[1].as_str() {
            "unpack-bzimage" => {
                kptools_base::log::set_log_enable(true);
                let image = crate::x86_64::load_x86_bzimage(std::path::Path::new(&argv[2]))?;
                kptools_base::io::write_file(std::path::Path::new(&argv[3]), &image.flat)?;
                kptools_base::logi!(
                    "x86 flat kernel written: {}, size: 0x{:x}",
                    argv[3],
                    image.flat.len()
                );
                return Ok(0);
            }
            "repack-bzimage" => {
                kptools_base::log::set_log_enable(true);
                let mut image = crate::x86_64::load_x86_bzimage(std::path::Path::new(&argv[2]))?;
                crate::x86_64::write_x86_bzimage(&mut image, std::path::Path::new(&argv[3]))?;
                return Ok(0);
            }
            _ => {}
        }
    }

    if argv.len() > 2 {
        match argv[1].as_str() {
            "unpack" => {
                kptools_base::log::set_log_enable(true);
                crate::bootimg::extract_kernel(
                    std::path::Path::new(&argv[2]),
                    std::path::Path::new("kernel"),
                )?;
                return Ok(0);
            }
            "unpacknolog" => {
                crate::bootimg::extract_kernel(
                    std::path::Path::new(&argv[2]),
                    std::path::Path::new("kernel"),
                )?;
                return Ok(0);
            }
            "repack" => {
                kptools_base::log::set_log_enable(true);
                let out = if argv.len() > 3 {
                    &argv[3]
                } else {
                    "new-boot.img"
                };
                crate::bootimg::repack_bootimg(
                    std::path::Path::new(&argv[2]),
                    std::path::Path::new("kernel"),
                    std::path::Path::new(out),
                )?;
                return Ok(0);
            }
            "sha1" => {
                let h = crate::bootimg::calculate_sha1(std::path::Path::new(&argv[2]))?;
                for b in h {
                    print!("{b:02x}");
                }
                println!();
                return Ok(0);
            }
            _ => {}
        }
    }

    let mut cmd: Option<char> = None;
    let mut kimg: Option<PathBuf> = None;
    let mut kpimg: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut superkey: Option<String> = None;
    let mut root_skey = false;
    let mut additional = Vec::new();
    let mut extras = Vec::new();

    let mut i = 1usize;
    while i < argv.len() {
        match argv[i].as_str() {
            "-h" | "--help" => {
                cmd = Some('h');
                i += 1;
            }
            "-v" | "--version" => {
                cmd = Some('v');
                i += 1;
            }
            "-p" | "--patch" => {
                cmd = Some('p');
                i += 1;
            }
            "-u" | "--unpatch" => {
                cmd = Some('u');
                i += 1;
            }
            "-r" | "--resetkey" => {
                cmd = Some('r');
                i += 1;
            }
            "-d" | "--dump" => {
                cmd = Some('d');
                i += 1;
            }
            "-f" | "--flag" => {
                cmd = Some('f');
                i += 1;
            }
            "-l" | "--list" => {
                cmd = Some('l');
                i += 1;
            }
            "-i" | "--image" => {
                kimg = Some(next_arg(&argv, i)?.into());
                i += 2;
            }
            "-k" | "--kpimg" => {
                kpimg = Some(next_arg(&argv, i)?.into());
                i += 2;
            }
            "-o" | "--out" => {
                out = Some(next_arg(&argv, i)?.into());
                i += 2;
            }
            "-s" | "--skey" => {
                superkey = Some(next_arg(&argv, i)?.to_string());
                i += 2;
            }
            "-S" | "--root-skey" => {
                superkey = Some(next_arg(&argv, i)?.to_string());
                root_skey = true;
                i += 2;
            }
            "-a" | "--addition" => {
                additional.push(next_arg(&argv, i)?.to_string());
                i += 2;
            }
            "-M" | "--embed-extra-path" => {
                let p = PathBuf::from(next_arg(&argv, i)?);
                extras.push(ExtraConfig::from_path(&p, ExtraType::Kpm)?);
                i += 2;
            }
            "-T" | "--extra-type" => {
                let value = next_arg(&argv, i)?;
                let ty = ExtraType::from_str_tag(value)
                    .ok_or_else(|| Error::invalid_arg(format!("invalid extra type: {value}")))?;
                if let Some(last) = extras.last_mut() {
                    last.extra_type = ty;
                    last.item.extra_type = ty.as_i32();
                }
                i += 2;
            }
            "-N" | "--extra-name" => {
                if let Some(last) = extras.last_mut() {
                    last.set_name = Some(next_arg(&argv, i)?.to_string());
                }
                i += 2;
            }
            "-V" | "--extra-event" => {
                if let Some(last) = extras.last_mut() {
                    last.set_event = Some(next_arg(&argv, i)?.to_string());
                }
                i += 2;
            }
            "-A" | "--extra-args" => {
                if let Some(last) = extras.last_mut() {
                    last.set_args = Some(next_arg(&argv, i)?.to_string());
                }
                i += 2;
            }
            other => {
                eprintln!("unknown flag: {other}");
                return Ok(1);
            }
        }
    }

    match cmd {
        Some('h') => {
            print_usage(&argv);
            Ok(0)
        }
        Some('v') => {
            println!("{:x}", version_u32());
            Ok(0)
        }
        Some('p') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            let kpimg = kpimg.ok_or_else(|| Error::invalid_arg("missing -k"))?;
            let out = out.ok_or_else(|| Error::invalid_arg("missing -o"))?;
            let (skey, root) = match superkey {
                Some(s) => (s, root_skey),
                None => (String::new(), true),
            };
            if crate::bootimg::is_bootimg(&kimg) {
                kptools_base::log::set_log_enable(true);
                kptools_base::logi!("detected Android boot image, patching kernel in place");
                crate::bootimg::patch_bootimg(
                    &kimg,
                    &kpimg,
                    &out,
                    &skey,
                    root,
                    &additional,
                    extras,
                )?;
            } else {
                patch::patch_update_img(PatchArgs {
                    kimg_path: &kimg,
                    kpimg_path: &kpimg,
                    out_path: &out,
                    superkey: &skey,
                    root_key: root,
                    additional,
                    extras,
                })?;
            }
            Ok(0)
        }
        Some('u') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            let out = out.ok_or_else(|| Error::invalid_arg("missing -o"))?;
            patch::unpatch_img(&kimg, &out)?;
            Ok(0)
        }
        Some('r') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            let out = out.ok_or_else(|| Error::invalid_arg("missing -o"))?;
            let skey = superkey.ok_or_else(|| Error::invalid_arg("missing -s"))?;
            patch::reset_key(&kimg, &out, &skey)?;
            Ok(0)
        }
        Some('d') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            patch::dump_kallsym_path(&kimg)?;
            Ok(0)
        }
        Some('f') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            patch::dump_ikconfig_path(&kimg)?;
            Ok(0)
        }
        Some('l') => {
            if let Some(kimg) = kimg {
                patch::print_image_patch_info_path(&kimg)?;
                return Ok(0);
            }
            if let Some(cfg) = extras.first() {
                if cfg.is_path && cfg.extra_type == ExtraType::Kpm {
                    let info = crate::kpm::get_kpm_info(&cfg.data)?;
                    println!("{}", crate::kpm::INFO_EXTRA_KPM_SESSION);
                    println!("name={}", info.name.as_deref().unwrap_or(""));
                    println!("version={}", info.version.as_deref().unwrap_or(""));
                    println!("license={}", info.license.as_deref().unwrap_or(""));
                    println!("author={}", info.author.as_deref().unwrap_or(""));
                    println!("description={}", info.description.as_deref().unwrap_or(""));
                    return Ok(0);
                }
            }
            if let Some(kpimg) = kpimg {
                patch::print_kp_image_info_path(&kpimg)?;
                return Ok(0);
            }
            Err(Error::invalid_arg("missing -i / -M / -k for -l"))
        }
        _ => {
            print_usage(&argv);
            Ok(1)
        }
    }
}

fn next_arg(argv: &[String], i: usize) -> Result<&str> {
    argv.get(i + 1)
        .map(String::as_str)
        .ok_or_else(|| Error::invalid_arg(format!("missing value after {}", argv[i])))
}

fn print_usage(argv: &[String]) {
    let prog = argv.first().map(|s| s.as_str()).unwrap_or("kptools");
    eprintln!(
        concat!(
            "Kernel Image Patch Tools. version: {:x}\n",
            "\n",
            "Usage: {} COMMAND [Options...]\n",
            "\n",
            "COMMAND:\n",
            "  -h, --help                       Print this message.\n",
            "  -v, --version                    Print version number.\n",
            "  -p, --patch                      Patch kernel image with a kpimg + superkey.\n",
            "                                   If -i is an Android boot image (ANDROID! magic), the kernel is extracted,\n",
            "                                   patched and the boot image is repacked automatically in one step.\n",
            "  -u, --unpatch                    Unpatch a previously-patched image.\n",
            "  -r, --resetkey                   Reset the superkey of a patched image.\n",
            "  -d, --dump                       Dump kallsyms table of arm64 or x86_64 kernel image.\n",
            "  -f, --flag                       Dump in-kernel CONFIG (IKCFG) if embedded.\n",
            "  -l, --list                       Print kpimg/KPM/kernel image info.\n",
            "  unpack-bzimage <bzImage> <kernel> Unpack an x86 bzImage to a flat kernel.\n",
            "  repack-bzimage <bzImage> <output> Repack an x86 bzImage payload.\n",
            "\n",
            "Options:\n",
            "  -i, --image PATH                 Kernel image path.\n",
            "  -k, --kpimg PATH                 KernelPatch image path.\n",
            "  -s, --skey KEY                   Set the superkey directly.\n",
            "  -S, --root-skey KEY              Set the root-superkey via SHA-256.\n",
            "  -o, --out PATH                   Patched image path.\n",
            "  -a, --addition KEY=VALUE         Add a key=value line to the addition block.\n",
            "  -M, --embed-extra-path PATH      Embed a KPM (.kpm file).\n",
            "  -T, --extra-type TYPE            Type of the previous -M entry.\n",
            "  -N, --extra-name NAME            Name override.\n",
            "  -V, --extra-event EVENT          Trigger event.\n",
            "  -A, --extra-args ARGS            Arguments.\n",
        ),
        version_u32(),
        prog
    );
}
