//! CLI dispatcher.
//!
//! Hand-rolled getopt-style parser so the binary ingests every
//! argv shape upstream's `kptools.c` accepts without pulling in a
//! full clap/argh surface. The short-form boot-image commands
//! (`unpack` / `repack` / `sha1`) share this entry too, but only
//! the patch + dump subset is wired in this slice — the `unpack` /
//! `repack` / `sha1` sub-paths land with the bootimg codec port
//! (that work is split out into its own follow-up because it drags
//! lz4 / xz / bzip2 deps that the kernel-patch path does not need).

use std::path::PathBuf;

use kptools_base::{Error, Result, logi};

use crate::preset::ExtraType;
use crate::patch::{self, ExtraConfig, PatchArgs};

pub fn version_u32() -> u32 {
    crate::preset::pack_version(0, 13, 1)
}

pub fn main(argv: Vec<String>) -> Result<i32> {
    if argv.len() < 2 {
        print_usage(&argv);
        return Ok(1);
    }

    // Short-form first-arg commands — these skip getopt parsing
    // and take positional args directly.
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
                let out = if argv.len() > 3 { &argv[3] } else { "new-boot.img" };
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

    // getopt-style flags. We only need the subset kptools actually
    // reads; anything else is printed as an error.
    let mut cmd: Option<char> = None;
    let mut kimg: Option<PathBuf> = None;
    let mut kpimg: Option<PathBuf> = None;
    let mut out: Option<PathBuf> = None;
    let mut superkey: Option<String> = None;
    let mut root_skey = false;
    let mut additional: Vec<String> = Vec::new();
    let mut extras: Vec<ExtraConfig> = Vec::new();

    let mut i = 1usize;
    while i < argv.len() {
        let a = &argv[i];
        match a.as_str() {
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
                kimg = Some(argv[i + 1].clone().into());
                i += 2;
            }
            "-k" | "--kpimg" => {
                kpimg = Some(argv[i + 1].clone().into());
                i += 2;
            }
            "-o" | "--out" => {
                out = Some(argv[i + 1].clone().into());
                i += 2;
            }
            "-s" | "--skey" => {
                superkey = Some(argv[i + 1].clone());
                i += 2;
            }
            "-S" | "--root-skey" => {
                superkey = Some(argv[i + 1].clone());
                root_skey = true;
                i += 2;
            }
            "-a" | "--addition" => {
                additional.push(argv[i + 1].clone());
                i += 2;
            }
            "-M" | "--embed-extra-path" => {
                let p = PathBuf::from(&argv[i + 1]);
                // Default to KPM for now; `-T` overrides.
                let cfg = ExtraConfig::from_path(&p, ExtraType::Kpm)?;
                extras.push(cfg);
                i += 2;
            }
            "-T" | "--extra-type" => {
                let ty = ExtraType::from_str_tag(&argv[i + 1]).ok_or_else(|| {
                    Error::invalid_arg(format!("invalid extra type: {}", argv[i + 1]))
                })?;
                if let Some(last) = extras.last_mut() {
                    last.extra_type = ty;
                    last.item.extra_type = ty.as_i32();
                }
                i += 2;
            }
            "-N" | "--extra-name" => {
                if let Some(last) = extras.last_mut() {
                    last.set_name = Some(argv[i + 1].clone());
                }
                i += 2;
            }
            "-V" | "--extra-event" => {
                if let Some(last) = extras.last_mut() {
                    last.set_event = Some(argv[i + 1].clone());
                }
                i += 2;
            }
            "-A" | "--extra-args" => {
                if let Some(last) = extras.last_mut() {
                    last.set_args = Some(argv[i + 1].clone());
                }
                i += 2;
            }
            _ => {
                eprintln!("unknown flag: {a}");
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
            let skey = superkey.ok_or_else(|| Error::invalid_arg("missing -s"))?;
            patch::patch_update_img(PatchArgs {
                kimg_path: &kimg,
                kpimg_path: &kpimg,
                out_path: &out,
                superkey: &skey,
                root_key: root_skey,
                additional,
                extras,
            })?;
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
            kptools_base::log::set_log_enable(true);
            let kf = crate::patch::KernelFile::read(&kimg)?;
            let mut kallsym = crate::kallsym::Kallsym::default();
            let mut buf = kf.kimg().to_vec();
            crate::kallsym::find_linux_banner(&mut kallsym, &buf)?;
            crate::kallsym::analyze_kallsym_info(
                &mut kallsym,
                &mut buf,
                crate::kallsym::ArchType::Arm64,
                true,
            )?;
            crate::kallsym::dump_all_symbols(&kallsym, &buf);
            Ok(0)
        }
        Some('f') => {
            let kimg = kimg.ok_or_else(|| Error::invalid_arg("missing -i"))?;
            kptools_base::log::set_log_enable(true);
            let kf = crate::patch::KernelFile::read(&kimg)?;
            crate::kallsym::dump_all_ikconfig(kf.kimg())?;
            Ok(0)
        }
        Some('l') => {
            if let Some(kimg) = kimg {
                crate::patch::print_image_patch_info_path(&kimg)?;
                return Ok(0);
            }
            // If no -i, check -M (first extra with a path).
            if let Some(cfg) = extras.first() {
                if cfg.is_path {
                    // `ExtraConfig::from_path` already read the
                    // file; invoke the kpm printer via a re-read so
                    // we match upstream's "path" flow exactly.
                    if cfg.extra_type == ExtraType::Kpm {
                        // Use first KPM data already loaded.
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
            }
            if let Some(kpimg) = kpimg {
                crate::patch::print_kp_image_info_path(&kpimg)?;
                return Ok(0);
            }
            Err(Error::invalid_arg("missing -i / -M / -k for -l"))?;
            Ok(1)
        }
        _ => {
            print_usage(&argv);
            Ok(1)
        }
    }
}

fn print_usage(argv: &[String]) {
    let prog = argv.first().map(|s| s.as_str()).unwrap_or("kptools");
    eprintln!(
        "Kernel Image Patch Tools. version: {:x}\n\
\n\
Usage: {prog} COMMAND [Options...]\n\
\n\
COMMAND:\n\
  -h, --help                       Print this message.\n\
  -v, --version                    Print version number.\n\
  -p, --patch                      Patch kernel image with a kpimg + superkey.\n\
  -u, --unpatch                    Unpatch a previously-patched image.\n\
  -r, --resetkey                   Reset the superkey of a patched image.\n\
  -d, --dump                       Dump kallsyms table of a kernel image.\n\
  -f, --flag                       Dump in-kernel CONFIG (IKCFG) if embedded.\n\
  -l, --list                       Print kpimg/KPM/kernel image info.\n\
\n\
Options:\n\
  -i, --image PATH                 Kernel image path.\n\
  -k, --kpimg PATH                 KernelPatch image path.\n\
  -s, --skey KEY                   Set the superkey directly.\n\
  -S, --root-skey KEY              Set the root-superkey via SHA-256.\n\
  -o, --out PATH                   Patched image path.\n\
  -a  --addition KEY=VALUE         Add a key=value line to the addition block.\n\
  -M, --embed-extra-path PATH      Embed a KPM (.kpm file).\n\
  -T, --extra-type TYPE            Type of the previous -M entry.\n\
  -N, --extra-name NAME            Name override.\n\
  -V, --extra-event EVENT          Trigger event.\n\
  -A, --extra-args ARGS            Arguments.\n",
        version_u32()
    );
}
