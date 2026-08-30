# kptools-rs

A pure-Rust implementation of the KernelPatch userspace tools. It patches arm64
raw kernel images and x86_64 `bzImage` kernels with a `kpimg`, requires no C
toolchain, and handles compression in-process.

## Build

```sh
cargo build --release
```

The binary is written to `target/release/kptools` (`kptools.exe` on Windows).

## CLI

```text
kptools unpack  <boot.img>                             # writes ./kernel
kptools repack  <boot.img> [out]                       # reads ./kernel
kptools sha1    <file>
kptools unpack-bzimage <bzImage> <kernel>              # writes flat x86_64 kernel
kptools repack-bzimage <bzImage> <output>              # recompresses x86_64 payload

kptools -p  -i <kimg>  -k <kpimg>  -s <skey>  [-S]  -o <out>
           [-a KEY=VALUE]...
           [-M <kpm> [-T <type>] [-N <name>] [-V <event>] [-A <args>]]...
kptools -u  -i <kimg>   -o <out>
kptools -r  -i <kimg>  -s <skey>  -o <out>
kptools -d  -i <kimg>                                   # arm64/x86_64 kallsyms
kptools -f  -i <kimg>                                   # arm64/x86_64 IKCONFIG
kptools -l  {-i <kimg> | -k <kpimg> | -M <kpm>}
kptools -v
kptools -h
```

## Library usage

```rust
use kptools::bootimg;
use kptools::patch::{self, ExtraConfig, PatchArgs};
use kptools::preset::ExtraType;

bootimg::extract_kernel(
    std::path::Path::new("boot.img"),
    std::path::Path::new("kernel"),
)?;

let extras = vec![ExtraConfig::from_path(
    std::path::Path::new("nohello.kpm"),
    ExtraType::Kpm,
)?];
patch::patch_update_img(PatchArgs {
    kimg_path: std::path::Path::new("kernel"),
    kpimg_path: std::path::Path::new("kpimg"),
    out_path: std::path::Path::new("kernel.out"),
    superkey: "mysecret",
    root_key: false,
    additional: Vec::new(),
    extras,
})?;

bootimg::repack_bootimg(
    std::path::Path::new("boot.img"),
    std::path::Path::new("kernel.out"),
    std::path::Path::new("new-boot.img"),
)?;
```

`kptools::Error` and `kptools::Result` are re-exported from `kptools-base`.
Library entry points return `Result` instead of terminating the host process.

## x86_64 support

The x86_64 path is experimental and has not been validated end-to-end against a
bootable `bzImage`. Tests cover parsers and injection bookkeeping only. x86_64
patching rejects KPM extras and `-a` additional properties.

## License

Licensed under the GNU General Public License, version 2 or later
(`GPL-2.0-or-later`).
