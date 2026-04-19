# kptools-rs

Pure-Rust port of the `tools/` directory from
[bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) v0.13.1.

The upstream `kptools` patches an arm64 kernel image with a
`kpimg` (KernelPatch kernel-mode image) + optional KPM extras,
producing a kernel blob that APatch / FolkPatch flash back onto
a device. This port keeps the same CLI surface so the binary is
drop-in compatible — every flag the original `kptools` parses
works here too. The kernel-side `kernel/` and `kpms/` trees stay
in C; this crate only builds the userspace tools.

## Build

```
cargo build --release
```

Output: `target/release/kptools(.exe)` — no C toolchain required.

## Coverage

| Upstream file      | Rust module                | Status          |
| ------------------ | -------------------------- | --------------- |
| `common.c/h`       | `base/src/{io,log,error}`  | ported          |
| `order.c/h`        | `base/src/endian`          | ported          |
| `image.c/h`        | `kptools::image`           | ported          |
| `insn.{c,h}`       | `kptools::insn`            | subset ported   |
| `kallsym.c/h`      | `kptools::kallsym`         | ported          |
| `symbol.c/h`       | `kptools::symbol`          | ported          |
| `kpm.c/h`          | `kptools::kpm`             | ported          |
| `patch.c/h`        | `kptools::patch`           | ported          |
| `bootimg.c/h`      | `kptools::bootimg`         | ported          |
| `kptools.c`        | `kptools::cli`             | ported          |

Every CLI surface upstream exposes is wired: `unpack`, `repack`,
`sha1`, `-p`, `-u`, `-r`, `-d` (dump kallsyms), `-f` (dump
ikconfig) and `-l` (list kimg / kpimg / KPM info). `pid_vnr` is
verified against SP_EL0 / SP via the A64 decoder subset ported in
`kptools::insn`, and every kernel compression codec boot images
ship (gzip, bzip2, lz4 frame+legacy, xz, lzma, zstd) round-trips
through `repack`.

## CLI

```
kptools unpack  <boot.img>                             # writes ./kernel
kptools repack  <boot.img> [out]                       # reads ./kernel
kptools sha1    <file>

kptools -p  -i <kimg>  -k <kpimg>  -s <skey>  [-S]  -o <out>
           [-a KEY=VALUE]...
           [-M <kpm> [-T <type>] [-N <name>] [-V <event>] [-A <args>]]...
kptools -u  -i <kimg>   -o <out>
kptools -r  -i <kimg>  -s <skey>  -o <out>
kptools -d  -i <kimg>                                   # dump kallsyms
kptools -f  -i <kimg>                                   # dump ikconfig
kptools -l  {-i <kimg> | -k <kpimg> | -M <kpm>}         # list info
kptools -v
kptools -h
```

## Library usage

The crate is consumable as a Rust library in addition to the
binary. Add a git dependency + call the public module entry
points directly, bypassing the CLI:

```rust
use kptools::bootimg;
use kptools::patch::{self, PatchArgs, ExtraConfig};
use kptools::preset::ExtraType;

// Extract the kernel section from an AOSP boot image.
bootimg::extract_kernel(
    std::path::Path::new("boot.img"),
    std::path::Path::new("kernel"),
)?;

// Patch the kernel with a kpimg + KPM module + superkey.
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

// Re-embed the patched kernel into the original boot image.
bootimg::repack_bootimg(
    std::path::Path::new("boot.img"),
    std::path::Path::new("kernel.out"),
    std::path::Path::new("new-boot.img"),
)?;
```

`kptools::Error` + `kptools::Result` are re-exports from the
`kptools-base` crate; every library entry point returns
`Result<T, Error>` instead of `exit()`ing, so embedding a patch
run inside a larger host process is safe.
`kptools_base::log::set_log_enable` toggles the `[+]` / `[?]` /
`[-]` stderr chatter for callers that want quiet runs.
