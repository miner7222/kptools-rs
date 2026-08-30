# kptools-rs

Pure-Rust port of the `tools/` directory from
[bmax121/KernelPatch](https://github.com/bmax121/KernelPatch) v0.13.8.

The upstream `kptools` patches arm64 raw kernel images and x86_64
`bzImage` kernels with a `kpimg` (KernelPatch kernel-mode image),
producing a kernel blob that APatch / FolkPatch can flash back onto
a device. This port keeps the userspace ABI and CLI surface aligned
with upstream while keeping compression/decompression in-process.

## Build

```sh
cargo build --release
```

Output: `target/release/kptools(.exe)` — no C toolchain is required.
The x86_64 bzImage path uses `flate2` and does not invoke an external
`gzip` executable.

## Coverage

| Upstream file      | Rust module                | Status          |
| ------------------ | -------------------------- | --------------- |
| `common.c/h`       | `base/src/{io,log,error}`  | ported          |
| `order.c/h`        | `base/src/endian`          | ported          |
| `image.c/h`        | `kptools::image`           | ported          |
| `insn.{c,h}`       | `kptools::insn`            | subset ported   |
| `kallsym.c/h`      | `kptools::kallsym`         | ported (0.13.8) |
| `symbol.c/h`       | `kptools::symbol`          | ported (0.13.8) |
| `kpm.c/h`          | `kptools::kpm`             | ported          |
| `patch.c/h`        | `kptools::patch`           | ported (0.13.8) |
| `x86_64.c/h`       | `kptools::x86_64`          | ported (0.13.8) |
| `bootimg.c/h`      | `kptools::bootimg`         | ported (0.13.8) |
| `kptools.c`        | `kptools::cli`             | ported (0.13.8) |

KernelPatch 0.13.8 compatibility includes the version-aware
`header_backup` lookup used for upgrading/unpatching older patched
images, legacy extra-header flag sanitizing, legacy `kconfig` extra
skipping, x86_64 relative/absolute-percpu kallsyms decoding, marker
table validation, and the stricter required/optional symbol rules.

KPM authoring APIs and macros such as `KPM_EVENT` and
`mod_eventcall_t` live on the KernelPatch kernel/KPM SDK side. They
are intentionally outside this crate's userspace `tools/` port.

### x86_64 bzImage support

For x86_64 the tool validates the `0xaa55` / `HdrS` boot header,
locates and inflates the gzip-compressed ELF64 payload, flattens
`PT_LOAD` segments, resolves `start_kernel`, and replaces its 5-byte
ftrace NOP with a `call rel32` to a 16-byte trampoline. The kpimg is
placed in an executable zero run and entered at `KP_X86_ENTRY_OFFSET`
(`0x600`). Repacking preserves the fixed compressed-payload slot,
updates `payload_length` / `syssize`, and regenerates the bzImage
checksum. Unpatch restores the saved 8-byte `start_kernel` header and
clears the injected payload/trampoline.

As in upstream 0.13.8, x86_64 patching currently rejects KPM extras
and `-a` additional properties.

End-to-end validation against a real bootable x86_64 bzImage has not yet
been completed in this repository. Treat the x86_64 path as experimental:
the current tests cover parser/compression helpers and injection bookkeeping,
not boot validation or byte parity with GNU `gzip -9` output.

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

The crate is also consumable as a Rust library:

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

`kptools::Error` and `kptools::Result` are re-exports from
`kptools-base`; library entry points return `Result<T, Error>` rather
than terminating the host process.
