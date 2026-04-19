//! Pure-Rust port of the `tools/` half of KernelPatch 0.13.1.
//!
//! Scope: every CLI the upstream `kptools` binary exposes, plus the
//! in-process library entry points an embedded caller needs. The
//! kernel-side (`kernel/`, `kpms/`, `user/`) is out of scope —
//! kptools only *produces* the patched kernel, it does not replace
//! the kernel-mode kpimg.
//!
//! Upstream is pinned to tag 0.13.1. Any version bump on the kernel
//! side invalidates the preset layout; the parser aborts hard when
//! it sees a mismatched `setup_header_t.kp_version`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod bootimg;
pub mod cli;
pub mod image;
pub mod insn;
pub mod kallsym;
pub mod kpm;
pub mod patch;
pub mod preset;
pub mod symbol;

pub use kptools_base::{Error, Result};
