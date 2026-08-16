//! Pure-Rust port of the userspace `tools/` half of KernelPatch 0.13.4.
//!
//! The crate keeps the on-disk preset ABI and CLI behavior aligned with
//! upstream while supporting both arm64 raw kernel images and x86_64
//! bzImages.

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
pub mod x86_64;

pub use kptools_base::log;
pub use kptools_base::{Error, Result};
