//! Shared primitives the kptools binary + helper modules agree on.
//!
//! Keeps the dependency graph flat — every other crate in the
//! workspace talks to these types instead of defining its own
//! parallel versions. Port of `tools/common.{c,h}` + `tools/order.{c,h}`
//! from upstream KernelPatch 0.13.1, plus the `align_ceil` helper the
//! upstream headers scatter across multiple files.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod endian;
pub mod error;
pub mod io;
pub mod log;

pub use error::{Error, Result};
