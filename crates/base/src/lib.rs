//! Shared error, I/O, logging, and endianness primitives for kptools.
//!
//! Port of upstream `tools/common.{c,h}` and `tools/order.{c,h}`.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod endian;
pub mod error;
pub mod io;
pub mod log;

pub use error::{Error, Result};
