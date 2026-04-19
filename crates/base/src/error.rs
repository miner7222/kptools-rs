//! Workspace-wide error + result types.
//!
//! Port replacement for upstream's `tools_loge_exit` macro, which just
//! `exit()`s the process on any failure. A library target needs to
//! surface errors as `Result<T, E>` instead so in-process callers
//! can recover.

use std::io;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("malformed kernel image: {0}")]
    BadKernel(String),
    #[error("malformed preset: {0}")]
    BadPreset(String),
    #[error("malformed kpimg: {0}")]
    BadKpimg(String),
    #[error("malformed kpm: {0}")]
    BadKpm(String),
    #[error("malformed boot image: {0}")]
    BadBootimg(String),
    #[error("kallsym parse error: {0}")]
    Kallsym(String),
    #[error("instruction encode error: {0}")]
    Insn(String),
    #[error("compression error: {0}")]
    Compress(String),
    #[error("decompression error: {0}")]
    Decompress(String),
    #[error("invalid argument: {0}")]
    InvalidArg(String),
    #[error("layout overflow: {0}")]
    Overflow(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    pub fn bad_kernel(msg: impl Into<String>) -> Self {
        Self::BadKernel(msg.into())
    }
    pub fn bad_preset(msg: impl Into<String>) -> Self {
        Self::BadPreset(msg.into())
    }
    pub fn bad_kpimg(msg: impl Into<String>) -> Self {
        Self::BadKpimg(msg.into())
    }
    pub fn bad_kpm(msg: impl Into<String>) -> Self {
        Self::BadKpm(msg.into())
    }
    pub fn bad_bootimg(msg: impl Into<String>) -> Self {
        Self::BadBootimg(msg.into())
    }
    pub fn kallsym(msg: impl Into<String>) -> Self {
        Self::Kallsym(msg.into())
    }
    pub fn insn(msg: impl Into<String>) -> Self {
        Self::Insn(msg.into())
    }
    pub fn compress(msg: impl Into<String>) -> Self {
        Self::Compress(msg.into())
    }
    pub fn decompress(msg: impl Into<String>) -> Self {
        Self::Decompress(msg.into())
    }
    pub fn invalid_arg(msg: impl Into<String>) -> Self {
        Self::InvalidArg(msg.into())
    }
    pub fn overflow(msg: impl Into<String>) -> Self {
        Self::Overflow(msg.into())
    }
}
