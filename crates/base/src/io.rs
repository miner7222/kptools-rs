//! File and alignment helpers ported from upstream tools.

use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;

use crate::{Error, Result};

/// Read the whole file at `path` into an owned buffer.
pub fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut f = File::open(path).map_err(Error::Io)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(Error::Io)?;
    Ok(buf)
}

/// Reads a file and zero-pads it to a multiple of `align`.
pub fn read_file_align(path: &Path, align: usize) -> Result<Vec<u8>> {
    let mut buf = read_file(path)?;
    let aligned = align_ceil(buf.len(), align);
    if aligned > buf.len() {
        buf.resize(aligned, 0);
    }
    Ok(buf)
}

/// Writes `data` to `path`, replacing an existing file.
pub fn write_file(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(Error::Io)?;
        }
    }
    let mut f = File::create(path).map_err(Error::Io)?;
    f.write_all(data).map_err(Error::Io)
}

/// Round `v` up to the next multiple of `a`.
#[inline]
pub const fn align_ceil(v: usize, a: usize) -> usize {
    if a == 0 {
        v
    } else {
        v.div_ceil(a) * a
    }
}

/// Round `u64` up to the next multiple of `a`.
#[inline]
pub const fn align_ceil_u64(v: u64, a: u64) -> u64 {
    if a == 0 {
        v
    } else {
        v.div_ceil(a) * a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn align_ceil_rounds_up() {
        assert_eq!(align_ceil(0, 4096), 0);
        assert_eq!(align_ceil(1, 4096), 4096);
        assert_eq!(align_ceil(4095, 4096), 4096);
        assert_eq!(align_ceil(4096, 4096), 4096);
        assert_eq!(align_ceil(4097, 4096), 8192);
        assert_eq!(align_ceil(0x1234, 0x10), 0x1240);
    }

    #[test]
    fn read_file_align_pads_tail() {
        let dir = tempdir_root();
        let p = dir.join("f.bin");
        std::fs::write(&p, b"ABC").unwrap();
        let v = read_file_align(&p, 16).unwrap();
        assert_eq!(v.len(), 16);
        assert_eq!(&v[..3], b"ABC");
        assert!(v[3..].iter().all(|b| *b == 0));
    }

    fn tempdir_root() -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "kptools-base-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
