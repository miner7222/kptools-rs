//! Byte-swap + host-endian helpers.
//!
//! Direct port of upstream `tools/order.{c,h}` — upstream exposes
//! one swap function per scalar + an `is_be()` macro that reads a
//! `uint16_t{1}` and checks the first byte. The Rust side collapses
//! everything into two primitives (`is_be` + `swap_if`) and lets the
//! caller mix-in whatever width it needs through the standard
//! `swap_bytes` inherent.
//!
//! Upstream callers branch on `is_be() ^ kinfo->is_be` to decide
//! whether to swap. Mirror that pattern rather than "always convert
//! to LE on disk" — the preset layout carries whatever endianness
//! the original kernel was built for, so a BE-host + BE-target pair
//! writes identical bytes as the C build.

/// True iff the host is big-endian. Matches upstream's `is_be()`
/// macro.
pub const fn is_be() -> bool {
    u16::from_ne_bytes([1, 0]) != 1
}

/// Swap `v` iff `swap` is true. Shorthand the port uses at every
/// `is_be() ^ kinfo.is_be` site.
#[inline]
pub fn swap_i16_if(v: i16, swap: bool) -> i16 {
    if swap { v.swap_bytes() } else { v }
}
#[inline]
pub fn swap_u16_if(v: u16, swap: bool) -> u16 {
    if swap { v.swap_bytes() } else { v }
}
#[inline]
pub fn swap_i32_if(v: i32, swap: bool) -> i32 {
    if swap { v.swap_bytes() } else { v }
}
#[inline]
pub fn swap_u32_if(v: u32, swap: bool) -> u32 {
    if swap { v.swap_bytes() } else { v }
}
#[inline]
pub fn swap_i64_if(v: i64, swap: bool) -> i64 {
    if swap { v.swap_bytes() } else { v }
}
#[inline]
pub fn swap_u64_if(v: u64, swap: bool) -> u64 {
    if swap { v.swap_bytes() } else { v }
}

/// `is_be() ^ kinfo.is_be` shorthand.
#[inline]
pub fn needs_swap(target_is_be: bool) -> bool {
    is_be() ^ target_is_be
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_endianness_is_le_on_intel() {
        // The port targets little-endian hosts (x86_64, aarch64-LE).
        // A big-endian host would just flip every swap branch, which
        // is still correct; this asserts the expected development
        // host for clarity.
        #[cfg(target_endian = "little")]
        assert!(!is_be());
        #[cfg(target_endian = "big")]
        assert!(is_be());
    }

    #[test]
    fn swap_if_mirrors_swap_bytes() {
        let v: u32 = 0x0102_0304;
        assert_eq!(swap_u32_if(v, false), v);
        assert_eq!(swap_u32_if(v, true), 0x0403_0201);
        assert_eq!(swap_u64_if(0x01020304_05060708, true), 0x08070605_04030201);
        assert_eq!(swap_i32_if(-1, true), -1);
    }
}
