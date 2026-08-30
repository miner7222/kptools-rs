//! Endianness helpers ported from upstream `tools/order.{c,h}`.
//!
//! Swap decisions mirror upstream's `is_be() ^ kinfo->is_be`; preset fields
//! retain the target kernel's endianness.

/// Returns whether the host is big-endian.
pub const fn is_be() -> bool {
    u16::from_ne_bytes([1, 0]) != 1
}

/// Swaps `v` when `swap` is true.
#[inline]
pub fn swap_i16_if(v: i16, swap: bool) -> i16 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}
#[inline]
pub fn swap_u16_if(v: u16, swap: bool) -> u16 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}
#[inline]
pub fn swap_i32_if(v: i32, swap: bool) -> i32 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}
#[inline]
pub fn swap_u32_if(v: u32, swap: bool) -> u32 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}
#[inline]
pub fn swap_i64_if(v: i64, swap: bool) -> i64 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}
#[inline]
pub fn swap_u64_if(v: u64, swap: bool) -> u64 {
    if swap {
        v.swap_bytes()
    } else {
        v
    }
}

/// Returns whether target-endian values need swapping on this host.
#[inline]
pub fn needs_swap(target_is_be: bool) -> bool {
    is_be() ^ target_is_be
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_endianness_is_le_on_intel() {
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
