//! Logging compatible with upstream `tools_log{i,w,e}`.
//!
//! The log toggle is retained, while fatal process exits are handled through
//! recoverable errors elsewhere in the base crate.

use std::sync::atomic::{AtomicBool, Ordering};

static LOG_ENABLE: AtomicBool = AtomicBool::new(false);

/// Enables or disables tool output.
pub fn set_log_enable(on: bool) {
    LOG_ENABLE.store(on, Ordering::Relaxed);
}

pub fn is_log_enabled() -> bool {
    LOG_ENABLE.load(Ordering::Relaxed)
}

/// Prints an informational message when logging is enabled.
#[macro_export]
macro_rules! logi {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[+] ");
            eprintln!($($arg)*);
        }
    }};
}

/// Prints a warning when logging is enabled.
#[macro_export]
macro_rules! logw {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[?] ");
            eprintln!($($arg)*);
        }
    }};
}

/// Prints an error without terminating the process.
#[macro_export]
macro_rules! loge {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[-] ");
            eprintln!($($arg)*);
        }
    }};
}
