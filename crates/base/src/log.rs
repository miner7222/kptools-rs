//! Port of upstream's `tools_log{i,w,e}` + `tools_loge_exit` macros.
//!
//! Upstream threads a `bool log_enable` global through stdout
//! `fprintf`s and exits the whole process on any error via
//! `tools_loge_exit`. Library callers need both to be recoverable +
//! silenceable, so we keep the log toggle but route errors through
//! `Result` instead of `exit()`.

use std::sync::atomic::{AtomicBool, Ordering};

static LOG_ENABLE: AtomicBool = AtomicBool::new(false);

/// Turn the `[+] ... [?] ... [-] ...` chatter on or off. The CLI
/// entry flips this to `true` for every command that used to call
/// `set_log_enable(true)` in upstream.
pub fn set_log_enable(on: bool) {
    LOG_ENABLE.store(on, Ordering::Relaxed);
}

pub fn is_log_enabled() -> bool {
    LOG_ENABLE.load(Ordering::Relaxed)
}

/// `tools_logi` — informational. Prints when logging is enabled.
#[macro_export]
macro_rules! logi {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[+] ");
            eprintln!($($arg)*);
        }
    }};
}

/// `tools_logw` — warning.
#[macro_export]
macro_rules! logw {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[?] ");
            eprintln!($($arg)*);
        }
    }};
}

/// `tools_loge` — error, but does not exit the process. Leaves the
/// exit / error routing to the caller's `Result`.
#[macro_export]
macro_rules! loge {
    ($($arg:tt)*) => {{
        if $crate::log::is_log_enabled() {
            eprint!("[-] ");
            eprintln!($($arg)*);
        }
    }};
}
