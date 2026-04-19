//! kptools binary entry — delegates to the library's `cli::main`.
//!
//! Later phases add the real argh dispatcher. The skeleton is here
//! so `cargo build` produces the expected target name.

fn main() {
    std::process::exit(kptools::cli::main(std::env::args().collect()).unwrap_or(1));
}
