//! kptools binary entry point.

fn main() {
    std::process::exit(kptools::cli::main(std::env::args().collect()).unwrap_or(1));
}
