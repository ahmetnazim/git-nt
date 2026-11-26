#![forbid(unsafe_code)]

use clap::Parser;
use nt_core as _;
use nt_mcp as _;
use nt_read as _;
use nt_write as _;

#[derive(Debug, Parser)]
#[command(
    name = "git-nt",
    version,
    about = "Pure-Rust Negative-Space memory and prompt-injection-hardened context hydration for Git"
)]
struct Cli {}

fn main() {
    let _cli = Cli::parse();
}
