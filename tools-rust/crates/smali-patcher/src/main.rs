use anyhow::Result;
use clap::Parser;
use smali_patcher::{run_cli, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}
