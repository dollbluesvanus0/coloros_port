use anyhow::Result;
use clap::Parser;
use rom_ops::{run_cli, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}
