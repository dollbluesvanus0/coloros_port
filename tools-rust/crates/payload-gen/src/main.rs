use anyhow::Result;
use clap::Parser;
use payload_gen::{run_cli, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}
