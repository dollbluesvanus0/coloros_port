use anyhow::Result;
use clap::Parser;
use xml_tool::{run_cli, Cli};

fn main() -> Result<()> {
    let cli = Cli::parse();
    run_cli(cli)
}
