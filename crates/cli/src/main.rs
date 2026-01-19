//! Proto Core CLI - Main entry point
//!
//! This is the main binary for the Proto Core command-line interface.
//! It provides all tools needed to interact with Proto Core nodes.

use clap::Parser;
use protocore_cli::{commands::Cli, commands::run_cli};
use std::process;

#[tokio::main]
async fn main() {
    // Parse command-line arguments
    let cli = Cli::parse();

    // Run the CLI
    if let Err(e) = run_cli(cli).await {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
