//! # Proto Core CLI
//!
//! Command-line interface for the Proto Core blockchain.
//!
//! This crate provides a comprehensive CLI for interacting with Proto Core nodes,
//! managing keys, querying blockchain state, and performing staking and governance operations.
//!
//! ## Available Commands
//!
//! - `init` - Initialize a new node with default configuration
//! - `start` - Start the node with specified configuration
//! - `keys` - Key management (generate, list, import, export)
//! - `query` - Query blockchain state (blocks, transactions, accounts)
//! - `staking` - Staking operations (stake, unstake, delegate, withdraw)
//! - `governance` - Governance operations (propose, vote, list proposals)
//! - `export` - Export state snapshot
//! - `import` - Import state snapshot
//! - `version` - Display version information
//!
//! ## Example Usage
//!
//! ```bash
//! # Initialize a new node
//! protocore init --data-dir ~/.protocore
//!
//! # Start the node
//! protocore start --config ~/.protocore/config.toml
//!
//! # Generate a new wallet key
//! protocore keys generate --key-type wallet
//!
//! # Query account balance
//! protocore query account 0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod commands;
pub mod utils;

// Re-export the main CLI types for convenience
pub use commands::{Cli, Commands, run_cli};
pub use utils::{CliError, CliResult, OutputFormat};

/// Version information for the CLI
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// CLI application name
pub const APP_NAME: &str = "protocore";

/// Default configuration file name
pub const DEFAULT_CONFIG_FILE: &str = "protocore.toml";

/// Default data directory name
pub const DEFAULT_DATA_DIR: &str = ".protocore";

/// Default keystore directory name
pub const DEFAULT_KEYSTORE_DIR: &str = "keystore";

/// Default RPC endpoint
pub const DEFAULT_RPC_ENDPOINT: &str = "http://127.0.0.1:8545";

/// Default WebSocket endpoint
pub const DEFAULT_WS_ENDPOINT: &str = "ws://127.0.0.1:8546";

/// Get the default data directory path
pub fn default_data_dir() -> std::path::PathBuf {
    dirs::home_dir()
        .map(|p| p.join(DEFAULT_DATA_DIR))
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_DATA_DIR))
}

/// Get the default keystore directory path
pub fn default_keystore_dir() -> std::path::PathBuf {
    default_data_dir().join(DEFAULT_KEYSTORE_DIR)
}

/// Get the default configuration file path
pub fn default_config_path() -> std::path::PathBuf {
    default_data_dir().join(DEFAULT_CONFIG_FILE)
}

