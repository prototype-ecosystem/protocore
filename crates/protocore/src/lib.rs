//! # Proto Core
//!
//! Proto Core is a lightweight, EVM-compatible blockchain with ProtoBFT consensus.
//!
//! This crate provides the main node binary and can also be used as a library
//! for embedding Proto Core nodes into other applications.
//!
//! ## Features
//!
//! - **Instant Finality**: 2-block finality (~4 seconds) with cryptographic guarantees
//! - **Full EVM Compatibility**: MetaMask works out of the box
//! - **ProtoBFT Consensus**: Deterministic Byzantine fault tolerant consensus
//! - **On-Chain Governance**: DAO proposals, voting, and upgrades
//! - **Minimal Codebase**: ~20,000 LOC in Rust
//!
//! ## Components
//!
//! - [`Node`] - Full node that syncs and validates the chain
//! - [`ValidatorNode`] - Validator node that participates in consensus
//! - [`BlockBuilder`] - Block production for validators
//!
//! ## Example
//!
//! ```rust,no_run
//! use protocore::{Node, ValidatorNode};
//! use protocore_config::Config;
//! use std::path::Path;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     // Load configuration
//!     let config = Config::load(Path::new("protocore.toml"))?;
//!
//!     // Start a full node
//!     let mut node = Node::new(config).await?;
//!     node.run().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Running a Validator
//!
//! ```rust,no_run
//! use protocore::ValidatorNode;
//! use protocore_config::Config;
//! use std::path::Path;
//!
//! #[tokio::main]
//! async fn main() -> anyhow::Result<()> {
//!     let config = Config::load(Path::new("protocore.toml"))?;
//!     let key_path = Path::new("validator.key");
//!
//!     let mut validator = ValidatorNode::new(config, key_path).await?;
//!     validator.run().await?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod block_builder;
pub mod node;
pub mod validator;

// Re-export main types at crate root
pub use block_builder::{
    BlockBuilder, BlockBuilderConfig, BlockBuilderStorage, BlockReceipt, LogEntry, SimpleStorage,
    SimulationResult,
};
pub use node::{Node, NodeEvent, NodeStatus};
pub use validator::{ValidatorKeys, ValidatorNode, ValidatorStats};

/// Crate version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default configuration file name
pub const DEFAULT_CONFIG_FILE: &str = "protocore.toml";

/// Default data directory
pub const DEFAULT_DATA_DIR: &str = ".protocore";

/// Re-export commonly used types from dependencies
pub mod prelude {
    //! Commonly used types for convenience
    pub use super::{BlockBuilder, Node, NodeEvent, NodeStatus, ValidatorNode};
    pub use protocore_config::Config;
    pub use protocore_types::{Address, Block, BlockHeader, Transaction, H256};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert!(!VERSION.is_empty());
    }

    #[test]
    fn test_constants() {
        assert_eq!(DEFAULT_CONFIG_FILE, "protocore.toml");
        assert_eq!(DEFAULT_DATA_DIR, ".protocore");
    }
}
