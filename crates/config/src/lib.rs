//! # Proto Core Configuration
//!
//! This crate provides configuration parsing and genesis handling for the Proto Core blockchain.
//!
//! Proto Core uses a single-config philosophy where all chain settings are defined in one
//! `protocore.toml` file, making deployment and configuration management straightforward.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use protocore_config::{Config, GenesisConfig};
//! use std::path::Path;
//!
//! // Load configuration from TOML file
//! let config = Config::load(Path::new("protocore.toml"))?;
//!
//! // Access nested configurations
//! println!("Chain ID: {}", config.chain.chain_id);
//! println!("Block time: {}ms", config.consensus.block_time_ms);
//!
//! // Generate genesis block
//! let genesis_block = config.genesis.generate_genesis_block()?;
//! ```
//!
//! ## Configuration Sections
//!
//! - `[chain]` - Chain identity (chain_id, token settings)
//! - `[consensus]` - Consensus parameters (timeouts, validator limits)
//! - `[economics]` - Economic parameters (gas limits, fees, rewards)
//! - `[staking]` - Staking parameters (min stake, unbonding period)
//! - `[slashing]` - Slashing parameters (penalties, jail duration)
//! - `[governance]` - Governance parameters (voting periods, thresholds)
//! - `[privacy]` - Privacy features (stealth addresses, confidential tx)
//! - `[network]` - P2P network settings (addresses, peers)
//! - `[rpc]` - RPC server settings (HTTP/WS addresses, rate limits)
//! - `[storage]` - Storage settings (data directory, pruning)
//! - `[logging]` - Logging settings (level, format, rotation)
//! - `[metrics]` - Prometheus metrics settings
//! - `[integrity]` - Binary integrity and tamper prevention settings (optional)
//! - `[[genesis.accounts]]` - Initial account balances
//! - `[[genesis.validators]]` - Initial validator set

mod config;
mod error;
mod genesis;

pub use config::*;
pub use error::*;
pub use genesis::*;

/// Re-export alloy primitives for convenience
pub use alloy_primitives::{Address, B256, U256};
