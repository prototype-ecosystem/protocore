//! # Proto Core RPC
//!
//! JSON-RPC API for the Proto Core blockchain.
//!
//! This crate provides a MetaMask-compatible JSON-RPC server with:
//! - Ethereum-compatible `eth_*` methods
//! - Proto Core-specific `mc_*` methods
//! - WebSocket subscriptions for real-time updates
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_rpc::{RpcServer, RpcServerConfig};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = RpcServerConfig {
//!         http_addr: "127.0.0.1:8545".parse()?,
//!         ws_addr: "127.0.0.1:8546".parse()?,
//!         chain_id: 123456,
//!         ..Default::default()
//!     };
//!
//!     let server = RpcServer::new(config);
//!     server.start().await?;
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod ddos;
pub mod eth;
pub mod protocore;
pub mod server;
pub mod types;
pub mod ws;

// Re-export main types at crate root
pub use eth::{EthApiImpl, EthApiServer, NetApiImpl, NetApiServer, StateProvider, Web3ApiImpl, Web3ApiServer};
pub use protocore::{
    DelegationInfo, EpochInfo, FinalityCert, GovernanceProposal, NetworkStats, ProposalStatus,
    ProposalType, ProtocoreApiImpl, ProtocoreApiServer, ProtocoreStateProvider, StakingInfo,
    StealthAddressResult, UnbondingInfo, ValidatorInfo,
};
pub use server::{RpcServer, RpcServerBuilder, RpcServerConfig};
pub use types::*;
pub use ws::{SubscriptionApiImpl, SubscriptionApiServer, SubscriptionManager};
pub use ddos::{
    ApiTier, CircuitState, MethodCosts, RateLimitResult, RpcDdosConfig, RpcDdosProtection,
    RpcDdosStats, RpcRejectReason,
};

/// Result type alias for RPC operations
pub type Result<T> = std::result::Result<T, RpcError>;

/// RPC error types
#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    /// Invalid parameters provided
    #[error("invalid params: {0}")]
    InvalidParams(String),

    /// Resource not found
    #[error("not found: {0}")]
    NotFound(String),

    /// Internal server error
    #[error("internal error: {0}")]
    Internal(String),

    /// Transaction rejected
    #[error("transaction rejected: {0}")]
    TransactionRejected(String),

    /// Execution error (e.g., revert)
    #[error("execution error: {0}")]
    ExecutionError(String),

    /// Block not found
    #[error("block not found")]
    BlockNotFound,

    /// Transaction not found
    #[error("transaction not found")]
    TransactionNotFound,

    /// Invalid block number or tag
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Invalid address format
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid hex data
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Subscription error
    #[error("subscription error: {0}")]
    SubscriptionError(String),

    /// Server not ready
    #[error("server not ready")]
    ServerNotReady,

    /// Rate limited
    #[error("rate limited")]
    RateLimited,
}

impl From<RpcError> for jsonrpsee::types::ErrorObjectOwned {
    fn from(err: RpcError) -> Self {
        let (code, message) = match &err {
            RpcError::InvalidParams(_) => (-32602, err.to_string()),
            RpcError::NotFound(_) => (-32001, err.to_string()),
            RpcError::Internal(_) => (-32603, err.to_string()),
            RpcError::TransactionRejected(_) => (-32003, err.to_string()),
            RpcError::ExecutionError(_) => (-32015, err.to_string()),
            RpcError::BlockNotFound => (-32001, err.to_string()),
            RpcError::TransactionNotFound => (-32001, err.to_string()),
            RpcError::InvalidBlock(_) => (-32602, err.to_string()),
            RpcError::InvalidAddress(_) => (-32602, err.to_string()),
            RpcError::InvalidHex(_) => (-32602, err.to_string()),
            RpcError::SubscriptionError(_) => (-32005, err.to_string()),
            RpcError::ServerNotReady => (-32002, err.to_string()),
            RpcError::RateLimited => (-32005, err.to_string()),
        };
        jsonrpsee::types::ErrorObjectOwned::owned(code, message, None::<()>)
    }
}
