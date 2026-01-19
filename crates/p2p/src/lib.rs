//! # Proto Core P2P
//!
//! Peer-to-peer networking layer for the Proto Core blockchain.
//!
//! This crate provides:
//! - **Gossipsub** - Efficient message propagation for blocks, transactions, and consensus
//! - **Kademlia DHT** - Peer discovery and routing
//! - **Network Service** - High-level API for blockchain networking
//!
//! ## Architecture
//!
//! The networking layer uses libp2p with the following protocols:
//! - **Noise** - Encryption for all connections
//! - **Yamux** - Stream multiplexing
//! - **Gossipsub** - Pub/sub message propagation
//! - **Kademlia** - DHT-based peer discovery
//! - **Identify** - Peer identification and capability exchange
//!
//! ## Topics
//!
//! Messages are organized into gossipsub topics:
//! - `/protocore/consensus/1.0.0` - Consensus messages (proposals, votes)
//! - `/protocore/blocks/1.0.0` - Block announcements
//! - `/protocore/txs/1.0.0` - Transaction propagation
//!
//! ## Example
//!
//! ```rust,no_run
//! use protocore_p2p::{NetworkService, NetworkConfig, NetworkEvent};
//! use tokio::sync::mpsc;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = NetworkConfig::default();
//!     let (event_tx, mut event_rx) = mpsc::channel(1000);
//!
//!     let mut service = NetworkService::new(config, event_tx).await?;
//!
//!     // Start the network service
//!     tokio::spawn(async move {
//!         service.run().await;
//!     });
//!
//!     // Handle network events
//!     while let Some(event) = event_rx.recv().await {
//!         match event {
//!             NetworkEvent::NewBlock(block) => {
//!                 println!("Received new block");
//!             }
//!             NetworkEvent::NewTransaction(tx) => {
//!                 println!("Received new transaction");
//!             }
//!             _ => {}
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod behaviour;
pub mod discovery;
pub mod gossip;
pub mod network;

// Re-export main types at crate root
pub use behaviour::{ProtocoreBehaviour, ProtocoreBehaviourEvent};
pub use discovery::{DiscoveryConfig, PeerDiscovery};
pub use gossip::{GossipMessage, MessageType, Topics};
pub use network::{
    Command, NetworkConfig, NetworkEvent, NetworkHandle, NetworkMessage, NetworkService, PeerInfo,
};

/// Result type alias for network operations
pub type Result<T> = std::result::Result<T, Error>;

/// Errors that can occur in the P2P networking layer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Transport error
    #[error("transport error: {0}")]
    Transport(String),

    /// Failed to dial peer
    #[error("dial error: {0}")]
    Dial(String),

    /// Failed to listen on address
    #[error("listen error: {0}")]
    Listen(String),

    /// Gossipsub error
    #[error("gossipsub error: {0}")]
    Gossipsub(String),

    /// Kademlia error
    #[error("kademlia error: {0}")]
    Kademlia(String),

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// Invalid message format
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    /// Peer not found
    #[error("peer not found: {0}")]
    PeerNotFound(String),

    /// Channel send error
    #[error("channel error: {0}")]
    Channel(String),

    /// Configuration error
    #[error("config error: {0}")]
    Config(String),

    /// IO error
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    /// Noise protocol error
    #[error("noise error: {0}")]
    Noise(String),

    /// Peer banned
    #[error("peer is banned: {0}")]
    PeerBanned(String),

    /// Maximum peer limit reached
    #[error("maximum peer limit reached")]
    MaxPeersReached,
}
