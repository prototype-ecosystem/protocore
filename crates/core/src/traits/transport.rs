//! Network transport traits for P2P communication.
//!
//! This module defines abstract traits for network operations,
//! allowing different P2P implementations (libp2p, custom protocols)
//! to be used interchangeably.

use async_trait::async_trait;
use bytes::Bytes;
use std::fmt;
use thiserror::Error;

/// Errors that can occur during network operations.
#[derive(Error, Debug)]
pub enum TransportError {
    /// The peer is not connected.
    #[error("peer not connected: {0}")]
    PeerNotConnected(String),

    /// Connection to peer failed.
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    /// The message could not be sent.
    #[error("send failed: {0}")]
    SendFailed(String),

    /// The topic does not exist.
    #[error("topic not found: {0}")]
    TopicNotFound(String),

    /// Network timeout.
    #[error("timeout: {0}")]
    Timeout(String),

    /// The network is not running.
    #[error("network not running")]
    NotRunning,

    /// Message too large.
    #[error("message too large: {size} > {max}")]
    MessageTooLarge {
        /// Actual message size.
        size: usize,
        /// Maximum allowed size.
        max: usize,
    },

    /// Rate limit exceeded.
    #[error("rate limit exceeded")]
    RateLimited,

    /// Generic network error.
    #[error("network error: {0}")]
    Internal(String),
}

/// Result type for transport operations.
pub type TransportResult<T> = Result<T, TransportError>;

/// A unique identifier for a network peer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub Bytes);

impl PeerId {
    /// Create a peer ID from raw bytes.
    pub fn from_bytes(bytes: impl Into<Bytes>) -> Self {
        Self(bytes.into())
    }

    /// Get the raw bytes of the peer ID.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Convert to a base58 string representation.
    pub fn to_base58(&self) -> String {
        bs58::encode(&self.0).into_string()
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl AsRef<[u8]> for PeerId {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// Information about a connected peer.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// The peer's unique identifier.
    pub id: PeerId,
    /// The peer's network addresses.
    pub addresses: Vec<String>,
    /// Protocols supported by the peer.
    pub protocols: Vec<String>,
    /// Connection direction (inbound/outbound).
    pub direction: ConnectionDirection,
    /// Latency to peer in milliseconds.
    pub latency_ms: Option<u64>,
    /// User agent / client version.
    pub user_agent: Option<String>,
}

/// Direction of peer connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionDirection {
    /// We connected to the peer.
    Outbound,
    /// The peer connected to us.
    Inbound,
}

/// A message received from the network.
#[derive(Debug, Clone)]
pub struct NetworkMessage {
    /// The peer that sent the message.
    pub source: PeerId,
    /// The topic the message was published on.
    pub topic: String,
    /// The message payload.
    pub data: Bytes,
    /// Message ID (for deduplication).
    pub message_id: Option<Bytes>,
}

/// Events emitted by the transport layer.
#[derive(Debug, Clone)]
pub enum TransportEvent {
    /// A new peer connected.
    PeerConnected(PeerInfo),
    /// A peer disconnected.
    PeerDisconnected(PeerId),
    /// A message was received.
    Message(NetworkMessage),
    /// We started listening on an address.
    Listening(String),
    /// A dial attempt failed.
    DialFailed {
        /// The peer we tried to connect to.
        peer: PeerId,
        /// Error message.
        error: String,
    },
}

/// Core trait for network transport.
///
/// Implementations provide P2P networking capabilities including
/// message broadcasting, direct messaging, and peer management.
///
/// # Thread Safety
///
/// All implementations must be thread-safe (`Send + Sync`).
///
/// # Example
///
/// ```ignore
/// use protocore_core::traits::{Transport, TransportResult};
///
/// async fn broadcast_block(transport: &impl Transport, block_data: &[u8]) -> TransportResult<()> {
///     transport.broadcast("blocks", block_data).await
/// }
/// ```
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    /// Broadcast a message to all peers subscribed to a topic.
    async fn broadcast(&self, topic: &str, data: &[u8]) -> TransportResult<()>;

    /// Send a message directly to a specific peer.
    async fn send(&self, peer: &PeerId, data: &[u8]) -> TransportResult<()>;

    /// Subscribe to a topic to receive messages.
    async fn subscribe(&self, topic: &str) -> TransportResult<()>;

    /// Unsubscribe from a topic.
    async fn unsubscribe(&self, topic: &str) -> TransportResult<()>;

    /// Get the local peer ID.
    fn local_peer_id(&self) -> PeerId;

    /// Get information about connected peers.
    fn connected_peers(&self) -> Vec<PeerInfo>;

    /// Get the number of connected peers.
    fn peer_count(&self) -> usize {
        self.connected_peers().len()
    }

    /// Check if a specific peer is connected.
    fn is_connected(&self, peer: &PeerId) -> bool;

    /// Dial a peer by multiaddress.
    async fn dial(&self, addr: &str) -> TransportResult<PeerId>;

    /// Disconnect from a peer.
    async fn disconnect(&self, peer: &PeerId) -> TransportResult<()>;

    /// Ban a peer (prevent future connections).
    async fn ban_peer(&self, peer: &PeerId, reason: &str) -> TransportResult<()>;

    /// Unban a peer.
    async fn unban_peer(&self, peer: &PeerId) -> TransportResult<()>;

    /// Get network statistics.
    fn stats(&self) -> TransportStats;
}

/// Network transport statistics.
#[derive(Debug, Clone, Default)]
pub struct TransportStats {
    /// Total bytes sent.
    pub bytes_sent: u64,
    /// Total bytes received.
    pub bytes_received: u64,
    /// Number of messages sent.
    pub messages_sent: u64,
    /// Number of messages received.
    pub messages_received: u64,
    /// Number of currently connected peers.
    pub connected_peers: usize,
    /// Total connections since startup.
    pub total_connections: u64,
    /// Number of banned peers.
    pub banned_peers: usize,
}

/// Trait for transport event handling.
#[async_trait]
pub trait TransportEventHandler: Send + Sync {
    /// Handle a transport event.
    async fn handle_event(&self, event: TransportEvent);
}

/// Trait for peer discovery.
#[async_trait]
pub trait PeerDiscovery: Send + Sync {
    /// Start the discovery process.
    async fn start(&self) -> TransportResult<()>;

    /// Stop the discovery process.
    async fn stop(&self) -> TransportResult<()>;

    /// Get discovered peers.
    fn discovered_peers(&self) -> Vec<PeerInfo>;

    /// Add a bootstrap peer.
    async fn add_bootstrap(&self, addr: &str) -> TransportResult<()>;

    /// Get discovery statistics.
    fn stats(&self) -> DiscoveryStats;
}

/// Peer discovery statistics.
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    /// Number of bootstrap nodes.
    pub bootstrap_nodes: usize,
    /// Number of discovered peers.
    pub discovered_peers: usize,
    /// Time since last discovery in seconds.
    pub last_discovery_secs: u64,
    /// Number of discovery rounds completed.
    pub discovery_rounds: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_display() {
        let peer_id = PeerId::from_bytes(vec![1, 2, 3, 4, 5]);
        let display = format!("{}", peer_id);
        assert!(!display.is_empty());
    }

    #[test]
    fn test_peer_id_to_base58() {
        let peer_id = PeerId::from_bytes(vec![0, 1, 2, 3]);
        let base58 = peer_id.to_base58();
        assert!(!base58.is_empty());
    }
}
