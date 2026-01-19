//! Tests for peer discovery functionality.

use libp2p::{identity::Keypair, Multiaddr, PeerId};
use protocore_p2p::{DiscoveryConfig, PeerDiscovery};
use protocore_p2p::discovery::PeerRecord;
use std::time::Duration;

fn test_peer_id() -> PeerId {
    let key = Keypair::generate_ed25519();
    PeerId::from(key.public())
}

fn test_addr() -> Multiaddr {
    "/ip4/127.0.0.1/tcp/9000".parse().unwrap()
}

#[test]
fn test_discovery_config_default() {
    let config = DiscoveryConfig::default();
    assert_eq!(config.min_peers, 8);
    assert_eq!(config.max_peers, 50);
    assert!(config.enable_discovery);
}

#[test]
fn test_peer_record_creation() {
    let peer_id = test_peer_id();
    let addr = test_addr();
    let record = PeerRecord::new(peer_id, addr.clone());

    assert_eq!(record.peer_id, peer_id);
    assert_eq!(record.addresses.len(), 1);
    assert!(!record.is_connected);
    assert_eq!(record.score, 0);
}

#[test]
fn test_peer_discovery_add_peer() {
    let local_id = test_peer_id();
    let config = DiscoveryConfig::default();
    let mut discovery = PeerDiscovery::new(local_id, config);

    let peer_id = test_peer_id();
    let addr = test_addr();
    discovery.add_peer(peer_id, addr);

    assert!(discovery.get_peer(&peer_id).is_some());
}

#[test]
fn test_peer_discovery_ban() {
    let local_id = test_peer_id();
    let config = DiscoveryConfig::default();
    let mut discovery = PeerDiscovery::new(local_id, config);

    let peer_id = test_peer_id();
    discovery.ban_peer(peer_id, Duration::from_secs(60));

    assert!(discovery.is_banned(&peer_id));
}

#[test]
fn test_needs_peers() {
    let local_id = test_peer_id();
    let config = DiscoveryConfig::default().min_peers(5);
    let discovery = PeerDiscovery::new(local_id, config);

    assert!(discovery.needs_peers());
    assert!(discovery.can_accept_peers());
}

#[test]
fn test_peer_connection_tracking() {
    let local_id = test_peer_id();
    let config = DiscoveryConfig::default();
    let mut discovery = PeerDiscovery::new(local_id, config);

    let peer_id = test_peer_id();
    discovery.add_peer(peer_id, test_addr());
    discovery.peer_connected(peer_id);

    assert_eq!(discovery.connected_count(), 1);
    assert!(discovery.get_peer(&peer_id).unwrap().is_connected);

    discovery.peer_disconnected(&peer_id);
    assert_eq!(discovery.connected_count(), 0);
}
