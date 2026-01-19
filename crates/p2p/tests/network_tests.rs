//! Tests for the network service configuration and handle.

use libp2p::{Multiaddr, PeerId};
use protocore_p2p::{NetworkConfig, NetworkHandle};
use tokio::sync::mpsc;

#[test]
fn test_network_config_default() {
    let config = NetworkConfig::default();
    assert_eq!(config.min_peers, 8);
    assert_eq!(config.max_peers, 50);
    assert!(config.enable_nat_traversal);
}

#[test]
fn test_network_config_with_boot_node() {
    let peer_id = PeerId::random();
    let addr: Multiaddr = "/ip4/127.0.0.1/tcp/9000".parse().unwrap();

    let config = NetworkConfig::default().add_boot_node(peer_id, addr.clone());
    assert_eq!(config.boot_nodes.len(), 1);
    assert_eq!(config.boot_nodes[0].0, peer_id);
}

#[tokio::test]
async fn test_network_handle_clone() {
    let (tx, _rx) = mpsc::channel(10);
    let handle = NetworkHandle::new(tx);
    let _cloned = handle.clone();
}
