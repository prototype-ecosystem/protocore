//! Tests for the ProtocoreBehaviour network behaviour.

use libp2p::{gossipsub, identity::Keypair, PeerId};
use protocore_p2p::ProtocoreBehaviour;

#[test]
fn test_behaviour_creation() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let behaviour = ProtocoreBehaviour::new(&keypair, peer_id);
    assert!(behaviour.is_ok());
}

#[test]
fn test_topic_subscription() {
    let keypair = Keypair::generate_ed25519();
    let peer_id = PeerId::from(keypair.public());
    let mut behaviour = ProtocoreBehaviour::new(&keypair, peer_id).unwrap();

    let topic = gossipsub::IdentTopic::new("/protocore/test/1.0.0");
    let result = behaviour.subscribe(&topic);
    assert!(result.is_ok());
}
