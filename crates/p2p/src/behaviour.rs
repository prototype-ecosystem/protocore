//! Custom libp2p NetworkBehaviour for Protocore.
//!
//! This module combines multiple libp2p protocols into a unified behaviour:
//! - Gossipsub for pub/sub message propagation
//! - Kademlia for peer discovery
//! - Identify for peer identification

use libp2p::{
    gossipsub::{self, Behaviour as Gossipsub, Event as GossipsubEvent, MessageAuthenticity},
    identify::{self, Behaviour as Identify, Event as IdentifyEvent},
    kad::{self, store::MemoryStore, Behaviour as Kademlia, Event as KademliaEvent},
    swarm::NetworkBehaviour,
    PeerId,
};
use std::time::Duration;

/// Combined network behaviour events
#[derive(Debug)]
pub enum ProtocoreBehaviourEvent {
    /// Gossipsub event
    Gossipsub(GossipsubEvent),
    /// Kademlia event
    Kademlia(KademliaEvent),
    /// Identify event
    Identify(IdentifyEvent),
}

impl From<GossipsubEvent> for ProtocoreBehaviourEvent {
    fn from(event: GossipsubEvent) -> Self {
        ProtocoreBehaviourEvent::Gossipsub(event)
    }
}

impl From<KademliaEvent> for ProtocoreBehaviourEvent {
    fn from(event: KademliaEvent) -> Self {
        ProtocoreBehaviourEvent::Kademlia(event)
    }
}

impl From<IdentifyEvent> for ProtocoreBehaviourEvent {
    fn from(event: IdentifyEvent) -> Self {
        ProtocoreBehaviourEvent::Identify(event)
    }
}

/// Combined network behaviour for Proto Core
#[derive(NetworkBehaviour)]
#[behaviour(to_swarm = "ProtocoreBehaviourEvent")]
pub struct ProtocoreBehaviour {
    /// Gossipsub for pub/sub messaging
    pub gossipsub: Gossipsub,
    /// Kademlia DHT for peer discovery
    pub kademlia: Kademlia<MemoryStore>,
    /// Identify protocol for peer identification
    pub identify: Identify,
}

impl ProtocoreBehaviour {
    /// Create a new Proto Core behaviour
    ///
    /// # Arguments
    /// * `keypair` - The local node's identity keypair
    /// * `local_peer_id` - The local peer ID
    ///
    /// # Returns
    /// A new `ProtocoreBehaviour` or an error
    pub fn new(
        keypair: &libp2p::identity::Keypair,
        local_peer_id: PeerId,
    ) -> crate::Result<Self> {
        // Configure Gossipsub
        let gossipsub_config = gossipsub::ConfigBuilder::default()
            // Set message validation mode
            .validation_mode(gossipsub::ValidationMode::Strict)
            // Heartbeat interval
            .heartbeat_interval(Duration::from_secs(1))
            // History parameters for message deduplication
            .history_length(12)
            .history_gossip(3)
            // Mesh parameters (set low to work with small validator sets)
            .mesh_n(2) // Target number of peers in mesh
            .mesh_n_low(1) // Minimum peers in mesh
            .mesh_n_high(6) // Maximum peers in mesh
            .mesh_outbound_min(1) // Minimum outbound peers
            // Gossip parameters
            .gossip_lazy(2) // Peers for lazy push
            .gossip_factor(0.25) // Fraction of peers to gossip to
            // Flood publishing for important messages
            .flood_publish(true)
            // Message ID function based on content hash
            .message_id_fn(|msg| {
                use std::hash::{Hash, Hasher};
                let mut hasher = std::collections::hash_map::DefaultHasher::new();
                msg.data.hash(&mut hasher);
                msg.topic.hash(&mut hasher);
                gossipsub::MessageId::from(hasher.finish().to_be_bytes().to_vec())
            })
            // Max message size (1 MB for blocks)
            .max_transmit_size(1024 * 1024)
            // IWANT/IHAVE parameters
            .iwant_followup_time(Duration::from_secs(3))
            .build()
            .map_err(|e| crate::Error::Gossipsub(e.to_string()))?;

        let gossipsub = Gossipsub::new(
            MessageAuthenticity::Signed(keypair.clone()),
            gossipsub_config,
        )
        .map_err(|e| crate::Error::Gossipsub(e.to_string()))?;

        // Configure Kademlia
        let mut kademlia_config = kad::Config::new(libp2p::StreamProtocol::new("/protocore/kad/1.0.0"));
        kademlia_config
            .set_query_timeout(Duration::from_secs(60))
            .set_replication_factor(std::num::NonZeroUsize::new(20).unwrap())
            .set_parallelism(std::num::NonZeroUsize::new(3).unwrap())
            .set_record_ttl(Some(Duration::from_secs(3600 * 24))) // 24 hours
            .set_provider_record_ttl(Some(Duration::from_secs(3600 * 24)))
            .set_provider_publication_interval(Some(Duration::from_secs(3600 * 12)));

        let store = MemoryStore::new(local_peer_id);
        let kademlia = Kademlia::with_config(local_peer_id, store, kademlia_config);

        // Configure Identify
        let identify_config = identify::Config::new(
            "/protocore/1.0.0".to_string(),
            keypair.public(),
        )
        .with_agent_version(format!("protocore/{}", env!("CARGO_PKG_VERSION")))
        .with_interval(Duration::from_secs(60)) // Periodic re-identification
        .with_push_listen_addr_updates(true);

        let identify = Identify::new(identify_config);

        Ok(Self {
            gossipsub,
            kademlia,
            identify,
        })
    }

    /// Subscribe to a gossipsub topic
    pub fn subscribe(&mut self, topic: &gossipsub::IdentTopic) -> crate::Result<bool> {
        self.gossipsub
            .subscribe(topic)
            .map_err(|e| crate::Error::Gossipsub(e.to_string()))
    }

    /// Unsubscribe from a gossipsub topic
    pub fn unsubscribe(&mut self, topic: &gossipsub::IdentTopic) -> crate::Result<bool> {
        self.gossipsub
            .unsubscribe(topic)
            .map_err(|e| crate::Error::Gossipsub(e.to_string()))
    }

    /// Publish a message to a topic
    pub fn publish(
        &mut self,
        topic: gossipsub::IdentTopic,
        data: impl Into<Vec<u8>>,
    ) -> crate::Result<gossipsub::MessageId> {
        self.gossipsub
            .publish(topic, data)
            .map_err(|e| crate::Error::Gossipsub(e.to_string()))
    }

    /// Add a peer to the Kademlia routing table
    pub fn add_address(&mut self, peer_id: &PeerId, addr: libp2p::Multiaddr) {
        self.kademlia.add_address(peer_id, addr);
    }

    /// Start a Kademlia bootstrap
    pub fn bootstrap(&mut self) -> crate::Result<kad::QueryId> {
        self.kademlia
            .bootstrap()
            .map_err(|e| crate::Error::Kademlia(e.to_string()))
    }

    /// Get closest peers to a peer ID
    pub fn get_closest_peers(&mut self, peer_id: PeerId) -> kad::QueryId {
        self.kademlia.get_closest_peers(peer_id)
    }

    /// Blacklist a peer from gossipsub
    pub fn blacklist_peer(&mut self, peer_id: &PeerId) {
        self.gossipsub.blacklist_peer(peer_id);
    }

    /// Remove peer from gossipsub blacklist
    pub fn remove_from_blacklist(&mut self, peer_id: &PeerId) {
        self.gossipsub.remove_blacklisted_peer(peer_id);
    }

    /// Get all peers subscribed to a topic
    pub fn mesh_peers(&self, topic: &gossipsub::TopicHash) -> impl Iterator<Item = &PeerId> {
        self.gossipsub.mesh_peers(topic)
    }

    /// Get all connected peers
    pub fn all_peers(&self) -> impl Iterator<Item = (&PeerId, Vec<&gossipsub::TopicHash>)> {
        self.gossipsub.all_peers()
    }

    /// Report message validation result
    pub fn report_message_validation_result(
        &mut self,
        msg_id: &gossipsub::MessageId,
        source: &PeerId,
        result: gossipsub::MessageAcceptance,
    ) -> crate::Result<bool> {
        self.gossipsub
            .report_message_validation_result(msg_id, source, result)
            .map_err(|e| crate::Error::Gossipsub(e.to_string()))
    }
}
