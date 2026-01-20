//! Main NetworkService for Proto Core P2P networking.
//!
//! This module provides the high-level network service that:
//! - Initializes the libp2p swarm with noise encryption and yamux multiplexing
//! - Manages connections to peers
//! - Broadcasts messages to the network
//! - Dispatches incoming messages to appropriate handlers

use crate::{
    behaviour::{ProtocoreBehaviour, ProtocoreBehaviourEvent},
    discovery::{DiscoveryConfig, PeerDiscovery, QueryType},
    gossip::{GossipMessage, TopicSubscription, Topics},
    Error, Result,
};
use futures::StreamExt;
use libp2p::{
    core::transport::upgrade::Version,
    gossipsub::{self, MessageAcceptance},
    identify::Event as IdentifyEvent,
    kad::Event as KademliaEvent,
    noise, tcp, yamux, Multiaddr, PeerId, Swarm, SwarmBuilder,
};
use std::{
    collections::{HashMap, HashSet},
    path::PathBuf,
    time::Duration,
};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Network configuration
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Address to listen on
    pub listen_addr: Multiaddr,
    /// External address (for NAT traversal announcement)
    pub external_addr: Option<Multiaddr>,
    /// Bootstrap/seed nodes
    pub boot_nodes: Vec<(PeerId, Multiaddr)>,
    /// Minimum peer count to maintain
    pub min_peers: usize,
    /// Maximum peer count
    pub max_peers: usize,
    /// Enable NAT traversal (relay, autonat)
    pub enable_nat_traversal: bool,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Peer discovery configuration
    pub discovery: DiscoveryConfig,
    /// Path to persist P2P identity keypair (if None, generates ephemeral key)
    pub p2p_key_path: Option<PathBuf>,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            listen_addr: "/ip4/0.0.0.0/tcp/30333".parse().unwrap(),
            external_addr: None,
            boot_nodes: Vec::new(),
            min_peers: 8,
            max_peers: 50,
            enable_nat_traversal: true,
            connection_timeout: Duration::from_secs(30),
            discovery: DiscoveryConfig::default(),
            p2p_key_path: None,
        }
    }
}

impl NetworkConfig {
    /// Create config with specific listen address
    pub fn with_listen_addr(addr: &str) -> Result<Self> {
        let listen_addr: Multiaddr = addr
            .parse()
            .map_err(|e| Error::Config(format!("Invalid listen address: {}", e)))?;
        Ok(Self {
            listen_addr,
            ..Default::default()
        })
    }

    /// Add a boot node
    pub fn add_boot_node(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.boot_nodes.push((peer_id, addr.clone()));
        self.discovery = self.discovery.add_boot_node(peer_id, addr);
        self
    }

    /// Set external address for NAT
    pub fn external_addr(mut self, addr: Multiaddr) -> Self {
        self.external_addr = Some(addr);
        self
    }
}

/// Information about a connected peer
#[derive(Debug, Clone)]
pub struct PeerInfo {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses
    pub addresses: Vec<Multiaddr>,
    /// Protocol version
    pub protocol_version: Option<String>,
    /// Agent version
    pub agent_version: Option<String>,
    /// Topics the peer is subscribed to
    pub subscribed_topics: Vec<String>,
    /// Connection status
    pub connected: bool,
}

/// Network message types for internal routing
#[derive(Debug, Clone)]
pub enum NetworkMessage {
    /// Consensus message (proposal, vote, etc.)
    Consensus(GossipMessage),
    /// Block-related message
    Block(GossipMessage),
    /// Transaction message
    Transaction(GossipMessage),
}

/// Events emitted by the network service
#[derive(Debug, Clone)]
pub enum NetworkEvent {
    /// New peer connected
    PeerConnected(PeerId),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Received consensus message
    ConsensusMessage {
        /// Source peer
        source: PeerId,
        /// The message
        message: GossipMessage,
    },
    /// Received new block
    NewBlock {
        /// Source peer
        source: PeerId,
        /// The message
        message: GossipMessage,
    },
    /// Received new transaction
    NewTransaction {
        /// Source peer
        source: PeerId,
        /// The message
        message: GossipMessage,
    },
    /// Peer discovery completed
    DiscoveryComplete,
    /// Network listening on address
    Listening(Multiaddr),
    /// Error occurred
    Error(String),
}

/// Commands that can be sent to the network service
#[derive(Debug)]
pub enum Command {
    /// Broadcast a gossip message
    Broadcast(GossipMessage),
    /// Connect to a peer
    Connect(PeerId, Multiaddr),
    /// Disconnect from a peer
    Disconnect(PeerId),
    /// Ban a peer
    Ban(PeerId, Duration),
    /// Unban a peer
    Unban(PeerId),
    /// Get connected peers
    GetPeers(mpsc::Sender<Vec<PeerInfo>>),
    /// Shutdown the network
    Shutdown,
}

/// Handle for sending commands to the network service
#[derive(Clone)]
pub struct NetworkHandle {
    command_tx: mpsc::Sender<Command>,
}

impl NetworkHandle {
    /// Create a new network handle
    pub fn new(command_tx: mpsc::Sender<Command>) -> Self {
        Self { command_tx }
    }

    /// Broadcast a message to the network
    pub async fn broadcast(&self, message: GossipMessage) -> Result<()> {
        self.command_tx
            .send(Command::Broadcast(message))
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }

    /// Connect to a peer
    pub async fn connect(&self, peer_id: PeerId, addr: Multiaddr) -> Result<()> {
        self.command_tx
            .send(Command::Connect(peer_id, addr))
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }

    /// Disconnect from a peer
    pub async fn disconnect(&self, peer_id: PeerId) -> Result<()> {
        self.command_tx
            .send(Command::Disconnect(peer_id))
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }

    /// Ban a peer
    pub async fn ban(&self, peer_id: PeerId, duration: Duration) -> Result<()> {
        self.command_tx
            .send(Command::Ban(peer_id, duration))
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }

    /// Unban a peer
    pub async fn unban(&self, peer_id: PeerId) -> Result<()> {
        self.command_tx
            .send(Command::Unban(peer_id))
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }

    /// Get list of connected peers
    pub async fn get_peers(&self) -> Result<Vec<PeerInfo>> {
        let (tx, mut rx) = mpsc::channel(1);
        self.command_tx
            .send(Command::GetPeers(tx))
            .await
            .map_err(|e| Error::Channel(e.to_string()))?;
        rx.recv()
            .await
            .ok_or_else(|| Error::Channel("Failed to receive peers".to_string()))
    }

    /// Shutdown the network service
    pub async fn shutdown(&self) -> Result<()> {
        self.command_tx
            .send(Command::Shutdown)
            .await
            .map_err(|e| Error::Channel(e.to_string()))
    }
}

/// Main network service
pub struct NetworkService {
    /// The libp2p swarm
    swarm: Swarm<ProtocoreBehaviour>,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Network configuration
    config: NetworkConfig,
    /// Topic subscriptions
    subscriptions: TopicSubscription,
    /// Peer discovery manager
    discovery: PeerDiscovery,
    /// Event sender for external consumers
    event_tx: mpsc::Sender<NetworkEvent>,
    /// Command receiver
    command_rx: mpsc::Receiver<Command>,
    /// Peer information cache
    peer_info: HashMap<PeerId, PeerInfo>,
    /// Topics instance
    topics: Topics,
    /// Pending dials
    pending_dials: HashSet<PeerId>,
}

impl NetworkService {
    /// Create a new network service
    pub async fn new(
        config: NetworkConfig,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<(Self, NetworkHandle)> {
        // Load or generate keypair for this node
        let keypair = Self::load_or_generate_keypair(&config.p2p_key_path)?;
        Self::with_keypair(keypair, config, event_tx).await
    }

    /// Load keypair from file if it exists, otherwise generate and save a new one
    fn load_or_generate_keypair(key_path: &Option<PathBuf>) -> Result<libp2p::identity::Keypair> {
        match key_path {
            Some(path) => {
                if path.exists() {
                    // Load existing key from protobuf encoding
                    let key_bytes = std::fs::read(path)
                        .map_err(|e| Error::Config(format!("Failed to read P2P key file: {}", e)))?;
                    let keypair = libp2p::identity::Keypair::from_protobuf_encoding(&key_bytes)
                        .map_err(|e| Error::Config(format!("Invalid P2P key: {}", e)))?;
                    let peer_id = PeerId::from(keypair.public());
                    info!(%peer_id, path = %path.display(), "Loaded P2P identity from file");
                    Ok(keypair)
                } else {
                    // Generate new key and save it in protobuf encoding
                    let keypair = libp2p::identity::Keypair::generate_ed25519();
                    let key_bytes = keypair.to_protobuf_encoding()
                        .map_err(|e| Error::Config(format!("Failed to encode P2P key: {}", e)))?;

                    // Create parent directory if it doesn't exist
                    if let Some(parent) = path.parent() {
                        std::fs::create_dir_all(parent)
                            .map_err(|e| Error::Config(format!("Failed to create key directory: {}", e)))?;
                    }

                    std::fs::write(path, &key_bytes)
                        .map_err(|e| Error::Config(format!("Failed to write P2P key file: {}", e)))?;

                    let peer_id = PeerId::from(keypair.public());
                    info!(%peer_id, path = %path.display(), "Generated and saved new P2P identity");
                    Ok(keypair)
                }
            }
            None => {
                // No key path specified, generate ephemeral key
                let keypair = libp2p::identity::Keypair::generate_ed25519();
                let peer_id = PeerId::from(keypair.public());
                info!(%peer_id, "Generated ephemeral P2P identity (no persistence)");
                Ok(keypair)
            }
        }
    }

    /// Create a new network service with a specific keypair
    pub async fn with_keypair(
        keypair: libp2p::identity::Keypair,
        config: NetworkConfig,
        event_tx: mpsc::Sender<NetworkEvent>,
    ) -> Result<(Self, NetworkHandle)> {
        let local_peer_id = PeerId::from(keypair.public());
        info!(%local_peer_id, "Initializing network service");

        // Build the transport with noise encryption and yamux multiplexing
        let swarm = SwarmBuilder::with_existing_identity(keypair.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|e| Error::Transport(e.to_string()))?
            .with_dns()
            .map_err(|e| Error::Transport(e.to_string()))?
            .with_behaviour(|key| {
                ProtocoreBehaviour::new(key, local_peer_id)
                    .expect("Failed to create behaviour")
            })
            .map_err(|e| Error::Transport(e.to_string()))?
            .with_swarm_config(|cfg| {
                cfg.with_idle_connection_timeout(Duration::from_secs(60))
            })
            .build();

        // Create discovery manager
        let discovery = PeerDiscovery::new(local_peer_id, config.discovery.clone());

        // Create command channel
        let (command_tx, command_rx) = mpsc::channel(1000);
        let handle = NetworkHandle::new(command_tx);

        let service = Self {
            swarm,
            local_peer_id,
            config,
            subscriptions: TopicSubscription::new(),
            discovery,
            event_tx,
            command_rx,
            peer_info: HashMap::new(),
            topics: Topics::new(),
            pending_dials: HashSet::new(),
        };

        Ok((service, handle))
    }

    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }

    /// Start the network service
    pub async fn run(&mut self) -> Result<()> {
        // Start listening
        self.swarm
            .listen_on(self.config.listen_addr.clone())
            .map_err(|e| Error::Listen(e.to_string()))?;

        // Subscribe to all topics
        self.subscribe_to_topics()?;

        // Initialize Kademlia with boot nodes
        self.discovery.init_kademlia(&mut self.swarm.behaviour_mut().kademlia);

        // Start bootstrap
        if !self.config.boot_nodes.is_empty() {
            self.discovery.start_bootstrap(&mut self.swarm.behaviour_mut().kademlia)?;
        } else {
            self.discovery.mark_bootstrapped();
        }

        // Connect to boot nodes
        for (peer_id, addr) in self.config.boot_nodes.clone() {
            self.dial_peer(peer_id, addr);
        }

        // Main event loop
        self.event_loop().await
    }

    /// Subscribe to gossipsub topics
    fn subscribe_to_topics(&mut self) -> Result<()> {
        let behaviour = self.swarm.behaviour_mut();

        behaviour.subscribe(&self.topics.consensus)?;
        behaviour.subscribe(&self.topics.blocks)?;
        behaviour.subscribe(&self.topics.transactions)?;

        self.subscriptions.mark_subscribed(&self.topics.consensus.to_string());
        self.subscriptions.mark_subscribed(&self.topics.blocks.to_string());
        self.subscriptions.mark_subscribed(&self.topics.transactions.to_string());

        info!("Subscribed to gossipsub topics");
        Ok(())
    }

    /// Main event loop
    async fn event_loop(&mut self) -> Result<()> {
        let mut peer_refresh_interval = tokio::time::interval(Duration::from_secs(30));
        let mut cleanup_interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                // Handle swarm events
                event = self.swarm.select_next_some() => {
                    self.handle_swarm_event(event).await;
                }

                // Handle commands
                Some(command) = self.command_rx.recv() => {
                    if self.handle_command(command).await? {
                        // Shutdown requested
                        info!("Network service shutting down");
                        return Ok(());
                    }
                }

                // Periodic peer refresh
                _ = peer_refresh_interval.tick() => {
                    self.maintain_peers().await;
                }

                // Periodic cleanup
                _ = cleanup_interval.tick() => {
                    self.discovery.cleanup_expired_bans();
                }
            }
        }
    }

    /// Handle swarm events
    async fn handle_swarm_event(&mut self, event: libp2p::swarm::SwarmEvent<ProtocoreBehaviourEvent>) {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(behaviour_event) => {
                self.handle_behaviour_event(behaviour_event).await;
            }
            libp2p::swarm::SwarmEvent::ConnectionEstablished {
                peer_id, endpoint, ..
            } => {
                debug!(%peer_id, ?endpoint, "Connection established");
                self.pending_dials.remove(&peer_id);
                self.discovery.peer_connected(peer_id);
                self.peer_info.entry(peer_id).or_insert_with(|| PeerInfo {
                    peer_id,
                    addresses: vec![endpoint.get_remote_address().clone()],
                    protocol_version: None,
                    agent_version: None,
                    subscribed_topics: Vec::new(),
                    connected: true,
                });
                let _ = self.event_tx.send(NetworkEvent::PeerConnected(peer_id)).await;
            }
            libp2p::swarm::SwarmEvent::ConnectionClosed { peer_id, cause, .. } => {
                debug!(%peer_id, ?cause, "Connection closed");
                self.discovery.peer_disconnected(&peer_id);
                if let Some(info) = self.peer_info.get_mut(&peer_id) {
                    info.connected = false;
                }
                let _ = self.event_tx.send(NetworkEvent::PeerDisconnected(peer_id)).await;
            }
            libp2p::swarm::SwarmEvent::NewListenAddr { address, .. } => {
                info!(%address, "Listening on address");
                let _ = self.event_tx.send(NetworkEvent::Listening(address)).await;
            }
            libp2p::swarm::SwarmEvent::OutgoingConnectionError { peer_id, error, .. } => {
                if let Some(peer_id) = peer_id {
                    warn!(%peer_id, %error, "Outgoing connection error");
                    self.pending_dials.remove(&peer_id);
                    if let Some(record) = self.discovery.get_peer_mut(&peer_id) {
                        record.penalize(5);
                    }
                }
            }
            libp2p::swarm::SwarmEvent::IncomingConnectionError { error, .. } => {
                warn!(%error, "Incoming connection error");
            }
            _ => {}
        }
    }

    /// Handle behaviour events
    async fn handle_behaviour_event(&mut self, event: ProtocoreBehaviourEvent) {
        match event {
            ProtocoreBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                propagation_source,
                message_id,
                message,
            }) => {
                self.handle_gossip_message(propagation_source, message_id, message)
                    .await;
            }
            ProtocoreBehaviourEvent::Gossipsub(gossipsub::Event::Subscribed { peer_id, topic }) => {
                debug!(%peer_id, %topic, "Peer subscribed to topic");
                if let Some(info) = self.peer_info.get_mut(&peer_id) {
                    info.subscribed_topics.push(topic.to_string());
                }
            }
            ProtocoreBehaviourEvent::Gossipsub(gossipsub::Event::Unsubscribed {
                peer_id,
                topic,
            }) => {
                debug!(%peer_id, %topic, "Peer unsubscribed from topic");
                if let Some(info) = self.peer_info.get_mut(&peer_id) {
                    info.subscribed_topics.retain(|t| t != &topic.to_string());
                }
            }
            ProtocoreBehaviourEvent::Kademlia(event) => {
                self.handle_kademlia_event(event).await;
            }
            ProtocoreBehaviourEvent::Identify(event) => {
                self.handle_identify_event(event);
            }
            _ => {}
        }
    }

    /// Handle incoming gossip message
    async fn handle_gossip_message(
        &mut self,
        source: PeerId,
        message_id: gossipsub::MessageId,
        message: gossipsub::Message,
    ) {
        info!(%source, topic = %message.topic, data_len = message.data.len(), "Received gossip message");

        // Decode the message
        let gossip_msg = match GossipMessage::decode(&message.data) {
            Ok(msg) => msg,
            Err(e) => {
                warn!(%source, %e, "Failed to decode gossip message");
                // Report invalid message
                let _ = self.swarm.behaviour_mut().report_message_validation_result(
                    &message_id,
                    &source,
                    MessageAcceptance::Reject,
                );
                return;
            }
        };

        // Validate and accept the message
        let _ = self.swarm.behaviour_mut().report_message_validation_result(
            &message_id,
            &source,
            MessageAcceptance::Accept,
        );

        // Reward peer for valid message
        self.discovery.reward_peer(&source, 1);

        // Dispatch based on message type
        let topic_str = message.topic.to_string();
        let event = if topic_str.contains("consensus") {
            NetworkEvent::ConsensusMessage {
                source,
                message: gossip_msg,
            }
        } else if topic_str.contains("blocks") {
            NetworkEvent::NewBlock {
                source,
                message: gossip_msg,
            }
        } else if topic_str.contains("txs") {
            NetworkEvent::NewTransaction {
                source,
                message: gossip_msg,
            }
        } else {
            warn!(%topic_str, "Unknown topic");
            return;
        };

        if let Err(e) = self.event_tx.send(event).await {
            error!(%e, "Failed to send network event");
        }
    }

    /// Handle Kademlia events
    async fn handle_kademlia_event(&mut self, event: KademliaEvent) {
        self.discovery.handle_kademlia_event(&event);

        if let KademliaEvent::OutboundQueryProgressed { id, result, .. } = &event {
            if let Some(query) = self.discovery.query_completed(id) {
                if query.query_type == QueryType::Bootstrap {
                    let _ = self.event_tx.send(NetworkEvent::DiscoveryComplete).await;
                }
            }

            // Add discovered peers to dial
            if let libp2p::kad::QueryResult::GetClosestPeers(Ok(result)) = result {
                for peer_info in &result.peers {
                    let peer_id = &peer_info.peer_id;
                    if !self.is_connected(peer_id) && self.discovery.can_accept_peers() {
                        // Try using the addresses from the peer info directly
                        if let Some(addr) = peer_info.addrs.first() {
                            self.dial_peer(*peer_id, addr.clone());
                        } else if let Some(record) = self.discovery.get_peer(peer_id) {
                            if let Some(addr) = record.addresses.first() {
                                self.dial_peer(*peer_id, addr.clone());
                            }
                        }
                    }
                }
            }
        }
    }

    /// Handle Identify events
    fn handle_identify_event(&mut self, event: IdentifyEvent) {
        match event {
            IdentifyEvent::Received { peer_id, info, connection_id: _ } => {
                debug!(%peer_id, agent = %info.agent_version, "Received identify info");

                // Add addresses to Kademlia
                for addr in &info.listen_addrs {
                    self.swarm
                        .behaviour_mut()
                        .kademlia
                        .add_address(&peer_id, addr.clone());
                    self.discovery.add_peer(peer_id, addr.clone());
                }

                // Update peer info
                self.peer_info
                    .entry(peer_id)
                    .and_modify(|p| {
                        p.protocol_version = Some(info.protocol_version.clone());
                        p.agent_version = Some(info.agent_version.clone());
                        p.addresses = info.listen_addrs.clone();
                    })
                    .or_insert_with(|| PeerInfo {
                        peer_id,
                        addresses: info.listen_addrs,
                        protocol_version: Some(info.protocol_version),
                        agent_version: Some(info.agent_version),
                        subscribed_topics: Vec::new(),
                        connected: true,
                    });
            }
            IdentifyEvent::Sent { peer_id, connection_id: _ } => {
                debug!(%peer_id, "Sent identify info");
            }
            IdentifyEvent::Error { peer_id, error, connection_id: _ } => {
                warn!(%peer_id, %error, "Identify error");
            }
            _ => {}
        }
    }

    /// Handle commands
    async fn handle_command(&mut self, command: Command) -> Result<bool> {
        match command {
            Command::Broadcast(message) => {
                // Don't let broadcast failures crash the network service
                // (e.g., if there are no peers to broadcast to)
                if let Err(e) = self.broadcast_message(message) {
                    debug!(error = %e, "Failed to broadcast message (non-fatal)");
                }
            }
            Command::Connect(peer_id, addr) => {
                self.dial_peer(peer_id, addr);
            }
            Command::Disconnect(peer_id) => {
                self.disconnect_peer(&peer_id);
            }
            Command::Ban(peer_id, duration) => {
                self.ban_peer(peer_id, duration);
            }
            Command::Unban(peer_id) => {
                self.unban_peer(&peer_id);
            }
            Command::GetPeers(tx) => {
                let peers: Vec<PeerInfo> = self.peer_info.values().cloned().collect();
                let _ = tx.send(peers).await;
            }
            Command::Shutdown => {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Broadcast a message to the network
    pub fn broadcast_message(&mut self, message: GossipMessage) -> Result<()> {
        let topic = message.topic(&self.topics);
        let data = message.encode()?;

        info!(
            topic = %topic,
            data_len = data.len(),
            msg_type = ?message.message_type(),
            "Broadcasting gossip message"
        );

        self.swarm
            .behaviour_mut()
            .publish(topic, data)
            .map_err(|e| Error::Gossipsub(e.to_string()))?;

        Ok(())
    }

    /// Broadcast a proposal
    pub fn broadcast_proposal(&mut self, proposal: crate::gossip::Proposal) -> Result<()> {
        self.broadcast_message(GossipMessage::Proposal(proposal))
    }

    /// Broadcast a vote
    pub fn broadcast_vote(&mut self, vote: crate::gossip::Vote) -> Result<()> {
        self.broadcast_message(GossipMessage::Vote(vote))
    }

    /// Broadcast a new block
    pub fn broadcast_block(&mut self, block: crate::gossip::NewBlock) -> Result<()> {
        self.broadcast_message(GossipMessage::NewBlock(block))
    }

    /// Broadcast a new transaction
    pub fn broadcast_transaction(&mut self, tx: crate::gossip::NewTransaction) -> Result<()> {
        self.broadcast_message(GossipMessage::NewTransaction(tx))
    }

    /// Dial a peer
    fn dial_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if peer_id == self.local_peer_id {
            return;
        }

        if self.discovery.is_banned(&peer_id) {
            debug!(%peer_id, "Not dialing banned peer");
            return;
        }

        if self.pending_dials.contains(&peer_id) {
            return;
        }

        if !self.discovery.can_accept_peers() {
            debug!("Max peers reached, not dialing");
            return;
        }

        // Add to Kademlia
        self.swarm
            .behaviour_mut()
            .kademlia
            .add_address(&peer_id, addr.clone());

        // Dial the peer
        if let Err(e) = self.swarm.dial(addr.clone()) {
            warn!(%peer_id, %addr, %e, "Failed to dial peer");
        } else {
            self.pending_dials.insert(peer_id);
            debug!(%peer_id, %addr, "Dialing peer");
        }

        // Track the connection attempt
        self.discovery.add_peer(peer_id, addr);
        if let Some(record) = self.discovery.get_peer_mut(&peer_id) {
            record.mark_connection_attempt();
        }
    }

    /// Disconnect from a peer
    fn disconnect_peer(&mut self, peer_id: &PeerId) {
        let _ = self.swarm.disconnect_peer_id(*peer_id);
        self.discovery.peer_disconnected(peer_id);
    }

    /// Ban a peer
    fn ban_peer(&mut self, peer_id: PeerId, duration: Duration) {
        self.disconnect_peer(&peer_id);
        self.discovery.ban_peer(peer_id, duration);
        self.swarm.behaviour_mut().blacklist_peer(&peer_id);
    }

    /// Unban a peer
    fn unban_peer(&mut self, peer_id: &PeerId) {
        self.discovery.unban_peer(peer_id);
        self.swarm.behaviour_mut().remove_from_blacklist(peer_id);
    }

    /// Check if connected to a peer
    fn is_connected(&self, peer_id: &PeerId) -> bool {
        self.swarm.is_connected(peer_id)
    }

    /// Maintain minimum peer count
    async fn maintain_peers(&mut self) {
        // Check if we need more peers
        if self.discovery.needs_peers() {
            info!(
                connected = self.discovery.connected_count(),
                min = self.config.min_peers,
                "Need more peers, initiating discovery"
            );

            // Try to connect to known peers - collect data first to avoid borrow issues
            let peers_to_dial: Vec<_> = self
                .discovery
                .peers_to_connect(self.config.min_peers - self.discovery.connected_count())
                .into_iter()
                .filter_map(|record| {
                    record.addresses.first().map(|addr| (record.peer_id, addr.clone()))
                })
                .collect();

            for (peer_id, addr) in peers_to_dial {
                self.dial_peer(peer_id, addr);
            }

            // Start a random walk to find more peers
            if self.discovery.is_bootstrapped() {
                let random_id = PeerDiscovery::random_peer_id();
                let query_id = self.swarm.behaviour_mut().kademlia.get_closest_peers(random_id);
                self.discovery.track_query(query_id, QueryType::RandomWalk);
            }
        }

        // Check if we should refresh peer discovery
        if self.discovery.should_refresh() && self.discovery.is_bootstrapped() {
            debug!("Refreshing peer discovery");
            self.discovery.mark_refresh_started();

            if let Err(e) = self.discovery.start_bootstrap(&mut self.swarm.behaviour_mut().kademlia) {
                warn!(%e, "Failed to refresh peers");
            }
        }
    }
}
