//! Peer discovery using Kademlia DHT.
//!
//! This module provides:
//! - Bootstrap from seed nodes
//! - Periodic peer refresh
//! - Minimum peer count maintenance
//! - Peer scoring and selection

use libp2p::{
    kad::{self, store::MemoryStore, Behaviour as Kademlia, Event as KademliaEvent, QueryId},
    Multiaddr, PeerId,
};
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

/// Configuration for peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// Bootstrap/seed nodes to connect to initially
    pub boot_nodes: Vec<(PeerId, Multiaddr)>,
    /// Minimum number of peers to maintain
    pub min_peers: usize,
    /// Maximum number of peers to connect to
    pub max_peers: usize,
    /// Interval for periodic peer refresh
    pub refresh_interval: Duration,
    /// Timeout for bootstrap queries
    pub bootstrap_timeout: Duration,
    /// Whether to enable automatic peer discovery
    pub enable_discovery: bool,
    /// Protocol ID for Kademlia
    pub protocol_id: String,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            boot_nodes: Vec::new(),
            min_peers: 8,
            max_peers: 50,
            refresh_interval: Duration::from_secs(300), // 5 minutes
            bootstrap_timeout: Duration::from_secs(60),
            enable_discovery: true,
            protocol_id: "/protocore/kad/1.0.0".to_string(),
        }
    }
}

impl DiscoveryConfig {
    /// Create a new discovery config with specified boot nodes
    pub fn with_boot_nodes(boot_nodes: Vec<(PeerId, Multiaddr)>) -> Self {
        Self {
            boot_nodes,
            ..Default::default()
        }
    }

    /// Set minimum peer count
    pub fn min_peers(mut self, count: usize) -> Self {
        self.min_peers = count;
        self
    }

    /// Set maximum peer count
    pub fn max_peers(mut self, count: usize) -> Self {
        self.max_peers = count;
        self
    }

    /// Set refresh interval
    pub fn refresh_interval(mut self, interval: Duration) -> Self {
        self.refresh_interval = interval;
        self
    }

    /// Add a boot node
    pub fn add_boot_node(mut self, peer_id: PeerId, addr: Multiaddr) -> Self {
        self.boot_nodes.push((peer_id, addr));
        self
    }
}

/// Peer information with metadata
#[derive(Debug, Clone)]
pub struct PeerRecord {
    /// Peer ID
    pub peer_id: PeerId,
    /// Known addresses for this peer
    pub addresses: Vec<Multiaddr>,
    /// When this peer was first discovered
    pub discovered_at: Instant,
    /// When we last heard from this peer
    pub last_seen: Instant,
    /// Connection attempts
    pub connection_attempts: u32,
    /// Successful connections
    pub successful_connections: u32,
    /// Current connection status
    pub is_connected: bool,
    /// Peer score (higher is better)
    pub score: i64,
}

impl PeerRecord {
    /// Create a new peer record
    pub fn new(peer_id: PeerId, addr: Multiaddr) -> Self {
        let now = Instant::now();
        Self {
            peer_id,
            addresses: vec![addr],
            discovered_at: now,
            last_seen: now,
            connection_attempts: 0,
            successful_connections: 0,
            is_connected: false,
            score: 0,
        }
    }

    /// Add an address for this peer
    pub fn add_address(&mut self, addr: Multiaddr) {
        if !self.addresses.contains(&addr) {
            self.addresses.push(addr);
        }
    }

    /// Update last seen time
    pub fn touch(&mut self) {
        self.last_seen = Instant::now();
    }

    /// Mark connection attempt
    pub fn mark_connection_attempt(&mut self) {
        self.connection_attempts += 1;
    }

    /// Mark successful connection
    pub fn mark_connected(&mut self) {
        self.successful_connections += 1;
        self.is_connected = true;
        self.touch();
        // Boost score on successful connection
        self.score += 10;
    }

    /// Mark disconnection
    pub fn mark_disconnected(&mut self) {
        self.is_connected = false;
    }

    /// Apply score penalty
    pub fn penalize(&mut self, amount: i64) {
        self.score = self.score.saturating_sub(amount);
    }

    /// Apply score reward
    pub fn reward(&mut self, amount: i64) {
        self.score = self.score.saturating_add(amount);
    }

    /// Calculate connection success rate
    pub fn success_rate(&self) -> f64 {
        if self.connection_attempts == 0 {
            return 0.0;
        }
        self.successful_connections as f64 / self.connection_attempts as f64
    }
}

/// State for tracking discovery queries
#[derive(Debug)]
pub struct DiscoveryQuery {
    /// Query ID from Kademlia
    pub query_id: QueryId,
    /// When the query was started
    pub started_at: Instant,
    /// Type of query
    pub query_type: QueryType,
}

/// Type of discovery query
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    /// Initial bootstrap
    Bootstrap,
    /// Periodic refresh
    Refresh,
    /// Finding specific peer
    FindPeer,
    /// Random walk for discovery
    RandomWalk,
}

/// Peer discovery manager
pub struct PeerDiscovery {
    /// Configuration
    config: DiscoveryConfig,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Known peers
    peers: HashMap<PeerId, PeerRecord>,
    /// Connected peer IDs
    connected_peers: HashSet<PeerId>,
    /// Banned peers
    banned_peers: HashMap<PeerId, Instant>,
    /// Active discovery queries
    active_queries: HashMap<QueryId, DiscoveryQuery>,
    /// Last bootstrap time
    last_bootstrap: Option<Instant>,
    /// Last refresh time
    last_refresh: Option<Instant>,
    /// Bootstrap completed flag
    bootstrapped: bool,
}

impl PeerDiscovery {
    /// Create a new peer discovery manager
    pub fn new(local_peer_id: PeerId, config: DiscoveryConfig) -> Self {
        Self {
            config,
            local_peer_id,
            peers: HashMap::new(),
            connected_peers: HashSet::new(),
            banned_peers: HashMap::new(),
            active_queries: HashMap::new(),
            last_bootstrap: None,
            last_refresh: None,
            bootstrapped: false,
        }
    }

    /// Get discovery configuration
    pub fn config(&self) -> &DiscoveryConfig {
        &self.config
    }

    /// Check if we need more peers
    pub fn needs_peers(&self) -> bool {
        self.connected_peers.len() < self.config.min_peers
    }

    /// Check if we can accept more peers
    pub fn can_accept_peers(&self) -> bool {
        self.connected_peers.len() < self.config.max_peers
    }

    /// Get connected peer count
    pub fn connected_count(&self) -> usize {
        self.connected_peers.len()
    }

    /// Check if bootstrapping is complete
    pub fn is_bootstrapped(&self) -> bool {
        self.bootstrapped
    }

    /// Mark bootstrapping as complete
    pub fn mark_bootstrapped(&mut self) {
        self.bootstrapped = true;
        self.last_bootstrap = Some(Instant::now());
        info!("Peer discovery bootstrap complete");
    }

    /// Check if peer is banned
    pub fn is_banned(&self, peer_id: &PeerId) -> bool {
        if let Some(banned_until) = self.banned_peers.get(peer_id) {
            if Instant::now() < *banned_until {
                return true;
            }
            // Ban expired, will be cleaned up later
        }
        false
    }

    /// Ban a peer for a duration
    pub fn ban_peer(&mut self, peer_id: PeerId, duration: Duration) {
        let until = Instant::now() + duration;
        self.banned_peers.insert(peer_id, until);
        self.connected_peers.remove(&peer_id);
        if let Some(record) = self.peers.get_mut(&peer_id) {
            record.mark_disconnected();
            record.penalize(100);
        }
        warn!(?peer_id, ?duration, "Peer banned");
    }

    /// Unban a peer
    pub fn unban_peer(&mut self, peer_id: &PeerId) {
        self.banned_peers.remove(peer_id);
        debug!(?peer_id, "Peer unbanned");
    }

    /// Clean up expired bans
    pub fn cleanup_expired_bans(&mut self) {
        let now = Instant::now();
        self.banned_peers.retain(|_, until| now < *until);
    }

    /// Add a discovered peer
    pub fn add_peer(&mut self, peer_id: PeerId, addr: Multiaddr) {
        if peer_id == self.local_peer_id {
            return;
        }

        if self.is_banned(&peer_id) {
            return;
        }

        if let Some(record) = self.peers.get_mut(&peer_id) {
            record.add_address(addr);
            record.touch();
        } else {
            self.peers.insert(peer_id, PeerRecord::new(peer_id, addr));
            debug!(?peer_id, "New peer discovered");
        }
    }

    /// Mark peer as connected
    pub fn peer_connected(&mut self, peer_id: PeerId) {
        if peer_id == self.local_peer_id {
            return;
        }

        self.connected_peers.insert(peer_id);
        if let Some(record) = self.peers.get_mut(&peer_id) {
            record.mark_connected();
        }
        debug!(?peer_id, connected = self.connected_peers.len(), "Peer connected");
    }

    /// Mark peer as disconnected
    pub fn peer_disconnected(&mut self, peer_id: &PeerId) {
        self.connected_peers.remove(peer_id);
        if let Some(record) = self.peers.get_mut(peer_id) {
            record.mark_disconnected();
        }
        debug!(?peer_id, connected = self.connected_peers.len(), "Peer disconnected");
    }

    /// Get all known peers
    pub fn known_peers(&self) -> impl Iterator<Item = &PeerRecord> {
        self.peers.values()
    }

    /// Get connected peers
    pub fn connected_peers(&self) -> impl Iterator<Item = &PeerId> {
        self.connected_peers.iter()
    }

    /// Get peer record
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerRecord> {
        self.peers.get(peer_id)
    }

    /// Get mutable peer record
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerRecord> {
        self.peers.get_mut(peer_id)
    }

    /// Check if it's time to refresh peers
    pub fn should_refresh(&self) -> bool {
        match self.last_refresh {
            Some(last) => last.elapsed() >= self.config.refresh_interval,
            None => self.bootstrapped,
        }
    }

    /// Mark refresh started
    pub fn mark_refresh_started(&mut self) {
        self.last_refresh = Some(Instant::now());
    }

    /// Track a discovery query
    pub fn track_query(&mut self, query_id: QueryId, query_type: QueryType) {
        self.active_queries.insert(
            query_id,
            DiscoveryQuery {
                query_id,
                started_at: Instant::now(),
                query_type,
            },
        );
    }

    /// Handle query completion
    pub fn query_completed(&mut self, query_id: &QueryId) -> Option<DiscoveryQuery> {
        self.active_queries.remove(query_id)
    }

    /// Get peers to connect to (sorted by score)
    pub fn peers_to_connect(&self, count: usize) -> Vec<&PeerRecord> {
        let mut peers: Vec<_> = self
            .peers
            .values()
            .filter(|p| !p.is_connected && !self.is_banned(&p.peer_id))
            .collect();

        // Sort by score (descending)
        peers.sort_by(|a, b| b.score.cmp(&a.score));
        peers.truncate(count);
        peers
    }

    /// Get peers to disconnect (lowest scored connected peers)
    pub fn peers_to_disconnect(&self, count: usize) -> Vec<PeerId> {
        let mut connected: Vec<_> = self
            .connected_peers
            .iter()
            .filter_map(|pid| self.peers.get(pid))
            .collect();

        // Sort by score (ascending, so lowest first)
        connected.sort_by(|a, b| a.score.cmp(&b.score));
        connected.truncate(count);
        connected.into_iter().map(|p| p.peer_id).collect()
    }

    /// Reward a peer for good behavior
    pub fn reward_peer(&mut self, peer_id: &PeerId, amount: i64) {
        if let Some(record) = self.peers.get_mut(peer_id) {
            record.reward(amount);
        }
    }

    /// Penalize a peer for bad behavior
    pub fn penalize_peer(&mut self, peer_id: &PeerId, amount: i64) {
        if let Some(record) = self.peers.get_mut(peer_id) {
            record.penalize(amount);
        }
    }

    /// Initialize Kademlia with boot nodes
    pub fn init_kademlia(&self, kademlia: &mut Kademlia<MemoryStore>) {
        for (peer_id, addr) in &self.config.boot_nodes {
            kademlia.add_address(peer_id, addr.clone());
            debug!(?peer_id, %addr, "Added boot node to Kademlia");
        }
    }

    /// Start bootstrap process
    pub fn start_bootstrap(&mut self, kademlia: &mut Kademlia<MemoryStore>) -> crate::Result<()> {
        if self.config.boot_nodes.is_empty() {
            warn!("No boot nodes configured, skipping bootstrap");
            self.mark_bootstrapped();
            return Ok(());
        }

        match kademlia.bootstrap() {
            Ok(query_id) => {
                self.track_query(query_id, QueryType::Bootstrap);
                info!("Started Kademlia bootstrap");
                Ok(())
            }
            Err(e) => {
                warn!("Failed to start bootstrap: {:?}", e);
                Err(crate::Error::Kademlia(e.to_string()))
            }
        }
    }

    /// Handle Kademlia event
    pub fn handle_kademlia_event(&mut self, event: &KademliaEvent) {
        match event {
            KademliaEvent::OutboundQueryProgressed { id, result, .. } => {
                self.handle_query_progress(*id, result);
            }
            KademliaEvent::RoutingUpdated {
                peer, addresses, ..
            } => {
                for addr in addresses.iter() {
                    self.add_peer(*peer, addr.clone());
                }
            }
            KademliaEvent::RoutablePeer { peer, address } => {
                self.add_peer(*peer, address.clone());
            }
            KademliaEvent::PendingRoutablePeer { peer, address } => {
                self.add_peer(*peer, address.clone());
            }
            _ => {}
        }
    }

    fn handle_query_progress(
        &mut self,
        query_id: QueryId,
        result: &kad::QueryResult,
    ) {
        let query = match self.active_queries.get(&query_id) {
            Some(q) => q,
            None => return,
        };

        match result {
            kad::QueryResult::Bootstrap(Ok(stats)) => {
                info!(
                    num_remaining = stats.num_remaining,
                    "Bootstrap query progressing"
                );
                if stats.num_remaining == 0 {
                    if let Some(query) = self.query_completed(&query_id) {
                        if query.query_type == QueryType::Bootstrap {
                            self.mark_bootstrapped();
                        }
                    }
                }
            }
            kad::QueryResult::Bootstrap(Err(e)) => {
                warn!("Bootstrap failed: {:?}", e);
                self.query_completed(&query_id);
            }
            kad::QueryResult::GetClosestPeers(Ok(result)) => {
                for peer_id in &result.peers {
                    debug!(?peer_id, "Found close peer");
                }
            }
            kad::QueryResult::GetClosestPeers(Err(e)) => {
                debug!("GetClosestPeers query error: {:?}", e);
            }
            _ => {}
        }
    }

    /// Generate a random peer ID for random walk discovery
    pub fn random_peer_id() -> PeerId {
        let random_key = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(random_key.public())
    }
}
