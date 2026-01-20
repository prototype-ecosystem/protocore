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

    /// Get all known peer IDs
    pub fn known_peer_ids(&self) -> impl Iterator<Item = &PeerId> {
        self.peers.keys()
    }

    /// Get the best N peers by score
    pub fn best_peers(&self, max: usize) -> Vec<&PeerRecord> {
        let mut peers: Vec<_> = self.peers.values().collect();
        peers.sort_by(|a, b| b.score.cmp(&a.score));
        peers.truncate(max);
        peers
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

// ============================================================================
// Multi-Method Peer Discovery (5 Methods)
// ============================================================================

/// Discovery method identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryMethod {
    /// Kademlia DHT discovery
    KademliaDHT,
    /// mDNS local network discovery
    Mdns,
    /// Static peer list from configuration
    StaticPeers,
    /// DNS-based discovery (TXT records)
    Dns,
    /// Peer Exchange (PEX) with connected peers
    PeerExchange,
}

impl DiscoveryMethod {
    /// Get all available discovery methods
    pub fn all() -> &'static [DiscoveryMethod] {
        &[
            DiscoveryMethod::KademliaDHT,
            DiscoveryMethod::Mdns,
            DiscoveryMethod::StaticPeers,
            DiscoveryMethod::Dns,
            DiscoveryMethod::PeerExchange,
        ]
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            DiscoveryMethod::KademliaDHT => "Kademlia DHT",
            DiscoveryMethod::Mdns => "mDNS",
            DiscoveryMethod::StaticPeers => "Static Peers",
            DiscoveryMethod::Dns => "DNS Discovery",
            DiscoveryMethod::PeerExchange => "Peer Exchange",
        }
    }
}

/// Configuration for multi-method discovery
#[derive(Debug, Clone)]
pub struct MultiDiscoveryConfig {
    /// Base discovery configuration
    pub base: DiscoveryConfig,
    /// Enabled discovery methods
    pub enabled_methods: Vec<DiscoveryMethod>,
    /// DNS discovery domain (e.g., "peers.protocore.network")
    pub dns_domain: Option<String>,
    /// DNS discovery interval
    pub dns_interval: Duration,
    /// mDNS service name
    pub mdns_service: String,
    /// PEX request interval
    pub pex_interval: Duration,
    /// Maximum peers to request via PEX
    pub pex_max_peers: usize,
    /// Registry URL for network configuration
    pub registry_url: Option<String>,
}

impl Default for MultiDiscoveryConfig {
    fn default() -> Self {
        Self {
            base: DiscoveryConfig::default(),
            enabled_methods: vec![
                DiscoveryMethod::StaticPeers,
                DiscoveryMethod::KademliaDHT,
                DiscoveryMethod::PeerExchange,
            ],
            dns_domain: None,
            dns_interval: Duration::from_secs(300), // 5 minutes
            mdns_service: "_protocore._tcp.local".to_string(),
            pex_interval: Duration::from_secs(60),
            pex_max_peers: 20,
            registry_url: None,
        }
    }
}

impl MultiDiscoveryConfig {
    /// Enable all discovery methods
    pub fn enable_all(mut self) -> Self {
        self.enabled_methods = DiscoveryMethod::all().to_vec();
        self
    }

    /// Enable local discovery (for testnet/devnet)
    pub fn with_local_discovery(mut self) -> Self {
        self.enabled_methods.push(DiscoveryMethod::Mdns);
        self
    }

    /// Set DNS discovery domain
    pub fn with_dns(mut self, domain: &str) -> Self {
        self.dns_domain = Some(domain.to_string());
        if !self.enabled_methods.contains(&DiscoveryMethod::Dns) {
            self.enabled_methods.push(DiscoveryMethod::Dns);
        }
        self
    }

    /// Set registry URL
    pub fn with_registry(mut self, url: &str) -> Self {
        self.registry_url = Some(url.to_string());
        self
    }
}

/// Peer discovered via a specific method
#[derive(Debug, Clone)]
pub struct DiscoveredPeer {
    /// Peer ID
    pub peer_id: PeerId,
    /// Discovered addresses
    pub addresses: Vec<Multiaddr>,
    /// Discovery method used
    pub method: DiscoveryMethod,
    /// Discovery timestamp
    pub discovered_at: Instant,
    /// Priority (higher = connect first)
    pub priority: u32,
}

impl DiscoveredPeer {
    /// Create a new discovered peer
    pub fn new(peer_id: PeerId, addresses: Vec<Multiaddr>, method: DiscoveryMethod) -> Self {
        Self {
            peer_id,
            addresses,
            method,
            discovered_at: Instant::now(),
            priority: Self::method_priority(&method),
        }
    }

    /// Get default priority for discovery method
    fn method_priority(method: &DiscoveryMethod) -> u32 {
        match method {
            DiscoveryMethod::StaticPeers => 100, // Highest - configured by operator
            DiscoveryMethod::Dns => 80,          // High - curated list
            DiscoveryMethod::PeerExchange => 60, // Medium - from trusted peers
            DiscoveryMethod::KademliaDHT => 40,  // Medium-low - decentralized
            DiscoveryMethod::Mdns => 20,         // Low - local network only
        }
    }
}

/// DNS discovery result
#[derive(Debug, Clone)]
pub struct DnsDiscoveryResult {
    /// Domain queried
    pub domain: String,
    /// Discovered peer records
    pub peers: Vec<(PeerId, Vec<Multiaddr>)>,
    /// Query timestamp
    pub queried_at: Instant,
    /// TTL for results
    pub ttl: Duration,
}

/// Peer Exchange (PEX) message
#[derive(Debug, Clone)]
pub enum PexMessage {
    /// Request peers from a connected peer
    Request {
        /// Maximum peers requested
        max_peers: u32,
        /// Exclude these peers (already known)
        exclude: Vec<PeerId>,
    },
    /// Response with peer list
    Response {
        /// Peers to share
        peers: Vec<PexPeerInfo>,
    },
}

/// Peer info shared via PEX
#[derive(Debug, Clone)]
pub struct PexPeerInfo {
    /// Peer ID (encoded)
    pub peer_id_bytes: Vec<u8>,
    /// Addresses (encoded multiaddrs)
    pub addresses: Vec<Vec<u8>>,
    /// Time since last seen (seconds)
    pub last_seen_ago: u32,
    /// Connection score
    pub score: i32,
}

impl PexPeerInfo {
    /// Create from a PeerRecord
    pub fn from_record(record: &PeerRecord) -> Self {
        Self {
            peer_id_bytes: record.peer_id.to_bytes(),
            addresses: record.addresses.iter().map(|a| a.to_vec()).collect(),
            last_seen_ago: record.last_seen.elapsed().as_secs() as u32,
            score: record.score as i32,
        }
    }

    /// Convert to peer ID and addresses
    pub fn to_peer_info(&self) -> Option<(PeerId, Vec<Multiaddr>)> {
        let peer_id = PeerId::from_bytes(&self.peer_id_bytes).ok()?;
        let addresses: Vec<Multiaddr> = self
            .addresses
            .iter()
            .filter_map(|a| Multiaddr::try_from(a.clone()).ok())
            .collect();
        Some((peer_id, addresses))
    }
}

/// Multi-method peer discovery manager
pub struct MultiMethodDiscovery {
    /// Configuration
    config: MultiDiscoveryConfig,
    /// Base peer discovery (Kademlia)
    base_discovery: PeerDiscovery,
    /// Peers discovered per method
    discovered_by_method: HashMap<DiscoveryMethod, Vec<DiscoveredPeer>>,
    /// Last discovery time per method
    last_discovery: HashMap<DiscoveryMethod, Instant>,
    /// DNS cache
    dns_cache: Option<DnsDiscoveryResult>,
    /// PEX state per peer
    pex_state: HashMap<PeerId, Instant>,
}

impl MultiMethodDiscovery {
    /// Create new multi-method discovery
    pub fn new(local_peer_id: PeerId, config: MultiDiscoveryConfig) -> Self {
        Self {
            base_discovery: PeerDiscovery::new(local_peer_id, config.base.clone()),
            config,
            discovered_by_method: HashMap::new(),
            last_discovery: HashMap::new(),
            dns_cache: None,
            pex_state: HashMap::new(),
        }
    }

    /// Check if a discovery method is enabled
    pub fn is_method_enabled(&self, method: DiscoveryMethod) -> bool {
        self.config.enabled_methods.contains(&method)
    }

    /// Get enabled methods
    pub fn enabled_methods(&self) -> &[DiscoveryMethod] {
        &self.config.enabled_methods
    }

    /// Add a discovered peer
    pub fn add_discovered_peer(&mut self, peer: DiscoveredPeer) {
        // Add to base discovery
        for addr in &peer.addresses {
            self.base_discovery.add_peer(peer.peer_id, addr.clone());
        }

        // Track by method
        self.discovered_by_method
            .entry(peer.method)
            .or_default()
            .push(peer);
    }

    /// Get peers discovered by a specific method
    pub fn peers_by_method(&self, method: DiscoveryMethod) -> &[DiscoveredPeer] {
        self.discovered_by_method
            .get(&method)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    /// Check if DNS discovery is due
    pub fn should_query_dns(&self) -> bool {
        if !self.is_method_enabled(DiscoveryMethod::Dns) || self.config.dns_domain.is_none() {
            return false;
        }

        match self.last_discovery.get(&DiscoveryMethod::Dns) {
            Some(last) => last.elapsed() >= self.config.dns_interval,
            None => true,
        }
    }

    /// Check if PEX request is due for a peer
    pub fn should_request_pex(&self, peer_id: &PeerId) -> bool {
        if !self.is_method_enabled(DiscoveryMethod::PeerExchange) {
            return false;
        }

        match self.pex_state.get(peer_id) {
            Some(last) => last.elapsed() >= self.config.pex_interval,
            None => true,
        }
    }

    /// Mark DNS discovery completed
    pub fn mark_dns_completed(&mut self, result: DnsDiscoveryResult) {
        for (peer_id, addresses) in &result.peers {
            let peer = DiscoveredPeer::new(*peer_id, addresses.clone(), DiscoveryMethod::Dns);
            self.add_discovered_peer(peer);
        }
        self.last_discovery
            .insert(DiscoveryMethod::Dns, Instant::now());
        self.dns_cache = Some(result);
    }

    /// Mark PEX request sent
    pub fn mark_pex_requested(&mut self, peer_id: PeerId) {
        self.pex_state.insert(peer_id, Instant::now());
    }

    /// Handle PEX response
    pub fn handle_pex_response(&mut self, _from: PeerId, peers: Vec<PexPeerInfo>) {
        for pex_info in peers {
            if let Some((peer_id, addresses)) = pex_info.to_peer_info() {
                let peer =
                    DiscoveredPeer::new(peer_id, addresses, DiscoveryMethod::PeerExchange);
                self.add_discovered_peer(peer);
            }
        }
        self.last_discovery
            .insert(DiscoveryMethod::PeerExchange, Instant::now());
    }

    /// Create a PEX request message
    pub fn create_pex_request(&self) -> PexMessage {
        let known: Vec<PeerId> = self.base_discovery.known_peer_ids().cloned().collect();
        PexMessage::Request {
            max_peers: self.config.pex_max_peers as u32,
            exclude: known,
        }
    }

    /// Create a PEX response message
    pub fn create_pex_response(&self, max_peers: usize) -> PexMessage {
        let peers: Vec<PexPeerInfo> = self
            .base_discovery
            .best_peers(max_peers)
            .iter()
            .map(|r| PexPeerInfo::from_record(r))
            .collect();
        PexMessage::Response { peers }
    }

    /// Add static peers from configuration
    pub fn add_static_peers(&mut self, peers: Vec<(PeerId, Multiaddr)>) {
        for (peer_id, addr) in peers {
            let peer = DiscoveredPeer::new(peer_id, vec![addr], DiscoveryMethod::StaticPeers);
            self.add_discovered_peer(peer);
        }
        self.last_discovery
            .insert(DiscoveryMethod::StaticPeers, Instant::now());
    }

    /// Add mDNS discovered peer
    pub fn add_mdns_peer(&mut self, peer_id: PeerId, addresses: Vec<Multiaddr>) {
        let peer = DiscoveredPeer::new(peer_id, addresses, DiscoveryMethod::Mdns);
        self.add_discovered_peer(peer);
        self.last_discovery
            .insert(DiscoveryMethod::Mdns, Instant::now());
    }

    /// Get discovery statistics
    pub fn stats(&self) -> DiscoveryStats {
        let mut by_method = HashMap::new();
        for method in DiscoveryMethod::all() {
            let count = self
                .discovered_by_method
                .get(method)
                .map(|v| v.len())
                .unwrap_or(0);
            by_method.insert(*method, count);
        }

        DiscoveryStats {
            total_known: self.base_discovery.known_peers().count(),
            total_connected: self.base_discovery.connected_count(),
            by_method,
            methods_enabled: self.config.enabled_methods.len(),
            dns_cached: self.dns_cache.is_some(),
        }
    }

    /// Get base discovery (for Kademlia operations)
    pub fn base(&self) -> &PeerDiscovery {
        &self.base_discovery
    }

    /// Get mutable base discovery
    pub fn base_mut(&mut self) -> &mut PeerDiscovery {
        &mut self.base_discovery
    }
}

/// Statistics about peer discovery
#[derive(Debug, Clone)]
pub struct DiscoveryStats {
    /// Total known peers
    pub total_known: usize,
    /// Total connected peers
    pub total_connected: usize,
    /// Peers discovered by method
    pub by_method: HashMap<DiscoveryMethod, usize>,
    /// Number of enabled methods
    pub methods_enabled: usize,
    /// Whether DNS cache is populated
    pub dns_cached: bool,
}

// ============================================================================
// DNS Discovery Helper Functions
// ============================================================================

/// DNS record format for peer discovery
/// TXT record format: "peer=<peer_id> addr=<multiaddr1> addr=<multiaddr2>"
pub mod dns {
    use super::*;

    /// Parse a DNS TXT record into peer info
    pub fn parse_txt_record(record: &str) -> Option<(PeerId, Vec<Multiaddr>)> {
        let mut peer_id: Option<PeerId> = None;
        let mut addresses = Vec::new();

        for part in record.split_whitespace() {
            if let Some(id_str) = part.strip_prefix("peer=") {
                peer_id = id_str.parse().ok();
            } else if let Some(addr_str) = part.strip_prefix("addr=") {
                if let Ok(addr) = addr_str.parse() {
                    addresses.push(addr);
                }
            }
        }

        peer_id.map(|id| (id, addresses))
    }

    /// Format peer info as DNS TXT record
    pub fn format_txt_record(peer_id: &PeerId, addresses: &[Multiaddr]) -> String {
        let mut record = format!("peer={}", peer_id);
        for addr in addresses {
            record.push_str(&format!(" addr={}", addr));
        }
        record
    }

    /// DNS domain for a network (e.g., "testnet" -> "_peers._protocore.testnet.network")
    pub fn discovery_domain(network: &str, base_domain: &str) -> String {
        format!("_peers._protocore.{}.{}", network, base_domain)
    }
}

#[cfg(test)]
mod multi_discovery_tests {
    use super::*;

    #[test]
    fn test_discovery_methods() {
        assert_eq!(DiscoveryMethod::all().len(), 5);
        assert_eq!(DiscoveryMethod::KademliaDHT.name(), "Kademlia DHT");
        assert_eq!(DiscoveryMethod::Mdns.name(), "mDNS");
    }

    #[test]
    fn test_method_priority() {
        // Static peers should have highest priority
        let static_peer = DiscoveredPeer::new(
            PeerId::random(),
            vec![],
            DiscoveryMethod::StaticPeers,
        );
        let dht_peer = DiscoveredPeer::new(
            PeerId::random(),
            vec![],
            DiscoveryMethod::KademliaDHT,
        );
        assert!(static_peer.priority > dht_peer.priority);
    }

    #[test]
    fn test_multi_discovery_config() {
        let config = MultiDiscoveryConfig::default()
            .enable_all()
            .with_dns("peers.example.com")
            .with_registry("https://registry.example.com");

        assert!(config.enabled_methods.contains(&DiscoveryMethod::Dns));
        assert!(config.dns_domain.is_some());
        assert!(config.registry_url.is_some());
    }

    #[test]
    fn test_pex_message() {
        let request = PexMessage::Request {
            max_peers: 10,
            exclude: vec![],
        };

        match request {
            PexMessage::Request { max_peers, .. } => {
                assert_eq!(max_peers, 10);
            }
            _ => panic!("Expected Request"),
        }
    }

    #[test]
    fn test_dns_parsing() {
        let record = "peer=12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN addr=/ip4/127.0.0.1/tcp/9000";
        let result = dns::parse_txt_record(record);
        assert!(result.is_some());
        let (peer_id, addresses) = result.unwrap();
        assert!(!addresses.is_empty());
        assert_eq!(peer_id.to_string(), "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN");
    }

    #[test]
    fn test_discovery_domain() {
        let domain = dns::discovery_domain("testnet", "protocore.network");
        assert_eq!(domain, "_peers._protocore.testnet.protocore.network");
    }
}
