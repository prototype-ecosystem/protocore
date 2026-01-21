//! Network Registry
//!
//! This module provides a canonical network registry that allows nodes to:
//!
//! - Discover network configurations (chain ID, genesis, validators)
//! - Get bootstrap peer lists from a central registry
//! - Fetch network parameters and RPC endpoints
//!
//! The registry supports multiple networks (mainnet, testnet, devnet) and
//! provides HTTP API for fetching configurations.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::{Multiaddr, PeerId};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

// ============================================================================
// Network Configuration Types
// ============================================================================

/// Network identifier
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkId {
    /// Production mainnet
    Mainnet,
    /// Public testnet
    Testnet,
    /// Development network
    Devnet,
    /// Local development
    Local,
    /// Custom network with chain ID
    Custom(u64),
}

impl NetworkId {
    /// Get the chain ID for this network
    pub fn chain_id(&self) -> u64 {
        match self {
            NetworkId::Mainnet => 1,
            NetworkId::Testnet => 31337,
            NetworkId::Devnet => 31338,
            NetworkId::Local => 31339,
            NetworkId::Custom(id) => *id,
        }
    }

    /// Get the network name
    pub fn name(&self) -> &'static str {
        match self {
            NetworkId::Mainnet => "mainnet",
            NetworkId::Testnet => "testnet",
            NetworkId::Devnet => "devnet",
            NetworkId::Local => "local",
            NetworkId::Custom(_) => "custom",
        }
    }

    /// Parse from string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "mainnet" => Some(NetworkId::Mainnet),
            "testnet" => Some(NetworkId::Testnet),
            "devnet" => Some(NetworkId::Devnet),
            "local" => Some(NetworkId::Local),
            _ => s.parse::<u64>().ok().map(NetworkId::Custom),
        }
    }
}

impl std::fmt::Display for NetworkId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkId::Custom(id) => write!(f, "custom-{}", id),
            _ => write!(f, "{}", self.name()),
        }
    }
}

/// Network configuration from registry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Network identifier
    pub network_id: NetworkId,
    /// Chain ID
    pub chain_id: u64,
    /// Human-readable network name
    pub name: String,
    /// Network description
    pub description: String,
    /// Genesis block hash
    pub genesis_hash: String,
    /// Native token symbol
    pub native_token: String,
    /// Native token decimals
    pub native_decimals: u8,
    /// Block time in seconds
    pub block_time_secs: u64,
    /// Bootstrap/seed nodes
    pub bootstrap_nodes: Vec<BootstrapNode>,
    /// RPC endpoints
    pub rpc_endpoints: Vec<RpcEndpoint>,
    /// Explorer URLs
    pub explorers: Vec<ExplorerInfo>,
    /// Network parameters
    pub params: NetworkParams,
    /// Last update timestamp
    pub updated_at: u64,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            network_id: NetworkId::Local,
            chain_id: 31339,
            name: "Local Network".to_string(),
            description: "Local development network".to_string(),
            genesis_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            native_token: "PCR".to_string(),
            native_decimals: 18,
            block_time_secs: 4,
            bootstrap_nodes: Vec::new(),
            rpc_endpoints: Vec::new(),
            explorers: Vec::new(),
            params: NetworkParams::default(),
            updated_at: 0,
        }
    }
}

/// Bootstrap node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Peer ID (base58 encoded)
    pub peer_id: String,
    /// Multiaddresses
    pub addresses: Vec<String>,
    /// Node name/label
    pub name: Option<String>,
    /// Operator/organization
    pub operator: Option<String>,
    /// Geographic region
    pub region: Option<String>,
}

impl BootstrapNode {
    /// Parse peer ID
    pub fn parse_peer_id(&self) -> Option<PeerId> {
        self.peer_id.parse().ok()
    }

    /// Parse addresses
    pub fn parse_addresses(&self) -> Vec<Multiaddr> {
        self.addresses
            .iter()
            .filter_map(|a| a.parse().ok())
            .collect()
    }

    /// Convert to peer ID and addresses tuple
    pub fn to_peer_info(&self) -> Option<(PeerId, Vec<Multiaddr>)> {
        let peer_id = self.parse_peer_id()?;
        let addresses = self.parse_addresses();
        if addresses.is_empty() {
            return None;
        }
        Some((peer_id, addresses))
    }
}

/// RPC endpoint information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcEndpoint {
    /// Endpoint URL
    pub url: String,
    /// Whether this is a public endpoint
    pub is_public: bool,
    /// Supported methods (empty = all)
    pub methods: Vec<String>,
    /// Rate limit (requests per minute)
    pub rate_limit: Option<u32>,
    /// Provider name
    pub provider: Option<String>,
}

/// Block explorer information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplorerInfo {
    /// Explorer name
    pub name: String,
    /// Explorer URL
    pub url: String,
    /// API endpoint (if available)
    pub api_url: Option<String>,
}

/// Network parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkParams {
    /// Minimum stake to be a validator
    pub min_validator_stake: u64,
    /// Maximum validators
    pub max_validators: u32,
    /// Epoch length in blocks
    pub epoch_length: u64,
    /// Inflation rate (basis points)
    pub inflation_rate_bp: u32,
    /// Minimum gas price
    pub min_gas_price: u64,
    /// Block gas limit
    pub block_gas_limit: u64,
}

impl Default for NetworkParams {
    fn default() -> Self {
        Self {
            min_validator_stake: 10_000_000_000_000_000_000, // 1000 tokens
            max_validators: 100,
            epoch_length: 28_800,         // ~1 day at 3s blocks
            inflation_rate_bp: 800,       // 8%
            min_gas_price: 1_000_000_000, // 1 gwei
            block_gas_limit: 30_000_000,
        }
    }
}

// ============================================================================
// Registry Configuration
// ============================================================================

/// Configuration for the network registry
#[derive(Debug, Clone)]
pub struct RegistryConfig {
    /// Registry base URL
    pub base_url: String,
    /// Refresh interval
    pub refresh_interval: Duration,
    /// Request timeout
    pub request_timeout: Duration,
    /// Enable caching
    pub enable_cache: bool,
    /// Cache TTL
    pub cache_ttl: Duration,
    /// Fallback to embedded configs if registry unavailable
    pub enable_fallback: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            base_url: "https://registry.protocore.network".to_string(),
            refresh_interval: Duration::from_secs(3600), // 1 hour
            request_timeout: Duration::from_secs(30),
            enable_cache: true,
            cache_ttl: Duration::from_secs(300), // 5 minutes
            enable_fallback: true,
        }
    }
}

impl RegistryConfig {
    /// Create config for testnet
    pub fn testnet() -> Self {
        Self {
            base_url: "https://testnet-registry.protocore.network".to_string(),
            ..Default::default()
        }
    }

    /// Create config for local development
    pub fn local() -> Self {
        Self {
            base_url: "http://localhost:8080".to_string(),
            refresh_interval: Duration::from_secs(60),
            cache_ttl: Duration::from_secs(30),
            ..Default::default()
        }
    }

    /// Set custom base URL
    pub fn with_url(mut self, url: &str) -> Self {
        self.base_url = url.to_string();
        self
    }
}

// ============================================================================
// Registry API Response Types
// ============================================================================

/// API response for listing networks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkListResponse {
    /// Available networks
    pub networks: Vec<NetworkSummary>,
    /// API version
    pub version: String,
}

/// Summary of a network for listing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Network ID
    pub id: String,
    /// Chain ID
    pub chain_id: u64,
    /// Network name
    pub name: String,
    /// Is currently active
    pub active: bool,
    /// Number of validators
    pub validator_count: u32,
}

/// API response for network details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkDetailResponse {
    /// Network configuration
    pub config: NetworkConfig,
    /// Current block height
    pub block_height: Option<u64>,
    /// Network status
    pub status: NetworkStatus,
}

/// Network status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkStatus {
    /// Network is operational
    Healthy,
    /// Network is degraded but operational
    Degraded,
    /// Network is down for maintenance
    Maintenance,
    /// Network is offline
    Offline,
}

// ============================================================================
// Network Registry
// ============================================================================

/// Cached network configuration
struct CachedConfig {
    config: NetworkConfig,
    fetched_at: Instant,
}

/// Network registry client
pub struct NetworkRegistry {
    /// Configuration
    config: RegistryConfig,
    /// Cached network configs
    cache: RwLock<HashMap<NetworkId, CachedConfig>>,
    /// Embedded fallback configs
    fallback_configs: HashMap<NetworkId, NetworkConfig>,
    /// Last refresh time
    last_refresh: RwLock<Option<Instant>>,
}

impl NetworkRegistry {
    /// Create a new registry client
    pub fn new(config: RegistryConfig) -> Self {
        let mut fallback_configs = HashMap::new();

        // Add embedded testnet config
        fallback_configs.insert(NetworkId::Testnet, Self::testnet_config());

        Self {
            config,
            cache: RwLock::new(HashMap::new()),
            fallback_configs,
            last_refresh: RwLock::new(None),
        }
    }

    /// Create with default config
    pub fn default_registry() -> Self {
        Self::new(RegistryConfig::default())
    }

    /// Get embedded testnet configuration
    fn testnet_config() -> NetworkConfig {
        NetworkConfig {
            network_id: NetworkId::Testnet,
            chain_id: 31337,
            name: "Proto Core Testnet".to_string(),
            description: "Public testnet for Proto Core".to_string(),
            genesis_hash: "0x0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
            native_token: "PCR".to_string(),
            native_decimals: 18,
            block_time_secs: 4,
            bootstrap_nodes: vec![
                BootstrapNode {
                    peer_id: "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".to_string(),
                    addresses: vec![
                        "/ip4/95.216.154.155/tcp/26656".to_string(),
                        "/ip4/95.216.154.155/tcp/26657/ws".to_string(),
                    ],
                    name: Some("Validator 0".to_string()),
                    operator: Some("Proto Core Team".to_string()),
                    region: Some("EU".to_string()),
                },
                BootstrapNode {
                    peer_id: "12D3KooWH8uJ8ZhNBXLKGY8MhRfCLxKVzNQYxV3Q9YL9sTjPn6qF".to_string(),
                    addresses: vec![
                        "/ip4/46.62.165.115/tcp/26656".to_string(),
                        "/ip4/46.62.165.115/tcp/26657/ws".to_string(),
                    ],
                    name: Some("Validator 1".to_string()),
                    operator: Some("Proto Core Team".to_string()),
                    region: Some("EU".to_string()),
                },
            ],
            rpc_endpoints: vec![
                RpcEndpoint {
                    url: "http://95.216.154.155:8545".to_string(),
                    is_public: true,
                    methods: vec![],
                    rate_limit: Some(100),
                    provider: Some("Proto Core Team".to_string()),
                },
                RpcEndpoint {
                    url: "http://46.62.165.115:8545".to_string(),
                    is_public: true,
                    methods: vec![],
                    rate_limit: Some(100),
                    provider: Some("Proto Core Team".to_string()),
                },
            ],
            explorers: vec![ExplorerInfo {
                name: "ProtoScan".to_string(),
                url: "http://65.108.94.1:8080".to_string(),
                api_url: Some("http://65.108.94.1:8080/api".to_string()),
            }],
            params: NetworkParams {
                min_validator_stake: 10_000_000_000_000_000_000,
                max_validators: 100,
                epoch_length: 28_800,
                inflation_rate_bp: 800,
                min_gas_price: 1_000_000_000,
                block_gas_limit: 30_000_000,
            },
            updated_at: 1737331200, // Jan 20, 2026
        }
    }

    /// Get configuration for a network
    pub fn get_config(&self, network: NetworkId) -> Option<NetworkConfig> {
        // Check cache first
        if self.config.enable_cache {
            let cache = self.cache.read();
            if let Some(cached) = cache.get(&network) {
                if cached.fetched_at.elapsed() < self.config.cache_ttl {
                    return Some(cached.config.clone());
                }
            }
        }

        // Return fallback if available
        if self.config.enable_fallback {
            if let Some(config) = self.fallback_configs.get(&network) {
                return Some(config.clone());
            }
        }

        None
    }

    /// Get bootstrap nodes for a network
    pub fn get_bootstrap_nodes(&self, network: NetworkId) -> Vec<(PeerId, Vec<Multiaddr>)> {
        self.get_config(network)
            .map(|c| {
                c.bootstrap_nodes
                    .iter()
                    .filter_map(|n| n.to_peer_info())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get RPC endpoints for a network
    pub fn get_rpc_endpoints(&self, network: NetworkId) -> Vec<RpcEndpoint> {
        self.get_config(network)
            .map(|c| c.rpc_endpoints)
            .unwrap_or_default()
    }

    /// Get a random public RPC endpoint
    pub fn get_random_rpc(&self, network: NetworkId) -> Option<String> {
        let endpoints = self.get_rpc_endpoints(network);
        let public: Vec<_> = endpoints.into_iter().filter(|e| e.is_public).collect();
        if public.is_empty() {
            return None;
        }
        // Simple random selection
        let idx = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as usize
            % public.len();
        Some(public[idx].url.clone())
    }

    /// Update cache with fetched config
    pub fn update_cache(&self, network: NetworkId, config: NetworkConfig) {
        let mut cache = self.cache.write();
        cache.insert(
            network,
            CachedConfig {
                config,
                fetched_at: Instant::now(),
            },
        );
    }

    /// Check if refresh is needed
    pub fn should_refresh(&self) -> bool {
        match *self.last_refresh.read() {
            Some(last) => last.elapsed() >= self.config.refresh_interval,
            None => true,
        }
    }

    /// Mark refresh completed
    pub fn mark_refreshed(&self) {
        *self.last_refresh.write() = Some(Instant::now());
    }

    /// Get registry API URL for a network
    pub fn api_url(&self, network: NetworkId) -> String {
        format!("{}/v1/networks/{}", self.config.base_url, network)
    }

    /// Get list URL
    pub fn list_url(&self) -> String {
        format!("{}/v1/networks", self.config.base_url)
    }

    /// Get all cached networks
    pub fn cached_networks(&self) -> Vec<NetworkId> {
        self.cache.read().keys().cloned().collect()
    }

    /// Get all available networks (cached + fallback)
    pub fn available_networks(&self) -> Vec<NetworkId> {
        let mut networks: Vec<NetworkId> = self.fallback_configs.keys().cloned().collect();
        for id in self.cache.read().keys() {
            if !networks.contains(id) {
                networks.push(*id);
            }
        }
        networks
    }

    /// Clear cache
    pub fn clear_cache(&self) {
        self.cache.write().clear();
    }
}

// ============================================================================
// Registry Service (HTTP API)
// ============================================================================

/// Network registry HTTP service
///
/// Provides HTTP endpoints for network configuration:
/// - `GET /v1/networks` - List all networks
/// - `GET /v1/networks/{id}` - Get network details
/// - `GET /v1/networks/{id}/bootstrap` - Get bootstrap nodes
/// - `GET /v1/networks/{id}/rpc` - Get RPC endpoints
pub struct RegistryService {
    /// Network configurations
    networks: Arc<RwLock<HashMap<NetworkId, NetworkConfig>>>,
}

impl RegistryService {
    /// Create a new registry service
    pub fn new() -> Self {
        let mut networks = HashMap::new();

        // Add testnet config
        networks.insert(NetworkId::Testnet, NetworkRegistry::testnet_config());

        Self {
            networks: Arc::new(RwLock::new(networks)),
        }
    }

    /// Add a network configuration
    pub fn add_network(&self, config: NetworkConfig) {
        self.networks.write().insert(config.network_id, config);
    }

    /// Remove a network
    pub fn remove_network(&self, network: NetworkId) {
        self.networks.write().remove(&network);
    }

    /// List all networks
    pub fn list_networks(&self) -> NetworkListResponse {
        let networks = self.networks.read();
        let summaries: Vec<NetworkSummary> = networks
            .values()
            .map(|c| NetworkSummary {
                id: c.network_id.to_string(),
                chain_id: c.chain_id,
                name: c.name.clone(),
                active: true,
                validator_count: c.bootstrap_nodes.len() as u32,
            })
            .collect();

        NetworkListResponse {
            networks: summaries,
            version: "1.0.0".to_string(),
        }
    }

    /// Get network details
    pub fn get_network(&self, network: NetworkId) -> Option<NetworkDetailResponse> {
        let networks = self.networks.read();
        networks.get(&network).map(|config| NetworkDetailResponse {
            config: config.clone(),
            block_height: None, // Would need RPC call to get this
            status: NetworkStatus::Healthy,
        })
    }

    /// Get bootstrap nodes for a network
    pub fn get_bootstrap(&self, network: NetworkId) -> Vec<BootstrapNode> {
        let networks = self.networks.read();
        networks
            .get(&network)
            .map(|c| c.bootstrap_nodes.clone())
            .unwrap_or_default()
    }

    /// Get RPC endpoints for a network
    pub fn get_rpc(&self, network: NetworkId) -> Vec<RpcEndpoint> {
        let networks = self.networks.read();
        networks
            .get(&network)
            .map(|c| c.rpc_endpoints.clone())
            .unwrap_or_default()
    }
}

impl Default for RegistryService {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_id() {
        assert_eq!(NetworkId::Mainnet.chain_id(), 1);
        assert_eq!(NetworkId::Testnet.chain_id(), 31337);
        assert_eq!(NetworkId::Custom(12345).chain_id(), 12345);

        assert_eq!(NetworkId::from_str("mainnet"), Some(NetworkId::Mainnet));
        assert_eq!(NetworkId::from_str("testnet"), Some(NetworkId::Testnet));
        assert_eq!(NetworkId::from_str("12345"), Some(NetworkId::Custom(12345)));
    }

    #[test]
    fn test_network_registry() {
        let registry = NetworkRegistry::default_registry();

        // Should have fallback testnet config
        let config = registry.get_config(NetworkId::Testnet);
        assert!(config.is_some());

        let config = config.unwrap();
        assert_eq!(config.chain_id, 31337);
        assert!(!config.bootstrap_nodes.is_empty());
    }

    #[test]
    fn test_bootstrap_nodes() {
        let registry = NetworkRegistry::default_registry();
        let nodes = registry.get_bootstrap_nodes(NetworkId::Testnet);

        // Should have 2 testnet validators
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn test_rpc_endpoints() {
        let registry = NetworkRegistry::default_registry();
        let endpoints = registry.get_rpc_endpoints(NetworkId::Testnet);

        assert!(!endpoints.is_empty());
        assert!(endpoints[0].is_public);
    }

    #[test]
    fn test_registry_service() {
        let service = RegistryService::new();

        let list = service.list_networks();
        assert!(!list.networks.is_empty());

        let details = service.get_network(NetworkId::Testnet);
        assert!(details.is_some());
    }

    #[test]
    fn test_bootstrap_node_parsing() {
        let node = BootstrapNode {
            peer_id: "12D3KooWDpJ7As7BWAwRMfu1VU2WCqNjvq387JEYKDBj4kx6nXTN".to_string(),
            addresses: vec!["/ip4/127.0.0.1/tcp/26656".to_string()],
            name: Some("Test".to_string()),
            operator: None,
            region: None,
        };

        let peer_id = node.parse_peer_id();
        assert!(peer_id.is_some());

        let addresses = node.parse_addresses();
        assert_eq!(addresses.len(), 1);

        let info = node.to_peer_info();
        assert!(info.is_some());
    }

    #[test]
    fn test_registry_config() {
        let config = RegistryConfig::default().with_url("https://custom.registry.com");

        assert_eq!(config.base_url, "https://custom.registry.com");
        assert!(config.enable_cache);
        assert!(config.enable_fallback);
    }
}
