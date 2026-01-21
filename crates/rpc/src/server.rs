//! RPC server implementation.
//!
//! This module provides the main RPC server that combines HTTP and WebSocket
//! endpoints with all the Ethereum and Proto Core RPC methods.

use crate::eth::{
    EthApiImpl, EthApiServer, NetApiImpl, NetApiServer, StateProvider, Web3ApiImpl, Web3ApiServer,
};
use crate::protocore::{ProtocoreApiImpl, ProtocoreApiServer, ProtocoreStateProvider};
use crate::ws::{SubscriptionApiImpl, SubscriptionApiServer, SubscriptionManager};
use crate::RpcError;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::RpcModule;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

// ============================================================================
// Server Configuration
// ============================================================================

/// Configuration for the RPC server.
#[derive(Debug, Clone)]
pub struct RpcServerConfig {
    /// HTTP server address.
    pub http_addr: SocketAddr,
    /// WebSocket server address.
    pub ws_addr: SocketAddr,
    /// Chain ID.
    pub chain_id: u64,
    /// Maximum number of connections.
    pub max_connections: u32,
    /// Maximum request body size (bytes).
    pub max_request_size: u32,
    /// Maximum response body size (bytes).
    pub max_response_size: u32,
    /// Request timeout.
    pub request_timeout: Duration,
    /// Enable CORS (for browser access).
    pub enable_cors: bool,
    /// Allowed CORS origins (empty = allow all).
    pub cors_origins: Vec<String>,
    /// Enable request logging.
    pub enable_logging: bool,
    /// Client version string.
    pub client_version: String,
    /// Maximum number of logs per request.
    pub max_logs_per_request: usize,
    /// Batch request limit.
    pub batch_request_limit: u32,
}

impl Default for RpcServerConfig {
    fn default() -> Self {
        Self {
            http_addr: "127.0.0.1:8545".parse().unwrap(),
            ws_addr: "127.0.0.1:8546".parse().unwrap(),
            chain_id: 123456,
            max_connections: 1000,
            max_request_size: 10 * 1024 * 1024,  // 10 MB
            max_response_size: 10 * 1024 * 1024, // 10 MB
            request_timeout: Duration::from_secs(30),
            enable_cors: true,
            cors_origins: vec![],
            enable_logging: true,
            client_version: "0.1.0".to_string(),
            max_logs_per_request: 10_000,
            batch_request_limit: 100,
        }
    }
}

// ============================================================================
// RPC Server
// ============================================================================

/// The main RPC server.
pub struct RpcServer<S, M> {
    config: RpcServerConfig,
    state: Arc<S>,
    mc_state: Arc<M>,
    subscription_manager: Arc<SubscriptionManager>,
    http_handle: Option<ServerHandle>,
    ws_handle: Option<ServerHandle>,
}

impl<S, M> RpcServer<S, M>
where
    S: StateProvider + 'static,
    M: ProtocoreStateProvider + 'static,
{
    /// Create a new RPC server.
    pub fn new(config: RpcServerConfig, state: Arc<S>, mc_state: Arc<M>) -> Self {
        Self {
            config,
            state,
            mc_state,
            subscription_manager: Arc::new(SubscriptionManager::new()),
            http_handle: None,
            ws_handle: None,
        }
    }

    /// Get the subscription manager for broadcasting events.
    pub fn subscription_manager(&self) -> Arc<SubscriptionManager> {
        self.subscription_manager.clone()
    }

    /// Build the RPC module with all methods.
    fn build_rpc_module(&self) -> Result<RpcModule<()>, RpcError> {
        let mut module = RpcModule::new(());

        // Add Ethereum API
        let eth_api =
            EthApiImpl::new(self.state.clone()).with_max_logs(self.config.max_logs_per_request);
        module
            .merge(eth_api.into_rpc())
            .map_err(|e| RpcError::Internal(format!("Failed to merge eth API: {}", e)))?;

        // Add Web3 API
        let web3_api = Web3ApiImpl::new(&self.config.client_version);
        module
            .merge(web3_api.into_rpc())
            .map_err(|e| RpcError::Internal(format!("Failed to merge web3 API: {}", e)))?;

        // Add Net API
        let net_api = NetApiImpl::new(self.config.chain_id);
        module
            .merge(net_api.into_rpc())
            .map_err(|e| RpcError::Internal(format!("Failed to merge net API: {}", e)))?;

        // Add Protocore API
        let mc_api = ProtocoreApiImpl::new(self.mc_state.clone());
        module
            .merge(mc_api.into_rpc())
            .map_err(|e| RpcError::Internal(format!("Failed to merge mc API: {}", e)))?;

        // Add Subscription API (for WebSocket)
        let sub_api = SubscriptionApiImpl::new(self.subscription_manager.clone());
        module
            .merge(sub_api.into_rpc())
            .map_err(|e| RpcError::Internal(format!("Failed to merge subscription API: {}", e)))?;

        Ok(module)
    }

    /// Start the HTTP and WebSocket servers.
    pub async fn start(&mut self) -> Result<(), RpcError> {
        let module = self.build_rpc_module()?;

        // Start HTTP server
        let http_handle = self.start_http_server(module.clone()).await?;
        self.http_handle = Some(http_handle);

        // Start WebSocket server
        let ws_handle = self.start_ws_server(module).await?;
        self.ws_handle = Some(ws_handle);

        info!(
            http_addr = %self.config.http_addr,
            ws_addr = %self.config.ws_addr,
            "RPC servers started"
        );

        Ok(())
    }

    /// Start the HTTP server.
    async fn start_http_server(&self, module: RpcModule<()>) -> Result<ServerHandle, RpcError> {
        let builder = ServerBuilder::default()
            .max_connections(self.config.max_connections)
            .max_request_body_size(self.config.max_request_size)
            .max_response_body_size(self.config.max_response_size)
            .set_batch_request_config(jsonrpsee::server::BatchRequestConfig::Limit(
                self.config.batch_request_limit,
            ));

        // Build and start the server
        let server = builder
            .build(self.config.http_addr)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to build HTTP server: {}", e)))?;

        let handle = server.start(module);

        info!(addr = %self.config.http_addr, "HTTP RPC server started");

        Ok(handle)
    }

    /// Start the WebSocket server.
    async fn start_ws_server(&self, module: RpcModule<()>) -> Result<ServerHandle, RpcError> {
        let builder = ServerBuilder::default()
            .max_connections(self.config.max_connections)
            .max_request_body_size(self.config.max_request_size)
            .max_response_body_size(self.config.max_response_size)
            .set_batch_request_config(jsonrpsee::server::BatchRequestConfig::Limit(
                self.config.batch_request_limit,
            ));

        let server = builder
            .build(self.config.ws_addr)
            .await
            .map_err(|e| RpcError::Internal(format!("Failed to build WebSocket server: {}", e)))?;

        let handle = server.start(module);

        info!(addr = %self.config.ws_addr, "WebSocket RPC server started");

        Ok(handle)
    }

    /// Stop the servers.
    pub async fn stop(&mut self) {
        if let Some(handle) = self.http_handle.take() {
            handle.stop().ok();
            info!("HTTP RPC server stopped");
        }

        if let Some(handle) = self.ws_handle.take() {
            handle.stop().ok();
            info!("WebSocket RPC server stopped");
        }
    }

    /// Wait for the servers to finish.
    pub async fn wait(&self) {
        if let Some(ref handle) = self.http_handle {
            handle.clone().stopped().await;
        }
        if let Some(ref handle) = self.ws_handle {
            handle.clone().stopped().await;
        }
    }
}

// ============================================================================
// Request Logging Middleware
// ============================================================================

/// Middleware for logging RPC requests.
#[derive(Debug, Clone)]
pub struct RequestLogger;

impl RequestLogger {
    /// Log an incoming request.
    pub fn log_request(method: &str, id: Option<&str>) {
        tracing::debug!(method, id, "RPC request");
    }

    /// Log a response.
    pub fn log_response(method: &str, id: Option<&str>, duration_ms: u64, success: bool) {
        if success {
            tracing::debug!(method, id, duration_ms, "RPC response");
        } else {
            tracing::warn!(method, id, duration_ms, "RPC error response");
        }
    }
}

// ============================================================================
// CORS Configuration
// ============================================================================

/// CORS configuration helper.
#[derive(Debug, Clone)]
pub struct CorsConfig {
    /// Allowed origins (empty = allow all).
    pub allowed_origins: Vec<String>,
    /// Allowed methods.
    pub allowed_methods: Vec<String>,
    /// Allowed headers.
    pub allowed_headers: Vec<String>,
    /// Max age for preflight cache.
    pub max_age: Duration,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: vec![],
            allowed_methods: vec!["POST".to_string(), "GET".to_string(), "OPTIONS".to_string()],
            allowed_headers: vec!["Content-Type".to_string()],
            max_age: Duration::from_secs(3600),
        }
    }
}

// ============================================================================
// Server Builder
// ============================================================================

/// Builder for creating RPC servers with custom configuration.
pub struct RpcServerBuilder<S, M> {
    config: RpcServerConfig,
    state: Option<Arc<S>>,
    mc_state: Option<Arc<M>>,
}

impl<S, M> RpcServerBuilder<S, M>
where
    S: StateProvider + 'static,
    M: ProtocoreStateProvider + 'static,
{
    /// Create a new server builder.
    pub fn new() -> Self {
        Self {
            config: RpcServerConfig::default(),
            state: None,
            mc_state: None,
        }
    }

    /// Set the HTTP address.
    pub fn http_addr(mut self, addr: SocketAddr) -> Self {
        self.config.http_addr = addr;
        self
    }

    /// Set the WebSocket address.
    pub fn ws_addr(mut self, addr: SocketAddr) -> Self {
        self.config.ws_addr = addr;
        self
    }

    /// Set the chain ID.
    pub fn chain_id(mut self, chain_id: u64) -> Self {
        self.config.chain_id = chain_id;
        self
    }

    /// Set the state provider.
    pub fn state(mut self, state: Arc<S>) -> Self {
        self.state = Some(state);
        self
    }

    /// Set the Protocore state provider.
    pub fn mc_state(mut self, mc_state: Arc<M>) -> Self {
        self.mc_state = Some(mc_state);
        self
    }

    /// Set the maximum number of connections.
    pub fn max_connections(mut self, max: u32) -> Self {
        self.config.max_connections = max;
        self
    }

    /// Set the maximum request size.
    pub fn max_request_size(mut self, max: u32) -> Self {
        self.config.max_request_size = max;
        self
    }

    /// Set the maximum response size.
    pub fn max_response_size(mut self, max: u32) -> Self {
        self.config.max_response_size = max;
        self
    }

    /// Set the request timeout.
    pub fn request_timeout(mut self, timeout: Duration) -> Self {
        self.config.request_timeout = timeout;
        self
    }

    /// Enable or disable CORS.
    pub fn enable_cors(mut self, enable: bool) -> Self {
        self.config.enable_cors = enable;
        self
    }

    /// Set allowed CORS origins.
    pub fn cors_origins(mut self, origins: Vec<String>) -> Self {
        self.config.cors_origins = origins;
        self
    }

    /// Set the client version.
    pub fn client_version(mut self, version: &str) -> Self {
        self.config.client_version = version.to_string();
        self
    }

    /// Set the maximum logs per request.
    pub fn max_logs_per_request(mut self, max: usize) -> Self {
        self.config.max_logs_per_request = max;
        self
    }

    /// Set the batch request limit.
    pub fn batch_request_limit(mut self, limit: u32) -> Self {
        self.config.batch_request_limit = limit;
        self
    }

    /// Build the server.
    pub fn build(self) -> Result<RpcServer<S, M>, RpcError> {
        let state = self
            .state
            .ok_or_else(|| RpcError::Internal("State provider required".to_string()))?;
        let mc_state = self
            .mc_state
            .ok_or_else(|| RpcError::Internal("Protocore state provider required".to_string()))?;

        Ok(RpcServer::new(self.config, state, mc_state))
    }
}

impl<S, M> Default for RpcServerBuilder<S, M>
where
    S: StateProvider + 'static,
    M: ProtocoreStateProvider + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Health Check Endpoint
// ============================================================================

/// Health check response.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HealthCheckResponse {
    /// Server status.
    pub status: String,
    /// Server version.
    pub version: String,
    /// Current block number.
    pub block_number: Option<u64>,
    /// Number of peers.
    pub peer_count: Option<usize>,
    /// Is syncing.
    pub syncing: bool,
}

impl Default for HealthCheckResponse {
    fn default() -> Self {
        Self {
            status: "ok".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            block_number: None,
            peer_count: None,
            syncing: false,
        }
    }
}
