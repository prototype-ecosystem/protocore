//! DDoS protection for RPC layer.
//!
//! This module provides multi-layered protection against denial of service attacks
//! targeting the JSON-RPC interface:
//! - Per-IP rate limiting
//! - Request cost model (expensive methods consume more quota)
//! - Circuit breaker pattern for graceful degradation
//! - API key tiers for differentiated service

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Configuration for RPC DDoS protection
#[derive(Debug, Clone)]
pub struct RpcDdosConfig {
    /// Maximum requests per IP per window (default tier)
    pub max_requests_per_ip: u32,
    /// Rate limit window duration
    pub window_duration: Duration,
    /// Request cost for different method categories
    pub method_costs: MethodCosts,
    /// Default request cost
    pub default_request_cost: u32,
    /// Total cost budget per IP per window
    pub cost_budget_per_ip: u32,
    /// Whether to enable circuit breaker
    pub enable_circuit_breaker: bool,
    /// Circuit breaker error threshold (errors per second)
    pub circuit_breaker_error_threshold: u32,
    /// Circuit breaker recovery time
    pub circuit_breaker_recovery_time: Duration,
    /// Ban duration for repeat offenders
    pub ban_duration: Duration,
    /// Number of rate limit hits before banning
    pub ban_after_violations: u32,
    /// Cleanup interval
    pub cleanup_interval: Duration,
    /// Maximum tracked IPs (memory limit)
    pub max_tracked_ips: usize,
    /// Exempt IPs (e.g., localhost for internal monitoring)
    pub exempt_ips: Vec<IpAddr>,
}

impl Default for RpcDdosConfig {
    fn default() -> Self {
        Self {
            max_requests_per_ip: 1000,
            window_duration: Duration::from_secs(60),
            method_costs: MethodCosts::default(),
            default_request_cost: 1,
            cost_budget_per_ip: 5000,
            enable_circuit_breaker: true,
            circuit_breaker_error_threshold: 100,
            circuit_breaker_recovery_time: Duration::from_secs(30),
            ban_duration: Duration::from_secs(3600), // 1 hour
            ban_after_violations: 10,
            cleanup_interval: Duration::from_secs(60),
            max_tracked_ips: 100_000,
            exempt_ips: vec![],
        }
    }
}

/// Request costs for different RPC method categories
#[derive(Debug, Clone)]
pub struct MethodCosts {
    /// Cost for eth_call (expensive EVM execution)
    pub eth_call: u32,
    /// Cost for eth_estimateGas (expensive EVM simulation)
    pub eth_estimate_gas: u32,
    /// Cost for eth_getLogs (potentially returns many results)
    pub eth_get_logs: u32,
    /// Cost for eth_getBlockByNumber with full transactions
    pub eth_get_block_full: u32,
    /// Cost for eth_getBlockByNumber without transactions
    pub eth_get_block_simple: u32,
    /// Cost for eth_sendRawTransaction
    pub eth_send_transaction: u32,
    /// Cost for simple read methods (eth_blockNumber, etc.)
    pub simple_read: u32,
    /// Cost for subscription operations
    pub subscription: u32,
    /// Cost for debug/trace methods
    pub debug_trace: u32,
}

impl Default for MethodCosts {
    fn default() -> Self {
        Self {
            eth_call: 10,
            eth_estimate_gas: 10,
            eth_get_logs: 20,
            eth_get_block_full: 5,
            eth_get_block_simple: 1,
            eth_send_transaction: 5,
            simple_read: 1,
            subscription: 3,
            debug_trace: 50,
        }
    }
}

impl MethodCosts {
    /// Get the cost for a given method name
    pub fn cost_for_method(&self, method: &str) -> u32 {
        match method {
            "eth_call" => self.eth_call,
            "eth_estimateGas" => self.eth_estimate_gas,
            "eth_getLogs" => self.eth_get_logs,
            "eth_getBlockByNumber" | "eth_getBlockByHash" => self.eth_get_block_full,
            "eth_sendRawTransaction" | "eth_sendTransaction" => self.eth_send_transaction,
            "eth_blockNumber" | "eth_chainId" | "eth_gasPrice" | "eth_syncing" | "eth_accounts"
            | "net_version" | "net_listening" | "net_peerCount" | "web3_clientVersion"
            | "web3_sha3" => self.simple_read,
            "eth_subscribe" | "eth_unsubscribe" => self.subscription,
            s if s.starts_with("debug_") || s.starts_with("trace_") => self.debug_trace,
            _ => self.eth_get_block_simple, // Default moderate cost
        }
    }
}

/// Per-IP rate limiting state
#[derive(Debug, Clone)]
struct IpRateLimitState {
    /// Request count in current window
    request_count: u32,
    /// Cost consumed in current window
    cost_consumed: u32,
    /// Window start time
    window_start: Instant,
    /// Rate limit violation count
    violations: u32,
    /// Last request time
    last_request: Instant,
}

impl Default for IpRateLimitState {
    fn default() -> Self {
        let now = Instant::now();
        Self {
            request_count: 0,
            cost_consumed: 0,
            window_start: now,
            violations: 0,
            last_request: now,
        }
    }
}

/// Circuit breaker state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation
    Closed,
    /// Limiting requests due to errors
    Open,
    /// Testing if service has recovered
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircuitState::Closed => write!(f, "closed"),
            CircuitState::Open => write!(f, "open"),
            CircuitState::HalfOpen => write!(f, "half-open"),
        }
    }
}

/// Reason for rejecting an RPC request
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RpcRejectReason {
    /// Request count rate limit exceeded
    RateLimited,
    /// Cost budget exceeded
    CostBudgetExceeded,
    /// IP is banned
    Banned,
    /// Circuit breaker is open
    CircuitOpen,
    /// Server is overloaded
    Overloaded,
}

impl std::fmt::Display for RpcRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RpcRejectReason::RateLimited => write!(f, "rate limited"),
            RpcRejectReason::CostBudgetExceeded => write!(f, "cost budget exceeded"),
            RpcRejectReason::Banned => write!(f, "IP banned"),
            RpcRejectReason::CircuitOpen => write!(f, "service unavailable"),
            RpcRejectReason::Overloaded => write!(f, "server overloaded"),
        }
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the request is allowed
    pub allowed: bool,
    /// Reason for rejection (if not allowed)
    pub reject_reason: Option<RpcRejectReason>,
    /// Remaining requests in window
    pub remaining_requests: u32,
    /// Remaining cost budget
    pub remaining_budget: u32,
    /// Time until window resets
    pub reset_in: Duration,
}

/// API key tier for differentiated service
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiTier {
    /// Anonymous/public access (most restrictive)
    Public,
    /// Free registered user
    Free,
    /// Paid basic tier
    Basic,
    /// Paid premium tier
    Premium,
    /// Internal/unlimited access
    Unlimited,
}

impl ApiTier {
    /// Get the rate limit multiplier for this tier
    pub fn rate_multiplier(&self) -> u32 {
        match self {
            ApiTier::Public => 1,
            ApiTier::Free => 2,
            ApiTier::Basic => 5,
            ApiTier::Premium => 20,
            ApiTier::Unlimited => u32::MAX,
        }
    }

    /// Get the cost budget multiplier for this tier
    pub fn budget_multiplier(&self) -> u32 {
        match self {
            ApiTier::Public => 1,
            ApiTier::Free => 2,
            ApiTier::Basic => 10,
            ApiTier::Premium => 50,
            ApiTier::Unlimited => u32::MAX,
        }
    }
}

/// RPC DDoS protection manager
pub struct RpcDdosProtection {
    config: RpcDdosConfig,
    /// Per-IP rate limiting state
    ip_states: RwLock<HashMap<IpAddr, IpRateLimitState>>,
    /// Banned IPs with expiry
    banned_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// API keys and their tiers
    api_keys: RwLock<HashMap<String, ApiTier>>,
    /// Circuit breaker state
    circuit_state: RwLock<CircuitState>,
    /// Circuit breaker open time
    circuit_open_time: RwLock<Option<Instant>>,
    /// Error count for circuit breaker
    error_count: AtomicU64,
    /// Error count window start
    error_window_start: RwLock<Instant>,
    /// Total requests served (for monitoring)
    total_requests: AtomicU64,
    /// Total requests rejected (for monitoring)
    total_rejected: AtomicU64,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
    /// Whether the service is in degraded mode
    degraded_mode: AtomicBool,
}

impl RpcDdosProtection {
    /// Create a new RPC DDoS protection manager
    pub fn new(config: RpcDdosConfig) -> Self {
        Self {
            config,
            ip_states: RwLock::new(HashMap::new()),
            banned_ips: RwLock::new(HashMap::new()),
            api_keys: RwLock::new(HashMap::new()),
            circuit_state: RwLock::new(CircuitState::Closed),
            circuit_open_time: RwLock::new(None),
            error_count: AtomicU64::new(0),
            error_window_start: RwLock::new(Instant::now()),
            total_requests: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
            last_cleanup: RwLock::new(Instant::now()),
            degraded_mode: AtomicBool::new(false),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RpcDdosConfig::default())
    }

    /// Check if a request should be allowed
    pub fn check_request(
        &self,
        ip: IpAddr,
        method: &str,
        api_key: Option<&str>,
    ) -> RateLimitResult {
        self.maybe_cleanup();
        self.total_requests.fetch_add(1, Ordering::Relaxed);

        // Check if IP is exempt
        if self.config.exempt_ips.contains(&ip) {
            return RateLimitResult {
                allowed: true,
                reject_reason: None,
                remaining_requests: u32::MAX,
                remaining_budget: u32::MAX,
                reset_in: Duration::ZERO,
            };
        }

        // Check circuit breaker
        if self.config.enable_circuit_breaker && !self.check_circuit_breaker() {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RpcRejectReason::CircuitOpen),
                remaining_requests: 0,
                remaining_budget: 0,
                reset_in: self.config.circuit_breaker_recovery_time,
            };
        }

        // Check if IP is banned
        if self.is_ip_banned(&ip) {
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RpcRejectReason::Banned),
                remaining_requests: 0,
                remaining_budget: 0,
                reset_in: self.config.ban_duration,
            };
        }

        // Get tier from API key
        let tier = api_key
            .and_then(|key| self.api_keys.read().get(key).copied())
            .unwrap_or(ApiTier::Public);

        // Calculate limits based on tier
        let max_requests = self
            .config
            .max_requests_per_ip
            .saturating_mul(tier.rate_multiplier());
        let max_budget = self
            .config
            .cost_budget_per_ip
            .saturating_mul(tier.budget_multiplier());

        // Get request cost
        let cost = self.config.method_costs.cost_for_method(method);

        let mut states = self.ip_states.write();
        let now = Instant::now();

        // Evict oldest entry if at capacity
        if !states.contains_key(&ip) && states.len() >= self.config.max_tracked_ips {
            if let Some(oldest_ip) = self.find_oldest_ip(&states) {
                states.remove(&oldest_ip);
            }
        }

        let state = states.entry(ip).or_default();

        // Check if window has expired
        if now.duration_since(state.window_start) >= self.config.window_duration {
            state.request_count = 0;
            state.cost_consumed = 0;
            state.window_start = now;
        }

        let reset_in = self
            .config
            .window_duration
            .saturating_sub(now.duration_since(state.window_start));

        // Check request count limit
        if state.request_count >= max_requests {
            state.violations += 1;
            self.check_and_ban(&ip, state.violations);
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RpcRejectReason::RateLimited),
                remaining_requests: 0,
                remaining_budget: max_budget.saturating_sub(state.cost_consumed),
                reset_in,
            };
        }

        // Check cost budget
        if state.cost_consumed + cost > max_budget {
            state.violations += 1;
            self.check_and_ban(&ip, state.violations);
            self.total_rejected.fetch_add(1, Ordering::Relaxed);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RpcRejectReason::CostBudgetExceeded),
                remaining_requests: max_requests.saturating_sub(state.request_count),
                remaining_budget: 0,
                reset_in,
            };
        }

        // Update state
        state.request_count += 1;
        state.cost_consumed += cost;
        state.last_request = now;

        RateLimitResult {
            allowed: true,
            reject_reason: None,
            remaining_requests: max_requests.saturating_sub(state.request_count),
            remaining_budget: max_budget.saturating_sub(state.cost_consumed),
            reset_in,
        }
    }

    /// Record an error for circuit breaker
    pub fn record_error(&self) {
        let now = Instant::now();
        let mut window_start = self.error_window_start.write();

        // Reset error count if window expired
        if now.duration_since(*window_start) >= Duration::from_secs(1) {
            self.error_count.store(0, Ordering::Relaxed);
            *window_start = now;
        }

        let count = self.error_count.fetch_add(1, Ordering::Relaxed) + 1;

        // Check if we should trip the circuit breaker
        if count >= self.config.circuit_breaker_error_threshold as u64 {
            self.trip_circuit_breaker();
        }
    }

    /// Record a successful request (for circuit breaker recovery)
    pub fn record_success(&self) {
        // If in half-open state, close the circuit
        let state = *self.circuit_state.read();
        if state == CircuitState::HalfOpen {
            *self.circuit_state.write() = CircuitState::Closed;
            *self.circuit_open_time.write() = None;
            info!("circuit breaker closed after successful request");
        }
    }

    /// Check if circuit breaker allows requests
    fn check_circuit_breaker(&self) -> bool {
        let state = *self.circuit_state.read();

        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if recovery time has passed
                let open_time = *self.circuit_open_time.read();
                if let Some(open_time) = open_time {
                    if open_time.elapsed() >= self.config.circuit_breaker_recovery_time {
                        // Transition to half-open
                        *self.circuit_state.write() = CircuitState::HalfOpen;
                        info!("circuit breaker transitioned to half-open");
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true, // Allow one request to test
        }
    }

    /// Trip the circuit breaker
    fn trip_circuit_breaker(&self) {
        let current = *self.circuit_state.read();
        if current == CircuitState::Closed {
            *self.circuit_state.write() = CircuitState::Open;
            *self.circuit_open_time.write() = Some(Instant::now());
            warn!("circuit breaker opened due to high error rate");
        }
    }

    /// Find oldest IP for eviction
    fn find_oldest_ip(&self, states: &HashMap<IpAddr, IpRateLimitState>) -> Option<IpAddr> {
        states
            .iter()
            .min_by_key(|(_, state)| state.last_request)
            .map(|(ip, _)| *ip)
    }

    /// Check if an IP should be banned
    fn check_and_ban(&self, ip: &IpAddr, violations: u32) {
        if violations >= self.config.ban_after_violations {
            self.ban_ip(*ip, self.config.ban_duration);
        }
    }

    /// Check if an IP is banned
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        let banned = self.banned_ips.read();
        if let Some(&expiry) = banned.get(ip) {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Ban an IP
    pub fn ban_ip(&self, ip: IpAddr, duration: Duration) {
        let expiry = Instant::now() + duration;
        self.banned_ips.write().insert(ip, expiry);
        warn!(?ip, ?duration, "IP banned from RPC");
    }

    /// Unban an IP
    pub fn unban_ip(&self, ip: &IpAddr) {
        self.banned_ips.write().remove(ip);
        self.ip_states.write().remove(ip);
        info!(?ip, "IP unbanned from RPC");
    }

    /// Register an API key with a tier
    pub fn register_api_key(&self, key: String, tier: ApiTier) {
        self.api_keys.write().insert(key, tier);
    }

    /// Revoke an API key
    pub fn revoke_api_key(&self, key: &str) {
        self.api_keys.write().remove(key);
    }

    /// Enable degraded mode (stricter rate limits)
    pub fn enable_degraded_mode(&self) {
        self.degraded_mode.store(true, Ordering::Relaxed);
        warn!("RPC entered degraded mode");
    }

    /// Disable degraded mode
    pub fn disable_degraded_mode(&self) {
        self.degraded_mode.store(false, Ordering::Relaxed);
        info!("RPC exited degraded mode");
    }

    /// Check if in degraded mode
    pub fn is_degraded(&self) -> bool {
        self.degraded_mode.load(Ordering::Relaxed)
    }

    /// Add an exempt IP
    pub fn add_exempt_ip(&mut self, ip: IpAddr) {
        self.config.exempt_ips.push(ip);
    }

    /// Periodic cleanup
    fn maybe_cleanup(&self) {
        let now = Instant::now();
        let should_cleanup = {
            let last = self.last_cleanup.read();
            now.duration_since(*last) >= self.config.cleanup_interval
        };

        if !should_cleanup {
            return;
        }

        *self.last_cleanup.write() = now;

        // Clean up expired bans
        {
            let mut banned = self.banned_ips.write();
            banned.retain(|_, expiry| now < *expiry);
        }

        // Clean up stale IP states
        {
            let window = self.config.window_duration;
            let mut states = self.ip_states.write();
            states.retain(|_, state| now.duration_since(state.window_start) < window * 2);
        }

        debug!("RPC DDoS protection cleanup completed");
    }

    /// Get statistics
    pub fn stats(&self) -> RpcDdosStats {
        RpcDdosStats {
            tracked_ips: self.ip_states.read().len(),
            banned_ips: self.banned_ips.read().len(),
            registered_api_keys: self.api_keys.read().len(),
            circuit_state: *self.circuit_state.read(),
            total_requests: self.total_requests.load(Ordering::Relaxed),
            total_rejected: self.total_rejected.load(Ordering::Relaxed),
            is_degraded: self.is_degraded(),
        }
    }

    /// Get current circuit state
    pub fn circuit_state(&self) -> CircuitState {
        *self.circuit_state.read()
    }
}

/// Statistics for RPC DDoS protection
#[derive(Debug, Clone)]
pub struct RpcDdosStats {
    /// Number of tracked IP addresses
    pub tracked_ips: usize,
    /// Number of banned IPs
    pub banned_ips: usize,
    /// Number of registered API keys
    pub registered_api_keys: usize,
    /// Current circuit breaker state
    pub circuit_state: CircuitState,
    /// Total requests processed
    pub total_requests: u64,
    /// Total requests rejected
    pub total_rejected: u64,
    /// Whether in degraded mode
    pub is_degraded: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    #[test]
    fn test_basic_rate_limiting() {
        let config = RpcDdosConfig {
            max_requests_per_ip: 3,
            window_duration: Duration::from_secs(60),
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let ip = test_ip();

        // First 3 should succeed
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );
        let result = protection.check_request(ip, "eth_blockNumber", None);
        assert!(result.allowed);
        assert_eq!(result.remaining_requests, 0);

        // 4th should fail
        let result = protection.check_request(ip, "eth_blockNumber", None);
        assert!(!result.allowed);
        assert_eq!(result.reject_reason, Some(RpcRejectReason::RateLimited));
    }

    #[test]
    fn test_cost_budget() {
        let config = RpcDdosConfig {
            max_requests_per_ip: 1000, // High limit
            cost_budget_per_ip: 20,    // Low budget
            method_costs: MethodCosts {
                eth_call: 10,
                ..Default::default()
            },
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let ip = test_ip();

        // First two eth_call should succeed (10 + 10 = 20)
        assert!(protection.check_request(ip, "eth_call", None).allowed);
        assert!(protection.check_request(ip, "eth_call", None).allowed);

        // Third should fail due to budget
        let result = protection.check_request(ip, "eth_call", None);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(RpcRejectReason::CostBudgetExceeded)
        );
    }

    #[test]
    fn test_api_key_tiers() {
        let config = RpcDdosConfig {
            max_requests_per_ip: 3,
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let ip = test_ip();

        // Register a premium API key
        protection.register_api_key("premium_key".to_string(), ApiTier::Premium);

        // Without key: 3 requests max
        for _ in 0..3 {
            assert!(
                protection
                    .check_request(ip, "eth_blockNumber", None)
                    .allowed
            );
        }
        assert!(
            !protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );

        // Different IP with premium key: 60 requests max (3 * 20)
        let ip2 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 2));
        for _ in 0..60 {
            assert!(
                protection
                    .check_request(ip2, "eth_blockNumber", Some("premium_key"))
                    .allowed
            );
        }
        let result = protection.check_request(ip2, "eth_blockNumber", Some("premium_key"));
        assert!(!result.allowed);
    }

    #[test]
    fn test_circuit_breaker() {
        let config = RpcDdosConfig {
            enable_circuit_breaker: true,
            circuit_breaker_error_threshold: 3,
            circuit_breaker_recovery_time: Duration::from_millis(100),
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let ip = test_ip();

        // Initially closed
        assert_eq!(protection.circuit_state(), CircuitState::Closed);
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );

        // Record errors to trip breaker
        protection.record_error();
        protection.record_error();
        protection.record_error();

        // Should be open now
        assert_eq!(protection.circuit_state(), CircuitState::Open);
        let result = protection.check_request(ip, "eth_blockNumber", None);
        assert!(!result.allowed);
        assert_eq!(result.reject_reason, Some(RpcRejectReason::CircuitOpen));

        // Wait for recovery
        std::thread::sleep(Duration::from_millis(150));

        // Should transition to half-open and allow request
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );
        assert_eq!(protection.circuit_state(), CircuitState::HalfOpen);

        // Successful request should close the circuit
        protection.record_success();
        assert_eq!(protection.circuit_state(), CircuitState::Closed);
    }

    #[test]
    fn test_ip_banning() {
        let config = RpcDdosConfig {
            max_requests_per_ip: 1,
            ban_after_violations: 2,
            ban_duration: Duration::from_secs(3600),
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let ip = test_ip();

        // First request succeeds
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );

        // Next requests cause violations
        assert!(
            !protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );
        assert!(
            !protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );

        // Should now be banned
        assert!(protection.is_ip_banned(&ip));
        let result = protection.check_request(ip, "eth_blockNumber", None);
        assert!(!result.allowed);
        assert_eq!(result.reject_reason, Some(RpcRejectReason::Banned));

        // Unban
        protection.unban_ip(&ip);
        assert!(!protection.is_ip_banned(&ip));
        assert!(
            protection
                .check_request(ip, "eth_blockNumber", None)
                .allowed
        );
    }

    #[test]
    fn test_exempt_ips() {
        let config = RpcDdosConfig {
            max_requests_per_ip: 1,
            exempt_ips: vec![IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))],
            ..Default::default()
        };
        let protection = RpcDdosProtection::new(config);
        let localhost = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));

        // Localhost should always be allowed
        for _ in 0..100 {
            assert!(
                protection
                    .check_request(localhost, "eth_blockNumber", None)
                    .allowed
            );
        }
    }
}
