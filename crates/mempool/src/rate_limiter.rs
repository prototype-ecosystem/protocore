//! Rate limiting for mempool transaction submission.
//!
//! This module provides per-sender rate limiting to prevent:
//! - Transaction spam from a single sender
//! - Mempool flooding attacks
//! - Resource exhaustion

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use protocore_types::Address;
use tracing::{debug, warn};

/// Configuration for mempool rate limiting
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    /// Maximum transactions per sender per window
    pub max_txs_per_sender_per_window: u32,
    /// Rate limit window duration
    pub window_duration: Duration,
    /// Minimum time between transactions from same sender (anti-burst)
    pub min_tx_interval: Duration,
    /// Whether to enable dynamic gas price floor based on mempool pressure
    pub dynamic_gas_floor: bool,
    /// Base minimum gas price (in wei)
    pub base_min_gas_price: u128,
    /// Maximum gas price multiplier when mempool is congested
    pub max_gas_price_multiplier: u128,
    /// Mempool utilization threshold to start increasing gas floor (0.0 - 1.0)
    pub congestion_threshold: f64,
    /// Cleanup interval for stale entries
    pub cleanup_interval: Duration,
    /// Maximum tracked senders (memory limit)
    pub max_tracked_senders: usize,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_txs_per_sender_per_window: 100,
            window_duration: Duration::from_secs(60),
            min_tx_interval: Duration::from_millis(100),
            dynamic_gas_floor: true,
            base_min_gas_price: 1_000_000_000, // 1 gwei
            max_gas_price_multiplier: 10,
            congestion_threshold: 0.8,
            cleanup_interval: Duration::from_secs(60),
            max_tracked_senders: 100_000,
        }
    }
}

/// Per-sender rate limit state
#[derive(Debug, Clone)]
struct SenderState {
    /// Transaction count in current window
    tx_count: u32,
    /// Window start time
    window_start: Instant,
    /// Last transaction time (for burst protection)
    last_tx_time: Instant,
    /// Whether sender is currently rate limited
    is_rate_limited: bool,
    /// Number of rate limit violations
    violations: u32,
}

impl SenderState {
    fn new() -> Self {
        let now = Instant::now();
        Self {
            tx_count: 0,
            window_start: now,
            // Set to past so first transaction is not burst-limited
            last_tx_time: now.checked_sub(Duration::from_secs(60)).unwrap_or(now),
            is_rate_limited: false,
            violations: 0,
        }
    }

    fn reset_window(&mut self) {
        self.tx_count = 0;
        self.window_start = Instant::now();
        self.is_rate_limited = false;
    }
}

/// Reason for rate limit rejection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitRejectReason {
    /// Too many transactions in the current window
    WindowLimitExceeded,
    /// Transaction submitted too quickly after previous one
    BurstLimitExceeded,
    /// Gas price below dynamic floor
    GasPriceTooLow,
    /// Sender is blocked due to repeated violations
    SenderBlocked,
}

impl std::fmt::Display for RateLimitRejectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RateLimitRejectReason::WindowLimitExceeded => {
                write!(f, "transaction rate limit exceeded")
            }
            RateLimitRejectReason::BurstLimitExceeded => {
                write!(f, "transaction submitted too quickly")
            }
            RateLimitRejectReason::GasPriceTooLow => {
                write!(f, "gas price below minimum floor")
            }
            RateLimitRejectReason::SenderBlocked => {
                write!(f, "sender temporarily blocked")
            }
        }
    }
}

/// Result of rate limit check
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    /// Whether the transaction is allowed
    pub allowed: bool,
    /// Reason for rejection (if not allowed)
    pub reject_reason: Option<RateLimitRejectReason>,
    /// Current dynamic gas price floor
    pub current_gas_floor: u128,
    /// Transactions remaining in window for this sender
    pub remaining_in_window: u32,
}

/// Mempool rate limiter
pub struct MempoolRateLimiter {
    config: RateLimitConfig,
    /// Per-sender rate limit state
    sender_states: RwLock<HashMap<Address, SenderState>>,
    /// Blocked senders (after too many violations)
    blocked_senders: RwLock<HashMap<Address, Instant>>,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
    /// Current mempool utilization (0.0 - 1.0)
    mempool_utilization: RwLock<f64>,
}

impl MempoolRateLimiter {
    /// Create a new rate limiter with the given configuration
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            sender_states: RwLock::new(HashMap::new()),
            blocked_senders: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
            mempool_utilization: RwLock::new(0.0),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(RateLimitConfig::default())
    }

    /// Check if a transaction from a sender should be allowed
    pub fn check_transaction(&self, sender: &Address, gas_price: u128) -> RateLimitResult {
        // Periodic cleanup
        self.maybe_cleanup();

        // Check if sender is blocked
        if self.is_sender_blocked(sender) {
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RateLimitRejectReason::SenderBlocked),
                current_gas_floor: self.current_gas_floor(),
                remaining_in_window: 0,
            };
        }

        // Check gas price against dynamic floor
        let gas_floor = self.current_gas_floor();
        if gas_price < gas_floor {
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RateLimitRejectReason::GasPriceTooLow),
                current_gas_floor: gas_floor,
                remaining_in_window: self.get_remaining(sender),
            };
        }

        let mut states = self.sender_states.write();
        let now = Instant::now();

        // Check if we need to enforce max tracked senders limit
        if !states.contains_key(sender) && states.len() >= self.config.max_tracked_senders {
            // Evict oldest entry (simple LRU approximation)
            if let Some(oldest_sender) = self.find_oldest_sender(&states) {
                states.remove(&oldest_sender);
            }
        }

        let state = states.entry(*sender).or_insert_with(SenderState::new);

        // Check if window has expired
        if now.duration_since(state.window_start) >= self.config.window_duration {
            state.reset_window();
        }

        // Check burst limit (minimum interval between transactions)
        if !state.last_tx_time.elapsed().is_zero()
            && now.duration_since(state.last_tx_time) < self.config.min_tx_interval
        {
            state.violations += 1;
            self.check_and_block(sender, state.violations);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RateLimitRejectReason::BurstLimitExceeded),
                current_gas_floor: gas_floor,
                remaining_in_window: self
                    .config
                    .max_txs_per_sender_per_window
                    .saturating_sub(state.tx_count),
            };
        }

        // Check window limit
        if state.tx_count >= self.config.max_txs_per_sender_per_window {
            state.is_rate_limited = true;
            state.violations += 1;
            self.check_and_block(sender, state.violations);
            return RateLimitResult {
                allowed: false,
                reject_reason: Some(RateLimitRejectReason::WindowLimitExceeded),
                current_gas_floor: gas_floor,
                remaining_in_window: 0,
            };
        }

        // Transaction allowed
        state.tx_count += 1;
        state.last_tx_time = now;

        RateLimitResult {
            allowed: true,
            reject_reason: None,
            current_gas_floor: gas_floor,
            remaining_in_window: self
                .config
                .max_txs_per_sender_per_window
                .saturating_sub(state.tx_count),
        }
    }

    /// Record a successful transaction submission
    ///
    /// Call this after the transaction is accepted into the mempool
    pub fn record_accepted(&self, _sender: &Address) {
        // Already tracked in check_transaction, nothing more needed
    }

    /// Get remaining transactions allowed for a sender in current window
    fn get_remaining(&self, sender: &Address) -> u32 {
        let states = self.sender_states.read();
        if let Some(state) = states.get(sender) {
            let now = Instant::now();
            if now.duration_since(state.window_start) >= self.config.window_duration {
                return self.config.max_txs_per_sender_per_window;
            }
            self.config
                .max_txs_per_sender_per_window
                .saturating_sub(state.tx_count)
        } else {
            self.config.max_txs_per_sender_per_window
        }
    }

    /// Find the oldest sender for eviction
    fn find_oldest_sender(&self, states: &HashMap<Address, SenderState>) -> Option<Address> {
        states
            .iter()
            .min_by_key(|(_, state)| state.last_tx_time)
            .map(|(addr, _)| *addr)
    }

    /// Check if a sender should be blocked based on violations
    fn check_and_block(&self, sender: &Address, violations: u32) {
        // Block sender after 10 violations
        const BLOCK_THRESHOLD: u32 = 10;
        const BLOCK_DURATION: Duration = Duration::from_secs(300); // 5 minutes

        if violations >= BLOCK_THRESHOLD {
            let expiry = Instant::now() + BLOCK_DURATION;
            self.blocked_senders.write().insert(*sender, expiry);
            warn!(
                ?sender,
                violations, "sender blocked due to rate limit violations"
            );
        }
    }

    /// Check if a sender is blocked
    fn is_sender_blocked(&self, sender: &Address) -> bool {
        let blocked = self.blocked_senders.read();
        if let Some(&expiry) = blocked.get(sender) {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Get the current dynamic gas price floor
    pub fn current_gas_floor(&self) -> u128 {
        if !self.config.dynamic_gas_floor {
            return self.config.base_min_gas_price;
        }

        let utilization = *self.mempool_utilization.read();

        if utilization < self.config.congestion_threshold {
            return self.config.base_min_gas_price;
        }

        // Calculate multiplier based on how far above threshold we are
        let excess = (utilization - self.config.congestion_threshold)
            / (1.0 - self.config.congestion_threshold);
        let multiplier = 1.0 + (excess * (self.config.max_gas_price_multiplier as f64 - 1.0));

        (self.config.base_min_gas_price as f64 * multiplier) as u128
    }

    /// Update mempool utilization for dynamic gas floor calculation
    pub fn update_mempool_utilization(&self, current_size: usize, max_size: usize) {
        let utilization = if max_size == 0 {
            0.0
        } else {
            current_size as f64 / max_size as f64
        };
        *self.mempool_utilization.write() = utilization;
    }

    /// Periodic cleanup of expired entries
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

        // Clean up expired blocked senders
        {
            let mut blocked = self.blocked_senders.write();
            blocked.retain(|_, expiry| now < *expiry);
        }

        // Clean up stale sender states
        {
            let window = self.config.window_duration;
            let mut states = self.sender_states.write();
            states.retain(|_, state| now.duration_since(state.window_start) < window * 2);
        }

        debug!("mempool rate limiter cleanup completed");
    }

    /// Unblock a sender (for administrative use)
    pub fn unblock_sender(&self, sender: &Address) {
        self.blocked_senders.write().remove(sender);
        self.sender_states.write().remove(sender);
    }

    /// Get statistics
    pub fn stats(&self) -> RateLimiterStats {
        RateLimiterStats {
            tracked_senders: self.sender_states.read().len(),
            blocked_senders: self.blocked_senders.read().len(),
            current_gas_floor: self.current_gas_floor(),
            mempool_utilization: *self.mempool_utilization.read(),
        }
    }
}

/// Statistics for the rate limiter
#[derive(Debug, Clone)]
pub struct RateLimiterStats {
    /// Number of tracked senders
    pub tracked_senders: usize,
    /// Number of blocked senders
    pub blocked_senders: usize,
    /// Current dynamic gas price floor
    pub current_gas_floor: u128,
    /// Current mempool utilization (0.0 - 1.0)
    pub mempool_utilization: f64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(n: u8) -> Address {
        Address::from([n; 20])
    }

    #[test]
    fn test_basic_rate_limiting() {
        let config = RateLimitConfig {
            max_txs_per_sender_per_window: 3,
            window_duration: Duration::from_secs(60),
            min_tx_interval: Duration::from_millis(0), // Disable burst limit for test
            ..Default::default()
        };
        let limiter = MempoolRateLimiter::new(config);
        let sender = test_address(1);
        let gas_price = 1_000_000_000u128;

        // First 3 should succeed
        assert!(limiter.check_transaction(&sender, gas_price).allowed);
        assert!(limiter.check_transaction(&sender, gas_price).allowed);
        let result = limiter.check_transaction(&sender, gas_price);
        assert!(result.allowed);
        assert_eq!(result.remaining_in_window, 0);

        // 4th should fail
        let result = limiter.check_transaction(&sender, gas_price);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(RateLimitRejectReason::WindowLimitExceeded)
        );
    }

    #[test]
    fn test_gas_price_floor() {
        let config = RateLimitConfig {
            base_min_gas_price: 1_000_000_000,
            ..Default::default()
        };
        let limiter = MempoolRateLimiter::new(config);
        let sender = test_address(1);

        // Should reject low gas price
        let result = limiter.check_transaction(&sender, 500_000_000);
        assert!(!result.allowed);
        assert_eq!(
            result.reject_reason,
            Some(RateLimitRejectReason::GasPriceTooLow)
        );

        // Should accept sufficient gas price
        let result = limiter.check_transaction(&sender, 1_000_000_000);
        assert!(result.allowed);
    }

    #[test]
    fn test_dynamic_gas_floor() {
        let config = RateLimitConfig {
            dynamic_gas_floor: true,
            base_min_gas_price: 1_000_000_000,
            max_gas_price_multiplier: 10,
            congestion_threshold: 0.8,
            ..Default::default()
        };
        let limiter = MempoolRateLimiter::new(config);

        // Below threshold, should use base price
        limiter.update_mempool_utilization(500, 1000);
        assert_eq!(limiter.current_gas_floor(), 1_000_000_000);

        // At 90% utilization, should be higher
        limiter.update_mempool_utilization(900, 1000);
        let floor = limiter.current_gas_floor();
        assert!(floor > 1_000_000_000);

        // At 100% utilization, should be at max multiplier
        limiter.update_mempool_utilization(1000, 1000);
        let floor = limiter.current_gas_floor();
        assert_eq!(floor, 10_000_000_000);
    }
}
