//! Relay Node Incentives
//!
//! This module provides incentives for relay nodes (non-validator nodes) that
//! forward transactions to the network. Relays receive a share of transaction
//! fees when the transactions they forwarded are included in blocks.
//!
//! ## How It Works
//!
//! 1. When a relay node receives a transaction, it signs an "origin claim"
//! 2. The transaction is forwarded with the claim attached
//! 3. When the transaction is included in a block, the claim is recorded
//! 4. At block finalization, relay fees are distributed
//!
//! ## Fee Distribution
//!
//! Transaction fees are split as follows:
//! - Proposer share: Typically 50-90% to block proposer
//! - Relay share: 5-40% to relay node that forwarded the transaction
//! - Burn/Treasury: Remaining percentage burned or sent to treasury

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Default relay fee share in basis points (10% = 1000 bp)
pub const DEFAULT_RELAY_SHARE_BP: u32 = 1000;

/// Minimum relay share (1%)
pub const MIN_RELAY_SHARE_BP: u32 = 100;

/// Maximum relay share (40%)
pub const MAX_RELAY_SHARE_BP: u32 = 4000;

/// Maximum claim age before expiration (1 hour)
pub const MAX_CLAIM_AGE: Duration = Duration::from_secs(3600);

/// Maximum claims to track per relay
pub const MAX_CLAIMS_PER_RELAY: usize = 10_000;

// ============================================================================
// Types
// ============================================================================

/// A 20-byte address type
pub type Address = [u8; 20];

/// A 32-byte hash type
pub type TxHash = [u8; 32];

/// Configuration for relay incentives
#[derive(Debug, Clone)]
pub struct RelayIncentivesConfig {
    /// Enable relay incentives
    pub enabled: bool,
    /// Relay's share of transaction fees in basis points
    pub relay_share_bp: u32,
    /// Minimum relay fee (below this, no relay share)
    pub min_relay_fee: u64,
    /// Maximum claim age before expiration
    pub max_claim_age: Duration,
    /// Maximum claims to track per relay
    pub max_claims_per_relay: usize,
    /// Require signature on claims
    pub require_claim_signature: bool,
}

impl Default for RelayIncentivesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            relay_share_bp: DEFAULT_RELAY_SHARE_BP,
            min_relay_fee: 1_000_000_000, // 1 gwei
            max_claim_age: MAX_CLAIM_AGE,
            max_claims_per_relay: MAX_CLAIMS_PER_RELAY,
            require_claim_signature: false,
        }
    }
}

impl RelayIncentivesConfig {
    /// Validate configuration
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.relay_share_bp < MIN_RELAY_SHARE_BP {
            return Err("Relay share below minimum");
        }
        if self.relay_share_bp > MAX_RELAY_SHARE_BP {
            return Err("Relay share above maximum");
        }
        Ok(())
    }

    /// Create config with custom relay share
    pub fn with_share(relay_share_bp: u32) -> Self {
        Self {
            relay_share_bp,
            ..Default::default()
        }
    }

    /// Disable relay incentives
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Default::default()
        }
    }
}

/// Origin claim for a transaction
///
/// When a relay node forwards a transaction, it creates an origin claim
/// to prove that it was the first to relay the transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OriginClaim {
    /// Transaction hash
    pub tx_hash: TxHash,
    /// Relay node address (to receive fees)
    pub relay_address: Address,
    /// Timestamp when the claim was made
    pub timestamp: u64,
    /// Optional signature proving the relay forwarded this tx
    pub signature: Option<Vec<u8>>,
    /// The block height when we first saw this tx
    pub seen_at_height: u64,
}

impl OriginClaim {
    /// Create a new origin claim
    pub fn new(tx_hash: TxHash, relay_address: Address, height: u64) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            tx_hash,
            relay_address,
            timestamp,
            signature: None,
            seen_at_height: height,
        }
    }

    /// Create a signed claim
    pub fn new_signed(
        tx_hash: TxHash,
        relay_address: Address,
        height: u64,
        signature: Vec<u8>,
    ) -> Self {
        let mut claim = Self::new(tx_hash, relay_address, height);
        claim.signature = Some(signature);
        claim
    }

    /// Check if claim is expired
    pub fn is_expired(&self, max_age: Duration) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp) > max_age.as_secs()
    }

    /// Get claim age in seconds
    pub fn age_secs(&self) -> u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(self.timestamp)
    }
}

/// Fee distribution for a transaction
#[derive(Debug, Clone)]
pub struct FeeDistribution {
    /// Total transaction fee
    pub total_fee: u64,
    /// Proposer's share
    pub proposer_share: u64,
    /// Relay's share
    pub relay_share: u64,
    /// Amount burned/treasury
    pub burned: u64,
}

impl FeeDistribution {
    /// Calculate fee distribution
    pub fn calculate(total_fee: u64, relay_share_bp: u32) -> Self {
        // Relay share
        let relay_share = (total_fee as u128 * relay_share_bp as u128 / 10_000) as u64;

        // Remainder goes to proposer
        let proposer_share = total_fee.saturating_sub(relay_share);

        Self {
            total_fee,
            proposer_share,
            relay_share,
            burned: 0,
        }
    }

    /// Calculate with burn percentage
    pub fn calculate_with_burn(total_fee: u64, relay_share_bp: u32, burn_bp: u32) -> Self {
        // Calculate shares
        let relay_share = (total_fee as u128 * relay_share_bp as u128 / 10_000) as u64;
        let burned = (total_fee as u128 * burn_bp as u128 / 10_000) as u64;
        let proposer_share = total_fee
            .saturating_sub(relay_share)
            .saturating_sub(burned);

        Self {
            total_fee,
            proposer_share,
            relay_share,
            burned,
        }
    }
}

/// Statistics about relay incentives
#[derive(Debug, Clone, Default)]
pub struct RelayIncentivesStats {
    /// Total claims recorded
    pub total_claims: u64,
    /// Active claims (not yet distributed)
    pub active_claims: u64,
    /// Total fees distributed to relays
    pub total_relay_fees: u64,
    /// Number of unique relays
    pub unique_relays: u64,
    /// Claims expired (tx not included in time)
    pub expired_claims: u64,
    /// Claims fulfilled (tx included, fees distributed)
    pub fulfilled_claims: u64,
}

// ============================================================================
// Relay Incentives Tracker
// ============================================================================

/// Internal claim state
struct ClaimState {
    claim: OriginClaim,
    received_at: Instant,
}

/// Relay incentives tracker
///
/// Tracks origin claims and distributes fees when transactions are included.
pub struct RelayIncentivesTracker {
    /// Configuration
    config: RelayIncentivesConfig,
    /// Claims by transaction hash
    claims: RwLock<HashMap<TxHash, ClaimState>>,
    /// Claims by relay address (for tracking limits)
    claims_by_relay: RwLock<HashMap<Address, Vec<TxHash>>>,
    /// Statistics
    stats: RwLock<RelayIncentivesStats>,
    /// Pending rewards (relay_address -> amount)
    pending_rewards: RwLock<HashMap<Address, u64>>,
}

impl RelayIncentivesTracker {
    /// Create a new tracker
    pub fn new(config: RelayIncentivesConfig) -> Self {
        Self {
            config,
            claims: RwLock::new(HashMap::new()),
            claims_by_relay: RwLock::new(HashMap::new()),
            stats: RwLock::new(RelayIncentivesStats::default()),
            pending_rewards: RwLock::new(HashMap::new()),
        }
    }

    /// Create with default config
    pub fn default_tracker() -> Self {
        Self::new(RelayIncentivesConfig::default())
    }

    /// Check if incentives are enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Record an origin claim
    pub fn record_claim(&self, claim: OriginClaim) -> Result<(), &'static str> {
        if !self.config.enabled {
            return Ok(());
        }

        // Check if claim already exists
        {
            let claims = self.claims.read();
            if claims.contains_key(&claim.tx_hash) {
                return Err("Claim already exists for this transaction");
            }
        }

        // Check per-relay limit
        {
            let relay_claims = self.claims_by_relay.read();
            if let Some(hashes) = relay_claims.get(&claim.relay_address) {
                if hashes.len() >= self.config.max_claims_per_relay {
                    return Err("Relay has too many pending claims");
                }
            }
        }

        // Verify signature if required
        if self.config.require_claim_signature && claim.signature.is_none() {
            return Err("Claim signature required but not provided");
        }

        let tx_hash = claim.tx_hash;
        let relay_address = claim.relay_address;

        // Store claim
        {
            let mut claims = self.claims.write();
            claims.insert(
                tx_hash,
                ClaimState {
                    claim,
                    received_at: Instant::now(),
                },
            );
        }

        // Track by relay
        {
            let mut relay_claims = self.claims_by_relay.write();
            relay_claims
                .entry(relay_address)
                .or_default()
                .push(tx_hash);
        }

        // Update stats
        {
            let mut stats = self.stats.write();
            stats.total_claims += 1;
            stats.active_claims += 1;
        }

        Ok(())
    }

    /// Get claim for a transaction
    pub fn get_claim(&self, tx_hash: &TxHash) -> Option<OriginClaim> {
        let claims = self.claims.read();
        claims.get(tx_hash).map(|s| s.claim.clone())
    }

    /// Check if we have a claim for a transaction
    pub fn has_claim(&self, tx_hash: &TxHash) -> bool {
        self.claims.read().contains_key(tx_hash)
    }

    /// Calculate fee distribution for a transaction
    pub fn calculate_distribution(&self, total_fee: u64) -> FeeDistribution {
        if !self.config.enabled || total_fee < self.config.min_relay_fee {
            return FeeDistribution {
                total_fee,
                proposer_share: total_fee,
                relay_share: 0,
                burned: 0,
            };
        }

        FeeDistribution::calculate(total_fee, self.config.relay_share_bp)
    }

    /// Process transaction inclusion and distribute fees
    ///
    /// Called when a transaction is included in a block.
    /// Returns the relay address and their share if a claim exists.
    pub fn process_inclusion(&self, tx_hash: &TxHash, total_fee: u64) -> Option<(Address, u64)> {
        if !self.config.enabled {
            return None;
        }

        // Get and remove claim
        let claim_state = {
            let mut claims = self.claims.write();
            claims.remove(tx_hash)?
        };

        let claim = claim_state.claim;

        // Remove from relay tracking
        {
            let mut relay_claims = self.claims_by_relay.write();
            if let Some(hashes) = relay_claims.get_mut(&claim.relay_address) {
                hashes.retain(|h| h != tx_hash);
            }
        }

        // Calculate relay share
        let distribution = self.calculate_distribution(total_fee);

        if distribution.relay_share > 0 {
            // Add to pending rewards
            {
                let mut pending = self.pending_rewards.write();
                *pending.entry(claim.relay_address).or_default() += distribution.relay_share;
            }

            // Update stats
            {
                let mut stats = self.stats.write();
                stats.active_claims = stats.active_claims.saturating_sub(1);
                stats.fulfilled_claims += 1;
                stats.total_relay_fees += distribution.relay_share;
            }

            Some((claim.relay_address, distribution.relay_share))
        } else {
            // Update stats (no relay share due to low fee)
            let mut stats = self.stats.write();
            stats.active_claims = stats.active_claims.saturating_sub(1);
            stats.fulfilled_claims += 1;

            None
        }
    }

    /// Get pending rewards for a relay
    pub fn pending_reward(&self, relay_address: &Address) -> u64 {
        *self
            .pending_rewards
            .read()
            .get(relay_address)
            .unwrap_or(&0)
    }

    /// Withdraw pending rewards
    ///
    /// Returns the amount withdrawn and resets the pending balance.
    pub fn withdraw_rewards(&self, relay_address: &Address) -> u64 {
        let mut pending = self.pending_rewards.write();
        pending.remove(relay_address).unwrap_or(0)
    }

    /// Get all pending rewards
    pub fn all_pending_rewards(&self) -> HashMap<Address, u64> {
        self.pending_rewards.read().clone()
    }

    /// Clean up expired claims
    pub fn cleanup_expired(&self) -> u64 {
        let expired_hashes: Vec<(TxHash, Address)> = {
            let claims = self.claims.read();
            claims
                .iter()
                .filter(|(_, state)| state.claim.is_expired(self.config.max_claim_age))
                .map(|(hash, state)| (*hash, state.claim.relay_address))
                .collect()
        };

        let count = expired_hashes.len() as u64;

        if count > 0 {
            // Remove expired claims
            {
                let mut claims = self.claims.write();
                for (hash, _) in &expired_hashes {
                    claims.remove(hash);
                }
            }

            // Remove from relay tracking
            {
                let mut relay_claims = self.claims_by_relay.write();
                for (hash, relay) in &expired_hashes {
                    if let Some(hashes) = relay_claims.get_mut(relay) {
                        hashes.retain(|h| h != hash);
                    }
                }
            }

            // Update stats
            {
                let mut stats = self.stats.write();
                stats.active_claims = stats.active_claims.saturating_sub(count);
                stats.expired_claims += count;
            }
        }

        count
    }

    /// Get statistics
    pub fn stats(&self) -> RelayIncentivesStats {
        let stats = self.stats.read();
        let mut result = stats.clone();

        // Count unique relays
        result.unique_relays = self
            .claims_by_relay
            .read()
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .count() as u64;

        result
    }

    /// Get claim count
    pub fn claim_count(&self) -> usize {
        self.claims.read().len()
    }
}

// ============================================================================
// Relay Registration (Optional)
// ============================================================================

/// Information about a registered relay
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    /// Relay address
    pub address: Address,
    /// Relay name/identifier
    pub name: Option<String>,
    /// Registration timestamp
    pub registered_at: u64,
    /// Total transactions relayed
    pub transactions_relayed: u64,
    /// Total fees earned
    pub total_fees_earned: u64,
    /// Is relay active
    pub is_active: bool,
}

/// Registry of known relay nodes
pub struct RelayRegistry {
    /// Registered relays
    relays: RwLock<HashMap<Address, RelayInfo>>,
}

impl RelayRegistry {
    /// Create a new registry
    pub fn new() -> Self {
        Self {
            relays: RwLock::new(HashMap::new()),
        }
    }

    /// Register a relay
    pub fn register(&self, address: Address, name: Option<String>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let info = RelayInfo {
            address,
            name,
            registered_at: now,
            transactions_relayed: 0,
            total_fees_earned: 0,
            is_active: true,
        };

        self.relays.write().insert(address, info);
    }

    /// Deactivate a relay
    pub fn deactivate(&self, address: &Address) {
        if let Some(info) = self.relays.write().get_mut(address) {
            info.is_active = false;
        }
    }

    /// Get relay info
    pub fn get(&self, address: &Address) -> Option<RelayInfo> {
        self.relays.read().get(address).cloned()
    }

    /// Update relay stats
    pub fn update_stats(&self, address: &Address, transactions: u64, fees: u64) {
        if let Some(info) = self.relays.write().get_mut(address) {
            info.transactions_relayed += transactions;
            info.total_fees_earned += fees;
        }
    }

    /// List all active relays
    pub fn active_relays(&self) -> Vec<RelayInfo> {
        self.relays
            .read()
            .values()
            .filter(|r| r.is_active)
            .cloned()
            .collect()
    }
}

impl Default for RelayRegistry {
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

    fn test_tx_hash() -> TxHash {
        [1u8; 32]
    }

    fn test_address() -> Address {
        [2u8; 20]
    }

    #[test]
    fn test_config_validation() {
        let config = RelayIncentivesConfig::default();
        assert!(config.validate().is_ok());

        let bad_config = RelayIncentivesConfig {
            relay_share_bp: 50, // Below minimum
            ..Default::default()
        };
        assert!(bad_config.validate().is_err());

        let bad_config2 = RelayIncentivesConfig {
            relay_share_bp: 5000, // Above maximum
            ..Default::default()
        };
        assert!(bad_config2.validate().is_err());
    }

    #[test]
    fn test_fee_distribution() {
        let dist = FeeDistribution::calculate(1_000_000, 1000); // 10%

        assert_eq!(dist.total_fee, 1_000_000);
        assert_eq!(dist.relay_share, 100_000); // 10%
        assert_eq!(dist.proposer_share, 900_000); // 90%
        assert_eq!(dist.burned, 0);
    }

    #[test]
    fn test_fee_distribution_with_burn() {
        let dist = FeeDistribution::calculate_with_burn(1_000_000, 1000, 500); // 10% relay, 5% burn

        assert_eq!(dist.total_fee, 1_000_000);
        assert_eq!(dist.relay_share, 100_000); // 10%
        assert_eq!(dist.burned, 50_000); // 5%
        assert_eq!(dist.proposer_share, 850_000); // 85%
    }

    #[test]
    fn test_origin_claim() {
        let claim = OriginClaim::new(test_tx_hash(), test_address(), 100);

        assert_eq!(claim.tx_hash, test_tx_hash());
        assert_eq!(claim.relay_address, test_address());
        assert_eq!(claim.seen_at_height, 100);
        assert!(claim.signature.is_none());
        assert!(!claim.is_expired(Duration::from_secs(60)));
    }

    #[test]
    fn test_record_claim() {
        let tracker = RelayIncentivesTracker::default_tracker();
        let claim = OriginClaim::new(test_tx_hash(), test_address(), 100);

        // First claim should succeed
        assert!(tracker.record_claim(claim.clone()).is_ok());

        // Duplicate claim should fail
        assert!(tracker.record_claim(claim).is_err());

        // Should have the claim
        assert!(tracker.has_claim(&test_tx_hash()));
    }

    #[test]
    fn test_process_inclusion() {
        let tracker = RelayIncentivesTracker::default_tracker();
        let claim = OriginClaim::new(test_tx_hash(), test_address(), 100);

        tracker.record_claim(claim).unwrap();

        // Process inclusion with 1 ETH fee
        let result = tracker.process_inclusion(&test_tx_hash(), 1_000_000_000_000_000_000);

        assert!(result.is_some());
        let (relay, share) = result.unwrap();
        assert_eq!(relay, test_address());
        assert_eq!(share, 100_000_000_000_000_000); // 10% of 1 ETH

        // Claim should be removed
        assert!(!tracker.has_claim(&test_tx_hash()));

        // Reward should be pending
        assert_eq!(
            tracker.pending_reward(&test_address()),
            100_000_000_000_000_000
        );
    }

    #[test]
    fn test_withdraw_rewards() {
        let tracker = RelayIncentivesTracker::default_tracker();
        let claim = OriginClaim::new(test_tx_hash(), test_address(), 100);

        tracker.record_claim(claim).unwrap();
        tracker.process_inclusion(&test_tx_hash(), 1_000_000_000_000_000_000);

        let withdrawn = tracker.withdraw_rewards(&test_address());
        assert_eq!(withdrawn, 100_000_000_000_000_000);

        // Should be empty after withdrawal
        assert_eq!(tracker.pending_reward(&test_address()), 0);
    }

    #[test]
    fn test_stats() {
        let tracker = RelayIncentivesTracker::default_tracker();

        for i in 0..5 {
            let tx_hash = [i as u8; 32];
            let claim = OriginClaim::new(tx_hash, test_address(), 100);
            tracker.record_claim(claim).unwrap();
        }

        let stats = tracker.stats();
        assert_eq!(stats.total_claims, 5);
        assert_eq!(stats.active_claims, 5);
        assert_eq!(stats.unique_relays, 1);
    }

    #[test]
    fn test_relay_registry() {
        let registry = RelayRegistry::new();

        registry.register(test_address(), Some("Test Relay".to_string()));

        let info = registry.get(&test_address());
        assert!(info.is_some());
        assert_eq!(info.unwrap().name, Some("Test Relay".to_string()));

        registry.update_stats(&test_address(), 10, 1000);

        let info = registry.get(&test_address()).unwrap();
        assert_eq!(info.transactions_relayed, 10);
        assert_eq!(info.total_fees_earned, 1000);
    }

    #[test]
    fn test_disabled_tracker() {
        let config = RelayIncentivesConfig::disabled();
        let tracker = RelayIncentivesTracker::new(config);

        let claim = OriginClaim::new(test_tx_hash(), test_address(), 100);

        // Recording should succeed but do nothing
        assert!(tracker.record_claim(claim).is_ok());

        // Processing should return None
        let result = tracker.process_inclusion(&test_tx_hash(), 1_000_000_000);
        assert!(result.is_none());
    }
}
