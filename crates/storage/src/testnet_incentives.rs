//! Testnet Incentives
//!
//! This module provides participation tracking and incentives for testnet users:
//!
//! - **Participation Tracking**: Track user activity (transactions, votes, staking)
//! - **Points System**: Award points for different types of participation
//! - **Leaderboards**: Maintain rankings of top participants
//! - **Airdrop Eligibility**: Track eligibility for mainnet airdrops
//!
//! ## Incentive Categories
//!
//! - **Transaction Activity**: Points for sending transactions
//! - **Validator Participation**: Points for running validators
//! - **Staking Activity**: Points for delegating to validators
//! - **Bug Reports**: Manual points for bug reports
//! - **Community Contribution**: Manual points for community activity

use std::collections::HashMap;
use std::time::{Duration, Instant};

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

/// Address type
pub type Address = [u8; 20];

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for testnet incentives
#[derive(Debug, Clone)]
pub struct TestnetIncentivesConfig {
    /// Points per transaction sent
    pub points_per_tx: u64,
    /// Points per transaction received
    pub points_per_tx_received: u64,
    /// Points per block proposed (validators)
    pub points_per_block_proposed: u64,
    /// Points per vote cast (validators)
    pub points_per_vote: u64,
    /// Points per epoch as active validator
    pub points_per_validator_epoch: u64,
    /// Points per stake delegated (per 1000 tokens)
    pub points_per_stake_unit: u64,
    /// Minimum transactions for airdrop eligibility
    pub min_txs_for_airdrop: u64,
    /// Minimum stake days for airdrop eligibility
    pub min_stake_days_for_airdrop: u64,
    /// Maximum points per day per user (anti-gaming)
    pub max_points_per_day: u64,
    /// Enable anti-sybil checks
    pub anti_sybil_enabled: bool,
}

impl Default for TestnetIncentivesConfig {
    fn default() -> Self {
        Self {
            points_per_tx: 10,
            points_per_tx_received: 2,
            points_per_block_proposed: 100,
            points_per_vote: 5,
            points_per_validator_epoch: 1000,
            points_per_stake_unit: 1, // Per 1000 tokens staked
            min_txs_for_airdrop: 10,
            min_stake_days_for_airdrop: 7,
            max_points_per_day: 10_000,
            anti_sybil_enabled: true,
        }
    }
}

// ============================================================================
// Participation Types
// ============================================================================

/// Type of participation activity
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ActivityType {
    /// Sent a transaction
    TransactionSent,
    /// Received a transaction
    TransactionReceived,
    /// Proposed a block (validator)
    BlockProposed,
    /// Cast a vote (validator)
    VoteCast,
    /// Active validator epoch
    ValidatorEpoch,
    /// Delegated stake
    StakeDelegated,
    /// Bug report (manual)
    BugReport,
    /// Community contribution (manual)
    CommunityContribution,
    /// Testnet faucet claim
    FaucetClaim,
    /// Contract deployment
    ContractDeployed,
}

impl ActivityType {
    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            ActivityType::TransactionSent => "Transaction Sent",
            ActivityType::TransactionReceived => "Transaction Received",
            ActivityType::BlockProposed => "Block Proposed",
            ActivityType::VoteCast => "Vote Cast",
            ActivityType::ValidatorEpoch => "Validator Epoch",
            ActivityType::StakeDelegated => "Stake Delegated",
            ActivityType::BugReport => "Bug Report",
            ActivityType::CommunityContribution => "Community Contribution",
            ActivityType::FaucetClaim => "Faucet Claim",
            ActivityType::ContractDeployed => "Contract Deployed",
        }
    }

    /// Check if this is a validator-only activity
    pub fn is_validator_activity(&self) -> bool {
        matches!(
            self,
            ActivityType::BlockProposed | ActivityType::VoteCast | ActivityType::ValidatorEpoch
        )
    }
}

/// A single participation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationEvent {
    /// User address
    pub address: Address,
    /// Type of activity
    pub activity_type: ActivityType,
    /// Points awarded
    pub points: u64,
    /// Block height when this occurred
    pub block_height: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Additional metadata (tx hash, etc.)
    pub metadata: Option<String>,
}

impl ParticipationEvent {
    /// Create a new participation event
    pub fn new(
        address: Address,
        activity_type: ActivityType,
        points: u64,
        block_height: u64,
    ) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        Self {
            address,
            activity_type,
            points,
            block_height,
            timestamp,
            metadata: None,
        }
    }

    /// Add metadata
    pub fn with_metadata(mut self, metadata: &str) -> Self {
        self.metadata = Some(metadata.to_string());
        self
    }
}

// ============================================================================
// User Statistics
// ============================================================================

/// Statistics for a single user
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UserStats {
    /// Total points earned
    pub total_points: u64,
    /// Points earned today (resets daily)
    pub points_today: u64,
    /// Total transactions sent
    pub transactions_sent: u64,
    /// Total transactions received
    pub transactions_received: u64,
    /// Blocks proposed (validators)
    pub blocks_proposed: u64,
    /// Votes cast (validators)
    pub votes_cast: u64,
    /// Epochs as active validator
    pub validator_epochs: u64,
    /// Contracts deployed
    pub contracts_deployed: u64,
    /// Bug reports submitted
    pub bug_reports: u64,
    /// Community contributions
    pub community_contributions: u64,
    /// First activity timestamp
    pub first_activity: Option<u64>,
    /// Last activity timestamp
    pub last_activity: Option<u64>,
    /// Is eligible for airdrop
    pub airdrop_eligible: bool,
    /// Rank on leaderboard
    pub rank: Option<u32>,
    /// Date of last daily reset (YYYYMMDD)
    pub last_daily_reset: u32,
}

impl UserStats {
    /// Check and reset daily points if needed
    pub fn check_daily_reset(&mut self) {
        let today = Self::today_date();
        if self.last_daily_reset != today {
            self.points_today = 0;
            self.last_daily_reset = today;
        }
    }

    /// Get today's date as YYYYMMDD
    fn today_date() -> u32 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        // Simple date calculation (not accounting for all edge cases)
        let days = secs / 86400;
        let years = days / 365;
        let remaining_days = days % 365;
        let months = remaining_days / 30;
        let day = remaining_days % 30;
        ((1970 + years) * 10000 + (months + 1) * 100 + (day + 1)) as u32
    }

    /// Update stats with an activity
    pub fn record_activity(&mut self, event: &ParticipationEvent, max_daily: u64) {
        self.check_daily_reset();

        // Check daily limit
        if self.points_today >= max_daily {
            return; // Hit daily cap
        }

        let points_to_add = event.points.min(max_daily - self.points_today);
        self.total_points += points_to_add;
        self.points_today += points_to_add;

        // Update activity-specific counters
        match event.activity_type {
            ActivityType::TransactionSent => self.transactions_sent += 1,
            ActivityType::TransactionReceived => self.transactions_received += 1,
            ActivityType::BlockProposed => self.blocks_proposed += 1,
            ActivityType::VoteCast => self.votes_cast += 1,
            ActivityType::ValidatorEpoch => self.validator_epochs += 1,
            ActivityType::ContractDeployed => self.contracts_deployed += 1,
            ActivityType::BugReport => self.bug_reports += 1,
            ActivityType::CommunityContribution => self.community_contributions += 1,
            _ => {}
        }

        // Update timestamps
        if self.first_activity.is_none() {
            self.first_activity = Some(event.timestamp);
        }
        self.last_activity = Some(event.timestamp);
    }

    /// Check if user qualifies for airdrop
    pub fn check_airdrop_eligibility(&mut self, config: &TestnetIncentivesConfig) {
        // Check minimum transactions
        let has_min_txs = self.transactions_sent >= config.min_txs_for_airdrop;

        // Check minimum stake duration (simplified: check validator epochs)
        let has_min_stake = self.validator_epochs > 0
            || self.first_activity.is_some_and(|first| {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                (now - first) >= config.min_stake_days_for_airdrop * 86400
            });

        self.airdrop_eligible = has_min_txs || has_min_stake;
    }
}

// ============================================================================
// Leaderboard
// ============================================================================

/// Entry on the leaderboard
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct LeaderboardEntry {
    /// User address
    pub address: Address,
    /// Total points
    pub points: u64,
    /// Rank
    pub rank: u32,
}

impl Ord for LeaderboardEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher points = better (so reverse order)
        other.points.cmp(&self.points)
    }
}

impl PartialOrd for LeaderboardEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Leaderboard snapshot
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LeaderboardSnapshot {
    /// Top entries
    pub entries: Vec<LeaderboardEntry>,
    /// Total participants
    pub total_participants: u64,
    /// Total points distributed
    pub total_points_distributed: u64,
    /// Snapshot timestamp
    pub timestamp: u64,
}

// Implement Serialize/Deserialize for LeaderboardEntry
impl Serialize for LeaderboardEntry {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut s = serializer.serialize_struct("LeaderboardEntry", 3)?;
        s.serialize_field("address", &hex::encode(self.address))?;
        s.serialize_field("points", &self.points)?;
        s.serialize_field("rank", &self.rank)?;
        s.end()
    }
}

impl<'de> Deserialize<'de> for LeaderboardEntry {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct Helper {
            address: String,
            points: u64,
            rank: u32,
        }
        let helper = Helper::deserialize(deserializer)?;
        let bytes = hex::decode(&helper.address).map_err(serde::de::Error::custom)?;
        let mut address = [0u8; 20];
        address.copy_from_slice(&bytes);
        Ok(LeaderboardEntry {
            address,
            points: helper.points,
            rank: helper.rank,
        })
    }
}

// ============================================================================
// Incentives Tracker
// ============================================================================

/// Testnet incentives tracker
pub struct TestnetIncentivesTracker {
    /// Configuration
    config: TestnetIncentivesConfig,
    /// User statistics
    user_stats: RwLock<HashMap<Address, UserStats>>,
    /// Recent events (for auditing)
    recent_events: RwLock<Vec<ParticipationEvent>>,
    /// Maximum events to keep
    max_recent_events: usize,
    /// Cached leaderboard
    cached_leaderboard: RwLock<Option<LeaderboardSnapshot>>,
    /// Leaderboard cache duration
    leaderboard_cache_duration: Duration,
    /// Last leaderboard update
    last_leaderboard_update: RwLock<Option<Instant>>,
}

impl TestnetIncentivesTracker {
    /// Create a new tracker
    pub fn new(config: TestnetIncentivesConfig) -> Self {
        Self {
            config,
            user_stats: RwLock::new(HashMap::new()),
            recent_events: RwLock::new(Vec::new()),
            max_recent_events: 10_000,
            cached_leaderboard: RwLock::new(None),
            leaderboard_cache_duration: Duration::from_secs(60),
            last_leaderboard_update: RwLock::new(None),
        }
    }

    /// Create with default config
    pub fn default_tracker() -> Self {
        Self::new(TestnetIncentivesConfig::default())
    }

    /// Record a transaction sent
    pub fn record_transaction_sent(
        &self,
        sender: Address,
        block_height: u64,
        tx_hash: Option<&str>,
    ) {
        let mut event = ParticipationEvent::new(
            sender,
            ActivityType::TransactionSent,
            self.config.points_per_tx,
            block_height,
        );
        if let Some(hash) = tx_hash {
            event = event.with_metadata(hash);
        }
        self.record_event(event);
    }

    /// Record a transaction received
    pub fn record_transaction_received(&self, receiver: Address, block_height: u64) {
        let event = ParticipationEvent::new(
            receiver,
            ActivityType::TransactionReceived,
            self.config.points_per_tx_received,
            block_height,
        );
        self.record_event(event);
    }

    /// Record a block proposed
    pub fn record_block_proposed(&self, validator: Address, block_height: u64) {
        let event = ParticipationEvent::new(
            validator,
            ActivityType::BlockProposed,
            self.config.points_per_block_proposed,
            block_height,
        );
        self.record_event(event);
    }

    /// Record a vote cast
    pub fn record_vote(&self, validator: Address, block_height: u64) {
        let event = ParticipationEvent::new(
            validator,
            ActivityType::VoteCast,
            self.config.points_per_vote,
            block_height,
        );
        self.record_event(event);
    }

    /// Record validator epoch completion
    pub fn record_validator_epoch(&self, validator: Address, epoch: u64) {
        let event = ParticipationEvent::new(
            validator,
            ActivityType::ValidatorEpoch,
            self.config.points_per_validator_epoch,
            epoch,
        );
        self.record_event(event);
    }

    /// Record stake delegation
    pub fn record_stake_delegation(&self, delegator: Address, stake_units: u64, block_height: u64) {
        let points = stake_units * self.config.points_per_stake_unit;
        let event = ParticipationEvent::new(
            delegator,
            ActivityType::StakeDelegated,
            points,
            block_height,
        );
        self.record_event(event);
    }

    /// Record a bug report (manual)
    pub fn record_bug_report(&self, reporter: Address, points: u64, description: &str) {
        let event = ParticipationEvent::new(reporter, ActivityType::BugReport, points, 0)
            .with_metadata(description);
        self.record_event(event);
    }

    /// Record community contribution (manual)
    pub fn record_community_contribution(
        &self,
        contributor: Address,
        points: u64,
        description: &str,
    ) {
        let event =
            ParticipationEvent::new(contributor, ActivityType::CommunityContribution, points, 0)
                .with_metadata(description);
        self.record_event(event);
    }

    /// Record a participation event
    fn record_event(&self, event: ParticipationEvent) {
        // Update user stats
        {
            let mut stats = self.user_stats.write();
            let user_stats = stats.entry(event.address).or_default();
            user_stats.record_activity(&event, self.config.max_points_per_day);
            user_stats.check_airdrop_eligibility(&self.config);
        }

        // Store recent event
        {
            let mut events = self.recent_events.write();
            events.push(event);
            // Trim if too many
            let len = events.len();
            if len > self.max_recent_events {
                let to_remove = len - self.max_recent_events;
                events.drain(0..to_remove);
            }
        }

        // Invalidate leaderboard cache
        *self.last_leaderboard_update.write() = None;
    }

    /// Get user stats
    pub fn get_user_stats(&self, address: &Address) -> Option<UserStats> {
        self.user_stats.read().get(address).cloned()
    }

    /// Get user points
    pub fn get_points(&self, address: &Address) -> u64 {
        self.user_stats
            .read()
            .get(address)
            .map(|s| s.total_points)
            .unwrap_or(0)
    }

    /// Get leaderboard
    pub fn get_leaderboard(&self, limit: usize) -> LeaderboardSnapshot {
        // Check cache
        {
            let last_update = self.last_leaderboard_update.read();
            if let Some(last) = *last_update {
                if last.elapsed() < self.leaderboard_cache_duration {
                    if let Some(cached) = self.cached_leaderboard.read().as_ref() {
                        let mut snapshot = cached.clone();
                        snapshot.entries.truncate(limit);
                        return snapshot;
                    }
                }
            }
        }

        // Build leaderboard
        let stats = self.user_stats.read();
        let mut entries: Vec<LeaderboardEntry> = stats
            .iter()
            .map(|(addr, s)| LeaderboardEntry {
                address: *addr,
                points: s.total_points,
                rank: 0,
            })
            .collect();

        // Sort by points (descending)
        entries.sort();

        // Assign ranks
        for (i, entry) in entries.iter_mut().enumerate() {
            entry.rank = (i + 1) as u32;
        }

        let total_points: u64 = entries.iter().map(|e| e.points).sum();

        let snapshot = LeaderboardSnapshot {
            entries: entries.clone(),
            total_participants: entries.len() as u64,
            total_points_distributed: total_points,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        // Cache full leaderboard
        *self.cached_leaderboard.write() = Some(snapshot.clone());
        *self.last_leaderboard_update.write() = Some(Instant::now());

        // Return truncated version
        let mut result = snapshot;
        result.entries.truncate(limit);
        result
    }

    /// Get users eligible for airdrop
    pub fn get_airdrop_eligible(&self) -> Vec<(Address, u64)> {
        self.user_stats
            .read()
            .iter()
            .filter(|(_, s)| s.airdrop_eligible)
            .map(|(addr, s)| (*addr, s.total_points))
            .collect()
    }

    /// Get total statistics
    pub fn get_total_stats(&self) -> TotalStats {
        let stats = self.user_stats.read();
        let total_points: u64 = stats.values().map(|s| s.total_points).sum();
        let total_txs: u64 = stats.values().map(|s| s.transactions_sent).sum();
        let total_blocks: u64 = stats.values().map(|s| s.blocks_proposed).sum();
        let airdrop_eligible = stats.values().filter(|s| s.airdrop_eligible).count();

        TotalStats {
            total_participants: stats.len() as u64,
            total_points_distributed: total_points,
            total_transactions: total_txs,
            total_blocks_proposed: total_blocks,
            airdrop_eligible_count: airdrop_eligible as u64,
        }
    }

    /// Get user rank
    pub fn get_user_rank(&self, address: &Address) -> Option<u32> {
        let leaderboard = self.get_leaderboard(usize::MAX);
        leaderboard
            .entries
            .iter()
            .find(|e| e.address == *address)
            .map(|e| e.rank)
    }

    /// Export data for airdrop
    pub fn export_airdrop_data(&self) -> AirdropExport {
        let eligible = self.get_airdrop_eligible();
        let total_points: u64 = eligible.iter().map(|(_, p)| *p).sum();

        AirdropExport {
            eligible_addresses: eligible,
            total_points,
            export_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

/// Total statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TotalStats {
    /// Total unique participants
    pub total_participants: u64,
    /// Total points distributed
    pub total_points_distributed: u64,
    /// Total transactions
    pub total_transactions: u64,
    /// Total blocks proposed
    pub total_blocks_proposed: u64,
    /// Users eligible for airdrop
    pub airdrop_eligible_count: u64,
}

/// Airdrop export data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AirdropExport {
    /// Eligible addresses and their points
    pub eligible_addresses: Vec<(Address, u64)>,
    /// Total points among eligible addresses
    pub total_points: u64,
    /// Export timestamp
    pub export_timestamp: u64,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_address(n: u8) -> Address {
        let mut addr = [0u8; 20];
        addr[0] = n;
        addr
    }

    #[test]
    fn test_config_defaults() {
        let config = TestnetIncentivesConfig::default();
        assert_eq!(config.points_per_tx, 10);
        assert_eq!(config.min_txs_for_airdrop, 10);
    }

    #[test]
    fn test_record_transaction() {
        let tracker = TestnetIncentivesTracker::default_tracker();

        tracker.record_transaction_sent(test_address(1), 100, Some("0xabc123"));

        let stats = tracker.get_user_stats(&test_address(1)).unwrap();
        assert_eq!(stats.total_points, 10);
        assert_eq!(stats.transactions_sent, 1);
    }

    #[test]
    fn test_validator_activity() {
        let tracker = TestnetIncentivesTracker::default_tracker();

        tracker.record_block_proposed(test_address(1), 100);
        tracker.record_vote(test_address(1), 100);

        let stats = tracker.get_user_stats(&test_address(1)).unwrap();
        assert_eq!(stats.blocks_proposed, 1);
        assert_eq!(stats.votes_cast, 1);
        assert_eq!(stats.total_points, 100 + 5); // Block + vote
    }

    #[test]
    fn test_leaderboard() {
        let tracker = TestnetIncentivesTracker::default_tracker();

        // Create users with different points
        for i in 0..5 {
            for _ in 0..((i + 1) * 10) {
                tracker.record_transaction_sent(test_address(i), 100, None);
            }
        }

        let leaderboard = tracker.get_leaderboard(10);
        assert_eq!(leaderboard.entries.len(), 5);
        // User 4 should be first (most txs)
        assert_eq!(leaderboard.entries[0].address, test_address(4));
        assert_eq!(leaderboard.entries[0].rank, 1);
    }

    #[test]
    fn test_airdrop_eligibility() {
        let tracker = TestnetIncentivesTracker::default_tracker();

        // User with 5 txs (not eligible)
        for _ in 0..5 {
            tracker.record_transaction_sent(test_address(1), 100, None);
        }

        // User with 15 txs (eligible)
        for _ in 0..15 {
            tracker.record_transaction_sent(test_address(2), 100, None);
        }

        let stats1 = tracker.get_user_stats(&test_address(1)).unwrap();
        let stats2 = tracker.get_user_stats(&test_address(2)).unwrap();

        assert!(!stats1.airdrop_eligible);
        assert!(stats2.airdrop_eligible);
    }

    #[test]
    fn test_daily_cap() {
        let config = TestnetIncentivesConfig {
            max_points_per_day: 100,
            points_per_tx: 20,
            ..Default::default()
        };
        let tracker = TestnetIncentivesTracker::new(config);

        // Send 10 transactions (200 points worth, but capped at 100)
        for _ in 0..10 {
            tracker.record_transaction_sent(test_address(1), 100, None);
        }

        let stats = tracker.get_user_stats(&test_address(1)).unwrap();
        assert_eq!(stats.total_points, 100); // Capped at daily max
    }

    #[test]
    fn test_total_stats() {
        let tracker = TestnetIncentivesTracker::default_tracker();

        tracker.record_transaction_sent(test_address(1), 100, None);
        tracker.record_transaction_sent(test_address(2), 100, None);
        tracker.record_block_proposed(test_address(3), 100);

        let total = tracker.get_total_stats();
        assert_eq!(total.total_participants, 3);
        assert_eq!(total.total_transactions, 2);
        assert_eq!(total.total_blocks_proposed, 1);
    }

    #[test]
    fn test_activity_types() {
        assert!(ActivityType::BlockProposed.is_validator_activity());
        assert!(ActivityType::VoteCast.is_validator_activity());
        assert!(!ActivityType::TransactionSent.is_validator_activity());
    }
}
