//! # Zero False-Positive Sybil Detection
//!
//! This module implements multi-signal Sybil detection for the inverse rewards system.
//! The design prioritizes zero false positives over aggressive detection, using:
//!
//! - **Multi-signal confirmation**: No penalty on single weak signals
//! - **Tiered confidence levels**: Graduated response based on evidence strength
//! - **Appeal process**: 7-day grace period before penalties take effect
//! - **Controversial vote focus**: Only correlations on disputed blocks matter
//!
//! ## Signal Weights
//!
//! | Signal | Weight | False Positive Risk |
//! |--------|--------|---------------------|
//! | Controversial vote correlation (>80%) | +2.0 | Very Low |
//! | Same withdrawal address | +3.0 (auto-confirms) | Very Low |
//! | Same /24 IP subnet | +1.0 | Medium |
//! | Vote timing <50ms correlation | +1.5 | Low |
//! | Registration same epoch | +0.5 | High |
//! | Identical stake amounts | +0.3 | High |
//!
//! ## Confidence Levels
//!
//! ```text
//! Score < 1.0  -> None      (no penalty)
//! Score >= 1.0 -> Low       (notification only)
//! Score >= 2.0 -> Medium    (80% cap after appeal window)
//! Score >= 3.5 -> High      (95% cap after appeal window)
//! Score >= 5.0 -> Confirmed (99% cap, governance flagged)
//! ```

use protocore_types::Address;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Confidence level for Sybil detection.
///
/// Higher confidence means stronger evidence of Sybil behavior.
/// Penalties only apply at Medium or above, and only after the appeal window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConfidenceLevel {
    /// Score < 1.0 - No Sybil signals detected
    None,
    /// Score >= 1.0 AND < 2.0 - Weak signals, notification only
    Low,
    /// Score >= 2.0 AND < 3.5 - Moderate signals, 80% penalty cap
    Medium,
    /// Score >= 3.5 AND < 5.0 - Strong signals, 95% penalty cap
    High,
    /// Score >= 5.0 OR governance flagged - Confirmed Sybil, 99% penalty cap
    Confirmed,
}

impl ConfidenceLevel {
    /// Determine confidence level from a signal score.
    pub fn from_score(score: f64) -> Self {
        if score >= 5.0 {
            ConfidenceLevel::Confirmed
        } else if score >= 3.5 {
            ConfidenceLevel::High
        } else if score >= 2.0 {
            ConfidenceLevel::Medium
        } else if score >= 1.0 {
            ConfidenceLevel::Low
        } else {
            ConfidenceLevel::None
        }
    }

    /// Returns true if this confidence level results in a penalty.
    pub fn has_penalty(&self) -> bool {
        matches!(
            self,
            ConfidenceLevel::Medium | ConfidenceLevel::High | ConfidenceLevel::Confirmed
        )
    }
}

impl Default for ConfidenceLevel {
    fn default() -> Self {
        ConfidenceLevel::None
    }
}

/// Types of signals that indicate potential Sybil behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SignalType {
    /// >80% correlation in controversial votes
    ControversialVoteCorrelation,
    /// Multiple validators share the same withdrawal address
    SameWithdrawalAddress,
    /// Multiple validators in the same /24 IP subnet
    SameIpSubnet,
    /// Votes submitted within 50ms of each other
    VoteTimingCorrelation,
    /// Validators registered in the same epoch
    SameRegistrationEpoch,
    /// Validators have identical stake amounts
    IdenticalStakeAmount,
    /// Flagged by governance vote
    GovernanceFlag,
}

impl SignalType {
    /// Get the default weight for this signal type.
    pub fn default_weight(&self) -> f64 {
        match self {
            SignalType::ControversialVoteCorrelation => 2.0,
            SignalType::SameWithdrawalAddress => 3.0,
            SignalType::SameIpSubnet => 1.0,
            SignalType::VoteTimingCorrelation => 1.5,
            SignalType::SameRegistrationEpoch => 0.5,
            SignalType::IdenticalStakeAmount => 0.3,
            SignalType::GovernanceFlag => 5.0,
        }
    }

    /// Returns true if this signal type auto-confirms Sybil status.
    pub fn auto_confirms(&self) -> bool {
        matches!(
            self,
            SignalType::SameWithdrawalAddress | SignalType::GovernanceFlag
        )
    }
}

/// A detected Sybil signal with evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilSignal {
    /// The type of signal detected
    pub signal_type: SignalType,
    /// Weight contribution to the total score
    pub weight: f64,
    /// Timestamp when the signal was detected (seconds since epoch)
    pub detected_at: u64,
    /// Other validators involved in this signal
    pub related_validators: Vec<Address>,
    /// Human-readable evidence description
    pub evidence: String,
}

impl SybilSignal {
    /// Create a new Sybil signal.
    pub fn new(
        signal_type: SignalType,
        detected_at: u64,
        related_validators: Vec<Address>,
        evidence: String,
    ) -> Self {
        Self {
            signal_type,
            weight: signal_type.default_weight(),
            detected_at,
            related_validators,
            evidence,
        }
    }

    /// Create a new Sybil signal with a custom weight.
    pub fn with_weight(
        signal_type: SignalType,
        weight: f64,
        detected_at: u64,
        related_validators: Vec<Address>,
        evidence: String,
    ) -> Self {
        Self {
            signal_type,
            weight,
            detected_at,
            related_validators,
            evidence,
        }
    }
}

/// Current status of an appeal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AppealState {
    /// Appeal submitted, awaiting review
    Pending,
    /// Appeal approved, signals cleared
    Approved,
    /// Appeal denied, penalty applies
    Denied,
}

/// Status of an appeal for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppealStatus {
    /// When the appeal was submitted (seconds since epoch)
    pub submitted_at: u64,
    /// Evidence provided by the validator
    pub evidence: String,
    /// Current state of the appeal
    pub status: AppealState,
    /// When the appeal was reviewed (if reviewed)
    pub reviewed_at: Option<u64>,
}

impl AppealStatus {
    /// Create a new pending appeal.
    pub fn new(submitted_at: u64, evidence: String) -> Self {
        Self {
            submitted_at,
            evidence,
            status: AppealState::Pending,
            reviewed_at: None,
        }
    }
}

/// Complete Sybil status for a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilStatus {
    /// Current confidence level
    pub confidence_level: ConfidenceLevel,
    /// Total signal score
    pub signal_score: f64,
    /// All active signals
    pub active_signals: Vec<SybilSignal>,
    /// Current penalty (0.0 to 0.99)
    pub penalty: f64,
    /// Active appeal status, if any
    pub appeal_status: Option<AppealStatus>,
    /// When the penalty becomes effective (after grace period)
    pub penalty_effective_at: Option<u64>,
}

impl Default for SybilStatus {
    fn default() -> Self {
        Self {
            confidence_level: ConfidenceLevel::None,
            signal_score: 0.0,
            active_signals: Vec::new(),
            penalty: 0.0,
            appeal_status: None,
            penalty_effective_at: None,
        }
    }
}

/// Configuration for the Sybil detector.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SybilConfig {
    /// Weight for controversial vote correlation signal
    pub weight_controversial_vote: f64,
    /// Weight for same withdrawal address signal
    pub weight_same_withdrawal: f64,
    /// Weight for same /24 IP subnet signal
    pub weight_same_ip_subnet: f64,
    /// Weight for vote timing correlation signal
    pub weight_vote_timing: f64,
    /// Weight for same registration epoch signal
    pub weight_same_registration: f64,
    /// Weight for identical stake amount signal
    pub weight_identical_stake: f64,
    /// Threshold for controversial vote correlation (0.0-1.0)
    pub controversial_threshold: f64,
    /// Maximum time difference for vote timing correlation (ms)
    pub vote_timing_threshold_ms: u64,
    /// Penalty cap for medium confidence (0.0-1.0)
    pub penalty_cap_medium: f64,
    /// Penalty cap for high confidence (0.0-1.0)
    pub penalty_cap_high: f64,
    /// Penalty cap for confirmed Sybils (0.0-1.0)
    pub penalty_cap_confirmed: f64,
    /// Grace period before penalty takes effect (seconds)
    pub appeal_grace_period_secs: u64,
}

impl Default for SybilConfig {
    fn default() -> Self {
        Self {
            weight_controversial_vote: 2.0,
            weight_same_withdrawal: 3.0,
            weight_same_ip_subnet: 1.0,
            weight_vote_timing: 1.5,
            weight_same_registration: 0.5,
            weight_identical_stake: 0.3,
            controversial_threshold: 0.80,
            vote_timing_threshold_ms: 50,
            penalty_cap_medium: 0.80,
            penalty_cap_high: 0.95,
            penalty_cap_confirmed: 0.99,
            appeal_grace_period_secs: 7 * 24 * 60 * 60, // 7 days
        }
    }
}

/// Tracks vote correlations for controversial blocks.
#[derive(Debug, Default)]
struct VoteCorrelationTracker {
    /// Votes per block: block_hash -> (validator -> (vote, timestamp_ms))
    votes: HashMap<[u8; 32], HashMap<Address, (bool, u64)>>,
    /// Set of controversial blocks (>10% disagreement)
    controversial: HashSet<[u8; 32]>,
    /// Maximum number of blocks to track (prevents unbounded growth)
    max_blocks: usize,
    /// Block hashes in order of insertion (for LRU eviction)
    block_order: Vec<[u8; 32]>,
}

impl VoteCorrelationTracker {
    /// Create a new vote correlation tracker.
    pub fn new(max_blocks: usize) -> Self {
        Self {
            votes: HashMap::new(),
            controversial: HashSet::new(),
            max_blocks,
            block_order: Vec::new(),
        }
    }

    /// Record a vote for a validator on a block.
    pub fn record_vote(
        &mut self,
        validator: Address,
        block_hash: [u8; 32],
        vote: bool,
        timestamp_ms: u64,
    ) {
        // Evict old blocks if needed
        if !self.votes.contains_key(&block_hash) && self.votes.len() >= self.max_blocks {
            if let Some(old_hash) = self.block_order.first().copied() {
                self.votes.remove(&old_hash);
                self.controversial.remove(&old_hash);
                self.block_order.remove(0);
            }
        }

        // Record the vote
        let block_votes = self.votes.entry(block_hash).or_default();
        if !block_votes.contains_key(&validator) {
            if !self.block_order.contains(&block_hash) {
                self.block_order.push(block_hash);
            }
        }
        block_votes.insert(validator, (vote, timestamp_ms));
    }

    /// Mark a block as controversial.
    pub fn mark_controversial(&mut self, block_hash: [u8; 32]) {
        self.controversial.insert(block_hash);
    }

    /// Get all controversial blocks with their votes.
    pub fn controversial_blocks(&self) -> impl Iterator<Item = (&[u8; 32], &HashMap<Address, (bool, u64)>)> {
        self.controversial.iter().filter_map(move |hash| {
            self.votes.get(hash).map(|votes| (hash, votes))
        })
    }

    /// Calculate vote correlation between two validators on controversial blocks.
    ///
    /// Returns (correlation_rate, vote_count) where correlation_rate is 0.0-1.0.
    pub fn calculate_correlation(&self, v1: &Address, v2: &Address) -> (f64, usize) {
        let mut matching = 0usize;
        let mut total = 0usize;

        for (hash, votes) in &self.votes {
            // Only consider controversial blocks
            if !self.controversial.contains(hash) {
                continue;
            }

            if let (Some((vote1, _)), Some((vote2, _))) = (votes.get(v1), votes.get(v2)) {
                total += 1;
                if vote1 == vote2 {
                    matching += 1;
                }
            }
        }

        if total == 0 {
            (0.0, 0)
        } else {
            (matching as f64 / total as f64, total)
        }
    }

    /// Find validators with vote timing correlation on controversial blocks.
    ///
    /// Returns pairs of validators whose votes were submitted within threshold_ms of each other.
    pub fn find_timing_correlations(
        &self,
        threshold_ms: u64,
    ) -> Vec<(Address, Address, usize)> {
        let mut correlations: HashMap<(Address, Address), usize> = HashMap::new();

        for (hash, votes) in &self.votes {
            // Only consider controversial blocks
            if !self.controversial.contains(hash) {
                continue;
            }

            let vote_list: Vec<_> = votes.iter().collect();
            for i in 0..vote_list.len() {
                for j in (i + 1)..vote_list.len() {
                    let (v1, (_, t1)) = vote_list[i];
                    let (v2, (_, t2)) = vote_list[j];

                    let time_diff = if *t1 > *t2 { t1 - t2 } else { t2 - t1 };
                    if time_diff <= threshold_ms {
                        let key = if v1 < v2 { (*v1, *v2) } else { (*v2, *v1) };
                        *correlations.entry(key).or_insert(0) += 1;
                    }
                }
            }
        }

        correlations
            .into_iter()
            .map(|((v1, v2), count)| (v1, v2, count))
            .collect()
    }
}

/// The main Sybil detection engine.
pub struct SybilDetector {
    /// Configuration parameters
    config: SybilConfig,
    /// Per-validator signals
    signals: HashMap<Address, Vec<SybilSignal>>,
    /// Active appeals
    appeals: HashMap<Address, AppealStatus>,
    /// Governance-confirmed Sybils
    confirmed_sybils: HashSet<Address>,
    /// Vote history for controversial vote detection
    vote_history: VoteCorrelationTracker,
    /// First signal detection time per validator (for grace period calculation)
    first_signal_at: HashMap<Address, u64>,
}

impl SybilDetector {
    /// Create a new Sybil detector with the given configuration.
    pub fn new(config: SybilConfig) -> Self {
        Self {
            config,
            signals: HashMap::new(),
            appeals: HashMap::new(),
            confirmed_sybils: HashSet::new(),
            vote_history: VoteCorrelationTracker::new(1000), // Track last 1000 blocks
            first_signal_at: HashMap::new(),
        }
    }

    /// Create a new Sybil detector with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(SybilConfig::default())
    }

    /// Add a signal for a validator.
    pub fn add_signal(&mut self, validator: Address, signal: SybilSignal) {
        // Track first signal time for grace period
        if !self.first_signal_at.contains_key(&validator) {
            self.first_signal_at.insert(validator, signal.detected_at);
        }

        self.signals.entry(validator).or_default().push(signal);
    }

    /// Record a vote for correlation tracking.
    pub fn record_vote(
        &mut self,
        validator: Address,
        block_hash: [u8; 32],
        vote: bool,
        timestamp_ms: u64,
    ) {
        self.vote_history.record_vote(validator, block_hash, vote, timestamp_ms);
    }

    /// Mark a block as controversial (>10% disagree).
    pub fn mark_controversial(&mut self, block_hash: [u8; 32]) {
        self.vote_history.mark_controversial(block_hash);
    }

    /// Analyze vote correlations and generate signals.
    ///
    /// This should be called periodically (e.g., every epoch) to detect correlated voting.
    pub fn analyze_correlations(&mut self, current_timestamp: u64) {
        // Get all validators that have voted
        let validators: HashSet<Address> = self
            .vote_history
            .controversial_blocks()
            .flat_map(|(_, votes)| votes.keys().copied())
            .collect();

        let validators: Vec<Address> = validators.into_iter().collect();

        // Check vote correlations
        for i in 0..validators.len() {
            for j in (i + 1)..validators.len() {
                let v1 = &validators[i];
                let v2 = &validators[j];

                let (correlation, vote_count) = self.vote_history.calculate_correlation(v1, v2);

                // Only trigger if correlation exceeds threshold and we have enough samples
                if correlation >= self.config.controversial_threshold && vote_count >= 3 {
                    let evidence = format!(
                        "Vote correlation {:.1}% on {} controversial blocks",
                        correlation * 100.0,
                        vote_count
                    );

                    // Add signal for both validators
                    let signal1 = SybilSignal::with_weight(
                        SignalType::ControversialVoteCorrelation,
                        self.config.weight_controversial_vote,
                        current_timestamp,
                        vec![*v2],
                        evidence.clone(),
                    );
                    let signal2 = SybilSignal::with_weight(
                        SignalType::ControversialVoteCorrelation,
                        self.config.weight_controversial_vote,
                        current_timestamp,
                        vec![*v1],
                        evidence,
                    );

                    // Only add if not already detected
                    if !self.has_signal_type(v1, SignalType::ControversialVoteCorrelation, v2) {
                        self.add_signal(*v1, signal1);
                    }
                    if !self.has_signal_type(v2, SignalType::ControversialVoteCorrelation, v1) {
                        self.add_signal(*v2, signal2);
                    }
                }
            }
        }

        // Check vote timing correlations
        let timing_correlations = self
            .vote_history
            .find_timing_correlations(self.config.vote_timing_threshold_ms);

        for (v1, v2, count) in timing_correlations {
            // Only trigger if we have enough correlated timing events
            if count >= 3 {
                let evidence = format!(
                    "Vote timing within {}ms on {} controversial blocks",
                    self.config.vote_timing_threshold_ms, count
                );

                let signal1 = SybilSignal::with_weight(
                    SignalType::VoteTimingCorrelation,
                    self.config.weight_vote_timing,
                    current_timestamp,
                    vec![v2],
                    evidence.clone(),
                );
                let signal2 = SybilSignal::with_weight(
                    SignalType::VoteTimingCorrelation,
                    self.config.weight_vote_timing,
                    current_timestamp,
                    vec![v1],
                    evidence,
                );

                if !self.has_signal_type(&v1, SignalType::VoteTimingCorrelation, &v2) {
                    self.add_signal(v1, signal1);
                }
                if !self.has_signal_type(&v2, SignalType::VoteTimingCorrelation, &v1) {
                    self.add_signal(v2, signal2);
                }
            }
        }
    }

    /// Check if a validator already has a specific signal type with a related validator.
    fn has_signal_type(&self, validator: &Address, signal_type: SignalType, related: &Address) -> bool {
        self.signals
            .get(validator)
            .map(|signals| {
                signals.iter().any(|s| {
                    s.signal_type == signal_type && s.related_validators.contains(related)
                })
            })
            .unwrap_or(false)
    }

    /// Check for validators sharing the same withdrawal address.
    ///
    /// Input: list of (validator_address, withdrawal_address) pairs.
    pub fn check_withdrawal_addresses(&mut self, validators: &[(Address, Address)], current_timestamp: u64) {
        // Group validators by withdrawal address
        let mut by_withdrawal: HashMap<Address, Vec<Address>> = HashMap::new();
        for (validator, withdrawal) in validators {
            by_withdrawal.entry(*withdrawal).or_default().push(*validator);
        }

        // Flag validators that share withdrawal addresses
        for (withdrawal, sharing_validators) in by_withdrawal {
            if sharing_validators.len() > 1 {
                for validator in &sharing_validators {
                    let related: Vec<Address> = sharing_validators
                        .iter()
                        .filter(|v| *v != validator)
                        .copied()
                        .collect();

                    let evidence = format!(
                        "Shares withdrawal address {} with {} other validator(s)",
                        withdrawal,
                        related.len()
                    );

                    // Check if we already have this signal
                    if !self.has_signal_type(validator, SignalType::SameWithdrawalAddress, &related[0]) {
                        let signal = SybilSignal::with_weight(
                            SignalType::SameWithdrawalAddress,
                            self.config.weight_same_withdrawal,
                            current_timestamp,
                            related,
                            evidence,
                        );
                        self.add_signal(*validator, signal);
                    }
                }
            }
        }
    }

    /// Check for IP clustering (/24 subnet).
    ///
    /// Input: list of (validator_address, ip_address) pairs.
    pub fn check_ip_clustering(&mut self, validators: &[(Address, [u8; 4])], current_timestamp: u64) {
        // Group validators by /24 subnet (first 3 octets)
        let mut by_subnet: HashMap<[u8; 3], Vec<(Address, [u8; 4])>> = HashMap::new();
        for (validator, ip) in validators {
            let subnet = [ip[0], ip[1], ip[2]];
            by_subnet.entry(subnet).or_default().push((*validator, *ip));
        }

        // Flag validators in subnets with multiple validators
        for (subnet, subnet_validators) in by_subnet {
            if subnet_validators.len() > 1 {
                for (validator, ip) in &subnet_validators {
                    let related: Vec<Address> = subnet_validators
                        .iter()
                        .filter(|(v, _)| v != validator)
                        .map(|(v, _)| *v)
                        .collect();

                    let evidence = format!(
                        "IP {}.{}.{}.{} in subnet {}.{}.{}.0/24 with {} other validator(s)",
                        ip[0], ip[1], ip[2], ip[3],
                        subnet[0], subnet[1], subnet[2],
                        related.len()
                    );

                    // Check if we already have this signal
                    if !self.has_signal_type(validator, SignalType::SameIpSubnet, &related[0]) {
                        let signal = SybilSignal::with_weight(
                            SignalType::SameIpSubnet,
                            self.config.weight_same_ip_subnet,
                            current_timestamp,
                            related,
                            evidence,
                        );
                        self.add_signal(*validator, signal);
                    }
                }
            }
        }
    }

    /// Check for validators registered in the same epoch.
    ///
    /// Input: list of (validator_address, registration_epoch) pairs.
    pub fn check_registration_epochs(&mut self, validators: &[(Address, u64)], current_timestamp: u64) {
        // Group validators by registration epoch
        let mut by_epoch: HashMap<u64, Vec<Address>> = HashMap::new();
        for (validator, epoch) in validators {
            by_epoch.entry(*epoch).or_default().push(*validator);
        }

        // Flag validators registered in the same epoch (only if multiple)
        for (epoch, epoch_validators) in by_epoch {
            if epoch_validators.len() > 1 {
                for validator in &epoch_validators {
                    let related: Vec<Address> = epoch_validators
                        .iter()
                        .filter(|v| *v != validator)
                        .copied()
                        .collect();

                    let evidence = format!(
                        "Registered in epoch {} with {} other validator(s)",
                        epoch,
                        related.len()
                    );

                    // Check if we already have this signal
                    if !related.is_empty() && !self.has_signal_type(validator, SignalType::SameRegistrationEpoch, &related[0]) {
                        let signal = SybilSignal::with_weight(
                            SignalType::SameRegistrationEpoch,
                            self.config.weight_same_registration,
                            current_timestamp,
                            related,
                            evidence,
                        );
                        self.add_signal(*validator, signal);
                    }
                }
            }
        }
    }

    /// Check for validators with identical stake amounts.
    ///
    /// Input: list of (validator_address, stake_amount) pairs.
    pub fn check_identical_stakes(&mut self, validators: &[(Address, u128)], current_timestamp: u64) {
        // Group validators by stake amount
        let mut by_stake: HashMap<u128, Vec<Address>> = HashMap::new();
        for (validator, stake) in validators {
            by_stake.entry(*stake).or_default().push(*validator);
        }

        // Flag validators with identical stakes (only if multiple)
        for (stake, stake_validators) in by_stake {
            if stake_validators.len() > 1 {
                for validator in &stake_validators {
                    let related: Vec<Address> = stake_validators
                        .iter()
                        .filter(|v| *v != validator)
                        .copied()
                        .collect();

                    let evidence = format!(
                        "Identical stake amount {} with {} other validator(s)",
                        stake,
                        related.len()
                    );

                    // Check if we already have this signal
                    if !related.is_empty() && !self.has_signal_type(validator, SignalType::IdenticalStakeAmount, &related[0]) {
                        let signal = SybilSignal::with_weight(
                            SignalType::IdenticalStakeAmount,
                            self.config.weight_identical_stake,
                            current_timestamp,
                            related,
                            evidence,
                        );
                        self.add_signal(*validator, signal);
                    }
                }
            }
        }
    }

    /// Calculate the total signal score for a validator.
    fn calculate_score(&self, validator: &Address) -> f64 {
        self.signals
            .get(validator)
            .map(|signals| signals.iter().map(|s| s.weight).sum())
            .unwrap_or(0.0)
    }

    /// Calculate the confidence level for a validator.
    pub fn confidence_level(&self, validator: &Address) -> ConfidenceLevel {
        // Governance-confirmed Sybils are always "Confirmed"
        if self.confirmed_sybils.contains(validator) {
            return ConfidenceLevel::Confirmed;
        }

        let score = self.calculate_score(validator);
        ConfidenceLevel::from_score(score)
    }

    /// Calculate the penalty for a validator.
    ///
    /// Returns a value between 0.0 (no penalty) and 0.99 (maximum penalty).
    /// Considers appeal status and grace period.
    pub fn calculate_penalty(&self, validator: &Address, current_timestamp: u64) -> f64 {
        let confidence = self.confidence_level(validator);

        // No penalty for None or Low confidence
        if !confidence.has_penalty() {
            return 0.0;
        }

        // Check if within grace period
        if let Some(first_signal) = self.first_signal_at.get(validator) {
            let elapsed = current_timestamp.saturating_sub(*first_signal);
            if elapsed < self.config.appeal_grace_period_secs {
                // Still in grace period - no penalty yet
                return 0.0;
            }
        }

        // Check appeal status
        if let Some(appeal) = self.appeals.get(validator) {
            match appeal.status {
                AppealState::Pending => {
                    // Appeal pending - no penalty during review
                    return 0.0;
                }
                AppealState::Approved => {
                    // Appeal approved - no penalty
                    return 0.0;
                }
                AppealState::Denied => {
                    // Appeal denied - apply penalty
                }
            }
        }

        // Apply penalty based on confidence level
        match confidence {
            ConfidenceLevel::None | ConfidenceLevel::Low => 0.0,
            ConfidenceLevel::Medium => self.config.penalty_cap_medium,
            ConfidenceLevel::High => self.config.penalty_cap_high,
            ConfidenceLevel::Confirmed => self.config.penalty_cap_confirmed,
        }
    }

    /// Get the full Sybil status for a validator.
    pub fn get_status(&self, validator: &Address, current_timestamp: u64) -> SybilStatus {
        let signal_score = self.calculate_score(validator);
        let confidence_level = if self.confirmed_sybils.contains(validator) {
            ConfidenceLevel::Confirmed
        } else {
            ConfidenceLevel::from_score(signal_score)
        };

        let active_signals = self
            .signals
            .get(validator)
            .cloned()
            .unwrap_or_default();

        let appeal_status = self.appeals.get(validator).cloned();

        let penalty = self.calculate_penalty(validator, current_timestamp);

        // Calculate when penalty becomes effective
        let penalty_effective_at = self.first_signal_at.get(validator).map(|first| {
            first + self.config.appeal_grace_period_secs
        });

        SybilStatus {
            confidence_level,
            signal_score,
            active_signals,
            penalty,
            appeal_status,
            penalty_effective_at,
        }
    }

    /// Submit an appeal for a validator.
    pub fn submit_appeal(&mut self, validator: Address, evidence: String, timestamp: u64) {
        let appeal = AppealStatus::new(timestamp, evidence);
        self.appeals.insert(validator, appeal);
    }

    /// Process an appeal (governance action).
    pub fn process_appeal(&mut self, validator: &Address, approved: bool, timestamp: u64) {
        if let Some(appeal) = self.appeals.get_mut(validator) {
            appeal.status = if approved {
                AppealState::Approved
            } else {
                AppealState::Denied
            };
            appeal.reviewed_at = Some(timestamp);
        }
    }

    /// Confirm a validator as a Sybil via governance.
    pub fn confirm_sybil(&mut self, validator: Address) {
        self.confirmed_sybils.insert(validator);
    }

    /// Remove a validator from confirmed Sybils (governance rehabilitation).
    pub fn clear_confirmed_sybil(&mut self, validator: &Address) {
        self.confirmed_sybils.remove(validator);
    }

    /// Clear all signals for a validator (after appeal approved).
    pub fn clear_signals(&mut self, validator: &Address) {
        self.signals.remove(validator);
        self.first_signal_at.remove(validator);
    }

    /// Get the configuration.
    pub fn config(&self) -> &SybilConfig {
        &self.config
    }

    /// Get all validators with active signals.
    pub fn flagged_validators(&self) -> impl Iterator<Item = &Address> {
        self.signals.keys()
    }

    /// Get all confirmed Sybils.
    pub fn confirmed_sybils(&self) -> impl Iterator<Item = &Address> {
        self.confirmed_sybils.iter()
    }

    /// Check if a validator has any active signals.
    pub fn has_signals(&self, validator: &Address) -> bool {
        self.signals.get(validator).map(|s| !s.is_empty()).unwrap_or(false)
    }

    /// Get the number of active signals for a validator.
    pub fn signal_count(&self, validator: &Address) -> usize {
        self.signals.get(validator).map(|s| s.len()).unwrap_or(0)
    }
}
