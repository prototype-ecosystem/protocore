//! # Participation Tracker for Inverse Rewards System
//!
//! This module implements the participation tracking component of Proto Core's
//! inverse rewards system. It tracks validator activity across epochs and calculates
//! participation scores used in reward distribution.
//!
//! ## Participation Formula
//!
//! ```text
//! ParticipationScore = (
//!     0.4 × (BlocksProposed / BlocksExpected) +
//!     0.4 × (VotesCast / VotesExpected) +
//!     0.2 × (UptimeSamples / TotalSamples)
//! )
//! ```
//!
//! ## Components
//!
//! - **Block Production (40%)**: Measures how many blocks a validator proposed
//!   out of expected opportunities
//! - **Vote Participation (40%)**: Measures vote participation in consensus rounds
//! - **Uptime (20%)**: Measures online availability through periodic sampling
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_consensus::participation::ParticipationTracker;
//! use protocore_types::Address;
//!
//! let mut tracker = ParticipationTracker::new(10); // Keep 10 epochs of history
//!
//! let validator: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".parse().unwrap();
//!
//! // Record expected and actual block production
//! tracker.record_block_expected(validator);
//! tracker.record_block_proposed(validator);
//!
//! // Record expected and actual votes
//! for _ in 0..10 {
//!     tracker.record_vote_expected(validator);
//!     tracker.record_vote(validator);
//! }
//!
//! // Record uptime samples
//! for _ in 0..5 {
//!     tracker.record_uptime_sample(validator, true);
//! }
//!
//! // Calculate participation score (0.0 - 1.0)
//! let score = tracker.calculate_score(&validator);
//! assert!(score > 0.9);
//!
//! // Transition to new epoch
//! tracker.transition_epoch(2);
//! ```

use protocore_types::Address;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Weight for block production in participation score (40%)
pub const BLOCK_WEIGHT: f64 = 0.4;

/// Weight for vote participation in participation score (40%)
pub const VOTE_WEIGHT: f64 = 0.4;

/// Weight for uptime in participation score (20%)
pub const UPTIME_WEIGHT: f64 = 0.2;

/// Tracks validator participation across epochs for the inverse rewards system.
///
/// The tracker maintains per-validator metrics for the current epoch and historical
/// participation scores for previous epochs. This data is used to calculate the
/// participation component of validator rewards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationTracker {
    /// Current epoch number
    epoch: u64,
    /// Per-validator metrics for the current epoch
    metrics: HashMap<Address, ValidatorParticipation>,
    /// Historical participation scores (last N epochs per validator)
    history: HashMap<Address, Vec<EpochParticipation>>,
    /// Maximum number of epochs to keep in history
    max_history_epochs: usize,
}

/// Participation metrics for a single validator in the current epoch.
///
/// Tracks block production, vote participation, and uptime samples
/// to calculate the validator's participation score.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ValidatorParticipation {
    /// Number of blocks actually proposed by this validator
    pub blocks_proposed: u64,
    /// Number of blocks the validator was expected to propose
    pub blocks_expected: u64,
    /// Number of consensus votes actually cast
    pub votes_cast: u64,
    /// Number of votes the validator was expected to cast
    pub votes_expected: u64,
    /// Number of uptime samples where validator was online
    pub uptime_samples: u64,
    /// Total number of uptime samples taken
    pub total_samples: u64,
}

/// Historical participation record for a single epoch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EpochParticipation {
    /// The epoch number
    pub epoch: u64,
    /// The calculated participation score (0.0 - 1.0)
    pub score: f64,
}

/// Snapshot of the participation tracker state for persistence.
///
/// This structure contains all data necessary to restore the tracker
/// to its current state after a restart.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipationSnapshot {
    /// Current epoch number
    pub epoch: u64,
    /// Current epoch metrics for all validators
    pub metrics: HashMap<Address, ValidatorParticipation>,
    /// Historical scores for all validators
    pub history: HashMap<Address, Vec<EpochParticipation>>,
    /// Maximum history epochs setting
    pub max_history_epochs: usize,
}

impl ValidatorParticipation {
    /// Creates a new empty participation record.
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculates the block production ratio (0.0 - 1.0).
    ///
    /// Returns 1.0 if no blocks were expected (perfect by default).
    pub fn block_ratio(&self) -> f64 {
        if self.blocks_expected == 0 {
            1.0
        } else {
            (self.blocks_proposed as f64) / (self.blocks_expected as f64)
        }
    }

    /// Calculates the vote participation ratio (0.0 - 1.0).
    ///
    /// Returns 1.0 if no votes were expected (perfect by default).
    pub fn vote_ratio(&self) -> f64 {
        if self.votes_expected == 0 {
            1.0
        } else {
            (self.votes_cast as f64) / (self.votes_expected as f64)
        }
    }

    /// Calculates the uptime ratio (0.0 - 1.0).
    ///
    /// Returns 1.0 if no samples were taken (perfect by default).
    pub fn uptime_ratio(&self) -> f64 {
        if self.total_samples == 0 {
            1.0
        } else {
            (self.uptime_samples as f64) / (self.total_samples as f64)
        }
    }

    /// Calculates the overall participation score using the weighted formula.
    ///
    /// Formula:
    /// ```text
    /// Score = 0.4 × BlockRatio + 0.4 × VoteRatio + 0.2 × UptimeRatio
    /// ```
    ///
    /// Returns a value between 0.0 and 1.0.
    pub fn calculate_score(&self) -> f64 {
        let block_component = BLOCK_WEIGHT * self.block_ratio();
        let vote_component = VOTE_WEIGHT * self.vote_ratio();
        let uptime_component = UPTIME_WEIGHT * self.uptime_ratio();

        // Clamp to [0.0, 1.0] to handle any floating point edge cases
        (block_component + vote_component + uptime_component).clamp(0.0, 1.0)
    }

    /// Resets all counters to zero.
    pub fn reset(&mut self) {
        self.blocks_proposed = 0;
        self.blocks_expected = 0;
        self.votes_cast = 0;
        self.votes_expected = 0;
        self.uptime_samples = 0;
        self.total_samples = 0;
    }

    /// Checks if any activity has been recorded.
    pub fn has_activity(&self) -> bool {
        self.blocks_expected > 0 || self.votes_expected > 0 || self.total_samples > 0
    }
}

impl ParticipationTracker {
    /// Creates a new participation tracker.
    ///
    /// # Arguments
    ///
    /// * `max_history_epochs` - Maximum number of historical epochs to retain per validator
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let tracker = ParticipationTracker::new(10);
    /// ```
    pub fn new(max_history_epochs: usize) -> Self {
        Self {
            epoch: 0,
            metrics: HashMap::new(),
            history: HashMap::new(),
            max_history_epochs,
        }
    }

    /// Returns the current epoch number.
    pub fn current_epoch(&self) -> u64 {
        self.epoch
    }

    /// Returns the maximum history epochs setting.
    pub fn max_history_epochs(&self) -> usize {
        self.max_history_epochs
    }

    /// Returns the number of validators being tracked in the current epoch.
    pub fn validator_count(&self) -> usize {
        self.metrics.len()
    }

    /// Gets the participation metrics for a validator in the current epoch.
    ///
    /// Returns `None` if the validator has no recorded activity.
    pub fn get_metrics(&self, validator: &Address) -> Option<&ValidatorParticipation> {
        self.metrics.get(validator)
    }

    /// Gets mutable access to the participation metrics for a validator.
    ///
    /// Creates a new entry if the validator is not yet tracked.
    fn get_or_create_metrics(&mut self, validator: Address) -> &mut ValidatorParticipation {
        self.metrics.entry(validator).or_default()
    }

    /// Records that a validator proposed a block.
    ///
    /// This should be called when a block is successfully committed
    /// and attributed to the proposing validator.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator that proposed the block
    pub fn record_block_proposed(&mut self, validator: Address) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.blocks_proposed = metrics.blocks_proposed.saturating_add(1);
        tracing::trace!(
            validator = %validator,
            blocks_proposed = metrics.blocks_proposed,
            "Recorded block proposed"
        );
    }

    /// Records that a validator was expected to propose a block.
    ///
    /// This should be called when a validator is selected as the proposer
    /// for a consensus round, regardless of whether they actually propose.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator expected to propose
    pub fn record_block_expected(&mut self, validator: Address) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.blocks_expected = metrics.blocks_expected.saturating_add(1);
        tracing::trace!(
            validator = %validator,
            blocks_expected = metrics.blocks_expected,
            "Recorded block expected"
        );
    }

    /// Records that a validator cast a consensus vote.
    ///
    /// This should be called when a validator's vote is received
    /// and validated during consensus.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator that voted
    pub fn record_vote(&mut self, validator: Address) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.votes_cast = metrics.votes_cast.saturating_add(1);
        tracing::trace!(
            validator = %validator,
            votes_cast = metrics.votes_cast,
            "Recorded vote cast"
        );
    }

    /// Records that a validator was expected to vote.
    ///
    /// This should be called for each consensus round where the validator
    /// is part of the active validator set and should participate.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator expected to vote
    pub fn record_vote_expected(&mut self, validator: Address) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.votes_expected = metrics.votes_expected.saturating_add(1);
        tracing::trace!(
            validator = %validator,
            votes_expected = metrics.votes_expected,
            "Recorded vote expected"
        );
    }

    /// Records an uptime sample for a validator.
    ///
    /// This should be called periodically (e.g., every few blocks) to sample
    /// whether the validator is online and reachable.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator being sampled
    /// * `was_online` - Whether the validator was online during this sample
    pub fn record_uptime_sample(&mut self, validator: Address, was_online: bool) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.total_samples = metrics.total_samples.saturating_add(1);
        if was_online {
            metrics.uptime_samples = metrics.uptime_samples.saturating_add(1);
        }
        tracing::trace!(
            validator = %validator,
            was_online = was_online,
            uptime_ratio = metrics.uptime_ratio(),
            "Recorded uptime sample"
        );
    }

    /// Records multiple uptime samples for a validator at once.
    ///
    /// This is useful for batch processing or catching up after downtime.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator
    /// * `online_samples` - Number of samples where validator was online
    /// * `total_samples` - Total number of samples in this batch
    pub fn record_uptime_batch(
        &mut self,
        validator: Address,
        online_samples: u64,
        total_samples: u64,
    ) {
        let metrics = self.get_or_create_metrics(validator);
        metrics.uptime_samples = metrics.uptime_samples.saturating_add(online_samples);
        metrics.total_samples = metrics.total_samples.saturating_add(total_samples);
        tracing::trace!(
            validator = %validator,
            online_samples = online_samples,
            total_samples = total_samples,
            uptime_ratio = metrics.uptime_ratio(),
            "Recorded uptime batch"
        );
    }

    /// Calculates the participation score for a validator (0.0 - 1.0).
    ///
    /// Uses the formula:
    /// ```text
    /// ParticipationScore = (
    ///     0.4 × (BlocksProposed / BlocksExpected) +
    ///     0.4 × (VotesCast / VotesExpected) +
    ///     0.2 × (UptimeSamples / TotalSamples)
    /// )
    /// ```
    ///
    /// Returns 0.0 if the validator has no recorded activity.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator to calculate score for
    ///
    /// # Returns
    ///
    /// A participation score between 0.0 (no participation) and 1.0 (perfect participation)
    pub fn calculate_score(&self, validator: &Address) -> f64 {
        match self.metrics.get(validator) {
            Some(metrics) if metrics.has_activity() => metrics.calculate_score(),
            _ => 0.0,
        }
    }

    /// Transitions to a new epoch, archiving current metrics.
    ///
    /// This method:
    /// 1. Calculates final scores for all validators in the current epoch
    /// 2. Archives these scores to the history
    /// 3. Resets current epoch metrics
    /// 4. Updates the epoch number
    ///
    /// Old history entries are pruned according to `max_history_epochs`.
    ///
    /// # Arguments
    ///
    /// * `new_epoch` - The new epoch number to transition to
    ///
    /// # Panics
    ///
    /// Does not panic, but logs a warning if `new_epoch` is not greater than
    /// the current epoch.
    pub fn transition_epoch(&mut self, new_epoch: u64) {
        if new_epoch <= self.epoch && self.epoch > 0 {
            tracing::warn!(
                current_epoch = self.epoch,
                new_epoch = new_epoch,
                "Attempted to transition to same or earlier epoch"
            );
            return;
        }

        tracing::info!(
            old_epoch = self.epoch,
            new_epoch = new_epoch,
            validators_tracked = self.metrics.len(),
            "Transitioning participation tracker to new epoch"
        );

        // Archive current epoch metrics to history
        for (validator, metrics) in &self.metrics {
            if metrics.has_activity() {
                let score = metrics.calculate_score();
                let epoch_participation = EpochParticipation {
                    epoch: self.epoch,
                    score,
                };

                let history = self.history.entry(*validator).or_default();
                history.push(epoch_participation);

                // Prune old history if needed
                while history.len() > self.max_history_epochs {
                    history.remove(0);
                }

                tracing::debug!(
                    validator = %validator,
                    epoch = self.epoch,
                    score = score,
                    history_len = history.len(),
                    "Archived validator participation"
                );
            }
        }

        // Reset metrics for new epoch
        self.metrics.clear();
        self.epoch = new_epoch;
    }

    /// Gets the historical average participation score for a validator.
    ///
    /// Calculates the average of the most recent `epochs` participation scores.
    /// If the validator has fewer historical entries, uses all available data.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator
    /// * `epochs` - Maximum number of recent epochs to include in the average
    ///
    /// # Returns
    ///
    /// The average score, or 0.0 if no history exists.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // Get average over last 5 epochs
    /// let avg = tracker.historical_average(&validator, 5);
    /// ```
    pub fn historical_average(&self, validator: &Address, epochs: usize) -> f64 {
        match self.history.get(validator) {
            Some(history) if !history.is_empty() => {
                let count = epochs.min(history.len());
                let start = history.len().saturating_sub(count);
                let sum: f64 = history[start..].iter().map(|e| e.score).sum();
                sum / (count as f64)
            }
            _ => 0.0,
        }
    }

    /// Gets the historical participation records for a validator.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator
    ///
    /// # Returns
    ///
    /// A slice of historical participation records, or an empty slice if none exist.
    pub fn get_history(&self, validator: &Address) -> &[EpochParticipation] {
        self.history.get(validator).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Checks if a validator has any historical participation data.
    pub fn has_history(&self, validator: &Address) -> bool {
        self.history
            .get(validator)
            .map(|h| !h.is_empty())
            .unwrap_or(false)
    }

    /// Gets the combined score including current epoch and historical average.
    ///
    /// This provides a smoothed score that accounts for both recent performance
    /// and historical reliability.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator
    /// * `history_weight` - Weight given to historical average (0.0 - 1.0)
    /// * `history_epochs` - Number of historical epochs to include
    ///
    /// # Returns
    ///
    /// Weighted combination: `(1 - history_weight) × current + history_weight × historical_avg`
    pub fn combined_score(
        &self,
        validator: &Address,
        history_weight: f64,
        history_epochs: usize,
    ) -> f64 {
        let current = self.calculate_score(validator);
        let historical = self.historical_average(validator, history_epochs);

        let history_weight = history_weight.clamp(0.0, 1.0);
        (1.0 - history_weight) * current + history_weight * historical
    }

    /// Creates a snapshot of the current tracker state for persistence.
    ///
    /// The snapshot contains all data necessary to restore the tracker
    /// to its current state using [`restore`](Self::restore).
    pub fn snapshot(&self) -> ParticipationSnapshot {
        ParticipationSnapshot {
            epoch: self.epoch,
            metrics: self.metrics.clone(),
            history: self.history.clone(),
            max_history_epochs: self.max_history_epochs,
        }
    }

    /// Restores a participation tracker from a snapshot.
    ///
    /// # Arguments
    ///
    /// * `snapshot` - The snapshot to restore from
    ///
    /// # Returns
    ///
    /// A new `ParticipationTracker` with the state from the snapshot.
    pub fn restore(snapshot: ParticipationSnapshot) -> Self {
        Self {
            epoch: snapshot.epoch,
            metrics: snapshot.metrics,
            history: snapshot.history,
            max_history_epochs: snapshot.max_history_epochs,
        }
    }

    /// Returns an iterator over all validators being tracked in the current epoch.
    pub fn validators(&self) -> impl Iterator<Item = &Address> {
        self.metrics.keys()
    }

    /// Returns an iterator over all validators with historical data.
    pub fn validators_with_history(&self) -> impl Iterator<Item = &Address> {
        self.history.keys()
    }

    /// Removes a validator from tracking (e.g., when they exit the validator set).
    ///
    /// This removes both current epoch metrics and historical data.
    ///
    /// # Arguments
    ///
    /// * `validator` - The address of the validator to remove
    ///
    /// # Returns
    ///
    /// `true` if the validator was being tracked, `false` otherwise.
    pub fn remove_validator(&mut self, validator: &Address) -> bool {
        let had_metrics = self.metrics.remove(validator).is_some();
        let had_history = self.history.remove(validator).is_some();
        had_metrics || had_history
    }

    /// Clears all tracking data but keeps the current epoch and settings.
    pub fn clear(&mut self) {
        self.metrics.clear();
        self.history.clear();
    }

    /// Records participation expectations for a set of validators.
    ///
    /// This is useful at the start of a consensus round to record that
    /// all active validators are expected to vote.
    ///
    /// # Arguments
    ///
    /// * `validators` - Iterator of validator addresses
    pub fn record_votes_expected_batch<'a>(
        &mut self,
        validators: impl IntoIterator<Item = &'a Address>,
    ) {
        for validator in validators {
            self.record_vote_expected(*validator);
        }
    }

    /// Gets aggregate statistics across all tracked validators.
    pub fn aggregate_stats(&self) -> AggregateStats {
        let mut total_blocks_proposed = 0u64;
        let mut total_blocks_expected = 0u64;
        let mut total_votes_cast = 0u64;
        let mut total_votes_expected = 0u64;
        let mut total_uptime_samples = 0u64;
        let mut total_samples = 0u64;
        let mut score_sum = 0.0f64;
        let mut active_validators = 0usize;

        for metrics in self.metrics.values() {
            if metrics.has_activity() {
                total_blocks_proposed += metrics.blocks_proposed;
                total_blocks_expected += metrics.blocks_expected;
                total_votes_cast += metrics.votes_cast;
                total_votes_expected += metrics.votes_expected;
                total_uptime_samples += metrics.uptime_samples;
                total_samples += metrics.total_samples;
                score_sum += metrics.calculate_score();
                active_validators += 1;
            }
        }

        let average_score = if active_validators > 0 {
            score_sum / (active_validators as f64)
        } else {
            0.0
        };

        AggregateStats {
            active_validators,
            total_blocks_proposed,
            total_blocks_expected,
            total_votes_cast,
            total_votes_expected,
            total_uptime_samples,
            total_samples,
            average_score,
        }
    }
}

/// Aggregate statistics across all tracked validators.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AggregateStats {
    /// Number of validators with recorded activity
    pub active_validators: usize,
    /// Total blocks proposed across all validators
    pub total_blocks_proposed: u64,
    /// Total blocks expected across all validators
    pub total_blocks_expected: u64,
    /// Total votes cast across all validators
    pub total_votes_cast: u64,
    /// Total votes expected across all validators
    pub total_votes_expected: u64,
    /// Total uptime samples (online) across all validators
    pub total_uptime_samples: u64,
    /// Total uptime samples taken across all validators
    pub total_samples: u64,
    /// Average participation score across all active validators
    pub average_score: f64,
}

impl Default for ParticipationTracker {
    fn default() -> Self {
        Self::new(24) // Default to 24 epochs of history
    }
}

