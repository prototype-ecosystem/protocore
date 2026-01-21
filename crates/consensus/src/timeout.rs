//! Timeout handling for MinBFT consensus with partial synchrony support.
//!
//! This module provides:
//! - [`TimeoutConfig`] - Configuration for consensus timeouts
//! - [`TimeoutScheduler`] - Manages timeout scheduling and cancellation
//! - [`BackoffMode`] - Linear or exponential backoff strategies
//! - [`TimeoutMetrics`] - Metrics for timeout monitoring
//!
//! Timeouts use configurable backoff to handle network delays and
//! Byzantine behavior without sacrificing liveness. For partial synchrony,
//! exponential backoff ensures eventual progress once GST (Global Stabilization
//! Time) is reached.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::Rng;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace, warn};

use crate::types::Step;

/// Backoff strategy for timeout increases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BackoffMode {
    /// Linear backoff: timeout = base + delta * round
    /// Predictable growth, suitable for stable networks
    #[default]
    Linear,
    /// Exponential backoff: timeout = base * 2^min(round, max_exponent)
    /// Fast growth, better for partial synchrony with unknown GST
    Exponential {
        /// Maximum exponent to prevent overflow (typically 5-8)
        max_exponent: u32,
    },
}

impl BackoffMode {
    /// Create exponential backoff with default max exponent of 6 (64x multiplier)
    pub fn exponential() -> Self {
        BackoffMode::Exponential { max_exponent: 6 }
    }

    /// Create exponential backoff with custom max exponent
    pub fn exponential_with_cap(max_exponent: u32) -> Self {
        BackoffMode::Exponential { max_exponent }
    }
}

/// Metrics for timeout monitoring and adaptive adjustment
#[derive(Debug, Clone, Default)]
pub struct TimeoutMetrics {
    /// Total propose timeouts that fired
    pub propose_timeouts: u64,
    /// Total prevote timeouts that fired
    pub prevote_timeouts: u64,
    /// Total precommit timeouts that fired
    pub precommit_timeouts: u64,
    /// Highest round reached (indicator of timeout adequacy)
    pub max_round_reached: u64,
    /// Average rounds per height (lower is better)
    pub avg_rounds_per_height: f64,
    /// Total heights committed
    pub heights_committed: u64,
    /// Estimated network latency in milliseconds (from message round-trips)
    pub estimated_latency_ms: u64,
}

impl TimeoutMetrics {
    /// Record a timeout event
    pub fn record_timeout(&mut self, step: Step, round: u64) {
        match step {
            Step::Propose => self.propose_timeouts += 1,
            Step::Prevote => self.prevote_timeouts += 1,
            Step::Precommit => self.precommit_timeouts += 1,
            _ => {}
        }
        if round > self.max_round_reached {
            self.max_round_reached = round;
        }
    }

    /// Record a successful commit
    pub fn record_commit(&mut self, rounds_taken: u64) {
        self.heights_committed += 1;
        // Update rolling average
        let total_rounds =
            self.avg_rounds_per_height * (self.heights_committed - 1) as f64 + rounds_taken as f64;
        self.avg_rounds_per_height = total_rounds / self.heights_committed as f64;
    }

    /// Update estimated network latency
    pub fn update_latency(&mut self, latency_ms: u64) {
        // Exponential moving average with alpha = 0.2
        if self.estimated_latency_ms == 0 {
            self.estimated_latency_ms = latency_ms;
        } else {
            self.estimated_latency_ms = (self.estimated_latency_ms * 4 + latency_ms) / 5;
        }
    }

    /// Check if timeouts seem too aggressive (causing many round changes)
    pub fn are_timeouts_too_aggressive(&self) -> bool {
        self.heights_committed >= 10 && self.avg_rounds_per_height > 2.0
    }

    /// Get recommended timeout multiplier based on metrics
    pub fn recommended_multiplier(&self) -> f64 {
        if self.heights_committed < 10 {
            return 1.0; // Not enough data
        }
        if self.avg_rounds_per_height <= 1.2 {
            1.0 // Timeouts are adequate
        } else if self.avg_rounds_per_height <= 2.0 {
            1.5 // Slightly increase
        } else {
            2.0 // Significantly increase
        }
    }
}

/// Timeout event sent to the consensus engine
#[derive(Debug, Clone)]
pub struct TimeoutInfo {
    /// The step that timed out
    pub step: Step,
    /// Block height when timeout was scheduled
    pub height: u64,
    /// Round when timeout was scheduled
    pub round: u64,
}

/// Configuration for consensus timeouts with configurable backoff
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Base duration for propose phase
    pub propose_base: Duration,
    /// Additional duration per round for propose (linear backoff)
    pub propose_delta: Duration,

    /// Base duration for prevote phase
    pub prevote_base: Duration,
    /// Additional duration per round for prevote (linear backoff)
    pub prevote_delta: Duration,

    /// Base duration for precommit phase
    pub precommit_base: Duration,
    /// Additional duration per round for precommit (linear backoff)
    pub precommit_delta: Duration,

    /// Maximum timeout duration (cap on backoff)
    pub max_timeout: Duration,

    /// Backoff mode (linear or exponential)
    pub backoff_mode: BackoffMode,

    /// Adaptive timeout multiplier (1.0 = no adjustment)
    /// Can be adjusted based on network conditions
    pub adaptive_multiplier: f64,

    /// Random jitter percentage (0.0 to 1.0)
    /// Adds randomness to prevent timing attacks and reduce synchronization.
    /// A value of 0.15 means timeouts can vary by up to 15%.
    pub jitter_percent: f64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            propose_base: Duration::from_millis(1000),
            propose_delta: Duration::from_millis(500),
            prevote_base: Duration::from_millis(1000),
            prevote_delta: Duration::from_millis(500),
            precommit_base: Duration::from_millis(1000),
            precommit_delta: Duration::from_millis(500),
            max_timeout: Duration::from_secs(60),
            backoff_mode: BackoffMode::Linear,
            adaptive_multiplier: 1.0,
            jitter_percent: 0.15, // 15% jitter for DoS protection
        }
    }
}

impl TimeoutConfig {
    /// Create a new timeout configuration with custom values
    pub fn new(
        propose_base: Duration,
        propose_delta: Duration,
        prevote_base: Duration,
        prevote_delta: Duration,
        precommit_base: Duration,
        precommit_delta: Duration,
    ) -> Self {
        Self {
            propose_base,
            propose_delta,
            prevote_base,
            prevote_delta,
            precommit_base,
            precommit_delta,
            max_timeout: Duration::from_secs(60),
            backoff_mode: BackoffMode::Linear,
            adaptive_multiplier: 1.0,
            jitter_percent: 0.15, // 15% jitter for DoS protection
        }
    }

    /// Create a configuration with exponential backoff for partial synchrony
    ///
    /// Exponential backoff is better when network conditions are unpredictable
    /// and GST (Global Stabilization Time) is unknown.
    pub fn partial_synchrony() -> Self {
        Self {
            propose_base: Duration::from_millis(1000),
            propose_delta: Duration::from_millis(500), // Used as minimum growth
            prevote_base: Duration::from_millis(1000),
            prevote_delta: Duration::from_millis(500),
            precommit_base: Duration::from_millis(1000),
            precommit_delta: Duration::from_millis(500),
            max_timeout: Duration::from_secs(60),
            backoff_mode: BackoffMode::exponential(),
            adaptive_multiplier: 1.0,
            jitter_percent: 0.15, // 15% jitter for DoS protection
        }
    }

    /// Create a fast configuration for testing
    pub fn fast() -> Self {
        Self {
            propose_base: Duration::from_millis(100),
            propose_delta: Duration::from_millis(50),
            prevote_base: Duration::from_millis(100),
            prevote_delta: Duration::from_millis(50),
            precommit_base: Duration::from_millis(100),
            precommit_delta: Duration::from_millis(50),
            max_timeout: Duration::from_secs(5),
            backoff_mode: BackoffMode::Linear,
            adaptive_multiplier: 1.0,
            jitter_percent: 0.10, // 10% jitter for testing
        }
    }

    /// Set the backoff mode
    pub fn with_backoff_mode(mut self, mode: BackoffMode) -> Self {
        self.backoff_mode = mode;
        self
    }

    /// Set the adaptive multiplier
    pub fn with_adaptive_multiplier(mut self, multiplier: f64) -> Self {
        self.adaptive_multiplier = multiplier.max(0.5).min(5.0); // Clamp to reasonable range
        self
    }

    /// Set the jitter percentage for DoS protection
    ///
    /// # Arguments
    /// * `percent` - Jitter as a fraction (e.g., 0.15 for 15%)
    ///
    /// Jitter adds unpredictability to timeout timing, making it harder
    /// for attackers to time network partitions or eclipse attacks.
    pub fn with_jitter(mut self, percent: f64) -> Self {
        self.jitter_percent = percent.max(0.0).min(0.5); // Clamp to 0-50%
        self
    }

    /// Adjust timeouts based on metrics
    pub fn adjust_from_metrics(&mut self, metrics: &TimeoutMetrics) {
        let recommended = metrics.recommended_multiplier();
        if (self.adaptive_multiplier - recommended).abs() > 0.1 {
            warn!(
                current = self.adaptive_multiplier,
                recommended = recommended,
                avg_rounds = metrics.avg_rounds_per_height,
                "Adjusting timeout multiplier based on metrics"
            );
            self.adaptive_multiplier = recommended;
        }
    }

    /// Calculate timeout duration for propose phase at given round
    ///
    /// timeout = propose_base + propose_delta * round
    pub fn propose(&self, round: u64) -> Duration {
        self.calculate_timeout(self.propose_base, self.propose_delta, round)
    }

    /// Calculate timeout duration for prevote phase at given round
    ///
    /// timeout = prevote_base + prevote_delta * round
    pub fn prevote(&self, round: u64) -> Duration {
        self.calculate_timeout(self.prevote_base, self.prevote_delta, round)
    }

    /// Calculate timeout duration for precommit phase at given round
    ///
    /// timeout = precommit_base + precommit_delta * round
    pub fn precommit(&self, round: u64) -> Duration {
        self.calculate_timeout(self.precommit_base, self.precommit_delta, round)
    }

    /// Calculate timeout for a specific step
    pub fn timeout_for(&self, step: Step, round: u64) -> Duration {
        match step {
            Step::NewHeight => Duration::ZERO, // No timeout for NewHeight
            Step::Propose => self.propose(round),
            Step::Prevote => self.prevote(round),
            Step::Precommit => self.precommit(round),
            Step::Commit => Duration::ZERO, // No timeout for commit
        }
    }

    fn calculate_timeout(&self, base: Duration, delta: Duration, round: u64) -> Duration {
        let raw_timeout = match self.backoff_mode {
            BackoffMode::Linear => {
                // Linear: timeout = base + delta * round
                let round_delta = delta.saturating_mul(round as u32);
                base.saturating_add(round_delta)
            }
            BackoffMode::Exponential { max_exponent } => {
                // Exponential: timeout = base * 2^min(round, max_exponent)
                let capped_round = round.min(max_exponent as u64);
                let multiplier = 1u32 << capped_round.min(31); // Cap at 2^31 to avoid overflow
                base.saturating_mul(multiplier)
            }
        };

        // Apply adaptive multiplier
        let adjusted = if (self.adaptive_multiplier - 1.0).abs() < 0.001 {
            raw_timeout
        } else {
            Duration::from_secs_f64(raw_timeout.as_secs_f64() * self.adaptive_multiplier)
        };

        // Apply random jitter for DoS protection
        // Jitter adds unpredictability to prevent attackers from timing attacks
        let with_jitter = if self.jitter_percent > 0.0 {
            let mut rng = rand::thread_rng();
            // Generate jitter in range [1.0, 1.0 + jitter_percent]
            let jitter_multiplier = 1.0 + rng.gen::<f64>() * self.jitter_percent;
            Duration::from_secs_f64(adjusted.as_secs_f64() * jitter_multiplier)
        } else {
            adjusted
        };

        // Cap at max_timeout
        with_jitter.min(self.max_timeout)
    }
}

/// Handle to a scheduled timeout that can be cancelled
#[derive(Debug)]
struct PendingTimeout {
    /// Step this timeout is for
    step: Step,
    /// Height when scheduled
    height: u64,
    /// Round when scheduled
    round: u64,
    /// When the timeout will fire
    deadline: Instant,
    /// Whether this timeout has been cancelled
    cancelled: bool,
}

/// Manages timeout scheduling and cancellation for consensus
pub struct TimeoutScheduler {
    /// Timeout configuration
    config: TimeoutConfig,
    /// Channel to send timeout events
    timeout_tx: mpsc::Sender<TimeoutInfo>,
    /// Current height (for cancellation)
    current_height: AtomicU64,
    /// Current round (for cancellation)
    current_round: AtomicU64,
    /// Pending timeouts (for tracking)
    pending: Arc<Mutex<Vec<PendingTimeout>>>,
}

impl TimeoutScheduler {
    /// Create a new timeout scheduler
    pub fn new(config: TimeoutConfig, timeout_tx: mpsc::Sender<TimeoutInfo>) -> Self {
        Self {
            config,
            timeout_tx,
            current_height: AtomicU64::new(0),
            current_round: AtomicU64::new(0),
            pending: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Update the current height and round (cancels outdated timeouts)
    pub fn set_height_round(&self, height: u64, round: u64) {
        self.current_height.store(height, Ordering::SeqCst);
        self.current_round.store(round, Ordering::SeqCst);

        // Cancel any pending timeouts for old height/round
        let mut pending = self.pending.lock();
        for timeout in pending.iter_mut() {
            if timeout.height < height || (timeout.height == height && timeout.round < round) {
                timeout.cancelled = true;
            }
        }
        pending.retain(|t| !t.cancelled);
    }

    /// Schedule a timeout for the given step at current height/round
    pub fn schedule(&self, step: Step, height: u64, round: u64) {
        let duration = self.config.timeout_for(step, round);
        if duration.is_zero() {
            return;
        }

        let deadline = Instant::now() + duration;

        debug!(
            step = %step,
            height = height,
            round = round,
            duration_ms = duration.as_millis(),
            "Scheduling timeout"
        );

        // Track the pending timeout
        {
            let mut pending = self.pending.lock();
            pending.push(PendingTimeout {
                step,
                height,
                round,
                deadline,
                cancelled: false,
            });
        }

        // Spawn timeout task
        let timeout_tx = self.timeout_tx.clone();
        let current_height = Arc::new(AtomicU64::new(height));
        let current_round = Arc::new(AtomicU64::new(round));
        let height_ref = self.current_height.load(Ordering::SeqCst);
        let round_ref = self.current_round.load(Ordering::SeqCst);

        // Clone for the async task
        let pending = self.pending.clone();

        tokio::spawn(async move {
            tokio::time::sleep(duration).await;

            // Check if timeout is still relevant
            let current_h = current_height.load(Ordering::SeqCst);
            let current_r = current_round.load(Ordering::SeqCst);

            // The timeout is only relevant if we're still at the same height/round
            // We compare against the values that were current when we scheduled
            if height_ref == current_h && round_ref == current_r {
                // Additional check: verify not cancelled
                let is_cancelled = {
                    let pending_lock = pending.lock();
                    pending_lock
                        .iter()
                        .find(|t| t.step == step && t.height == height && t.round == round)
                        .map(|t| t.cancelled)
                        .unwrap_or(true)
                };

                if !is_cancelled {
                    trace!(
                        step = %step,
                        height = height,
                        round = round,
                        "Timeout fired"
                    );

                    let _ = timeout_tx
                        .send(TimeoutInfo {
                            step,
                            height,
                            round,
                        })
                        .await;
                }
            }

            // Clean up
            let mut pending_lock = pending.lock();
            pending_lock.retain(|t| !(t.step == step && t.height == height && t.round == round));
        });
    }

    /// Cancel all pending timeouts for a specific step at the given height/round
    pub fn cancel(&self, step: Step, height: u64, round: u64) {
        let mut pending = self.pending.lock();
        for timeout in pending.iter_mut() {
            if timeout.step == step && timeout.height == height && timeout.round == round {
                timeout.cancelled = true;
                debug!(
                    step = %step,
                    height = height,
                    round = round,
                    "Cancelled timeout"
                );
            }
        }
        pending.retain(|t| !t.cancelled);
    }

    /// Cancel all pending timeouts
    pub fn cancel_all(&self) {
        let mut pending = self.pending.lock();
        pending.clear();
    }

    /// Get the timeout configuration
    pub fn config(&self) -> &TimeoutConfig {
        &self.config
    }

    /// Get the number of pending timeouts
    pub fn pending_count(&self) -> usize {
        self.pending.lock().len()
    }
}

/// A simpler synchronous timeout tracker (for testing or non-async contexts)
#[derive(Debug)]
pub struct SyncTimeoutTracker {
    /// Timeout configuration
    config: TimeoutConfig,
    /// Start time for current step
    step_start: Option<Instant>,
    /// Current step being tracked
    current_step: Option<Step>,
    /// Current round (for timeout calculation)
    current_round: u64,
}

impl SyncTimeoutTracker {
    /// Create a new sync timeout tracker
    pub fn new(config: TimeoutConfig) -> Self {
        Self {
            config,
            step_start: None,
            current_step: None,
            current_round: 0,
        }
    }

    /// Start tracking a new step
    pub fn start_step(&mut self, step: Step, round: u64) {
        self.step_start = Some(Instant::now());
        self.current_step = Some(step);
        self.current_round = round;
    }

    /// Check if the current step has timed out
    pub fn is_timed_out(&self) -> bool {
        match (self.step_start, self.current_step) {
            (Some(start), Some(step)) => {
                let timeout = self.config.timeout_for(step, self.current_round);
                start.elapsed() >= timeout
            }
            _ => false,
        }
    }

    /// Get the remaining time before timeout
    pub fn remaining(&self) -> Option<Duration> {
        match (self.step_start, self.current_step) {
            (Some(start), Some(step)) => {
                let timeout = self.config.timeout_for(step, self.current_round);
                let elapsed = start.elapsed();
                if elapsed >= timeout {
                    Some(Duration::ZERO)
                } else {
                    Some(timeout - elapsed)
                }
            }
            _ => None,
        }
    }

    /// Clear the current tracking
    pub fn clear(&mut self) {
        self.step_start = None;
        self.current_step = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linear_backoff() {
        // Disable jitter for deterministic test results
        let config = TimeoutConfig::default().with_jitter(0.0);

        // Round 0: base = 1000ms
        assert_eq!(config.propose(0), Duration::from_millis(1000));

        // Round 1: base + delta = 1500ms
        assert_eq!(config.propose(1), Duration::from_millis(1500));

        // Round 2: base + 2*delta = 2000ms
        assert_eq!(config.propose(2), Duration::from_millis(2000));

        // Round 10: base + 10*delta = 6000ms
        assert_eq!(config.propose(10), Duration::from_millis(6000));
    }

    #[test]
    fn test_exponential_backoff() {
        // Disable jitter for deterministic test results
        let config = TimeoutConfig::partial_synchrony().with_jitter(0.0);

        // Round 0: base * 2^0 = 1000ms
        assert_eq!(config.propose(0), Duration::from_millis(1000));

        // Round 1: base * 2^1 = 2000ms
        assert_eq!(config.propose(1), Duration::from_millis(2000));

        // Round 2: base * 2^2 = 4000ms
        assert_eq!(config.propose(2), Duration::from_millis(4000));

        // Round 3: base * 2^3 = 8000ms
        assert_eq!(config.propose(3), Duration::from_millis(8000));

        // Round 5: base * 2^5 = 32000ms (still under 60s max)
        assert_eq!(config.propose(5), Duration::from_millis(32000));

        // Round 6: base * 2^6 = 64000ms, but capped at max_timeout (60s)
        assert_eq!(config.propose(6), config.max_timeout);

        // Round 10: also capped at max_timeout
        assert_eq!(config.propose(10), config.max_timeout);
    }

    #[test]
    fn test_adaptive_multiplier() {
        // Disable jitter for deterministic test results
        let config = TimeoutConfig::default()
            .with_jitter(0.0)
            .with_adaptive_multiplier(2.0);

        // Round 0 with 2x multiplier: 2000ms
        assert_eq!(config.propose(0), Duration::from_millis(2000));

        // Round 1 with 2x multiplier: 3000ms
        assert_eq!(config.propose(1), Duration::from_millis(3000));
    }

    #[test]
    fn test_adaptive_multiplier_clamping() {
        // Multiplier too low is clamped to 0.5
        let config = TimeoutConfig::default().with_adaptive_multiplier(0.1);
        assert_eq!(config.adaptive_multiplier, 0.5);

        // Multiplier too high is clamped to 5.0
        let config = TimeoutConfig::default().with_adaptive_multiplier(10.0);
        assert_eq!(config.adaptive_multiplier, 5.0);
    }

    #[test]
    fn test_max_timeout_cap() {
        let config = TimeoutConfig {
            propose_base: Duration::from_secs(10),
            propose_delta: Duration::from_secs(10),
            prevote_base: Duration::from_secs(10),
            prevote_delta: Duration::from_secs(10),
            precommit_base: Duration::from_secs(10),
            precommit_delta: Duration::from_secs(10),
            max_timeout: Duration::from_secs(30),
            backoff_mode: BackoffMode::Linear,
            adaptive_multiplier: 1.0,
            jitter_percent: 0.0, // No jitter for this test
        };

        // Round 5 would be 60s but capped at 30s
        assert_eq!(config.propose(5), Duration::from_secs(30));
    }

    #[test]
    fn test_timeout_metrics() {
        let mut metrics = TimeoutMetrics::default();

        // Record some timeouts
        metrics.record_timeout(Step::Propose, 0);
        metrics.record_timeout(Step::Prevote, 1);
        metrics.record_timeout(Step::Precommit, 2);

        assert_eq!(metrics.propose_timeouts, 1);
        assert_eq!(metrics.prevote_timeouts, 1);
        assert_eq!(metrics.precommit_timeouts, 1);
        assert_eq!(metrics.max_round_reached, 2);

        // Record commits
        metrics.record_commit(1);
        metrics.record_commit(2);
        metrics.record_commit(3);

        assert_eq!(metrics.heights_committed, 3);
        assert!((metrics.avg_rounds_per_height - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_metrics_recommended_multiplier() {
        let mut metrics = TimeoutMetrics::default();

        // Not enough data
        assert_eq!(metrics.recommended_multiplier(), 1.0);

        // Simulate 10 commits with 1 round each
        for _ in 0..10 {
            metrics.record_commit(1);
        }
        assert_eq!(metrics.recommended_multiplier(), 1.0);

        // Reset and simulate high round counts
        let mut metrics2 = TimeoutMetrics::default();
        for _ in 0..10 {
            metrics2.record_commit(3);
        }
        assert_eq!(metrics2.recommended_multiplier(), 2.0);
    }

    #[test]
    fn test_backoff_mode_constructors() {
        let exp = BackoffMode::exponential();
        assert!(matches!(exp, BackoffMode::Exponential { max_exponent: 6 }));

        let exp_custom = BackoffMode::exponential_with_cap(4);
        assert!(matches!(
            exp_custom,
            BackoffMode::Exponential { max_exponent: 4 }
        ));
    }
}
