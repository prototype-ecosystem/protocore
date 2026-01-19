//! Timeout handling for MinBFT consensus.
//!
//! This module provides:
//! - [`TimeoutConfig`] - Configuration for consensus timeouts
//! - [`TimeoutScheduler`] - Manages timeout scheduling and cancellation
//!
//! Timeouts use exponential backoff to handle network delays and
//! Byzantine behavior without sacrificing liveness.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tracing::{debug, trace};

use crate::types::Step;

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

/// Configuration for consensus timeouts with exponential backoff
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Base duration for propose phase
    pub propose_base: Duration,
    /// Additional duration per round for propose (backoff)
    pub propose_delta: Duration,

    /// Base duration for prevote phase
    pub prevote_base: Duration,
    /// Additional duration per round for prevote (backoff)
    pub prevote_delta: Duration,

    /// Base duration for precommit phase
    pub precommit_base: Duration,
    /// Additional duration per round for precommit (backoff)
    pub precommit_delta: Duration,

    /// Maximum timeout duration (cap on exponential backoff)
    pub max_timeout: Duration,
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
            Step::Propose => self.propose(round),
            Step::Prevote => self.prevote(round),
            Step::Precommit => self.precommit(round),
            Step::Commit => Duration::ZERO, // No timeout for commit
        }
    }

    fn calculate_timeout(&self, base: Duration, delta: Duration, round: u64) -> Duration {
        // Use saturating multiplication to avoid overflow
        let round_delta = delta.saturating_mul(round as u32);
        let total = base.saturating_add(round_delta);
        total.min(self.max_timeout)
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
