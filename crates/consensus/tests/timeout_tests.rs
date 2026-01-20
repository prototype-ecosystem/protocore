//! Tests for timeout handling and scheduling.
//!
//! These tests verify the timeout configuration, calculation, and scheduling
//! functionality for the MinBFT consensus protocol.

use protocore_consensus::{Step, TimeoutConfig, TimeoutInfo, TimeoutScheduler};
use std::time::Duration;
use tokio::sync::mpsc;

/// Synchronous timeout tracker for testing
pub struct SyncTimeoutTracker {
    config: TimeoutConfig,
    step_start: Option<std::time::Instant>,
    current_step: Option<Step>,
    current_round: u64,
}

impl SyncTimeoutTracker {
    pub fn new(config: TimeoutConfig) -> Self {
        Self {
            config,
            step_start: None,
            current_step: None,
            current_round: 0,
        }
    }

    pub fn start_step(&mut self, step: Step, round: u64) {
        self.step_start = Some(std::time::Instant::now());
        self.current_step = Some(step);
        self.current_round = round;
    }

    pub fn is_timed_out(&self) -> bool {
        match (self.step_start, self.current_step) {
            (Some(start), Some(step)) => {
                let timeout = self.config.timeout_for(step, self.current_round);
                start.elapsed() >= timeout
            }
            _ => false,
        }
    }

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

    pub fn clear(&mut self) {
        self.step_start = None;
        self.current_step = None;
    }
}

// Helper trait for timeout_for which is not public in the crate
trait TimeoutConfigExt {
    fn timeout_for(&self, step: Step, round: u64) -> Duration;
}

impl TimeoutConfigExt for TimeoutConfig {
    fn timeout_for(&self, step: Step, round: u64) -> Duration {
        match step {
            Step::Propose => self.propose(round),
            Step::Prevote => self.prevote(round),
            Step::Precommit => self.precommit(round),
            Step::Commit | Step::NewHeight => Duration::ZERO,
        }
    }
}

#[test]
fn test_timeout_config_defaults() {
    let config = TimeoutConfig::default();
    assert_eq!(config.propose_base, Duration::from_millis(1000));
    assert_eq!(config.prevote_base, Duration::from_millis(1000));
    assert_eq!(config.precommit_base, Duration::from_millis(1000));
}

#[test]
fn test_timeout_calculation() {
    let config = TimeoutConfig::default();

    // Round 0: base only
    assert_eq!(config.propose(0), Duration::from_millis(1000));

    // Round 1: base + 1 * delta
    assert_eq!(config.propose(1), Duration::from_millis(1500));

    // Round 2: base + 2 * delta
    assert_eq!(config.propose(2), Duration::from_millis(2000));
}

#[test]
fn test_timeout_max_cap() {
    let config = TimeoutConfig {
        propose_base: Duration::from_secs(1),
        propose_delta: Duration::from_secs(10),
        max_timeout: Duration::from_secs(30),
        ..Default::default()
    };

    // Round 10 would be 1 + 10*10 = 101 seconds, but capped at 30
    assert_eq!(config.propose(10), Duration::from_secs(30));
}

#[test]
fn test_timeout_for_step() {
    let config = TimeoutConfig::default();

    assert_eq!(config.timeout_for(Step::Propose, 0), config.propose(0));
    assert_eq!(config.timeout_for(Step::Prevote, 0), config.prevote(0));
    assert_eq!(config.timeout_for(Step::Precommit, 0), config.precommit(0));
    assert_eq!(config.timeout_for(Step::Commit, 0), Duration::ZERO);
}

#[test]
fn test_sync_timeout_tracker() {
    let config = TimeoutConfig::fast();
    let mut tracker = SyncTimeoutTracker::new(config);

    // Not started yet
    assert!(!tracker.is_timed_out());
    assert!(tracker.remaining().is_none());

    // Start tracking
    tracker.start_step(Step::Propose, 0);
    assert!(!tracker.is_timed_out());
    assert!(tracker.remaining().is_some());

    // After clearing
    tracker.clear();
    assert!(!tracker.is_timed_out());
}

#[tokio::test]
async fn test_timeout_scheduler_basic() {
    let config = TimeoutConfig {
        propose_base: Duration::from_millis(50),
        propose_delta: Duration::from_millis(10),
        ..TimeoutConfig::fast()
    };

    let (tx, mut rx) = mpsc::channel(10);
    let scheduler = TimeoutScheduler::new(config, tx);

    // Set the scheduler to the height/round we're scheduling for
    // This is required because the scheduler checks that the current height/round
    // matches the scheduled height/round when firing timeouts
    scheduler.set_height_round(1, 0);

    // Schedule a timeout
    scheduler.schedule(Step::Propose, 1, 0);

    // Wait for timeout
    let timeout = tokio::time::timeout(Duration::from_millis(200), rx.recv())
        .await
        .expect("timeout should fire")
        .expect("should receive timeout");

    assert_eq!(timeout.step, Step::Propose);
    assert_eq!(timeout.height, 1);
    assert_eq!(timeout.round, 0);
}

#[tokio::test]
async fn test_timeout_scheduler_cancel() {
    let config = TimeoutConfig {
        propose_base: Duration::from_millis(100),
        ..TimeoutConfig::fast()
    };

    let (tx, mut rx) = mpsc::channel(10);
    let scheduler = TimeoutScheduler::new(config, tx);

    // Set the scheduler to the height/round we're scheduling for
    scheduler.set_height_round(1, 0);

    // Schedule and immediately cancel
    scheduler.schedule(Step::Propose, 1, 0);
    scheduler.cancel(Step::Propose, 1, 0);

    // Should not receive timeout
    let result = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(result.is_err(), "should not receive cancelled timeout");
}
