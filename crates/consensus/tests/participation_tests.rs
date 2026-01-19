//! Integration tests for participation tracking module.

use protocore_consensus::{
    AggregateStats, EpochParticipation, ParticipationSnapshot, ParticipationTracker,
    ValidatorParticipation, BLOCK_WEIGHT, UPTIME_WEIGHT, VOTE_WEIGHT,
};
use protocore_types::Address;

fn test_address(n: u8) -> Address {
    Address::new([n; 20])
}

#[test]
fn test_new_tracker() {
    let tracker = ParticipationTracker::new(10);
    assert_eq!(tracker.current_epoch(), 0);
    assert_eq!(tracker.max_history_epochs(), 10);
    assert_eq!(tracker.validator_count(), 0);
}

#[test]
fn test_default_tracker() {
    let tracker = ParticipationTracker::default();
    assert_eq!(tracker.max_history_epochs(), 24);
}

#[test]
fn test_record_block_proposed() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);

    let metrics = tracker.get_metrics(&validator).unwrap();
    assert_eq!(metrics.blocks_expected, 1);
    assert_eq!(metrics.blocks_proposed, 1);
    assert_eq!(metrics.block_ratio(), 1.0);
}

#[test]
fn test_record_votes() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    for _ in 0..10 {
        tracker.record_vote_expected(validator);
    }
    for _ in 0..8 {
        tracker.record_vote(validator);
    }

    let metrics = tracker.get_metrics(&validator).unwrap();
    assert_eq!(metrics.votes_expected, 10);
    assert_eq!(metrics.votes_cast, 8);
    assert!((metrics.vote_ratio() - 0.8).abs() < f64::EPSILON);
}

#[test]
fn test_record_uptime_sample() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_uptime_sample(validator, true);
    tracker.record_uptime_sample(validator, true);
    tracker.record_uptime_sample(validator, false);
    tracker.record_uptime_sample(validator, true);

    let metrics = tracker.get_metrics(&validator).unwrap();
    assert_eq!(metrics.total_samples, 4);
    assert_eq!(metrics.uptime_samples, 3);
    assert!((metrics.uptime_ratio() - 0.75).abs() < f64::EPSILON);
}

#[test]
fn test_uptime_batch() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_uptime_batch(validator, 90, 100);

    let metrics = tracker.get_metrics(&validator).unwrap();
    assert_eq!(metrics.total_samples, 100);
    assert_eq!(metrics.uptime_samples, 90);
    assert!((metrics.uptime_ratio() - 0.9).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_score_perfect() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // Perfect participation
    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    for _ in 0..10 {
        tracker.record_vote_expected(validator);
        tracker.record_vote(validator);
    }
    for _ in 0..5 {
        tracker.record_uptime_sample(validator, true);
    }

    let score = tracker.calculate_score(&validator);
    assert!((score - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_calculate_score_partial() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // 50% blocks, 80% votes, 90% uptime
    for _ in 0..2 {
        tracker.record_block_expected(validator);
    }
    tracker.record_block_proposed(validator); // 1/2 = 50%

    for _ in 0..10 {
        tracker.record_vote_expected(validator);
    }
    for _ in 0..8 {
        tracker.record_vote(validator); // 8/10 = 80%
    }

    for _ in 0..10 {
        tracker.record_uptime_sample(validator, true);
    }
    tracker.record_uptime_sample(validator, false); // 9/10 = ~90.9%

    let score = tracker.calculate_score(&validator);
    // 0.4 * 0.5 + 0.4 * 0.8 + 0.2 * (10/11)
    // = 0.2 + 0.32 + 0.2 * 0.909...
    // = 0.52 + 0.1818...
    // = 0.7018
    let expected = 0.4 * 0.5 + 0.4 * 0.8 + 0.2 * (10.0 / 11.0);
    assert!((score - expected).abs() < 0.001);
}

#[test]
fn test_calculate_score_no_activity() {
    let tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    let score = tracker.calculate_score(&validator);
    assert_eq!(score, 0.0);
}

#[test]
fn test_transition_epoch() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // Epoch 0: Perfect participation
    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    tracker.record_vote_expected(validator);
    tracker.record_vote(validator);
    tracker.record_uptime_sample(validator, true);

    assert_eq!(tracker.calculate_score(&validator), 1.0);

    // Transition to epoch 1
    tracker.transition_epoch(1);

    assert_eq!(tracker.current_epoch(), 1);
    assert!(tracker.get_metrics(&validator).is_none()); // Metrics cleared
    assert!(tracker.has_history(&validator));

    let history = tracker.get_history(&validator);
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].epoch, 0);
    assert!((history[0].score - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_historical_average() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // Epoch 0: Score = 1.0
    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    tracker.record_vote_expected(validator);
    tracker.record_vote(validator);
    tracker.record_uptime_sample(validator, true);
    tracker.transition_epoch(1);

    // Epoch 1: Score = 0.6 (only uptime)
    tracker.record_uptime_sample(validator, true);
    tracker.record_block_expected(validator);
    tracker.record_vote_expected(validator);
    tracker.transition_epoch(2);

    // Historical average should be (1.0 + 0.2) / 2 = 0.6
    // (block and vote components are 0 since expected but not performed)
    let avg = tracker.historical_average(&validator, 2);
    let expected = (1.0 + 0.2) / 2.0;
    assert!((avg - expected).abs() < 0.001);
}

#[test]
fn test_history_pruning() {
    let mut tracker = ParticipationTracker::new(3); // Only keep 3 epochs
    let validator = test_address(1);

    for epoch in 0..5 {
        tracker.record_uptime_sample(validator, true);
        tracker.transition_epoch(epoch + 1);
    }

    let history = tracker.get_history(&validator);
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].epoch, 2);
    assert_eq!(history[1].epoch, 3);
    assert_eq!(history[2].epoch, 4);
}

#[test]
fn test_snapshot_restore() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    tracker.record_vote_expected(validator);
    tracker.record_vote(validator);
    tracker.record_uptime_sample(validator, true);
    tracker.transition_epoch(1);
    tracker.record_uptime_sample(validator, false);

    let snapshot = tracker.snapshot();
    let restored = ParticipationTracker::restore(snapshot);

    assert_eq!(restored.current_epoch(), tracker.current_epoch());
    assert_eq!(restored.max_history_epochs(), tracker.max_history_epochs());
    assert_eq!(
        restored.get_metrics(&validator),
        tracker.get_metrics(&validator)
    );
    assert_eq!(restored.get_history(&validator), tracker.get_history(&validator));
}

#[test]
fn test_combined_score() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // Epoch 0: Perfect (1.0)
    tracker.record_uptime_sample(validator, true);
    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    tracker.record_vote_expected(validator);
    tracker.record_vote(validator);
    tracker.transition_epoch(1);

    // Epoch 1: Only uptime (0.2)
    tracker.record_uptime_sample(validator, true);
    tracker.record_block_expected(validator);
    tracker.record_vote_expected(validator);

    // Current score = 0.2
    // Historical average = 1.0
    // Combined with 50% history weight = 0.5 * 0.2 + 0.5 * 1.0 = 0.6
    let combined = tracker.combined_score(&validator, 0.5, 1);
    let expected = 0.5 * 0.2 + 0.5 * 1.0;
    assert!((combined - expected).abs() < 0.001);
}

#[test]
fn test_remove_validator() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_uptime_sample(validator, true);
    tracker.transition_epoch(1);
    tracker.record_uptime_sample(validator, true);

    assert!(tracker.remove_validator(&validator));
    assert!(tracker.get_metrics(&validator).is_none());
    assert!(!tracker.has_history(&validator));
    assert!(!tracker.remove_validator(&validator)); // Already removed
}

#[test]
fn test_multiple_validators() {
    let mut tracker = ParticipationTracker::new(10);
    let v1 = test_address(1);
    let v2 = test_address(2);
    let v3 = test_address(3);

    // V1: Perfect - all expectations met
    tracker.record_block_expected(v1);
    tracker.record_block_proposed(v1);
    tracker.record_vote_expected(v1);
    tracker.record_vote(v1);
    tracker.record_uptime_sample(v1, true);

    // V2: Partial - expected but didn't deliver blocks/votes
    tracker.record_block_expected(v2);
    tracker.record_vote_expected(v2);
    tracker.record_uptime_sample(v2, true);

    // V3: Only uptime, no expectations for blocks/votes
    // When no blocks/votes expected, those components default to 1.0 (perfect)
    // So score = 0.4 * 1.0 + 0.4 * 1.0 + 0.2 * 1.0 = 1.0
    tracker.record_uptime_sample(v3, true);

    assert_eq!(tracker.validator_count(), 3);
    assert!((tracker.calculate_score(&v1) - 1.0).abs() < f64::EPSILON);
    assert!((tracker.calculate_score(&v2) - 0.2).abs() < f64::EPSILON);
    // V3 has no expectations, so all ratios default to 1.0
    assert!((tracker.calculate_score(&v3) - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_aggregate_stats() {
    let mut tracker = ParticipationTracker::new(10);
    let v1 = test_address(1);
    let v2 = test_address(2);

    tracker.record_block_expected(v1);
    tracker.record_block_proposed(v1);
    tracker.record_vote_expected(v1);
    tracker.record_vote(v1);
    tracker.record_uptime_sample(v1, true);

    tracker.record_block_expected(v2);
    tracker.record_vote_expected(v2);
    tracker.record_uptime_sample(v2, false);

    let stats = tracker.aggregate_stats();
    assert_eq!(stats.active_validators, 2);
    assert_eq!(stats.total_blocks_proposed, 1);
    assert_eq!(stats.total_blocks_expected, 2);
    assert_eq!(stats.total_votes_cast, 1);
    assert_eq!(stats.total_votes_expected, 2);
    assert_eq!(stats.total_uptime_samples, 1);
    assert_eq!(stats.total_samples, 2);
    // Average: (1.0 + 0.0) / 2 = 0.5
    assert!((stats.average_score - 0.5).abs() < 0.001);
}

#[test]
fn test_votes_expected_batch() {
    let mut tracker = ParticipationTracker::new(10);
    let validators = [test_address(1), test_address(2), test_address(3)];

    tracker.record_votes_expected_batch(&validators);

    for v in &validators {
        let metrics = tracker.get_metrics(v).unwrap();
        assert_eq!(metrics.votes_expected, 1);
    }
}

#[test]
fn test_validator_participation_default() {
    let participation = ValidatorParticipation::default();
    assert_eq!(participation.blocks_proposed, 0);
    assert_eq!(participation.blocks_expected, 0);
    assert_eq!(participation.votes_cast, 0);
    assert_eq!(participation.votes_expected, 0);
    assert_eq!(participation.uptime_samples, 0);
    assert_eq!(participation.total_samples, 0);
}

#[test]
fn test_validator_participation_ratios_zero_expected() {
    let participation = ValidatorParticipation::default();
    // With 0 expected, ratios should return 1.0 (perfect by default)
    assert_eq!(participation.block_ratio(), 1.0);
    assert_eq!(participation.vote_ratio(), 1.0);
    assert_eq!(participation.uptime_ratio(), 1.0);
}

#[test]
fn test_validator_participation_reset() {
    let mut participation = ValidatorParticipation {
        blocks_proposed: 5,
        blocks_expected: 10,
        votes_cast: 8,
        votes_expected: 10,
        uptime_samples: 9,
        total_samples: 10,
    };

    participation.reset();

    assert_eq!(participation.blocks_proposed, 0);
    assert_eq!(participation.blocks_expected, 0);
    assert_eq!(participation.votes_cast, 0);
    assert_eq!(participation.votes_expected, 0);
    assert_eq!(participation.uptime_samples, 0);
    assert_eq!(participation.total_samples, 0);
}

#[test]
fn test_validator_participation_has_activity() {
    let mut participation = ValidatorParticipation::default();
    assert!(!participation.has_activity());

    participation.blocks_expected = 1;
    assert!(participation.has_activity());

    participation.blocks_expected = 0;
    participation.votes_expected = 1;
    assert!(participation.has_activity());

    participation.votes_expected = 0;
    participation.total_samples = 1;
    assert!(participation.has_activity());
}

#[test]
fn test_epoch_transition_to_same_epoch_rejected() {
    let mut tracker = ParticipationTracker::new(10);
    tracker.transition_epoch(5);

    let validator = test_address(1);
    tracker.record_uptime_sample(validator, true);

    // Try to transition to same epoch - should be rejected
    tracker.transition_epoch(5);
    assert_eq!(tracker.current_epoch(), 5);

    // Metrics should not be cleared
    assert!(tracker.get_metrics(&validator).is_some());
}

#[test]
fn test_epoch_transition_to_earlier_rejected() {
    let mut tracker = ParticipationTracker::new(10);
    tracker.transition_epoch(5);

    let validator = test_address(1);
    tracker.record_uptime_sample(validator, true);

    // Try to transition to earlier epoch - should be rejected
    tracker.transition_epoch(3);
    assert_eq!(tracker.current_epoch(), 5);

    // Metrics should not be cleared
    assert!(tracker.get_metrics(&validator).is_some());
}

#[test]
fn test_clear() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_uptime_sample(validator, true);
    tracker.transition_epoch(1);
    tracker.record_uptime_sample(validator, true);

    tracker.clear();

    assert!(tracker.get_metrics(&validator).is_none());
    assert!(!tracker.has_history(&validator));
    assert_eq!(tracker.current_epoch(), 1); // Epoch preserved
}

#[test]
fn test_score_clamped_to_valid_range() {
    let participation = ValidatorParticipation {
        blocks_proposed: 10,
        blocks_expected: 5, // More than expected
        votes_cast: 10,
        votes_expected: 5, // More than expected
        uptime_samples: 10,
        total_samples: 5, // More than expected
    };

    // Even with ratios > 1.0, score should be clamped to 1.0
    let score = participation.calculate_score();
    assert_eq!(score, 1.0);
}

#[test]
fn test_historical_average_partial_history() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    // Only 2 epochs of history, but request 5
    // Each epoch: uptime with expectation but missed blocks/votes
    tracker.record_uptime_sample(validator, true);
    tracker.record_block_expected(validator);
    tracker.record_vote_expected(validator);
    tracker.transition_epoch(1);

    tracker.record_uptime_sample(validator, true);
    tracker.record_block_expected(validator);
    tracker.record_vote_expected(validator);
    tracker.transition_epoch(2);

    // Should use all available (2 epochs)
    // Each epoch: 0.4*0 + 0.4*0 + 0.2*1.0 = 0.2
    let avg = tracker.historical_average(&validator, 5);
    assert!((avg - 0.2).abs() < f64::EPSILON);
}

#[test]
fn test_iterator_methods() {
    let mut tracker = ParticipationTracker::new(10);
    let v1 = test_address(1);
    let v2 = test_address(2);

    tracker.record_uptime_sample(v1, true);
    tracker.record_uptime_sample(v2, true);
    tracker.transition_epoch(1);
    tracker.record_uptime_sample(v1, true);

    let current: Vec<_> = tracker.validators().collect();
    assert_eq!(current.len(), 1);
    assert!(current.contains(&&v1));

    let with_history: Vec<_> = tracker.validators_with_history().collect();
    assert_eq!(with_history.len(), 2);
    assert!(with_history.contains(&&v1));
    assert!(with_history.contains(&&v2));
}

#[test]
fn test_weights_sum_to_one() {
    assert!((BLOCK_WEIGHT + VOTE_WEIGHT + UPTIME_WEIGHT - 1.0).abs() < f64::EPSILON);
}

#[test]
fn test_serde_roundtrip() {
    let mut tracker = ParticipationTracker::new(10);
    let validator = test_address(1);

    tracker.record_block_expected(validator);
    tracker.record_block_proposed(validator);
    tracker.transition_epoch(1);

    let json = serde_json::to_string(&tracker).unwrap();
    let restored: ParticipationTracker = serde_json::from_str(&json).unwrap();

    assert_eq!(restored.current_epoch(), tracker.current_epoch());
    assert_eq!(restored.get_history(&validator), tracker.get_history(&validator));
}
