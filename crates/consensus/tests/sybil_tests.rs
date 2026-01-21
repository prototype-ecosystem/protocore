//! Integration tests for Sybil detection module.

use protocore_consensus::{
    AppealState, ConfidenceLevel, SignalType, SybilConfig, SybilDetector, SybilSignal,
};
use protocore_types::Address;

fn make_address(n: u8) -> Address {
    let mut bytes = [0u8; 20];
    bytes[19] = n;
    Address::new(bytes)
}

fn make_block_hash(n: u8) -> [u8; 32] {
    let mut hash = [0u8; 32];
    hash[31] = n;
    hash
}

#[test]
fn test_confidence_level_from_score() {
    assert_eq!(ConfidenceLevel::from_score(0.0), ConfidenceLevel::None);
    assert_eq!(ConfidenceLevel::from_score(0.5), ConfidenceLevel::None);
    assert_eq!(ConfidenceLevel::from_score(0.99), ConfidenceLevel::None);
    assert_eq!(ConfidenceLevel::from_score(1.0), ConfidenceLevel::Low);
    assert_eq!(ConfidenceLevel::from_score(1.5), ConfidenceLevel::Low);
    assert_eq!(ConfidenceLevel::from_score(1.99), ConfidenceLevel::Low);
    assert_eq!(ConfidenceLevel::from_score(2.0), ConfidenceLevel::Medium);
    assert_eq!(ConfidenceLevel::from_score(3.0), ConfidenceLevel::Medium);
    assert_eq!(ConfidenceLevel::from_score(3.49), ConfidenceLevel::Medium);
    assert_eq!(ConfidenceLevel::from_score(3.5), ConfidenceLevel::High);
    assert_eq!(ConfidenceLevel::from_score(4.5), ConfidenceLevel::High);
    assert_eq!(ConfidenceLevel::from_score(4.99), ConfidenceLevel::High);
    assert_eq!(ConfidenceLevel::from_score(5.0), ConfidenceLevel::Confirmed);
    assert_eq!(
        ConfidenceLevel::from_score(10.0),
        ConfidenceLevel::Confirmed
    );
}

#[test]
fn test_single_weak_signal_no_penalty() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let current_time = 1000000u64;

    // Add a single weak signal (same registration epoch: +0.5)
    let signal = SybilSignal::new(
        SignalType::SameRegistrationEpoch,
        current_time,
        vec![make_address(2)],
        "Same epoch".to_string(),
    );
    detector.add_signal(validator, signal);

    // Score should be 0.5, confidence should be None
    let status = detector.get_status(&validator, current_time);
    assert_eq!(status.signal_score, 0.5);
    assert_eq!(status.confidence_level, ConfidenceLevel::None);
    assert_eq!(status.penalty, 0.0);
}

#[test]
fn test_multiple_weak_signals_low_confidence() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let current_time = 1000000u64;

    // Add same registration epoch (+0.5)
    let signal1 = SybilSignal::new(
        SignalType::SameRegistrationEpoch,
        current_time,
        vec![make_address(2)],
        "Same epoch".to_string(),
    );
    detector.add_signal(validator, signal1);

    // Add identical stake (+0.3)
    let signal2 = SybilSignal::new(
        SignalType::IdenticalStakeAmount,
        current_time,
        vec![make_address(2)],
        "Same stake".to_string(),
    );
    detector.add_signal(validator, signal2);

    // Add same IP subnet (+1.0)
    let signal3 = SybilSignal::new(
        SignalType::SameIpSubnet,
        current_time,
        vec![make_address(2)],
        "Same subnet".to_string(),
    );
    detector.add_signal(validator, signal3);

    // Score = 0.5 + 0.3 + 1.0 = 1.8 -> Low confidence
    let status = detector.get_status(&validator, current_time);
    assert!((status.signal_score - 1.8).abs() < 0.001);
    assert_eq!(status.confidence_level, ConfidenceLevel::Low);
    // Low confidence = no penalty (just notification)
    assert_eq!(status.penalty, 0.0);
}

#[test]
fn test_medium_confidence_penalty_after_grace_period() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add signals totaling >= 2.0 (medium confidence)
    // Same IP subnet (+1.0) + Vote timing (+1.5) = 2.5
    let signal1 = SybilSignal::new(
        SignalType::SameIpSubnet,
        signal_time,
        vec![make_address(2)],
        "Same subnet".to_string(),
    );
    detector.add_signal(validator, signal1);

    let signal2 = SybilSignal::new(
        SignalType::VoteTimingCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote timing".to_string(),
    );
    detector.add_signal(validator, signal2);

    // During grace period - no penalty
    let during_grace = signal_time + 1000;
    let status = detector.get_status(&validator, during_grace);
    assert_eq!(status.confidence_level, ConfidenceLevel::Medium);
    assert_eq!(status.penalty, 0.0); // Still in grace period

    // After grace period - penalty applies
    let after_grace = signal_time + detector.config().appeal_grace_period_secs + 1;
    let status = detector.get_status(&validator, after_grace);
    assert_eq!(status.confidence_level, ConfidenceLevel::Medium);
    assert_eq!(status.penalty, 0.80); // Medium confidence cap
}

#[test]
fn test_high_confidence_penalty() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add signals totaling >= 3.5 (high confidence)
    // Controversial vote (+2.0) + Vote timing (+1.5) = 3.5
    let signal1 = SybilSignal::new(
        SignalType::ControversialVoteCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote correlation".to_string(),
    );
    detector.add_signal(validator, signal1);

    let signal2 = SybilSignal::new(
        SignalType::VoteTimingCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote timing".to_string(),
    );
    detector.add_signal(validator, signal2);

    let after_grace = signal_time + detector.config().appeal_grace_period_secs + 1;
    let status = detector.get_status(&validator, after_grace);
    assert_eq!(status.confidence_level, ConfidenceLevel::High);
    assert_eq!(status.penalty, 0.95); // High confidence cap
}

#[test]
fn test_confirmed_sybil_penalty() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add signals totaling >= 5.0 (confirmed)
    // Same withdrawal address (+3.0) + Controversial vote (+2.0) = 5.0
    let signal1 = SybilSignal::new(
        SignalType::SameWithdrawalAddress,
        signal_time,
        vec![make_address(2)],
        "Same withdrawal".to_string(),
    );
    detector.add_signal(validator, signal1);

    let signal2 = SybilSignal::new(
        SignalType::ControversialVoteCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote correlation".to_string(),
    );
    detector.add_signal(validator, signal2);

    let after_grace = signal_time + detector.config().appeal_grace_period_secs + 1;
    let status = detector.get_status(&validator, after_grace);
    assert_eq!(status.confidence_level, ConfidenceLevel::Confirmed);
    assert_eq!(status.penalty, 0.99); // Confirmed cap
}

#[test]
fn test_governance_confirmed_sybil() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let current_time = 1000000u64;

    // No signals, but governance confirms
    detector.confirm_sybil(validator);

    let status = detector.get_status(&validator, current_time);
    assert_eq!(status.confidence_level, ConfidenceLevel::Confirmed);
    // Note: penalty requires grace period to pass
    // But governance confirmation should bypass that
    assert_eq!(status.signal_score, 0.0); // No signals
}

#[test]
fn test_appeal_flow() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add medium confidence signals
    let signal = SybilSignal::new(
        SignalType::ControversialVoteCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote correlation".to_string(),
    );
    detector.add_signal(validator, signal);

    // After grace period, penalty would apply
    let after_grace = signal_time + detector.config().appeal_grace_period_secs + 1;

    // But validator submits appeal first
    let appeal_time = signal_time + 1000;
    detector.submit_appeal(
        validator,
        "We are different operators, here's proof".to_string(),
        appeal_time,
    );

    // Penalty suspended during appeal
    let status = detector.get_status(&validator, after_grace);
    assert_eq!(status.penalty, 0.0);
    assert!(status.appeal_status.is_some());
    assert_eq!(
        status.appeal_status.as_ref().unwrap().status,
        AppealState::Pending
    );

    // Appeal approved
    let review_time = after_grace + 1000;
    detector.process_appeal(&validator, true, review_time);

    let status = detector.get_status(&validator, review_time);
    assert_eq!(status.penalty, 0.0);
    assert_eq!(
        status.appeal_status.as_ref().unwrap().status,
        AppealState::Approved
    );

    // Clear signals after approval
    detector.clear_signals(&validator);
    let status = detector.get_status(&validator, review_time);
    assert_eq!(status.confidence_level, ConfidenceLevel::None);
    assert_eq!(status.signal_score, 0.0);
}

#[test]
fn test_appeal_denied() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add medium confidence signals
    let signal = SybilSignal::new(
        SignalType::ControversialVoteCorrelation,
        signal_time,
        vec![make_address(2)],
        "Vote correlation".to_string(),
    );
    detector.add_signal(validator, signal);

    let after_grace = signal_time + detector.config().appeal_grace_period_secs + 1;

    // Submit and deny appeal
    detector.submit_appeal(validator, "Evidence".to_string(), signal_time + 1000);
    detector.process_appeal(&validator, false, after_grace);

    // Penalty now applies
    let status = detector.get_status(&validator, after_grace);
    assert_eq!(
        status.appeal_status.as_ref().unwrap().status,
        AppealState::Denied
    );
    assert_eq!(status.penalty, 0.80); // Medium confidence
}

#[test]
fn test_controversial_vote_correlation_detection() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let v3 = make_address(3);
    let current_time = 1000000u64;

    // Record votes on 5 controversial blocks
    for i in 0..5 {
        let hash = make_block_hash(i);
        detector.mark_controversial(hash);

        // v1 and v2 always vote the same (within 10ms of each other)
        detector.record_vote(v1, hash, true, current_time + (i as u64 * 1000));
        detector.record_vote(v2, hash, true, current_time + (i as u64 * 1000) + 10);

        // v3 votes differently AND at a different time (500ms later, well outside timing threshold)
        detector.record_vote(v3, hash, i % 2 == 0, current_time + (i as u64 * 1000) + 500);
    }

    // Analyze correlations
    detector.analyze_correlations(current_time);

    // v1 and v2 should be flagged (100% correlation >= 80% threshold)
    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);

    assert!(status1.signal_score >= 2.0); // At least controversial vote signal
    assert!(status2.signal_score >= 2.0);

    // v3 should not be flagged (no high correlation with others, and no timing correlation)
    let status3 = detector.get_status(&v3, current_time);
    assert!(status3.signal_score < 2.0);
}

#[test]
fn test_vote_timing_correlation_detection() {
    let mut detector = SybilDetector::new(SybilConfig {
        vote_timing_threshold_ms: 50,
        ..Default::default()
    });
    let v1 = make_address(1);
    let v2 = make_address(2);
    let current_time = 1000000u64;

    // Record votes with tight timing on 5 controversial blocks
    for i in 0..5 {
        let hash = make_block_hash(i);
        detector.mark_controversial(hash);

        // v1 and v2 vote within 30ms (under 50ms threshold)
        detector.record_vote(v1, hash, true, current_time + (i as u64 * 1000));
        detector.record_vote(v2, hash, true, current_time + (i as u64 * 1000) + 30);
    }

    detector.analyze_correlations(current_time);

    // Both should have timing correlation signal
    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);

    // Should have vote timing signal (1.5) + controversial vote (2.0) = 3.5
    assert!(status1.signal_score >= 3.0);
    assert!(status2.signal_score >= 3.0);
}

#[test]
fn test_check_withdrawal_addresses() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let v3 = make_address(3);
    let withdrawal1 = make_address(100);
    let withdrawal2 = make_address(101);
    let current_time = 1000000u64;

    let validators = vec![
        (v1, withdrawal1),
        (v2, withdrawal1), // Same as v1
        (v3, withdrawal2), // Different
    ];

    detector.check_withdrawal_addresses(&validators, current_time);

    // v1 and v2 should be flagged
    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);
    let status3 = detector.get_status(&v3, current_time);

    assert_eq!(status1.signal_score, 3.0); // Same withdrawal weight
    assert_eq!(status2.signal_score, 3.0);
    assert_eq!(status3.signal_score, 0.0); // No match
}

#[test]
fn test_check_ip_clustering() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let v3 = make_address(3);
    let current_time = 1000000u64;

    let validators = vec![
        (v1, [192, 168, 1, 10]),
        (v2, [192, 168, 1, 20]), // Same /24 as v1
        (v3, [10, 0, 0, 1]),     // Different subnet
    ];

    detector.check_ip_clustering(&validators, current_time);

    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);
    let status3 = detector.get_status(&v3, current_time);

    assert_eq!(status1.signal_score, 1.0); // Same IP subnet weight
    assert_eq!(status2.signal_score, 1.0);
    assert_eq!(status3.signal_score, 0.0);
}

#[test]
fn test_check_registration_epochs() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let v3 = make_address(3);
    let current_time = 1000000u64;

    let validators = vec![
        (v1, 100), // Epoch 100
        (v2, 100), // Same epoch
        (v3, 200), // Different epoch
    ];

    detector.check_registration_epochs(&validators, current_time);

    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);
    let status3 = detector.get_status(&v3, current_time);

    assert_eq!(status1.signal_score, 0.5); // Same registration epoch weight
    assert_eq!(status2.signal_score, 0.5);
    assert_eq!(status3.signal_score, 0.0);
}

#[test]
fn test_check_identical_stakes() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let v3 = make_address(3);
    let current_time = 1000000u64;

    let validators = vec![
        (v1, 10000u128),
        (v2, 10000u128), // Same as v1
        (v3, 50000u128), // Different
    ];

    detector.check_identical_stakes(&validators, current_time);

    let status1 = detector.get_status(&v1, current_time);
    let status2 = detector.get_status(&v2, current_time);
    let status3 = detector.get_status(&v3, current_time);

    assert_eq!(status1.signal_score, 0.3); // Identical stake weight
    assert_eq!(status2.signal_score, 0.3);
    assert_eq!(status3.signal_score, 0.0);
}

#[test]
fn test_combined_signals_scenario() {
    // Realistic scenario: Two validators that look suspicious
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let withdrawal = make_address(100);
    let current_time = 1000000u64;

    // They share withdrawal address (+3.0)
    detector.check_withdrawal_addresses(&[(v1, withdrawal), (v2, withdrawal)], current_time);

    // They're in the same IP subnet (+1.0)
    detector.check_ip_clustering(
        &[(v1, [192, 168, 1, 10]), (v2, [192, 168, 1, 20])],
        current_time,
    );

    // They registered in the same epoch (+0.5)
    detector.check_registration_epochs(&[(v1, 100), (v2, 100)], current_time);

    // Total: 3.0 + 1.0 + 0.5 = 4.5 -> High confidence
    let status = detector.get_status(&v1, current_time);
    assert!((status.signal_score - 4.5).abs() < 0.001);
    assert_eq!(status.confidence_level, ConfidenceLevel::High);

    // After grace period
    let after_grace = current_time + detector.config().appeal_grace_period_secs + 1;
    let status = detector.get_status(&v1, after_grace);
    assert_eq!(status.penalty, 0.95); // High cap
}

#[test]
fn test_signal_deduplication() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let withdrawal = make_address(100);
    let current_time = 1000000u64;

    // Check withdrawal addresses twice
    detector.check_withdrawal_addresses(&[(v1, withdrawal), (v2, withdrawal)], current_time);
    detector.check_withdrawal_addresses(&[(v1, withdrawal), (v2, withdrawal)], current_time);

    // Should only have one signal, not two
    let status = detector.get_status(&v1, current_time);
    assert_eq!(status.signal_score, 3.0); // Not 6.0
    assert_eq!(status.active_signals.len(), 1);
}

#[test]
fn test_honest_validators_not_penalized() {
    // Two honest validators that happen to:
    // - Use same cloud provider (could be same /24)
    // - Stake round number
    // - Register near each other

    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let current_time = 1000000u64;

    // Same registration epoch (+0.5)
    detector.check_registration_epochs(&[(v1, 100), (v2, 100)], current_time);

    // Same stake amount (+0.3)
    detector.check_identical_stakes(&[(v1, 10000), (v2, 10000)], current_time);

    // Total: 0.8 -> None confidence (below 1.0 threshold)
    let status = detector.get_status(&v1, current_time);
    assert!((status.signal_score - 0.8).abs() < 0.001);
    assert_eq!(status.confidence_level, ConfidenceLevel::None);
    assert_eq!(status.penalty, 0.0);

    // Even with same IP subnet (+1.0), total = 1.8 -> Low (no penalty)
    detector.check_ip_clustering(
        &[(v1, [52, 72, 1, 10]), (v2, [52, 72, 1, 20])],
        current_time,
    );

    let status = detector.get_status(&v1, current_time);
    assert!((status.signal_score - 1.8).abs() < 0.001);
    assert_eq!(status.confidence_level, ConfidenceLevel::Low);
    assert_eq!(status.penalty, 0.0); // Still no penalty - just notification
}

#[test]
fn test_clear_signals_after_appeal() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    // Add signals
    let signal = SybilSignal::new(
        SignalType::SameIpSubnet,
        signal_time,
        vec![make_address(2)],
        "Same subnet".to_string(),
    );
    detector.add_signal(validator, signal);

    assert!(detector.has_signals(&validator));
    assert_eq!(detector.signal_count(&validator), 1);

    // Clear signals
    detector.clear_signals(&validator);

    assert!(!detector.has_signals(&validator));
    assert_eq!(detector.signal_count(&validator), 0);

    let status = detector.get_status(&validator, signal_time);
    assert_eq!(status.signal_score, 0.0);
    assert_eq!(status.confidence_level, ConfidenceLevel::None);
}

#[test]
fn test_flagged_validators_iterator() {
    let mut detector = SybilDetector::with_defaults();
    let v1 = make_address(1);
    let v2 = make_address(2);
    let current_time = 1000000u64;

    let signal1 = SybilSignal::new(
        SignalType::SameIpSubnet,
        current_time,
        vec![v2],
        "Same subnet".to_string(),
    );
    detector.add_signal(v1, signal1);

    let signal2 = SybilSignal::new(
        SignalType::SameIpSubnet,
        current_time,
        vec![v1],
        "Same subnet".to_string(),
    );
    detector.add_signal(v2, signal2);

    let flagged: Vec<_> = detector.flagged_validators().collect();
    assert_eq!(flagged.len(), 2);
    assert!(flagged.contains(&&v1));
    assert!(flagged.contains(&&v2));
}

#[test]
fn test_penalty_effective_at_calculation() {
    let mut detector = SybilDetector::with_defaults();
    let validator = make_address(1);
    let signal_time = 1000000u64;

    let signal = SybilSignal::new(
        SignalType::SameWithdrawalAddress,
        signal_time,
        vec![make_address(2)],
        "Same withdrawal".to_string(),
    );
    detector.add_signal(validator, signal);

    let status = detector.get_status(&validator, signal_time);
    assert!(status.penalty_effective_at.is_some());
    assert_eq!(
        status.penalty_effective_at.unwrap(),
        signal_time + detector.config().appeal_grace_period_secs
    );
}
