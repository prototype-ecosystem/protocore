//! Integration tests for Loyalty Tracker

use protocore_storage::loyalty::{LoyaltyError, LoyaltyTracker};

/// Seconds in a day
const SECONDS_PER_DAY: u64 = 86_400;

/// Seconds in a month (approximation: 30 days)
const SECONDS_PER_MONTH: f64 = 30.0 * 86_400.0;

fn make_address(seed: u8) -> [u8; 20] {
    [seed; 20]
}

fn days_to_seconds(days: u64) -> u64 {
    days * SECONDS_PER_DAY
}

fn months_to_seconds(months: f64) -> u64 {
    (months * SECONDS_PER_MONTH) as u64
}

#[test]
fn test_new_tracker() {
    let tracker = LoyaltyTracker::new(24, 90);
    assert_eq!(tracker.maturity_months(), 24);
    assert_eq!(tracker.cooldown_days(), 90);
    assert_eq!(tracker.active_validator_count(), 0);
}

#[test]
fn test_default_tracker() {
    let tracker = LoyaltyTracker::default();
    assert_eq!(tracker.maturity_months(), 24);
    assert_eq!(tracker.cooldown_days(), 90);
}

#[test]
fn test_register_validator() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let timestamp = 1000000;

    assert!(tracker.can_register(&addr, timestamp));
    assert!(tracker.register_validator(addr, timestamp).is_ok());
    assert!(!tracker.can_register(&addr, timestamp));
    assert_eq!(tracker.active_validator_count(), 1);
}

#[test]
fn test_double_registration_fails() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let timestamp = 1000000;

    assert!(tracker.register_validator(addr, timestamp).is_ok());
    let result = tracker.register_validator(addr, timestamp);
    assert_eq!(result, Err(LoyaltyError::AlreadyRegistered));
}

#[test]
fn test_loyalty_score_calculation() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();

    // At registration, score should be 0
    let score = tracker.calculate_score(&addr, start_time);
    assert!((score - 0.0).abs() < 0.001);

    // After 6 months, score should be sqrt(6/24) = sqrt(0.25) = 0.5
    let six_months_later = start_time + months_to_seconds(6.0);
    let score = tracker.calculate_score(&addr, six_months_later);
    assert!((score - 0.5).abs() < 0.01);

    // After 12 months, score should be sqrt(12/24) = sqrt(0.5) ~= 0.707
    let twelve_months_later = start_time + months_to_seconds(12.0);
    let score = tracker.calculate_score(&addr, twelve_months_later);
    assert!((score - 0.707).abs() < 0.01);

    // After 24 months, score should be 1.0
    let twenty_four_months_later = start_time + months_to_seconds(24.0);
    let score = tracker.calculate_score(&addr, twenty_four_months_later);
    assert!((score - 1.0).abs() < 0.01);

    // After 48 months, score should still be capped at 1.0
    let forty_eight_months_later = start_time + months_to_seconds(48.0);
    let score = tracker.calculate_score(&addr, forty_eight_months_later);
    assert!((score - 1.0).abs() < 0.001);
}

#[test]
fn test_get_status() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();

    // After 18 months
    let timestamp = start_time + months_to_seconds(18.0);
    let status = tracker.get_status(&addr, timestamp).unwrap();

    assert!((status.months_active - 18.0).abs() < 0.1);
    assert_eq!(status.maturity_months, 24);
    assert!(!status.is_mature);
    assert!((status.loyalty_score - 0.866).abs() < 0.01); // sqrt(18/24) ~= 0.866
    assert!((status.full_bonus_in_months - 6.0).abs() < 0.1);
}

#[test]
fn test_status_mature_validator() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();

    // After 30 months (beyond maturity)
    let timestamp = start_time + months_to_seconds(30.0);
    let status = tracker.get_status(&addr, timestamp).unwrap();

    assert!(status.is_mature);
    assert!((status.loyalty_score - 1.0).abs() < 0.001);
    assert!((status.full_bonus_in_months - 0.0).abs() < 0.001);
}

#[test]
fn test_unregister_and_cooldown() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();
    assert_eq!(tracker.active_validator_count(), 1);

    // Unregister
    tracker.unregister_validator(addr, start_time + 1000);

    // Should be in cooldown, so score should be 0
    let score = tracker.calculate_score(&addr, start_time + 2000);
    assert!((score - 0.0).abs() < 0.001);

    // Cannot register during cooldown
    let during_cooldown = start_time + days_to_seconds(45);
    assert!(!tracker.can_register(&addr, during_cooldown));

    // Can register after cooldown
    let after_cooldown = start_time + days_to_seconds(91);
    assert!(tracker.can_register(&addr, after_cooldown));
}

#[test]
fn test_cooldown_remaining_days() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();
    tracker.unregister_validator(addr, start_time);

    // After 30 days, should still have 60 days remaining
    let after_30_days = start_time + days_to_seconds(30);
    assert!(!tracker.can_register(&addr, after_30_days));

    // After exactly 90 days, cooldown should have just ended
    let after_90_days = start_time + days_to_seconds(90);
    // Note: cooldown_end = start_time + 90 * SECONDS_PER_DAY
    // So at exactly cooldown_end, timestamp >= cooldown_end is true
    assert!(tracker.can_register(&addr, after_90_days));
}

#[test]
fn test_ban_validator() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let current_time = 1000000u64;
    let ban_until = current_time + days_to_seconds(365); // 1 year ban

    tracker.register_validator(addr, current_time).unwrap();
    tracker.ban_validator(addr, ban_until);

    // Should be banned
    assert!(tracker.is_banned(&addr, current_time));
    assert!(!tracker.can_register(&addr, current_time));

    // Should still be banned after 6 months
    let six_months_later = current_time + days_to_seconds(180);
    assert!(tracker.is_banned(&addr, six_months_later));
    assert!(!tracker.can_register(&addr, six_months_later));

    // Should not be banned after ban expires
    let after_ban = ban_until + 1;
    assert!(!tracker.is_banned(&addr, after_ban));
    assert!(tracker.can_register(&addr, after_ban));
}

#[test]
fn test_register_banned_address_fails() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let current_time = 1000000u64;
    let ban_until = current_time + days_to_seconds(365);

    tracker.ban_validator(addr, ban_until);

    let result = tracker.register_validator(addr, current_time);
    assert!(matches!(result, Err(LoyaltyError::Banned { until }) if until == ban_until));
}

#[test]
fn test_link_addresses() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let primary = make_address(1);
    let secondary1 = make_address(2);
    let secondary2 = make_address(3);
    let timestamp = 1000000u64;

    tracker.register_validator(primary, timestamp).unwrap();

    // Link addresses
    tracker.link_addresses(&primary, secondary1);
    tracker.link_addresses(&primary, secondary2);

    let linked = tracker.get_linked_addresses(&primary);
    assert_eq!(linked.len(), 2);
    assert!(linked.contains(&secondary1));
    assert!(linked.contains(&secondary2));
}

#[test]
fn test_link_addresses_no_duplicates() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let primary = make_address(1);
    let secondary = make_address(2);
    let timestamp = 1000000u64;

    tracker.register_validator(primary, timestamp).unwrap();

    // Link same address twice
    tracker.link_addresses(&primary, secondary);
    tracker.link_addresses(&primary, secondary);

    let linked = tracker.get_linked_addresses(&primary);
    assert_eq!(linked.len(), 1);
}

#[test]
fn test_get_linked_addresses_unregistered() {
    let tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);

    let linked = tracker.get_linked_addresses(&addr);
    assert!(linked.is_empty());
}

#[test]
fn test_snapshot_and_restore() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr1 = make_address(1);
    let addr2 = make_address(2);
    let addr3 = make_address(3);
    let timestamp = 1000000u64;

    // Set up state
    tracker.register_validator(addr1, timestamp).unwrap();
    tracker.register_validator(addr2, timestamp + 1000).unwrap();
    tracker.link_addresses(&addr1, addr3);
    tracker.ban_validator(addr3, timestamp + days_to_seconds(365));

    // Take snapshot
    let snapshot = tracker.snapshot();

    // Restore from snapshot
    let restored = LoyaltyTracker::restore(snapshot);

    // Verify restored state
    assert_eq!(restored.maturity_months(), 24);
    assert_eq!(restored.cooldown_days(), 90);
    assert_eq!(restored.active_validator_count(), 2);
    assert!(restored.is_banned(&addr3, timestamp));

    // Check scores match
    let score1 = tracker.calculate_score(&addr1, timestamp + 1000);
    let restored_score1 = restored.calculate_score(&addr1, timestamp + 1000);
    assert!((score1 - restored_score1).abs() < 0.001);

    // Check linked addresses
    let linked = restored.get_linked_addresses(&addr1);
    assert_eq!(linked.len(), 1);
    assert!(linked.contains(&addr3));
}

#[test]
fn test_clear_expired_bans() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr1 = make_address(1);
    let addr2 = make_address(2);
    let current_time = 1000000u64;

    // Ban addr1 for 30 days, addr2 for 365 days
    tracker.ban_validator(addr1, current_time + days_to_seconds(30));
    tracker.ban_validator(addr2, current_time + days_to_seconds(365));

    assert_eq!(tracker.get_banned_addresses().len(), 2);

    // After 60 days, addr1's ban should be expired
    let after_60_days = current_time + days_to_seconds(60);
    tracker.clear_expired_bans(after_60_days);

    let banned = tracker.get_banned_addresses();
    assert_eq!(banned.len(), 1);
    assert!(!tracker.is_banned(&addr1, after_60_days));
    assert!(tracker.is_banned(&addr2, after_60_days));
}

#[test]
fn test_clear_expired_cooldowns() {
    let mut tracker = LoyaltyTracker::new(24, 30); // 30 day cooldown for easier testing
    let addr1 = make_address(1);
    let addr2 = make_address(2);
    let current_time = 1000000u64;

    tracker.register_validator(addr1, current_time).unwrap();
    tracker.register_validator(addr2, current_time).unwrap();

    // Unregister addr1 (starts cooldown)
    tracker.unregister_validator(addr1, current_time);

    // After 45 days, addr1's cooldown should be expired
    let after_45_days = current_time + days_to_seconds(45);
    tracker.clear_expired_cooldowns(after_45_days);

    // addr2 should still be registered (not in cooldown)
    assert_eq!(tracker.active_validator_count(), 1);
}

#[test]
fn test_score_unregistered_address() {
    let tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);

    let score = tracker.calculate_score(&addr, 1000000);
    assert!((score - 0.0).abs() < 0.001);
}

#[test]
fn test_status_unregistered_address() {
    let tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);

    let status = tracker.get_status(&addr, 1000000);
    assert!(status.is_none());
}

#[test]
fn test_status_in_cooldown() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let timestamp = 1000000u64;

    tracker.register_validator(addr, timestamp).unwrap();
    tracker.unregister_validator(addr, timestamp + 1000);

    // Status should be None for validators in cooldown
    let status = tracker.get_status(&addr, timestamp + 2000);
    assert!(status.is_none());
}

#[test]
fn test_loyalty_error_display() {
    let err1 = LoyaltyError::InCooldown { remaining_days: 45 };
    assert!(err1.to_string().contains("45"));
    assert!(err1.to_string().contains("cooldown"));

    let err2 = LoyaltyError::Banned { until: 1000000 };
    assert!(err2.to_string().contains("banned"));
    assert!(err2.to_string().contains("1000000"));

    let err3 = LoyaltyError::AlreadyRegistered;
    assert!(err3.to_string().contains("already registered"));
}

#[test]
fn test_multiple_validators_different_tenures() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr1 = make_address(1);
    let addr2 = make_address(2);
    let addr3 = make_address(3);

    // Register validators at different times
    let base_time = 1000000u64;
    tracker.register_validator(addr1, base_time).unwrap(); // 24 months ago
    tracker
        .register_validator(addr2, base_time + months_to_seconds(12.0))
        .unwrap(); // 12 months ago
    tracker
        .register_validator(addr3, base_time + months_to_seconds(18.0))
        .unwrap(); // 6 months ago

    let current_time = base_time + months_to_seconds(24.0);

    let score1 = tracker.calculate_score(&addr1, current_time);
    let score2 = tracker.calculate_score(&addr2, current_time);
    let score3 = tracker.calculate_score(&addr3, current_time);

    // addr1: 24 months -> score = 1.0
    assert!((score1 - 1.0).abs() < 0.01);

    // addr2: 12 months -> score = sqrt(12/24) = 0.707
    assert!((score2 - 0.707).abs() < 0.01);

    // addr3: 6 months -> score = sqrt(6/24) = 0.5
    assert!((score3 - 0.5).abs() < 0.01);
}

#[test]
fn test_re_registration_after_cooldown() {
    let mut tracker = LoyaltyTracker::new(24, 90);
    let addr = make_address(1);
    let start_time = 1000000u64;

    // First registration
    tracker.register_validator(addr, start_time).unwrap();

    // After 6 months, unregister
    let six_months = start_time + months_to_seconds(6.0);
    tracker.unregister_validator(addr, six_months);

    // Clear the cooldown entry after it expires (simulating time passing)
    let after_cooldown = six_months + days_to_seconds(91);
    tracker.clear_expired_cooldowns(after_cooldown);

    // Re-register after cooldown
    assert!(tracker.can_register(&addr, after_cooldown));
    tracker.register_validator(addr, after_cooldown).unwrap();

    // Score should reset (new registration time)
    let score = tracker.calculate_score(&addr, after_cooldown);
    assert!((score - 0.0).abs() < 0.01);

    // After 6 more months, score should be 0.5 again
    let six_more_months = after_cooldown + months_to_seconds(6.0);
    let score = tracker.calculate_score(&addr, six_more_months);
    assert!((score - 0.5).abs() < 0.01);
}

#[test]
fn test_custom_maturity_period() {
    let mut tracker = LoyaltyTracker::new(12, 90); // 12 month maturity
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();

    // After 12 months (not 24), should reach full maturity
    let twelve_months = start_time + months_to_seconds(12.0);
    let score = tracker.calculate_score(&addr, twelve_months);
    assert!((score - 1.0).abs() < 0.01);

    let status = tracker.get_status(&addr, twelve_months).unwrap();
    assert!(status.is_mature);
}

#[test]
fn test_custom_cooldown_period() {
    let mut tracker = LoyaltyTracker::new(24, 30); // 30 day cooldown
    let addr = make_address(1);
    let start_time = 1000000u64;

    tracker.register_validator(addr, start_time).unwrap();
    tracker.unregister_validator(addr, start_time);

    // After 31 days (not 90), can re-register
    let after_cooldown = start_time + days_to_seconds(31);
    assert!(tracker.can_register(&addr, after_cooldown));
}
