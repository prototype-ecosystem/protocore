//! Tests for Config module

use protocore_config::{
    AttestationConfig, BanType, ChainConfig, Config, ConfigError, ConsensusConfig, EconomicsConfig,
    FailureAction, IntegrityConfig, IntegritySlashingConfig,
    RpcConfig, StorageConfig,
    UpgradeConfig,
};

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.chain.chain_id, 1);
    assert_eq!(config.consensus.block_time_ms, 2000);
    assert_eq!(config.economics.block_gas_limit, 30_000_000);
}

#[test]
fn test_consensus_timeouts() {
    let config = ConsensusConfig::default();
    assert_eq!(config.propose_timeout(0), 1000);
    assert_eq!(config.propose_timeout(1), 1500);
    assert_eq!(config.propose_timeout(2), 2000);
}

#[test]
fn test_invalid_chain_id() {
    let mut config = ChainConfig::default();
    config.chain_id = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidChainId)
    ));
}

#[test]
fn test_invalid_block_time() {
    let mut config = ConsensusConfig::default();
    config.block_time_ms = 50;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidBlockTime(50))
    ));
}

#[test]
fn test_invalid_gas_limit() {
    let mut config = EconomicsConfig::default();
    config.block_gas_limit = 1000;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidGasLimit(1000))
    ));
}

#[test]
fn test_rpc_method_filtering() {
    let mut config = RpcConfig::default();

    // All methods enabled by default
    assert!(config.is_method_enabled("eth_blockNumber"));
    assert!(config.is_method_enabled("eth_sendTransaction"));

    // Disable specific methods
    config.disabled_methods = vec!["eth_sendTransaction".to_string()];
    assert!(config.is_method_enabled("eth_blockNumber"));
    assert!(!config.is_method_enabled("eth_sendTransaction"));

    // Enable only specific methods
    config.disabled_methods = Vec::new();
    config.enabled_methods = vec!["eth_blockNumber".to_string()];
    assert!(config.is_method_enabled("eth_blockNumber"));
    assert!(!config.is_method_enabled("eth_sendTransaction"));
}

#[test]
fn test_storage_archive_mode() {
    let mut config = StorageConfig::default();
    assert!(config.is_archive_mode());

    config.state_pruning = 1000;
    assert!(!config.is_archive_mode());
}

// =========================================================================
// Integrity Config Tests
// =========================================================================

#[test]
fn test_integrity_config_default() {
    let config = IntegrityConfig::default();
    assert!(config.verify_on_startup);
    assert!(!config.allow_skip);
    assert!(config.attestation.enabled);
    assert_eq!(config.attestation.challenge_interval_secs, 300);
    assert_eq!(config.attestation.response_timeout_secs, 30);
    assert_eq!(
        config.attestation.failure_action,
        FailureAction::ReduceScore
    );
    assert_eq!(config.attestation.jail_threshold, 3);
    assert!(config.validate().is_ok());
}

#[test]
fn test_attestation_config_default() {
    let config = AttestationConfig::default();
    assert!(config.enabled);
    assert_eq!(config.challenge_interval_secs, 300);
    assert_eq!(config.response_timeout_secs, 30);
    assert_eq!(config.failure_action, FailureAction::ReduceScore);
    assert_eq!(config.jail_threshold, 3);
    assert!(config.validate().is_ok());
}

#[test]
fn test_attestation_config_invalid_challenge_interval() {
    let mut config = AttestationConfig::default();
    config.challenge_interval_secs = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidTimeout {
            name: "challenge_interval_secs",
            value: 0
        })
    ));
}

#[test]
fn test_attestation_config_invalid_response_timeout() {
    let mut config = AttestationConfig::default();
    config.response_timeout_secs = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidTimeout {
            name: "response_timeout_secs",
            value: 0
        })
    ));
}

#[test]
fn test_integrity_slashing_config_default() {
    let config = IntegritySlashingConfig::default();
    assert_eq!(config.double_sign_slash_percent, 5);
    assert_eq!(config.double_sign_ban, BanType::Permanent);
    assert_eq!(config.invalid_block_slash_percent, 10);
    assert_eq!(config.invalid_block_jail_days, 7);
    assert_eq!(config.censorship_slash_percent, 2);
    assert_eq!(config.censorship_jail_days, 3);
    assert_eq!(config.evidence_reward_percent, 10);
    assert!(config.validate().is_ok());
}

#[test]
fn test_integrity_slashing_config_invalid_double_sign_percent() {
    let mut config = IntegritySlashingConfig::default();
    config.double_sign_slash_percent = 101;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidPercentage {
            name: "double_sign_slash_percent",
            value: 101
        })
    ));
}

#[test]
fn test_integrity_slashing_config_invalid_invalid_block_percent() {
    let mut config = IntegritySlashingConfig::default();
    config.invalid_block_slash_percent = 150;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidPercentage {
            name: "invalid_block_slash_percent",
            value: 150
        })
    ));
}

#[test]
fn test_integrity_slashing_config_invalid_censorship_percent() {
    let mut config = IntegritySlashingConfig::default();
    config.censorship_slash_percent = 200;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidPercentage {
            name: "censorship_slash_percent",
            value: 200
        })
    ));
}

#[test]
fn test_integrity_slashing_config_invalid_evidence_reward_percent() {
    let mut config = IntegritySlashingConfig::default();
    config.evidence_reward_percent = 255;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidPercentage {
            name: "evidence_reward_percent",
            value: 255
        })
    ));
}

#[test]
fn test_upgrade_config_default() {
    let config = UpgradeConfig::default();
    assert_eq!(config.required_signatures, 3);
    assert_eq!(config.min_activation_delay_blocks, 43200);
    assert_eq!(config.approval_threshold, 0.67);
    assert!(config.validate().is_ok());
}

#[test]
fn test_upgrade_config_invalid_required_signatures() {
    let mut config = UpgradeConfig::default();
    config.required_signatures = 0;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidRequiredSignatures(0))
    ));
}

#[test]
fn test_upgrade_config_invalid_approval_threshold_too_high() {
    let mut config = UpgradeConfig::default();
    config.approval_threshold = 1.5;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidApprovalThreshold(_))
    ));
}

#[test]
fn test_upgrade_config_invalid_approval_threshold_negative() {
    let mut config = UpgradeConfig::default();
    config.approval_threshold = -0.5;
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidApprovalThreshold(_))
    ));
}

#[test]
fn test_upgrade_config_valid_boundary_thresholds() {
    let mut config = UpgradeConfig::default();

    // Test 0.0 threshold
    config.approval_threshold = 0.0;
    assert!(config.validate().is_ok());

    // Test 1.0 threshold
    config.approval_threshold = 1.0;
    assert!(config.validate().is_ok());
}

#[test]
fn test_failure_action_enum() {
    assert_eq!(FailureAction::default(), FailureAction::ReduceScore);
    assert_ne!(FailureAction::Log, FailureAction::Jail);
}

#[test]
fn test_ban_type_enum() {
    assert_eq!(BanType::default(), BanType::Permanent);
    assert_ne!(BanType::Permanent, BanType::Temporary);
}

#[test]
fn test_config_with_integrity() {
    let mut config = Config::default();
    config.integrity = Some(IntegrityConfig::default());
    assert!(config.validate().is_ok());
}

#[test]
fn test_config_with_invalid_integrity() {
    let mut config = Config::default();
    let mut integrity = IntegrityConfig::default();
    integrity.slashing.double_sign_slash_percent = 150;
    config.integrity = Some(integrity);
    assert!(matches!(
        config.validate(),
        Err(ConfigError::InvalidPercentage {
            name: "double_sign_slash_percent",
            value: 150
        })
    ));
}
