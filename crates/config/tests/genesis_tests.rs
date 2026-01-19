//! Tests for Genesis module

use alloy_primitives::{B256, U256};
use protocore_config::{
    ConfigError, GenesisAccount, GenesisConfig, GenesisValidator, GovernanceParams,
    StakingConfig, StakingParams,
};

fn test_validator() -> GenesisValidator {
    GenesisValidator {
        address: "0x1234567890123456789012345678901234567890".to_string(),
        pubkey: format!("0x{}", "ab".repeat(48)),
        stake: "100000000000000000000000".to_string(),
        commission: 1000,
    }
}

fn test_account() -> GenesisAccount {
    GenesisAccount {
        address: "0x1234567890123456789012345678901234567890".to_string(),
        balance: "1000000000000000000000".to_string(),
    }
}

#[test]
fn test_valid_account() {
    let account = test_account();
    assert!(account.validate().is_ok());
}

#[test]
fn test_invalid_account_address() {
    let mut account = test_account();
    account.address = "invalid".to_string();
    assert!(matches!(
        account.validate(),
        Err(ConfigError::InvalidAddress(_))
    ));
}

#[test]
fn test_invalid_account_balance() {
    let mut account = test_account();
    account.balance = "not_a_number".to_string();
    assert!(matches!(
        account.validate(),
        Err(ConfigError::InvalidBalance(_))
    ));
}

#[test]
fn test_valid_validator() {
    let validator = test_validator();
    assert!(validator.validate().is_ok());
}

#[test]
fn test_invalid_validator_address() {
    let mut validator = test_validator();
    validator.address = "0x123".to_string();
    assert!(matches!(
        validator.validate(),
        Err(ConfigError::InvalidAddress(_))
    ));
}

#[test]
fn test_invalid_validator_pubkey() {
    let mut validator = test_validator();
    validator.pubkey = "0x1234".to_string();
    assert!(matches!(
        validator.validate(),
        Err(ConfigError::InvalidPubkey(_))
    ));
}

#[test]
fn test_invalid_commission_rate() {
    let mut validator = test_validator();
    validator.commission = 15000; // 150%
    assert!(matches!(
        validator.validate(),
        Err(ConfigError::InvalidCommissionRate(15000))
    ));
}

#[test]
fn test_commission_rate_conversion() {
    let validator = test_validator();
    assert!((validator.commission_rate() - 0.1).abs() < f64::EPSILON);
}

#[test]
fn test_genesis_config_default() {
    let genesis = GenesisConfig::default();
    assert!(!genesis.accounts.is_empty());
    assert!(!genesis.validators.is_empty());
}

#[test]
fn test_genesis_no_validators() {
    let genesis = GenesisConfig {
        accounts: vec![test_account()],
        validators: vec![],
    };
    let staking = StakingConfig::default();
    assert!(matches!(
        genesis.validate(&staking),
        Err(ConfigError::NoValidators)
    ));
}

#[test]
fn test_genesis_duplicate_account() {
    let account = test_account();
    let genesis = GenesisConfig {
        accounts: vec![account.clone(), account],
        validators: vec![test_validator()],
    };
    let staking = StakingConfig::default();
    assert!(matches!(
        genesis.validate(&staking),
        Err(ConfigError::DuplicateAccount(_))
    ));
}

#[test]
fn test_genesis_duplicate_validator() {
    let validator = test_validator();
    let genesis = GenesisConfig {
        accounts: vec![test_account()],
        validators: vec![validator.clone(), validator],
    };
    let staking = StakingConfig::default();
    assert!(matches!(
        genesis.validate(&staking),
        Err(ConfigError::DuplicateValidator(_))
    ));
}

#[test]
fn test_genesis_block_generation() {
    let genesis = GenesisConfig::default();
    let block = genesis.generate_genesis_block(1).unwrap();

    assert_eq!(block.chain_id, 1);
    assert_eq!(block.height, 0);
    assert_eq!(block.parent_hash, B256::ZERO);
    assert!(!block.validators.is_empty());
}

#[test]
fn test_genesis_block_hash_consistency() {
    let genesis = GenesisConfig::default();
    let block = genesis.generate_genesis_block(1).unwrap();

    let hash1 = block.calculate_hash();
    let hash2 = block.calculate_hash();

    assert_eq!(hash1, hash2);
}

#[test]
fn test_total_stake_calculation() {
    let genesis = GenesisConfig {
        accounts: vec![],
        validators: vec![
            GenesisValidator {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                pubkey: format!("0x{}", "aa".repeat(48)),
                stake: "1000".to_string(),
                commission: 1000,
            },
            GenesisValidator {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                pubkey: format!("0x{}", "bb".repeat(48)),
                stake: "2000".to_string(),
                commission: 1000,
            },
        ],
    };

    assert_eq!(genesis.total_validator_stake(), U256::from(3000));
}

#[test]
fn test_total_balance_calculation() {
    let genesis = GenesisConfig {
        accounts: vec![
            GenesisAccount {
                address: "0x1111111111111111111111111111111111111111".to_string(),
                balance: "1000".to_string(),
            },
            GenesisAccount {
                address: "0x2222222222222222222222222222222222222222".to_string(),
                balance: "2000".to_string(),
            },
        ],
        validators: vec![],
    };

    assert_eq!(genesis.total_account_balance(), U256::from(3000));
}

#[test]
fn test_governance_params_validation() {
    let params = GovernanceParams::default();
    assert!(params.validate().is_ok());

    let mut invalid = params.clone();
    invalid.quorum = 0;
    assert!(matches!(
        invalid.validate(),
        Err(ConfigError::InvalidQuorum(0))
    ));

    let mut invalid = params.clone();
    invalid.threshold = 101;
    assert!(matches!(
        invalid.validate(),
        Err(ConfigError::InvalidThreshold(101))
    ));
}

#[test]
fn test_staking_params_validation() {
    let params = StakingParams::default();
    assert!(params.validate().is_ok());

    let mut invalid = params.clone();
    invalid.min_stake = "0".to_string();
    assert!(matches!(invalid.validate(), Err(ConfigError::InvalidMinStake)));

    let mut invalid = params.clone();
    invalid.max_validators = 2;
    assert!(matches!(
        invalid.validate(),
        Err(ConfigError::TooFewValidators(2))
    ));
}
