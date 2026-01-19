//! Tests for transaction validation.

use protocore_mempool::{
    AccountStateProvider, MockAccountState, ValidationConfig, ValidationError,
};
use protocore_types::Address;

#[test]
fn test_validation_config_default() {
    let config = ValidationConfig::default();
    assert_eq!(config.min_gas_price, 1_000_000_000); // 1 gwei
    assert_eq!(config.max_tx_size, 131_072); // 128 KB
    assert_eq!(config.block_gas_limit, 30_000_000); // 30M
    assert_eq!(config.min_gas_limit, 21_000);
    assert_eq!(config.chain_id, 1);
}

#[test]
fn test_mock_account_state() {
    let state = MockAccountState::new();
    let address = Address::default();

    assert_eq!(state.get_nonce(&address), 0);
    assert_eq!(state.get_balance(&address), 0);

    state.set_nonce(address, 5);
    state.set_balance(address, 1_000_000);

    assert_eq!(state.get_nonce(&address), 5);
    assert_eq!(state.get_balance(&address), 1_000_000);
}

#[test]
fn test_validation_error_display() {
    let err = ValidationError::InvalidSignature("bad sig".to_string());
    assert_eq!(err.to_string(), "invalid signature: bad sig");

    let err = ValidationError::NonceTooLow {
        expected: 5,
        actual: 3,
    };
    assert_eq!(err.to_string(), "nonce too low: expected >= 5, got 3");

    let err = ValidationError::InsufficientBalance {
        required: 1000,
        available: 500,
    };
    assert_eq!(
        err.to_string(),
        "insufficient balance: required 1000, available 500"
    );
}
