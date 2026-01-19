//! Integration tests for EVM executor

use protocore_evm::{
    executor::EvmConfig,
    DEFAULT_BLOCK_GAS_LIMIT, MAINNET_CHAIN_ID,
};

#[test]
fn test_evm_config_mainnet() {
    let config = EvmConfig::mainnet();
    assert_eq!(config.chain_id, MAINNET_CHAIN_ID);
    assert_eq!(config.block_gas_limit, DEFAULT_BLOCK_GAS_LIMIT);
}
