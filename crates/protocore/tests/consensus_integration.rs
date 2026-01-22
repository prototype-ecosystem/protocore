//! Integration tests for consensus engine initialization
//!
//! These tests verify that the consensus engine is properly wired up
//! and can be started when a validator node runs.

use protocore_config::{Config, GenesisValidator};
use protocore_crypto::bls::BlsPrivateKey;
use protocore_crypto::PrivateKey;
use std::path::PathBuf;
use tempfile::TempDir;

/// Helper to generate test validator keys and save them
fn generate_test_validator_keys(dir: &std::path::Path) -> (PathBuf, String, String) {
    // Generate BLS keypair
    let bls_private_key = BlsPrivateKey::random();
    let bls_public_key = bls_private_key.public_key();
    let bls_pubkey_hex = format!("0x{}", hex::encode(bls_public_key.to_bytes()));

    // Generate ECDSA keypair for address
    let ecdsa_private_key = PrivateKey::random();
    let address = ecdsa_private_key.public_key().to_address();
    let address_hex = format!("0x{}", hex::encode(address));

    // Save keys to directory
    let key_path = dir.join("validator.keys");

    // Create key file content (matching ValidatorKeys format)
    let key_content = serde_json::json!({
        "bls_private_key": hex::encode(bls_private_key.to_bytes()),
        "bls_public_key": bls_pubkey_hex,
        "ecdsa_private_key": hex::encode(ecdsa_private_key.to_bytes()),
        "address": address_hex,
    });

    std::fs::write(
        &key_path,
        serde_json::to_string_pretty(&key_content).unwrap(),
    )
    .unwrap();

    (key_path, bls_pubkey_hex, address_hex)
}

/// Create a test config with the given validators in genesis
fn create_test_config(validators: Vec<(String, String)>) -> Config {
    let mut config = Config::default();

    // Set up genesis validators
    config.genesis.validators = validators
        .into_iter()
        .map(|(address, pubkey)| GenesisValidator {
            address,
            pubkey,
            stake: "10000000000000000000000".to_string(), // 10000 tokens
            commission: 1000,                             // 10%
        })
        .collect();

    config
}

#[test]
fn test_config_with_validators_validates() {
    // Create temp directory for keys
    let temp_dir = TempDir::new().unwrap();

    // Generate validator keys
    let (_, bls_pubkey, address) = generate_test_validator_keys(temp_dir.path());

    // Create config with this validator
    let config = create_test_config(vec![(address, bls_pubkey)]);

    // Verify genesis has one validator
    assert_eq!(config.genesis.validators.len(), 1);

    // Verify validator stake can be parsed
    let stake: u128 = config.genesis.validators[0].stake.parse().unwrap();
    assert_eq!(stake, 10000000000000000000000u128);
}

#[test]
fn test_bls_pubkey_parsing() {
    // Generate a BLS keypair
    let bls_private_key = BlsPrivateKey::random();
    let bls_public_key = bls_private_key.public_key();
    let pubkey_bytes = bls_public_key.to_bytes();
    let pubkey_hex = format!("0x{}", hex::encode(pubkey_bytes));

    // Verify we can decode it back
    let decoded = hex::decode(pubkey_hex.trim_start_matches("0x")).unwrap();
    assert_eq!(decoded.len(), 48, "BLS public key should be 48 bytes");

    // Verify we can convert to array
    let pubkey_array: [u8; 48] = decoded.try_into().unwrap();
    assert_eq!(&pubkey_array, &pubkey_bytes);
}

#[test]
fn test_validator_set_construction() {
    use protocore_consensus::{Validator, ValidatorSet};

    // Create two validators
    let keypair1 = BlsPrivateKey::random();
    let keypair2 = BlsPrivateKey::random();

    let validators = vec![
        Validator::new(0, keypair1.public_key(), [1u8; 20], 10000, 1000),
        Validator::new(1, keypair2.public_key(), [2u8; 20], 10000, 1000),
    ];

    let validator_set = ValidatorSet::new(validators);

    // Verify set properties
    assert_eq!(validator_set.len(), 2);
    assert_eq!(validator_set.total_stake, 20000);

    // Verify proposer rotation
    let proposer_h0_r0 = validator_set.proposer(0, 0);
    let proposer_h1_r0 = validator_set.proposer(1, 0);
    assert_ne!(
        proposer_h0_r0.id, proposer_h1_r0.id,
        "Different heights should have different proposers"
    );
}

#[test]
fn test_consensus_channel_types() {
    use protocore_consensus::{CommittedBlock, ConsensusMessage, Proposal, TimeoutInfo};
    use protocore_types::Block;
    use tokio::sync::mpsc;

    // Verify channel types compile and work
    let (network_tx, mut network_rx) = mpsc::channel::<ConsensusMessage>(10);
    let (_commit_tx, _commit_rx) = mpsc::channel::<CommittedBlock>(10);
    let (_timeout_tx, _timeout_rx) = mpsc::channel::<TimeoutInfo>(10);

    // Create a valid proposal to send
    let block = Block::default();
    let proposal = Proposal::new(1, 0, block, -1);

    // Channels should be usable
    assert!(network_tx
        .try_send(ConsensusMessage::Proposal(proposal))
        .is_ok());

    // Verify we can receive
    assert!(network_rx.try_recv().is_ok());
}

/// Test that checks the consensus engine can be created with proper validator set
#[test]
fn test_consensus_engine_creation() {
    use async_trait::async_trait;
    use protocore_consensus::{
        BlockBuilder, BlockValidator, CommittedBlock, ConsensusMessage, TimeoutInfo,
    };
    use protocore_consensus::{ConsensusEngine, TimeoutConfig, Validator, ValidatorSet};
    use protocore_types::{Address, Block, BlockHeader, H256};
    use std::sync::Arc;
    use tokio::sync::mpsc;

    // Hash type is [u8; 32]
    type Hash = [u8; 32];

    // Create mock block validator
    struct MockBlockValidator;

    #[async_trait]
    impl BlockValidator for MockBlockValidator {
        async fn validate_block(&self, _block: &Block, _parent_hash: &Hash) -> Result<(), String> {
            Ok(())
        }
    }

    // Create mock block builder
    struct MockBlockBuilder;

    #[async_trait]
    impl BlockBuilder for MockBlockBuilder {
        async fn build_block(&self, height: u64, parent_hash: Hash, proposer: Address) -> Block {
            let mut header = BlockHeader::default();
            header.height = height;
            header.parent_hash = H256::from(parent_hash);
            header.proposer = proposer;
            Block::new(header, Vec::new())
        }
    }

    // Generate keypair for validator
    let bls_private_key = BlsPrivateKey::random();

    // Create validator set with one validator
    let validators = vec![Validator::new(
        0,
        bls_private_key.public_key(),
        [1u8; 20],
        10000,
        1000,
    )];
    let validator_set = ValidatorSet::new(validators);

    // Create channels
    let (network_tx, _network_rx) = mpsc::channel::<ConsensusMessage>(10);
    let (commit_tx, _commit_rx) = mpsc::channel::<CommittedBlock>(10);
    let (timeout_tx, _timeout_rx) = mpsc::channel::<TimeoutInfo>(10);

    // Create engine - this verifies the full construction path works
    let engine = ConsensusEngine::new(
        0, // validator_id
        bls_private_key,
        validator_set,
        TimeoutConfig::default(),
        Arc::new(MockBlockValidator),
        Arc::new(MockBlockBuilder),
        network_tx,
        commit_tx,
        timeout_tx,
    );

    // Verify engine was created (engine starts at height 1 to build the first block)
    let state = engine.state();
    assert_eq!(state.height, 1);
    assert_eq!(state.round, 0);
}

#[test]
fn test_ecdsa_address_generation() {
    // Generate ECDSA keypair
    let private_key = PrivateKey::random();
    let address = private_key.public_key().to_address();

    // Address should be 20 bytes
    assert_eq!(address.len(), 20);

    // Address should be deterministic from private key
    let address2 = private_key.public_key().to_address();
    assert_eq!(address, address2);
}
