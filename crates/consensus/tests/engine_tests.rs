//! Integration tests for consensus engine module.

use protocore_consensus::timeout::TimeoutConfig;
use protocore_consensus::timeout::TimeoutInfo;
use protocore_consensus::types::{CommittedBlock, ConsensusMessage, Validator, ValidatorSet};
use protocore_consensus::{BlockBuilder, BlockValidator, ConsensusEngine, ConsensusState, Step};
use protocore_crypto::bls::BlsPrivateKey;
use protocore_crypto::Hash;
use protocore_types::{Address, Block, BlockHeader};

use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::mpsc;

struct MockBlockValidator;

#[async_trait]
impl BlockValidator for MockBlockValidator {
    async fn validate_block(&self, _block: &Block, _parent_hash: &Hash) -> Result<(), String> {
        Ok(())
    }
}

struct MockBlockBuilder;

#[async_trait]
impl BlockBuilder for MockBlockBuilder {
    async fn build_block(&self, height: u64, parent_hash: Hash, proposer: Address) -> Block {
        Block {
            header: BlockHeader {
                height,
                parent_hash: parent_hash.into(),
                proposer,
                ..Default::default()
            },
            transactions: vec![],
        }
    }
}

fn create_test_engine() -> (
    ConsensusEngine<MockBlockValidator, MockBlockBuilder>,
    mpsc::Receiver<ConsensusMessage>,
    mpsc::Receiver<CommittedBlock>,
    mpsc::Receiver<TimeoutInfo>,
) {
    let (network_tx, network_rx) = mpsc::channel(100);
    let (commit_tx, commit_rx) = mpsc::channel(100);
    let (timeout_tx, timeout_rx) = mpsc::channel(100);

    let key = BlsPrivateKey::random();
    let validators = vec![Validator::new(0, key.public_key(), [0u8; 20], 1000, 500)];
    let validator_set = ValidatorSet::new(validators);

    let engine = ConsensusEngine::new(
        0,
        key,
        validator_set,
        TimeoutConfig::fast(),
        Arc::new(MockBlockValidator),
        Arc::new(MockBlockBuilder),
        network_tx,
        commit_tx,
        timeout_tx,
    );

    (engine, network_rx, commit_rx, timeout_rx)
}

#[test]
fn test_consensus_state_new() {
    let state = ConsensusState::new();
    assert_eq!(state.height, 1);
    assert_eq!(state.round, 0);
    // Default step is NewHeight (initial state before consensus starts)
    assert_eq!(state.step, Step::NewHeight);
    assert!(state.locked_value.is_none());
    assert_eq!(state.locked_round, -1);
}

#[test]
fn test_consensus_state_reset() {
    let mut state = ConsensusState::new();
    state.height = 10;
    state.round = 5;
    state.locked_round = 3;

    state.reset_for_height(20);

    assert_eq!(state.height, 20);
    assert_eq!(state.round, 0);
    assert_eq!(state.locked_round, -1);
}

#[tokio::test]
async fn test_engine_creation() {
    let (engine, _, _, _) = create_test_engine();

    let state = engine.state();
    assert_eq!(state.height, 1);
    assert_eq!(engine.validator_id(), 0);
}
