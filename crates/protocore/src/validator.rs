//! # Proto Core Validator Node
//!
//! This module implements validator-specific functionality that extends the base node.
//!
//! A validator node participates in the ProtoBFT consensus by:
//! - Proposing blocks when selected as the proposer
//! - Voting (prevote/precommit) on proposed blocks
//! - Signing consensus messages with BLS keys
//! - Handling block rewards and commission

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use protocore_config::Config;
use protocore_consensus::{
    BlockBuilder as ConsensusBlockBuilder, BlockValidator as ConsensusBlockValidator,
    CommittedBlock, ConsensusEngine, ConsensusMessage, FinalityCert, Proposal, TimeoutConfig,
    ValidatorSet as ConsensusValidatorSet, Vote, VoteType,
};
use protocore_crypto::{BlsPrivateKey, BlsPublicKey, BlsSignature};
use protocore_storage::{Database, StateDB};
use protocore_types::{Address, Block, BlockHeader, H256};

use crate::node::{Node, NodeEvent, NodeStatus};

/// Validator key pair for consensus participation
#[derive(Clone)]
pub struct ValidatorKeys {
    /// BLS private key for signing consensus messages
    pub bls_private_key: BlsPrivateKey,
    /// BLS public key (derived from private key)
    pub bls_public_key: BlsPublicKey,
    /// Validator's Ethereum-style address (for rewards)
    pub address: Address,
}

impl ValidatorKeys {
    /// Load validator keys from a file
    pub fn load(path: &Path) -> Result<Self> {
        let key_bytes = std::fs::read(path)
            .with_context(|| format!("Failed to read validator key from {:?}", path))?;

        // Parse the key file (JSON format)
        let key_data: ValidatorKeyFile = serde_json::from_slice(&key_bytes)
            .context("Failed to parse validator key file")?;

        let key_bytes = hex::decode(&key_data.bls_private_key)?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|v: Vec<u8>| anyhow::anyhow!("Expected 32 bytes for BLS key, got {}", v.len()))?;
        let bls_private_key = BlsPrivateKey::from_bytes(&key_array)?;
        let bls_public_key = bls_private_key.public_key();

        let address = Address::from_slice(&hex::decode(&key_data.address.trim_start_matches("0x"))?)?;

        Ok(Self {
            bls_private_key,
            bls_public_key,
            address,
        })
    }

    /// Generate new validator keys
    pub fn generate() -> Self {
        let bls_private_key = BlsPrivateKey::random();
        let bls_public_key = bls_private_key.public_key();

        // Derive Ethereum address from BLS public key
        // In practice, this might use a separate ECDSA key
        let address_bytes = protocore_crypto::keccak256(&bls_public_key.to_bytes());
        let mut address = [0u8; 20];
        address.copy_from_slice(&address_bytes[12..32]);
        let address = Address::from(address);

        Self {
            bls_private_key,
            bls_public_key,
            address,
        }
    }

    /// Save validator keys to a file
    pub fn save(&self, path: &Path) -> Result<()> {
        let key_data = ValidatorKeyFile {
            bls_private_key: hex::encode(self.bls_private_key.to_bytes()),
            bls_public_key: hex::encode(self.bls_public_key.to_bytes()),
            address: format!("0x{}", hex::encode(self.address.as_bytes())),
        };

        let json = serde_json::to_string_pretty(&key_data)?;
        std::fs::write(path, json)?;

        Ok(())
    }

    /// Sign a message with the BLS private key
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        self.bls_private_key.sign(message)
    }
}

/// Validator key file format
#[derive(Serialize, Deserialize)]
struct ValidatorKeyFile {
    bls_private_key: String,
    bls_public_key: String,
    address: String,
}

/// Validator node that extends the base Node with consensus participation
pub struct ValidatorNode {
    /// Base node functionality
    node: Node,

    /// Node configuration (for checking genesis validators)
    config: Config,

    /// Validator keys
    keys: ValidatorKeys,

    /// Validator ID in the current validator set
    validator_id: Option<u64>,

    /// Track if we are in the active validator set
    is_active_validator: bool,

    /// Track accumulated rewards
    accumulated_rewards: u128,

    /// Track blocks we've proposed
    blocks_proposed: u64,

    /// Track blocks we've voted on
    blocks_voted: u64,

    /// Channel for committed blocks
    committed_tx: broadcast::Sender<CommittedBlock>,
}

impl ValidatorNode {
    /// Create a new validator node
    pub async fn new(config: Config, key_path: &Path) -> Result<Self> {
        info!(key_path = ?key_path, "Loading validator keys");

        // Load validator keys
        let keys = ValidatorKeys::load(key_path)
            .context("Failed to load validator keys")?;

        info!(
            address = %format!("0x{}", hex::encode(keys.address.as_bytes())),
            "Validator address loaded"
        );

        // Create the base node
        let node = Node::new(config.clone()).await?;

        // Create committed block channel
        let (committed_tx, _) = broadcast::channel(100);

        Ok(Self {
            node,
            config,
            keys,
            validator_id: None,
            is_active_validator: false,
            accumulated_rewards: 0,
            blocks_proposed: 0,
            blocks_voted: 0,
            committed_tx,
        })
    }

    /// Run the validator node
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting validator node");

        // First, check if we're in the active validator set
        self.check_validator_status().await?;

        if !self.is_active_validator {
            warn!(
                "Validator is not in the active set. Running as observer until activated."
            );
        } else {
            info!(
                validator_id = self.validator_id,
                "Validator is active in the validator set"
            );
        }

        // Run the base node (this blocks until shutdown)
        self.node.run().await
    }

    /// Check if this validator is in the active validator set
    async fn check_validator_status(&mut self) -> Result<()> {
        // Check if our validator address is in the genesis validator set
        let our_address = format!("0x{}", hex::encode(self.keys.address.as_bytes()));
        let our_address_lower = our_address.to_lowercase();

        debug!(
            validator_address = %our_address,
            genesis_validators = self.config.genesis.validators.len(),
            "Checking validator status against genesis"
        );

        // Iterate through genesis validators to find our position
        for (index, genesis_validator) in self.config.genesis.validators.iter().enumerate() {
            let genesis_addr_lower = genesis_validator.address.to_lowercase();

            if genesis_addr_lower == our_address_lower {
                self.is_active_validator = true;
                self.validator_id = Some(index as u64);

                info!(
                    validator_id = index,
                    address = %our_address,
                    "Validator found in genesis validator set"
                );
                return Ok(());
            }
        }

        // Not found in genesis validators
        self.is_active_validator = false;
        self.validator_id = None;

        debug!(
            address = %our_address,
            "Validator not found in genesis validator set"
        );

        Ok(())
    }

    /// Handle incoming consensus messages from the network
    pub async fn handle_consensus_message(&self, message: ConsensusMessage) -> Result<()> {
        match message {
            ConsensusMessage::Proposal(proposal) => {
                debug!(
                    height = proposal.height,
                    round = proposal.round,
                    "Received proposal"
                );
                // Process proposal in consensus engine
            }
            ConsensusMessage::Vote(vote) => {
                debug!(
                    height = vote.height,
                    round = vote.round,
                    vote_type = ?vote.vote_type,
                    "Received vote"
                );
                // Process vote in consensus engine
            }
        }

        Ok(())
    }

    /// Create a signed vote
    fn create_vote(
        &self,
        vote_type: VoteType,
        height: u64,
        round: u64,
        block_hash: [u8; 32],
    ) -> Vote {
        let validator_id = self.validator_id.unwrap_or(0);

        // Create vote signing bytes
        let mut signing_bytes = Vec::new();
        signing_bytes.push(vote_type as u8);
        signing_bytes.extend(&height.to_le_bytes());
        signing_bytes.extend(&round.to_le_bytes());
        signing_bytes.extend(&block_hash);

        // Sign the vote
        let signature = self.keys.sign(&signing_bytes);

        Vote {
            vote_type,
            height,
            round,
            block_hash,
            validator_id,
            signature,
        }
    }

    /// Create proposal signing bytes
    fn proposal_signing_bytes(height: u64, round: u64, block: &Block) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend(&height.to_le_bytes());
        bytes.extend(&round.to_le_bytes());
        bytes.extend(block.hash().as_bytes());
        bytes
    }

    /// Get validator statistics
    pub fn stats(&self) -> ValidatorStats {
        ValidatorStats {
            address: self.keys.address,
            validator_id: self.validator_id,
            is_active: self.is_active_validator,
            blocks_proposed: self.blocks_proposed,
            blocks_voted: self.blocks_voted,
            accumulated_rewards: self.accumulated_rewards,
        }
    }

    /// Get the validator's address
    pub fn address(&self) -> &Address {
        &self.keys.address
    }

    /// Get the validator's BLS public key
    pub fn bls_public_key(&self) -> &BlsPublicKey {
        &self.keys.bls_public_key
    }

    /// Check if the validator is active
    pub fn is_active(&self) -> bool {
        self.is_active_validator
    }

    /// Get the validator's ID in the current set
    pub fn validator_id(&self) -> Option<u64> {
        self.validator_id
    }

    /// Get a reference to the underlying node
    pub fn node(&self) -> &Node {
        &self.node
    }

    /// Get a mutable reference to the underlying node
    pub fn node_mut(&mut self) -> &mut Node {
        &mut self.node
    }

    /// Subscribe to committed blocks
    pub fn subscribe_commits(&self) -> broadcast::Receiver<CommittedBlock> {
        self.committed_tx.subscribe()
    }
}

/// Statistics about validator performance
#[derive(Debug, Clone)]
pub struct ValidatorStats {
    /// Validator's address
    pub address: Address,
    /// Validator ID in the current set
    pub validator_id: Option<u64>,
    /// Whether the validator is in the active set
    pub is_active: bool,
    /// Number of blocks proposed
    pub blocks_proposed: u64,
    /// Number of blocks voted on
    pub blocks_voted: u64,
    /// Total accumulated rewards (in wei)
    pub accumulated_rewards: u128,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_validator_keys_generate_and_save() {
        let keys = ValidatorKeys::generate();

        // Verify the keys are valid
        let message = b"test message";
        let signature = keys.sign(message);

        assert!(signature.verify(message, &keys.bls_public_key));
    }

    #[test]
    fn test_validator_keys_save_and_load() {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("validator.key");

        // Generate and save
        let keys = ValidatorKeys::generate();
        keys.save(&key_path).unwrap();

        // Load
        let loaded = ValidatorKeys::load(&key_path).unwrap();

        // Verify they match
        assert_eq!(
            keys.bls_public_key.to_bytes(),
            loaded.bls_public_key.to_bytes()
        );
        assert_eq!(keys.address, loaded.address);
    }

    #[test]
    fn test_proposal_signing_bytes() {
        // Create a mock block
        let block = Block::default();

        let bytes1 = ValidatorNode::proposal_signing_bytes(1, 0, &block);
        let bytes2 = ValidatorNode::proposal_signing_bytes(1, 1, &block);
        let bytes3 = ValidatorNode::proposal_signing_bytes(2, 0, &block);

        // Different rounds/heights should produce different signing bytes
        assert_ne!(bytes1, bytes2);
        assert_ne!(bytes1, bytes3);
    }
}
