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
    TimeoutInfo, Validator as ConsensusValidator, ValidatorSet as ConsensusValidatorSet,
    Vote, VoteType,
};
use protocore_crypto::{BlsPrivateKey, BlsPublicKey, BlsSignature};
use protocore_p2p::{GossipMessage, NetworkHandle};
use protocore_storage::{Database, StateDB};
use protocore_types::{Address, Block, BlockHeader, H256};

use crate::node::{Node, NodeBlockBuilder, NodeBlockValidator, NodeEvent, NodeStatus};

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

    /// Consensus engine (active when validator is in the set)
    consensus: Option<Arc<ConsensusEngine<NodeBlockValidator, NodeBlockBuilder>>>,

    /// Channel receivers for consensus tasks
    consensus_msg_rx: Option<mpsc::Receiver<GossipMessage>>,
    timeout_rx: Option<mpsc::Receiver<TimeoutInfo>>,
    commit_rx: Option<mpsc::Receiver<CommittedBlock>>,

    /// Sender for outbound consensus messages to network
    network_msg_rx: Option<mpsc::Receiver<ConsensusMessage>>,
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
            consensus: None,
            consensus_msg_rx: None,
            timeout_rx: None,
            commit_rx: None,
            network_msg_rx: None,
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

            // Set up consensus message channel on the node
            let (consensus_tx, consensus_rx) = mpsc::channel(1000);
            self.node.set_consensus_channel(consensus_tx);
            self.consensus_msg_rx = Some(consensus_rx);

            // Start network early so we can get the handle for consensus
            info!("Starting network early for consensus");
            self.node.start_network_early().await?;

            // Initialize the consensus engine
            self.init_consensus_engine().await?;

            // Get current chain tip
            let (height, parent_hash) = self.get_chain_tip()?;
            info!(height = height, "Starting consensus from chain tip");

            // Spawn consensus background tasks (now network handle is available)
            self.spawn_consensus_tasks();

            // Start consensus at the next height
            if let Some(engine) = &self.consensus {
                info!(height = height + 1, "Starting consensus");
                engine.start(height + 1, parent_hash).await;
            }
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

    /// Initialize the consensus engine with channels and validator set
    async fn init_consensus_engine(&mut self) -> Result<()> {
        info!("Initializing consensus engine");

        // Build validator set from genesis config
        let mut validators = Vec::new();
        for (i, genesis_val) in self.config.genesis.validators.iter().enumerate() {
            // Parse BLS public key
            let pubkey_bytes = hex::decode(genesis_val.pubkey.trim_start_matches("0x"))
                .context("Invalid BLS public key hex")?;
            let pubkey_array: [u8; 48] = pubkey_bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("BLS public key must be 48 bytes"))?;
            let pubkey = BlsPublicKey::from_bytes(&pubkey_array)
                .map_err(|e| anyhow::anyhow!("Invalid BLS public key: {}", e))?;

            // Parse address
            let address_bytes = hex::decode(genesis_val.address.trim_start_matches("0x"))
                .context("Invalid address hex")?;
            let mut address = [0u8; 20];
            address.copy_from_slice(&address_bytes);

            // Parse stake from string to u128
            let stake: u128 = genesis_val.stake.parse()
                .context("Invalid stake value")?;

            validators.push(ConsensusValidator::new(
                i as u64,
                pubkey,
                address,
                stake,
                genesis_val.commission,
            ));
        }
        let validator_set = ConsensusValidatorSet::new(validators);

        info!(
            validator_count = validator_set.len(),
            our_id = self.validator_id,
            "Built validator set from genesis"
        );

        // Create channels for consensus
        let (network_tx, network_rx) = mpsc::channel(100);
        let (commit_tx, commit_rx) = mpsc::channel(100);
        let (timeout_tx, timeout_rx) = mpsc::channel(100);

        // Store receivers for spawned tasks
        self.network_msg_rx = Some(network_rx);
        self.commit_rx = Some(commit_rx);
        self.timeout_rx = Some(timeout_rx);

        // Create block validator and builder
        let block_validator = Arc::new(NodeBlockValidator::new(
            Arc::clone(self.node.state_db()),
            Arc::clone(self.node.database()),
            self.config.chain.chain_id,
        ));
        let block_builder = Arc::new(NodeBlockBuilder::new(
            Arc::clone(self.node.mempool()),
            Arc::clone(self.node.database()),
            self.config.chain.chain_id,
            self.config.economics.block_gas_limit,
        ));

        // Create the consensus engine
        let engine = ConsensusEngine::new(
            self.validator_id.unwrap(),
            self.keys.bls_private_key.clone(),
            validator_set,
            TimeoutConfig::default(),
            block_validator,
            block_builder,
            network_tx,
            commit_tx,
            timeout_tx,
        );

        self.consensus = Some(Arc::new(engine));
        info!("Consensus engine initialized");

        Ok(())
    }

    /// Get the current chain tip (height and hash)
    fn get_chain_tip(&self) -> Result<(u64, [u8; 32])> {
        // Get latest height from metadata
        let database = self.node.database();

        // Try to get the latest block height from metadata
        if let Some(height_bytes) = database.get_metadata(b"latest_height")
            .map_err(|e| anyhow::anyhow!("Failed to get latest height: {}", e))?
        {
            if height_bytes.len() >= 8 {
                let height = u64::from_le_bytes(height_bytes[..8].try_into().unwrap());
                // Try to get the block hash for this height
                if let Some(hash_bytes) = database.get_metadata(&format!("block_hash_{}", height).into_bytes())
                    .map_err(|e| anyhow::anyhow!("Failed to get block hash: {}", e))?
                {
                    if hash_bytes.len() >= 32 {
                        let mut hash = [0u8; 32];
                        hash.copy_from_slice(&hash_bytes[..32]);
                        return Ok((height, hash));
                    }
                }
            }
        }

        // No blocks yet, return genesis (height 0, zero hash for parent)
        // The first block at height 1 will have parent_hash = zero
        Ok((0, [0u8; 32]))
    }

    /// Spawn background tasks for consensus message handling
    fn spawn_consensus_tasks(&mut self) {
        let engine = self.consensus.clone().expect("Consensus engine must be initialized");

        // Task 1: Handle incoming consensus messages from network
        if let Some(mut rx) = self.consensus_msg_rx.take() {
            let eng = engine.clone();
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    match msg {
                        GossipMessage::Proposal(proposal) => {
                            debug!(height = proposal.height, round = proposal.round, "Processing proposal");
                            eng.on_proposal(proposal).await;
                        }
                        GossipMessage::Vote(vote) => {
                            debug!(height = vote.height, round = vote.round, "Processing vote");
                            eng.on_vote(vote).await;
                        }
                        _ => {
                            // Ignore non-consensus messages
                        }
                    }
                }
                info!("Consensus message handler exiting");
            });
        }

        // Task 2: Handle timeout events
        if let Some(mut rx) = self.timeout_rx.take() {
            let eng = engine.clone();
            tokio::spawn(async move {
                while let Some(timeout) = rx.recv().await {
                    debug!(
                        height = timeout.height,
                        round = timeout.round,
                        step = ?timeout.step,
                        "Processing timeout"
                    );
                    eng.on_timeout(timeout).await;
                }
                info!("Timeout handler exiting");
            });
        }

        // Task 3: Handle committed blocks
        if let Some(mut rx) = self.commit_rx.take() {
            let committed_tx = self.committed_tx.clone();
            let eng = engine.clone();
            let database = Arc::clone(self.node.database());
            let state_db = Arc::clone(self.node.state_db());
            let mempool = Arc::clone(self.node.mempool());
            tokio::spawn(async move {
                while let Some(committed) = rx.recv().await {
                    let height = committed.block.header.height;
                    let hash = committed.block.hash();
                    let tx_count = committed.block.transactions.len();
                    info!(
                        height = height,
                        hash = %hex::encode(&hash.as_bytes()[..8]),
                        txs = tx_count,
                        "Block committed"
                    );

                    // Process transactions: update state (nonces, balances)
                    let mut tx_hashes = Vec::with_capacity(tx_count);
                    for tx in &committed.block.transactions {
                        // Get sender address
                        let sender = match tx.sender() {
                            Ok(addr) => addr,
                            Err(e) => {
                                error!(error = %e, "Failed to recover tx sender");
                                continue;
                            }
                        };

                        // Collect transaction hash for mempool removal
                        tx_hashes.push(tx.hash());

                        // Increment sender's nonce
                        state_db.increment_nonce(sender.as_fixed_bytes());

                        // Transfer value from sender to recipient (if any)
                        let value = tx.value();
                        if value > 0 {
                            if let Some(to) = tx.to() {
                                if let Err(e) = state_db.transfer(
                                    sender.as_fixed_bytes(),
                                    to.as_fixed_bytes(),
                                    value,
                                ) {
                                    error!(
                                        error = %e,
                                        from = %sender,
                                        to = %to,
                                        value = value,
                                        "Failed to transfer value"
                                    );
                                }
                            }
                        }

                        debug!(
                            tx_hash = %hex::encode(&tx.hash().as_bytes()[..8]),
                            sender = %sender,
                            "Processed transaction"
                        );
                    }

                    // Remove processed transactions from mempool
                    if !tx_hashes.is_empty() {
                        mempool.remove_transactions(&tx_hashes);
                        debug!(count = tx_hashes.len(), "Removed transactions from mempool");
                    }

                    // Commit state changes
                    if let Err(e) = state_db.commit() {
                        error!(error = %e, "Failed to commit state changes");
                    }

                    // Persist the committed block to database
                    let encoded = committed.block.rlp_encode();
                    if let Err(e) = database.put_block(hash.as_bytes(), &encoded) {
                        error!(error = %e, "Failed to persist committed block");
                    }

                    // Update latest height metadata
                    if let Err(e) = database.put_metadata(b"latest_height", &height.to_le_bytes()) {
                        error!(error = %e, "Failed to update latest height");
                    }

                    // Store block hash by height for lookups
                    let height_key = format!("block_hash_{}", height);
                    if let Err(e) = database.put_metadata(height_key.as_bytes(), hash.as_bytes()) {
                        error!(error = %e, "Failed to store block hash mapping");
                    }

                    info!(height = height, txs = tx_count, "Block persisted to database");

                    // Broadcast committed block event
                    let _ = committed_tx.send(committed.clone());

                    // Start next height consensus
                    let parent_hash: [u8; 32] = hash.into();
                    eng.start(height + 1, parent_hash).await;
                }
                info!("Commit handler exiting");
            });
        }

        // Task 4: Forward outbound consensus messages to network
        if let Some(mut rx) = self.network_msg_rx.take() {
            // Clone the network handle if available
            let network_handle = self.node.network_handle().cloned();
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    let gossip_msg = match msg {
                        ConsensusMessage::Proposal(p) => {
                            debug!(height = p.height, round = p.round, "Broadcasting proposal");
                            GossipMessage::Proposal(p)
                        }
                        ConsensusMessage::Vote(v) => {
                            debug!(height = v.height, round = v.round, "Broadcasting vote");
                            GossipMessage::Vote(v)
                        }
                    };

                    if let Some(ref handle) = network_handle {
                        if let Err(e) = handle.broadcast(gossip_msg).await {
                            warn!(error = %e, "Failed to broadcast consensus message");
                        }
                    } else {
                        warn!("Network handle not available, cannot broadcast");
                    }
                }
                info!("Network sender exiting");
            });
        }

        info!("Consensus tasks spawned");
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
