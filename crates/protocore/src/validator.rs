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
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, error, info, warn};

use alloy_primitives::{Address as AlloyAddress, Bytes, U256, B256};
use protocore_config::Config;
use protocore_consensus::{
    CommittedBlock, ConsensusEngine, ConsensusMessage, TimeoutConfig, TimeoutInfo,
    Validator as ConsensusValidator, ValidatorSet as ConsensusValidatorSet, Vote, VoteType,
};
use protocore_crypto::{BlsPrivateKey, BlsPublicKey, BlsSignature};
use protocore_evm::{BlockContext, EvmConfig, EvmExecutor, MemoryDb, StateRootProvider, TransactionData};
use protocore_p2p::GossipMessage;
use protocore_storage::StateDB;
use protocore_types::{Address, Block};
use revm::primitives::{AccountInfo, HashMap as RevmHashMap};
use std::collections::HashMap;

/// Database wrapper for EVM execution that reads from StateDB and tracks writes
struct ExecutionDb {
    state_db: Arc<StateDB>,
    accounts: HashMap<AlloyAddress, AccountInfo>,
    storage_writes: HashMap<AlloyAddress, HashMap<U256, U256>>,
    code: HashMap<B256, revm::primitives::Bytecode>,
}

impl ExecutionDb {
    fn new(state_db: Arc<StateDB>) -> Self {
        Self {
            state_db,
            accounts: HashMap::new(),
            storage_writes: HashMap::new(),
            code: HashMap::new(),
        }
    }

    fn insert_account(&mut self, address: AlloyAddress, account: AccountInfo) {
        self.accounts.insert(address, account);
    }

    fn insert_code(&mut self, code: revm::primitives::Bytecode) -> B256 {
        let hash = code.hash_slow();
        self.code.insert(hash, code);
        hash
    }

    /// Get storage writes after execution
    fn storage_writes(&self) -> &HashMap<AlloyAddress, HashMap<U256, U256>> {
        &self.storage_writes
    }
}

#[derive(Debug)]
struct ExecutionDbError;

impl std::fmt::Display for ExecutionDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ExecutionDb error")
    }
}

impl std::error::Error for ExecutionDbError {}

impl revm::Database for ExecutionDb {
    type Error = ExecutionDbError;

    fn basic(&mut self, address: AlloyAddress) -> Result<Option<AccountInfo>, Self::Error> {
        // Check cached accounts first
        if let Some(account) = self.accounts.get(&address) {
            return Ok(Some(account.clone()));
        }

        // Fall back to state_db
        let addr_bytes: [u8; 20] = address.0.into();
        if let Some(account) = self.state_db.get_account(&addr_bytes) {
            let code_hash = if account.code_hash == [0u8; 32] {
                B256::ZERO
            } else {
                B256::from_slice(&account.code_hash)
            };
            Ok(Some(AccountInfo {
                balance: U256::from(account.balance),
                nonce: account.nonce,
                code_hash,
                code: None,
            }))
        } else {
            Ok(None)
        }
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<revm::primitives::Bytecode, Self::Error> {
        // Check local cache first
        if let Some(code) = self.code.get(&code_hash) {
            return Ok(code.clone());
        }

        // Fall back to state_db
        if let Some(code) = self.state_db.get_code(&code_hash.0) {
            Ok(revm::primitives::Bytecode::new_raw(Bytes::from(code)))
        } else {
            Ok(revm::primitives::Bytecode::new())
        }
    }

    fn storage(&mut self, address: AlloyAddress, index: U256) -> Result<U256, Self::Error> {
        // Check writes cache first
        if let Some(account_storage) = self.storage_writes.get(&address) {
            if let Some(value) = account_storage.get(&index) {
                return Ok(*value);
            }
        }

        // Fall back to state_db
        let addr_bytes: [u8; 20] = address.0.into();
        let slot_bytes: [u8; 32] = index.to_be_bytes();
        let value = self.state_db.get_storage(&addr_bytes, &slot_bytes);
        Ok(U256::from_be_bytes(value))
    }

    fn block_hash(&mut self, _number: u64) -> Result<B256, Self::Error> {
        Ok(B256::ZERO)
    }
}

impl revm::DatabaseCommit for ExecutionDb {
    fn commit(&mut self, changes: RevmHashMap<AlloyAddress, revm::primitives::Account>) {
        for (address, account) in changes {
            // Update account info
            self.accounts.insert(address, account.info);

            // Track storage writes
            let storage = self.storage_writes.entry(address).or_default();
            for (slot, value) in account.storage {
                storage.insert(slot, value.present_value);
            }
        }
    }
}

impl StateRootProvider for ExecutionDb {
    fn state_root(&self) -> B256 {
        B256::ZERO // Not needed for transaction execution
    }
}

use crate::node::{Node, NodeBlockBuilder, NodeBlockValidator};

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
        let key_data: ValidatorKeyFile =
            serde_json::from_slice(&key_bytes).context("Failed to parse validator key file")?;

        let key_bytes = hex::decode(&key_data.bls_private_key)?;
        let key_array: [u8; 32] = key_bytes.try_into().map_err(|v: Vec<u8>| {
            anyhow::anyhow!("Expected 32 bytes for BLS key, got {}", v.len())
        })?;
        let bls_private_key = BlsPrivateKey::from_bytes(&key_array)?;
        let bls_public_key = bls_private_key.public_key();

        let address =
            Address::from_slice(&hex::decode(key_data.address.trim_start_matches("0x"))?)?;

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
        let keys = ValidatorKeys::load(key_path).context("Failed to load validator keys")?;

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
            warn!("Validator is not in the active set. Running as observer until activated.");
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
            let stake: u128 = genesis_val.stake.parse().context("Invalid stake value")?;

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
        if let Some(height_bytes) = database
            .get_metadata(b"latest_height")
            .map_err(|e| anyhow::anyhow!("Failed to get latest height: {}", e))?
        {
            if height_bytes.len() >= 8 {
                let height = u64::from_le_bytes(height_bytes[..8].try_into().unwrap());
                // Try to get the block hash for this height
                if let Some(hash_bytes) = database
                    .get_metadata(&format!("block_hash_{}", height).into_bytes())
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
        let engine = self
            .consensus
            .clone()
            .expect("Consensus engine must be initialized");

        // Task 1: Handle incoming consensus messages from network
        if let Some(mut rx) = self.consensus_msg_rx.take() {
            let eng = engine.clone();
            tokio::spawn(async move {
                while let Some(msg) = rx.recv().await {
                    match msg {
                        GossipMessage::Proposal(proposal) => {
                            debug!(
                                height = proposal.height,
                                round = proposal.round,
                                "Processing proposal"
                            );
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
            let block_time_ms = self.config.consensus.block_time_ms;
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

                    // Process transactions using EVM for proper execution
                    let mut tx_hashes = Vec::with_capacity(tx_count);
                    let chain_id = 31337u64; // TODO: get from config

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

                        // Check if this transaction has contract data (call or deployment)
                        let has_data = !tx.data().is_empty();
                        let is_contract_creation = tx.to().is_none();

                        if has_data || is_contract_creation {
                            // Execute via EVM for contract interactions
                            info!(
                                tx_hash = %hex::encode(&tx.hash().as_bytes()[..8]),
                                has_data = has_data,
                                is_contract_creation = is_contract_creation,
                                data_len = tx.data().len(),
                                "Executing transaction via EVM"
                            );

                            // Create ExecutionDb that reads from StateDB and tracks writes
                            let mut exec_db = ExecutionDb::new(Arc::clone(&state_db));

                            let from_alloy = AlloyAddress::from_slice(sender.as_fixed_bytes());
                            let sender_balance = state_db.get_balance(sender.as_fixed_bytes());
                            let sender_nonce = state_db.get_nonce(sender.as_fixed_bytes());

                            exec_db.insert_account(
                                from_alloy,
                                AccountInfo {
                                    balance: U256::from(sender_balance),
                                    nonce: sender_nonce,
                                    ..Default::default()
                                },
                            );

                            // Load recipient account (for contract calls)
                            if let Some(to) = tx.to() {
                                let to_alloy = AlloyAddress::from_slice(to.as_fixed_bytes());
                                let to_balance = state_db.get_balance(to.as_fixed_bytes());
                                let to_nonce = state_db.get_nonce(to.as_fixed_bytes());

                                // Load contract code if exists
                                if let Some(account) = state_db.get_account(to.as_fixed_bytes()) {
                                    if let Some(code) = state_db.get_code(&account.code_hash) {
                                        if !code.is_empty() {
                                            let bytecode = revm::primitives::Bytecode::new_raw(Bytes::from(code));
                                            let code_hash = exec_db.insert_code(bytecode);
                                            exec_db.insert_account(
                                                to_alloy,
                                                AccountInfo {
                                                    balance: U256::from(to_balance),
                                                    nonce: to_nonce,
                                                    code_hash,
                                                    ..Default::default()
                                                },
                                            );
                                        }
                                    }

                                    // Load existing storage for the contract
                                    // For a full implementation, we'd iterate all storage slots
                                    // For now, storage is loaded lazily via the HybridDb pattern
                                }
                            }

                            // Create EVM executor with ExecutionDb
                            let evm_config = EvmConfig {
                                chain_id,
                                ..EvmConfig::default()
                            };
                            let mut executor = EvmExecutor::new(exec_db, evm_config);

                            // Build transaction data
                            let tx_data = TransactionData {
                                hash: B256::from_slice(tx.hash().as_bytes()),
                                from: from_alloy,
                                to: tx.to().map(|a| AlloyAddress::from_slice(a.as_fixed_bytes())),
                                value: U256::from(tx.value()),
                                data: Bytes::from(tx.data().to_vec()),
                                gas_limit: tx.gas_limit() as u64,
                                max_fee_per_gas: tx.max_fee_per_gas() as u128,
                                max_priority_fee_per_gas: tx.max_priority_fee_per_gas() as u128,
                                nonce: tx.nonce() as u64,
                                access_list: vec![],
                            };

                            // Create block context
                            let block_context = BlockContext {
                                number: height,
                                timestamp: committed.block.header.timestamp,
                                gas_limit: 30_000_000,
                                coinbase: AlloyAddress::ZERO,
                                base_fee: 1_000_000_000,
                                prev_randao: B256::ZERO,
                            };

                            // Execute the transaction
                            match executor.execute_transaction(&tx_data, &block_context) {
                                Ok(result) => {
                                    debug!(
                                        tx_hash = %hex::encode(&tx.hash().as_bytes()[..8]),
                                        success = result.success,
                                        gas_used = result.gas_used,
                                        "EVM transaction executed"
                                    );

                                    // Apply state changes to StateDB
                                    // First, update sender nonce
                                    state_db.increment_nonce(sender.as_fixed_bytes());

                                    // Deduct gas cost from sender
                                    let gas_cost = (result.gas_used as u128) * (tx.max_fee_per_gas() as u128);
                                    if let Err(e) = state_db.sub_balance(sender.as_fixed_bytes(), gas_cost) {
                                        error!(error = %e, "Failed to deduct gas cost");
                                    }

                                    // Handle value transfer
                                    if tx.value() > 0 {
                                        if let Some(to) = tx.to() {
                                            if let Err(e) = state_db.transfer(
                                                sender.as_fixed_bytes(),
                                                to.as_fixed_bytes(),
                                                tx.value(),
                                            ) {
                                                error!(error = %e, "Failed to transfer value");
                                            }
                                        } else if is_contract_creation {
                                            // For contract creation, deduct value from sender
                                            // (it goes to the new contract)
                                            if let Err(e) = state_db.sub_balance(sender.as_fixed_bytes(), tx.value()) {
                                                error!(error = %e, "Failed to deduct contract creation value");
                                            }
                                        }
                                    }

                                    // If this was a contract creation, store the contract code
                                    if is_contract_creation && result.success {
                                        if let Some(ref output) = result.output {
                                            // Calculate contract address
                                            use protocore_crypto::keccak256;
                                            let mut rlp_stream = rlp::RlpStream::new_list(2);
                                            rlp_stream.append(&sender.as_fixed_bytes().as_slice());
                                            rlp_stream.append(&tx.nonce());
                                            let encoded = rlp_stream.out();
                                            let hash = keccak256(&encoded);
                                            let mut contract_addr = [0u8; 20];
                                            contract_addr.copy_from_slice(&hash[12..32]);

                                            // Store contract code and get its hash
                                            match state_db.set_code(output) {
                                                Ok(code_hash) => {
                                                    // Create contract account with code hash and value
                                                    let account = protocore_storage::Account {
                                                        nonce: 1,
                                                        balance: tx.value(),
                                                        code_hash,
                                                        storage_root: [0u8; 32],
                                                    };
                                                    state_db.set_account(&contract_addr, account);

                                                    debug!(
                                                        contract = %hex::encode(&contract_addr),
                                                        code_size = output.len(),
                                                        "Contract deployed"
                                                    );
                                                }
                                                Err(e) => {
                                                    error!(error = %e, "Failed to store contract code");
                                                }
                                            }
                                        }
                                    }

                                    // Apply storage changes from EVM execution
                                    // The EVM executor commits changes to its internal StateAdapter
                                    // We need to extract and apply those to StateDB
                                    let db = executor.db();
                                    let changes = db.pending_changes();

                                    info!(
                                        tx_hash = %hex::encode(&tx.hash().as_bytes()[..8]),
                                        changes_count = changes.len(),
                                        "Applying EVM storage changes"
                                    );

                                    for (address, account_changes) in changes {
                                        let addr_bytes: [u8; 20] = address.0.into();

                                        info!(
                                            address = %hex::encode(&addr_bytes),
                                            storage_changes = account_changes.storage.len(),
                                            "Processing account changes"
                                        );

                                        // Apply storage changes
                                        for (slot, value) in &account_changes.storage {
                                            let slot_bytes: [u8; 32] = slot.to_be_bytes();
                                            let value_bytes: [u8; 32] = value.to_be_bytes();
                                            state_db.set_storage(&addr_bytes, &slot_bytes, value_bytes);
                                            info!(
                                                address = %hex::encode(&addr_bytes),
                                                slot = %hex::encode(&slot_bytes),
                                                value = %hex::encode(&value_bytes),
                                                "Storage slot updated"
                                            );
                                        }
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        error = %e,
                                        tx_hash = %hex::encode(&tx.hash().as_bytes()[..8]),
                                        "EVM execution failed"
                                    );
                                    // Still increment nonce for failed transactions
                                    state_db.increment_nonce(sender.as_fixed_bytes());
                                }
                            }
                        } else {
                            // Simple value transfer (no contract interaction)
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

                    // Store transaction indexes and receipts
                    for (tx_index, tx) in committed.block.transactions.iter().enumerate() {
                        let tx_hash = tx.hash();

                        // Create transaction location data: block_hash + block_height + tx_index
                        let mut tx_location = Vec::with_capacity(32 + 8 + 8);
                        tx_location.extend_from_slice(hash.as_bytes());
                        tx_location.extend_from_slice(&height.to_le_bytes());
                        tx_location.extend_from_slice(&(tx_index as u64).to_le_bytes());

                        if let Err(e) = database.put_transaction(tx_hash.as_bytes(), &tx_location) {
                            error!(error = %e, tx_hash = %hex::encode(&tx_hash.as_bytes()[..8]), "Failed to store transaction");
                        }

                        // Create receipt data: tx_hash(32) + block_hash(32) + block_height(8) + tx_index(8) + status(1) + gas_used(8)
                        let mut receipt_data = Vec::with_capacity(89);
                        receipt_data.extend_from_slice(tx_hash.as_bytes());
                        receipt_data.extend_from_slice(hash.as_bytes());
                        receipt_data.extend_from_slice(&height.to_le_bytes());
                        receipt_data.extend_from_slice(&(tx_index as u64).to_le_bytes());
                        receipt_data.push(1u8); // success status
                        receipt_data.extend_from_slice(&21000u64.to_le_bytes()); // gas_used placeholder

                        if let Err(e) = database.put_receipt(tx_hash.as_bytes(), &receipt_data) {
                            error!(error = %e, tx_hash = %hex::encode(&tx_hash.as_bytes()[..8]), "Failed to store receipt");
                        }

                        debug!(
                            tx_hash = %hex::encode(&tx_hash.as_bytes()[..8]),
                            tx_index = tx_index,
                            "Stored transaction and receipt"
                        );
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

                    info!(
                        height = height,
                        txs = tx_count,
                        "Block persisted to database"
                    );

                    // Broadcast committed block event
                    let _ = committed_tx.send(committed.clone());

                    // Wait for block time before starting next height
                    // This ensures proper block timing and allows other validators to sync
                    if block_time_ms > 0 {
                        debug!(
                            height = height,
                            block_time_ms = block_time_ms,
                            "Waiting for block time before next height"
                        );
                        tokio::time::sleep(Duration::from_millis(block_time_ms)).await;
                    }

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
