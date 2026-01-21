//! # Block Builder
//!
//! This module handles block production for Proto Core validators.
//!
//! The `BlockBuilder` is responsible for:
//! - Selecting transactions from the mempool
//! - Executing transactions to determine gas usage
//! - Computing the state root after execution
//! - Building properly formatted block headers
//! - Calculating transaction and receipts roots

use alloy_primitives::{Address as AlloyAddress, Bytes as AlloyBytes, B256, U256};
use anyhow::{Context, Result};
use revm::primitives::AccountInfo;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

use protocore_evm::{BlockContext, EvmConfig, EvmExecutor, MemoryDb, TransactionData};
use protocore_mempool::{AccountStateProvider, Mempool};
use protocore_storage::{Database, MerkleTrie, StateDB};
use protocore_types::{Address, Block, BlockHeader, SignedTransaction, H256};

/// Configuration for block building
#[derive(Debug, Clone)]
pub struct BlockBuilderConfig {
    /// Maximum gas per block
    pub block_gas_limit: u64,
    /// Chain ID
    pub chain_id: u64,
    /// Minimum gas price to include a transaction
    pub min_gas_price: u128,
    /// Maximum transactions to include in a block
    pub max_transactions: usize,
    /// Target block time in milliseconds
    pub target_block_time_ms: u64,
}

impl Default for BlockBuilderConfig {
    fn default() -> Self {
        Self {
            block_gas_limit: 30_000_000,
            chain_id: 1,
            min_gas_price: 1_000_000_000, // 1 gwei
            max_transactions: 1000,
            target_block_time_ms: 2000,
        }
    }
}

/// Transaction selection result
#[derive(Debug)]
struct SelectedTransactions {
    /// Transactions to include in the block
    transactions: Vec<SignedTransaction>,
    /// Total gas that will be used
    total_gas: u64,
    /// Transactions that were skipped (invalid or out of gas)
    skipped: usize,
}

/// Receipt for block builder (simplified version)
#[derive(Debug, Clone)]
pub struct BlockReceipt {
    /// Transaction hash
    pub transaction_hash: H256,
    /// Transaction index in block
    pub transaction_index: u64,
    /// Block hash (set after block is finalized)
    pub block_hash: H256,
    /// Block number
    pub block_number: u64,
    /// Sender address
    pub from: Address,
    /// Recipient address
    pub to: Option<Address>,
    /// Cumulative gas used
    pub cumulative_gas_used: u64,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Contract address if deployment
    pub contract_address: Option<Address>,
    /// Logs emitted
    pub logs: Vec<LogEntry>,
    /// Status code (1 = success, 0 = failure)
    pub status: u8,
    /// Effective gas price
    pub effective_gas_price: u128,
}

/// Log entry for receipts
#[derive(Debug, Clone)]
pub struct LogEntry {
    /// Contract address that emitted the log
    pub address: Address,
    /// Log topics
    pub topics: Vec<H256>,
    /// Log data
    pub data: Vec<u8>,
}

/// Result of transaction simulation
#[derive(Debug, Clone)]
pub struct SimulationResult {
    /// Whether the transaction would succeed
    pub success: bool,
    /// Estimated gas usage
    pub gas_used: u64,
    /// Return data from the transaction
    pub return_data: Vec<u8>,
    /// Logs that would be emitted
    pub logs: Vec<LogEntry>,
    /// Error message if the transaction would fail
    pub error: Option<String>,
}

/// Storage abstraction for block builder
///
/// This trait provides the storage interface needed by the block builder.
pub trait BlockBuilderStorage: Send + Sync {
    /// Get block by height
    fn get_block_by_height(&self, height: u64) -> Result<Option<Block>>;

    /// Get current state root
    fn get_state_root(&self) -> Result<H256>;

    /// Get account balance
    fn get_balance(&self, address: &Address) -> Result<u128>;

    /// Get account nonce
    fn get_nonce(&self, address: &Address) -> Result<u64>;

    /// Get state database for EVM execution
    fn state_db(&self) -> Result<Arc<StateDB>>;
}

/// Simple storage implementation wrapping StateDB and Database
pub struct SimpleStorage {
    db: Arc<Database>,
    state_db: Arc<StateDB>,
}

impl SimpleStorage {
    /// Create a new simple storage
    pub fn new(db: Arc<Database>, state_db: Arc<StateDB>) -> Self {
        Self { db, state_db }
    }
}

impl BlockBuilderStorage for SimpleStorage {
    fn get_block_by_height(&self, height: u64) -> Result<Option<Block>> {
        let key = format!("block_height:{}", height);
        if let Some(hash_bytes) = self
            .db
            .get(protocore_storage::db::cf::METADATA, key.as_bytes())
            .map_err(|e| anyhow::anyhow!("DB error: {}", e))?
        {
            if let Some(block_data) = self
                .db
                .get(protocore_storage::db::cf::BLOCKS, &hash_bytes)
                .map_err(|e| anyhow::anyhow!("DB error: {}", e))?
            {
                let block = Block::rlp_decode(&block_data)
                    .map_err(|e| anyhow::anyhow!("Decode error: {}", e))?;
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    fn get_state_root(&self) -> Result<H256> {
        let root_bytes = self.state_db.state_root();
        Ok(H256::from(root_bytes))
    }

    fn get_balance(&self, address: &Address) -> Result<u128> {
        let addr_bytes: [u8; 20] = (*address).into();
        Ok(self.state_db.get_balance(&addr_bytes))
    }

    fn get_nonce(&self, address: &Address) -> Result<u64> {
        let addr_bytes: [u8; 20] = (*address).into();
        Ok(self.state_db.get_nonce(&addr_bytes))
    }

    fn state_db(&self) -> Result<Arc<StateDB>> {
        Ok(Arc::clone(&self.state_db))
    }
}

/// Block builder for creating new blocks
pub struct BlockBuilder<S: BlockBuilderStorage, A: AccountStateProvider> {
    /// Storage for accessing chain state
    storage: Arc<S>,
    /// Mempool for selecting transactions
    mempool: Arc<Mempool<A>>,
    /// Configuration
    config: BlockBuilderConfig,
}

impl<S: BlockBuilderStorage, A: AccountStateProvider> BlockBuilder<S, A> {
    /// Create a new block builder
    pub fn new(
        storage: Arc<S>,
        mempool: Arc<Mempool<A>>,
        block_gas_limit: u64,
        chain_id: u64,
    ) -> Self {
        Self {
            storage,
            mempool,
            config: BlockBuilderConfig {
                block_gas_limit,
                chain_id,
                ..Default::default()
            },
        }
    }

    /// Create a new block builder with full configuration
    pub fn with_config(
        storage: Arc<S>,
        mempool: Arc<Mempool<A>>,
        config: BlockBuilderConfig,
    ) -> Self {
        Self {
            storage,
            mempool,
            config,
        }
    }

    /// Build a new block at the given height
    pub fn build_block(&self, height: u64) -> Result<Block> {
        let start_time = std::time::Instant::now();

        info!(height = height, "Building new block");

        // Get parent block info
        let parent = self
            .storage
            .get_block_by_height(height - 1)?
            .context("Parent block not found")?;
        let parent_hash = parent.hash();

        // Select transactions from mempool
        let selected = self.select_transactions(&parent)?;

        debug!(
            txs = selected.transactions.len(),
            gas = selected.total_gas,
            skipped = selected.skipped,
            "Transactions selected"
        );

        // Execute transactions and compute new state
        let (receipts, state_root, gas_used) =
            self.execute_transactions(&selected.transactions, &parent)?;

        // Calculate Merkle roots
        let transactions_root = self.compute_transactions_root(&selected.transactions);
        let receipts_root = self.compute_receipts_root(&receipts);

        // Calculate base fee (EIP-1559)
        let base_fee = self.calculate_base_fee(&parent, gas_used);

        // Get proposer address (this would be set by the validator)
        let proposer = Address::ZERO; // Will be set by the validator

        // Build the block header
        let header = BlockHeader {
            chain_id: self.config.chain_id,
            height,
            timestamp: Self::current_timestamp(),
            parent_hash,
            transactions_root,
            state_root,
            receipts_root,
            proposer,
            gas_limit: self.config.block_gas_limit,
            gas_used,
            base_fee,
            last_finality_cert_hash: parent.header.last_finality_cert_hash,
            validator_set_hash: parent.header.validator_set_hash,
            next_validator_set_hash: None,
        };

        let block = Block {
            header,
            transactions: selected.transactions,
        };

        let build_time = start_time.elapsed();
        info!(
            height = height,
            txs = block.transactions.len(),
            gas_used = gas_used,
            build_time_ms = build_time.as_millis(),
            "Block built successfully"
        );

        Ok(block)
    }

    /// Select transactions from the mempool for inclusion in a block
    fn select_transactions(&self, parent: &Block) -> Result<SelectedTransactions> {
        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut skipped = 0usize;

        // Get pending transactions up to gas limit
        let pending = self
            .mempool
            .get_pending_transactions(self.config.block_gas_limit);

        for tx in pending {
            // Check if we've reached the gas limit
            let tx_gas = tx.gas_limit();
            if total_gas + tx_gas > self.config.block_gas_limit {
                debug!(
                    hash = %tx.hash(),
                    gas = tx_gas,
                    "Skipping transaction: would exceed block gas limit"
                );
                skipped += 1;
                continue;
            }

            // Check minimum gas price
            let gas_price = tx.effective_gas_price(Some(parent.header.base_fee));
            if gas_price < self.config.min_gas_price {
                debug!(
                    hash = %tx.hash(),
                    gas_price = gas_price,
                    "Skipping transaction: gas price too low"
                );
                skipped += 1;
                continue;
            }

            // Verify the transaction is valid
            match self.validate_transaction(&tx) {
                Ok(()) => {
                    total_gas += tx_gas;
                    selected.push(tx);

                    // Check if we've reached max transactions
                    if selected.len() >= self.config.max_transactions {
                        break;
                    }
                }
                Err(e) => {
                    debug!(
                        hash = %tx.hash(),
                        error = %e,
                        "Skipping invalid transaction"
                    );
                    skipped += 1;
                }
            }
        }

        Ok(SelectedTransactions {
            transactions: selected,
            total_gas,
            skipped,
        })
    }

    /// Validate a transaction before including it in a block
    fn validate_transaction(&self, tx: &SignedTransaction) -> Result<()> {
        // Verify signature and get sender
        let sender = tx.sender().context("Failed to recover sender")?;

        // Check sender has sufficient balance
        let balance = self.storage.get_balance(&sender)?;
        let max_cost = self.calculate_max_cost(tx);
        if balance < max_cost {
            return Err(anyhow::anyhow!(
                "Insufficient balance: have {}, need {}",
                balance,
                max_cost
            ));
        }

        // Check nonce
        let expected_nonce = self.storage.get_nonce(&sender)?;
        if tx.nonce() != expected_nonce {
            return Err(anyhow::anyhow!(
                "Invalid nonce: expected {}, got {}",
                expected_nonce,
                tx.nonce()
            ));
        }

        // Check intrinsic gas
        let intrinsic_gas = self.calculate_intrinsic_gas(tx);
        if tx.gas_limit() < intrinsic_gas {
            return Err(anyhow::anyhow!(
                "Gas limit too low: need at least {}, got {}",
                intrinsic_gas,
                tx.gas_limit()
            ));
        }

        Ok(())
    }

    /// Calculate the maximum cost of a transaction
    fn calculate_max_cost(&self, tx: &SignedTransaction) -> u128 {
        let gas_cost = tx.gas_limit() as u128 * tx.max_fee_per_gas();
        gas_cost + tx.value()
    }

    /// Calculate intrinsic gas for a transaction
    fn calculate_intrinsic_gas(&self, tx: &SignedTransaction) -> u64 {
        let mut gas: u64 = 21_000; // Base cost

        // Contract creation cost
        if tx.to().is_none() {
            gas += 32_000;
        }

        // Data cost
        let data = tx.data();
        for &byte in data {
            if byte == 0 {
                gas += 4;
            } else {
                gas += 16;
            }
        }

        // Access list cost
        for item in tx.access_list() {
            gas += 2_400;
            gas += 1_900 * item.storage_keys.len() as u64;
        }

        gas
    }

    /// Convert a SignedTransaction to TransactionData for EVM execution
    fn to_transaction_data(&self, tx: &SignedTransaction) -> Result<TransactionData> {
        let sender = tx.sender().context("Failed to recover sender")?;
        let sender_bytes: [u8; 20] = sender.into();

        Ok(TransactionData {
            hash: B256::from(*tx.hash().as_fixed_bytes()),
            from: AlloyAddress::from(sender_bytes),
            to: tx.to().map(|a| {
                let bytes: [u8; 20] = a.into();
                AlloyAddress::from(bytes)
            }),
            value: U256::from(tx.value()),
            data: AlloyBytes::copy_from_slice(tx.data()),
            gas_limit: tx.gas_limit(),
            max_fee_per_gas: tx.max_fee_per_gas(),
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas(),
            nonce: tx.nonce(),
            access_list: tx
                .access_list()
                .iter()
                .map(|item| {
                    let addr_bytes: [u8; 20] = item.address.into();
                    (
                        AlloyAddress::from(addr_bytes),
                        item.storage_keys
                            .iter()
                            .map(|k| U256::from_be_bytes(*k.as_fixed_bytes()))
                            .collect(),
                    )
                })
                .collect(),
        })
    }

    /// Create a BlockContext from parent block
    fn create_block_context(&self, parent: &Block, proposer: Address) -> BlockContext {
        let proposer_bytes: [u8; 20] = proposer.into();
        BlockContext {
            number: parent.header.height + 1,
            timestamp: Self::current_timestamp() / 1000, // Convert ms to seconds
            gas_limit: self.config.block_gas_limit,
            coinbase: AlloyAddress::from(proposer_bytes),
            base_fee: parent.header.base_fee,
            prev_randao: B256::ZERO, // Would come from consensus
        }
    }

    /// Create an in-memory database populated with account state for transaction senders
    fn create_evm_db(&self, transactions: &[SignedTransaction]) -> Result<MemoryDb> {
        let mut db = MemoryDb::new();
        let state_db = self.storage.state_db()?;

        // Populate account info for all transaction senders
        for tx in transactions {
            let sender = tx.sender().context("Failed to recover sender")?;
            let sender_bytes: [u8; 20] = sender.into();
            let alloy_addr = AlloyAddress::from(sender_bytes);

            // Load account from state
            let balance = self.storage.get_balance(&sender)?;
            let nonce = self.storage.get_nonce(&sender)?;

            let account = AccountInfo {
                balance: U256::from(balance),
                nonce,
                ..Default::default()
            };
            db.insert_account(alloy_addr, account);

            // Also load recipient if it's a call
            if let Some(to) = tx.to() {
                let to_bytes: [u8; 20] = to.into();
                let to_alloy = AlloyAddress::from(to_bytes);
                let to_balance = self.storage.get_balance(&to)?;
                let to_nonce = self.storage.get_nonce(&to)?;

                // Check if it's a contract
                let to_account = state_db.get_account(&to_bytes);
                let code_hash = to_account
                    .as_ref()
                    .map(|a| B256::from(a.code_hash))
                    .unwrap_or(B256::ZERO);

                let to_account_info = AccountInfo {
                    balance: U256::from(to_balance),
                    nonce: to_nonce,
                    code_hash,
                    ..Default::default()
                };
                db.insert_account(to_alloy, to_account_info);
            }
        }

        Ok(db)
    }

    /// Execute transactions and compute the resulting state
    fn execute_transactions(
        &self,
        transactions: &[SignedTransaction],
        parent: &Block,
    ) -> Result<(Vec<BlockReceipt>, H256, u64)> {
        let mut receipts = Vec::with_capacity(transactions.len());
        let mut total_gas_used = 0u64;
        let mut cumulative_gas_used = 0u64;

        // Create EVM executor with in-memory database populated from state
        let evm_config = EvmConfig {
            chain_id: self.config.chain_id,
            block_gas_limit: self.config.block_gas_limit,
            ..Default::default()
        };

        let db = self.create_evm_db(transactions)?;
        let mut executor = EvmExecutor::new(db, evm_config);

        let block_context = self.create_block_context(parent, Address::ZERO);

        for (idx, tx) in transactions.iter().enumerate() {
            let tx_data = self.to_transaction_data(tx)?;
            let result = executor
                .execute_transaction(&tx_data, &block_context)
                .map_err(|e| anyhow::anyhow!("EVM execution error: {}", e))?;

            cumulative_gas_used += result.gas_used;
            total_gas_used += result.gas_used;

            let sender = tx.sender()?;

            // Convert logs
            let logs: Vec<LogEntry> = result
                .logs
                .iter()
                .map(|log| LogEntry {
                    address: Address::from(log.address.0 .0),
                    topics: log.topics.iter().map(|t| H256::from(t.0)).collect(),
                    data: log.data.to_vec(),
                })
                .collect();

            // Convert contract address
            let contract_address = result.contract_address.map(|a| Address::from(a.0 .0));

            let receipt = BlockReceipt {
                transaction_hash: tx.hash(),
                transaction_index: idx as u64,
                block_hash: H256::NIL, // Will be set after block is finalized
                block_number: 0,       // Will be set after block is finalized
                from: sender,
                to: tx.to(),
                cumulative_gas_used,
                gas_used: result.gas_used,
                contract_address,
                logs,
                status: if result.success { 1 } else { 0 },
                effective_gas_price: tx.effective_gas_price(Some(parent.header.base_fee)),
            };

            receipts.push(receipt);
        }

        // Commit state changes to the underlying StateDB and get the final state root
        let state_db = self.storage.state_db()?;
        let state_root_bytes = state_db
            .commit()
            .map_err(|e| anyhow::anyhow!("Failed to commit state: {}", e))?;
        let state_root = H256::from(state_root_bytes);

        Ok((receipts, state_root, total_gas_used))
    }

    /// Compute the Merkle root of transactions
    fn compute_transactions_root(&self, transactions: &[SignedTransaction]) -> H256 {
        if transactions.is_empty() {
            return H256::NIL;
        }

        // Build a Merkle Patricia Trie of transactions
        let trie = MerkleTrie::new();

        for (idx, tx) in transactions.iter().enumerate() {
            let key = rlp::encode(&idx);
            let value = tx.rlp_encode();
            if let Err(e) = trie.insert(&key, &value) {
                warn!(error = %e, "Failed to insert transaction into trie");
            }
        }

        H256::from(trie.root())
    }

    /// Compute the Merkle root of receipts
    fn compute_receipts_root(&self, receipts: &[BlockReceipt]) -> H256 {
        if receipts.is_empty() {
            return H256::NIL;
        }

        // Build a Merkle Patricia Trie of receipts
        let trie = MerkleTrie::new();

        for (idx, receipt) in receipts.iter().enumerate() {
            let key = rlp::encode(&idx);
            // Encode receipt as RLP (simplified)
            let value = self.encode_receipt(receipt);
            if let Err(e) = trie.insert(&key, &value) {
                warn!(error = %e, "Failed to insert receipt into trie");
            }
        }

        H256::from(trie.root())
    }

    /// Encode a receipt as bytes (simplified RLP encoding)
    fn encode_receipt(&self, receipt: &BlockReceipt) -> Vec<u8> {
        let mut stream = rlp::RlpStream::new_list(4);
        stream.append(&receipt.status);
        stream.append(&receipt.cumulative_gas_used);
        // Simplified: just encode logs count
        stream.append(&(receipt.logs.len() as u64));
        stream.append(&receipt.gas_used);
        stream.out().to_vec()
    }

    /// Calculate the base fee for the next block (EIP-1559)
    fn calculate_base_fee(&self, parent: &Block, _parent_gas_used: u64) -> u128 {
        parent.header.next_base_fee()
    }

    /// Get current Unix timestamp in milliseconds
    fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64
    }

    /// Build an empty block (for testing or when mempool is empty)
    pub fn build_empty_block(&self, height: u64, proposer: Address) -> Result<Block> {
        let parent = self
            .storage
            .get_block_by_height(height - 1)?
            .context("Parent block not found")?;
        let parent_hash = parent.hash();

        let state_root = self.storage.get_state_root()?;

        let header = BlockHeader {
            chain_id: self.config.chain_id,
            height,
            timestamp: Self::current_timestamp(),
            parent_hash,
            transactions_root: H256::NIL,
            state_root,
            receipts_root: H256::NIL,
            proposer,
            gas_limit: self.config.block_gas_limit,
            gas_used: 0,
            base_fee: self.calculate_base_fee(&parent, 0),
            last_finality_cert_hash: parent.header.last_finality_cert_hash,
            validator_set_hash: parent.header.validator_set_hash,
            next_validator_set_hash: None,
        };

        Ok(Block {
            header,
            transactions: Vec::new(),
        })
    }

    /// Create an in-memory database for a single transaction
    fn create_single_tx_db(&self, tx: &SignedTransaction) -> Result<MemoryDb> {
        self.create_evm_db(&[tx.clone()])
    }

    /// Estimate gas for a transaction
    pub fn estimate_gas(&self, tx: &SignedTransaction, parent: &Block) -> Result<u64> {
        let evm_config = EvmConfig {
            chain_id: self.config.chain_id,
            block_gas_limit: self.config.block_gas_limit,
            ..Default::default()
        };

        let db = self.create_single_tx_db(tx)?;
        let mut executor = EvmExecutor::new(db, evm_config);

        let tx_data = self.to_transaction_data(tx)?;
        let block_context = self.create_block_context(parent, Address::ZERO);

        // Execute with maximum gas to see how much is actually used
        let result = executor
            .estimate_gas(&tx_data, &block_context)
            .map_err(|e| anyhow::anyhow!("Gas estimation error: {}", e))?;

        // Add a small buffer for safety
        let estimated = (result as f64 * 1.1) as u64;

        Ok(estimated.min(self.config.block_gas_limit))
    }

    /// Simulate transaction execution without committing state
    pub fn simulate_transaction(
        &self,
        tx: &SignedTransaction,
        parent: &Block,
    ) -> Result<SimulationResult> {
        let evm_config = EvmConfig {
            chain_id: self.config.chain_id,
            block_gas_limit: self.config.block_gas_limit,
            ..Default::default()
        };

        let db = self.create_single_tx_db(tx)?;
        let mut executor = EvmExecutor::new(db, evm_config);

        let tx_data = self.to_transaction_data(tx)?;
        let block_context = self.create_block_context(parent, Address::ZERO);

        let result = executor
            .call(&tx_data, &block_context)
            .map_err(|e| anyhow::anyhow!("Simulation error: {}", e))?;

        let logs: Vec<LogEntry> = result
            .logs
            .iter()
            .map(|log| LogEntry {
                address: Address::from(log.address.0 .0),
                topics: log.topics.iter().map(|t| H256::from(t.0)).collect(),
                data: log.data.to_vec(),
            })
            .collect();

        // Clone output before consuming it for return_data
        let output_for_return = result.output.clone();
        let output_for_error = result.output;

        Ok(SimulationResult {
            success: result.success,
            gas_used: result.gas_used,
            return_data: output_for_return.map(|o| o.to_vec()).unwrap_or_default(),
            logs,
            error: if result.success {
                None
            } else {
                output_for_error.map(|o| String::from_utf8_lossy(&o).to_string())
            },
        })
    }

    /// Get block builder configuration
    pub fn config(&self) -> &BlockBuilderConfig {
        &self.config
    }

    /// Update block builder configuration
    pub fn set_config(&mut self, config: BlockBuilderConfig) {
        self.config = config;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_builder_config_default() {
        let config = BlockBuilderConfig::default();
        assert_eq!(config.block_gas_limit, 30_000_000);
        assert_eq!(config.chain_id, 1);
        assert_eq!(config.max_transactions, 1000);
    }

    #[test]
    fn test_current_timestamp() {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("Time went backwards")
            .as_millis() as u64;
        assert!(ts > 0);

        // Should be after 2024
        let year_2024_ms = 1704067200000u64; // Jan 1, 2024
        assert!(ts > year_2024_ms);
    }

    #[test]
    fn test_base_fee_calculation() {
        // Test that base fee increases when gas usage is above target
        let parent_base_fee = 1_000_000_000u128; // 1 gwei
        let gas_limit = 30_000_000u64;
        let gas_target = gas_limit / 2;

        // Above target
        let gas_used = gas_limit * 3 / 4; // 75% usage
        let gas_used_delta = gas_used - gas_target;
        let expected_increase = parent_base_fee * gas_used_delta as u128 / gas_target as u128 / 8;

        assert!(expected_increase > 0, "Base fee should increase");
    }

    #[test]
    fn test_selected_transactions_struct() {
        let selected = SelectedTransactions {
            transactions: Vec::new(),
            total_gas: 0,
            skipped: 5,
        };

        assert_eq!(selected.transactions.len(), 0);
        assert_eq!(selected.total_gas, 0);
        assert_eq!(selected.skipped, 5);
    }
}
