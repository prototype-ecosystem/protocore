//! EVM Executor
//!
//! This module provides the main EVM execution engine that wraps revm
//! for executing transactions and blocks.

use alloy_primitives::{Address as AlloyAddress, Bytes, B256, U256};
use revm::{
    primitives::{
        BlockEnv, CfgEnv, Env, EnvWithHandlerCfg, ExecutionResult, HandlerCfg, Output, SpecId,
        TransactTo, TxEnv,
    },
    Database, DatabaseCommit, Evm,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

use crate::{
    gas::{BaseFeeCalculator, GasConfig},
    precompiles::PrecompileRegistry,
    state_adapter::{StateAdapter, StateRootProvider},
    BLOCKS_PER_EPOCH, DEFAULT_BLOCK_GAS_LIMIT, MAINNET_CHAIN_ID,
};

/// Errors that can occur during EVM execution
#[derive(Error, Debug)]
pub enum ExecutionError {
    /// Transaction failed validation
    #[error("transaction validation failed: {0}")]
    ValidationFailed(String),

    /// Insufficient balance for transaction
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance {
        /// Required balance
        required: U256,
        /// Available balance
        available: U256,
    },

    /// Nonce mismatch
    #[error("nonce mismatch: expected {expected}, got {actual}")]
    NonceMismatch {
        /// Expected nonce
        expected: u64,
        /// Actual nonce
        actual: u64,
    },

    /// Gas limit exceeded block limit
    #[error("gas limit {tx_gas} exceeds block limit {block_limit}")]
    GasLimitExceeded {
        /// Transaction gas limit
        tx_gas: u64,
        /// Block gas limit
        block_limit: u64,
    },

    /// Block gas limit exceeded
    #[error("block gas limit exceeded")]
    BlockGasLimitExceeded,

    /// EVM execution error
    #[error("EVM execution error: {0}")]
    EvmError(String),

    /// Precompile error
    #[error("precompile error: {0}")]
    PrecompileError(#[from] crate::precompiles::PrecompileError),

    /// State database error
    #[error("state database error: {0}")]
    StateError(String),

    /// Invalid sender address
    #[error("invalid sender address: {0}")]
    InvalidSender(String),

    /// Contract creation failed
    #[error("contract creation failed: {0}")]
    ContractCreationFailed(String),

    /// Revert with data
    #[error("execution reverted")]
    Reverted(Bytes),
}

/// EVM executor configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmConfig {
    /// Chain ID
    pub chain_id: u64,
    /// Block gas limit
    pub block_gas_limit: u64,
    /// Gas configuration
    pub gas_config: GasConfig,
    /// EVM specification ID (determines which hardfork rules to use)
    pub spec_id: SpecIdWrapper,
}

/// Wrapper for revm SpecId to implement Serialize/Deserialize
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum SpecIdWrapper {
    /// Cancun hardfork
    Cancun,
    /// Shanghai hardfork
    Shanghai,
    /// Paris (The Merge)
    Paris,
    /// London (EIP-1559)
    London,
}

impl From<SpecIdWrapper> for SpecId {
    fn from(wrapper: SpecIdWrapper) -> Self {
        match wrapper {
            SpecIdWrapper::Cancun => SpecId::CANCUN,
            SpecIdWrapper::Shanghai => SpecId::SHANGHAI,
            SpecIdWrapper::Paris => SpecId::MERGE,
            SpecIdWrapper::London => SpecId::LONDON,
        }
    }
}

impl Default for EvmConfig {
    fn default() -> Self {
        Self::mainnet()
    }
}

impl EvmConfig {
    /// Create configuration for Proto Core mainnet
    pub fn mainnet() -> Self {
        Self {
            chain_id: MAINNET_CHAIN_ID,
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            gas_config: GasConfig::default(),
            spec_id: SpecIdWrapper::Cancun,
        }
    }

    /// Create configuration for Proto Core testnet
    pub fn testnet() -> Self {
        Self {
            chain_id: crate::TESTNET_CHAIN_ID,
            block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            gas_config: GasConfig::default(),
            spec_id: SpecIdWrapper::Cancun,
        }
    }
}

/// Result of executing a single transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionResult {
    /// Whether execution succeeded
    pub success: bool,
    /// Gas used by the transaction
    pub gas_used: u64,
    /// Gas refunded
    pub gas_refunded: u64,
    /// Output data (return value or revert reason)
    pub output: Option<Bytes>,
    /// Contract address if deployment
    pub contract_address: Option<AlloyAddress>,
    /// Logs emitted during execution
    pub logs: Vec<Log>,
}

/// Event log emitted during execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Contract address that emitted the log
    pub address: AlloyAddress,
    /// Log topics (first is event signature hash)
    pub topics: Vec<B256>,
    /// Log data
    pub data: Bytes,
}

impl From<revm::primitives::Log> for Log {
    fn from(log: revm::primitives::Log) -> Self {
        Self {
            address: log.address,
            topics: log.data.topics().to_vec(),
            data: log.data.data.clone(),
        }
    }
}

/// Result of executing an entire block
#[derive(Debug, Clone)]
pub struct BlockExecutionResult {
    /// State root after execution
    pub state_root: B256,
    /// Receipts root
    pub receipts_root: B256,
    /// Logs bloom filter
    pub logs_bloom: Vec<u8>,
    /// Transaction receipts
    pub receipts: Vec<Receipt>,
    /// Total gas used in block
    pub gas_used: u64,
}

/// Transaction receipt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    /// Transaction hash
    pub tx_hash: B256,
    /// Transaction index in block
    pub tx_index: u64,
    /// Cumulative gas used up to this transaction
    pub cumulative_gas_used: u64,
    /// Gas used by this transaction
    pub gas_used: u64,
    /// Effective gas price paid
    pub effective_gas_price: u128,
    /// Contract address created (if any)
    pub contract_address: Option<AlloyAddress>,
    /// Logs emitted
    pub logs: Vec<Log>,
    /// Logs bloom filter
    pub logs_bloom: Vec<u8>,
    /// Status code (1 = success, 0 = failure)
    pub status: u8,
}

/// Block header information needed for execution
#[derive(Debug, Clone)]
pub struct BlockContext {
    /// Block number/height
    pub number: u64,
    /// Block timestamp (seconds since epoch)
    pub timestamp: u64,
    /// Block gas limit
    pub gas_limit: u64,
    /// Block coinbase (proposer address)
    pub coinbase: AlloyAddress,
    /// Base fee per gas (EIP-1559)
    pub base_fee: u128,
    /// Previous block's RANDAO mix (for PREVRANDAO opcode)
    pub prev_randao: B256,
}

/// Transaction data for execution
#[derive(Debug, Clone)]
pub struct TransactionData {
    /// Transaction hash
    pub hash: B256,
    /// Sender address (recovered from signature)
    pub from: AlloyAddress,
    /// Recipient address (None for contract creation)
    pub to: Option<AlloyAddress>,
    /// Value to transfer in wei
    pub value: U256,
    /// Input data (calldata or init code)
    pub data: Bytes,
    /// Gas limit
    pub gas_limit: u64,
    /// Max fee per gas (EIP-1559)
    pub max_fee_per_gas: u128,
    /// Max priority fee per gas (EIP-1559)
    pub max_priority_fee_per_gas: u128,
    /// Sender nonce
    pub nonce: u64,
    /// Access list for EIP-2930
    pub access_list: Vec<(AlloyAddress, Vec<U256>)>,
}

/// EVM Executor that wraps revm
pub struct EvmExecutor<DB: Database + DatabaseCommit + StateRootProvider> {
    /// Configuration
    config: EvmConfig,
    /// State database adapter
    db: StateAdapter<DB>,
    /// Precompile registry
    precompiles: PrecompileRegistry,
    /// Base fee calculator
    base_fee_calculator: BaseFeeCalculator,
}

impl<DB: Database + DatabaseCommit + StateRootProvider> EvmExecutor<DB>
where
    DB::Error: std::fmt::Debug,
{
    /// Create a new EVM executor
    pub fn new(db: DB, config: EvmConfig) -> Self {
        let base_fee_calculator = BaseFeeCalculator::new(config.gas_config.clone());
        Self {
            config,
            db: StateAdapter::new(db),
            precompiles: PrecompileRegistry::default(),
            base_fee_calculator,
        }
    }

    /// Get the chain ID
    pub fn chain_id(&self) -> u64 {
        self.config.chain_id
    }

    /// Get mutable reference to the database
    pub fn db_mut(&mut self) -> &mut StateAdapter<DB> {
        &mut self.db
    }

    /// Get reference to the database
    pub fn db(&self) -> &StateAdapter<DB> {
        &self.db
    }

    /// Execute a single transaction
    pub fn execute_transaction(
        &mut self,
        tx: &TransactionData,
        block: &BlockContext,
    ) -> Result<TransactionResult, ExecutionError> {
        trace!(
            tx_hash = %tx.hash,
            from = %tx.from,
            to = ?tx.to,
            value = %tx.value,
            "Executing transaction"
        );

        // Check if this is a Proto Core system precompile call
        // Note: Standard Ethereum precompiles (0x01-0x09) are handled by revm,
        // we only intercept Proto Core precompiles (staking, slashing, governance)
        if let Some(to) = tx.to {
            if self.is_protocore_precompile(to) {
                return self.execute_precompile(tx, block, to);
            }
        }

        // Build EVM environment
        let env = self.build_env(tx, block);

        // Create and run EVM
        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut self.db)
                .with_env_with_handler_cfg(env)
                .build();

            evm.transact_commit()
                .map_err(|e| ExecutionError::EvmError(format!("{:?}", e)))?
        };

        // Convert result
        let tx_result = self.convert_execution_result(result);

        debug!(
            tx_hash = %tx.hash,
            success = tx_result.success,
            gas_used = tx_result.gas_used,
            "Transaction executed"
        );

        Ok(tx_result)
    }

    /// Execute all transactions in a block
    ///
    /// For empty blocks (no transactions), this skips EVM execution entirely
    /// and returns immediately with the current state root, saving computation.
    pub fn execute_block(
        &mut self,
        transactions: &[TransactionData],
        block: &BlockContext,
    ) -> Result<BlockExecutionResult, ExecutionError> {
        info!(
            block_number = block.number,
            tx_count = transactions.len(),
            "Executing block"
        );

        // Fast path for empty blocks - skip EVM execution entirely
        if transactions.is_empty() {
            debug!(
                block_number = block.number,
                "Empty block - skipping EVM execution"
            );

            // Still need to process end-of-block operations (epoch transitions, etc.)
            self.process_end_of_block(block)?;

            // Get current state root without any state changes
            let state_root = self.compute_state_root();

            return Ok(BlockExecutionResult {
                state_root,
                receipts_root: B256::ZERO, // Empty receipts root
                logs_bloom: vec![0u8; 256],
                receipts: Vec::new(),
                gas_used: 0,
            });
        }

        let mut receipts = Vec::with_capacity(transactions.len());
        let mut cumulative_gas_used = 0u64;

        for (idx, tx) in transactions.iter().enumerate() {
            // Check block gas limit
            if cumulative_gas_used + tx.gas_limit > block.gas_limit {
                warn!(
                    tx_index = idx,
                    cumulative_gas = cumulative_gas_used,
                    tx_gas = tx.gas_limit,
                    block_limit = block.gas_limit,
                    "Transaction would exceed block gas limit"
                );
                return Err(ExecutionError::BlockGasLimitExceeded);
            }

            // Execute transaction
            let result = self.execute_transaction(tx, block)?;

            cumulative_gas_used += result.gas_used;

            // Calculate effective gas price
            let priority_fee = std::cmp::min(
                tx.max_priority_fee_per_gas,
                tx.max_fee_per_gas.saturating_sub(block.base_fee),
            );
            let effective_gas_price = block.base_fee + priority_fee;

            // Build receipt
            // Note: compute logs_bloom for this transaction's logs before moving them
            let tx_logs_bloom = self.compute_logs_bloom(&result.logs);
            let receipt = Receipt {
                tx_hash: tx.hash,
                tx_index: idx as u64,
                cumulative_gas_used,
                gas_used: result.gas_used,
                effective_gas_price,
                contract_address: result.contract_address,
                logs: result.logs,
                logs_bloom: tx_logs_bloom,
                status: if result.success { 1 } else { 0 },
            };

            receipts.push(receipt);
        }

        // Process end-of-block operations
        self.process_end_of_block(block)?;

        // Compute state root (implementation depends on storage backend)
        let state_root = self.compute_state_root();
        let receipts_root = self.compute_receipts_root(&receipts);
        let logs_bloom = self.compute_block_logs_bloom(&receipts);

        info!(
            block_number = block.number,
            gas_used = cumulative_gas_used,
            receipts = receipts.len(),
            "Block execution complete"
        );

        Ok(BlockExecutionResult {
            state_root,
            receipts_root,
            logs_bloom,
            receipts,
            gas_used: cumulative_gas_used,
        })
    }

    /// Execute a call (read-only, no state changes)
    pub fn call(
        &mut self,
        tx: &TransactionData,
        block: &BlockContext,
    ) -> Result<TransactionResult, ExecutionError> {
        trace!(
            from = %tx.from,
            to = ?tx.to,
            "Executing call"
        );

        // Build EVM environment
        let env = self.build_env(tx, block);

        // Create EVM in simulation mode (no commit)
        let result = {
            let mut evm = Evm::builder()
                .with_db(&mut self.db)
                .with_env_with_handler_cfg(env)
                .build();

            evm.transact()
                .map_err(|e| ExecutionError::EvmError(format!("{:?}", e)))?
        };

        Ok(self.convert_execution_result(result.result))
    }

    /// Estimate gas for a transaction
    pub fn estimate_gas(
        &mut self,
        tx: &TransactionData,
        block: &BlockContext,
    ) -> Result<u64, ExecutionError> {
        // Start with the transaction's gas limit as upper bound
        let mut upper_bound = tx.gas_limit;
        let mut lower_bound = 21000u64; // Minimum transaction gas

        // Binary search for minimum gas
        while lower_bound + 1 < upper_bound {
            let mid = (lower_bound + upper_bound) / 2;

            let mut test_tx = tx.clone();
            test_tx.gas_limit = mid;

            match self.call(&test_tx, block) {
                Ok(result) if result.success => {
                    upper_bound = mid;
                }
                _ => {
                    lower_bound = mid;
                }
            }
        }

        // Add 10% buffer for safety
        let estimated = upper_bound + (upper_bound / 10);
        Ok(std::cmp::min(estimated, tx.gas_limit))
    }

    /// Check if an address is a precompile (standard or Proto Core)
    fn is_precompile_address(&self, address: AlloyAddress) -> bool {
        // Standard Ethereum precompiles (0x01 - 0x09)
        let addr_bytes = address.0 .0;
        if addr_bytes[..18].iter().all(|&b| b == 0) {
            let low_bytes = u16::from_be_bytes([addr_bytes[18], addr_bytes[19]]);
            if (1..=9).contains(&low_bytes) {
                return true;
            }
            // Proto Core precompiles (0x1000 - 0x1002)
            if (0x1000..=0x1002).contains(&low_bytes) {
                return true;
            }
        }
        false
    }

    /// Check if an address is a Proto Core system precompile (not standard Ethereum)
    ///
    /// Proto Core precompiles (staking, slashing, governance) need custom handling,
    /// while standard Ethereum precompiles (0x01-0x09) are handled by revm.
    fn is_protocore_precompile(&self, address: AlloyAddress) -> bool {
        let addr_bytes = address.0 .0;
        if addr_bytes[..18].iter().all(|&b| b == 0) {
            let low_bytes = u16::from_be_bytes([addr_bytes[18], addr_bytes[19]]);
            // Only Proto Core precompiles (0x1000 - 0x1002)
            return (0x1000..=0x1002).contains(&low_bytes);
        }
        false
    }

    /// Execute a precompile call
    fn execute_precompile(
        &mut self,
        tx: &TransactionData,
        block: &BlockContext,
        precompile_address: AlloyAddress,
    ) -> Result<TransactionResult, ExecutionError> {
        trace!(
            precompile = %precompile_address,
            "Executing precompile"
        );

        let output = self.precompiles.execute(
            precompile_address,
            tx.from,
            &tx.data,
            tx.value,
            block.number,
            &mut self.db,
        )?;

        // Calculate gas used (precompile gas + base tx gas)
        let gas_used = output.gas_used + 21000;

        Ok(TransactionResult {
            success: true,
            gas_used,
            gas_refunded: 0,
            output: Some(output.output),
            contract_address: None,
            logs: output.logs.into_iter().map(Log::from).collect(),
        })
    }

    /// Build EVM environment from transaction and block context
    fn build_env(&self, tx: &TransactionData, block: &BlockContext) -> EnvWithHandlerCfg {
        let mut cfg = CfgEnv::default();
        cfg.chain_id = self.config.chain_id;

        let block_env = BlockEnv {
            number: U256::from(block.number),
            timestamp: U256::from(block.timestamp),
            gas_limit: U256::from(block.gas_limit),
            coinbase: block.coinbase,
            basefee: U256::from(block.base_fee),
            prevrandao: Some(block.prev_randao),
            ..Default::default()
        };

        let tx_env = TxEnv {
            caller: tx.from,
            gas_limit: tx.gas_limit,
            gas_price: U256::from(tx.max_fee_per_gas),
            gas_priority_fee: Some(U256::from(tx.max_priority_fee_per_gas)),
            transact_to: match tx.to {
                Some(addr) => TransactTo::Call(addr),
                None => TransactTo::Create,
            },
            value: tx.value,
            data: tx.data.clone(),
            chain_id: Some(self.config.chain_id),
            nonce: Some(tx.nonce),
            access_list: tx
                .access_list
                .iter()
                .map(|(addr, keys)| revm::primitives::AccessListItem {
                    address: *addr,
                    storage_keys: keys.iter().map(|k| B256::from(*k)).collect(),
                })
                .collect(),
            ..Default::default()
        };

        let env = Env {
            cfg,
            block: block_env,
            tx: tx_env,
        };

        let handler_cfg = HandlerCfg::new(self.config.spec_id.into());
        EnvWithHandlerCfg::new(Box::new(env), handler_cfg)
    }

    /// Convert revm ExecutionResult to our TransactionResult
    fn convert_execution_result(&self, result: ExecutionResult) -> TransactionResult {
        match result {
            ExecutionResult::Success {
                output,
                gas_used,
                gas_refunded,
                logs,
                ..
            } => {
                let (output_data, contract_address) = match output {
                    Output::Create(bytes, addr) => (Some(bytes), addr),
                    Output::Call(bytes) => (Some(bytes), None),
                };

                TransactionResult {
                    success: true,
                    gas_used,
                    gas_refunded,
                    output: output_data,
                    contract_address,
                    logs: logs.into_iter().map(Log::from).collect(),
                }
            }
            ExecutionResult::Revert { output, gas_used } => TransactionResult {
                success: false,
                gas_used,
                gas_refunded: 0,
                output: Some(output),
                contract_address: None,
                logs: vec![],
            },
            ExecutionResult::Halt { gas_used, .. } => TransactionResult {
                success: false,
                gas_used,
                gas_refunded: 0,
                output: None,
                contract_address: None,
                logs: vec![],
            },
        }
    }

    /// Process end-of-block operations
    fn process_end_of_block(&mut self, block: &BlockContext) -> Result<(), ExecutionError> {
        // Block reward distribution would happen here
        // For now, this is handled by the consensus layer

        // Epoch processing
        if block.number % BLOCKS_PER_EPOCH == 0 {
            self.process_epoch_end(block.number)?;
        }

        Ok(())
    }

    /// Process end-of-epoch operations
    fn process_epoch_end(&mut self, _block_number: u64) -> Result<(), ExecutionError> {
        debug!("Processing epoch end");
        // Epoch-specific operations:
        // - Reward distribution
        // - Validator set rotation
        // - Unbonding completion
        Ok(())
    }

    /// Compute logs bloom filter for logs
    ///
    /// Implements Ethereum's 2048-bit bloom filter as specified in the Yellow Paper.
    /// Each item (address or topic) sets 3 bits determined by the first 6 bytes
    /// of its Keccak256 hash.
    fn compute_logs_bloom(&self, logs: &[Log]) -> Vec<u8> {
        let mut bloom = vec![0u8; 256];

        for log in logs {
            // Add address to bloom
            Self::add_to_bloom(&mut bloom, log.address.as_slice());

            // Add each topic to bloom
            for topic in &log.topics {
                Self::add_to_bloom(&mut bloom, topic.as_slice());
            }
        }

        bloom
    }

    /// Add a single item to a bloom filter
    ///
    /// Uses Keccak256 hash and takes 3 pairs of 2 bytes to determine which bits to set.
    fn add_to_bloom(bloom: &mut [u8], item: &[u8]) {
        use sha3::{Digest, Keccak256};

        let hash = Keccak256::digest(item);

        // Set 3 bits based on hash[0:1], hash[2:3], hash[4:5]
        for i in 0..3 {
            let byte_pair_start = i * 2;
            // Take 11 bits from each pair to determine bit position (0-2047)
            let bit_pos = ((hash[byte_pair_start] as usize & 0x07) << 8)
                | (hash[byte_pair_start + 1] as usize);
            // Convert to byte index and bit within byte
            let byte_idx = 255 - (bit_pos / 8);
            let bit_idx = bit_pos % 8;
            bloom[byte_idx] |= 1 << bit_idx;
        }
    }

    /// Compute logs bloom filter for an entire block
    fn compute_block_logs_bloom(&self, receipts: &[Receipt]) -> Vec<u8> {
        let mut bloom = vec![0u8; 256];
        for receipt in receipts {
            for (i, byte) in receipt.logs_bloom.iter().enumerate() {
                if i < 256 {
                    bloom[i] |= byte;
                }
            }
        }
        bloom
    }

    /// Compute state root after execution
    ///
    /// Returns the current state root from the underlying database.
    /// For MemoryDb, this computes a hash of all accounts.
    /// For production StateDB, this returns the MPT root.
    ///
    /// Note: The caller should ensure all pending changes are committed
    /// before calling this method to get the accurate post-execution root.
    fn compute_state_root(&self) -> B256 {
        self.db.state_root()
    }

    /// Compute receipts root using RLP-encoded receipts
    ///
    /// Computes a Keccak256 hash of the RLP-encoded receipt list.
    /// Note: For full Ethereum compatibility, this should use an ordered trie
    /// with receipt indices as keys.
    fn compute_receipts_root(&self, receipts: &[Receipt]) -> B256 {
        use sha3::{Digest, Keccak256};

        if receipts.is_empty() {
            // Empty trie root (keccak256 of RLP empty string)
            return B256::from_slice(&[
                0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
                0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
                0xe3, 0x63, 0xb4, 0x21,
            ]);
        }

        // Encode receipts using a simple concatenation scheme
        // Note: Full Ethereum compatibility requires MPT with index keys
        let mut hasher = Keccak256::new();
        for (i, receipt) in receipts.iter().enumerate() {
            // Encode receipt fields
            hasher.update([receipt.status]);
            hasher.update(receipt.cumulative_gas_used.to_le_bytes());
            hasher.update(&receipt.logs_bloom);
            hasher.update((receipt.logs.len() as u32).to_le_bytes());
            for log in &receipt.logs {
                hasher.update(log.address.as_slice());
                hasher.update((log.topics.len() as u32).to_le_bytes());
                for topic in &log.topics {
                    hasher.update(topic.as_slice());
                }
                hasher.update((log.data.len() as u32).to_le_bytes());
                hasher.update(&log.data);
            }
            // Include index for ordering
            hasher.update((i as u32).to_le_bytes());
        }

        B256::from_slice(&hasher.finalize())
    }

    /// Calculate the next block's base fee
    pub fn calculate_next_base_fee(
        &self,
        parent_gas_used: u64,
        parent_gas_limit: u64,
        parent_base_fee: u128,
    ) -> u128 {
        self.base_fee_calculator.calculate_next_base_fee(
            parent_gas_used,
            parent_gas_limit,
            parent_base_fee,
        )
    }
}
