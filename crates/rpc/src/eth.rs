//! Ethereum-compatible JSON-RPC methods.
//!
//! This module implements the standard Ethereum JSON-RPC API (eth_* methods)
//! for MetaMask and other wallet compatibility.

use crate::types::*;
use crate::RpcError;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use parking_lot::RwLock;
use std::sync::Arc;
use tracing::{debug, info, instrument, warn};

// ============================================================================
// Ethereum RPC API Trait Definition
// ============================================================================

/// Ethereum-compatible JSON-RPC API.
///
/// This trait defines all the standard Ethereum RPC methods required
/// for MetaMask and other wallet compatibility.
#[rpc(server, namespace = "eth")]
pub trait EthApi {
    /// Returns the chain ID (EIP-155).
    ///
    /// # Returns
    /// Hex-encoded chain ID.
    #[method(name = "chainId")]
    async fn chain_id(&self) -> RpcResult<String>;

    /// Returns the current block number.
    ///
    /// # Returns
    /// Hex-encoded block number.
    #[method(name = "blockNumber")]
    async fn block_number(&self) -> RpcResult<String>;

    /// Returns the balance of an account.
    ///
    /// # Arguments
    /// * `address` - Account address
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded balance in wei.
    #[method(name = "getBalance")]
    async fn get_balance(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<String>;

    /// Returns the number of transactions sent from an address (nonce).
    ///
    /// # Arguments
    /// * `address` - Account address
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded transaction count.
    #[method(name = "getTransactionCount")]
    async fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumberOrTag,
    ) -> RpcResult<String>;

    /// Submits a signed transaction to the network.
    ///
    /// # Arguments
    /// * `data` - Hex-encoded signed transaction data
    ///
    /// # Returns
    /// Transaction hash.
    #[method(name = "sendRawTransaction")]
    async fn send_raw_transaction(&self, data: HexBytes) -> RpcResult<H256>;

    /// Executes a call without creating a transaction.
    ///
    /// # Arguments
    /// * `tx` - Call request parameters
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded return data.
    #[method(name = "call")]
    async fn call(&self, tx: CallRequest, block: BlockNumberOrTag) -> RpcResult<String>;

    /// Estimates the gas required for a transaction.
    ///
    /// # Arguments
    /// * `tx` - Call request parameters
    /// * `block` - Optional block number or tag
    ///
    /// # Returns
    /// Hex-encoded gas estimate.
    #[method(name = "estimateGas")]
    async fn estimate_gas(
        &self,
        tx: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<String>;

    /// Returns a block by number.
    ///
    /// # Arguments
    /// * `block` - Block number or tag
    /// * `full` - Whether to return full transaction objects
    ///
    /// # Returns
    /// Block object or null if not found.
    #[method(name = "getBlockByNumber")]
    async fn get_block_by_number(
        &self,
        block: BlockNumberOrTag,
        full: bool,
    ) -> RpcResult<Option<RpcBlock>>;

    /// Returns a block by hash.
    ///
    /// # Arguments
    /// * `hash` - Block hash
    /// * `full` - Whether to return full transaction objects
    ///
    /// # Returns
    /// Block object or null if not found.
    #[method(name = "getBlockByHash")]
    async fn get_block_by_hash(&self, hash: H256, full: bool) -> RpcResult<Option<RpcBlock>>;

    /// Returns a transaction by hash.
    ///
    /// # Arguments
    /// * `hash` - Transaction hash
    ///
    /// # Returns
    /// Transaction object or null if not found.
    #[method(name = "getTransactionByHash")]
    async fn get_transaction_by_hash(&self, hash: H256) -> RpcResult<Option<RpcTransaction>>;

    /// Returns the receipt of a transaction.
    ///
    /// # Arguments
    /// * `hash` - Transaction hash
    ///
    /// # Returns
    /// Receipt object or null if not found.
    #[method(name = "getTransactionReceipt")]
    async fn get_transaction_receipt(&self, hash: H256) -> RpcResult<Option<RpcReceipt>>;

    /// Returns the code at an address.
    ///
    /// # Arguments
    /// * `address` - Contract address
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded bytecode or "0x" if no code.
    #[method(name = "getCode")]
    async fn get_code(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<String>;

    /// Returns the value from a storage position.
    ///
    /// # Arguments
    /// * `address` - Contract address
    /// * `position` - Storage position
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded 32-byte value.
    #[method(name = "getStorageAt")]
    async fn get_storage_at(
        &self,
        address: Address,
        position: H256,
        block: BlockNumberOrTag,
    ) -> RpcResult<String>;

    /// Returns the current gas price.
    ///
    /// # Returns
    /// Hex-encoded gas price in wei.
    #[method(name = "gasPrice")]
    async fn gas_price(&self) -> RpcResult<String>;

    /// Returns logs matching a filter.
    ///
    /// # Arguments
    /// * `filter` - Log filter parameters
    ///
    /// # Returns
    /// Array of log objects.
    #[method(name = "getLogs")]
    async fn get_logs(&self, filter: LogFilter) -> RpcResult<Vec<RpcLog>>;

    /// Returns the fee history for a range of blocks.
    ///
    /// # Arguments
    /// * `block_count` - Number of blocks to return
    /// * `newest_block` - Highest block in the range
    /// * `reward_percentiles` - Percentiles for priority fee calculation
    ///
    /// # Returns
    /// Fee history object.
    #[method(name = "feeHistory")]
    async fn fee_history(
        &self,
        block_count: HexU64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory>;

    /// Returns the max priority fee per gas.
    ///
    /// # Returns
    /// Hex-encoded priority fee in wei.
    #[method(name = "maxPriorityFeePerGas")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<String>;

    /// Returns the sync status of the node.
    ///
    /// # Returns
    /// False if not syncing, or sync progress object.
    #[method(name = "syncing")]
    async fn syncing(&self) -> RpcResult<SyncStatus>;

    /// Returns a list of accounts owned by the client (always empty for Proto Core).
    ///
    /// # Returns
    /// Empty array (no account management in RPC).
    #[method(name = "accounts")]
    async fn accounts(&self) -> RpcResult<Vec<Address>>;

    /// Returns the client version.
    ///
    /// # Returns
    /// Client version string.
    #[method(name = "protocolVersion")]
    async fn protocol_version(&self) -> RpcResult<String>;

    /// Returns the block transaction count by number.
    ///
    /// # Arguments
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Hex-encoded transaction count.
    #[method(name = "getBlockTransactionCountByNumber")]
    async fn get_block_transaction_count_by_number(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<Option<String>>;

    /// Returns the block transaction count by hash.
    ///
    /// # Arguments
    /// * `hash` - Block hash
    ///
    /// # Returns
    /// Hex-encoded transaction count.
    #[method(name = "getBlockTransactionCountByHash")]
    async fn get_block_transaction_count_by_hash(&self, hash: H256) -> RpcResult<Option<String>>;

    /// Returns a transaction by block number and index.
    ///
    /// # Arguments
    /// * `block` - Block number or tag
    /// * `index` - Transaction index
    ///
    /// # Returns
    /// Transaction object or null.
    #[method(name = "getTransactionByBlockNumberAndIndex")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        block: BlockNumberOrTag,
        index: HexU64,
    ) -> RpcResult<Option<RpcTransaction>>;

    /// Returns a transaction by block hash and index.
    ///
    /// # Arguments
    /// * `hash` - Block hash
    /// * `index` - Transaction index
    ///
    /// # Returns
    /// Transaction object or null.
    #[method(name = "getTransactionByBlockHashAndIndex")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        hash: H256,
        index: HexU64,
    ) -> RpcResult<Option<RpcTransaction>>;
}

// ============================================================================
// State Provider Trait
// ============================================================================

/// Trait for providing blockchain state to the RPC handler.
///
/// Implement this trait to connect the RPC server to your blockchain state.
#[async_trait]
pub trait StateProvider: Send + Sync {
    /// Get the current chain ID.
    fn chain_id(&self) -> u64;

    /// Get the current block number.
    async fn block_number(&self) -> Result<u64, RpcError>;

    /// Get an account balance.
    async fn get_balance(
        &self,
        address: &Address,
        block: &BlockNumberOrTag,
    ) -> Result<u128, RpcError>;

    /// Get the transaction count (nonce) for an address.
    async fn get_transaction_count(
        &self,
        address: &Address,
        block: &BlockNumberOrTag,
    ) -> Result<u64, RpcError>;

    /// Get a block by number.
    async fn get_block_by_number(
        &self,
        block: &BlockNumberOrTag,
        full: bool,
    ) -> Result<Option<RpcBlock>, RpcError>;

    /// Get a block by hash.
    async fn get_block_by_hash(
        &self,
        hash: &H256,
        full: bool,
    ) -> Result<Option<RpcBlock>, RpcError>;

    /// Get a transaction by hash.
    async fn get_transaction(&self, hash: &H256) -> Result<Option<RpcTransaction>, RpcError>;

    /// Get a transaction receipt.
    async fn get_receipt(&self, hash: &H256) -> Result<Option<RpcReceipt>, RpcError>;

    /// Get contract code at an address.
    async fn get_code(
        &self,
        address: &Address,
        block: &BlockNumberOrTag,
    ) -> Result<Vec<u8>, RpcError>;

    /// Get storage value at a position.
    async fn get_storage(
        &self,
        address: &Address,
        position: &H256,
        block: &BlockNumberOrTag,
    ) -> Result<H256, RpcError>;

    /// Execute a call (read-only).
    async fn call(&self, tx: &CallRequest, block: &BlockNumberOrTag) -> Result<Vec<u8>, RpcError>;

    /// Estimate gas for a transaction.
    async fn estimate_gas(
        &self,
        tx: &CallRequest,
        block: &BlockNumberOrTag,
    ) -> Result<u64, RpcError>;

    /// Get the current gas price.
    async fn gas_price(&self) -> Result<u64, RpcError>;

    /// Get logs matching a filter.
    async fn get_logs(&self, filter: &LogFilter) -> Result<Vec<RpcLog>, RpcError>;

    /// Get fee history.
    async fn fee_history(
        &self,
        block_count: u64,
        newest_block: &BlockNumberOrTag,
        reward_percentiles: &[f64],
    ) -> Result<FeeHistory, RpcError>;

    /// Get the sync status.
    async fn sync_status(&self) -> Result<SyncStatus, RpcError>;

    /// Submit a raw transaction.
    async fn send_raw_transaction(&self, data: &[u8]) -> Result<H256, RpcError>;

    /// Get block transaction count.
    async fn get_block_transaction_count(
        &self,
        block: &BlockNumberOrTag,
    ) -> Result<Option<u64>, RpcError>;

    /// Get block transaction count by hash.
    async fn get_block_transaction_count_by_hash(
        &self,
        hash: &H256,
    ) -> Result<Option<u64>, RpcError>;

    /// Get transaction by block and index.
    async fn get_transaction_by_index(
        &self,
        block: &BlockNumberOrTag,
        index: u64,
    ) -> Result<Option<RpcTransaction>, RpcError>;

    /// Get transaction by block hash and index.
    async fn get_transaction_by_hash_and_index(
        &self,
        hash: &H256,
        index: u64,
    ) -> Result<Option<RpcTransaction>, RpcError>;
}

// ============================================================================
// EthApi Implementation
// ============================================================================

/// Helper to convert RpcError to jsonrpsee ErrorObjectOwned
fn rpc_err(e: RpcError) -> jsonrpsee::types::ErrorObjectOwned {
    e.into()
}

/// Implementation of the Ethereum RPC API.
pub struct EthApiImpl<S> {
    state: Arc<S>,
    max_logs: usize,
}

impl<S> EthApiImpl<S>
where
    S: StateProvider,
{
    /// Create a new EthApi implementation.
    pub fn new(state: Arc<S>) -> Self {
        Self {
            state,
            max_logs: 10_000,
        }
    }

    /// Set the maximum number of logs to return in a single request.
    pub fn with_max_logs(mut self, max_logs: usize) -> Self {
        self.max_logs = max_logs;
        self
    }
}

#[async_trait]
impl<S> EthApiServer for EthApiImpl<S>
where
    S: StateProvider + 'static,
{
    #[instrument(skip(self), level = "debug")]
    async fn chain_id(&self) -> RpcResult<String> {
        let chain_id = self.state.chain_id();
        debug!(chain_id, "eth_chainId");
        Ok(format!("0x{:x}", chain_id))
    }

    #[instrument(skip(self), level = "debug")]
    async fn block_number(&self) -> RpcResult<String> {
        let number = self.state.block_number().await.map_err(rpc_err)?;
        debug!(number, "eth_blockNumber");
        Ok(format!("0x{:x}", number))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_balance(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<String> {
        let balance = self
            .state
            .get_balance(&address, &block)
            .await
            .map_err(rpc_err)?;
        debug!(?address, ?block, balance, "eth_getBalance");
        Ok(format!("0x{:x}", balance))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_transaction_count(
        &self,
        address: Address,
        block: BlockNumberOrTag,
    ) -> RpcResult<String> {
        let count = self
            .state
            .get_transaction_count(&address, &block)
            .await
            .map_err(rpc_err)?;
        debug!(?address, ?block, count, "eth_getTransactionCount");
        Ok(format!("0x{:x}", count))
    }

    #[instrument(skip(self), level = "debug")]
    async fn send_raw_transaction(&self, data: HexBytes) -> RpcResult<H256> {
        info!(data_len = data.0.len(), "eth_sendRawTransaction");
        let hash = self
            .state
            .send_raw_transaction(&data.0)
            .await
            .map_err(rpc_err)?;
        debug!(?hash, "Transaction submitted");
        Ok(hash)
    }

    #[instrument(skip(self), level = "debug")]
    async fn call(&self, tx: CallRequest, block: BlockNumberOrTag) -> RpcResult<String> {
        let result = self.state.call(&tx, &block).await.map_err(rpc_err)?;
        debug!(?tx.to, ?block, result_len = result.len(), "eth_call");
        Ok(format!("0x{}", hex::encode(&result)))
    }

    #[instrument(skip(self), level = "debug")]
    async fn estimate_gas(
        &self,
        tx: CallRequest,
        block: Option<BlockNumberOrTag>,
    ) -> RpcResult<String> {
        let block = block.unwrap_or(BlockNumberOrTag::Latest);
        let gas = self
            .state
            .estimate_gas(&tx, &block)
            .await
            .map_err(rpc_err)?;
        debug!(?tx.to, ?block, gas, "eth_estimateGas");
        Ok(format!("0x{:x}", gas))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_block_by_number(
        &self,
        block: BlockNumberOrTag,
        full: bool,
    ) -> RpcResult<Option<RpcBlock>> {
        let result = self
            .state
            .get_block_by_number(&block, full)
            .await
            .map_err(rpc_err)?;
        debug!(
            ?block,
            full,
            found = result.is_some(),
            "eth_getBlockByNumber"
        );
        Ok(result)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_block_by_hash(&self, hash: H256, full: bool) -> RpcResult<Option<RpcBlock>> {
        let result = self
            .state
            .get_block_by_hash(&hash, full)
            .await
            .map_err(rpc_err)?;
        debug!(?hash, full, found = result.is_some(), "eth_getBlockByHash");
        Ok(result)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_transaction_by_hash(&self, hash: H256) -> RpcResult<Option<RpcTransaction>> {
        let result = self.state.get_transaction(&hash).await.map_err(rpc_err)?;
        debug!(?hash, found = result.is_some(), "eth_getTransactionByHash");
        Ok(result)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_transaction_receipt(&self, hash: H256) -> RpcResult<Option<RpcReceipt>> {
        let result = self.state.get_receipt(&hash).await.map_err(rpc_err)?;
        debug!(?hash, found = result.is_some(), "eth_getTransactionReceipt");
        Ok(result)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_code(&self, address: Address, block: BlockNumberOrTag) -> RpcResult<String> {
        let code = self
            .state
            .get_code(&address, &block)
            .await
            .map_err(rpc_err)?;
        debug!(?address, ?block, code_len = code.len(), "eth_getCode");
        if code.is_empty() {
            Ok("0x".to_string())
        } else {
            Ok(format!("0x{}", hex::encode(&code)))
        }
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_storage_at(
        &self,
        address: Address,
        position: H256,
        block: BlockNumberOrTag,
    ) -> RpcResult<String> {
        let value = self
            .state
            .get_storage(&address, &position, &block)
            .await
            .map_err(rpc_err)?;
        debug!(?address, ?position, ?block, "eth_getStorageAt");
        Ok(format!("0x{}", hex::encode(value.0)))
    }

    #[instrument(skip(self), level = "debug")]
    async fn gas_price(&self) -> RpcResult<String> {
        let price = self.state.gas_price().await.map_err(rpc_err)?;
        debug!(price, "eth_gasPrice");
        Ok(format!("0x{:x}", price))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_logs(&self, filter: LogFilter) -> RpcResult<Vec<RpcLog>> {
        let logs = self.state.get_logs(&filter).await.map_err(rpc_err)?;

        if logs.len() > self.max_logs {
            warn!(
                count = logs.len(),
                max = self.max_logs,
                "Log query returned too many results"
            );
            return Err(RpcError::InvalidParams(format!(
                "Query returned {} logs, max is {}",
                logs.len(),
                self.max_logs
            ))
            .into());
        }

        debug!(count = logs.len(), "eth_getLogs");
        Ok(logs)
    }

    #[instrument(skip(self), level = "debug")]
    async fn fee_history(
        &self,
        block_count: HexU64,
        newest_block: BlockNumberOrTag,
        reward_percentiles: Option<Vec<f64>>,
    ) -> RpcResult<FeeHistory> {
        let percentiles = reward_percentiles.unwrap_or_default();
        let history = self
            .state
            .fee_history(block_count.0, &newest_block, &percentiles)
            .await
            .map_err(rpc_err)?;
        debug!(block_count = block_count.0, "eth_feeHistory");
        Ok(history)
    }

    #[instrument(skip(self), level = "debug")]
    async fn max_priority_fee_per_gas(&self) -> RpcResult<String> {
        // Default to 1 gwei for Proto Core
        let fee = 1_000_000_000u64;
        debug!(fee, "eth_maxPriorityFeePerGas");
        Ok(format!("0x{:x}", fee))
    }

    #[instrument(skip(self), level = "debug")]
    async fn syncing(&self) -> RpcResult<SyncStatus> {
        let status = self.state.sync_status().await.map_err(rpc_err)?;
        debug!(?status, "eth_syncing");
        Ok(status)
    }

    #[instrument(skip(self), level = "debug")]
    async fn accounts(&self) -> RpcResult<Vec<Address>> {
        // Proto Core RPC doesn't manage accounts
        debug!("eth_accounts - returning empty list");
        Ok(vec![])
    }

    #[instrument(skip(self), level = "debug")]
    async fn protocol_version(&self) -> RpcResult<String> {
        // Return EVM version
        debug!("eth_protocolVersion");
        Ok("0x41".to_string()) // 65 = Berlin
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_block_transaction_count_by_number(
        &self,
        block: BlockNumberOrTag,
    ) -> RpcResult<Option<String>> {
        let count = self
            .state
            .get_block_transaction_count(&block)
            .await
            .map_err(rpc_err)?;
        debug!(?block, count, "eth_getBlockTransactionCountByNumber");
        Ok(count.map(|c| format!("0x{:x}", c)))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_block_transaction_count_by_hash(&self, hash: H256) -> RpcResult<Option<String>> {
        let count = self
            .state
            .get_block_transaction_count_by_hash(&hash)
            .await
            .map_err(rpc_err)?;
        debug!(?hash, count, "eth_getBlockTransactionCountByHash");
        Ok(count.map(|c| format!("0x{:x}", c)))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_transaction_by_block_number_and_index(
        &self,
        block: BlockNumberOrTag,
        index: HexU64,
    ) -> RpcResult<Option<RpcTransaction>> {
        let tx = self
            .state
            .get_transaction_by_index(&block, index.0)
            .await
            .map_err(rpc_err)?;
        debug!(
            ?block,
            index = index.0,
            found = tx.is_some(),
            "eth_getTransactionByBlockNumberAndIndex"
        );
        Ok(tx)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_transaction_by_block_hash_and_index(
        &self,
        hash: H256,
        index: HexU64,
    ) -> RpcResult<Option<RpcTransaction>> {
        let tx = self
            .state
            .get_transaction_by_hash_and_index(&hash, index.0)
            .await
            .map_err(rpc_err)?;
        debug!(
            ?hash,
            index = index.0,
            found = tx.is_some(),
            "eth_getTransactionByBlockHashAndIndex"
        );
        Ok(tx)
    }
}

// ============================================================================
// Web3 API (for compatibility)
// ============================================================================

/// Web3 namespace API.
#[rpc(server, namespace = "web3")]
pub trait Web3Api {
    /// Returns the client version.
    #[method(name = "clientVersion")]
    async fn client_version(&self) -> RpcResult<String>;

    /// Returns Keccak256 hash of the input.
    #[method(name = "sha3")]
    async fn sha3(&self, data: HexBytes) -> RpcResult<H256>;
}

/// Web3 API implementation.
pub struct Web3ApiImpl {
    version: String,
}

impl Web3ApiImpl {
    /// Create a new Web3 API implementation.
    pub fn new(version: &str) -> Self {
        Self {
            version: version.to_string(),
        }
    }
}

#[async_trait]
impl Web3ApiServer for Web3ApiImpl {
    async fn client_version(&self) -> RpcResult<String> {
        Ok(format!("Proto Core/{}", self.version))
    }

    async fn sha3(&self, data: HexBytes) -> RpcResult<H256> {
        // Use the same keccak256 from types module
        let hash = crate::types::sha3_keccak256(&data.0);
        Ok(H256(hash))
    }
}

// ============================================================================
// Net API (for compatibility)
// ============================================================================

/// Net namespace API.
#[rpc(server, namespace = "net")]
pub trait NetApi {
    /// Returns the network ID.
    #[method(name = "version")]
    async fn version(&self) -> RpcResult<String>;

    /// Returns true if the client is listening for connections.
    #[method(name = "listening")]
    async fn listening(&self) -> RpcResult<bool>;

    /// Returns the number of connected peers.
    #[method(name = "peerCount")]
    async fn peer_count(&self) -> RpcResult<String>;
}

/// Net API implementation.
pub struct NetApiImpl {
    chain_id: u64,
    peer_count: Arc<RwLock<usize>>,
}

impl NetApiImpl {
    /// Create a new Net API implementation.
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id,
            peer_count: Arc::new(RwLock::new(0)),
        }
    }

    /// Update the peer count.
    pub fn set_peer_count(&self, count: usize) {
        *self.peer_count.write() = count;
    }
}

#[async_trait]
impl NetApiServer for NetApiImpl {
    async fn version(&self) -> RpcResult<String> {
        Ok(self.chain_id.to_string())
    }

    async fn listening(&self) -> RpcResult<bool> {
        Ok(true)
    }

    async fn peer_count(&self) -> RpcResult<String> {
        let count = *self.peer_count.read();
        Ok(format!("0x{:x}", count))
    }
}
