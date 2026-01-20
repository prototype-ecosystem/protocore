//! # Proto Core Full Node
//!
//! This module implements the full node that orchestrates all blockchain components.
//!
//! The `Node` struct is responsible for:
//! - Initializing and managing storage
//! - Starting the P2P network
//! - Running the mempool
//! - Starting the RPC server
//! - Coordinating state synchronization
//! - Handling graceful shutdown

use anyhow::Result;
use async_trait::async_trait;
use libp2p::{Multiaddr, PeerId, multiaddr::Protocol};
use parking_lot::RwLock;
use serde_json;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;
use tracing::{debug, error, info, warn};

use protocore_config::Config;
use protocore_consensus::{BlockBuilder, BlockValidator, ConsensusEngine};
use protocore_crypto::Hash as CryptoHash;
use protocore_mempool::{AccountStateProvider, Mempool, MempoolConfig, ValidationConfig};
use protocore_p2p::{GossipMessage, NetworkConfig, NetworkEvent, NetworkHandle, NetworkService};
use protocore_rpc::{
    BlockNumberOrTag, CallRequest, EpochInfo, FeeHistory, FinalityCert, GovernanceProposal,
    HexU256, HexU64, LogFilter, NetworkStats, ProposalStatus, ProtocoreStateProvider, RpcBlock,
    RpcError, RpcLog, RpcReceipt, RpcServer, RpcServerConfig, RpcTransaction, StakingInfo,
    StateProvider, StealthAddressResult, ValidatorInfo,
};
use protocore_storage::{Database, DatabaseConfig, StateDB};
use protocore_types::{Address, Block, BlockHeader, H256};

/// Adapter to provide account state from StateDB to the Mempool
/// This implements the AccountStateProvider trait required by Mempool
pub struct StateDBAdapter {
    state_db: Arc<StateDB>,
}

impl StateDBAdapter {
    /// Create a new StateDBAdapter wrapping a StateDB
    pub fn new(state_db: Arc<StateDB>) -> Self {
        Self { state_db }
    }
}

impl AccountStateProvider for StateDBAdapter {
    fn get_nonce(&self, address: &Address) -> u64 {
        // StateDB uses [u8; 20] for addresses
        self.state_db.get_nonce(address.as_fixed_bytes())
    }

    fn get_balance(&self, address: &Address) -> u128 {
        self.state_db.get_balance(address.as_fixed_bytes())
    }
}

// =============================================================================
// RPC State Provider Adapters
// =============================================================================

/// Adapter implementing StateProvider for the RPC server
pub struct RpcStateAdapter {
    database: Arc<Database>,
    state_db: Arc<StateDB>,
    mempool: Arc<Mempool<StateDBAdapter>>,
    chain_id: u64,
}

impl RpcStateAdapter {
    /// Create a new RpcStateAdapter
    pub fn new(
        database: Arc<Database>,
        state_db: Arc<StateDB>,
        mempool: Arc<Mempool<StateDBAdapter>>,
        chain_id: u64,
    ) -> Self {
        Self { database, state_db, mempool, chain_id }
    }

    /// Get block number from tag
    fn resolve_block_number(&self, block: &BlockNumberOrTag) -> Result<u64, RpcError> {
        match block {
            BlockNumberOrTag::Latest | BlockNumberOrTag::Safe | BlockNumberOrTag::Finalized => {
                Ok(self.get_latest_height())
            }
            BlockNumberOrTag::Earliest => Ok(0),
            BlockNumberOrTag::Pending => Ok(self.get_latest_height() + 1),
            BlockNumberOrTag::Number(n) => Ok(*n),
        }
    }

    fn get_latest_height(&self) -> u64 {
        self.database
            .get_metadata(b"latest_height")
            .ok()
            .flatten()
            .map(|data| {
                if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    /// Internal helper to get a block by height
    fn get_block_by_height_internal(&self, height: u64) -> Option<Block> {
        // Get block hash from height
        let height_key = format!("block_hash_{}", height);
        let hash_bytes = match self.database.get_metadata(height_key.as_bytes()) {
            Ok(Some(bytes)) if bytes.len() >= 32 => bytes,
            _ => return None,
        };

        // Get block data by hash
        let block_bytes = match self.database.get_block(&hash_bytes[..32]) {
            Ok(Some(bytes)) => bytes,
            _ => return None,
        };

        // Decode block
        Block::rlp_decode(&block_bytes).ok()
    }

    /// Internal helper to get a block by hash
    fn get_block_by_hash_internal(&self, hash: &[u8; 32]) -> Option<Block> {
        // Get block data by hash
        let block_bytes = match self.database.get_block(hash) {
            Ok(Some(bytes)) => bytes,
            _ => return None,
        };

        // Decode block
        Block::rlp_decode(&block_bytes).ok()
    }

    /// Convert a Block to RpcBlock format
    fn block_to_rpc(&self, block: &Block, full: bool) -> RpcBlock {
        use protocore_rpc::{HexBytes, Transactions};

        let block_hash = block.hash();
        let header = &block.header;

        // Convert transactions to hashes or full objects
        let transactions = if full {
            Transactions::Full(
                block.transactions.iter().enumerate().map(|(idx, tx)| {
                    self.tx_to_rpc(tx, Some(&block_hash), Some(header.height), Some(idx as u64))
                }).collect()
            )
        } else {
            Transactions::Hashes(
                block.transactions.iter().map(|tx| {
                    protocore_rpc::H256(tx.hash().into())
                }).collect()
            )
        };

        // Calculate block size (RLP encoded length)
        let size = block.rlp_encode().len() as u64;

        RpcBlock {
            number: HexU64(header.height),
            hash: protocore_rpc::H256(*block_hash.as_fixed_bytes()),
            parent_hash: protocore_rpc::H256(*header.parent_hash.as_fixed_bytes()),
            nonce: HexU64(0), // PoS, no nonce
            sha3_uncles: protocore_rpc::H256([0u8; 32]), // No uncles
            logs_bloom: HexBytes(vec![0u8; 256]), // Empty bloom
            transactions_root: protocore_rpc::H256(*header.transactions_root.as_fixed_bytes()),
            state_root: protocore_rpc::H256(*header.state_root.as_fixed_bytes()),
            receipts_root: protocore_rpc::H256(*header.receipts_root.as_fixed_bytes()),
            miner: protocore_rpc::Address(header.proposer.into()),
            difficulty: HexU64(0), // PoS
            total_difficulty: HexU256::from_u128(0),
            extra_data: HexBytes(vec![]),
            size: HexU64(size),
            gas_limit: HexU64(header.gas_limit),
            gas_used: HexU64(header.gas_used),
            timestamp: HexU64(header.timestamp / 1000), // Convert ms to seconds
            transactions,
            uncles: vec![],
            base_fee_per_gas: Some(HexU64(header.base_fee as u64)),
            mix_hash: Some(protocore_rpc::H256([0u8; 32])),
            withdrawals_root: None,
        }
    }

    /// Convert a SignedTransaction to RpcTransaction format
    fn tx_to_rpc(&self, tx: &protocore_types::SignedTransaction, block_hash: Option<&protocore_types::H256>, block_number: Option<u64>, tx_index: Option<u64>) -> RpcTransaction {
        use protocore_rpc::HexBytes;

        let inner_tx = &tx.transaction;
        let sig = &tx.signature;

        // Get sender address, fallback to zero address on error
        let from_addr = tx.sender().unwrap_or_default();

        // Determine transaction type
        let tx_type_byte = inner_tx.tx_type.as_byte();

        RpcTransaction {
            hash: protocore_rpc::H256(tx.hash().into()),
            nonce: HexU64(inner_tx.nonce),
            block_hash: block_hash.map(|h| protocore_rpc::H256(*h.as_fixed_bytes())),
            block_number: block_number.map(HexU64),
            transaction_index: tx_index.map(HexU64),
            from: protocore_rpc::Address(from_addr.into()),
            to: inner_tx.to.map(|addr| protocore_rpc::Address(addr.into())),
            value: HexU256::from_u128(inner_tx.value),
            // For EIP-1559, gas_price is typically max_fee_per_gas
            gas_price: Some(HexU64(inner_tx.max_fee_per_gas as u64)),
            gas: HexU64(inner_tx.gas_limit),
            input: HexBytes(inner_tx.data.to_vec()),
            v: HexU64(sig.v),
            r: HexU256(*sig.r.as_fixed_bytes()),
            s: HexU256(*sig.s.as_fixed_bytes()),
            tx_type: Some(HexU64(tx_type_byte as u64)),
            max_fee_per_gas: Some(HexU64(inner_tx.max_fee_per_gas as u64)),
            max_priority_fee_per_gas: Some(HexU64(inner_tx.max_priority_fee_per_gas as u64)),
            chain_id: Some(HexU64(inner_tx.chain_id)),
            access_list: None,
        }
    }
}

#[async_trait]
impl StateProvider for RpcStateAdapter {
    fn chain_id(&self) -> u64 {
        self.chain_id
    }

    async fn block_number(&self) -> Result<u64, RpcError> {
        Ok(self.get_latest_height())
    }

    async fn get_balance(&self, address: &protocore_rpc::Address, _block: &BlockNumberOrTag) -> Result<u128, RpcError> {
        Ok(self.state_db.get_balance(&address.0))
    }

    async fn get_transaction_count(&self, address: &protocore_rpc::Address, _block: &BlockNumberOrTag) -> Result<u64, RpcError> {
        Ok(self.state_db.get_nonce(&address.0))
    }

    async fn get_block_by_number(&self, block_tag: &BlockNumberOrTag, full: bool) -> Result<Option<RpcBlock>, RpcError> {
        let height = self.resolve_block_number(block_tag)?;
        debug!(height = height, "get_block_by_number called");

        match self.get_block_by_height_internal(height) {
            Some(block) => Ok(Some(self.block_to_rpc(&block, full))),
            None => Ok(None),
        }
    }

    async fn get_block_by_hash(&self, hash: &protocore_rpc::H256, full: bool) -> Result<Option<RpcBlock>, RpcError> {
        debug!(hash = %hex::encode(&hash.0[..8]), "get_block_by_hash called");

        match self.get_block_by_hash_internal(&hash.0) {
            Some(block) => Ok(Some(self.block_to_rpc(&block, full))),
            None => Ok(None),
        }
    }

    async fn get_transaction(&self, _hash: &protocore_rpc::H256) -> Result<Option<RpcTransaction>, RpcError> {
        // In production, would fetch transaction from database
        Ok(None)
    }

    async fn get_receipt(&self, _hash: &protocore_rpc::H256) -> Result<Option<RpcReceipt>, RpcError> {
        // In production, would fetch receipt from database
        Ok(None)
    }

    async fn get_code(&self, address: &protocore_rpc::Address, _block: &BlockNumberOrTag) -> Result<Vec<u8>, RpcError> {
        // get_code takes a code_hash, not an address
        // For now, return empty code
        let _ = address;
        Ok(vec![])
    }

    async fn get_storage(&self, address: &protocore_rpc::Address, position: &protocore_rpc::H256, _block: &BlockNumberOrTag) -> Result<protocore_rpc::H256, RpcError> {
        let value = self.state_db.get_storage(&address.0, &position.0);
        Ok(protocore_rpc::H256(value))
    }

    async fn call(&self, _tx: &CallRequest, _block: &BlockNumberOrTag) -> Result<Vec<u8>, RpcError> {
        // In production, would execute call via EVM
        Err(RpcError::Internal("Call execution not implemented".to_string()))
    }

    async fn estimate_gas(&self, _tx: &CallRequest, _block: &BlockNumberOrTag) -> Result<u64, RpcError> {
        // Default gas estimate
        Ok(21000)
    }

    async fn gas_price(&self) -> Result<u64, RpcError> {
        // Return a reasonable default gas price (1 gwei)
        Ok(1_000_000_000)
    }

    async fn get_logs(&self, _filter: &LogFilter) -> Result<Vec<RpcLog>, RpcError> {
        // In production, would query logs from database
        Ok(vec![])
    }

    async fn fee_history(
        &self,
        _block_count: u64,
        _newest_block: &BlockNumberOrTag,
        _reward_percentiles: &[f64],
    ) -> Result<FeeHistory, RpcError> {
        // Return empty fee history for now
        Ok(FeeHistory {
            oldest_block: HexU64(0),
            base_fee_per_gas: vec![HexU64(1_000_000_000)], // 1 gwei
            gas_used_ratio: vec![0.5],
            reward: None,
        })
    }

    async fn sync_status(&self) -> Result<protocore_rpc::SyncStatus, RpcError> {
        // Not syncing - return false
        Ok(protocore_rpc::SyncStatus::NotSyncing(false))
    }

    async fn send_raw_transaction(&self, data: &[u8]) -> Result<protocore_rpc::H256, RpcError> {
        use protocore_types::SignedTransaction;

        // Decode the raw transaction
        let tx = SignedTransaction::rlp_decode(data)
            .map_err(|e| RpcError::InvalidParams(format!("Failed to decode transaction: {}", e)))?;

        // Verify chain ID matches
        if tx.chain_id() != Some(self.chain_id) {
            return Err(RpcError::InvalidParams(format!(
                "Chain ID mismatch: expected {}, got {:?}",
                self.chain_id,
                tx.chain_id()
            )));
        }

        // Add to mempool (validates signature, nonce, balance, etc.)
        let hash = self.mempool.add_transaction(tx)
            .map_err(|e| RpcError::TransactionRejected(format!("{}", e)))?;

        info!(
            tx_hash = %hex::encode(&hash.as_bytes()[..8]),
            "Transaction submitted to mempool"
        );

        Ok(protocore_rpc::H256(*hash.as_fixed_bytes()))
    }

    async fn get_block_transaction_count(&self, block: &BlockNumberOrTag) -> Result<Option<u64>, RpcError> {
        let height = self.resolve_block_number(block)?;

        match self.get_block_by_height_internal(height) {
            Some(block) => Ok(Some(block.transactions.len() as u64)),
            None => Ok(None),
        }
    }

    async fn get_block_transaction_count_by_hash(&self, hash: &protocore_rpc::H256) -> Result<Option<u64>, RpcError> {
        match self.get_block_by_hash_internal(&hash.0) {
            Some(block) => Ok(Some(block.transactions.len() as u64)),
            None => Ok(None),
        }
    }

    async fn get_transaction_by_index(&self, block: &BlockNumberOrTag, index: u64) -> Result<Option<RpcTransaction>, RpcError> {
        let height = self.resolve_block_number(block)?;

        let block = match self.get_block_by_height_internal(height) {
            Some(b) => b,
            None => return Ok(None),
        };

        let tx = match block.transactions.get(index as usize) {
            Some(t) => t,
            None => return Ok(None),
        };

        let block_hash = block.hash();
        Ok(Some(self.tx_to_rpc(tx, Some(&block_hash), Some(height), Some(index))))
    }

    async fn get_transaction_by_hash_and_index(&self, hash: &protocore_rpc::H256, index: u64) -> Result<Option<RpcTransaction>, RpcError> {
        let block = match self.get_block_by_hash_internal(&hash.0) {
            Some(b) => b,
            None => return Ok(None),
        };

        let tx = match block.transactions.get(index as usize) {
            Some(t) => t,
            None => return Ok(None),
        };

        let block_number = block.header.height;
        let block_hash = protocore_types::H256::from(hash.0);
        Ok(Some(self.tx_to_rpc(tx, Some(&block_hash), Some(block_number), Some(index))))
    }
}

/// Adapter implementing ProtocoreStateProvider for the RPC server
pub struct RpcProtocoreAdapter {
    database: Arc<Database>,
    state_db: Arc<StateDB>,
    config: Arc<Config>,
}

impl RpcProtocoreAdapter {
    /// Create a new RpcProtocoreAdapter
    pub fn new(database: Arc<Database>, state_db: Arc<StateDB>, config: Arc<Config>) -> Self {
        Self { database, state_db, config }
    }

    fn get_latest_height(&self) -> u64 {
        self.database
            .get_metadata(b"latest_height")
            .ok()
            .flatten()
            .map(|data| {
                if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }
}

#[async_trait]
impl ProtocoreStateProvider for RpcProtocoreAdapter {
    async fn get_validators(&self) -> Result<Vec<ValidatorInfo>, RpcError> {
        // In production, would query validator set from consensus state
        Ok(vec![])
    }

    async fn get_validator(&self, _address: &protocore_rpc::Address) -> Result<Option<ValidatorInfo>, RpcError> {
        Ok(None)
    }

    async fn get_staking_info(&self, address: &protocore_rpc::Address) -> Result<StakingInfo, RpcError> {
        Ok(StakingInfo {
            address: address.clone(),
            is_validator: false,
            validator: None,
            delegations: vec![],
            total_delegated: HexU256([0u8; 32]),
            pending_rewards: HexU256([0u8; 32]),
            unbonding: vec![],
        })
    }

    async fn get_proposal(&self, _id: u64) -> Result<Option<GovernanceProposal>, RpcError> {
        Ok(None)
    }

    async fn get_proposals(&self, _status: Option<ProposalStatus>) -> Result<Vec<GovernanceProposal>, RpcError> {
        Ok(vec![])
    }

    async fn get_epoch_info(&self) -> Result<EpochInfo, RpcError> {
        let height = self.get_latest_height();
        let blocks_per_epoch = self.config.consensus.blocks_per_epoch;
        let current_epoch = height / blocks_per_epoch;
        let blocks_remaining = blocks_per_epoch - (height % blocks_per_epoch);
        let block_time_ms = self.config.consensus.block_time_ms;
        let time_remaining = blocks_remaining * block_time_ms / 1000;

        Ok(EpochInfo {
            epoch: HexU64(current_epoch),
            start_block: HexU64(current_epoch * blocks_per_epoch),
            end_block: HexU64((current_epoch + 1) * blocks_per_epoch - 1),
            epoch_length: HexU64(blocks_per_epoch),
            current_block: HexU64(height),
            blocks_remaining: HexU64(blocks_remaining),
            time_remaining: HexU64(time_remaining),
            active_validators: 0,
            total_stake: HexU256([0u8; 32]),
        })
    }

    async fn get_finality_cert(&self, _block: &BlockNumberOrTag) -> Result<Option<FinalityCert>, RpcError> {
        Ok(None)
    }

    async fn is_finalized(&self, _block: &BlockNumberOrTag) -> Result<bool, RpcError> {
        // All blocks are considered finalized for now (2-block finality)
        Ok(true)
    }

    async fn finalized_block_number(&self) -> Result<u64, RpcError> {
        // With 2-block finality, finalized = latest - 1
        let latest = self.get_latest_height();
        Ok(latest.saturating_sub(1))
    }

    async fn generate_stealth_address(&self, _meta_address: &[u8]) -> Result<StealthAddressResult, RpcError> {
        Err(RpcError::Internal("Stealth addresses not enabled".to_string()))
    }

    async fn get_pending_rewards(&self, _address: &protocore_rpc::Address) -> Result<u128, RpcError> {
        Ok(0)
    }

    async fn get_min_validator_stake(&self) -> Result<u128, RpcError> {
        self.config.staking.min_validator_stake
            .parse()
            .map_err(|_| RpcError::Internal("Invalid min stake config".to_string()))
    }

    async fn get_unbonding_period(&self) -> Result<u64, RpcError> {
        Ok(self.config.staking.unbonding_period_blocks)
    }

    async fn get_network_stats(&self) -> Result<NetworkStats, RpcError> {
        let height = self.get_latest_height();
        Ok(NetworkStats {
            total_validators: 0,
            active_validators: 0,
            total_staked: HexU256([0u8; 32]),
            block_height: HexU64(height),
            finalized_height: HexU64(height.saturating_sub(1)),
            tps: 0.0,
            avg_block_time: 2.0, // 2 seconds
            total_transactions: HexU64(0),
            chain_id: HexU64(self.config.chain.chain_id),
        })
    }
}

/// Node status representing the current state of the node
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeStatus {
    /// Node is starting up
    Starting,
    /// Node is synchronizing with the network
    Syncing,
    /// Node is fully synced and running
    Running,
    /// Node is shutting down
    ShuttingDown,
    /// Node has stopped
    Stopped,
}

/// Events emitted by the node for external monitoring
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Node status changed
    StatusChanged(NodeStatus),
    /// New block committed
    BlockCommitted { height: u64, hash: H256 },
    /// Peer connected
    PeerConnected { peer_id: String },
    /// Peer disconnected
    PeerDisconnected { peer_id: String },
    /// Sync progress update
    SyncProgress { current: u64, target: u64 },
}

/// Component handles for graceful shutdown
struct ComponentHandles {
    /// Network service handle
    network: Option<JoinHandle<()>>,
    /// RPC server handle
    rpc: Option<JoinHandle<()>>,
    /// Mempool service handle
    mempool: Option<JoinHandle<()>>,
    /// State sync handle (if syncing)
    state_sync: Option<JoinHandle<()>>,
    /// Block executor handle
    executor: Option<JoinHandle<()>>,
}

impl Default for ComponentHandles {
    fn default() -> Self {
        Self {
            network: None,
            rpc: None,
            mempool: None,
            state_sync: None,
            executor: None,
        }
    }
}

/// Full node implementation
///
/// The Node orchestrates all components of the Proto Core blockchain:
/// - Storage layer (RocksDB + Merkle Patricia Trie)
/// - P2P networking (libp2p)
/// - Transaction mempool
/// - RPC server (JSON-RPC + WebSocket)
/// - State synchronization
pub struct Node {
    /// Node configuration (shared for RPC adapters)
    config: Arc<Config>,

    /// Current node status
    status: Arc<RwLock<NodeStatus>>,

    /// Database layer
    database: Arc<Database>,

    /// State database
    state_db: Arc<StateDB>,

    /// Transaction mempool
    mempool: Arc<Mempool<StateDBAdapter>>,

    /// Network handle for sending messages
    network_handle: Option<NetworkHandle>,

    /// Consensus engine (non-voting for full nodes)
    consensus: Option<Arc<RwLock<ConsensusEngine<NodeBlockValidator, NodeBlockBuilder>>>>,

    /// Channel to forward consensus messages to validator (if set)
    consensus_msg_tx: Option<mpsc::Sender<GossipMessage>>,

    /// Event broadcaster for node events
    event_tx: broadcast::Sender<NodeEvent>,

    /// Shutdown signal sender
    shutdown_tx: Option<broadcast::Sender<()>>,

    /// Component task handles
    handles: ComponentHandles,
}

/// Block validator implementation for the node
pub struct NodeBlockValidator {
    state_db: Arc<StateDB>,
    database: Arc<Database>,
    chain_id: u64,
}

impl NodeBlockValidator {
    /// Create a new block validator
    pub fn new(state_db: Arc<StateDB>, database: Arc<Database>, chain_id: u64) -> Self {
        Self { state_db, database, chain_id }
    }

    /// Get parent header from database
    fn get_parent_header(&self, parent_hash: &[u8; 32]) -> std::result::Result<BlockHeader, String> {
        let block_bytes = self.database
            .get_block(parent_hash)
            .map_err(|e| format!("Database error: {}", e))?
            .ok_or_else(|| "Parent block not found".to_string())?;

        // Decode the block to get header
        let block = Block::rlp_decode(&block_bytes)
            .map_err(|e| format!("Failed to decode parent block: {}", e))?;

        Ok(block.header)
    }
}

#[async_trait::async_trait]
impl BlockValidator for NodeBlockValidator {
    async fn validate_block(
        &self,
        block: &Block,
        parent_hash: &CryptoHash,
    ) -> std::result::Result<(), String> {
        // 1. Parent hash validation
        let block_parent: [u8; 32] = block.header.parent_hash.into();
        if &block_parent != parent_hash {
            return Err(format!(
                "Parent hash mismatch: expected {:?}, got {:?}",
                parent_hash, block_parent
            ));
        }

        // 2. Get parent header for further validation
        let parent_header = self.get_parent_header(parent_hash)?;

        // 3. Height validation
        if block.header.height != parent_header.height + 1 {
            return Err(format!(
                "Invalid height: expected {}, got {}",
                parent_header.height + 1,
                block.header.height
            ));
        }

        // 4. Timestamp validation (must be strictly increasing)
        if block.header.timestamp <= parent_header.timestamp {
            return Err(format!(
                "Timestamp not increasing: parent={}, block={}",
                parent_header.timestamp, block.header.timestamp
            ));
        }

        // 5. Chain ID validation
        if block.header.chain_id != self.chain_id {
            return Err(format!(
                "Chain ID mismatch: expected {}, got {}",
                self.chain_id, block.header.chain_id
            ));
        }

        // 6. Gas limit validation (can change by at most 1/1024 per block)
        let parent_gas_limit = parent_header.gas_limit;
        let gas_limit_delta = parent_gas_limit / 1024;
        let min_gas_limit = parent_gas_limit.saturating_sub(gas_limit_delta);
        let max_gas_limit = parent_gas_limit.saturating_add(gas_limit_delta);

        if block.header.gas_limit < min_gas_limit || block.header.gas_limit > max_gas_limit {
            return Err(format!(
                "Gas limit change too large: parent={}, block={}, allowed range=[{}, {}]",
                parent_gas_limit, block.header.gas_limit, min_gas_limit, max_gas_limit
            ));
        }

        // 7. Basic header validation
        block.header.validate_basic()
            .map_err(|e| format!("Header validation failed: {}", e))?;

        // 8. Transaction validation
        let mut total_gas = 0u64;
        for (i, tx) in block.transactions.iter().enumerate() {
            // Validate transaction signature
            let sender = tx.sender()
                .map_err(|e| format!("Transaction {} signature invalid: {}", i, e))?;

            // Get account state for nonce/balance validation
            let nonce = self.state_db.get_nonce(sender.as_fixed_bytes());
            let balance = self.state_db.get_balance(sender.as_fixed_bytes());

            // Nonce validation
            if tx.nonce() < nonce {
                return Err(format!(
                    "Transaction {} nonce too low: expected >= {}, got {}",
                    i, nonce, tx.nonce()
                ));
            }

            // Balance validation (must cover gas * max_fee_per_gas + value)
            let max_fee = tx.gas_limit() as u128 * tx.max_fee_per_gas();
            let required = max_fee + tx.value();
            if balance < required {
                return Err(format!(
                    "Transaction {} insufficient balance: required {}, has {}",
                    i, required, balance
                ));
            }

            // Accumulate gas
            total_gas = total_gas.saturating_add(tx.gas_limit());
        }

        // 9. Total gas validation
        if total_gas > block.header.gas_limit {
            return Err(format!(
                "Block gas limit exceeded: total={}, limit={}",
                total_gas, block.header.gas_limit
            ));
        }

        // 10. Base fee validation (EIP-1559)
        let expected_base_fee = parent_header.next_base_fee();
        if block.header.base_fee != expected_base_fee {
            return Err(format!(
                "Invalid base fee: expected {}, got {}",
                expected_base_fee, block.header.base_fee
            ));
        }

        Ok(())
    }
}

/// Block builder implementation for the node
pub struct NodeBlockBuilder {
    mempool: Arc<Mempool<StateDBAdapter>>,
    database: Arc<Database>,
    chain_id: u64,
    gas_limit: u64,
}

impl NodeBlockBuilder {
    /// Create a new block builder
    pub fn new(
        mempool: Arc<Mempool<StateDBAdapter>>,
        database: Arc<Database>,
        chain_id: u64,
        gas_limit: u64,
    ) -> Self {
        Self { mempool, database, chain_id, gas_limit }
    }

    /// Get parent header from database
    fn get_parent_header(&self, parent_hash: &[u8; 32]) -> Option<BlockHeader> {
        let block_bytes = self.database.get_block(parent_hash).ok()??;
        let block = Block::rlp_decode(&block_bytes).ok()?;
        Some(block.header)
    }
}

#[async_trait::async_trait]
impl BlockBuilder for NodeBlockBuilder {
    async fn build_block(&self, height: u64, parent_hash: CryptoHash) -> Block {
        // Get pending transactions from mempool
        let txs = self.mempool.get_pending_transactions(self.gas_limit);

        // Debug log to trace transaction inclusion
        info!(
            height = height,
            pending_txs = txs.len(),
            gas_limit = self.gas_limit,
            "Building block"
        );

        // Get current timestamp
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        // Get parent header for base fee calculation
        let (gas_limit, base_fee) = self.get_parent_header(&parent_hash)
            .map(|parent| (parent.gas_limit, parent.next_base_fee()))
            .unwrap_or((self.gas_limit, 1_000_000_000));

        Block {
            header: BlockHeader {
                chain_id: self.chain_id,
                height,
                timestamp,
                parent_hash: H256::new(parent_hash),
                transactions_root: H256::NIL,
                state_root: H256::NIL,
                receipts_root: H256::NIL,
                proposer: Address::ZERO, // Will be set by consensus
                gas_limit,
                gas_used: 0,
                base_fee,
                last_finality_cert_hash: None,
                validator_set_hash: H256::NIL, // TODO: Compute from genesis validators
                next_validator_set_hash: None,
            },
            transactions: txs,
        }
    }
}

impl Node {
    /// Create a new full node with the given configuration
    pub async fn new(config: Config) -> Result<Self> {
        info!("Initializing Proto Core node");

        // Wrap config in Arc for sharing with RPC adapters
        let config = Arc::new(config);

        // Initialize database
        let database = Self::init_database(&config)?;

        // Initialize genesis block if this is first startup
        let is_fresh_genesis = Self::init_genesis(&database, &config)?;

        let database = Arc::new(database);

        // Initialize state database
        let state_db = Arc::new(StateDB::new(Arc::clone(&database)));

        // Initialize genesis accounts if this is a fresh genesis
        if is_fresh_genesis {
            Self::init_genesis_accounts(&state_db, &config)?;
        }

        // Create state adapter for mempool
        let state_adapter = Arc::new(StateDBAdapter::new(Arc::clone(&state_db)));

        // Initialize mempool with proper config
        let mempool_config = MempoolConfig {
            max_size: config.storage.cache_size_mb as usize * 100, // Approximate max transactions
            max_bytes: config.storage.cache_size_mb as usize * 1024 * 1024,
            max_tx_size: 131_072, // 128 KB
            ttl_seconds: 3600,
            eviction_interval: 60,
            price_bump_percentage: 10,
            max_pending_per_sender: 64,
            max_queued_per_sender: 64,
            dedup_retention_blocks: 128,  // Keep hashes for ~128 blocks for replay protection
            dedup_max_size: 100_000,      // Max 100k seen transaction hashes
        };
        // Use validation config with correct chain_id from node config
        let validation_config = ValidationConfig {
            chain_id: config.chain.chain_id,
            ..Default::default()
        };
        let mempool = Arc::new(Mempool::with_validation_config(mempool_config, validation_config, state_adapter));

        // Create event broadcaster
        let (event_tx, _) = broadcast::channel(1000);

        Ok(Self {
            config,
            status: Arc::new(RwLock::new(NodeStatus::Starting)),
            database,
            state_db,
            mempool,
            network_handle: None,
            consensus: None,
            consensus_msg_tx: None,
            event_tx,
            shutdown_tx: None,
            handles: ComponentHandles::default(),
        })
    }

    /// Initialize the database layer
    fn init_database(config: &Config) -> Result<Database> {
        info!(data_dir = %config.storage.data_dir, "Initializing database");

        let db_config = DatabaseConfig {
            path: config.storage.data_dir.clone(),
            enable_compression: true,
            max_open_files: 512,
            write_buffer_size: 64 * 1024 * 1024,
            max_write_buffer_number: 4,
            block_cache_size: config.storage.cache_size_mb as usize * 1024 * 1024,
            enable_wal: true,
        };

        Database::open(db_config).map_err(|e| anyhow::anyhow!("Failed to open database: {}", e))
    }

    /// Initialize genesis block if needed (first time startup)
    /// Returns true if this was a fresh genesis initialization
    fn init_genesis(database: &Database, config: &Config) -> Result<bool> {
        // Check if genesis already exists by looking for latest_height metadata
        if database.get_metadata(b"latest_height")
            .map_err(|e| anyhow::anyhow!("Failed to check metadata: {}", e))?
            .is_some()
        {
            info!("Genesis block already exists, skipping initialization");
            return Ok(false);
        }

        info!("Initializing genesis block");

        // Create genesis block header
        // Use timestamp 0 for genesis (deterministic across all nodes)
        let genesis_timestamp = 0u64;

        let header = BlockHeader {
            chain_id: config.chain.chain_id,
            height: 0,
            timestamp: genesis_timestamp,
            parent_hash: H256::NIL,
            transactions_root: H256::NIL,
            state_root: H256::NIL,  // State root computed after account initialization
            receipts_root: H256::NIL,
            proposer: Address::ZERO,
            gas_limit: config.economics.block_gas_limit,
            gas_used: 0,
            base_fee: config.economics.min_base_fee.parse().unwrap_or(1_000_000_000),
            last_finality_cert_hash: None,
            validator_set_hash: H256::NIL, // TODO: Compute from genesis validators
            next_validator_set_hash: None,
        };

        let genesis_block = Block::new(header, Vec::new());
        let genesis_hash = genesis_block.hash();

        // Encode and store the genesis block
        let encoded = genesis_block.rlp_encode();
        database.put_block(genesis_hash.as_bytes(), &encoded)
            .map_err(|e| anyhow::anyhow!("Failed to store genesis block: {}", e))?;

        // Store metadata
        database.put_metadata(b"latest_height", &0u64.to_le_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to store latest height: {}", e))?;
        database.put_metadata(&format!("block_hash_0").into_bytes(), genesis_hash.as_bytes())
            .map_err(|e| anyhow::anyhow!("Failed to store genesis hash: {}", e))?;

        info!(
            genesis_hash = %hex::encode(&genesis_hash.as_bytes()[..8]),
            "Genesis block initialized"
        );

        Ok(true) // Return true to indicate fresh genesis
    }

    /// Initialize genesis accounts in StateDB after it's created
    fn init_genesis_accounts(state_db: &StateDB, config: &Config) -> Result<()> {
        if config.genesis.accounts.is_empty() {
            return Ok(());
        }

        info!(
            accounts = config.genesis.accounts.len(),
            "Initializing genesis account balances"
        );

        for account in &config.genesis.accounts {
            // Parse address (strip 0x prefix if present)
            let addr_hex = account.address.strip_prefix("0x").unwrap_or(&account.address);
            let addr_bytes = hex::decode(addr_hex)
                .map_err(|e| anyhow::anyhow!("Invalid genesis address {}: {}", account.address, e))?;

            if addr_bytes.len() != 20 {
                return Err(anyhow::anyhow!("Invalid address length for {}", account.address));
            }

            let mut address = [0u8; 20];
            address.copy_from_slice(&addr_bytes);

            // Parse balance (support both decimal and hex)
            let balance: u128 = if account.balance.starts_with("0x") {
                u128::from_str_radix(account.balance.strip_prefix("0x").unwrap(), 16)
                    .map_err(|e| anyhow::anyhow!("Invalid balance {}: {}", account.balance, e))?
            } else {
                account.balance.parse()
                    .map_err(|e| anyhow::anyhow!("Invalid balance {}: {}", account.balance, e))?
            };

            // Create account with balance using StateDB's set_account
            let account_data = protocore_storage::Account::with_balance(balance);
            state_db.set_account(&address, account_data);

            info!(
                address = %account.address,
                balance = %balance,
                "Initialized genesis account"
            );
        }

        // Commit state changes to persist genesis accounts
        state_db.commit()
            .map_err(|e| anyhow::anyhow!("Failed to commit genesis accounts: {}", e))?;

        info!("Genesis accounts committed to state");
        Ok(())
    }

    /// Set the consensus message channel for forwarding consensus messages to the validator
    pub fn set_consensus_channel(&mut self, tx: mpsc::Sender<GossipMessage>) {
        self.consensus_msg_tx = Some(tx);
    }

    /// Get a reference to the network handle
    pub fn network_handle(&self) -> Option<&NetworkHandle> {
        self.network_handle.as_ref()
    }

    /// Get a reference to the database
    pub fn database(&self) -> &Arc<Database> {
        &self.database
    }

    /// Get a reference to the state database
    pub fn state_db(&self) -> &Arc<StateDB> {
        &self.state_db
    }

    /// Get a reference to the mempool
    pub fn mempool(&self) -> &Arc<Mempool<StateDBAdapter>> {
        &self.mempool
    }

    /// Get the config
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Run the node - this is the main entry point
    ///
    /// This method starts all components and runs until shutdown is requested.
    pub async fn run(&mut self) -> Result<()> {
        info!("Starting Proto Core node");

        // Create shutdown channel if not already created (e.g., by start_network_early)
        if self.shutdown_tx.is_none() {
            let (shutdown_tx, _) = broadcast::channel(1);
            self.shutdown_tx = Some(shutdown_tx);
        }

        // Update status
        self.set_status(NodeStatus::Starting);

        // Check if we need to sync
        let needs_sync = self.check_sync_status().await?;

        if needs_sync {
            self.set_status(NodeStatus::Syncing);
            self.start_state_sync().await?;
        }

        // Start all components
        self.start_network().await?;
        self.start_mempool().await?;
        self.start_rpc().await?;
        self.start_block_executor().await?;

        // Mark as running
        self.set_status(NodeStatus::Running);

        info!(
            height = self.get_current_height(),
            peers = self.get_peer_count(),
            "Node is running"
        );

        // Wait for shutdown signal
        self.wait_for_shutdown().await?;

        // Perform graceful shutdown
        self.shutdown().await?;

        Ok(())
    }

    /// Start the P2P network service
    /// Start the network early (before full run)
    /// This allows consensus to get the network handle before the main loop starts
    pub async fn start_network_early(&mut self) -> Result<()> {
        if self.network_handle.is_some() {
            // Network already started
            return Ok(());
        }
        // Initialize shutdown channel if not already done
        if self.shutdown_tx.is_none() {
            let (shutdown_tx, _) = broadcast::channel(1);
            self.shutdown_tx = Some(shutdown_tx);
        }
        self.start_network().await
    }

    async fn start_network(&mut self) -> Result<()> {
        // Check if already started (e.g., by start_network_early)
        if self.network_handle.is_some() {
            debug!("Network already started, skipping");
            return Ok(());
        }

        info!(
            listen_addr = %self.config.network.listen_address,
            "Starting P2P network"
        );

        // Create network config using our configuration
        // NetworkConfig uses Multiaddr for addresses, so we parse the string

        // Parse boot nodes from config
        // Expected format: /ip4/1.2.3.4/tcp/30300/p2p/12D3KooW...
        let boot_nodes: Vec<(PeerId, Multiaddr)> = self.config.network.boot_nodes
            .iter()
            .filter_map(|addr_str| {
                let addr: Multiaddr = addr_str.parse().ok()?;
                let peer_id = addr.iter().find_map(|p| match p {
                    Protocol::P2p(peer_id) => Some(peer_id),
                    _ => None,
                })?;
                let addr_without_p2p: Multiaddr = addr.iter()
                    .filter(|p| !matches!(p, Protocol::P2p(_)))
                    .collect();
                Some((peer_id, addr_without_p2p))
            })
            .collect();

        if !boot_nodes.is_empty() {
            info!(count = boot_nodes.len(), "Parsed boot nodes from config");
        }

        // Use p2p.key in the data directory for persistent peer identity
        let p2p_key_path = std::path::PathBuf::from(&self.config.storage.data_dir).join("p2p.key");

        let network_config = NetworkConfig {
            listen_addr: self.config.network.listen_address.parse()
                .map_err(|e| anyhow::anyhow!("Invalid listen address: {}", e))?,
            external_addr: None,
            boot_nodes,
            min_peers: 8,
            max_peers: self.config.network.max_peers as usize,
            p2p_key_path: Some(p2p_key_path),
            ..Default::default()
        };

        // Create channels for network events
        let (event_tx, mut event_rx) = mpsc::channel(1000);

        // Create the network service (returns tuple of service and handle)
        let (mut network_service, network_handle) = NetworkService::new(network_config, event_tx).await?;
        self.network_handle = Some(network_handle);

        // Clone references for the event handler task
        let database = Arc::clone(&self.database);
        let state_db = Arc::clone(&self.state_db);
        let mempool = Arc::clone(&self.mempool);
        let node_event_tx = self.event_tx.clone();
        let consensus_tx = self.consensus_msg_tx.clone();
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        // Spawn network event handler
        let event_handler = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(event) = event_rx.recv() => {
                        if let Err(e) = Self::handle_network_event(
                            event,
                            &database,
                            &state_db,
                            &mempool,
                            &node_event_tx,
                            &consensus_tx,
                        ).await {
                            warn!(error = %e, "Error handling network event");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Network event handler shutting down");
                        break;
                    }
                }
            }
        });

        // Spawn the network service
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();
        let network_task = tokio::spawn(async move {
            tokio::select! {
                _ = network_service.run() => {}
                _ = shutdown_rx.recv() => {
                    info!("Network service shutting down");
                }
            }
        });

        self.handles.network = Some(network_task);

        Ok(())
    }

    /// Handle incoming network events
    async fn handle_network_event(
        event: NetworkEvent,
        _database: &Arc<Database>,
        _state_db: &Arc<StateDB>,
        _mempool: &Arc<Mempool<StateDBAdapter>>,
        event_tx: &broadcast::Sender<NodeEvent>,
        consensus_tx: &Option<mpsc::Sender<GossipMessage>>,
    ) -> Result<()> {
        match event {
            NetworkEvent::NewBlock { source, message: _ } => {
                debug!(source = %source, "Received new block from network");
                // The message contains a GossipMessage - in production we would:
                // 1. Deserialize the block from the message
                // 2. Validate the block
                // 3. Add to pending blocks for processing
            }
            NetworkEvent::NewTransaction { source, message: _ } => {
                debug!(source = %source, "Received new transaction from network");
                // The message contains a GossipMessage - in production we would:
                // 1. Deserialize the transaction from the message
                // 2. Validate and add to mempool
            }
            NetworkEvent::PeerConnected(peer_id) => {
                info!(peer_id = %peer_id, "Peer connected");
                let _ = event_tx.send(NodeEvent::PeerConnected {
                    peer_id: peer_id.to_string(),
                });
            }
            NetworkEvent::PeerDisconnected(peer_id) => {
                info!(peer_id = %peer_id, "Peer disconnected");
                let _ = event_tx.send(NodeEvent::PeerDisconnected {
                    peer_id: peer_id.to_string(),
                });
            }
            NetworkEvent::ConsensusMessage { source, message } => {
                info!(source = %source, msg_type = ?message.message_type(), "Received consensus message from network");
                // Forward to consensus engine if we're a validator
                if let Some(tx) = consensus_tx {
                    if let Err(e) = tx.send(message).await {
                        warn!(error = %e, "Failed to forward consensus message");
                    } else {
                        info!("Forwarded consensus message to engine");
                    }
                } else {
                    debug!("No consensus channel set, ignoring message");
                }
            }
            NetworkEvent::DiscoveryComplete => {
                debug!("Peer discovery completed");
            }
            NetworkEvent::Listening(addr) => {
                info!(address = %addr, "Network listening");
            }
            NetworkEvent::Error(err) => {
                warn!(error = %err, "Network error");
            }
        }
        Ok(())
    }

    /// Start the mempool service
    async fn start_mempool(&mut self) -> Result<()> {
        info!("Starting mempool service");

        let mempool = Arc::clone(&self.mempool);
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        // Spawn mempool maintenance task
        let mempool_task = tokio::spawn(async move {
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        // Perform mempool maintenance - remove expired transactions
                        let removed = mempool.remove_expired();
                        if removed > 0 {
                            debug!(removed = removed, "Removed expired transactions from mempool");
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Mempool service shutting down");
                        break;
                    }
                }
            }
        });

        self.handles.mempool = Some(mempool_task);

        Ok(())
    }

    /// Start the JSON-RPC server
    async fn start_rpc(&mut self) -> Result<()> {
        info!(
            http_addr = %self.config.rpc.http_address,
            ws_addr = %self.config.rpc.ws_address,
            "Starting RPC server"
        );

        // Create state provider adapters
        let state_provider = Arc::new(RpcStateAdapter::new(
            Arc::clone(&self.database),
            Arc::clone(&self.state_db),
            Arc::clone(&self.mempool),
            self.config.chain.chain_id,
        ));

        let protocore_provider = Arc::new(RpcProtocoreAdapter::new(
            Arc::clone(&self.database),
            Arc::clone(&self.state_db),
            Arc::clone(&self.config),
        ));

        // Parse addresses
        let http_addr: SocketAddr = self.config.rpc.http_address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid HTTP address: {}", e))?;
        let ws_addr: SocketAddr = self.config.rpc.ws_address
            .parse()
            .map_err(|e| anyhow::anyhow!("Invalid WS address: {}", e))?;

        // Create RPC server config
        let rpc_config = RpcServerConfig {
            http_addr,
            ws_addr,
            chain_id: self.config.chain.chain_id,
            max_connections: 1000,
            max_request_size: 10 * 1024 * 1024,
            max_response_size: 10 * 1024 * 1024,
            request_timeout: Duration::from_secs(30),
            enable_cors: true,
            cors_origins: self.config.rpc.cors_origins.clone(),
            enable_logging: true,
            client_version: env!("CARGO_PKG_VERSION").to_string(),
            max_logs_per_request: 10_000,
            batch_request_limit: self.config.rpc.max_batch_size,
        };

        // Create and start the RPC server
        let mut rpc_server = RpcServer::new(rpc_config, state_provider, protocore_provider);

        match rpc_server.start().await {
            Ok(()) => {
                info!(
                    "RPC server listening on http://{} and ws://{}",
                    http_addr, ws_addr
                );
            }
            Err(e) => {
                error!("Failed to start RPC server: {}", e);
                return Err(anyhow::anyhow!("RPC server failed to start: {}", e));
            }
        }

        // Keep server running until shutdown
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let rpc_task = tokio::spawn(async move {
            shutdown_rx.recv().await.ok();
            rpc_server.stop().await;
            info!("RPC server stopped");
        });

        self.handles.rpc = Some(rpc_task);

        Ok(())
    }

    /// Start state synchronization if needed
    async fn start_state_sync(&mut self) -> Result<()> {
        info!("Starting state synchronization");

        // State sync requires implementations of SyncNetwork and StateStorage traits.
        // In a production implementation, we would:
        // 1. Create a NetworkAdapter implementing SyncNetwork using our P2P layer
        // 2. Create a StorageAdapter implementing StateStorage using Database + StateDB
        // 3. Create StateSyncManager with these adapters

        // For now, use the default config and log that sync would be performed
        let sync_config = protocore_state_sync::StateSyncConfig::default();
        info!(
            "State sync configured with min_peers={}, require_finality={}",
            sync_config.min_peers,
            sync_config.require_finality
        );

        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let sync_task = tokio::spawn(async move {
            // State sync placeholder - in production, this would run the actual sync
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("State sync shutting down");
                        break;
                    }
                }
            }
        });

        self.handles.state_sync = Some(sync_task);

        Ok(())
    }

    /// Start the block executor (processes new blocks)
    async fn start_block_executor(&mut self) -> Result<()> {
        info!("Starting block executor");

        let database = Arc::clone(&self.database);
        let state_db = Arc::clone(&self.state_db);
        let mempool = Arc::clone(&self.mempool);
        let event_tx = self.event_tx.clone();
        let status = Arc::clone(&self.status);

        // Create channel for receiving committed blocks
        let (block_tx, mut block_rx) = mpsc::channel::<(Block, Vec<u8>)>(100);

        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        let executor_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some((block, finality_cert)) = block_rx.recv() => {
                        let height = block.header.height;
                        let hash = block.hash();

                        debug!(height = height, hash = %hash, "Processing committed block");

                        // Execute block and update state
                        match Self::execute_block(&database, &state_db, &block).await {
                            Ok(()) => {
                                // Remove executed transactions from mempool
                                let tx_hashes: Vec<H256> = block.transactions.iter()
                                    .map(|tx| tx.hash())
                                    .collect();
                                mempool.remove_transactions(&tx_hashes);

                                // Emit event
                                let _ = event_tx.send(NodeEvent::BlockCommitted { height, hash });

                                info!(height = height, txs = block.transactions.len(), "Block committed");
                            }
                            Err(e) => {
                                error!(height = height, error = %e, "Failed to execute block");
                            }
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        info!("Block executor shutting down");
                        break;
                    }
                }
            }
        });

        self.handles.executor = Some(executor_task);

        Ok(())
    }

    /// Execute a block and update the state
    ///
    /// This is a placeholder that stores the block in the database.
    /// In a production implementation, this would:
    /// 1. Create an EVM executor with a state adapter wrapping StateDB
    /// 2. Execute all transactions in sequence
    /// 3. Verify the resulting state root matches the block header
    /// 4. Commit state changes and persist the block
    async fn execute_block(
        database: &Arc<Database>,
        state_db: &Arc<StateDB>,
        block: &Block,
    ) -> Result<()> {
        // Note: Full EVM execution requires creating a StateAdapter that wraps StateDB
        // and implements revm's Database + DatabaseCommit traits.
        // For now, we just store the block and commit state.

        debug!(
            height = block.header.height,
            txs = block.transactions.len(),
            "Executing block"
        );

        // Commit any pending state changes
        state_db.commit()?;

        // Store block in database (RLP encoded, consistent with genesis block storage)
        let block_hash = block.hash();
        let block_data = block.rlp_encode();
        database.put_block(block_hash.as_bytes(), &block_data)?;

        // Update latest height in metadata
        let height_bytes = block.header.height.to_le_bytes();
        database.put_metadata(b"latest_height", &height_bytes)?;

        Ok(())
    }

    /// Check if the node needs to sync
    async fn check_sync_status(&self) -> Result<bool> {
        // Get the latest height from database metadata
        let current_height = self
            .database
            .get_metadata(b"latest_height")?
            .map(|data| {
                if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0);

        // In a real implementation, we would query peers for the latest height
        // For now, we'll just return false (assume we're synced)
        debug!(current_height = current_height, "Checking sync status");

        Ok(false)
    }

    /// Wait for shutdown signal
    async fn wait_for_shutdown(&self) -> Result<()> {
        let mut shutdown_rx = self.shutdown_tx.as_ref().unwrap().subscribe();

        // Also listen for Ctrl+C
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("Received shutdown signal");
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received Ctrl+C, initiating shutdown");
            }
        }

        Ok(())
    }

    /// Perform graceful shutdown
    async fn shutdown(&mut self) -> Result<()> {
        info!("Initiating graceful shutdown");
        self.set_status(NodeStatus::ShuttingDown);

        // Send shutdown signal to all components
        if let Some(ref shutdown_tx) = self.shutdown_tx {
            let _ = shutdown_tx.send(());
        }

        // Wait for components to finish (with timeout)
        let timeout = tokio::time::Duration::from_secs(30);

        if let Some(handle) = self.handles.rpc.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(_) => debug!("RPC server stopped"),
                Err(_) => warn!("RPC server shutdown timed out"),
            }
        }

        if let Some(handle) = self.handles.network.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(_) => debug!("Network service stopped"),
                Err(_) => warn!("Network service shutdown timed out"),
            }
        }

        if let Some(handle) = self.handles.mempool.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(_) => debug!("Mempool service stopped"),
                Err(_) => warn!("Mempool service shutdown timed out"),
            }
        }

        if let Some(handle) = self.handles.executor.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(_) => debug!("Block executor stopped"),
                Err(_) => warn!("Block executor shutdown timed out"),
            }
        }

        if let Some(handle) = self.handles.state_sync.take() {
            match tokio::time::timeout(timeout, handle).await {
                Ok(_) => debug!("State sync stopped"),
                Err(_) => warn!("State sync shutdown timed out"),
            }
        }

        // Flush database
        self.database.flush_all()?;

        self.set_status(NodeStatus::Stopped);
        info!("Node shutdown complete");

        Ok(())
    }

    /// Update node status and emit event
    fn set_status(&self, status: NodeStatus) {
        let mut current = self.status.write();
        *current = status;
        let _ = self.event_tx.send(NodeEvent::StatusChanged(status));
    }

    /// Get current block height
    pub fn get_current_height(&self) -> u64 {
        self.database
            .get_metadata(b"latest_height")
            .ok()
            .flatten()
            .map(|data| {
                if data.len() >= 8 {
                    u64::from_le_bytes(data[..8].try_into().unwrap())
                } else {
                    0
                }
            })
            .unwrap_or(0)
    }

    /// Get current peer count
    /// Note: This returns 0 for now since getting peer count requires an async call.
    /// For actual peer count, use network_handle().get_peers() asynchronously.
    pub fn get_peer_count(&self) -> usize {
        // NetworkHandle::get_peers() is async, so we return 0 for sync access.
        // In production, peer count should be tracked in a shared state.
        0
    }

    /// Get node status
    pub fn status(&self) -> NodeStatus {
        *self.status.read()
    }

    /// Subscribe to node events
    pub fn subscribe_events(&self) -> broadcast::Receiver<NodeEvent> {
        self.event_tx.subscribe()
    }

    /// Request node shutdown
    pub fn request_shutdown(&self) {
        if let Some(ref shutdown_tx) = self.shutdown_tx {
            let _ = shutdown_tx.send(());
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        // Ensure shutdown is requested when node is dropped
        self.request_shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_status_transitions() {
        let status = NodeStatus::Starting;
        assert_eq!(status, NodeStatus::Starting);

        // Status should be copyable and comparable
        let status2 = status;
        assert_eq!(status, status2);
    }

    #[test]
    fn test_node_event_clone() {
        let event = NodeEvent::StatusChanged(NodeStatus::Running);
        let cloned = event.clone();

        match (event, cloned) {
            (NodeEvent::StatusChanged(s1), NodeEvent::StatusChanged(s2)) => {
                assert_eq!(s1, s2);
            }
            _ => panic!("Events should match"),
        }
    }
}
