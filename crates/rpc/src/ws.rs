//! WebSocket subscription support.
//!
//! This module implements Ethereum-compatible WebSocket subscriptions:
//! - `eth_subscribe` / `eth_unsubscribe`
//! - Subscription types: newHeads, logs, pendingTransactions, syncing

use crate::types::*;
use crate::RpcError;
use async_trait::async_trait;
use jsonrpsee::core::SubscriptionResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::{PendingSubscriptionSink, SubscriptionMessage};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{debug, info, warn};

// ============================================================================
// Subscription Types
// ============================================================================

/// Subscription type for eth_subscribe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum SubscriptionKind {
    /// New block headers.
    NewHeads,
    /// Log entries matching a filter.
    Logs,
    /// New pending transactions.
    NewPendingTransactions,
    /// Sync status changes.
    Syncing,
}

impl std::str::FromStr for SubscriptionKind {
    type Err = RpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "newheads" => Ok(Self::NewHeads),
            "logs" => Ok(Self::Logs),
            "newpendingtransactions" => Ok(Self::NewPendingTransactions),
            "syncing" => Ok(Self::Syncing),
            _ => Err(RpcError::InvalidParams(format!(
                "unknown subscription type: {}",
                s
            ))),
        }
    }
}

/// Parameters for log subscriptions.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogSubscriptionParams {
    /// Contract address(es) to filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressFilter>,
    /// Topics to filter.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<TopicFilter>>>,
}

/// Block header for newHeads subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubscriptionBlockHeader {
    /// Block number.
    pub number: HexU64,
    /// Block hash.
    pub hash: H256,
    /// Parent hash.
    pub parent_hash: H256,
    /// Nonce (always 0 for PoS).
    pub nonce: HexU64,
    /// SHA3 uncles.
    pub sha3_uncles: H256,
    /// Logs bloom.
    pub logs_bloom: HexBytes,
    /// Transactions root.
    pub transactions_root: H256,
    /// State root.
    pub state_root: H256,
    /// Receipts root.
    pub receipts_root: H256,
    /// Miner/proposer address.
    pub miner: Address,
    /// Difficulty (always 0).
    pub difficulty: HexU64,
    /// Extra data.
    pub extra_data: HexBytes,
    /// Gas limit.
    pub gas_limit: HexU64,
    /// Gas used.
    pub gas_used: HexU64,
    /// Timestamp.
    pub timestamp: HexU64,
    /// Base fee per gas.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<HexU64>,
}

/// Sync status for syncing subscription.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncingSubscriptionResult {
    /// Whether currently syncing.
    pub syncing: bool,
    /// Sync status (if syncing).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<SyncProgress>,
}

// ============================================================================
// Subscription API Trait
// ============================================================================

/// Ethereum-compatible subscription API.
#[rpc(server, namespace = "eth")]
pub trait SubscriptionApi {
    /// Subscribe to events.
    ///
    /// # Arguments
    /// * `kind` - Subscription type (newHeads, logs, newPendingTransactions, syncing)
    /// * `params` - Optional parameters (for logs subscription)
    ///
    /// # Returns
    /// Subscription ID.
    #[subscription(name = "subscribe" => "subscription", unsubscribe = "unsubscribe", item = serde_json::Value)]
    async fn subscribe(
        &self,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult;
}

// ============================================================================
// Subscription Manager
// ============================================================================

/// Subscription ID type.
pub type SubscriptionId = u64;

/// Internal subscription state.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// Subscription ID.
    pub id: SubscriptionId,
    /// Subscription kind.
    pub kind: SubscriptionKind,
    /// Log filter parameters (for logs subscription).
    pub log_filter: Option<LogSubscriptionParams>,
}

/// Manager for handling subscriptions.
pub struct SubscriptionManager {
    next_id: AtomicU64,
    subscriptions: RwLock<HashMap<SubscriptionId, Subscription>>,
    new_heads_tx: broadcast::Sender<SubscriptionBlockHeader>,
    logs_tx: broadcast::Sender<RpcLog>,
    pending_tx_tx: broadcast::Sender<H256>,
    syncing_tx: broadcast::Sender<SyncingSubscriptionResult>,
}

impl SubscriptionManager {
    /// Create a new subscription manager.
    pub fn new() -> Self {
        let (new_heads_tx, _) = broadcast::channel(1024);
        let (logs_tx, _) = broadcast::channel(4096);
        let (pending_tx_tx, _) = broadcast::channel(4096);
        let (syncing_tx, _) = broadcast::channel(16);

        Self {
            next_id: AtomicU64::new(1),
            subscriptions: RwLock::new(HashMap::new()),
            new_heads_tx,
            logs_tx,
            pending_tx_tx,
            syncing_tx,
        }
    }

    /// Create a new subscription.
    pub fn create_subscription(
        &self,
        kind: SubscriptionKind,
        log_filter: Option<LogSubscriptionParams>,
    ) -> Subscription {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let sub = Subscription {
            id,
            kind: kind.clone(),
            log_filter,
        };
        self.subscriptions.write().insert(id, sub.clone());
        debug!(id, ?kind, "Created subscription");
        sub
    }

    /// Remove a subscription.
    pub fn remove_subscription(&self, id: SubscriptionId) -> bool {
        let removed = self.subscriptions.write().remove(&id).is_some();
        if removed {
            debug!(id, "Removed subscription");
        }
        removed
    }

    /// Get subscription count.
    pub fn subscription_count(&self) -> usize {
        self.subscriptions.read().len()
    }

    /// Subscribe to new block headers.
    pub fn subscribe_new_heads(&self) -> broadcast::Receiver<SubscriptionBlockHeader> {
        self.new_heads_tx.subscribe()
    }

    /// Subscribe to logs.
    pub fn subscribe_logs(&self) -> broadcast::Receiver<RpcLog> {
        self.logs_tx.subscribe()
    }

    /// Subscribe to pending transactions.
    pub fn subscribe_pending_transactions(&self) -> broadcast::Receiver<H256> {
        self.pending_tx_tx.subscribe()
    }

    /// Subscribe to sync status.
    pub fn subscribe_syncing(&self) -> broadcast::Receiver<SyncingSubscriptionResult> {
        self.syncing_tx.subscribe()
    }

    /// Broadcast a new block header.
    pub fn broadcast_new_head(&self, header: SubscriptionBlockHeader) {
        let _ = self.new_heads_tx.send(header);
    }

    /// Broadcast a log entry.
    pub fn broadcast_log(&self, log: RpcLog) {
        let _ = self.logs_tx.send(log);
    }

    /// Broadcast a pending transaction hash.
    pub fn broadcast_pending_transaction(&self, hash: H256) {
        let _ = self.pending_tx_tx.send(hash);
    }

    /// Broadcast sync status change.
    pub fn broadcast_sync_status(&self, status: SyncingSubscriptionResult) {
        let _ = self.syncing_tx.send(status);
    }
}

impl Default for SubscriptionManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Subscription API Implementation
// ============================================================================

/// Implementation of the subscription API.
pub struct SubscriptionApiImpl {
    manager: Arc<SubscriptionManager>,
}

impl SubscriptionApiImpl {
    /// Create a new subscription API implementation.
    pub fn new(manager: Arc<SubscriptionManager>) -> Self {
        Self { manager }
    }
}

#[async_trait]
impl SubscriptionApiServer for SubscriptionApiImpl {
    async fn subscribe(
        &self,
        pending: PendingSubscriptionSink,
        kind: String,
        params: Option<serde_json::Value>,
    ) -> SubscriptionResult {
        // Parse the subscription kind
        let sub_kind: SubscriptionKind = match kind.parse() {
            Ok(k) => k,
            Err(e) => {
                let _ = pending
                    .reject(jsonrpsee::types::ErrorObject::owned(
                        -32602,
                        e.to_string(),
                        None::<()>,
                    ))
                    .await;
                return Ok(());
            }
        };

        // Parse log subscription params if provided
        let log_params: Option<LogSubscriptionParams> = if let Some(p) = params {
            serde_json::from_value(p).ok()
        } else {
            None
        };

        let subscription = self
            .manager
            .create_subscription(sub_kind.clone(), log_params.clone());
        let sub_id = subscription.id;

        info!(id = sub_id, ?sub_kind, "New subscription");

        // Accept the subscription
        let sink = pending.accept().await?;

        // Spawn a task to handle the subscription
        let manager = self.manager.clone();

        match sub_kind {
            SubscriptionKind::NewHeads => {
                let mut rx = manager.subscribe_new_heads();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(header) => {
                                let msg = SubscriptionMessage::from_json(&header).unwrap();
                                if sink.send(msg).await.is_err() {
                                    debug!(id = sub_id, "Subscription sink closed");
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(id = sub_id, lagged = n, "Subscription lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!(id = sub_id, "Broadcast channel closed");
                                break;
                            }
                        }
                    }
                    manager.remove_subscription(sub_id);
                });
            }
            SubscriptionKind::Logs => {
                let mut rx = manager.subscribe_logs();
                let filter = log_params.unwrap_or_default();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(log) => {
                                // Apply filter
                                if !matches_log_filter(&log, &filter) {
                                    continue;
                                }

                                let msg = SubscriptionMessage::from_json(&log).unwrap();
                                if sink.send(msg).await.is_err() {
                                    debug!(id = sub_id, "Subscription sink closed");
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(id = sub_id, lagged = n, "Subscription lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!(id = sub_id, "Broadcast channel closed");
                                break;
                            }
                        }
                    }
                    manager.remove_subscription(sub_id);
                });
            }
            SubscriptionKind::NewPendingTransactions => {
                let mut rx = manager.subscribe_pending_transactions();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(hash) => {
                                let msg = SubscriptionMessage::from_json(&hash).unwrap();
                                if sink.send(msg).await.is_err() {
                                    debug!(id = sub_id, "Subscription sink closed");
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(id = sub_id, lagged = n, "Subscription lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!(id = sub_id, "Broadcast channel closed");
                                break;
                            }
                        }
                    }
                    manager.remove_subscription(sub_id);
                });
            }
            SubscriptionKind::Syncing => {
                let mut rx = manager.subscribe_syncing();
                tokio::spawn(async move {
                    loop {
                        match rx.recv().await {
                            Ok(status) => {
                                let msg = SubscriptionMessage::from_json(&status).unwrap();
                                if sink.send(msg).await.is_err() {
                                    debug!(id = sub_id, "Subscription sink closed");
                                    break;
                                }
                            }
                            Err(broadcast::error::RecvError::Lagged(n)) => {
                                warn!(id = sub_id, lagged = n, "Subscription lagged");
                            }
                            Err(broadcast::error::RecvError::Closed) => {
                                debug!(id = sub_id, "Broadcast channel closed");
                                break;
                            }
                        }
                    }
                    manager.remove_subscription(sub_id);
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Log Filter Matching
// ============================================================================

/// Check if a log matches the subscription filter.
fn matches_log_filter(log: &RpcLog, filter: &LogSubscriptionParams) -> bool {
    // Check address filter
    if let Some(ref addr_filter) = filter.address {
        let matches = match addr_filter {
            AddressFilter::Single(addr) => &log.address == addr,
            AddressFilter::Multiple(addrs) => addrs.contains(&log.address),
        };
        if !matches {
            return false;
        }
    }

    // Check topics filter
    if let Some(ref topics) = filter.topics {
        for (i, topic_filter) in topics.iter().enumerate() {
            if let Some(filter) = topic_filter {
                // If log doesn't have this topic index, it doesn't match
                if i >= log.topics.len() {
                    return false;
                }

                let log_topic = &log.topics[i];
                let matches = match filter {
                    TopicFilter::Single(t) => log_topic == t,
                    TopicFilter::Multiple(ts) => ts.contains(log_topic),
                };
                if !matches {
                    return false;
                }
            }
            // None means any topic matches
        }
    }

    true
}

// ============================================================================
// Block Header Conversion Helper
// ============================================================================

impl From<&RpcBlock> for SubscriptionBlockHeader {
    fn from(block: &RpcBlock) -> Self {
        Self {
            number: block.number,
            hash: block.hash,
            parent_hash: block.parent_hash,
            nonce: block.nonce,
            sha3_uncles: block.sha3_uncles,
            logs_bloom: block.logs_bloom.clone(),
            transactions_root: block.transactions_root,
            state_root: block.state_root,
            receipts_root: block.receipts_root,
            miner: block.miner,
            difficulty: block.difficulty,
            extra_data: block.extra_data.clone(),
            gas_limit: block.gas_limit,
            gas_used: block.gas_used,
            timestamp: block.timestamp,
            base_fee_per_gas: block.base_fee_per_gas,
        }
    }
}
