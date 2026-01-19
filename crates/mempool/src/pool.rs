//! Main mempool implementation.
//!
//! This module provides the core transaction pool with:
//! - Pending pool for transactions ready for inclusion
//! - Queued pool for transactions with future nonces
//! - Gas price-based ordering for block building
//! - Eviction policies for pool capacity management
//! - TTL-based expiration
//! - Reorg handling

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use protocore_types::{Address, SignedTransaction, H256};
use parking_lot::RwLock;
use tracing::{debug, info, trace, warn};

use crate::validation::{AccountStateProvider, TransactionValidator, ValidationConfig};
use crate::{MempoolError, Result};

/// Mempool configuration
#[derive(Debug, Clone)]
pub struct MempoolConfig {
    /// Maximum number of transactions in the pool
    pub max_size: usize,
    /// Maximum total bytes in the pool
    pub max_bytes: usize,
    /// Maximum size of a single transaction in bytes
    pub max_tx_size: usize,
    /// Time-to-live for transactions in seconds
    pub ttl_seconds: u64,
    /// Eviction check interval in seconds
    pub eviction_interval: u64,
    /// Minimum gas price bump percentage for replacement (e.g., 10 = 10%)
    pub price_bump_percentage: u64,
    /// Maximum number of pending transactions per sender
    pub max_pending_per_sender: usize,
    /// Maximum number of queued transactions per sender
    pub max_queued_per_sender: usize,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_size: 10_000,
            max_bytes: 100_000_000, // 100 MB
            max_tx_size: 131_072,   // 128 KB
            ttl_seconds: 3600,      // 1 hour
            eviction_interval: 60,  // 1 minute
            price_bump_percentage: 10,
            max_pending_per_sender: 64,
            max_queued_per_sender: 64,
        }
    }
}

/// Status of a transaction in the mempool
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Transaction is in the pending pool (ready for inclusion)
    Pending,
    /// Transaction is in the queued pool (waiting for nonce gap to be filled)
    Queued,
    /// Transaction is not in the pool
    NotFound,
}

/// Pending transaction with metadata
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    /// The signed transaction
    pub tx: SignedTransaction,
    /// Time when the transaction was received
    pub received_at: Instant,
    /// Effective gas price for ordering
    pub gas_price: u128,
    /// Sender address
    pub sender: Address,
    /// Transaction size in bytes
    pub size: usize,
}

impl PendingTransaction {
    /// Check if the transaction has expired
    pub fn is_expired(&self, ttl: Duration) -> bool {
        self.received_at.elapsed() > ttl
    }

    /// Get the transaction hash
    pub fn hash(&self) -> H256 {
        self.tx.hash()
    }

    /// Get the transaction nonce
    pub fn nonce(&self) -> u64 {
        self.tx.nonce()
    }
}

/// Transaction ordering key for the price-sorted index
///
/// Transactions are sorted by:
/// 1. Gas price (descending)
/// 2. Received time (ascending - first come first served for same price)
/// 3. Hash (for deterministic ordering)
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PriceOrderKey {
    /// Negated gas price for descending order
    neg_gas_price: i128,
    /// Received timestamp for FIFO within same price
    received_at_nanos: u128,
    /// Transaction hash for deterministic ordering
    hash: H256,
}

impl PriceOrderKey {
    fn new(gas_price: u128, received_at: Instant, hash: H256) -> Self {
        // Use negative gas price so higher prices come first in BTreeSet
        Self {
            neg_gas_price: -(gas_price as i128),
            // Use elapsed().as_nanos() as a proxy for ordering
            received_at_nanos: received_at.elapsed().as_nanos(),
            hash,
        }
    }
}

/// Internal mempool state
struct MempoolInner {
    /// All transactions by hash (both pending and queued)
    by_hash: HashMap<H256, PendingTransaction>,

    /// Pending transactions by sender and nonce
    pending_by_sender: HashMap<Address, BTreeMap<u64, H256>>,

    /// Queued transactions by sender and nonce (future nonces)
    queued_by_sender: HashMap<Address, BTreeMap<u64, H256>>,

    /// Pending transactions sorted by gas price (for block building)
    pending_by_price: BTreeSet<PriceOrderKey>,

    /// Total size in bytes
    total_bytes: usize,

    /// Total number of transactions
    total_count: usize,
}

impl MempoolInner {
    fn new() -> Self {
        Self {
            by_hash: HashMap::new(),
            pending_by_sender: HashMap::new(),
            queued_by_sender: HashMap::new(),
            pending_by_price: BTreeSet::new(),
            total_bytes: 0,
            total_count: 0,
        }
    }
}

/// Transaction mempool
///
/// Thread-safe transaction pool that manages pending and queued transactions.
pub struct Mempool<S: AccountStateProvider> {
    /// Internal state protected by RwLock
    inner: RwLock<MempoolInner>,
    /// Configuration
    config: MempoolConfig,
    /// Transaction validator
    validator: TransactionValidator<S>,
    /// State provider for nonce lookups
    state: Arc<S>,
}

impl<S: AccountStateProvider> Mempool<S> {
    /// Create a new mempool
    pub fn new(config: MempoolConfig, state: Arc<S>) -> Self {
        let validation_config = ValidationConfig {
            min_gas_price: 1_000_000_000, // 1 gwei
            max_tx_size: config.max_tx_size,
            block_gas_limit: 30_000_000,
            min_gas_limit: 21_000,
            chain_id: 1,
        };

        Self {
            inner: RwLock::new(MempoolInner::new()),
            config,
            validator: TransactionValidator::new(validation_config, Arc::clone(&state)),
            state,
        }
    }

    /// Create a new mempool with custom validation config
    pub fn with_validation_config(
        config: MempoolConfig,
        validation_config: ValidationConfig,
        state: Arc<S>,
    ) -> Self {
        Self {
            inner: RwLock::new(MempoolInner::new()),
            config,
            validator: TransactionValidator::new(validation_config, Arc::clone(&state)),
            state,
        }
    }

    /// Add a transaction to the mempool
    ///
    /// The transaction will be validated and placed in either the pending
    /// or queued pool depending on its nonce.
    pub fn add_transaction(&self, tx: SignedTransaction) -> Result<H256> {
        let hash = tx.hash();

        trace!(tx_hash = ?hash, "adding transaction to mempool");

        // Check if already exists
        {
            let inner = self.inner.read();
            if inner.by_hash.contains_key(&hash) {
                return Err(MempoolError::AlreadyExists);
            }
        }

        // Validate transaction
        let validation_result = self.validator.validate(&tx)?;

        let pending_tx = PendingTransaction {
            tx,
            received_at: Instant::now(),
            gas_price: validation_result.effective_gas_price,
            sender: validation_result.sender,
            size: validation_result.tx_size,
        };

        // Add to pool
        let mut inner = self.inner.write();

        // Check capacity
        self.ensure_capacity(&mut inner, pending_tx.size)?;

        // Determine if pending or queued based on nonce
        let account_nonce = self.state.get_nonce(&pending_tx.sender);
        let is_pending = self.try_add_pending(&mut inner, &pending_tx, account_nonce)?;

        if !is_pending {
            self.add_queued(&mut inner, &pending_tx)?;
        }

        // Add to main hash index
        inner.by_hash.insert(hash, pending_tx.clone());
        inner.total_bytes += pending_tx.size;
        inner.total_count += 1;

        debug!(
            tx_hash = ?hash,
            sender = ?pending_tx.sender,
            nonce = pending_tx.nonce(),
            gas_price = pending_tx.gas_price,
            is_pending = is_pending,
            "transaction added to mempool"
        );

        Ok(hash)
    }

    /// Try to add transaction to pending pool
    ///
    /// Returns true if added to pending, false if should be queued
    fn try_add_pending(
        &self,
        inner: &mut MempoolInner,
        pending_tx: &PendingTransaction,
        account_nonce: u64,
    ) -> Result<bool> {
        let tx_nonce = pending_tx.nonce();
        let sender = pending_tx.sender;

        // Get or calculate the next expected nonce for this sender
        let expected_nonce = self.get_pending_nonce_inner(inner, &sender, account_nonce);

        if tx_nonce < expected_nonce {
            // Check if this is a replacement
            return self.try_replace_transaction(inner, pending_tx, expected_nonce);
        }

        if tx_nonce == expected_nonce {
            // This transaction is ready for pending pool
            self.add_to_pending_pool(inner, pending_tx);

            // Promote any queued transactions that are now executable
            self.promote_queued_transactions(inner, &sender, tx_nonce + 1);

            return Ok(true);
        }

        // tx_nonce > expected_nonce - should be queued
        Ok(false)
    }

    /// Try to replace an existing transaction with the same nonce
    fn try_replace_transaction(
        &self,
        inner: &mut MempoolInner,
        pending_tx: &PendingTransaction,
        expected_nonce: u64,
    ) -> Result<bool> {
        let tx_nonce = pending_tx.nonce();
        let sender = pending_tx.sender;

        if tx_nonce >= expected_nonce {
            return Ok(false);
        }

        // Find existing transaction with same nonce
        let existing_hash = inner
            .pending_by_sender
            .get(&sender)
            .and_then(|nonces| nonces.get(&tx_nonce))
            .copied();

        if let Some(existing_hash) = existing_hash {
            // Extract data we need before modifying inner
            let (existing_gas_price, existing_size) = {
                if let Some(existing) = inner.by_hash.get(&existing_hash) {
                    (existing.gas_price, existing.size)
                } else {
                    // Entry doesn't exist anymore, fall through
                    return Err(MempoolError::NonceTooLow {
                        expected: expected_nonce,
                        actual: tx_nonce,
                    });
                }
            };

            // Check if new gas price is high enough (price bump required)
            let min_price = existing_gas_price
                + (existing_gas_price * self.config.price_bump_percentage as u128) / 100;

            if pending_tx.gas_price < min_price {
                return Err(MempoolError::ReplacementUnderpriced {
                    minimum: min_price,
                    provided: pending_tx.gas_price,
                });
            }

            // Replace the transaction - now safe since we extracted the data we needed
            self.remove_from_pending_pool(inner, &existing_hash);
            inner.by_hash.remove(&existing_hash);
            inner.total_bytes -= existing_size;
            inner.total_count -= 1;

            // Add new transaction
            self.add_to_pending_pool(inner, pending_tx);
            return Ok(true);
        }

        // Nonce is lower than what we have, reject
        Err(MempoolError::NonceTooLow {
            expected: expected_nonce,
            actual: tx_nonce,
        })
    }

    /// Add transaction to the pending pool internal indexes
    fn add_to_pending_pool(&self, inner: &mut MempoolInner, pending_tx: &PendingTransaction) {
        let hash = pending_tx.hash();

        // Add to sender index
        inner
            .pending_by_sender
            .entry(pending_tx.sender)
            .or_default()
            .insert(pending_tx.nonce(), hash);

        // Add to price-sorted index
        let price_key = PriceOrderKey::new(pending_tx.gas_price, pending_tx.received_at, hash);
        inner.pending_by_price.insert(price_key);
    }

    /// Remove transaction from the pending pool internal indexes
    fn remove_from_pending_pool(&self, inner: &mut MempoolInner, hash: &H256) {
        if let Some(pending_tx) = inner.by_hash.get(hash) {
            // Remove from sender index
            if let Some(nonces) = inner.pending_by_sender.get_mut(&pending_tx.sender) {
                nonces.remove(&pending_tx.nonce());
                if nonces.is_empty() {
                    inner.pending_by_sender.remove(&pending_tx.sender);
                }
            }

            // Remove from price-sorted index
            let price_key =
                PriceOrderKey::new(pending_tx.gas_price, pending_tx.received_at, *hash);
            inner.pending_by_price.remove(&price_key);
        }
    }

    /// Add transaction to the queued pool
    fn add_queued(&self, inner: &mut MempoolInner, pending_tx: &PendingTransaction) -> Result<()> {
        let sender = pending_tx.sender;

        // Check queued limit per sender
        let queued_count = inner
            .queued_by_sender
            .get(&sender)
            .map(|m| m.len())
            .unwrap_or(0);

        if queued_count >= self.config.max_queued_per_sender {
            // Evict lowest gas price queued transaction from this sender
            self.evict_queued_from_sender(inner, &sender)?;
        }

        inner
            .queued_by_sender
            .entry(sender)
            .or_default()
            .insert(pending_tx.nonce(), pending_tx.hash());

        Ok(())
    }

    /// Remove transaction from the queued pool
    fn remove_from_queued_pool(&self, inner: &mut MempoolInner, hash: &H256) {
        if let Some(pending_tx) = inner.by_hash.get(hash) {
            if let Some(nonces) = inner.queued_by_sender.get_mut(&pending_tx.sender) {
                nonces.remove(&pending_tx.nonce());
                if nonces.is_empty() {
                    inner.queued_by_sender.remove(&pending_tx.sender);
                }
            }
        }
    }

    /// Promote queued transactions to pending when nonce gaps are filled
    fn promote_queued_transactions(
        &self,
        inner: &mut MempoolInner,
        sender: &Address,
        start_nonce: u64,
    ) {
        let mut next_nonce = start_nonce;

        loop {
            // Check if there's a queued transaction with the next nonce
            let hash = inner
                .queued_by_sender
                .get(sender)
                .and_then(|nonces| nonces.get(&next_nonce))
                .copied();

            match hash {
                Some(hash) => {
                    if let Some(pending_tx) = inner.by_hash.get(&hash).cloned() {
                        // Remove from queued
                        if let Some(nonces) = inner.queued_by_sender.get_mut(sender) {
                            nonces.remove(&next_nonce);
                            if nonces.is_empty() {
                                inner.queued_by_sender.remove(sender);
                            }
                        }

                        // Add to pending
                        self.add_to_pending_pool(inner, &pending_tx);

                        trace!(
                            tx_hash = ?hash,
                            nonce = next_nonce,
                            "promoted transaction from queued to pending"
                        );

                        next_nonce += 1;
                    } else {
                        break;
                    }
                }
                None => break,
            }
        }
    }

    /// Evict lowest gas price queued transaction from a sender
    fn evict_queued_from_sender(&self, inner: &mut MempoolInner, sender: &Address) -> Result<()> {
        let lowest_hash = inner
            .queued_by_sender
            .get(sender)
            .and_then(|nonces| {
                nonces
                    .values()
                    .filter_map(|h| inner.by_hash.get(h))
                    .min_by_key(|tx| tx.gas_price)
                    .map(|tx| tx.hash())
            });

        if let Some(hash) = lowest_hash {
            self.remove_from_queued_pool(inner, &hash);
            if let Some(removed) = inner.by_hash.remove(&hash) {
                inner.total_bytes -= removed.size;
                inner.total_count -= 1;
            }
            Ok(())
        } else {
            Err(MempoolError::PoolFull)
        }
    }

    /// Get the next pending nonce for a sender
    fn get_pending_nonce_inner(
        &self,
        inner: &MempoolInner,
        sender: &Address,
        account_nonce: u64,
    ) -> u64 {
        inner
            .pending_by_sender
            .get(sender)
            .and_then(|nonces| nonces.keys().max())
            .map(|max_nonce| max_nonce + 1)
            .unwrap_or(account_nonce)
    }

    /// Ensure there's capacity for a new transaction
    fn ensure_capacity(&self, inner: &mut MempoolInner, tx_size: usize) -> Result<()> {
        // Evict if over count limit
        while inner.total_count >= self.config.max_size {
            self.evict_lowest_price(inner)?;
        }

        // Evict if over byte limit
        while inner.total_bytes + tx_size > self.config.max_bytes {
            self.evict_lowest_price(inner)?;
        }

        Ok(())
    }

    /// Evict the transaction with lowest gas price from pending pool
    fn evict_lowest_price(&self, inner: &mut MempoolInner) -> Result<()> {
        // Get lowest price pending transaction
        let lowest = inner.pending_by_price.iter().next_back().cloned();

        if let Some(price_key) = lowest {
            let hash = price_key.hash;
            self.remove_from_pending_pool(inner, &hash);

            if let Some(removed) = inner.by_hash.remove(&hash) {
                inner.total_bytes -= removed.size;
                inner.total_count -= 1;
                debug!(tx_hash = ?hash, "evicted transaction due to pool capacity");
                return Ok(());
            }
        }

        // Try evicting from queued if pending is empty
        let first_sender = inner.queued_by_sender.keys().next().cloned();
        if let Some(sender) = first_sender {
            return self.evict_queued_from_sender(inner, &sender);
        }

        Err(MempoolError::PoolFull)
    }

    /// Remove a transaction from the mempool (after inclusion in a block)
    pub fn remove_transaction(&self, hash: &H256) -> Option<PendingTransaction> {
        let mut inner = self.inner.write();

        // Check if in pending pool
        if inner
            .by_hash
            .get(hash)
            .map(|tx| {
                inner
                    .pending_by_sender
                    .get(&tx.sender)
                    .map(|nonces| nonces.contains_key(&tx.nonce()))
                    .unwrap_or(false)
            })
            .unwrap_or(false)
        {
            self.remove_from_pending_pool(&mut inner, hash);
        } else {
            // Check if in queued pool
            self.remove_from_queued_pool(&mut inner, hash);
        }

        // Remove from main index
        let removed = inner.by_hash.remove(hash);
        if let Some(ref tx) = removed {
            inner.total_bytes -= tx.size;
            inner.total_count -= 1;
        }

        removed
    }

    /// Remove multiple transactions (batch removal after block)
    pub fn remove_transactions(&self, hashes: &[H256]) {
        let mut inner = self.inner.write();

        for hash in hashes {
            if inner
                .by_hash
                .get(hash)
                .map(|tx| {
                    inner
                        .pending_by_sender
                        .get(&tx.sender)
                        .map(|nonces| nonces.contains_key(&tx.nonce()))
                        .unwrap_or(false)
                })
                .unwrap_or(false)
            {
                self.remove_from_pending_pool(&mut inner, hash);
            } else {
                self.remove_from_queued_pool(&mut inner, hash);
            }

            if let Some(removed) = inner.by_hash.remove(hash) {
                inner.total_bytes -= removed.size;
                inner.total_count -= 1;
            }
        }
    }

    /// Get pending transactions sorted by gas price for block building
    ///
    /// Returns transactions up to the given gas limit, respecting nonce ordering.
    pub fn get_pending_transactions(&self, gas_limit: u64) -> Vec<SignedTransaction> {
        let inner = self.inner.read();
        let mut result = Vec::new();
        let mut gas_used = 0u64;
        let mut included_nonces: HashMap<Address, u64> = HashMap::new();

        // Iterate by gas price (highest first)
        for price_key in &inner.pending_by_price {
            let hash = price_key.hash;

            if let Some(pending) = inner.by_hash.get(&hash) {
                let tx_gas = pending.tx.gas_limit();

                // Check if fits in gas limit
                if gas_used.saturating_add(tx_gas) > gas_limit {
                    continue;
                }

                // Check nonce ordering
                let account_nonce = self.state.get_nonce(&pending.sender);
                let expected_nonce = included_nonces
                    .get(&pending.sender)
                    .copied()
                    .unwrap_or(account_nonce);

                if pending.nonce() != expected_nonce {
                    continue;
                }

                // Include this transaction
                result.push(pending.tx.clone());
                gas_used += tx_gas;
                included_nonces.insert(pending.sender, pending.nonce() + 1);

                // Early exit if we've hit the gas limit
                if gas_used >= gas_limit {
                    break;
                }
            }
        }

        result
    }

    /// Get a transaction by hash
    pub fn get_transaction(&self, hash: &H256) -> Option<SignedTransaction> {
        self.inner
            .read()
            .by_hash
            .get(hash)
            .map(|p| p.tx.clone())
    }

    /// Get a pending transaction with metadata by hash
    pub fn get_pending_transaction(&self, hash: &H256) -> Option<PendingTransaction> {
        self.inner.read().by_hash.get(hash).cloned()
    }

    /// Get transaction status
    pub fn get_status(&self, hash: &H256) -> TransactionStatus {
        let inner = self.inner.read();

        if let Some(pending) = inner.by_hash.get(hash) {
            if inner
                .pending_by_sender
                .get(&pending.sender)
                .map(|nonces| nonces.contains_key(&pending.nonce()))
                .unwrap_or(false)
            {
                TransactionStatus::Pending
            } else {
                TransactionStatus::Queued
            }
        } else {
            TransactionStatus::NotFound
        }
    }

    /// Get all pending transactions from a sender
    pub fn get_transactions_by_sender(&self, sender: &Address) -> Vec<SignedTransaction> {
        let inner = self.inner.read();

        inner
            .pending_by_sender
            .get(sender)
            .map(|nonces| {
                nonces
                    .values()
                    .filter_map(|hash| inner.by_hash.get(hash))
                    .map(|p| p.tx.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get the pending nonce for a sender (account nonce + pending count)
    pub fn get_pending_nonce(&self, sender: &Address) -> u64 {
        let inner = self.inner.read();
        let account_nonce = self.state.get_nonce(sender);
        self.get_pending_nonce_inner(&inner, sender, account_nonce)
    }

    /// Handle chain reorg by re-adding transactions from reverted blocks
    ///
    /// This should be called when blocks are reverted, to re-add their
    /// transactions to the mempool for potential re-inclusion.
    pub fn handle_reorg(&self, reverted_txs: Vec<SignedTransaction>) {
        info!(
            count = reverted_txs.len(),
            "handling reorg, re-adding transactions"
        );

        for tx in reverted_txs {
            // Try to add back to mempool
            // Transactions may fail validation if state has changed
            match self.add_transaction(tx) {
                Ok(hash) => {
                    trace!(tx_hash = ?hash, "re-added reverted transaction");
                }
                Err(e) => {
                    trace!(error = %e, "failed to re-add reverted transaction");
                }
            }
        }
    }

    /// Remove expired transactions (TTL-based eviction)
    pub fn remove_expired(&self) -> usize {
        let ttl = Duration::from_secs(self.config.ttl_seconds);
        let mut inner = self.inner.write();

        let expired: Vec<H256> = inner
            .by_hash
            .iter()
            .filter(|(_, tx)| tx.is_expired(ttl))
            .map(|(hash, _)| *hash)
            .collect();

        let count = expired.len();

        for hash in expired {
            if inner
                .by_hash
                .get(&hash)
                .map(|tx| {
                    inner
                        .pending_by_sender
                        .get(&tx.sender)
                        .map(|nonces| nonces.contains_key(&tx.nonce()))
                        .unwrap_or(false)
                })
                .unwrap_or(false)
            {
                self.remove_from_pending_pool(&mut inner, &hash);
            } else {
                self.remove_from_queued_pool(&mut inner, &hash);
            }

            if let Some(removed) = inner.by_hash.remove(&hash) {
                inner.total_bytes -= removed.size;
                inner.total_count -= 1;
            }
        }

        if count > 0 {
            debug!(count = count, "removed expired transactions");
        }

        count
    }

    /// Update after new block - remove included transactions and update nonces
    pub fn on_new_block(&self, included_tx_hashes: &[H256]) {
        // Remove included transactions
        self.remove_transactions(included_tx_hashes);

        // Promote queued transactions that are now executable
        let mut inner = self.inner.write();

        // Get all senders with queued transactions
        let senders: Vec<Address> = inner.queued_by_sender.keys().cloned().collect();

        for sender in senders {
            let account_nonce = self.state.get_nonce(&sender);
            let pending_nonce = self.get_pending_nonce_inner(&inner, &sender, account_nonce);
            self.promote_queued_transactions(&mut inner, &sender, pending_nonce);
        }
    }

    /// Get mempool statistics
    pub fn stats(&self) -> MempoolStats {
        let inner = self.inner.read();

        let pending_count = inner
            .pending_by_sender
            .values()
            .map(|m| m.len())
            .sum();

        let queued_count = inner
            .queued_by_sender
            .values()
            .map(|m| m.len())
            .sum();

        MempoolStats {
            pending_count,
            queued_count,
            total_count: inner.total_count,
            total_bytes: inner.total_bytes,
            unique_senders: inner.pending_by_sender.len() + inner.queued_by_sender.len(),
        }
    }

    /// Clear all transactions from the mempool
    pub fn clear(&self) {
        let mut inner = self.inner.write();
        inner.by_hash.clear();
        inner.pending_by_sender.clear();
        inner.queued_by_sender.clear();
        inner.pending_by_price.clear();
        inner.total_bytes = 0;
        inner.total_count = 0;
    }
}

/// Mempool statistics
#[derive(Debug, Clone)]
pub struct MempoolStats {
    /// Number of pending (executable) transactions
    pub pending_count: usize,
    /// Number of queued (future) transactions
    pub queued_count: usize,
    /// Total number of transactions
    pub total_count: usize,
    /// Total size in bytes
    pub total_bytes: usize,
    /// Number of unique senders
    pub unique_senders: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_order_key_ordering() {
        let hash1 = H256::default();
        let hash2 = H256::default();
        let now = Instant::now();

        // Higher gas price should come first (lower neg_gas_price)
        let key1 = PriceOrderKey::new(100, now, hash1);
        let key2 = PriceOrderKey::new(50, now, hash2);

        assert!(key1 < key2); // key1 has higher price, so it should be "less" (come first)
    }
}
