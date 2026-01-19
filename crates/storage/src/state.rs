//! State storage and management
//!
//! This module provides account state management with support for:
//! - Account state (nonce, balance, code_hash, storage_root)
//! - Storage slots per account
//! - Commit/revert with state root computation
//! - State diff tracking

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::{debug, trace};

use crate::db::{cf, Database, WriteBatch};
use crate::trie::MerkleTrie;
use crate::{keccak256, Address, Hash, Result, StorageError, EMPTY_HASH, EMPTY_ROOT, ZERO_HASH};

/// Account state
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Account {
    /// Transaction nonce
    pub nonce: u64,
    /// Account balance in wei
    pub balance: u128,
    /// Hash of the account's contract code (EMPTY_HASH if no code)
    pub code_hash: Hash,
    /// Root hash of the account's storage trie
    pub storage_root: Hash,
}

impl Account {
    /// Create a new empty account
    pub fn new() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            code_hash: EMPTY_HASH,
            storage_root: EMPTY_ROOT,
        }
    }

    /// Create an account with balance
    pub fn with_balance(balance: u128) -> Self {
        Self {
            nonce: 0,
            balance,
            code_hash: EMPTY_HASH,
            storage_root: EMPTY_ROOT,
        }
    }

    /// Check if this is an empty account
    pub fn is_empty(&self) -> bool {
        self.nonce == 0 && self.balance == 0 && self.code_hash == EMPTY_HASH
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash != EMPTY_HASH
    }

    /// Encode the account for storage
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode an account from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

/// State change for a single account
#[derive(Debug, Clone)]
pub struct AccountChange {
    /// Previous account state (None if newly created)
    pub previous: Option<Account>,
    /// New account state (None if deleted)
    pub current: Option<Account>,
    /// Storage changes (slot -> (previous, current))
    pub storage: HashMap<Hash, (Hash, Hash)>,
}

/// State diff tracking all changes
#[derive(Debug, Clone, Default)]
pub struct StateDiff {
    /// Account changes
    pub accounts: HashMap<Address, AccountChange>,
    /// Previous state root
    pub previous_root: Hash,
    /// New state root
    pub new_root: Hash,
}

impl StateDiff {
    /// Create a new empty state diff
    pub fn new(previous_root: Hash) -> Self {
        Self {
            accounts: HashMap::new(),
            previous_root,
            new_root: previous_root,
        }
    }

    /// Check if the diff is empty
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
    }

    /// Get all modified addresses
    pub fn modified_addresses(&self) -> HashSet<Address> {
        self.accounts.keys().copied().collect()
    }
}

/// State snapshot for reverting changes
#[derive(Debug, Clone)]
pub struct StateSnapshot {
    /// Snapshot ID
    pub id: u64,
    /// State root at snapshot time
    pub root: Hash,
    /// Account cache at snapshot time
    pub accounts: HashMap<Address, Option<Account>>,
    /// Storage cache at snapshot time
    pub storage: HashMap<(Address, Hash), Hash>,
}

/// State database managing account and storage state
pub struct StateDB {
    /// Underlying database
    db: Arc<Database>,
    /// State trie
    state_trie: MerkleTrie,
    /// Storage tries per account
    storage_tries: RwLock<HashMap<Address, MerkleTrie>>,
    /// Account cache
    account_cache: RwLock<HashMap<Address, Option<Account>>>,
    /// Storage cache
    storage_cache: RwLock<HashMap<(Address, Hash), Hash>>,
    /// Dirty accounts (modified since last commit)
    dirty_accounts: RwLock<HashSet<Address>>,
    /// Dirty storage slots
    dirty_storage: RwLock<HashSet<(Address, Hash)>>,
    /// Snapshot counter
    snapshot_id: RwLock<u64>,
    /// Snapshots
    snapshots: RwLock<Vec<StateSnapshot>>,
    /// Current state diff
    current_diff: RwLock<StateDiff>,
}

impl StateDB {
    /// Create a new StateDB with an existing database
    pub fn new(db: Arc<Database>) -> Self {
        let root = Self::load_state_root(&db).unwrap_or(EMPTY_ROOT);
        let state_trie = MerkleTrie::new();

        Self {
            db,
            state_trie,
            storage_tries: RwLock::new(HashMap::new()),
            account_cache: RwLock::new(HashMap::new()),
            storage_cache: RwLock::new(HashMap::new()),
            dirty_accounts: RwLock::new(HashSet::new()),
            dirty_storage: RwLock::new(HashSet::new()),
            snapshot_id: RwLock::new(0),
            snapshots: RwLock::new(Vec::new()),
            current_diff: RwLock::new(StateDiff::new(root)),
        }
    }

    /// Load state root from database
    fn load_state_root(db: &Database) -> Result<Hash> {
        db.get_metadata(b"state_root")?
            .map(|data| {
                let mut hash = [0u8; 32];
                if data.len() == 32 {
                    hash.copy_from_slice(&data);
                }
                hash
            })
            .ok_or_else(|| StorageError::NotFound("state_root".to_string()))
    }

    /// Get the current state root
    pub fn state_root(&self) -> Hash {
        self.state_trie.root()
    }

    /// Get an account by address
    pub fn get_account(&self, address: &Address) -> Option<Account> {
        // Check cache first
        if let Some(cached) = self.account_cache.read().get(address) {
            return cached.clone();
        }

        // Load from trie
        let account = self.load_account_from_trie(address);

        // Cache the result
        self.account_cache.write().insert(*address, account.clone());

        account
    }

    /// Load account from the state trie
    fn load_account_from_trie(&self, address: &Address) -> Option<Account> {
        self.state_trie
            .get(address)
            .ok()
            .flatten()
            .and_then(|data| Account::decode(&data).ok())
    }

    /// Set account state
    pub fn set_account(&self, address: &Address, account: Account) {
        let previous = self.get_account(address);

        // Update cache
        self.account_cache
            .write()
            .insert(*address, Some(account.clone()));

        // Mark as dirty
        self.dirty_accounts.write().insert(*address);

        // Track in diff
        self.update_account_diff(address, previous, Some(account));

        trace!("Set account {:?}", address);
    }

    /// Delete an account
    pub fn delete_account(&self, address: &Address) {
        let previous = self.get_account(address);

        // Update cache
        self.account_cache.write().insert(*address, None);

        // Mark as dirty
        self.dirty_accounts.write().insert(*address);

        // Track in diff
        self.update_account_diff(address, previous, None);

        // Clear storage cache for this account
        self.storage_cache
            .write()
            .retain(|(addr, _), _| addr != address);

        trace!("Deleted account {:?}", address);
    }

    /// Update account diff tracking
    fn update_account_diff(
        &self,
        address: &Address,
        previous: Option<Account>,
        current: Option<Account>,
    ) {
        let mut diff = self.current_diff.write();
        if let Some(change) = diff.accounts.get_mut(address) {
            change.current = current;
        } else {
            diff.accounts.insert(
                *address,
                AccountChange {
                    previous,
                    current,
                    storage: HashMap::new(),
                },
            );
        }
    }

    /// Get a storage value
    pub fn get_storage(&self, address: &Address, slot: &Hash) -> Hash {
        let key = (*address, *slot);

        // Check cache first
        if let Some(&value) = self.storage_cache.read().get(&key) {
            return value;
        }

        // Load from storage trie
        let value = self.load_storage_from_trie(address, slot);

        // Cache the result
        self.storage_cache.write().insert(key, value);

        value
    }

    /// Load storage from account's storage trie
    fn load_storage_from_trie(&self, address: &Address, slot: &Hash) -> Hash {
        // Get or create storage trie for this account
        let storage_tries = self.storage_tries.read();
        if let Some(trie) = storage_tries.get(address) {
            trie.get(slot)
                .ok()
                .flatten()
                .map(|data| {
                    let mut hash = [0u8; 32];
                    if data.len() == 32 {
                        hash.copy_from_slice(&data);
                    }
                    hash
                })
                .unwrap_or(ZERO_HASH)
        } else {
            // Try to load from database
            let db_key = self.storage_db_key(address, slot);
            self.db
                .get(cf::STATE, &db_key)
                .ok()
                .flatten()
                .map(|data| {
                    let mut hash = [0u8; 32];
                    if data.len() == 32 {
                        hash.copy_from_slice(&data);
                    }
                    hash
                })
                .unwrap_or(ZERO_HASH)
        }
    }

    /// Set a storage value
    pub fn set_storage(&self, address: &Address, slot: &Hash, value: Hash) {
        let previous = self.get_storage(address, slot);
        let key = (*address, *slot);

        // Update cache
        self.storage_cache.write().insert(key, value);

        // Mark as dirty
        self.dirty_storage.write().insert(key);

        // Track in diff
        self.update_storage_diff(address, slot, previous, value);

        trace!("Set storage {:?}[{:?}] = {:?}", address, slot, value);
    }

    /// Update storage diff tracking
    fn update_storage_diff(
        &self,
        address: &Address,
        slot: &Hash,
        previous: Hash,
        current: Hash,
    ) {
        let mut diff = self.current_diff.write();
        if let Some(change) = diff.accounts.get_mut(address) {
            change.storage.insert(*slot, (previous, current));
        } else {
            let mut storage = HashMap::new();
            storage.insert(*slot, (previous, current));
            diff.accounts.insert(
                *address,
                AccountChange {
                    previous: self.get_account(address),
                    current: self.get_account(address),
                    storage,
                },
            );
        }
    }

    /// Create database key for account
    fn account_db_key(&self, address: &Address) -> Vec<u8> {
        let mut key = vec![0x00]; // Account prefix
        key.extend(address);
        key
    }

    /// Create database key for storage
    fn storage_db_key(&self, address: &Address, slot: &Hash) -> Vec<u8> {
        let mut key = vec![0x01]; // Storage prefix
        key.extend(address);
        key.extend(slot);
        key
    }

    /// Create database key for code
    fn code_db_key(&self, code_hash: &Hash) -> Vec<u8> {
        let mut key = vec![0x02]; // Code prefix
        key.extend(code_hash);
        key
    }

    /// Get contract code by hash
    pub fn get_code(&self, code_hash: &Hash) -> Option<Vec<u8>> {
        if *code_hash == EMPTY_HASH {
            return Some(Vec::new());
        }

        let key = self.code_db_key(code_hash);
        self.db.get(cf::STATE, &key).ok().flatten()
    }

    /// Store contract code
    pub fn set_code(&self, code: &[u8]) -> Result<Hash> {
        if code.is_empty() {
            return Ok(EMPTY_HASH);
        }

        let code_hash = keccak256(code);
        let key = self.code_db_key(&code_hash);
        self.db.put(cf::STATE, &key, code)?;

        Ok(code_hash)
    }

    /// Create a snapshot of the current state
    pub fn snapshot(&self) -> u64 {
        let mut id = self.snapshot_id.write();
        *id += 1;
        let snapshot_id = *id;

        let snapshot = StateSnapshot {
            id: snapshot_id,
            root: self.state_root(),
            accounts: self.account_cache.read().clone(),
            storage: self.storage_cache.read().clone(),
        };

        self.snapshots.write().push(snapshot);

        debug!("Created state snapshot {}", snapshot_id);
        snapshot_id
    }

    /// Revert to a snapshot
    pub fn revert_to_snapshot(&self, id: u64) -> Result<()> {
        let mut snapshots = self.snapshots.write();

        // Find the snapshot
        let idx = snapshots
            .iter()
            .position(|s| s.id == id)
            .ok_or_else(|| StorageError::Snapshot(format!("Snapshot {} not found", id)))?;

        let snapshot = snapshots[idx].clone();

        // Remove this and all later snapshots
        snapshots.truncate(idx);

        // Restore state
        *self.account_cache.write() = snapshot.accounts;
        *self.storage_cache.write() = snapshot.storage;

        // Clear dirty sets (changes are discarded)
        self.dirty_accounts.write().clear();
        self.dirty_storage.write().clear();

        // Reset diff
        *self.current_diff.write() = StateDiff::new(snapshot.root);

        debug!("Reverted to snapshot {}", id);
        Ok(())
    }

    /// Discard a snapshot (keep changes)
    pub fn discard_snapshot(&self, id: u64) {
        let mut snapshots = self.snapshots.write();
        snapshots.retain(|s| s.id != id);
        debug!("Discarded snapshot {}", id);
    }

    /// Commit all changes and compute new state root
    pub fn commit(&self) -> Result<Hash> {
        let dirty_accounts: Vec<Address> = self.dirty_accounts.read().iter().copied().collect();
        let dirty_storage: Vec<(Address, Hash)> =
            self.dirty_storage.read().iter().copied().collect();

        debug!(
            "Committing {} accounts and {} storage slots",
            dirty_accounts.len(),
            dirty_storage.len()
        );

        // Prepare batch write
        let mut batch = WriteBatch::new();
        let cf = self.db.cf_handle(cf::STATE)?;

        // Update storage tries and persist storage
        for (address, slot) in &dirty_storage {
            if let Some(&value) = self.storage_cache.read().get(&(*address, *slot)) {
                let key = self.storage_db_key(address, slot);
                if value == ZERO_HASH {
                    batch.delete_cf(&cf, &key);
                } else {
                    batch.put_cf(&cf, &key, &value);
                }

                // Update storage trie
                let mut storage_tries = self.storage_tries.write();
                let storage_trie = storage_tries.entry(*address).or_insert_with(MerkleTrie::new);
                if value == ZERO_HASH {
                    let _ = storage_trie.delete(slot);
                } else {
                    storage_trie.insert(slot, &value)?;
                }
            }
        }

        // Update accounts with new storage roots
        for address in &dirty_accounts {
            if let Some(Some(mut account)) = self.account_cache.read().get(address).cloned() {
                // Update storage root if account has storage changes
                if let Some(storage_trie) = self.storage_tries.read().get(address) {
                    account.storage_root = storage_trie.root();
                }

                // Update state trie
                self.state_trie.insert(address, &account.encode())?;

                // Persist to database
                let key = self.account_db_key(address);
                batch.put_cf(&cf, &key, &account.encode());
            } else {
                // Account deleted
                let _ = self.state_trie.delete(address);
                let key = self.account_db_key(address);
                batch.delete_cf(&cf, &key);
            }
        }

        // Write batch to database
        self.db.write_batch(batch)?;

        // Get new state root
        let new_root = self.state_trie.root();

        // Persist state root
        self.db.put_metadata(b"state_root", &new_root)?;

        // Update diff
        {
            let mut diff = self.current_diff.write();
            diff.new_root = new_root;
        }

        // Clear dirty sets
        self.dirty_accounts.write().clear();
        self.dirty_storage.write().clear();

        debug!("Committed state, new root: {:?}", new_root);
        Ok(new_root)
    }

    /// Get the current state diff
    pub fn state_diff(&self) -> StateDiff {
        self.current_diff.read().clone()
    }

    /// Clear the state diff
    pub fn clear_diff(&self) {
        let root = self.state_root();
        *self.current_diff.write() = StateDiff::new(root);
    }

    /// Get account nonce
    pub fn get_nonce(&self, address: &Address) -> u64 {
        self.get_account(address).map(|a| a.nonce).unwrap_or(0)
    }

    /// Increment account nonce
    pub fn increment_nonce(&self, address: &Address) {
        let mut account = self.get_account(address).unwrap_or_default();
        account.nonce += 1;
        self.set_account(address, account);
    }

    /// Get account balance
    pub fn get_balance(&self, address: &Address) -> u128 {
        self.get_account(address).map(|a| a.balance).unwrap_or(0)
    }

    /// Add to account balance
    pub fn add_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self.get_account(address).unwrap_or_default();
        account.balance = account
            .balance
            .checked_add(amount)
            .ok_or_else(|| StorageError::Trie("Balance overflow".to_string()))?;
        self.set_account(address, account);
        Ok(())
    }

    /// Subtract from account balance
    pub fn sub_balance(&self, address: &Address, amount: u128) -> Result<()> {
        let mut account = self.get_account(address).unwrap_or_default();
        account.balance = account
            .balance
            .checked_sub(amount)
            .ok_or_else(|| StorageError::Trie("Insufficient balance".to_string()))?;
        self.set_account(address, account);
        Ok(())
    }

    /// Transfer balance between accounts
    pub fn transfer(&self, from: &Address, to: &Address, amount: u128) -> Result<()> {
        self.sub_balance(from, amount)?;
        self.add_balance(to, amount)?;
        Ok(())
    }

    /// Check if an account exists
    pub fn exists(&self, address: &Address) -> bool {
        self.get_account(address).is_some()
    }

    /// Check if an account is empty
    pub fn is_empty_account(&self, address: &Address) -> bool {
        self.get_account(address)
            .map(|a| a.is_empty())
            .unwrap_or(true)
    }

    /// Get the database reference
    pub fn database(&self) -> &Database {
        &self.db
    }

    /// Get the number of cached accounts
    pub fn cached_accounts(&self) -> usize {
        self.account_cache.read().len()
    }

    /// Get the number of cached storage slots
    pub fn cached_storage(&self) -> usize {
        self.storage_cache.read().len()
    }

    /// Clear all caches
    pub fn clear_cache(&self) {
        self.account_cache.write().clear();
        self.storage_cache.write().clear();
    }
}

