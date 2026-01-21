//! State Adapter
//!
//! Adapts the Proto Core storage layer to work with revm's Database trait.

use alloy_primitives::{Address, B256, U256};
use revm::{
    primitives::{AccountInfo, Bytecode, HashMap},
    Database, DatabaseCommit,
};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use tracing::trace;

/// Trait for databases that can provide a state root
///
/// This is used by the EVM executor to get the actual state root
/// from the underlying storage (e.g., Merkle Patricia Trie).
pub trait StateRootProvider {
    /// Get the current state root after all pending changes are committed
    fn state_root(&self) -> B256;
}

/// State adapter that wraps the underlying database for revm compatibility
pub struct StateAdapter<DB: Database> {
    /// Underlying database
    db: DB,
    /// Pending account changes (not yet committed)
    pending_accounts: HashMap<Address, AccountInfo>,
    /// Pending storage changes (not yet committed)
    pending_storage: HashMap<Address, HashMap<U256, U256>>,
    /// Pending code changes (not yet committed)
    pending_code: HashMap<B256, Bytecode>,
}

impl<DB: Database> StateAdapter<DB> {
    /// Create a new state adapter wrapping the given database
    pub fn new(db: DB) -> Self {
        Self {
            db,
            pending_accounts: HashMap::default(),
            pending_storage: HashMap::default(),
            pending_code: HashMap::default(),
        }
    }

    /// Get a reference to the underlying database
    pub fn inner(&self) -> &DB {
        &self.db
    }

    /// Get a mutable reference to the underlying database
    pub fn inner_mut(&mut self) -> &mut DB {
        &mut self.db
    }

    /// Check if there are pending changes
    pub fn has_pending_changes(&self) -> bool {
        !self.pending_accounts.is_empty()
            || !self.pending_storage.is_empty()
            || !self.pending_code.is_empty()
    }

    /// Clear all pending changes without committing
    pub fn rollback(&mut self) {
        self.pending_accounts.clear();
        self.pending_storage.clear();
        self.pending_code.clear();
    }
}

/// Additional methods for StateAdapter when the underlying DB provides state root
impl<DB: Database + StateRootProvider> StateAdapter<DB> {
    /// Get the state root from the underlying database
    ///
    /// This delegates to the underlying DB's state root provider.
    /// Note: The caller should ensure pending changes are committed first.
    pub fn state_root(&self) -> B256 {
        self.db.state_root()
    }
}

impl<DB: Database> StateAdapter<DB> {
    /// Get account balance
    pub fn get_balance(&mut self, address: Address) -> Result<U256, DB::Error> {
        if let Some(account) = self.pending_accounts.get(&address) {
            return Ok(account.balance);
        }
        Ok(self.db.basic(address)?.map_or(U256::ZERO, |a| a.balance))
    }

    /// Get account nonce
    pub fn get_nonce(&mut self, address: Address) -> Result<u64, DB::Error> {
        if let Some(account) = self.pending_accounts.get(&address) {
            return Ok(account.nonce);
        }
        Ok(self.db.basic(address)?.map_or(0, |a| a.nonce))
    }

    /// Set account balance (pending until commit)
    pub fn set_balance(&mut self, address: Address, balance: U256) -> Result<(), DB::Error> {
        let account = self
            .pending_accounts
            .entry(address)
            .or_insert_with(|| self.db.basic(address).ok().flatten().unwrap_or_default());
        account.balance = balance;
        Ok(())
    }

    /// Add to account balance (pending until commit)
    pub fn add_balance(&mut self, address: Address, amount: U256) -> Result<(), DB::Error> {
        let current = self.get_balance(address)?;
        self.set_balance(address, current.saturating_add(amount))
    }

    /// Subtract from account balance (pending until commit)
    pub fn sub_balance(&mut self, address: Address, amount: U256) -> Result<(), DB::Error> {
        let current = self.get_balance(address)?;
        self.set_balance(address, current.saturating_sub(amount))
    }

    /// Increment account nonce (pending until commit)
    pub fn increment_nonce(&mut self, address: Address) -> Result<(), DB::Error> {
        let account = self
            .pending_accounts
            .entry(address)
            .or_insert_with(|| self.db.basic(address).ok().flatten().unwrap_or_default());
        account.nonce += 1;
        Ok(())
    }

    /// Get storage value
    pub fn get_storage(&mut self, address: Address, slot: U256) -> Result<U256, DB::Error> {
        // Check pending storage first
        if let Some(account_storage) = self.pending_storage.get(&address) {
            if let Some(value) = account_storage.get(&slot) {
                return Ok(*value);
            }
        }
        self.db.storage(address, slot)
    }

    /// Set storage value (pending until commit)
    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.pending_storage
            .entry(address)
            .or_default()
            .insert(slot, value);
    }

    /// Get code by hash
    pub fn get_code(&mut self, code_hash: B256) -> Result<Bytecode, DB::Error> {
        if let Some(code) = self.pending_code.get(&code_hash) {
            return Ok(code.clone());
        }
        self.db.code_by_hash(code_hash)
    }

    /// Set code (pending until commit)
    pub fn set_code(&mut self, code_hash: B256, code: Bytecode) {
        self.pending_code.insert(code_hash, code);
    }
}

impl<DB: Database> Database for StateAdapter<DB>
where
    DB::Error: std::fmt::Debug,
{
    type Error = DB::Error;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        // Check pending changes first
        if let Some(account) = self.pending_accounts.get(&address) {
            trace!(address = %address, "Loading account from pending");
            return Ok(Some(account.clone()));
        }

        // Fall through to underlying database
        trace!(address = %address, "Loading account from database");
        self.db.basic(address)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        // Check pending code first
        if let Some(code) = self.pending_code.get(&code_hash) {
            trace!(hash = %code_hash, "Loading code from pending");
            return Ok(code.clone());
        }

        // Fall through to underlying database
        trace!(hash = %code_hash, "Loading code from database");
        self.db.code_by_hash(code_hash)
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        // Check pending storage first
        if let Some(account_storage) = self.pending_storage.get(&address) {
            if let Some(value) = account_storage.get(&index) {
                trace!(address = %address, slot = %index, "Loading storage from pending");
                return Ok(*value);
            }
        }

        // Fall through to underlying database
        trace!(address = %address, slot = %index, "Loading storage from database");
        self.db.storage(address, index)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        trace!(number = number, "Loading block hash");
        self.db.block_hash(number)
    }
}

impl<DB: Database + DatabaseCommit> DatabaseCommit for StateAdapter<DB>
where
    DB::Error: std::fmt::Debug,
{
    fn commit(&mut self, changes: HashMap<Address, revm::primitives::Account>) {
        trace!(changes = changes.len(), "Committing state changes");

        // Merge pending changes with the new changes
        for (address, account) in changes {
            // Update account info
            self.pending_accounts.insert(address, account.info.clone());

            // Update storage
            let storage_changes = self.pending_storage.entry(address).or_default();
            for (slot, value) in account.storage {
                storage_changes.insert(slot, value.present_value);
            }
        }

        // Commit to underlying database
        // Note: In a real implementation, we would pass the merged changes to the underlying DB
        // For now, we just keep them in pending until flush is called
    }
}

/// An in-memory database for testing
#[derive(Debug, Default)]
pub struct MemoryDb {
    /// Account states
    accounts: HashMap<Address, AccountInfo>,
    /// Storage: address -> slot -> value
    storage: HashMap<Address, HashMap<U256, U256>>,
    /// Code by hash
    code: HashMap<B256, Bytecode>,
    /// Block hashes
    block_hashes: BTreeMap<u64, B256>,
}

impl MemoryDb {
    /// Create a new empty memory database
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert an account
    pub fn insert_account(&mut self, address: Address, account: AccountInfo) {
        self.accounts.insert(address, account);
    }

    /// Insert storage value
    pub fn insert_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.storage.entry(address).or_default().insert(slot, value);
    }

    /// Insert code
    pub fn insert_code(&mut self, code: Bytecode) -> B256 {
        let hash = code.hash_slow();
        self.code.insert(hash, code);
        hash
    }

    /// Insert block hash
    pub fn insert_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }
}

/// Error type for MemoryDb
#[derive(Debug, thiserror::Error)]
pub enum MemoryDbError {
    /// Code not found
    #[error("code not found: {0}")]
    CodeNotFound(B256),
}

impl Database for MemoryDb {
    type Error = MemoryDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or(MemoryDbError::CodeNotFound(code_hash))
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(self
            .storage
            .get(&address)
            .and_then(|s| s.get(&index))
            .copied()
            .unwrap_or(U256::ZERO))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        Ok(self
            .block_hashes
            .get(&number)
            .copied()
            .unwrap_or(B256::ZERO))
    }
}

impl DatabaseCommit for MemoryDb {
    fn commit(&mut self, changes: HashMap<Address, revm::primitives::Account>) {
        for (address, account) in changes {
            self.accounts.insert(address, account.info);

            let storage = self.storage.entry(address).or_default();
            for (slot, value) in account.storage {
                if value.present_value == U256::ZERO {
                    storage.remove(&slot);
                } else {
                    storage.insert(slot, value.present_value);
                }
            }
        }
    }
}

impl StateRootProvider for MemoryDb {
    /// Compute state root from current account state
    ///
    /// For MemoryDb, this computes a simple Merkle root by hashing all accounts.
    /// In production, the real StateDB uses a proper Merkle Patricia Trie.
    fn state_root(&self) -> B256 {
        if self.accounts.is_empty() {
            // Empty trie root (keccak256 of RLP empty string)
            return B256::from_slice(&[
                0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
                0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
                0xe3, 0x63, 0xb4, 0x21,
            ]);
        }

        // Sort accounts by address for deterministic ordering
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by(|a, b| a.0.cmp(b.0));

        // Hash each account and combine
        let mut hasher = Keccak256::new();
        for (address, account) in sorted_accounts {
            hasher.update(address.as_slice());
            hasher.update(account.balance.to_be_bytes::<32>());
            hasher.update(account.nonce.to_be_bytes());
            hasher.update(account.code_hash.as_slice());

            // Include storage hash
            if let Some(storage) = self.storage.get(address) {
                let mut storage_sorted: Vec<_> = storage.iter().collect();
                storage_sorted.sort_by(|a, b| a.0.cmp(b.0));
                for (slot, value) in storage_sorted {
                    hasher.update(slot.to_be_bytes::<32>());
                    hasher.update(value.to_be_bytes::<32>());
                }
            }
        }

        B256::from_slice(&hasher.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_db_account() {
        let mut db = MemoryDb::new();
        let addr = Address::from([0x42; 20]);

        assert!(db.basic(addr).unwrap().is_none());

        let account = AccountInfo {
            balance: U256::from(1000),
            nonce: 1,
            ..Default::default()
        };
        db.insert_account(addr, account.clone());

        let loaded = db.basic(addr).unwrap().unwrap();
        assert_eq!(loaded.balance, U256::from(1000));
        assert_eq!(loaded.nonce, 1);
    }

    #[test]
    fn test_memory_db_storage() {
        let mut db = MemoryDb::new();
        let addr = Address::from([0x42; 20]);
        let slot = U256::from(1);

        assert_eq!(db.storage(addr, slot).unwrap(), U256::ZERO);

        db.insert_storage(addr, slot, U256::from(42));

        assert_eq!(db.storage(addr, slot).unwrap(), U256::from(42));
    }

    #[test]
    fn test_state_adapter_pending() {
        let db = MemoryDb::new();
        let mut adapter = StateAdapter::new(db);
        let addr = Address::from([0x42; 20]);

        assert_eq!(adapter.get_balance(addr).unwrap(), U256::ZERO);

        adapter.set_balance(addr, U256::from(1000)).unwrap();

        assert_eq!(adapter.get_balance(addr).unwrap(), U256::from(1000));
        assert!(adapter.has_pending_changes());
    }

    #[test]
    fn test_state_adapter_rollback() {
        let db = MemoryDb::new();
        let mut adapter = StateAdapter::new(db);
        let addr = Address::from([0x42; 20]);

        adapter.set_balance(addr, U256::from(1000)).unwrap();
        assert!(adapter.has_pending_changes());

        adapter.rollback();
        assert!(!adapter.has_pending_changes());
        assert_eq!(adapter.get_balance(addr).unwrap(), U256::ZERO);
    }

    #[test]
    fn test_state_root_changes_after_modification() {
        let mut db = MemoryDb::new();

        // Empty state has the empty trie root
        let root_before = db.state_root();
        assert_eq!(
            root_before,
            B256::from_slice(&[
                0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
                0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
                0xe3, 0x63, 0xb4, 0x21,
            ]),
            "Empty state should have empty trie root"
        );

        // Add an account
        let addr = Address::from([0x42; 20]);
        let account = AccountInfo {
            balance: U256::from(1_000_000),
            nonce: 1,
            ..Default::default()
        };
        db.insert_account(addr, account);

        // State root must change after modification
        let root_after = db.state_root();
        assert_ne!(
            root_before, root_after,
            "State root should change after account insertion"
        );
        assert_ne!(
            root_after,
            B256::ZERO,
            "State root should not be zero after modification"
        );

        // Same state should produce same root (deterministic)
        let root_again = db.state_root();
        assert_eq!(root_after, root_again, "State root should be deterministic");

        // Modify balance and verify root changes
        let account2 = AccountInfo {
            balance: U256::from(2_000_000),
            nonce: 2,
            ..Default::default()
        };
        db.insert_account(addr, account2);
        let root_after_update = db.state_root();
        assert_ne!(
            root_after, root_after_update,
            "State root should change after balance update"
        );
    }

    #[test]
    fn test_state_root_includes_storage() {
        let mut db = MemoryDb::new();
        let addr = Address::from([0x42; 20]);

        // Add account
        let account = AccountInfo {
            balance: U256::from(1000),
            ..Default::default()
        };
        db.insert_account(addr, account);
        let root_before_storage = db.state_root();

        // Add storage
        db.insert_storage(addr, U256::from(1), U256::from(42));
        let root_after_storage = db.state_root();

        // Storage changes should affect state root
        assert_ne!(
            root_before_storage, root_after_storage,
            "Storage changes should affect state root"
        );
    }
}
