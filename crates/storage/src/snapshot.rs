//! State snapshots for fast sync
//!
//! This module provides snapshot functionality for efficient state synchronization.
//! Snapshots allow new nodes to quickly sync to the latest state without replaying
//! all historical blocks.

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, info};

use crate::db::{cf, Database};
use crate::state::Account;
use crate::{keccak256, Address, Hash, Result, StorageError, ZERO_HASH};

/// Default chunk size (1 MB)
pub const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Maximum chunk size (16 MB)
pub const MAX_CHUNK_SIZE: usize = 16 * 1024 * 1024;

/// Snapshot metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    /// Block height at which snapshot was taken
    pub height: u64,
    /// State root at this height
    pub state_root: Hash,
    /// Block hash at this height
    pub block_hash: Hash,
    /// Total number of chunks
    pub chunk_count: u64,
    /// Size of each chunk in bytes
    pub chunk_size: usize,
    /// Total size of snapshot in bytes
    pub total_size: u64,
    /// Timestamp when snapshot was created
    pub timestamp: u64,
    /// Chunk hashes for verification
    pub chunk_hashes: Vec<Hash>,
}

impl Snapshot {
    /// Create a new snapshot
    pub fn new(height: u64, state_root: Hash, block_hash: Hash) -> Self {
        Self {
            height,
            state_root,
            block_hash,
            chunk_count: 0,
            chunk_size: DEFAULT_CHUNK_SIZE,
            total_size: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            chunk_hashes: Vec::new(),
        }
    }

    /// Verify a chunk against its expected hash
    pub fn verify_chunk(&self, chunk_id: u64, data: &[u8]) -> bool {
        if chunk_id >= self.chunk_count {
            return false;
        }

        let computed_hash = keccak256(data);
        self.chunk_hashes
            .get(chunk_id as usize)
            .map(|expected| *expected == computed_hash)
            .unwrap_or(false)
    }

    /// Encode snapshot metadata
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode snapshot metadata
    pub fn decode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

/// A chunk of snapshot data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotChunk {
    /// Chunk index
    pub id: u64,
    /// Snapshot height this chunk belongs to
    pub height: u64,
    /// State updates in this chunk
    pub updates: Vec<StateUpdate>,
    /// Hash of this chunk's data
    pub hash: Hash,
}

impl SnapshotChunk {
    /// Create a new chunk
    pub fn new(id: u64, height: u64, updates: Vec<StateUpdate>) -> Self {
        let data = bincode::serialize(&updates).unwrap_or_default();
        let hash = keccak256(&data);

        Self {
            id,
            height,
            updates,
            hash,
        }
    }

    /// Verify chunk integrity
    pub fn verify(&self) -> bool {
        let data = bincode::serialize(&self.updates).unwrap_or_default();
        keccak256(&data) == self.hash
    }

    /// Encode chunk for transmission
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode chunk from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| StorageError::Serialization(e.to_string()))
    }

    /// Get the size of this chunk in bytes
    pub fn size(&self) -> usize {
        self.encode().len()
    }
}

/// State update types for snapshot chunks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StateUpdate {
    /// Account update
    Account {
        /// Account address
        address: Address,
        /// Account data
        account: Account,
    },
    /// Storage update
    Storage {
        /// Account address
        address: Address,
        /// Storage slot
        slot: Hash,
        /// Storage value
        value: Hash,
    },
    /// Code update
    Code {
        /// Code hash
        hash: Hash,
        /// Contract bytecode
        code: Vec<u8>,
    },
}

/// Snapshot creation progress
#[derive(Debug, Clone, Default)]
pub struct SnapshotProgress {
    /// Total accounts to process
    pub total_accounts: u64,
    /// Accounts processed
    pub processed_accounts: u64,
    /// Total storage slots to process
    pub total_storage: u64,
    /// Storage slots processed
    pub processed_storage: u64,
    /// Chunks created
    pub chunks_created: u64,
    /// Current chunk size
    pub current_chunk_size: usize,
}

impl SnapshotProgress {
    /// Get progress percentage
    pub fn percentage(&self) -> f64 {
        let total = self.total_accounts + self.total_storage;
        if total == 0 {
            return 100.0;
        }
        let processed = self.processed_accounts + self.processed_storage;
        (processed as f64 / total as f64) * 100.0
    }
}

/// Snapshot manager for creating and applying snapshots
pub struct SnapshotManager {
    /// Database reference
    db: Arc<Database>,
    /// Current snapshot being created/imported
    current_snapshot: RwLock<Option<Snapshot>>,
    /// Chunks for current snapshot
    chunks: RwLock<HashMap<u64, SnapshotChunk>>,
    /// Creation progress
    progress: RwLock<SnapshotProgress>,
    /// Chunk size configuration
    chunk_size: usize,
}

impl SnapshotManager {
    /// Create a new snapshot manager
    pub fn new(db: Arc<Database>) -> Self {
        Self {
            db,
            current_snapshot: RwLock::new(None),
            chunks: RwLock::new(HashMap::new()),
            progress: RwLock::new(SnapshotProgress::default()),
            chunk_size: DEFAULT_CHUNK_SIZE,
        }
    }

    /// Create a new snapshot manager with custom chunk size
    pub fn with_chunk_size(db: Arc<Database>, chunk_size: usize) -> Self {
        let chunk_size = chunk_size.min(MAX_CHUNK_SIZE);
        Self {
            db,
            current_snapshot: RwLock::new(None),
            chunks: RwLock::new(HashMap::new()),
            progress: RwLock::new(SnapshotProgress::default()),
            chunk_size,
        }
    }

    /// Create a snapshot at the given height
    pub fn create_snapshot(
        &self,
        height: u64,
        state_root: Hash,
        block_hash: Hash,
    ) -> Result<Snapshot> {
        info!("Creating snapshot at height {}", height);

        let mut snapshot = Snapshot::new(height, state_root, block_hash);
        snapshot.chunk_size = self.chunk_size;

        // Reset progress
        *self.progress.write() = SnapshotProgress::default();

        // Collect all state data
        let mut chunk_id = 0u64;
        let mut current_chunk_updates: Vec<StateUpdate> = Vec::new();
        let mut current_chunk_size = 0usize;

        // Iterate over all accounts
        let iter = self.db.iterator(cf::STATE)?;
        for result in iter {
            let (key, value) = result?;

            let update = self.parse_state_entry(&key, &value)?;
            if let Some(upd) = update {
                let update_size = bincode::serialized_size(&upd).unwrap_or(0) as usize;

                // Check if we need to create a new chunk
                if current_chunk_size + update_size > self.chunk_size
                    && !current_chunk_updates.is_empty()
                {
                    let chunk = SnapshotChunk::new(chunk_id, height, current_chunk_updates);
                    snapshot.chunk_hashes.push(chunk.hash);
                    snapshot.total_size += chunk.size() as u64;
                    self.chunks.write().insert(chunk_id, chunk);

                    chunk_id += 1;
                    current_chunk_updates = Vec::new();
                    current_chunk_size = 0;

                    let mut progress = self.progress.write();
                    progress.chunks_created = chunk_id;
                }

                current_chunk_updates.push(upd);
                current_chunk_size += update_size;
            }
        }

        // Create final chunk if there are remaining updates
        if !current_chunk_updates.is_empty() {
            let chunk = SnapshotChunk::new(chunk_id, height, current_chunk_updates);
            snapshot.chunk_hashes.push(chunk.hash);
            snapshot.total_size += chunk.size() as u64;
            self.chunks.write().insert(chunk_id, chunk);
            chunk_id += 1;
        }

        snapshot.chunk_count = chunk_id;

        // Store snapshot metadata
        let snapshot_key = format!("snapshot:{}", height);
        self.db
            .put_metadata(snapshot_key.as_bytes(), &snapshot.encode())?;

        *self.current_snapshot.write() = Some(snapshot.clone());

        info!(
            "Created snapshot with {} chunks, total size: {} bytes",
            snapshot.chunk_count, snapshot.total_size
        );

        Ok(snapshot)
    }

    /// Parse a state database entry into a state update
    fn parse_state_entry(&self, key: &[u8], value: &[u8]) -> Result<Option<StateUpdate>> {
        if key.is_empty() {
            return Ok(None);
        }

        match key[0] {
            0x00 => {
                // Account
                if key.len() < 21 {
                    return Ok(None);
                }
                let mut address = [0u8; 20];
                address.copy_from_slice(&key[1..21]);

                let account = Account::decode(value).unwrap_or_default();

                self.progress.write().processed_accounts += 1;

                Ok(Some(StateUpdate::Account { address, account }))
            }
            0x01 => {
                // Storage
                if key.len() < 53 {
                    return Ok(None);
                }
                let mut address = [0u8; 20];
                address.copy_from_slice(&key[1..21]);

                let mut slot = [0u8; 32];
                slot.copy_from_slice(&key[21..53]);

                let mut val = ZERO_HASH;
                if value.len() >= 32 {
                    val.copy_from_slice(&value[..32]);
                }

                self.progress.write().processed_storage += 1;

                Ok(Some(StateUpdate::Storage {
                    address,
                    slot,
                    value: val,
                }))
            }
            0x02 => {
                // Code
                if key.len() < 33 {
                    return Ok(None);
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&key[1..33]);

                Ok(Some(StateUpdate::Code {
                    hash,
                    code: value.to_vec(),
                }))
            }
            _ => Ok(None),
        }
    }

    /// Get a snapshot chunk
    pub fn get_chunk(&self, chunk_id: u64) -> Option<SnapshotChunk> {
        self.chunks.read().get(&chunk_id).cloned()
    }

    /// Export a chunk for transmission
    pub fn export_chunk(&self, chunk_id: u64) -> Result<Vec<u8>> {
        self.chunks
            .read()
            .get(&chunk_id)
            .map(|c| c.encode())
            .ok_or_else(|| StorageError::Snapshot(format!("Chunk {} not found", chunk_id)))
    }

    /// Import a chunk from external source
    pub fn import_chunk(&self, data: &[u8]) -> Result<SnapshotChunk> {
        let chunk = SnapshotChunk::decode(data)?;

        if !chunk.verify() {
            return Err(StorageError::Snapshot(
                "Chunk verification failed".to_string(),
            ));
        }

        self.chunks.write().insert(chunk.id, chunk.clone());

        debug!(
            "Imported chunk {} with {} updates",
            chunk.id,
            chunk.updates.len()
        );

        Ok(chunk)
    }

    /// Apply a chunk to the database
    pub fn apply_chunk(&self, chunk: &SnapshotChunk) -> Result<()> {
        debug!(
            "Applying chunk {} with {} updates",
            chunk.id,
            chunk.updates.len()
        );

        for update in &chunk.updates {
            match update {
                StateUpdate::Account { address, account } => {
                    let key = self.account_key(address);
                    self.db.put(cf::STATE, &key, &account.encode())?;
                }
                StateUpdate::Storage {
                    address,
                    slot,
                    value,
                } => {
                    let key = self.storage_key(address, slot);
                    if *value == ZERO_HASH {
                        self.db.delete(cf::STATE, &key)?;
                    } else {
                        self.db.put(cf::STATE, &key, value)?;
                    }
                }
                StateUpdate::Code { hash, code } => {
                    let key = self.code_key(hash);
                    self.db.put(cf::STATE, &key, code)?;
                }
            }
        }

        Ok(())
    }

    /// Verify chunk integrity against snapshot metadata
    pub fn verify_chunk(&self, chunk_id: u64, data: &[u8]) -> bool {
        if let Some(snapshot) = self.current_snapshot.read().as_ref() {
            snapshot.verify_chunk(chunk_id, data)
        } else {
            false
        }
    }

    /// Get snapshot by height
    pub fn get_snapshot(&self, height: u64) -> Result<Option<Snapshot>> {
        let snapshot_key = format!("snapshot:{}", height);
        self.db
            .get_metadata(snapshot_key.as_bytes())?
            .map(|data| Snapshot::decode(&data))
            .transpose()
    }

    /// List available snapshots
    pub fn list_snapshots(&self) -> Result<Vec<Snapshot>> {
        let mut snapshots = Vec::new();

        let iter = self.db.prefix_iterator(cf::METADATA, b"snapshot:")?;
        for result in iter {
            let (_, value) = result?;
            if let Ok(snapshot) = Snapshot::decode(&value) {
                snapshots.push(snapshot);
            }
        }

        snapshots.sort_by_key(|s| s.height);
        Ok(snapshots)
    }

    /// Delete a snapshot
    pub fn delete_snapshot(&self, height: u64) -> Result<()> {
        let snapshot_key = format!("snapshot:{}", height);
        self.db.delete(cf::METADATA, snapshot_key.as_bytes())?;

        info!("Deleted snapshot at height {}", height);
        Ok(())
    }

    /// Get current snapshot creation progress
    pub fn progress(&self) -> SnapshotProgress {
        self.progress.read().clone()
    }

    /// Get current snapshot metadata
    pub fn current_snapshot(&self) -> Option<Snapshot> {
        self.current_snapshot.read().clone()
    }

    /// Clear current snapshot and chunks
    pub fn clear(&self) {
        *self.current_snapshot.write() = None;
        self.chunks.write().clear();
        *self.progress.write() = SnapshotProgress::default();
    }

    /// Helper to create account key
    fn account_key(&self, address: &Address) -> Vec<u8> {
        let mut key = vec![0x00];
        key.extend(address);
        key
    }

    /// Helper to create storage key
    fn storage_key(&self, address: &Address, slot: &Hash) -> Vec<u8> {
        let mut key = vec![0x01];
        key.extend(address);
        key.extend(slot);
        key
    }

    /// Helper to create code key
    fn code_key(&self, hash: &Hash) -> Vec<u8> {
        let mut key = vec![0x02];
        key.extend(hash);
        key
    }
}
