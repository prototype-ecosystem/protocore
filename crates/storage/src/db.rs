//! RocksDB wrapper with column families for blockchain data
//!
//! This module provides a high-level interface to RocksDB with predefined
//! column families for different types of blockchain data.

use parking_lot::RwLock;
use rocksdb::{
    BoundColumnFamily, ColumnFamilyDescriptor, DBIteratorWithThreadMode, DBWithThreadMode,
    Direction, IteratorMode, MultiThreaded, Options, ReadOptions, SnapshotWithThreadMode,
    WriteBatchWithTransaction, WriteOptions, DB,
};
use std::path::Path;
use std::sync::Arc;
use tracing::{debug, info};

use crate::{Result, StorageError};

/// Column family names
pub mod cf {
    /// Blocks column family - stores block headers and bodies
    pub const BLOCKS: &str = "blocks";
    /// Transactions column family - stores transaction data
    pub const TRANSACTIONS: &str = "transactions";
    /// State column family - stores account state trie nodes
    pub const STATE: &str = "state";
    /// Receipts column family - stores transaction receipts
    pub const RECEIPTS: &str = "receipts";
    /// Consensus column family - stores consensus-related data (votes, finality certs)
    pub const CONSENSUS: &str = "consensus";
    /// Metadata column family - stores chain metadata (heights, hashes, config)
    pub const METADATA: &str = "metadata";

    /// All column families
    pub const ALL: &[&str] = &[BLOCKS, TRANSACTIONS, STATE, RECEIPTS, CONSENSUS, METADATA];
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct DatabaseConfig {
    /// Path to the database directory
    pub path: String,
    /// Enable compression (LZ4)
    pub enable_compression: bool,
    /// Maximum number of open files
    pub max_open_files: i32,
    /// Write buffer size in bytes
    pub write_buffer_size: usize,
    /// Maximum number of write buffers
    pub max_write_buffer_number: i32,
    /// Block cache size in bytes
    pub block_cache_size: usize,
    /// Enable WAL (Write-Ahead Log)
    pub enable_wal: bool,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            path: String::from("./data/protocore"),
            enable_compression: true,
            max_open_files: 512,
            write_buffer_size: 64 * 1024 * 1024, // 64 MB
            max_write_buffer_number: 4,
            block_cache_size: 128 * 1024 * 1024, // 128 MB
            enable_wal: true,
        }
    }
}

/// Write batch for atomic operations
pub struct WriteBatch {
    inner: WriteBatchWithTransaction<false>,
}

impl WriteBatch {
    /// Create a new write batch
    pub fn new() -> Self {
        Self {
            inner: WriteBatchWithTransaction::default(),
        }
    }

    /// Put a key-value pair into the batch for a specific column family
    pub fn put_cf(&mut self, cf: &Arc<BoundColumnFamily<'_>>, key: &[u8], value: &[u8]) {
        self.inner.put_cf(cf, key, value);
    }

    /// Delete a key from the batch for a specific column family
    pub fn delete_cf(&mut self, cf: &Arc<BoundColumnFamily<'_>>, key: &[u8]) {
        self.inner.delete_cf(cf, key);
    }

    /// Get the number of operations in the batch
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the batch is empty
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Clear the batch
    pub fn clear(&mut self) {
        self.inner.clear();
    }
}

impl Default for WriteBatch {
    fn default() -> Self {
        Self::new()
    }
}

/// Database snapshot for consistent reads
pub struct DbSnapshot<'a> {
    snapshot: SnapshotWithThreadMode<'a, DBWithThreadMode<MultiThreaded>>,
    db: &'a Database,
}

impl<'a> DbSnapshot<'a> {
    /// Get a value from the snapshot
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.db.cf_handle(cf_name)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_snapshot(&self.snapshot);
        self.db
            .inner
            .get_cf_opt(&cf, key, &read_opts)
            .map_err(|e| StorageError::Database(e.to_string()))
    }
}

/// Iterator over database entries
pub struct DbIterator<'a> {
    inner: DBIteratorWithThreadMode<'a, DBWithThreadMode<MultiThreaded>>,
}

impl<'a> Iterator for DbIterator<'a> {
    type Item = Result<(Box<[u8]>, Box<[u8]>)>;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next().map(|result| {
            result
                .map_err(|e| StorageError::Database(e.to_string()))
        })
    }
}

/// RocksDB wrapper with column families
pub struct Database {
    inner: DBWithThreadMode<MultiThreaded>,
    config: DatabaseConfig,
    /// Lock for coordinating writes
    write_lock: RwLock<()>,
}

impl Database {
    /// Open or create a database at the specified path
    pub fn open(config: DatabaseConfig) -> Result<Self> {
        info!("Opening database at: {}", config.path);

        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.create_missing_column_families(true);
        opts.set_max_open_files(config.max_open_files);
        opts.set_write_buffer_size(config.write_buffer_size);
        opts.set_max_write_buffer_number(config.max_write_buffer_number);

        if config.enable_compression {
            opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        }

        // Create column family descriptors
        let cf_descriptors: Vec<ColumnFamilyDescriptor> = cf::ALL
            .iter()
            .map(|name| {
                let mut cf_opts = Options::default();
                if config.enable_compression {
                    cf_opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
                }
                ColumnFamilyDescriptor::new(*name, cf_opts)
            })
            .collect();

        let path = Path::new(&config.path);
        let db = DB::open_cf_descriptors(&opts, path, cf_descriptors)
            .map_err(|e| StorageError::Database(e.to_string()))?;

        info!("Database opened successfully with {} column families", cf::ALL.len());

        Ok(Self {
            inner: db,
            config,
            write_lock: RwLock::new(()),
        })
    }

    /// Open database with default configuration
    pub fn open_default<P: AsRef<Path>>(path: P) -> Result<Self> {
        let config = DatabaseConfig {
            path: path.as_ref().to_string_lossy().to_string(),
            ..Default::default()
        };
        Self::open(config)
    }

    /// Get a column family handle
    pub fn cf_handle(&self, name: &str) -> Result<Arc<BoundColumnFamily<'_>>> {
        self.inner
            .cf_handle(name)
            .ok_or_else(|| StorageError::ColumnFamilyNotFound(name.to_string()))
    }

    /// Get a value from a column family
    pub fn get(&self, cf_name: &str, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let cf = self.cf_handle(cf_name)?;
        self.inner
            .get_cf(&cf, key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Put a value into a column family
    pub fn put(&self, cf_name: &str, key: &[u8], value: &[u8]) -> Result<()> {
        let cf = self.cf_handle(cf_name)?;
        let _guard = self.write_lock.write();
        self.inner
            .put_cf(&cf, key, value)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Delete a value from a column family
    pub fn delete(&self, cf_name: &str, key: &[u8]) -> Result<()> {
        let cf = self.cf_handle(cf_name)?;
        let _guard = self.write_lock.write();
        self.inner
            .delete_cf(&cf, key)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Execute a write batch atomically
    pub fn write_batch(&self, batch: WriteBatch) -> Result<()> {
        let _guard = self.write_lock.write();
        let mut write_opts = WriteOptions::default();
        if self.config.enable_wal {
            write_opts.set_sync(false);
        } else {
            write_opts.disable_wal(true);
        }
        self.inner
            .write_opt(batch.inner, &write_opts)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Create a snapshot of the current database state
    pub fn snapshot(&self) -> DbSnapshot<'_> {
        DbSnapshot {
            snapshot: self.inner.snapshot(),
            db: self,
        }
    }

    /// Create an iterator over a column family
    pub fn iterator(&self, cf_name: &str) -> Result<DbIterator<'_>> {
        let cf = self.cf_handle(cf_name)?;
        let iter = self.inner.iterator_cf(&cf, IteratorMode::Start);
        Ok(DbIterator { inner: iter })
    }

    /// Create an iterator starting from a specific key
    pub fn iterator_from(&self, cf_name: &str, key: &[u8]) -> Result<DbIterator<'_>> {
        let cf = self.cf_handle(cf_name)?;
        let iter = self
            .inner
            .iterator_cf(&cf, IteratorMode::From(key, Direction::Forward));
        Ok(DbIterator { inner: iter })
    }

    /// Create a prefix iterator
    pub fn prefix_iterator(&self, cf_name: &str, prefix: &[u8]) -> Result<DbIterator<'_>> {
        let cf = self.cf_handle(cf_name)?;
        let mut read_opts = ReadOptions::default();
        read_opts.set_prefix_same_as_start(true);
        let iter = self
            .inner
            .iterator_cf_opt(&cf, read_opts, IteratorMode::From(prefix, Direction::Forward));
        Ok(DbIterator { inner: iter })
    }

    /// Check if a key exists in a column family
    pub fn exists(&self, cf_name: &str, key: &[u8]) -> Result<bool> {
        self.get(cf_name, key).map(|v| v.is_some())
    }

    /// Get multiple values at once
    pub fn multi_get(&self, cf_name: &str, keys: &[&[u8]]) -> Result<Vec<Option<Vec<u8>>>> {
        let cf = self.cf_handle(cf_name)?;
        let cf_keys: Vec<_> = keys.iter().map(|k| (&cf, *k)).collect();

        self.inner
            .multi_get_cf(cf_keys)
            .into_iter()
            .map(|r| r.map_err(|e| StorageError::Database(e.to_string())))
            .collect()
    }

    /// Flush all memtables to disk
    pub fn flush(&self, cf_name: &str) -> Result<()> {
        let cf = self.cf_handle(cf_name)?;
        self.inner
            .flush_cf(&cf)
            .map_err(|e| StorageError::Database(e.to_string()))
    }

    /// Flush all column families
    pub fn flush_all(&self) -> Result<()> {
        for cf_name in cf::ALL {
            self.flush(cf_name)?;
        }
        Ok(())
    }

    /// Compact a range of keys in a column family
    pub fn compact(&self, cf_name: &str, start: Option<&[u8]>, end: Option<&[u8]>) -> Result<()> {
        let cf = self.cf_handle(cf_name)?;
        self.inner.compact_range_cf(&cf, start, end);
        debug!("Compacted range in column family: {}", cf_name);
        Ok(())
    }

    /// Get database statistics
    pub fn stats(&self) -> Option<String> {
        self.inner.property_value("rocksdb.stats").ok().flatten()
    }

    /// Get the path to the database
    pub fn path(&self) -> &str {
        &self.config.path
    }

    /// Get the configuration
    pub fn config(&self) -> &DatabaseConfig {
        &self.config
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        debug!("Closing database at: {}", self.config.path);
        // RocksDB handles cleanup automatically
    }
}

// Block storage helpers
impl Database {
    /// Store a block
    pub fn put_block(&self, hash: &[u8], data: &[u8]) -> Result<()> {
        self.put(cf::BLOCKS, hash, data)
    }

    /// Get a block by hash
    pub fn get_block(&self, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(cf::BLOCKS, hash)
    }

    /// Store a transaction
    pub fn put_transaction(&self, hash: &[u8], data: &[u8]) -> Result<()> {
        self.put(cf::TRANSACTIONS, hash, data)
    }

    /// Get a transaction by hash
    pub fn get_transaction(&self, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(cf::TRANSACTIONS, hash)
    }

    /// Store a receipt
    pub fn put_receipt(&self, hash: &[u8], data: &[u8]) -> Result<()> {
        self.put(cf::RECEIPTS, hash, data)
    }

    /// Get a receipt by transaction hash
    pub fn get_receipt(&self, hash: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(cf::RECEIPTS, hash)
    }

    /// Store consensus data
    pub fn put_consensus(&self, key: &[u8], data: &[u8]) -> Result<()> {
        self.put(cf::CONSENSUS, key, data)
    }

    /// Get consensus data
    pub fn get_consensus(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(cf::CONSENSUS, key)
    }

    /// Store metadata
    pub fn put_metadata(&self, key: &[u8], data: &[u8]) -> Result<()> {
        self.put(cf::METADATA, key, data)
    }

    /// Get metadata
    pub fn get_metadata(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        self.get(cf::METADATA, key)
    }
}

