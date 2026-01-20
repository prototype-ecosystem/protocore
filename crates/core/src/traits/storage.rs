//! Storage backend traits for swappable database implementations.
//!
//! This module defines the core storage abstractions that allow different
//! database backends (RocksDB, MDBX, ParityDB, etc.) to be used interchangeably.

use async_trait::async_trait;
use bytes::Bytes;
use std::sync::Arc;
use thiserror::Error;

/// Errors that can occur during storage operations.
#[derive(Error, Debug)]
pub enum StorageError {
    /// The requested key was not found.
    #[error("key not found")]
    NotFound,

    /// The column family does not exist.
    #[error("column family not found: {0}")]
    ColumnFamilyNotFound(String),

    /// A database I/O error occurred.
    #[error("database I/O error: {0}")]
    Io(String),

    /// Data corruption was detected.
    #[error("data corruption: {0}")]
    Corruption(String),

    /// The database is full or quota exceeded.
    #[error("storage quota exceeded")]
    QuotaExceeded,

    /// A serialization/deserialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Generic internal error.
    #[error("internal storage error: {0}")]
    Internal(String),
}

/// Result type for storage operations.
pub type StorageResult<T> = Result<T, StorageError>;

/// A batch of write operations to be applied atomically.
#[derive(Debug, Default, Clone)]
pub struct WriteBatch {
    /// Operations in this batch.
    pub operations: Vec<WriteOperation>,
}

impl WriteBatch {
    /// Create a new empty write batch.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a put operation to the batch.
    pub fn put(&mut self, cf: impl Into<String>, key: impl Into<Bytes>, value: impl Into<Bytes>) {
        self.operations.push(WriteOperation::Put {
            cf: cf.into(),
            key: key.into(),
            value: value.into(),
        });
    }

    /// Add a delete operation to the batch.
    pub fn delete(&mut self, cf: impl Into<String>, key: impl Into<Bytes>) {
        self.operations.push(WriteOperation::Delete {
            cf: cf.into(),
            key: key.into(),
        });
    }

    /// Returns true if the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.operations.is_empty()
    }

    /// Returns the number of operations in the batch.
    pub fn len(&self) -> usize {
        self.operations.len()
    }
}

/// A single write operation within a batch.
#[derive(Debug, Clone)]
pub enum WriteOperation {
    /// Insert or update a key-value pair.
    Put {
        /// Column family name.
        cf: String,
        /// Key to write.
        key: Bytes,
        /// Value to write.
        value: Bytes,
    },
    /// Delete a key.
    Delete {
        /// Column family name.
        cf: String,
        /// Key to delete.
        key: Bytes,
    },
}

/// Core trait for key-value storage backends.
///
/// Implementations of this trait provide the low-level storage primitives
/// that the blockchain uses for persisting blocks, state, and metadata.
///
/// # Thread Safety
///
/// All implementations must be thread-safe (`Send + Sync`).
///
/// # Example
///
/// ```ignore
/// use protocore_core::traits::StorageBackend;
///
/// async fn example(db: impl StorageBackend) {
///     // Single write
///     db.put("blocks", b"key", b"value").await.unwrap();
///
///     // Read back
///     let value = db.get("blocks", b"key").await.unwrap();
///     assert_eq!(value, Some(b"value".to_vec().into()));
///
///     // Batch write
///     let mut batch = WriteBatch::new();
///     batch.put("blocks", b"key1", b"value1");
///     batch.put("blocks", b"key2", b"value2");
///     db.write_batch(batch).await.unwrap();
/// }
/// ```
#[async_trait]
pub trait StorageBackend: Send + Sync + 'static {
    /// Get a value by key from a column family.
    ///
    /// Returns `Ok(None)` if the key does not exist.
    async fn get(&self, cf: &str, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Put a key-value pair into a column family.
    async fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> StorageResult<()>;

    /// Delete a key from a column family.
    ///
    /// Returns `Ok(())` even if the key does not exist.
    async fn delete(&self, cf: &str, key: &[u8]) -> StorageResult<()>;

    /// Check if a key exists in a column family.
    async fn contains(&self, cf: &str, key: &[u8]) -> StorageResult<bool> {
        Ok(self.get(cf, key).await?.is_some())
    }

    /// Apply a batch of write operations atomically.
    ///
    /// Either all operations succeed or none do.
    async fn write_batch(&self, batch: WriteBatch) -> StorageResult<()>;

    /// Flush any buffered writes to disk.
    async fn flush(&self) -> StorageResult<()>;

    /// Create a snapshot for consistent reads.
    fn snapshot(&self) -> StorageResult<Arc<dyn StorageSnapshot>>;

    /// Get database statistics.
    fn stats(&self) -> StorageStats;
}

/// A read-only snapshot of the database at a point in time.
///
/// Snapshots provide a consistent view of the database, unaffected
/// by subsequent writes.
#[async_trait]
pub trait StorageSnapshot: Send + Sync {
    /// Get a value from the snapshot.
    async fn get(&self, cf: &str, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Check if a key exists in the snapshot.
    async fn contains(&self, cf: &str, key: &[u8]) -> StorageResult<bool> {
        Ok(self.get(cf, key).await?.is_some())
    }
}

/// Database statistics and metrics.
#[derive(Debug, Clone, Default)]
pub struct StorageStats {
    /// Total bytes stored on disk.
    pub disk_size_bytes: u64,
    /// Number of keys in the database.
    pub num_keys: u64,
    /// Number of pending compactions.
    pub pending_compactions: u64,
    /// Cache hit ratio (0.0 - 1.0).
    pub cache_hit_ratio: f64,
    /// Average read latency in microseconds.
    pub avg_read_latency_us: u64,
    /// Average write latency in microseconds.
    pub avg_write_latency_us: u64,
}

/// Trait for iterating over key-value pairs.
#[async_trait]
pub trait StorageIterator: Send {
    /// Advance to the next key-value pair.
    async fn next(&mut self) -> StorageResult<Option<(Bytes, Bytes)>>;

    /// Seek to the first key >= the given key.
    async fn seek(&mut self, key: &[u8]) -> StorageResult<()>;

    /// Seek to the first key.
    async fn seek_to_first(&mut self) -> StorageResult<()>;

    /// Seek to the last key.
    async fn seek_to_last(&mut self) -> StorageResult<()>;
}

/// Extension trait for storage backends with iteration support.
#[async_trait]
pub trait StorageBackendExt: StorageBackend {
    /// Create an iterator over a column family.
    fn iter(&self, cf: &str) -> StorageResult<Box<dyn StorageIterator>>;

    /// Create an iterator starting from a specific key.
    fn iter_from(&self, cf: &str, start_key: &[u8]) -> StorageResult<Box<dyn StorageIterator>>;

    /// Create a reverse iterator over a column family.
    fn iter_rev(&self, cf: &str) -> StorageResult<Box<dyn StorageIterator>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_batch() {
        let mut batch = WriteBatch::new();
        assert!(batch.is_empty());

        batch.put("cf1", b"key1".to_vec(), b"value1".to_vec());
        batch.delete("cf1", b"key2".to_vec());

        assert_eq!(batch.len(), 2);
        assert!(!batch.is_empty());
    }
}
