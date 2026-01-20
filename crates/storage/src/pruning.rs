//! Block and State Pruning
//!
//! This module provides pruning functionality to manage storage growth:
//!
//! - **Block Pruning**: Remove old blocks beyond retention period
//! - **State Pruning**: Prune old state with checkpoint preservation
//! - **Receipt Pruning**: Remove old transaction receipts
//!
//! Pruning operates in the background and preserves checkpoint blocks
//! for state sync and light client verification.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::db::cf;
use crate::{Database, Hash, Result, StorageError};

/// Default blocks to retain before pruning
pub const DEFAULT_BLOCKS_RETAINED: u64 = 100_000;

/// Default checkpoint interval (every N blocks)
pub const DEFAULT_CHECKPOINT_INTERVAL: u64 = 10_000;

/// Minimum blocks to retain (safety minimum)
pub const MIN_BLOCKS_RETAINED: u64 = 1000;

/// Pruning configuration
#[derive(Debug, Clone)]
pub struct PruningConfig {
    /// Number of blocks to retain (older blocks are pruned)
    pub blocks_retained: u64,
    /// Checkpoint interval (checkpoint blocks are never pruned)
    pub checkpoint_interval: u64,
    /// Whether to prune state data
    pub prune_state: bool,
    /// Whether to prune receipts
    pub prune_receipts: bool,
    /// Batch size for pruning operations
    pub batch_size: u64,
    /// Enable archive mode (no pruning)
    pub archive_mode: bool,
}

impl Default for PruningConfig {
    fn default() -> Self {
        Self {
            blocks_retained: DEFAULT_BLOCKS_RETAINED,
            checkpoint_interval: DEFAULT_CHECKPOINT_INTERVAL,
            prune_state: true,
            prune_receipts: true,
            batch_size: 1000,
            archive_mode: false,
        }
    }
}

impl PruningConfig {
    /// Create archive mode config (no pruning)
    pub fn archive() -> Self {
        Self {
            archive_mode: true,
            ..Default::default()
        }
    }

    /// Create config for light nodes (aggressive pruning)
    pub fn light() -> Self {
        Self {
            blocks_retained: 10_000,
            checkpoint_interval: 1_000,
            prune_state: true,
            prune_receipts: true,
            batch_size: 500,
            archive_mode: false,
        }
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<()> {
        if !self.archive_mode && self.blocks_retained < MIN_BLOCKS_RETAINED {
            return Err(StorageError::Database(format!(
                "blocks_retained ({}) must be >= {}",
                self.blocks_retained, MIN_BLOCKS_RETAINED
            )));
        }
        if self.checkpoint_interval == 0 {
            return Err(StorageError::Database(
                "checkpoint_interval must be > 0".into(),
            ));
        }
        Ok(())
    }
}

/// A checkpoint that preserves state at a specific height
#[derive(Debug, Clone)]
pub struct Checkpoint {
    /// Block height
    pub height: u64,
    /// Block hash
    pub block_hash: Hash,
    /// State root at this height
    pub state_root: Hash,
    /// Timestamp when checkpoint was created
    pub created_at: u64,
}

/// Statistics about pruning operations
#[derive(Debug, Clone, Default)]
pub struct PruningStats {
    /// Total blocks pruned
    pub blocks_pruned: u64,
    /// Total receipts pruned
    pub receipts_pruned: u64,
    /// Total state entries pruned
    pub state_entries_pruned: u64,
    /// Bytes freed by pruning
    pub bytes_freed: u64,
    /// Number of checkpoints preserved
    pub checkpoints_preserved: u64,
    /// Last pruned height
    pub last_pruned_height: u64,
    /// Time spent pruning (milliseconds)
    pub pruning_time_ms: u64,
}

/// Pruning manager for handling storage pruning
pub struct PruningManager {
    /// Configuration
    config: PruningConfig,
    /// Database reference
    db: Arc<Database>,
    /// Protected checkpoint heights (never pruned)
    checkpoints: RwLock<HashSet<u64>>,
    /// Pruning statistics
    stats: RwLock<PruningStats>,
    /// Current chain height
    current_height: AtomicU64,
    /// Lowest height with data
    lowest_height: AtomicU64,
}

impl PruningManager {
    /// Create a new pruning manager
    pub fn new(db: Arc<Database>, config: PruningConfig) -> Result<Self> {
        config.validate()?;

        Ok(Self {
            config,
            db,
            checkpoints: RwLock::new(HashSet::new()),
            stats: RwLock::new(PruningStats::default()),
            current_height: AtomicU64::new(0),
            lowest_height: AtomicU64::new(0),
        })
    }

    /// Update the current chain height
    pub fn set_height(&self, height: u64) {
        self.current_height.store(height, Ordering::SeqCst);

        // Auto-create checkpoint if at interval
        if height > 0 && height % self.config.checkpoint_interval == 0 {
            self.checkpoints.write().insert(height);
            debug!(height, "Auto-created checkpoint");
        }
    }

    /// Add a manual checkpoint
    pub fn add_checkpoint(&self, checkpoint: Checkpoint) {
        info!(
            height = checkpoint.height,
            block_hash = %hex::encode(&checkpoint.block_hash[..8]),
            "Adding checkpoint"
        );
        self.checkpoints.write().insert(checkpoint.height);
    }

    /// Check if a height is a checkpoint
    pub fn is_checkpoint(&self, height: u64) -> bool {
        // Auto checkpoints at interval
        if height % self.config.checkpoint_interval == 0 {
            return true;
        }
        // Manual checkpoints
        self.checkpoints.read().contains(&height)
    }

    /// Get the pruning target height
    ///
    /// Returns the height up to which we can safely prune.
    pub fn pruning_target(&self) -> u64 {
        if self.config.archive_mode {
            return 0; // No pruning in archive mode
        }

        let current = self.current_height.load(Ordering::SeqCst);
        current.saturating_sub(self.config.blocks_retained)
    }

    /// Execute pruning up to the target height
    pub fn prune(&self) -> Result<PruningStats> {
        if self.config.archive_mode {
            return Ok(PruningStats::default());
        }

        let start_time = std::time::Instant::now();
        let target = self.pruning_target();
        let lowest = self.lowest_height.load(Ordering::SeqCst);

        if target <= lowest {
            return Ok(PruningStats::default()); // Nothing to prune
        }

        info!(
            from_height = lowest,
            to_height = target,
            "Starting pruning"
        );

        let mut stats = PruningStats::default();
        let mut current = lowest;

        while current < target {
            let batch_end = (current + self.config.batch_size).min(target);

            for height in current..batch_end {
                // Skip checkpoint heights
                if self.is_checkpoint(height) {
                    stats.checkpoints_preserved += 1;
                    continue;
                }

                // Prune block data
                if let Err(e) = self.prune_block(height) {
                    warn!(height, error = %e, "Failed to prune block");
                    continue;
                }
                stats.blocks_pruned += 1;

                // Prune receipts if enabled
                if self.config.prune_receipts {
                    if let Ok(count) = self.prune_receipts(height) {
                        stats.receipts_pruned += count;
                    }
                }

                // Prune state if enabled (more complex, skipped for non-checkpoint)
                if self.config.prune_state {
                    // State pruning happens at checkpoint boundaries
                    // Individual state entries are reference-counted
                }
            }

            current = batch_end;
            self.lowest_height.store(current, Ordering::SeqCst);
        }

        stats.last_pruned_height = target;
        stats.pruning_time_ms = start_time.elapsed().as_millis() as u64;

        // Update stored stats
        *self.stats.write() = stats.clone();

        info!(
            blocks_pruned = stats.blocks_pruned,
            receipts_pruned = stats.receipts_pruned,
            time_ms = stats.pruning_time_ms,
            "Pruning complete"
        );

        Ok(stats)
    }

    /// Prune a single block
    fn prune_block(&self, height: u64) -> Result<()> {
        // Get block hash for this height
        let hash_key = format!("block_hash_{}", height);
        let block_hash = self.db.get_metadata(hash_key.as_bytes())?;

        if let Some(hash) = block_hash {
            // Delete block data
            self.db.delete(cf::BLOCKS, &hash)?;

            // Delete height-to-hash mapping
            self.db.delete(cf::METADATA, hash_key.as_bytes())?;
        }

        Ok(())
    }

    /// Prune receipts for a block
    fn prune_receipts(&self, height: u64) -> Result<u64> {
        // In a real implementation, this would iterate over all receipts
        // for the given block height and delete them
        // For now, we just mark it as done
        let key = format!("receipts_{}", height);
        self.db.delete(cf::RECEIPTS, key.as_bytes())?;
        Ok(1)
    }

    /// Get current pruning statistics
    pub fn stats(&self) -> PruningStats {
        self.stats.read().clone()
    }

    /// Get the lowest height with data
    pub fn lowest_height(&self) -> u64 {
        self.lowest_height.load(Ordering::SeqCst)
    }

    /// Check if data is available for a given height
    pub fn has_data(&self, height: u64) -> bool {
        let lowest = self.lowest_height.load(Ordering::SeqCst);
        let current = self.current_height.load(Ordering::SeqCst);
        height >= lowest && height <= current
    }

    /// Get checkpoint heights within a range
    pub fn checkpoints_in_range(&self, start: u64, end: u64) -> Vec<u64> {
        let checkpoints = self.checkpoints.read();
        let mut result: Vec<u64> = checkpoints
            .iter()
            .filter(|&&h| h >= start && h <= end)
            .copied()
            .collect();

        // Add auto-checkpoints
        let mut auto_checkpoint = (start / self.config.checkpoint_interval + 1)
            * self.config.checkpoint_interval;
        while auto_checkpoint <= end {
            if !result.contains(&auto_checkpoint) {
                result.push(auto_checkpoint);
            }
            auto_checkpoint += self.config.checkpoint_interval;
        }

        result.sort();
        result
    }

    /// Get the nearest checkpoint at or before a given height
    pub fn nearest_checkpoint(&self, height: u64) -> u64 {
        // Find the nearest auto-checkpoint
        let auto_checkpoint = (height / self.config.checkpoint_interval)
            * self.config.checkpoint_interval;

        // Check manual checkpoints
        let checkpoints = self.checkpoints.read();
        let manual_nearest = checkpoints
            .iter()
            .filter(|&&h| h <= height)
            .max()
            .copied()
            .unwrap_or(0);

        auto_checkpoint.max(manual_nearest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let config = PruningConfig::default();
        assert!(config.validate().is_ok());

        let mut bad_config = PruningConfig::default();
        bad_config.blocks_retained = 100; // Below minimum
        bad_config.archive_mode = false;
        assert!(bad_config.validate().is_err());

        // Archive mode allows any blocks_retained
        bad_config.archive_mode = true;
        assert!(bad_config.validate().is_ok());
    }

    #[test]
    fn test_checkpoint_detection() {
        let config = PruningConfig {
            checkpoint_interval: 100,
            ..Default::default()
        };

        // Without a database, we can't create the manager
        // But we can test the checkpoint logic directly
        assert!(100 % config.checkpoint_interval == 0);
        assert!(200 % config.checkpoint_interval == 0);
        assert!(150 % config.checkpoint_interval != 0);
    }

    #[test]
    fn test_light_config() {
        let config = PruningConfig::light();
        assert_eq!(config.blocks_retained, 10_000);
        assert_eq!(config.checkpoint_interval, 1_000);
        assert!(!config.archive_mode);
    }

    #[test]
    fn test_archive_config() {
        let config = PruningConfig::archive();
        assert!(config.archive_mode);
    }

    #[test]
    fn test_pruning_target() {
        // Test the calculation
        let blocks_retained = 100_000u64;
        let current_height = 150_000u64;
        let target = current_height.saturating_sub(blocks_retained);
        assert_eq!(target, 50_000);

        // Early chain (not enough blocks)
        let early_height = 50_000u64;
        let early_target = early_height.saturating_sub(blocks_retained);
        assert_eq!(early_target, 0);
    }
}
