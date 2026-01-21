//! Write-Ahead Log (WAL) for Consensus State Persistence
//!
//! This module provides durable persistence for consensus state to ensure:
//! 1. No equivocation after restart (never sign conflicting messages)
//! 2. State recovery after crash (restore height, round, locked value)
//! 3. Crash safety at any point (fsync before signing)
//!
//! ## WAL Format
//!
//! The WAL uses a simple binary format with CRC32 checksums for integrity:
//!
//! ```text
//! ┌──────────────────────────────────────────────────────────────────┐
//! │                         WAL Entry                                 │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ Magic (4 bytes)   │ Version (1 byte)  │ Entry Type (1 byte)      │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ Payload Length (4 bytes, little-endian)                          │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ Payload (variable length)                                        │
//! ├──────────────────────────────────────────────────────────────────┤
//! │ CRC32 Checksum (4 bytes, little-endian)                          │
//! └──────────────────────────────────────────────────────────────────┘
//! ```
//!
//! ## Entry Types
//!
//! - `HeightStart`: Beginning of a new height (resets round state)
//! - `VoteSigned`: Records a signed vote (prevote or precommit)
//! - `ProposalSigned`: Records a signed proposal
//! - `Locked`: Records locking on a block
//! - `Committed`: Records block commitment (allows pruning)
//!
//! ## Usage
//!
//! ```rust,ignore
//! use protocore_consensus::wal::{ConsensusWal, WalConfig};
//!
//! // Create WAL
//! let wal = ConsensusWal::open(WalConfig::default())?;
//!
//! // Before signing a vote, write to WAL
//! wal.write_vote_signed(height, round, vote_type, block_hash)?;
//!
//! // Check if we've already signed (anti-equivocation)
//! if wal.has_signed_vote(height, round, VoteType::Prevote) {
//!     // Skip signing, already signed
//! }
//!
//! // On startup, recover state
//! let state = wal.recover()?;
//! ```

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::types::VoteType;
use protocore_crypto::Hash;

/// Magic bytes to identify WAL files
const WAL_MAGIC: [u8; 4] = [0x50, 0x52, 0x57, 0x4C]; // "PRWL" - ProtoCore WAL

/// Current WAL format version
const WAL_VERSION: u8 = 1;

/// Header size in bytes (magic + version + entry_type + length)
const HEADER_SIZE: usize = 10;

/// CRC32 checksum size
const CRC_SIZE: usize = 4;

/// Errors that can occur during WAL operations
#[derive(Debug, Error)]
pub enum WalError {
    /// I/O error during WAL operations
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Corrupted WAL entry (checksum mismatch or invalid format)
    #[error("corrupted WAL entry at offset {offset}: {message}")]
    Corrupted {
        /// Byte offset in the WAL file
        offset: u64,
        /// Description of the corruption
        message: String,
    },

    /// Invalid WAL magic bytes
    #[error("invalid WAL magic bytes")]
    InvalidMagic,

    /// Unsupported WAL version
    #[error("unsupported WAL version: {0} (expected {WAL_VERSION})")]
    UnsupportedVersion(u8),

    /// Equivocation detected - attempting to sign conflicting message
    #[error(
        "equivocation detected at height {height}, round {round}: already signed {existing:?}"
    )]
    EquivocationDetected {
        /// Block height
        height: u64,
        /// Consensus round
        round: u64,
        /// Hash of the existing signed message
        existing: Hash,
    },

    /// Serialization error
    #[error("serialization error: {0}")]
    Serialization(String),

    /// WAL is read-only (for recovery mode)
    #[error("WAL is in read-only mode")]
    ReadOnly,
}

/// Result type for WAL operations
pub type WalResult<T> = Result<T, WalError>;

/// Configuration for the consensus WAL
#[derive(Debug, Clone)]
pub struct WalConfig {
    /// Path to the WAL directory
    pub dir: PathBuf,
    /// Whether to fsync after each write
    pub sync_on_write: bool,
    /// Maximum number of heights to keep in WAL (0 = unlimited)
    pub max_heights_retained: u64,
    /// Whether to fail on corrupted entries (false = truncate and continue)
    pub strict_recovery: bool,
}

impl Default for WalConfig {
    fn default() -> Self {
        Self {
            dir: PathBuf::from("./data/consensus-wal"),
            sync_on_write: true,
            max_heights_retained: 100,
            strict_recovery: false,
        }
    }
}

/// Entry types in the WAL
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum WalEntryType {
    /// Start of a new height
    HeightStart = 1,
    /// Vote was signed (prevote or precommit)
    VoteSigned = 2,
    /// Proposal was signed
    ProposalSigned = 3,
    /// Locked on a block
    Locked = 4,
    /// Block was committed
    Committed = 5,
}

impl TryFrom<u8> for WalEntryType {
    type Error = WalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(WalEntryType::HeightStart),
            2 => Ok(WalEntryType::VoteSigned),
            3 => Ok(WalEntryType::ProposalSigned),
            4 => Ok(WalEntryType::Locked),
            5 => Ok(WalEntryType::Committed),
            _ => Err(WalError::Corrupted {
                offset: 0,
                message: format!("invalid entry type: {}", value),
            }),
        }
    }
}

/// Payload for HeightStart entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeightStartPayload {
    /// Block height
    pub height: u64,
    /// Parent block hash
    pub parent_hash: Hash,
    /// Timestamp when height started (Unix millis)
    pub timestamp_ms: u64,
}

/// Payload for VoteSigned entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoteSignedPayload {
    /// Block height
    pub height: u64,
    /// Consensus round
    pub round: u64,
    /// Vote type (Prevote or Precommit)
    pub vote_type: VoteType,
    /// Hash of the block voted for (or NIL_HASH)
    pub block_hash: Hash,
    /// Timestamp when vote was signed (Unix millis)
    pub timestamp_ms: u64,
}

/// Payload for ProposalSigned entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProposalSignedPayload {
    /// Block height
    pub height: u64,
    /// Consensus round
    pub round: u64,
    /// Hash of the proposed block
    pub block_hash: Hash,
    /// Valid round (-1 if none)
    pub valid_round: i64,
    /// Timestamp when proposal was signed (Unix millis)
    pub timestamp_ms: u64,
}

/// Payload for Locked entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LockedPayload {
    /// Block height
    pub height: u64,
    /// Round when locked
    pub round: u64,
    /// Hash of the locked block
    pub block_hash: Hash,
    /// Timestamp when lock occurred (Unix millis)
    pub timestamp_ms: u64,
}

/// Payload for Committed entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedPayload {
    /// Block height that was committed
    pub height: u64,
    /// Hash of the committed block
    pub block_hash: Hash,
    /// Timestamp when commit occurred (Unix millis)
    pub timestamp_ms: u64,
}

/// A WAL entry with type and payload
#[derive(Debug, Clone)]
pub struct WalEntry {
    /// Type of the entry
    pub entry_type: WalEntryType,
    /// Serialized payload
    pub payload: Vec<u8>,
}

impl WalEntry {
    /// Create a new HeightStart entry
    pub fn height_start(height: u64, parent_hash: Hash) -> Self {
        let payload = HeightStartPayload {
            height,
            parent_hash,
            timestamp_ms: current_time_ms(),
        };
        Self {
            entry_type: WalEntryType::HeightStart,
            payload: bincode_serialize(&payload),
        }
    }

    /// Create a new VoteSigned entry
    pub fn vote_signed(height: u64, round: u64, vote_type: VoteType, block_hash: Hash) -> Self {
        let payload = VoteSignedPayload {
            height,
            round,
            vote_type,
            block_hash,
            timestamp_ms: current_time_ms(),
        };
        Self {
            entry_type: WalEntryType::VoteSigned,
            payload: bincode_serialize(&payload),
        }
    }

    /// Create a new ProposalSigned entry
    pub fn proposal_signed(height: u64, round: u64, block_hash: Hash, valid_round: i64) -> Self {
        let payload = ProposalSignedPayload {
            height,
            round,
            block_hash,
            valid_round,
            timestamp_ms: current_time_ms(),
        };
        Self {
            entry_type: WalEntryType::ProposalSigned,
            payload: bincode_serialize(&payload),
        }
    }

    /// Create a new Locked entry
    pub fn locked(height: u64, round: u64, block_hash: Hash) -> Self {
        let payload = LockedPayload {
            height,
            round,
            block_hash,
            timestamp_ms: current_time_ms(),
        };
        Self {
            entry_type: WalEntryType::Locked,
            payload: bincode_serialize(&payload),
        }
    }

    /// Create a new Committed entry
    pub fn committed(height: u64, block_hash: Hash) -> Self {
        let payload = CommittedPayload {
            height,
            block_hash,
            timestamp_ms: current_time_ms(),
        };
        Self {
            entry_type: WalEntryType::Committed,
            payload: bincode_serialize(&payload),
        }
    }

    /// Serialize the entry to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let payload_len = self.payload.len() as u32;
        let mut data = Vec::with_capacity(HEADER_SIZE + self.payload.len() + CRC_SIZE);

        // Write header
        data.extend_from_slice(&WAL_MAGIC);
        data.push(WAL_VERSION);
        data.push(self.entry_type as u8);
        data.extend_from_slice(&payload_len.to_le_bytes());

        // Write payload
        data.extend_from_slice(&self.payload);

        // Compute and write CRC32 checksum
        let crc = crc32_checksum(&data);
        data.extend_from_slice(&crc.to_le_bytes());

        data
    }

    /// Deserialize an entry from bytes
    pub fn from_bytes(data: &[u8], offset: u64) -> WalResult<Self> {
        if data.len() < HEADER_SIZE + CRC_SIZE {
            return Err(WalError::Corrupted {
                offset,
                message: "entry too short".to_string(),
            });
        }

        // Verify magic
        if data[0..4] != WAL_MAGIC {
            return Err(WalError::InvalidMagic);
        }

        // Check version
        let version = data[4];
        if version != WAL_VERSION {
            return Err(WalError::UnsupportedVersion(version));
        }

        // Parse entry type
        let entry_type = WalEntryType::try_from(data[5]).map_err(|_| WalError::Corrupted {
            offset,
            message: format!("invalid entry type: {}", data[5]),
        })?;

        // Parse payload length
        let payload_len = u32::from_le_bytes(data[6..10].try_into().unwrap()) as usize;

        // Verify we have enough data
        let total_len = HEADER_SIZE + payload_len + CRC_SIZE;
        if data.len() < total_len {
            return Err(WalError::Corrupted {
                offset,
                message: format!(
                    "incomplete entry: expected {} bytes, got {}",
                    total_len,
                    data.len()
                ),
            });
        }

        // Verify CRC
        let stored_crc = u32::from_le_bytes(
            data[HEADER_SIZE + payload_len..HEADER_SIZE + payload_len + CRC_SIZE]
                .try_into()
                .unwrap(),
        );
        let computed_crc = crc32_checksum(&data[..HEADER_SIZE + payload_len]);
        if stored_crc != computed_crc {
            return Err(WalError::Corrupted {
                offset,
                message: format!(
                    "CRC mismatch: stored {:#x}, computed {:#x}",
                    stored_crc, computed_crc
                ),
            });
        }

        Ok(Self {
            entry_type,
            payload: data[HEADER_SIZE..HEADER_SIZE + payload_len].to_vec(),
        })
    }

    /// Get the total serialized size of this entry
    pub fn serialized_size(&self) -> usize {
        HEADER_SIZE + self.payload.len() + CRC_SIZE
    }

    /// Parse as HeightStart payload
    pub fn as_height_start(&self) -> WalResult<HeightStartPayload> {
        bincode_deserialize(&self.payload)
    }

    /// Parse as VoteSigned payload
    pub fn as_vote_signed(&self) -> WalResult<VoteSignedPayload> {
        bincode_deserialize(&self.payload)
    }

    /// Parse as ProposalSigned payload
    pub fn as_proposal_signed(&self) -> WalResult<ProposalSignedPayload> {
        bincode_deserialize(&self.payload)
    }

    /// Parse as Locked payload
    pub fn as_locked(&self) -> WalResult<LockedPayload> {
        bincode_deserialize(&self.payload)
    }

    /// Parse as Committed payload
    pub fn as_committed(&self) -> WalResult<CommittedPayload> {
        bincode_deserialize(&self.payload)
    }
}

/// Recovered consensus state from WAL
#[derive(Debug, Clone, Default)]
pub struct RecoveredState {
    /// Last height that was started
    pub last_height: u64,
    /// Parent hash for the last height
    pub last_parent_hash: Option<Hash>,
    /// Highest committed height
    pub committed_height: u64,
    /// Locked value (block hash) if any
    pub locked_value: Option<Hash>,
    /// Round when locked
    pub locked_round: Option<u64>,
    /// All signed votes (for anti-equivocation)
    pub signed_votes: HashMap<(u64, u64, VoteType), Hash>,
    /// All signed proposals (for anti-equivocation)
    pub signed_proposals: HashMap<(u64, u64), Hash>,
    /// Number of entries recovered
    pub entries_recovered: usize,
    /// Number of corrupted entries skipped (if strict_recovery=false)
    pub corrupted_entries: usize,
}

impl RecoveredState {
    /// Check if we've already signed a vote at this position
    pub fn has_signed_vote(&self, height: u64, round: u64, vote_type: VoteType) -> bool {
        self.signed_votes.contains_key(&(height, round, vote_type))
    }

    /// Get what we signed for a vote at this position
    pub fn get_signed_vote(&self, height: u64, round: u64, vote_type: VoteType) -> Option<Hash> {
        self.signed_votes.get(&(height, round, vote_type)).copied()
    }

    /// Check if we've already signed a proposal at this position
    pub fn has_signed_proposal(&self, height: u64, round: u64) -> bool {
        self.signed_proposals.contains_key(&(height, round))
    }

    /// Get what we signed for a proposal at this position
    pub fn get_signed_proposal(&self, height: u64, round: u64) -> Option<Hash> {
        self.signed_proposals.get(&(height, round)).copied()
    }
}

/// The consensus Write-Ahead Log
///
/// Provides durable persistence for consensus state to prevent equivocation
/// and enable state recovery after crashes.
pub struct ConsensusWal {
    /// Configuration
    config: WalConfig,
    /// WAL file handle
    file: Mutex<Option<BufWriter<File>>>,
    /// Recovered state (for fast lookups)
    state: Mutex<RecoveredState>,
    /// Current file offset
    offset: Mutex<u64>,
}

impl ConsensusWal {
    /// Open or create a consensus WAL
    pub fn open(config: WalConfig) -> WalResult<Self> {
        // Create directory if it doesn't exist
        std::fs::create_dir_all(&config.dir)?;

        let wal_path = config.dir.join("consensus.wal");
        info!("Opening consensus WAL at: {:?}", wal_path);

        // Open file in append mode
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&wal_path)?;

        // Get current file size
        let offset = file.metadata()?.len();

        let wal = Self {
            config: config.clone(),
            file: Mutex::new(Some(BufWriter::new(file))),
            state: Mutex::new(RecoveredState::default()),
            offset: Mutex::new(offset),
        };

        // Recover state from existing WAL
        if offset > 0 {
            wal.recover_internal()?;
        }

        Ok(wal)
    }

    /// Recover state from the WAL file
    fn recover_internal(&self) -> WalResult<()> {
        let wal_path = self.config.dir.join("consensus.wal");
        let file = File::open(&wal_path)?;
        let file_len = file.metadata()?.len();

        if file_len == 0 {
            return Ok(());
        }

        let mut reader = BufReader::new(file);
        let mut offset: u64 = 0;
        let mut state = RecoveredState::default();
        let mut last_valid_offset = 0u64;

        info!("Recovering consensus WAL ({} bytes)", file_len);

        while offset < file_len {
            // Read header first to determine entry size
            let mut header = [0u8; HEADER_SIZE];
            match reader.read_exact(&mut header) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!("WAL truncated at offset {}", offset);
                    break;
                }
                Err(e) => return Err(WalError::Io(e)),
            }

            // Parse header to get payload length
            if header[0..4] != WAL_MAGIC {
                if self.config.strict_recovery {
                    return Err(WalError::InvalidMagic);
                }
                warn!("Invalid magic at offset {}, truncating WAL", offset);
                state.corrupted_entries += 1;
                break;
            }

            let payload_len = u32::from_le_bytes(header[6..10].try_into().unwrap()) as usize;
            let total_len = HEADER_SIZE + payload_len + CRC_SIZE;

            // Read the rest of the entry
            let mut entry_data = vec![0u8; total_len];
            entry_data[..HEADER_SIZE].copy_from_slice(&header);

            match reader.read_exact(&mut entry_data[HEADER_SIZE..]) {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    warn!("WAL entry truncated at offset {}", offset);
                    state.corrupted_entries += 1;
                    break;
                }
                Err(e) => return Err(WalError::Io(e)),
            }

            // Parse entry
            match WalEntry::from_bytes(&entry_data, offset) {
                Ok(entry) => {
                    self.apply_entry_to_state(&entry, &mut state)?;
                    state.entries_recovered += 1;
                    last_valid_offset = offset + total_len as u64;
                }
                Err(e) => {
                    if self.config.strict_recovery {
                        return Err(e);
                    }
                    warn!("Corrupted entry at offset {}: {}", offset, e);
                    state.corrupted_entries += 1;
                    break;
                }
            }

            offset += total_len as u64;
        }

        // Truncate to last valid offset if we had corruption
        if state.corrupted_entries > 0 {
            warn!(
                "Truncating WAL to last valid offset {} (skipped {} corrupted entries)",
                last_valid_offset, state.corrupted_entries
            );
            // Reopen in write mode to truncate
            let file = OpenOptions::new().write(true).open(&wal_path)?;
            file.set_len(last_valid_offset)?;
            *self.offset.lock() = last_valid_offset;
        }

        info!(
            "WAL recovery complete: {} entries, last_height={}, committed_height={}",
            state.entries_recovered, state.last_height, state.committed_height
        );

        *self.state.lock() = state;
        Ok(())
    }

    /// Apply a WAL entry to the recovered state
    fn apply_entry_to_state(&self, entry: &WalEntry, state: &mut RecoveredState) -> WalResult<()> {
        match entry.entry_type {
            WalEntryType::HeightStart => {
                let payload = entry.as_height_start()?;
                if payload.height > state.last_height {
                    state.last_height = payload.height;
                    state.last_parent_hash = Some(payload.parent_hash);
                    // Clear locked state for new height
                    state.locked_value = None;
                    state.locked_round = None;
                }
            }
            WalEntryType::VoteSigned => {
                let payload = entry.as_vote_signed()?;
                state.signed_votes.insert(
                    (payload.height, payload.round, payload.vote_type),
                    payload.block_hash,
                );
            }
            WalEntryType::ProposalSigned => {
                let payload = entry.as_proposal_signed()?;
                state
                    .signed_proposals
                    .insert((payload.height, payload.round), payload.block_hash);
            }
            WalEntryType::Locked => {
                let payload = entry.as_locked()?;
                if payload.height >= state.last_height {
                    state.locked_value = Some(payload.block_hash);
                    state.locked_round = Some(payload.round);
                }
            }
            WalEntryType::Committed => {
                let payload = entry.as_committed()?;
                if payload.height > state.committed_height {
                    state.committed_height = payload.height;
                }
            }
        }
        Ok(())
    }

    /// Write an entry to the WAL with fsync
    fn write_entry(&self, entry: WalEntry) -> WalResult<()> {
        let data = entry.to_bytes();

        let mut file_guard = self.file.lock();
        let file = file_guard.as_mut().ok_or(WalError::ReadOnly)?;

        file.write_all(&data)?;

        if self.config.sync_on_write {
            file.flush()?;
            file.get_ref().sync_all()?;
        }

        *self.offset.lock() += data.len() as u64;

        debug!(
            "WAL entry written: {:?} ({} bytes)",
            entry.entry_type,
            data.len()
        );

        Ok(())
    }

    /// Record the start of a new height
    ///
    /// This should be called when starting consensus for a new height.
    pub fn write_height_start(&self, height: u64, parent_hash: Hash) -> WalResult<()> {
        let entry = WalEntry::height_start(height, parent_hash);
        self.write_entry(entry)?;

        // Update in-memory state
        let mut state = self.state.lock();
        if height > state.last_height {
            state.last_height = height;
            state.last_parent_hash = Some(parent_hash);
            state.locked_value = None;
            state.locked_round = None;
        }

        Ok(())
    }

    /// Record a signed vote (prevote or precommit)
    ///
    /// MUST be called BEFORE signing. Returns error if we've already signed
    /// a different value for this (height, round, vote_type).
    pub fn write_vote_signed(
        &self,
        height: u64,
        round: u64,
        vote_type: VoteType,
        block_hash: Hash,
    ) -> WalResult<()> {
        // Check for equivocation
        {
            let state = self.state.lock();
            if let Some(existing) = state.signed_votes.get(&(height, round, vote_type)) {
                if *existing != block_hash {
                    return Err(WalError::EquivocationDetected {
                        height,
                        round,
                        existing: *existing,
                    });
                }
                // Same value, already recorded - this is OK (idempotent)
                return Ok(());
            }
        }

        // Write to WAL
        let entry = WalEntry::vote_signed(height, round, vote_type, block_hash);
        self.write_entry(entry)?;

        // Update in-memory state
        self.state
            .lock()
            .signed_votes
            .insert((height, round, vote_type), block_hash);

        Ok(())
    }

    /// Record a signed proposal
    ///
    /// MUST be called BEFORE signing. Returns error if we've already signed
    /// a different proposal for this (height, round).
    pub fn write_proposal_signed(
        &self,
        height: u64,
        round: u64,
        block_hash: Hash,
        valid_round: i64,
    ) -> WalResult<()> {
        // Check for equivocation
        {
            let state = self.state.lock();
            if let Some(existing) = state.signed_proposals.get(&(height, round)) {
                if *existing != block_hash {
                    return Err(WalError::EquivocationDetected {
                        height,
                        round,
                        existing: *existing,
                    });
                }
                // Same value, already recorded - this is OK (idempotent)
                return Ok(());
            }
        }

        // Write to WAL
        let entry = WalEntry::proposal_signed(height, round, block_hash, valid_round);
        self.write_entry(entry)?;

        // Update in-memory state
        self.state
            .lock()
            .signed_proposals
            .insert((height, round), block_hash);

        Ok(())
    }

    /// Record locking on a block
    pub fn write_locked(&self, height: u64, round: u64, block_hash: Hash) -> WalResult<()> {
        let entry = WalEntry::locked(height, round, block_hash);
        self.write_entry(entry)?;

        // Update in-memory state
        let mut state = self.state.lock();
        state.locked_value = Some(block_hash);
        state.locked_round = Some(round);

        Ok(())
    }

    /// Record block commitment
    ///
    /// This enables pruning of old WAL entries.
    pub fn write_committed(&self, height: u64, block_hash: Hash) -> WalResult<()> {
        let entry = WalEntry::committed(height, block_hash);
        self.write_entry(entry)?;

        // Update in-memory state
        let mut state = self.state.lock();
        if height > state.committed_height {
            state.committed_height = height;
        }

        Ok(())
    }

    /// Check if we've already signed a vote at this position
    pub fn has_signed_vote(&self, height: u64, round: u64, vote_type: VoteType) -> bool {
        self.state
            .lock()
            .signed_votes
            .contains_key(&(height, round, vote_type))
    }

    /// Get what we signed for a vote at this position
    pub fn get_signed_vote(&self, height: u64, round: u64, vote_type: VoteType) -> Option<Hash> {
        self.state
            .lock()
            .signed_votes
            .get(&(height, round, vote_type))
            .copied()
    }

    /// Check if we've already signed a proposal at this position
    pub fn has_signed_proposal(&self, height: u64, round: u64) -> bool {
        self.state
            .lock()
            .signed_proposals
            .contains_key(&(height, round))
    }

    /// Get what we signed for a proposal at this position
    pub fn get_signed_proposal(&self, height: u64, round: u64) -> Option<Hash> {
        self.state
            .lock()
            .signed_proposals
            .get(&(height, round))
            .copied()
    }

    /// Get the recovered state
    pub fn recovered_state(&self) -> RecoveredState {
        self.state.lock().clone()
    }

    /// Get the last height that was started
    pub fn last_height(&self) -> u64 {
        self.state.lock().last_height
    }

    /// Get the highest committed height
    pub fn committed_height(&self) -> u64 {
        self.state.lock().committed_height
    }

    /// Get the locked value and round
    pub fn locked_state(&self) -> (Option<Hash>, Option<u64>) {
        let state = self.state.lock();
        (state.locked_value, state.locked_round)
    }

    /// Prune old WAL entries
    ///
    /// Creates a new WAL file with only entries for heights >= min_height.
    pub fn prune(&self, min_height: u64) -> WalResult<()> {
        let wal_path = self.config.dir.join("consensus.wal");
        let temp_path = self.config.dir.join("consensus.wal.tmp");

        info!("Pruning WAL entries below height {}", min_height);

        // Close current file
        {
            let mut file_guard = self.file.lock();
            if let Some(f) = file_guard.take() {
                drop(f);
            }
        }

        // Read all entries and filter
        let old_file = File::open(&wal_path)?;
        let file_len = old_file.metadata()?.len();
        let mut reader = BufReader::new(old_file);
        let mut new_file = BufWriter::new(File::create(&temp_path)?);

        let mut offset: u64 = 0;
        let mut pruned_count = 0;
        let mut kept_count = 0;

        while offset < file_len {
            // Read header
            let mut header = [0u8; HEADER_SIZE];
            if reader.read_exact(&mut header).is_err() {
                break;
            }

            if header[0..4] != WAL_MAGIC {
                break;
            }

            let payload_len = u32::from_le_bytes(header[6..10].try_into().unwrap()) as usize;
            let total_len = HEADER_SIZE + payload_len + CRC_SIZE;

            // Read full entry
            let mut entry_data = vec![0u8; total_len];
            entry_data[..HEADER_SIZE].copy_from_slice(&header);
            if reader.read_exact(&mut entry_data[HEADER_SIZE..]).is_err() {
                break;
            }

            // Parse and check if we should keep it
            if let Ok(entry) = WalEntry::from_bytes(&entry_data, offset) {
                let keep = match entry.entry_type {
                    WalEntryType::HeightStart => entry
                        .as_height_start()
                        .map(|p| p.height >= min_height)
                        .unwrap_or(false),
                    WalEntryType::VoteSigned => entry
                        .as_vote_signed()
                        .map(|p| p.height >= min_height)
                        .unwrap_or(false),
                    WalEntryType::ProposalSigned => entry
                        .as_proposal_signed()
                        .map(|p| p.height >= min_height)
                        .unwrap_or(false),
                    WalEntryType::Locked => entry
                        .as_locked()
                        .map(|p| p.height >= min_height)
                        .unwrap_or(false),
                    WalEntryType::Committed => entry
                        .as_committed()
                        .map(|p| p.height >= min_height)
                        .unwrap_or(false),
                };

                if keep {
                    new_file.write_all(&entry_data)?;
                    kept_count += 1;
                } else {
                    pruned_count += 1;
                }
            }

            offset += total_len as u64;
        }

        // Flush and sync new file
        new_file.flush()?;
        new_file.get_ref().sync_all()?;
        drop(new_file);

        // Replace old file with new one
        std::fs::rename(&temp_path, &wal_path)?;

        // Reopen the file
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .append(true)
            .open(&wal_path)?;

        let new_offset = file.metadata()?.len();
        *self.offset.lock() = new_offset;
        *self.file.lock() = Some(BufWriter::new(file));

        // Update in-memory state
        {
            let mut state = self.state.lock();
            state.signed_votes.retain(|(h, _, _), _| *h >= min_height);
            state.signed_proposals.retain(|(h, _), _| *h >= min_height);
        }

        info!(
            "WAL pruned: removed {} entries, kept {} entries",
            pruned_count, kept_count
        );

        Ok(())
    }

    /// Close the WAL
    pub fn close(&self) -> WalResult<()> {
        let mut file_guard = self.file.lock();
        if let Some(mut f) = file_guard.take() {
            f.flush()?;
            f.get_ref().sync_all()?;
        }
        Ok(())
    }

    /// Flush any buffered writes
    pub fn flush(&self) -> WalResult<()> {
        let mut file_guard = self.file.lock();
        if let Some(f) = file_guard.as_mut() {
            f.flush()?;
            if self.config.sync_on_write {
                f.get_ref().sync_all()?;
            }
        }
        Ok(())
    }

    /// Get the current WAL file size
    pub fn file_size(&self) -> u64 {
        *self.offset.lock()
    }

    /// Get the configuration
    pub fn config(&self) -> &WalConfig {
        &self.config
    }
}

impl Drop for ConsensusWal {
    fn drop(&mut self) {
        if let Err(e) = self.close() {
            error!("Error closing WAL: {}", e);
        }
    }
}

// ============================================================================
// Helper functions
// ============================================================================

/// Get current time in milliseconds
fn current_time_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// CRC32 checksum (using IEEE polynomial)
fn crc32_checksum(data: &[u8]) -> u32 {
    // Simple CRC32 implementation (IEEE polynomial 0xEDB88320)
    const TABLE: [u32; 256] = generate_crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        let index = ((crc ^ (*byte as u32)) & 0xFF) as usize;
        crc = TABLE[index] ^ (crc >> 8);
    }
    !crc
}

/// Generate CRC32 lookup table at compile time
const fn generate_crc32_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut crc = i as u32;
        let mut j = 0;
        while j < 8 {
            if crc & 1 != 0 {
                crc = 0xEDB8_8320 ^ (crc >> 1);
            } else {
                crc >>= 1;
            }
            j += 1;
        }
        table[i] = crc;
        i += 1;
    }
    table
}

/// Simple bincode-like serialization
fn bincode_serialize<T: Serialize>(value: &T) -> Vec<u8> {
    // Use a simple length-prefixed format compatible with serde
    let json = serde_json::to_vec(value).unwrap_or_default();
    let mut result = Vec::with_capacity(4 + json.len());
    result.extend_from_slice(&(json.len() as u32).to_le_bytes());
    result.extend_from_slice(&json);
    result
}

/// Simple bincode-like deserialization
fn bincode_deserialize<T: for<'de> Deserialize<'de>>(data: &[u8]) -> WalResult<T> {
    if data.len() < 4 {
        return Err(WalError::Serialization("data too short".to_string()));
    }
    let len = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
    if data.len() < 4 + len {
        return Err(WalError::Serialization("incomplete data".to_string()));
    }
    serde_json::from_slice(&data[4..4 + len]).map_err(|e| WalError::Serialization(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_test_wal() -> (ConsensusWal, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let config = WalConfig {
            dir: dir.path().to_path_buf(),
            sync_on_write: false, // Faster for tests
            max_heights_retained: 10,
            strict_recovery: true,
        };
        let wal = ConsensusWal::open(config).unwrap();
        (wal, dir)
    }

    #[test]
    fn test_wal_entry_roundtrip() {
        let entry = WalEntry::vote_signed(100, 5, VoteType::Prevote, [42u8; 32]);
        let bytes = entry.to_bytes();
        let recovered = WalEntry::from_bytes(&bytes, 0).unwrap();

        assert_eq!(recovered.entry_type, WalEntryType::VoteSigned);
        let payload = recovered.as_vote_signed().unwrap();
        assert_eq!(payload.height, 100);
        assert_eq!(payload.round, 5);
        assert_eq!(payload.vote_type, VoteType::Prevote);
        assert_eq!(payload.block_hash, [42u8; 32]);
    }

    #[test]
    fn test_write_and_recover() {
        let (wal, _dir) = create_test_wal();

        // Write some entries
        wal.write_height_start(100, [1u8; 32]).unwrap();
        wal.write_vote_signed(100, 0, VoteType::Prevote, [2u8; 32])
            .unwrap();
        wal.write_vote_signed(100, 0, VoteType::Precommit, [2u8; 32])
            .unwrap();
        wal.write_locked(100, 0, [2u8; 32]).unwrap();
        wal.write_committed(100, [2u8; 32]).unwrap();

        // Close and reopen
        wal.close().unwrap();

        let config = WalConfig {
            dir: _dir.path().to_path_buf(),
            sync_on_write: false,
            max_heights_retained: 10,
            strict_recovery: true,
        };
        let wal2 = ConsensusWal::open(config).unwrap();

        // Verify recovered state
        let state = wal2.recovered_state();
        assert_eq!(state.last_height, 100);
        assert_eq!(state.committed_height, 100);
        assert_eq!(state.locked_value, Some([2u8; 32]));
        assert!(state.has_signed_vote(100, 0, VoteType::Prevote));
        assert!(state.has_signed_vote(100, 0, VoteType::Precommit));
    }

    #[test]
    fn test_equivocation_detection() {
        let (wal, _dir) = create_test_wal();

        // Sign a vote
        wal.write_vote_signed(100, 0, VoteType::Prevote, [1u8; 32])
            .unwrap();

        // Try to sign different value - should fail
        let result = wal.write_vote_signed(100, 0, VoteType::Prevote, [2u8; 32]);
        assert!(matches!(result, Err(WalError::EquivocationDetected { .. })));

        // Same value should succeed (idempotent)
        wal.write_vote_signed(100, 0, VoteType::Prevote, [1u8; 32])
            .unwrap();
    }

    #[test]
    fn test_has_signed_checks() {
        let (wal, _dir) = create_test_wal();

        // Initially nothing signed
        assert!(!wal.has_signed_vote(100, 0, VoteType::Prevote));
        assert!(!wal.has_signed_proposal(100, 0));

        // Sign a vote
        wal.write_vote_signed(100, 0, VoteType::Prevote, [1u8; 32])
            .unwrap();
        assert!(wal.has_signed_vote(100, 0, VoteType::Prevote));
        assert!(!wal.has_signed_vote(100, 0, VoteType::Precommit));

        // Sign a proposal
        wal.write_proposal_signed(100, 0, [2u8; 32], -1).unwrap();
        assert!(wal.has_signed_proposal(100, 0));
        assert!(!wal.has_signed_proposal(100, 1));
    }

    #[test]
    fn test_pruning() {
        let (wal, _dir) = create_test_wal();

        // Write entries for multiple heights
        for height in 1..=10 {
            wal.write_height_start(height, [height as u8; 32]).unwrap();
            wal.write_vote_signed(height, 0, VoteType::Prevote, [height as u8; 32])
                .unwrap();
            wal.write_committed(height, [height as u8; 32]).unwrap();
        }

        // Prune heights < 5
        wal.prune(5).unwrap();

        // Verify state
        let state = wal.recovered_state();
        assert!(!state.has_signed_vote(1, 0, VoteType::Prevote));
        assert!(!state.has_signed_vote(4, 0, VoteType::Prevote));
        assert!(state.has_signed_vote(5, 0, VoteType::Prevote));
        assert!(state.has_signed_vote(10, 0, VoteType::Prevote));
    }

    #[test]
    fn test_crc32_checksum() {
        // Known test vector
        let data = b"123456789";
        let crc = crc32_checksum(data);
        assert_eq!(crc, 0xCBF43926);
    }

    #[test]
    fn test_corrupted_entry_detection() {
        let entry = WalEntry::vote_signed(100, 0, VoteType::Prevote, [1u8; 32]);
        let mut bytes = entry.to_bytes();

        // Corrupt a byte
        bytes[15] ^= 0xFF;

        let result = WalEntry::from_bytes(&bytes, 0);
        assert!(matches!(result, Err(WalError::Corrupted { .. })));
    }

    #[test]
    fn test_height_start_resets_lock() {
        let (wal, _dir) = create_test_wal();

        // Lock at height 100
        wal.write_height_start(100, [1u8; 32]).unwrap();
        wal.write_locked(100, 0, [2u8; 32]).unwrap();

        let (locked, round) = wal.locked_state();
        assert_eq!(locked, Some([2u8; 32]));
        assert_eq!(round, Some(0));

        // Start new height - should reset lock
        wal.write_height_start(101, [3u8; 32]).unwrap();

        let (locked, round) = wal.locked_state();
        assert_eq!(locked, None);
        assert_eq!(round, None);
    }
}
