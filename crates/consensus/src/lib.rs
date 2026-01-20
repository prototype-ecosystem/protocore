//! # Proto Core Consensus
//!
//! ProtoBFT consensus engine for the Prototype Network blockchain.
//!
//! This crate implements a simplified Byzantine Fault Tolerant consensus protocol
//! based on Tendermint's core ideas, providing deterministic finality in 2 phases.
//!
//! ## Features
//!
//! - **2-block finality** (~4 seconds with default timeouts)
//! - **BFT safety**: Tolerates f Byzantine validators where n = 3f + 1
//! - **Aggregated BLS signatures** for efficient finality certificates
//! - **Exponential backoff timeouts** for liveness under network partitions
//!
//! ## Consensus Flow
//!
//! ```text
//! Round r, Height h:
//!
//! ┌──────────────┐
//! │   PROPOSE    │  proposer = validators[(h + r) % n]
//! │              │  broadcast Proposal{h, r, block, valid_round}
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │   PREVOTE    │  IF valid(block) AND locking_rules_satisfied:
//! │              │      broadcast Vote{PREVOTE, h, r, hash(block)}
//! │              │  ELSE:
//! │              │      broadcast Vote{PREVOTE, h, r, NIL}
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │  PRECOMMIT   │  ON 2f+1 PREVOTES for block_hash:
//! │              │      lock on block
//! │              │      broadcast Vote{PRECOMMIT, h, r, block_hash}
//! └──────┬───────┘
//!        │
//!        ▼
//! ┌──────────────┐
//! │   COMMIT     │  ON 2f+1 PRECOMMITS for block_hash != NIL:
//! │              │      finality_cert = aggregate_signatures(precommits)
//! │              │      commit_block(block, finality_cert)
//! └──────────────┘
//! ```
//!
//! ## Example
//!
//! ```rust,ignore
//! use protocore_consensus::{ConsensusEngine, ConsensusState, TimeoutConfig};
//! use protocore_consensus::types::{ValidatorSet, Validator};
//! use protocore_crypto::BlsPrivateKey;
//!
//! // Create validator set
//! let key = BlsPrivateKey::random();
//! let validators = vec![
//!     Validator::new(0, key.public_key(), [0u8; 20], 1000, 500),
//! ];
//! let validator_set = ValidatorSet::new(validators);
//!
//! // Create channels
//! let (network_tx, network_rx) = tokio::sync::mpsc::channel(100);
//! let (commit_tx, commit_rx) = tokio::sync::mpsc::channel(100);
//! let (timeout_tx, timeout_rx) = tokio::sync::mpsc::channel(100);
//!
//! // Create and start engine
//! let engine = ConsensusEngine::new(
//!     0,  // validator_id
//!     key,
//!     validator_set,
//!     TimeoutConfig::default(),
//!     block_validator,
//!     block_builder,
//!     network_tx,
//!     commit_tx,
//!     timeout_tx,
//! );
//!
//! // Start consensus at height 1
//! engine.start(1, [0u8; 32]).await;
//! ```
//!
//! ## Safety Guarantees
//!
//! **Agreement**: No two honest validators commit different blocks at the same height.
//!
//! **Finality**: Once a block is committed (with finality certificate), it cannot be reverted.
//!
//! **Liveness**: The chain makes progress as long as >2/3 validators are honest and online.
//!
//! ## Fault Tolerance
//!
//! - Tolerates up to `f` Byzantine validators where `n = 3f + 1`
//! - With 51 validators: tolerates 16 Byzantine nodes
//! - Requires `2f + 1 = 35` signatures for finality

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]
#![deny(unsafe_code)]

pub mod ddos;
pub mod deduplication;
pub mod engine;
pub mod epoch;
pub mod evidence;
pub mod fork_choice;
// pub mod integrity;  // Deferred to phase2/
// pub mod inverse_rewards;  // Deferred to phase2/
pub mod light_client;
pub mod participation;
pub mod proposer;
pub mod randomness;
pub mod signing_coordinator;
pub mod state_machine;
pub mod sybil;
pub mod timeout;
pub mod types;
pub mod vote_set;
pub mod wal;

// Re-export main types at crate root for convenience
pub use engine::{BlockBuilder, BlockValidator, ConsensusEngine, ConsensusError, ConsensusState};
pub use participation::{
    AggregateStats, EpochParticipation, ParticipationSnapshot, ParticipationTracker,
    ValidatorParticipation, BLOCK_WEIGHT, UPTIME_WEIGHT, VOTE_WEIGHT,
};
pub use randomness::{BlockRandomness, RandomnessBeacon, RandomnessBeaconSnapshot, RandomnessError};
pub use timeout::{BackoffMode, TimeoutConfig, TimeoutInfo, TimeoutMetrics, TimeoutScheduler};
pub use types::{
    CommittedBlock, ConsensusMessage, FinalityCert, Proposal, Step, ValidatorId, ValidatorSet,
    Validator, Vote, VoteType, NIL_HASH, domains,
};
pub use vote_set::{HeightVoteSet, VoteSet, VoteSetError};
// Deferred to phase2/:
// pub use inverse_rewards::{...};
// pub use integrity::{...};
pub use sybil::{
    AppealState, AppealStatus, ConfidenceLevel, SignalType, SybilConfig, SybilDetector,
    SybilSignal, SybilStatus,
};
pub use proposer::{
    ProposerConfig, ProposerError, ProposerResult, ProposerSelection, ProposerSelector,
    ProposerSnapshot, ProposerStats,
};
pub use evidence::{
    EquivocationDetector, EquivocationEvidence, EvidenceError, EvidencePool,
    EVIDENCE_MAX_AGE_BLOCKS,
};
pub use state_machine::{
    CommitHistory, ConsensusEvent, ConsensusStateMachine, StateMachineError,
    StateMachineResult, StateMachineSnapshot, VotePhase,
};
pub use deduplication::{
    CacheStats, DeduplicationConfig, DeduplicationResult, MessageDeduplicationCache,
    MessageId, compute_message_id, compute_proposal_id, compute_vote_id,
};
pub use signing_coordinator::{
    LeaderLease, SigningCoordinator, SigningCoordinatorConfig, SigningCoordinatorError,
    SigningKey, SigningLockGuard, SigningRecord, SigningRole,
    DEFAULT_LEASE_DURATION_MS, DEFAULT_LEASE_RENEWAL_THRESHOLD_MS,
    DEFAULT_MISSED_BLOCKS_THRESHOLD, DEFAULT_TAKEOVER_TIMEOUT_MS,
};
pub use types::ChainContext;
pub use wal::{
    ConsensusWal, RecoveredState, WalConfig, WalEntry, WalEntryType, WalError, WalResult,
    CommittedPayload, HeightStartPayload, LockedPayload, ProposalSignedPayload, VoteSignedPayload,
};
pub use epoch::{
    compute_validator_set_hash, EpochConfig, EpochError, EpochInfo, EpochManager,
    EpochManagerSnapshot, EpochNumber, EpochResult, EpochValidatorSet, ValidatorSetBuilder,
    DEFAULT_EPOCH_LENGTH, MAX_EPOCH_LENGTH, MIN_EPOCH_LENGTH,
};
pub use light_client::{
    BisectionHelper, LightClientError, LightClientResult, LightClientSnapshot, LightClientState,
    TrustedHeader, ValidatorSetProof, DEFAULT_TRUST_PERIOD_SECS, MAX_SEQUENTIAL_VERIFY_HEIGHT,
};
pub use ddos::{
    ConsensusDdosConfig, ConsensusDdosProtection, ConsensusDdosStats, ConsensusMessageType,
    ConsensusRejectReason, ConsensusValidationResult,
};
pub use fork_choice::{
    ChainHead, ChainSelector, CommitRules, ForkChoiceError, ForkChoiceResult, ForkChoiceRule,
    ForkChoiceState,
};
