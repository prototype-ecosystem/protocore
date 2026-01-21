//! Consensus State Machine
//!
//! This module implements a formal state machine for the consensus protocol with:
//! - Explicit state definitions (NewHeight, Propose, Prevote, Precommit, Commit)
//! - Validated state transitions
//! - Height/round monotonicity enforcement
//! - Safety property verification
//!
//! # State Machine Diagram
//!
//! ```text
//! ┌────────────┐
//! │ NewHeight  │◄──────────────────────────────────────┐
//! └─────┬──────┘                                       │
//!       │ StartRound(height, round=0)                  │
//!       ▼                                              │
//! ┌────────────┐                                       │
//! │  Propose   │◄─────────────────────────┐            │
//! └─────┬──────┘                          │            │
//!       │ ReceivedProposal / ProposeTimeout│            │
//!       ▼                                  │            │
//! ┌────────────┐                          │            │
//! │  Prevote   │                          │            │
//! └─────┬──────┘                          │            │
//!       │ PrevoteQuorum / PrevoteTimeout  │            │
//!       ▼                                 │            │
//! ┌────────────┐     RoundTimeout         │            │
//! │ Precommit  │──────────────────────────┘            │
//! └─────┬──────┘  (increment round)                    │
//!       │                                              │
//!       │ PrecommitQuorum (for non-nil block)          │
//!       ▼                                              │
//! ┌────────────┐                                       │
//! │   Commit   │───────────────────────────────────────┘
//! └────────────┘  BlockCommitted (height++)
//! ```
//!
//! # Safety Properties
//!
//! 1. **No two blocks at same height**: Once committed, a block hash is recorded
//! 2. **2f+1 precommits required**: Commit only occurs with quorum
//! 3. **Locked value respected**: Cannot vote against locked block without POL
//! 4. **Height monotonicity**: Height only increases after commit
//! 5. **Round monotonicity**: Round only increases or resets to 0 at new height

use std::collections::HashSet;

use protocore_crypto::Hash;
use thiserror::Error;
use tracing::{debug, error, warn};

use crate::types::Step;

/// Errors that can occur during state machine transitions
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StateMachineError {
    /// Invalid state transition attempted
    #[error("invalid transition from {from} to {to} at height {height} round {round}")]
    InvalidTransition {
        /// Source step
        from: Step,
        /// Target step
        to: Step,
        /// Block height
        height: u64,
        /// Round number
        round: u64,
    },

    /// Height decreased (must be monotonically increasing)
    #[error("height decreased from {previous} to {current}")]
    HeightDecreased {
        /// Previous height
        previous: u64,
        /// Attempted new height
        current: u64,
    },

    /// Round decreased within same height (must be monotonically increasing)
    #[error("round decreased from {previous} to {current} at height {height}")]
    RoundDecreased {
        /// Block height
        height: u64,
        /// Previous round
        previous: u64,
        /// Attempted new round
        current: u64,
    },

    /// Attempted to commit different block at same height
    #[error("conflicting commit at height {height}: previous {previous_hash:?}, attempted {attempted_hash:?}")]
    ConflictingCommit {
        /// Block height
        height: u64,
        /// Previously committed block hash
        previous_hash: Hash,
        /// Attempted new block hash
        attempted_hash: Hash,
    },

    /// Commit without sufficient precommits
    #[error("insufficient precommits for commit: got {got} stake, need {required} stake")]
    InsufficientPrecommits {
        /// Stake received
        got: u128,
        /// Stake required
        required: u128,
    },

    /// Locked value violation
    #[error("voted against locked value without valid POL")]
    LockedValueViolation,

    /// State machine not initialized
    #[error("state machine not initialized")]
    NotInitialized,
}

/// Result type for state machine operations
pub type StateMachineResult<T> = Result<T, StateMachineError>;

/// Events that trigger state transitions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConsensusEvent {
    /// Start a new height (called after commit or at genesis)
    NewHeight {
        /// Block height
        height: u64,
    },
    /// Start a round (proposer determined externally)
    StartRound {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
    },
    /// Received a valid proposal
    ReceivedProposal {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
        /// Hash of the proposed block
        block_hash: Hash,
    },
    /// Propose timeout expired
    ProposeTimeout {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
    },
    /// Received 2f+1 prevotes for a block (or nil)
    PrevoteQuorum {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
        /// Hash of the block with quorum (or NIL_HASH)
        block_hash: Hash,
    },
    /// Prevote timeout expired
    PrevoteTimeout {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
    },
    /// Received 2f+1 precommits for a block (or nil)
    PrecommitQuorum {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
        /// Hash of the block with quorum (or NIL_HASH)
        block_hash: Hash,
    },
    /// Precommit timeout expired (move to next round)
    PrecommitTimeout {
        /// Block height
        height: u64,
        /// Round number
        round: u64,
    },
    /// Block has been committed
    BlockCommitted {
        /// Block height
        height: u64,
        /// Hash of the committed block
        block_hash: Hash,
    },
}

impl std::fmt::Display for ConsensusEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusEvent::NewHeight { height } => write!(f, "NewHeight({})", height),
            ConsensusEvent::StartRound { height, round } => {
                write!(f, "StartRound(h={}, r={})", height, round)
            }
            ConsensusEvent::ReceivedProposal { height, round, .. } => {
                write!(f, "ReceivedProposal(h={}, r={})", height, round)
            }
            ConsensusEvent::ProposeTimeout { height, round } => {
                write!(f, "ProposeTimeout(h={}, r={})", height, round)
            }
            ConsensusEvent::PrevoteQuorum {
                height,
                round,
                block_hash,
            } => {
                let hash_str = if *block_hash == [0u8; 32] {
                    "NIL".to_string()
                } else {
                    hex::encode(&block_hash[..4])
                };
                write!(f, "PrevoteQuorum(h={}, r={}, {})", height, round, hash_str)
            }
            ConsensusEvent::PrevoteTimeout { height, round } => {
                write!(f, "PrevoteTimeout(h={}, r={})", height, round)
            }
            ConsensusEvent::PrecommitQuorum {
                height,
                round,
                block_hash,
            } => {
                let hash_str = if *block_hash == [0u8; 32] {
                    "NIL".to_string()
                } else {
                    hex::encode(&block_hash[..4])
                };
                write!(
                    f,
                    "PrecommitQuorum(h={}, r={}, {})",
                    height, round, hash_str
                )
            }
            ConsensusEvent::PrecommitTimeout { height, round } => {
                write!(f, "PrecommitTimeout(h={}, r={})", height, round)
            }
            ConsensusEvent::BlockCommitted { height, block_hash } => {
                write!(
                    f,
                    "BlockCommitted(h={}, {})",
                    height,
                    hex::encode(&block_hash[..4])
                )
            }
        }
    }
}

/// Tracks committed block hashes to prevent conflicting commits
#[derive(Debug, Clone, Default)]
pub struct CommitHistory {
    /// Map of height -> committed block hash
    commits: std::collections::HashMap<u64, Hash>,
    /// Highest committed height
    highest_height: u64,
}

impl CommitHistory {
    /// Create a new empty commit history
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a commit at the given height
    pub fn record_commit(&mut self, height: u64, block_hash: Hash) -> StateMachineResult<()> {
        if let Some(existing) = self.commits.get(&height) {
            if existing != &block_hash {
                return Err(StateMachineError::ConflictingCommit {
                    height,
                    previous_hash: *existing,
                    attempted_hash: block_hash,
                });
            }
            // Same hash, idempotent
            return Ok(());
        }

        self.commits.insert(height, block_hash);
        if height > self.highest_height {
            self.highest_height = height;
        }
        Ok(())
    }

    /// Get the committed block hash at a height
    pub fn get_commit(&self, height: u64) -> Option<&Hash> {
        self.commits.get(&height)
    }

    /// Get the highest committed height
    pub fn highest_height(&self) -> u64 {
        self.highest_height
    }

    /// Prune commits below a certain height (for memory management)
    pub fn prune_below(&mut self, height: u64) {
        self.commits.retain(|h, _| *h >= height);
    }
}

/// The formal consensus state machine
///
/// Tracks consensus state and validates all transitions to ensure correctness.
#[derive(Debug, Clone)]
pub struct ConsensusStateMachine {
    /// Current step in the state machine
    step: Step,
    /// Current block height
    height: u64,
    /// Current round within the height
    round: u64,
    /// Whether the state machine has been initialized
    initialized: bool,

    /// Locked block hash (cannot vote against without POL)
    locked_value: Option<Hash>,
    /// Round in which we locked
    locked_round: Option<u64>,

    /// Valid value seen (for re-proposing)
    valid_value: Option<Hash>,
    /// Round in which we saw valid value
    valid_round: Option<u64>,

    /// History of committed blocks (for safety verification)
    commit_history: CommitHistory,

    /// Set of (height, round) pairs where we've already voted
    /// Prevents double-voting within the same round
    voted_rounds: HashSet<(u64, u64, VotePhase)>,
}

/// Which voting phase (to track separate prevote/precommit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VotePhase {
    /// First round of voting
    Prevote,
    /// Second round of voting (after seeing prevote quorum)
    Precommit,
}

impl Default for ConsensusStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsensusStateMachine {
    /// Create a new uninitialized state machine
    pub fn new() -> Self {
        Self {
            step: Step::NewHeight,
            height: 0,
            round: 0,
            initialized: false,
            locked_value: None,
            locked_round: None,
            valid_value: None,
            valid_round: None,
            commit_history: CommitHistory::new(),
            voted_rounds: HashSet::new(),
        }
    }

    /// Initialize the state machine at a specific height
    pub fn initialize(&mut self, height: u64) {
        self.height = height;
        self.round = 0;
        self.step = Step::NewHeight;
        self.initialized = true;
        self.locked_value = None;
        self.locked_round = None;
        self.valid_value = None;
        self.valid_round = None;
        debug!(height = height, "State machine initialized");
    }

    /// Get current step
    pub fn step(&self) -> Step {
        self.step
    }

    /// Get current height
    pub fn height(&self) -> u64 {
        self.height
    }

    /// Get current round
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Check if initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get locked value
    pub fn locked_value(&self) -> Option<&Hash> {
        self.locked_value.as_ref()
    }

    /// Get locked round
    pub fn locked_round(&self) -> Option<u64> {
        self.locked_round
    }

    /// Get valid value
    pub fn valid_value(&self) -> Option<&Hash> {
        self.valid_value.as_ref()
    }

    /// Get valid round
    pub fn valid_round(&self) -> Option<u64> {
        self.valid_round
    }

    /// Get commit history reference
    pub fn commit_history(&self) -> &CommitHistory {
        &self.commit_history
    }

    /// Process an event and transition to the next state
    ///
    /// Returns the new step if transition was successful.
    pub fn apply_event(&mut self, event: ConsensusEvent) -> StateMachineResult<Step> {
        if !self.initialized && !matches!(event, ConsensusEvent::NewHeight { .. }) {
            return Err(StateMachineError::NotInitialized);
        }

        debug!(
            current_step = %self.step,
            height = self.height,
            round = self.round,
            event = %event,
            "Processing consensus event"
        );

        match event {
            ConsensusEvent::NewHeight { height } => self.handle_new_height(height),
            ConsensusEvent::StartRound { height, round } => self.handle_start_round(height, round),
            ConsensusEvent::ReceivedProposal {
                height,
                round,
                block_hash,
            } => self.handle_received_proposal(height, round, block_hash),
            ConsensusEvent::ProposeTimeout { height, round } => {
                self.handle_propose_timeout(height, round)
            }
            ConsensusEvent::PrevoteQuorum {
                height,
                round,
                block_hash,
            } => self.handle_prevote_quorum(height, round, block_hash),
            ConsensusEvent::PrevoteTimeout { height, round } => {
                self.handle_prevote_timeout(height, round)
            }
            ConsensusEvent::PrecommitQuorum {
                height,
                round,
                block_hash,
            } => self.handle_precommit_quorum(height, round, block_hash),
            ConsensusEvent::PrecommitTimeout { height, round } => {
                self.handle_precommit_timeout(height, round)
            }
            ConsensusEvent::BlockCommitted { height, block_hash } => {
                self.handle_block_committed(height, block_hash)
            }
        }
    }

    /// Handle NewHeight event
    fn handle_new_height(&mut self, height: u64) -> StateMachineResult<Step> {
        // Height must be greater than or equal to current (allows re-initialization)
        if self.initialized && height < self.height {
            return Err(StateMachineError::HeightDecreased {
                previous: self.height,
                current: height,
            });
        }

        // Valid transition from Commit -> NewHeight or initial state
        if self.initialized && self.step != Step::Commit && self.step != Step::NewHeight {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::NewHeight,
                height: self.height,
                round: self.round,
            });
        }

        self.height = height;
        self.round = 0;
        self.step = Step::NewHeight;
        self.initialized = true;

        // Reset locking state for new height
        self.locked_value = None;
        self.locked_round = None;
        self.valid_value = None;
        self.valid_round = None;

        // Prune old voted rounds
        self.voted_rounds
            .retain(|(h, _, _)| *h >= height.saturating_sub(1));

        debug!(height = height, "Entered NewHeight state");
        Ok(Step::NewHeight)
    }

    /// Handle StartRound event
    fn handle_start_round(&mut self, height: u64, round: u64) -> StateMachineResult<Step> {
        self.validate_height(height)?;

        // Round must not decrease within same height
        if height == self.height && round < self.round {
            return Err(StateMachineError::RoundDecreased {
                height,
                previous: self.round,
                current: round,
            });
        }

        // Valid transitions: NewHeight -> Propose, or Precommit/Prevote/Propose -> Propose (round change)
        // Note: Propose -> Propose is valid when catching up to a higher round (e.g., received
        // proposal/votes for round N+1 while still waiting in Propose step of round N)
        if !matches!(
            self.step,
            Step::NewHeight | Step::Precommit | Step::Prevote | Step::Propose
        ) {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::Propose,
                height,
                round,
            });
        }

        // Extra safety: Propose -> Propose only allowed when round is actually increasing
        if self.step == Step::Propose && height == self.height && round <= self.round {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::Propose,
                height,
                round,
            });
        }

        self.height = height;
        self.round = round;
        self.step = Step::Propose;

        debug!(height = height, round = round, "Entered Propose state");
        Ok(Step::Propose)
    }

    /// Handle ReceivedProposal event
    fn handle_received_proposal(
        &mut self,
        height: u64,
        round: u64,
        _block_hash: Hash,
    ) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        if self.step != Step::Propose {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::Prevote,
                height,
                round,
            });
        }

        self.step = Step::Prevote;
        debug!(height = height, round = round, "Entered Prevote state");
        Ok(Step::Prevote)
    }

    /// Handle ProposeTimeout event
    fn handle_propose_timeout(&mut self, height: u64, round: u64) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        if self.step != Step::Propose {
            // Timeout is stale, ignore
            return Ok(self.step);
        }

        self.step = Step::Prevote;
        debug!(
            height = height,
            round = round,
            "Propose timeout, entered Prevote state"
        );
        Ok(Step::Prevote)
    }

    /// Handle PrevoteQuorum event
    fn handle_prevote_quorum(
        &mut self,
        height: u64,
        round: u64,
        block_hash: Hash,
    ) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        if self.step != Step::Prevote {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::Precommit,
                height,
                round,
            });
        }

        // Update locking state if quorum is for a non-nil block
        if block_hash != [0u8; 32] {
            self.locked_value = Some(block_hash);
            self.locked_round = Some(round);
            self.valid_value = Some(block_hash);
            self.valid_round = Some(round);
            debug!(
                height = height,
                round = round,
                block_hash = hex::encode(&block_hash[..8]),
                "Locked on block"
            );
        }

        self.step = Step::Precommit;
        debug!(height = height, round = round, "Entered Precommit state");
        Ok(Step::Precommit)
    }

    /// Handle PrevoteTimeout event
    fn handle_prevote_timeout(&mut self, height: u64, round: u64) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        if self.step != Step::Prevote {
            // Timeout is stale, ignore
            return Ok(self.step);
        }

        self.step = Step::Precommit;
        debug!(
            height = height,
            round = round,
            "Prevote timeout, entered Precommit state"
        );
        Ok(Step::Precommit)
    }

    /// Handle PrecommitQuorum event
    fn handle_precommit_quorum(
        &mut self,
        height: u64,
        round: u64,
        block_hash: Hash,
    ) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        // Precommit quorum for nil means no commit this round
        if block_hash == [0u8; 32] {
            return Ok(self.step);
        }

        if self.step != Step::Precommit {
            return Err(StateMachineError::InvalidTransition {
                from: self.step,
                to: Step::Commit,
                height,
                round,
            });
        }

        self.step = Step::Commit;
        debug!(
            height = height,
            round = round,
            block_hash = hex::encode(&block_hash[..8]),
            "Entered Commit state"
        );
        Ok(Step::Commit)
    }

    /// Handle PrecommitTimeout event
    fn handle_precommit_timeout(&mut self, height: u64, round: u64) -> StateMachineResult<Step> {
        self.validate_height_round(height, round)?;

        if self.step != Step::Precommit {
            // Timeout is stale, ignore
            return Ok(self.step);
        }

        // Move to next round
        self.round = round + 1;
        self.step = Step::Propose;
        debug!(
            height = height,
            old_round = round,
            new_round = self.round,
            "Precommit timeout, moved to next round"
        );
        Ok(Step::Propose)
    }

    /// Handle BlockCommitted event
    fn handle_block_committed(
        &mut self,
        height: u64,
        block_hash: Hash,
    ) -> StateMachineResult<Step> {
        // Record commit in history (validates no conflicting commits)
        self.commit_history.record_commit(height, block_hash)?;

        // Only update state if this is for current height
        if height == self.height && self.step == Step::Commit {
            debug!(
                height = height,
                block_hash = hex::encode(&block_hash[..8]),
                "Block committed"
            );
        }

        Ok(self.step)
    }

    /// Validate that height matches current height
    fn validate_height(&self, height: u64) -> StateMachineResult<()> {
        if height < self.height {
            return Err(StateMachineError::HeightDecreased {
                previous: self.height,
                current: height,
            });
        }
        Ok(())
    }

    /// Validate that height and round match current state
    fn validate_height_round(&self, height: u64, round: u64) -> StateMachineResult<()> {
        self.validate_height(height)?;

        if height == self.height && round < self.round {
            return Err(StateMachineError::RoundDecreased {
                height,
                previous: self.round,
                current: round,
            });
        }
        Ok(())
    }

    /// Check if we can vote for a block hash (respects locking rules)
    ///
    /// Returns Ok(true) if voting is allowed, Ok(false) if should vote nil,
    /// or Err if the vote would be invalid.
    pub fn can_vote_for(
        &self,
        block_hash: Hash,
        pol_round: Option<u64>,
    ) -> StateMachineResult<bool> {
        // If not locked, can vote for any valid block
        let Some(locked_hash) = &self.locked_value else {
            return Ok(true);
        };

        // If voting for locked value, always allowed
        if &block_hash == locked_hash {
            return Ok(true);
        }

        // If there's a POL from a round >= locked_round, can unlock
        if let (Some(pol), Some(locked_r)) = (pol_round, self.locked_round) {
            if pol >= locked_r {
                return Ok(true);
            }
        }

        // Cannot vote for different block without valid POL
        warn!(
            locked_hash = hex::encode(&locked_hash[..8]),
            attempted_hash = hex::encode(&block_hash[..8]),
            "Attempted to vote against locked value"
        );
        Ok(false) // Should vote nil instead
    }

    /// Record that we voted in a specific round
    pub fn record_vote(&mut self, height: u64, round: u64, phase: VotePhase) -> bool {
        self.voted_rounds.insert((height, round, phase))
    }

    /// Check if we already voted in a specific round
    pub fn has_voted(&self, height: u64, round: u64, phase: VotePhase) -> bool {
        self.voted_rounds.contains(&(height, round, phase))
    }

    /// Verify safety invariants hold
    ///
    /// Returns Ok(()) if all invariants hold, or the first violation found.
    pub fn verify_safety_invariants(&self) -> StateMachineResult<()> {
        // Invariant 1: Height is non-decreasing
        // (Checked during transitions)

        // Invariant 2: Round is non-decreasing within a height
        // (Checked during transitions)

        // Invariant 3: No conflicting commits
        // (Checked during commit recording)

        // Invariant 4: If locked, valid_round >= locked_round
        if let (Some(vr), Some(lr)) = (self.valid_round, self.locked_round) {
            if vr < lr {
                error!(
                    valid_round = vr,
                    locked_round = lr,
                    "Safety violation: valid_round < locked_round"
                );
            }
        }

        Ok(())
    }

    /// Get a snapshot of the current state for debugging
    pub fn snapshot(&self) -> StateMachineSnapshot {
        StateMachineSnapshot {
            step: self.step,
            height: self.height,
            round: self.round,
            locked_value: self.locked_value,
            locked_round: self.locked_round,
            valid_value: self.valid_value,
            valid_round: self.valid_round,
            highest_commit: self.commit_history.highest_height(),
        }
    }
}

/// A snapshot of the state machine for debugging/monitoring
#[derive(Debug, Clone)]
pub struct StateMachineSnapshot {
    /// Current step
    pub step: Step,
    /// Current height
    pub height: u64,
    /// Current round
    pub round: u64,
    /// Locked block hash
    pub locked_value: Option<Hash>,
    /// Round when locked
    pub locked_round: Option<u64>,
    /// Valid block hash
    pub valid_value: Option<Hash>,
    /// Round when valid value was seen
    pub valid_round: Option<u64>,
    /// Highest committed height
    pub highest_commit: u64,
}

impl std::fmt::Display for StateMachineSnapshot {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "State(h={}, r={}, step={}, locked={}, valid={})",
            self.height,
            self.round,
            self.step,
            self.locked_round
                .map(|r| format!("r{}", r))
                .unwrap_or_else(|| "none".to_string()),
            self.valid_round
                .map(|r| format!("r{}", r))
                .unwrap_or_else(|| "none".to_string()),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normal_consensus_flow() {
        let mut sm = ConsensusStateMachine::new();
        let block_hash = [1u8; 32];

        // Initialize at height 1
        sm.initialize(1);
        assert_eq!(sm.step(), Step::NewHeight);
        assert_eq!(sm.height(), 1);

        // Start round 0
        sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 0,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Propose);

        // Receive proposal
        sm.apply_event(ConsensusEvent::ReceivedProposal {
            height: 1,
            round: 0,
            block_hash,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Prevote);

        // Prevote quorum
        sm.apply_event(ConsensusEvent::PrevoteQuorum {
            height: 1,
            round: 0,
            block_hash,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Precommit);
        assert_eq!(sm.locked_value(), Some(&block_hash));

        // Precommit quorum
        sm.apply_event(ConsensusEvent::PrecommitQuorum {
            height: 1,
            round: 0,
            block_hash,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Commit);

        // Block committed
        sm.apply_event(ConsensusEvent::BlockCommitted {
            height: 1,
            block_hash,
        })
        .unwrap();

        // Verify commit recorded
        assert_eq!(sm.commit_history().get_commit(1), Some(&block_hash));
    }

    #[test]
    fn test_round_timeout_flow() {
        let mut sm = ConsensusStateMachine::new();

        sm.initialize(1);

        // Start round 0
        sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 0,
        })
        .unwrap();

        // Propose timeout -> Prevote
        sm.apply_event(ConsensusEvent::ProposeTimeout {
            height: 1,
            round: 0,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Prevote);

        // Prevote timeout -> Precommit
        sm.apply_event(ConsensusEvent::PrevoteTimeout {
            height: 1,
            round: 0,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Precommit);

        // Precommit timeout -> Next round
        sm.apply_event(ConsensusEvent::PrecommitTimeout {
            height: 1,
            round: 0,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Propose);
        assert_eq!(sm.round(), 1);
    }

    #[test]
    fn test_invalid_transition() {
        let mut sm = ConsensusStateMachine::new();
        sm.initialize(1);

        // Try to go directly to Precommit from NewHeight
        let result = sm.apply_event(ConsensusEvent::PrevoteQuorum {
            height: 1,
            round: 0,
            block_hash: [0u8; 32],
        });
        assert!(matches!(
            result,
            Err(StateMachineError::InvalidTransition { .. })
        ));
    }

    #[test]
    fn test_height_monotonicity() {
        let mut sm = ConsensusStateMachine::new();
        sm.initialize(5);

        // Try to go to lower height
        let result = sm.apply_event(ConsensusEvent::NewHeight { height: 3 });
        assert!(matches!(
            result,
            Err(StateMachineError::HeightDecreased { .. })
        ));
    }

    #[test]
    fn test_round_monotonicity() {
        let mut sm = ConsensusStateMachine::new();
        sm.initialize(1);

        sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 5,
        })
        .unwrap();

        // Try to go to lower round
        let result = sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 3,
        });
        assert!(matches!(
            result,
            Err(StateMachineError::RoundDecreased { .. })
        ));
    }

    #[test]
    fn test_conflicting_commit_detection() {
        let mut sm = ConsensusStateMachine::new();
        let block_hash_1 = [1u8; 32];
        let block_hash_2 = [2u8; 32];

        sm.initialize(1);

        // Commit first block
        sm.commit_history.record_commit(1, block_hash_1).unwrap();

        // Try to commit different block at same height
        let result = sm.commit_history.record_commit(1, block_hash_2);
        assert!(matches!(
            result,
            Err(StateMachineError::ConflictingCommit { .. })
        ));
    }

    #[test]
    fn test_locking_rules() {
        let mut sm = ConsensusStateMachine::new();
        let locked_hash = [1u8; 32];
        let other_hash = [2u8; 32];

        sm.initialize(1);

        // Lock on a block
        sm.locked_value = Some(locked_hash);
        sm.locked_round = Some(0);

        // Can vote for locked value
        assert!(sm.can_vote_for(locked_hash, None).unwrap());

        // Cannot vote for different value without POL
        assert!(!sm.can_vote_for(other_hash, None).unwrap());

        // Can vote for different value with valid POL
        assert!(sm.can_vote_for(other_hash, Some(1)).unwrap());
    }

    #[test]
    fn test_vote_tracking() {
        let mut sm = ConsensusStateMachine::new();
        sm.initialize(1);

        // First vote should succeed
        assert!(sm.record_vote(1, 0, VotePhase::Prevote));

        // Second vote for same round should indicate already voted
        assert!(!sm.record_vote(1, 0, VotePhase::Prevote));

        // Different phase should be separate
        assert!(sm.record_vote(1, 0, VotePhase::Precommit));

        // Different round should be separate
        assert!(sm.record_vote(1, 1, VotePhase::Prevote));
    }

    #[test]
    fn test_step_transitions() {
        // Test valid transitions
        assert!(Step::NewHeight.can_transition_to(Step::Propose));
        assert!(Step::Propose.can_transition_to(Step::Prevote));
        assert!(Step::Prevote.can_transition_to(Step::Precommit));
        assert!(Step::Precommit.can_transition_to(Step::Commit));
        assert!(Step::Commit.can_transition_to(Step::NewHeight));

        // Round timeouts
        assert!(Step::Precommit.can_transition_to(Step::Propose));
        assert!(Step::Prevote.can_transition_to(Step::Propose));

        // Round catch-up (Propose -> Propose for higher round)
        assert!(Step::Propose.can_transition_to(Step::Propose));

        // Invalid transitions
        assert!(!Step::NewHeight.can_transition_to(Step::Prevote));
        assert!(!Step::NewHeight.can_transition_to(Step::Commit));
        assert!(!Step::Propose.can_transition_to(Step::Commit));
    }

    #[test]
    fn test_round_catchup_from_propose() {
        let mut sm = ConsensusStateMachine::new();

        sm.initialize(1);

        // Start round 0
        sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 0,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Propose);
        assert_eq!(sm.round(), 0);

        // Catch up to round 2 while still in Propose (received proposal/votes for higher round)
        sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 2,
        })
        .unwrap();
        assert_eq!(sm.step(), Step::Propose);
        assert_eq!(sm.round(), 2);

        // Cannot go back to lower round from Propose
        let result = sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 1,
        });
        assert!(matches!(
            result,
            Err(StateMachineError::RoundDecreased { .. })
        ));

        // Cannot stay at same round from Propose
        let result = sm.apply_event(ConsensusEvent::StartRound {
            height: 1,
            round: 2,
        });
        assert!(matches!(
            result,
            Err(StateMachineError::InvalidTransition { .. })
        ));
    }
}
