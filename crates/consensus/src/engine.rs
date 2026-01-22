//! MinBFT Consensus Engine
//!
//! This module implements the core consensus state machine for Proto Core.
//!
//! ## Consensus Flow
//!
//! For each height, the protocol proceeds through rounds until a block is committed:
//!
//! 1. **Propose**: Proposer broadcasts a block proposal
//! 2. **Prevote**: Validators vote on whether the proposal is valid
//! 3. **Precommit**: Validators commit to the block if they saw >2/3 prevotes
//! 4. **Commit**: Block is finalized when >2/3 precommits are collected
//!
//! ## Safety Guarantees
//!
//! - **Agreement**: No two honest validators commit different blocks at the same height
//! - **Finality**: Once committed, a block cannot be reverted
//! - **Liveness**: Chain makes progress when >2/3 validators are honest and online
//!
//! ## Fault Tolerance
//!
//! Tolerates f Byzantine validators where n = 3f + 1 (e.g., 51 validators can
//! tolerate 16 Byzantine nodes, requiring 35 signatures for finality).

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::RwLock;
use protocore_crypto::{
    bls::{BlsPrivateKey, BlsSignature},
    Hash,
};
use protocore_types::{Address, Block};
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::state_machine::{ConsensusEvent, ConsensusStateMachine, StateMachineError, VotePhase};
use crate::timeout::{TimeoutConfig, TimeoutInfo, TimeoutScheduler};
use crate::types::{
    CommittedBlock, ConsensusMessage, FinalityCert, Proposal, Step, ValidatorId, ValidatorSet,
    Vote, VoteType, NIL_HASH,
};
use crate::vote_set::{HeightVoteSet, VoteSet, VoteSetError};
use crate::wal::{ConsensusWal, WalConfig, WalError};

/// Errors that can occur during consensus operations
#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    /// Block validation failed
    #[error("invalid block: {0}")]
    InvalidBlock(String),

    /// Invalid proposal
    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    /// Invalid vote
    #[error("invalid vote: {0}")]
    InvalidVote(#[from] VoteSetError),

    /// Not the proposer for this round
    #[error("not the proposer for height {height} round {round}")]
    NotProposer { height: u64, round: u64 },

    /// Missing proposal for vote
    #[error("no proposal for height {height} round {round}")]
    MissingProposal { height: u64, round: u64 },

    /// Channel send error
    #[error("channel error: {0}")]
    ChannelError(String),

    /// Invalid signature
    #[error("invalid signature")]
    InvalidSignature,

    /// State machine error (invalid transition, safety violation, etc.)
    #[error("state machine error: {0}")]
    StateMachineError(#[from] StateMachineError),

    /// WAL error (persistence/recovery failure)
    #[error("WAL error: {0}")]
    WalError(#[from] WalError),

    /// Equivocation attempt detected (safety critical)
    #[error(
        "equivocation attempt at height {height}, round {round}: already signed different value"
    )]
    EquivocationAttempt {
        /// Block height
        height: u64,
        /// Consensus round
        round: u64,
    },
}

/// Trait for block validation (implemented by EVM executor)
#[async_trait]
pub trait BlockValidator: Send + Sync {
    /// Validate a proposed block
    async fn validate_block(&self, block: &Block, parent_hash: &Hash) -> Result<(), String>;
}

/// Trait for block building (implemented by mempool/block builder)
#[async_trait]
pub trait BlockBuilder: Send + Sync {
    /// Build a new block for the given height with the given proposer
    async fn build_block(&self, height: u64, parent_hash: Hash, proposer: Address) -> Block;
}

/// Current consensus state
#[derive(Debug, Clone)]
pub struct ConsensusState {
    /// Current block height
    pub height: u64,
    /// Current round within the height
    pub round: u64,
    /// Current step within the round
    pub step: Step,

    /// Block we've locked on (won't vote for different block unless POL)
    pub locked_value: Option<Block>,
    /// Round in which we locked (-1 if not locked)
    pub locked_round: i64,

    /// Valid value we've seen (for re-proposing)
    pub valid_value: Option<Block>,
    /// Round in which we saw valid value
    pub valid_round: i64,
}

impl ConsensusState {
    /// Create initial state at genesis
    pub fn new() -> Self {
        Self {
            height: 1,
            round: 0,
            step: Step::NewHeight,
            locked_value: None,
            locked_round: -1,
            valid_value: None,
            valid_round: -1,
        }
    }

    /// Reset state for a new height
    pub fn reset_for_height(&mut self, height: u64) {
        self.height = height;
        self.round = 0;
        self.step = Step::NewHeight;
        self.locked_value = None;
        self.locked_round = -1;
        self.valid_value = None;
        self.valid_round = -1;
    }

    /// Move to next round
    pub fn next_round(&mut self) {
        self.round += 1;
        self.step = Step::Propose;
    }
}

impl Default for ConsensusState {
    fn default() -> Self {
        Self::new()
    }
}

/// Main consensus engine
pub struct ConsensusEngine<V: BlockValidator, B: BlockBuilder> {
    /// Our validator ID
    validator_id: ValidatorId,
    /// Our BLS private key for signing
    private_key: BlsPrivateKey,

    /// Current consensus state
    state: RwLock<ConsensusState>,

    /// Formal state machine for transition validation
    state_machine: RwLock<ConsensusStateMachine>,

    /// Vote tracking for current height
    height_votes: RwLock<HeightVoteSet>,

    /// Proposals by round (for current height)
    proposals: RwLock<HashMap<u64, Proposal>>,

    /// Current validator set
    validator_set: RwLock<ValidatorSet>,

    /// Parent block hash (for validation)
    parent_hash: RwLock<Hash>,

    /// Timeout scheduler
    timeout_scheduler: TimeoutScheduler,

    /// Block validator
    block_validator: Arc<V>,

    /// Block builder
    block_builder: Arc<B>,

    /// Channel to send consensus messages to network
    network_tx: mpsc::Sender<ConsensusMessage>,

    /// Channel to send committed blocks
    commit_tx: mpsc::Sender<CommittedBlock>,

    /// Write-Ahead Log for consensus state persistence (optional)
    wal: Option<Arc<ConsensusWal>>,
}

impl<V: BlockValidator, B: BlockBuilder> ConsensusEngine<V, B> {
    /// Create a new consensus engine
    pub fn new(
        validator_id: ValidatorId,
        private_key: BlsPrivateKey,
        validator_set: ValidatorSet,
        timeout_config: TimeoutConfig,
        block_validator: Arc<V>,
        block_builder: Arc<B>,
        network_tx: mpsc::Sender<ConsensusMessage>,
        commit_tx: mpsc::Sender<CommittedBlock>,
        timeout_tx: mpsc::Sender<TimeoutInfo>,
    ) -> Self {
        let state = ConsensusState::new();
        let height_votes = HeightVoteSet::new(state.height);

        Self {
            validator_id,
            private_key,
            state: RwLock::new(state),
            state_machine: RwLock::new(ConsensusStateMachine::new()),
            height_votes: RwLock::new(height_votes),
            proposals: RwLock::new(HashMap::new()),
            validator_set: RwLock::new(validator_set),
            parent_hash: RwLock::new([0u8; 32]),
            timeout_scheduler: TimeoutScheduler::new(timeout_config, timeout_tx),
            block_validator,
            block_builder,
            network_tx,
            commit_tx,
            wal: None,
        }
    }

    /// Create a new consensus engine with WAL enabled
    ///
    /// The WAL provides crash recovery and anti-equivocation guarantees.
    /// All signing operations will be persisted to the WAL before execution.
    pub fn with_wal(
        validator_id: ValidatorId,
        private_key: BlsPrivateKey,
        validator_set: ValidatorSet,
        timeout_config: TimeoutConfig,
        block_validator: Arc<V>,
        block_builder: Arc<B>,
        network_tx: mpsc::Sender<ConsensusMessage>,
        commit_tx: mpsc::Sender<CommittedBlock>,
        timeout_tx: mpsc::Sender<TimeoutInfo>,
        wal_config: WalConfig,
    ) -> Result<Self, WalError> {
        let wal = ConsensusWal::open(wal_config)?;
        let recovered = wal.recovered_state();

        // Initialize state from WAL if available
        let mut state = ConsensusState::new();
        if recovered.last_height > 0 {
            state.height = recovered.last_height;
            // Restore locked state if any
            if let (Some(_locked_hash), Some(locked_round)) =
                (recovered.locked_value, recovered.locked_round)
            {
                state.locked_round = locked_round as i64;
                // Note: We don't restore locked_value (Block) here because we only
                // stored the hash. The actual block will need to be re-fetched from
                // storage if needed. For safety, we keep the locked_round to prevent
                // voting against the locked value.
            }
            info!(
                height = recovered.last_height,
                committed = recovered.committed_height,
                "Recovered consensus state from WAL"
            );
        }

        let height_votes = HeightVoteSet::new(state.height);

        Ok(Self {
            validator_id,
            private_key,
            state: RwLock::new(state),
            state_machine: RwLock::new(ConsensusStateMachine::new()),
            height_votes: RwLock::new(height_votes),
            proposals: RwLock::new(HashMap::new()),
            validator_set: RwLock::new(validator_set),
            parent_hash: RwLock::new([0u8; 32]),
            timeout_scheduler: TimeoutScheduler::new(timeout_config, timeout_tx),
            block_validator,
            block_builder,
            network_tx,
            commit_tx,
            wal: Some(Arc::new(wal)),
        })
    }

    /// Set the WAL after construction
    pub fn set_wal(&mut self, wal: Arc<ConsensusWal>) {
        self.wal = Some(wal);
    }

    /// Get a reference to the WAL (if enabled)
    pub fn wal(&self) -> Option<&Arc<ConsensusWal>> {
        self.wal.as_ref()
    }

    /// Start consensus at a specific height
    pub async fn start(&self, height: u64, parent_hash: Hash) {
        info!(height = height, "Starting consensus");

        // Write height start to WAL BEFORE any other operations
        if let Some(wal) = &self.wal {
            if let Err(e) = wal.write_height_start(height, parent_hash) {
                error!(height = height, error = %e, "Failed to write height start to WAL");
                return;
            }
        }

        // Initialize the formal state machine
        {
            let mut sm = self.state_machine.write();
            sm.initialize(height);
            // Apply NewHeight event
            if let Err(e) = sm.apply_event(ConsensusEvent::NewHeight { height }) {
                error!(height = height, error = %e, "Failed to apply NewHeight event");
                return;
            }
        }

        {
            let mut state = self.state.write();
            state.reset_for_height(height);
        }
        {
            let mut votes = self.height_votes.write();
            *votes = HeightVoteSet::new(height);
        }
        {
            let mut hash = self.parent_hash.write();
            *hash = parent_hash;
        }
        self.proposals.write().clear();

        self.enter_round(height, 0).await;
    }

    /// Enter a new round (boxed to allow recursive calls from on_proposal/on_vote)
    pub fn enter_round(
        &self,
        height: u64,
        round: u64,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            info!(height = height, round = round, "Entering round");

            // Validate transition using the formal state machine
            {
                let mut sm = self.state_machine.write();
                if let Err(e) = sm.apply_event(ConsensusEvent::StartRound { height, round }) {
                    error!(
                        height = height,
                        round = round,
                        error = %e,
                        "Invalid state transition to round"
                    );
                    return;
                }
            }

            // Update state
            {
                let mut state = self.state.write();
                state.height = height;
                state.round = round;
                state.step = Step::Propose;
            }

            // Update timeout scheduler
            self.timeout_scheduler.set_height_round(height, round);

            // Check if we are the proposer
            let is_proposer = {
                let vs = self.validator_set.read();
                vs.proposer_id(height, round) == self.validator_id
            };

            if is_proposer {
                self.do_propose().await;
            } else {
                // Schedule propose timeout
                self.timeout_scheduler
                    .schedule(Step::Propose, height, round);
            }
        })
    }

    /// Create and broadcast a proposal (when we are the proposer)
    async fn do_propose(&self) {
        let (height, round, valid_value, valid_round, parent_hash, proposer_address) = {
            let state = self.state.read();
            let parent = *self.parent_hash.read();
            // Get our address from the validator set
            let vs = self.validator_set.read();
            let our_address = vs
                .get_validator(self.validator_id)
                .map(|v| Address::from(v.address))
                .unwrap_or(Address::ZERO);
            (
                state.height,
                state.round,
                state.valid_value.clone(),
                state.valid_round,
                parent,
                our_address,
            )
        };

        // Build or re-propose block
        let block = if let Some(valid) = valid_value {
            debug!(height = height, round = round, "Re-proposing valid value");
            valid
        } else {
            debug!(height = height, round = round, "Building new block");
            self.block_builder
                .build_block(height, parent_hash, proposer_address)
                .await
        };

        let block_hash = block.hash();
        let block_hash_arr: [u8; 32] = block_hash.into();

        // Write proposal to WAL BEFORE signing (anti-equivocation)
        if let Some(wal) = &self.wal {
            // Check if we've already signed a different proposal for this round
            if let Some(existing_hash) = wal.get_signed_proposal(height, round) {
                if existing_hash != block_hash_arr {
                    error!(
                        height = height,
                        round = round,
                        existing = hex::encode(&existing_hash[..8]),
                        attempted = hex::encode(&block_hash_arr[..8]),
                        "CRITICAL: Attempted to sign different proposal - equivocation prevented"
                    );
                    return;
                }
                // Same hash, we can proceed (idempotent)
            }

            if let Err(e) = wal.write_proposal_signed(height, round, block_hash_arr, valid_round) {
                error!(
                    height = height,
                    round = round,
                    error = %e,
                    "Failed to write proposal to WAL - refusing to sign"
                );
                return;
            }
        }

        // Create and sign proposal
        let mut proposal = Proposal::new(height, round, block, valid_round);
        proposal.signature = self.private_key.sign(&proposal.signing_bytes());

        info!(
            height = height,
            round = round,
            block_hash = hex::encode(&block_hash.as_bytes()[..8]),
            "Proposing block"
        );

        // Broadcast proposal
        if let Err(e) = self
            .network_tx
            .send(ConsensusMessage::Proposal(proposal.clone()))
            .await
        {
            error!("Failed to broadcast proposal: {}", e);
        }

        // Process our own proposal
        self.on_proposal(proposal).await;
    }

    /// Handle an incoming proposal
    pub async fn on_proposal(&self, proposal: Proposal) {
        let (height, round, step) = {
            let state = self.state.read();
            (state.height, state.round, state.step)
        };

        // Check height
        if proposal.height != height {
            trace!(
                proposal_height = proposal.height,
                our_height = height,
                "Ignoring proposal for different height"
            );
            return;
        }

        // Verify proposer signature
        let expected_proposer_id = {
            let vs = self.validator_set.read();
            vs.proposer_id(proposal.height, proposal.round)
        };

        let proposer_pubkey = {
            let vs = self.validator_set.read();
            vs.get_validator(expected_proposer_id)
                .map(|v| v.pubkey.clone())
        };

        let Some(pubkey) = proposer_pubkey else {
            warn!(
                "Unknown proposer for height {} round {}",
                proposal.height, proposal.round
            );
            return;
        };

        if !proposal
            .signature
            .verify(&proposal.signing_bytes(), &pubkey)
        {
            warn!(
                height = proposal.height,
                round = proposal.round,
                "Invalid proposal signature"
            );
            return;
        }

        // Validate block
        let parent_hash = *self.parent_hash.read();
        if let Err(e) = self
            .block_validator
            .validate_block(&proposal.block, &parent_hash)
            .await
        {
            warn!(
                height = proposal.height,
                round = proposal.round,
                error = %e,
                "Invalid block in proposal - rejecting"
            );
            // IMPORTANT: Do NOT store invalid proposals. They could:
            // 1. Poison the proposal cache for future rounds
            // 2. Be used in POL checks incorrectly
            // 3. Cause undefined behavior in the state machine
            //
            // Instead, we simply prevote NIL and return without caching.
            if proposal.round == round && step == Step::Propose {
                self.prevote(NIL_HASH).await;
            }
            return;
        }

        // Store proposal
        self.proposals
            .write()
            .insert(proposal.round, proposal.clone());

        // Round catch-up: if valid proposal is for a higher round, advance to it
        if proposal.round > round {
            info!(
                height = height,
                current_round = round,
                proposal_round = proposal.round,
                "Catching up to higher round from valid proposal"
            );
            self.enter_round(height, proposal.round).await;
            // After entering the round, we're in Propose step, so process this proposal
            self.process_proposal(&proposal).await;
            return;
        }

        // If this is for our current round and we're in propose step, process it
        if proposal.round == round && step == Step::Propose {
            self.process_proposal(&proposal).await;
        }
    }

    /// Process a valid proposal and decide whether to prevote
    async fn process_proposal(&self, proposal: &Proposal) {
        let block_hash_arr: [u8; 32] = proposal.block.hash().into();

        let (locked_round, locked_value) = {
            let state = self.state.read();
            (state.locked_round, state.locked_value.clone())
        };

        // Decide whether to prevote for block or nil (Tendermint locking rules)
        let should_prevote = if locked_round == -1 {
            // Not locked, vote for valid proposal
            true
        } else if locked_value
            .as_ref()
            .map(|b| b.hash().as_bytes() == &block_hash_arr)
            .unwrap_or(false)
        {
            // Proposal matches our locked value
            true
        } else if proposal.valid_round >= locked_round {
            // Proposal has POL from a round >= our locked round
            // Need to verify POL exists
            let vs = self.validator_set.read();
            let votes = self.height_votes.read();
            votes
                .has_pol_from(&block_hash_arr, proposal.valid_round as u64, &vs)
                .is_some()
        } else {
            false
        };

        if should_prevote {
            self.prevote(block_hash_arr).await;
        } else {
            debug!(
                height = proposal.height,
                round = proposal.round,
                "Prevoting nil due to locking rules"
            );
            self.prevote(NIL_HASH).await;
        }
    }

    /// Broadcast a prevote
    async fn prevote(&self, block_hash: Hash) {
        let (height, round, step) = {
            let state = self.state.read();
            (state.height, state.round, state.step)
        };

        if step != Step::Propose {
            return;
        }

        // Check if we already voted in this round (equivocation prevention via state machine)
        {
            let sm = self.state_machine.read();
            if sm.has_voted(height, round, VotePhase::Prevote) {
                warn!(
                    height = height,
                    round = round,
                    "Already voted in this round, skipping prevote"
                );
                return;
            }
        }

        // Write vote to WAL BEFORE signing (anti-equivocation)
        if let Some(wal) = &self.wal {
            // Check if we've already signed a different vote for this position
            if let Some(existing_hash) = wal.get_signed_vote(height, round, VoteType::Prevote) {
                if existing_hash != block_hash {
                    error!(
                        height = height,
                        round = round,
                        existing = if existing_hash == NIL_HASH {
                            "NIL".to_string()
                        } else {
                            hex::encode(&existing_hash[..8])
                        },
                        attempted = if block_hash == NIL_HASH {
                            "NIL".to_string()
                        } else {
                            hex::encode(&block_hash[..8])
                        },
                        "CRITICAL: Attempted to sign different prevote - equivocation prevented"
                    );
                    return;
                }
                // Same hash, we can proceed (idempotent) but check state machine too
            }

            if let Err(e) = wal.write_vote_signed(height, round, VoteType::Prevote, block_hash) {
                error!(
                    height = height,
                    round = round,
                    error = %e,
                    "Failed to write prevote to WAL - refusing to sign"
                );
                return;
            }
        }

        // Record vote in state machine
        {
            let mut sm = self.state_machine.write();
            sm.record_vote(height, round, VotePhase::Prevote);
        }

        // Update step
        {
            let mut state = self.state.write();
            state.step = Step::Prevote;
        }

        // Cancel propose timeout
        self.timeout_scheduler.cancel(Step::Propose, height, round);

        // Create and sign vote
        let mut vote = Vote::new(
            VoteType::Prevote,
            height,
            round,
            block_hash,
            self.validator_id,
        );
        vote.signature = self.private_key.sign(&vote.signing_bytes());

        debug!(
            height = height,
            round = round,
            block_hash = if block_hash == NIL_HASH {
                "NIL".to_string()
            } else {
                hex::encode(&block_hash[..8])
            },
            "Sending prevote"
        );

        // Broadcast
        if let Err(e) = self
            .network_tx
            .send(ConsensusMessage::Vote(vote.clone()))
            .await
        {
            error!("Failed to broadcast prevote: {}", e);
        }

        // Process our own vote
        self.on_vote(vote).await;

        // Schedule prevote timeout
        self.timeout_scheduler
            .schedule(Step::Prevote, height, round);
    }

    /// Handle an incoming vote
    pub fn on_vote(
        &self,
        vote: Vote,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let (height, round) = {
                let state = self.state.read();
                (state.height, state.round)
            };

            if vote.height != height {
                trace!(
                    vote_height = vote.height,
                    our_height = height,
                    "Ignoring vote for different height"
                );
                return;
            }

            // Add vote to appropriate set
            let vs = self.validator_set.read().clone();
            let quorum_hash = match vote.vote_type {
                VoteType::Prevote => {
                    let mut votes = self.height_votes.write();
                    match votes.prevotes(vote.round).add_vote(vote.clone(), &vs) {
                        Ok(hash) => hash,
                        Err(e) => {
                            trace!(error = %e, "Failed to add prevote");
                            None
                        }
                    }
                }
                VoteType::Precommit => {
                    let mut votes = self.height_votes.write();
                    match votes.precommits(vote.round).add_vote(vote.clone(), &vs) {
                        Ok(hash) => hash,
                        Err(e) => {
                            trace!(error = %e, "Failed to add precommit");
                            None
                        }
                    }
                }
            };

            // Handle quorum if reached
            if let Some(hash) = quorum_hash {
                match vote.vote_type {
                    VoteType::Prevote => {
                        // Round catch-up: if quorum is for a higher round, advance to it
                        if vote.round > round {
                            info!(
                                height = height,
                                current_round = round,
                                quorum_round = vote.round,
                                "Catching up to higher round from prevote quorum"
                            );
                            self.enter_round(height, vote.round).await;
                            self.on_prevote_quorum(hash).await;
                        } else if vote.round == round {
                            self.on_prevote_quorum(hash).await;
                        }
                    }
                    VoteType::Precommit => {
                        // Round catch-up for precommit quorum as well
                        if vote.round > round {
                            info!(
                                height = height,
                                current_round = round,
                                quorum_round = vote.round,
                                "Catching up to higher round from precommit quorum"
                            );
                            self.enter_round(height, vote.round).await;
                        }
                        self.on_precommit_quorum(hash, vote.round).await;
                    }
                }
            }
        }) // End of Box::pin async block
    }

    /// Called when we have >2/3 prevotes for a value
    async fn on_prevote_quorum(&self, block_hash: Hash) {
        let (height, round, step) = {
            let state = self.state.read();
            (state.height, state.round, state.step)
        };

        if step != Step::Prevote {
            return;
        }

        // Cancel prevote timeout
        self.timeout_scheduler.cancel(Step::Prevote, height, round);

        if block_hash != NIL_HASH {
            // Lock on this value
            let proposal = self.proposals.read().get(&round).cloned();

            if let Some(p) = proposal {
                let p_hash: [u8; 32] = p.block.hash().into();
                if p_hash == block_hash {
                    // Write lock to WAL BEFORE updating state
                    if let Some(wal) = &self.wal {
                        if let Err(e) = wal.write_locked(height, round, block_hash) {
                            error!(
                                height = height,
                                round = round,
                                error = %e,
                                "Failed to write lock to WAL"
                            );
                            // Continue anyway - locking is for safety, but we can still precommit
                        }
                    }

                    let mut state = self.state.write();
                    state.locked_value = Some(p.block.clone());
                    state.locked_round = round as i64;
                    state.valid_value = Some(p.block.clone());
                    state.valid_round = round as i64;

                    info!(
                        height = height,
                        round = round,
                        block_hash = hex::encode(&block_hash[..8]),
                        "Locked on block"
                    );
                }
            }

            self.precommit(block_hash).await;
        } else {
            // Quorum for nil
            self.precommit(NIL_HASH).await;
        }
    }

    /// Broadcast a precommit
    async fn precommit(&self, block_hash: Hash) {
        let (height, round, step) = {
            let state = self.state.read();
            (state.height, state.round, state.step)
        };

        if step != Step::Prevote {
            return;
        }

        // Check if we already precommitted in this round (equivocation prevention via state machine)
        {
            let sm = self.state_machine.read();
            if sm.has_voted(height, round, VotePhase::Precommit) {
                warn!(
                    height = height,
                    round = round,
                    "Already precommitted in this round, skipping"
                );
                return;
            }
        }

        // Write vote to WAL BEFORE signing (anti-equivocation)
        if let Some(wal) = &self.wal {
            // Check if we've already signed a different precommit for this position
            if let Some(existing_hash) = wal.get_signed_vote(height, round, VoteType::Precommit) {
                if existing_hash != block_hash {
                    error!(
                        height = height,
                        round = round,
                        existing = if existing_hash == NIL_HASH {
                            "NIL".to_string()
                        } else {
                            hex::encode(&existing_hash[..8])
                        },
                        attempted = if block_hash == NIL_HASH {
                            "NIL".to_string()
                        } else {
                            hex::encode(&block_hash[..8])
                        },
                        "CRITICAL: Attempted to sign different precommit - equivocation prevented"
                    );
                    return;
                }
                // Same hash, we can proceed (idempotent)
            }

            if let Err(e) = wal.write_vote_signed(height, round, VoteType::Precommit, block_hash) {
                error!(
                    height = height,
                    round = round,
                    error = %e,
                    "Failed to write precommit to WAL - refusing to sign"
                );
                return;
            }
        }

        // Record this precommit vote in state machine
        {
            let mut sm = self.state_machine.write();
            sm.record_vote(height, round, VotePhase::Precommit);
        }

        // Update step
        {
            let mut state = self.state.write();
            state.step = Step::Precommit;
        }

        // Create and sign vote
        let mut vote = Vote::new(
            VoteType::Precommit,
            height,
            round,
            block_hash,
            self.validator_id,
        );
        vote.signature = self.private_key.sign(&vote.signing_bytes());

        debug!(
            height = height,
            round = round,
            block_hash = if block_hash == NIL_HASH {
                "NIL".to_string()
            } else {
                hex::encode(&block_hash[..8])
            },
            "Sending precommit"
        );

        // Broadcast
        if let Err(e) = self
            .network_tx
            .send(ConsensusMessage::Vote(vote.clone()))
            .await
        {
            error!("Failed to broadcast precommit: {}", e);
        }

        // Process our own vote
        self.on_vote(vote).await;

        // Schedule precommit timeout
        self.timeout_scheduler
            .schedule(Step::Precommit, height, round);
    }

    /// Called when we have >2/3 precommits for a value
    async fn on_precommit_quorum(&self, block_hash: Hash, vote_round: u64) {
        if block_hash == NIL_HASH {
            // Quorum for nil, don't commit (will timeout to next round)
            return;
        }

        // Get the proposal for this round
        let proposal = self.proposals.read().get(&vote_round).cloned();

        if let Some(p) = proposal {
            let p_hash: [u8; 32] = p.block.hash().into();
            if p_hash == block_hash {
                self.commit(p.block, vote_round).await;
            }
        }
    }

    /// Commit a finalized block
    async fn commit(&self, block: Block, round: u64) {
        let block_hash: [u8; 32] = block.hash().into();

        let height = {
            let mut state = self.state.write();
            state.step = Step::Commit;
            state.height
        };

        // Write commit to WAL
        if let Some(wal) = &self.wal {
            if let Err(e) = wal.write_committed(height, block_hash) {
                error!(
                    height = height,
                    error = %e,
                    "Failed to write commit to WAL"
                );
                // Continue anyway - commit has already happened
            }

            // Prune old WAL entries if configured
            let max_retained = wal.config().max_heights_retained;
            if max_retained > 0 && height > max_retained {
                let prune_below = height.saturating_sub(max_retained);
                if let Err(e) = wal.prune(prune_below) {
                    warn!(
                        height = height,
                        prune_below = prune_below,
                        error = %e,
                        "Failed to prune WAL"
                    );
                }
            }
        }

        // Record commit in state machine for safety tracking (prevents conflicting commits)
        {
            let mut sm = self.state_machine.write();
            if let Err(e) = sm.apply_event(ConsensusEvent::BlockCommitted { height, block_hash }) {
                error!(
                    height = height,
                    error = %e,
                    "CRITICAL: Failed to record commit in state machine - potential safety violation"
                );
                // Continue anyway since the block was already committed by consensus
            }
        }

        // Cancel all timeouts
        self.timeout_scheduler.cancel_all();

        // Create finality certificate
        let finality_cert = self.create_finality_cert(&block, round);

        info!(
            height = height,
            round = round,
            block_hash = hex::encode(&block_hash[..8]),
            signers = finality_cert.signer_count(),
            "COMMITTED block"
        );

        // Send committed block to validator for persistence
        // IMPORTANT: We do NOT start the next height here. The validator must call
        // start() after persisting the block to ensure the parent is in the database
        // before the next proposer tries to build a block.
        let committed = CommittedBlock::new(block.clone(), finality_cert);
        if let Err(e) = self.commit_tx.send(committed).await {
            error!("Failed to send committed block: {}", e);
        }
    }

    /// Create a finality certificate from precommit votes
    fn create_finality_cert(&self, block: &Block, round: u64) -> FinalityCert {
        let block_hash: [u8; 32] = block.hash().into();

        let (precommits, vs) = {
            let votes = self.height_votes.read();
            let vs = self.validator_set.read().clone();
            (
                votes.get_precommits(round).cloned().unwrap_or_else(|| {
                    VoteSet::new(block.header.height, round, VoteType::Precommit)
                }),
                vs,
            )
        };

        // Get all precommits for this block
        let voters = precommits.get_voters_for(&block_hash);
        let signatures: Vec<BlsSignature> = voters
            .iter()
            .filter_map(|id| precommits.get_vote(*id))
            .map(|v| v.signature.clone())
            .collect();

        // Create signers bitmap
        let bitmap = precommits.create_signers_bitmap(&block_hash, &vs);

        // Aggregate signatures
        let sig_refs: Vec<&BlsSignature> = signatures.iter().collect();
        let aggregate_signature =
            BlsSignature::aggregate(&sig_refs).unwrap_or_else(|_| BlsSignature::default());

        FinalityCert::new(block.header.height, block_hash, aggregate_signature, bitmap)
    }

    /// Handle a timeout event
    pub async fn on_timeout(&self, timeout: TimeoutInfo) {
        let (height, round, step) = {
            let state = self.state.read();
            (state.height, state.round, state.step)
        };

        // Check if timeout is still relevant
        if timeout.height != height || timeout.round != round {
            return;
        }

        match timeout.step {
            Step::NewHeight => {
                // NewHeight timeout should not occur in normal operation
                warn!(height = height, "Unexpected NewHeight timeout");
            }
            Step::Propose => {
                if step == Step::Propose {
                    debug!(
                        height = height,
                        round = round,
                        "Propose timeout, prevoting nil"
                    );
                    self.prevote(NIL_HASH).await;
                }
            }
            Step::Prevote => {
                if step == Step::Prevote {
                    debug!(
                        height = height,
                        round = round,
                        "Prevote timeout, precommitting nil"
                    );
                    self.precommit(NIL_HASH).await;
                }
            }
            Step::Precommit => {
                if step == Step::Precommit {
                    debug!(
                        height = height,
                        round = round,
                        "Precommit timeout, moving to next round"
                    );
                    self.next_round().await;
                }
            }
            Step::Commit => {}
        }
    }

    /// Move to the next round
    async fn next_round(&self) {
        let (height, round) = {
            let mut state = self.state.write();
            state.next_round();
            (state.height, state.round)
        };

        self.enter_round(height, round).await;
    }

    /// Get the current consensus state
    pub fn state(&self) -> ConsensusState {
        self.state.read().clone()
    }

    /// Update the validator set (for epoch transitions)
    ///
    /// **Important**: This should only be called at epoch boundaries. The caller
    /// is responsible for:
    /// 1. Computing the new validator set from staking state
    /// 2. Ensuring the transition happens at the correct block height
    /// 3. Ensuring all nodes transition at the same block
    ///
    /// See the `epoch` module for epoch management utilities.
    pub fn set_validator_set(&self, validator_set: ValidatorSet) {
        let old_count = self.validator_set.read().len();
        let new_count = validator_set.len();
        let new_hash = validator_set.compute_hash();

        info!(
            old_validator_count = old_count,
            new_validator_count = new_count,
            new_validator_set_hash = hex::encode(&new_hash[..8]),
            "Updating validator set for epoch transition"
        );

        *self.validator_set.write() = validator_set;
    }

    /// Update the validator set with epoch transition tracking
    ///
    /// This is the preferred method for epoch transitions as it validates
    /// that our validator ID is still valid in the new set.
    ///
    /// Returns an error if this validator is not in the new set.
    pub fn transition_validator_set(
        &self,
        new_validator_set: ValidatorSet,
        new_epoch: u64,
    ) -> Result<(), ConsensusError> {
        // Check if we're still a validator in the current set
        let our_address = {
            let current_set = self.validator_set.read();
            current_set
                .get_validator(self.validator_id)
                .map(|v| v.address)
        };

        let our_address = our_address.ok_or({
            ConsensusError::InvalidVote(crate::vote_set::VoteSetError::InvalidValidator(
                self.validator_id,
            ))
        })?;

        // Find our new validator ID in the new set (it may have changed)
        let new_id = new_validator_set.get_by_address(&our_address).map(|v| v.id);

        let new_hash = new_validator_set.compute_hash();

        info!(
            new_epoch = new_epoch,
            old_validator_id = self.validator_id,
            new_validator_id = ?new_id,
            validator_count = new_validator_set.len(),
            validator_set_hash = hex::encode(&new_hash[..8]),
            "Transitioning to new epoch validator set"
        );

        // Log if we're no longer a validator
        if new_id.is_none() {
            warn!(
                our_address = hex::encode(our_address),
                new_epoch = new_epoch,
                "This node is no longer a validator in the new epoch"
            );
        }

        *self.validator_set.write() = new_validator_set;

        Ok(())
    }

    /// Checks if this node is an active validator in the current set
    pub fn is_active_validator(&self) -> bool {
        let vs = self.validator_set.read();
        vs.get_validator(self.validator_id)
            .map(|v| v.active)
            .unwrap_or(false)
    }

    /// Checks if a given validator ID is in the current set
    pub fn is_validator_in_current_set(&self, id: ValidatorId) -> bool {
        self.validator_set.read().get_validator(id).is_some()
    }

    /// Gets the current validator set hash
    pub fn current_validator_set_hash(&self) -> protocore_crypto::Hash {
        self.validator_set.read().compute_hash()
    }

    /// Gets the current validator set (cloned)
    pub fn current_validator_set(&self) -> ValidatorSet {
        self.validator_set.read().clone()
    }

    /// Get our validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }

    /// Get a snapshot of the formal state machine for debugging/monitoring
    pub fn state_machine_snapshot(&self) -> crate::state_machine::StateMachineSnapshot {
        self.state_machine.read().snapshot()
    }

    /// Verify that all safety invariants hold
    ///
    /// Returns Ok(()) if all safety properties are satisfied, or an error describing
    /// the first violation found.
    pub fn verify_safety(&self) -> Result<(), StateMachineError> {
        self.state_machine.read().verify_safety_invariants()
    }

    /// Check if a block has already been committed at a given height
    ///
    /// This is used to detect potential conflicting commits (safety violation).
    pub fn get_committed_block_hash(&self, height: u64) -> Option<Hash> {
        self.state_machine
            .read()
            .commit_history()
            .get_commit(height)
            .copied()
    }

    /// Get the highest committed height
    pub fn highest_committed_height(&self) -> u64 {
        self.state_machine.read().commit_history().highest_height()
    }
}
