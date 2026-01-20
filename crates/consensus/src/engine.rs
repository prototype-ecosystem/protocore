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
use protocore_crypto::{bls::{BlsPrivateKey, BlsSignature}, Hash};
use protocore_types::Block;
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{debug, error, info, trace, warn};

use crate::timeout::{TimeoutConfig, TimeoutInfo, TimeoutScheduler};
use crate::types::{
    CommittedBlock, ConsensusMessage, FinalityCert, Proposal, Step, ValidatorId, ValidatorSet,
    Vote, VoteType, NIL_HASH,
};
use crate::vote_set::{HeightVoteSet, VoteSet, VoteSetError};

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
    /// Build a new block for the given height
    async fn build_block(&self, height: u64, parent_hash: Hash) -> Block;
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
            step: Step::Propose,
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
        self.step = Step::Propose;
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
            height_votes: RwLock::new(height_votes),
            proposals: RwLock::new(HashMap::new()),
            validator_set: RwLock::new(validator_set),
            parent_hash: RwLock::new([0u8; 32]),
            timeout_scheduler: TimeoutScheduler::new(timeout_config, timeout_tx),
            block_validator,
            block_builder,
            network_tx,
            commit_tx,
        }
    }

    /// Start consensus at a specific height
    pub async fn start(&self, height: u64, parent_hash: Hash) {
        info!(height = height, "Starting consensus");

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
    pub fn enter_round(&self, height: u64, round: u64) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            info!(height = height, round = round, "Entering round");

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
                self.timeout_scheduler.schedule(Step::Propose, height, round);
            }
        })
    }

    /// Create and broadcast a proposal (when we are the proposer)
    async fn do_propose(&self) {
        let (height, round, valid_value, valid_round, parent_hash) = {
            let state = self.state.read();
            let parent = *self.parent_hash.read();
            (
                state.height,
                state.round,
                state.valid_value.clone(),
                state.valid_round,
                parent,
            )
        };

        // Build or re-propose block
        let block = if let Some(valid) = valid_value {
            debug!(height = height, round = round, "Re-proposing valid value");
            valid
        } else {
            debug!(height = height, round = round, "Building new block");
            self.block_builder.build_block(height, parent_hash).await
        };

        let block_hash = block.hash();

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
            warn!("Unknown proposer for height {} round {}", proposal.height, proposal.round);
            return;
        };

        if !proposal.signature.verify(&proposal.signing_bytes(), &pubkey) {
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
        self.proposals.write().insert(proposal.round, proposal.clone());

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
        } else if locked_value.as_ref().map(|b| b.hash().as_bytes() == &block_hash_arr).unwrap_or(false)
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

        // Update step
        {
            let mut state = self.state.write();
            state.step = Step::Prevote;
        }

        // Cancel propose timeout
        self.timeout_scheduler.cancel(Step::Propose, height, round);

        // Create and sign vote
        let mut vote = Vote::new(VoteType::Prevote, height, round, block_hash, self.validator_id);
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
        self.timeout_scheduler.schedule(Step::Prevote, height, round);
    }

    /// Handle an incoming vote
    pub fn on_vote(&self, vote: Vote) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + '_>> {
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
        let height = {
            let mut state = self.state.write();
            state.step = Step::Commit;
            state.height
        };

        // Cancel all timeouts
        self.timeout_scheduler.cancel_all();

        // Create finality certificate
        let finality_cert = self.create_finality_cert(&block, round);

        info!(
            height = height,
            round = round,
            block_hash = hex::encode(&block.hash().as_bytes()[..8]),
            signers = finality_cert.signer_count(),
            "COMMITTED block"
        );

        // Send committed block
        let committed = CommittedBlock::new(block.clone(), finality_cert);
        if let Err(e) = self.commit_tx.send(committed).await {
            error!("Failed to send committed block: {}", e);
        }

        // Update parent hash for next height
        {
            let mut parent = self.parent_hash.write();
            *parent = block.hash().into();
        }

        // Start next height
        self.start(height + 1, block.hash().into()).await;
    }

    /// Create a finality certificate from precommit votes
    fn create_finality_cert(&self, block: &Block, round: u64) -> FinalityCert {
        let block_hash: [u8; 32] = block.hash().into();

        let (precommits, vs) = {
            let votes = self.height_votes.read();
            let vs = self.validator_set.read().clone();
            (
                votes
                    .get_precommits(round)
                    .map(|s| s.clone())
                    .unwrap_or_else(|| VoteSet::new(block.header.height, round, VoteType::Precommit)),
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
        let aggregate_signature = BlsSignature::aggregate(&sig_refs)
            .unwrap_or_else(|_| BlsSignature::default());

        FinalityCert::new(
            block.header.height,
            block_hash,
            aggregate_signature,
            bitmap,
        )
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
    pub fn set_validator_set(&self, validator_set: ValidatorSet) {
        *self.validator_set.write() = validator_set;
    }

    /// Get our validator ID
    pub fn validator_id(&self) -> ValidatorId {
        self.validator_id
    }
}

