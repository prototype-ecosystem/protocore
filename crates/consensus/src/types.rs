//! Consensus-specific types for MinBFT protocol.
//!
//! This module defines the core data structures used in the consensus protocol:
//! - [`ValidatorId`] - Unique identifier for validators
//! - [`Step`] - Consensus step within a round
//! - [`VoteType`] - Type of vote (Prevote or Precommit)
//! - [`Proposal`] - Block proposal message
//! - [`Vote`] - Vote message for prevotes and precommits
//! - [`FinalityCert`] - Proof of block finality
//! - [`Validator`] and [`ValidatorSet`] - Validator management

use protocore_crypto::{bls::{BlsPublicKey, BlsSignature}, Hash};
use protocore_types::{Block, H256};
use serde::{Deserialize, Serialize};

/// Unique identifier for a validator (index in validator set)
pub type ValidatorId = u64;

/// NIL hash constant - represents "no block" in votes
pub const NIL_HASH: Hash = [0u8; 32];

/// Domain separators for signature security
///
/// These prefixes prevent signature replay attacks across different contexts.
/// A signature for a proposal cannot be reused as a vote signature, etc.
pub mod domains {
    /// Domain separator for block proposals
    pub const PROPOSAL: &[u8] = b"PROTOCORE_PROPOSAL_V1";
    /// Domain separator for prevote messages
    pub const PREVOTE: &[u8] = b"PROTOCORE_PREVOTE_V1";
    /// Domain separator for precommit messages
    pub const PRECOMMIT: &[u8] = b"PROTOCORE_PRECOMMIT_V1";
    /// Domain separator for finality certificates
    pub const FINALITY_CERT: &[u8] = b"PROTOCORE_FINALITY_V1";
}

/// Consensus step within a round
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Step {
    /// Proposer creates and broadcasts a block proposal
    Propose,
    /// Validators vote on whether the proposal is valid
    Prevote,
    /// Validators commit to the block if they saw enough prevotes
    Precommit,
    /// Block is being committed
    Commit,
}

impl std::fmt::Display for Step {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Step::Propose => write!(f, "Propose"),
            Step::Prevote => write!(f, "Prevote"),
            Step::Precommit => write!(f, "Precommit"),
            Step::Commit => write!(f, "Commit"),
        }
    }
}

/// Vote type for consensus messages
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub enum VoteType {
    /// First round of voting - indicates validator received valid proposal
    #[default]
    Prevote,
    /// Second round of voting - indicates validator saw quorum of prevotes
    Precommit,
}

impl std::fmt::Display for VoteType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VoteType::Prevote => write!(f, "Prevote"),
            VoteType::Precommit => write!(f, "Precommit"),
        }
    }
}

/// Block proposal message from the designated proposer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    /// Block height
    pub height: u64,
    /// Round number within the height
    pub round: u64,
    /// The proposed block
    pub block: Block,
    /// Round in which proposer has valid value locked (-1 if none)
    /// This enables Proof of Lock (POL) for consensus safety
    pub valid_round: i64,
    /// Proposer's BLS signature over the proposal
    pub signature: BlsSignature,
}

impl Proposal {
    /// Create a new unsigned proposal
    pub fn new(height: u64, round: u64, block: Block, valid_round: i64) -> Self {
        Self {
            height,
            round,
            block,
            valid_round,
            signature: BlsSignature::default(),
        }
    }

    /// Get the signing bytes for this proposal
    ///
    /// Includes domain separator to prevent cross-context signature replay.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(domains::PROPOSAL.len() + 48);
        // Domain separator prefix
        bytes.extend(domains::PROPOSAL);
        // Message content
        bytes.extend(&self.height.to_le_bytes());
        bytes.extend(&self.round.to_le_bytes());
        bytes.extend(self.block.hash().as_bytes());
        bytes.extend(&self.valid_round.to_le_bytes());
        bytes
    }

    /// Get the block hash
    pub fn block_hash(&self) -> H256 {
        self.block.hash()
    }
}

/// Vote message (prevote or precommit)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vote {
    /// Type of vote
    pub vote_type: VoteType,
    /// Block height
    pub height: u64,
    /// Round number
    pub round: u64,
    /// Hash of the block being voted for (NIL_HASH for nil vote)
    pub block_hash: Hash,
    /// Validator index in the validator set
    pub validator_id: ValidatorId,
    /// Validator's BLS signature
    pub signature: BlsSignature,
}

impl Vote {
    /// Create a new unsigned vote
    pub fn new(
        vote_type: VoteType,
        height: u64,
        round: u64,
        block_hash: Hash,
        validator_id: ValidatorId,
    ) -> Self {
        Self {
            vote_type,
            height,
            round,
            block_hash,
            validator_id,
            signature: BlsSignature::default(),
        }
    }

    /// Get the signing bytes for this vote
    ///
    /// Includes domain separator (PREVOTE or PRECOMMIT) to prevent cross-context
    /// signature replay. A prevote signature cannot be reused as a precommit.
    pub fn signing_bytes(&self) -> Vec<u8> {
        let domain = match self.vote_type {
            VoteType::Prevote => domains::PREVOTE,
            VoteType::Precommit => domains::PRECOMMIT,
        };
        let mut bytes = Vec::with_capacity(domain.len() + 49);
        // Domain separator prefix (includes vote type implicitly)
        bytes.extend(domain);
        // Message content
        bytes.extend(&self.height.to_le_bytes());
        bytes.extend(&self.round.to_le_bytes());
        bytes.extend(&self.block_hash);
        bytes
    }

    /// Check if this is a nil vote
    pub fn is_nil(&self) -> bool {
        self.block_hash == NIL_HASH
    }
}

/// Finality certificate - cryptographic proof that a block has been finalized
///
/// This is created when 2f+1 validators have precommitted to a block.
/// It contains an aggregated BLS signature for efficient verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityCert {
    /// Block height
    pub height: u64,
    /// Hash of the finalized block
    pub block_hash: Hash,
    /// Aggregated BLS signature from >2/3 validators
    pub aggregate_signature: BlsSignature,
    /// Bitmap indicating which validators signed (bit i = validator i signed)
    pub signers_bitmap: Vec<u8>,
}

impl FinalityCert {
    /// Create a new finality certificate
    pub fn new(
        height: u64,
        block_hash: Hash,
        aggregate_signature: BlsSignature,
        signers_bitmap: Vec<u8>,
    ) -> Self {
        Self {
            height,
            block_hash,
            aggregate_signature,
            signers_bitmap,
        }
    }

    /// Get the list of validator IDs that signed this certificate
    pub fn get_signers(&self) -> Vec<ValidatorId> {
        let mut signers = Vec::new();
        for (byte_idx, byte) in self.signers_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    signers.push((byte_idx * 8 + bit) as ValidatorId);
                }
            }
        }
        signers
    }

    /// Verify the finality certificate against a validator set
    pub fn verify(&self, validator_set: &ValidatorSet) -> bool {
        let signers = self.get_signers();

        // Calculate total stake of signers
        let total_stake: u128 = signers
            .iter()
            .filter_map(|id| validator_set.get_validator(*id))
            .map(|v| v.stake)
            .sum();

        // Require >2/3 stake for quorum
        if total_stake * 3 <= validator_set.total_stake * 2 {
            return false;
        }

        // Collect public keys for signature verification
        let pubkeys: Vec<&BlsPublicKey> = signers
            .iter()
            .filter_map(|id| validator_set.get_validator(*id))
            .map(|v| &v.pubkey)
            .collect();

        // Verify aggregated signature
        self.aggregate_signature
            .verify_aggregate(&self.block_hash, &pubkeys)
    }

    /// Get the number of signers
    pub fn signer_count(&self) -> u32 {
        self.signers_bitmap
            .iter()
            .map(|b| b.count_ones())
            .sum()
    }
}

/// Default implementation for FinalityCert (empty certificate)
impl Default for FinalityCert {
    fn default() -> Self {
        Self {
            height: 0,
            block_hash: NIL_HASH,
            aggregate_signature: BlsSignature::default(),
            signers_bitmap: Vec::new(),
        }
    }
}

/// Validator information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Validator index in the set
    pub id: ValidatorId,
    /// BLS public key for consensus signatures
    pub pubkey: BlsPublicKey,
    /// Ethereum-style address (derived from ECDSA public key)
    pub address: [u8; 20],
    /// Staked amount in the native token
    pub stake: u128,
    /// Commission rate in basis points (e.g., 1000 = 10%)
    pub commission: u16,
    /// Whether the validator is currently active
    pub active: bool,
}

impl Validator {
    /// Create a new validator
    pub fn new(
        id: ValidatorId,
        pubkey: BlsPublicKey,
        address: [u8; 20],
        stake: u128,
        commission: u16,
    ) -> Self {
        Self {
            id,
            pubkey,
            address,
            stake,
            commission,
            active: true,
        }
    }

    /// Get the validator's address as a hex string
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Set of active validators for a consensus epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Ordered list of validators (index = ValidatorId)
    pub validators: Vec<Validator>,
    /// Total stake across all validators
    pub total_stake: u128,
}

impl ValidatorSet {
    /// Create a new validator set from a list of validators
    pub fn new(mut validators: Vec<Validator>) -> Self {
        // Ensure validator IDs match their indices
        for (i, v) in validators.iter_mut().enumerate() {
            v.id = i as ValidatorId;
        }

        let total_stake: u128 = validators.iter().map(|v| v.stake).sum();

        Self {
            validators,
            total_stake,
        }
    }

    /// Get the proposer for a given height and round
    ///
    /// Uses round-robin selection: proposer = validators[(height + round) % n]
    pub fn proposer(&self, height: u64, round: u64) -> &Validator {
        let idx = ((height + round) as usize) % self.validators.len();
        &self.validators[idx]
    }

    /// Get the proposer ID for a given height and round
    pub fn proposer_id(&self, height: u64, round: u64) -> ValidatorId {
        ((height + round) % self.validators.len() as u64) as ValidatorId
    }

    /// Calculate the stake required for quorum (>2/3)
    ///
    /// For n = 3f + 1 validators, quorum requires 2f + 1 signatures
    pub fn quorum_stake(&self) -> u128 {
        // Need > 2/3, so we need (2 * total / 3) + 1
        (self.total_stake * 2 / 3) + 1
    }

    /// Get the number of validators
    pub fn len(&self) -> usize {
        self.validators.len()
    }

    /// Check if the validator set is empty
    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }

    /// Get a validator by ID
    pub fn get_validator(&self, id: ValidatorId) -> Option<&Validator> {
        self.validators.get(id as usize)
    }

    /// Get a validator by address
    pub fn get_by_address(&self, address: &[u8; 20]) -> Option<&Validator> {
        self.validators.iter().find(|v| &v.address == address)
    }

    /// Check if an address is a validator
    pub fn is_validator(&self, address: &[u8; 20]) -> bool {
        self.get_by_address(address).is_some()
    }

    /// Calculate the maximum number of Byzantine validators tolerated
    ///
    /// For n = 3f + 1, we tolerate f Byzantine validators
    pub fn max_byzantine(&self) -> usize {
        (self.validators.len() - 1) / 3
    }

    /// Get the minimum number of honest validators required
    ///
    /// For n = 3f + 1, we need at least 2f + 1 honest validators
    pub fn min_honest(&self) -> usize {
        self.validators.len() - self.max_byzantine()
    }
}

impl Default for ValidatorSet {
    fn default() -> Self {
        Self {
            validators: Vec::new(),
            total_stake: 0,
        }
    }
}

/// Consensus message types for network communication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// Block proposal from proposer
    Proposal(Proposal),
    /// Vote (prevote or precommit)
    Vote(Vote),
}

/// Committed block with its finality certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedBlock {
    /// The finalized block
    pub block: Block,
    /// Finality certificate proving consensus
    pub finality_cert: FinalityCert,
}

impl CommittedBlock {
    /// Create a new committed block
    pub fn new(block: Block, finality_cert: FinalityCert) -> Self {
        Self {
            block,
            finality_cert,
        }
    }
}
