//! Light Client Support for Validator Set Verification
//!
//! This module provides types and utilities for light clients to verify
//! validator set transitions without downloading full block data.
//!
//! # Overview
//!
//! Light clients need to track the validator set to verify finality certificates.
//! When the validator set changes at epoch boundaries, light clients must:
//!
//! 1. Verify the transition is authorized by the previous validator set
//! 2. Update their trusted validator set
//! 3. Use the new set to verify subsequent blocks
//!
//! # Trust Period
//!
//! Light clients have a trust period during which they trust a given validator set.
//! If a light client is offline longer than the trust period, they must perform
//! bisection to catch up on validator set changes.
//!
//! # Example
//!
//! ```rust,ignore
//! use protocore_consensus::light_client::{LightClientState, ValidatorSetProof};
//!
//! // Initialize light client with genesis validator set
//! let mut light_client = LightClientState::new(genesis_header, genesis_validators);
//!
//! // Verify a new block header
//! if light_client.verify_header(&new_header, &finality_cert).is_ok() {
//!     // Header is valid, update state
//!     light_client.update(new_header, finality_cert);
//! }
//! ```

use protocore_crypto::Hash;
use protocore_types::{BlockHeader, H256};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, warn};

use crate::epoch::{compute_validator_set_hash, EpochConfig, EpochNumber};
use crate::types::{FinalityCert, ValidatorSet};

/// Default trust period in seconds (3 weeks)
pub const DEFAULT_TRUST_PERIOD_SECS: u64 = 3 * 7 * 24 * 60 * 60;

/// Maximum header height difference for sequential verification
pub const MAX_SEQUENTIAL_VERIFY_HEIGHT: u64 = 1000;

/// Errors that can occur during light client verification
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum LightClientError {
    /// Trust period has expired
    #[error(
        "trust period expired: last trusted at {last_trusted_time}, current time {current_time}"
    )]
    TrustPeriodExpired {
        /// Last trusted timestamp
        last_trusted_time: u64,
        /// Current timestamp
        current_time: u64,
    },

    /// Validator set hash mismatch
    #[error("validator set hash mismatch: expected {expected}, got {actual}")]
    ValidatorSetMismatch {
        /// Expected hash
        expected: String,
        /// Actual hash
        actual: String,
    },

    /// Insufficient signatures for quorum
    #[error("insufficient signatures: got {got} stake, need {required} stake")]
    InsufficientSignatures {
        /// Stake received
        got: u128,
        /// Stake required
        required: u128,
    },

    /// Invalid finality certificate
    #[error("invalid finality certificate: {reason}")]
    InvalidFinalityCert {
        /// Reason for invalidity
        reason: String,
    },

    /// Header verification failed
    #[error("header verification failed: {reason}")]
    HeaderVerificationFailed {
        /// Reason for failure
        reason: String,
    },

    /// Height jump too large
    #[error("height jump too large: from {from} to {to}, need bisection")]
    HeightJumpTooLarge {
        /// Starting height
        from: u64,
        /// Target height
        to: u64,
    },

    /// Missing validator set for epoch
    #[error("missing validator set for epoch {epoch}")]
    MissingValidatorSet {
        /// The epoch
        epoch: EpochNumber,
    },

    /// Invalid validator set proof
    #[error("invalid validator set proof: {reason}")]
    InvalidProof {
        /// Reason for invalidity
        reason: String,
    },

    /// Conflicting header at same height
    #[error("conflicting header at height {height}")]
    ConflictingHeader {
        /// The height
        height: u64,
    },
}

/// Result type for light client operations
pub type LightClientResult<T> = Result<T, LightClientError>;

/// Proof of a validator set for light client verification
///
/// This contains the full validator set along with a proof that it's
/// the correct set for a given epoch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetProof {
    /// The epoch this validator set is for
    pub epoch: EpochNumber,
    /// The full validator set
    pub validator_set: ValidatorSet,
    /// The hash of this validator set
    pub validator_set_hash: Hash,
    /// Block header that commits to this validator set as the next epoch's set
    /// (the last block of the previous epoch)
    pub committing_header: Option<BlockHeader>,
    /// Finality certificate for the committing header
    pub committing_cert: Option<FinalityCert>,
}

impl ValidatorSetProof {
    /// Creates a new validator set proof
    pub fn new(epoch: EpochNumber, validator_set: ValidatorSet) -> Self {
        let validator_set_hash = compute_validator_set_hash(&validator_set);
        Self {
            epoch,
            validator_set,
            validator_set_hash,
            committing_header: None,
            committing_cert: None,
        }
    }

    /// Creates a proof with the committing header and certificate
    pub fn with_commitment(
        epoch: EpochNumber,
        validator_set: ValidatorSet,
        committing_header: BlockHeader,
        committing_cert: FinalityCert,
    ) -> Self {
        let validator_set_hash = compute_validator_set_hash(&validator_set);
        Self {
            epoch,
            validator_set,
            validator_set_hash,
            committing_header: Some(committing_header),
            committing_cert: Some(committing_cert),
        }
    }

    /// Verifies the proof is internally consistent
    pub fn verify_internal(&self) -> LightClientResult<()> {
        // Check that the computed hash matches
        let computed_hash = compute_validator_set_hash(&self.validator_set);
        if computed_hash != self.validator_set_hash {
            return Err(LightClientError::ValidatorSetMismatch {
                expected: hex::encode(&self.validator_set_hash[..8]),
                actual: hex::encode(&computed_hash[..8]),
            });
        }

        // If we have a committing header, verify it commits to this set
        if let Some(header) = &self.committing_header {
            if let Some(next_hash) = &header.next_validator_set_hash {
                if next_hash.as_bytes() != &self.validator_set_hash {
                    return Err(LightClientError::InvalidProof {
                        reason: "header's next_validator_set_hash doesn't match proof".into(),
                    });
                }
            } else {
                return Err(LightClientError::InvalidProof {
                    reason: "committing header has no next_validator_set_hash".into(),
                });
            }
        }

        Ok(())
    }
}

/// A trusted header stored by the light client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedHeader {
    /// The block header
    pub header: BlockHeader,
    /// The finality certificate
    pub finality_cert: FinalityCert,
    /// The validator set that signed this header
    pub validator_set_hash: Hash,
    /// Timestamp when this header was trusted
    pub trusted_at: u64,
}

impl TrustedHeader {
    /// Creates a new trusted header
    pub fn new(
        header: BlockHeader,
        finality_cert: FinalityCert,
        validator_set_hash: Hash,
        trusted_at: u64,
    ) -> Self {
        Self {
            header,
            finality_cert,
            validator_set_hash,
            trusted_at,
        }
    }

    /// Returns the block height
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Returns the block hash
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }
}

/// Light client state for tracking validator sets and verifying headers
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientState {
    /// Chain ID
    chain_id: u64,
    /// Epoch configuration
    epoch_config: EpochConfig,
    /// Current trusted validator set
    current_validator_set: ValidatorSet,
    /// Hash of current validator set
    current_validator_set_hash: Hash,
    /// Current epoch
    current_epoch: EpochNumber,
    /// Most recently verified header
    latest_trusted_header: TrustedHeader,
    /// Trust period in seconds
    trust_period_secs: u64,
    /// Historical validator sets (limited history)
    historical_sets: Vec<(EpochNumber, Hash)>,
    /// Maximum historical sets to keep
    max_historical_sets: usize,
}

impl LightClientState {
    /// Creates a new light client state from a trusted genesis
    pub fn new(
        chain_id: u64,
        epoch_config: EpochConfig,
        genesis_header: BlockHeader,
        genesis_validators: ValidatorSet,
        trusted_at: u64,
    ) -> Self {
        let validator_set_hash = compute_validator_set_hash(&genesis_validators);

        let trusted_header = TrustedHeader::new(
            genesis_header.clone(),
            FinalityCert::default(), // Genesis has no finality cert
            validator_set_hash,
            trusted_at,
        );

        Self {
            chain_id,
            epoch_config,
            current_validator_set: genesis_validators,
            current_validator_set_hash: validator_set_hash,
            current_epoch: 0,
            latest_trusted_header: trusted_header,
            trust_period_secs: DEFAULT_TRUST_PERIOD_SECS,
            historical_sets: vec![(0, validator_set_hash)],
            max_historical_sets: 100,
        }
    }

    /// Returns the current epoch
    pub fn current_epoch(&self) -> EpochNumber {
        self.current_epoch
    }

    /// Returns the current validator set
    pub fn current_validator_set(&self) -> &ValidatorSet {
        &self.current_validator_set
    }

    /// Returns the current validator set hash
    pub fn current_validator_set_hash(&self) -> Hash {
        self.current_validator_set_hash
    }

    /// Returns the latest trusted header
    pub fn latest_trusted_header(&self) -> &TrustedHeader {
        &self.latest_trusted_header
    }

    /// Returns the latest trusted height
    pub fn latest_trusted_height(&self) -> u64 {
        self.latest_trusted_header.height()
    }

    /// Sets the trust period
    pub fn set_trust_period(&mut self, secs: u64) {
        self.trust_period_secs = secs;
    }

    /// Checks if the trust period has expired
    pub fn is_trust_expired(&self, current_time: u64) -> bool {
        current_time > self.latest_trusted_header.trusted_at + self.trust_period_secs
    }

    /// Verifies a new header and finality certificate
    ///
    /// This is the main verification function for light clients.
    pub fn verify_header(
        &self,
        header: &BlockHeader,
        finality_cert: &FinalityCert,
        current_time: u64,
    ) -> LightClientResult<()> {
        // Check trust period
        if self.is_trust_expired(current_time) {
            return Err(LightClientError::TrustPeriodExpired {
                last_trusted_time: self.latest_trusted_header.trusted_at,
                current_time,
            });
        }

        // Check chain ID
        if header.chain_id != self.chain_id {
            return Err(LightClientError::HeaderVerificationFailed {
                reason: format!(
                    "chain ID mismatch: expected {}, got {}",
                    self.chain_id, header.chain_id
                ),
            });
        }

        // Check height is increasing
        if header.height <= self.latest_trusted_header.height() {
            return Err(LightClientError::HeaderVerificationFailed {
                reason: format!(
                    "height not increasing: current {}, new {}",
                    self.latest_trusted_header.height(),
                    header.height
                ),
            });
        }

        // Determine which validator set should sign this header
        let header_epoch = self.epoch_config.epoch_for_height(header.height);

        // Verify validator set hash in header matches expected
        let expected_vs_hash = if header_epoch == self.current_epoch {
            self.current_validator_set_hash
        } else {
            // New epoch - need the next validator set hash from last trusted header
            // or we need bisection
            return Err(LightClientError::HeightJumpTooLarge {
                from: self.latest_trusted_header.height(),
                to: header.height,
            });
        };

        if header.validator_set_hash.as_bytes() != &expected_vs_hash {
            return Err(LightClientError::ValidatorSetMismatch {
                expected: hex::encode(&expected_vs_hash[..8]),
                actual: header.validator_set_hash.to_hex()[..18].to_string(),
            });
        }

        // Verify finality certificate
        self.verify_finality_cert(header, finality_cert)?;

        Ok(())
    }

    /// Verifies a finality certificate against the current validator set
    fn verify_finality_cert(
        &self,
        header: &BlockHeader,
        finality_cert: &FinalityCert,
    ) -> LightClientResult<()> {
        // Check certificate height matches header
        if finality_cert.height != header.height {
            return Err(LightClientError::InvalidFinalityCert {
                reason: format!(
                    "height mismatch: header {}, cert {}",
                    header.height, finality_cert.height
                ),
            });
        }

        // Check certificate block hash matches header
        let header_hash: [u8; 32] = header.hash().into();
        if finality_cert.block_hash != header_hash {
            return Err(LightClientError::InvalidFinalityCert {
                reason: "block hash mismatch".into(),
            });
        }

        // Verify quorum
        if !finality_cert.verify(&self.current_validator_set) {
            let signers = finality_cert.get_signers();
            let total_stake: u128 = signers
                .iter()
                .filter_map(|id| self.current_validator_set.get_validator(*id))
                .map(|v| v.stake)
                .sum();

            return Err(LightClientError::InsufficientSignatures {
                got: total_stake,
                required: self.current_validator_set.quorum_stake(),
            });
        }

        Ok(())
    }

    /// Updates the light client state with a verified header
    ///
    /// Call this after `verify_header` returns Ok.
    pub fn update(
        &mut self,
        header: BlockHeader,
        finality_cert: FinalityCert,
        current_time: u64,
    ) -> LightClientResult<()> {
        let header_epoch = self.epoch_config.epoch_for_height(header.height);

        // Check for epoch transition
        if header_epoch > self.current_epoch {
            // We should have received the new validator set
            // For now, this requires bisection/sequential verification
            warn!(
                old_epoch = self.current_epoch,
                new_epoch = header_epoch,
                "Epoch transition detected, may need bisection"
            );
        }

        // Update latest trusted header
        self.latest_trusted_header = TrustedHeader::new(
            header.clone(),
            finality_cert,
            self.current_validator_set_hash,
            current_time,
        );

        // If this header is at an epoch boundary, prepare for next epoch
        if header.next_validator_set_hash.is_some() {
            debug!(
                height = header.height,
                epoch = header_epoch,
                "Header is at epoch boundary"
            );
        }

        Ok(())
    }

    /// Updates the validator set for a new epoch
    ///
    /// This should be called when transitioning to a new epoch with a proven
    /// new validator set.
    pub fn update_validator_set(
        &mut self,
        new_epoch: EpochNumber,
        new_validator_set: ValidatorSet,
        proof: &ValidatorSetProof,
    ) -> LightClientResult<()> {
        // Verify the proof
        proof.verify_internal()?;

        // Verify the proof is for the correct epoch
        if proof.epoch != new_epoch {
            return Err(LightClientError::InvalidProof {
                reason: format!(
                    "epoch mismatch: expected {}, got {}",
                    new_epoch, proof.epoch
                ),
            });
        }

        // Verify the validator set matches the proof
        let computed_hash = compute_validator_set_hash(&new_validator_set);
        if computed_hash != proof.validator_set_hash {
            return Err(LightClientError::ValidatorSetMismatch {
                expected: hex::encode(&proof.validator_set_hash[..8]),
                actual: hex::encode(&computed_hash[..8]),
            });
        }

        // If we have a committing header and cert, verify them
        if let (Some(header), Some(cert)) = (&proof.committing_header, &proof.committing_cert) {
            // The committing header should be signed by the CURRENT validator set
            self.verify_finality_cert(header, cert)?;
        }

        // Archive the old validator set
        self.historical_sets
            .push((self.current_epoch, self.current_validator_set_hash));

        // Prune old history
        while self.historical_sets.len() > self.max_historical_sets {
            self.historical_sets.remove(0);
        }

        // Update to new validator set
        self.current_epoch = new_epoch;
        self.current_validator_set = new_validator_set;
        self.current_validator_set_hash = computed_hash;

        debug!(
            new_epoch = new_epoch,
            validator_count = self.current_validator_set.len(),
            "Updated light client validator set"
        );

        Ok(())
    }

    /// Verifies a sequence of headers from current state to target
    ///
    /// This is used for bisection when the light client needs to catch up
    /// across multiple epochs.
    pub fn verify_header_sequence(
        &mut self,
        headers: &[(BlockHeader, FinalityCert)],
        current_time: u64,
    ) -> LightClientResult<()> {
        for (header, cert) in headers {
            self.verify_header(header, cert, current_time)?;
            self.update(header.clone(), cert.clone(), current_time)?;
        }
        Ok(())
    }

    /// Gets the validator set hash for a historical epoch
    pub fn get_historical_validator_set_hash(&self, epoch: EpochNumber) -> Option<Hash> {
        if epoch == self.current_epoch {
            return Some(self.current_validator_set_hash);
        }
        self.historical_sets
            .iter()
            .find(|(e, _)| *e == epoch)
            .map(|(_, h)| *h)
    }

    /// Creates a snapshot of the light client state for persistence
    pub fn snapshot(&self) -> LightClientSnapshot {
        LightClientSnapshot {
            chain_id: self.chain_id,
            epoch_config: self.epoch_config,
            current_validator_set: self.current_validator_set.clone(),
            current_validator_set_hash: self.current_validator_set_hash,
            current_epoch: self.current_epoch,
            latest_trusted_header: self.latest_trusted_header.clone(),
            trust_period_secs: self.trust_period_secs,
            historical_sets: self.historical_sets.clone(),
        }
    }

    /// Restores from a snapshot
    pub fn from_snapshot(snapshot: LightClientSnapshot) -> Self {
        Self {
            chain_id: snapshot.chain_id,
            epoch_config: snapshot.epoch_config,
            current_validator_set: snapshot.current_validator_set,
            current_validator_set_hash: snapshot.current_validator_set_hash,
            current_epoch: snapshot.current_epoch,
            latest_trusted_header: snapshot.latest_trusted_header,
            trust_period_secs: snapshot.trust_period_secs,
            historical_sets: snapshot.historical_sets,
            max_historical_sets: 100,
        }
    }
}

/// Snapshot of light client state for persistence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientSnapshot {
    /// Chain ID
    pub chain_id: u64,
    /// Epoch configuration
    pub epoch_config: EpochConfig,
    /// Current validator set
    pub current_validator_set: ValidatorSet,
    /// Current validator set hash
    pub current_validator_set_hash: Hash,
    /// Current epoch
    pub current_epoch: EpochNumber,
    /// Latest trusted header
    pub latest_trusted_header: TrustedHeader,
    /// Trust period
    pub trust_period_secs: u64,
    /// Historical validator set hashes
    pub historical_sets: Vec<(EpochNumber, Hash)>,
}

/// Helper for bisection when catching up across epochs
#[derive(Debug, Clone)]
pub struct BisectionHelper {
    /// Starting height
    pub from_height: u64,
    /// Target height
    pub to_height: u64,
    /// Epoch boundaries that need to be verified
    pub epoch_boundaries: Vec<u64>,
}

impl BisectionHelper {
    /// Creates a new bisection helper
    pub fn new(from_height: u64, to_height: u64, epoch_config: &EpochConfig) -> Self {
        let mut epoch_boundaries = Vec::new();

        // Find all epoch boundaries between from and to
        let from_epoch = epoch_config.epoch_for_height(from_height);
        let to_epoch = epoch_config.epoch_for_height(to_height);

        for epoch in from_epoch + 1..=to_epoch {
            let boundary = epoch_config.epoch_start_height(epoch);
            if boundary > from_height && boundary <= to_height {
                epoch_boundaries.push(boundary);
            }
        }

        Self {
            from_height,
            to_height,
            epoch_boundaries,
        }
    }

    /// Returns the heights that need to be verified
    pub fn verification_heights(&self) -> Vec<u64> {
        let mut heights = Vec::new();

        // Add epoch boundaries (for validator set transitions)
        heights.extend(&self.epoch_boundaries);

        // Add the target height
        if !heights.contains(&self.to_height) {
            heights.push(self.to_height);
        }

        heights.sort_unstable();
        heights
    }

    /// Checks if bisection is needed
    pub fn needs_bisection(&self) -> bool {
        !self.epoch_boundaries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Validator, ValidatorId};
    use protocore_crypto::bls::BlsPrivateKey;

    fn make_test_validator(id: ValidatorId, stake: u128) -> Validator {
        // Generate a random key pair for testing
        let private_key = BlsPrivateKey::random();
        let pubkey = private_key.public_key();
        Validator {
            id,
            pubkey,
            address: [id as u8; 20],
            stake,
            commission: 100,
            active: true,
        }
    }

    fn make_test_validator_set(count: usize) -> ValidatorSet {
        let validators: Vec<Validator> = (0..count)
            .map(|i| make_test_validator(i as ValidatorId, 1000 * (count - i) as u128))
            .collect();
        ValidatorSet::new(validators)
    }

    #[test]
    fn test_validator_set_proof() {
        let vs = make_test_validator_set(4);
        let proof = ValidatorSetProof::new(0, vs.clone());

        // Verify internal consistency
        assert!(proof.verify_internal().is_ok());

        // Verify hash matches
        assert_eq!(proof.validator_set_hash, compute_validator_set_hash(&vs));
    }

    #[test]
    fn test_bisection_helper() {
        let config = EpochConfig::new(100).unwrap();
        let helper = BisectionHelper::new(50, 350, &config);

        // Should have epoch boundaries at 101, 201, 301
        assert_eq!(helper.epoch_boundaries, vec![101, 201, 301]);
        assert!(helper.needs_bisection());

        let heights = helper.verification_heights();
        assert_eq!(heights, vec![101, 201, 301, 350]);
    }

    #[test]
    fn test_bisection_no_crossing() {
        let config = EpochConfig::new(100).unwrap();
        let helper = BisectionHelper::new(50, 80, &config);

        // No epoch boundaries
        assert!(helper.epoch_boundaries.is_empty());
        assert!(!helper.needs_bisection());
    }

    #[test]
    fn test_light_client_trust_period() {
        let config = EpochConfig::new(100).unwrap();
        let vs = make_test_validator_set(4);
        let genesis = BlockHeader::genesis(1, H256::NIL, 1000);

        let lc = LightClientState::new(1, config, genesis, vs, 1000);

        // Trust period is default (3 weeks)
        assert!(!lc.is_trust_expired(1000 + 1000));

        // Expired after trust period
        assert!(lc.is_trust_expired(1000 + DEFAULT_TRUST_PERIOD_SECS + 1));
    }
}
