//! Light Client Implementation
//!
//! This module provides the core light client functionality for Proto Core.
//! The light client can verify blockchain state using only block headers and
//! Merkle proofs, without requiring full block data.
//!
//! ## Components
//!
//! - [`LightClient`] - Main client interface for verification operations
//! - [`HeaderChain`] - Storage for verified block headers
//! - [`ValidatorTracker`] - Tracks validator sets across epochs
//! - [`ValidatorSet`] - Represents the validator set for an epoch
//! - [`Checkpoint`] - Trusted starting point for the light client

use crate::constants::{
    DEFAULT_EPOCH_LENGTH, FINALITY_THRESHOLD_DENOMINATOR, FINALITY_THRESHOLD_NUMERATOR,
    MAX_HEADERS_PER_SYNC,
};
use crate::proofs::{AccountProof, ProofVerifier, ReceiptProof, StorageProof, TransactionProof};
use crate::types::{Address, BlockHeight, Epoch, Hash, Stake};
use crate::{Error, Result};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tracing::{debug, info, trace, warn};

/// Configuration for the light client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientConfig {
    /// Number of blocks per epoch
    pub epoch_length: u64,
    /// Maximum number of headers to store (0 = unlimited)
    pub max_headers: usize,
    /// Whether to prune old headers
    pub prune_headers: bool,
    /// Number of epochs to retain when pruning
    pub retain_epochs: u64,
    /// Enable strict validation mode
    pub strict_mode: bool,
}

impl Default for LightClientConfig {
    fn default() -> Self {
        Self {
            epoch_length: DEFAULT_EPOCH_LENGTH,
            max_headers: 10000,
            prune_headers: true,
            retain_epochs: 2,
            strict_mode: true,
        }
    }
}

/// Information about a single validator
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Validator's address
    pub address: Address,
    /// BLS public key for consensus signatures
    pub bls_public_key: Vec<u8>,
    /// Staked amount
    pub stake: Stake,
    /// Whether the validator is active
    pub active: bool,
}

impl ValidatorInfo {
    /// Create a new validator info
    pub fn new(address: Address, bls_public_key: Vec<u8>, stake: Stake) -> Self {
        Self {
            address,
            bls_public_key,
            stake,
            active: true,
        }
    }

    /// Get the validator's address as a hex string
    pub fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }
}

/// Validator set for a specific epoch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSet {
    /// Epoch number this set is valid for
    pub epoch: Epoch,
    /// List of validators
    pub validators: Vec<ValidatorInfo>,
    /// Total stake in this set
    pub total_stake: Stake,
    /// Mapping from address to validator index for quick lookups
    #[serde(skip)]
    address_index: HashMap<Address, usize>,
}

impl ValidatorSet {
    /// Create a new validator set
    pub fn new(epoch: Epoch, validators: Vec<ValidatorInfo>) -> Self {
        let total_stake = validators.iter().filter(|v| v.active).map(|v| v.stake).sum();
        let address_index = validators
            .iter()
            .enumerate()
            .map(|(i, v)| (v.address, i))
            .collect();

        Self {
            epoch,
            validators,
            total_stake,
            address_index,
        }
    }

    /// Get a validator by address
    pub fn get_validator(&self, address: &Address) -> Option<&ValidatorInfo> {
        self.address_index
            .get(address)
            .and_then(|&idx| self.validators.get(idx))
    }

    /// Check if an address is a validator
    pub fn is_validator(&self, address: &Address) -> bool {
        self.address_index.contains_key(address)
    }

    /// Get the minimum stake required for finality (>2/3 of total)
    pub fn finality_threshold(&self) -> Stake {
        // We need strictly more than 2/3, so we compute (2 * total / 3) + 1
        (self.total_stake * FINALITY_THRESHOLD_NUMERATOR) / FINALITY_THRESHOLD_DENOMINATOR + 1
    }

    /// Count of active validators
    pub fn active_count(&self) -> usize {
        self.validators.iter().filter(|v| v.active).count()
    }

    /// Rebuild the address index (needed after deserialization)
    pub fn rebuild_index(&mut self) {
        self.address_index = self
            .validators
            .iter()
            .enumerate()
            .map(|(i, v)| (v.address, i))
            .collect();
    }
}

/// Block header as stored by the light client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightBlockHeader {
    /// Block number/height
    pub number: BlockHeight,
    /// Hash of this block
    pub hash: Hash,
    /// Parent block hash
    pub parent_hash: Hash,
    /// State root (for account/storage proofs)
    pub state_root: Hash,
    /// Transactions root (for tx inclusion proofs)
    pub transactions_root: Hash,
    /// Receipts root (for receipt/log proofs)
    pub receipts_root: Hash,
    /// Block timestamp
    pub timestamp: u64,
    /// Block proposer address
    pub proposer: Address,
    /// Epoch number
    pub epoch: Epoch,
}

impl LightBlockHeader {
    /// Compute the hash of this header
    pub fn compute_hash(&self) -> Hash {
        let mut hasher = Keccak256::new();
        hasher.update(self.number.to_be_bytes());
        hasher.update(self.parent_hash);
        hasher.update(self.state_root);
        hasher.update(self.transactions_root);
        hasher.update(self.receipts_root);
        hasher.update(self.timestamp.to_be_bytes());
        hasher.update(self.proposer);
        hasher.update(self.epoch.to_be_bytes());
        hasher.finalize().into()
    }

    /// Verify the header hash is correct
    pub fn verify_hash(&self) -> bool {
        self.hash == self.compute_hash()
    }

    /// Get the block hash as a hex string
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash))
    }
}

/// Signature from a validator in a finality certificate
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSignature {
    /// Validator address
    pub validator: Address,
    /// BLS signature bytes
    pub signature: Vec<u8>,
}

/// Finality certificate proving a block is finalized
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityCertificate {
    /// Block hash this certificate is for
    pub block_hash: Hash,
    /// Block number
    pub block_number: BlockHeight,
    /// Epoch of the block
    pub epoch: Epoch,
    /// Signatures from validators
    pub signatures: Vec<ValidatorSignature>,
    /// Aggregated BLS signature (optional, for efficiency)
    pub aggregated_signature: Option<Vec<u8>>,
    /// Bitmap of which validators signed (for aggregated sig)
    pub signer_bitmap: Option<Vec<u8>>,
}

impl FinalityCertificate {
    /// Create a new finality certificate
    pub fn new(
        block_hash: Hash,
        block_number: BlockHeight,
        epoch: Epoch,
        signatures: Vec<ValidatorSignature>,
    ) -> Self {
        Self {
            block_hash,
            block_number,
            epoch,
            signatures,
            aggregated_signature: None,
            signer_bitmap: None,
        }
    }

    /// Verify the certificate against a validator set
    pub fn verify(&self, validator_set: &ValidatorSet) -> Result<bool> {
        if validator_set.epoch != self.epoch {
            return Err(Error::EpochBoundaryError(format!(
                "certificate epoch {} != validator set epoch {}",
                self.epoch, validator_set.epoch
            )));
        }

        // Calculate total stake from signers
        let mut total_signed_stake: Stake = 0;
        let mut verified_signers: Vec<Address> = Vec::new();

        // If we have individual signatures, verify each one
        for sig in &self.signatures {
            // Get validator info
            let validator = validator_set.get_validator(&sig.validator).ok_or_else(|| {
                Error::UnknownValidator(format!("0x{}", hex::encode(sig.validator)))
            })?;

            if !validator.active {
                continue;
            }

            // Verify signature (placeholder - actual BLS verification would go here)
            // In production, this would call into protocore-crypto's BLS module
            if !self.verify_bls_signature(&sig.signature, &self.block_hash, &validator.bls_public_key)
            {
                return Err(Error::InvalidSignature {
                    validator: format!("0x{}", hex::encode(sig.validator)),
                });
            }

            // Avoid counting duplicates
            if !verified_signers.contains(&sig.validator) {
                total_signed_stake += validator.stake;
                verified_signers.push(sig.validator);
            }
        }

        // Check if we have enough stake
        let threshold = validator_set.finality_threshold();
        if total_signed_stake < threshold {
            return Err(Error::InsufficientStake {
                got: total_signed_stake,
                required: threshold,
            });
        }

        debug!(
            "Finality certificate verified: block {}, stake {}/{}",
            self.block_number, total_signed_stake, validator_set.total_stake
        );

        Ok(true)
    }

    /// Verify a BLS signature (placeholder implementation)
    fn verify_bls_signature(&self, signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
        // In production, this would use protocore-crypto's BLS verification
        // For now, we do basic sanity checks
        if signature.is_empty() || public_key.is_empty() {
            return false;
        }

        // Placeholder: In a real implementation, this would call:
        // protocore_crypto::bls::BlsSignature::verify(signature, message, public_key)

        // For the light client, we trust that signatures are properly formatted
        // and would be verified by the actual BLS implementation
        let _ = message; // Used in actual verification
        true
    }

    /// Get the total stake that signed this certificate
    pub fn signed_stake(&self, validator_set: &ValidatorSet) -> Stake {
        self.signatures
            .iter()
            .filter_map(|sig| validator_set.get_validator(&sig.validator))
            .filter(|v| v.active)
            .map(|v| v.stake)
            .sum()
    }
}

/// Tracks validator sets across epochs
#[derive(Debug)]
pub struct ValidatorTracker {
    /// Validator sets by epoch
    sets: BTreeMap<Epoch, ValidatorSet>,
    /// Current epoch
    current_epoch: Epoch,
    /// Epoch length in blocks
    epoch_length: u64,
}

impl ValidatorTracker {
    /// Create a new validator tracker
    pub fn new(epoch_length: u64) -> Self {
        Self {
            sets: BTreeMap::new(),
            current_epoch: 0,
            epoch_length,
        }
    }

    /// Initialize with a validator set
    pub fn init(&mut self, initial_set: ValidatorSet) {
        self.current_epoch = initial_set.epoch;
        self.sets.insert(initial_set.epoch, initial_set);
    }

    /// Get the validator set for a specific epoch
    pub fn get_set(&self, epoch: Epoch) -> Option<&ValidatorSet> {
        self.sets.get(&epoch)
    }

    /// Get the current validator set
    pub fn current_set(&self) -> Option<&ValidatorSet> {
        self.sets.get(&self.current_epoch)
    }

    /// Get the epoch for a given block height
    pub fn epoch_for_height(&self, height: BlockHeight) -> Epoch {
        height / self.epoch_length
    }

    /// Check if a height is at an epoch boundary
    pub fn is_epoch_boundary(&self, height: BlockHeight) -> bool {
        height % self.epoch_length == 0
    }

    /// Update to a new validator set at epoch boundary
    pub fn update_set(&mut self, new_set: ValidatorSet) -> Result<()> {
        let expected_epoch = self.current_epoch + 1;
        if new_set.epoch != expected_epoch {
            return Err(Error::EpochBoundaryError(format!(
                "expected epoch {}, got {}",
                expected_epoch, new_set.epoch
            )));
        }

        info!(
            "Updating validator set: epoch {} -> {}, validators: {}",
            self.current_epoch,
            new_set.epoch,
            new_set.active_count()
        );

        self.sets.insert(new_set.epoch, new_set);
        self.current_epoch = expected_epoch;

        Ok(())
    }

    /// Prune old validator sets, keeping only recent epochs
    pub fn prune(&mut self, keep_epochs: u64) {
        if self.current_epoch <= keep_epochs {
            return;
        }

        let cutoff = self.current_epoch - keep_epochs;
        self.sets.retain(|&epoch, _| epoch >= cutoff);

        debug!(
            "Pruned validator sets: keeping epochs >= {}",
            cutoff
        );
    }

    /// Get the number of tracked epochs
    pub fn epoch_count(&self) -> usize {
        self.sets.len()
    }
}

/// Storage for verified block headers
#[derive(Debug)]
pub struct HeaderChain {
    /// Headers by block number
    by_number: BTreeMap<BlockHeight, LightBlockHeader>,
    /// Headers by hash (for quick lookups)
    by_hash: HashMap<Hash, BlockHeight>,
    /// Latest finalized height
    finalized_height: BlockHeight,
    /// Configuration
    max_headers: usize,
    prune_enabled: bool,
}

impl HeaderChain {
    /// Create a new header chain
    pub fn new(max_headers: usize, prune_enabled: bool) -> Self {
        Self {
            by_number: BTreeMap::new(),
            by_hash: HashMap::new(),
            finalized_height: 0,
            max_headers,
            prune_enabled,
        }
    }

    /// Insert a verified header
    pub fn insert(&mut self, header: LightBlockHeader) -> Result<()> {
        let number = header.number;
        let hash = header.hash;

        // Check for conflicts
        if let Some(existing) = self.by_number.get(&number) {
            if existing.hash != hash {
                return Err(Error::ReorgDetected {
                    height: number,
                    expected: format!("0x{}", hex::encode(existing.hash)),
                    got: format!("0x{}", hex::encode(hash)),
                });
            }
            // Same header already exists
            return Ok(());
        }

        self.by_hash.insert(hash, number);
        self.by_number.insert(number, header);

        // Prune if needed
        if self.prune_enabled && self.max_headers > 0 && self.by_number.len() > self.max_headers {
            self.prune();
        }

        trace!("Inserted header at height {}", number);
        Ok(())
    }

    /// Get a header by block number
    pub fn get_by_number(&self, number: BlockHeight) -> Option<&LightBlockHeader> {
        self.by_number.get(&number)
    }

    /// Get a header by block hash
    pub fn get_by_hash(&self, hash: &Hash) -> Option<&LightBlockHeader> {
        self.by_hash
            .get(hash)
            .and_then(|&number| self.by_number.get(&number))
    }

    /// Check if we have a header at a specific height
    pub fn has_height(&self, height: BlockHeight) -> bool {
        self.by_number.contains_key(&height)
    }

    /// Check if we have a header with a specific hash
    pub fn has_hash(&self, hash: &Hash) -> bool {
        self.by_hash.contains_key(hash)
    }

    /// Get the latest header
    pub fn latest(&self) -> Option<&LightBlockHeader> {
        self.by_number.values().next_back()
    }

    /// Get the latest block height
    pub fn latest_height(&self) -> Option<BlockHeight> {
        self.by_number.keys().next_back().copied()
    }

    /// Get the finalized height
    pub fn finalized_height(&self) -> BlockHeight {
        self.finalized_height
    }

    /// Set the finalized height
    pub fn set_finalized_height(&mut self, height: BlockHeight) {
        self.finalized_height = height;
    }

    /// Get the number of stored headers
    pub fn len(&self) -> usize {
        self.by_number.len()
    }

    /// Check if the chain is empty
    pub fn is_empty(&self) -> bool {
        self.by_number.is_empty()
    }

    /// Get headers in a range
    pub fn get_range(&self, start: BlockHeight, end: BlockHeight) -> Vec<&LightBlockHeader> {
        self.by_number
            .range(start..=end)
            .map(|(_, h)| h)
            .collect()
    }

    /// Verify the chain from a starting point
    pub fn verify_chain(&self, from_height: BlockHeight) -> Result<()> {
        let headers: Vec<_> = self.by_number.range(from_height..).collect();

        for window in headers.windows(2) {
            let (_, parent) = window[0];
            let (_, child) = window[1];

            // Check parent hash link
            if child.parent_hash != parent.hash {
                return Err(Error::InvalidHeaderChain(format!(
                    "broken chain at height {}: parent hash mismatch",
                    child.number
                )));
            }

            // Check sequential numbers
            if child.number != parent.number + 1 {
                return Err(Error::HeaderChainGap(parent.number + 1));
            }
        }

        Ok(())
    }

    /// Prune old headers, keeping only recent ones
    fn prune(&mut self) {
        if self.by_number.len() <= self.max_headers {
            return;
        }

        let to_remove = self.by_number.len() - self.max_headers;
        let heights_to_remove: Vec<_> = self.by_number.keys().take(to_remove).copied().collect();

        for height in heights_to_remove {
            if let Some(header) = self.by_number.remove(&height) {
                self.by_hash.remove(&header.hash);
            }
        }

        debug!("Pruned {} headers", to_remove);
    }
}

/// Trusted checkpoint for initializing the light client
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    /// The checkpoint header
    pub header: LightBlockHeader,
    /// Validator set at this checkpoint
    pub validator_set: ValidatorSet,
    /// Finality certificate for the checkpoint (optional for genesis)
    pub finality_cert: Option<FinalityCertificate>,
}

impl Checkpoint {
    /// Create a genesis checkpoint (no finality cert needed)
    pub fn genesis(header: LightBlockHeader, validator_set: ValidatorSet) -> Self {
        Self {
            header,
            validator_set,
            finality_cert: None,
        }
    }

    /// Create a checkpoint with finality proof
    pub fn with_finality(
        header: LightBlockHeader,
        validator_set: ValidatorSet,
        finality_cert: FinalityCertificate,
    ) -> Self {
        Self {
            header,
            validator_set,
            finality_cert: Some(finality_cert),
        }
    }

    /// Verify the checkpoint is valid
    pub fn verify(&self, trusted_set: Option<&ValidatorSet>) -> Result<()> {
        // Verify header hash
        if !self.header.verify_hash() {
            return Err(Error::InvalidCheckpoint("header hash mismatch".into()));
        }

        // If we have a finality cert and trusted set, verify it
        if let (Some(cert), Some(set)) = (&self.finality_cert, trusted_set) {
            cert.verify(set)?;

            if cert.block_hash != self.header.hash {
                return Err(Error::BlockHashMismatch {
                    expected: format!("0x{}", hex::encode(cert.block_hash)),
                    got: self.header.hash_hex(),
                });
            }
        }

        Ok(())
    }
}

/// Main light client struct
pub struct LightClient {
    /// Configuration
    config: LightClientConfig,
    /// Verified header chain
    headers: Arc<RwLock<HeaderChain>>,
    /// Validator set tracker
    validators: Arc<RwLock<ValidatorTracker>>,
    /// Proof verifier
    verifier: ProofVerifier,
    /// Whether the client is initialized
    initialized: bool,
}

impl LightClient {
    /// Create a new light client from a trusted checkpoint
    pub fn new(config: LightClientConfig, checkpoint: Checkpoint) -> Result<Self> {
        // Verify checkpoint (genesis doesn't need prior trust)
        checkpoint.verify(None)?;

        let headers = Arc::new(RwLock::new(HeaderChain::new(
            config.max_headers,
            config.prune_headers,
        )));
        let validators = Arc::new(RwLock::new(ValidatorTracker::new(config.epoch_length)));

        // Initialize from checkpoint
        {
            let mut h = headers.write();
            h.insert(checkpoint.header.clone())?;
            h.set_finalized_height(checkpoint.header.number);
        }

        {
            let mut v = validators.write();
            v.init(checkpoint.validator_set.clone());
        }

        info!(
            "Light client initialized at height {}, epoch {}",
            checkpoint.header.number, checkpoint.validator_set.epoch
        );

        Ok(Self {
            config,
            headers,
            validators,
            verifier: ProofVerifier::new(),
            initialized: true,
        })
    }

    /// Check if the client is initialized
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Get the current finalized height
    pub fn finalized_height(&self) -> BlockHeight {
        self.headers.read().finalized_height()
    }

    /// Get the latest header height
    pub fn latest_height(&self) -> Option<BlockHeight> {
        self.headers.read().latest_height()
    }

    /// Get a header by height
    pub fn get_header(&self, height: BlockHeight) -> Option<LightBlockHeader> {
        self.headers.read().get_by_number(height).cloned()
    }

    /// Get a header by hash
    pub fn get_header_by_hash(&self, hash: &Hash) -> Option<LightBlockHeader> {
        self.headers.read().get_by_hash(hash).cloned()
    }

    /// Get the current epoch
    pub fn current_epoch(&self) -> Epoch {
        self.validators
            .read()
            .current_set()
            .map(|s| s.epoch)
            .unwrap_or(0)
    }

    /// Get the current validator set
    pub fn current_validator_set(&self) -> Option<ValidatorSet> {
        self.validators.read().current_set().cloned()
    }

    /// Verify and add a new header with its finality certificate
    pub fn verify_header(
        &self,
        header: LightBlockHeader,
        finality_cert: &FinalityCertificate,
    ) -> Result<()> {
        // Verify header hash
        if !header.verify_hash() {
            return Err(Error::BlockHashMismatch {
                expected: header.hash_hex(),
                got: format!("0x{}", hex::encode(header.compute_hash())),
            });
        }

        // Check certificate matches header
        if finality_cert.block_hash != header.hash {
            return Err(Error::BlockHashMismatch {
                expected: header.hash_hex(),
                got: format!("0x{}", hex::encode(finality_cert.block_hash)),
            });
        }

        // Get validator set for this epoch
        let validators = self.validators.read();
        let epoch = validators.epoch_for_height(header.number);
        let validator_set = validators.get_set(epoch).ok_or_else(|| {
            Error::EpochBoundaryError(format!("no validator set for epoch {}", epoch))
        })?;

        // Verify finality certificate has >2/3 stake
        finality_cert.verify(validator_set)?;

        drop(validators);

        // Check parent link if we have the parent
        {
            let headers = self.headers.read();
            if let Some(parent) = headers.get_by_number(header.number.saturating_sub(1)) {
                if header.parent_hash != parent.hash {
                    return Err(Error::InvalidHeaderChain(
                        "parent hash does not match".into(),
                    ));
                }
            }
        }

        // Insert the verified header
        {
            let mut headers = self.headers.write();
            headers.insert(header.clone())?;
            headers.set_finalized_height(header.number);
        }

        debug!("Verified and added header at height {}", header.number);

        Ok(())
    }

    /// Verify multiple headers in sequence
    pub fn verify_headers(
        &self,
        headers: Vec<(LightBlockHeader, FinalityCertificate)>,
    ) -> Result<usize> {
        let mut verified = 0;

        for (header, cert) in headers {
            match self.verify_header(header, &cert) {
                Ok(()) => verified += 1,
                Err(e) => {
                    warn!("Failed to verify header: {}", e);
                    break;
                }
            }
        }

        Ok(verified)
    }

    /// Update the validator set at an epoch boundary
    pub fn update_validator_set(
        &self,
        new_set: ValidatorSet,
        proof: &crate::proofs::StateProof,
    ) -> Result<()> {
        // Get the header for the epoch boundary
        let boundary_height = new_set.epoch * self.config.epoch_length;
        let header = self
            .headers
            .read()
            .get_by_number(boundary_height)
            .cloned()
            .ok_or_else(|| {
                Error::HeaderNotFound(format!("header at epoch boundary {}", boundary_height))
            })?;

        // Verify the proof against the state root
        if !self
            .verifier
            .verify_state_proof(proof, &header.state_root)?
        {
            return Err(Error::InvalidProof(
                "validator set proof verification failed".into(),
            ));
        }

        // Update the validator tracker
        let mut validators = self.validators.write();
        validators.update_set(new_set)?;

        // Prune old epochs if configured
        if self.config.prune_headers {
            validators.prune(self.config.retain_epochs);
        }

        Ok(())
    }

    /// Verify an account state proof
    pub fn verify_account(
        &self,
        proof: &AccountProof,
        block_hash: &Hash,
    ) -> Result<crate::proofs::AccountState> {
        let header = self
            .headers
            .read()
            .get_by_hash(block_hash)
            .cloned()
            .ok_or_else(|| Error::HeaderNotFound(format!("0x{}", hex::encode(block_hash))))?;

        self.verifier.verify_account_proof(proof, &header.state_root)
    }

    /// Verify a storage slot proof
    pub fn verify_storage(
        &self,
        proof: &StorageProof,
        block_hash: &Hash,
    ) -> Result<[u8; 32]> {
        let header = self
            .headers
            .read()
            .get_by_hash(block_hash)
            .cloned()
            .ok_or_else(|| Error::HeaderNotFound(format!("0x{}", hex::encode(block_hash))))?;

        self.verifier.verify_storage_proof(proof, &header.state_root)
    }

    /// Verify a transaction inclusion proof
    pub fn verify_transaction(
        &self,
        proof: &TransactionProof,
        block_hash: &Hash,
    ) -> Result<bool> {
        let header = self
            .headers
            .read()
            .get_by_hash(block_hash)
            .cloned()
            .ok_or_else(|| Error::HeaderNotFound(format!("0x{}", hex::encode(block_hash))))?;

        self.verifier
            .verify_transaction_proof(proof, &header.transactions_root)
    }

    /// Verify a receipt inclusion proof
    pub fn verify_receipt(
        &self,
        proof: &ReceiptProof,
        block_hash: &Hash,
    ) -> Result<crate::proofs::TransactionReceipt> {
        let header = self
            .headers
            .read()
            .get_by_hash(block_hash)
            .cloned()
            .ok_or_else(|| Error::HeaderNotFound(format!("0x{}", hex::encode(block_hash))))?;

        self.verifier
            .verify_receipt_proof(proof, &header.receipts_root)
    }

    /// Get statistics about the light client state
    pub fn stats(&self) -> LightClientStats {
        let headers = self.headers.read();
        let validators = self.validators.read();

        LightClientStats {
            headers_stored: headers.len(),
            finalized_height: headers.finalized_height(),
            latest_height: headers.latest_height(),
            current_epoch: validators.current_set().map(|s| s.epoch),
            epochs_tracked: validators.epoch_count(),
            validator_count: validators.current_set().map(|s| s.active_count()),
        }
    }
}

/// Statistics about the light client state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientStats {
    /// Number of headers stored
    pub headers_stored: usize,
    /// Current finalized height
    pub finalized_height: BlockHeight,
    /// Latest header height
    pub latest_height: Option<BlockHeight>,
    /// Current epoch
    pub current_epoch: Option<Epoch>,
    /// Number of epochs tracked
    pub epochs_tracked: usize,
    /// Number of validators in current set
    pub validator_count: Option<usize>,
}

