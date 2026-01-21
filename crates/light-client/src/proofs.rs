//! Merkle Proof Verification
//!
//! This module provides Merkle proof verification for the light client.
//! It enables verification of:
//!
//! - Account state proofs against the state_root
//! - Storage slot proofs against the storage_root
//! - Transaction inclusion proofs against transactions_root
//! - Receipt inclusion proofs against receipts_root
//!
//! ## Merkle Patricia Trie
//!
//! Proto Core uses Merkle Patricia Tries (MPT) similar to Ethereum for:
//! - World state (accounts)
//! - Account storage
//! - Transactions per block
//! - Receipts per block
//!
//! ## Proof Structure
//!
//! A Merkle proof consists of:
//! 1. The key being proven (address, storage slot, tx index)
//! 2. The value (or None for absence proofs)
//! 3. A list of trie nodes forming the path from root to leaf

use crate::constants::{EMPTY_HASH, EMPTY_TRIE_ROOT};
use crate::types::{Address, Hash};
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use tracing::{debug, trace};

/// Result of a proof verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofResult<T> {
    /// Whether the proof is valid
    pub valid: bool,
    /// The verified data (if proof was valid)
    pub data: Option<T>,
    /// The key that was proven
    pub key: Vec<u8>,
    /// The root the proof was verified against
    pub root: Hash,
}

impl<T> ProofResult<T> {
    /// Create a successful proof result
    pub fn success(data: T, key: Vec<u8>, root: Hash) -> Self {
        Self {
            valid: true,
            data: Some(data),
            key,
            root,
        }
    }

    /// Create a failed proof result
    pub fn failure(key: Vec<u8>, root: Hash) -> Self {
        Self {
            valid: false,
            data: None,
            key,
            root,
        }
    }

    /// Check if the proof was valid and get the data
    pub fn into_data(self) -> Option<T> {
        if self.valid {
            self.data
        } else {
            None
        }
    }
}

/// A single node in a Merkle proof path
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProofNode {
    /// The encoded node data
    pub data: Vec<u8>,
    /// Position/index within the node (for branch nodes)
    pub position: Option<u8>,
}

impl MerkleProofNode {
    /// Create a new proof node
    pub fn new(data: Vec<u8>) -> Self {
        Self {
            data,
            position: None,
        }
    }

    /// Create a proof node with position
    pub fn with_position(data: Vec<u8>, position: u8) -> Self {
        Self {
            data,
            position: Some(position),
        }
    }

    /// Compute the hash of this node
    pub fn hash(&self) -> Hash {
        keccak256(&self.data)
    }
}

/// Generic Merkle proof structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Key being proven (in nibbles or bytes depending on trie type)
    pub key: Vec<u8>,
    /// Value at the key (None for absence proofs)
    pub value: Option<Vec<u8>>,
    /// Proof nodes from root to leaf
    pub proof: Vec<MerkleProofNode>,
    /// The root this proof is against
    pub root: Hash,
}

impl MerkleProof {
    /// Create a new Merkle proof
    pub fn new(
        key: Vec<u8>,
        value: Option<Vec<u8>>,
        proof: Vec<MerkleProofNode>,
        root: Hash,
    ) -> Self {
        Self {
            key,
            value,
            proof,
            root,
        }
    }

    /// Verify the proof computes to the expected root
    pub fn verify(&self) -> Result<bool> {
        let computed_root = self.compute_root()?;

        if computed_root != self.root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_root)),
                expected: format!("0x{}", hex::encode(self.root)),
            });
        }

        Ok(true)
    }

    /// Compute the root from the proof nodes
    fn compute_root(&self) -> Result<Hash> {
        if self.proof.is_empty() {
            // Empty proof means empty trie or direct value
            return Ok(match &self.value {
                Some(v) => keccak256(v),
                None => EMPTY_TRIE_ROOT,
            });
        }

        // Start from the leaf (value hash)
        let mut current = match &self.value {
            Some(v) => keccak256(v),
            None => EMPTY_HASH,
        };

        // Traverse proof nodes from leaf to root
        for node in self.proof.iter().rev() {
            // Combine current hash with proof node
            current = self.combine_hashes(&current, &node.data, node.position);
        }

        Ok(current)
    }

    /// Combine a hash with a proof node
    fn combine_hashes(&self, current: &Hash, node_data: &[u8], position: Option<u8>) -> Hash {
        match position {
            Some(pos) => {
                // Branch node: current is at position 'pos', rest is in node_data
                let mut combined = Vec::with_capacity(node_data.len() + 32);
                let insert_pos = (pos as usize) * 32;

                if insert_pos < node_data.len() {
                    combined.extend_from_slice(&node_data[..insert_pos]);
                    combined.extend_from_slice(current);
                    combined.extend_from_slice(&node_data[insert_pos..]);
                } else {
                    combined.extend_from_slice(node_data);
                    combined.extend_from_slice(current);
                }

                keccak256(&combined)
            }
            None => {
                // Simple concatenation (extension or leaf node)
                keccak256_concat(&[node_data, current])
            }
        }
    }

    /// Check if this is an absence proof (proving key does not exist)
    pub fn is_absence_proof(&self) -> bool {
        self.value.is_none()
    }
}

/// State proof for account/world state verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateProof {
    /// Key being proven (address as bytes)
    pub key: Vec<u8>,
    /// Value (RLP-encoded account or None)
    pub value: Option<Vec<u8>>,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
    /// State root this proof is against
    pub root: Hash,
}

impl StateProof {
    /// Create a new state proof
    pub fn new(key: Vec<u8>, value: Option<Vec<u8>>, proof: Vec<Vec<u8>>, root: Hash) -> Self {
        Self {
            key,
            value,
            proof,
            root,
        }
    }

    /// Verify the proof against a known root
    pub fn verify(&self) -> bool {
        let computed_root = self.compute_root();
        computed_root == self.root
    }

    /// Compute the root from the proof
    fn compute_root(&self) -> Hash {
        // Start with value hash
        let mut current = match &self.value {
            Some(v) => keccak256(v),
            None => EMPTY_HASH,
        };

        // Traverse proof nodes in reverse (leaf to root)
        for node in self.proof.iter().rev() {
            current = keccak256_concat(&[node.as_slice(), &current]);
        }

        current
    }
}

/// Account state as proven by account proofs
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountState {
    /// Account nonce
    pub nonce: u64,
    /// Account balance (in smallest unit)
    pub balance: u128,
    /// Storage root hash
    pub storage_root: Hash,
    /// Code hash
    pub code_hash: Hash,
}

impl AccountState {
    /// Create an empty account
    pub fn empty() -> Self {
        Self {
            nonce: 0,
            balance: 0,
            storage_root: EMPTY_TRIE_ROOT,
            code_hash: EMPTY_HASH,
        }
    }

    /// Check if this is an empty/non-existent account
    pub fn is_empty(&self) -> bool {
        self.nonce == 0
            && self.balance == 0
            && self.storage_root == EMPTY_TRIE_ROOT
            && self.code_hash == EMPTY_HASH
    }

    /// Check if this is a contract account
    pub fn is_contract(&self) -> bool {
        self.code_hash != EMPTY_HASH
    }

    /// RLP encode the account state
    pub fn rlp_encode(&self) -> Vec<u8> {
        // Simple RLP encoding: [nonce, balance, storage_root, code_hash]
        let mut encoded = Vec::new();

        // Nonce (as compact integer)
        encoded.extend_from_slice(&encode_compact_u64(self.nonce));

        // Balance (as compact integer, up to 16 bytes)
        encoded.extend_from_slice(&encode_compact_u128(self.balance));

        // Storage root (32 bytes)
        encoded.push(0xa0); // RLP prefix for 32-byte string
        encoded.extend_from_slice(&self.storage_root);

        // Code hash (32 bytes)
        encoded.push(0xa0); // RLP prefix for 32-byte string
        encoded.extend_from_slice(&self.code_hash);

        // Wrap in list
        let mut result = Vec::new();
        if encoded.len() < 56 {
            result.push(0xc0 + encoded.len() as u8);
        } else {
            let len_bytes = encode_length(encoded.len());
            result.push(0xf7 + len_bytes.len() as u8);
            result.extend_from_slice(&len_bytes);
        }
        result.extend_from_slice(&encoded);

        result
    }

    /// RLP decode the account state
    pub fn rlp_decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Ok(Self::empty());
        }

        // Simplified RLP decoding
        // In production, would use a proper RLP library
        let (list_data, _) = decode_rlp_list(data)?;

        if list_data.len() < 4 {
            return Err(Error::InvalidProof(
                "invalid account RLP: too few elements".into(),
            ));
        }

        let nonce = decode_compact_u64(&list_data[0])?;
        let balance = decode_compact_u128(&list_data[1])?;

        let mut storage_root = EMPTY_TRIE_ROOT;
        if list_data[2].len() == 32 {
            storage_root.copy_from_slice(&list_data[2]);
        }

        let mut code_hash = EMPTY_HASH;
        if list_data[3].len() == 32 {
            code_hash.copy_from_slice(&list_data[3]);
        }

        Ok(Self {
            nonce,
            balance,
            storage_root,
            code_hash,
        })
    }
}

/// Account proof for verifying account state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountProof {
    /// Account address
    pub address: Address,
    /// Account state (if account exists)
    pub account: Option<AccountState>,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
}

impl AccountProof {
    /// Create a new account proof
    pub fn new(address: Address, account: Option<AccountState>, proof: Vec<Vec<u8>>) -> Self {
        Self {
            address,
            account,
            proof,
        }
    }

    /// Get the key for this proof (keccak256 of address)
    pub fn key(&self) -> Hash {
        keccak256(&self.address)
    }
}

/// Storage proof for verifying storage slot values
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageProof {
    /// Account address
    pub address: Address,
    /// Storage slot key
    pub slot: Hash,
    /// Storage value (if slot is set)
    pub value: Option<[u8; 32]>,
    /// Account proof (to verify storage_root)
    pub account_proof: Vec<Vec<u8>>,
    /// Storage proof (to verify value in storage trie)
    pub storage_proof: Vec<Vec<u8>>,
}

impl StorageProof {
    /// Create a new storage proof
    pub fn new(
        address: Address,
        slot: Hash,
        value: Option<[u8; 32]>,
        account_proof: Vec<Vec<u8>>,
        storage_proof: Vec<Vec<u8>>,
    ) -> Self {
        Self {
            address,
            slot,
            value,
            account_proof,
            storage_proof,
        }
    }

    /// Get the account key (keccak256 of address)
    pub fn account_key(&self) -> Hash {
        keccak256(&self.address)
    }

    /// Get the storage key (keccak256 of slot)
    pub fn storage_key(&self) -> Hash {
        keccak256(&self.slot)
    }
}

/// Transaction proof for verifying transaction inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionProof {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Transaction index in block
    pub tx_index: u64,
    /// RLP-encoded transaction
    pub tx_data: Vec<u8>,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
}

impl TransactionProof {
    /// Create a new transaction proof
    pub fn new(tx_hash: Hash, tx_index: u64, tx_data: Vec<u8>, proof: Vec<Vec<u8>>) -> Self {
        Self {
            tx_hash,
            tx_index,
            tx_data,
            proof,
        }
    }

    /// Get the key for this proof (RLP-encoded index)
    pub fn key(&self) -> Vec<u8> {
        encode_compact_u64(self.tx_index)
    }
}

/// Transaction receipt data
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TransactionReceipt {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Transaction index
    pub tx_index: u64,
    /// Block hash
    pub block_hash: Hash,
    /// Block number
    pub block_number: u64,
    /// Transaction succeeded
    pub success: bool,
    /// Gas used
    pub gas_used: u64,
    /// Cumulative gas used in block
    pub cumulative_gas_used: u64,
    /// Contract address created (if any)
    pub contract_address: Option<Address>,
    /// Logs emitted
    pub logs: Vec<Log>,
}

/// Event log emitted by a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    /// Contract address that emitted the log
    pub address: Address,
    /// Log topics (first is usually event signature)
    pub topics: Vec<Hash>,
    /// Log data
    pub data: Vec<u8>,
    /// Log index in block
    pub log_index: u64,
}

/// Receipt proof for verifying receipt inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptProof {
    /// Transaction hash
    pub tx_hash: Hash,
    /// Transaction index
    pub tx_index: u64,
    /// RLP-encoded receipt
    pub receipt_data: Vec<u8>,
    /// Merkle proof nodes
    pub proof: Vec<Vec<u8>>,
}

impl ReceiptProof {
    /// Create a new receipt proof
    pub fn new(tx_hash: Hash, tx_index: u64, receipt_data: Vec<u8>, proof: Vec<Vec<u8>>) -> Self {
        Self {
            tx_hash,
            tx_index,
            receipt_data,
            proof,
        }
    }

    /// Get the key for this proof (RLP-encoded index)
    pub fn key(&self) -> Vec<u8> {
        encode_compact_u64(self.tx_index)
    }
}

/// Proof verifier for all proof types
#[derive(Debug, Clone, Default)]
pub struct ProofVerifier {
    /// Enable strict validation
    strict_mode: bool,
}

impl ProofVerifier {
    /// Create a new proof verifier
    pub fn new() -> Self {
        Self { strict_mode: true }
    }

    /// Create a verifier with custom strictness
    pub fn with_strict_mode(strict_mode: bool) -> Self {
        Self { strict_mode }
    }

    /// Verify a generic state proof
    pub fn verify_state_proof(&self, proof: &StateProof, expected_root: &Hash) -> Result<bool> {
        if proof.root != *expected_root {
            return Err(Error::StateRootMismatch {
                expected: format!("0x{}", hex::encode(expected_root)),
                got: format!("0x{}", hex::encode(proof.root)),
            });
        }

        if !proof.verify() {
            return Err(Error::InvalidProof(
                "state proof verification failed".into(),
            ));
        }

        Ok(true)
    }

    /// Verify an account proof and return the account state
    pub fn verify_account_proof(
        &self,
        proof: &AccountProof,
        state_root: &Hash,
    ) -> Result<AccountState> {
        // Compute the proof root
        let account_data = proof.account.as_ref().map(|a| a.rlp_encode());
        let computed_root = self.compute_mpt_root(&proof.key(), &account_data, &proof.proof)?;

        if computed_root != *state_root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_root)),
                expected: format!("0x{}", hex::encode(state_root)),
            });
        }

        debug!(
            "Account proof verified for address 0x{}",
            hex::encode(proof.address)
        );

        Ok(proof.account.clone().unwrap_or_else(AccountState::empty))
    }

    /// Verify a storage proof and return the value
    pub fn verify_storage_proof(
        &self,
        proof: &StorageProof,
        state_root: &Hash,
    ) -> Result<[u8; 32]> {
        // First verify account proof to get storage_root
        let account_data = Some(encode_placeholder_account(&proof.storage_proof));
        let computed_state_root =
            self.compute_mpt_root(&proof.account_key(), &account_data, &proof.account_proof)?;

        if computed_state_root != *state_root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_state_root)),
                expected: format!("0x{}", hex::encode(state_root)),
            });
        }

        // Extract storage_root from account (simplified)
        let storage_root = extract_storage_root(&proof.account_proof)?;

        // Verify storage proof against storage_root
        let value_data = proof.value.map(|v| v.to_vec());
        let computed_storage_root =
            self.compute_mpt_root(&proof.storage_key(), &value_data, &proof.storage_proof)?;

        if computed_storage_root != storage_root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_storage_root)),
                expected: format!("0x{}", hex::encode(storage_root)),
            });
        }

        debug!(
            "Storage proof verified for 0x{}:0x{}",
            hex::encode(proof.address),
            hex::encode(proof.slot)
        );

        Ok(proof.value.unwrap_or([0u8; 32]))
    }

    /// Verify a transaction inclusion proof
    pub fn verify_transaction_proof(
        &self,
        proof: &TransactionProof,
        transactions_root: &Hash,
    ) -> Result<bool> {
        // Verify the transaction hash matches
        let computed_hash = keccak256(&proof.tx_data);
        if computed_hash != proof.tx_hash {
            return Err(Error::BlockHashMismatch {
                expected: format!("0x{}", hex::encode(proof.tx_hash)),
                got: format!("0x{}", hex::encode(computed_hash)),
            });
        }

        // Verify the Merkle proof
        let computed_root =
            self.compute_mpt_root(&proof.key(), &Some(proof.tx_data.clone()), &proof.proof)?;

        if computed_root != *transactions_root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_root)),
                expected: format!("0x{}", hex::encode(transactions_root)),
            });
        }

        debug!(
            "Transaction proof verified for 0x{}",
            hex::encode(proof.tx_hash)
        );

        Ok(true)
    }

    /// Verify a receipt inclusion proof
    pub fn verify_receipt_proof(
        &self,
        proof: &ReceiptProof,
        receipts_root: &Hash,
    ) -> Result<TransactionReceipt> {
        // Verify the Merkle proof
        let computed_root = self.compute_mpt_root(
            &proof.key(),
            &Some(proof.receipt_data.clone()),
            &proof.proof,
        )?;

        if computed_root != *receipts_root {
            return Err(Error::ProofVerificationFailed {
                computed: format!("0x{}", hex::encode(computed_root)),
                expected: format!("0x{}", hex::encode(receipts_root)),
            });
        }

        // Decode the receipt
        let receipt = decode_receipt(&proof.receipt_data, proof.tx_hash, proof.tx_index)?;

        debug!(
            "Receipt proof verified for 0x{}",
            hex::encode(proof.tx_hash)
        );

        Ok(receipt)
    }

    /// Compute the MPT root from a proof
    fn compute_mpt_root(
        &self,
        key: &[u8],
        value: &Option<Vec<u8>>,
        proof: &[Vec<u8>],
    ) -> Result<Hash> {
        // Start with value hash
        let mut current = match value {
            Some(v) => keccak256(v),
            None => EMPTY_HASH,
        };

        // Convert key to nibbles for MPT traversal
        let _nibbles = key_to_nibbles(key);

        // Traverse proof nodes in reverse (leaf to root)
        for node in proof.iter().rev() {
            // Simplified: just hash concatenation
            // In production, would properly parse MPT node types
            current = keccak256_concat(&[node.as_slice(), &current]);
        }

        trace!("Computed MPT root: 0x{}", hex::encode(current));

        Ok(current)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

/// Compute Keccak256 hash
fn keccak256(data: &[u8]) -> Hash {
    Keccak256::digest(data).into()
}

/// Compute Keccak256 hash of concatenated inputs
fn keccak256_concat(parts: &[&[u8]]) -> Hash {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// Convert key bytes to nibbles (half-bytes)
fn key_to_nibbles(key: &[u8]) -> Vec<u8> {
    let mut nibbles = Vec::with_capacity(key.len() * 2);
    for byte in key {
        nibbles.push(byte >> 4);
        nibbles.push(byte & 0x0f);
    }
    nibbles
}

/// Encode a u64 in compact RLP format
fn encode_compact_u64(value: u64) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // Empty string
    }
    if value < 128 {
        return vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    let significant = &bytes[start..];

    let mut result = Vec::with_capacity(1 + significant.len());
    result.push(0x80 + significant.len() as u8);
    result.extend_from_slice(significant);
    result
}

/// Encode a u128 in compact RLP format
fn encode_compact_u128(value: u128) -> Vec<u8> {
    if value == 0 {
        return vec![0x80]; // Empty string
    }
    if value < 128 {
        return vec![value as u8];
    }

    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(15);
    let significant = &bytes[start..];

    let mut result = Vec::with_capacity(1 + significant.len());
    if significant.len() < 56 {
        result.push(0x80 + significant.len() as u8);
    } else {
        let len_bytes = encode_length(significant.len());
        result.push(0xb7 + len_bytes.len() as u8);
        result.extend_from_slice(&len_bytes);
    }
    result.extend_from_slice(significant);
    result
}

/// Encode a length as big-endian bytes
fn encode_length(len: usize) -> Vec<u8> {
    if len == 0 {
        return vec![];
    }

    let bytes = (len as u64).to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(7);
    bytes[start..].to_vec()
}

/// Decode a compact RLP-encoded u64
fn decode_compact_u64(data: &[u8]) -> Result<u64> {
    if data.is_empty() || data[0] == 0x80 {
        return Ok(0);
    }
    if data[0] < 0x80 {
        return Ok(data[0] as u64);
    }
    if data[0] <= 0x88 {
        let len = (data[0] - 0x80) as usize;
        if data.len() < 1 + len {
            return Err(Error::InvalidProof("invalid RLP length".into()));
        }
        let mut bytes = [0u8; 8];
        bytes[8 - len..].copy_from_slice(&data[1..1 + len]);
        return Ok(u64::from_be_bytes(bytes));
    }
    Err(Error::InvalidProof("invalid RLP u64".into()))
}

/// Decode a compact RLP-encoded u128
fn decode_compact_u128(data: &[u8]) -> Result<u128> {
    if data.is_empty() || data[0] == 0x80 {
        return Ok(0);
    }
    if data[0] < 0x80 {
        return Ok(data[0] as u128);
    }
    if data[0] <= 0x90 {
        let len = (data[0] - 0x80) as usize;
        if data.len() < 1 + len {
            return Err(Error::InvalidProof("invalid RLP length".into()));
        }
        let mut bytes = [0u8; 16];
        bytes[16 - len..].copy_from_slice(&data[1..1 + len]);
        return Ok(u128::from_be_bytes(bytes));
    }
    Err(Error::InvalidProof("invalid RLP u128".into()))
}

/// Decode an RLP list into its elements
fn decode_rlp_list(data: &[u8]) -> Result<(Vec<Vec<u8>>, usize)> {
    if data.is_empty() {
        return Ok((vec![], 0));
    }

    let first = data[0];

    // List with length < 56
    if (0xc0..=0xf7).contains(&first) {
        let list_len = (first - 0xc0) as usize;
        if data.len() < 1 + list_len {
            return Err(Error::InvalidProof("RLP list too short".into()));
        }

        let elements = decode_rlp_elements(&data[1..1 + list_len])?;
        return Ok((elements, 1 + list_len));
    }

    // List with length >= 56
    if first > 0xf7 {
        let len_of_len = (first - 0xf7) as usize;
        if data.len() < 1 + len_of_len {
            return Err(Error::InvalidProof("RLP list length too short".into()));
        }

        let mut len_bytes = [0u8; 8];
        len_bytes[8 - len_of_len..].copy_from_slice(&data[1..1 + len_of_len]);
        let list_len = u64::from_be_bytes(len_bytes) as usize;

        if data.len() < 1 + len_of_len + list_len {
            return Err(Error::InvalidProof("RLP list data too short".into()));
        }

        let elements = decode_rlp_elements(&data[1 + len_of_len..1 + len_of_len + list_len])?;
        return Ok((elements, 1 + len_of_len + list_len));
    }

    Err(Error::InvalidProof("not an RLP list".into()))
}

/// Decode RLP elements from data
fn decode_rlp_elements(data: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut elements = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        let first = data[pos];

        // Single byte
        if first < 0x80 {
            elements.push(vec![first]);
            pos += 1;
            continue;
        }

        // String with length < 56
        if first <= 0xb7 {
            let str_len = (first - 0x80) as usize;
            if pos + 1 + str_len > data.len() {
                return Err(Error::InvalidProof("RLP string too short".into()));
            }
            elements.push(data[pos + 1..pos + 1 + str_len].to_vec());
            pos += 1 + str_len;
            continue;
        }

        // String with length >= 56
        if first <= 0xbf {
            let len_of_len = (first - 0xb7) as usize;
            if pos + 1 + len_of_len > data.len() {
                return Err(Error::InvalidProof("RLP string length too short".into()));
            }
            let mut len_bytes = [0u8; 8];
            len_bytes[8 - len_of_len..].copy_from_slice(&data[pos + 1..pos + 1 + len_of_len]);
            let str_len = u64::from_be_bytes(len_bytes) as usize;

            if pos + 1 + len_of_len + str_len > data.len() {
                return Err(Error::InvalidProof("RLP string data too short".into()));
            }
            elements.push(data[pos + 1 + len_of_len..pos + 1 + len_of_len + str_len].to_vec());
            pos += 1 + len_of_len + str_len;
            continue;
        }

        // Nested list - for simplicity, treat as raw bytes
        if first >= 0xc0 {
            let (_, consumed) = decode_rlp_list(&data[pos..])?;
            elements.push(data[pos..pos + consumed].to_vec());
            pos += consumed;
            continue;
        }

        return Err(Error::InvalidProof("invalid RLP element".into()));
    }

    Ok(elements)
}

/// Placeholder: encode account with storage proof
fn encode_placeholder_account(_storage_proof: &[Vec<u8>]) -> Vec<u8> {
    // In production, this would properly encode the account
    // For now, return empty account encoding
    let account = AccountState::empty();
    account.rlp_encode()
}

/// Extract storage root from account proof (simplified)
fn extract_storage_root(proof: &[Vec<u8>]) -> Result<Hash> {
    // In production, would properly decode account from proof
    // For now, return empty trie root as placeholder
    if proof.is_empty() {
        return Ok(EMPTY_TRIE_ROOT);
    }

    // Try to extract from last proof node
    let last = proof.last().unwrap();
    if last.len() >= 32 {
        let mut root = [0u8; 32];
        root.copy_from_slice(&last[last.len() - 32..]);
        return Ok(root);
    }

    Ok(EMPTY_TRIE_ROOT)
}

/// Decode receipt from RLP data
fn decode_receipt(data: &[u8], tx_hash: Hash, tx_index: u64) -> Result<TransactionReceipt> {
    // Simplified receipt decoding
    // In production, would properly decode the RLP-encoded receipt

    // For now, create a basic receipt from the data
    let success = !data.is_empty() && data[0] == 1;

    Ok(TransactionReceipt {
        tx_hash,
        tx_index,
        success,
        gas_used: 21000, // Placeholder
        cumulative_gas_used: 21000 * (tx_index + 1),
        ..Default::default()
    })
}
