//! Block and BlockHeader types for Proto Core.
//!
//! This module provides the block-related types:
//! - [`BlockHeader`] - The header containing metadata and state roots
//! - [`Block`] - A complete block with header and transactions
//! - [`FinalityCert`] - Cryptographic proof of block finalization

use crate::{Address, Error, Result, SignedTransaction, H256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;

/// A block header containing all metadata about a block.
///
/// The header includes:
/// - Chain identification (chain_id)
/// - Block position (height, parent_hash)
/// - State commitments (state_root, transactions_root, receipts_root)
/// - Execution context (gas_limit, gas_used, base_fee)
/// - Consensus data (proposer, timestamp, last_finality_cert)
/// - Validator set data (validator_set_hash, next_validator_set_hash)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Chain identifier (prevents cross-chain replay)
    pub chain_id: u64,
    /// Block height (0-indexed, genesis is height 0)
    pub height: u64,
    /// Unix timestamp in milliseconds
    pub timestamp: u64,
    /// Hash of the parent block (NIL for genesis)
    pub parent_hash: H256,
    /// Merkle root of the transactions in this block
    pub transactions_root: H256,
    /// Merkle root of the world state after executing this block
    pub state_root: H256,
    /// Merkle root of the transaction receipts
    pub receipts_root: H256,
    /// Address of the block proposer/validator
    pub proposer: Address,
    /// Maximum gas allowed in this block
    pub gas_limit: u64,
    /// Total gas used by all transactions in this block
    pub gas_used: u64,
    /// Base fee per gas (EIP-1559)
    pub base_fee: u128,
    /// Hash of the finality certificate for the previous block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_finality_cert_hash: Option<H256>,
    /// Hash of the current validator set for this block's epoch
    ///
    /// This enables light clients to verify that votes came from the correct
    /// validator set without downloading the full validator list.
    pub validator_set_hash: H256,
    /// Hash of the next epoch's validator set (only set at epoch boundaries)
    ///
    /// When a block is at an epoch boundary (last block of an epoch), this field
    /// contains the hash of the validator set that will be active in the next epoch.
    /// Light clients use this to follow validator set transitions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_validator_set_hash: Option<H256>,
}

impl Default for BlockHeader {
    fn default() -> Self {
        Self {
            chain_id: 1,
            height: 0,
            timestamp: 0,
            parent_hash: H256::NIL,
            transactions_root: H256::NIL,
            state_root: H256::NIL,
            receipts_root: H256::NIL,
            proposer: Address::ZERO,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee: 1_000_000_000, // 1 gwei
            last_finality_cert_hash: None,
            validator_set_hash: H256::NIL,
            next_validator_set_hash: None,
        }
    }
}

impl BlockHeader {
    /// Creates a new block header.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        height: u64,
        timestamp: u64,
        parent_hash: H256,
        proposer: Address,
    ) -> Self {
        Self {
            chain_id,
            height,
            timestamp,
            parent_hash,
            proposer,
            ..Default::default()
        }
    }

    /// Computes the hash of this block header.
    ///
    /// The hash is the Keccak256 of the RLP-encoded header.
    pub fn hash(&self) -> H256 {
        let encoded = self.rlp_encode();
        H256::keccak256(&encoded)
    }

    /// RLP encodes the header.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(14);
        stream.append(&self.chain_id);
        stream.append(&self.height);
        stream.append(&self.timestamp);
        stream.append(&self.parent_hash);
        stream.append(&self.transactions_root);
        stream.append(&self.state_root);
        stream.append(&self.receipts_root);
        stream.append(&self.proposer);
        stream.append(&self.gas_limit);
        stream.append(&self.gas_used);
        stream.append(&self.base_fee);
        match &self.last_finality_cert_hash {
            Some(hash) => stream.append(hash),
            None => stream.append(&""),
        };
        stream.append(&self.validator_set_hash);
        match &self.next_validator_set_hash {
            Some(hash) => stream.append(hash),
            None => stream.append(&""),
        };
        stream.out().to_vec()
    }

    /// Decodes a header from RLP bytes.
    pub fn rlp_decode(data: &[u8]) -> Result<Self> {
        let rlp = Rlp::new(data);
        Self::decode(&rlp).map_err(Error::RlpDecode)
    }

    /// Validates the header against basic rules.
    pub fn validate_basic(&self) -> Result<()> {
        // Height must be positive (except genesis)
        if self.height > 0 && self.parent_hash.is_nil() {
            return Err(Error::InvalidTransaction(
                "non-genesis block must have parent hash".into(),
            ));
        }

        // Gas used cannot exceed gas limit
        if self.gas_used > self.gas_limit {
            return Err(Error::InvalidTransaction(format!(
                "gas used ({}) exceeds gas limit ({})",
                self.gas_used, self.gas_limit
            )));
        }

        // Timestamp must be reasonable (not zero for non-genesis)
        if self.height > 0 && self.timestamp == 0 {
            return Err(Error::InvalidTransaction(
                "non-genesis block must have timestamp".into(),
            ));
        }

        Ok(())
    }

    /// Creates a genesis block header.
    pub fn genesis(chain_id: u64, state_root: H256, timestamp: u64) -> Self {
        Self {
            chain_id,
            height: 0,
            timestamp,
            parent_hash: H256::NIL,
            transactions_root: H256::NIL,
            state_root,
            receipts_root: H256::NIL,
            proposer: Address::ZERO,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee: 1_000_000_000,
            last_finality_cert_hash: None,
            validator_set_hash: H256::NIL,
            next_validator_set_hash: None,
        }
    }

    /// Creates a genesis block header with a validator set hash.
    pub fn genesis_with_validators(
        chain_id: u64,
        state_root: H256,
        timestamp: u64,
        validator_set_hash: H256,
    ) -> Self {
        Self {
            chain_id,
            height: 0,
            timestamp,
            parent_hash: H256::NIL,
            transactions_root: H256::NIL,
            state_root,
            receipts_root: H256::NIL,
            proposer: Address::ZERO,
            gas_limit: 30_000_000,
            gas_used: 0,
            base_fee: 1_000_000_000,
            last_finality_cert_hash: None,
            validator_set_hash,
            next_validator_set_hash: None,
        }
    }

    /// Sets the validator set hashes
    pub fn with_validator_set_hashes(
        mut self,
        validator_set_hash: H256,
        next_validator_set_hash: Option<H256>,
    ) -> Self {
        self.validator_set_hash = validator_set_hash;
        self.next_validator_set_hash = next_validator_set_hash;
        self
    }

    /// Checks if this block is at an epoch boundary (has next validator set hash)
    pub fn is_epoch_boundary(&self) -> bool {
        self.next_validator_set_hash.is_some()
    }

    /// Sets the state roots.
    pub fn with_roots(
        mut self,
        transactions_root: H256,
        state_root: H256,
        receipts_root: H256,
    ) -> Self {
        self.transactions_root = transactions_root;
        self.state_root = state_root;
        self.receipts_root = receipts_root;
        self
    }

    /// Sets the gas fields.
    pub fn with_gas(mut self, gas_limit: u64, gas_used: u64, base_fee: u128) -> Self {
        self.gas_limit = gas_limit;
        self.gas_used = gas_used;
        self.base_fee = base_fee;
        self
    }

    /// Calculates the next block's base fee using EIP-1559 formula.
    pub fn next_base_fee(&self) -> u128 {
        let target_gas = self.gas_limit / 2;

        if self.gas_used == target_gas {
            return self.base_fee;
        }

        if self.gas_used > target_gas {
            // Increase base fee
            let gas_delta = self.gas_used - target_gas;
            let fee_delta = self.base_fee * gas_delta as u128 / target_gas as u128 / 8;
            self.base_fee + std::cmp::max(fee_delta, 1)
        } else {
            // Decrease base fee
            let gas_delta = target_gas - self.gas_used;
            let fee_delta = self.base_fee * gas_delta as u128 / target_gas as u128 / 8;
            self.base_fee.saturating_sub(fee_delta)
        }
    }
}

impl Encodable for BlockHeader {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(14);
        s.append(&self.chain_id);
        s.append(&self.height);
        s.append(&self.timestamp);
        s.append(&self.parent_hash);
        s.append(&self.transactions_root);
        s.append(&self.state_root);
        s.append(&self.receipts_root);
        s.append(&self.proposer);
        s.append(&self.gas_limit);
        s.append(&self.gas_used);
        s.append(&self.base_fee);
        match &self.last_finality_cert_hash {
            Some(hash) => s.append(hash),
            None => s.append(&""),
        };
        s.append(&self.validator_set_hash);
        match &self.next_validator_set_hash {
            Some(hash) => s.append(hash),
            None => s.append(&""),
        };
    }
}

impl Decodable for BlockHeader {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 14 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let cert_bytes: Vec<u8> = rlp.val_at(11)?;
        let last_finality_cert_hash = if cert_bytes.is_empty() {
            None
        } else {
            Some(H256::from_slice(&cert_bytes).map_err(|_| DecoderError::RlpInvalidLength)?)
        };

        let next_vs_bytes: Vec<u8> = rlp.val_at(13)?;
        let next_validator_set_hash = if next_vs_bytes.is_empty() {
            None
        } else {
            Some(H256::from_slice(&next_vs_bytes).map_err(|_| DecoderError::RlpInvalidLength)?)
        };

        Ok(Self {
            chain_id: rlp.val_at(0)?,
            height: rlp.val_at(1)?,
            timestamp: rlp.val_at(2)?,
            parent_hash: rlp.val_at(3)?,
            transactions_root: rlp.val_at(4)?,
            state_root: rlp.val_at(5)?,
            receipts_root: rlp.val_at(6)?,
            proposer: rlp.val_at(7)?,
            gas_limit: rlp.val_at(8)?,
            gas_used: rlp.val_at(9)?,
            base_fee: rlp.val_at(10)?,
            last_finality_cert_hash,
            validator_set_hash: rlp.val_at(12)?,
            next_validator_set_hash,
        })
    }
}

impl fmt::Display for BlockHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block #{} (hash: {}, parent: {}, txs_root: {})",
            self.height,
            self.hash(),
            self.parent_hash,
            self.transactions_root
        )
    }
}

/// A complete block containing header and transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    /// The block header
    pub header: BlockHeader,
    /// The transactions in this block
    pub transactions: Vec<SignedTransaction>,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            header: BlockHeader::default(),
            transactions: Vec::new(),
        }
    }
}

impl Block {
    /// Creates a new block with the given header and transactions.
    pub fn new(header: BlockHeader, transactions: Vec<SignedTransaction>) -> Self {
        Self {
            header,
            transactions,
        }
    }

    /// Creates an empty block with the given header.
    pub fn empty(header: BlockHeader) -> Self {
        Self::new(header, Vec::new())
    }

    /// Returns the block hash (hash of the header).
    pub fn hash(&self) -> H256 {
        self.header.hash()
    }

    /// Returns the block height.
    pub fn height(&self) -> u64 {
        self.header.height
    }

    /// Returns the parent hash.
    pub fn parent_hash(&self) -> H256 {
        self.header.parent_hash
    }

    /// Returns the number of transactions in the block.
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }

    /// Checks if the block has any transactions.
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Computes the transactions merkle root.
    ///
    /// For simplicity, this uses a simple hash of concatenated tx hashes.
    /// A production implementation would use a proper Merkle tree.
    pub fn compute_transactions_root(&self) -> H256 {
        if self.transactions.is_empty() {
            return H256::NIL;
        }

        let mut hasher = Keccak256::new();
        for tx in &self.transactions {
            hasher.update(tx.hash().as_bytes());
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        H256::from(bytes)
    }

    /// Validates that the transactions root matches the computed root.
    pub fn validate_transactions_root(&self) -> bool {
        self.header.transactions_root == self.compute_transactions_root()
    }

    /// RLP encodes the block.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(2);
        stream.append(&self.header);

        stream.begin_list(self.transactions.len());
        for tx in &self.transactions {
            stream.append_raw(&tx.rlp_encode(), 1);
        }

        stream.out().to_vec()
    }

    /// Decodes a block from RLP bytes.
    pub fn rlp_decode(data: &[u8]) -> Result<Self> {
        let rlp = Rlp::new(data);

        if rlp.item_count().map_err(Error::RlpDecode)? != 2 {
            return Err(Error::InvalidTransaction("invalid block RLP".into()));
        }

        let header: BlockHeader = rlp.val_at(0).map_err(Error::RlpDecode)?;

        let tx_rlp = rlp.at(1).map_err(Error::RlpDecode)?;
        let tx_count = tx_rlp.item_count().map_err(Error::RlpDecode)?;

        let mut transactions = Vec::with_capacity(tx_count);
        for i in 0..tx_count {
            let tx_data = tx_rlp.at(i).map_err(Error::RlpDecode)?.as_raw();
            let tx = SignedTransaction::rlp_decode(tx_data)?;
            transactions.push(tx);
        }

        Ok(Self {
            header,
            transactions,
        })
    }

    /// Creates a genesis block.
    pub fn genesis(chain_id: u64, state_root: H256, timestamp: u64) -> Self {
        Self {
            header: BlockHeader::genesis(chain_id, state_root, timestamp),
            transactions: Vec::new(),
        }
    }
}

impl fmt::Display for Block {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Block #{} (hash: {}, {} txs)",
            self.header.height,
            self.hash(),
            self.transactions.len()
        )
    }
}

/// A finality certificate proving that a block has been finalized.
///
/// This contains an aggregated BLS signature from 2f+1 validators
/// (where f is the maximum number of Byzantine validators).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FinalityCert {
    /// Block height
    pub height: u64,
    /// Hash of the finalized block
    pub block_hash: H256,
    /// Aggregated BLS signature from validators
    #[serde(with = "hex_bytes")]
    pub aggregate_signature: Vec<u8>,
    /// Bitmap indicating which validators signed
    #[serde(with = "hex_bytes")]
    pub signers_bitmap: Vec<u8>,
}

impl FinalityCert {
    /// Creates a new finality certificate.
    pub fn new(
        height: u64,
        block_hash: H256,
        aggregate_signature: Vec<u8>,
        signers_bitmap: Vec<u8>,
    ) -> Self {
        Self {
            height,
            block_hash,
            aggregate_signature,
            signers_bitmap,
        }
    }

    /// Returns the hash of this finality certificate.
    pub fn hash(&self) -> H256 {
        let mut hasher = Keccak256::new();
        hasher.update(&self.height.to_le_bytes());
        hasher.update(self.block_hash.as_bytes());
        hasher.update(&self.aggregate_signature);
        hasher.update(&self.signers_bitmap);
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        H256::from(bytes)
    }

    /// Returns the list of validator indices that signed.
    pub fn get_signers(&self) -> Vec<u64> {
        let mut signers = Vec::new();
        for (byte_idx, byte) in self.signers_bitmap.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    signers.push((byte_idx * 8 + bit) as u64);
                }
            }
        }
        signers
    }

    /// Returns the number of validators that signed.
    pub fn signer_count(&self) -> usize {
        self.signers_bitmap
            .iter()
            .map(|b| b.count_ones() as usize)
            .sum()
    }

    /// Checks if a specific validator signed.
    pub fn has_signed(&self, validator_id: u64) -> bool {
        let byte_idx = (validator_id / 8) as usize;
        let bit_idx = (validator_id % 8) as usize;

        if byte_idx >= self.signers_bitmap.len() {
            return false;
        }

        self.signers_bitmap[byte_idx] & (1 << bit_idx) != 0
    }
}

impl Encodable for FinalityCert {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(4);
        s.append(&self.height);
        s.append(&self.block_hash);
        s.append(&self.aggregate_signature);
        s.append(&self.signers_bitmap);
    }
}

impl Decodable for FinalityCert {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 4 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        Ok(Self {
            height: rlp.val_at(0)?,
            block_hash: rlp.val_at(1)?,
            aggregate_signature: rlp.val_at(2)?,
            signers_bitmap: rlp.val_at(3)?,
        })
    }
}

/// Serde helper for serializing bytes as hex.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

