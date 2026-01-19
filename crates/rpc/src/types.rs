//! RPC request and response types.
//!
//! This module defines all the types used in the JSON-RPC API,
//! with proper hex encoding for Ethereum compatibility.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

// ============================================================================
// Block Number or Tag
// ============================================================================

/// Block identifier - can be a number or a tag like "latest", "pending", "earliest".
///
/// This is used throughout the Ethereum JSON-RPC API to specify which block
/// state to query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockNumberOrTag {
    /// The latest mined block
    Latest,
    /// The pending state (not yet mined)
    Pending,
    /// The earliest/genesis block
    Earliest,
    /// A specific block number
    Number(u64),
    /// Safe block (finalized by consensus)
    Safe,
    /// Finalized block (irreversible)
    Finalized,
}

impl Default for BlockNumberOrTag {
    fn default() -> Self {
        Self::Latest
    }
}

impl FromStr for BlockNumberOrTag {
    type Err = crate::RpcError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "latest" => Ok(Self::Latest),
            "pending" => Ok(Self::Pending),
            "earliest" => Ok(Self::Earliest),
            "safe" => Ok(Self::Safe),
            "finalized" => Ok(Self::Finalized),
            _ => {
                // Try to parse as hex number
                let s = s.strip_prefix("0x").unwrap_or(s);
                u64::from_str_radix(s, 16)
                    .map(Self::Number)
                    .map_err(|_| crate::RpcError::InvalidBlock(format!("invalid block: {}", s)))
            }
        }
    }
}

impl fmt::Display for BlockNumberOrTag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Latest => write!(f, "latest"),
            Self::Pending => write!(f, "pending"),
            Self::Earliest => write!(f, "earliest"),
            Self::Safe => write!(f, "safe"),
            Self::Finalized => write!(f, "finalized"),
            Self::Number(n) => write!(f, "0x{:x}", n),
        }
    }
}

impl Serialize for BlockNumberOrTag {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for BlockNumberOrTag {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_str(&s).map_err(serde::de::Error::custom)
    }
}

// ============================================================================
// Hex-encoded types
// ============================================================================

/// A hex-encoded unsigned 64-bit integer (quantity).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HexU64(pub u64);

impl From<u64> for HexU64 {
    fn from(v: u64) -> Self {
        Self(v)
    }
}

impl From<HexU64> for u64 {
    fn from(v: HexU64) -> Self {
        v.0
    }
}

impl Serialize for HexU64 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for HexU64 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        u64::from_str_radix(s, 16)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A hex-encoded unsigned 128-bit integer (for large quantities like balances).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct HexU128(pub u128);

impl From<u128> for HexU128 {
    fn from(v: u128) -> Self {
        Self(v)
    }
}

impl From<HexU128> for u128 {
    fn from(v: HexU128) -> Self {
        v.0
    }
}

impl Serialize for HexU128 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{:x}", self.0))
    }
}

impl<'de> Deserialize<'de> for HexU128 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        u128::from_str_radix(s, 16)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// A hex-encoded 256-bit integer (for values, gas limits, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HexU256(pub [u8; 32]);

impl HexU256 {
    /// Create from a u128 value.
    pub fn from_u128(v: u128) -> Self {
        let mut bytes = [0u8; 32];
        bytes[16..].copy_from_slice(&v.to_be_bytes());
        Self(bytes)
    }

    /// Create from a u64 value.
    pub fn from_u64(v: u64) -> Self {
        let mut bytes = [0u8; 32];
        bytes[24..].copy_from_slice(&v.to_be_bytes());
        Self(bytes)
    }

    /// Check if the value is zero.
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl Serialize for HexU256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Trim leading zeros for compact representation
        let hex = hex::encode(self.0);
        let trimmed = hex.trim_start_matches('0');
        if trimmed.is_empty() {
            serializer.serialize_str("0x0")
        } else {
            serializer.serialize_str(&format!("0x{}", trimmed))
        }
    }
}

impl<'de> Deserialize<'de> for HexU256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);

        // Pad to 64 hex characters (32 bytes)
        let padded = format!("{:0>64}", s);
        let bytes = hex::decode(&padded).map_err(serde::de::Error::custom)?;

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Hex-encoded bytes (arbitrary length).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HexBytes(pub Vec<u8>);

impl From<Vec<u8>> for HexBytes {
    fn from(v: Vec<u8>) -> Self {
        Self(v)
    }
}

impl From<&[u8]> for HexBytes {
    fn from(v: &[u8]) -> Self {
        Self(v.to_vec())
    }
}

impl Serialize for HexBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(&self.0)))
    }
}

impl<'de> Deserialize<'de> for HexBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s)
            .map(Self)
            .map_err(serde::de::Error::custom)
    }
}

/// 32-byte hash (block hash, transaction hash, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct H256(pub [u8; 32]);

impl H256 {
    /// Zero hash constant.
    pub const ZERO: Self = Self([0u8; 32]);

    /// Create from a slice (must be exactly 32 bytes).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 32 {
            return None;
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(slice);
        Some(Self(arr))
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<[u8; 32]> for H256 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl Serialize for H256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(self.0)))
    }
}

impl<'de> Deserialize<'de> for H256 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// 20-byte address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Hash)]
pub struct Address(pub [u8; 20]);

impl Address {
    /// Zero address constant.
    pub const ZERO: Self = Self([0u8; 20]);

    /// Create from a slice (must be exactly 20 bytes).
    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != 20 {
            return None;
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(slice);
        Some(Self(arr))
    }

    /// Get as bytes.
    pub fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }
}

impl From<[u8; 20]> for Address {
    fn from(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Use checksummed format for addresses
        let hex_addr = hex::encode(self.0);
        let hash = sha3_keccak256(hex_addr.as_bytes());

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                let hash_byte = hash[i / 2];
                let hash_nibble = if i % 2 == 0 {
                    hash_byte >> 4
                } else {
                    hash_byte & 0x0F
                };
                if hash_nibble >= 8 {
                    result.push(c.to_ascii_uppercase());
                } else {
                    result.push(c.to_ascii_lowercase());
                }
            } else {
                result.push(c);
            }
        }

        serializer.serialize_str(&result)
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 20 {
            return Err(serde::de::Error::custom("expected 20 bytes"));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Simple Keccak256 hash function for checksumming.
pub(crate) fn sha3_keccak256(data: &[u8]) -> [u8; 32] {
    // Keccak256 implementation constants
    const ROUNDS: usize = 24;
    const RC: [u64; 24] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
        0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
        0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
        0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
        0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
        0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
        0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ];

    fn keccak_f(state: &mut [u64; 25]) {
        for round in 0..ROUNDS {
            // Theta
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
            }
            let mut d = [0u64; 5];
            for x in 0..5 {
                d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            }
            for x in 0..5 {
                for y in 0..5 {
                    state[x + 5 * y] ^= d[x];
                }
            }

            // Rho and Pi
            let mut b = [0u64; 25];
            for x in 0..5 {
                for y in 0..5 {
                    let (nx, ny) = (y, (2 * x + 3 * y) % 5);
                    let rot = ((x + 1) * (x + 2) / 2 + y * (y + 1) * 3) % 64;
                    b[nx + 5 * ny] = state[x + 5 * y].rotate_left(rot as u32);
                }
            }

            // Chi
            for x in 0..5 {
                for y in 0..5 {
                    state[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
                }
            }

            // Iota
            state[0] ^= RC[round];
        }
    }

    // Keccak256 uses rate = 1088 bits = 136 bytes
    let rate = 136;
    let mut state = [0u64; 25];

    // Absorb
    let mut pos = 0;
    let mut block = [0u8; 136];

    for &byte in data {
        block[pos] = byte;
        pos += 1;
        if pos == rate {
            for i in 0..(rate / 8) {
                state[i] ^= u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
            }
            keccak_f(&mut state);
            pos = 0;
            block = [0u8; 136];
        }
    }

    // Padding (0x01...0x80)
    block[pos] = 0x01;
    block[rate - 1] |= 0x80;

    for i in 0..(rate / 8) {
        state[i] ^= u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
    }
    keccak_f(&mut state);

    // Squeeze (32 bytes)
    let mut output = [0u8; 32];
    for i in 0..4 {
        output[i * 8..(i + 1) * 8].copy_from_slice(&state[i].to_le_bytes());
    }
    output
}

// ============================================================================
// RPC Block Type
// ============================================================================

/// RPC representation of a block.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcBlock {
    /// Block number
    pub number: HexU64,
    /// Block hash
    pub hash: H256,
    /// Parent block hash
    pub parent_hash: H256,
    /// Nonce (PoW field, always 0 for PoS)
    pub nonce: HexU64,
    /// SHA3 of uncles data
    pub sha3_uncles: H256,
    /// Logs bloom filter
    pub logs_bloom: HexBytes,
    /// Transactions root
    pub transactions_root: H256,
    /// State root
    pub state_root: H256,
    /// Receipts root
    pub receipts_root: H256,
    /// Block miner/proposer address
    pub miner: Address,
    /// Difficulty (always 0 for PoS)
    pub difficulty: HexU64,
    /// Total difficulty (cumulative)
    pub total_difficulty: HexU256,
    /// Extra data (empty for Proto Core)
    pub extra_data: HexBytes,
    /// Block size in bytes
    pub size: HexU64,
    /// Gas limit
    pub gas_limit: HexU64,
    /// Gas used
    pub gas_used: HexU64,
    /// Block timestamp (Unix seconds)
    pub timestamp: HexU64,
    /// Transactions (hashes or full objects)
    pub transactions: Transactions,
    /// Uncle block hashes (always empty for Proto Core)
    pub uncles: Vec<H256>,
    /// Base fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<HexU64>,
    /// Mix hash (PoW field, always 0)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mix_hash: Option<H256>,
    /// Withdrawals root (post-Shanghai, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<H256>,
}

/// Transactions can be either hashes only or full transaction objects.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Transactions {
    /// Transaction hashes only
    Hashes(Vec<H256>),
    /// Full transaction objects
    Full(Vec<RpcTransaction>),
}

// ============================================================================
// RPC Transaction Type
// ============================================================================

/// RPC representation of a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcTransaction {
    /// Transaction hash
    pub hash: H256,
    /// Nonce
    pub nonce: HexU64,
    /// Block hash (null if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<H256>,
    /// Block number (null if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_number: Option<HexU64>,
    /// Transaction index in block (null if pending)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transaction_index: Option<HexU64>,
    /// Sender address
    pub from: Address,
    /// Recipient address (null for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Value transferred in wei
    pub value: HexU256,
    /// Gas price (legacy and EIP-2930)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<HexU64>,
    /// Gas limit
    pub gas: HexU64,
    /// Input data
    pub input: HexBytes,
    /// ECDSA recovery id
    pub v: HexU64,
    /// ECDSA signature r
    pub r: HexU256,
    /// ECDSA signature s
    pub s: HexU256,
    /// Transaction type (0 = legacy, 1 = EIP-2930, 2 = EIP-1559)
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<HexU64>,
    /// Chain ID (EIP-155)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<HexU64>,
    /// Max fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<HexU64>,
    /// Max priority fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<HexU64>,
    /// Access list (EIP-2930)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<AccessListEntry>>,
}

/// Access list entry (EIP-2930).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccessListEntry {
    /// Account address
    pub address: Address,
    /// Storage keys
    pub storage_keys: Vec<H256>,
}

// ============================================================================
// RPC Receipt Type
// ============================================================================

/// RPC representation of a transaction receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcReceipt {
    /// Transaction hash
    pub transaction_hash: H256,
    /// Transaction index in block
    pub transaction_index: HexU64,
    /// Block hash
    pub block_hash: H256,
    /// Block number
    pub block_number: HexU64,
    /// Sender address
    pub from: Address,
    /// Recipient address (null for contract creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Cumulative gas used in block
    pub cumulative_gas_used: HexU64,
    /// Effective gas price
    pub effective_gas_price: HexU64,
    /// Gas used by this transaction
    pub gas_used: HexU64,
    /// Contract address created (if any)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_address: Option<Address>,
    /// Logs emitted by this transaction
    pub logs: Vec<RpcLog>,
    /// Logs bloom filter
    pub logs_bloom: HexBytes,
    /// Transaction type
    #[serde(rename = "type")]
    pub tx_type: HexU64,
    /// Status (1 = success, 0 = failure)
    pub status: HexU64,
}

/// RPC representation of a log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RpcLog {
    /// Address that emitted the log
    pub address: Address,
    /// Indexed topics
    pub topics: Vec<H256>,
    /// Non-indexed data
    pub data: HexBytes,
    /// Block number
    pub block_number: HexU64,
    /// Transaction hash
    pub transaction_hash: H256,
    /// Transaction index in block
    pub transaction_index: HexU64,
    /// Block hash
    pub block_hash: H256,
    /// Log index in block
    pub log_index: HexU64,
    /// Whether this log was removed due to reorg
    pub removed: bool,
}

// ============================================================================
// Call Request (for eth_call and eth_estimateGas)
// ============================================================================

/// Request parameters for eth_call and eth_estimateGas.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct CallRequest {
    /// Sender address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from: Option<Address>,
    /// Recipient address
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to: Option<Address>,
    /// Gas limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas: Option<HexU64>,
    /// Gas price (legacy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_price: Option<HexU64>,
    /// Max fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fee_per_gas: Option<HexU64>,
    /// Max priority fee per gas (EIP-1559)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_priority_fee_per_gas: Option<HexU64>,
    /// Value to send
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<HexU256>,
    /// Input data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<HexBytes>,
    /// Input data (alias for `data`)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<HexBytes>,
    /// Nonce
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<HexU64>,
    /// Access list
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_list: Option<Vec<AccessListEntry>>,
    /// Transaction type
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub tx_type: Option<HexU64>,
}

impl CallRequest {
    /// Get the input data (prefers `input` over `data`).
    pub fn get_input(&self) -> Option<&HexBytes> {
        self.input.as_ref().or(self.data.as_ref())
    }
}

// ============================================================================
// Log Filter (for eth_getLogs)
// ============================================================================

/// Filter parameters for eth_getLogs and eth_newFilter.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LogFilter {
    /// Start block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub from_block: Option<BlockNumberOrTag>,
    /// End block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub to_block: Option<BlockNumberOrTag>,
    /// Contract address(es) to filter
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<AddressFilter>,
    /// Topics to filter (up to 4)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub topics: Option<Vec<Option<TopicFilter>>>,
    /// Block hash (alternative to from_block/to_block)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_hash: Option<H256>,
}

/// Address filter - single address or array of addresses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AddressFilter {
    /// Single address
    Single(Address),
    /// Multiple addresses
    Multiple(Vec<Address>),
}

/// Topic filter - single topic, array of topics, or null (any).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum TopicFilter {
    /// Single topic
    Single(H256),
    /// Any of these topics
    Multiple(Vec<H256>),
}

// ============================================================================
// Fee History (EIP-1559)
// ============================================================================

/// Response for eth_feeHistory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeeHistory {
    /// Oldest block number in the range
    pub oldest_block: HexU64,
    /// Base fee per gas for each block
    pub base_fee_per_gas: Vec<HexU64>,
    /// Gas used ratio (0.0-1.0) for each block
    pub gas_used_ratio: Vec<f64>,
    /// Reward percentiles for each block
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reward: Option<Vec<Vec<HexU64>>>,
}

// ============================================================================
// Sync Status
// ============================================================================

/// Sync status response for eth_syncing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SyncStatus {
    /// Not syncing
    NotSyncing(bool),
    /// Syncing progress
    Syncing(SyncProgress),
}

/// Sync progress details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SyncProgress {
    /// Starting block
    pub starting_block: HexU64,
    /// Current block
    pub current_block: HexU64,
    /// Highest block
    pub highest_block: HexU64,
}

