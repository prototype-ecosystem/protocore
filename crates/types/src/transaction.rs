//! Transaction types including EIP-1559 support.
//!
//! This module provides transaction-related types for Proto Core:
//! - [`Transaction`] - The core transaction structure with EIP-1559 fields
//! - [`SignedTransaction`] - A transaction with signature and computed hash
//! - [`Signature`] - ECDSA signature components (v, r, s)
//! - [`TxType`] - Transaction type enumeration

use crate::{Address, Error, Result, H256};
use bytes::Bytes;
use k256::ecdsa::{RecoveryId, Signature as K256Signature, SigningKey, VerifyingKey};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::fmt;

/// Transaction type identifier (EIP-2718).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[repr(u8)]
pub enum TxType {
    /// Legacy transaction (pre-EIP-2718)
    Legacy = 0x00,
    /// EIP-2930 Access List transaction
    AccessList = 0x01,
    /// EIP-1559 Dynamic Fee transaction (default for Proto Core)
    #[default]
    DynamicFee = 0x02,
}

impl TxType {
    /// Returns the transaction type byte.
    pub const fn as_byte(&self) -> u8 {
        *self as u8
    }

    /// Creates a TxType from a byte.
    pub fn from_byte(byte: u8) -> Result<Self> {
        match byte {
            0x00 => Ok(Self::Legacy),
            0x01 => Ok(Self::AccessList),
            0x02 => Ok(Self::DynamicFee),
            _ => Err(Error::InvalidTransaction(format!(
                "unknown transaction type: 0x{:02x}",
                byte
            ))),
        }
    }
}

/// An access list entry for EIP-2930/EIP-1559 transactions.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct AccessListItem {
    /// The address being accessed
    pub address: Address,
    /// Storage keys being accessed
    pub storage_keys: Vec<H256>,
}

impl Encodable for AccessListItem {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(2);
        s.append(&self.address);
        s.begin_list(self.storage_keys.len());
        for key in &self.storage_keys {
            s.append(key);
        }
    }
}

impl Decodable for AccessListItem {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 2 {
            return Err(DecoderError::RlpIncorrectListLen);
        }
        Ok(Self {
            address: rlp.val_at(0)?,
            storage_keys: rlp.list_at(1)?,
        })
    }
}

/// ECDSA signature components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
pub struct Signature {
    /// Recovery ID (0 or 1, or legacy v value)
    pub v: u64,
    /// R component (32 bytes)
    pub r: H256,
    /// S component (32 bytes)
    pub s: H256,
}

impl Signature {
    /// Creates a new signature from components.
    pub const fn new(v: u64, r: H256, s: H256) -> Self {
        Self { v, r, s }
    }

    /// Returns the recovery ID (0 or 1) for EIP-1559 transactions.
    pub fn recovery_id(&self) -> u8 {
        // For EIP-1559, v is either 0 or 1
        // For legacy, v is 27 or 28, or chainId * 2 + 35/36
        if self.v == 0 || self.v == 1 {
            self.v as u8
        } else if self.v == 27 || self.v == 28 {
            (self.v - 27) as u8
        } else {
            // EIP-155: v = chainId * 2 + 35 + recovery_id
            ((self.v - 35) % 2) as u8
        }
    }

    /// Checks if this is a valid signature (non-zero r and s).
    pub fn is_valid(&self) -> bool {
        !self.r.is_zero() && !self.s.is_zero()
    }

    /// Creates a signature from raw bytes (65 bytes: r[32] || s[32] || v[1]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 65 {
            return Err(Error::InvalidLength {
                expected: 65,
                actual: bytes.len(),
            });
        }
        let r = H256::from_slice(&bytes[0..32])?;
        let s = H256::from_slice(&bytes[32..64])?;
        let v = bytes[64] as u64;
        Ok(Self { v, r, s })
    }

    /// Converts the signature to raw bytes (65 bytes: r[32] || s[32] || v[1]).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(self.r.as_bytes());
        bytes[32..64].copy_from_slice(self.s.as_bytes());
        bytes[64] = self.v as u8;
        bytes
    }
}

/// An EIP-1559 transaction.
///
/// This is the primary transaction format for Proto Core, supporting:
/// - Dynamic fee pricing (base fee + priority fee)
/// - Access lists for gas optimization
/// - Optional recipient (contract creation when None)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction type
    #[serde(default)]
    pub tx_type: TxType,
    /// Chain ID (prevents replay attacks across chains)
    pub chain_id: u64,
    /// Sender nonce (prevents replay attacks)
    pub nonce: u64,
    /// Maximum priority fee per gas (tip to validator)
    pub max_priority_fee_per_gas: u128,
    /// Maximum total fee per gas (base fee + priority fee)
    pub max_fee_per_gas: u128,
    /// Gas limit for this transaction
    pub gas_limit: u64,
    /// Recipient address (None for contract creation)
    pub to: Option<Address>,
    /// Value to transfer in wei
    pub value: u128,
    /// Input data (calldata or contract init code)
    #[serde(with = "hex_bytes")]
    pub data: Bytes,
    /// Access list (addresses and storage keys to warm)
    #[serde(default)]
    pub access_list: Vec<AccessListItem>,
}

impl Default for Transaction {
    fn default() -> Self {
        Self {
            tx_type: TxType::DynamicFee,
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: 0,
            max_fee_per_gas: 0,
            gas_limit: 21000,
            to: None,
            value: 0,
            data: Bytes::new(),
            access_list: Vec::new(),
        }
    }
}

impl Transaction {
    /// Creates a new EIP-1559 transaction.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        chain_id: u64,
        nonce: u64,
        max_priority_fee_per_gas: u128,
        max_fee_per_gas: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: u128,
        data: impl Into<Bytes>,
    ) -> Self {
        Self {
            tx_type: TxType::DynamicFee,
            chain_id,
            nonce,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            gas_limit,
            to,
            value,
            data: data.into(),
            access_list: Vec::new(),
        }
    }

    /// Creates a simple transfer transaction.
    pub fn transfer(chain_id: u64, nonce: u64, to: Address, value: u128) -> Self {
        Self::new(chain_id, nonce, 0, 0, 21000, Some(to), value, Bytes::new())
    }

    /// Creates a contract deployment transaction.
    pub fn deploy(chain_id: u64, nonce: u64, init_code: impl Into<Bytes>, value: u128) -> Self {
        Self::new(chain_id, nonce, 0, 0, 0, None, value, init_code)
    }

    /// Sets the gas fees.
    pub fn with_gas(mut self, gas_limit: u64, max_fee: u128, priority_fee: u128) -> Self {
        self.gas_limit = gas_limit;
        self.max_fee_per_gas = max_fee;
        self.max_priority_fee_per_gas = priority_fee;
        self
    }

    /// Sets the access list.
    pub fn with_access_list(mut self, access_list: Vec<AccessListItem>) -> Self {
        self.access_list = access_list;
        self
    }

    /// Checks if this is a contract creation transaction.
    pub fn is_create(&self) -> bool {
        self.to.is_none()
    }

    /// Returns the effective priority fee given a base fee.
    pub fn effective_priority_fee(&self, base_fee: u128) -> u128 {
        std::cmp::min(
            self.max_priority_fee_per_gas,
            self.max_fee_per_gas.saturating_sub(base_fee),
        )
    }

    /// Returns the effective gas price given a base fee.
    pub fn effective_gas_price(&self, base_fee: u128) -> u128 {
        base_fee + self.effective_priority_fee(base_fee)
    }

    /// Encodes the transaction for signing (without type prefix for the hash).
    fn rlp_encode_for_signing(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(9);
        stream.append(&self.chain_id);
        stream.append(&self.nonce);
        stream.append(&self.max_priority_fee_per_gas);
        stream.append(&self.max_fee_per_gas);
        stream.append(&self.gas_limit);

        match &self.to {
            Some(addr) => stream.append(addr),
            None => stream.append(&""),
        };

        stream.append(&self.value);
        stream.append(&self.data.as_ref());

        // Access list
        stream.begin_list(self.access_list.len());
        for item in &self.access_list {
            stream.append(item);
        }

        stream.out().to_vec()
    }

    /// Returns the signing hash for this transaction (EIP-1559).
    pub fn signing_hash(&self) -> H256 {
        let mut data = Vec::with_capacity(1 + 256);
        data.push(TxType::DynamicFee.as_byte());
        data.extend_from_slice(&self.rlp_encode_for_signing());
        H256::keccak256(&data)
    }

    /// Signs the transaction with the given private key.
    pub fn sign(self, signing_key: &SigningKey) -> Result<SignedTransaction> {
        let hash = self.signing_hash();

        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(hash.as_bytes())
            .map_err(|e| Error::Signature(e.to_string()))?;

        let sig_bytes = signature.to_bytes();
        let r = H256::from_slice(&sig_bytes[0..32])?;
        let s = H256::from_slice(&sig_bytes[32..64])?;
        let v = recovery_id.to_byte() as u64;

        let signature = Signature::new(v, r, s);

        SignedTransaction::new(self, signature)
    }
}

impl Encodable for Transaction {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.begin_list(9);
        s.append(&self.chain_id);
        s.append(&self.nonce);
        s.append(&self.max_priority_fee_per_gas);
        s.append(&self.max_fee_per_gas);
        s.append(&self.gas_limit);

        match &self.to {
            Some(addr) => s.append(addr),
            None => s.append(&""),
        };

        s.append(&self.value);
        s.append(&self.data.as_ref());

        s.begin_list(self.access_list.len());
        for item in &self.access_list {
            s.append(item);
        }
    }
}

impl Decodable for Transaction {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        if rlp.item_count()? != 9 {
            return Err(DecoderError::RlpIncorrectListLen);
        }

        let to_bytes: Vec<u8> = rlp.val_at(5)?;
        let to = if to_bytes.is_empty() {
            None
        } else {
            Some(Address::from_slice(&to_bytes).map_err(|_| DecoderError::RlpInvalidLength)?)
        };

        let data_bytes: Vec<u8> = rlp.val_at(7)?;

        Ok(Self {
            tx_type: TxType::DynamicFee,
            chain_id: rlp.val_at(0)?,
            nonce: rlp.val_at(1)?,
            max_priority_fee_per_gas: rlp.val_at(2)?,
            max_fee_per_gas: rlp.val_at(3)?,
            gas_limit: rlp.val_at(4)?,
            to,
            value: rlp.val_at(6)?,
            data: Bytes::from(data_bytes),
            access_list: rlp.list_at(8)?,
        })
    }
}

/// A signed transaction with its hash and recovered sender.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTransaction {
    /// The transaction data
    pub transaction: Transaction,
    /// The signature
    pub signature: Signature,
    /// The transaction hash (computed)
    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<H256>,
    /// The recovered sender address (computed)
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<Address>,
}

impl SignedTransaction {
    /// Creates a new signed transaction.
    pub fn new(transaction: Transaction, signature: Signature) -> Result<Self> {
        let mut tx = Self {
            transaction,
            signature,
            hash: None,
            from: None,
        };
        // Compute and cache the hash
        tx.hash = Some(tx.compute_hash());
        // Recover and cache the sender
        tx.from = Some(tx.recover_sender()?);
        Ok(tx)
    }

    /// Returns the transaction hash.
    pub fn hash(&self) -> H256 {
        self.hash.unwrap_or_else(|| self.compute_hash())
    }

    /// Computes the transaction hash.
    fn compute_hash(&self) -> H256 {
        let encoded = self.rlp_encode();
        H256::keccak256(&encoded)
    }

    /// RLP encodes the signed transaction.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(12);
        stream.append(&self.transaction.chain_id);
        stream.append(&self.transaction.nonce);
        stream.append(&self.transaction.max_priority_fee_per_gas);
        stream.append(&self.transaction.max_fee_per_gas);
        stream.append(&self.transaction.gas_limit);

        match &self.transaction.to {
            Some(addr) => stream.append(addr),
            None => stream.append(&""),
        };

        stream.append(&self.transaction.value);
        stream.append(&self.transaction.data.as_ref());

        stream.begin_list(self.transaction.access_list.len());
        for item in &self.transaction.access_list {
            stream.append(item);
        }

        stream.append(&self.signature.v);
        stream.append(&self.signature.r);
        stream.append(&self.signature.s);

        let rlp_bytes = stream.out().to_vec();

        // Prepend type byte for EIP-2718
        let mut result = Vec::with_capacity(1 + rlp_bytes.len());
        result.push(TxType::DynamicFee.as_byte());
        result.extend_from_slice(&rlp_bytes);
        result
    }

    /// Decodes a signed transaction from RLP bytes.
    pub fn rlp_decode(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(Error::InvalidTransaction("empty transaction data".into()));
        }

        // Check type byte
        let tx_type = TxType::from_byte(data[0])?;
        if tx_type != TxType::DynamicFee {
            return Err(Error::InvalidTransaction(format!(
                "unsupported transaction type: {:?}",
                tx_type
            )));
        }

        let rlp = Rlp::new(&data[1..]);
        if rlp.item_count()? != 12 {
            return Err(Error::InvalidTransaction("invalid RLP item count".into()));
        }

        let to_bytes: Vec<u8> = rlp.val_at(5).map_err(Error::RlpDecode)?;
        let to = if to_bytes.is_empty() {
            None
        } else {
            Some(Address::from_slice(&to_bytes)?)
        };

        let data_bytes: Vec<u8> = rlp.val_at(7).map_err(Error::RlpDecode)?;

        let transaction = Transaction {
            tx_type: TxType::DynamicFee,
            chain_id: rlp.val_at(0).map_err(Error::RlpDecode)?,
            nonce: rlp.val_at(1).map_err(Error::RlpDecode)?,
            max_priority_fee_per_gas: rlp.val_at(2).map_err(Error::RlpDecode)?,
            max_fee_per_gas: rlp.val_at(3).map_err(Error::RlpDecode)?,
            gas_limit: rlp.val_at(4).map_err(Error::RlpDecode)?,
            to,
            value: rlp.val_at(6).map_err(Error::RlpDecode)?,
            data: Bytes::from(data_bytes),
            access_list: rlp.list_at(8).map_err(Error::RlpDecode)?,
        };

        let v: u64 = rlp.val_at(9).map_err(Error::RlpDecode)?;
        let r: H256 = rlp.val_at(10).map_err(Error::RlpDecode)?;
        let s: H256 = rlp.val_at(11).map_err(Error::RlpDecode)?;

        let signature = Signature::new(v, r, s);

        Self::new(transaction, signature)
    }

    /// Returns the sender address.
    pub fn sender(&self) -> Result<Address> {
        if let Some(from) = self.from {
            return Ok(from);
        }
        self.recover_sender()
    }

    /// Recovers the sender address from the signature.
    fn recover_sender(&self) -> Result<Address> {
        let signing_hash = self.transaction.signing_hash();

        // Reconstruct the signature for recovery
        let mut sig_bytes = [0u8; 64];
        sig_bytes[0..32].copy_from_slice(self.signature.r.as_bytes());
        sig_bytes[32..64].copy_from_slice(self.signature.s.as_bytes());

        let signature = K256Signature::from_bytes((&sig_bytes).into())
            .map_err(|e| Error::Signature(e.to_string()))?;

        let recovery_id = RecoveryId::from_byte(self.signature.recovery_id())
            .ok_or_else(|| Error::Signature("invalid recovery id".into()))?;

        let verifying_key =
            VerifyingKey::recover_from_prehash(signing_hash.as_bytes(), &signature, recovery_id)
                .map_err(|e| Error::Signature(e.to_string()))?;

        // Get the uncompressed public key (65 bytes with 0x04 prefix)
        let pubkey_bytes = verifying_key.to_encoded_point(false);
        let pubkey_uncompressed = pubkey_bytes.as_bytes();

        // Hash the public key (without the 0x04 prefix) to get the address
        let hash = Keccak256::digest(&pubkey_uncompressed[1..]);
        let mut addr_bytes = [0u8; 20];
        addr_bytes.copy_from_slice(&hash[12..32]);

        Ok(Address::from(addr_bytes))
    }

    /// Verifies that the signature is valid.
    pub fn verify(&self) -> Result<bool> {
        self.recover_sender().map(|_| true)
    }

    /// Returns the inner transaction.
    pub fn inner(&self) -> &Transaction {
        &self.transaction
    }

    /// Consumes self and returns the inner transaction.
    pub fn into_inner(self) -> Transaction {
        self.transaction
    }

    // ==========================================================================
    // Forwarding methods for convenience
    // ==========================================================================

    /// Returns the transaction nonce.
    pub fn nonce(&self) -> u64 {
        self.transaction.nonce
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        self.transaction.gas_limit
    }

    /// Returns the max fee per gas.
    pub fn max_fee_per_gas(&self) -> u128 {
        self.transaction.max_fee_per_gas
    }

    /// Returns the max priority fee per gas.
    pub fn max_priority_fee_per_gas(&self) -> u128 {
        self.transaction.max_priority_fee_per_gas
    }

    /// Returns the value being transferred.
    pub fn value(&self) -> u128 {
        self.transaction.value
    }

    /// Returns the chain ID.
    pub fn chain_id(&self) -> Option<u64> {
        Some(self.transaction.chain_id)
    }

    /// Returns the recipient address, if any.
    pub fn to(&self) -> Option<Address> {
        self.transaction.to
    }

    /// Returns the transaction data.
    pub fn data(&self) -> &Bytes {
        &self.transaction.data
    }

    /// Returns the effective gas price given a base fee.
    /// If base_fee is None, uses max_fee_per_gas as the effective price.
    pub fn effective_gas_price(&self, base_fee: Option<u128>) -> u128 {
        match base_fee {
            Some(fee) => self.transaction.effective_gas_price(fee),
            None => self.transaction.max_fee_per_gas,
        }
    }

    /// Returns the access list.
    pub fn access_list(&self) -> &[AccessListItem] {
        &self.transaction.access_list
    }

    /// Returns the estimated encoded size of the transaction.
    pub fn encoded_size(&self) -> usize {
        // Rough estimate: header + transaction fields + signature
        // RLP overhead (type byte + list prefix) + chain_id (9) + nonce (9) +
        // max_priority_fee (9) + max_fee (9) + gas_limit (9) + to (21) +
        // value (9) + data length + access_list overhead + signature (67)
        let base_size = 1 + 9 + 9 + 9 + 9 + 9 + 21 + 9 + 67;
        let data_size = self.transaction.data.len();
        let access_list_size = self.transaction.access_list.len() * 53; // rough estimate
        base_size + data_size + access_list_size
    }
}

impl fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Tx {{ hash: {}, nonce: {}, to: {}, value: {} }}",
            self.hash(),
            self.transaction.nonce,
            self.transaction
                .to
                .map(|a| a.to_string())
                .unwrap_or_else(|| "CREATE".to_string()),
            self.transaction.value
        )
    }
}

/// Serde helper for serializing bytes as hex.
mod hex_bytes {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Bytes, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{}", hex::encode(bytes)))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Bytes, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s)
            .map(Bytes::from)
            .map_err(serde::de::Error::custom)
    }
}
