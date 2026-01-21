//! # BLS12-381 Signatures for Consensus
//!
//! This module provides BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 curve.
//! BLS signatures are used in Proto Core's MinBFT consensus for their key property:
//! **signature aggregation** - multiple signatures can be combined into a single signature
//! that verifies against the aggregated public keys.
//!
//! ## Security Features
//!
//! - **Rogue Key Protection**: Proof-of-possession (PoP) required for all BLS keys
//! - **Domain Separation**: Unique tags per message type, includes chain_id
//! - **Canonical Encoding**: Signatures validated for canonical form
//! - **Deterministic Aggregation**: Ordered by public key for consistency
//!
//! ## Why BLS for Consensus?
//!
//! - **Aggregation**: Combine 35+ validator signatures into one 96-byte signature
//! - **Efficiency**: Finality certificates are constant size regardless of validator count
//! - **Security**: 128-bit security level with BLS12-381
//!
//! ## Key Types
//!
//! - `BlsPrivateKey` - Secret key for signing (32 bytes scalar)
//! - `BlsPublicKey` - Public key (48 bytes G1 point)
//! - `BlsSignature` - Signature (96 bytes G2 point)
//! - `BlsProofOfPossession` - Proof that holder knows the private key
//! - `DomainTag` - Message type-specific domain separation
//!
//! ## Example
//!
//! ```rust
//! use protocore_crypto::bls::{BlsPrivateKey, BlsPublicKey, BlsSignature, DomainTag};
//!
//! // Single signature with domain separation
//! let sk = BlsPrivateKey::random();
//! let pk = sk.public_key();
//! let domain = DomainTag::new_proposal("mainnet-1");
//! let sig = sk.sign_with_domain(b"block hash", &domain);
//! assert!(sig.verify_with_domain(b"block hash", &pk, &domain));
//!
//! // Generate proof-of-possession for validator registration
//! let pop = sk.generate_proof_of_possession();
//! assert!(pop.verify(&pk));
//!
//! // Aggregate signatures (for consensus)
//! let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
//! let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
//! let domain = DomainTag::new_prevote("mainnet-1");
//! let message = b"consensus message";
//!
//! let signatures: Vec<_> = keys.iter().map(|k| k.sign_with_domain(message, &domain)).collect();
//! let sig_refs: Vec<_> = signatures.iter().collect();
//!
//! let aggregate = BlsSignature::aggregate_with_domain(&sig_refs, &domain).unwrap();
//! let pk_refs: Vec<_> = pubkeys.iter().collect();
//! assert!(aggregate.verify_aggregate_with_domain(message, &pk_refs, &domain));
//! ```

use crate::{CryptoError, Result};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;

/// Base domain separation tag prefix for Proto Core BLS signatures.
const DST_PREFIX: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_PROTOCORE_";

/// Domain separation tag for legacy/default signing (backwards compatibility).
const DST_LEGACY: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_PROTOCORE_";

/// Domain separation tag for proof-of-possession.
const DST_POP: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_PROTOCORE_POP_";

// ============================================================================
// Domain Separation
// ============================================================================

/// Message types for domain separation.
///
/// Each message type gets a unique domain tag to prevent cross-message
/// signature reuse attacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Block proposal message
    Proposal,
    /// Prevote consensus message
    Prevote,
    /// Precommit consensus message
    Precommit,
    /// Finality certificate
    Finality,
    /// Generic/custom message type
    Custom,
}

impl MessageType {
    /// Get the string tag for this message type.
    pub fn as_tag(&self) -> &'static str {
        match self {
            MessageType::Proposal => "PROPOSAL",
            MessageType::Prevote => "PREVOTE",
            MessageType::Precommit => "PRECOMMIT",
            MessageType::Finality => "FINALITY",
            MessageType::Custom => "CUSTOM",
        }
    }
}

/// Domain separation tag for BLS signatures.
///
/// Format: `PROTOCORE_<MESSAGE_TYPE>_<CHAIN_ID>`
///
/// This ensures signatures are unique per:
/// - Protocol (Proto Core)
/// - Message type (proposal, prevote, precommit, etc.)
/// - Chain (mainnet, testnet, etc.)
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DomainTag {
    /// The message type
    message_type: MessageType,
    /// The chain identifier
    chain_id: String,
    /// Cached full DST bytes
    dst: Vec<u8>,
}

impl DomainTag {
    /// Create a new domain tag.
    ///
    /// # Arguments
    ///
    /// * `message_type` - The type of message being signed
    /// * `chain_id` - The chain identifier (e.g., "mainnet-1", "testnet-2")
    pub fn new(message_type: MessageType, chain_id: impl Into<String>) -> Self {
        let chain_id = chain_id.into();
        let dst = Self::build_dst(&message_type, &chain_id);
        Self {
            message_type,
            chain_id,
            dst,
        }
    }

    /// Create a domain tag for proposal messages.
    pub fn new_proposal(chain_id: impl Into<String>) -> Self {
        Self::new(MessageType::Proposal, chain_id)
    }

    /// Create a domain tag for prevote messages.
    pub fn new_prevote(chain_id: impl Into<String>) -> Self {
        Self::new(MessageType::Prevote, chain_id)
    }

    /// Create a domain tag for precommit messages.
    pub fn new_precommit(chain_id: impl Into<String>) -> Self {
        Self::new(MessageType::Precommit, chain_id)
    }

    /// Create a domain tag for finality certificates.
    pub fn new_finality(chain_id: impl Into<String>) -> Self {
        Self::new(MessageType::Finality, chain_id)
    }

    /// Create a domain tag for custom messages.
    pub fn new_custom(chain_id: impl Into<String>) -> Self {
        Self::new(MessageType::Custom, chain_id)
    }

    /// Get the message type.
    pub fn message_type(&self) -> MessageType {
        self.message_type
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Get the full DST bytes for signing.
    pub fn dst(&self) -> &[u8] {
        &self.dst
    }

    /// Build the DST bytes from message type and chain ID.
    fn build_dst(message_type: &MessageType, chain_id: &str) -> Vec<u8> {
        let mut dst = Vec::with_capacity(DST_PREFIX.len() + 32 + chain_id.len());
        dst.extend_from_slice(DST_PREFIX);
        dst.extend_from_slice(message_type.as_tag().as_bytes());
        dst.push(b'_');
        dst.extend_from_slice(chain_id.as_bytes());
        dst
    }
}

impl Serialize for DomainTag {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        let mut state = serializer.serialize_struct("DomainTag", 2)?;
        state.serialize_field("message_type", &self.message_type)?;
        state.serialize_field("chain_id", &self.chain_id)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for DomainTag {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct DomainTagHelper {
            message_type: MessageType,
            chain_id: String,
        }
        let helper = DomainTagHelper::deserialize(deserializer)?;
        Ok(Self::new(helper.message_type, helper.chain_id))
    }
}

// ============================================================================
// Proof of Possession
// ============================================================================

/// Proof of Possession (PoP) for a BLS public key.
///
/// A PoP proves that the holder of a public key knows the corresponding
/// private key. This prevents rogue key attacks in BLS aggregation.
///
/// The PoP is a signature over the public key bytes using a dedicated
/// domain separation tag.
#[derive(Clone, PartialEq, Eq)]
pub struct BlsProofOfPossession {
    inner: Signature,
}

impl BlsProofOfPossession {
    /// Create a proof of possession from compressed bytes (96 bytes).
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self> {
        let sig = Signature::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;

        // Validate canonical encoding
        let reencoded = sig.to_bytes();
        if reencoded != *bytes {
            return Err(CryptoError::BlsError(
                "non-canonical signature encoding".to_string(),
            ));
        }

        Ok(Self { inner: sig })
    }

    /// Create a proof of possession from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidLength {
                expected: 96,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Get the compressed bytes (96 bytes).
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.to_bytes()
    }

    /// Get the hex-encoded proof.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Verify the proof of possession against a public key.
    ///
    /// Returns true if this PoP proves knowledge of the private key
    /// corresponding to the given public key.
    pub fn verify(&self, public_key: &BlsPublicKey) -> bool {
        let pk_bytes = public_key.to_bytes();
        let result = self
            .inner
            .verify(true, &pk_bytes, DST_POP, &[], &public_key.inner, true);
        result == BLST_ERROR::BLST_SUCCESS
    }
}

impl std::fmt::Debug for BlsProofOfPossession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsProofOfPossession")
            .field("bytes", &self.to_hex())
            .finish()
    }
}

impl Serialize for BlsProofOfPossession {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for BlsProofOfPossession {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            BlsProofOfPossession::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            if bytes.len() != 96 {
                return Err(serde::de::Error::custom(format!(
                    "expected 96 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&bytes);
            BlsProofOfPossession::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

// ============================================================================
// BLS Private Key
// ============================================================================

/// BLS private key (secret key)
///
/// A 32-byte scalar used for signing. Must be kept secret.
pub struct BlsPrivateKey {
    inner: SecretKey,
}

impl BlsPrivateKey {
    /// Generate a random BLS private key using a cryptographically secure RNG.
    pub fn random() -> Self {
        let mut ikm = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut ikm);
        // Use key derivation with random IKM
        let sk = SecretKey::key_gen(&ikm, &[]).expect("key generation failed");
        Self { inner: sk }
    }

    /// Create a BLS private key from a 32-byte seed.
    ///
    /// Uses BLS key derivation (IKM -> secret key).
    ///
    /// # Arguments
    ///
    /// * `ikm` - Input keying material (at least 32 bytes recommended)
    pub fn from_seed(ikm: &[u8]) -> Result<Self> {
        if ikm.len() < 32 {
            return Err(CryptoError::InvalidLength {
                expected: 32,
                actual: ikm.len(),
            });
        }
        let sk = SecretKey::key_gen(ikm, &[])
            .map_err(|_| CryptoError::InvalidPrivateKey("key generation failed".to_string()))?;
        Ok(Self { inner: sk })
    }

    /// Create a BLS private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte scalar in big-endian format
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let sk = SecretKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPrivateKey(format!("{:?}", e)))?;
        Ok(Self { inner: sk })
    }

    /// Create a BLS private key from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Get the raw bytes of the private key.
    ///
    /// # Security
    ///
    /// Be careful with the returned bytes - they are the secret key!
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    /// Get the hex-encoded private key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Derive the public key from this private key.
    pub fn public_key(&self) -> BlsPublicKey {
        let pk = self.inner.sk_to_pk();
        BlsPublicKey { inner: pk }
    }

    /// Generate a proof of possession for this key.
    ///
    /// The PoP proves that we know the private key corresponding to our public key.
    /// This should be generated once when creating a validator key and stored
    /// with the validator record.
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_crypto::bls::BlsPrivateKey;
    ///
    /// let sk = BlsPrivateKey::random();
    /// let pk = sk.public_key();
    /// let pop = sk.generate_proof_of_possession();
    ///
    /// // Verify the PoP
    /// assert!(pop.verify(&pk));
    /// ```
    pub fn generate_proof_of_possession(&self) -> BlsProofOfPossession {
        let pk = self.public_key();
        let pk_bytes = pk.to_bytes();
        let sig = self.inner.sign(&pk_bytes, DST_POP, &[]);
        BlsProofOfPossession { inner: sig }
    }

    /// Sign a message with domain separation.
    ///
    /// This is the recommended signing method for production use.
    /// It ensures signatures cannot be replayed across different
    /// message types or chains.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    /// * `domain` - The domain tag specifying message type and chain
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_crypto::bls::{BlsPrivateKey, DomainTag};
    ///
    /// let sk = BlsPrivateKey::random();
    /// let domain = DomainTag::new_prevote("mainnet-1");
    /// let sig = sk.sign_with_domain(b"block hash", &domain);
    /// ```
    pub fn sign_with_domain(&self, message: &[u8], domain: &DomainTag) -> BlsSignature {
        let sig = self.inner.sign(message, domain.dst(), &[]);
        BlsSignature {
            inner: sig,
            domain: Some(domain.clone()),
        }
    }

    /// Sign a message using the legacy domain separation tag.
    ///
    /// **Warning**: Prefer `sign_with_domain` for new code.
    /// This method exists for backwards compatibility.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig = self.inner.sign(message, DST_LEGACY, &[]);
        BlsSignature {
            inner: sig,
            domain: None,
        }
    }
}

impl Clone for BlsPrivateKey {
    fn clone(&self) -> Self {
        let bytes = self.to_bytes();
        Self::from_bytes(&bytes).expect("cloning valid key should succeed")
    }
}

impl std::fmt::Debug for BlsPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsPrivateKey")
            .field("public_key", &self.public_key().to_hex())
            .finish()
    }
}

/// BLS public key (48 bytes, G1 point)
///
/// Used for verifying signatures and can be aggregated with other public keys.
/// Implements Ord for deterministic ordering in aggregation.
#[derive(Clone)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

impl BlsPublicKey {
    /// Create a public key from compressed bytes (48 bytes).
    ///
    /// Validates that the bytes represent a valid point on the curve
    /// and are in canonical form.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 48-byte compressed G1 point
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self> {
        let pk = PublicKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))?;

        // Validate canonical encoding
        let reencoded = pk.to_bytes();
        if reencoded != *bytes {
            return Err(CryptoError::BlsError(
                "non-canonical public key encoding".to_string(),
            ));
        }

        Ok(Self { inner: pk })
    }

    /// Create a public key from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 48 {
            return Err(CryptoError::InvalidLength {
                expected: 48,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 48];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Get the compressed public key bytes (48 bytes).
    pub fn to_bytes(&self) -> [u8; 48] {
        self.inner.to_bytes()
    }

    /// Get the hex-encoded public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Verify a signature against a message using the legacy DST.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        signature.verify(message, self)
    }

    /// Verify a signature with domain separation.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    /// * `domain` - The domain tag used for signing
    pub fn verify_with_domain(
        &self,
        message: &[u8],
        signature: &BlsSignature,
        domain: &DomainTag,
    ) -> bool {
        signature.verify_with_domain(message, self, domain)
    }

    /// Aggregate multiple public keys into one.
    ///
    /// The resulting public key can be used to verify an aggregated signature
    /// that was created from signatures by the corresponding private keys.
    ///
    /// # Arguments
    ///
    /// * `pubkeys` - Public keys to aggregate
    pub fn aggregate(pubkeys: &[&BlsPublicKey]) -> Result<Self> {
        if pubkeys.is_empty() {
            return Err(CryptoError::BlsError(
                "cannot aggregate empty list".to_string(),
            ));
        }

        let pks: Vec<&PublicKey> = pubkeys.iter().map(|pk| &pk.inner).collect();
        let agg = AggregatePublicKey::aggregate(&pks, false)
            .map_err(|e| CryptoError::BlsError(format!("aggregation failed: {:?}", e)))?;

        Ok(Self {
            inner: agg.to_public_key(),
        })
    }

    /// Aggregate public keys in deterministic (sorted) order.
    ///
    /// This ensures the same set of public keys always produces the same
    /// aggregated key, regardless of input order.
    ///
    /// # Arguments
    ///
    /// * `pubkeys` - Public keys to aggregate (will be sorted internally)
    pub fn aggregate_sorted(pubkeys: &[&BlsPublicKey]) -> Result<Self> {
        if pubkeys.is_empty() {
            return Err(CryptoError::BlsError(
                "cannot aggregate empty list".to_string(),
            ));
        }

        // Sort by bytes for deterministic ordering
        let mut sorted: Vec<&BlsPublicKey> = pubkeys.to_vec();
        sorted.sort();

        let pks: Vec<&PublicKey> = sorted.iter().map(|pk| &pk.inner).collect();
        let agg = AggregatePublicKey::aggregate(&pks, false)
            .map_err(|e| CryptoError::BlsError(format!("aggregation failed: {:?}", e)))?;

        Ok(Self {
            inner: agg.to_public_key(),
        })
    }
}

impl PartialEq for BlsPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsPublicKey {}

impl PartialOrd for BlsPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BlsPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_bytes().cmp(&other.to_bytes())
    }
}

impl std::hash::Hash for BlsPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.to_bytes().hash(state);
    }
}

impl std::fmt::Debug for BlsPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsPublicKey")
            .field("bytes", &self.to_hex())
            .finish()
    }
}

impl Serialize for BlsPublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for BlsPublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            BlsPublicKey::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            if bytes.len() != 48 {
                return Err(serde::de::Error::custom(format!(
                    "expected 48 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 48];
            arr.copy_from_slice(&bytes);
            BlsPublicKey::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

// ============================================================================
// BLS Signature
// ============================================================================

/// BLS signature (96 bytes, G2 point)
///
/// Can be aggregated with other signatures for efficient verification.
/// Optionally tracks the domain used for signing to prevent cross-domain aggregation.
#[derive(Clone)]
pub struct BlsSignature {
    inner: Signature,
    /// The domain tag used for signing, if domain-aware signing was used.
    /// None indicates legacy signing without domain separation.
    domain: Option<DomainTag>,
}

impl BlsSignature {
    /// Create a signature from compressed bytes (96 bytes).
    ///
    /// Validates canonical encoding to prevent malleability attacks.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 96-byte compressed G2 point
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self> {
        let sig = Signature::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;

        // Validate canonical encoding to prevent malleability
        let reencoded = sig.to_bytes();
        if reencoded != *bytes {
            return Err(CryptoError::BlsError(
                "non-canonical signature encoding".to_string(),
            ));
        }

        Ok(Self {
            inner: sig,
            domain: None,
        })
    }

    /// Create a signature from bytes with a specific domain.
    pub fn from_bytes_with_domain(bytes: &[u8; 96], domain: DomainTag) -> Result<Self> {
        let mut sig = Self::from_bytes(bytes)?;
        sig.domain = Some(domain);
        Ok(sig)
    }

    /// Create a signature from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 96 {
            return Err(CryptoError::InvalidLength {
                expected: 96,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 96];
        arr.copy_from_slice(&bytes);
        Self::from_bytes(&arr)
    }

    /// Get the compressed signature bytes (96 bytes).
    pub fn to_bytes(&self) -> [u8; 96] {
        self.inner.to_bytes()
    }

    /// Get the hex-encoded signature.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Get the domain tag, if any.
    pub fn domain(&self) -> Option<&DomainTag> {
        self.domain.as_ref()
    }

    /// Verify the signature against a message and public key using legacy DST.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `public_key` - The public key to verify against
    pub fn verify(&self, message: &[u8], public_key: &BlsPublicKey) -> bool {
        let result = self
            .inner
            .verify(true, message, DST_LEGACY, &[], &public_key.inner, true);
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify the signature with domain separation.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `public_key` - The public key to verify against
    /// * `domain` - The domain tag used for signing
    pub fn verify_with_domain(
        &self,
        message: &[u8],
        public_key: &BlsPublicKey,
        domain: &DomainTag,
    ) -> bool {
        let result = self
            .inner
            .verify(true, message, domain.dst(), &[], &public_key.inner, true);
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Aggregate multiple signatures into one (legacy, no domain check).
    ///
    /// All signatures must be on the SAME message for aggregation to be meaningful.
    /// The resulting signature can be verified against the aggregated public keys.
    ///
    /// **Warning**: Prefer `aggregate_with_domain` for production use.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Signatures to aggregate
    pub fn aggregate(signatures: &[&BlsSignature]) -> Result<Self> {
        if signatures.is_empty() {
            return Err(CryptoError::BlsError(
                "cannot aggregate empty list".to_string(),
            ));
        }

        let sigs: Vec<&Signature> = signatures.iter().map(|s| &s.inner).collect();
        let agg = AggregateSignature::aggregate(&sigs, false)
            .map_err(|e| CryptoError::BlsError(format!("aggregation failed: {:?}", e)))?;

        Ok(Self {
            inner: agg.to_signature(),
            domain: None,
        })
    }

    /// Aggregate signatures with domain verification.
    ///
    /// This is the recommended method for production use. It ensures all
    /// signatures were created with the same domain tag, preventing
    /// cross-domain aggregation attacks.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Signatures to aggregate (must all have the same domain)
    /// * `expected_domain` - The domain all signatures should match
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The signature list is empty
    /// - Any signature has a different domain than expected
    /// - Any signature has no domain (was created with legacy signing)
    pub fn aggregate_with_domain(
        signatures: &[&BlsSignature],
        expected_domain: &DomainTag,
    ) -> Result<Self> {
        if signatures.is_empty() {
            return Err(CryptoError::BlsError(
                "cannot aggregate empty list".to_string(),
            ));
        }

        // Verify all signatures have the expected domain
        for (i, sig) in signatures.iter().enumerate() {
            match &sig.domain {
                Some(domain) if domain == expected_domain => {}
                Some(domain) => {
                    return Err(CryptoError::BlsError(format!(
                        "signature {} has mismatched domain: expected {:?}, got {:?}",
                        i,
                        expected_domain.message_type(),
                        domain.message_type()
                    )));
                }
                None => {
                    return Err(CryptoError::BlsError(format!(
                        "signature {} has no domain (legacy signature cannot be aggregated with domain-aware signatures)",
                        i
                    )));
                }
            }
        }

        let sigs: Vec<&Signature> = signatures.iter().map(|s| &s.inner).collect();
        let agg = AggregateSignature::aggregate(&sigs, false)
            .map_err(|e| CryptoError::BlsError(format!("aggregation failed: {:?}", e)))?;

        Ok(Self {
            inner: agg.to_signature(),
            domain: Some(expected_domain.clone()),
        })
    }

    /// Verify an aggregated signature against multiple public keys (legacy).
    ///
    /// All signers must have signed the SAME message for this to verify.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that all signers signed
    /// * `public_keys` - The public keys of all signers
    pub fn verify_aggregate(&self, message: &[u8], public_keys: &[&BlsPublicKey]) -> bool {
        if public_keys.is_empty() {
            return false;
        }

        // Aggregate the public keys
        let pks: Vec<&PublicKey> = public_keys.iter().map(|pk| &pk.inner).collect();
        let agg_pk = match AggregatePublicKey::aggregate(&pks, false) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Verify against aggregated public key
        let result = self.inner.verify(
            true,
            message,
            DST_LEGACY,
            &[],
            &agg_pk.to_public_key(),
            true,
        );
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify an aggregated signature with domain separation.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that all signers signed
    /// * `public_keys` - The public keys of all signers
    /// * `domain` - The domain tag used for signing
    pub fn verify_aggregate_with_domain(
        &self,
        message: &[u8],
        public_keys: &[&BlsPublicKey],
        domain: &DomainTag,
    ) -> bool {
        if public_keys.is_empty() {
            return false;
        }

        // Aggregate the public keys
        let pks: Vec<&PublicKey> = public_keys.iter().map(|pk| &pk.inner).collect();
        let agg_pk = match AggregatePublicKey::aggregate(&pks, false) {
            Ok(pk) => pk,
            Err(_) => return false,
        };

        // Verify against aggregated public key with domain
        let result = self.inner.verify(
            true,
            message,
            domain.dst(),
            &[],
            &agg_pk.to_public_key(),
            true,
        );
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify aggregated signature using fast aggregate verification (legacy).
    ///
    /// This is optimized for the case where all signers signed the same message.
    /// It's faster than aggregating public keys separately.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that all signers signed
    /// * `public_keys` - The public keys of all signers (as raw 48-byte arrays)
    pub fn fast_aggregate_verify(&self, message: &[u8], public_keys: &[[u8; 48]]) -> bool {
        if public_keys.is_empty() {
            return false;
        }

        // Convert byte arrays to PublicKey objects
        let pks: std::result::Result<Vec<PublicKey>, _> = public_keys
            .iter()
            .map(|bytes| PublicKey::from_bytes(bytes))
            .collect();

        let pks = match pks {
            Ok(pks) => pks,
            Err(_) => return false,
        };

        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        let result = self
            .inner
            .fast_aggregate_verify(true, message, DST_LEGACY, &pk_refs);
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify aggregated signature using fast aggregate verification with domain.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that all signers signed
    /// * `public_keys` - The public keys of all signers (as raw 48-byte arrays)
    /// * `domain` - The domain tag used for signing
    pub fn fast_aggregate_verify_with_domain(
        &self,
        message: &[u8],
        public_keys: &[[u8; 48]],
        domain: &DomainTag,
    ) -> bool {
        if public_keys.is_empty() {
            return false;
        }

        // Convert byte arrays to PublicKey objects
        let pks: std::result::Result<Vec<PublicKey>, _> = public_keys
            .iter()
            .map(|bytes| PublicKey::from_bytes(bytes))
            .collect();

        let pks = match pks {
            Ok(pks) => pks,
            Err(_) => return false,
        };

        let pk_refs: Vec<&PublicKey> = pks.iter().collect();

        let result = self
            .inner
            .fast_aggregate_verify(true, message, domain.dst(), &pk_refs);
        result == BLST_ERROR::BLST_SUCCESS
    }
}

impl PartialEq for BlsSignature {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsSignature {}

impl Default for BlsSignature {
    /// Create a default (placeholder) signature.
    ///
    /// Note: This creates a signature by signing empty data with a random key.
    /// It should only be used as a placeholder that will be replaced.
    fn default() -> Self {
        // Create a valid but meaningless signature for initialization
        let sk = BlsPrivateKey::from_seed(&[0u8; 32]).expect("seed should work");
        sk.sign(b"")
    }
}

impl std::fmt::Debug for BlsSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlsSignature")
            .field("bytes", &self.to_hex())
            .finish()
    }
}

impl Serialize for BlsSignature {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_bytes();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for BlsSignature {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            BlsSignature::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            if bytes.len() != 96 {
                return Err(serde::de::Error::custom(format!(
                    "expected 96 bytes, got {}",
                    bytes.len()
                )));
            }
            let mut arr = [0u8; 96];
            arr.copy_from_slice(&bytes);
            BlsSignature::from_bytes(&arr).map_err(serde::de::Error::custom)
        }
    }
}

/// Verify an aggregated BLS signature against multiple public keys.
///
/// This is a convenience function that wraps `BlsSignature::verify_aggregate`.
///
/// # Arguments
///
/// * `pubkeys` - Slice of 48-byte public key arrays
/// * `message` - The message that was signed
/// * `signature` - The 96-byte aggregated signature
pub fn bls_verify_aggregate(
    pubkeys: &[[u8; 48]],
    message: &[u8; 32],
    signature: &[u8; 96],
) -> bool {
    let sig = match BlsSignature::from_bytes(signature) {
        Ok(s) => s,
        Err(_) => return false,
    };

    sig.fast_aggregate_verify(message, pubkeys)
}

/// Aggregate multiple BLS signatures into one.
///
/// # Arguments
///
/// * `signatures` - Slice of 96-byte signature arrays
///
/// # Returns
///
/// The aggregated 96-byte signature, or None if aggregation fails.
pub fn bls_aggregate(signatures: &[[u8; 96]]) -> Option<[u8; 96]> {
    if signatures.is_empty() {
        return None;
    }

    let sigs: std::result::Result<Vec<BlsSignature>, _> =
        signatures.iter().map(BlsSignature::from_bytes).collect();

    let sigs = sigs.ok()?;
    let sig_refs: Vec<&BlsSignature> = sigs.iter().collect();

    let aggregate = BlsSignature::aggregate(&sig_refs).ok()?;
    Some(aggregate.to_bytes())
}

// ============================================================================
// Validator Key Pair
// ============================================================================

/// A complete BLS key pair for a validator, including proof-of-possession.
///
/// This is the recommended type for validator key management. It ensures
/// that every validator key has a valid proof-of-possession, preventing
/// rogue key attacks.
///
/// # Example
///
/// ```rust
/// use protocore_crypto::bls::{ValidatorKeyPair, DomainTag};
///
/// // Generate a new validator key pair
/// let keypair = ValidatorKeyPair::generate();
///
/// // Verify the PoP (should always succeed for generated keys)
/// assert!(keypair.verify_proof_of_possession());
///
/// // Sign a consensus message
/// let domain = DomainTag::new_prevote("mainnet-1");
/// let sig = keypair.sign_with_domain(b"block hash", &domain);
/// assert!(sig.verify_with_domain(b"block hash", keypair.public_key(), &domain));
/// ```
#[derive(Clone)]
pub struct ValidatorKeyPair {
    private_key: BlsPrivateKey,
    public_key: BlsPublicKey,
    proof_of_possession: BlsProofOfPossession,
}

impl ValidatorKeyPair {
    /// Generate a new random validator key pair with proof-of-possession.
    pub fn generate() -> Self {
        let private_key = BlsPrivateKey::random();
        let public_key = private_key.public_key();
        let proof_of_possession = private_key.generate_proof_of_possession();

        Self {
            private_key,
            public_key,
            proof_of_possession,
        }
    }

    /// Create a validator key pair from an existing private key.
    ///
    /// Generates the proof-of-possession automatically.
    pub fn from_private_key(private_key: BlsPrivateKey) -> Self {
        let public_key = private_key.public_key();
        let proof_of_possession = private_key.generate_proof_of_possession();

        Self {
            private_key,
            public_key,
            proof_of_possession,
        }
    }

    /// Create a validator key pair from components.
    ///
    /// # Arguments
    ///
    /// * `private_key` - The BLS private key
    /// * `proof_of_possession` - Pre-generated proof-of-possession
    ///
    /// # Errors
    ///
    /// Returns an error if the proof-of-possession is invalid.
    pub fn from_components(
        private_key: BlsPrivateKey,
        proof_of_possession: BlsProofOfPossession,
    ) -> Result<Self> {
        let public_key = private_key.public_key();

        // Verify the PoP matches this key
        if !proof_of_possession.verify(&public_key) {
            return Err(CryptoError::BlsError(
                "proof-of-possession verification failed".to_string(),
            ));
        }

        Ok(Self {
            private_key,
            public_key,
            proof_of_possession,
        })
    }

    /// Get the private key.
    pub fn private_key(&self) -> &BlsPrivateKey {
        &self.private_key
    }

    /// Get the public key.
    pub fn public_key(&self) -> &BlsPublicKey {
        &self.public_key
    }

    /// Get the proof-of-possession.
    pub fn proof_of_possession(&self) -> &BlsProofOfPossession {
        &self.proof_of_possession
    }

    /// Verify the proof-of-possession is valid for this key pair.
    pub fn verify_proof_of_possession(&self) -> bool {
        self.proof_of_possession.verify(&self.public_key)
    }

    /// Sign a message with domain separation.
    pub fn sign_with_domain(&self, message: &[u8], domain: &DomainTag) -> BlsSignature {
        self.private_key.sign_with_domain(message, domain)
    }

    /// Sign a message using legacy DST.
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        self.private_key.sign(message)
    }
}

impl std::fmt::Debug for ValidatorKeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ValidatorKeyPair")
            .field("public_key", &self.public_key.to_hex())
            .field("pop_valid", &self.verify_proof_of_possession())
            .finish()
    }
}

// ============================================================================
// Aggregation Helpers
// ============================================================================

/// Aggregate signatures with deterministic ordering based on public keys.
///
/// This function sorts signatures by their corresponding public keys before
/// aggregation, ensuring deterministic results regardless of input order.
///
/// # Arguments
///
/// * `signed_messages` - Tuples of (public key, signature)
/// * `domain` - The expected domain for all signatures
///
/// # Returns
///
/// A tuple of (sorted public keys, aggregated signature)
pub fn aggregate_sorted_with_domain(
    signed_messages: &[(&BlsPublicKey, &BlsSignature)],
    domain: &DomainTag,
) -> Result<(Vec<BlsPublicKey>, BlsSignature)> {
    if signed_messages.is_empty() {
        return Err(CryptoError::BlsError(
            "cannot aggregate empty list".to_string(),
        ));
    }

    // Sort by public key for deterministic ordering
    let mut sorted: Vec<(&BlsPublicKey, &BlsSignature)> = signed_messages.to_vec();
    sorted.sort_by_key(|(pk, _)| pk.to_bytes());

    // Extract sorted components
    let sorted_pubkeys: Vec<BlsPublicKey> = sorted.iter().map(|(pk, _)| (*pk).clone()).collect();
    let sorted_sigs: Vec<&BlsSignature> = sorted.iter().map(|(_, sig)| *sig).collect();

    // Aggregate with domain verification
    let aggregate = BlsSignature::aggregate_with_domain(&sorted_sigs, domain)?;

    Ok((sorted_pubkeys, aggregate))
}

/// Verify a proof-of-possession for a public key.
///
/// This is a convenience function for verifying PoPs during validator registration.
pub fn verify_proof_of_possession(public_key: &BlsPublicKey, pop: &BlsProofOfPossession) -> bool {
    pop.verify(public_key)
}

/// Batch verify multiple proof-of-possessions.
///
/// Returns true only if ALL proofs are valid.
pub fn batch_verify_proofs_of_possession(
    keys_and_pops: &[(&BlsPublicKey, &BlsProofOfPossession)],
) -> bool {
    keys_and_pops.iter().all(|(pk, pop)| pop.verify(pk))
}
