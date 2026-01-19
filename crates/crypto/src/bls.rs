//! # BLS12-381 Signatures for Consensus
//!
//! This module provides BLS (Boneh-Lynn-Shacham) signatures using the BLS12-381 curve.
//! BLS signatures are used in Proto Core's MinBFT consensus for their key property:
//! **signature aggregation** - multiple signatures can be combined into a single signature
//! that verifies against the aggregated public keys.
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
//!
//! ## Example
//!
//! ```rust
//! use protocore_crypto::bls::{BlsPrivateKey, BlsPublicKey, BlsSignature};
//!
//! // Single signature
//! let sk = BlsPrivateKey::random();
//! let pk = sk.public_key();
//! let sig = sk.sign(b"block hash");
//! assert!(sig.verify(b"block hash", &pk));
//!
//! // Aggregate signatures (for consensus)
//! let keys: Vec<_> = (0..3).map(|_| BlsPrivateKey::random()).collect();
//! let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
//! let message = b"consensus message";
//!
//! let signatures: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
//! let sig_refs: Vec<_> = signatures.iter().collect();
//!
//! let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
//! let pk_refs: Vec<_> = pubkeys.iter().collect();
//! assert!(aggregate.verify_aggregate(message, &pk_refs));
//! ```

use crate::{CryptoError, Result};
use blst::min_pk::{AggregatePublicKey, AggregateSignature, PublicKey, SecretKey, Signature};
use blst::BLST_ERROR;
use rand::RngCore;
use serde::{Deserialize, Serialize};

/// Domain separation tag for Proto Core BLS signatures.
/// This ensures signatures are unique to our protocol.
const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_PROTOCORE_";

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

    /// Sign a message.
    ///
    /// Uses the hash-to-curve algorithm specified by the BLS signature scheme
    /// with our domain separation tag.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    pub fn sign(&self, message: &[u8]) -> BlsSignature {
        let sig = self.inner.sign(message, DST, &[]);
        BlsSignature { inner: sig }
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
#[derive(Clone)]
pub struct BlsPublicKey {
    inner: PublicKey,
}

impl BlsPublicKey {
    /// Create a public key from compressed bytes (48 bytes).
    ///
    /// # Arguments
    ///
    /// * `bytes` - 48-byte compressed G1 point
    pub fn from_bytes(bytes: &[u8; 48]) -> Result<Self> {
        let pk = PublicKey::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(format!("{:?}", e)))?;
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

    /// Verify a signature against a message.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `signature` - The signature to verify
    pub fn verify(&self, message: &[u8], signature: &BlsSignature) -> bool {
        signature.verify(message, self)
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
}

impl PartialEq for BlsPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.to_bytes() == other.to_bytes()
    }
}

impl Eq for BlsPublicKey {}

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

/// BLS signature (96 bytes, G2 point)
///
/// Can be aggregated with other signatures for efficient verification.
#[derive(Clone)]
pub struct BlsSignature {
    inner: Signature,
}

impl BlsSignature {
    /// Create a signature from compressed bytes (96 bytes).
    ///
    /// # Arguments
    ///
    /// * `bytes` - 96-byte compressed G2 point
    pub fn from_bytes(bytes: &[u8; 96]) -> Result<Self> {
        let sig = Signature::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidSignature(format!("{:?}", e)))?;
        Ok(Self { inner: sig })
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

    /// Verify the signature against a message and public key.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that was signed
    /// * `public_key` - The public key to verify against
    pub fn verify(&self, message: &[u8], public_key: &BlsPublicKey) -> bool {
        let result = self.inner.verify(true, message, DST, &[], &public_key.inner, true);
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Aggregate multiple signatures into one.
    ///
    /// All signatures must be on the SAME message for aggregation to be meaningful.
    /// The resulting signature can be verified against the aggregated public keys.
    ///
    /// # Arguments
    ///
    /// * `signatures` - Signatures to aggregate
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_crypto::bls::{BlsPrivateKey, BlsSignature};
    ///
    /// let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    /// let message = b"consensus block";
    ///
    /// let sigs: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
    /// let sig_refs: Vec<_> = sigs.iter().collect();
    ///
    /// let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    /// ```
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
        })
    }

    /// Verify an aggregated signature against multiple public keys.
    ///
    /// All signers must have signed the SAME message for this to verify.
    ///
    /// # Arguments
    ///
    /// * `message` - The message that all signers signed
    /// * `public_keys` - The public keys of all signers
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_crypto::bls::{BlsPrivateKey, BlsSignature};
    ///
    /// let keys: Vec<_> = (0..5).map(|_| BlsPrivateKey::random()).collect();
    /// let pubkeys: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
    /// let message = b"finality cert";
    ///
    /// let sigs: Vec<_> = keys.iter().map(|k| k.sign(message)).collect();
    /// let sig_refs: Vec<_> = sigs.iter().collect();
    /// let aggregate = BlsSignature::aggregate(&sig_refs).unwrap();
    ///
    /// let pk_refs: Vec<_> = pubkeys.iter().collect();
    /// assert!(aggregate.verify_aggregate(message, &pk_refs));
    /// ```
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
        let result = self
            .inner
            .verify(true, message, DST, &[], &agg_pk.to_public_key(), true);
        result == BLST_ERROR::BLST_SUCCESS
    }

    /// Verify aggregated signature using fast aggregate verification.
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
            .fast_aggregate_verify(true, message, DST, &pk_refs);
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
pub fn bls_verify_aggregate(pubkeys: &[[u8; 48]], message: &[u8; 32], signature: &[u8; 96]) -> bool {
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

