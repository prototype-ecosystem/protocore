//! # ECDSA Signatures using secp256k1
//!
//! This module provides ECDSA signing and verification using the secp256k1 curve,
//! compatible with Ethereum transaction signing.
//!
//! ## Key Types
//!
//! - `PrivateKey` - 32-byte secret key for signing
//! - `PublicKey` - Uncompressed (64 bytes) or compressed (33 bytes) public key
//! - `Signature` - ECDSA signature with recovery ID (r, s, v)
//! - `Address` - 20-byte Ethereum-style address
//!
//! ## Example
//!
//! ```rust
//! use protocore_crypto::ecdsa::{PrivateKey, Signature};
//!
//! // Generate a random private key
//! let private_key = PrivateKey::random();
//!
//! // Get the public key
//! let public_key = private_key.public_key();
//!
//! // Derive Ethereum address
//! let address = public_key.to_address();
//!
//! // Sign a message (with Ethereum prefix)
//! let signature = private_key.sign_message(b"Hello, Proto Core!").unwrap();
//!
//! // Verify the signature
//! assert!(signature.verify_message(b"Hello, Proto Core!", &public_key).unwrap());
//!
//! // Recover public key from signature
//! let recovered = signature.recover_from_message(b"Hello, Proto Core!").unwrap();
//! assert_eq!(recovered, public_key);
//! ```

use crate::{keccak256, CryptoError, Result};
use k256::{
    ecdsa::{
        signature::hazmat::PrehashSigner, RecoveryId, Signature as K256Signature, SigningKey,
        VerifyingKey,
    },
    elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint},
    EncodedPoint, PublicKey as K256PublicKey, SecretKey,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

/// Ethereum-style 20-byte address
pub type Address = [u8; 20];

/// ECDSA private key (32 bytes)
///
/// This is the secret key used for signing. Keep it secure!
#[derive(Clone)]
pub struct PrivateKey {
    inner: SigningKey,
}

impl PrivateKey {
    /// Generate a random private key using a cryptographically secure RNG.
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_crypto::ecdsa::PrivateKey;
    ///
    /// let key = PrivateKey::random();
    /// ```
    pub fn random() -> Self {
        let secret_key = SecretKey::random(&mut OsRng);
        Self {
            inner: SigningKey::from(secret_key),
        }
    }

    /// Create a private key from raw bytes.
    ///
    /// # Arguments
    ///
    /// * `bytes` - 32-byte array representing the private key
    ///
    /// # Errors
    ///
    /// Returns an error if the bytes don't represent a valid private key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let secret_key = SecretKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::InvalidPrivateKey(e.to_string()))?;
        Ok(Self {
            inner: SigningKey::from(secret_key),
        })
    }

    /// Create a private key from a hex string.
    ///
    /// # Arguments
    ///
    /// * `hex` - Hex-encoded private key (with or without 0x prefix)
    ///
    /// # Errors
    ///
    /// Returns an error if the hex is invalid or doesn't represent a valid key.
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
        self.inner.to_bytes().into()
    }

    /// Get the hex-encoded private key.
    ///
    /// # Security
    ///
    /// Be careful with the returned string - it is the secret key!
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Derive the public key from this private key.
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            inner: *self.inner.verifying_key(),
        }
    }

    /// Sign raw data (hash it first, then sign).
    ///
    /// This hashes the data with Keccak256 before signing.
    ///
    /// # Arguments
    ///
    /// * `data` - The data to sign
    ///
    /// # Returns
    ///
    /// A signature with recovery ID.
    pub fn sign(&self, data: &[u8]) -> Result<Signature> {
        let hash = keccak256(data);
        self.sign_prehash(&hash)
    }

    /// Sign a pre-hashed message (32-byte hash).
    ///
    /// Use this when you already have the hash of the data.
    ///
    /// # Arguments
    ///
    /// * `hash` - 32-byte hash to sign
    ///
    /// # Returns
    ///
    /// A signature with recovery ID.
    pub fn sign_prehash(&self, hash: &[u8; 32]) -> Result<Signature> {
        let (sig, recovery_id) = self
            .inner
            .sign_prehash_recoverable(hash)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;

        let r_bytes: [u8; 32] = sig.r().to_bytes().into();
        let s_bytes: [u8; 32] = sig.s().to_bytes().into();

        Ok(Signature {
            r: r_bytes,
            s: s_bytes,
            v: recovery_id.to_byte(),
        })
    }

    /// Sign a message with Ethereum personal_sign prefix.
    ///
    /// This prefixes the message with "\x19Ethereum Signed Message:\n{length}"
    /// before hashing and signing, making it compatible with Ethereum wallets.
    ///
    /// # Arguments
    ///
    /// * `message` - The message to sign
    ///
    /// # Returns
    ///
    /// A signature with recovery ID.
    pub fn sign_message(&self, message: &[u8]) -> Result<Signature> {
        let hash = hash_message(message);
        self.sign_prehash(&hash)
    }
}

impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("public_key", &self.public_key().to_hex_compressed())
            .finish()
    }
}

// Implement zeroize on drop for security
impl Drop for PrivateKey {
    fn drop(&mut self) {
        // The inner SigningKey implements zeroize, but we add this note
        // to make security intentions clear
    }
}

/// ECDSA public key
///
/// Can be represented in compressed (33 bytes) or uncompressed (64 bytes) format.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PublicKey {
    inner: VerifyingKey,
}

impl PublicKey {
    /// Create a public key from uncompressed bytes (64 bytes, without prefix).
    ///
    /// # Arguments
    ///
    /// * `bytes` - 64-byte uncompressed public key (x || y coordinates)
    pub fn from_uncompressed(bytes: &[u8; 64]) -> Result<Self> {
        // Add the 0x04 prefix for uncompressed format
        let mut prefixed = [0u8; 65];
        prefixed[0] = 0x04;
        prefixed[1..].copy_from_slice(bytes);

        let point = EncodedPoint::from_bytes(&prefixed)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let public_key = K256PublicKey::from_encoded_point(&point);
        if public_key.is_none().into() {
            return Err(CryptoError::InvalidPublicKey(
                "invalid point on curve".to_string(),
            ));
        }

        let verifying_key = VerifyingKey::from(public_key.unwrap());
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Create a public key from compressed bytes (33 bytes).
    ///
    /// # Arguments
    ///
    /// * `bytes` - 33-byte compressed public key (prefix || x coordinate)
    pub fn from_compressed(bytes: &[u8; 33]) -> Result<Self> {
        let point = EncodedPoint::from_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let public_key = K256PublicKey::from_encoded_point(&point);
        if public_key.is_none().into() {
            return Err(CryptoError::InvalidPublicKey(
                "invalid point on curve".to_string(),
            ));
        }

        let verifying_key = VerifyingKey::from(public_key.unwrap());
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Create a public key from SEC1 encoded bytes (handles both formats).
    ///
    /// Accepts:
    /// - 33 bytes: compressed format
    /// - 65 bytes: uncompressed format with 0x04 prefix
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self> {
        let verifying_key = VerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;
        Ok(Self {
            inner: verifying_key,
        })
    }

    /// Create a public key from a hex string.
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        Self::from_sec1_bytes(&bytes)
    }

    /// Get the uncompressed public key bytes (64 bytes, without 0x04 prefix).
    pub fn to_uncompressed(&self) -> [u8; 64] {
        let point = self.inner.to_encoded_point(false);
        let bytes = point.as_bytes();
        // Skip the 0x04 prefix
        let mut result = [0u8; 64];
        result.copy_from_slice(&bytes[1..65]);
        result
    }

    /// Get the compressed public key bytes (33 bytes).
    pub fn to_compressed(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut result = [0u8; 33];
        result.copy_from_slice(bytes);
        result
    }

    /// Get the hex-encoded compressed public key.
    pub fn to_hex_compressed(&self) -> String {
        hex::encode(self.to_compressed())
    }

    /// Get the hex-encoded uncompressed public key.
    pub fn to_hex_uncompressed(&self) -> String {
        hex::encode(self.to_uncompressed())
    }

    /// Derive the Ethereum-style address from this public key.
    ///
    /// The address is the last 20 bytes of the Keccak256 hash
    /// of the uncompressed public key (without the 0x04 prefix).
    pub fn to_address(&self) -> Address {
        let uncompressed = self.to_uncompressed();
        let hash = keccak256(&uncompressed);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        address
    }

    /// Get the address as a hex string with 0x prefix.
    pub fn to_address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.to_address()))
    }

    /// Get the address as a checksummed hex string (EIP-55).
    pub fn to_address_checksum(&self) -> String {
        checksum_address(&self.to_address())
    }

    /// Verify a signature against pre-hashed data.
    pub fn verify_prehash(&self, hash: &[u8; 32], signature: &Signature) -> Result<bool> {
        let sig = signature.to_k256_signature()?;

        use k256::ecdsa::signature::hazmat::PrehashVerifier;
        match self.inner.verify_prehash(hash, &sig) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Verify a signature against raw data (will be hashed first).
    pub fn verify(&self, data: &[u8], signature: &Signature) -> Result<bool> {
        let hash = keccak256(data);
        self.verify_prehash(&hash, signature)
    }

    /// Verify a signature against a message (with Ethereum prefix).
    pub fn verify_message(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        let hash = hash_message(message);
        self.verify_prehash(&hash, signature)
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PublicKey")
            .field("compressed", &self.to_hex_compressed())
            .field("address", &self.to_address_hex())
            .finish()
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let bytes = self.to_compressed();
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(&bytes)
        }
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            PublicKey::from_hex(&s).map_err(serde::de::Error::custom)
        } else {
            let bytes = <Vec<u8>>::deserialize(deserializer)?;
            PublicKey::from_sec1_bytes(&bytes).map_err(serde::de::Error::custom)
        }
    }
}

/// ECDSA signature with recovery ID
///
/// Contains:
/// - `r` - 32 bytes
/// - `s` - 32 bytes
/// - `v` - recovery ID (0 or 1, sometimes 27/28 in Ethereum legacy format)
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Signature {
    /// The r component of the signature (32 bytes)
    pub r: [u8; 32],
    /// The s component of the signature (32 bytes)
    pub s: [u8; 32],
    /// Recovery ID (0 or 1)
    pub v: u8,
}

impl Signature {
    /// Create a signature from r, s, v components.
    pub fn new(r: [u8; 32], s: [u8; 32], v: u8) -> Self {
        Self { r, s, v }
    }

    /// Create a signature from raw bytes (65 bytes: r || s || v).
    pub fn from_bytes(bytes: &[u8; 65]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        let v = bytes[64];
        Self { r, s, v }
    }

    /// Create a signature from r, s, v byte slices.
    pub fn from_rsv(r: &[u8; 32], s: &[u8; 32], v: u8) -> Self {
        Self { r: *r, s: *s, v }
    }

    /// Create a signature from a hex string (130 characters or 132 with 0x).
    pub fn from_hex(hex: &str) -> Result<Self> {
        let hex = hex.strip_prefix("0x").unwrap_or(hex);
        let bytes = hex::decode(hex)?;
        if bytes.len() != 65 {
            return Err(CryptoError::InvalidLength {
                expected: 65,
                actual: bytes.len(),
            });
        }
        let mut arr = [0u8; 65];
        arr.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&arr))
    }

    /// Get the signature as raw bytes (65 bytes: r || s || v).
    pub fn to_bytes(&self) -> [u8; 65] {
        let mut bytes = [0u8; 65];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes[64] = self.v;
        bytes
    }

    /// Get the signature as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_bytes())
    }

    /// Get the v value in Ethereum legacy format (27 or 28).
    pub fn v_legacy(&self) -> u8 {
        if self.v < 27 {
            self.v + 27
        } else {
            self.v
        }
    }

    /// Get the normalized v value (0 or 1).
    pub fn v_normalized(&self) -> u8 {
        if self.v >= 27 {
            self.v - 27
        } else {
            self.v
        }
    }

    /// Convert to k256 signature type.
    fn to_k256_signature(&self) -> Result<K256Signature> {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        K256Signature::from_bytes((&bytes).into())
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    }

    /// Recover the public key from this signature and the signed hash.
    pub fn recover_prehash(&self, hash: &[u8; 32]) -> Result<PublicKey> {
        let sig = self.to_k256_signature()?;
        let recovery_id = RecoveryId::from_byte(self.v_normalized())
            .ok_or_else(|| CryptoError::RecoveryFailed("invalid recovery id".to_string()))?;

        let verifying_key = VerifyingKey::recover_from_prehash(hash, &sig, recovery_id)
            .map_err(|e| CryptoError::RecoveryFailed(e.to_string()))?;

        Ok(PublicKey {
            inner: verifying_key,
        })
    }

    /// Recover the public key from this signature and raw data.
    pub fn recover(&self, data: &[u8]) -> Result<PublicKey> {
        let hash = keccak256(data);
        self.recover_prehash(&hash)
    }

    /// Recover the public key from this signature and a message (with Ethereum prefix).
    pub fn recover_from_message(&self, message: &[u8]) -> Result<PublicKey> {
        let hash = hash_message(message);
        self.recover_prehash(&hash)
    }

    /// Verify this signature against a hash and public key.
    pub fn verify_prehash(&self, hash: &[u8; 32], public_key: &PublicKey) -> Result<bool> {
        public_key.verify_prehash(hash, self)
    }

    /// Verify this signature against raw data and public key.
    pub fn verify(&self, data: &[u8], public_key: &PublicKey) -> Result<bool> {
        public_key.verify(data, self)
    }

    /// Verify this signature against a message and public key (with Ethereum prefix).
    pub fn verify_message(&self, message: &[u8], public_key: &PublicKey) -> Result<bool> {
        public_key.verify_message(message, self)
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Signature")
            .field("r", &hex::encode(self.r))
            .field("s", &hex::encode(self.s))
            .field("v", &self.v)
            .finish()
    }
}

/// Hash a message with the Ethereum personal_sign prefix.
///
/// Computes: keccak256("\x19Ethereum Signed Message:\n" + len(message) + message)
pub fn hash_message(message: &[u8]) -> [u8; 32] {
    let prefix = format!("\x19Ethereum Signed Message:\n{}", message.len());
    crate::keccak256_concat(&[prefix.as_bytes(), message])
}

/// Derive an Ethereum address from an uncompressed public key (64 bytes).
///
/// This is the standard Ethereum address derivation:
/// address = keccak256(pubkey)[12..32]
pub fn address_from_pubkey(uncompressed_pubkey: &[u8; 64]) -> Address {
    let hash = keccak256(uncompressed_pubkey);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..32]);
    address
}

/// Convert an address to checksummed format (EIP-55).
pub fn checksum_address(address: &Address) -> String {
    let addr_hex = hex::encode(address);
    let hash = keccak256(addr_hex.as_bytes());

    let mut result = String::with_capacity(42);
    result.push_str("0x");

    for (i, c) in addr_hex.chars().enumerate() {
        let hash_nibble = if i % 2 == 0 {
            hash[i / 2] >> 4
        } else {
            hash[i / 2] & 0x0f
        };

        if hash_nibble >= 8 {
            result.push(c.to_ascii_uppercase());
        } else {
            result.push(c);
        }
    }

    result
}

/// Verify a checksummed address (EIP-55).
pub fn verify_checksum_address(address: &str) -> bool {
    let address = address.strip_prefix("0x").unwrap_or(address);
    if address.len() != 40 {
        return false;
    }

    let bytes = match hex::decode(address) {
        Ok(b) if b.len() == 20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(&b);
            arr
        }
        _ => return false,
    };

    let expected = checksum_address(&bytes);
    format!("0x{}", address) == expected
}

