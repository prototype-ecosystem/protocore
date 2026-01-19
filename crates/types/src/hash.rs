//! 32-byte hash type with Keccak256 support.
//!
//! This module provides the [`H256`] type, which represents a 32-byte hash value.
//! It includes support for Keccak256 hashing, hex encoding/decoding, and various
//! utility methods.

use crate::{Error, Result};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::str::FromStr;

/// Size of a hash in bytes
pub const HASH_SIZE: usize = 32;

/// A 32-byte hash value.
///
/// This type is used throughout Proto Core for block hashes, transaction hashes,
/// state roots, and other cryptographic digests. It supports Keccak256 hashing
/// as used in Ethereum.
///
/// # Example
///
/// ```rust
/// use protocore_types::H256;
///
/// // Hash some data
/// let hash = H256::keccak256(b"hello world");
///
/// // Parse from hex
/// let parsed: H256 = "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad".parse().unwrap();
///
/// // Check for nil/zero hash
/// assert_ne!(hash, H256::NIL);
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct H256([u8; HASH_SIZE]);

impl H256 {
    /// The nil hash (all zeros) - used to represent "no hash" or "nil vote" in consensus.
    pub const NIL: Self = Self([0u8; HASH_SIZE]);

    /// Alias for NIL - the zero hash.
    pub const ZERO: Self = Self::NIL;

    /// Creates a new hash from a 32-byte array.
    #[inline]
    pub const fn new(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates a hash from a slice.
    ///
    /// Returns an error if the slice length is not exactly 32 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != HASH_SIZE {
            return Err(Error::InvalidLength {
                expected: HASH_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; HASH_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Computes the Keccak256 hash of the given data.
    ///
    /// # Example
    ///
    /// ```rust
    /// use protocore_types::H256;
    ///
    /// let hash = H256::keccak256(b"hello");
    /// ```
    pub fn keccak256(data: &[u8]) -> Self {
        let mut hasher = Keccak256::new();
        hasher.update(data);
        let result = hasher.finalize();
        let mut bytes = [0u8; HASH_SIZE];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Computes the Keccak256 hash of multiple data slices.
    ///
    /// This is more efficient than concatenating the slices first.
    pub fn keccak256_concat(data: &[&[u8]]) -> Self {
        let mut hasher = Keccak256::new();
        for slice in data {
            hasher.update(slice);
        }
        let result = hasher.finalize();
        let mut bytes = [0u8; HASH_SIZE];
        bytes.copy_from_slice(&result);
        Self(bytes)
    }

    /// Returns the hash as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the hash as a fixed-size byte array.
    #[inline]
    pub const fn as_fixed_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    /// Returns the hash as a mutable byte slice.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Checks if this is the nil/zero hash.
    #[inline]
    pub fn is_nil(&self) -> bool {
        self == &Self::NIL
    }

    /// Alias for is_nil.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.is_nil()
    }

    /// Creates a hash from its hex representation.
    ///
    /// The input can optionally have a `0x` prefix.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = s.strip_prefix("0X").unwrap_or(s);

        if s.len() != 64 {
            return Err(Error::InvalidHash(format!(
                "expected 64 hex characters, got {}",
                s.len()
            )));
        }

        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }

    /// Returns the hex representation with 0x prefix.
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.0))
    }

    /// Creates a random hash (for testing purposes).
    #[cfg(feature = "test-utils")]
    pub fn random() -> Self {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let mut bytes = [0u8; HASH_SIZE];
        rng.fill(&mut bytes);
        Self(bytes)
    }
}

impl fmt::Debug for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "H256(0x{})", hex::encode(self.0))
    }
}

impl fmt::Display for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl fmt::LowerHex for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl fmt::UpperHex for H256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        for byte in &self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}

impl FromStr for H256 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl From<[u8; HASH_SIZE]> for H256 {
    fn from(bytes: [u8; HASH_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<H256> for [u8; HASH_SIZE] {
    fn from(hash: H256) -> Self {
        hash.0
    }
}

impl AsRef<[u8]> for H256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; HASH_SIZE]> for H256 {
    fn as_ref(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }
}

impl From<alloy_primitives::B256> for H256 {
    fn from(hash: alloy_primitives::B256) -> Self {
        Self(hash.0)
    }
}

impl From<H256> for alloy_primitives::B256 {
    fn from(hash: H256) -> Self {
        alloy_primitives::B256::from(hash.0)
    }
}

impl Serialize for H256 {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for H256 {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Encodable for H256 {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.encoder().encode_value(&self.0);
    }
}

impl Decodable for H256 {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        let bytes: Vec<u8> = rlp.as_val()?;
        if bytes.len() != HASH_SIZE {
            return Err(DecoderError::RlpInvalidLength);
        }
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

/// Computes the Keccak256 hash of the given data.
///
/// This is a convenience function that calls [`H256::keccak256`].
#[inline]
pub fn keccak256(data: &[u8]) -> H256 {
    H256::keccak256(data)
}

/// Computes the Keccak256 hash of multiple data slices.
///
/// This is a convenience function that calls [`H256::keccak256_concat`].
#[inline]
pub fn keccak256_concat(data: &[&[u8]]) -> H256 {
    H256::keccak256_concat(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        // Keccak256("") = c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
        let hash = H256::keccak256(b"");
        assert_eq!(
            hash.to_hex(),
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak256_hello() {
        // Keccak256("hello") = 1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8
        let hash = H256::keccak256(b"hello");
        assert_eq!(
            hash.to_hex(),
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_nil_hash() {
        let nil = H256::NIL;
        assert!(nil.is_nil());
        assert!(nil.is_zero());
        assert_eq!(
            nil.to_hex(),
            "0x0000000000000000000000000000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_hash_from_hex() {
        let hex_str = "0x47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        let hash = H256::from_hex(hex_str).unwrap();
        assert_eq!(hash.to_hex(), hex_str);

        // Without 0x prefix
        let hash2 = H256::from_hex(&hex_str[2..]).unwrap();
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_display() {
        let hash = H256::keccak256(b"test");
        let display = hash.to_string();
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_hash_serde() {
        let hash = H256::keccak256(b"test");
        let json = serde_json::to_string(&hash).unwrap();
        let decoded: H256 = serde_json::from_str(&json).unwrap();
        assert_eq!(hash, decoded);
    }

    #[test]
    fn test_hash_from_bytes() {
        let bytes = [0x42u8; 32];
        let hash = H256::from(bytes);
        assert_eq!(hash.as_fixed_bytes(), &bytes);
    }

    #[test]
    fn test_keccak256_concat() {
        let parts: &[&[u8]] = &[b"hello", b" ", b"world"];
        let hash1 = H256::keccak256_concat(parts);
        let hash2 = H256::keccak256(b"hello world");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_invalid_hash() {
        // Too short
        assert!(H256::from_hex("0x1234").is_err());
        // Too long
        assert!(H256::from_hex(&format!("0x{}", "aa".repeat(33))).is_err());
        // Invalid hex
        assert!(H256::from_hex(&format!("0x{}", "GG".repeat(32))).is_err());
    }

    #[test]
    fn test_hash_ordering() {
        let h1 = H256::from([0x00; 32]);
        let h2 = H256::from([0x01; 32]);
        let h3 = H256::from([0xFF; 32]);

        assert!(h1 < h2);
        assert!(h2 < h3);
        assert!(h1 < h3);
    }
}
