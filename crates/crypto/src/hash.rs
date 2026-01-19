//! # Keccak256 Hashing Utilities
//!
//! This module provides Keccak256 hashing functions compatible with Ethereum.
//!
//! ## Functions
//!
//! - `keccak256` - Hash a single byte slice
//! - `keccak256_concat` - Hash multiple byte slices concatenated
//!
//! ## Streaming Hasher
//!
//! For large or incremental data, use the `Hasher` struct:
//!
//! ```rust
//! use protocore_crypto::hash::Hasher;
//!
//! let mut hasher = Hasher::new();
//! hasher.update(b"hello");
//! hasher.update(b" world");
//! let hash = hasher.finalize();
//! ```

use sha3::{Digest, Keccak256};

/// Compute the Keccak256 hash of the input data.
///
/// This is the standard hash function used throughout Ethereum and Proto Core
/// for transaction hashes, state roots, and address derivation.
///
/// # Arguments
///
/// * `data` - The byte slice to hash
///
/// # Returns
///
/// A 32-byte array containing the Keccak256 hash
///
/// # Example
///
/// ```rust
/// use protocore_crypto::keccak256;
///
/// let hash = keccak256(b"hello");
/// assert_eq!(hash.len(), 32);
/// ```
#[inline]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute the Keccak256 hash of multiple concatenated inputs.
///
/// This is more efficient than manually concatenating the inputs
/// and then hashing, as it avoids allocating a temporary buffer.
///
/// # Arguments
///
/// * `parts` - A slice of byte slices to hash together
///
/// # Returns
///
/// A 32-byte array containing the Keccak256 hash of the concatenated inputs
///
/// # Example
///
/// ```rust
/// use protocore_crypto::keccak256_concat;
///
/// let hash = keccak256_concat(&[b"hello", b" ", b"world"]);
/// // Equivalent to: keccak256(b"hello world")
/// ```
#[inline]
pub fn keccak256_concat(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

/// A streaming Keccak256 hasher for incremental hashing.
///
/// Use this when you need to hash data that arrives in chunks
/// or when the full data is too large to fit in memory.
///
/// # Example
///
/// ```rust
/// use protocore_crypto::Hasher;
///
/// let mut hasher = Hasher::new();
/// hasher.update(b"part1");
/// hasher.update(b"part2");
/// let hash = hasher.finalize();
/// ```
#[derive(Clone)]
pub struct Hasher {
    inner: Keccak256,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Create a new Keccak256 hasher.
    #[inline]
    pub fn new() -> Self {
        Self {
            inner: Keccak256::new(),
        }
    }

    /// Update the hasher with additional data.
    ///
    /// This can be called multiple times to feed data incrementally.
    ///
    /// # Arguments
    ///
    /// * `data` - The byte slice to add to the hash computation
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Update the hasher with multiple data chunks.
    ///
    /// Convenience method for adding multiple pieces of data at once.
    ///
    /// # Arguments
    ///
    /// * `parts` - A slice of byte slices to add to the hash computation
    #[inline]
    pub fn update_many(&mut self, parts: &[&[u8]]) {
        for part in parts {
            self.inner.update(part);
        }
    }

    /// Finalize the hasher and return the hash.
    ///
    /// This consumes the hasher. To continue hashing, create a new `Hasher`.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the Keccak256 hash
    #[inline]
    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }

    /// Reset the hasher to its initial state.
    ///
    /// This allows reusing the hasher for a new hash computation.
    #[inline]
    pub fn reset(&mut self) {
        self.inner = Keccak256::new();
    }

    /// Finalize and return the hash, then reset for reuse.
    ///
    /// This is useful when computing multiple hashes with the same hasher instance.
    ///
    /// # Returns
    ///
    /// A 32-byte array containing the Keccak256 hash
    #[inline]
    pub fn finalize_reset(&mut self) -> [u8; 32] {
        let result = self.inner.clone().finalize().into();
        self.reset();
        result
    }
}

impl std::fmt::Debug for Hasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Hasher").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak256_empty() {
        let hash = keccak256(b"");
        // Known hash of empty input
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_keccak256_hello() {
        let hash = keccak256(b"hello");
        assert_eq!(
            hex::encode(hash),
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_keccak256_concat_equivalence() {
        let hash1 = keccak256(b"hello world");
        let hash2 = keccak256_concat(&[b"hello", b" ", b"world"]);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hasher_streaming() {
        let direct = keccak256(b"hello world");

        let mut hasher = Hasher::new();
        hasher.update(b"hello");
        hasher.update(b" ");
        hasher.update(b"world");
        let streamed = hasher.finalize();

        assert_eq!(direct, streamed);
    }

    #[test]
    fn test_hasher_update_many() {
        let direct = keccak256(b"abcdef");

        let mut hasher = Hasher::new();
        hasher.update_many(&[b"ab", b"cd", b"ef"]);
        let streamed = hasher.finalize();

        assert_eq!(direct, streamed);
    }

    #[test]
    fn test_hasher_reset() {
        let mut hasher = Hasher::new();
        hasher.update(b"garbage");
        hasher.reset();
        hasher.update(b"hello");
        let hash = hasher.finalize();

        assert_eq!(hash, keccak256(b"hello"));
    }

    #[test]
    fn test_hasher_finalize_reset() {
        let mut hasher = Hasher::new();

        hasher.update(b"first");
        let hash1 = hasher.finalize_reset();

        hasher.update(b"second");
        let hash2 = hasher.finalize_reset();

        assert_eq!(hash1, keccak256(b"first"));
        assert_eq!(hash2, keccak256(b"second"));
    }

    #[test]
    fn test_hasher_clone() {
        let mut hasher1 = Hasher::new();
        hasher1.update(b"hello");

        let mut hasher2 = hasher1.clone();
        hasher1.update(b" world");
        hasher2.update(b" rust");

        assert_eq!(hasher1.finalize(), keccak256(b"hello world"));
        assert_eq!(hasher2.finalize(), keccak256(b"hello rust"));
    }

    #[test]
    fn test_keccak256_deterministic() {
        let hash1 = keccak256(b"test data");
        let hash2 = keccak256(b"test data");
        assert_eq!(hash1, hash2);
    }
}
