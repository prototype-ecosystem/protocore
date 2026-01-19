//! Ethereum-compatible 20-byte address type.
//!
//! This module provides the [`Address`] type, which represents an Ethereum-style
//! address as a 20-byte array. It supports:
//!
//! - Hex encoding/decoding with `0x` prefix
//! - Serde serialization as hex strings
//! - Display formatting (checksummed and lowercase)
//! - Various conversions to/from byte arrays

use crate::{Error, Result, H256};
use rlp::{Decodable, DecoderError, Encodable, Rlp, RlpStream};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Keccak256};
use std::fmt;
use std::str::FromStr;

/// Size of an Ethereum address in bytes
pub const ADDRESS_SIZE: usize = 20;

/// An Ethereum-compatible 20-byte address.
///
/// Addresses are typically displayed as 40 hex characters with a `0x` prefix.
/// This type supports EIP-55 checksummed encoding for display.
///
/// # Example
///
/// ```rust
/// use protocore_types::Address;
///
/// // Parse from hex string
/// let addr: Address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1".parse().unwrap();
///
/// // Display with checksum
/// println!("{}", addr);
///
/// // Get raw bytes
/// let bytes: [u8; 20] = addr.into();
/// ```
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Address([u8; ADDRESS_SIZE]);

impl Address {
    /// The zero address (0x0000000000000000000000000000000000000000)
    pub const ZERO: Self = Self([0u8; ADDRESS_SIZE]);

    /// Creates a new address from a 20-byte array.
    #[inline]
    pub const fn new(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }

    /// Creates an address from a slice.
    ///
    /// Returns an error if the slice length is not exactly 20 bytes.
    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ADDRESS_SIZE {
            return Err(Error::InvalidLength {
                expected: ADDRESS_SIZE,
                actual: slice.len(),
            });
        }
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(slice);
        Ok(Self(bytes))
    }

    /// Returns the address as a byte slice.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the address as a fixed-size byte array.
    #[inline]
    pub const fn as_fixed_bytes(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }

    /// Returns the address as a mutable byte slice.
    #[inline]
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Checks if this is the zero address.
    #[inline]
    pub fn is_zero(&self) -> bool {
        self == &Self::ZERO
    }

    /// Computes the EIP-55 checksum encoding of this address.
    ///
    /// This returns the hex string with mixed-case characters according to EIP-55.
    pub fn to_checksum_string(&self) -> String {
        let hex_addr = hex::encode(self.0);
        let hash = Keccak256::digest(hex_addr.as_bytes());

        let mut result = String::with_capacity(42);
        result.push_str("0x");

        for (i, c) in hex_addr.chars().enumerate() {
            if c.is_ascii_alphabetic() {
                // Check the corresponding nibble in the hash
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

        result
    }

    /// Creates an address from its hex representation.
    ///
    /// The input can optionally have a `0x` prefix.
    pub fn from_hex(s: &str) -> Result<Self> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let s = s.strip_prefix("0X").unwrap_or(s);

        if s.len() != 40 {
            return Err(Error::InvalidAddress(format!(
                "expected 40 hex characters, got {}",
                s.len()
            )));
        }

        let bytes = hex::decode(s)?;
        Self::from_slice(&bytes)
    }

    /// Derives an address from a public key using Keccak256.
    ///
    /// Takes the last 20 bytes of the Keccak256 hash of the public key.
    pub fn from_public_key(pubkey: &[u8]) -> Self {
        let hash = Keccak256::digest(pubkey);
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash[12..32]);
        Self(bytes)
    }

    /// Computes a contract address created by this address at the given nonce.
    ///
    /// Uses the standard CREATE formula: keccak256(rlp([sender, nonce]))[12..]
    pub fn create_contract_address(&self, nonce: u64) -> Self {
        let mut stream = RlpStream::new_list(2);
        stream.append(&self.0.as_slice());
        stream.append(&nonce);
        let rlp_encoded = stream.out();

        let hash = Keccak256::digest(&rlp_encoded);
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash[12..32]);
        Self(bytes)
    }

    /// Computes a contract address using CREATE2.
    ///
    /// Formula: keccak256(0xff ++ sender ++ salt ++ keccak256(init_code))[12..]
    pub fn create2_contract_address(&self, salt: &H256, init_code_hash: &H256) -> Self {
        let mut data = Vec::with_capacity(1 + 20 + 32 + 32);
        data.push(0xff);
        data.extend_from_slice(&self.0);
        data.extend_from_slice(salt.as_bytes());
        data.extend_from_slice(init_code_hash.as_bytes());

        let hash = Keccak256::digest(&data);
        let mut bytes = [0u8; ADDRESS_SIZE];
        bytes.copy_from_slice(&hash[12..32]);
        Self(bytes)
    }
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Address({})", self.to_checksum_string())
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_checksum_string())
    }
}

impl fmt::LowerHex for Address {
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

impl fmt::UpperHex for Address {
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

impl FromStr for Address {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

impl From<[u8; ADDRESS_SIZE]> for Address {
    fn from(bytes: [u8; ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<Address> for [u8; ADDRESS_SIZE] {
    fn from(addr: Address) -> Self {
        addr.0
    }
}

impl AsRef<[u8]> for Address {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl AsRef<[u8; ADDRESS_SIZE]> for Address {
    fn as_ref(&self) -> &[u8; ADDRESS_SIZE] {
        &self.0
    }
}

impl From<alloy_primitives::Address> for Address {
    fn from(addr: alloy_primitives::Address) -> Self {
        Self(addr.into_array())
    }
}

impl From<Address> for alloy_primitives::Address {
    fn from(addr: Address) -> Self {
        alloy_primitives::Address::from(addr.0)
    }
}

impl Serialize for Address {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_checksum_string())
    }
}

impl<'de> Deserialize<'de> for Address {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl Encodable for Address {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.encoder().encode_value(&self.0);
    }
}

impl Decodable for Address {
    fn decode(rlp: &Rlp<'_>) -> std::result::Result<Self, DecoderError> {
        let bytes: Vec<u8> = rlp.as_val()?;
        if bytes.len() != ADDRESS_SIZE {
            return Err(DecoderError::RlpInvalidLength);
        }
        let mut arr = [0u8; ADDRESS_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_from_hex() {
        let addr =
            Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
        assert!(!addr.is_zero());

        // Without 0x prefix
        let addr2 =
            Address::from_hex("742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_address_display() {
        let addr =
            Address::from_hex("0x742d35cc6634c0532925a3b844bc9e7595f0beb1").unwrap();
        let display = addr.to_string();
        // The display should be checksummed
        assert!(display.starts_with("0x"));
        assert_eq!(display.len(), 42);
    }

    #[test]
    fn test_zero_address() {
        let zero = Address::ZERO;
        assert!(zero.is_zero());
        assert_eq!(
            zero.to_string(),
            "0x0000000000000000000000000000000000000000"
        );
    }

    #[test]
    fn test_address_from_bytes() {
        let bytes = [0x42u8; 20];
        let addr = Address::from(bytes);
        assert_eq!(addr.as_fixed_bytes(), &bytes);
    }

    #[test]
    fn test_address_serde() {
        let addr =
            Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
        let json = serde_json::to_string(&addr).unwrap();
        let decoded: Address = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, decoded);
    }

    #[test]
    fn test_create_contract_address() {
        let sender =
            Address::from_hex("0x6ac7ea33f8831ea9dcc53393aaa88b25a785dbf0").unwrap();
        let contract = sender.create_contract_address(0);
        assert!(!contract.is_zero());
    }

    #[test]
    fn test_invalid_address() {
        // Too short
        assert!(Address::from_hex("0x1234").is_err());
        // Too long
        assert!(Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1ff").is_err());
        // Invalid hex
        assert!(Address::from_hex("0xGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG").is_err());
    }
}
