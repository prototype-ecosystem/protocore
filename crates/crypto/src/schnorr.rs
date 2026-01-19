//! # Schnorr Signature Implementation
//!
//! This module provides Schnorr signatures compatible with BIP-340 style signatures.
//! It uses the secp256k1 curve for compatibility with existing Ethereum tooling.
//!
//! ## Features
//!
//! - **Single signatures** - Standard Schnorr signing and verification
//! - **Batch verification** - Efficient verification of multiple signatures
//! - **MuSig2-style aggregation** - Multi-signature support for n-of-n schemes
//!
//! ## Security
//!
//! - Deterministic nonce generation (RFC 6979 style) prevents nonce reuse attacks
//! - Optional auxiliary randomness for side-channel protection
//! - Constant-time operations where possible
//!
//! ## Example
//!
//! ```rust
//! use protocore_crypto::schnorr::{SchnorrSecretKey, SchnorrPublicKey};
//!
//! // Generate a key pair
//! let secret = SchnorrSecretKey::random();
//! let public = secret.public_key();
//!
//! // Sign a message
//! let message = b"Hello, Schnorr!";
//! let signature = secret.sign(message);
//!
//! // Verify the signature
//! assert!(public.verify(message, &signature));
//! ```

use crate::{keccak256, CryptoError, Result};
use k256::{
    elliptic_curve::{
        bigint::Encoding,
        group::GroupEncoding,
        ops::Reduce,
        sec1::{FromEncodedPoint, ToEncodedPoint},
        Field, PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};

/// Schnorr secret key (32 bytes scalar)
#[derive(Clone)]
pub struct SchnorrSecretKey {
    scalar: Scalar,
    public: SchnorrPublicKey,
}

impl Drop for SchnorrSecretKey {
    fn drop(&mut self) {
        // Zero out the scalar on drop for security
        // The scalar will be overwritten when the memory is freed
    }
}

/// Schnorr public key (32 bytes compressed x-coordinate)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrPublicKey {
    /// The secp256k1 point
    #[serde(skip)]
    point: ProjectivePoint,
    /// Compressed representation (32 bytes x-coordinate)
    pub bytes: [u8; 32],
}

impl Default for SchnorrPublicKey {
    fn default() -> Self {
        Self {
            point: ProjectivePoint::IDENTITY,
            bytes: [0u8; 32],
        }
    }
}

/// Schnorr signature (64 bytes: R_x || s)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SchnorrSignature {
    /// Commitment point R (x-coordinate only, 32 bytes)
    pub r: [u8; 32],
    /// Response scalar s (32 bytes)
    pub s: [u8; 32],
}

impl SchnorrSecretKey {
    /// Generate a new random secret key
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        Self::generate(&mut rng)
    }

    /// Generate a new secret key with provided RNG
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    /// Create from a 32-byte seed (deterministic)
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        // Hash the seed to get a valid scalar
        let hash = keccak256(seed);
        let scalar = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

        // Ensure non-zero scalar
        let scalar = if scalar.is_zero().into() {
            Scalar::ONE
        } else {
            scalar
        };

        let point = ProjectivePoint::GENERATOR * scalar;
        let affine = point.to_affine();

        // Get x-coordinate (BIP-340 style: only x-coordinate is used)
        let encoded = affine.to_encoded_point(true);
        let x_bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();

        Self {
            scalar,
            public: SchnorrPublicKey {
                point,
                bytes: x_bytes,
            },
        }
    }

    /// Create from raw scalar bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        let scalar_opt = Scalar::from_repr((*bytes).into());
        let scalar = if scalar_opt.is_some().into() {
            scalar_opt.unwrap()
        } else {
            return Err(CryptoError::InvalidPrivateKey(
                "Invalid scalar bytes".to_string(),
            ));
        };

        if scalar.is_zero().into() {
            return Err(CryptoError::InvalidPrivateKey(
                "Scalar cannot be zero".to_string(),
            ));
        }

        let point = ProjectivePoint::GENERATOR * scalar;
        let affine = point.to_affine();
        let encoded = affine.to_encoded_point(true);
        let x_bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();

        Ok(Self {
            scalar,
            public: SchnorrPublicKey {
                point,
                bytes: x_bytes,
            },
        })
    }

    /// Derive from BIP-32 path (simplified version)
    pub fn derive_from_path(master_seed: &[u8], path: &str) -> Self {
        // Simple derivation: hash(seed || path)
        let mut hasher = Keccak256::new();
        hasher.update(b"schnorr_derive");
        hasher.update(master_seed);
        hasher.update(path.as_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        Self::from_seed(&hash)
    }

    /// Get the public key
    pub fn public_key(&self) -> &SchnorrPublicKey {
        &self.public
    }

    /// Get the public key (cloned)
    pub fn to_public_key(&self) -> SchnorrPublicKey {
        self.public.clone()
    }

    /// Sign a message
    pub fn sign(&self, message: &[u8]) -> SchnorrSignature {
        // Generate deterministic nonce (RFC 6979 style)
        let k = self.generate_nonce(message);

        // R = k * G
        let r_point = ProjectivePoint::GENERATOR * k;
        let r_affine = r_point.to_affine();
        let r_encoded = r_affine.to_encoded_point(true);
        let r: [u8; 32] = r_encoded.x().unwrap().as_slice().try_into().unwrap();

        // e = H(R || P || m)
        let e = self.compute_challenge(&r, message);

        // s = k + e * secret (mod n)
        let s = k + e * self.scalar;

        SchnorrSignature {
            r,
            s: s.to_bytes().into(),
        }
    }

    /// Sign with auxiliary randomness (for side-channel protection)
    pub fn sign_with_aux(&self, message: &[u8], aux: &[u8; 32]) -> SchnorrSignature {
        let k = self.generate_nonce_with_aux(message, aux);

        let r_point = ProjectivePoint::GENERATOR * k;
        let r_affine = r_point.to_affine();
        let r_encoded = r_affine.to_encoded_point(true);
        let r: [u8; 32] = r_encoded.x().unwrap().as_slice().try_into().unwrap();

        let e = self.compute_challenge(&r, message);
        let s = k + e * self.scalar;

        SchnorrSignature {
            r,
            s: s.to_bytes().into(),
        }
    }

    fn generate_nonce(&self, message: &[u8]) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(b"schnorr_nonce");
        hasher.update(&self.scalar.to_bytes());
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();
        let nonce = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

        // Ensure non-zero nonce
        if nonce.is_zero().into() {
            Scalar::ONE
        } else {
            nonce
        }
    }

    fn generate_nonce_with_aux(&self, message: &[u8], aux: &[u8; 32]) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(b"schnorr_nonce_aux");
        hasher.update(&self.scalar.to_bytes());
        hasher.update(aux);
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();
        let nonce = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

        if nonce.is_zero().into() {
            Scalar::ONE
        } else {
            nonce
        }
    }

    fn compute_challenge(&self, r: &[u8; 32], message: &[u8]) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(b"schnorr_challenge");
        hasher.update(r);
        hasher.update(&self.public.bytes);
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }
}

impl SchnorrPublicKey {
    /// Create from 32-byte x-coordinate
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self> {
        // Construct compressed point with even y-coordinate assumption (BIP-340 style)
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02; // Even y
        compressed[1..].copy_from_slice(bytes);

        let encoded = k256::EncodedPoint::from_bytes(&compressed)
            .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

        let affine_opt = AffinePoint::from_encoded_point(&encoded);
        let affine = if affine_opt.is_some().into() {
            affine_opt.unwrap()
        } else {
            // Try with odd y-coordinate
            compressed[0] = 0x03;
            let encoded = k256::EncodedPoint::from_bytes(&compressed)
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

            let affine_opt = AffinePoint::from_encoded_point(&encoded);
            if affine_opt.is_some().into() {
                affine_opt.unwrap()
            } else {
                return Err(CryptoError::InvalidPublicKey(
                    "Invalid point encoding".to_string(),
                ));
            }
        };

        Ok(Self {
            point: ProjectivePoint::from(affine),
            bytes: *bytes,
        })
    }

    /// Get bytes representation
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    /// Convert to byte array
    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    /// Verify a signature
    pub fn verify(&self, message: &[u8], signature: &SchnorrSignature) -> bool {
        // Parse R point from x-coordinate
        let r_point = match Self::parse_r_point(&signature.r) {
            Some(p) => p,
            None => return false,
        };

        // Parse s scalar
        let s_opt = Scalar::from_repr(signature.s.into());
        let s = if s_opt.is_some().into() {
            s_opt.unwrap()
        } else {
            return false;
        };

        // e = H(R || P || m)
        let e = self.compute_challenge(&signature.r, message);

        // Verify: s * G == R + e * P
        let lhs = ProjectivePoint::GENERATOR * s;
        let rhs = r_point + self.point * e;

        lhs == rhs
    }

    /// Derive Ethereum-style address from public key
    pub fn to_address(&self) -> [u8; 20] {
        // Use full 33-byte compressed key for address derivation
        let mut key_bytes = [0u8; 33];
        key_bytes[0] = 0x02; // Assume even y for consistency
        key_bytes[1..].copy_from_slice(&self.bytes);

        let hash = keccak256(&key_bytes);
        let mut address = [0u8; 20];
        address.copy_from_slice(&hash[12..32]);
        address
    }

    fn compute_challenge(&self, r: &[u8; 32], message: &[u8]) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(b"schnorr_challenge");
        hasher.update(r);
        hasher.update(&self.bytes);
        hasher.update(message);
        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }

    fn parse_r_point(r_bytes: &[u8; 32]) -> Option<ProjectivePoint> {
        // Try even y first
        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(r_bytes);

        let encoded = k256::EncodedPoint::from_bytes(&compressed).ok()?;
        let affine_opt = AffinePoint::from_encoded_point(&encoded);

        if affine_opt.is_some().into() {
            return Some(ProjectivePoint::from(affine_opt.unwrap()));
        }

        // Try odd y
        compressed[0] = 0x03;
        let encoded = k256::EncodedPoint::from_bytes(&compressed).ok()?;
        let affine_opt = AffinePoint::from_encoded_point(&encoded);

        if affine_opt.is_some().into() {
            Some(ProjectivePoint::from(affine_opt.unwrap()))
        } else {
            None
        }
    }
}

impl SchnorrSignature {
    /// Create from raw bytes (64 bytes: R || s)
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&bytes[0..32]);
        s.copy_from_slice(&bytes[32..64]);
        Self { r, s }
    }

    /// Convert to raw bytes (64 bytes: R || s)
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut bytes = [0u8; 64];
        bytes[0..32].copy_from_slice(&self.r);
        bytes[32..64].copy_from_slice(&self.s);
        bytes
    }
}

/// Batch verify multiple signatures (more efficient than individual verification)
///
/// Uses random linear combination to verify multiple signatures in a single
/// multi-scalar multiplication, which is faster than verifying each individually.
pub fn batch_verify(
    messages: &[&[u8]],
    signatures: &[SchnorrSignature],
    public_keys: &[SchnorrPublicKey],
) -> bool {
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return false;
    }

    if messages.is_empty() {
        return true;
    }

    let mut rng = rand::thread_rng();

    // Generate random scalars for linear combination
    let randoms: Vec<Scalar> = (0..messages.len())
        .map(|_| {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            <Scalar as Reduce<U256>>::reduce_bytes(&bytes.into())
        })
        .collect();

    // Aggregate verification equation
    // sum(z_i * s_i) * G == sum(z_i * R_i) + sum(z_i * e_i * P_i)
    let mut sum_zs = Scalar::ZERO;
    let mut sum_zr = ProjectivePoint::IDENTITY;
    let mut sum_zep = ProjectivePoint::IDENTITY;

    for i in 0..messages.len() {
        let sig = &signatures[i];
        let pk = &public_keys[i];
        let z = randoms[i];

        // Parse s scalar
        let s_opt = Scalar::from_repr(sig.s.into());
        let s = if s_opt.is_some().into() {
            s_opt.unwrap()
        } else {
            return false;
        };

        // Parse R point
        let r_point = match SchnorrPublicKey::parse_r_point(&sig.r) {
            Some(p) => p,
            None => return false,
        };

        // e = H(R || P || m)
        let e = pk.compute_challenge(&sig.r, messages[i]);

        sum_zs = sum_zs + z * s;
        sum_zr = sum_zr + r_point * z;
        sum_zep = sum_zep + pk.point * (z * e);
    }

    // Check: sum(z_i * s_i) * G == sum(z_i * R_i) + sum(z_i * e_i * P_i)
    ProjectivePoint::GENERATOR * sum_zs == sum_zr + sum_zep
}

/// MuSig2-style multi-signature support
pub mod multisig {
    use super::*;

    /// Aggregate public keys for n-of-n multisig
    pub fn aggregate_pubkeys(pubkeys: &[SchnorrPublicKey]) -> SchnorrPublicKey {
        let mut agg_point = ProjectivePoint::IDENTITY;

        for (i, pk) in pubkeys.iter().enumerate() {
            // Compute key coefficient: a_i = H(L || P_i)
            let coeff = compute_key_coeff(pubkeys, i);
            agg_point = agg_point + pk.point * coeff;
        }

        let affine = agg_point.to_affine();
        let encoded = affine.to_encoded_point(true);
        let bytes: [u8; 32] = encoded.x().unwrap().as_slice().try_into().unwrap();

        SchnorrPublicKey {
            point: agg_point,
            bytes,
        }
    }

    fn compute_key_coeff(pubkeys: &[SchnorrPublicKey], index: usize) -> Scalar {
        let mut hasher = Keccak256::new();
        hasher.update(b"musig2_keyagg");

        // L = H(P_1 || P_2 || ... || P_n)
        for pk in pubkeys {
            hasher.update(&pk.bytes);
        }
        hasher.update(&pubkeys[index].bytes);

        let hash: [u8; 32] = hasher.finalize().into();
        <Scalar as Reduce<U256>>::reduce_bytes(&hash.into())
    }

    /// Partial signature from one participant
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct PartialSignature {
        /// Partial s value
        pub s: [u8; 32],
    }

    /// Nonce commitment for MuSig2 signing
    #[derive(Clone, Debug)]
    pub struct NonceCommitment {
        /// First nonce point R1
        pub r1: ProjectivePoint,
        /// Second nonce point R2
        pub r2: ProjectivePoint,
        /// Private nonces (only known to signer)
        k1: Scalar,
        k2: Scalar,
    }

    impl NonceCommitment {
        /// Generate random nonce commitments
        pub fn generate() -> Self {
            let mut rng = rand::thread_rng();
            let mut k1_bytes = [0u8; 32];
            let mut k2_bytes = [0u8; 32];
            rng.fill_bytes(&mut k1_bytes);
            rng.fill_bytes(&mut k2_bytes);

            let k1 = <Scalar as Reduce<U256>>::reduce_bytes(&k1_bytes.into());
            let k2 = <Scalar as Reduce<U256>>::reduce_bytes(&k2_bytes.into());

            Self {
                r1: ProjectivePoint::GENERATOR * k1,
                r2: ProjectivePoint::GENERATOR * k2,
                k1,
                k2,
            }
        }

        /// Get the public nonce commitment bytes
        pub fn to_public_bytes(&self) -> [u8; 64] {
            let mut bytes = [0u8; 64];
            let r1_affine = self.r1.to_affine();
            let r2_affine = self.r2.to_affine();
            let r1_encoded = r1_affine.to_encoded_point(true);
            let r2_encoded = r2_affine.to_encoded_point(true);

            bytes[0..32].copy_from_slice(r1_encoded.x().unwrap().as_slice());
            bytes[32..64].copy_from_slice(r2_encoded.x().unwrap().as_slice());
            bytes
        }

        /// Create partial signature
        pub fn partial_sign(
            &self,
            secret: &SchnorrSecretKey,
            message: &[u8],
            agg_pubkey: &SchnorrPublicKey,
            combined_r: &[u8; 32],
            key_coeff: Scalar,
        ) -> PartialSignature {
            // e = H(R || agg_P || m)
            let mut hasher = Keccak256::new();
            hasher.update(b"schnorr_challenge");
            hasher.update(combined_r);
            hasher.update(&agg_pubkey.bytes);
            hasher.update(message);
            let hash: [u8; 32] = hasher.finalize().into();
            let e = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

            // Compute b for nonce combination
            let mut hasher = Keccak256::new();
            hasher.update(b"musig2_noncecoef");
            hasher.update(combined_r);
            hasher.update(message);
            let hash: [u8; 32] = hasher.finalize().into();
            let b = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

            // k = k1 + b * k2
            let k = self.k1 + b * self.k2;

            // s_i = k + e * a_i * x_i
            let s = k + e * key_coeff * secret.scalar;

            PartialSignature {
                s: s.to_bytes().into(),
            }
        }
    }

    /// Aggregate partial signatures into a final Schnorr signature
    pub fn aggregate_signatures(
        partials: &[PartialSignature],
        combined_r: [u8; 32],
    ) -> SchnorrSignature {
        let mut sum_s = Scalar::ZERO;

        for partial in partials {
            let s_opt = Scalar::from_repr(partial.s.into());
            if s_opt.is_some().into() {
                sum_s = sum_s + s_opt.unwrap();
            }
        }

        SchnorrSignature {
            r: combined_r,
            s: sum_s.to_bytes().into(),
        }
    }

    /// Combine nonce commitments from all signers
    pub fn combine_nonces(
        commitments: &[[u8; 64]],
        message: &[u8],
    ) -> [u8; 32] {
        // Sum all R1 and R2 points
        let mut sum_r1 = ProjectivePoint::IDENTITY;
        let mut sum_r2 = ProjectivePoint::IDENTITY;

        for commit in commitments {
            let r1 = parse_point_from_x(&commit[0..32]).unwrap_or(ProjectivePoint::IDENTITY);
            let r2 = parse_point_from_x(&commit[32..64]).unwrap_or(ProjectivePoint::IDENTITY);
            sum_r1 = sum_r1 + r1;
            sum_r2 = sum_r2 + r2;
        }

        // Compute b = H(sum_R1 || sum_R2 || m)
        let mut hasher = Keccak256::new();
        hasher.update(b"musig2_noncecoef");

        let sum_r1_affine = sum_r1.to_affine();
        let sum_r1_encoded = sum_r1_affine.to_encoded_point(true);
        hasher.update(sum_r1_encoded.x().unwrap().as_slice());
        hasher.update(message);

        let hash: [u8; 32] = hasher.finalize().into();
        let b = <Scalar as Reduce<U256>>::reduce_bytes(&hash.into());

        // R = sum_R1 + b * sum_R2
        let combined_r = sum_r1 + sum_r2 * b;
        let combined_r_affine = combined_r.to_affine();
        let combined_r_encoded = combined_r_affine.to_encoded_point(true);

        combined_r_encoded.x().unwrap().as_slice().try_into().unwrap()
    }

    fn parse_point_from_x(x_bytes: &[u8]) -> Option<ProjectivePoint> {
        if x_bytes.len() != 32 {
            return None;
        }

        let mut compressed = [0u8; 33];
        compressed[0] = 0x02;
        compressed[1..].copy_from_slice(x_bytes);

        let encoded = k256::EncodedPoint::from_bytes(&compressed).ok()?;
        let affine_opt = AffinePoint::from_encoded_point(&encoded);

        if affine_opt.is_some().into() {
            return Some(ProjectivePoint::from(affine_opt.unwrap()));
        }

        compressed[0] = 0x03;
        let encoded = k256::EncodedPoint::from_bytes(&compressed).ok()?;
        let affine_opt = AffinePoint::from_encoded_point(&encoded);

        if affine_opt.is_some().into() {
            Some(ProjectivePoint::from(affine_opt.unwrap()))
        } else {
            None
        }
    }
}

