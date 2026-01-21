//! # VRF (Verifiable Random Function) Cryptography
//!
//! This module implements a Verifiable Random Function based on the ECVRF-EDWARDS25519-SHA512-TAI
//! construction. VRFs provide unpredictable, verifiable on-chain randomness.
//!
//! ## Overview
//!
//! A VRF is a cryptographic primitive that produces a pseudorandom output along with a proof
//! that the output was correctly computed. Given a secret key and an input, the VRF produces:
//! - A pseudorandom output that is unpredictable without the secret key
//! - A proof that anyone can verify using the corresponding public key
//!
//! ## Usage
//!
//! ```rust,ignore
//! use protocore_crypto::vrf::{VrfSecretKey, VrfPublicKey};
//!
//! // Generate a VRF key pair from a 32-byte seed
//! let seed = [0u8; 32];
//! let secret_key = VrfSecretKey::from_seed(&seed);
//! let public_key = secret_key.public_key();
//!
//! // Generate a VRF proof for some input
//! let input = b"block randomness input";
//! let (output, proof) = secret_key.prove(input);
//!
//! // Anyone can verify the proof and recover the same output
//! let verified_output = public_key.verify(input, &proof);
//! assert_eq!(verified_output, Some(output));
//! ```

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_POINT,
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

/// VRF secret key (same as validator's signing key)
///
/// The secret key is derived from a 32-byte seed using SHA-512 and clamping,
/// following the Ed25519 key derivation process.
#[derive(Clone)]
pub struct VrfSecretKey {
    scalar: Scalar,
    public: VrfPublicKey,
}

/// VRF public key
///
/// The public key is a point on the Ed25519 curve, stored both as an
/// `EdwardsPoint` for computation and as compressed bytes for serialization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfPublicKey {
    point: EdwardsPoint,
    compressed: [u8; 32],
}

/// VRF proof that can be verified
///
/// The proof contains all information needed to verify that a VRF output
/// was correctly computed for a given input and public key.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct VrfProof {
    /// Gamma point (compressed)
    pub gamma: [u8; 32],
    /// Challenge scalar
    pub c: [u8; 32],
    /// Response scalar
    pub s: [u8; 32],
}

/// VRF output (the random value)
///
/// The output is a 64-byte value derived from the gamma point.
/// This is the pseudorandom value that can be used as randomness.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VrfOutput {
    pub value: [u8; 64],
}

impl Default for VrfOutput {
    fn default() -> Self {
        Self { value: [0u8; 64] }
    }
}

impl Serialize for VrfOutput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.value)
    }
}

impl<'de> Deserialize<'de> for VrfOutput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 64 {
            return Err(D::Error::custom("VRF output must be 64 bytes"));
        }

        let mut value = [0u8; 64];
        value.copy_from_slice(&bytes);
        Ok(VrfOutput { value })
    }
}

impl VrfSecretKey {
    /// Create a VRF secret key from a 32-byte seed
    ///
    /// The seed is hashed with SHA-512 and the first 32 bytes are clamped
    /// according to the Ed25519 specification to produce the scalar.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let mut hasher = Sha512::new();
        hasher.update(seed);
        let hash = hasher.finalize();

        let mut scalar_bytes = [0u8; 32];
        scalar_bytes.copy_from_slice(&hash[..32]);
        // Clamp the scalar according to Ed25519 spec
        scalar_bytes[0] &= 248;
        scalar_bytes[31] &= 127;
        scalar_bytes[31] |= 64;

        let scalar = Scalar::from_bytes_mod_order(scalar_bytes);
        let point = &scalar * ED25519_BASEPOINT_POINT;

        Self {
            scalar,
            public: VrfPublicKey {
                point,
                compressed: point.compress().to_bytes(),
            },
        }
    }

    /// Get the corresponding public key
    pub fn public_key(&self) -> &VrfPublicKey {
        &self.public
    }

    /// Clone the public key
    pub fn public_key_owned(&self) -> VrfPublicKey {
        self.public.clone()
    }

    /// Generate VRF proof for input
    ///
    /// Returns both the VRF output (random value) and the proof that can be
    /// used to verify the output was correctly computed.
    pub fn prove(&self, input: &[u8]) -> (VrfOutput, VrfProof) {
        // Hash input to curve point
        let h = hash_to_curve(input);

        // Gamma = secret * H
        let gamma = self.scalar * h;

        // Generate deterministic nonce k
        let k = self.generate_nonce(input);

        // U = k * G
        let u = &k * ED25519_BASEPOINT_POINT;

        // V = k * H
        let v = k * h;

        // Challenge c = hash(G, H, public, Gamma, U, V)
        let c = self.compute_challenge(&h, &gamma, &u, &v);

        // Response s = k - c * secret
        let s = k - c * self.scalar;

        // Output = hash(Gamma)
        let output = VrfOutput {
            value: hash_point(&gamma),
        };

        let proof = VrfProof {
            gamma: gamma.compress().to_bytes(),
            c: c.to_bytes(),
            s: s.to_bytes(),
        };

        (output, proof)
    }

    /// Generate a deterministic nonce for the proof
    ///
    /// This ensures the proof is deterministic for the same input,
    /// preventing nonce reuse attacks.
    fn generate_nonce(&self, input: &[u8]) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"VRF_nonce");
        hasher.update(self.scalar.as_bytes());
        hasher.update(input);
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }

    /// Compute the challenge scalar for the proof
    fn compute_challenge(
        &self,
        h: &EdwardsPoint,
        gamma: &EdwardsPoint,
        u: &EdwardsPoint,
        v: &EdwardsPoint,
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"VRF_challenge");
        hasher.update(ED25519_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(h.compress().as_bytes());
        hasher.update(self.public.compressed);
        hasher.update(gamma.compress().as_bytes());
        hasher.update(u.compress().as_bytes());
        hasher.update(v.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }
}

impl VrfPublicKey {
    /// Create a VRF public key from compressed bytes
    ///
    /// Returns `None` if the bytes do not represent a valid curve point.
    pub fn from_bytes(bytes: &[u8; 32]) -> Option<Self> {
        let compressed = CompressedEdwardsY::from_slice(bytes).ok()?;
        let point = compressed.decompress()?;
        Some(Self {
            point,
            compressed: *bytes,
        })
    }

    /// Get the compressed bytes representation
    pub fn to_bytes(&self) -> [u8; 32] {
        self.compressed
    }

    /// Verify a VRF proof and return the output if valid
    ///
    /// Returns `Some(VrfOutput)` if the proof is valid, `None` otherwise.
    /// The returned output will match the output from `VrfSecretKey::prove()`
    /// for the same input.
    pub fn verify(&self, input: &[u8], proof: &VrfProof) -> Option<VrfOutput> {
        // Decompress gamma point
        let gamma = CompressedEdwardsY::from_slice(&proof.gamma)
            .ok()?
            .decompress()?;

        // Decode scalars - use from_canonical_bytes for strict validation
        let c_bytes: [u8; 32] = proof.c;
        let s_bytes: [u8; 32] = proof.s;

        let c = Scalar::from_canonical_bytes(c_bytes);
        let s = Scalar::from_canonical_bytes(s_bytes);

        // Handle Option return from from_canonical_bytes
        let c = if c.is_some().into() {
            c.unwrap()
        } else {
            return None;
        };
        let s = if s.is_some().into() {
            s.unwrap()
        } else {
            return None;
        };

        // Hash input to curve
        let h = hash_to_curve(input);

        // U = s * G + c * public
        let u = EdwardsPoint::vartime_double_scalar_mul_basepoint(&c, &self.point, &s);

        // V = s * H + c * Gamma
        let v = EdwardsPoint::vartime_multiscalar_mul(&[s, c], &[h, gamma]);

        // Recompute challenge
        let c_prime = self.compute_challenge_verify(&h, &gamma, &u, &v);

        if c_prime == c {
            Some(VrfOutput {
                value: hash_point(&gamma),
            })
        } else {
            None
        }
    }

    /// Compute the challenge for verification
    fn compute_challenge_verify(
        &self,
        h: &EdwardsPoint,
        gamma: &EdwardsPoint,
        u: &EdwardsPoint,
        v: &EdwardsPoint,
    ) -> Scalar {
        let mut hasher = Sha512::new();
        hasher.update(b"VRF_challenge");
        hasher.update(ED25519_BASEPOINT_POINT.compress().as_bytes());
        hasher.update(h.compress().as_bytes());
        hasher.update(self.compressed);
        hasher.update(gamma.compress().as_bytes());
        hasher.update(u.compress().as_bytes());
        hasher.update(v.compress().as_bytes());
        let hash = hasher.finalize();
        Scalar::from_bytes_mod_order_wide(&hash.into())
    }
}

impl Serialize for VrfPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_bytes(&self.compressed)
    }
}

impl<'de> Deserialize<'de> for VrfPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;

        let bytes: Vec<u8> = Vec::deserialize(deserializer)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("VRF public key must be 32 bytes"));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);

        VrfPublicKey::from_bytes(&arr).ok_or_else(|| D::Error::custom("Invalid VRF public key"))
    }
}

/// Hash arbitrary data to a curve point using Elligator2
///
/// This is a deterministic mapping from arbitrary byte strings to curve points,
/// used to hash the VRF input to the curve.
fn hash_to_curve(data: &[u8]) -> EdwardsPoint {
    let mut hasher = Sha512::new();
    hasher.update(b"VRF_hash_to_curve");
    hasher.update(data);
    let hash = hasher.finalize();

    // Use the nonspec_map_to_curve which uses Elligator2 internally
    // This maps arbitrary bytes to a curve point deterministically
    EdwardsPoint::nonspec_map_to_curve::<Sha512>(&hash)
}

/// Hash a curve point to a 64-byte output
///
/// This derives the final VRF output from the gamma point.
fn hash_point(point: &EdwardsPoint) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(b"VRF_output");
    hasher.update(point.compress().as_bytes());
    let hash = hasher.finalize();
    hash.into()
}
