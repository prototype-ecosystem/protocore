//! # Proto Core - Core Abstractions
//!
//! This crate provides the foundational traits and abstractions for the
//! Proto Core blockchain. It defines interfaces for:
//!
//! - **Storage**: Database backends for persisting blockchain data
//! - **Crypto**: Cryptographic operations (signing, verification, hashing)
//! - **Transport**: Network communication protocols
//!
//! # Design Philosophy
//!
//! The core crate follows these principles:
//!
//! 1. **Trait-based abstractions**: All major components are defined as traits,
//!    allowing different implementations to be swapped.
//!
//! 2. **Minimal dependencies**: This crate has few dependencies to avoid
//!    pulling in large libraries transitively.
//!
//! 3. **Thread safety**: All traits require `Send + Sync` for safe concurrent use.
//!
//! 4. **Async-first**: I/O operations use async/await for efficient concurrency.
//!
//! # Swappable Components
//!
//! | Component | Trait | Default Impl | Alternatives |
//! |-----------|-------|--------------|--------------|
//! | Storage | `StorageBackend` | RocksDB | MDBX, ParityDB |
//! | Signing | `Signer` | ECDSA/BLS | Ed25519, Schnorr |
//! | Network | `Transport` | libp2p | Custom P2P |
//!
//! # Example
//!
//! ```ignore
//! use protocore_core::traits::{StorageBackend, Signer, Transport};
//!
//! // Generic function that works with any implementation
//! async fn sync_chain<S, T>(storage: &S, network: &T)
//! where
//!     S: StorageBackend,
//!     T: Transport,
//! {
//!     // Works with any storage and network backend
//! }
//! ```

#![deny(missing_docs)]
#![deny(unsafe_code)]
#![warn(clippy::all)]

pub mod traits;

// Re-export commonly used types
pub use traits::{
    // Crypto
    BlsAggregator, CryptoError, CryptoResult, HashAlgorithm, Hasher, KeyGenerator, PublicKey,
    Signature, SignatureScheme, Signer, Verifier,
    // Storage
    StorageBackend, StorageBackendExt, StorageError, StorageIterator, StorageResult,
    StorageSnapshot, StorageStats, WriteBatch, WriteOperation,
    // Transport
    ConnectionDirection, DiscoveryStats, NetworkMessage, PeerDiscovery, PeerId, PeerInfo,
    Transport, TransportError, TransportEvent, TransportEventHandler, TransportResult,
    TransportStats,
};
