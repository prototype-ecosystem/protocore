//! Core traits for Proto Core blockchain.
//!
//! This module defines abstract traits that allow different implementations
//! to be swapped in for storage, cryptography, and networking.
//!
//! # Architecture
//!
//! The traits are organized into three main categories:
//!
//! - **Storage**: Database backends (RocksDB, MDBX, etc.)
//! - **Crypto**: Signature schemes (ECDSA, BLS, Schnorr)
//! - **Transport**: Network protocols (libp2p, custom P2P)
//!
//! # Usage
//!
//! Other crates depend on these traits rather than concrete implementations,
//! enabling flexibility and testability.
//!
//! ```ignore
//! use protocore_core::traits::{StorageBackend, Signer, Transport};
//!
//! // Use trait bounds instead of concrete types
//! fn process_block<S: StorageBackend, T: Transport>(
//!     storage: &S,
//!     transport: &T,
//!     block: Block,
//! ) {
//!     // Implementation works with any backend
//! }
//! ```

mod crypto;
mod storage;
mod transport;

pub use crypto::*;
pub use storage::*;
pub use transport::*;
