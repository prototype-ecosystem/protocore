//! Merkle Patricia Trie implementation
//!
//! This module implements a Merkle Patricia Trie for efficient and verifiable
//! storage of key-value data. It is used for computing state_root, transactions_root,
//! and receipts_root in block headers.

use bytes::Bytes;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::{keccak256, Hash, Result, StorageError, EMPTY_ROOT};

/// Nibble representation for trie paths
#[derive(Debug, Clone, PartialEq, Eq)]
struct Nibbles(Vec<u8>);

impl Nibbles {
    /// Create nibbles from bytes
    fn from_bytes(bytes: &[u8]) -> Self {
        let mut nibbles = Vec::with_capacity(bytes.len() * 2);
        for byte in bytes {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0f);
        }
        Nibbles(nibbles)
    }

    /// Convert nibbles back to bytes (must have even length)
    fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity((self.0.len() + 1) / 2);
        for i in (0..self.0.len()).step_by(2) {
            if i + 1 < self.0.len() {
                bytes.push((self.0[i] << 4) | self.0[i + 1]);
            } else {
                bytes.push(self.0[i] << 4);
            }
        }
        bytes
    }

    /// Get the length
    fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Get a slice
    fn slice(&self, start: usize) -> Nibbles {
        Nibbles(self.0[start..].to_vec())
    }

    /// Get common prefix length with another nibbles
    fn common_prefix_len(&self, other: &Nibbles) -> usize {
        self.0
            .iter()
            .zip(other.0.iter())
            .take_while(|(a, b)| a == b)
            .count()
    }

    /// Encode nibbles with prefix for compact encoding
    /// - For leaf nodes: prefix with 0x20 (even length) or 0x3 (odd length)
    /// - For extension nodes: prefix with 0x00 (even length) or 0x1 (odd length)
    fn encode_compact(&self, is_leaf: bool) -> Vec<u8> {
        let odd = self.0.len() % 2 == 1;
        let mut result = Vec::with_capacity((self.0.len() + 2) / 2);

        let prefix = match (is_leaf, odd) {
            (false, false) => 0x00,
            (false, true) => 0x01,
            (true, false) => 0x02,
            (true, true) => 0x03,
        };

        if odd {
            result.push((prefix << 4) | self.0[0]);
            for i in (1..self.0.len()).step_by(2) {
                if i + 1 < self.0.len() {
                    result.push((self.0[i] << 4) | self.0[i + 1]);
                }
            }
        } else {
            result.push(prefix << 4);
            for i in (0..self.0.len()).step_by(2) {
                if i + 1 < self.0.len() {
                    result.push((self.0[i] << 4) | self.0[i + 1]);
                }
            }
        }

        result
    }

    /// Decode compact encoding
    fn decode_compact(data: &[u8]) -> (Nibbles, bool) {
        if data.is_empty() {
            return (Nibbles(vec![]), false);
        }

        let prefix = data[0] >> 4;
        let is_leaf = prefix >= 2;
        let odd = prefix % 2 == 1;

        let mut nibbles = Vec::new();

        if odd {
            nibbles.push(data[0] & 0x0f);
        }

        for &byte in &data[1..] {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0f);
        }

        (Nibbles(nibbles), is_leaf)
    }
}

/// Trie node types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrieNode {
    /// Empty node
    Empty,
    /// Leaf node with path suffix and value
    Leaf {
        /// Path suffix (compact encoded)
        path: Vec<u8>,
        /// Value stored at this leaf
        value: Vec<u8>,
    },
    /// Extension node with shared path prefix
    Extension {
        /// Shared path prefix (compact encoded)
        path: Vec<u8>,
        /// Hash of child node
        child: Hash,
    },
    /// Branch node with 16 children and optional value
    Branch {
        /// Children (16 slots for each nibble 0-f)
        children: [Option<Hash>; 16],
        /// Value if this node is also a leaf
        value: Option<Vec<u8>>,
    },
}

impl TrieNode {
    /// Compute the hash of this node
    pub fn hash(&self) -> Hash {
        let encoded = self.encode();
        keccak256(&encoded)
    }

    /// Encode the node for storage
    pub fn encode(&self) -> Vec<u8> {
        bincode::serialize(self).unwrap_or_default()
    }

    /// Decode a node from bytes
    pub fn decode(data: &[u8]) -> Result<Self> {
        bincode::deserialize(data).map_err(|e| StorageError::Serialization(e.to_string()))
    }
}

/// Merkle proof for verifying inclusion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Key being proven
    pub key: Vec<u8>,
    /// Value (None if proving absence)
    pub value: Option<Vec<u8>>,
    /// Proof nodes from leaf to root
    pub nodes: Vec<Vec<u8>>,
    /// Root hash this proof is against
    pub root: Hash,
}

impl MerkleProof {
    /// Verify the proof against its root
    pub fn verify(&self) -> bool {
        if self.nodes.is_empty() {
            return self.root == EMPTY_ROOT && self.value.is_none();
        }

        let key_nibbles = Nibbles::from_bytes(&self.key);
        let mut current_hash = self.root;
        let mut key_offset = 0;

        for node_data in &self.nodes {
            if let Ok(node) = TrieNode::decode(node_data) {
                // Verify node hash matches expected
                if node.hash() != current_hash {
                    return false;
                }

                match node {
                    TrieNode::Empty => {
                        return self.value.is_none();
                    }
                    TrieNode::Leaf { path, value } => {
                        let (path_nibbles, is_leaf) = Nibbles::decode_compact(&path);
                        if !is_leaf {
                            return false;
                        }

                        // Check remaining path matches
                        let remaining = key_nibbles.slice(key_offset);
                        if path_nibbles.0 != remaining.0 {
                            return self.value.is_none();
                        }

                        return self.value.as_ref() == Some(&value);
                    }
                    TrieNode::Extension { path, child } => {
                        let (path_nibbles, _) = Nibbles::decode_compact(&path);

                        // Check path matches
                        let remaining = key_nibbles.slice(key_offset);
                        if remaining.0.len() < path_nibbles.0.len() {
                            return false;
                        }
                        for i in 0..path_nibbles.0.len() {
                            if remaining.0[i] != path_nibbles.0[i] {
                                return false;
                            }
                        }

                        key_offset += path_nibbles.len();
                        current_hash = child;
                    }
                    TrieNode::Branch {
                        children,
                        value: branch_value,
                    } => {
                        if key_offset >= key_nibbles.len() {
                            return self.value == branch_value;
                        }

                        let nibble = key_nibbles.0[key_offset] as usize;
                        key_offset += 1;

                        match children[nibble] {
                            Some(child_hash) => {
                                current_hash = child_hash;
                            }
                            None => {
                                return self.value.is_none();
                            }
                        }
                    }
                }
            } else {
                return false;
            }
        }

        false
    }
}

/// Merkle Patricia Trie
pub struct MerkleTrie {
    /// Node storage (hash -> node)
    nodes: Arc<RwLock<HashMap<Hash, TrieNode>>>,
    /// Current root hash
    root: RwLock<Hash>,
}

impl MerkleTrie {
    /// Create a new empty trie
    pub fn new() -> Self {
        Self {
            nodes: Arc::new(RwLock::new(HashMap::new())),
            root: RwLock::new(EMPTY_ROOT),
        }
    }

    /// Create a trie from an existing root
    pub fn from_root(root: Hash, nodes: HashMap<Hash, TrieNode>) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(nodes)),
            root: RwLock::new(root),
        }
    }

    /// Get the current root hash
    pub fn root(&self) -> Hash {
        *self.root.read()
    }

    /// Insert a key-value pair
    pub fn insert(&self, key: &[u8], value: &[u8]) -> Result<()> {
        let key_nibbles = Nibbles::from_bytes(key);
        let current_root = *self.root.read();

        let new_root = self.insert_at(current_root, key_nibbles, Bytes::copy_from_slice(value))?;
        *self.root.write() = new_root;

        Ok(())
    }

    /// Internal insert implementation
    fn insert_at(&self, node_hash: Hash, path: Nibbles, value: Bytes) -> Result<Hash> {
        if node_hash == EMPTY_ROOT {
            // Create a new leaf node
            let leaf = TrieNode::Leaf {
                path: path.encode_compact(true),
                value: value.to_vec(),
            };
            return self.store_node(leaf);
        }

        let node = self.get_node(&node_hash)?;

        match node {
            TrieNode::Empty => {
                let leaf = TrieNode::Leaf {
                    path: path.encode_compact(true),
                    value: value.to_vec(),
                };
                self.store_node(leaf)
            }
            TrieNode::Leaf {
                path: leaf_path,
                value: leaf_value,
            } => {
                let (leaf_nibbles, _) = Nibbles::decode_compact(&leaf_path);

                if leaf_nibbles.0 == path.0 {
                    // Same key, update value
                    let new_leaf = TrieNode::Leaf {
                        path: leaf_path,
                        value: value.to_vec(),
                    };
                    self.store_node(new_leaf)
                } else {
                    // Different keys, need to create a branch
                    let common_len = leaf_nibbles.common_prefix_len(&path);

                    let mut branch_children: [Option<Hash>; 16] = Default::default();
                    let mut branch_value = None;

                    // Insert existing leaf
                    if common_len < leaf_nibbles.len() {
                        let nibble = leaf_nibbles.0[common_len] as usize;
                        let remaining = leaf_nibbles.slice(common_len + 1);
                        if remaining.is_empty() {
                            branch_value = Some(leaf_value.clone());
                        } else {
                            let new_leaf = TrieNode::Leaf {
                                path: remaining.encode_compact(true),
                                value: leaf_value,
                            };
                            branch_children[nibble] = Some(self.store_node(new_leaf)?);
                        }
                    } else {
                        branch_value = Some(leaf_value);
                    }

                    // Insert new value
                    if common_len < path.len() {
                        let nibble = path.0[common_len] as usize;
                        let remaining = path.slice(common_len + 1);
                        if remaining.is_empty() {
                            branch_value = Some(value.to_vec());
                        } else {
                            let new_leaf = TrieNode::Leaf {
                                path: remaining.encode_compact(true),
                                value: value.to_vec(),
                            };
                            branch_children[nibble] = Some(self.store_node(new_leaf)?);
                        }
                    } else {
                        branch_value = Some(value.to_vec());
                    }

                    let branch = TrieNode::Branch {
                        children: branch_children,
                        value: branch_value,
                    };
                    let branch_hash = self.store_node(branch)?;

                    // If there's a common prefix, create an extension node
                    if common_len > 0 {
                        let prefix = Nibbles(path.0[..common_len].to_vec());
                        let extension = TrieNode::Extension {
                            path: prefix.encode_compact(false),
                            child: branch_hash,
                        };
                        self.store_node(extension)
                    } else {
                        Ok(branch_hash)
                    }
                }
            }
            TrieNode::Extension {
                path: ext_path,
                child,
            } => {
                let (ext_nibbles, _) = Nibbles::decode_compact(&ext_path);
                let common_len = ext_nibbles.common_prefix_len(&path);

                if common_len == ext_nibbles.len() {
                    // Path goes through extension
                    let remaining = path.slice(common_len);
                    let new_child = self.insert_at(child, remaining, value)?;
                    let new_ext = TrieNode::Extension {
                        path: ext_path,
                        child: new_child,
                    };
                    self.store_node(new_ext)
                } else {
                    // Need to split extension
                    let mut branch_children: [Option<Hash>; 16] = Default::default();

                    // Remaining of extension
                    if common_len + 1 < ext_nibbles.len() {
                        let nibble = ext_nibbles.0[common_len] as usize;
                        let remaining = ext_nibbles.slice(common_len + 1);
                        let new_ext = TrieNode::Extension {
                            path: remaining.encode_compact(false),
                            child,
                        };
                        branch_children[nibble] = Some(self.store_node(new_ext)?);
                    } else {
                        let nibble = ext_nibbles.0[common_len] as usize;
                        branch_children[nibble] = Some(child);
                    }

                    // New value
                    let mut branch_value = None;
                    if common_len < path.len() {
                        let nibble = path.0[common_len] as usize;
                        let remaining = path.slice(common_len + 1);
                        if remaining.is_empty() {
                            branch_value = Some(value.to_vec());
                        } else {
                            let new_leaf = TrieNode::Leaf {
                                path: remaining.encode_compact(true),
                                value: value.to_vec(),
                            };
                            branch_children[nibble] = Some(self.store_node(new_leaf)?);
                        }
                    } else {
                        branch_value = Some(value.to_vec());
                    }

                    let branch = TrieNode::Branch {
                        children: branch_children,
                        value: branch_value,
                    };
                    let branch_hash = self.store_node(branch)?;

                    if common_len > 0 {
                        let prefix = Nibbles(path.0[..common_len].to_vec());
                        let extension = TrieNode::Extension {
                            path: prefix.encode_compact(false),
                            child: branch_hash,
                        };
                        self.store_node(extension)
                    } else {
                        Ok(branch_hash)
                    }
                }
            }
            TrieNode::Branch {
                mut children,
                value: branch_value,
            } => {
                if path.is_empty() {
                    let new_branch = TrieNode::Branch {
                        children,
                        value: Some(value.to_vec()),
                    };
                    self.store_node(new_branch)
                } else {
                    let nibble = path.0[0] as usize;
                    let remaining = path.slice(1);
                    let child_hash = children[nibble].unwrap_or(EMPTY_ROOT);
                    let new_child = self.insert_at(child_hash, remaining, value)?;
                    children[nibble] = Some(new_child);
                    let new_branch = TrieNode::Branch {
                        children,
                        value: branch_value,
                    };
                    self.store_node(new_branch)
                }
            }
        }
    }

    /// Get a value by key
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>> {
        let key_nibbles = Nibbles::from_bytes(key);
        let root = *self.root.read();
        self.get_at(root, key_nibbles)
    }

    /// Internal get implementation
    fn get_at(&self, node_hash: Hash, path: Nibbles) -> Result<Option<Vec<u8>>> {
        if node_hash == EMPTY_ROOT {
            return Ok(None);
        }

        let node = self.get_node(&node_hash)?;

        match node {
            TrieNode::Empty => Ok(None),
            TrieNode::Leaf {
                path: leaf_path,
                value,
            } => {
                let (leaf_nibbles, _) = Nibbles::decode_compact(&leaf_path);
                if leaf_nibbles.0 == path.0 {
                    Ok(Some(value))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Extension {
                path: ext_path,
                child,
            } => {
                let (ext_nibbles, _) = Nibbles::decode_compact(&ext_path);
                if path.0.len() >= ext_nibbles.len() && path.0[..ext_nibbles.len()] == ext_nibbles.0
                {
                    let remaining = path.slice(ext_nibbles.len());
                    self.get_at(child, remaining)
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch { children, value } => {
                if path.is_empty() {
                    Ok(value)
                } else {
                    let nibble = path.0[0] as usize;
                    match children[nibble] {
                        Some(child_hash) => {
                            let remaining = path.slice(1);
                            self.get_at(child_hash, remaining)
                        }
                        None => Ok(None),
                    }
                }
            }
        }
    }

    /// Delete a key from the trie
    pub fn delete(&self, key: &[u8]) -> Result<bool> {
        let key_nibbles = Nibbles::from_bytes(key);
        let current_root = *self.root.read();

        match self.delete_at(current_root, key_nibbles)? {
            Some(new_root) => {
                *self.root.write() = new_root;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Internal delete implementation
    fn delete_at(&self, node_hash: Hash, path: Nibbles) -> Result<Option<Hash>> {
        if node_hash == EMPTY_ROOT {
            return Ok(None);
        }

        let node = self.get_node(&node_hash)?;

        match node {
            TrieNode::Empty => Ok(None),
            TrieNode::Leaf {
                path: leaf_path, ..
            } => {
                let (leaf_nibbles, _) = Nibbles::decode_compact(&leaf_path);
                if leaf_nibbles.0 == path.0 {
                    Ok(Some(EMPTY_ROOT))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Extension {
                path: ext_path,
                child,
            } => {
                let (ext_nibbles, _) = Nibbles::decode_compact(&ext_path);
                if path.0.len() >= ext_nibbles.len() && path.0[..ext_nibbles.len()] == ext_nibbles.0
                {
                    let remaining = path.slice(ext_nibbles.len());
                    if let Some(new_child) = self.delete_at(child, remaining)? {
                        if new_child == EMPTY_ROOT {
                            Ok(Some(EMPTY_ROOT))
                        } else {
                            let new_ext = TrieNode::Extension {
                                path: ext_path,
                                child: new_child,
                            };
                            Ok(Some(self.store_node(new_ext)?))
                        }
                    } else {
                        Ok(None)
                    }
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch {
                mut children,
                value,
            } => {
                if path.is_empty() {
                    if value.is_none() {
                        return Ok(None);
                    }
                    // Remove value from branch
                    let new_branch = TrieNode::Branch {
                        children,
                        value: None,
                    };
                    Ok(Some(self.store_node(new_branch)?))
                } else {
                    let nibble = path.0[0] as usize;
                    match children[nibble] {
                        Some(child_hash) => {
                            let remaining = path.slice(1);
                            if let Some(new_child) = self.delete_at(child_hash, remaining)? {
                                if new_child == EMPTY_ROOT {
                                    children[nibble] = None;
                                } else {
                                    children[nibble] = Some(new_child);
                                }
                                let new_branch = TrieNode::Branch { children, value };
                                Ok(Some(self.store_node(new_branch)?))
                            } else {
                                Ok(None)
                            }
                        }
                        None => Ok(None),
                    }
                }
            }
        }
    }

    /// Generate a Merkle proof for a key
    pub fn prove(&self, key: &[u8]) -> Result<MerkleProof> {
        let key_nibbles = Nibbles::from_bytes(key);
        let root = *self.root.read();
        let mut nodes = Vec::new();
        let value = self.prove_at(root, key_nibbles, &mut nodes)?;

        Ok(MerkleProof {
            key: key.to_vec(),
            value,
            nodes,
            root,
        })
    }

    /// Internal prove implementation
    fn prove_at(
        &self,
        node_hash: Hash,
        path: Nibbles,
        proof_nodes: &mut Vec<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        if node_hash == EMPTY_ROOT {
            return Ok(None);
        }

        let node = self.get_node(&node_hash)?;
        proof_nodes.push(node.encode());

        match &node {
            TrieNode::Empty => Ok(None),
            TrieNode::Leaf {
                path: leaf_path,
                value,
            } => {
                let (leaf_nibbles, _) = Nibbles::decode_compact(leaf_path);
                if leaf_nibbles.0 == path.0 {
                    Ok(Some(value.clone()))
                } else {
                    Ok(None)
                }
            }
            TrieNode::Extension {
                path: ext_path,
                child,
            } => {
                let (ext_nibbles, _) = Nibbles::decode_compact(ext_path);
                if path.0.len() >= ext_nibbles.len() && path.0[..ext_nibbles.len()] == ext_nibbles.0
                {
                    let remaining = path.slice(ext_nibbles.len());
                    self.prove_at(*child, remaining, proof_nodes)
                } else {
                    Ok(None)
                }
            }
            TrieNode::Branch { children, value } => {
                if path.is_empty() {
                    Ok(value.clone())
                } else {
                    let nibble = path.0[0] as usize;
                    match children[nibble] {
                        Some(child_hash) => {
                            let remaining = path.slice(1);
                            self.prove_at(child_hash, remaining, proof_nodes)
                        }
                        None => Ok(None),
                    }
                }
            }
        }
    }

    /// Store a node and return its hash
    fn store_node(&self, node: TrieNode) -> Result<Hash> {
        let hash = node.hash();
        self.nodes.write().insert(hash, node);
        Ok(hash)
    }

    /// Get a node by hash
    fn get_node(&self, hash: &Hash) -> Result<TrieNode> {
        self.nodes
            .read()
            .get(hash)
            .cloned()
            .ok_or_else(|| StorageError::NotFound(format!("Node not found: {:?}", hash)))
    }

    /// Check if the trie is empty
    pub fn is_empty(&self) -> bool {
        *self.root.read() == EMPTY_ROOT
    }

    /// Get all nodes (for persistence)
    pub fn nodes(&self) -> HashMap<Hash, TrieNode> {
        self.nodes.read().clone()
    }

    /// Clear the trie
    pub fn clear(&self) {
        self.nodes.write().clear();
        *self.root.write() = EMPTY_ROOT;
    }
}

impl Default for MerkleTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for MerkleTrie {
    fn clone(&self) -> Self {
        Self {
            nodes: Arc::new(RwLock::new(self.nodes.read().clone())),
            root: RwLock::new(*self.root.read()),
        }
    }
}

/// Verify a Merkle proof
pub fn verify_proof(proof: &MerkleProof) -> bool {
    proof.verify()
}
