//! Gossipsub topics and message handling for Protocore.
//!
//! This module defines:
//! - Topic constants for different message types
//! - Message serialization/deserialization
//! - Topic subscription management

use libp2p::gossipsub::IdentTopic;
use serde::{Deserialize, Serialize};

// Re-export consensus types for use in GossipMessage
pub use protocore_consensus::{FinalityCert, Proposal, Vote};

/// New view message for view change protocol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewView {
    /// New view number
    pub view: u64,
    /// Height
    pub height: u64,
    /// Validator index
    pub validator_index: u64,
    /// Highest locked block (if any)
    pub locked_block: Option<[u8; 32]>,
    /// Signature
    pub signature: Vec<u8>,
}

/// Gossipsub topic names for Protocore
pub mod topics {
    /// Topic for consensus messages (proposals, votes, finality certificates)
    pub const CONSENSUS: &str = "/protocore/consensus/1.0.0";
    /// Topic for block announcements
    pub const BLOCKS: &str = "/protocore/blocks/1.0.0";
    /// Topic for transaction propagation
    pub const TRANSACTIONS: &str = "/protocore/txs/1.0.0";
}

/// Wrapper for gossipsub topics
pub struct Topics {
    /// Consensus topic for proposals and votes
    pub consensus: IdentTopic,
    /// Blocks topic for new block announcements
    pub blocks: IdentTopic,
    /// Transactions topic for new transaction propagation
    pub transactions: IdentTopic,
}

impl Default for Topics {
    fn default() -> Self {
        Self::new()
    }
}

impl Topics {
    /// Create new topic instances
    pub fn new() -> Self {
        Self {
            consensus: IdentTopic::new(topics::CONSENSUS),
            blocks: IdentTopic::new(topics::BLOCKS),
            transactions: IdentTopic::new(topics::TRANSACTIONS),
        }
    }

    /// Get all topics as a vector
    pub fn all(&self) -> Vec<&IdentTopic> {
        vec![&self.consensus, &self.blocks, &self.transactions]
    }

    /// Get topic by message type
    pub fn for_message_type(&self, msg_type: &MessageType) -> &IdentTopic {
        match msg_type {
            MessageType::Proposal
            | MessageType::Vote
            | MessageType::FinalityCert
            | MessageType::NewView => &self.consensus,
            MessageType::NewBlock | MessageType::BlockRequest | MessageType::BlockResponse => {
                &self.blocks
            }
            MessageType::NewTransaction | MessageType::TransactionRequest => &self.transactions,
        }
    }
}

/// Message types for categorization
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MessageType {
    /// Consensus proposal message
    Proposal,
    /// Consensus vote message
    Vote,
    /// Finality certificate
    FinalityCert,
    /// New view message for view change
    NewView,
    /// New block announcement
    NewBlock,
    /// Request for a specific block
    BlockRequest,
    /// Response with requested block
    BlockResponse,
    /// New transaction announcement
    NewTransaction,
    /// Request for a specific transaction
    TransactionRequest,
}

// Note: Proposal, Vote, FinalityCert, and NewView are now re-exported from protocore-consensus

/// Block announcement message
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewBlock {
    /// Serialized block header
    pub header: Vec<u8>,
    /// Block height (for quick filtering)
    pub height: u64,
    /// Block hash
    pub hash: [u8; 32],
    /// Finality certificate
    pub finality_cert: FinalityCert,
}

/// Request for a specific block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockRequest {
    /// Requested block height
    pub height: u64,
    /// Optional: request by hash instead
    pub hash: Option<[u8; 32]>,
}

/// Response with requested block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockResponse {
    /// Serialized full block
    pub block: Vec<u8>,
    /// Finality certificate
    pub cert: FinalityCert,
}

/// New transaction announcement
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewTransaction {
    /// Transaction hash
    pub hash: [u8; 32],
    /// Serialized transaction data
    pub data: Vec<u8>,
}

/// Request for a specific transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    /// Transaction hash
    pub hash: [u8; 32],
}

/// Gossip message wrapper containing typed message data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GossipMessage {
    /// Consensus proposal
    Proposal(Proposal),
    /// Consensus vote
    Vote(Vote),
    /// Finality certificate
    FinalityCert(FinalityCert),
    /// New view message
    NewView(NewView),
    /// New block announcement
    NewBlock(NewBlock),
    /// Block request
    BlockRequest(BlockRequest),
    /// Block response
    BlockResponse(BlockResponse),
    /// New transaction
    NewTransaction(NewTransaction),
    /// Transaction request
    TransactionRequest(TransactionRequest),
}

impl GossipMessage {
    /// Get the message type
    pub fn message_type(&self) -> MessageType {
        match self {
            GossipMessage::Proposal(_) => MessageType::Proposal,
            GossipMessage::Vote(_) => MessageType::Vote,
            GossipMessage::FinalityCert(_) => MessageType::FinalityCert,
            GossipMessage::NewView(_) => MessageType::NewView,
            GossipMessage::NewBlock(_) => MessageType::NewBlock,
            GossipMessage::BlockRequest(_) => MessageType::BlockRequest,
            GossipMessage::BlockResponse(_) => MessageType::BlockResponse,
            GossipMessage::NewTransaction(_) => MessageType::NewTransaction,
            GossipMessage::TransactionRequest(_) => MessageType::TransactionRequest,
        }
    }

    /// Serialize the message to bytes
    pub fn encode(&self) -> crate::Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(crate::Error::Serialization)
    }

    /// Deserialize message from bytes
    pub fn decode(data: &[u8]) -> crate::Result<Self> {
        serde_json::from_slice(data).map_err(crate::Error::Serialization)
    }

    /// Get the topic this message should be published to
    pub fn topic(&self, topics: &Topics) -> IdentTopic {
        topics.for_message_type(&self.message_type()).clone()
    }

    /// Check if this is a consensus message
    pub fn is_consensus(&self) -> bool {
        matches!(
            self,
            GossipMessage::Proposal(_)
                | GossipMessage::Vote(_)
                | GossipMessage::FinalityCert(_)
                | GossipMessage::NewView(_)
        )
    }

    /// Check if this is a block-related message
    pub fn is_block(&self) -> bool {
        matches!(
            self,
            GossipMessage::NewBlock(_)
                | GossipMessage::BlockRequest(_)
                | GossipMessage::BlockResponse(_)
        )
    }

    /// Check if this is a transaction-related message
    pub fn is_transaction(&self) -> bool {
        matches!(
            self,
            GossipMessage::NewTransaction(_) | GossipMessage::TransactionRequest(_)
        )
    }

    /// Extract height from message (if applicable)
    pub fn height(&self) -> Option<u64> {
        match self {
            GossipMessage::Proposal(p) => Some(p.height),
            GossipMessage::Vote(v) => Some(v.height),
            GossipMessage::FinalityCert(c) => Some(c.height),
            GossipMessage::NewView(nv) => Some(nv.height),
            GossipMessage::NewBlock(b) => Some(b.height),
            GossipMessage::BlockRequest(r) => Some(r.height),
            _ => None,
        }
    }
}

/// Subscription manager for gossipsub topics
pub struct TopicSubscription {
    topics: Topics,
    subscribed: std::collections::HashSet<String>,
}

impl Default for TopicSubscription {
    fn default() -> Self {
        Self::new()
    }
}

impl TopicSubscription {
    /// Create a new subscription manager
    pub fn new() -> Self {
        Self {
            topics: Topics::new(),
            subscribed: std::collections::HashSet::new(),
        }
    }

    /// Get the topics instance
    pub fn topics(&self) -> &Topics {
        &self.topics
    }

    /// Check if subscribed to a topic
    pub fn is_subscribed(&self, topic: &str) -> bool {
        self.subscribed.contains(topic)
    }

    /// Mark a topic as subscribed
    pub fn mark_subscribed(&mut self, topic: &str) {
        self.subscribed.insert(topic.to_string());
    }

    /// Mark a topic as unsubscribed
    pub fn mark_unsubscribed(&mut self, topic: &str) {
        self.subscribed.remove(topic);
    }

    /// Subscribe to all default topics
    pub fn subscribe_all<F>(&mut self, mut subscribe_fn: F) -> crate::Result<()>
    where
        F: FnMut(&IdentTopic) -> crate::Result<bool>,
    {
        // Subscribe to consensus topic
        subscribe_fn(&self.topics.consensus)?;
        let consensus_name = self.topics.consensus.to_string();

        // Subscribe to blocks topic
        subscribe_fn(&self.topics.blocks)?;
        let blocks_name = self.topics.blocks.to_string();

        // Subscribe to transactions topic
        subscribe_fn(&self.topics.transactions)?;
        let transactions_name = self.topics.transactions.to_string();

        // Mark all as subscribed
        self.mark_subscribed(&consensus_name);
        self.mark_subscribed(&blocks_name);
        self.mark_subscribed(&transactions_name);

        Ok(())
    }

    /// Subscribe to consensus topic only
    pub fn subscribe_consensus<F>(&mut self, mut subscribe_fn: F) -> crate::Result<()>
    where
        F: FnMut(&IdentTopic) -> crate::Result<bool>,
    {
        subscribe_fn(&self.topics.consensus)?;
        self.mark_subscribed(&self.topics.consensus.to_string());
        Ok(())
    }

    /// Subscribe to blocks topic only
    pub fn subscribe_blocks<F>(&mut self, mut subscribe_fn: F) -> crate::Result<()>
    where
        F: FnMut(&IdentTopic) -> crate::Result<bool>,
    {
        subscribe_fn(&self.topics.blocks)?;
        self.mark_subscribed(&self.topics.blocks.to_string());
        Ok(())
    }

    /// Subscribe to transactions topic only
    pub fn subscribe_transactions<F>(&mut self, mut subscribe_fn: F) -> crate::Result<()>
    where
        F: FnMut(&IdentTopic) -> crate::Result<bool>,
    {
        subscribe_fn(&self.topics.transactions)?;
        self.mark_subscribed(&self.topics.transactions.to_string());
        Ok(())
    }
}
