//! Tests for gossipsub topics and message handling.

use protocore_p2p::{
    gossip::{
        topics, GossipMessage, MessageType, Proposal, TopicSubscription, Topics, Vote, VoteType,
    },
};

#[test]
fn test_topics_creation() {
    let topics_instance = Topics::new();
    assert_eq!(topics_instance.consensus.to_string(), topics::CONSENSUS);
    assert_eq!(topics_instance.blocks.to_string(), topics::BLOCKS);
    assert_eq!(topics_instance.transactions.to_string(), topics::TRANSACTIONS);
}

#[test]
fn test_message_encoding_decoding() {
    let vote = Vote {
        height: 100,
        view: 1,
        validator_index: 5,
        block_hash: [0u8; 32],
        vote_type: VoteType::Prevote,
        signature: vec![1, 2, 3, 4],
    };

    let msg = GossipMessage::Vote(vote);
    let encoded = msg.encode().unwrap();
    let decoded = GossipMessage::decode(&encoded).unwrap();

    assert!(matches!(decoded, GossipMessage::Vote(_)));
    if let GossipMessage::Vote(v) = decoded {
        assert_eq!(v.height, 100);
        assert_eq!(v.validator_index, 5);
    }
}

#[test]
fn test_message_type_classification() {
    let proposal = GossipMessage::Proposal(Proposal {
        height: 1,
        view: 1,
        proposer: 0,
        block_hash: [0u8; 32],
        parent_hash: [0u8; 32],
        block_data: vec![],
        signature: vec![],
    });

    assert!(proposal.is_consensus());
    assert!(!proposal.is_block());
    assert!(!proposal.is_transaction());
    assert_eq!(proposal.message_type(), MessageType::Proposal);
}

#[test]
fn test_topic_for_message_type() {
    let topics_instance = Topics::new();

    assert_eq!(
        topics_instance.for_message_type(&MessageType::Vote).to_string(),
        topics::CONSENSUS
    );
    assert_eq!(
        topics_instance.for_message_type(&MessageType::NewBlock).to_string(),
        topics::BLOCKS
    );
    assert_eq!(
        topics_instance
            .for_message_type(&MessageType::NewTransaction)
            .to_string(),
        topics::TRANSACTIONS
    );
}

#[test]
fn test_subscription_manager() {
    let mut sub = TopicSubscription::new();
    assert!(!sub.is_subscribed(topics::CONSENSUS));

    sub.mark_subscribed(topics::CONSENSUS);
    assert!(sub.is_subscribed(topics::CONSENSUS));

    sub.mark_unsubscribed(topics::CONSENSUS);
    assert!(!sub.is_subscribed(topics::CONSENSUS));
}
