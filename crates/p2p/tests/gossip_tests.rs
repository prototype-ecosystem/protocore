//! Tests for gossipsub topics and message handling.

use protocore_p2p::gossip::{topics, MessageType, TopicSubscription, Topics};

#[test]
fn test_topics_creation() {
    let topics_instance = Topics::new();
    assert_eq!(topics_instance.consensus.to_string(), topics::CONSENSUS);
    assert_eq!(topics_instance.blocks.to_string(), topics::BLOCKS);
    assert_eq!(
        topics_instance.transactions.to_string(),
        topics::TRANSACTIONS
    );
}

#[test]
fn test_topic_for_message_type() {
    let topics_instance = Topics::new();

    assert_eq!(
        topics_instance
            .for_message_type(&MessageType::Vote)
            .to_string(),
        topics::CONSENSUS
    );
    assert_eq!(
        topics_instance
            .for_message_type(&MessageType::NewBlock)
            .to_string(),
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
