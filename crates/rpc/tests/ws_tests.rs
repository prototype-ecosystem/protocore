//! Tests for WebSocket subscriptions

use protocore_rpc::ws::{LogSubscriptionParams, SubscriptionKind, SubscriptionManager};
use protocore_rpc::types::{
    Address, AddressFilter, H256, HexBytes, HexU64, RpcLog, TopicFilter,
};

// Helper function for log filter matching (replicated from ws.rs for testing)
fn matches_log_filter(log: &RpcLog, filter: &LogSubscriptionParams) -> bool {
    // Check address filter
    if let Some(ref addr_filter) = filter.address {
        match addr_filter {
            AddressFilter::Single(addr) => {
                if log.address != *addr {
                    return false;
                }
            }
            AddressFilter::Multiple(addrs) => {
                if !addrs.contains(&log.address) {
                    return false;
                }
            }
        }
    }

    // Check topic filters
    if let Some(ref topic_filters) = filter.topics {
        let topic_filters: &Vec<Option<TopicFilter>> = topic_filters;
        for (i, topic_filter) in topic_filters.iter().enumerate() {
            if let Some(ref tf) = topic_filter {
                if i >= log.topics.len() {
                    return false;
                }
                match tf {
                    TopicFilter::Single(topic) => {
                        if log.topics[i] != *topic {
                            return false;
                        }
                    }
                    TopicFilter::Multiple(topics) => {
                        if !topics.contains(&log.topics[i]) {
                            return false;
                        }
                    }
                }
            }
        }
    }

    true
}

#[test]
fn test_subscription_kind_parse() {
    assert_eq!(
        "newHeads".parse::<SubscriptionKind>().unwrap(),
        SubscriptionKind::NewHeads
    );
    assert_eq!(
        "logs".parse::<SubscriptionKind>().unwrap(),
        SubscriptionKind::Logs
    );
    assert_eq!(
        "newPendingTransactions".parse::<SubscriptionKind>().unwrap(),
        SubscriptionKind::NewPendingTransactions
    );
    assert_eq!(
        "syncing".parse::<SubscriptionKind>().unwrap(),
        SubscriptionKind::Syncing
    );
}

#[test]
fn test_subscription_manager() {
    let manager = SubscriptionManager::new();

    let sub1 = manager.create_subscription(SubscriptionKind::NewHeads, None);
    let sub2 = manager.create_subscription(SubscriptionKind::Logs, None);

    assert_eq!(manager.subscription_count(), 2);
    assert_ne!(sub1.id, sub2.id);

    assert!(manager.remove_subscription(sub1.id));
    assert_eq!(manager.subscription_count(), 1);

    assert!(!manager.remove_subscription(sub1.id)); // Already removed
}

#[test]
fn test_log_filter_matching() {
    let log = RpcLog {
        address: Address([0x42; 20]),
        topics: vec![
            H256([0x01; 32]),
            H256([0x02; 32]),
        ],
        data: HexBytes(vec![]),
        block_number: HexU64(100),
        transaction_hash: H256::ZERO,
        transaction_index: HexU64(0),
        block_hash: H256::ZERO,
        log_index: HexU64(0),
        removed: false,
    };

    // No filter - matches everything
    let filter = LogSubscriptionParams::default();
    assert!(matches_log_filter(&log, &filter));

    // Address filter - match
    let filter = LogSubscriptionParams {
        address: Some(AddressFilter::Single(Address([0x42; 20]))),
        topics: None,
    };
    assert!(matches_log_filter(&log, &filter));

    // Address filter - no match
    let filter = LogSubscriptionParams {
        address: Some(AddressFilter::Single(Address([0x43; 20]))),
        topics: None,
    };
    assert!(!matches_log_filter(&log, &filter));

    // Topic filter - match
    let filter = LogSubscriptionParams {
        address: None,
        topics: Some(vec![Some(TopicFilter::Single(H256([0x01; 32])))]),
    };
    assert!(matches_log_filter(&log, &filter));

    // Topic filter - no match
    let filter = LogSubscriptionParams {
        address: None,
        topics: Some(vec![Some(TopicFilter::Single(H256([0x99; 32])))]),
    };
    assert!(!matches_log_filter(&log, &filter));
}
