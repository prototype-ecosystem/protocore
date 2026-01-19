//! Tests for mempool pool implementation.

use std::sync::Arc;

use protocore_mempool::{Mempool, MempoolConfig, MockAccountState, TransactionStatus};
use protocore_types::H256;

fn create_mempool() -> Mempool<MockAccountState> {
    let config = MempoolConfig::default();
    let state = Arc::new(MockAccountState::new());
    Mempool::new(config, state)
}

#[test]
fn test_mempool_config_default() {
    let config = MempoolConfig::default();
    assert_eq!(config.max_size, 10_000);
    assert_eq!(config.max_bytes, 100_000_000);
    assert_eq!(config.ttl_seconds, 3600);
    assert_eq!(config.price_bump_percentage, 10);
}

#[test]
fn test_mempool_stats() {
    let mempool = create_mempool();
    let stats = mempool.stats();

    assert_eq!(stats.pending_count, 0);
    assert_eq!(stats.queued_count, 0);
    assert_eq!(stats.total_count, 0);
    assert_eq!(stats.total_bytes, 0);
}

#[test]
fn test_transaction_status_not_found() {
    let mempool = create_mempool();
    let hash = H256::default();

    assert_eq!(mempool.get_status(&hash), TransactionStatus::NotFound);
}

#[test]
fn test_mempool_clear() {
    let mempool = create_mempool();
    mempool.clear();

    let stats = mempool.stats();
    assert_eq!(stats.total_count, 0);
}

// Note: PriceOrderKey is private, so we cannot test it directly from integration tests.
// The ordering behavior is implicitly tested through the mempool's transaction ordering.
