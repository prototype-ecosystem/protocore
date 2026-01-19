//! Tests for header synchronization

use protocore_light_client::{
    client::{
        Checkpoint, FinalityCertificate, HeaderChain, LightBlockHeader, ValidatorInfo,
        ValidatorSet, ValidatorSignature, ValidatorTracker,
    },
    constants::{DEFAULT_EPOCH_LENGTH, MAX_HEADERS_PER_SYNC},
    sync::{
        handle_reorg, verify_header_chain, HeaderSync, MockHeaderFetcher, SyncConfig, SyncHeader,
        SyncStatus,
    },
    types::Hash,
    Error,
};
use parking_lot::RwLock;
use std::sync::Arc;

fn create_test_header(number: u64, parent_hash: Hash) -> LightBlockHeader {
    let mut header = LightBlockHeader {
        number,
        hash: [0u8; 32],
        parent_hash,
        state_root: [1u8; 32],
        transactions_root: [2u8; 32],
        receipts_root: [3u8; 32],
        timestamp: 1000 + number * 12,
        proposer: [0u8; 20],
        epoch: number / DEFAULT_EPOCH_LENGTH,
    };
    header.hash = header.compute_hash();
    header
}

fn create_test_validator_set(epoch: u64) -> ValidatorSet {
    let validators = vec![
        ValidatorInfo::new([1u8; 20], vec![1u8; 48], 1000),
        ValidatorInfo::new([2u8; 20], vec![2u8; 48], 1000),
        ValidatorInfo::new([3u8; 20], vec![3u8; 48], 1000),
    ];
    ValidatorSet::new(epoch, validators)
}

fn create_test_finality_cert(header: &LightBlockHeader) -> FinalityCertificate {
    let signatures = vec![
        ValidatorSignature {
            validator: [1u8; 20],
            signature: vec![1u8; 96],
        },
        ValidatorSignature {
            validator: [2u8; 20],
            signature: vec![2u8; 96],
        },
        ValidatorSignature {
            validator: [3u8; 20],
            signature: vec![3u8; 96],
        },
    ];

    FinalityCertificate::new(header.hash, header.number, header.epoch, signatures)
}

#[test]
fn test_sync_status_progress() {
    let mut status = SyncStatus::default();
    status.start_height = 0;
    status.current_height = 50;
    status.target_height = Some(100);

    assert_eq!(status.progress(), 50.0);

    status.current_height = 100;
    assert_eq!(status.progress(), 100.0);
}

#[test]
fn test_verify_header_chain() {
    let header0 = create_test_header(0, [0u8; 32]);
    let header1 = create_test_header(1, header0.hash);
    let header2 = create_test_header(2, header1.hash);

    let chain = vec![header0, header1, header2];
    assert!(verify_header_chain(&chain).is_ok());
}

#[test]
fn test_verify_header_chain_gap() {
    let header0 = create_test_header(0, [0u8; 32]);
    let header2 = create_test_header(2, header0.hash); // Missing header 1

    let chain = vec![header0, header2];
    let result = verify_header_chain(&chain);
    assert!(matches!(result, Err(Error::HeaderChainGap(1))));
}

#[test]
fn test_verify_header_chain_broken_link() {
    let header0 = create_test_header(0, [0u8; 32]);
    let mut header1 = create_test_header(1, [99u8; 32]); // Wrong parent hash
    header1.hash = header1.compute_hash();

    let chain = vec![header0, header1];
    let result = verify_header_chain(&chain);
    assert!(matches!(result, Err(Error::InvalidHeaderChain(_))));
}

#[test]
fn test_sync_header() {
    let header = create_test_header(0, [0u8; 32]);
    let cert = create_test_finality_cert(&header);
    let sync_header = SyncHeader::new(header.clone(), cert);

    assert_eq!(sync_header.height(), 0);
    assert_eq!(sync_header.hash(), header.hash);
}

#[test]
fn test_sync_config_default() {
    let config = SyncConfig::default();
    assert_eq!(config.batch_size, MAX_HEADERS_PER_SYNC);
    assert!(config.checkpoint_sync);
}

#[test]
fn test_handle_reorg_no_conflict() {
    let mut chain = HeaderChain::new(100, false);
    let header = create_test_header(0, [0u8; 32]);
    chain.insert(header.clone()).unwrap();

    // Same header should not trigger reorg
    assert!(handle_reorg(&mut chain, &header).is_ok());
}

#[test]
fn test_handle_reorg_conflict() {
    let mut chain = HeaderChain::new(100, false);
    let header1 = create_test_header(0, [0u8; 32]);
    chain.insert(header1).unwrap();

    // Different header at same height
    let mut header2 = create_test_header(0, [1u8; 32]);
    header2.hash = header2.compute_hash();

    let result = handle_reorg(&mut chain, &header2);
    assert!(matches!(result, Err(Error::ReorgDetected { .. })));
}

#[tokio::test]
async fn test_mock_fetcher() {
    let fetcher = MockHeaderFetcher::new();

    // Add some headers
    for i in 0..10 {
        let parent = if i == 0 {
            [0u8; 32]
        } else {
            create_test_header(i - 1, [0u8; 32]).hash
        };
        let header = create_test_header(i, parent);
        let cert = create_test_finality_cert(&header);
        fetcher.add_header(SyncHeader::new(header, cert));
    }

    use protocore_light_client::sync::HeaderFetcher;
    let latest = fetcher.get_latest_height().await.unwrap();
    assert_eq!(latest, 9);

    let headers = fetcher.fetch_headers(0, 5).await.unwrap();
    assert_eq!(headers.len(), 5);
    assert_eq!(headers[0].height(), 0);
    assert_eq!(headers[4].height(), 4);
}

#[tokio::test]
async fn test_header_sync_basic() {
    let fetcher = Arc::new(MockHeaderFetcher::new());
    let headers = Arc::new(RwLock::new(HeaderChain::new(100, false)));
    let validators = Arc::new(RwLock::new(ValidatorTracker::new(DEFAULT_EPOCH_LENGTH)));

    // Initialize with genesis
    let genesis = create_test_header(0, [0u8; 32]);
    headers.write().insert(genesis.clone()).unwrap();

    let genesis_set = create_test_validator_set(0);
    validators.write().init(genesis_set.clone());

    // Add headers to fetcher
    let mut parent_hash = genesis.hash;
    for i in 1..5 {
        let header = create_test_header(i, parent_hash);
        let cert = create_test_finality_cert(&header);
        fetcher.add_header(SyncHeader::new(header.clone(), cert));
        parent_hash = header.hash;
    }

    // Create sync
    let config = SyncConfig::default();
    let sync = HeaderSync::new(config, fetcher, headers.clone(), validators);

    // Run sync
    sync.sync().await.unwrap();

    // Verify headers were synced
    let final_height = headers.read().latest_height();
    assert_eq!(final_height, Some(4));
}
