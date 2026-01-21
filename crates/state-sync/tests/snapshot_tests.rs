//! Tests for the Snapshot Protocol
//!
//! Tests extracted from snapshot.rs

use protocore_state_sync::{
    keccak256,
    snapshot::{
        FinalityCertificate, SnapshotAvailability, SnapshotInfo, SnapshotList, SnapshotListEntry,
        SnapshotMetadata, SnapshotRequest, SnapshotSelector, SnapshotValidationError,
    },
    Hash,
};

fn create_test_metadata(height: u64, chunk_count: usize) -> SnapshotMetadata {
    let chunk_hashes: Vec<Hash> = (0..chunk_count).map(|i| keccak256(&[i as u8])).collect();

    SnapshotMetadata::new(
        height,
        keccak256(b"state_root"),
        keccak256(b"block_hash"),
        1024 * 1024,
        chunk_hashes,
        chunk_count as u64 * 1024 * 1024,
    )
}

#[test]
fn test_snapshot_metadata_creation() {
    let metadata = create_test_metadata(100, 10);

    assert_eq!(metadata.height, 100);
    assert_eq!(metadata.chunk_count, 10);
    assert_eq!(metadata.chunk_hashes.len(), 10);
}

#[test]
fn test_snapshot_metadata_validation() {
    let metadata = create_test_metadata(100, 10);
    assert!(metadata.validate().is_ok());
}

#[test]
fn test_snapshot_metadata_invalid_chunk_count() {
    let mut metadata = create_test_metadata(100, 10);
    metadata.chunk_count = 20; // Mismatch with chunk_hashes.len()

    let result = metadata.validate();
    assert!(matches!(
        result,
        Err(SnapshotValidationError::ChunkCountMismatch { .. })
    ));
}

#[test]
fn test_chunks_root_computation() {
    let hashes: Vec<Hash> = (0..4).map(|i| keccak256(&[i as u8])).collect();

    let root1 = SnapshotMetadata::compute_chunks_root(&hashes);
    let root2 = SnapshotMetadata::compute_chunks_root(&hashes);

    assert_eq!(root1, root2);

    // Different hashes should give different root
    let different_hashes: Vec<Hash> = (10..14).map(|i| keccak256(&[i as u8])).collect();
    let root3 = SnapshotMetadata::compute_chunks_root(&different_hashes);

    assert_ne!(root1, root3);
}

#[test]
fn test_finality_certificate_quorum() {
    let cert = FinalityCertificate::new(
        100,
        keccak256(b"block"),
        keccak256(b"state"),
        1,
        1,
        vec![1, 2, 3],
        vec![0xFF],
        67,
        100,
    );

    assert!(cert.has_quorum());

    let cert_no_quorum = FinalityCertificate::new(
        100,
        keccak256(b"block"),
        keccak256(b"state"),
        1,
        1,
        vec![1, 2, 3],
        vec![0xFF],
        60,
        100,
    );

    assert!(!cert_no_quorum.has_quorum());
}

#[test]
fn test_snapshot_selector() {
    let selector = SnapshotSelector::new(1000)
        .with_min_peers(1)
        .with_finality(false);

    let metadata = create_test_metadata(900, 10);
    let mut info = SnapshotInfo::new(metadata, None);
    info.add_peer([1u8; 32]);

    let snapshots = vec![info];
    let selected = selector.select_best(&snapshots);

    assert!(selected.is_some());
    assert_eq!(selected.unwrap().metadata.height, 900);
}

#[test]
fn test_snapshot_availability() {
    let mut availability = SnapshotAvailability::new();

    let metadata = create_test_metadata(100, 5);
    let entry = SnapshotListEntry::new(metadata.clone(), None);
    let peer1 = [1u8; 32];
    let peer2 = [2u8; 32];

    availability.add_snapshot(entry.clone(), peer1);
    availability.add_snapshot(entry, peer2);

    let snapshots = availability.at_height(100);
    assert_eq!(snapshots.len(), 1);
    assert_eq!(snapshots[0].peer_count(), 2);
}

#[test]
fn test_snapshot_request() {
    let request = SnapshotRequest::from_height(100).with_max_results(5);

    assert_eq!(request.min_height, 100);
    assert_eq!(request.max_height, u64::MAX);
    assert_eq!(request.max_results, 5);
}

#[test]
fn test_snapshot_list_sorting() {
    let entries = vec![
        SnapshotListEntry::new(create_test_metadata(100, 5), None),
        SnapshotListEntry::new(create_test_metadata(300, 5), None),
        SnapshotListEntry::new(create_test_metadata(200, 5), None),
    ];

    let list = SnapshotList::new(entries, 1, 400);
    let sorted = list.sorted_by_height();

    assert_eq!(sorted[0].metadata.height, 300);
    assert_eq!(sorted[1].metadata.height, 200);
    assert_eq!(sorted[2].metadata.height, 100);
}
