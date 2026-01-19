//! Tests for Chunk Handling
//!
//! Tests extracted from chunks.rs

use protocore_state_sync::{
    chunks::{
        ChunkDownloadProgress, ChunkId, ChunkProof, ChunkReassembler, ChunkRequest,
        ChunkResponse, ChunkVerifier, StateChunk,
    },
    keccak256,
    Hash,
};
use std::time::Duration;

#[test]
fn test_chunk_id() {
    let id = ChunkId::new(100, 5);
    assert_eq!(id.snapshot_height, 100);
    assert_eq!(id.chunk_index, 5);

    let id2 = ChunkId::new(100, 5);
    assert_eq!(id.hash(), id2.hash());
}

#[test]
fn test_state_chunk_verification() {
    let id = ChunkId::new(100, 0);
    let data = vec![1, 2, 3, 4, 5];
    let data_hash = keccak256(&data);
    let proof = ChunkProof::empty(data_hash);

    let chunk = StateChunk::new(
        id,
        vec![0],
        vec![255],
        data,
        proof,
        10,
    );

    assert!(chunk.verify_data_hash());
}

#[test]
fn test_chunk_verifier() {
    let state_root = keccak256(b"state");
    let chunk_data = vec![1, 2, 3];
    let chunk_hash = keccak256(&chunk_data);
    let chunk_hashes = vec![chunk_hash];

    let mut verifier = ChunkVerifier::new(state_root, chunk_hashes);

    let id = ChunkId::new(100, 0);
    let proof = ChunkProof::empty(state_root);

    let chunk = StateChunk::new(
        id,
        vec![0],
        vec![255],
        chunk_data,
        proof,
        1,
    );

    let result = verifier.verify(&chunk);
    assert!(result.is_ok());
    assert!(verifier.is_verified(0));
    assert!(verifier.is_complete());
}

#[test]
fn test_chunk_proof_verification() {
    let chunk_hash = keccak256(b"chunk");
    let root = chunk_hash; // Empty proof means hash equals root

    let proof = ChunkProof::empty(root);
    assert!(proof.verify(&chunk_hash));

    // Wrong hash should fail
    let wrong_hash = keccak256(b"wrong");
    assert!(!proof.verify(&wrong_hash));
}

#[test]
fn test_chunk_reassembler() {
    let mut reassembler = ChunkReassembler::new(3);

    let id0 = ChunkId::new(100, 0);
    let id1 = ChunkId::new(100, 1);
    let id2 = ChunkId::new(100, 2);

    let chunk0 = StateChunk::new(
        id0,
        vec![0],
        vec![85],
        vec![1],
        ChunkProof::empty([0u8; 32]),
        1,
    );
    let chunk1 = StateChunk::new(
        id1,
        vec![85],
        vec![170],
        vec![2],
        ChunkProof::empty([0u8; 32]),
        1,
    );
    let chunk2 = StateChunk::new(
        id2,
        vec![170],
        vec![255],
        vec![3],
        ChunkProof::empty([0u8; 32]),
        1,
    );

    // Add out of order
    reassembler.add_chunk(chunk1.clone()).unwrap();
    assert!(!reassembler.is_complete());

    reassembler.add_chunk(chunk0.clone()).unwrap();
    assert!(!reassembler.is_complete());

    reassembler.add_chunk(chunk2.clone()).unwrap();
    assert!(reassembler.is_complete());

    let chunks = reassembler.into_chunks().unwrap();
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].id.chunk_index, 0);
    assert_eq!(chunks[1].id.chunk_index, 1);
    assert_eq!(chunks[2].id.chunk_index, 2);
}

#[test]
fn test_chunk_download_progress() {
    let progress = ChunkDownloadProgress {
        completed: 50,
        total: 100,
        bytes_downloaded: 50 * 1024 * 1024,
        elapsed: Duration::from_secs(10),
    };

    assert_eq!(progress.percentage(), 50.0);
    assert_eq!(progress.bytes_per_second(), 5.0 * 1024.0 * 1024.0);
}

#[test]
fn test_chunk_request_response() {
    let id = ChunkId::new(100, 0);
    let hash = keccak256(b"chunk");

    let request = ChunkRequest::new(id, hash);
    assert!(request.include_proof);

    let request_no_proof = request.clone().with_proof(false);
    assert!(!request_no_proof.include_proof);

    // Test error response
    let error_response = ChunkResponse::error(request.request_id, "not found".to_string());
    assert!(!error_response.is_success());
    assert_eq!(error_response.error, Some("not found".to_string()));
}
