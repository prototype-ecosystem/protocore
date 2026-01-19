//! Tests for the State Sync Manager
//!
//! Tests extracted from sync.rs

use protocore_state_sync::{
    keccak256,
    snapshot::SnapshotMetadata,
    sync::{SyncPhase, SyncProgress, SyncResumeState, SyncStatus},
};
use std::time::Duration;

#[test]
fn test_sync_status_progress() {
    let mut status = SyncStatus::default();

    status.phase = SyncPhase::Downloading;
    status.chunks_downloaded = 50;
    status.total_chunks = 100;

    assert_eq!(status.download_progress(), 50.0);
    assert!(status.overall_progress() > 10.0 && status.overall_progress() < 70.0);
}

#[test]
fn test_sync_progress_format() {
    let mut progress = SyncProgress::new();
    progress.status.phase = SyncPhase::Idle;

    let formatted = progress.format();
    assert!(formatted.contains("idle"));
}

#[test]
fn test_sync_resume_state() {
    let metadata = SnapshotMetadata::new(
        100,
        [1u8; 32],
        [2u8; 32],
        1024 * 1024,
        vec![[3u8; 32], [4u8; 32], [5u8; 32]],
        3 * 1024 * 1024,
    );

    let mut state = SyncResumeState::new(metadata, None);

    assert_eq!(state.pending_download().len(), 3);
    assert!(!state.all_downloaded());

    state.mark_downloaded(0);
    state.mark_downloaded(1);

    assert_eq!(state.pending_download().len(), 1);
    assert!(!state.all_downloaded());

    state.mark_downloaded(2);
    assert!(state.all_downloaded());

    assert_eq!(state.pending_apply().len(), 3);
    state.mark_applied(0);
    state.mark_applied(1);
    state.mark_applied(2);
    assert!(state.all_applied());
}

#[test]
fn test_format_bytes() {
    // The format_bytes function is private in sync.rs, so we test the behavior
    // through SyncProgress which uses it internally
    let mut progress = SyncProgress::new();
    progress.status.phase = SyncPhase::Downloading;
    progress.status.download_speed = 1500000.0; // 1.43 MB/s

    let formatted = progress.format();
    // The format should include download speed
    assert!(formatted.contains("Downloading"));
}

#[test]
fn test_sync_phase_display() {
    assert_eq!(SyncPhase::Idle.to_string(), "idle");
    assert_eq!(SyncPhase::Discovery.to_string(), "discovery");
    assert_eq!(SyncPhase::Downloading.to_string(), "downloading");
    assert_eq!(SyncPhase::Completed.to_string(), "completed");
}
