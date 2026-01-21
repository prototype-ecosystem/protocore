//! Integration tests for State snapshots

use protocore_storage::db::{cf, DatabaseConfig};
use protocore_storage::snapshot::{
    Snapshot, SnapshotChunk, SnapshotManager, SnapshotProgress, StateUpdate,
};
use protocore_storage::state::Account;
use protocore_storage::{keccak256, Database};
use std::sync::Arc;
use tempfile::TempDir;

fn create_test_db() -> (Arc<Database>, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = DatabaseConfig {
        path: temp_dir.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let db = Arc::new(Database::open(config).unwrap());
    (db, temp_dir)
}

#[test]
fn test_snapshot_new() {
    let snapshot = Snapshot::new(100, [1u8; 32], [2u8; 32]);
    assert_eq!(snapshot.height, 100);
    assert_eq!(snapshot.state_root, [1u8; 32]);
    assert_eq!(snapshot.block_hash, [2u8; 32]);
    assert_eq!(snapshot.chunk_count, 0);
}

#[test]
fn test_snapshot_encode_decode() {
    let mut snapshot = Snapshot::new(100, [1u8; 32], [2u8; 32]);
    snapshot.chunk_count = 5;
    snapshot.total_size = 1000;

    let encoded = snapshot.encode();
    let decoded = Snapshot::decode(&encoded).unwrap();

    assert_eq!(decoded.height, snapshot.height);
    assert_eq!(decoded.chunk_count, snapshot.chunk_count);
    assert_eq!(decoded.total_size, snapshot.total_size);
}

#[test]
fn test_chunk_creation() {
    let updates = vec![
        StateUpdate::Account {
            address: [1u8; 20],
            account: Account::with_balance(1000),
        },
        StateUpdate::Storage {
            address: [2u8; 20],
            slot: [3u8; 32],
            value: [4u8; 32],
        },
    ];

    let chunk = SnapshotChunk::new(0, 100, updates);
    assert_eq!(chunk.id, 0);
    assert_eq!(chunk.height, 100);
    assert!(chunk.verify());
}

#[test]
fn test_chunk_encode_decode() {
    let updates = vec![StateUpdate::Account {
        address: [1u8; 20],
        account: Account::with_balance(1000),
    }];

    let chunk = SnapshotChunk::new(0, 100, updates);
    let encoded = chunk.encode();
    let decoded = SnapshotChunk::decode(&encoded).unwrap();

    assert_eq!(decoded.id, chunk.id);
    assert_eq!(decoded.hash, chunk.hash);
    assert!(decoded.verify());
}

#[test]
fn test_snapshot_manager_new() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db);
    assert!(manager.current_snapshot().is_none());
}

#[test]
fn test_create_empty_snapshot() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db);

    let snapshot = manager.create_snapshot(100, [1u8; 32], [2u8; 32]).unwrap();

    assert_eq!(snapshot.height, 100);
    assert_eq!(snapshot.chunk_count, 0);
}

#[test]
fn test_snapshot_with_data() {
    let (db, _temp_dir) = create_test_db();

    // Add some state data
    let account = Account::with_balance(1000);
    let key = {
        let mut k = vec![0x00];
        k.extend([1u8; 20]);
        k
    };
    db.put(cf::STATE, &key, &account.encode()).unwrap();

    let manager = SnapshotManager::new(db);
    let snapshot = manager.create_snapshot(100, [1u8; 32], [2u8; 32]).unwrap();

    assert_eq!(snapshot.height, 100);
    assert!(snapshot.chunk_count > 0 || snapshot.total_size > 0);
}

#[test]
fn test_import_export_chunk() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db);

    let updates = vec![StateUpdate::Account {
        address: [1u8; 20],
        account: Account::with_balance(1000),
    }];

    let chunk = SnapshotChunk::new(0, 100, updates);
    let encoded = chunk.encode();

    let imported = manager.import_chunk(&encoded).unwrap();
    assert_eq!(imported.id, chunk.id);
    assert!(imported.verify());
}

#[test]
fn test_apply_chunk() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db.clone());

    let updates = vec![StateUpdate::Account {
        address: [1u8; 20],
        account: Account::with_balance(1000),
    }];

    let chunk = SnapshotChunk::new(0, 100, updates);
    manager.apply_chunk(&chunk).unwrap();

    // Verify the data was written
    let key = {
        let mut k = vec![0x00];
        k.extend([1u8; 20]);
        k
    };
    let data = db.get(cf::STATE, &key).unwrap();
    assert!(data.is_some());
}

#[test]
fn test_snapshot_progress() {
    let progress = SnapshotProgress {
        total_accounts: 100,
        processed_accounts: 50,
        total_storage: 100,
        processed_storage: 50,
        chunks_created: 5,
        current_chunk_size: 1000,
    };

    assert_eq!(progress.percentage(), 50.0);
}

#[test]
fn test_verify_chunk() {
    let mut snapshot = Snapshot::new(100, [1u8; 32], [2u8; 32]);
    snapshot.chunk_count = 1;

    let updates = vec![StateUpdate::Account {
        address: [1u8; 20],
        account: Account::with_balance(1000),
    }];
    let data = bincode::serialize(&updates).unwrap();
    let hash = keccak256(&data);
    snapshot.chunk_hashes.push(hash);

    assert!(snapshot.verify_chunk(0, &data));
    assert!(!snapshot.verify_chunk(0, b"invalid data"));
    assert!(!snapshot.verify_chunk(1, &data)); // Invalid chunk_id
}

#[test]
fn test_list_snapshots() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db);

    manager.create_snapshot(100, [1u8; 32], [2u8; 32]).unwrap();
    manager.create_snapshot(200, [3u8; 32], [4u8; 32]).unwrap();

    let snapshots = manager.list_snapshots().unwrap();
    assert_eq!(snapshots.len(), 2);
    assert_eq!(snapshots[0].height, 100);
    assert_eq!(snapshots[1].height, 200);
}

#[test]
fn test_delete_snapshot() {
    let (db, _temp_dir) = create_test_db();
    let manager = SnapshotManager::new(db);

    manager.create_snapshot(100, [1u8; 32], [2u8; 32]).unwrap();

    assert!(manager.get_snapshot(100).unwrap().is_some());

    manager.delete_snapshot(100).unwrap();

    assert!(manager.get_snapshot(100).unwrap().is_none());
}
