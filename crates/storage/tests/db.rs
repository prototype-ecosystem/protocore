//! Integration tests for RocksDB wrapper

use protocore_storage::db::{cf, DatabaseConfig, WriteBatch};
use protocore_storage::Database;
use tempfile::TempDir;

fn create_test_db() -> (Database, TempDir) {
    let temp_dir = TempDir::new().unwrap();
    let config = DatabaseConfig {
        path: temp_dir.path().to_string_lossy().to_string(),
        ..Default::default()
    };
    let db = Database::open(config).unwrap();
    (db, temp_dir)
}

#[test]
fn test_open_database() {
    let (_db, _temp_dir) = create_test_db();
}

#[test]
fn test_put_get() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"key1", b"value1").unwrap();
    let value = db.get(cf::BLOCKS, b"key1").unwrap();
    assert_eq!(value, Some(b"value1".to_vec()));
}

#[test]
fn test_delete() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"key1", b"value1").unwrap();
    db.delete(cf::BLOCKS, b"key1").unwrap();
    let value = db.get(cf::BLOCKS, b"key1").unwrap();
    assert_eq!(value, None);
}

#[test]
fn test_write_batch() {
    let (db, _temp_dir) = create_test_db();

    let mut batch = WriteBatch::new();
    let cf = db.cf_handle(cf::BLOCKS).unwrap();
    batch.put_cf(&cf, b"key1", b"value1");
    batch.put_cf(&cf, b"key2", b"value2");

    db.write_batch(batch).unwrap();

    assert_eq!(
        db.get(cf::BLOCKS, b"key1").unwrap(),
        Some(b"value1".to_vec())
    );
    assert_eq!(
        db.get(cf::BLOCKS, b"key2").unwrap(),
        Some(b"value2".to_vec())
    );
}

#[test]
fn test_snapshot() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"key1", b"value1").unwrap();
    let snapshot = db.snapshot();

    // Modify after snapshot
    db.put(cf::BLOCKS, b"key1", b"value2").unwrap();

    // Snapshot should still see old value
    let value = snapshot.get(cf::BLOCKS, b"key1").unwrap();
    assert_eq!(value, Some(b"value1".to_vec()));

    // Current db should see new value
    let value = db.get(cf::BLOCKS, b"key1").unwrap();
    assert_eq!(value, Some(b"value2".to_vec()));
}

#[test]
fn test_iterator() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"a", b"1").unwrap();
    db.put(cf::BLOCKS, b"b", b"2").unwrap();
    db.put(cf::BLOCKS, b"c", b"3").unwrap();

    let iter = db.iterator(cf::BLOCKS).unwrap();
    let entries: Vec<_> = iter.filter_map(|r| r.ok()).collect();
    assert_eq!(entries.len(), 3);
}

#[test]
fn test_exists() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"key1", b"value1").unwrap();
    assert!(db.exists(cf::BLOCKS, b"key1").unwrap());
    assert!(!db.exists(cf::BLOCKS, b"key2").unwrap());
}

#[test]
fn test_multi_get() {
    let (db, _temp_dir) = create_test_db();

    db.put(cf::BLOCKS, b"key1", b"value1").unwrap();
    db.put(cf::BLOCKS, b"key2", b"value2").unwrap();

    let keys: Vec<&[u8]> = vec![b"key1", b"key2", b"key3"];
    let values = db.multi_get(cf::BLOCKS, &keys).unwrap();

    assert_eq!(values[0], Some(b"value1".to_vec()));
    assert_eq!(values[1], Some(b"value2".to_vec()));
    assert_eq!(values[2], None);
}

#[test]
fn test_block_helpers() {
    let (db, _temp_dir) = create_test_db();

    let hash = [1u8; 32];
    let data = b"block data";

    db.put_block(&hash, data).unwrap();
    let result = db.get_block(&hash).unwrap();
    assert_eq!(result, Some(data.to_vec()));
}
