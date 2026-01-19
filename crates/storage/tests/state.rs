//! Integration tests for state storage and management

use protocore_storage::db::DatabaseConfig;
use protocore_storage::state::{Account, StateDB};
use protocore_storage::{Database, EMPTY_HASH, EMPTY_ROOT};
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
fn test_account_new() {
    let account = Account::new();
    assert_eq!(account.nonce, 0);
    assert_eq!(account.balance, 0);
    assert!(account.is_empty());
    assert!(!account.is_contract());
}

#[test]
fn test_account_encode_decode() {
    let account = Account {
        nonce: 42,
        balance: 1000000,
        code_hash: [1u8; 32],
        storage_root: [2u8; 32],
    };

    let encoded = account.encode();
    let decoded = Account::decode(&encoded).unwrap();

    assert_eq!(account, decoded);
}

#[test]
fn test_state_db_new() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);
    assert_eq!(state.state_root(), EMPTY_ROOT);
}

#[test]
fn test_get_set_account() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    let account = Account::with_balance(1000);

    assert!(state.get_account(&address).is_none());

    state.set_account(&address, account.clone());

    let retrieved = state.get_account(&address).unwrap();
    assert_eq!(retrieved.balance, 1000);
}

#[test]
fn test_delete_account() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::with_balance(1000));

    assert!(state.get_account(&address).is_some());

    state.delete_account(&address);

    assert!(state.get_account(&address).is_none());
}

#[test]
fn test_get_set_storage() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    let slot = [2u8; 32];
    let value = [3u8; 32];

    assert_eq!(state.get_storage(&address, &slot), protocore_storage::ZERO_HASH);

    state.set_storage(&address, &slot, value);

    assert_eq!(state.get_storage(&address, &slot), value);
}

#[test]
fn test_snapshot_revert() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::with_balance(1000));

    let snap_id = state.snapshot();

    state.set_account(&address, Account::with_balance(2000));
    assert_eq!(state.get_balance(&address), 2000);

    state.revert_to_snapshot(snap_id).unwrap();
    assert_eq!(state.get_balance(&address), 1000);
}

#[test]
fn test_commit() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::with_balance(1000));

    let root1 = state.state_root();
    let root2 = state.commit().unwrap();

    assert_ne!(root1, root2);
}

#[test]
fn test_balance_operations() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::with_balance(1000));

    state.add_balance(&address, 500).unwrap();
    assert_eq!(state.get_balance(&address), 1500);

    state.sub_balance(&address, 300).unwrap();
    assert_eq!(state.get_balance(&address), 1200);
}

#[test]
fn test_transfer() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let from = [1u8; 20];
    let to = [2u8; 20];

    state.set_account(&from, Account::with_balance(1000));
    state.set_account(&to, Account::with_balance(500));

    state.transfer(&from, &to, 300).unwrap();

    assert_eq!(state.get_balance(&from), 700);
    assert_eq!(state.get_balance(&to), 800);
}

#[test]
fn test_nonce_operations() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::new());

    assert_eq!(state.get_nonce(&address), 0);

    state.increment_nonce(&address);
    assert_eq!(state.get_nonce(&address), 1);

    state.increment_nonce(&address);
    assert_eq!(state.get_nonce(&address), 2);
}

#[test]
fn test_state_diff() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let address = [1u8; 20];
    state.set_account(&address, Account::with_balance(1000));

    let diff = state.state_diff();
    assert!(!diff.is_empty());
    assert!(diff.accounts.contains_key(&address));
}

#[test]
fn test_code_storage() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let code = b"contract code here";
    let code_hash = state.set_code(code).unwrap();

    let retrieved = state.get_code(&code_hash).unwrap();
    assert_eq!(retrieved, code.to_vec());
}

#[test]
fn test_empty_code() {
    let (db, _temp_dir) = create_test_db();
    let state = StateDB::new(db);

    let code_hash = state.set_code(&[]).unwrap();
    assert_eq!(code_hash, EMPTY_HASH);

    let retrieved = state.get_code(&EMPTY_HASH).unwrap();
    assert!(retrieved.is_empty());
}
