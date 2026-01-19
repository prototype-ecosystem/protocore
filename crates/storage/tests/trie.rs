//! Integration tests for Merkle Patricia Trie

use protocore_storage::trie::MerkleTrie;
use protocore_storage::EMPTY_ROOT;

#[test]
fn test_nibbles_from_bytes() {
    // This is an internal test - we test the public API instead
    let trie = MerkleTrie::new();
    trie.insert(&[0xab, 0xcd], b"value").unwrap();
    assert_eq!(trie.get(&[0xab, 0xcd]).unwrap(), Some(b"value".to_vec()));
}

#[test]
fn test_nibbles_to_bytes() {
    // This is an internal test - we test the public API instead
    let trie = MerkleTrie::new();
    trie.insert(&[0xab, 0xcd], b"value").unwrap();
    let retrieved = trie.get(&[0xab, 0xcd]).unwrap();
    assert_eq!(retrieved, Some(b"value".to_vec()));
}

#[test]
fn test_nibbles_compact_encoding() {
    // This is an internal test - we test the public API through insert/get
    let trie = MerkleTrie::new();
    // Test with various key patterns
    trie.insert(&[0x12, 0x34], b"even").unwrap();
    trie.insert(&[0x12, 0x34, 0x56], b"odd").unwrap();

    assert_eq!(trie.get(&[0x12, 0x34]).unwrap(), Some(b"even".to_vec()));
    assert_eq!(trie.get(&[0x12, 0x34, 0x56]).unwrap(), Some(b"odd".to_vec()));
}

#[test]
fn test_empty_trie() {
    let trie = MerkleTrie::new();
    assert!(trie.is_empty());
    assert_eq!(trie.root(), EMPTY_ROOT);
}

#[test]
fn test_insert_and_get() {
    let trie = MerkleTrie::new();

    trie.insert(b"key1", b"value1").unwrap();
    trie.insert(b"key2", b"value2").unwrap();

    assert_eq!(trie.get(b"key1").unwrap(), Some(b"value1".to_vec()));
    assert_eq!(trie.get(b"key2").unwrap(), Some(b"value2".to_vec()));
    assert_eq!(trie.get(b"key3").unwrap(), None);
}

#[test]
fn test_update_value() {
    let trie = MerkleTrie::new();

    trie.insert(b"key1", b"value1").unwrap();
    let root1 = trie.root();

    trie.insert(b"key1", b"value2").unwrap();
    let root2 = trie.root();

    assert_ne!(root1, root2);
    assert_eq!(trie.get(b"key1").unwrap(), Some(b"value2".to_vec()));
}

#[test]
fn test_delete() {
    let trie = MerkleTrie::new();

    trie.insert(b"key1", b"value1").unwrap();
    trie.insert(b"key2", b"value2").unwrap();

    assert!(trie.delete(b"key1").unwrap());
    assert_eq!(trie.get(b"key1").unwrap(), None);
    assert_eq!(trie.get(b"key2").unwrap(), Some(b"value2".to_vec()));

    assert!(!trie.delete(b"key1").unwrap()); // Already deleted
}

#[test]
fn test_merkle_proof() {
    let trie = MerkleTrie::new();

    trie.insert(b"key1", b"value1").unwrap();
    trie.insert(b"key2", b"value2").unwrap();

    let proof = trie.prove(b"key1").unwrap();
    assert!(proof.verify());
    assert_eq!(proof.value, Some(b"value1".to_vec()));

    // Proof for non-existent key
    let proof = trie.prove(b"key3").unwrap();
    assert!(proof.verify());
    assert_eq!(proof.value, None);
}

#[test]
fn test_root_changes_on_modification() {
    let trie = MerkleTrie::new();

    let root0 = trie.root();
    trie.insert(b"key1", b"value1").unwrap();
    let root1 = trie.root();
    trie.insert(b"key2", b"value2").unwrap();
    let root2 = trie.root();

    assert_ne!(root0, root1);
    assert_ne!(root1, root2);
    assert_ne!(root0, root2);
}

#[test]
fn test_deterministic_root() {
    let trie1 = MerkleTrie::new();
    trie1.insert(b"a", b"1").unwrap();
    trie1.insert(b"b", b"2").unwrap();

    let trie2 = MerkleTrie::new();
    trie2.insert(b"a", b"1").unwrap();
    trie2.insert(b"b", b"2").unwrap();

    assert_eq!(trie1.root(), trie2.root());
}

#[test]
fn test_many_keys() {
    let trie = MerkleTrie::new();

    for i in 0..100 {
        let key = format!("key{:03}", i);
        let value = format!("value{:03}", i);
        trie.insert(key.as_bytes(), value.as_bytes()).unwrap();
    }

    for i in 0..100 {
        let key = format!("key{:03}", i);
        let value = format!("value{:03}", i);
        assert_eq!(
            trie.get(key.as_bytes()).unwrap(),
            Some(value.as_bytes().to_vec())
        );
    }
}
