//! Tests for Transaction types

use bytes::Bytes;
use k256::ecdsa::SigningKey;
use protocore_types::transaction::{
    AccessListItem, Signature, SignedTransaction, Transaction, TxType,
};
use protocore_types::{Address, H256};

fn test_signing_key() -> SigningKey {
    // A fixed test private key (do not use in production!)
    let key_bytes = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e,
        0x1f, 0x20,
    ];
    SigningKey::from_bytes((&key_bytes).into()).unwrap()
}

#[test]
fn test_transaction_default() {
    let tx = Transaction::default();
    assert_eq!(tx.tx_type, TxType::DynamicFee);
    assert_eq!(tx.chain_id, 1);
    assert_eq!(tx.nonce, 0);
    assert_eq!(tx.gas_limit, 21000);
    assert!(tx.to.is_none());
}

#[test]
fn test_transaction_transfer() {
    let to = Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
    let tx = Transaction::transfer(1, 5, to, 1000000);
    assert_eq!(tx.nonce, 5);
    assert_eq!(tx.to, Some(to));
    assert_eq!(tx.value, 1000000);
    assert!(!tx.is_create());
}

#[test]
fn test_transaction_deploy() {
    let init_code = vec![0x60, 0x80, 0x60, 0x40];
    let tx = Transaction::deploy(1, 0, init_code, 0);
    assert!(tx.is_create());
    assert!(tx.to.is_none());
}

#[test]
fn test_transaction_signing_hash() {
    let tx = Transaction::new(1, 0, 1000000000, 2000000000, 21000, None, 0, Bytes::new());

    let hash = tx.signing_hash();
    assert!(!hash.is_zero());

    // Same transaction should produce same hash
    let hash2 = tx.signing_hash();
    assert_eq!(hash, hash2);
}

#[test]
fn test_sign_and_verify() {
    let signing_key = test_signing_key();
    let to = Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
    let tx = Transaction::transfer(1, 0, to, 1000000000000000000);

    let signed = tx.sign(&signing_key).unwrap();

    // Verify the signature
    assert!(signed.verify().unwrap());

    // Check sender recovery
    let sender = signed.sender().unwrap();
    assert!(!sender.is_zero());
}

#[test]
fn test_signed_transaction_rlp_roundtrip() {
    let signing_key = test_signing_key();
    let to = Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
    let tx = Transaction::transfer(1, 42, to, 1000000000000000000)
        .with_gas(21000, 2000000000, 1000000000);

    let signed = tx.sign(&signing_key).unwrap();
    let encoded = signed.rlp_encode();

    let decoded = SignedTransaction::rlp_decode(&encoded).unwrap();

    assert_eq!(signed.hash(), decoded.hash());
    assert_eq!(signed.transaction.chain_id, decoded.transaction.chain_id);
    assert_eq!(signed.transaction.nonce, decoded.transaction.nonce);
    assert_eq!(signed.transaction.to, decoded.transaction.to);
    assert_eq!(signed.transaction.value, decoded.transaction.value);
}

#[test]
fn test_effective_gas_price() {
    let tx = Transaction::new(1, 0, 1000000000, 3000000000, 21000, None, 0, Bytes::new());

    // Base fee = 1000000000
    // Priority fee = min(1000000000, 3000000000 - 1000000000) = 1000000000
    // Effective = 1000000000 + 1000000000 = 2000000000
    assert_eq!(tx.effective_gas_price(1000000000), 2000000000);

    // Base fee = 2500000000
    // Priority fee = min(1000000000, 3000000000 - 2500000000) = 500000000
    // Effective = 2500000000 + 500000000 = 3000000000
    assert_eq!(tx.effective_gas_price(2500000000), 3000000000);
}

#[test]
fn test_signature_recovery_id() {
    let sig = Signature::new(0, H256::NIL, H256::NIL);
    assert_eq!(sig.recovery_id(), 0);

    let sig = Signature::new(1, H256::NIL, H256::NIL);
    assert_eq!(sig.recovery_id(), 1);

    let sig = Signature::new(27, H256::NIL, H256::NIL);
    assert_eq!(sig.recovery_id(), 0);

    let sig = Signature::new(28, H256::NIL, H256::NIL);
    assert_eq!(sig.recovery_id(), 1);
}

#[test]
fn test_transaction_serde() {
    let to = Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
    let tx = Transaction::transfer(1, 0, to, 1000000);

    let json = serde_json::to_string(&tx).unwrap();
    let decoded: Transaction = serde_json::from_str(&json).unwrap();

    assert_eq!(tx, decoded);
}

#[test]
fn test_access_list() {
    let to = Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap();
    let access_list = vec![AccessListItem {
        address: to,
        storage_keys: vec![H256::NIL, H256::keccak256(b"key")],
    }];

    let tx = Transaction::transfer(1, 0, to, 0).with_access_list(access_list.clone());

    assert_eq!(tx.access_list.len(), 1);
    assert_eq!(tx.access_list[0].storage_keys.len(), 2);
}
