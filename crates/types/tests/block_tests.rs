//! Tests for Block and BlockHeader types

use protocore_types::block::{Block, BlockHeader, FinalityCert};
use protocore_types::{Address, H256};

#[test]
fn test_block_header_default() {
    let header = BlockHeader::default();
    assert_eq!(header.chain_id, 1);
    assert_eq!(header.height, 0);
    assert_eq!(header.gas_limit, 30_000_000);
    assert!(header.parent_hash.is_nil());
}

#[test]
fn test_block_header_hash() {
    let header = BlockHeader::default();
    let hash = header.hash();
    assert!(!hash.is_nil());

    // Same header should produce same hash
    let hash2 = header.hash();
    assert_eq!(hash, hash2);

    // Different header should produce different hash
    let mut header2 = header.clone();
    header2.height = 1;
    assert_ne!(header.hash(), header2.hash());
}

#[test]
fn test_block_header_genesis() {
    let state_root = H256::keccak256(b"genesis state");
    let genesis = BlockHeader::genesis(42, state_root, 1000);

    assert_eq!(genesis.chain_id, 42);
    assert_eq!(genesis.height, 0);
    assert_eq!(genesis.timestamp, 1000);
    assert!(genesis.parent_hash.is_nil());
    assert_eq!(genesis.state_root, state_root);
}

#[test]
fn test_block_header_rlp_roundtrip() {
    let header = BlockHeader::new(
        1,
        100,
        1234567890,
        H256::keccak256(b"parent"),
        Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap(),
    );

    let encoded = header.rlp_encode();
    let decoded = BlockHeader::rlp_decode(&encoded).unwrap();

    assert_eq!(header, decoded);
}

#[test]
fn test_block_header_next_base_fee() {
    // Exactly at target - no change
    let header = BlockHeader::default().with_gas(20_000_000, 10_000_000, 1_000_000_000);
    assert_eq!(header.next_base_fee(), 1_000_000_000);

    // Above target - fee increases
    let header = BlockHeader::default().with_gas(20_000_000, 15_000_000, 1_000_000_000);
    assert!(header.next_base_fee() > 1_000_000_000);

    // Below target - fee decreases
    let header = BlockHeader::default().with_gas(20_000_000, 5_000_000, 1_000_000_000);
    assert!(header.next_base_fee() < 1_000_000_000);
}

#[test]
fn test_block_empty() {
    let header = BlockHeader::default();
    let block = Block::empty(header.clone());

    assert!(block.is_empty());
    assert_eq!(block.transaction_count(), 0);
    assert_eq!(block.header, header);
}

#[test]
fn test_block_hash() {
    let header = BlockHeader::default();
    let block = Block::empty(header.clone());

    // Block hash should equal header hash
    assert_eq!(block.hash(), header.hash());
}

#[test]
fn test_block_genesis() {
    let state_root = H256::keccak256(b"state");
    let genesis = Block::genesis(1, state_root, 0);

    assert_eq!(genesis.height(), 0);
    assert!(genesis.parent_hash().is_nil());
    assert!(genesis.is_empty());
}

#[test]
fn test_finality_cert() {
    let cert = FinalityCert::new(
        100,
        H256::keccak256(b"block"),
        vec![0u8; 96],                // Mock BLS signature
        vec![0b11111111, 0b00001111], // First 12 validators signed
    );

    assert_eq!(cert.height, 100);
    assert_eq!(cert.signer_count(), 12);
    assert!(cert.has_signed(0));
    assert!(cert.has_signed(7));
    assert!(cert.has_signed(11));
    assert!(!cert.has_signed(12));
}

#[test]
fn test_finality_cert_get_signers() {
    let cert = FinalityCert::new(
        1,
        H256::NIL,
        vec![],
        vec![0b00000101], // Validators 0 and 2 signed
    );

    let signers = cert.get_signers();
    assert_eq!(signers, vec![0, 2]);
}

#[test]
fn test_block_header_serde() {
    let header = BlockHeader::new(
        1,
        100,
        1234567890,
        H256::keccak256(b"parent"),
        Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap(),
    );

    let json = serde_json::to_string(&header).unwrap();
    let decoded: BlockHeader = serde_json::from_str(&json).unwrap();

    assert_eq!(header, decoded);
}

#[test]
fn test_block_validate_basic() {
    // Genesis block - valid
    let genesis = BlockHeader::genesis(1, H256::NIL, 1000);
    assert!(genesis.validate_basic().is_ok());

    // Non-genesis without parent - invalid
    let mut header = BlockHeader::default();
    header.height = 1;
    header.timestamp = 1000;
    assert!(header.validate_basic().is_err());

    // Gas used > gas limit - invalid
    let mut header = BlockHeader::default();
    header.gas_used = 40_000_000;
    header.gas_limit = 30_000_000;
    assert!(header.validate_basic().is_err());
}

#[test]
fn test_transactions_root() {
    let block = Block::empty(BlockHeader::default());
    assert_eq!(block.compute_transactions_root(), H256::NIL);
}

#[test]
fn test_block_rlp_roundtrip_with_transactions() {
    use bytes::Bytes;
    use protocore_types::transaction::{Signature, SignedTransaction, Transaction, TxType};

    // Create a transaction
    let tx = Transaction {
        tx_type: TxType::DynamicFee,
        chain_id: 1,
        nonce: 0,
        max_priority_fee_per_gas: 1_000_000_000,
        max_fee_per_gas: 2_000_000_000,
        gas_limit: 21000,
        to: Some(Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap()),
        value: 1_000_000_000_000_000_000, // 1 ETH
        data: Bytes::new(),
        access_list: vec![],
    };

    let signed_tx = SignedTransaction::new(
        tx,
        Signature {
            v: 1,
            r: H256::from([1u8; 32]),
            s: H256::from([2u8; 32]),
        },
    )
    .expect("Failed to create signed tx");

    // Create block with transaction
    let header = BlockHeader::new(
        1,
        100,
        1234567890,
        H256::keccak256(b"parent"),
        Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap(),
    );

    let block = Block::new(header.clone(), vec![signed_tx]);
    assert_eq!(block.transaction_count(), 1);

    // Encode and decode
    let encoded = block.rlp_encode();
    let decoded = Block::rlp_decode(&encoded).expect("Failed to decode block with transaction");

    // Verify
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.transaction_count(), 1);
    assert_eq!(decoded.transactions[0].transaction.nonce, 0);
    assert_eq!(
        decoded.transactions[0].transaction.value,
        1_000_000_000_000_000_000
    );
}

#[test]
fn test_block_rlp_roundtrip_multiple_transactions() {
    use bytes::Bytes;
    use protocore_types::transaction::{Signature, SignedTransaction, Transaction, TxType};

    // Create 5 transactions using the same valid signature pattern as the single-tx test
    let mut transactions = Vec::new();

    for i in 0u64..5 {
        let tx = Transaction {
            tx_type: TxType::DynamicFee,
            chain_id: 1,
            nonce: i,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 2_000_000_000,
            gas_limit: 21000,
            to: Some(Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap()),
            value: (i as u128 + 1) * 1_000_000_000_000_000_000,
            data: Bytes::new(),
            access_list: vec![],
        };

        // Use the same valid signature pattern that works in single-tx test
        let signed_tx = SignedTransaction::new(
            tx,
            Signature {
                v: 1,
                r: H256::from([1u8; 32]),
                s: H256::from([2u8; 32]),
            },
        )
        .expect("Failed to create signed tx");
        transactions.push(signed_tx);
    }

    let header = BlockHeader::new(
        1,
        100,
        1234567890,
        H256::keccak256(b"parent"),
        Address::from_hex("0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb1").unwrap(),
    );

    let block = Block::new(header.clone(), transactions);
    assert_eq!(block.transaction_count(), 5);

    // Encode and decode
    let encoded = block.rlp_encode();
    let decoded =
        Block::rlp_decode(&encoded).expect("Failed to decode block with multiple transactions");

    // Verify
    assert_eq!(decoded.header, header);
    assert_eq!(decoded.transaction_count(), 5);

    for i in 0u64..5 {
        assert_eq!(decoded.transactions[i as usize].transaction.nonce, i);
        assert_eq!(
            decoded.transactions[i as usize].transaction.value,
            (i as u128 + 1) * 1_000_000_000_000_000_000
        );
    }
}
