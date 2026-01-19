//! Tests for RPC types

use protocore_rpc::types::{
    Address, BlockNumberOrTag, CallRequest, H256, HexBytes, HexU64,
};

#[test]
fn test_block_number_or_tag_parse() {
    assert_eq!("latest".parse::<BlockNumberOrTag>().unwrap(), BlockNumberOrTag::Latest);
    assert_eq!("pending".parse::<BlockNumberOrTag>().unwrap(), BlockNumberOrTag::Pending);
    assert_eq!("earliest".parse::<BlockNumberOrTag>().unwrap(), BlockNumberOrTag::Earliest);
    assert_eq!("0x10".parse::<BlockNumberOrTag>().unwrap(), BlockNumberOrTag::Number(16));
}

#[test]
fn test_hex_u64_serde() {
    let val = HexU64(255);
    let json = serde_json::to_string(&val).unwrap();
    assert_eq!(json, "\"0xff\"");

    let parsed: HexU64 = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.0, 255);
}

#[test]
fn test_address_serde() {
    let addr = Address([0x12; 20]);
    let json = serde_json::to_string(&addr).unwrap();
    assert!(json.starts_with("\"0x"));

    let parsed: Address = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.0, addr.0);
}

#[test]
fn test_h256_serde() {
    let hash = H256([0xab; 32]);
    let json = serde_json::to_string(&hash).unwrap();
    assert!(json.contains("abab"));

    let parsed: H256 = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.0, hash.0);
}

#[test]
fn test_call_request_serde() {
    let req = CallRequest {
        to: Some(Address([0x42; 20])),
        data: Some(HexBytes(vec![0x01, 0x02, 0x03])),
        ..Default::default()
    };

    let json = serde_json::to_string(&req).unwrap();
    let parsed: CallRequest = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.to, req.to);
    assert_eq!(parsed.data, req.data);
}
