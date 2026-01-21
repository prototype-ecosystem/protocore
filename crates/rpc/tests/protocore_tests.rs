//! Tests for Proto Core RPC methods

use protocore_rpc::protocore::{ProposalStatus, ValidatorInfo};
use protocore_rpc::types::{Address, HexBytes, HexU256, HexU64};

#[test]
fn test_proposal_status_serde() {
    let status = ProposalStatus::Voting;
    let json = serde_json::to_string(&status).unwrap();
    assert_eq!(json, "\"voting\"");

    let parsed: ProposalStatus = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed, ProposalStatus::Voting);
}

#[test]
fn test_validator_info_serde() {
    let info = ValidatorInfo {
        address: Address([0x42; 20]),
        pubkey: HexBytes(vec![0; 48]),
        stake: HexU256::from_u128(1_000_000_000_000_000_000),
        self_stake: HexU256::from_u128(500_000_000_000_000_000),
        delegated_stake: HexU256::from_u128(500_000_000_000_000_000),
        commission: 1000,
        active: true,
        jailed: false,
        blocks_proposed: HexU64(100),
        blocks_signed: HexU64(1000),
        uptime: 99.5,
    };

    let json = serde_json::to_string(&info).unwrap();
    let parsed: ValidatorInfo = serde_json::from_str(&json).unwrap();

    assert_eq!(parsed.address, info.address);
    assert_eq!(parsed.commission, info.commission);
    assert!(parsed.active);
}
