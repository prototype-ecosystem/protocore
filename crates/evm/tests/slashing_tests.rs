//! Integration tests for slashing precompile

use protocore_evm::precompiles::slashing::{
    EvidenceType,
    CENSORSHIP_JAIL_DURATION, CENSORSHIP_SLASH_PERCENT, DOUBLE_SIGN_SLASH_PERCENT,
    DOWNTIME_JAIL_DURATION, DOWNTIME_SLASH_PERCENT_BPS, INVALID_BLOCK_SLASH_PERCENT,
    PERMANENT_JAIL,
};

#[test]
fn test_evidence_type_conversion() {
    assert_eq!(EvidenceType::try_from(0).unwrap(), EvidenceType::DoubleSigning);
    assert_eq!(EvidenceType::try_from(1).unwrap(), EvidenceType::Downtime);
    assert_eq!(EvidenceType::try_from(2).unwrap(), EvidenceType::InvalidBlock);
    assert_eq!(EvidenceType::try_from(3).unwrap(), EvidenceType::Censorship);
    assert!(EvidenceType::try_from(4).is_err());
}

#[test]
fn test_slash_percentages() {
    assert_eq!(DOUBLE_SIGN_SLASH_PERCENT, 5);
    assert_eq!(DOWNTIME_SLASH_PERCENT_BPS, 10);
    assert_eq!(INVALID_BLOCK_SLASH_PERCENT, 5);
    assert_eq!(CENSORSHIP_SLASH_PERCENT, 2);
}

#[test]
fn test_jail_durations() {
    assert_eq!(DOWNTIME_JAIL_DURATION, 43200);
    assert_eq!(CENSORSHIP_JAIL_DURATION, 302400);
    assert_eq!(PERMANENT_JAIL, u64::MAX);
}
