//! Tests for Ethereum RPC methods

#[test]
fn test_hex_formatting() {
    assert_eq!(format!("0x{:x}", 255u64), "0xff");
    assert_eq!(format!("0x{:x}", 0u64), "0x0");
    assert_eq!(format!("0x{:x}", 123456u64), "0x1e240");
}
