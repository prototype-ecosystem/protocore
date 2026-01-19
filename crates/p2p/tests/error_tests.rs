//! Tests for error types in the protocore-p2p crate.

use protocore_p2p::Error;

#[test]
fn test_error_display() {
    let err = Error::Transport("connection refused".to_string());
    assert!(err.to_string().contains("transport error"));
}
