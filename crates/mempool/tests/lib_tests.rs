//! Tests for mempool error types.

use protocore_mempool::MempoolError;

#[test]
fn test_error_display() {
    let err = MempoolError::AlreadyExists;
    assert_eq!(err.to_string(), "transaction already exists in pool");

    let err = MempoolError::NonceTooLow {
        expected: 5,
        actual: 3,
    };
    assert_eq!(err.to_string(), "nonce too low: expected at least 5, got 3");

    let err = MempoolError::ReplacementUnderpriced {
        minimum: 10,
        provided: 5,
    };
    assert_eq!(
        err.to_string(),
        "replacement transaction underpriced: minimum 10 gwei, got 5 gwei"
    );
}
