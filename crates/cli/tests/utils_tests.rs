//! Tests for utils.rs shared utilities

use std::time::Duration;
use protocore_cli::utils::{
    parse_amount, format_balance, format_with_commas, format_duration, OutputFormat,
};

#[test]
fn test_parse_amount_simple() {
    assert_eq!(parse_amount("1000").unwrap(), 1000);
    assert_eq!(parse_amount("1k").unwrap(), 1000);
    assert_eq!(parse_amount("1m").unwrap(), 1_000_000);
    assert_eq!(parse_amount("1b").unwrap(), 1_000_000_000);
}

#[test]
fn test_parse_amount_tokens() {
    assert_eq!(parse_amount("1eth").unwrap(), 1_000_000_000_000_000_000);
    assert_eq!(parse_amount("1mct").unwrap(), 1_000_000_000_000_000_000);
    assert_eq!(parse_amount("0.5eth").unwrap(), 500_000_000_000_000_000);
}

#[test]
fn test_format_balance() {
    assert_eq!(format_balance("0"), "0 MCT");
    assert_eq!(format_balance("1000000000000000000"), "1 MCT");
    assert_eq!(format_balance("1500000000000000000"), "1.5 MCT");
}

#[test]
fn test_format_with_commas() {
    assert_eq!(format_with_commas(1000), "1,000");
    assert_eq!(format_with_commas(1000000), "1,000,000");
    assert_eq!(format_with_commas(123), "123");
}

#[test]
fn test_format_duration() {
    assert_eq!(format_duration(Duration::from_secs(30)), "30s");
    assert_eq!(format_duration(Duration::from_secs(90)), "1m 30s");
    assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m");
    assert_eq!(format_duration(Duration::from_secs(90000)), "1d 1h");
}

#[test]
fn test_output_format_default() {
    assert!(matches!(OutputFormat::default(), OutputFormat::Text));
}
