//! Tests for RPC server configuration

use protocore_rpc::server::{CorsConfig, RpcServerConfig};

#[test]
fn test_default_config() {
    let config = RpcServerConfig::default();
    assert_eq!(config.http_addr, "127.0.0.1:8545".parse().unwrap());
    assert_eq!(config.ws_addr, "127.0.0.1:8546".parse().unwrap());
    assert_eq!(config.chain_id, 123456);
}

#[test]
fn test_cors_config_default() {
    let cors = CorsConfig::default();
    assert!(cors.allowed_origins.is_empty());
    assert!(cors.allowed_methods.contains(&"POST".to_string()));
}
