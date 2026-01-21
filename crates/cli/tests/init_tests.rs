//! Tests for commands/init.rs initialization functionality

use protocore_cli::commands::init::{execute, InitArgs};
use protocore_cli::utils::OutputFormat;
use protocore_cli::DEFAULT_KEYSTORE_DIR;
use tempfile::tempdir;

#[tokio::test]
async fn test_init_creates_directory_structure() {
    let temp_dir = tempdir().unwrap();
    let data_dir = temp_dir.path().join("testnode");

    let args = InitArgs {
        data_dir: Some(data_dir.to_string_lossy().to_string()),
        chain_id: 12345,
        validators: 1,
        network: "devnet".to_string(),
        validator: false,
        force: false,
        token_name: "TestToken".to_string(),
        token_symbol: "TT".to_string(),
        initial_supply: "1000000000000000000000000000".to_string(),
    };

    let result = execute(args, OutputFormat::Json).await;
    assert!(result.is_ok());

    // Verify directories exist
    assert!(data_dir.exists());
    assert!(data_dir.join(DEFAULT_KEYSTORE_DIR).exists());
    assert!(data_dir.join("data").exists());
    assert!(data_dir.join("logs").exists());

    // Verify files exist
    assert!(data_dir.join(protocore_cli::DEFAULT_CONFIG_FILE).exists());
    assert!(data_dir.join("node.key").exists());
}

#[tokio::test]
async fn test_init_with_validator() {
    let temp_dir = tempdir().unwrap();
    let data_dir = temp_dir.path().join("validatornode");

    let args = InitArgs {
        data_dir: Some(data_dir.to_string_lossy().to_string()),
        chain_id: 12345,
        validators: 1,
        network: "devnet".to_string(),
        validator: true,
        force: false,
        token_name: "TestToken".to_string(),
        token_symbol: "TT".to_string(),
        initial_supply: "1000000000000000000000000000".to_string(),
    };

    let result = execute(args, OutputFormat::Json).await;
    assert!(result.is_ok());

    // Verify validator key exists
    assert!(data_dir.join("validator.key").exists());
    assert!(data_dir.join("genesis.json").exists());
}

// Note: test_generate_config_toml requires access to internal functions
// that are not pub. If needed, consider making them pub(crate) and
// re-exporting for tests, or test through the execute function.
