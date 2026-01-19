//! Tests for lib.rs constants and default paths

use protocore_cli::{
    APP_NAME, DEFAULT_CONFIG_FILE, DEFAULT_DATA_DIR, DEFAULT_KEYSTORE_DIR,
    default_data_dir, default_keystore_dir, default_config_path,
};

#[test]
fn test_constants() {
    assert_eq!(APP_NAME, "protocore");
    assert_eq!(DEFAULT_CONFIG_FILE, "protocore.toml");
    assert_eq!(DEFAULT_DATA_DIR, ".protocore");
}

#[test]
fn test_default_paths() {
    let data_dir = default_data_dir();
    assert!(data_dir.ends_with(DEFAULT_DATA_DIR));

    let keystore_dir = default_keystore_dir();
    assert!(keystore_dir.ends_with(DEFAULT_KEYSTORE_DIR));

    let config_path = default_config_path();
    assert!(config_path.ends_with(DEFAULT_CONFIG_FILE));
}
