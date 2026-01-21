//! Node initialization command.
//!
//! This module handles the `protocore init` command, which sets up a new node
//! with the required directory structure, configuration files, and initial keys.

use clap::Parser;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::utils::{print_info, print_success, print_warning, CliError, CliResult, OutputFormat};
use crate::{DEFAULT_CONFIG_FILE, DEFAULT_KEYSTORE_DIR};

/// Arguments for the init command
#[derive(Parser, Debug)]
pub struct InitArgs {
    /// Data directory for the node
    #[arg(short, long)]
    pub data_dir: Option<String>,

    /// Chain ID for the network
    #[arg(long, default_value = "1")]
    pub chain_id: u64,

    /// Number of initial validators (for testnet setup)
    #[arg(long, default_value = "4")]
    pub validators: u32,

    /// Network name (mainnet, testnet, devnet, or custom)
    #[arg(long, default_value = "devnet")]
    pub network: String,

    /// Generate validator key
    #[arg(long)]
    pub validator: bool,

    /// Overwrite existing configuration
    #[arg(long)]
    pub force: bool,

    /// Custom token name
    #[arg(long, default_value = "MicroToken")]
    pub token_name: String,

    /// Custom token symbol
    #[arg(long, default_value = "MCT")]
    pub token_symbol: String,

    /// Initial token supply (in base units)
    #[arg(long, default_value = "1000000000000000000000000000")]
    pub initial_supply: String,
}

/// Execute the init command
pub async fn execute(args: InitArgs, output_format: OutputFormat) -> CliResult<()> {
    let data_dir = args
        .data_dir
        .as_ref()
        .map(PathBuf::from)
        .unwrap_or_else(crate::default_data_dir);

    print_info(&format!(
        "Initializing Proto Core node at: {}",
        data_dir.display()
    ));

    // Check if directory already exists and has config
    let config_path = data_dir.join(DEFAULT_CONFIG_FILE);
    if config_path.exists() && !args.force {
        return Err(CliError::ConfigError(format!(
            "Configuration already exists at {}. Use --force to overwrite.",
            config_path.display()
        )));
    }

    // Create directory structure
    create_directory_structure(&data_dir)?;

    // Generate node key
    let node_key_path = data_dir.join("node.key");
    let node_key_info = generate_node_key(&node_key_path)?;

    // Generate validator key if requested
    let validator_key_info = if args.validator {
        let validator_key_path = data_dir.join("validator.key");
        Some(generate_validator_key(&validator_key_path)?)
    } else {
        None
    };

    // Create default configuration file
    create_config_file(&config_path, &args, &node_key_info)?;

    // Create genesis file for devnet
    if args.network == "devnet" {
        let genesis_path = data_dir.join("genesis.json");
        create_genesis_file(&genesis_path, &args, validator_key_info.as_ref())?;
    }

    // Output results
    let result = InitResult {
        data_dir: data_dir.to_string_lossy().to_string(),
        config_file: config_path.to_string_lossy().to_string(),
        node_key: node_key_info,
        validator_key: validator_key_info,
        chain_id: args.chain_id,
        network: args.network.clone(),
    };

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Text => {
            print_success("Proto Core node initialized successfully!");
            println!();
            println!("Configuration:");
            println!("  Data Directory: {}", result.data_dir);
            println!("  Config File:    {}", result.config_file);
            println!("  Network:        {}", result.network);
            println!("  Chain ID:       {}", result.chain_id);
            println!();
            println!("Node Identity:");
            println!("  Node ID:        {}", result.node_key.node_id);
            println!("  Public Key:     {}", result.node_key.public_key);
            if let Some(ref vk) = result.validator_key {
                println!();
                println!("Validator Identity:");
                println!("  Address:        {}", vk.address);
                println!("  BLS Public Key: {}", vk.bls_public_key);
            }
            println!();
            println!("Next steps:");
            println!("  1. Review configuration: {}", result.config_file);
            println!(
                "  2. Start the node:       protocore start --config {}",
                result.config_file
            );
            if result.validator_key.is_some() {
                println!(
                    "  3. For validator mode:   protocore start --config {} --validator",
                    result.config_file
                );
            }
        }
    }

    Ok(())
}

/// Create the required directory structure
fn create_directory_structure(data_dir: &Path) -> CliResult<()> {
    let directories = [
        data_dir.to_path_buf(),
        data_dir.join(DEFAULT_KEYSTORE_DIR),
        data_dir.join("data"),
        data_dir.join("data/blocks"),
        data_dir.join("data/state"),
        data_dir.join("data/receipts"),
        data_dir.join("logs"),
        data_dir.join("snapshots"),
    ];

    for dir in &directories {
        if !dir.exists() {
            fs::create_dir_all(dir)?;
            tracing::debug!("Created directory: {}", dir.display());
        }
    }

    print_info("Created directory structure");
    Ok(())
}

/// Generate node identity key
fn generate_node_key(path: &Path) -> CliResult<NodeKeyInfo> {
    use protocore_crypto::ecdsa::PrivateKey;

    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();
    let address = public_key.to_address();

    // Save private key to file (hex encoded)
    let key_hex = hex::encode(private_key.to_bytes());
    let mut file = fs::File::create(path)?;
    file.write_all(key_hex.as_bytes())?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    let node_id = format!("0x{}", hex::encode(address));
    let public_key_hex = format!("0x{}", hex::encode(public_key.to_compressed()));

    print_info(&format!("Generated node key: {}", path.display()));

    Ok(NodeKeyInfo {
        key_file: path.to_string_lossy().to_string(),
        node_id,
        public_key: public_key_hex,
    })
}

/// Generate validator identity key (includes BLS key)
fn generate_validator_key(path: &Path) -> CliResult<ValidatorKeyInfo> {
    use protocore_crypto::bls::BlsPrivateKey;
    use protocore_crypto::ecdsa::PrivateKey;

    // Generate ECDSA key for transactions
    let ecdsa_key = PrivateKey::random();
    let ecdsa_public = ecdsa_key.public_key();
    let address = ecdsa_public.to_address();

    // Generate BLS key for consensus
    let bls_key = BlsPrivateKey::random();
    let bls_public = bls_key.public_key();

    // Create validator key file content
    let validator_key = ValidatorKeyFile {
        ecdsa_private_key: hex::encode(ecdsa_key.to_bytes()),
        bls_private_key: hex::encode(bls_key.to_bytes()),
    };

    let key_json = serde_json::to_string_pretty(&validator_key)?;
    let mut file = fs::File::create(path)?;
    file.write_all(key_json.as_bytes())?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(path, perms)?;
    }

    let address_hex = format!("0x{}", hex::encode(address));
    let bls_public_hex = format!("0x{}", hex::encode(bls_public.to_bytes()));

    print_info(&format!("Generated validator key: {}", path.display()));
    print_warning("Keep your validator key secure! Do not share or expose it.");

    Ok(ValidatorKeyInfo {
        key_file: path.to_string_lossy().to_string(),
        address: address_hex,
        bls_public_key: bls_public_hex,
    })
}

/// Create the default configuration file
fn create_config_file(path: &Path, args: &InitArgs, node_key: &NodeKeyInfo) -> CliResult<()> {
    let config_content = generate_config_toml(args, node_key);

    let mut file = fs::File::create(path)?;
    file.write_all(config_content.as_bytes())?;

    print_info(&format!("Created configuration file: {}", path.display()));
    Ok(())
}

/// Generate TOML configuration content
fn generate_config_toml(args: &InitArgs, node_key: &NodeKeyInfo) -> String {
    let data_dir = args.data_dir.as_deref().unwrap_or("~/.protocore");

    format!(
        r#"# Proto Core Node Configuration
# Generated by protocore init

[chain]
# Network identification
chain_id = {chain_id}
network_name = "{network}"

# Token configuration
token_name = "{token_name}"
token_symbol = "{token_symbol}"
decimals = 18

[consensus]
# MinBFT consensus parameters
block_time_ms = 2000
min_validators = 1
max_validators = 100

# Timeout configurations (milliseconds)
propose_timeout_ms = 3000
prevote_timeout_ms = 1000
precommit_timeout_ms = 1000

[economics]
# Gas parameters
min_gas_price = "1000000000"
block_gas_limit = 30000000

# Validator rewards
block_reward = "2000000000000000000"
inflation_rate_bps = 500

[staking]
# Staking parameters
min_stake = "100000000000000000000000"
min_delegation = "1000000000000000000000"
max_validators = 100
unbonding_period_blocks = 21600

[slashing]
# Slashing parameters
downtime_jail_duration_blocks = 1000
double_sign_slash_rate_bps = 500
downtime_slash_rate_bps = 100

[governance]
# Governance parameters
min_deposit = "10000000000000000000000"
voting_period_blocks = 17280
quorum_bps = 3400
threshold_bps = 5000

[network]
# P2P network configuration
listen_address = "/ip4/0.0.0.0/tcp/30303"
external_address = ""
max_peers = 50
node_key_file = "{data_dir}/node.key"

# Bootstrap nodes (empty for devnet)
bootstrap_nodes = []

[rpc]
# JSON-RPC configuration
http_enabled = true
http_address = "127.0.0.1"
http_port = 8545

ws_enabled = true
ws_address = "127.0.0.1"
ws_port = 8546

# Rate limiting
max_connections = 100
rate_limit_per_second = 100

[storage]
# Storage configuration
data_dir = "{data_dir}/data"
cache_size_mb = 512
enable_pruning = false
pruning_keep_blocks = 1000000

[logging]
# Logging configuration
level = "info"
format = "text"
output = "stdout"
log_file = "{data_dir}/logs/protocore.log"
rotation = "daily"

[metrics]
# Prometheus metrics
enabled = true
address = "127.0.0.1"
port = 9090

[validator]
# Validator configuration (if running as validator)
enabled = {validator}
key_file = "{data_dir}/validator.key"
"#,
        chain_id = args.chain_id,
        network = args.network,
        token_name = args.token_name,
        token_symbol = args.token_symbol,
        data_dir = data_dir,
        validator = args.validator,
    )
}

/// Create genesis file for devnet
fn create_genesis_file(
    path: &Path,
    args: &InitArgs,
    validator_key: Option<&ValidatorKeyInfo>,
) -> CliResult<()> {
    let genesis = generate_genesis_json(args, validator_key);

    let mut file = fs::File::create(path)?;
    file.write_all(genesis.as_bytes())?;

    print_info(&format!("Created genesis file: {}", path.display()));
    Ok(())
}

/// Generate genesis JSON content
fn generate_genesis_json(args: &InitArgs, validator_key: Option<&ValidatorKeyInfo>) -> String {
    let timestamp = chrono::Utc::now().timestamp();

    let validators_json = if let Some(vk) = validator_key {
        format!(
            r#"[
        {{
            "address": "{}",
            "bls_public_key": "{}",
            "stake": "100000000000000000000000",
            "commission_rate_bps": 1000
        }}
    ]"#,
            vk.address, vk.bls_public_key
        )
    } else {
        "[]".to_string()
    };

    let accounts_json = if let Some(vk) = validator_key {
        format!(
            r#"[
        {{
            "address": "{}",
            "balance": "{}",
            "nonce": 0
        }}
    ]"#,
            vk.address, args.initial_supply
        )
    } else {
        format!(
            r#"[
        {{
            "address": "0x0000000000000000000000000000000000000001",
            "balance": "{}",
            "nonce": 0
        }}
    ]"#,
            args.initial_supply
        )
    };

    format!(
        r#"{{
    "chain_id": {chain_id},
    "timestamp": {timestamp},
    "token": {{
        "name": "{token_name}",
        "symbol": "{token_symbol}",
        "decimals": 18,
        "initial_supply": "{initial_supply}"
    }},
    "consensus": {{
        "type": "minbft",
        "block_time_ms": 2000,
        "min_validators": 1
    }},
    "accounts": {accounts},
    "validators": {validators},
    "system_contracts": {{
        "staking": "0x0000000000000000000000000000000000001000",
        "governance": "0x0000000000000000000000000000000000001001",
        "slashing": "0x0000000000000000000000000000000000001002"
    }}
}}"#,
        chain_id = args.chain_id,
        timestamp = timestamp,
        token_name = args.token_name,
        token_symbol = args.token_symbol,
        initial_supply = args.initial_supply,
        accounts = accounts_json,
        validators = validators_json,
    )
}

/// Result of initialization
#[derive(Debug, serde::Serialize)]
struct InitResult {
    data_dir: String,
    config_file: String,
    node_key: NodeKeyInfo,
    #[serde(skip_serializing_if = "Option::is_none")]
    validator_key: Option<ValidatorKeyInfo>,
    chain_id: u64,
    network: String,
}

/// Node key information
#[derive(Debug, serde::Serialize)]
struct NodeKeyInfo {
    key_file: String,
    node_id: String,
    public_key: String,
}

/// Validator key information
#[derive(Debug, serde::Serialize)]
struct ValidatorKeyInfo {
    key_file: String,
    address: String,
    bls_public_key: String,
}

/// Validator key file format
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct ValidatorKeyFile {
    ecdsa_private_key: String,
    bls_private_key: String,
}
