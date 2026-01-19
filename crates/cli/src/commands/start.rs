//! Node startup command.
//!
//! This module handles the `protocore start` command, which initializes and runs
//! the blockchain node with all its components (consensus, networking, RPC, etc.).

use clap::Parser;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::signal;
use tokio::sync::broadcast;

use crate::utils::{CliError, CliResult, OutputFormat, print_error, print_info, print_success, print_warning};

/// Arguments for the start command
#[derive(Parser, Debug)]
pub struct StartArgs {
    /// Path to configuration file
    #[arg(short, long, default_value = "protocore.toml")]
    pub config: String,

    /// Data directory (overrides config file setting)
    #[arg(short, long)]
    pub data_dir: Option<String>,

    /// Enable validator mode
    #[arg(long)]
    pub validator: bool,

    /// Path to validator key file
    #[arg(long)]
    pub validator_key: Option<String>,

    /// Override chain ID
    #[arg(long)]
    pub chain_id: Option<u64>,

    /// P2P listen address (e.g., /ip4/0.0.0.0/tcp/30303)
    #[arg(long)]
    pub p2p_address: Option<String>,

    /// RPC HTTP port
    #[arg(long)]
    pub rpc_port: Option<u16>,

    /// RPC WebSocket port
    #[arg(long)]
    pub ws_port: Option<u16>,

    /// Bootstrap nodes (comma-separated)
    #[arg(long)]
    pub bootnodes: Option<String>,

    /// Disable RPC server
    #[arg(long)]
    pub no_rpc: bool,

    /// Disable P2P networking (solo mode)
    #[arg(long)]
    pub no_network: bool,

    /// Enable metrics server
    #[arg(long)]
    pub metrics: bool,

    /// Metrics port
    #[arg(long, default_value = "9090")]
    pub metrics_port: u16,

    /// Maximum number of peers
    #[arg(long)]
    pub max_peers: Option<usize>,

    /// Log level (error, warn, info, debug, trace)
    #[arg(long)]
    pub log_level: Option<String>,

    /// Sync mode (full, fast, light)
    #[arg(long, default_value = "full")]
    pub sync_mode: String,
}

/// Execute the start command
pub async fn execute(args: StartArgs, output_format: OutputFormat) -> CliResult<()> {
    // Load configuration
    let config_path = PathBuf::from(&args.config);
    if !config_path.exists() {
        return Err(CliError::FileNotFound(args.config.clone()));
    }

    print_info(&format!("Loading configuration from: {}", args.config));

    // Load and parse configuration
    let config = load_config(&config_path, &args)?;

    // Display startup information
    display_startup_info(&config, &args, output_format)?;

    // Create shutdown signal channel
    let (shutdown_tx, _) = broadcast::channel::<()>(1);

    // Initialize components
    let node = initialize_node(&config, &args, shutdown_tx.clone()).await?;

    print_success("Proto Core node started successfully!");

    if args.validator {
        print_info("Running in VALIDATOR mode");
    } else {
        print_info("Running in FULL NODE mode");
    }

    // Display connection information
    println!();
    println!("Endpoints:");
    if !args.no_rpc {
        let http_port = args.rpc_port.unwrap_or(config.rpc_http_port);
        let ws_port = args.ws_port.unwrap_or(config.rpc_ws_port);
        println!("  HTTP RPC:   http://{}:{}", config.rpc_address, http_port);
        println!("  WebSocket:  ws://{}:{}", config.rpc_address, ws_port);
    }
    if !args.no_network {
        println!("  P2P:        {}", config.p2p_address);
    }
    if args.metrics {
        println!("  Metrics:    http://127.0.0.1:{}/metrics", args.metrics_port);
    }
    println!();
    println!("Press Ctrl+C to stop the node");

    // Wait for shutdown signal
    wait_for_shutdown(shutdown_tx, node).await?;

    print_info("Node shutdown complete");
    Ok(())
}

/// Node configuration (parsed from file and CLI overrides)
#[derive(Debug)]
struct NodeConfig {
    chain_id: u64,
    network_name: String,
    data_dir: PathBuf,
    validator_enabled: bool,
    validator_key_path: Option<PathBuf>,
    p2p_address: String,
    rpc_address: String,
    rpc_http_port: u16,
    rpc_ws_port: u16,
    max_peers: usize,
    bootstrap_nodes: Vec<String>,
    log_level: String,
    sync_mode: SyncMode,
}

/// Synchronization mode
#[derive(Debug, Clone, Copy)]
enum SyncMode {
    Full,
    Fast,
    Light,
}

impl std::str::FromStr for SyncMode {
    type Err = CliError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "full" => Ok(SyncMode::Full),
            "fast" => Ok(SyncMode::Fast),
            "light" => Ok(SyncMode::Light),
            _ => Err(CliError::InvalidArgument(format!("Invalid sync mode: {}", s))),
        }
    }
}

/// Load and merge configuration
fn load_config(config_path: &Path, args: &StartArgs) -> CliResult<NodeConfig> {
    let config_content = std::fs::read_to_string(config_path)?;
    let toml_value: toml::Value = toml::from_str(&config_content)
        .map_err(|e| CliError::ConfigError(format!("Failed to parse config: {}", e)))?;

    // Extract values with defaults
    let chain = toml_value.get("chain").and_then(|v| v.as_table());
    let network = toml_value.get("network").and_then(|v| v.as_table());
    let rpc = toml_value.get("rpc").and_then(|v| v.as_table());
    let storage = toml_value.get("storage").and_then(|v| v.as_table());
    let logging = toml_value.get("logging").and_then(|v| v.as_table());
    let validator_section = toml_value.get("validator").and_then(|v| v.as_table());

    // Chain configuration
    let chain_id = args.chain_id.unwrap_or_else(|| {
        chain.and_then(|c| c.get("chain_id")).and_then(|v| v.as_integer()).unwrap_or(1) as u64
    });

    let network_name = chain
        .and_then(|c| c.get("network_name"))
        .and_then(|v| v.as_str())
        .unwrap_or("mainnet")
        .to_string();

    // Data directory
    let config_data_dir = storage
        .and_then(|s| s.get("data_dir"))
        .and_then(|v| v.as_str())
        .map(|s| s.replace("~", &dirs::home_dir().unwrap_or_default().to_string_lossy()));

    let data_dir = args.data_dir.clone()
        .or(config_data_dir)
        .map(PathBuf::from)
        .unwrap_or_else(crate::default_data_dir);

    // Validator configuration
    let validator_enabled = args.validator || validator_section
        .and_then(|v| v.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let validator_key_path = args.validator_key.clone()
        .or_else(|| validator_section
            .and_then(|v| v.get("key_file"))
            .and_then(|v| v.as_str())
            .map(|s| s.replace("~", &dirs::home_dir().unwrap_or_default().to_string_lossy())))
        .map(PathBuf::from);

    // P2P configuration
    let p2p_address = args.p2p_address.clone().unwrap_or_else(|| {
        network
            .and_then(|n| n.get("listen_address"))
            .and_then(|v| v.as_str())
            .unwrap_or("/ip4/0.0.0.0/tcp/30303")
            .to_string()
    });

    let max_peers = args.max_peers.unwrap_or_else(|| {
        network.and_then(|n| n.get("max_peers")).and_then(|v| v.as_integer()).unwrap_or(50) as usize
    });

    let bootstrap_nodes: Vec<String> = args.bootnodes
        .as_ref()
        .map(|s| s.split(',').map(|s| s.trim().to_string()).collect())
        .unwrap_or_else(|| {
            network
                .and_then(|n| n.get("bootstrap_nodes"))
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        });

    // RPC configuration
    let rpc_address = rpc
        .and_then(|r| r.get("http_address"))
        .and_then(|v| v.as_str())
        .unwrap_or("127.0.0.1")
        .to_string();

    let rpc_http_port = rpc
        .and_then(|r| r.get("http_port"))
        .and_then(|v| v.as_integer())
        .unwrap_or(8545) as u16;

    let rpc_ws_port = rpc
        .and_then(|r| r.get("ws_port"))
        .and_then(|v| v.as_integer())
        .unwrap_or(8546) as u16;

    // Logging configuration
    let log_level = args.log_level.clone().unwrap_or_else(|| {
        logging
            .and_then(|l| l.get("level"))
            .and_then(|v| v.as_str())
            .unwrap_or("info")
            .to_string()
    });

    // Sync mode
    let sync_mode: SyncMode = args.sync_mode.parse()?;

    Ok(NodeConfig {
        chain_id,
        network_name,
        data_dir,
        validator_enabled,
        validator_key_path,
        p2p_address,
        rpc_address,
        rpc_http_port,
        rpc_ws_port,
        max_peers,
        bootstrap_nodes,
        log_level,
        sync_mode,
    })
}

/// Display startup information
fn display_startup_info(
    config: &NodeConfig,
    args: &StartArgs,
    output_format: OutputFormat,
) -> CliResult<()> {
    let info = serde_json::json!({
        "chain_id": config.chain_id,
        "network": config.network_name,
        "data_dir": config.data_dir.to_string_lossy(),
        "validator_mode": config.validator_enabled,
        "sync_mode": format!("{:?}", config.sync_mode),
        "p2p_enabled": !args.no_network,
        "rpc_enabled": !args.no_rpc,
        "max_peers": config.max_peers,
        "bootstrap_nodes": config.bootstrap_nodes.len(),
    });

    match output_format {
        OutputFormat::Json => {
            // In JSON mode, we'll output status updates as JSON lines
            tracing::debug!("Startup config: {}", serde_json::to_string(&info)?);
        }
        OutputFormat::Text => {
            println!();
            println!("Proto Core Node Starting");
            println!("========================");
            println!("  Chain ID:      {}", config.chain_id);
            println!("  Network:       {}", config.network_name);
            println!("  Data Dir:      {}", config.data_dir.display());
            println!("  Sync Mode:     {:?}", config.sync_mode);
            println!("  Max Peers:     {}", config.max_peers);
            if !config.bootstrap_nodes.is_empty() {
                println!("  Boot Nodes:    {}", config.bootstrap_nodes.len());
            }
            println!();
        }
    }

    Ok(())
}

/// Node handle for managing running components
struct NodeHandle {
    _shutdown_tx: broadcast::Sender<()>,
    // TODO: Add handles for each component when they're implemented
    // consensus_handle: JoinHandle<()>,
    // p2p_handle: JoinHandle<()>,
    // rpc_handle: JoinHandle<()>,
}

/// Initialize all node components
async fn initialize_node(
    config: &NodeConfig,
    args: &StartArgs,
    shutdown_tx: broadcast::Sender<()>,
) -> CliResult<NodeHandle> {
    print_info("Initializing node components...");

    // Verify data directory exists
    if !config.data_dir.exists() {
        return Err(CliError::ConfigError(format!(
            "Data directory does not exist: {}. Run 'protocore init' first.",
            config.data_dir.display()
        )));
    }

    // Initialize storage
    print_info("Initializing storage...");
    initialize_storage(config).await?;

    // Load validator key if in validator mode
    if config.validator_enabled {
        print_info("Loading validator key...");
        load_validator_key(config).await?;
    }

    // Initialize P2P networking
    if !args.no_network {
        print_info("Initializing P2P network...");
        initialize_p2p(config).await?;
    }

    // Initialize consensus engine
    print_info("Initializing consensus engine...");
    initialize_consensus(config).await?;

    // Initialize mempool
    print_info("Initializing transaction mempool...");
    initialize_mempool(config).await?;

    // Initialize RPC server
    if !args.no_rpc {
        print_info("Starting RPC server...");
        initialize_rpc(config, args).await?;
    }

    // Initialize metrics server
    if args.metrics {
        print_info("Starting metrics server...");
        initialize_metrics(args).await?;
    }

    Ok(NodeHandle {
        _shutdown_tx: shutdown_tx,
    })
}

/// Initialize storage subsystem
async fn initialize_storage(config: &NodeConfig) -> CliResult<()> {
    let db_path = config.data_dir.join("data");

    // TODO: Initialize protocore-storage Database
    // let db_config = protocore_storage::DatabaseConfig {
    //     path: db_path,
    //     cache_size_mb: 512,
    // };
    // let _db = protocore_storage::Database::open(db_config)?;

    tracing::debug!("Storage initialized at: {}", db_path.display());
    Ok(())
}

/// Load validator key from file
async fn load_validator_key(config: &NodeConfig) -> CliResult<()> {
    let key_path = config.validator_key_path.as_ref().ok_or_else(|| {
        CliError::ConfigError("Validator mode enabled but no key file specified".to_string())
    })?;

    if !key_path.exists() {
        return Err(CliError::FileNotFound(key_path.to_string_lossy().to_string()));
    }

    // TODO: Load and validate the validator key
    // let key_content = std::fs::read_to_string(key_path)?;
    // let key_file: ValidatorKeyFile = serde_json::from_str(&key_content)?;

    tracing::debug!("Validator key loaded from: {}", key_path.display());
    Ok(())
}

/// Initialize P2P networking
async fn initialize_p2p(config: &NodeConfig) -> CliResult<()> {
    // TODO: Initialize protocore-p2p NetworkService
    // let p2p_config = protocore_p2p::NetworkConfig {
    //     listen_address: config.p2p_address.parse()?,
    //     max_peers: config.max_peers,
    //     bootstrap_nodes: config.bootstrap_nodes.clone(),
    // };
    // let _network = protocore_p2p::NetworkService::new(p2p_config).await?;

    tracing::debug!("P2P network listening on: {}", config.p2p_address);
    Ok(())
}

/// Initialize consensus engine
async fn initialize_consensus(config: &NodeConfig) -> CliResult<()> {
    // TODO: Initialize protocore-consensus ProtoBFT engine
    // let consensus_config = protocore_consensus::ConsensusConfig {
    //     chain_id: config.chain_id,
    //     validator_enabled: config.validator_enabled,
    // };
    // let _consensus = protocore_consensus::ProtoBftEngine::new(consensus_config).await?;

    tracing::debug!("Consensus engine initialized for chain: {}", config.chain_id);
    Ok(())
}

/// Initialize transaction mempool
async fn initialize_mempool(_config: &NodeConfig) -> CliResult<()> {
    // TODO: Initialize protocore-mempool
    // let mempool_config = protocore_mempool::MempoolConfig::default();
    // let _mempool = protocore_mempool::Mempool::new(mempool_config);

    tracing::debug!("Mempool initialized");
    Ok(())
}

/// Initialize RPC server
async fn initialize_rpc(config: &NodeConfig, args: &StartArgs) -> CliResult<()> {
    let http_port = args.rpc_port.unwrap_or(config.rpc_http_port);
    let ws_port = args.ws_port.unwrap_or(config.rpc_ws_port);

    // TODO: Initialize protocore-rpc server
    // let rpc_config = protocore_rpc::RpcConfig {
    //     http_address: format!("{}:{}", config.rpc_address, http_port),
    //     ws_address: format!("{}:{}", config.rpc_address, ws_port),
    // };
    // let _rpc = protocore_rpc::RpcServer::start(rpc_config).await?;

    tracing::debug!("RPC server started - HTTP: {}, WS: {}", http_port, ws_port);
    Ok(())
}

/// Initialize metrics server
async fn initialize_metrics(args: &StartArgs) -> CliResult<()> {
    // TODO: Initialize Prometheus metrics endpoint
    // let metrics_addr = format!("127.0.0.1:{}", args.metrics_port);
    // tokio::spawn(async move {
    //     // Start metrics HTTP server
    // });

    tracing::debug!("Metrics server started on port: {}", args.metrics_port);
    Ok(())
}

/// Wait for shutdown signal and gracefully stop the node
async fn wait_for_shutdown(shutdown_tx: broadcast::Sender<()>, _node: NodeHandle) -> CliResult<()> {
    // Wait for Ctrl+C
    match signal::ctrl_c().await {
        Ok(()) => {
            println!();
            print_info("Shutdown signal received, stopping node...");
        }
        Err(err) => {
            print_error(&format!("Error listening for shutdown signal: {}", err));
        }
    }

    // Signal all components to shutdown
    let _ = shutdown_tx.send(());

    // Give components time to gracefully shutdown
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    Ok(())
}

