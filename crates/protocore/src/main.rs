//! # Proto Core Node
//!
//! Main entry point for the Proto Core blockchain node.
//!
//! This binary provides the complete Proto Core node implementation including:
//! - Full node operation (sync, validate, serve RPC)
//! - Validator node operation (propose blocks, participate in consensus)
//! - CLI tools for key management, queries, and chain operations

use anyhow::Result;
use clap::Parser;
use tracing::info;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

mod block_builder;
mod node;
mod validator;

pub use block_builder::BlockBuilder;
pub use node::Node;
pub use validator::ValidatorNode;

/// Proto Core node and tools
#[derive(Parser, Debug)]
#[command(name = "protocore")]
#[command(author = "Proto Core Team")]
#[command(version)]
#[command(about = "Proto Core blockchain node - lightweight EVM with ProtoBFT consensus")]
#[command(long_about = None)]
struct Cli {
    /// Enable verbose logging (can be repeated for more verbosity)
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    /// Log format: text, json, or compact
    #[arg(long, default_value = "text")]
    log_format: LogFormat,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum LogFormat {
    Text,
    Json,
    Compact,
}

#[derive(clap::Subcommand, Debug)]
enum Commands {
    /// Start the Proto Core node
    Start {
        /// Configuration file path
        #[arg(short, long, default_value = "protocore.toml")]
        config: String,

        /// Data directory (overrides config file)
        #[arg(short, long)]
        data_dir: Option<String>,

        /// Enable validator mode
        #[arg(long)]
        validator: bool,

        /// Path to validator key file (required for validator mode)
        #[arg(long)]
        validator_key: Option<String>,

        /// RPC HTTP listen address (overrides config)
        #[arg(long)]
        rpc_addr: Option<String>,

        /// P2P listen address (overrides config)
        #[arg(long)]
        p2p_addr: Option<String>,

        /// Bootstrap peers (comma-separated multiaddrs)
        #[arg(long)]
        bootstrap_peers: Option<String>,
    },

    /// Initialize a new chain
    Init {
        /// Output directory for chain files
        #[arg(short, long, default_value = ".")]
        output: String,

        /// Chain ID
        #[arg(long)]
        chain_id: u64,

        /// Number of initial validators
        #[arg(long, default_value = "4")]
        validators: u32,

        /// Token name
        #[arg(long, default_value = "ProtoCore")]
        token_name: String,

        /// Token symbol
        #[arg(long, default_value = "PCR")]
        token_symbol: String,
    },

    /// Key management commands
    Keys {
        #[command(subcommand)]
        command: KeysCommands,
    },

    /// Query chain state
    Query {
        #[command(subcommand)]
        command: QueryCommands,
    },

    /// Transaction commands
    Tx {
        #[command(subcommand)]
        command: TxCommands,
    },

    /// Staking commands
    Staking {
        #[command(subcommand)]
        command: StakingCommands,
    },

    /// Governance commands
    Governance {
        #[command(subcommand)]
        command: GovernanceCommands,
    },

    /// Export state snapshot
    Export {
        /// Output file path
        #[arg(short, long)]
        output: String,

        /// Block height to export (default: latest)
        #[arg(long)]
        height: Option<u64>,

        /// RPC endpoint to connect to
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Import state snapshot
    Import {
        /// Input snapshot file
        #[arg(short, long)]
        input: String,

        /// Data directory
        #[arg(short, long)]
        data_dir: String,
    },

    /// Show version information
    Version,
}

#[derive(clap::Subcommand, Debug)]
enum KeysCommands {
    /// Generate a new key
    Generate {
        /// Key type: wallet, validator
        #[arg(long, default_value = "wallet")]
        key_type: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,

        /// Encrypt with password
        #[arg(long)]
        password: bool,
    },

    /// Import key from mnemonic phrase
    Import {
        /// Mnemonic phrase (12 or 24 words)
        #[arg(long)]
        mnemonic: String,

        /// Key type: wallet, validator
        #[arg(long, default_value = "wallet")]
        key_type: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// List stored keys
    List {
        /// Keystore directory
        #[arg(long, default_value = "./keystore")]
        keystore: String,
    },

    /// Show key details
    Show {
        /// Key name or address
        name: String,

        /// Keystore directory
        #[arg(long, default_value = "./keystore")]
        keystore: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum QueryCommands {
    /// Get block by number or hash
    Block {
        /// Block number or "latest"
        #[arg(default_value = "latest")]
        block: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get transaction by hash
    Tx {
        /// Transaction hash (0x...)
        hash: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get account balance
    Balance {
        /// Account address (0x...)
        address: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get account nonce
    Nonce {
        /// Account address (0x...)
        address: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get current validator set
    Validators {
        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get staking info for an address
    Staking {
        /// Account address
        address: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get chain status
    Status {
        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum TxCommands {
    /// Send native tokens
    Send {
        /// Recipient address
        #[arg(long)]
        to: String,

        /// Amount to send (in wei)
        #[arg(long)]
        amount: String,

        /// Sender key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,

        /// Gas price (optional, uses network estimate if not provided)
        #[arg(long)]
        gas_price: Option<String>,

        /// Gas limit (optional)
        #[arg(long)]
        gas_limit: Option<u64>,
    },

    /// Call a contract
    Call {
        /// Contract address
        #[arg(long)]
        to: String,

        /// Call data (hex encoded)
        #[arg(long)]
        data: String,

        /// Value to send (optional)
        #[arg(long, default_value = "0")]
        value: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum StakingCommands {
    /// Register as a validator
    CreateValidator {
        /// Initial stake amount (in wei)
        #[arg(long)]
        amount: String,

        /// Commission rate (basis points, e.g., 1000 = 10%)
        #[arg(long)]
        commission: u16,

        /// Validator key file
        #[arg(long)]
        key: String,

        /// BLS public key (hex)
        #[arg(long)]
        bls_pubkey: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Delegate to a validator
    Delegate {
        /// Validator address
        #[arg(long)]
        validator: String,

        /// Amount to delegate (in wei)
        #[arg(long)]
        amount: String,

        /// Delegator key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Undelegate from a validator
    Undelegate {
        /// Validator address
        #[arg(long)]
        validator: String,

        /// Amount to undelegate (in wei)
        #[arg(long)]
        amount: String,

        /// Delegator key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Claim staking rewards
    ClaimRewards {
        /// Delegator key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Withdraw unbonded tokens
    Withdraw {
        /// Delegator key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[derive(clap::Subcommand, Debug)]
enum GovernanceCommands {
    /// Create a governance proposal
    Propose {
        /// Proposal type: parameter-change, upgrade, text
        #[arg(long)]
        proposal_type: String,

        /// Proposal title
        #[arg(long)]
        title: String,

        /// Proposal description
        #[arg(long)]
        description: String,

        /// Proposer key file
        #[arg(long)]
        key: String,

        /// Deposit amount
        #[arg(long)]
        deposit: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Vote on a proposal
    Vote {
        /// Proposal ID
        #[arg(long)]
        proposal_id: u64,

        /// Vote option: for, against, abstain
        #[arg(long)]
        vote: String,

        /// Voter key file
        #[arg(long)]
        key: String,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// Get proposal details
    GetProposal {
        /// Proposal ID
        #[arg(long)]
        proposal_id: u64,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },

    /// List all proposals
    List {
        /// Filter by status: pending, active, passed, rejected
        #[arg(long)]
        status: Option<String>,

        /// RPC endpoint
        #[arg(long, default_value = "http://localhost:8545")]
        rpc: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing/logging
    init_tracing(&cli)?;

    info!(version = env!("CARGO_PKG_VERSION"), "Starting Proto Core");

    match cli.command {
        Commands::Start {
            config,
            data_dir,
            validator,
            validator_key,
            rpc_addr,
            p2p_addr,
            bootstrap_peers,
        } => {
            handle_start(
                config,
                data_dir,
                validator,
                validator_key,
                rpc_addr,
                p2p_addr,
                bootstrap_peers,
            )
            .await
        }

        Commands::Init {
            output,
            chain_id,
            validators,
            token_name,
            token_symbol,
        } => handle_init(output, chain_id, validators, token_name, token_symbol).await,

        Commands::Keys { command } => handle_keys(command).await,
        Commands::Query { command } => handle_query(command).await,
        Commands::Tx { command } => handle_tx(command).await,
        Commands::Staking { command } => handle_staking(command).await,
        Commands::Governance { command } => handle_governance(command).await,

        Commands::Export {
            output,
            height,
            rpc,
        } => handle_export(output, height, rpc).await,
        Commands::Import { input, data_dir } => handle_import(input, data_dir).await,
        Commands::Version => handle_version(),
    }
}

/// Initialize tracing with the configured format and verbosity
fn init_tracing(cli: &Cli) -> Result<()> {
    let filter = match cli.verbose {
        0 => "info,protocore=info",
        1 => "info,protocore=debug",
        2 => "debug,protocore=debug",
        _ => "trace,protocore=trace",
    };

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter));

    match cli.log_format {
        LogFormat::Text => {
            tracing_subscriber::registry()
                .with(fmt::layer().with_target(true))
                .with(env_filter)
                .init();
        }
        LogFormat::Json => {
            tracing_subscriber::registry()
                .with(fmt::layer().json())
                .with(env_filter)
                .init();
        }
        LogFormat::Compact => {
            tracing_subscriber::registry()
                .with(fmt::layer().compact())
                .with(env_filter)
                .init();
        }
    }

    Ok(())
}

/// Handle the `start` command - starts a full node or validator
async fn handle_start(
    config_path: String,
    data_dir: Option<String>,
    validator_mode: bool,
    validator_key: Option<String>,
    rpc_addr: Option<String>,
    p2p_addr: Option<String>,
    bootstrap_peers: Option<String>,
) -> Result<()> {
    use std::path::Path;

    info!(config = %config_path, "Loading configuration");

    // Load configuration
    let mut config = protocore_config::Config::load(Path::new(&config_path))?;

    // Apply command-line overrides
    if let Some(dir) = data_dir {
        config.storage.data_dir = dir;
    }
    if let Some(addr) = rpc_addr {
        config.rpc.http_address = addr;
    }
    if let Some(addr) = p2p_addr {
        config.network.listen_address = addr;
    }
    if let Some(peers) = bootstrap_peers {
        config.network.boot_nodes = peers.split(',').map(String::from).collect();
    }

    if validator_mode {
        // Validator mode requires a key
        let key_path = validator_key.ok_or_else(|| {
            anyhow::anyhow!("--validator-key is required when running in validator mode")
        })?;

        info!(key = %key_path, "Starting validator node");

        let mut validator = ValidatorNode::new(config, Path::new(&key_path)).await?;
        validator.run().await
    } else {
        info!("Starting full node");

        let mut node = Node::new(config).await?;
        node.run().await
    }
}

/// Handle the `init` command - initialize a new chain
async fn handle_init(
    output: String,
    chain_id: u64,
    validators: u32,
    token_name: String,
    token_symbol: String,
) -> Result<()> {
    info!(
        output = %output,
        chain_id = chain_id,
        validators = validators,
        "Initializing new chain"
    );

    // Create output directory
    std::fs::create_dir_all(&output)?;

    // Generate validator keys
    for i in 0..validators {
        let keys = validator::ValidatorKeys::generate();
        let key_path = std::path::Path::new(&output).join(format!("validator_{}.key", i));
        keys.save(&key_path)?;
        info!(key = %key_path.display(), "Generated validator key {}", i);
    }

    // Generate genesis config
    let genesis_config = serde_json::json!({
        "chain_id": chain_id,
        "token_name": token_name,
        "token_symbol": token_symbol,
        "validators": validators,
        "initial_supply": "1000000000000000000000000000",
        "block_time_ms": 2000,
        "max_validators": 100,
    });

    let config_path = std::path::Path::new(&output).join("genesis.json");
    std::fs::write(&config_path, serde_json::to_string_pretty(&genesis_config)?)?;
    info!(path = %config_path.display(), "Wrote genesis configuration");

    println!("Chain initialized successfully!");
    println!("  Output directory: {}", output);
    println!("  Chain ID: {}", chain_id);
    println!("  Validators: {}", validators);
    println!("  Token: {} ({})", token_name, token_symbol);

    Ok(())
}

/// Handle keys subcommands
async fn handle_keys(command: KeysCommands) -> Result<()> {
    match command {
        KeysCommands::Generate {
            key_type,
            output,
            password: _,
        } => {
            let keys = validator::ValidatorKeys::generate();
            let output_path = output.unwrap_or_else(|| format!("{}.key", key_type));
            keys.save(std::path::Path::new(&output_path))?;
            println!("Generated {} key: {}", key_type, output_path);
            println!("Address: 0x{}", hex::encode(keys.address.as_bytes()));
            Ok(())
        }
        KeysCommands::Import {
            mnemonic: _,
            key_type,
            output: _,
        } => {
            // TODO: Implement mnemonic import
            println!(
                "Mnemonic import not yet implemented for key type: {}",
                key_type
            );
            Ok(())
        }
        KeysCommands::List { keystore } => {
            println!("Listing keys in: {}", keystore);
            let path = std::path::Path::new(&keystore);
            if path.exists() {
                for entry in std::fs::read_dir(path)? {
                    let entry = entry?;
                    if entry.path().extension().is_some_and(|e| e == "key") {
                        println!("  {}", entry.file_name().to_string_lossy());
                    }
                }
            } else {
                println!("  (keystore directory does not exist)");
            }
            Ok(())
        }
        KeysCommands::Show { name, keystore } => {
            let key_path = std::path::Path::new(&keystore).join(&name);
            if key_path.exists() {
                let keys = validator::ValidatorKeys::load(&key_path)?;
                println!("Key: {}", name);
                println!("  Address: 0x{}", hex::encode(keys.address.as_bytes()));
                println!(
                    "  BLS Public Key: {}",
                    hex::encode(keys.bls_public_key.to_bytes())
                );
            } else {
                println!("Key not found: {}", name);
            }
            Ok(())
        }
    }
}

/// Handle query subcommands
async fn handle_query(command: QueryCommands) -> Result<()> {
    // TODO: Implement RPC client for these queries
    match command {
        QueryCommands::Block { block, rpc } => {
            println!("Querying block {} from {}", block, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Tx { hash, rpc } => {
            println!("Querying transaction {} from {}", hash, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Balance { address, rpc } => {
            println!("Querying balance for {} from {}", address, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Nonce { address, rpc } => {
            println!("Querying nonce for {} from {}", address, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Validators { rpc } => {
            println!("Querying validators from {}", rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Staking { address, rpc } => {
            println!("Querying staking info for {} from {}", address, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        QueryCommands::Status { rpc } => {
            println!("Querying chain status from {}", rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
    }
}

/// Handle transaction subcommands
async fn handle_tx(command: TxCommands) -> Result<()> {
    // TODO: Implement RPC client for transaction submission
    match command {
        TxCommands::Send {
            to,
            amount,
            key,
            rpc,
            gas_price,
            gas_limit,
        } => {
            println!("Sending {} to {} using key {} via {}", amount, to, key, rpc);
            if let Some(gp) = gas_price {
                println!("  Gas price: {}", gp);
            }
            if let Some(gl) = gas_limit {
                println!("  Gas limit: {}", gl);
            }
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        TxCommands::Call {
            to,
            data,
            value,
            rpc,
        } => {
            println!(
                "Calling contract {} with data {} (value: {}) via {}",
                to, data, value, rpc
            );
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
    }
}

/// Handle staking subcommands
async fn handle_staking(command: StakingCommands) -> Result<()> {
    // TODO: Implement RPC client for staking operations
    match command {
        StakingCommands::CreateValidator {
            amount,
            commission,
            key,
            bls_pubkey,
            rpc,
        } => {
            println!(
                "Creating validator with {} stake, {}bp commission",
                amount, commission
            );
            println!("  Key: {}", key);
            println!("  BLS pubkey: {}", bls_pubkey);
            println!("  RPC: {}", rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        StakingCommands::Delegate {
            validator,
            amount,
            key,
            rpc,
        } => {
            println!(
                "Delegating {} to {} using key {} via {}",
                amount, validator, key, rpc
            );
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        StakingCommands::Undelegate {
            validator,
            amount,
            key,
            rpc,
        } => {
            println!(
                "Undelegating {} from {} using key {} via {}",
                amount, validator, key, rpc
            );
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        StakingCommands::ClaimRewards { key, rpc } => {
            println!("Claiming rewards using key {} via {}", key, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        StakingCommands::Withdraw { key, rpc } => {
            println!("Withdrawing unbonded tokens using key {} via {}", key, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
    }
}

/// Handle governance subcommands
async fn handle_governance(command: GovernanceCommands) -> Result<()> {
    // TODO: Implement RPC client for governance operations
    match command {
        GovernanceCommands::Propose {
            proposal_type,
            title,
            description,
            key,
            deposit,
            rpc,
        } => {
            println!("Creating {} proposal: {}", proposal_type, title);
            println!("  Description: {}", description);
            println!("  Key: {}", key);
            println!("  Deposit: {}", deposit);
            println!("  RPC: {}", rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        GovernanceCommands::Vote {
            proposal_id,
            vote,
            key,
            rpc,
        } => {
            println!(
                "Voting {} on proposal {} using key {} via {}",
                vote, proposal_id, key, rpc
            );
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        GovernanceCommands::GetProposal { proposal_id, rpc } => {
            println!("Getting proposal {} from {}", proposal_id, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
        GovernanceCommands::List { status, rpc } => {
            println!("Listing proposals (status: {:?}) from {}", status, rpc);
            println!("  (RPC client not yet implemented)");
            Ok(())
        }
    }
}

/// Handle export command
async fn handle_export(output: String, height: Option<u64>, rpc: String) -> Result<()> {
    info!(output = %output, height = ?height, "Exporting state snapshot");
    println!("Exporting state snapshot to: {}", output);
    println!("  Height: {:?}", height);
    println!("  RPC: {}", rpc);
    println!("  (Snapshot export not yet implemented)");
    Ok(())
}

/// Handle import command
async fn handle_import(input: String, data_dir: String) -> Result<()> {
    info!(input = %input, data_dir = %data_dir, "Importing state snapshot");
    println!("Importing state snapshot from: {}", input);
    println!("  Data dir: {}", data_dir);
    println!("  (Snapshot import not yet implemented)");
    Ok(())
}

/// Handle version command
fn handle_version() -> Result<()> {
    println!("Proto Core {}", env!("CARGO_PKG_VERSION"));
    println!("  Rust: {}", env!("CARGO_PKG_RUST_VERSION"));
    println!("  Git: {}", option_env!("GIT_HASH").unwrap_or("unknown"));
    println!(
        "  Build: {}",
        option_env!("BUILD_DATE").unwrap_or("unknown")
    );
    Ok(())
}
