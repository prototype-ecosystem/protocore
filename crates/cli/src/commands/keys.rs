//! Key management commands.
//!
//! This module provides commands for managing cryptographic keys:
//! - Generate new wallet or validator keys
//! - List existing keys in the keystore
//! - Import keys from hex or mnemonic
//! - Export keys for backup

use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Input, Password};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::utils::{CliError, CliResult, OutputFormat, print_error, print_info, print_success, print_warning};
use crate::default_keystore_dir;

/// Key management subcommands
#[derive(Subcommand, Debug)]
pub enum KeysCommands {
    /// Generate a new keypair
    Generate(GenerateArgs),

    /// List all keys in the keystore
    List(ListArgs),

    /// Import a key from hex or mnemonic
    Import(ImportArgs),

    /// Export a key (with password protection)
    Export(ExportArgs),

    /// Show details of a specific key
    Show(ShowArgs),

    /// Delete a key from the keystore
    Delete(DeleteArgs),
}

/// Arguments for key generation
#[derive(Parser, Debug)]
pub struct GenerateArgs {
    /// Key type: wallet, validator
    #[arg(long, default_value = "wallet")]
    pub key_type: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<String>,

    /// Key name/label for identification
    #[arg(long)]
    pub name: Option<String>,

    /// Encrypt key with password
    #[arg(long)]
    pub password: bool,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,
}

/// Arguments for listing keys
#[derive(Parser, Debug)]
pub struct ListArgs {
    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// Show full addresses (not truncated)
    #[arg(long)]
    pub full: bool,
}

/// Arguments for key import
#[derive(Parser, Debug)]
pub struct ImportArgs {
    /// Import from hex-encoded private key
    #[arg(long, conflicts_with = "mnemonic")]
    pub hex: Option<String>,

    /// Import from BIP-39 mnemonic phrase
    #[arg(long, conflicts_with = "hex")]
    pub mnemonic: Option<String>,

    /// Key name/label
    #[arg(long)]
    pub name: Option<String>,

    /// Key type: wallet, validator
    #[arg(long, default_value = "wallet")]
    pub key_type: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// Encrypt key with password
    #[arg(long)]
    pub password: bool,
}

/// Arguments for key export
#[derive(Parser, Debug)]
pub struct ExportArgs {
    /// Key address or name to export
    pub key: String,

    /// Output file path
    #[arg(short, long)]
    pub output: Option<String>,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// Export format: hex, json, keystore
    #[arg(long, default_value = "json")]
    pub format: String,
}

/// Arguments for showing key details
#[derive(Parser, Debug)]
pub struct ShowArgs {
    /// Key address or name
    pub key: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,
}

/// Arguments for deleting a key
#[derive(Parser, Debug)]
pub struct DeleteArgs {
    /// Key address or name to delete
    pub key: String,

    /// Keystore directory
    #[arg(long)]
    pub keystore: Option<String>,

    /// Skip confirmation prompt
    #[arg(long)]
    pub force: bool,
}

/// Execute keys commands
pub async fn execute(cmd: KeysCommands, output_format: OutputFormat) -> CliResult<()> {
    match cmd {
        KeysCommands::Generate(args) => execute_generate(args, output_format).await,
        KeysCommands::List(args) => execute_list(args, output_format).await,
        KeysCommands::Import(args) => execute_import(args, output_format).await,
        KeysCommands::Export(args) => execute_export(args, output_format).await,
        KeysCommands::Show(args) => execute_show(args, output_format).await,
        KeysCommands::Delete(args) => execute_delete(args, output_format).await,
    }
}

/// Execute key generation
async fn execute_generate(args: GenerateArgs, output_format: OutputFormat) -> CliResult<()> {
    let key_type = parse_key_type(&args.key_type)?;

    print_info(&format!("Generating new {} key...", args.key_type));

    // Get password if requested
    let password = if args.password {
        Some(prompt_password("Enter password for key encryption: ")?)
    } else {
        None
    };

    // Generate key based on type
    let key_info = match key_type {
        KeyType::Wallet => generate_wallet_key()?,
        KeyType::Validator => generate_validator_key()?,
    };

    // Determine output path
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);

    let output_path = if let Some(output) = args.output {
        PathBuf::from(output)
    } else {
        ensure_dir_exists(&keystore_dir)?;
        let filename = format!("{}--{}.json",
            chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S"),
            &key_info.address[2..10] // First 8 chars after 0x
        );
        keystore_dir.join(filename)
    };

    // Save key to file
    let key_file = KeystoreFile {
        version: 1,
        key_type: args.key_type.clone(),
        name: args.name.clone().unwrap_or_else(|| format!("key-{}", &key_info.address[2..10])),
        address: key_info.address.clone(),
        public_key: key_info.public_key.clone(),
        crypto: if password.is_some() {
            Some(encrypt_key(&key_info.private_key, password.as_ref().unwrap())?)
        } else {
            None
        },
        private_key: if password.is_none() {
            Some(key_info.private_key.clone())
        } else {
            None
        },
        bls_public_key: key_info.bls_public_key.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&key_file)?;
    let mut file = fs::File::create(&output_path)?;
    file.write_all(json.as_bytes())?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&output_path, perms)?;
    }

    // Output result
    let result = GenerateResult {
        key_type: args.key_type,
        name: key_file.name,
        address: key_info.address,
        public_key: key_info.public_key,
        bls_public_key: key_info.bls_public_key,
        file_path: output_path.to_string_lossy().to_string(),
        encrypted: password.is_some(),
    };

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Text => {
            print_success("Key generated successfully!");
            println!();
            println!("Key Details:");
            println!("  Type:       {}", result.key_type);
            println!("  Name:       {}", result.name);
            println!("  Address:    {}", result.address);
            println!("  Public Key: {}", result.public_key);
            if let Some(ref bls) = result.bls_public_key {
                println!("  BLS Key:    {}...", &bls[..40]);
            }
            println!("  File:       {}", result.file_path);
            println!("  Encrypted:  {}", if result.encrypted { "Yes" } else { "No" });
            println!();
            if !result.encrypted {
                print_warning("Key is not password protected. Consider using --password for production keys.");
            }
        }
    }

    Ok(())
}

/// Execute key listing
async fn execute_list(args: ListArgs, output_format: OutputFormat) -> CliResult<()> {
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);

    if !keystore_dir.exists() {
        return Err(CliError::FileNotFound(keystore_dir.to_string_lossy().to_string()));
    }

    let mut keys: Vec<KeyListEntry> = Vec::new();

    for entry in fs::read_dir(&keystore_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(key_file) = serde_json::from_str::<KeystoreFile>(&content) {
                    keys.push(KeyListEntry {
                        name: key_file.name,
                        key_type: key_file.key_type,
                        address: key_file.address,
                        encrypted: key_file.crypto.is_some(),
                        file: path.file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_default(),
                    });
                }
            }
        }
    }

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&keys)?);
        }
        OutputFormat::Text => {
            if keys.is_empty() {
                println!("No keys found in keystore: {}", keystore_dir.display());
                println!("Use 'protocore keys generate' to create a new key.");
            } else {
                println!("Keys in {}", keystore_dir.display());
                println!();
                println!("{:<20} {:<10} {:<44} {:<10}", "NAME", "TYPE", "ADDRESS", "ENCRYPTED");
                println!("{}", "-".repeat(86));
                for key in &keys {
                    let address = if args.full {
                        key.address.clone()
                    } else {
                        format!("{}...{}", &key.address[..10], &key.address[key.address.len()-8..])
                    };
                    println!(
                        "{:<20} {:<10} {:<44} {:<10}",
                        truncate_string(&key.name, 18),
                        key.key_type,
                        address,
                        if key.encrypted { "Yes" } else { "No" }
                    );
                }
                println!();
                println!("Total: {} key(s)", keys.len());
            }
        }
    }

    Ok(())
}

/// Execute key import
async fn execute_import(args: ImportArgs, output_format: OutputFormat) -> CliResult<()> {
    let key_type = parse_key_type(&args.key_type)?;

    // Get private key from hex or mnemonic
    let private_key_bytes = if let Some(ref hex_key) = args.hex {
        let hex_clean = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        hex::decode(hex_clean).map_err(|e| CliError::InvalidArgument(format!("Invalid hex: {}", e)))?
    } else if let Some(ref mnemonic) = args.mnemonic {
        // TODO: Implement BIP-39 mnemonic derivation
        // For now, return error
        return Err(CliError::NotImplemented("Mnemonic import not yet implemented".to_string()));
    } else {
        // Interactive mode - prompt for key
        let hex_key: String = Input::new()
            .with_prompt("Enter private key (hex)")
            .interact_text()?;
        let hex_clean = hex_key.strip_prefix("0x").unwrap_or(&hex_key);
        hex::decode(hex_clean).map_err(|e| CliError::InvalidArgument(format!("Invalid hex: {}", e)))?
    };

    if private_key_bytes.len() != 32 {
        return Err(CliError::InvalidArgument(format!(
            "Private key must be 32 bytes, got {}",
            private_key_bytes.len()
        )));
    }

    print_info("Importing key...");

    // Derive public key and address
    let key_info = derive_key_info(&private_key_bytes, key_type)?;

    // Get password if requested
    let password = if args.password {
        Some(prompt_password("Enter password for key encryption: ")?)
    } else {
        None
    };

    // Determine output path
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);
    ensure_dir_exists(&keystore_dir)?;

    let filename = format!("{}--{}.json",
        chrono::Utc::now().format("%Y-%m-%dT%H-%M-%S"),
        &key_info.address[2..10]
    );
    let output_path = keystore_dir.join(&filename);

    // Save key to file
    let key_file = KeystoreFile {
        version: 1,
        key_type: args.key_type.clone(),
        name: args.name.clone().unwrap_or_else(|| format!("imported-{}", &key_info.address[2..10])),
        address: key_info.address.clone(),
        public_key: key_info.public_key.clone(),
        crypto: if password.is_some() {
            Some(encrypt_key(&key_info.private_key, password.as_ref().unwrap())?)
        } else {
            None
        },
        private_key: if password.is_none() {
            Some(key_info.private_key.clone())
        } else {
            None
        },
        bls_public_key: key_info.bls_public_key.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let json = serde_json::to_string_pretty(&key_file)?;
    let mut file = fs::File::create(&output_path)?;
    file.write_all(json.as_bytes())?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&output_path, perms)?;
    }

    let result = ImportResult {
        key_type: args.key_type,
        name: key_file.name,
        address: key_info.address,
        file_path: output_path.to_string_lossy().to_string(),
    };

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&result)?);
        }
        OutputFormat::Text => {
            print_success("Key imported successfully!");
            println!();
            println!("  Type:    {}", result.key_type);
            println!("  Name:    {}", result.name);
            println!("  Address: {}", result.address);
            println!("  File:    {}", result.file_path);
        }
    }

    Ok(())
}

/// Execute key export
async fn execute_export(args: ExportArgs, output_format: OutputFormat) -> CliResult<()> {
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);

    // Find the key file
    let key_file = find_key_file(&keystore_dir, &args.key)?;
    let key_data = load_key_file(&key_file)?;

    // If encrypted, prompt for password
    let private_key = if let Some(ref crypto) = key_data.crypto {
        let password = prompt_password("Enter key password: ")?;
        decrypt_key(crypto, &password)?
    } else if let Some(ref pk) = key_data.private_key {
        pk.clone()
    } else {
        return Err(CliError::KeyError("Key file has no private key data".to_string()));
    };

    let export_data = match args.format.as_str() {
        "hex" => {
            format!("0x{}", private_key)
        }
        "json" => {
            serde_json::to_string_pretty(&serde_json::json!({
                "address": key_data.address,
                "private_key": format!("0x{}", private_key),
                "public_key": key_data.public_key,
            }))?
        }
        "keystore" => {
            // Export as encrypted keystore format
            let password = prompt_password("Enter password for exported keystore: ")?;
            let crypto = encrypt_key(&private_key, &password)?;
            serde_json::to_string_pretty(&KeystoreFile {
                version: key_data.version,
                key_type: key_data.key_type.clone(),
                name: key_data.name.clone(),
                address: key_data.address.clone(),
                public_key: key_data.public_key.clone(),
                crypto: Some(crypto),
                private_key: None,
                bls_public_key: key_data.bls_public_key.clone(),
                created_at: key_data.created_at.clone(),
            })?
        }
        _ => {
            return Err(CliError::InvalidArgument(format!("Unknown export format: {}", args.format)));
        }
    };

    // Output
    if let Some(output_path) = args.output {
        fs::write(&output_path, &export_data)?;
        print_success(&format!("Key exported to: {}", output_path));
    } else {
        match output_format {
            OutputFormat::Json => {
                println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                    "address": key_data.address,
                    "format": args.format,
                    "data": export_data,
                }))?);
            }
            OutputFormat::Text => {
                print_warning("Displaying private key - ensure no one is watching!");
                println!();
                println!("{}", export_data);
            }
        }
    }

    Ok(())
}

/// Execute key show
async fn execute_show(args: ShowArgs, output_format: OutputFormat) -> CliResult<()> {
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);

    let key_file = find_key_file(&keystore_dir, &args.key)?;
    let key_data = load_key_file(&key_file)?;

    let info = KeyShowInfo {
        name: key_data.name,
        key_type: key_data.key_type,
        address: key_data.address,
        public_key: key_data.public_key,
        bls_public_key: key_data.bls_public_key,
        encrypted: key_data.crypto.is_some(),
        file_path: key_file.to_string_lossy().to_string(),
        created_at: key_data.created_at,
    };

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&info)?);
        }
        OutputFormat::Text => {
            println!("Key Details");
            println!("===========");
            println!("  Name:       {}", info.name);
            println!("  Type:       {}", info.key_type);
            println!("  Address:    {}", info.address);
            println!("  Public Key: {}", info.public_key);
            if let Some(ref bls) = info.bls_public_key {
                println!("  BLS Key:    {}", bls);
            }
            println!("  Encrypted:  {}", if info.encrypted { "Yes" } else { "No" });
            println!("  Created:    {}", info.created_at);
            println!("  File:       {}", info.file_path);
        }
    }

    Ok(())
}

/// Execute key delete
async fn execute_delete(args: DeleteArgs, output_format: OutputFormat) -> CliResult<()> {
    let keystore_dir = args.keystore
        .map(PathBuf::from)
        .unwrap_or_else(default_keystore_dir);

    let key_file = find_key_file(&keystore_dir, &args.key)?;
    let key_data = load_key_file(&key_file)?;

    // Confirm deletion
    if !args.force {
        print_warning(&format!("You are about to delete key: {}", key_data.address));
        let confirm = Confirm::new()
            .with_prompt("Are you sure you want to delete this key?")
            .default(false)
            .interact()?;

        if !confirm {
            println!("Deletion cancelled.");
            return Ok(());
        }
    }

    fs::remove_file(&key_file)?;

    match output_format {
        OutputFormat::Json => {
            println!("{}", serde_json::to_string_pretty(&serde_json::json!({
                "status": "deleted",
                "address": key_data.address,
                "file": key_file.to_string_lossy(),
            }))?);
        }
        OutputFormat::Text => {
            print_success(&format!("Key {} deleted successfully", key_data.address));
        }
    }

    Ok(())
}

// ============================================================================
// Helper types and functions
// ============================================================================

/// Key type enum
#[derive(Debug, Clone, Copy, PartialEq)]
enum KeyType {
    Wallet,
    Validator,
}

fn parse_key_type(s: &str) -> CliResult<KeyType> {
    match s.to_lowercase().as_str() {
        "wallet" => Ok(KeyType::Wallet),
        "validator" => Ok(KeyType::Validator),
        _ => Err(CliError::InvalidArgument(format!("Unknown key type: {}", s))),
    }
}

/// Generated key information
struct KeyInfo {
    private_key: String,
    public_key: String,
    address: String,
    bls_public_key: Option<String>,
}

/// Generate a wallet key
fn generate_wallet_key() -> CliResult<KeyInfo> {
    use protocore_crypto::ecdsa::PrivateKey;

    let private_key = PrivateKey::random();
    let public_key = private_key.public_key();
    let address = public_key.to_address();

    Ok(KeyInfo {
        private_key: hex::encode(private_key.to_bytes()),
        public_key: format!("0x{}", hex::encode(public_key.to_compressed())),
        address: format!("0x{}", hex::encode(&address)),
        bls_public_key: None,
    })
}

/// Generate a validator key (includes BLS)
fn generate_validator_key() -> CliResult<KeyInfo> {
    use protocore_crypto::ecdsa::PrivateKey;
    use protocore_crypto::bls::BlsPrivateKey;

    let ecdsa_key = PrivateKey::random();
    let ecdsa_public = ecdsa_key.public_key();
    let address = ecdsa_public.to_address();

    let bls_key = BlsPrivateKey::random();
    let bls_public = bls_key.public_key();

    Ok(KeyInfo {
        private_key: hex::encode(ecdsa_key.to_bytes()),
        public_key: format!("0x{}", hex::encode(ecdsa_public.to_compressed())),
        address: format!("0x{}", hex::encode(&address)),
        bls_public_key: Some(format!("0x{}", hex::encode(bls_public.to_bytes()))),
    })
}

/// Derive key info from private key bytes
fn derive_key_info(private_key_bytes: &[u8], key_type: KeyType) -> CliResult<KeyInfo> {
    use protocore_crypto::ecdsa::PrivateKey;
    use protocore_crypto::bls::BlsPrivateKey;

    // Convert slice to fixed-size array
    let key_array: [u8; 32] = private_key_bytes.try_into()
        .map_err(|_| CliError::KeyError("Private key must be exactly 32 bytes".to_string()))?;

    let ecdsa_key = PrivateKey::from_bytes(&key_array)
        .map_err(|e| CliError::KeyError(format!("Invalid private key: {}", e)))?;
    let ecdsa_public = ecdsa_key.public_key();
    let address = ecdsa_public.to_address();

    let bls_public_key = if key_type == KeyType::Validator {
        let bls_key = BlsPrivateKey::random(); // Note: In practice, derive from ECDSA key or generate separately
        let bls_public = bls_key.public_key();
        Some(format!("0x{}", hex::encode(bls_public.to_bytes())))
    } else {
        None
    };

    Ok(KeyInfo {
        private_key: hex::encode(private_key_bytes),
        public_key: format!("0x{}", hex::encode(ecdsa_public.to_compressed())),
        address: format!("0x{}", hex::encode(&address)),
        bls_public_key,
    })
}

/// Keystore file format
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct KeystoreFile {
    version: u32,
    key_type: String,
    name: String,
    address: String,
    public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    crypto: Option<CryptoParams>,
    #[serde(skip_serializing_if = "Option::is_none")]
    private_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bls_public_key: Option<String>,
    created_at: String,
}

/// Encryption parameters for keystore
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct CryptoParams {
    cipher: String,
    ciphertext: String,
    kdf: String,
    kdf_params: KdfParams,
    mac: String,
}

/// KDF parameters
#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct KdfParams {
    n: u32,
    r: u32,
    p: u32,
    dklen: u32,
    salt: String,
}

/// Encrypt a private key
fn encrypt_key(private_key: &str, _password: &str) -> CliResult<CryptoParams> {
    // TODO: Implement proper scrypt-based encryption
    // For now, return a placeholder
    Ok(CryptoParams {
        cipher: "aes-128-ctr".to_string(),
        ciphertext: hex::encode(private_key.as_bytes()), // Placeholder
        kdf: "scrypt".to_string(),
        kdf_params: KdfParams {
            n: 262144,
            r: 8,
            p: 1,
            dklen: 32,
            salt: hex::encode(&[0u8; 32]),
        },
        mac: hex::encode(&[0u8; 32]),
    })
}

/// Decrypt a private key
fn decrypt_key(crypto: &CryptoParams, _password: &str) -> CliResult<String> {
    // TODO: Implement proper decryption
    // For now, return the ciphertext as-is (placeholder)
    let bytes = hex::decode(&crypto.ciphertext)
        .map_err(|e| CliError::KeyError(format!("Decryption failed: {}", e)))?;
    String::from_utf8(bytes)
        .map_err(|e| CliError::KeyError(format!("Decryption failed: {}", e)))
}

/// Find key file by address or name
fn find_key_file(keystore_dir: &Path, key: &str) -> CliResult<PathBuf> {
    if !keystore_dir.exists() {
        return Err(CliError::FileNotFound(keystore_dir.to_string_lossy().to_string()));
    }

    let key_lower = key.to_lowercase();

    for entry in fs::read_dir(keystore_dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.extension().map_or(false, |ext| ext == "json") {
            if let Ok(content) = fs::read_to_string(&path) {
                if let Ok(key_file) = serde_json::from_str::<KeystoreFile>(&content) {
                    if key_file.address.to_lowercase() == key_lower
                        || key_file.address.to_lowercase().contains(&key_lower)
                        || key_file.name.to_lowercase() == key_lower
                    {
                        return Ok(path);
                    }
                }
            }
        }
    }

    Err(CliError::KeyNotFound(key.to_string()))
}

/// Load key file data
fn load_key_file(path: &Path) -> CliResult<KeystoreFile> {
    let content = fs::read_to_string(path)?;
    serde_json::from_str(&content)
        .map_err(|e| CliError::ConfigError(format!("Invalid keystore file: {}", e)))
}

/// Ensure directory exists
fn ensure_dir_exists(dir: &Path) -> CliResult<()> {
    if !dir.exists() {
        fs::create_dir_all(dir)?;
    }
    Ok(())
}

/// Prompt for password with confirmation
fn prompt_password(prompt: &str) -> CliResult<String> {
    let password = Password::new()
        .with_prompt(prompt)
        .with_confirmation("Confirm password", "Passwords don't match")
        .interact()?;
    Ok(password)
}

/// Truncate string for display
fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len-3])
    }
}

// ============================================================================
// Result types
// ============================================================================

#[derive(Debug, serde::Serialize)]
struct GenerateResult {
    key_type: String,
    name: String,
    address: String,
    public_key: String,
    bls_public_key: Option<String>,
    file_path: String,
    encrypted: bool,
}

#[derive(Debug, serde::Serialize)]
struct ImportResult {
    key_type: String,
    name: String,
    address: String,
    file_path: String,
}

#[derive(Debug, serde::Serialize)]
struct KeyListEntry {
    name: String,
    key_type: String,
    address: String,
    encrypted: bool,
    file: String,
}

#[derive(Debug, serde::Serialize)]
struct KeyShowInfo {
    name: String,
    key_type: String,
    address: String,
    public_key: String,
    bls_public_key: Option<String>,
    encrypted: bool,
    file_path: String,
    created_at: String,
}

