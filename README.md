# Proto Core

[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)

Proto Core is the reference implementation of a blockchain node for **Prototype Network**. It provides a complete execution environment with full EVM compatibility and deterministic finality through ProtoBFT consensus.

**~44,000 lines of Rust** across 14 crates, prioritizing correctness, performance, and auditability.

## Features

### Consensus: ProtoBFT
- **2-block finality** (~4 seconds) - no probabilistic waiting
- **BLS signature aggregation** - efficient multi-validator signing
- **Byzantine fault tolerant** - tolerates f faulty validators where n = 3f + 1
- **Shuffled round-robin proposer selection** - fair and unpredictable

### Execution: Full EVM Compatibility
- **revm-based executor** - production-tested EVM implementation
- **Parallel transaction execution** - concurrent processing with conflict detection
- **Account Abstraction (ERC-4337)** - smart contract wallets supported
- **Precompiles** for staking, slashing, and governance

### Economics
- **Inverse rewards** - smaller validators earn proportionally more, promoting decentralization
- **State rent** - storage cost management for sustainable state growth
- **On-chain governance** - parameter changes and upgrades via proposals

### Privacy (Opt-in)
- **Stealth addresses (EIP-5564)** - unlinkable recipient addresses
- **View keys** - selective disclosure for compliance
- **Exchange-compatible** - transparent by default, privacy opt-in

### Security
- **VRF randomness beacon** - verifiable random functions for fair selection
- **Binary integrity** - 6-layer tamper prevention
- **Slashing** - penalties for double-signing and downtime

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Prototype Network                           │
│                                                                     │
│  ┌───────────────────────────────────────────────────────────────┐  │
│  │                         Proto Core                             │  │
│  │                                                                │  │
│  │  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────────────┐   │  │
│  │  │   CLI   │  │   RPC   │  │ Mempool │  │   Light Client  │   │  │
│  │  └────┬────┘  └────┬────┘  └────┬────┘  └────────┬────────┘   │  │
│  │       │            │            │                │            │  │
│  │  ┌────▼────────────▼────────────▼────────────────▼────────┐   │  │
│  │  │                      Proto Core                         │   │  │
│  │  │              (Node Orchestration Layer)                 │   │  │
│  │  └─────────────────────────┬──────────────────────────────┘   │  │
│  │                            │                                  │  │
│  │       ┌────────────────────┼────────────────────┐             │  │
│  │       │                    │                    │             │  │
│  │  ┌────▼────┐         ┌─────▼─────┐        ┌─────▼─────┐       │  │
│  │  │   EVM   │         │ ProtoBFT  │        │    P2P    │       │  │
│  │  │Executor │         │ Consensus │        │  Network  │       │  │
│  │  └────┬────┘         └─────┬─────┘        └─────┬─────┘       │  │
│  │       │                    │                    │             │  │
│  │  ┌────▼────────────────────▼────────────────────▼────────┐    │  │
│  │  │                      Storage                           │    │  │
│  │  │            (RocksDB + Merkle Patricia Trie)            │    │  │
│  │  └───────────────────────────────────────────────────────┘    │  │
│  │                                                                │  │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐   │  │
│  │  │  Types   │  │  Crypto  │  │  Config  │  │   Privacy    │   │  │
│  │  └──────────┘  └──────────┘  └──────────┘  └──────────────┘   │  │
│  │                                                                │  │
│  └───────────────────────────────────────────────────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Crate Structure

| Crate | Description |
|-------|-------------|
| `protocore` | Node orchestration and entry point |
| `consensus` | ProtoBFT consensus engine with BLS aggregation |
| `evm` | EVM executor (revm) with parallel execution |
| `p2p` | libp2p networking (Gossipsub, Kademlia, Noise) |
| `storage` | RocksDB with Merkle Patricia Trie |
| `mempool` | Transaction pool with validation and ordering |
| `rpc` | JSON-RPC server (HTTP + WebSocket) |
| `light-client` | Header verification via finality proofs |
| `state-sync` | Chunk-based snapshot synchronization |
| `privacy` | Stealth addresses and view keys |
| `config` | Configuration and genesis handling |
| `types` | Core data structures |
| `crypto` | ECDSA, BLS12-381, Keccak |
| `cli` | Command-line interface |

## Quick Start

### Requirements

- Rust 1.75+
- Clang, CMake, OpenSSL dev headers
- ~2GB RAM for compilation

### Build

```bash
git clone https://github.com/prototype-ecosystem/protocore.git
cd protocore

# Build release binary
cargo build --release

# Run tests
cargo test --workspace

# Binary location
./target/release/protocore --version
```

### Initialize a Network

```bash
# Generate genesis with 4 validators
./target/release/protocore init \
    --chain-id 31337 \
    --validators 4 \
    --output ./testnet
```

### Run a Full Node

```bash
./target/release/protocore start \
    --config ./testnet/protocore.toml \
    --data-dir ./data
```

### Run a Validator

```bash
./target/release/protocore start \
    --config ./testnet/protocore.toml \
    --data-dir ./data \
    --validator \
    --validator-key ./testnet/validator-0.key
```

## Configuration

Proto Core uses TOML configuration:

```toml
[chain]
chain_id = 31337
chain_name = "ProtoCore Testnet"

[consensus]
block_time_ms = 3000
propose_timeout_base = 3000
prevote_timeout_base = 1000
precommit_timeout_base = 1000

[network]
listen_address = "/ip4/0.0.0.0/tcp/30300"
max_peers = 50
boot_nodes = []

[rpc]
http_address = "0.0.0.0:8545"
ws_address = "0.0.0.0:8546"

[storage]
data_dir = "./data"
cache_size_mb = 256
```

## JSON-RPC API

Proto Core exposes an Ethereum-compatible JSON-RPC API:

| Method | Description |
|--------|-------------|
| `eth_blockNumber` | Current block height |
| `eth_getBlockByNumber` | Block by number |
| `eth_getBlockByHash` | Block by hash |
| `eth_getTransactionByHash` | Transaction by hash |
| `eth_getTransactionReceipt` | Transaction receipt |
| `eth_sendRawTransaction` | Submit signed transaction |
| `eth_call` | Execute call without state change |
| `eth_estimateGas` | Estimate gas for transaction |
| `eth_getBalance` | Account balance |
| `eth_getCode` | Contract bytecode |
| `eth_getLogs` | Event logs by filter |

Chain-specific methods available under `protocore_*` namespace.

## CLI Reference

```bash
# Key management
protocore keys generate --key-type validator
protocore keys list --keystore ./keystore

# Chain queries
protocore query block latest
protocore query balance 0x...
protocore query validators

# Transactions
protocore tx send --to 0x... --amount 1eth --key ./key.json

# Staking
protocore staking delegate --validator 0x... --amount 1000eth
protocore staking claim-rewards

# Governance
protocore governance propose --type parameter-change --title "..."
protocore governance vote --proposal-id 1 --vote for
```

## Testnet

Public testnet coming soon. For now, run a local network:

```bash
# Terminal 1: Validator 0
protocore start --config node0.toml --validator --validator-key validator_0.key

# Terminal 2: Validator 1
protocore start --config node1.toml --validator --validator-key validator_1.key
```

## Documentation

- [Specification](./specification.md) - Full protocol specification
- [Architecture](./additions.md) - Feature implementations
- [Branding](./branding.md) - Naming conventions

## Contributing

Contributions are welcome. Please ensure:

1. Code compiles without warnings (`cargo clippy`)
2. All tests pass (`cargo test --workspace`)
3. New code includes tests
4. Documentation is updated

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.
