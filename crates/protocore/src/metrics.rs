//! # Prometheus Metrics
//!
//! This module provides Prometheus metrics for monitoring the Proto Core node.
//!
//! Metrics are collected for:
//! - Consensus (height, round, blocks committed, signers)
//! - P2P networking (peers connected, messages received)
//! - RPC (requests handled)
//! - EVM (transactions executed, gas used)
//!
//! The metrics are served via a minimal HTTP server on the configured address.

use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounter, IntGauge, TextEncoder};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::{error, info};

// =============================================================================
// Metric Definitions
// =============================================================================

/// Current block height
pub static CONSENSUS_HEIGHT: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("consensus_height", "Current block height").unwrap()
});

/// Current consensus round
pub static CONSENSUS_ROUND: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("consensus_round", "Current consensus round").unwrap()
});

/// Total blocks committed
pub static BLOCKS_COMMITTED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("blocks_committed_total", "Total blocks committed").unwrap()
});

/// Number of signers in last finality certificate
pub static CONSENSUS_SIGNERS: Lazy<IntGauge> = Lazy::new(|| {
    IntGauge::new("consensus_signers", "Number of signers in last finality cert").unwrap()
});

// NOTE: P2P metrics (p2p_peers_connected, p2p_messages_received_total) are
// defined in `protocore_p2p::network` and registered with the global Prometheus
// registry on first access. They are gathered automatically by `prometheus::gather()`.

/// Total RPC requests handled
pub static RPC_REQUESTS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("rpc_requests_total", "RPC requests handled").unwrap()
});

/// Total EVM transactions executed
pub static EVM_TRANSACTIONS_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("evm_transactions_total", "Transactions executed").unwrap()
});

/// Total gas used
pub static EVM_GAS_USED_TOTAL: Lazy<IntCounter> = Lazy::new(|| {
    IntCounter::new("evm_gas_used_total", "Total gas used").unwrap()
});

// =============================================================================
// Registration
// =============================================================================

/// Register all metrics with the default Prometheus registry.
///
/// This must be called once at startup before any metrics are recorded.
/// Panics if registration fails (indicates a bug in metric definitions).
pub fn register_all() {
    let registry = prometheus::default_registry();

    let metrics: Vec<Box<dyn prometheus::core::Collector>> = vec![
        Box::new(CONSENSUS_HEIGHT.clone()),
        Box::new(CONSENSUS_ROUND.clone()),
        Box::new(BLOCKS_COMMITTED_TOTAL.clone()),
        Box::new(CONSENSUS_SIGNERS.clone()),
        Box::new(RPC_REQUESTS_TOTAL.clone()),
        Box::new(EVM_TRANSACTIONS_TOTAL.clone()),
        Box::new(EVM_GAS_USED_TOTAL.clone()),
    ];

    for metric in metrics {
        if let Err(e) = registry.register(metric) {
            // AlreadyReg is fine (e.g., tests calling register_all multiple times)
            if !matches!(e, prometheus::Error::AlreadyReg) {
                panic!("Failed to register metric: {}", e);
            }
        }
    }
}

// =============================================================================
// Metrics HTTP Server
// =============================================================================

/// A minimal HTTP server that exposes Prometheus metrics on `/metrics`.
pub struct MetricsServer {
    addr: SocketAddr,
}

impl MetricsServer {
    /// Create a new metrics server bound to `addr`.
    pub fn new(addr: SocketAddr) -> Self {
        Self { addr }
    }

    /// Spawn the server as a background tokio task.
    ///
    /// The task runs until the runtime is shut down.
    pub fn spawn(self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            if let Err(e) = self.run().await {
                error!(error = %e, "Metrics server exited with error");
            }
        })
    }

    /// Run the metrics server (blocking within the async context).
    async fn run(self) -> std::io::Result<()> {
        let listener = TcpListener::bind(self.addr).await?;
        info!(addr = %self.addr, "Metrics server listening");

        loop {
            let (mut stream, peer) = listener.accept().await?;
            tracing::debug!(peer = %peer, "Metrics request");

            // Read the request (we don't need to parse it — any GET gets metrics)
            let mut buf = [0u8; 1024];
            let _ = tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await;

            // Encode metrics
            let encoder = TextEncoder::new();
            let metric_families = prometheus::gather();
            let mut body = Vec::new();
            encoder.encode(&metric_families, &mut body).unwrap();

            // Write raw HTTP response
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.flush().await;
        }
    }
}
