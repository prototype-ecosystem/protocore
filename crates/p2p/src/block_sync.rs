//! Block Sync Protocol for Protocore.
//!
//! Implements a request-response protocol that allows new nodes to catch up
//! to the chain tip by requesting historical blocks from peers.
//!
//! Protocol: `/protocore/sync/1.0.0`
//!
//! ## Design
//!
//! - Request: `BlockSyncRequest` — ask for a batch of blocks by height range (max 100)
//! - Response: `BlockSyncResponse` — serialized blocks or `NoBlocks`
//! - Codec: JSON serialization (consistent with gossipsub messages)
//! - Limits: 1 KB max request, 10 MB max response

use futures::prelude::*;
use libp2p::{request_response, StreamProtocol};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// Maximum blocks per sync request (prevents DOS)
pub const MAX_BLOCKS_PER_REQUEST: u64 = 100;

/// Maximum request size in bytes (1 KB)
const MAX_REQUEST_SIZE: u64 = 1024;

/// Maximum response size in bytes (10 MB)
const MAX_RESPONSE_SIZE: u64 = 10 * 1024 * 1024;

/// Protocol identifier for block sync
pub const PROTOCOL_NAME: &str = "/protocore/sync/1.0.0";

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

/// Block sync request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSyncRequest {
    /// Request blocks in a height range (inclusive)
    GetBlocks {
        /// Start height (inclusive)
        start_height: u64,
        /// End height (inclusive). Must be >= start_height and span at most
        /// [`MAX_BLOCKS_PER_REQUEST`] blocks.
        end_height: u64,
    },
}

/// Block sync response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockSyncResponse {
    /// Blocks returned (each entry is a serialized block + height for ordering)
    Blocks {
        /// Serialized blocks ordered by height
        blocks: Vec<SyncBlock>,
    },
    /// Peer has no blocks in the requested range
    NoBlocks,
}

/// A single block in a sync response (height + raw bytes)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncBlock {
    /// Block height
    pub height: u64,
    /// RLP-encoded block data (same encoding used in the DB)
    pub data: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Codec — JSON over async read/write (matches existing gossip serialisation)
// ---------------------------------------------------------------------------

/// Codec for serializing/deserializing block sync messages
#[derive(Debug, Clone, Default)]
pub struct BlockSyncCodec;

#[async_trait::async_trait]
impl request_response::Codec for BlockSyncCodec {
    type Protocol = StreamProtocol;
    type Request = BlockSyncRequest;
    type Response = BlockSyncResponse;

    async fn read_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        // Read length-prefixed JSON (4-byte big-endian length prefix)
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as u64;

        if len > MAX_REQUEST_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("request too large: {} bytes (max {})", len, MAX_REQUEST_SIZE),
            ));
        }

        let mut buf = vec![0u8; len as usize];
        io.read_exact(&mut buf).await?;

        serde_json::from_slice(&buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, format!("bad request: {}", e))
        })
    }

    async fn read_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
    ) -> std::io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let mut len_buf = [0u8; 4];
        io.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as u64;

        if len > MAX_RESPONSE_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "response too large: {} bytes (max {})",
                    len, MAX_RESPONSE_SIZE
                ),
            ));
        }

        let mut buf = vec![0u8; len as usize];
        io.read_exact(&mut buf).await?;

        serde_json::from_slice(&buf).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("bad response: {}", e),
            )
        })
    }

    async fn write_request<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        req: Self::Request,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&req).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("encode request: {}", e),
            )
        })?;

        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.close().await?;
        Ok(())
    }

    async fn write_response<T>(
        &mut self,
        _protocol: &Self::Protocol,
        io: &mut T,
        resp: Self::Response,
    ) -> std::io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        let data = serde_json::to_vec(&resp).map_err(|e| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("encode response: {}", e),
            )
        })?;

        let len = (data.len() as u32).to_be_bytes();
        io.write_all(&len).await?;
        io.write_all(&data).await?;
        io.close().await?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// BlockSyncManager — tracks sync state, generates requests
// ---------------------------------------------------------------------------

/// Current sync state
#[derive(Debug, Clone)]
pub struct SyncState {
    /// Our local chain height
    pub local_height: u64,
    /// Highest height seen on the network
    pub target_height: u64,
    /// Whether we are actively syncing
    pub syncing: bool,
}

/// Manages block sync lifecycle
#[derive(Debug)]
pub struct BlockSyncManager {
    state: SyncState,
}

impl BlockSyncManager {
    /// Create a new sync manager starting at `local_height`
    pub fn new(local_height: u64) -> Self {
        Self {
            state: SyncState {
                local_height,
                target_height: local_height,
                syncing: false,
            },
        }
    }

    /// Returns `true` when the local node is behind the network
    pub fn needs_sync(local_height: u64, network_height: u64) -> bool {
        network_height > local_height
    }

    /// Start syncing towards `target_height`
    pub fn start_sync(&mut self, target_height: u64) {
        debug!(
            local = self.state.local_height,
            target = target_height,
            "Starting block sync"
        );
        self.state.target_height = target_height;
        self.state.syncing = true;
    }

    /// Build the next request based on current progress
    pub fn next_request(&self) -> Option<BlockSyncRequest> {
        if !self.state.syncing {
            return None;
        }
        if self.state.local_height >= self.state.target_height {
            return None;
        }

        let start = self.state.local_height + 1;
        let end = std::cmp::min(
            start + MAX_BLOCKS_PER_REQUEST - 1,
            self.state.target_height,
        );

        Some(BlockSyncRequest::GetBlocks {
            start_height: start,
            end_height: end,
        })
    }

    /// Update local height after successfully applying blocks
    pub fn advance(&mut self, new_height: u64) {
        self.state.local_height = new_height;
        if self.state.local_height >= self.state.target_height {
            debug!(height = new_height, "Block sync complete");
            self.state.syncing = false;
        }
    }

    /// Update target height (e.g., when a peer announces a higher height)
    pub fn set_target(&mut self, target: u64) {
        if target > self.state.target_height {
            self.state.target_height = target;
            if !self.state.syncing && target > self.state.local_height {
                self.state.syncing = true;
                debug!(
                    local = self.state.local_height,
                    target,
                    "Resuming block sync — new target"
                );
            }
        }
    }

    /// Stop syncing
    pub fn stop_sync(&mut self) {
        self.state.syncing = false;
    }

    /// Whether we are currently syncing
    pub fn is_syncing(&self) -> bool {
        self.state.syncing
    }

    /// Get a snapshot of the current sync state
    pub fn state(&self) -> &SyncState {
        &self.state
    }
}

// ---------------------------------------------------------------------------
// Helper: build the request-response Behaviour
// ---------------------------------------------------------------------------

/// Create a new block sync request-response behaviour
pub fn new_behaviour() -> request_response::Behaviour<BlockSyncCodec> {
    request_response::Behaviour::new(
        [(
            StreamProtocol::new(PROTOCOL_NAME),
            request_response::ProtocolSupport::Full,
        )],
        request_response::Config::default(),
    )
}

// ---------------------------------------------------------------------------
// Validate incoming request bounds
// ---------------------------------------------------------------------------

/// Validate a block sync request (bounds check).
/// Returns `Err(reason)` if invalid.
pub fn validate_request(req: &BlockSyncRequest) -> std::result::Result<(), &'static str> {
    match req {
        BlockSyncRequest::GetBlocks {
            start_height,
            end_height,
        } => {
            if end_height < start_height {
                return Err("end_height < start_height");
            }
            if end_height - start_height + 1 > MAX_BLOCKS_PER_REQUEST {
                return Err("requested range exceeds MAX_BLOCKS_PER_REQUEST");
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_request_ok() {
        let req = BlockSyncRequest::GetBlocks {
            start_height: 1,
            end_height: 100,
        };
        assert!(validate_request(&req).is_ok());
    }

    #[test]
    fn test_validate_request_reversed() {
        let req = BlockSyncRequest::GetBlocks {
            start_height: 50,
            end_height: 10,
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_validate_request_too_large() {
        let req = BlockSyncRequest::GetBlocks {
            start_height: 1,
            end_height: 200,
        };
        assert!(validate_request(&req).is_err());
    }

    #[test]
    fn test_sync_manager_basic() {
        let mut mgr = BlockSyncManager::new(0);
        assert!(!mgr.is_syncing());

        mgr.start_sync(250);
        assert!(mgr.is_syncing());

        // First batch: 1..=100
        let req = mgr.next_request().unwrap();
        match req {
            BlockSyncRequest::GetBlocks {
                start_height,
                end_height,
            } => {
                assert_eq!(start_height, 1);
                assert_eq!(end_height, 100);
            }
        }

        mgr.advance(100);
        assert!(mgr.is_syncing());

        // Second batch: 101..=200
        let req = mgr.next_request().unwrap();
        match req {
            BlockSyncRequest::GetBlocks {
                start_height,
                end_height,
            } => {
                assert_eq!(start_height, 101);
                assert_eq!(end_height, 200);
            }
        }

        mgr.advance(200);
        assert!(mgr.is_syncing());

        // Third batch: 201..=250
        let req = mgr.next_request().unwrap();
        match req {
            BlockSyncRequest::GetBlocks {
                start_height,
                end_height,
            } => {
                assert_eq!(start_height, 201);
                assert_eq!(end_height, 250);
            }
        }

        mgr.advance(250);
        assert!(!mgr.is_syncing());
        assert!(mgr.next_request().is_none());
    }

    #[test]
    fn test_needs_sync() {
        assert!(BlockSyncManager::needs_sync(0, 10));
        assert!(!BlockSyncManager::needs_sync(10, 10));
        assert!(!BlockSyncManager::needs_sync(10, 5));
    }

    #[test]
    fn test_roundtrip_request() {
        let req = BlockSyncRequest::GetBlocks {
            start_height: 42,
            end_height: 99,
        };
        let data = serde_json::to_vec(&req).unwrap();
        let decoded: BlockSyncRequest = serde_json::from_slice(&data).unwrap();
        match decoded {
            BlockSyncRequest::GetBlocks {
                start_height,
                end_height,
            } => {
                assert_eq!(start_height, 42);
                assert_eq!(end_height, 99);
            }
        }
    }

    #[test]
    fn test_roundtrip_response() {
        let resp = BlockSyncResponse::Blocks {
            blocks: vec![
                SyncBlock {
                    height: 1,
                    data: vec![0xAA, 0xBB],
                },
                SyncBlock {
                    height: 2,
                    data: vec![0xCC],
                },
            ],
        };
        let data = serde_json::to_vec(&resp).unwrap();
        let decoded: BlockSyncResponse = serde_json::from_slice(&data).unwrap();
        match decoded {
            BlockSyncResponse::Blocks { blocks } => {
                assert_eq!(blocks.len(), 2);
                assert_eq!(blocks[0].height, 1);
                assert_eq!(blocks[1].height, 2);
            }
            _ => panic!("expected Blocks"),
        }
    }
}
