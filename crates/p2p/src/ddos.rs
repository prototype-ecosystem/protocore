//! DDoS protection for P2P networking layer.
//!
//! This module provides multi-layered protection against denial of service attacks:
//! - Connection rate limiting per IP
//! - Peer behavior scoring with automatic bans
//! - Resource limits per peer
//! - Abuse pattern detection

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use libp2p::PeerId;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

/// Configuration for DDoS protection
#[derive(Debug, Clone)]
pub struct DdosConfig {
    /// Maximum connection attempts per IP per window
    pub max_connections_per_ip: u32,
    /// Time window for connection rate limiting (seconds)
    pub connection_window_secs: u64,
    /// Maximum messages per peer per second
    pub max_messages_per_peer_per_sec: u32,
    /// Maximum bytes per peer per second
    pub max_bytes_per_peer_per_sec: u64,
    /// Score threshold for automatic ban (negative score)
    pub ban_threshold: i64,
    /// Duration for automatic bans
    pub ban_duration: Duration,
    /// Score penalty for invalid message
    pub invalid_message_penalty: i64,
    /// Score penalty for rate limit violation
    pub rate_limit_penalty: i64,
    /// Score penalty for protocol violation
    pub protocol_violation_penalty: i64,
    /// Score decay rate per second (recovers reputation)
    pub score_decay_per_sec: i64,
    /// Maximum concurrent connections from same IP
    pub max_connections_same_ip: u32,
    /// Cleanup interval for expired entries
    pub cleanup_interval: Duration,
}

impl Default for DdosConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 10,
            connection_window_secs: 60,
            max_messages_per_peer_per_sec: 100,
            max_bytes_per_peer_per_sec: 1_000_000, // 1 MB/s
            ban_threshold: -100,
            ban_duration: Duration::from_secs(3600), // 1 hour
            invalid_message_penalty: 20,
            rate_limit_penalty: 10,
            protocol_violation_penalty: 50,
            score_decay_per_sec: 1,
            max_connections_same_ip: 3,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

/// Connection attempt record for rate limiting
#[derive(Debug, Clone)]
struct ConnectionRecord {
    /// Number of connection attempts in the current window
    attempts: u32,
    /// When the window started
    window_start: Instant,
    /// Active connections count
    active_connections: u32,
}

impl ConnectionRecord {
    fn new() -> Self {
        Self {
            attempts: 0,
            window_start: Instant::now(),
            active_connections: 0,
        }
    }

    fn increment(&mut self, window_secs: u64) {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= window_secs {
            // Reset window
            self.attempts = 1;
            self.window_start = now;
        } else {
            self.attempts += 1;
        }
    }

    fn attempts_in_window(&self, window_secs: u64) -> u32 {
        let now = Instant::now();
        if now.duration_since(self.window_start).as_secs() >= window_secs {
            0
        } else {
            self.attempts
        }
    }
}

/// Per-peer rate limiting state
#[derive(Debug, Clone)]
struct PeerRateLimitState {
    /// Messages received in current second
    messages_this_second: u32,
    /// Bytes received in current second
    bytes_this_second: u64,
    /// Current second timestamp
    current_second: u64,
    /// Cumulative behavior score (negative = bad)
    score: i64,
    /// Last score update time
    last_score_update: Instant,
    /// Whether currently rate limited
    is_rate_limited: bool,
    /// Rate limit violations count
    rate_limit_violations: u32,
}

impl Default for PeerRateLimitState {
    fn default() -> Self {
        Self {
            messages_this_second: 0,
            bytes_this_second: 0,
            current_second: 0,
            score: 0,
            last_score_update: Instant::now(),
            is_rate_limited: false,
            rate_limit_violations: 0,
        }
    }
}

/// Reason for rejecting a connection or message
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    /// Too many connection attempts from this IP
    ConnectionRateLimited,
    /// Too many active connections from this IP
    MaxConnectionsExceeded,
    /// Peer is banned
    Banned,
    /// Message rate limit exceeded
    MessageRateLimited,
    /// Bytes rate limit exceeded
    BytesRateLimited,
}

impl std::fmt::Display for RejectionReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RejectionReason::ConnectionRateLimited => write!(f, "connection rate limited"),
            RejectionReason::MaxConnectionsExceeded => write!(f, "max connections exceeded"),
            RejectionReason::Banned => write!(f, "peer is banned"),
            RejectionReason::MessageRateLimited => write!(f, "message rate limited"),
            RejectionReason::BytesRateLimited => write!(f, "bytes rate limited"),
        }
    }
}

/// Types of protocol violations that can be penalized
#[derive(Debug, Clone, Copy)]
pub enum ViolationType {
    /// Sent an invalid/malformed message
    InvalidMessage,
    /// Exceeded rate limits
    RateLimitViolation,
    /// Protocol misbehavior (e.g., sent proposal when not proposer)
    ProtocolViolation,
    /// Sent duplicate message
    DuplicateMessage,
    /// Timeout/unresponsive behavior
    Timeout,
}

/// DDoS protection manager
pub struct DdosProtection {
    config: DdosConfig,
    /// Connection rate limiting by IP
    connection_records: RwLock<HashMap<IpAddr, ConnectionRecord>>,
    /// Per-peer rate limiting state
    peer_states: RwLock<HashMap<PeerId, PeerRateLimitState>>,
    /// Banned peers with expiration time
    banned_peers: RwLock<HashMap<PeerId, Instant>>,
    /// Banned IPs with expiration time
    banned_ips: RwLock<HashMap<IpAddr, Instant>>,
    /// Last cleanup time
    last_cleanup: RwLock<Instant>,
}

impl DdosProtection {
    /// Create a new DDoS protection manager
    pub fn new(config: DdosConfig) -> Self {
        Self {
            config,
            connection_records: RwLock::new(HashMap::new()),
            peer_states: RwLock::new(HashMap::new()),
            banned_peers: RwLock::new(HashMap::new()),
            banned_ips: RwLock::new(HashMap::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(DdosConfig::default())
    }

    /// Check if a new connection from an IP should be allowed
    pub fn check_connection(&self, ip: IpAddr) -> Result<(), RejectionReason> {
        // Check IP ban
        {
            let banned = self.banned_ips.read();
            if let Some(&expiry) = banned.get(&ip) {
                if Instant::now() < expiry {
                    return Err(RejectionReason::Banned);
                }
            }
        }

        let mut records = self.connection_records.write();
        let record = records.entry(ip).or_insert_with(ConnectionRecord::new);

        // Check active connections limit
        if record.active_connections >= self.config.max_connections_same_ip {
            debug!(?ip, "rejecting connection: max connections exceeded");
            return Err(RejectionReason::MaxConnectionsExceeded);
        }

        // Check rate limit
        let attempts = record.attempts_in_window(self.config.connection_window_secs);
        if attempts >= self.config.max_connections_per_ip {
            debug!(?ip, attempts, "rejecting connection: rate limited");
            return Err(RejectionReason::ConnectionRateLimited);
        }

        // Record this attempt
        record.increment(self.config.connection_window_secs);

        Ok(())
    }

    /// Record a successful connection from an IP
    pub fn connection_established(&self, ip: IpAddr) {
        let mut records = self.connection_records.write();
        if let Some(record) = records.get_mut(&ip) {
            record.active_connections += 1;
        }
    }

    /// Record a connection close from an IP
    pub fn connection_closed(&self, ip: IpAddr) {
        let mut records = self.connection_records.write();
        if let Some(record) = records.get_mut(&ip) {
            record.active_connections = record.active_connections.saturating_sub(1);
        }
    }

    /// Check if a message from a peer should be allowed
    pub fn check_message(
        &self,
        peer_id: &PeerId,
        message_bytes: usize,
    ) -> Result<(), RejectionReason> {
        // Check peer ban
        {
            let banned = self.banned_peers.read();
            if let Some(&expiry) = banned.get(peer_id) {
                if Instant::now() < expiry {
                    return Err(RejectionReason::Banned);
                }
            }
        }

        let mut states = self.peer_states.write();
        let state = states.entry(*peer_id).or_default();

        // Get current second (truncated timestamp)
        let now_secs = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Reset counters if we're in a new second
        if now_secs != state.current_second {
            state.messages_this_second = 0;
            state.bytes_this_second = 0;
            state.current_second = now_secs;
            state.is_rate_limited = false;
        }

        // Apply score decay
        self.apply_score_decay(state);

        // Check message rate limit
        if state.messages_this_second >= self.config.max_messages_per_peer_per_sec {
            state.is_rate_limited = true;
            state.rate_limit_violations += 1;
            state.score -= self.config.rate_limit_penalty;
            self.check_and_ban(peer_id, state.score);
            return Err(RejectionReason::MessageRateLimited);
        }

        // Check bytes rate limit
        if state.bytes_this_second + message_bytes as u64 > self.config.max_bytes_per_peer_per_sec {
            state.is_rate_limited = true;
            state.rate_limit_violations += 1;
            state.score -= self.config.rate_limit_penalty;
            self.check_and_ban(peer_id, state.score);
            return Err(RejectionReason::BytesRateLimited);
        }

        // Update counters
        state.messages_this_second += 1;
        state.bytes_this_second += message_bytes as u64;

        Ok(())
    }

    /// Apply score decay to restore reputation over time
    fn apply_score_decay(&self, state: &mut PeerRateLimitState) {
        let elapsed_secs = state.last_score_update.elapsed().as_secs() as i64;
        if elapsed_secs > 0 && state.score < 0 {
            let recovery = elapsed_secs * self.config.score_decay_per_sec;
            state.score = (state.score + recovery).min(0);
            state.last_score_update = Instant::now();
        }
    }

    /// Check if peer should be banned based on score
    fn check_and_ban(&self, peer_id: &PeerId, score: i64) {
        if score <= self.config.ban_threshold {
            self.ban_peer(*peer_id, self.config.ban_duration);
        }
    }

    /// Report a violation from a peer
    pub fn report_violation(&self, peer_id: &PeerId, violation: ViolationType) {
        let penalty = match violation {
            ViolationType::InvalidMessage => self.config.invalid_message_penalty,
            ViolationType::RateLimitViolation => self.config.rate_limit_penalty,
            ViolationType::ProtocolViolation => self.config.protocol_violation_penalty,
            ViolationType::DuplicateMessage => 5, // Minor penalty for duplicates
            ViolationType::Timeout => 3,          // Minor penalty for timeouts
        };

        let mut states = self.peer_states.write();
        let state = states.entry(*peer_id).or_default();
        state.score -= penalty;

        debug!(
            ?peer_id,
            ?violation,
            penalty,
            new_score = state.score,
            "recorded violation"
        );

        // Check if we should ban
        if state.score <= self.config.ban_threshold {
            drop(states); // Release lock before banning
            self.ban_peer(*peer_id, self.config.ban_duration);
        }
    }

    /// Reward a peer for good behavior
    pub fn reward_peer(&self, peer_id: &PeerId, amount: i64) {
        let mut states = self.peer_states.write();
        let state = states.entry(*peer_id).or_default();
        // Cap score at 0 (neutral), don't allow positive scores
        state.score = (state.score + amount).min(0);
    }

    /// Ban a peer for a specified duration
    pub fn ban_peer(&self, peer_id: PeerId, duration: Duration) {
        let expiry = Instant::now() + duration;
        self.banned_peers.write().insert(peer_id, expiry);
        warn!(?peer_id, ?duration, "peer banned");
    }

    /// Ban an IP address for a specified duration
    pub fn ban_ip(&self, ip: IpAddr, duration: Duration) {
        let expiry = Instant::now() + duration;
        self.banned_ips.write().insert(ip, expiry);
        warn!(?ip, ?duration, "IP banned");
    }

    /// Unban a peer
    pub fn unban_peer(&self, peer_id: &PeerId) {
        self.banned_peers.write().remove(peer_id);
        self.peer_states.write().remove(peer_id);
        info!(?peer_id, "peer unbanned");
    }

    /// Unban an IP
    pub fn unban_ip(&self, ip: &IpAddr) {
        self.banned_ips.write().remove(ip);
        self.connection_records.write().remove(ip);
        info!(?ip, "IP unbanned");
    }

    /// Check if a peer is banned
    pub fn is_peer_banned(&self, peer_id: &PeerId) -> bool {
        let banned = self.banned_peers.read();
        if let Some(&expiry) = banned.get(peer_id) {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Check if an IP is banned
    pub fn is_ip_banned(&self, ip: &IpAddr) -> bool {
        let banned = self.banned_ips.read();
        if let Some(&expiry) = banned.get(ip) {
            Instant::now() < expiry
        } else {
            false
        }
    }

    /// Get peer score (returns None if peer is unknown)
    pub fn get_peer_score(&self, peer_id: &PeerId) -> Option<i64> {
        self.peer_states.read().get(peer_id).map(|s| s.score)
    }

    /// Clean up expired bans and stale records
    pub fn cleanup(&self) {
        let now = Instant::now();

        // Check if cleanup is needed
        {
            let last = self.last_cleanup.read();
            if now.duration_since(*last) < self.config.cleanup_interval {
                return;
            }
        }

        // Update last cleanup time
        *self.last_cleanup.write() = now;

        // Clean up expired peer bans
        {
            let mut banned = self.banned_peers.write();
            banned.retain(|_, expiry| now < *expiry);
        }

        // Clean up expired IP bans
        {
            let mut banned = self.banned_ips.write();
            banned.retain(|_, expiry| now < *expiry);
        }

        // Clean up stale connection records (no activity in 5 minutes)
        {
            let stale_threshold = Duration::from_secs(300);
            let mut records = self.connection_records.write();
            records.retain(|_, record| {
                record.active_connections > 0
                    || now.duration_since(record.window_start) < stale_threshold
            });
        }

        // Clean up stale peer states (no activity in 5 minutes and score is 0)
        {
            let stale_threshold = Duration::from_secs(300);
            let mut states = self.peer_states.write();
            states.retain(|_, state| {
                state.score < 0 || now.duration_since(state.last_score_update) < stale_threshold
            });
        }

        debug!("DDoS protection cleanup completed");
    }

    /// Get statistics for monitoring
    pub fn stats(&self) -> DdosStats {
        DdosStats {
            tracked_ips: self.connection_records.read().len(),
            tracked_peers: self.peer_states.read().len(),
            banned_peers: self.banned_peers.read().len(),
            banned_ips: self.banned_ips.read().len(),
        }
    }
}

/// Statistics for the DDoS protection system
#[derive(Debug, Clone)]
pub struct DdosStats {
    /// Number of tracked IP addresses
    pub tracked_ips: usize,
    /// Number of tracked peers
    pub tracked_peers: usize,
    /// Number of currently banned peers
    pub banned_peers: usize,
    /// Number of currently banned IPs
    pub banned_ips: usize,
}

/// Thread-safe wrapper for DDoS protection
pub type SharedDdosProtection = Arc<DdosProtection>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn test_ip() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
    }

    fn test_peer_id() -> PeerId {
        let keypair = libp2p::identity::Keypair::generate_ed25519();
        PeerId::from(keypair.public())
    }

    #[test]
    fn test_connection_rate_limiting() {
        let config = DdosConfig {
            max_connections_per_ip: 5,
            connection_window_secs: 60,
            ..Default::default()
        };
        let protection = DdosProtection::new(config);
        let ip = test_ip();

        // First 5 should succeed
        for i in 0..5 {
            assert!(
                protection.check_connection(ip).is_ok(),
                "Connection {} should succeed",
                i
            );
        }

        // 6th should fail
        assert_eq!(
            protection.check_connection(ip),
            Err(RejectionReason::ConnectionRateLimited)
        );
    }

    #[test]
    fn test_peer_message_rate_limiting() {
        let config = DdosConfig {
            max_messages_per_peer_per_sec: 5,
            ..Default::default()
        };
        let protection = DdosProtection::new(config);
        let peer = test_peer_id();

        // First 5 should succeed
        for _ in 0..5 {
            assert!(protection.check_message(&peer, 100).is_ok());
        }

        // 6th should fail
        assert_eq!(
            protection.check_message(&peer, 100),
            Err(RejectionReason::MessageRateLimited)
        );
    }

    #[test]
    fn test_peer_banning() {
        let config = DdosConfig {
            ban_threshold: -50,
            protocol_violation_penalty: 60,
            ban_duration: Duration::from_secs(3600),
            ..Default::default()
        };
        let protection = DdosProtection::new(config);
        let peer = test_peer_id();

        // Report a serious violation
        protection.report_violation(&peer, ViolationType::ProtocolViolation);

        // Peer should now be banned
        assert!(protection.is_peer_banned(&peer));

        // Messages should be rejected
        assert_eq!(
            protection.check_message(&peer, 100),
            Err(RejectionReason::Banned)
        );

        // Unban and verify
        protection.unban_peer(&peer);
        assert!(!protection.is_peer_banned(&peer));
        assert!(protection.check_message(&peer, 100).is_ok());
    }

    #[test]
    fn test_ip_banning() {
        let protection = DdosProtection::with_defaults();
        let ip = test_ip();

        protection.ban_ip(ip, Duration::from_secs(3600));
        assert!(protection.is_ip_banned(&ip));

        assert_eq!(
            protection.check_connection(ip),
            Err(RejectionReason::Banned)
        );

        protection.unban_ip(&ip);
        assert!(!protection.is_ip_banned(&ip));
        assert!(protection.check_connection(ip).is_ok());
    }
}
