//! Protocore-specific JSON-RPC methods.
//!
//! This module implements Protocore extension methods (pc_* namespace)
//! for blockchain-specific functionality like validators, staking, and governance.

use crate::types::*;
use crate::RpcError;
use async_trait::async_trait;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, instrument};

// ============================================================================
// Protocore-specific Types
// ============================================================================

/// Information about a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ValidatorInfo {
    /// Validator's Ethereum-style address.
    pub address: Address,
    /// BLS public key for consensus (hex-encoded 48 bytes).
    pub pubkey: HexBytes,
    /// Total stake (self + delegated) in wei.
    pub stake: HexU256,
    /// Self-bonded stake in wei.
    pub self_stake: HexU256,
    /// Delegated stake in wei.
    pub delegated_stake: HexU256,
    /// Commission rate in basis points (100 = 1%).
    pub commission: u16,
    /// Whether the validator is currently active.
    pub active: bool,
    /// Whether the validator is jailed (slashed).
    pub jailed: bool,
    /// Number of blocks proposed.
    pub blocks_proposed: HexU64,
    /// Number of blocks signed.
    pub blocks_signed: HexU64,
    /// Uptime percentage (0-100).
    pub uptime: f64,
}

/// Staking information for an address.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StakingInfo {
    /// Address being queried.
    pub address: Address,
    /// Whether this address is a validator.
    pub is_validator: bool,
    /// Validator info (if is_validator is true).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validator: Option<ValidatorInfo>,
    /// Delegations made by this address.
    pub delegations: Vec<DelegationInfo>,
    /// Total delegated amount.
    pub total_delegated: HexU256,
    /// Pending rewards claimable.
    pub pending_rewards: HexU256,
    /// Unbonding delegations (not yet withdrawable).
    pub unbonding: Vec<UnbondingInfo>,
}

/// Information about a delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationInfo {
    /// Validator address.
    pub validator: Address,
    /// Delegated amount.
    pub amount: HexU256,
    /// Pending rewards from this delegation.
    pub pending_rewards: HexU256,
}

/// Information about an unbonding delegation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnbondingInfo {
    /// Validator address.
    pub validator: Address,
    /// Amount being unbonded.
    pub amount: HexU256,
    /// Block height when unbonding completes.
    pub completion_height: HexU64,
    /// Estimated completion timestamp.
    pub completion_time: HexU64,
}

/// Governance proposal information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GovernanceProposal {
    /// Proposal ID.
    pub id: HexU64,
    /// Proposer address.
    pub proposer: Address,
    /// Proposal title.
    pub title: String,
    /// Proposal description.
    pub description: String,
    /// Proposal type.
    pub proposal_type: ProposalType,
    /// Current status.
    pub status: ProposalStatus,
    /// Block when voting starts.
    pub voting_start: HexU64,
    /// Block when voting ends.
    pub voting_end: HexU64,
    /// Execution delay (blocks after voting ends).
    pub execution_delay: HexU64,
    /// Total votes for.
    pub votes_for: HexU256,
    /// Total votes against.
    pub votes_against: HexU256,
    /// Total votes abstain.
    pub votes_abstain: HexU256,
    /// Quorum requirement (basis points).
    pub quorum: u16,
    /// Threshold requirement (basis points).
    pub threshold: u16,
    /// Whether quorum has been reached.
    pub quorum_reached: bool,
    /// Whether the proposal has passed (meets threshold).
    pub passed: bool,
}

/// Proposal type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProposalType {
    /// Parameter change proposal.
    ParameterChange,
    /// Software upgrade proposal.
    SoftwareUpgrade,
    /// Text/signaling proposal.
    Text,
    /// Treasury spend proposal.
    TreasurySpend,
    /// Emergency proposal.
    Emergency,
}

/// Proposal status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProposalStatus {
    /// Proposal is in deposit period.
    Deposit,
    /// Proposal is in voting period.
    Voting,
    /// Proposal passed and is pending execution.
    Passed,
    /// Proposal was rejected.
    Rejected,
    /// Proposal was executed.
    Executed,
    /// Proposal failed to execute.
    Failed,
    /// Proposal was cancelled.
    Cancelled,
}

/// Epoch information.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EpochInfo {
    /// Current epoch number.
    pub epoch: HexU64,
    /// First block of the epoch.
    pub start_block: HexU64,
    /// Last block of the epoch (estimated).
    pub end_block: HexU64,
    /// Blocks per epoch.
    pub epoch_length: HexU64,
    /// Current block within the epoch.
    pub current_block: HexU64,
    /// Blocks remaining in the epoch.
    pub blocks_remaining: HexU64,
    /// Estimated time until epoch end (seconds).
    pub time_remaining: HexU64,
    /// Number of active validators.
    pub active_validators: u32,
    /// Total stake in the epoch.
    pub total_stake: HexU256,
}

/// Finality certificate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FinalityCert {
    /// Block height.
    pub height: HexU64,
    /// Block hash.
    pub block_hash: H256,
    /// Aggregated BLS signature (hex-encoded 96 bytes).
    pub aggregate_signature: HexBytes,
    /// Bitmap of which validators signed.
    pub signers_bitmap: HexBytes,
    /// Number of signers.
    pub signer_count: u32,
    /// Total stake that signed.
    pub signed_stake: HexU256,
    /// Whether the certificate is valid.
    pub valid: bool,
}

/// Stealth address result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StealthAddressResult {
    /// Generated stealth address.
    pub stealth_address: Address,
    /// Ephemeral public key (for recipient to derive private key).
    pub ephemeral_pubkey: HexBytes,
    /// View tag (for efficient scanning).
    pub view_tag: u8,
}

// ============================================================================
// Protocore RPC API Trait Definition
// ============================================================================

/// Protocore-specific JSON-RPC API.
///
/// This trait defines all the Protocore extension methods for validators,
/// staking, governance, and finality.
#[rpc(server, namespace = "mc")]
pub trait ProtocoreApi {
    /// Returns the current validator set.
    ///
    /// # Returns
    /// Array of validator information objects.
    #[method(name = "getValidators")]
    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>>;

    /// Returns staking information for an address.
    ///
    /// # Arguments
    /// * `address` - Address to query
    ///
    /// # Returns
    /// Staking information object.
    #[method(name = "getStakingInfo")]
    async fn get_staking_info(&self, address: Address) -> RpcResult<StakingInfo>;

    /// Returns a governance proposal by ID.
    ///
    /// # Arguments
    /// * `id` - Proposal ID
    ///
    /// # Returns
    /// Proposal object or null if not found.
    #[method(name = "getGovernanceProposal")]
    async fn get_governance_proposal(&self, id: HexU64) -> RpcResult<Option<GovernanceProposal>>;

    /// Returns all governance proposals with optional status filter.
    ///
    /// # Arguments
    /// * `status` - Optional status filter
    ///
    /// # Returns
    /// Array of proposal objects.
    #[method(name = "getProposals")]
    async fn get_proposals(&self, status: Option<ProposalStatus>) -> RpcResult<Vec<GovernanceProposal>>;

    /// Returns current epoch information.
    ///
    /// # Returns
    /// Epoch information object.
    #[method(name = "getEpochInfo")]
    async fn get_epoch_info(&self) -> RpcResult<EpochInfo>;

    /// Returns the finality certificate for a block.
    ///
    /// # Arguments
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// Finality certificate or null if not finalized.
    #[method(name = "getFinalityCert")]
    async fn get_finality_cert(&self, block: BlockNumberOrTag) -> RpcResult<Option<FinalityCert>>;

    /// Checks if a block is finalized.
    ///
    /// # Arguments
    /// * `block` - Block number or tag
    ///
    /// # Returns
    /// True if the block is finalized.
    #[method(name = "isFinalized")]
    async fn is_finalized(&self, block: BlockNumberOrTag) -> RpcResult<bool>;

    /// Returns the latest finalized block number.
    ///
    /// # Returns
    /// Hex-encoded block number.
    #[method(name = "finalizedBlockNumber")]
    async fn finalized_block_number(&self) -> RpcResult<String>;

    /// Generates a stealth address from a meta-address.
    ///
    /// # Arguments
    /// * `meta_address` - Stealth meta-address (spending + viewing pubkeys)
    ///
    /// # Returns
    /// Stealth address result with ephemeral pubkey.
    #[method(name = "generateStealthAddress")]
    async fn generate_stealth_address(&self, meta_address: HexBytes) -> RpcResult<StealthAddressResult>;

    /// Returns validator information by address.
    ///
    /// # Arguments
    /// * `address` - Validator address
    ///
    /// # Returns
    /// Validator info or null if not a validator.
    #[method(name = "getValidator")]
    async fn get_validator(&self, address: Address) -> RpcResult<Option<ValidatorInfo>>;

    /// Returns the pending rewards for an address.
    ///
    /// # Arguments
    /// * `address` - Delegator or validator address
    ///
    /// # Returns
    /// Hex-encoded pending rewards in wei.
    #[method(name = "getPendingRewards")]
    async fn get_pending_rewards(&self, address: Address) -> RpcResult<String>;

    /// Returns the current minimum stake required to become a validator.
    ///
    /// # Returns
    /// Hex-encoded minimum stake in wei.
    #[method(name = "getMinValidatorStake")]
    async fn get_min_validator_stake(&self) -> RpcResult<String>;

    /// Returns the unbonding period in blocks.
    ///
    /// # Returns
    /// Hex-encoded unbonding period.
    #[method(name = "getUnbondingPeriod")]
    async fn get_unbonding_period(&self) -> RpcResult<String>;

    /// Returns network statistics.
    ///
    /// # Returns
    /// Network statistics object.
    #[method(name = "getNetworkStats")]
    async fn get_network_stats(&self) -> RpcResult<NetworkStats>;
}

/// Network statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkStats {
    /// Total number of validators.
    pub total_validators: u32,
    /// Number of active validators.
    pub active_validators: u32,
    /// Total staked amount.
    pub total_staked: HexU256,
    /// Current block height.
    pub block_height: HexU64,
    /// Latest finalized block.
    pub finalized_height: HexU64,
    /// Transactions per second (recent average).
    pub tps: f64,
    /// Average block time (seconds).
    pub avg_block_time: f64,
    /// Total transactions ever processed.
    pub total_transactions: HexU64,
    /// Chain ID.
    pub chain_id: HexU64,
}

// ============================================================================
// State Provider Trait for Protocore API
// ============================================================================

/// Trait for providing Protocore-specific state.
#[async_trait]
pub trait ProtocoreStateProvider: Send + Sync {
    /// Get the current validator set.
    async fn get_validators(&self) -> Result<Vec<ValidatorInfo>, RpcError>;

    /// Get a specific validator by address.
    async fn get_validator(&self, address: &Address) -> Result<Option<ValidatorInfo>, RpcError>;

    /// Get staking information for an address.
    async fn get_staking_info(&self, address: &Address) -> Result<StakingInfo, RpcError>;

    /// Get a governance proposal by ID.
    async fn get_proposal(&self, id: u64) -> Result<Option<GovernanceProposal>, RpcError>;

    /// Get all proposals with optional status filter.
    async fn get_proposals(&self, status: Option<ProposalStatus>) -> Result<Vec<GovernanceProposal>, RpcError>;

    /// Get current epoch information.
    async fn get_epoch_info(&self) -> Result<EpochInfo, RpcError>;

    /// Get finality certificate for a block.
    async fn get_finality_cert(&self, block: &BlockNumberOrTag) -> Result<Option<FinalityCert>, RpcError>;

    /// Check if a block is finalized.
    async fn is_finalized(&self, block: &BlockNumberOrTag) -> Result<bool, RpcError>;

    /// Get the latest finalized block number.
    async fn finalized_block_number(&self) -> Result<u64, RpcError>;

    /// Generate a stealth address.
    async fn generate_stealth_address(&self, meta_address: &[u8]) -> Result<StealthAddressResult, RpcError>;

    /// Get pending rewards for an address.
    async fn get_pending_rewards(&self, address: &Address) -> Result<u128, RpcError>;

    /// Get minimum validator stake.
    async fn get_min_validator_stake(&self) -> Result<u128, RpcError>;

    /// Get unbonding period in blocks.
    async fn get_unbonding_period(&self) -> Result<u64, RpcError>;

    /// Get network statistics.
    async fn get_network_stats(&self) -> Result<NetworkStats, RpcError>;
}

// ============================================================================
// ProtocoreApi Implementation
// ============================================================================

/// Helper to convert RpcError to jsonrpsee ErrorObjectOwned
fn rpc_err(e: RpcError) -> jsonrpsee::types::ErrorObjectOwned {
    e.into()
}

/// Implementation of the Protocore RPC API.
pub struct ProtocoreApiImpl<S> {
    state: Arc<S>,
}

impl<S> ProtocoreApiImpl<S>
where
    S: ProtocoreStateProvider,
{
    /// Create a new Protocore API implementation.
    pub fn new(state: Arc<S>) -> Self {
        Self { state }
    }
}

#[async_trait]
impl<S> ProtocoreApiServer for ProtocoreApiImpl<S>
where
    S: ProtocoreStateProvider + 'static,
{
    #[instrument(skip(self), level = "debug")]
    async fn get_validators(&self) -> RpcResult<Vec<ValidatorInfo>> {
        let validators = self.state.get_validators().await.map_err(rpc_err)?;
        debug!(count = validators.len(), "pc_getValidators");
        Ok(validators)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_staking_info(&self, address: Address) -> RpcResult<StakingInfo> {
        let info = self.state.get_staking_info(&address).await.map_err(rpc_err)?;
        debug!(?address, "pc_getStakingInfo");
        Ok(info)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_governance_proposal(&self, id: HexU64) -> RpcResult<Option<GovernanceProposal>> {
        let proposal = self.state.get_proposal(id.0).await.map_err(rpc_err)?;
        debug!(id = id.0, found = proposal.is_some(), "pc_getGovernanceProposal");
        Ok(proposal)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_proposals(&self, status: Option<ProposalStatus>) -> RpcResult<Vec<GovernanceProposal>> {
        let proposals = self.state.get_proposals(status).await.map_err(rpc_err)?;
        debug!(?status, count = proposals.len(), "pc_getProposals");
        Ok(proposals)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_epoch_info(&self) -> RpcResult<EpochInfo> {
        let info = self.state.get_epoch_info().await.map_err(rpc_err)?;
        debug!(epoch = info.epoch.0, "pc_getEpochInfo");
        Ok(info)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_finality_cert(&self, block: BlockNumberOrTag) -> RpcResult<Option<FinalityCert>> {
        let cert = self.state.get_finality_cert(&block).await.map_err(rpc_err)?;
        debug!(?block, found = cert.is_some(), "pc_getFinalityCert");
        Ok(cert)
    }

    #[instrument(skip(self), level = "debug")]
    async fn is_finalized(&self, block: BlockNumberOrTag) -> RpcResult<bool> {
        let finalized = self.state.is_finalized(&block).await.map_err(rpc_err)?;
        debug!(?block, finalized, "pc_isFinalized");
        Ok(finalized)
    }

    #[instrument(skip(self), level = "debug")]
    async fn finalized_block_number(&self) -> RpcResult<String> {
        let number = self.state.finalized_block_number().await.map_err(rpc_err)?;
        debug!(number, "pc_finalizedBlockNumber");
        Ok(format!("0x{:x}", number))
    }

    #[instrument(skip(self), level = "debug")]
    async fn generate_stealth_address(&self, meta_address: HexBytes) -> RpcResult<StealthAddressResult> {
        let result = self
            .state
            .generate_stealth_address(&meta_address.0)
            .await
            .map_err(rpc_err)?;
        debug!(?result.stealth_address, "pc_generateStealthAddress");
        Ok(result)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_validator(&self, address: Address) -> RpcResult<Option<ValidatorInfo>> {
        let validator = self.state.get_validator(&address).await.map_err(rpc_err)?;
        debug!(?address, found = validator.is_some(), "pc_getValidator");
        Ok(validator)
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_pending_rewards(&self, address: Address) -> RpcResult<String> {
        let rewards = self.state.get_pending_rewards(&address).await.map_err(rpc_err)?;
        debug!(?address, rewards, "pc_getPendingRewards");
        Ok(format!("0x{:x}", rewards))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_min_validator_stake(&self) -> RpcResult<String> {
        let stake = self.state.get_min_validator_stake().await.map_err(rpc_err)?;
        debug!(stake, "pc_getMinValidatorStake");
        Ok(format!("0x{:x}", stake))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_unbonding_period(&self) -> RpcResult<String> {
        let period = self.state.get_unbonding_period().await.map_err(rpc_err)?;
        debug!(period, "pc_getUnbondingPeriod");
        Ok(format!("0x{:x}", period))
    }

    #[instrument(skip(self), level = "debug")]
    async fn get_network_stats(&self) -> RpcResult<NetworkStats> {
        let stats = self.state.get_network_stats().await.map_err(rpc_err)?;
        debug!(?stats.block_height, "pc_getNetworkStats");
        Ok(stats)
    }
}

