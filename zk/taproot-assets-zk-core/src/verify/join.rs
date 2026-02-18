//! Receipt composition helpers for join proofs.

use alloc::vec::Vec;
use risc0_zkvm::ReceiptClaim;
use serde::{Deserialize, Serialize};
use taproot_assets_types::asset::SerializedKey;

/// Receipt claim input used by join proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReceiptClaimInput {
    /// Receipt claim for the guest execution.
    pub claim: ReceiptClaim,
}

/// Input payload for joining the proof claims.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JoinInput {
    /// Receipt claim for the anchor claim prover.
    pub anchor: ReceiptClaimInput,
    /// Receipt claim for the asset integrity claim prover.
    pub asset: ReceiptClaimInput,
    /// Receipt claims for taproot inclusion/exclusion proofs.
    pub taproot_claims: Vec<ReceiptClaimInput>,
    /// Receipt claims for STXO proofs (matching taproot claims).
    pub stxo_claims: Vec<ReceiptClaimInput>,
    /// Optional receipt claim for a split-root proof.
    pub split_root: Option<ReceiptClaimInput>,
}

/// Output payload for the join proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinOutput {
    /// The transaction ID of the anchor transaction.
    pub anchor_txid: [u8; 32],
    /// The hash of the block header.
    pub block_hash: [u8; 32],
    /// The block height.
    pub block_height: u32,
    /// The taproot output key (verified consistent across claims).
    pub taproot_output_key: [u8; 32],
    /// The tap commitment root hash.
    pub tap_commitment_root: [u8; 32],
    /// The tap commitment root sum.
    pub tap_commitment_sum: u64,
    /// The asset ID.
    pub asset_id: [u8; 32],
    /// The group key, if present.
    pub group_key: Option<SerializedKey>,
    /// The meta hash, if present.
    pub meta_hash: Option<[u8; 32]>,
    /// The proof version committed by the asset claim.
    pub proof_version: u32,
}
