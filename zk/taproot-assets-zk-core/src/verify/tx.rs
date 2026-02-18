//! Anchor transaction verification helpers with RISC0 hashing.

use risc0_zkvm::sha::Impl as Sha256Impl;
use risc0_zkvm::sha::Sha256;
use taproot_assets_core::verify::tx::{verify_tx_merkle_proof_input_with_hasher, MerkleHasher};

/// Input for transaction merkle proof verification.
pub type VerifyMerkleProofInput = taproot_assets_core::verify::tx::VerifyMerkleProofInput;

/// Input for anchor claim verification.
pub type AnchorClaimInput = taproot_assets_core::verify::tx::AnchorClaimInput;

/// Output digest for the anchor claim.
pub type AnchorClaimOutput = taproot_assets_core::verify::tx::AnchorClaimOutput;

/// RISC0-backed Merkle hasher using double-SHA-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct Risc0MerkleHasher;

impl MerkleHasher for Risc0MerkleHasher {
    /// Hashes a node pair with double-SHA-256 using the zk-VM gadget.
    fn hash_nodes(&self, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        // Concatenate the two nodes into a 64-byte buffer.
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left);
        buf[32..].copy_from_slice(&right);

        // Double-SHA-256 using zk-VM gadget.
        let h = Sha256Impl::hash_bytes(&Sha256Impl::hash_bytes(&buf).as_bytes());

        h.as_bytes().try_into().unwrap()
    }
}

/// Verify a Merkle proof for a transaction ID against the expected Merkle root.
pub fn verify_tx_merkle_proof(input: &VerifyMerkleProofInput) -> bool {
    verify_tx_merkle_proof_input_with_hasher(input, &Risc0MerkleHasher).is_ok()
}

/// Verify an anchor claim and return the digest.
pub fn verify_anchor_claim(
    input: &AnchorClaimInput,
) -> Result<AnchorClaimOutput, taproot_assets_core::verify::tx::Error> {
    taproot_assets_core::verify::tx::verify_anchor_claim_with_hasher(input, &Risc0MerkleHasher)
}
