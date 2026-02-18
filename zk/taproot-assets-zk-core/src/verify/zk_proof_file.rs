//! ZK proof-file types and digest helpers.
//!
//! The ZkProofFile artifact is a host-serialized container that binds:
//! - proof-file metadata (version/count/checksum-chain tip),
//! - a proof-chain claim output + receipt,
//! - per-proof join outputs,
//! - opaque join receipt bytes.
//!
//! The digest helpers in this module are used to derive a deterministic
//! file-level commitment that can be transported or anchored elsewhere.

use alloc::vec::Vec;
use core::fmt;

use bitcoin::hashes::{sha256, Hash};
use serde::{Deserialize, Serialize};

use crate::verify::join::JoinOutput;
use crate::verify::proof_chain::ProofChainClaimOutput;

/// Magic bytes used by host encoders for ZkProofFile blobs.
pub const ZK_PROOF_FILE_MAGIC: [u8; 4] = *b"TZKF";
/// Format version for [`ZkProofFile`].
pub const ZK_PROOF_FILE_VERSION: u32 = 1;

const FILE_DOMAIN_TAG: &[u8] = b"taproot-assets-zk-proof-file-v1";
const ENTRY_DOMAIN_TAG: &[u8] = b"taproot-assets-zk-proof-file-entry-v1";
const JOIN_OUTPUT_DOMAIN_TAG: &[u8] = b"taproot-assets-zk-join-output-v1";
const PROOF_CHAIN_CLAIM_DOMAIN_TAG: &[u8] = b"taproot-assets-zk-proof-chain-claim-v1";

/// Errors returned by ZkProofFile validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    /// The artifact carries an unsupported format version.
    UnsupportedFormatVersion { expected: u32, got: u32 },
    /// `proof_count` does not match the number of encoded entries.
    ProofCountMismatch {
        proof_count: u32,
        entry_count: usize,
    },
    /// A proof index is outside `[0, proof_count)`.
    ProofIndexOutOfRange { proof_index: u32, proof_count: u32 },
    /// Entries must be strictly sorted by `proof_index`.
    NonCanonicalEntryOrder,
    /// Proof-chain claim version does not match the proof-file version.
    ProofChainVersionMismatch {
        proof_file_version: u32,
        claim_version: u32,
    },
    /// Proof-chain claim proof count does not match the artifact proof count.
    ProofChainCountMismatch { proof_count: u32, claim_count: u32 },
    /// Proof-chain claim checksum tip does not match the artifact checksum tip.
    ProofChainTipMismatch,
    /// Proof-chain receipt bytes are empty.
    MissingProofChainReceipt,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedFormatVersion { expected, got } => {
                write!(
                    f,
                    "unsupported zk proof-file format version: expected {expected}, got {got}"
                )
            }
            Self::ProofCountMismatch {
                proof_count,
                entry_count,
            } => {
                write!(
                    f,
                    "proof count mismatch: header {proof_count}, entries {entry_count}"
                )
            }
            Self::ProofIndexOutOfRange {
                proof_index,
                proof_count,
            } => {
                write!(
                    f,
                    "proof index out of range: index {proof_index}, proof_count {proof_count}"
                )
            }
            Self::NonCanonicalEntryOrder => {
                write!(
                    f,
                    "zk proof-file entries are not in strictly increasing index order"
                )
            }
            Self::ProofChainVersionMismatch {
                proof_file_version,
                claim_version,
            } => {
                write!(
                    f,
                    "proof-chain claim version mismatch: file {proof_file_version}, claim {claim_version}"
                )
            }
            Self::ProofChainCountMismatch {
                proof_count,
                claim_count,
            } => {
                write!(
                    f,
                    "proof-chain claim count mismatch: file {proof_count}, claim {claim_count}"
                )
            }
            Self::ProofChainTipMismatch => {
                write!(f, "proof-chain claim tip does not match artifact tip")
            }
            Self::MissingProofChainReceipt => write!(f, "missing proof-chain receipt"),
        }
    }
}

/// A ZkProofFile entry for a single proof in the source proof file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofFileEntry {
    /// Index of the source proof in `proof::File.proofs`.
    pub proof_index: u32,
    /// Chained checksum (`HashedProof.hash`) from the source proof file.
    pub proof_checksum: [u8; 32],
    /// Joined digest output committed by the join prover.
    pub join_output: JoinOutput,
    /// Opaque serialized join receipt bytes.
    pub join_receipt: Vec<u8>,
}

impl ZkProofFileEntry {
    /// Deterministic commitment to this entry.
    pub fn commitment(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(ENTRY_DOMAIN_TAG);
        preimage.extend_from_slice(&self.proof_index.to_be_bytes());
        preimage.extend_from_slice(&self.proof_checksum);
        preimage.extend_from_slice(&join_output_commitment(&self.join_output));
        preimage.extend_from_slice(&hash_bytes(&self.join_receipt));
        hash_bytes(&preimage)
    }
}

/// Versioned ZkProofFile artifact for an entire proof file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofFile {
    /// ZkProofFile format version.
    pub format_version: u32,
    /// Original proof-file version from `proof::File`.
    pub proof_file_version: u32,
    /// Number of proofs in the original proof file.
    pub proof_count: u32,
    /// Last checksum in the source proof file's hash chain.
    pub proof_chain_tip: [u8; 32],
    /// Proof-chain claim output committed by the proof-chain claim guest.
    pub proof_chain_claim: ProofChainClaimOutput,
    /// Opaque serialized proof-chain receipt bytes.
    pub proof_chain_receipt: Vec<u8>,
    /// One ZkProofFile entry per proof.
    pub entries: Vec<ZkProofFileEntry>,
}

impl ZkProofFile {
    /// Creates a version-1 ZkProofFile from proof-file metadata and entries.
    pub fn new(
        proof_file_version: u32,
        proof_chain_tip: [u8; 32],
        proof_chain_claim: ProofChainClaimOutput,
        proof_chain_receipt: Vec<u8>,
        entries: Vec<ZkProofFileEntry>,
    ) -> Self {
        Self {
            format_version: ZK_PROOF_FILE_VERSION,
            proof_file_version,
            proof_count: entries.len() as u32,
            proof_chain_tip,
            proof_chain_claim,
            proof_chain_receipt,
            entries,
        }
    }

    /// Performs structural checks on the artifact.
    pub fn validate_basic(&self) -> Result<(), ValidationError> {
        if self.format_version != ZK_PROOF_FILE_VERSION {
            return Err(ValidationError::UnsupportedFormatVersion {
                expected: ZK_PROOF_FILE_VERSION,
                got: self.format_version,
            });
        }

        if self.proof_count as usize != self.entries.len() {
            return Err(ValidationError::ProofCountMismatch {
                proof_count: self.proof_count,
                entry_count: self.entries.len(),
            });
        }
        if self.proof_chain_claim.proof_file_version != self.proof_file_version {
            return Err(ValidationError::ProofChainVersionMismatch {
                proof_file_version: self.proof_file_version,
                claim_version: self.proof_chain_claim.proof_file_version,
            });
        }
        if self.proof_chain_claim.proof_count != self.proof_count {
            return Err(ValidationError::ProofChainCountMismatch {
                proof_count: self.proof_count,
                claim_count: self.proof_chain_claim.proof_count,
            });
        }
        if self.proof_chain_claim.last_proof_checksum != self.proof_chain_tip {
            return Err(ValidationError::ProofChainTipMismatch);
        }
        if self.proof_chain_receipt.is_empty() {
            return Err(ValidationError::MissingProofChainReceipt);
        }

        let mut previous_index: Option<u32> = None;
        for entry in &self.entries {
            if entry.proof_index >= self.proof_count {
                return Err(ValidationError::ProofIndexOutOfRange {
                    proof_index: entry.proof_index,
                    proof_count: self.proof_count,
                });
            }

            if let Some(prev) = previous_index {
                if entry.proof_index <= prev {
                    return Err(ValidationError::NonCanonicalEntryOrder);
                }
            }
            previous_index = Some(entry.proof_index);
        }

        Ok(())
    }

    /// Deterministic file-level commitment for the ZkProofFile artifact.
    pub fn artifact_digest(&self) -> [u8; 32] {
        let mut preimage = Vec::new();
        preimage.extend_from_slice(FILE_DOMAIN_TAG);
        preimage.extend_from_slice(&self.format_version.to_be_bytes());
        preimage.extend_from_slice(&self.proof_file_version.to_be_bytes());
        preimage.extend_from_slice(&self.proof_count.to_be_bytes());
        preimage.extend_from_slice(&self.proof_chain_tip);
        preimage.extend_from_slice(&proof_chain_claim_commitment(&self.proof_chain_claim));
        preimage.extend_from_slice(&hash_bytes(&self.proof_chain_receipt));
        for entry in &self.entries {
            preimage.extend_from_slice(&entry.commitment());
        }
        hash_bytes(&preimage)
    }
}

fn hash_bytes(data: &[u8]) -> [u8; 32] {
    sha256::Hash::hash(data).to_byte_array()
}

fn join_output_commitment(output: &JoinOutput) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(JOIN_OUTPUT_DOMAIN_TAG);
    preimage.extend_from_slice(&output.anchor_txid);
    preimage.extend_from_slice(&output.block_hash);
    preimage.extend_from_slice(&output.block_height.to_be_bytes());
    preimage.extend_from_slice(&output.taproot_output_key);
    preimage.extend_from_slice(&output.tap_commitment_root);
    preimage.extend_from_slice(&output.tap_commitment_sum.to_be_bytes());
    preimage.extend_from_slice(&output.asset_id);

    if let Some(group_key) = output.group_key {
        preimage.push(1);
        preimage.extend_from_slice(&group_key.bytes);
    } else {
        preimage.push(0);
    }

    if let Some(meta_hash) = output.meta_hash {
        preimage.push(1);
        preimage.extend_from_slice(&meta_hash);
    } else {
        preimage.push(0);
    }

    preimage.extend_from_slice(&output.proof_version.to_be_bytes());
    hash_bytes(&preimage)
}

fn proof_chain_claim_commitment(output: &ProofChainClaimOutput) -> [u8; 32] {
    let mut preimage = Vec::new();
    preimage.extend_from_slice(PROOF_CHAIN_CLAIM_DOMAIN_TAG);
    preimage.extend_from_slice(&output.proof_file_version.to_be_bytes());
    preimage.extend_from_slice(&output.proof_count.to_be_bytes());
    preimage.extend_from_slice(&output.last_proof_checksum);
    match output.last_proof_outpoint {
        Some(outpoint) => {
            preimage.push(1);
            preimage.extend_from_slice(outpoint.txid.as_byte_array());
            preimage.extend_from_slice(&outpoint.vout.to_be_bytes());
        }
        None => preimage.push(0),
    }
    hash_bytes(&preimage)
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::verify::proof_chain::ProofChainClaimOutput;
    use alloc::vec;
    use taproot_assets_types::asset::SerializedKey;

    fn sample_join_output() -> JoinOutput {
        JoinOutput {
            anchor_txid: [1u8; 32],
            block_hash: [2u8; 32],
            block_height: 100,
            taproot_output_key: [3u8; 32],
            tap_commitment_root: [4u8; 32],
            tap_commitment_sum: 77,
            asset_id: [5u8; 32],
            group_key: Some(SerializedKey { bytes: [6u8; 33] }),
            meta_hash: Some([7u8; 32]),
            proof_version: 1,
        }
    }

    fn sample_proof_chain_output() -> ProofChainClaimOutput {
        ProofChainClaimOutput {
            proof_file_version: 0,
            proof_count: 1,
            last_proof_checksum: [10u8; 32],
            last_proof_outpoint: None,
        }
    }

    #[test]
    fn artifact_digest_is_stable() {
        let entry = ZkProofFileEntry {
            proof_index: 0,
            proof_checksum: [8u8; 32],
            join_output: sample_join_output(),
            join_receipt: vec![9u8; 16],
        };
        let zk_proof_file = ZkProofFile::new(
            0,
            [10u8; 32],
            sample_proof_chain_output(),
            vec![11u8; 16],
            vec![entry],
        );

        let digest_1 = zk_proof_file.artifact_digest();
        let digest_2 = zk_proof_file.artifact_digest();
        assert_eq!(digest_1, digest_2);
    }

    #[test]
    fn validate_rejects_non_canonical_order() {
        let entry_a = ZkProofFileEntry {
            proof_index: 1,
            proof_checksum: [8u8; 32],
            join_output: sample_join_output(),
            join_receipt: vec![9u8; 16],
        };
        let entry_b = ZkProofFileEntry {
            proof_index: 0,
            proof_checksum: [11u8; 32],
            join_output: sample_join_output(),
            join_receipt: vec![12u8; 16],
        };
        let zk_proof_file = ZkProofFile {
            format_version: ZK_PROOF_FILE_VERSION,
            proof_file_version: 0,
            proof_count: 2,
            proof_chain_tip: [13u8; 32],
            proof_chain_claim: ProofChainClaimOutput {
                proof_file_version: 0,
                proof_count: 2,
                last_proof_checksum: [13u8; 32],
                last_proof_outpoint: None,
            },
            proof_chain_receipt: vec![14u8; 16],
            entries: vec![entry_a, entry_b],
        };

        assert_eq!(
            zk_proof_file.validate_basic(),
            Err(ValidationError::NonCanonicalEntryOrder)
        );
    }
}
