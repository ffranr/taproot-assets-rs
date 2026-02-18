//! Proof-file checksum/continuity claim helpers.

extern crate alloc;

use alloc::vec::Vec;
use core::fmt;

use bitcoin::OutPoint;
use risc0_zkvm::sha::{Impl as Sha256Impl, Sha256};
use serde::{Deserialize, Serialize};
use taproot_assets_types as types;
use taproot_assets_types::proof::Proof;

/// Input payload for the proof-chain claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChainClaimInput {
    /// Source proof-file version.
    pub proof_file_version: u32,
    /// Ordered proof entries from the source file.
    pub entries: Vec<ProofChainEntryInput>,
}

impl ProofChainClaimInput {
    /// Builds a proof-chain claim input from a decoded proof file.
    pub fn from_file(file: &types::proof::File) -> Self {
        let mut entries = Vec::with_capacity(file.proofs.len());
        for proof in &file.proofs {
            entries.push(ProofChainEntryInput {
                proof_bytes: proof.proof_bytes.clone(),
                proof_checksum: proof.hash,
            });
        }
        Self {
            proof_file_version: file.version,
            entries,
        }
    }
}

/// A single proof-chain claim entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChainEntryInput {
    /// Raw encoded proof bytes.
    pub proof_bytes: Vec<u8>,
    /// Claimed chained checksum for this proof.
    pub proof_checksum: [u8; 32],
}

/// Output digest for the proof-chain claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofChainClaimOutput {
    /// Source proof-file version.
    pub proof_file_version: u32,
    /// Number of proofs in the file.
    pub proof_count: u32,
    /// Last checksum in the chained hash sequence.
    pub last_proof_checksum: [u8; 32],
    /// Outpoint of the asset committed by the last proof (if any).
    pub last_proof_outpoint: Option<OutPoint>,
}

/// Errors returned by proof-chain claim verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// The number of proofs exceeds `u32::MAX`.
    TooManyProofs(usize),
    /// A proof checksum doesn't match SHA256(prev_hash || proof_bytes).
    ChecksumMismatch { index: u32 },
    /// A proof could not be decoded.
    InvalidProofEncoding { index: u32 },
    /// The proof's `prev_out` does not link to the previous proof outpoint.
    PrevOutChainMismatch { index: u32 },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyProofs(count) => write!(f, "too many proofs for claim: {count}"),
            Self::ChecksumMismatch { index } => {
                write!(f, "proof checksum mismatch at index {index}")
            }
            Self::InvalidProofEncoding { index } => {
                write!(f, "invalid proof encoding at index {index}")
            }
            Self::PrevOutChainMismatch { index } => {
                write!(
                    f,
                    "proof prev_out does not match prior outpoint at index {index}"
                )
            }
        }
    }
}

/// Verifies a proof-file checksum chain and proof outpoint continuity.
pub fn verify_proof_chain_claim(
    input: &ProofChainClaimInput,
) -> Result<ProofChainClaimOutput, Error> {
    let proof_count_u32 = u32::try_from(input.entries.len())
        .map_err(|_| Error::TooManyProofs(input.entries.len()))?;

    let mut prev_checksum = [0u8; 32];
    let mut expected_prev_outpoint: Option<OutPoint> = None;
    let mut last_outpoint: Option<OutPoint> = None;

    for (idx, entry) in input.entries.iter().enumerate() {
        let index = idx as u32;
        let expected_checksum = hash_proof(entry.proof_bytes.as_slice(), prev_checksum);
        if expected_checksum != entry.proof_checksum {
            return Err(Error::ChecksumMismatch { index });
        }

        let proof = Proof::from_bytes(&entry.proof_bytes)
            .map_err(|_| Error::InvalidProofEncoding { index })?;
        if let Some(expected_prev) = expected_prev_outpoint {
            if proof.prev_out != expected_prev {
                return Err(Error::PrevOutChainMismatch { index });
            }
        }

        let outpoint = OutPoint {
            txid: proof.anchor_tx.compute_txid(),
            vout: proof.inclusion_proof.output_index,
        };
        last_outpoint = Some(outpoint);
        expected_prev_outpoint = Some(outpoint);
        prev_checksum = entry.proof_checksum;
    }

    Ok(ProofChainClaimOutput {
        proof_file_version: input.proof_file_version,
        proof_count: proof_count_u32,
        last_proof_checksum: prev_checksum,
        last_proof_outpoint: last_outpoint,
    })
}

fn hash_proof(proof_bytes: &[u8], prev_hash: [u8; 32]) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(32 + proof_bytes.len());
    preimage.extend_from_slice(&prev_hash);
    preimage.extend_from_slice(proof_bytes);
    let digest = Sha256Impl::hash_bytes(&preimage);
    digest.as_bytes().try_into().unwrap()
}
