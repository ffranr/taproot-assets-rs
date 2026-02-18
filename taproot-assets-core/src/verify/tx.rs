//! Anchor transaction verification helpers.

extern crate alloc;

use alloc::vec::Vec;

use bitcoin::block::Header;
use bitcoin::hashes::{Hash, sha256d::Hash as Sha256dHash};
use bitcoin::{OutPoint, Script, Transaction, TxMerkleNode};
use serde::{Deserialize, Serialize};
use taproot_assets_types::asset::SerializedKey;
use taproot_assets_types::proof::{Proof, TxMerkleProof};
use thiserror::Error;

use crate::{OpsError, TaprootOps};

/// Errors returned by anchor transaction verification helpers.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The anchor transaction does not spend the claimed previous outpoint.
    #[error("anchor tx missing prev out")]
    AnchorTxMissingPrevOut,
    /// The claimed outpoint hash does not match the transaction hash.
    #[error("outpoint hash does not match tx hash")]
    OutpointHashMismatch,
    /// The claimed output index is invalid for the transaction.
    #[error("output index {index} invalid for {output_count} outputs")]
    OutputIndexInvalid {
        /// Claimed output index.
        index: u32,
        /// Total number of outputs in the transaction.
        output_count: usize,
    },
    /// The output script does not match the derived Taproot output key.
    #[error("output script does not match derived taproot output key")]
    OutputScriptMismatch,
    /// The merkle proof node and bit counts do not match.
    #[error("merkle proof shape mismatch: nodes={nodes}, bits={bits}")]
    InvalidMerkleProofShape {
        /// Number of merkle proof nodes.
        nodes: usize,
        /// Number of merkle proof bits.
        bits: usize,
    },
    /// The merkle proof does not match the expected root.
    #[error("invalid transaction merkle proof")]
    InvalidTxMerkleProof,
    /// The block header failed verification.
    #[error("invalid block header")]
    InvalidBlockHeader,
    /// Taproot output key bytes are invalid.
    #[error("invalid taproot output key")]
    InvalidTaprootOutputKey,
    /// Taproot operation failed.
    #[error(transparent)]
    Ops(#[from] OpsError),
}

/// Input for transaction merkle proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyMerkleProofInput {
    /// The transaction ID which is expected to be committed in the Merkle tree.
    pub txid: [u8; 32],
    /// The list of sibling hashes along the Merkle path from the transaction up to the root.
    pub nodes: Vec<[u8; 32]>,
    /// Direction bits: `false` means the node is on the left, `true` means on the right.
    pub bits: Vec<bool>,
    /// The expected Merkle root which commits to the transaction ID.
    pub merkle_root: [u8; 32],
}

/// Input for anchor claim verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorClaimInput {
    /// The anchor transaction.
    pub anchor_tx: Transaction,
    /// The merkle proof for the anchor transaction.
    pub tx_merkle_proof: TxMerkleProof,
    /// The block header committing to the anchor transaction.
    pub block_header: Header,
    /// The block height.
    pub block_height: u32,
    /// The previous outpoint spent by the anchor transaction.
    pub prev_out: OutPoint,
    /// The output index of the anchor transaction carrying the asset.
    pub output_index: u32,
}

/// Output digest for the anchor claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorClaimOutput {
    /// The transaction ID of the anchor transaction.
    pub anchor_txid: [u8; 32],
    /// The hash of the block header.
    pub block_hash: [u8; 32],
    /// The block height.
    pub block_height: u32,
    /// The output index.
    pub output_index: u32,
    /// The taproot output key derived from the anchor transaction output.
    pub taproot_output_key: [u8; 32],
    /// All P2TR outputs with their taproot output keys.
    pub p2tr_outputs: Vec<AnchorP2trOutput>,
}

/// Taproot output metadata extracted from the anchor transaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnchorP2trOutput {
    /// Output index in the anchor transaction.
    pub output_index: u32,
    /// The taproot output key for the P2TR output.
    pub taproot_output_key: [u8; 32],
}

/// Trait for hashing Merkle node pairs.
pub trait MerkleHasher {
    /// Hashes a left/right node pair into its parent.
    fn hash_nodes(&self, left: [u8; 32], right: [u8; 32]) -> [u8; 32];
}

/// Bitcoin merkle hasher using double-SHA-256.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitcoinMerkleHasher;

impl MerkleHasher for BitcoinMerkleHasher {
    /// Hashes a node pair with double-SHA-256.
    fn hash_nodes(&self, left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
        let mut buf = [0u8; 64];
        buf[..32].copy_from_slice(&left);
        buf[32..].copy_from_slice(&right);
        Sha256dHash::hash(&buf).to_byte_array()
    }
}

/// Trait for verifying a block header at a given height.
pub trait HeaderVerifier {
    /// Returns true if the header is valid for the provided height.
    fn verify_header(&self, header: &Header, height: u32) -> bool;
}

/// Verifies the anchor transaction against its merkle proof and block header.
pub fn verify_anchor_tx<H: HeaderVerifier>(proof: &Proof, verifier: &H) -> Result<(), Error> {
    if !tx_spends_prev_out(&proof.anchor_tx, &proof.prev_out) {
        return Err(Error::AnchorTxMissingPrevOut);
    }

    verify_tx_merkle_proof(
        &proof.anchor_tx,
        &proof.tx_merkle_proof,
        proof.block_header.merkle_root,
    )?;

    if !verifier.verify_header(&proof.block_header, proof.block_height) {
        return Err(Error::InvalidBlockHeader);
    }

    Ok(())
}

/// Verifies the anchor claim and returns the output digest.
pub fn verify_anchor_claim_with_hasher<H: MerkleHasher>(
    input: &AnchorClaimInput,
    hasher: &H,
) -> Result<AnchorClaimOutput, Error> {
    if !tx_spends_prev_out(&input.anchor_tx, &input.prev_out) {
        return Err(Error::AnchorTxMissingPrevOut);
    }

    let nodes: Vec<[u8; 32]> = input
        .tx_merkle_proof
        .nodes
        .iter()
        .map(|node| node.to_byte_array())
        .collect();

    verify_tx_merkle_proof_with_hasher(
        input.anchor_tx.compute_txid().to_byte_array(),
        &nodes,
        &input.tx_merkle_proof.bits,
        input.block_header.merkle_root.to_byte_array(),
        hasher,
    )?;

    if input.output_index as usize >= input.anchor_tx.output.len() {
        return Err(Error::OutputIndexInvalid {
            index: input.output_index,
            output_count: input.anchor_tx.output.len(),
        });
    }

    let output = &input.anchor_tx.output[input.output_index as usize];
    let taproot_output_key = extract_taproot_output_key(output.script_pubkey.as_script())?;
    let mut p2tr_outputs = Vec::new();
    for (idx, output) in input.anchor_tx.output.iter().enumerate() {
        if output.script_pubkey.is_p2tr() {
            let taproot_output_key = extract_taproot_output_key(output.script_pubkey.as_script())?;
            p2tr_outputs.push(AnchorP2trOutput {
                output_index: idx as u32,
                taproot_output_key,
            });
        }
    }

    Ok(AnchorClaimOutput {
        anchor_txid: input.anchor_tx.compute_txid().to_byte_array(),
        block_hash: input.block_header.block_hash().to_byte_array(),
        block_height: input.block_height,
        output_index: input.output_index,
        taproot_output_key,
        p2tr_outputs,
    })
}

/// Verifies that a claimed outpoint matches a transaction and Taproot output.
pub fn verify_tx_outpoint<O: TaprootOps>(
    ops: &O,
    tx: &Transaction,
    outpoint: &OutPoint,
    internal_key: &SerializedKey,
    tapscript_root: Option<[u8; 32]>,
) -> Result<(), Error> {
    if outpoint.txid != tx.compute_txid() {
        return Err(Error::OutpointHashMismatch);
    }

    if outpoint.vout as usize >= tx.output.len() {
        return Err(Error::OutputIndexInvalid {
            index: outpoint.vout,
            output_count: tx.output.len(),
        });
    }

    let output = &tx.output[outpoint.vout as usize];
    let expected_key = derive_taproot_output_key(ops, internal_key, tapscript_root)?;
    let expected_xonly = xonly_from_serialized_key(&expected_key)?;
    let claimed_xonly = extract_taproot_output_key(output.script_pubkey.as_script())?;

    if expected_xonly == claimed_xonly {
        Ok(())
    } else {
        Err(Error::OutputScriptMismatch)
    }
}

/// Verifies a merkle proof for the given transaction and merkle root.
pub fn verify_tx_merkle_proof(
    tx: &Transaction,
    proof: &TxMerkleProof,
    merkle_root: TxMerkleNode,
) -> Result<(), Error> {
    let nodes: Vec<[u8; 32]> = proof
        .nodes
        .iter()
        .map(|node| node.to_byte_array())
        .collect();
    verify_tx_merkle_proof_with_hasher(
        tx.compute_txid().to_byte_array(),
        &nodes,
        &proof.bits,
        merkle_root.to_byte_array(),
        &BitcoinMerkleHasher,
    )
}

/// Verifies a merkle proof described by a minimal input payload.
pub fn verify_tx_merkle_proof_input(input: &VerifyMerkleProofInput) -> Result<(), Error> {
    verify_tx_merkle_proof_input_with_hasher(input, &BitcoinMerkleHasher)
}

/// Verifies a merkle proof input using a caller-provided node hasher.
pub fn verify_tx_merkle_proof_input_with_hasher<H: MerkleHasher>(
    input: &VerifyMerkleProofInput,
    hasher: &H,
) -> Result<(), Error> {
    verify_tx_merkle_proof_with_hasher(
        input.txid,
        &input.nodes,
        &input.bits,
        input.merkle_root,
        hasher,
    )
}

/// Verifies a merkle proof using a caller-provided node hasher.
pub fn verify_tx_merkle_proof_with_hasher<H: MerkleHasher>(
    txid: [u8; 32],
    nodes: &[[u8; 32]],
    bits: &[bool],
    merkle_root: [u8; 32],
    hasher: &H,
) -> Result<(), Error> {
    if nodes.len() != bits.len() {
        return Err(Error::InvalidMerkleProofShape {
            nodes: nodes.len(),
            bits: bits.len(),
        });
    }

    let mut current = txid;
    for (node, is_right) in nodes.iter().zip(bits.iter()) {
        let (left, right) = if *is_right {
            (current, *node)
        } else {
            (*node, current)
        };
        current = hasher.hash_nodes(left, right);
    }

    if current == merkle_root {
        Ok(())
    } else {
        Err(Error::InvalidTxMerkleProof)
    }
}

/// Returns true if the transaction spends the specified outpoint.
pub fn tx_spends_prev_out(tx: &Transaction, prev_out: &OutPoint) -> bool {
    tx.input
        .iter()
        .any(|input| input.previous_output == *prev_out)
}

/// Derives a Taproot output key from an internal key and tapscript root.
fn derive_taproot_output_key<O: TaprootOps>(
    ops: &O,
    internal_key: &SerializedKey,
    tapscript_root: Option<[u8; 32]>,
) -> Result<SerializedKey, Error> {
    let internal = ops.parse_internal_key(internal_key)?;
    ops.taproot_output_key(&internal, tapscript_root)
        .map_err(Error::from)
}

/// Extracts the x-only taproot output key from a P2TR script.
fn extract_taproot_output_key(script: &Script) -> Result<[u8; 32], Error> {
    if !script.is_p2tr() {
        return Err(Error::OutputScriptMismatch);
    }

    let bytes = script.as_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes[2..34]);
    Ok(key_bytes)
}

/// Extracts an x-only key from a serialized compressed public key.
fn xonly_from_serialized_key(key: &SerializedKey) -> Result<[u8; 32], Error> {
    match key.bytes[0] {
        0x02 | 0x03 => {
            let mut xonly = [0u8; 32];
            xonly.copy_from_slice(&key.bytes[1..]);
            Ok(xonly)
        }
        _ => Err(Error::InvalidTaprootOutputKey),
    }
}
