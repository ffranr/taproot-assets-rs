use std::path::PathBuf;

use anyhow::{Context, Result};
use taproot_assets_types as types;
use taproot_assets_zk_core::verify::proof_chain::{
    verify_proof_chain_claim, Error, ProofChainClaimInput, ProofChainEntryInput,
};

const PROOF_FILE_VECTOR: &str =
    "../../external/taproot-assets-upstream/proof/testdata/proof-file.hex";

#[test]
fn proof_chain_claim_matches_vector() -> Result<()> {
    let Some(file) = load_vector_file()? else {
        eprintln!("skipping proof-chain test: vector file missing");
        return Ok(());
    };
    let input = ProofChainClaimInput::from_file(&file);
    let output = verify_proof_chain_claim(&input)
        .map_err(|err| anyhow::anyhow!("proof-chain claim failed: {err}"))?;

    assert_eq!(output.proof_file_version, file.version);
    assert_eq!(output.proof_count as usize, file.proofs.len());
    let expected_tip = file
        .proofs
        .last()
        .map(|proof| proof.hash)
        .unwrap_or([0u8; 32]);
    assert_eq!(output.last_proof_checksum, expected_tip);
    assert_eq!(
        output.last_proof_outpoint.is_some(),
        !file.proofs.is_empty()
    );
    Ok(())
}

#[test]
fn proof_chain_claim_rejects_checksum_mismatch() -> Result<()> {
    let Some(file) = load_vector_file()? else {
        eprintln!("skipping proof-chain checksum test: vector file missing");
        return Ok(());
    };
    if file.proofs.is_empty() {
        eprintln!("skipping proof-chain checksum test: vector file empty");
        return Ok(());
    }

    let mut input = ProofChainClaimInput::from_file(&file);
    input.entries[0].proof_checksum[0] ^= 0x01;

    let err = verify_proof_chain_claim(&input).expect_err("expected checksum mismatch");
    assert_eq!(err, Error::ChecksumMismatch { index: 0 });
    Ok(())
}

#[test]
fn proof_chain_claim_rejects_prev_out_break() -> Result<()> {
    let Some(file) = load_vector_file()? else {
        eprintln!("skipping proof-chain prev-out test: vector file missing");
        return Ok(());
    };
    if file.proofs.is_empty() {
        eprintln!("skipping proof-chain prev-out test: vector file empty");
        return Ok(());
    }

    let proof_bytes = file.proofs[0].proof_bytes.clone();
    let first_checksum = hash_proof(&proof_bytes, [0u8; 32]);
    let second_checksum = hash_proof(&proof_bytes, first_checksum);
    let input = ProofChainClaimInput {
        proof_file_version: file.version,
        entries: vec![
            ProofChainEntryInput {
                proof_bytes: proof_bytes.clone(),
                proof_checksum: first_checksum,
            },
            ProofChainEntryInput {
                proof_bytes,
                proof_checksum: second_checksum,
            },
        ],
    };

    let err = verify_proof_chain_claim(&input).expect_err("expected prev_out mismatch");
    assert_eq!(err, Error::PrevOutChainMismatch { index: 1 });
    Ok(())
}

fn load_vector_file() -> Result<Option<types::proof::File>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(PROOF_FILE_VECTOR);
    if !path.exists() {
        return Ok(None);
    }
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let stripped: String = contents.split_whitespace().collect();
    let bytes =
        hex::decode(stripped).with_context(|| format!("failed to decode {}", path.display()))?;
    let file = types::proof::File::from_bytes(&bytes)
        .with_context(|| format!("failed to decode {}", path.display()))?;
    Ok(Some(file))
}

fn hash_proof(proof_bytes: &[u8], prev_hash: [u8; 32]) -> [u8; 32] {
    use bitcoin::hashes::{sha256, Hash};

    let mut preimage = Vec::with_capacity(32 + proof_bytes.len());
    preimage.extend_from_slice(&prev_hash);
    preimage.extend_from_slice(proof_bytes);
    sha256::Hash::hash(&preimage).to_byte_array()
}
