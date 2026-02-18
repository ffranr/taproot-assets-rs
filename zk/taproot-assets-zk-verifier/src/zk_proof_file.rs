//! Host helpers for building and encoding ZkProofFile artifacts.

use anyhow::{anyhow, Context, Result};
use bincode::{
    config::standard,
    serde::{decode_from_slice, encode_to_vec},
};
use risc0_zkvm::{ExecutorEnv, Receipt};
use taproot_assets_types as types;
use taproot_assets_zk_core::verify::proof_chain::{ProofChainClaimInput, ProofChainClaimOutput};
use taproot_assets_zk_core::verify::zk_proof_file::{
    ZkProofFile, ZkProofFileEntry, ZK_PROOF_FILE_MAGIC,
};

use crate::join::{prove_join_with_receipt, ClaimElfs};

/// Proves all entries in a proof file and builds a ZkProofFile artifact.
pub fn prove_zk_proof_file(
    prover: &dyn risc0_zkvm::Prover,
    proof_file: &types::proof::File,
    elfs: &ClaimElfs,
) -> Result<ZkProofFile> {
    let proof_chain_input = ProofChainClaimInput::from_file(proof_file);
    let proof_chain_receipt = prove(prover, &elfs.proof_chain, &proof_chain_input)
        .context("failed to prove proof-chain claim")?;
    let proof_chain_output: ProofChainClaimOutput = proof_chain_receipt
        .journal
        .decode()
        .context("failed to decode proof-chain claim output")?;
    let proof_chain_receipt = encode_to_vec(&proof_chain_receipt, standard())
        .context("failed to encode proof-chain receipt")?;

    let mut entries = Vec::with_capacity(proof_file.proofs.len());

    for (index, hashed_proof) in proof_file.proofs.iter().enumerate() {
        let proof = types::proof::Proof::from_bytes(&hashed_proof.proof_bytes)
            .with_context(|| format!("failed to decode proof at index {index}"))?;
        let join_result = prove_join_with_receipt(prover, &proof, elfs)
            .with_context(|| format!("failed to prove join for proof index {index}"))?;
        let join_receipt = encode_to_vec(&join_result.receipt, standard())
            .with_context(|| format!("failed to encode join receipt for proof index {index}"))?;

        entries.push(ZkProofFileEntry {
            proof_index: index as u32,
            proof_checksum: hashed_proof.hash,
            join_output: join_result.output,
            join_receipt,
        });
    }

    let chain_tip = proof_file
        .proofs
        .last()
        .map(|proof| proof.hash)
        .unwrap_or([0u8; 32]);
    let zk_proof_file = ZkProofFile::new(
        proof_file.version,
        chain_tip,
        proof_chain_output,
        proof_chain_receipt,
        entries,
    );
    zk_proof_file
        .validate_basic()
        .map_err(|err| anyhow!("invalid zk proof-file artifact: {err}"))?;
    Ok(zk_proof_file)
}

fn prove<T: serde::Serialize>(
    prover: &dyn risc0_zkvm::Prover,
    elf: &[u8],
    input: &T,
) -> Result<Receipt> {
    let env = ExecutorEnv::builder().write(input)?.build()?;
    Ok(prover.prove(env, elf)?.receipt)
}

/// Encodes a ZkProofFile artifact as:
/// `magic(4 bytes) || bincode(v2 serde payload)`.
pub fn encode_zk_proof_file_blob(zk_proof_file: &ZkProofFile) -> Result<Vec<u8>> {
    zk_proof_file
        .validate_basic()
        .map_err(|err| anyhow!("invalid zk proof-file artifact: {err}"))?;

    let payload =
        encode_to_vec(zk_proof_file, standard()).context("failed to encode zk proof-file")?;
    let mut blob = Vec::with_capacity(ZK_PROOF_FILE_MAGIC.len() + payload.len());
    blob.extend_from_slice(&ZK_PROOF_FILE_MAGIC);
    blob.extend_from_slice(&payload);
    Ok(blob)
}

/// Decodes a ZkProofFile blob and validates structural invariants.
pub fn decode_zk_proof_file_blob(blob: &[u8]) -> Result<ZkProofFile> {
    if blob.len() < ZK_PROOF_FILE_MAGIC.len() {
        return Err(anyhow!("zk proof-file blob too short"));
    }
    if blob[..ZK_PROOF_FILE_MAGIC.len()] != ZK_PROOF_FILE_MAGIC {
        return Err(anyhow!("invalid zk proof-file blob magic"));
    }

    let payload = &blob[ZK_PROOF_FILE_MAGIC.len()..];
    let (zk_proof_file, read_bytes): (ZkProofFile, usize) =
        decode_from_slice(payload, standard()).context("failed to decode zk proof-file payload")?;
    if read_bytes != payload.len() {
        return Err(anyhow!(
            "zk proof-file payload has trailing bytes: decoded {read_bytes}, payload {}",
            payload.len()
        ));
    }

    zk_proof_file
        .validate_basic()
        .map_err(|err| anyhow!("invalid zk proof-file artifact: {err}"))?;
    Ok(zk_proof_file)
}

#[cfg(test)]
mod tests {
    use super::*;
    use taproot_assets_types::asset::SerializedKey;
    use taproot_assets_zk_core::verify::join::JoinOutput;
    use taproot_assets_zk_core::verify::proof_chain::ProofChainClaimOutput;

    fn sample_zk_proof_file() -> ZkProofFile {
        let entry = ZkProofFileEntry {
            proof_index: 0,
            proof_checksum: [1u8; 32],
            join_output: JoinOutput {
                anchor_txid: [2u8; 32],
                block_hash: [3u8; 32],
                block_height: 42,
                taproot_output_key: [4u8; 32],
                tap_commitment_root: [5u8; 32],
                tap_commitment_sum: 21,
                asset_id: [6u8; 32],
                group_key: Some(SerializedKey { bytes: [7u8; 33] }),
                meta_hash: Some([8u8; 32]),
                proof_version: 1,
            },
            join_receipt: vec![9u8; 8],
        };
        ZkProofFile::new(
            0,
            [10u8; 32],
            ProofChainClaimOutput {
                proof_file_version: 0,
                proof_count: 1,
                last_proof_checksum: [10u8; 32],
                last_proof_outpoint: None,
            },
            vec![11u8; 8],
            vec![entry],
        )
    }

    #[test]
    fn zk_proof_file_blob_round_trip() -> Result<()> {
        let zk_proof_file = sample_zk_proof_file();
        let blob = encode_zk_proof_file_blob(&zk_proof_file)?;
        let decoded = decode_zk_proof_file_blob(&blob)?;
        assert_eq!(decoded, zk_proof_file);
        Ok(())
    }
}
