use std::path::PathBuf;

use anyhow::{Context, Result};
use risc0_zkvm::default_prover;
use taproot_assets::verify::BitcoinTaprootOps;
use taproot_assets_core::verify::proof::{
    AssetClaimInput, TaprootClaimInput, verify_asset_claim_with_ops, verify_genesis_reveal,
    verify_proofs,
};
use taproot_assets_core::verify::tx::{
    AnchorClaimInput, BitcoinMerkleHasher, verify_anchor_claim_with_hasher,
};
use taproot_assets_types as types;
use taproot_assets_zk_core::verify::join::JoinOutput;
use taproot_assets_zk_verifier::join::{ClaimElfs, default_elf_dir, prove_join};

const VECTOR_HEX_FILES: &[&str] = &[
    "../../external/taproot-assets-upstream/proof/testdata/proof-file.hex",
    "../../external/taproot-assets-upstream/proof/testdata/proof.hex",
    "../../external/taproot-assets-upstream/proof/testdata/ownership-proof.hex",
];

#[test]
fn zk_join_matches_core_for_proof_file() -> Result<()> {
    if std::env::var("RUN_ZK_PARITY").is_err() {
        eprintln!("skipping ZK parity test: set RUN_ZK_PARITY=1 to enable");
        return Ok(());
    }

    let elfs = match ClaimElfs::load_from_dir(&default_elf_dir()) {
        Ok(elfs) => elfs,
        Err(err) => {
            eprintln!("skipping ZK parity test: {err}");
            return Ok(());
        }
    };

    let prover = default_prover();
    let proofs = load_proofs_from_vectors()?;
    let mut verified_any = false;

    for (index, proof) in proofs.into_iter().enumerate() {
        let ops = BitcoinTaprootOps::new();
        if verify_proofs(&ops, &proof).is_err() || verify_genesis_reveal(&proof).is_err() {
            eprintln!("skipping proof {index}: core verification failed");
            continue;
        }

        verified_any = true;
        let expected = expected_join_output(&ops, &proof)?;
        let actual = prove_join(&prover, &proof, &elfs)
            .with_context(|| format!("ZK join failed {index}"))?;

        assert_eq!(actual, expected, "join output mismatch for proof {index}");
    }

    if !verified_any {
        eprintln!("skipping ZK parity test: no vectors passed core verification");
    }

    Ok(())
}

fn expected_join_output(
    ops: &BitcoinTaprootOps,
    proof: &types::proof::Proof,
) -> Result<JoinOutput> {
    let anchor_input = AnchorClaimInput {
        anchor_tx: proof.anchor_tx.clone(),
        tx_merkle_proof: proof.tx_merkle_proof.clone(),
        block_header: proof.block_header,
        block_height: proof.block_height,
        prev_out: proof.prev_out,
        output_index: proof.inclusion_proof.output_index,
    };
    let anchor_output = verify_anchor_claim_with_hasher(&anchor_input, &BitcoinMerkleHasher)
        .map_err(|err| anyhow::anyhow!("anchor claim failed: {err}"))?;

    let taproot_input = TaprootClaimInput {
        taproot_proof: proof.inclusion_proof.clone(),
        asset: proof.asset.clone(),
        expected_taproot_output_key: anchor_output.taproot_output_key,
        inclusion: true,
    };
    let taproot_output =
        taproot_assets_core::verify::proof::verify_taproot_claim_with_ops(ops, &taproot_input)
            .map_err(|err| anyhow::anyhow!("taproot claim failed: {err}"))?;

    let asset_input = AssetClaimInput::from_proof(proof);
    let asset_output = verify_asset_claim_with_ops(ops, &asset_input)
        .map_err(|err| anyhow::anyhow!("asset claim failed: {err}"))?;

    Ok(JoinOutput {
        anchor_txid: anchor_output.anchor_txid,
        block_hash: anchor_output.block_hash,
        block_height: anchor_output.block_height,
        taproot_output_key: anchor_output.taproot_output_key,
        tap_commitment_root: taproot_output.tap_commitment.root_hash,
        tap_commitment_sum: taproot_output.tap_commitment.root_sum,
        asset_id: asset_output.asset_id,
        group_key: asset_output.group_key,
        meta_hash: asset_output.meta_hash,
        proof_version: asset_output.proof_version,
    })
}

fn load_proofs_from_vectors() -> Result<Vec<types::proof::Proof>> {
    let mut proofs = Vec::new();
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    for path in VECTOR_HEX_FILES {
        let full_path = base.join(path);
        if !full_path.exists() {
            eprintln!("skipping vector {path}: file not found");
            continue;
        }
        match load_proofs_from_hex(path) {
            Ok(mut loaded) => proofs.append(&mut loaded),
            Err(err) => eprintln!("skipping vector {path}: {err}"),
        }
    }
    Ok(proofs)
}

fn load_proofs_from_hex(relative_path: &str) -> Result<Vec<types::proof::Proof>> {
    let bytes = load_hex_bytes(relative_path)?;
    if let Ok(file) = types::proof::File::from_bytes(&bytes) {
        let mut proofs = Vec::new();
        for (index, hashed) in file.proofs.iter().enumerate() {
            let proof = types::proof::Proof::from_bytes(&hashed.proof_bytes)
                .with_context(|| format!("failed to decode proof {index} from {relative_path}"))?;
            proofs.push(proof);
        }
        return Ok(proofs);
    }

    let proof = types::proof::Proof::from_bytes(&bytes)
        .with_context(|| format!("failed to decode proof from {relative_path}"))?;
    Ok(vec![proof])
}

fn load_hex_bytes(relative_path: &str) -> Result<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let contents = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    let stripped: String = contents.split_whitespace().collect();
    hex::decode(stripped).with_context(|| format!("failed to decode hex {}", path.display()))
}
