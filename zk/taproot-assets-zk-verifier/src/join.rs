//! Join proof helpers used by binaries and tests.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use risc0_zkvm::{ExecutorEnv, Receipt};
use taproot_assets_core::verify::proof::{AssetClaimInput, StxoClaimInput, TaprootClaimInput};
use taproot_assets_types as types;
use taproot_assets_zk_core as zk_core;
use zk_core::verify::join::{JoinInput, JoinOutput, ReceiptClaimInput};
use zk_core::verify::tx::AnchorClaimInput;

/// ELF bundle used to generate claim receipts.
#[derive(Debug, Clone)]
pub struct ClaimElfs {
    pub anchor: Vec<u8>,
    pub taproot: Vec<u8>,
    pub stxo: Vec<u8>,
    pub asset: Vec<u8>,
    pub proof_chain: Vec<u8>,
    pub join: Vec<u8>,
}

impl ClaimElfs {
    /// Loads claim ELF binaries from the default target directory.
    pub fn load_default() -> Result<Self> {
        let dir = default_elf_dir();
        Self::load_from_dir(&dir)
    }

    /// Loads claim ELF binaries from a directory.
    pub fn load_from_dir(dir: &Path) -> Result<Self> {
        let anchor = read_elf(dir, "anchor-claim-prover.bin")?;
        let taproot = read_elf(dir, "taproot-commitment-prover.bin")?;
        let stxo = read_elf(dir, "stxo-claim-prover.bin")?;
        let asset = read_elf(dir, "asset-claim-prover.bin")?;
        let proof_chain = read_elf(dir, "proof-chain-claim-prover.bin")?;
        let join = read_elf(dir, "join-prover.bin")?;
        Ok(Self {
            anchor,
            taproot,
            stxo,
            asset,
            proof_chain,
            join,
        })
    }
}

/// Returns the default ELF directory relative to the workspace root.
pub fn default_elf_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/riscv32im-risc0-zkvm-elf/docker")
}

/// Result returned by the join prover host flow.
#[derive(Debug, Clone)]
pub struct JoinProofResult {
    pub output: JoinOutput,
    pub receipt: Receipt,
}

/// Proves all claims for a proof entry and returns the join output.
pub fn prove_join(
    prover: &dyn risc0_zkvm::Prover,
    proof: &types::proof::Proof,
    elfs: &ClaimElfs,
) -> Result<JoinOutput> {
    Ok(prove_join_with_receipt(prover, proof, elfs)?.output)
}

/// Proves all claims for a proof entry and returns the join output + receipt.
pub fn prove_join_with_receipt(
    prover: &dyn risc0_zkvm::Prover,
    proof: &types::proof::Proof,
    elfs: &ClaimElfs,
) -> Result<JoinProofResult> {
    // Build and run anchor claim.
    let anchor_input = AnchorClaimInput {
        anchor_tx: proof.anchor_tx.clone(),
        tx_merkle_proof: proof.tx_merkle_proof.clone(),
        block_header: proof.block_header,
        block_height: proof.block_height,
        prev_out: proof.prev_out,
        output_index: proof.inclusion_proof.output_index,
    };
    let anchor_receipt = prove(prover, &elfs.anchor, &anchor_input)?;
    let anchor_output: zk_core::verify::tx::AnchorClaimOutput = anchor_receipt.journal.decode()?;

    let mut expected_output_keys = BTreeMap::new();
    for output in &anchor_output.p2tr_outputs {
        expected_output_keys.insert(output.output_index, output.taproot_output_key);
    }

    let mut taproot_claims = Vec::new();
    let mut taproot_receipts = Vec::new();
    let mut stxo_claims = Vec::new();
    let mut stxo_receipts = Vec::new();
    let mut split_root_claim = None;
    let mut split_root_receipt = None;

    // Build and run taproot commitment claim (inclusion).
    let taproot_input = TaprootClaimInput {
        taproot_proof: proof.inclusion_proof.clone(),
        asset: proof.asset.clone(),
        expected_taproot_output_key: anchor_output.taproot_output_key,
        inclusion: true,
    };
    let taproot_receipt = prove(prover, &elfs.taproot, &taproot_input)?;
    taproot_claims.push(receipt_claim_input(&taproot_receipt, "taproot inclusion")?);
    taproot_receipts.push(taproot_receipt);

    // Build and run STXO claim (inclusion).
    let stxo_input = StxoClaimInput {
        taproot_proof: proof.inclusion_proof.clone(),
        asset: proof.asset.clone(),
        proof_version: proof.version,
        expected_taproot_output_key: anchor_output.taproot_output_key,
        inclusion: true,
    };
    let stxo_receipt = prove(prover, &elfs.stxo, &stxo_input)?;
    stxo_claims.push(receipt_claim_input(&stxo_receipt, "stxo inclusion")?);
    stxo_receipts.push(stxo_receipt);

    // Build and run taproot + STXO claims for all exclusion proofs.
    for exclusion_proof in &proof.exclusion_proofs {
        let output_index = exclusion_proof.output_index;
        let expected_key = *expected_output_keys
            .get(&output_index)
            .with_context(|| format!("missing expected key for exclusion output {output_index}"))?;

        let taproot_input = TaprootClaimInput {
            taproot_proof: exclusion_proof.clone(),
            asset: proof.asset.clone(),
            expected_taproot_output_key: expected_key,
            inclusion: false,
        };
        let taproot_receipt = prove(prover, &elfs.taproot, &taproot_input)?;
        taproot_claims.push(receipt_claim_input(&taproot_receipt, "taproot exclusion")?);
        taproot_receipts.push(taproot_receipt);

        let stxo_input = StxoClaimInput {
            taproot_proof: exclusion_proof.clone(),
            asset: proof.asset.clone(),
            proof_version: proof.version,
            expected_taproot_output_key: expected_key,
            inclusion: false,
        };
        let stxo_receipt = prove(prover, &elfs.stxo, &stxo_input)?;
        stxo_claims.push(receipt_claim_input(&stxo_receipt, "stxo exclusion")?);
        stxo_receipts.push(stxo_receipt);
    }

    // Build and run optional split-root taproot claim.
    if let Some(split_root_proof) = proof.split_root_proof.as_ref() {
        let root_asset = split_root_asset(proof)?;
        let output_index = split_root_proof.output_index;
        let expected_key = *expected_output_keys.get(&output_index).with_context(|| {
            format!("missing expected key for split-root output {output_index}")
        })?;

        let taproot_input = TaprootClaimInput {
            taproot_proof: split_root_proof.clone(),
            asset: root_asset.clone(),
            expected_taproot_output_key: expected_key,
            inclusion: true,
        };
        let taproot_receipt = prove(prover, &elfs.taproot, &taproot_input)?;
        split_root_claim = Some(receipt_claim_input(&taproot_receipt, "split-root taproot")?);
        split_root_receipt = Some(taproot_receipt);
    }

    // Build and run asset integrity claim.
    let asset_input = AssetClaimInput::from_proof(proof);
    let asset_receipt = prove(prover, &elfs.asset, &asset_input)?;

    // Build join input from all receipt claims.
    let join_input = JoinInput {
        anchor: receipt_claim_input(&anchor_receipt, "anchor")?,
        asset: receipt_claim_input(&asset_receipt, "asset")?,
        taproot_claims,
        stxo_claims,
        split_root: split_root_claim,
    };

    let mut join_env = ExecutorEnv::builder();
    join_env.write(&join_input)?;
    join_env.add_assumption(anchor_receipt);
    join_env.add_assumption(asset_receipt);
    for receipt in taproot_receipts {
        join_env.add_assumption(receipt);
    }
    for receipt in stxo_receipts {
        join_env.add_assumption(receipt);
    }
    if let Some(receipt) = split_root_receipt {
        join_env.add_assumption(receipt);
    }
    let join_env = join_env.build()?;
    let join_receipt = prover.prove(join_env, &elfs.join)?.receipt;
    let join_output: JoinOutput = join_receipt.journal.decode()?;
    Ok(JoinProofResult {
        output: join_output,
        receipt: join_receipt,
    })
}

fn prove<T: serde::Serialize>(
    prover: &dyn risc0_zkvm::Prover,
    elf: &[u8],
    input: &T,
) -> Result<Receipt> {
    let env = ExecutorEnv::builder().write(input)?.build()?;
    Ok(prover.prove(env, elf)?.receipt)
}

fn receipt_claim_input(receipt: &Receipt, label: &'static str) -> Result<ReceiptClaimInput> {
    let claim = receipt
        .claim()?
        .value()
        .with_context(|| format!("{label} claim is pruned"))?;
    Ok(ReceiptClaimInput { claim })
}

fn split_root_asset(proof: &types::proof::Proof) -> Result<&types::asset::Asset> {
    let witness = proof
        .asset
        .prev_witnesses
        .first()
        .context("split-root proof missing prev witness")?;
    let split_commitment = witness
        .split_commitment
        .as_ref()
        .context("split-root proof missing split commitment")?;
    Ok(split_commitment.root_asset.as_ref())
}

fn read_elf(dir: &Path, file: &str) -> Result<Vec<u8>> {
    let path = dir.join(file);
    std::fs::read(&path).with_context(|| format!("failed to read ELF {}", path.display()))
}
