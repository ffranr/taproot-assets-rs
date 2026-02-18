//! -----------------------------------------------------
//! Guest program (RISC Zero) that verifies claim receipts and commits
//! a combined result after checking consistency and coverage.
//!
//! • Expects a single bincode-encoded `JoinInput` from the host
//! • Verifies anchor, asset, taproot, stxo, and optional split-root receipts
//! • Checks taproot output key consistency and coverage for all P2TR outputs
//! • Commits `JoinOutput` with combined claim data
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-12-15 risczero build \
//!       -p join-prover --release \
//!       --target riscv32im-risc0-zkvm-elf
//! -----------------------------------------------------

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use risc0_zkvm::ReceiptClaim;
use risc0_zkvm::guest::{entry, env};
use risc0_zkvm::serde::from_slice;
use taproot_assets_zk_core::verify::join::JoinInput;
use taproot_assets_zk_core::verify::join::JoinOutput;
use taproot_assets_zk_core::verify::proof::{
    AssetClaimOutput, StxoClaimOutput, TaprootClaimOutput,
};
use taproot_assets_zk_core::verify::tx::AnchorClaimOutput;

entry!(main);

/// Entry point for the join prover guest.
fn main() {
    let input: JoinInput = env::read();

    // Verify anchor and asset claims.
    env::verify_integrity(&input.anchor.claim).expect("anchor claim integrity failed");
    let anchor_output: AnchorClaimOutput =
        decode_journal(&input.anchor.claim).expect("anchor claim decode failed");

    env::verify_integrity(&input.asset.claim).expect("asset claim integrity failed");
    let asset_output: AssetClaimOutput =
        decode_journal(&input.asset.claim).expect("asset claim decode failed");

    // Build expected output map from anchor claim.
    let mut expected_outputs = BTreeMap::new();
    for output in &anchor_output.p2tr_outputs {
        if expected_outputs
            .insert(output.output_index, output.taproot_output_key)
            .is_some()
        {
            panic!("duplicate anchor output index");
        }
    }
    if expected_outputs.is_empty() {
        panic!("anchor claim reported no p2tr outputs");
    }

    // Decode taproot claim receipts and enforce coverage.
    let mut taproot_claims = BTreeMap::new();
    for claim in &input.taproot_claims {
        env::verify_integrity(&claim.claim).expect("taproot claim integrity failed");
        let output: TaprootClaimOutput =
            decode_journal(&claim.claim).expect("taproot claim decode failed");
        let expected_key = expected_outputs
            .get(&output.output_index)
            .expect("taproot claim output index missing");
        assert_eq!(
            &output.taproot_output_key, expected_key,
            "taproot output key mismatch"
        );
        if taproot_claims.insert(output.output_index, output).is_some() {
            panic!("duplicate taproot claim output index");
        }
    }

    if taproot_claims.is_empty() {
        panic!("missing taproot claims");
    }

    if taproot_claims.len() != expected_outputs.len() {
        panic!("taproot claim coverage mismatch");
    }
    for output_index in expected_outputs.keys() {
        if !taproot_claims.contains_key(output_index) {
            panic!("missing taproot claim for output");
        }
    }

    let inclusion_output = taproot_claims
        .get(&anchor_output.output_index)
        .expect("missing inclusion taproot claim");

    // Decode STXO claim receipts and enforce coverage when required.
    let mut stxo_claims = BTreeMap::new();
    for claim in &input.stxo_claims {
        env::verify_integrity(&claim.claim).expect("stxo claim integrity failed");
        let output: StxoClaimOutput =
            decode_journal(&claim.claim).expect("stxo claim decode failed");
        let expected_key = expected_outputs
            .get(&output.output_index)
            .expect("stxo claim output index missing");
        assert_eq!(
            &output.taproot_output_key, expected_key,
            "stxo output key mismatch"
        );
        if stxo_claims.insert(output.output_index, output).is_some() {
            panic!("duplicate stxo claim output index");
        }
    }

    if asset_output.stxo_required {
        if stxo_claims.len() != taproot_claims.len() {
            panic!("stxo claim coverage mismatch");
        }
        for output_index in taproot_claims.keys() {
            if !stxo_claims.contains_key(output_index) {
                panic!("missing stxo claim for output");
            }
        }
    }

    // Verify optional split-root claim if present/required.
    if let Some(split_root) = &input.split_root {
        env::verify_integrity(&split_root.claim).expect("split-root claim integrity failed");
        let output: TaprootClaimOutput =
            decode_journal(&split_root.claim).expect("split-root claim decode failed");
        let expected_key = expected_outputs
            .get(&output.output_index)
            .expect("split-root output index missing");
        assert_eq!(
            &output.taproot_output_key, expected_key,
            "split-root output key mismatch"
        );
    } else if asset_output.has_split_commitment {
        panic!("missing split-root claim");
    }

    // Build combined output.
    let output = JoinOutput {
        anchor_txid: anchor_output.anchor_txid,
        block_hash: anchor_output.block_hash,
        block_height: anchor_output.block_height,
        taproot_output_key: anchor_output.taproot_output_key,
        tap_commitment_root: inclusion_output.tap_commitment.root_hash,
        tap_commitment_sum: inclusion_output.tap_commitment.root_sum,
        asset_id: asset_output.asset_id,
        group_key: asset_output.group_key,
        meta_hash: asset_output.meta_hash,
        proof_version: asset_output.proof_version,
    };

    env::commit(&output);
}

/// Decodes the journal from a receipt claim.
fn decode_journal<T: serde::de::DeserializeOwned>(claim: &ReceiptClaim) -> Option<T> {
    let output = claim.output.as_value().ok()?;
    let output = output.as_ref()?;
    let journal = output.journal.as_value().ok()?;
    from_slice::<T, u8>(journal).ok()
}
