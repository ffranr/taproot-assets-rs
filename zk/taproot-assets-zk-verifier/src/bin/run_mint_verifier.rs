use risc0_zkvm::{default_prover, ExecutorEnv};
use std::path::Path;
use taproot_assets_types as types;

use bincode::config::standard;
use bincode::serde::decode_from_slice;

use taproot_assets_zk_core as core;

use bitcoin::hashes::Hash;

fn main() -> anyhow::Result<()> {
    // Read the proof from a file.
    let proof_file_path = "/home/user/dev/tmp/itest-proof.bin";
    let proof_bytes = std::fs::read(proof_file_path)?;
    let (asset_state_proof, _) =
        decode_from_slice::<types::proof::Proof, _>(&proof_bytes, standard())?;

    let anchor_info = asset_state_proof.asset.chain_anchor.unwrap();

    println!(
        "number of proof nodes: {}",
        asset_state_proof.tx_merkle_proof.nodes.len()
    );
    println!(
        "number of proof direction bits: {}",
        asset_state_proof.tx_merkle_proof.bits.len()
    );

    let input = core::mint::GuestInput {
        txid: anchor_info.anchor_tx.compute_txid().to_byte_array(),
        proof: core::mint::TxMerkleProof {
            nodes: asset_state_proof
                .tx_merkle_proof
                .nodes
                .into_iter()
                .map(|node| node.to_byte_array())
                .collect(),
            bits: vec![false], //asset_state_proof.tx_merkle_proof.bits,
        },
        merkle_root: anchor_info.merkle_root.to_byte_array(),
    };

    let ok = core::mint::verify_tx_merkle_proof(&input);
    println!("Proof verified? {ok}");

    // // Executor environment (the bytes become guest stdin).
    // let env = ExecutorEnv::builder()
    //     .write(&input)?
    //     .build()?;

    // // Run the guest ELF.
    // let elf = std::fs::read(Path::new(
    //     "target/riscv32im-risc0-zkvm-elf/docker/mint-prover.bin",
    // ))?;

    // let prover = default_prover();
    // let receipt = prover.prove(env, &elf)?;

    // // Decode the journal (bool).
    // let (ok, _bytes_used) =
    //     decode_from_slice::<bool, _>(&receipt.receipt.journal.bytes, standard())?;
    // println!("Proof verified? {ok}");

    Ok(())
}
