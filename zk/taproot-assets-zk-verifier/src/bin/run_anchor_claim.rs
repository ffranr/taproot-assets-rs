use std::path::Path;

use rayon::ThreadPoolBuilder;
use risc0_zkvm::{ExecutorEnv, default_prover};
use taproot_assets_types as types;
use taproot_assets_zk_core as zk_core;

/// Runs the anchor claim verifier against the first proof in the local proof file.
fn main() -> anyhow::Result<()> {
    let (available_threads, desired_threads) = thread_counts();
    let pool = ThreadPoolBuilder::new()
        .num_threads(desired_threads)
        .build()?;
    pool.install(|| run(desired_threads, available_threads))
}

fn run(desired_threads: usize, available_threads: usize) -> anyhow::Result<()> {
    println!(
        "rayon threads: {} (desired {}, available {})",
        rayon::current_num_threads(),
        desired_threads,
        available_threads
    );

    // Read the proof from a file.
    let home = std::env::var("HOME")?;
    let proof_file_path = format!("{}/dev/tmp/itest-proof-file.bin", home);
    let proof_file_bytes = std::fs::read(proof_file_path)?;

    let proof_file = types::proof::File::from_bytes(&proof_file_bytes)?;

    println!("number of proofs: {}", proof_file.proofs.len());

    let hashed_proof = &proof_file.proofs[0];
    let proof = types::proof::Proof::from_bytes(&hashed_proof.proof_bytes)?;

    let block_merkle_root = proof.block_header.merkle_root;
    println!("block merkle root: {}", block_merkle_root);

    let merkle_proof_node = proof.tx_merkle_proof.nodes[0];
    println!("merkle proof node: {}", merkle_proof_node);

    let txid = proof.anchor_tx.compute_txid();
    println!("anchor txid: {}", txid);

    let input = zk_core::verify::tx::AnchorClaimInput {
        anchor_tx: proof.anchor_tx.clone(),
        tx_merkle_proof: proof.tx_merkle_proof.clone(),
        block_header: proof.block_header,
        block_height: proof.block_height,
        prev_out: proof.prev_out,
        output_index: proof.inclusion_proof.output_index,
    };

    let output = zk_core::verify::tx::verify_anchor_claim(&input)?;
    println!("anchor claim verified? true");
    println!("anchor claim host output: {:?}", output);

    let prover = default_prover();
    let elf = std::fs::read(Path::new(
        "target/riscv32im-risc0-zkvm-elf/docker/anchor-claim-prover.bin",
    ))?;
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let receipt = prover.prove(env, &elf)?.receipt;
    let output: zk_core::verify::tx::AnchorClaimOutput = receipt.journal.decode()?;
    println!("anchor claim receipt ok? true");
    println!("receipt output: {:?}", output);

    Ok(())
}

fn thread_counts() -> (usize, usize) {
    let available = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let desired = available.saturating_sub(3).max(1);
    (available, desired)
}
