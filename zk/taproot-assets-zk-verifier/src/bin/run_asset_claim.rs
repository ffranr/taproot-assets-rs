use std::path::Path;

use rayon::ThreadPoolBuilder;
use risc0_zkvm::{ExecutorEnv, default_prover};
use taproot_assets_types as types;
use taproot_assets_zk_core as zk_core;

/// Runs the asset claim verifier against the first proof in the local proof file.
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

    let input = zk_core::verify::proof::AssetClaimInput::from_proof(&proof);

    let output = zk_core::verify::proof::verify_asset_claim(&input)
        .map_err(|err| anyhow::anyhow!("asset claim verification failed: {}", err))?;
    println!("asset claim verified? true");
    println!("asset claim host output: {:?}", output);

    let prover = default_prover();
    let elf = std::fs::read(Path::new(
        "target/riscv32im-risc0-zkvm-elf/docker/asset-claim-prover.bin",
    ))?;
    let env = ExecutorEnv::builder().write(&input)?.build()?;
    let receipt = prover.prove(env, &elf)?.receipt;
    let output: zk_core::verify::proof::AssetClaimOutput = receipt.journal.decode()?;
    println!("asset claim receipt ok? true");
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
