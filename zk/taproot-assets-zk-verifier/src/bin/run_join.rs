use anyhow::Result;
use rayon::ThreadPoolBuilder;
use risc0_zkvm::default_prover;
use taproot_assets_types as types;
use taproot_assets_zk_verifier::join::{default_elf_dir, ClaimElfs};
use taproot_assets_zk_verifier::zk_proof_file::{encode_zk_proof_file_blob, prove_zk_proof_file};

/// Runs claim provers for a full proof entry and joins them with the join prover.
fn main() -> Result<()> {
    let (available_threads, desired_threads) = thread_counts();
    let pool = ThreadPoolBuilder::new()
        .num_threads(desired_threads)
        .build()?;
    pool.install(|| run(desired_threads, available_threads))
}

fn run(desired_threads: usize, available_threads: usize) -> Result<()> {
    println!(
        "rayon threads: {} (desired {}, available {})",
        rayon::current_num_threads(),
        desired_threads,
        available_threads
    );

    // Read the proof from a file.
    let home = std::env::var("HOME")?;
    let proof_file_path = format!("{}/dev/tmp/itest-proof-file.bin", home);
    let proof_file_bytes = std::fs::read(&proof_file_path)?;
    let proof_file = types::proof::File::from_bytes(&proof_file_bytes)?;

    println!("number of proofs: {}", proof_file.proofs.len());

    let prover = default_prover();
    let elf_dir = default_elf_dir();
    let elfs = ClaimElfs::load_from_dir(&elf_dir)?;

    println!("Running join prover for all proof-file entries...");
    let zk_proof_file = prove_zk_proof_file(&prover, &proof_file, &elfs)?;
    let zk_proof_file_digest = zk_proof_file.artifact_digest();
    let zk_proof_file_blob = encode_zk_proof_file_blob(&zk_proof_file)?;
    let output_path = format!("{}/dev/tmp/itest-proof-file.zk-proof-file.bin", home);
    std::fs::write(&output_path, &zk_proof_file_blob)?;

    println!("\nZkProofFile artifact complete!");
    println!("  format_version:      {}", zk_proof_file.format_version);
    println!(
        "  proof_file_version:  {}",
        zk_proof_file.proof_file_version
    );
    println!("  proof_count:         {}", zk_proof_file.proof_count);
    println!(
        "  proof_chain_tip:     {}",
        hex::encode(zk_proof_file.proof_chain_tip)
    );
    println!(
        "  proof_chain_count:   {}",
        zk_proof_file.proof_chain_claim.proof_count
    );
    if let Some(outpoint) = zk_proof_file.proof_chain_claim.last_proof_outpoint {
        println!(
            "  proof_chain_outpoint: {}:{}",
            outpoint.txid, outpoint.vout
        );
    }
    println!(
        "  artifact_digest:     {}",
        hex::encode(zk_proof_file_digest)
    );
    println!("  artifact_size:       {} bytes", zk_proof_file_blob.len());
    println!("  artifact_path:       {}", output_path);

    if let Some(last_entry) = zk_proof_file.entries.last() {
        println!("\nLast proof join summary:");
        println!("  proof_index:         {}", last_entry.proof_index);
        println!(
            "  proof_checksum:      {}",
            hex::encode(last_entry.proof_checksum)
        );
        println!(
            "  anchor_txid:         {}",
            hex::encode(last_entry.join_output.anchor_txid)
        );
        println!(
            "  tap_commitment_root: {}",
            hex::encode(last_entry.join_output.tap_commitment_root)
        );
        println!(
            "  asset_id:            {}",
            hex::encode(last_entry.join_output.asset_id)
        );
    }

    Ok(())
}

fn thread_counts() -> (usize, usize) {
    let available = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(1);
    let desired = available.saturating_sub(3).max(1);
    (available, desired)
}
