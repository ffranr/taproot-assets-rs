use taproot_assets_types as types;

use taproot_assets_zk_core as zk_core;

use bitcoin::hashes::Hash;

fn main() -> anyhow::Result<()> {
    // Read the proof from a file.
    let proof_file_path = "/home/user/dev/tmp/itest-proof-file.bin";
    let proof_file_bytes = std::fs::read(proof_file_path)?;

    let proof_file = types::proof::File::from_bytes(&proof_file_bytes)?;

    println!("number of proofs: {}", proof_file.proofs.len());

    let hashed_proof = &proof_file.proofs[0];
    let proof = types::proof::Proof::from_bytes(&hashed_proof.proof_bytes)?;
    println!("proof: {:?}", proof);

    let block_merkle_root = proof.block_header.merkle_root;
    println!("block merkle root: {}", block_merkle_root);

    let merkle_proof_node = proof.tx_merkle_proof.nodes[0];
    println!("merkle proof node: {}", merkle_proof_node);

    let txid = proof.anchor_tx.compute_txid();
    println!("anchor txid: {}", txid);

    let tx_merkle_proof_raw = zk_core::mint::TxMerkleProof {
        nodes: proof
            .tx_merkle_proof
            .nodes
            .into_iter()
            .map(|node| node.to_byte_array())
            .collect(),
        bits: proof.tx_merkle_proof.bits,
    };

    let input = zk_core::mint::VerifyMerkleProofInput {
        txid: txid.to_byte_array(),
        proof: tx_merkle_proof_raw,
        merkle_root: proof.block_header.merkle_root.to_byte_array(),
    };

    let ok = zk_core::mint::verify_tx_merkle_proof(&input);
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
