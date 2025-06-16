//! -----------------------------------------------------
//! Guest program (RISC Zero) that checks a transaction
//! Merkle proof against a block’s merkle root.
//!
//! • Expects a single bincode-encoded `Input` from the host
//! • Commits `true` if the proof is valid, otherwise `false`
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-05-15 risczero build \
//!       -p mint-prover --release \
//!       --target riscv32im-risc0-zkvm-elf
//! -----------------------------------------------------

#![no_std]
#![no_main]

extern crate alloc;

use risc0_zkvm::guest::{entry, env};
use taproot_assets_zk_core as core;

entry!(main);

fn main() {
    // Read input.
    let input: core::mint::VerifyMerkleProofInput = env::read();

    let ok = core::mint::verify_tx_merkle_proof(&input);
    env::commit(&ok);
}
