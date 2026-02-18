//! -----------------------------------------------------
//! Guest program (RISC Zero) for the proof-chain claim.
//!
//! • Expects a single bincode-encoded `ProofChainClaimInput` from the host
//! • Commits the `ProofChainClaimOutput` digest if the claim is valid
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-05-15 risczero build \
//!       -p proof-chain-claim-prover --release \
//!       --target riscv32im-risc0-zkvm-elf
//! -----------------------------------------------------

#![no_std]
#![no_main]

extern crate alloc;

use risc0_zkvm::guest::{entry, env};
use taproot_assets_zk_core as core;

entry!(main);

fn main() {
    let input: core::verify::proof_chain::ProofChainClaimInput = env::read();
    let output = core::verify::proof_chain::verify_proof_chain_claim(&input)
        .expect("proof-chain claim verification failed");
    env::commit(&output);
}
