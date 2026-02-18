//! -----------------------------------------------------
//! Guest program (RISC Zero) for the STXO claim.
//!
//! • Expects a single bincode-encoded `StxoClaimInput` from the host
//! • Commits the `StxoClaimOutput` digest if the claim is valid
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-05-15 risczero build \
//!       -p stxo-claim-prover --release \
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
    let input: core::verify::proof::StxoClaimInput = env::read();

    // Verify the STXO claim and get the result.
    let output =
        core::verify::proof::verify_stxo_claim(&input).expect("STXO claim verification failed");

    // Commit the output.
    env::commit(&output);
}
