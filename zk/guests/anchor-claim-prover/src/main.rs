//! -----------------------------------------------------
//! Guest program (RISC Zero) for the anchor claim.
//!
//! • Expects a single bincode-encoded `AnchorClaimInput` from the host
//! • Commits the `AnchorClaimOutput` digest if the claim is valid
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-05-15 risczero build \
//!       -p anchor-claim-prover --release \
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
    let input: core::verify::tx::AnchorClaimInput = env::read();

    // Verify the anchor claim and get the digest.
    let output =
        core::verify::tx::verify_anchor_claim(&input).expect("Anchor claim verification failed");

    // Commit the output digest.
    env::commit(&output);
}
