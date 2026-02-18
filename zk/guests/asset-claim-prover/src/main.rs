//! -----------------------------------------------------
//! Guest program (RISC Zero) for the asset integrity claim.
//!
//! • Expects a single bincode-encoded `AssetClaimInput` from the host
//! • Commits the `AssetClaimOutput` digest if the claim is valid
//!
//! Build (nightly toolchain with riscv target):
//!   cargo +nightly-2024-05-15 risczero build \
//!       -p asset-claim-prover --release \
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
    let input: core::verify::proof::AssetClaimInput = env::read();

    // Verify the asset integrity claim and get the digest.
    let output =
        core::verify::proof::verify_asset_claim(&input).expect("Asset claim verification failed");

    // Commit the output digest.
    env::commit(&output);
}
