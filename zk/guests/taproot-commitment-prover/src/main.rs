#![no_std]
#![no_main]

extern crate alloc;

use risc0_zkvm::guest::{entry, env};
use taproot_assets_zk_core as core;

entry!(main);

fn main() {
    let input: core::verify::proof::TaprootClaimInput = env::read();

    let output = core::verify::proof::verify_taproot_claim(&input)
        .expect("Taproot commitment claim verification failed");

    env::commit(&output);
}
