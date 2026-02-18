use crate::Risc0TaprootOps;
pub use taproot_assets_core::verify::proof::{
    AssetClaimInput, AssetClaimOutput, GenesisRevealInput, StxoClaimInput, StxoClaimOutput,
    TaprootClaimInput, TaprootClaimOutput,
};
use taproot_assets_types::proof::Proof;

/// Verifies the Taproot commitment claim using the RISC0 TaprootOps implementation.
pub fn verify_taproot_claim(
    input: &TaprootClaimInput,
) -> Result<TaprootClaimOutput, taproot_assets_core::verify::proof::Error> {
    taproot_assets_core::verify::proof::verify_taproot_claim_with_ops(&Risc0TaprootOps, input)
}

/// Verifies the STXO claim using the RISC0 TaprootOps implementation.
pub fn verify_stxo_claim(
    input: &StxoClaimInput,
) -> Result<StxoClaimOutput, taproot_assets_core::verify::proof::Error> {
    taproot_assets_core::verify::proof::verify_stxo_claim_with_ops(&Risc0TaprootOps, input)
}

/// Verifies asset integrity using the RISC0 TaprootOps implementation.
pub fn verify_asset_claim(
    input: &AssetClaimInput,
) -> Result<AssetClaimOutput, taproot_assets_core::verify::proof::Error> {
    taproot_assets_core::verify::proof::verify_asset_claim_with_ops(&Risc0TaprootOps, input)
}

/// Verifies genesis and meta reveal constraints.
pub fn verify_genesis_reveal_input(
    input: &GenesisRevealInput,
) -> Result<(), taproot_assets_core::verify::proof::Error> {
    taproot_assets_core::verify::proof::verify_genesis_reveal_input(input)
}

/// Verifies genesis and meta reveal constraints from a full proof.
pub fn verify_genesis_reveal(
    proof: &Proof,
) -> Result<(), taproot_assets_core::verify::proof::Error> {
    taproot_assets_core::verify::proof::verify_genesis_reveal(proof)
}
