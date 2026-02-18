#![no_std]
#![no_main]

extern crate alloc;

/// ZK verification helpers that mirror `taproot-assets-core::verify`.
pub mod verify;

use bitcoin::TapNodeHash;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, Scalar, Secp256k1};
use taproot_assets_core::{OpsError, TaprootOps};
use taproot_assets_types::asset::SerializedKey;

/// A TaprootOps implementation backed by the RISC0 zkVM.
#[derive(Debug, Clone, Copy, Default)]
pub struct Risc0TaprootOps;

impl TaprootOps for Risc0TaprootOps {
    type PubKey = SecpPublicKey;

    fn parse_group_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidRawGroupKey)
    }

    fn parse_internal_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidInternalKey)
    }

    fn add_tweak(&self, pubkey: &Self::PubKey, tweak: [u8; 32]) -> Result<Self::PubKey, OpsError> {
        let secp = Secp256k1::verification_only();
        let scalar = Scalar::from_be_bytes(tweak).map_err(|_| OpsError::AssetIdTweakOutOfRange)?;
        pubkey
            .add_exp_tweak(&secp, &scalar)
            .map_err(|_| OpsError::InvalidGroupKeyTweak)
    }

    fn taproot_output_key(
        &self,
        internal_key: &Self::PubKey,
        tapscript_root: Option<[u8; 32]>,
    ) -> Result<SerializedKey, OpsError> {
        let secp = Secp256k1::verification_only();
        let merkle_root = tapscript_root.map(TapNodeHash::from_byte_array);
        let (xonly_key, _) = internal_key.x_only_public_key();
        let (tweaked, parity) = xonly_key.tap_tweak(&secp, merkle_root);
        let output_key =
            SecpPublicKey::from_x_only_public_key(tweaked.to_x_only_public_key(), parity);

        Ok(SerializedKey {
            bytes: output_key.serialize(),
        })
    }
}
