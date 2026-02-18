//! Host-side verification utilities backed by bitcoin/secp256k1.

use bitcoin::TapNodeHash;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{self, PublicKey as SecpPublicKey, Scalar, Secp256k1};
use taproot_assets_core::{OpsError, TaprootOps, verify, verify::group_key_reveal};
use taproot_assets_types::asset::{AssetID, GroupKeyReveal, SerializedKey};
use taproot_assets_types::proof::Proof;

/// Taproot operations implemented with bitcoin/secp256k1 types.
#[derive(Debug)]
pub struct BitcoinTaprootOps {
    /// Secp256k1 context used for verification-only operations.
    secp: Secp256k1<secp256k1::VerifyOnly>,
}

impl BitcoinTaprootOps {
    /// Creates a new Taproot operations backend.
    pub fn new() -> Self {
        Self {
            secp: Secp256k1::verification_only(),
        }
    }
}

impl TaprootOps for BitcoinTaprootOps {
    type PubKey = SecpPublicKey;

    /// Parses a raw group key into the backend representation.
    fn parse_group_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidRawGroupKey)
    }

    /// Parses an internal key into the backend representation.
    fn parse_internal_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidInternalKey)
    }

    /// Adds a scalar tweak to a public key.
    fn add_tweak(&self, pubkey: &Self::PubKey, tweak: [u8; 32]) -> Result<Self::PubKey, OpsError> {
        let tweak = Scalar::from_be_bytes(tweak).map_err(|_| OpsError::AssetIdTweakOutOfRange)?;
        pubkey
            .add_exp_tweak(&self.secp, &tweak)
            .map_err(|_| OpsError::InvalidGroupKeyTweak)
    }

    /// Computes the Taproot output key for an internal key and optional tapscript root.
    fn taproot_output_key(
        &self,
        internal_key: &Self::PubKey,
        tapscript_root: Option<[u8; 32]>,
    ) -> Result<SerializedKey, OpsError> {
        let merkle_root = tapscript_root.map(TapNodeHash::from_byte_array);
        let (xonly_key, _) = internal_key.x_only_public_key();
        let (tweaked, parity) = xonly_key.tap_tweak(&self.secp, merkle_root);
        let output_key =
            SecpPublicKey::from_x_only_public_key(tweaked.to_x_only_public_key(), parity);

        Ok(SerializedKey {
            bytes: output_key.serialize(),
        })
    }
}

/// Derives the compressed group key bytes using the bitcoin backend.
pub fn group_pubkey_from_reveal(
    reveal: &GroupKeyReveal,
    asset_id: &AssetID,
) -> Result<SerializedKey, verify::Error> {
    let ops = BitcoinTaprootOps::new();
    group_key_reveal::group_pubkey_from_reveal(&ops, reveal, asset_id).map_err(verify::Error::from)
}

/// Verifies that the group key reveal derives the asset's group key using the bitcoin backend.
pub fn verify_group_key_reveal(proof: &Proof) -> Result<(), verify::Error> {
    let ops = BitcoinTaprootOps::new();
    group_key_reveal::verify_group_key_reveal(&ops, proof).map_err(verify::Error::from)
}
