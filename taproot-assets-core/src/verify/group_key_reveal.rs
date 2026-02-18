//! Group key reveal verification logic.

use bitcoin::hashes::Hash;
use taproot_assets_types::asset::{
    Asset, AssetID, GroupKeyReveal, NonSpendLeafVersion, SerializedKey,
};
use taproot_assets_types::proof::Proof;

use crate::{OpsError, TaprootOps};

/// Errors returned by group key reveal verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Group key reveal is present but the asset has no group key.
    MissingGroupKey,
    /// Group key reveal requires genesis information.
    MissingGenesis,
    /// Asset group key length is invalid.
    InvalidGroupKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Derived group key does not match the asset group key.
    GroupKeyMismatch,
    /// Missing tapscript root for a V1 group key reveal.
    MissingTapscriptRoot {
        /// Reveal version that requires a tapscript root.
        version: NonSpendLeafVersion,
    },
    /// Taproot operation failed.
    Ops(OpsError),
}

impl From<OpsError> for Error {
    /// Converts an ops error into a group key reveal error.
    fn from(err: OpsError) -> Self {
        Self::Ops(err)
    }
}

impl core::fmt::Display for Error {
    /// Formats the error for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::MissingGroupKey => {
                write!(f, "group key reveal present but asset has no group key")
            }
            Error::MissingGenesis => write!(f, "group key reveal requires genesis information"),
            Error::InvalidGroupKeyLength { expected, actual } => write!(
                f,
                "asset group key length must be {}, got {}",
                expected, actual
            ),
            Error::GroupKeyMismatch => write!(f, "group key reveal mismatch"),
            Error::MissingTapscriptRoot { version } => write!(
                f,
                "missing tapscript root for group key reveal version {:?}",
                version
            ),
            Error::Ops(err) => core::fmt::Display::fmt(err, f),
        }
    }
}

/// Derives the compressed group key bytes for a group key reveal.
pub fn group_pubkey_from_reveal<O: TaprootOps>(
    ops: &O,
    reveal: &GroupKeyReveal,
    asset_id: &AssetID,
) -> Result<SerializedKey, Error> {
    let tapscript_root = reveal.tapscript_root.map(|root| root.to_byte_array());
    let custom_subtree_root = reveal.custom_subtree_root.map(|root| root.to_byte_array());

    match reveal.version {
        None => derive_group_pubkey_v0(ops, &reveal.raw_group_key, asset_id, tapscript_root),
        Some(version) => derive_group_pubkey_v1(
            ops,
            version,
            &reveal.raw_group_key,
            asset_id,
            tapscript_root,
            custom_subtree_root,
        ),
    }
}

/// Verifies that the group key reveal derives the asset's group key.
pub fn verify_group_key_reveal<O: TaprootOps>(ops: &O, proof: &Proof) -> Result<(), Error> {
    verify_group_key_reveal_with_asset(ops, &proof.asset, proof.group_key_reveal.as_ref())
        .map(|_| ())
}

/// Verifies that the group key reveal derives the asset's group key.
pub fn verify_group_key_reveal_with_asset<O: TaprootOps>(
    ops: &O,
    asset: &Asset,
    reveal: Option<&GroupKeyReveal>,
) -> Result<Option<SerializedKey>, Error> {
    let reveal = match reveal {
        Some(reveal) => reveal,
        None => return Ok(None),
    };
    let asset_group = asset.asset_group.as_ref().ok_or(Error::MissingGroupKey)?;
    let asset_id = asset
        .asset_genesis
        .as_ref()
        .ok_or(Error::MissingGenesis)?
        .asset_id;
    let expected_key = if !asset_group.tweaked_group_key.is_empty() {
        &asset_group.tweaked_group_key
    } else {
        &asset_group.raw_group_key
    };
    if expected_key.len() != 33 {
        return Err(Error::InvalidGroupKeyLength {
            expected: 33,
            actual: expected_key.len(),
        });
    }

    let derived_key = group_pubkey_from_reveal(ops, reveal, &asset_id)?;
    if expected_key.as_slice() != &derived_key.bytes[..] {
        return Err(Error::GroupKeyMismatch);
    }

    Ok(Some(derived_key))
}

/// Derives the tweaked group public key for a V0 group key reveal.
fn derive_group_pubkey_v0<O: TaprootOps>(
    ops: &O,
    raw_key: &SerializedKey,
    asset_id: &AssetID,
    tapscript_root: Option<[u8; 32]>,
) -> Result<SerializedKey, Error> {
    let raw_pubkey = ops.parse_group_key(raw_key)?;
    let tweak = asset_id.to_byte_array();
    let internal_key = ops.add_tweak(&raw_pubkey, tweak)?;

    let output_key = ops.taproot_output_key(&internal_key, tapscript_root)?;
    Ok(output_key)
}

/// Derives the tweaked group public key for a V1 group key reveal.
fn derive_group_pubkey_v1<O: TaprootOps>(
    ops: &O,
    version: NonSpendLeafVersion,
    internal_key: &SerializedKey,
    _asset_id: &AssetID,
    tapscript_root: Option<[u8; 32]>,
    _custom_subtree_root: Option<[u8; 32]>,
) -> Result<SerializedKey, Error> {
    let root = tapscript_root.ok_or(Error::MissingTapscriptRoot { version })?;
    let internal_pubkey = ops.parse_internal_key(internal_key)?;

    let output_key = ops.taproot_output_key(&internal_pubkey, Some(root))?;
    Ok(output_key)
}
