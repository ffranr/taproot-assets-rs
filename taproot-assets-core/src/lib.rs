#![no_std]

extern crate alloc;

use taproot_assets_types::asset::SerializedKey;
use thiserror::Error;

/// Errors returned by TaprootOps implementations.
#[derive(Error, Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpsError {
    /// Raw group key bytes are invalid.
    #[error("invalid group key reveal raw key")]
    InvalidRawGroupKey,
    /// Internal key bytes are invalid.
    #[error("invalid group key reveal internal key")]
    InvalidInternalKey,
    /// Asset ID tweak is out of range.
    #[error("asset id tweak out of range")]
    AssetIdTweakOutOfRange,
    /// Failed to apply the group key tweak.
    #[error("invalid group key tweak")]
    InvalidGroupKeyTweak,
    /// Taproot output key derivation failed.
    #[error("invalid taproot output key")]
    InvalidTaprootOutputKey,
}

/// Trait that supplies cryptographic operations needed by verifier core.
pub trait TaprootOps {
    /// Backend-specific public key representation.
    type PubKey;

    /// Parses a raw group key into the backend representation.
    fn parse_group_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError>;

    /// Parses an internal key into the backend representation.
    fn parse_internal_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError>;

    /// Adds a scalar tweak to a public key.
    fn add_tweak(&self, pubkey: &Self::PubKey, tweak: [u8; 32]) -> Result<Self::PubKey, OpsError>;

    /// Computes the Taproot output key for an internal key and optional tapscript root.
    fn taproot_output_key(
        &self,
        internal_key: &Self::PubKey,
        tapscript_root: Option<[u8; 32]>,
    ) -> Result<SerializedKey, OpsError>;
}

/// Verification routines for Taproot Assets proofs.
pub mod verify;
