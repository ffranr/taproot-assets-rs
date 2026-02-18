//! Verification routines for Taproot Assets proofs.

/// Group key reveal verification helpers.
pub mod group_key_reveal;
/// Proof verification helpers.
pub mod proof;
/// Taproot proof verification helpers.
pub mod taproot_proof;
/// Anchor transaction verification helpers.
pub mod tx;

/// Result type for verification helpers.
pub type Result<T> = core::result::Result<T, Error>;

/// Errors returned by verification helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Group key reveal verification failed.
    GroupKeyReveal(group_key_reveal::Error),
    /// Proof verification failed.
    Proof(proof::Error),
    /// Taproot proof verification failed.
    TaprootProof(taproot_proof::Error),
    /// Anchor transaction verification failed.
    Tx(tx::Error),
}

impl From<group_key_reveal::Error> for Error {
    /// Converts a group key reveal error into a verification error.
    fn from(err: group_key_reveal::Error) -> Self {
        Self::GroupKeyReveal(err)
    }
}

impl From<proof::Error> for Error {
    /// Converts a proof error into a verification error.
    fn from(err: proof::Error) -> Self {
        Self::Proof(err)
    }
}

impl From<taproot_proof::Error> for Error {
    /// Converts a taproot proof error into a verification error.
    fn from(err: taproot_proof::Error) -> Self {
        Self::TaprootProof(err)
    }
}

impl From<tx::Error> for Error {
    /// Converts a transaction error into a verification error.
    fn from(err: tx::Error) -> Self {
        Self::Tx(err)
    }
}

impl core::fmt::Display for Error {
    /// Formats the error for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::GroupKeyReveal(err) => core::fmt::Display::fmt(err, f),
            Error::Proof(err) => core::fmt::Display::fmt(err, f),
            Error::TaprootProof(err) => core::fmt::Display::fmt(err, f),
            Error::Tx(err) => core::fmt::Display::fmt(err, f),
        }
    }
}
