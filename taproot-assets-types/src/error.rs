use crate::alloc::string::String; // For no_std compatibility
use bitcoin::io::Error as BitcoinIoError;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(BitcoinIoError),

    #[error("TLV stream error: {0}")]
    TlvStream(String),

    #[error("Missing TLV field: {0}")]
    MissingTlvField(String),

    #[error("Bitcoin serialization error: {0}")]
    BitcoinSerialization(String),

    #[error("Unknown TLV type: {0}")]
    UnknownTlvType(u64),

    #[error("Invalid TLV value for type {0}: {1}")]
    InvalidTlvValue(u64, String),
}
