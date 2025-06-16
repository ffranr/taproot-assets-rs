use crate::asset::AssetVersion;
use crate::error::Error;
use crate::mssmt::MssmtProof;
use crate::tlv::{Stream, Type};
use alloc::collections::BTreeMap;
use bitcoin::io::Read;

use crate::alloc::string::ToString;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Denotes the structure of the Taproot Asset commitment MS-SMT and the procedure
/// for building a TapLeaf from a Taproot Asset commitment.
/// This corresponds to `commitment.TapCommitmentVersion` in Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TapCommitmentVersion {
    /// Initial Taproot Asset Commitment version. Uses legacy TapLeaf format, ONLY commits to V0 assets.
    V0 = 0,
    /// Used by Taproot Asset Commitments that commit to V0 or V1 assets. Uses legacy TapLeaf format.
    V1 = 1,
    /// Used by Taproot Asset Commitments that commit to V0 or V1 assets. Uses V1 TapLeaf format.
    V2 = 2,
}

impl TapCommitmentVersion {
    pub(crate) fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(TapCommitmentVersion::V0),
            1 => Ok(TapCommitmentVersion::V1),
            2 => Ok(TapCommitmentVersion::V2),
            _ => Err(Error::InvalidTlvValue(
                0,
                alloc::format!("Unknown TapCommitmentVersion: {}", val),
            )),
        }
    }
}

/// Type of tapscript sibling preimage.
/// This corresponds to `commitment.TapscriptPreimageType` in Go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(u8)]
pub enum TapscriptPreimageType {
    /// Pre-image that's a leaf script.
    LeafPreimage = 0,
    /// Pre-image that's a branch (64-bytes of two child pre-images).
    BranchPreimage = 1,
}

impl TapscriptPreimageType {
    pub(crate) fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(TapscriptPreimageType::LeafPreimage),
            1 => Ok(TapscriptPreimageType::BranchPreimage),
            _ => Err(Error::InvalidTlvValue(
                0,
                alloc::format!("Unknown TapscriptPreimageType: {}", val),
            )),
        }
    }
}

/// Wraps a pre-image byte slice with a type byte that self identifies what type of pre-image it is.
/// This corresponds to `commitment.TapscriptPreimage` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapscriptPreimage {
    /// The pre-image itself. This will be 64 bytes if representing a TapBranch,
    /// or any size under 4 MBytes if representing a TapLeaf.
    pub sibling_preimage: Vec<u8>,
    /// The type of the pre-image.
    pub sibling_type: TapscriptPreimageType,
}

impl TapscriptPreimage {
    /// Decodes a TapscriptPreimage directly from a reader.
    /// The format is: 1-byte type, then variable-length preimage bytes.
    pub fn decode_tlv<R: Read>(mut r: R) -> Result<Self, Error> {
        let mut type_buf = [0u8; 1];
        r.read_exact(&mut type_buf).map_err(Error::Io)?;
        let sibling_type_byte = type_buf[0];
        let sibling_type = TapscriptPreimageType::from_u8(sibling_type_byte)?;

        let mut sibling_preimage = Vec::new();
        // Manual read_to_end for no_std compatibility
        let mut chunk = [0u8; 512]; // Read in 512-byte chunks
        loop {
            match r.read(&mut chunk) {
                Ok(0) => break, // EOF
                Ok(n) => sibling_preimage.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(Error::Io(e)), // Propagate actual IO errors
            }
        }

        // Basic validation based on type, more can be added if needed.
        match sibling_type {
            TapscriptPreimageType::BranchPreimage if sibling_preimage.len() != 64 => {
                return Err(Error::InvalidTlvValue(
                    sibling_type_byte as u64,
                    "BranchPreimage must be 64 bytes".to_string(),
                ));
            }
            _ => {}
        }

        Ok(TapscriptPreimage {
            sibling_preimage,
            sibling_type,
        })
    }
}

/// Proof used along with an asset leaf to arrive at the root of the AssetCommitment MS-SMT.
/// This corresponds to `commitment.AssetProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetProof {
    /// The underlying MS-SMT proof.
    pub proof: MssmtProof,
    /// Max version of the assets committed.
    pub version: AssetVersion,
    /// Common identifier for all assets found within the AssetCommitment.
    /// Can be an asset.ID or an asset.GroupKey hash.
    pub tap_key: [u8; 32],
    /// Map of unknown odd types encountered during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl AssetProof {
    pub fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut mssmt_proof: Option<MssmtProof> = None;
        let mut version: Option<AssetVersion> = None;
        let mut tap_key: Option<[u8; 32]> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                ASSET_PROOF_MSSMT_PROOF_TYPE => {
                    mssmt_proof = Some(MssmtProof::decode_tlv(record.value_reader())?);
                }
                ASSET_PROOF_VERSION_TYPE => {
                    if record.value().len() != 1 {
                        return Err(Error::InvalidTlvValue(
                            ASSET_PROOF_VERSION_TYPE.0,
                            "Length must be 1 for AssetVersion".to_string(),
                        ));
                    }
                    version = Some(AssetVersion::from_u8(record.value()[0])?);
                }
                ASSET_PROOF_TAP_KEY_TYPE => {
                    if record.value().len() != 32 {
                        return Err(Error::InvalidTlvValue(
                            ASSET_PROOF_TAP_KEY_TYPE.0,
                            "Length must be 32 for TapKey".to_string(),
                        ));
                    }
                    let mut key_bytes = [0u8; 32];
                    key_bytes.copy_from_slice(record.value());
                    tap_key = Some(key_bytes);
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        return Err(Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }
        Ok(AssetProof {
            proof: mssmt_proof.ok_or(Error::MissingTlvField("AssetProof.proof".to_string()))?,
            version: version.ok_or(Error::MissingTlvField("AssetProof.version".to_string()))?,
            tap_key: tap_key.ok_or(Error::MissingTlvField("AssetProof.tap_key".to_string()))?,
            unknown_odd_types,
        })
    }
}

/// Proof used along with an asset commitment leaf to arrive at the root of the TapCommitment MS-SMT.
/// This corresponds to `commitment.TaprootAssetProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaprootAssetProof {
    /// The underlying MS-SMT proof.
    pub proof: MssmtProof,
    /// Version of the TapCommitment used to create the proof.
    pub version: TapCommitmentVersion,
    /// Map of unknown odd types encountered during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl TaprootAssetProof {
    pub fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut mssmt_proof: Option<MssmtProof> = None;
        let mut version: Option<TapCommitmentVersion> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                TAPROOT_ASSET_PROOF_MSSMT_PROOF_TYPE => {
                    mssmt_proof = Some(MssmtProof::decode_tlv(record.value_reader())?);
                }
                TAPROOT_ASSET_PROOF_VERSION_TYPE => {
                    if record.value().len() != 1 {
                        return Err(Error::InvalidTlvValue(
                            TAPROOT_ASSET_PROOF_VERSION_TYPE.0,
                            "Length must be 1 for TapCommitmentVersion".to_string(),
                        ));
                    }
                    version = Some(TapCommitmentVersion::from_u8(record.value()[0])?);
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        return Err(Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }
        Ok(TaprootAssetProof {
            proof: mssmt_proof.ok_or(Error::MissingTlvField(
                "TaprootAssetProof.proof".to_string(),
            ))?,
            version: version.ok_or(Error::MissingTlvField(
                "TaprootAssetProof.version".to_string(),
            ))?,
            unknown_odd_types,
        })
    }
}

/// Represents a full commitment proof for a particular `Asset`. It proves
/// that an asset does or does not exist within a Taproot Asset commitment.
/// This corresponds to `commitment.Proof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Proof used along with the asset to arrive at the root of the AssetCommitment MS-SMT.
    /// NOTE: This proof must be None if the asset commitment for this
    /// particular asset is not found within the Taproot Asset commitment.
    pub asset_proof: Option<AssetProof>,
    /// Proof used along with the asset commitment to arrive at the root of the TapCommitment
    /// MS-SMT.
    pub taproot_asset_proof: TaprootAssetProof,
    /// Map of unknown odd types encountered during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl Proof {
    pub fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut asset_proof: Option<AssetProof> = None;
        let mut taproot_asset_proof: Option<TaprootAssetProof> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                PROOF_ASSET_PROOF_TYPE => {
                    asset_proof = Some(AssetProof::decode_tlv(record.value_reader())?);
                }
                PROOF_TAPROOT_ASSET_PROOF_TYPE => {
                    taproot_asset_proof =
                        Some(TaprootAssetProof::decode_tlv(record.value_reader())?);
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        return Err(Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }
        Ok(Proof {
            asset_proof,
            taproot_asset_proof: taproot_asset_proof.ok_or(Error::MissingTlvField(
                "Proof.taproot_asset_proof".to_string(),
            ))?,
            unknown_odd_types,
        })
    }
}

// --- TLV Type Constants for commitment structures ---

// For commitment::Proof
const PROOF_ASSET_PROOF_TYPE: Type = Type(0);
const PROOF_TAPROOT_ASSET_PROOF_TYPE: Type = Type(2);

// For commitment::AssetProof
const ASSET_PROOF_VERSION_TYPE: Type = Type(0);
const ASSET_PROOF_TAP_KEY_TYPE: Type = Type(2); // Renamed from AssetID in Go for clarity
const ASSET_PROOF_MSSMT_PROOF_TYPE: Type = Type(4); // "AssetProofRecord" in Go

// For commitment::TaprootAssetProof
const TAPROOT_ASSET_PROOF_VERSION_TYPE: Type = Type(0);
const TAPROOT_ASSET_PROOF_MSSMT_PROOF_TYPE: Type = Type(2); // "TaprootAssetProofRecord" in Go
