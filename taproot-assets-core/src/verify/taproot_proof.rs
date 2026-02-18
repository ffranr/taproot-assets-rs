//! Taproot proof verification helpers.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use bitcoin::hashes::{Hash, HashEngine, sha256::Hash as Sha256Hash};
use bitcoin::secp256k1::{PublicKey as SecpPublicKey, XOnlyPublicKey};
use bitcoin::taproot::{LeafVersion, TapNodeHash};
use bitcoin::{OutPoint, Script, ScriptBuf, Transaction, Witness};
use serde::{Deserialize, Serialize};
use taproot_assets_types::asset::{
    Asset, AssetType, AssetVersion, GenesisInfo, PrevId, PrevWitness, SerializedKey,
    SplitCommitment,
};
use taproot_assets_types::commitment::{
    TapCommitmentVersion, TapscriptPreimage, TapscriptPreimageType,
};
use taproot_assets_types::mssmt::{MssmtNode, MssmtProof};
use taproot_assets_types::proof::{CommitmentProof, TaprootProof, TapscriptProof};

use crate::{OpsError, TaprootOps};

/// Errors returned by taproot proof verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Taproot output index is invalid.
    InvalidTaprootOutputIndex {
        /// Index requested in the anchor transaction outputs.
        output_index: u32,
        /// Total number of outputs in the anchor transaction.
        output_count: usize,
    },
    /// Script pubkey is not a Taproot v1 witness program.
    InvalidTaprootWitnessProgram,
    /// Taproot output key bytes are invalid.
    InvalidTaprootOutputKey,
    /// Taproot proof does not include a supported method.
    MissingTaprootProofMethod,
    /// Taproot proof commitment data is invalid or missing.
    InvalidCommitmentProof,
    /// Taproot proof is missing a commitment proof.
    MissingCommitmentProof,
    /// Taproot proof is missing an asset proof.
    MissingAssetProof,
    /// Taproot proof is invalid for tapscript verification.
    InvalidTapscriptProof,
    /// Taproot proof derived key does not match the anchor output.
    InvalidTaprootProof,
    /// Tapscript preimage is empty.
    EmptyTapscriptPreimage,
    /// Tapscript preimage length is invalid.
    InvalidTapscriptPreimageLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Tapleaf script version is not supported.
    InvalidTapLeafScriptVersion,
    /// Tapleaf script length is invalid.
    InvalidTapLeafScriptLength,
    /// Tapscript preimage is a Taproot Asset commitment leaf.
    TapscriptPreimageIsTapCommitment,
    /// Asset genesis information is missing.
    MissingAssetGenesis,
    /// Asset script key length is invalid.
    InvalidAssetScriptKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// Asset script key is invalid.
    InvalidAssetScriptKey,
    /// Asset group key is invalid.
    InvalidAssetGroupKey,
    /// Asset script version is invalid.
    InvalidAssetScriptVersion,
    /// Asset group key length is invalid.
    InvalidGroupKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// MS-SMT proof length is invalid.
    InvalidMssmtProofLength {
        /// Expected proof length.
        expected: usize,
        /// Actual proof length.
        actual: usize,
    },
    /// MS-SMT sum overflowed while hashing.
    MssmtSumOverflow,
    /// Taproot operation failed.
    Ops(OpsError),
}

impl From<OpsError> for Error {
    /// Converts an ops error into a taproot proof error.
    fn from(err: OpsError) -> Self {
        Self::Ops(err)
    }
}

impl core::fmt::Display for Error {
    /// Formats the error for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::InvalidTaprootOutputIndex {
                output_index,
                output_count,
            } => write!(
                f,
                "invalid taproot output index {} for {} outputs",
                output_index, output_count
            ),
            Error::InvalidTaprootWitnessProgram => {
                write!(f, "script pubkey is not a Taproot v1 witness program")
            }
            Error::InvalidTaprootOutputKey => write!(f, "invalid taproot output key"),
            Error::MissingTaprootProofMethod => {
                write!(f, "taproot proof missing commitment or tapscript data")
            }
            Error::InvalidCommitmentProof => write!(f, "invalid commitment proof"),
            Error::MissingCommitmentProof => write!(f, "missing commitment proof"),
            Error::MissingAssetProof => write!(f, "missing asset proof"),
            Error::InvalidTapscriptProof => write!(f, "invalid tapscript proof"),
            Error::InvalidTaprootProof => write!(f, "invalid taproot proof"),
            Error::EmptyTapscriptPreimage => write!(f, "empty tapscript preimage"),
            Error::InvalidTapscriptPreimageLength { expected, actual } => write!(
                f,
                "invalid tapscript preimage length {}, expected {}",
                actual, expected
            ),
            Error::InvalidTapLeafScriptVersion => {
                write!(f, "invalid tapleaf script version")
            }
            Error::InvalidTapLeafScriptLength => write!(f, "invalid tapleaf script length"),
            Error::TapscriptPreimageIsTapCommitment => {
                write!(f, "tapscript preimage is a taproot asset commitment")
            }
            Error::MissingAssetGenesis => write!(f, "missing asset genesis"),
            Error::InvalidAssetScriptKeyLength { expected, actual } => write!(
                f,
                "asset script key length {}, expected {}",
                actual, expected
            ),
            Error::InvalidAssetScriptKey => write!(f, "invalid asset script key"),
            Error::InvalidAssetGroupKey => write!(f, "invalid asset group key"),
            Error::InvalidAssetScriptVersion => write!(f, "invalid asset script version"),
            Error::InvalidGroupKeyLength { expected, actual } => write!(
                f,
                "asset group key length must be {}, got {}",
                expected, actual
            ),
            Error::InvalidMssmtProofLength { expected, actual } => write!(
                f,
                "invalid mssmt proof length {}, expected {}",
                actual, expected
            ),
            Error::MssmtSumOverflow => write!(f, "mssmt sum overflow"),
            Error::Ops(err) => core::fmt::Display::fmt(err, f),
        }
    }
}

/// Number of levels in an MS-SMT.
const MSSMT_TREE_LEVELS: usize = 256;
/// Length in bytes of a Taproot Asset commitment leaf script.
const TAPROOT_ASSET_COMMITMENT_SCRIPT_SIZE: usize = 1 + 32 + 32 + 8;
/// Marker tag for legacy Taproot Asset commitment leaves.
const TAPROOT_ASSETS_MARKER_TAG: &str = "taproot-assets";
/// Marker tag for V2 Taproot Asset commitment leaves.
const TAPROOT_ASSETS_V2_TAG: &str = "taproot-assets:194243";
/// Length in bytes of a TapBranch preimage without tag.
const TAP_BRANCH_PREIMAGE_LEN: usize = 64;
/// Maximum tapscript size accepted for leaf preimages.
const MAX_TAPLEAF_SCRIPT_SIZE: usize = 4_000_000;

/// Map of derived taproot output keys to their commitments.
type ProofCommitmentKeys = BTreeMap<SerializedKey, TapCommitment>;

/// Minimal TapCommitment representation derived during verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapCommitment {
    /// Taproot Asset commitment version.
    pub version: TapCommitmentVersion,
    /// Root hash of the TapCommitment MS-SMT.
    pub root_hash: [u8; 32],
    /// Root sum of the TapCommitment MS-SMT.
    pub root_sum: u64,
}

impl TapCommitment {
    /// Returns the tapscript leaf script for this commitment.
    fn tap_leaf_script(&self) -> Vec<u8> {
        let mut script = Vec::with_capacity(TAPROOT_ASSET_COMMITMENT_SCRIPT_SIZE);
        match self.version {
            TapCommitmentVersion::V0 | TapCommitmentVersion::V1 => {
                script.push(self.version as u8);
                script.extend_from_slice(&taproot_assets_marker());
                script.extend_from_slice(&self.root_hash);
                script.extend_from_slice(&self.root_sum.to_be_bytes());
            }
            TapCommitmentVersion::V2 => {
                script.extend_from_slice(&taproot_assets_v2_tag());
                script.push(self.version as u8);
                script.extend_from_slice(&self.root_hash);
                script.extend_from_slice(&self.root_sum.to_be_bytes());
            }
        }

        script
    }

    /// Returns the TapNodeHash for this commitment leaf.
    fn tap_leaf_hash(&self) -> TapNodeHash {
        let script = ScriptBuf::from_bytes(self.tap_leaf_script());
        TapNodeHash::from_script(script.as_script(), LeafVersion::TapScript)
    }

    /// Returns the tapscript root for this commitment and optional sibling.
    fn tapscript_root(&self, sibling: Option<&TapscriptPreimage>) -> Result<TapNodeHash, Error> {
        let commitment_hash = self.tap_leaf_hash();
        let sibling_hash = match sibling {
            Some(preimage) => Some(tapscript_preimage_hash(preimage)?),
            None => None,
        };

        Ok(match sibling_hash {
            Some(hash) => TapNodeHash::from_node_hashes(commitment_hash, hash),
            None => commitment_hash,
        })
    }

    /// Returns a downgraded TapCommitment version with the same root.
    fn downgrade(&self) -> TapCommitment {
        TapCommitment {
            version: TapCommitmentVersion::V0,
            root_hash: self.root_hash,
            root_sum: self.root_sum,
        }
    }
}

/// MS-SMT root data along with its immediate children.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MssmtRoot {
    /// Root hash of the MS-SMT.
    root_hash: [u8; 32],
    /// Root sum of the MS-SMT.
    root_sum: u64,
    /// Root left child hash.
    left_hash: [u8; 32],
    /// Root right child hash.
    right_hash: [u8; 32],
}

/// Extracts the taproot output key from an anchor transaction output.
pub fn extract_taproot_key(
    anchor_tx: &Transaction,
    output_index: u32,
) -> Result<XOnlyPublicKey, Error> {
    let output_count = anchor_tx.output.len();
    let output =
        anchor_tx
            .output
            .get(output_index as usize)
            .ok_or(Error::InvalidTaprootOutputIndex {
                output_index,
                output_count,
            })?;

    extract_taproot_key_from_script(output.script_pubkey.as_script())
}

/// Extracts the taproot output key from a script pubkey.
pub fn extract_taproot_key_from_script(script: &Script) -> Result<XOnlyPublicKey, Error> {
    if !script.is_p2tr() {
        return Err(Error::InvalidTaprootWitnessProgram);
    }

    let bytes = script.as_bytes();
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&bytes[2..34]);

    XOnlyPublicKey::from_slice(&key_bytes).map_err(|_| Error::InvalidTaprootOutputKey)
}

/// Verifies a taproot proof against the anchor transaction output.
pub fn verify_taproot_proof<O: TaprootOps>(
    ops: &O,
    anchor_tx: &Transaction,
    proof: &TaprootProof,
    asset: &Asset,
    inclusion: bool,
) -> Result<(), Error> {
    verify_taproot_proof_with_commitment(ops, anchor_tx, proof, asset, inclusion).map(|_| ())
}

/// Verifies a taproot proof and returns the matched TapCommitment, if any.
pub fn verify_taproot_proof_with_commitment<O: TaprootOps>(
    ops: &O,
    anchor_tx: &Transaction,
    proof: &TaprootProof,
    asset: &Asset,
    inclusion: bool,
) -> Result<Option<TapCommitment>, Error> {
    let expected_key = extract_taproot_key(anchor_tx, proof.output_index)?;
    verify_taproot_proof_with_commitment_and_key(ops, expected_key, proof, asset, inclusion)
}

/// Verifies a taproot proof against an expected key and returns the matched TapCommitment, if any.
pub fn verify_taproot_proof_with_commitment_and_key<O: TaprootOps>(
    ops: &O,
    expected_key: XOnlyPublicKey,
    proof: &TaprootProof,
    asset: &Asset,
    inclusion: bool,
) -> Result<Option<TapCommitment>, Error> {
    if inclusion {
        let derived = derive_by_asset_inclusion(ops, proof, asset)?;
        return verify_expected_key_with_commitment(&expected_key, &derived);
    }

    if proof.commitment_proof.is_some() {
        let derived = derive_by_asset_exclusion(ops, proof, asset)?;
        return verify_expected_key_with_commitment(&expected_key, &derived);
    }

    if proof.tapscript_proof.is_some() {
        let derived = derive_by_tapscript_proof(ops, proof)?;
        let expected = expected_key.serialize();
        let derived_xonly = xonly_from_serialized_key(&derived)?;
        return if expected == derived_xonly {
            Ok(None)
        } else {
            Err(Error::InvalidTaprootProof)
        };
    }

    Err(Error::MissingTaprootProofMethod)
}

/// Verifies the derived key set and returns the matching commitment, if any.
fn verify_expected_key_with_commitment(
    expected_key: &XOnlyPublicKey,
    derived: &ProofCommitmentKeys,
) -> Result<Option<TapCommitment>, Error> {
    let expected = expected_key.serialize();
    for (key, commitment) in derived {
        let derived_xonly = xonly_from_serialized_key(key)?;
        if derived_xonly == expected {
            return Ok(Some(commitment.clone()));
        }
    }

    Err(Error::InvalidTaprootProof)
}

/// Derives commitment keys for an inclusion proof.
fn derive_by_asset_inclusion<O: TaprootOps>(
    ops: &O,
    proof: &TaprootProof,
    asset: &Asset,
) -> Result<ProofCommitmentKeys, Error> {
    let commitment_proof = proof
        .commitment_proof
        .as_ref()
        .ok_or(Error::MissingCommitmentProof)?;
    if proof.tapscript_proof.is_some() {
        return Err(Error::InvalidCommitmentProof);
    }

    let mut asset = asset.clone();
    if asset_has_split_commitment_witness(&asset) {
        asset = asset_without_split_commitment(&asset);
    }

    let tap_commitment = derive_commitment_by_asset_inclusion(commitment_proof, &asset)?;
    let internal_key = serialized_key_from_pubkey(&proof.internal_key);
    derive_commitment_keys(
        ops,
        &tap_commitment,
        &internal_key,
        commitment_proof.tap_sibling_preimage.as_ref(),
        true,
    )
}

/// Derives commitment keys for an exclusion proof.
fn derive_by_asset_exclusion<O: TaprootOps>(
    ops: &O,
    proof: &TaprootProof,
    asset: &Asset,
) -> Result<ProofCommitmentKeys, Error> {
    let commitment_proof = proof
        .commitment_proof
        .as_ref()
        .ok_or(Error::MissingCommitmentProof)?;
    if proof.tapscript_proof.is_some() {
        return Err(Error::InvalidCommitmentProof);
    }

    let asset_commitment_key = asset_commitment_key(asset)?;
    let tap_commitment_key = tap_commitment_key(asset)?;
    let tap_commitment = if commitment_proof.proof.asset_proof.is_none() {
        derive_commitment_by_asset_commitment_exclusion(commitment_proof, tap_commitment_key)?
    } else {
        derive_commitment_by_asset_exclusion(commitment_proof, asset_commitment_key)?
    };

    let internal_key = serialized_key_from_pubkey(&proof.internal_key);
    derive_commitment_keys(
        ops,
        &tap_commitment,
        &internal_key,
        commitment_proof.tap_sibling_preimage.as_ref(),
        true,
    )
}

/// Derives the taproot output key for a tapscript proof.
fn derive_by_tapscript_proof<O: TaprootOps>(
    ops: &O,
    proof: &TaprootProof,
) -> Result<SerializedKey, Error> {
    let tapscript_proof = proof
        .tapscript_proof
        .as_ref()
        .ok_or(Error::InvalidTapscriptProof)?;
    if proof.commitment_proof.is_some() {
        return Err(Error::InvalidTapscriptProof);
    }

    let internal_key = serialized_key_from_pubkey(&proof.internal_key);
    derive_taproot_key_from_tapscript(ops, &internal_key, tapscript_proof)
}

/// Derives all taproot output keys from a TapCommitment.
fn derive_commitment_keys<O: TaprootOps>(
    ops: &O,
    commitment: &TapCommitment,
    internal_key: &SerializedKey,
    sibling: Option<&TapscriptPreimage>,
    downgrade: bool,
) -> Result<ProofCommitmentKeys, Error> {
    let mut keys = ProofCommitmentKeys::new();
    let key_v2 = derive_taproot_key_from_commitment(ops, commitment, internal_key, sibling)?;
    keys.insert(key_v2, commitment.clone());

    if downgrade {
        let downgraded = commitment.downgrade();
        let key_v0 = derive_taproot_key_from_commitment(ops, &downgraded, internal_key, sibling)?;
        keys.insert(key_v0, downgraded);
    }

    Ok(keys)
}

/// Derives a taproot output key from a commitment and sibling preimage.
fn derive_taproot_key_from_commitment<O: TaprootOps>(
    ops: &O,
    commitment: &TapCommitment,
    internal_key: &SerializedKey,
    sibling: Option<&TapscriptPreimage>,
) -> Result<SerializedKey, Error> {
    let internal_pubkey = ops.parse_internal_key(internal_key)?;
    let tapscript_root = commitment.tapscript_root(sibling)?;
    let output_key =
        ops.taproot_output_key(&internal_pubkey, Some(tapscript_root.to_byte_array()))?;
    Ok(output_key)
}

/// Derives a taproot output key from a tapscript proof.
fn derive_taproot_key_from_tapscript<O: TaprootOps>(
    ops: &O,
    internal_key: &SerializedKey,
    proof: &TapscriptProof,
) -> Result<SerializedKey, Error> {
    let internal_pubkey = ops.parse_internal_key(internal_key)?;
    let preimage1 = proof.tap_preimage1.as_ref();
    let preimage2 = proof.tap_preimage2.as_ref();
    let preimage1_empty = preimage1.map_or(true, |p| p.sibling_preimage.is_empty());
    let preimage2_empty = preimage2.map_or(true, |p| p.sibling_preimage.is_empty());

    let tapscript_root = if !preimage1_empty
        && !preimage2_empty
        && preimage1.unwrap().sibling_type == TapscriptPreimageType::LeafPreimage
        && preimage2.unwrap().sibling_type == TapscriptPreimageType::LeafPreimage
    {
        let left = tapscript_preimage_hash(preimage1.unwrap())?;
        let right = tapscript_preimage_hash(preimage2.unwrap())?;
        Some(TapNodeHash::from_node_hashes(left, right).to_byte_array())
    } else if !preimage1_empty
        && !preimage2_empty
        && preimage1.unwrap().sibling_type == TapscriptPreimageType::BranchPreimage
        && preimage2.unwrap().sibling_type == TapscriptPreimageType::BranchPreimage
    {
        let left = tapscript_preimage_hash(preimage1.unwrap())?;
        let right = tapscript_preimage_hash(preimage2.unwrap())?;
        Some(TapNodeHash::from_node_hashes(left, right).to_byte_array())
    } else if !preimage1_empty
        && !preimage2_empty
        && preimage1.unwrap().sibling_type == TapscriptPreimageType::LeafPreimage
        && preimage2.unwrap().sibling_type == TapscriptPreimageType::BranchPreimage
    {
        let left = tapscript_preimage_hash(preimage1.unwrap())?;
        let right = tapscript_preimage_hash(preimage2.unwrap())?;
        Some(TapNodeHash::from_node_hashes(left, right).to_byte_array())
    } else if !preimage1_empty
        && preimage2_empty
        && preimage1.unwrap().sibling_type == TapscriptPreimageType::LeafPreimage
    {
        let leaf = tapscript_preimage_hash(preimage1.unwrap())?;
        Some(leaf.to_byte_array())
    } else if proof.bip86 {
        None
    } else {
        return Err(Error::InvalidTapscriptProof);
    };

    let output_key = ops.taproot_output_key(&internal_pubkey, tapscript_root)?;
    Ok(output_key)
}

/// Computes the tap hash for a tapscript preimage.
fn tapscript_preimage_hash(preimage: &TapscriptPreimage) -> Result<TapNodeHash, Error> {
    if preimage.sibling_preimage.is_empty() {
        return Err(Error::EmptyTapscriptPreimage);
    }

    match preimage.sibling_type {
        TapscriptPreimageType::LeafPreimage => {
            let (leaf_version, script) = decode_tapleaf_preimage(&preimage.sibling_preimage)?;
            if is_taproot_asset_commitment_script(&script) {
                return Err(Error::TapscriptPreimageIsTapCommitment);
            }
            let script = ScriptBuf::from_bytes(script);
            Ok(TapNodeHash::from_script(script.as_script(), leaf_version))
        }
        TapscriptPreimageType::BranchPreimage => {
            let actual = preimage.sibling_preimage.len();
            if actual != TAP_BRANCH_PREIMAGE_LEN {
                return Err(Error::InvalidTapscriptPreimageLength {
                    expected: TAP_BRANCH_PREIMAGE_LEN,
                    actual,
                });
            }

            let mut left = [0u8; 32];
            left.copy_from_slice(&preimage.sibling_preimage[..32]);
            let mut right = [0u8; 32];
            right.copy_from_slice(&preimage.sibling_preimage[32..]);

            Ok(TapNodeHash::from_node_hashes(
                TapNodeHash::from_byte_array(left),
                TapNodeHash::from_byte_array(right),
            ))
        }
    }
}

/// Decodes a tapleaf preimage into a leaf version and script.
fn decode_tapleaf_preimage(preimage: &[u8]) -> Result<(LeafVersion, Vec<u8>), Error> {
    if preimage.len() < 2 {
        return Err(Error::InvalidTapLeafScriptLength);
    }

    let leaf_version =
        LeafVersion::from_consensus(preimage[0]).map_err(|_| Error::InvalidTapLeafScriptVersion)?;
    if leaf_version != LeafVersion::TapScript {
        return Err(Error::InvalidTapLeafScriptVersion);
    }
    let (script_len, len_len) = decode_compact_size(&preimage[1..])?;
    let script_start = 1 + len_len;
    let script_len = usize::try_from(script_len).map_err(|_| Error::InvalidTapLeafScriptLength)?;
    let script_end = script_start
        .checked_add(script_len)
        .ok_or(Error::InvalidTapLeafScriptLength)?;
    if script_end != preimage.len() {
        return Err(Error::InvalidTapLeafScriptLength);
    }

    let script = preimage[script_start..script_end].to_vec();
    if script.is_empty() || script.len() >= MAX_TAPLEAF_SCRIPT_SIZE {
        return Err(Error::InvalidTapLeafScriptLength);
    }

    Ok((leaf_version, script))
}

/// Decodes a Bitcoin compact size integer from a byte slice.
fn decode_compact_size(bytes: &[u8]) -> Result<(u64, usize), Error> {
    let first = *bytes.first().ok_or(Error::InvalidTapLeafScriptLength)?;
    match first {
        0..=0xFC => Ok((first as u64, 1)),
        0xFD => {
            if bytes.len() < 3 {
                return Err(Error::InvalidTapLeafScriptLength);
            }
            let val = u16::from_le_bytes([bytes[1], bytes[2]]) as u64;
            Ok((val, 3))
        }
        0xFE => {
            if bytes.len() < 5 {
                return Err(Error::InvalidTapLeafScriptLength);
            }
            let val = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as u64;
            Ok((val, 5))
        }
        0xFF => {
            if bytes.len() < 9 {
                return Err(Error::InvalidTapLeafScriptLength);
            }
            let val = u64::from_le_bytes([
                bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
            ]);
            Ok((val, 9))
        }
    }
}

/// Returns true if the script matches the Taproot Asset commitment pattern.
fn is_taproot_asset_commitment_script(script: &[u8]) -> bool {
    if script.len() != TAPROOT_ASSET_COMMITMENT_SCRIPT_SIZE {
        return false;
    }

    match script[0] {
        v if v == TapCommitmentVersion::V0 as u8 || v == TapCommitmentVersion::V1 as u8 => {
            script[1..33] == taproot_assets_marker()
        }
        _ => script[..32] == taproot_assets_v2_tag(),
    }
}

/// Returns the Taproot Asset marker for V0 and V1 commitments.
fn taproot_assets_marker() -> [u8; 32] {
    Sha256Hash::hash(TAPROOT_ASSETS_MARKER_TAG.as_bytes()).to_byte_array()
}

/// Returns the Taproot Asset marker for V2 commitments.
fn taproot_assets_v2_tag() -> [u8; 32] {
    Sha256Hash::hash(TAPROOT_ASSETS_V2_TAG.as_bytes()).to_byte_array()
}

/// Builds a TapCommitment from an inclusion proof.
fn derive_commitment_by_asset_inclusion(
    commitment_proof: &CommitmentProof,
    asset: &Asset,
) -> Result<TapCommitment, Error> {
    let asset_proof = commitment_proof
        .proof
        .asset_proof
        .as_ref()
        .ok_or(Error::MissingAssetProof)?;
    let taproot_asset_proof = &commitment_proof.proof.taproot_asset_proof;

    let asset_key = asset_commitment_key(asset)?;
    let asset_leaf = asset_leaf(asset)?;
    let asset_root = mssmt_root(asset_key, asset_leaf, &asset_proof.proof)?;
    let asset_commitment_root = asset_commitment_root(asset_proof.tap_key, &asset_root);
    let asset_commitment_leaf = asset_commitment_leaf(
        asset_proof.version,
        asset_commitment_root,
        asset_root.root_sum,
    );
    let asset_commitment_leaf_node = mssmt_leaf(&asset_commitment_leaf, asset_root.root_sum);
    let taproot_root = mssmt_root(
        asset_proof.tap_key,
        asset_commitment_leaf_node,
        &taproot_asset_proof.proof,
    )?;

    Ok(TapCommitment {
        version: taproot_asset_proof.version,
        root_hash: taproot_root.root_hash,
        root_sum: taproot_root.root_sum,
    })
}

/// Builds a TapCommitment from an asset exclusion proof.
fn derive_commitment_by_asset_exclusion(
    commitment_proof: &CommitmentProof,
    asset_commitment_key: [u8; 32],
) -> Result<TapCommitment, Error> {
    let asset_proof = commitment_proof
        .proof
        .asset_proof
        .as_ref()
        .ok_or(Error::MissingAssetProof)?;
    let taproot_asset_proof = &commitment_proof.proof.taproot_asset_proof;
    let empty_leaf = mssmt_leaf(&[], 0);
    let asset_root = mssmt_root(asset_commitment_key, empty_leaf, &asset_proof.proof)?;
    let asset_commitment_root = asset_commitment_root(asset_proof.tap_key, &asset_root);
    let asset_commitment_leaf = asset_commitment_leaf(
        asset_proof.version,
        asset_commitment_root,
        asset_root.root_sum,
    );
    let asset_commitment_leaf_node = mssmt_leaf(&asset_commitment_leaf, asset_root.root_sum);
    let taproot_root = mssmt_root(
        asset_proof.tap_key,
        asset_commitment_leaf_node,
        &taproot_asset_proof.proof,
    )?;

    Ok(TapCommitment {
        version: taproot_asset_proof.version,
        root_hash: taproot_root.root_hash,
        root_sum: taproot_root.root_sum,
    })
}

/// Builds a TapCommitment from an asset commitment exclusion proof.
fn derive_commitment_by_asset_commitment_exclusion(
    commitment_proof: &CommitmentProof,
    tap_commitment_key: [u8; 32],
) -> Result<TapCommitment, Error> {
    if commitment_proof.proof.asset_proof.is_some() {
        return Err(Error::InvalidCommitmentProof);
    }
    let taproot_asset_proof = &commitment_proof.proof.taproot_asset_proof;
    let empty_leaf = mssmt_leaf(&[], 0);
    let taproot_root = mssmt_root(tap_commitment_key, empty_leaf, &taproot_asset_proof.proof)?;

    Ok(TapCommitment {
        version: taproot_asset_proof.version,
        root_hash: taproot_root.root_hash,
        root_sum: taproot_root.root_sum,
    })
}

/// Computes the asset commitment root hash from MS-SMT root data.
fn asset_commitment_root(tap_key: [u8; 32], root: &MssmtRoot) -> [u8; 32] {
    let mut engine = Sha256Hash::engine();
    engine.input(&tap_key);
    engine.input(&root.left_hash);
    engine.input(&root.right_hash);
    engine.input(&root.root_sum.to_be_bytes());
    Sha256Hash::from_engine(engine).to_byte_array()
}

/// Encodes an asset commitment leaf for insertion into the TapCommitment tree.
fn asset_commitment_leaf(version: AssetVersion, root_hash: [u8; 32], sum: u64) -> Vec<u8> {
    let mut leaf = Vec::with_capacity(1 + 32 + 8);
    leaf.push(version as u8);
    leaf.extend_from_slice(&root_hash);
    leaf.extend_from_slice(&sum.to_be_bytes());
    leaf
}

/// Computes the taproot asset commitment key for an asset.
fn tap_commitment_key(asset: &Asset) -> Result<[u8; 32], Error> {
    if let Some(group) = &asset.asset_group {
        let key_bytes = if group.tweaked_group_key.is_empty() {
            &group.raw_group_key
        } else {
            &group.tweaked_group_key
        };
        if key_bytes.len() != 33 {
            return Err(Error::InvalidGroupKeyLength {
                expected: 33,
                actual: key_bytes.len(),
            });
        }

        let pubkey =
            SecpPublicKey::from_slice(key_bytes).map_err(|_| Error::InvalidAssetGroupKey)?;
        let (xonly, _) = pubkey.x_only_public_key();
        let hash = Sha256Hash::hash(&xonly.serialize());
        return Ok(hash.to_byte_array());
    }

    let genesis = asset
        .asset_genesis
        .as_ref()
        .ok_or(Error::MissingAssetGenesis)?;
    Ok(genesis.asset_id.to_byte_array())
}

/// Computes the asset commitment key for an asset.
fn asset_commitment_key(asset: &Asset) -> Result<[u8; 32], Error> {
    let genesis = asset
        .asset_genesis
        .as_ref()
        .ok_or(Error::MissingAssetGenesis)?;
    if asset.script_key.len() != 33 {
        return Err(Error::InvalidAssetScriptKeyLength {
            expected: 33,
            actual: asset.script_key.len(),
        });
    }
    let script_key =
        SecpPublicKey::from_slice(&asset.script_key).map_err(|_| Error::InvalidAssetScriptKey)?;
    let (xonly, _) = script_key.x_only_public_key();

    let issuance_disabled = asset.asset_group.is_none();
    if issuance_disabled {
        return Ok(Sha256Hash::hash(&xonly.serialize()).to_byte_array());
    }

    let mut engine = Sha256Hash::engine();
    engine.input(&genesis.asset_id.to_byte_array());
    engine.input(&xonly.serialize());
    Ok(Sha256Hash::from_engine(engine).to_byte_array())
}

/// Returns true if the asset contains a split commitment witness.
fn asset_has_split_commitment_witness(asset: &Asset) -> bool {
    if asset.prev_witnesses.len() != 1 {
        return false;
    }

    let witness = &asset.prev_witnesses[0];
    witness.prev_id.is_some() && witness.tx_witness.is_empty() && witness.split_commitment.is_some()
}

/// Returns a copy of the asset without any split commitment witness.
fn asset_without_split_commitment(asset: &Asset) -> Asset {
    let mut asset = asset.clone();
    if asset_has_split_commitment_witness(&asset) {
        asset.prev_witnesses[0].split_commitment = None;
    }
    asset
}

/// Builds an MS-SMT leaf from bytes and a sum.
fn mssmt_leaf(value: &[u8], sum: u64) -> MssmtNode {
    let mut engine = Sha256Hash::engine();
    engine.input(value);
    engine.input(&sum.to_be_bytes());
    let hash = Sha256Hash::from_engine(engine);
    MssmtNode { hash, sum }
}

/// Builds an MS-SMT branch from two child nodes.
fn mssmt_branch(left: &MssmtNode, right: &MssmtNode) -> Result<MssmtNode, Error> {
    let sum = left
        .sum
        .checked_add(right.sum)
        .ok_or(Error::MssmtSumOverflow)?;

    let mut engine = Sha256Hash::engine();
    engine.input(&left.hash.to_byte_array());
    engine.input(&right.hash.to_byte_array());
    engine.input(&sum.to_be_bytes());
    let hash = Sha256Hash::from_engine(engine);
    Ok(MssmtNode { hash, sum })
}

/// Computes the MS-SMT root for a leaf and proof.
fn mssmt_root(key: [u8; 32], leaf: MssmtNode, proof: &MssmtProof) -> Result<MssmtRoot, Error> {
    let nodes = normalize_mssmt_nodes(&proof.nodes)?;
    let mut current = leaf;
    let mut root_left = [0u8; 32];
    let mut root_right = [0u8; 32];

    for i in (0..MSSMT_TREE_LEVELS).rev() {
        let sibling = &nodes[MSSMT_TREE_LEVELS - 1 - i];
        let bit = mssmt_bit_index(i as u8, &key);
        let (left, right) = if bit == 0 {
            (&current, sibling)
        } else {
            (sibling, &current)
        };

        if i == 0 {
            root_left = left.hash.to_byte_array();
            root_right = right.hash.to_byte_array();
        }

        current = mssmt_branch(left, right)?;
    }

    Ok(MssmtRoot {
        root_hash: current.hash.to_byte_array(),
        root_sum: current.sum,
        left_hash: root_left,
        right_hash: root_right,
    })
}

/// Returns the bit at an index for an MS-SMT key.
fn mssmt_bit_index(idx: u8, key: &[u8; 32]) -> u8 {
    let byte_val = key[(idx / 8) as usize];
    (byte_val >> (idx % 8)) & 1
}

/// Normalizes MS-SMT proof nodes, expanding empty nodes as needed.
fn normalize_mssmt_nodes(nodes: &[MssmtNode]) -> Result<Vec<MssmtNode>, Error> {
    if nodes.len() != MSSMT_TREE_LEVELS {
        return Err(Error::InvalidMssmtProofLength {
            expected: MSSMT_TREE_LEVELS,
            actual: nodes.len(),
        });
    }

    let empty_nodes = mssmt_empty_nodes();
    let mut normalized = Vec::with_capacity(MSSMT_TREE_LEVELS);
    for (idx, node) in nodes.iter().enumerate() {
        let height = MSSMT_TREE_LEVELS - idx;
        if is_zero_mssmt_node(node) {
            normalized.push(empty_nodes[height].clone());
        } else {
            normalized.push(node.clone());
        }
    }

    Ok(normalized)
}

/// Returns true if an MS-SMT node is the zero placeholder.
fn is_zero_mssmt_node(node: &MssmtNode) -> bool {
    node.hash == Sha256Hash::all_zeros() && node.sum == 0
}

/// Returns the empty MS-SMT nodes from root to leaf.
fn mssmt_empty_nodes() -> Vec<MssmtNode> {
    let mut nodes = Vec::with_capacity(MSSMT_TREE_LEVELS + 1);
    nodes.resize_with(MSSMT_TREE_LEVELS + 1, || MssmtNode {
        hash: Sha256Hash::all_zeros(),
        sum: 0,
    });

    let leaf = mssmt_leaf(&[], 0);
    nodes[MSSMT_TREE_LEVELS] = leaf.clone();
    for i in (0..MSSMT_TREE_LEVELS).rev() {
        let parent = mssmt_branch(&nodes[i + 1], &nodes[i + 1]).unwrap_or(leaf.clone());
        nodes[i] = parent;
    }

    nodes
}

/// Encodes an asset into a leaf node.
fn asset_leaf(asset: &Asset) -> Result<MssmtNode, Error> {
    let include_witness = asset.version == AssetVersion::V0;
    let bytes = encode_asset(asset, include_witness)?;
    Ok(mssmt_leaf(&bytes, asset.amount))
}

/// Encodes an asset into TLV bytes.
fn encode_asset(asset: &Asset, include_tx_witness: bool) -> Result<Vec<u8>, Error> {
    let genesis = asset
        .asset_genesis
        .as_ref()
        .ok_or(Error::MissingAssetGenesis)?;
    let mut out = Vec::new();

    encode_record(ASSET_LEAF_VERSION, &[asset.version as u8], &mut out);
    let genesis_bytes = encode_genesis_info(genesis)?;
    encode_record(ASSET_LEAF_GENESIS, &genesis_bytes, &mut out);
    encode_record(
        ASSET_LEAF_TYPE,
        &[asset_type_byte(genesis.asset_type)],
        &mut out,
    );
    let amount_bytes = encode_bigsize_to_vec(asset.amount);
    encode_record(ASSET_LEAF_AMOUNT, &amount_bytes, &mut out);
    if asset.lock_time > 0 {
        let bytes = encode_bigsize_to_vec(asset.lock_time as u64);
        encode_record(ASSET_LEAF_LOCK_TIME, &bytes, &mut out);
    }
    if asset.relative_lock_time > 0 {
        let bytes = encode_bigsize_to_vec(asset.relative_lock_time as u64);
        encode_record(ASSET_LEAF_RELATIVE_LOCK_TIME, &bytes, &mut out);
    }
    if !asset.prev_witnesses.is_empty() {
        let witnesses = encode_prev_witnesses(&asset.prev_witnesses, include_tx_witness)?;
        encode_record(ASSET_LEAF_PREV_WITNESS, &witnesses, &mut out);
    }
    if let Some(root) = asset.split_commitment_root.as_ref() {
        let bytes = encode_split_commitment_root(root);
        encode_record(ASSET_LEAF_SPLIT_COMMITMENT_ROOT, &bytes, &mut out);
    }
    let script_version =
        u16::try_from(asset.script_version).map_err(|_| Error::InvalidAssetScriptVersion)?;
    encode_record(
        ASSET_LEAF_SCRIPT_VERSION,
        &script_version.to_be_bytes(),
        &mut out,
    );
    if asset.script_key.len() != 33 {
        return Err(Error::InvalidAssetScriptKeyLength {
            expected: 33,
            actual: asset.script_key.len(),
        });
    }
    encode_record(ASSET_LEAF_SCRIPT_KEY, &asset.script_key, &mut out);
    if let Some(group) = asset.asset_group.as_ref() {
        let key_bytes = &group.raw_group_key;
        if key_bytes.len() != 33 {
            return Err(Error::InvalidGroupKeyLength {
                expected: 33,
                actual: key_bytes.len(),
            });
        }
        encode_record(ASSET_LEAF_GROUP_KEY, key_bytes, &mut out);
    }

    Ok(out)
}

/// Encodes a genesis record into TLV bytes.
fn encode_genesis_info(genesis: &GenesisInfo) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_outpoint(&genesis.genesis_point, &mut out);
    encode_inline_var_bytes(genesis.name.as_bytes(), &mut out);
    out.extend_from_slice(&genesis.meta_hash.to_byte_array());
    out.extend_from_slice(&genesis.output_index.to_be_bytes());
    out.push(asset_type_byte(genesis.asset_type));
    Ok(out)
}

/// Encodes a Bitcoin outpoint into bytes.
fn encode_outpoint(out_point: &OutPoint, out: &mut Vec<u8>) {
    out.extend_from_slice(&out_point.txid.to_byte_array());
    out.extend_from_slice(&out_point.vout.to_be_bytes());
}

/// Encodes an asset type to a protocol byte.
fn asset_type_byte(asset_type: AssetType) -> u8 {
    match asset_type {
        AssetType::Normal => 0,
        AssetType::Collectible => 1,
    }
}

/// Encodes a list of prev witnesses into TLV bytes.
fn encode_prev_witnesses(
    witnesses: &[PrevWitness],
    include_tx_witness: bool,
) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    encode_bigsize(witnesses.len() as u64, &mut out);
    for witness in witnesses {
        let bytes = encode_prev_witness(witness, include_tx_witness)?;
        encode_inline_var_bytes(&bytes, &mut out);
    }
    Ok(out)
}

/// Encodes a prev witness into TLV bytes.
fn encode_prev_witness(witness: &PrevWitness, include_tx_witness: bool) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();

    if let Some(prev_id) = witness.prev_id.as_ref() {
        let bytes = encode_prev_id(prev_id);
        encode_record(WITNESS_PREV_ID, &bytes, &mut out);
    }
    if include_tx_witness && !witness.tx_witness.is_empty() {
        let bytes = encode_tx_witness(&witness.tx_witness);
        encode_record(WITNESS_TX_WITNESS, &bytes, &mut out);
    }
    if let Some(split_commitment) = witness.split_commitment.as_ref() {
        let bytes = encode_split_commitment(split_commitment)?;
        encode_record(WITNESS_SPLIT_COMMITMENT, &bytes, &mut out);
    }

    Ok(out)
}

/// Encodes a prev ID into bytes.
fn encode_prev_id(prev_id: &PrevId) -> Vec<u8> {
    let mut out = Vec::new();
    encode_outpoint(&prev_id.out_point, &mut out);
    out.extend_from_slice(&prev_id.asset_id.to_byte_array());
    out.extend_from_slice(&prev_id.script_key.bytes);
    out
}

/// Encodes a transaction witness into bytes.
fn encode_tx_witness(witness: &Witness) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bigsize(witness.len() as u64, &mut out);
    for item in witness.iter() {
        encode_inline_var_bytes(item, &mut out);
    }
    out
}

/// Encodes a split commitment into bytes.
fn encode_split_commitment(commitment: &SplitCommitment) -> Result<Vec<u8>, Error> {
    let proof_bytes = encode_compressed_proof(&commitment.proof)?;
    let asset_bytes = encode_asset(&commitment.root_asset, true)?;
    let mut out = Vec::new();
    encode_inline_var_bytes(&proof_bytes, &mut out);
    encode_inline_var_bytes(&asset_bytes, &mut out);
    Ok(out)
}

/// Encodes a compressed MS-SMT proof into bytes.
fn encode_compressed_proof(proof: &MssmtProof) -> Result<Vec<u8>, Error> {
    let nodes = normalize_mssmt_nodes(&proof.nodes)?;
    let empty_nodes = mssmt_empty_nodes();
    let mut bits = Vec::with_capacity(MSSMT_TREE_LEVELS);
    let mut explicit_nodes = Vec::new();
    for (idx, node) in nodes.iter().enumerate() {
        let height = MSSMT_TREE_LEVELS - idx;
        let empty = &empty_nodes[height];
        let is_empty = node.hash == empty.hash && node.sum == empty.sum;
        bits.push(is_empty);
        if !is_empty {
            explicit_nodes.push(node);
        }
    }

    let mut out = Vec::new();
    let node_count = u16::try_from(explicit_nodes.len()).unwrap_or(u16::MAX);
    out.extend_from_slice(&node_count.to_be_bytes());
    for node in explicit_nodes {
        out.extend_from_slice(&node.hash.to_byte_array());
        out.extend_from_slice(&node.sum.to_be_bytes());
    }
    let packed = pack_bits(&bits);
    out.extend_from_slice(&packed);
    Ok(out)
}

/// Encodes a split commitment root node into bytes.
fn encode_split_commitment_root(root: &MssmtNode) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + 8);
    out.extend_from_slice(&root.hash.to_byte_array());
    out.extend_from_slice(&root.sum.to_be_bytes());
    out
}

/// Packs a bit slice into bytes using little-endian bit ordering.
fn pack_bits(bits: &[bool]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity((bits.len() + 7) / 8);
    bytes.resize((bits.len() + 7) / 8, 0);
    for (idx, bit) in bits.iter().enumerate() {
        if *bit {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            bytes[byte_idx] |= 1 << bit_idx;
        }
    }
    bytes
}

/// Encodes a TLV record into the provided buffer.
fn encode_record(tlv_type: u64, value: &[u8], out: &mut Vec<u8>) {
    encode_bigsize(tlv_type, out);
    encode_bigsize(value.len() as u64, out);
    out.extend_from_slice(value);
}

/// Encodes a BigSize varint into the provided buffer.
fn encode_bigsize(value: u64, out: &mut Vec<u8>) {
    match value {
        0..=0xFC => out.push(value as u8),
        0xFD..=0xFFFF => {
            out.push(0xFD);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xFFFF_FFFF => {
            out.push(0xFE);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(0xFF);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

/// Encodes a BigSize varint into a new byte vector.
fn encode_bigsize_to_vec(value: u64) -> Vec<u8> {
    let mut out = Vec::new();
    encode_bigsize(value, &mut out);
    out
}

/// Encodes inline var bytes into the provided buffer.
fn encode_inline_var_bytes(bytes: &[u8], out: &mut Vec<u8>) {
    encode_bigsize(bytes.len() as u64, out);
    out.extend_from_slice(bytes);
}

/// Converts a full public key into a serialized key wrapper.
fn serialized_key_from_pubkey(pubkey: &bitcoin::PublicKey) -> SerializedKey {
    SerializedKey {
        bytes: pubkey.inner.serialize(),
    }
}

/// Extracts an x-only key from a serialized compressed public key.
fn xonly_from_serialized_key(key: &SerializedKey) -> Result<[u8; 32], Error> {
    let pubkey =
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| Error::InvalidTaprootOutputKey)?;
    let (xonly, _) = pubkey.x_only_public_key();
    Ok(xonly.serialize())
}

/// TLV type for the asset version field.
const ASSET_LEAF_VERSION: u64 = 0;
/// TLV type for the asset genesis field.
const ASSET_LEAF_GENESIS: u64 = 2;
/// TLV type for the asset type field.
const ASSET_LEAF_TYPE: u64 = 4;
/// TLV type for the asset amount field.
const ASSET_LEAF_AMOUNT: u64 = 6;
/// TLV type for the asset lock time field.
const ASSET_LEAF_LOCK_TIME: u64 = 7;
/// TLV type for the asset relative lock time field.
const ASSET_LEAF_RELATIVE_LOCK_TIME: u64 = 9;
/// TLV type for the asset prev witness field.
const ASSET_LEAF_PREV_WITNESS: u64 = 11;
/// TLV type for the asset split commitment root field.
const ASSET_LEAF_SPLIT_COMMITMENT_ROOT: u64 = 13;
/// TLV type for the asset script version field.
const ASSET_LEAF_SCRIPT_VERSION: u64 = 14;
/// TLV type for the asset script key field.
const ASSET_LEAF_SCRIPT_KEY: u64 = 16;
/// TLV type for the asset group key field.
const ASSET_LEAF_GROUP_KEY: u64 = 17;

/// TLV type for the witness prev ID field.
const WITNESS_PREV_ID: u64 = 1;
/// TLV type for the witness tx witness field.
const WITNESS_TX_WITNESS: u64 = 3;
/// TLV type for the witness split commitment field.
const WITNESS_SPLIT_COMMITMENT: u64 = 5;
