use crate::taprpc;
use taproot_assets_types as types;

use bitcoin::hashes::{sha256::Hash as Sha256Hash, Hash};
use bitcoin::{BlockHash, OutPoint, Witness};
use std::convert::{TryFrom, TryInto};
use std::str::FromStr;

#[derive(Debug)]
pub enum ConversionError {
    InvalidEnumValue(String),
    MissingField(String), // Kept for future use, not used in current impl
    InvalidStringFormat(String),
    InvalidHashBytes(String),
    InvalidWitnessData(String), // Kept for future use
    RecursiveError(Box<ConversionError>),
    Other(String), // Generic fallback
}

pub type Result<T> = std::result::Result<T, ConversionError>;

impl std::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConversionError::InvalidEnumValue(s) => write!(f, "Invalid enum value: {}", s),
            ConversionError::MissingField(s) => write!(f, "Missing field: {}", s),
            ConversionError::InvalidStringFormat(s) => write!(f, "Invalid string format: {}", s),
            ConversionError::InvalidHashBytes(s) => write!(f, "Invalid hash bytes: {}", s),
            ConversionError::InvalidWitnessData(s) => write!(f, "Invalid witness data: {}", s),
            ConversionError::RecursiveError(e) => write!(f, "Recursive conversion error: {}", e),
            ConversionError::Other(s) => write!(f, "Conversion error: {}", s),
        }
    }
}

impl std::error::Error for ConversionError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConversionError::RecursiveError(e) => Some(e.as_ref()),
            _ => None,
        }
    }
}

impl From<bitcoin::hashes::FromSliceError> for ConversionError {
    fn from(e: bitcoin::hashes::FromSliceError) -> Self {
        ConversionError::InvalidHashBytes(format!("Failed to convert from slice: {}", e))
    }
}

impl From<bitcoin::consensus::encode::Error> for ConversionError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        ConversionError::Other(format!("Bitcoin consensus decoding error: {}", e))
    }
}

// Helper for hash conversion from Vec<u8> to Sha256Hash
fn vec_to_sha256hash(bytes: Vec<u8>, field_name: &str) -> Result<Sha256Hash> {
    Sha256Hash::from_slice(&bytes).map_err(|err| {
        ConversionError::InvalidHashBytes(format!(
            "Invalid {} hash bytes (expected 32 for {}): {}, (got {} bytes)",
            field_name,
            field_name,
            err,
            bytes.len()
        ))
    })
}

// Helper to parse OutPoint from string "txid:vout"
fn string_to_outpoint(s: String, field_name: &str) -> Result<OutPoint> {
    OutPoint::from_str(&s).map_err(|e| {
        ConversionError::InvalidStringFormat(format!(
            "Failed to parse {} from '{}': {}",
            field_name, s, e
        ))
    })
}

// Helper to parse BlockHash from string
fn string_to_blockhash(s: String, field_name: &str) -> Result<BlockHash> {
    BlockHash::from_str(&s).map_err(|e| {
        ConversionError::InvalidStringFormat(format!(
            "Failed to parse {} from '{}': {}",
            field_name, s, e
        ))
    })
}

// Helper for Option<F> -> Result<Option<R>, E> conversion
fn try_option<F, R>(opt_f: Option<F>) -> Result<Option<R>>
where
    F: TryInto<R, Error = ConversionError>,
{
    opt_f
        .map(TryInto::try_into)
        .transpose()
        .map_err(|err| ConversionError::RecursiveError(Box::new(err)))
}

// Helper for Vec<F> -> Result<Vec<R>, E> conversion
fn try_vec<F, R>(vec_f: Vec<F>) -> Result<Vec<R>>
where
    F: TryInto<R, Error = ConversionError>,
{
    vec_f
        .into_iter()
        .map(TryInto::try_into)
        .collect::<std::result::Result<Vec<R>, ConversionError>>()
        .map_err(|err| ConversionError::RecursiveError(Box::new(err)))
}

// --- Struct Conversions ---

impl TryFrom<taprpc::DecimalDisplay> for types::asset::DecimalDisplay {
    type Error = ConversionError;

    fn try_from(value: taprpc::DecimalDisplay) -> Result<Self> {
        Ok(types::asset::DecimalDisplay {
            decimal_display: value.decimal_display,
        })
    }
}

impl TryFrom<taprpc::GenesisInfo> for types::asset::GenesisInfo {
    type Error = ConversionError;

    fn try_from(value: taprpc::GenesisInfo) -> Result<Self> {
        Ok(types::asset::GenesisInfo {
            genesis_point: string_to_outpoint(value.genesis_point, "GenesisInfo.genesis_point")?,
            name: value.name,
            meta_hash: vec_to_sha256hash(value.meta_hash, "GenesisInfo.meta_hash")?,
            asset_id: vec_to_sha256hash(value.asset_id, "GenesisInfo.asset_id")?,
            asset_type: types::asset::AssetType::try_from(value.asset_type).map_err(|e| {
                ConversionError::InvalidEnumValue(format!(
                    "GenesisInfo.asset_type (value: {}): {}",
                    value.asset_type, e
                ))
            })?,
            output_index: value.output_index,
        })
    }
}

impl TryFrom<taprpc::AssetGroup> for types::asset::AssetGroup {
    type Error = ConversionError;

    fn try_from(value: taprpc::AssetGroup) -> Result<Self> {
        let tapscript_root = if value.tapscript_root.is_empty() {
            None
        } else {
            Some(vec_to_sha256hash(
                value.tapscript_root,
                "AssetGroup.tapscript_root",
            )?)
        };

        Ok(types::asset::AssetGroup {
            raw_group_key: value.raw_group_key,
            tweaked_group_key: value.tweaked_group_key,
            asset_witness: value.asset_witness,
            tapscript_root: tapscript_root,
        })
    }
}

impl TryFrom<taprpc::AnchorInfo> for types::asset::AnchorInfo {
    type Error = ConversionError;

    fn try_from(value: taprpc::AnchorInfo) -> Result<Self> {
        let tx = bitcoin::consensus::encode::deserialize(&value.anchor_tx)?;

        Ok(types::asset::AnchorInfo {
            anchor_tx: tx,
            anchor_block_hash: string_to_blockhash(
                value.anchor_block_hash,
                "AnchorInfo.anchor_block_hash",
            )?,
            anchor_outpoint: string_to_outpoint(
                value.anchor_outpoint,
                "AnchorInfo.anchor_outpoint",
            )?,
            internal_key: value.internal_key,
            merkle_root: vec_to_sha256hash(value.merkle_root, "AnchorInfo.merkle_root")?,
            tapscript_sibling: value.tapscript_sibling,
            block_height: value.block_height,
            block_timestamp: value.block_timestamp,
        })
    }
}

impl TryFrom<taprpc::PrevInputAsset> for types::asset::PrevInputAsset {
    type Error = ConversionError;

    fn try_from(value: taprpc::PrevInputAsset) -> Result<Self> {
        Ok(types::asset::PrevInputAsset {
            anchor_point: string_to_outpoint(value.anchor_point, "PrevInputAsset.anchor_point")?,
            asset_id: vec_to_sha256hash(value.asset_id, "PrevInputAsset.asset_id")?,
            script_key: value.script_key,
            amount: value.amount,
        })
    }
}

impl TryFrom<taprpc::Asset> for types::asset::Asset {
    type Error = ConversionError;

    fn try_from(value: taprpc::Asset) -> Result<Self> {
        Ok(types::asset::Asset {
            version: types::asset::AssetVersion::try_from(value.version).map_err(|e| {
                ConversionError::InvalidEnumValue(format!(
                    "Asset.version (value: {}): {}",
                    value.version, e
                ))
            })?,
            asset_genesis: try_option(value.asset_genesis)?,
            amount: value.amount,
            lock_time: value.lock_time,
            relative_lock_time: value.relative_lock_time,
            script_version: value.script_version,
            script_key: value.script_key,
            script_key_is_local: value.script_key_is_local,
            asset_group: try_option(value.asset_group)?,
            chain_anchor: try_option(value.chain_anchor)?,
            prev_witnesses: try_vec(value.prev_witnesses)?,
            is_spent: value.is_spent,
            lease_owner: value.lease_owner,
            lease_expiry: value.lease_expiry,
            is_burn: value.is_burn,
            script_key_declared_known: value.script_key_declared_known,
            script_key_has_script_path: value.script_key_has_script_path,
            decimal_display: try_option(value.decimal_display)?,
            script_key_type: types::asset::ScriptKeyType::try_from(value.script_key_type).map_err(
                |e| {
                    ConversionError::InvalidEnumValue(format!(
                        "Asset.script_key_type (value: {}): {}",
                        value.script_key_type, e
                    ))
                },
            )?,
        })
    }
}

impl TryFrom<taprpc::SplitCommitment> for types::asset::SplitCommitment {
    type Error = ConversionError;

    fn try_from(value: taprpc::SplitCommitment) -> Result<Self> {
        let root_asset = match value.root_asset {
            Some(rpc_asset) => {
                let domain_asset: types::asset::Asset = rpc_asset
                    .try_into()
                    .map_err(|e: ConversionError| ConversionError::RecursiveError(Box::new(e)))?;
                Some(Box::new(domain_asset))
            }
            None => None,
        };
        Ok(types::asset::SplitCommitment { root_asset })
    }
}

impl TryFrom<taprpc::PrevWitness> for types::asset::PrevWitness {
    type Error = ConversionError;

    fn try_from(value: taprpc::PrevWitness) -> Result<Self> {
        Ok(types::asset::PrevWitness {
            prev_id: try_option(value.prev_id)?,
            tx_witness: Witness::from(value.tx_witness),
            split_commitment: try_option(value.split_commitment)?,
        })
    }
}

impl TryFrom<taprpc::ListAssetResponse> for crate::taprpc::types::ListAssetsResponse {
    type Error = ConversionError;

    fn try_from(value: taprpc::ListAssetResponse) -> Result<Self> {
        let assets = value
            .assets
            .into_iter()
            .map(types::asset::Asset::try_from)
            .collect::<Result<Vec<types::asset::Asset>>>()
            .map_err(|e| ConversionError::RecursiveError(Box::new(e)))?;

        Ok(crate::taprpc::types::ListAssetsResponse {
            assets,
            unconfirmed_transfers: value.unconfirmed_transfers,
            unconfirmed_mints: value.unconfirmed_mints,
        })
    }
}

impl TryFrom<taprpc::ProofFile> for crate::taprpc::types::ExportProofResponse {
    type Error = ConversionError;

    fn try_from(value: taprpc::ProofFile) -> Result<Self> {
        let genesis_point = if value.genesis_point.is_empty() {
            None
        } else {
            Some(string_to_outpoint(
                value.genesis_point,
                "ProofFile.genesis_point",
            )?)
        };

        Ok(crate::taprpc::types::ExportProofResponse {
            raw_proof_file: value.raw_proof_file,
            genesis_point: genesis_point,
        })
    }
}

impl TryFrom<taprpc::VerifyProofResponse> for crate::taprpc::types::VerifyProofResponse {
    type Error = ConversionError;

    fn try_from(value: taprpc::VerifyProofResponse) -> Result<Self> {
        Ok(crate::taprpc::types::VerifyProofResponse {
            valid: value.valid,
            decoded_proof: try_option(value.decoded_proof)?,
        })
    }
}

// --- Proof Conversion ---

impl TryFrom<taprpc::AssetMeta> for types::asset::AssetMeta {
    type Error = ConversionError;

    fn try_from(value: taprpc::AssetMeta) -> Result<Self> {
        Ok(types::asset::AssetMeta {
            data: value.data,
            meta_type: types::asset::AssetMetaType::try_from(value.r#type).map_err(|e| {
                ConversionError::InvalidEnumValue(format!(
                    "AssetMeta.type (value: {}): {}",
                    value.r#type, e
                ))
            })?,
        })
    }
}

// --- Fixed GenesisReveal conversion ---
impl TryFrom<taprpc::GenesisReveal> for types::asset::GenesisReveal {
    type Error = ConversionError;

    fn try_from(value: taprpc::GenesisReveal) -> Result<Self> {
        // The taprpc::GenesisReveal only contains genesis_base_reveal, but
        // types::asset::GenesisReveal requires additional fields. Since these
        // aren't available in the RPC structure, we use reasonable defaults.
        Ok(types::asset::GenesisReveal {
            genesis_base: try_option(value.genesis_base_reveal)?,
            asset_type: types::asset::AssetType::Normal, // Default to Normal type
            amount: 0,         // Default amount since not available in RPC
            meta_reveal: None, // No meta reveal available in RPC
        })
    }
}

impl TryFrom<taprpc::GroupKeyReveal> for types::asset::GroupKeyReveal {
    type Error = ConversionError;

    fn try_from(value: taprpc::GroupKeyReveal) -> Result<Self> {
        let tapscript_root = if value.tapscript_root.is_empty() {
            None
        } else {
            Some(vec_to_sha256hash(
                value.tapscript_root,
                "GroupKeyReveal.tapscript_root",
            )?)
        };

        Ok(types::asset::GroupKeyReveal {
            raw_group_key: value.raw_group_key,
            tapscript_root,
        })
    }
}

impl TryFrom<taprpc::DecodedProof> for crate::taprpc::types::DecodedProof {
    type Error = ConversionError;

    fn try_from(value: taprpc::DecodedProof) -> Result<Self> {
        let challenge_witness = if value.challenge_witness.is_empty() {
            None
        } else {
            Some(Witness::from(value.challenge_witness))
        };

        let inclusion_proof = types::proof::TaprootProof::from_bytes(&value.inclusion_proof)
            .map_err(|e| {
                ConversionError::Other(format!("Failed to decode inclusion proof: {}", e))
            })?;

        let exclusion_proofs = value
            .exclusion_proofs
            .into_iter()
            .map(|proof_bytes| {
                types::proof::TaprootProof::from_bytes(&proof_bytes).map_err(|e| {
                    ConversionError::Other(format!("Failed to decode exclusion proof: {}", e))
                })
            })
            .collect::<Result<Vec<types::proof::TaprootProof>>>()?;

        let split_root_proof = if value.split_root_proof.is_empty() {
            None
        } else {
            Some(
                types::proof::TaprootProof::from_bytes(&value.split_root_proof).map_err(|e| {
                    ConversionError::Other(format!("Failed to decode split root proof: {}", e))
                })?,
            )
        };

        let tx_merkle_proof = types::proof::TxMerkleProof::from_bytes(&value.tx_merkle_proof)
            .map_err(|e| {
                ConversionError::Other(format!("Failed to decode tx merkle proof: {}", e))
            })?;

        Ok(crate::taprpc::types::DecodedProof {
            proof_at_depth: value.proof_at_depth,
            number_of_proofs: value.number_of_proofs,
            asset: value
                .asset
                .ok_or_else(|| ConversionError::MissingField("DecodedProof.asset".to_string()))?
                .try_into()?,
            meta_reveal: try_option(value.meta_reveal)?,
            tx_merkle_proof,
            inclusion_proof,
            exclusion_proofs,
            split_root_proof,
            num_additional_inputs: value.num_additional_inputs,
            challenge_witness,
            is_burn: value.is_burn,
            genesis_reveal: try_option(value.genesis_reveal)?,
            group_key_reveal: try_option(value.group_key_reveal)?,
        })
    }
}

// --- Commenting out TxMerkleProof conversion due to field mismatch ---
/*
impl TryFrom<taprpc::TxMerkleProof> for types::proof::TxMerkleProof {
    type Error = ConversionError;

    fn try_from(value: taprpc::TxMerkleProof) -> Result<Self> {
        // The `taprpc::TxMerkleProof` does not contain the `bits` field that is
        // part of `types::proof::TxMerkleProof`. The `bits` are used to
        // determine the side of the sibling hash in the merkle tree.
        // Without this information, we cannot fully construct the proof.
        // The `block_header` and `tx_index` are also not used here.
        // This suggests a potential mismatch between the rpc and type definitions.
        let nodes = value
            .merkle_nodes
            .into_iter()
            .map(|node_bytes| {
                bitcoin::TxMerkleNode::from_slice(&node_bytes).map_err(|e| {
                    ConversionError::InvalidHashBytes(format!(
                        "Invalid TxMerkleNode hash bytes: {}",
                        e
                    ))
                })
            })
            .collect::<Result<Vec<bitcoin::TxMerkleNode>>>()?;

        Ok(types::proof::TxMerkleProof {
            nodes,
            bits: vec![], // Bits are not available in taprpc::TxMerkleProof
        })
    }
}
*/
