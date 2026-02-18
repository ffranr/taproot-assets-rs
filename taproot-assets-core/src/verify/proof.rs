//! Proof-level verification helpers.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::{Hash, HashEngine, sha256::Hash as Sha256Hash};
use bitcoin::secp256k1::{Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{OutPoint, Transaction, Txid};
use serde::{Deserialize, Serialize};
use taproot_assets_types::asset::{
    Asset, AssetType, AssetVersion, GenesisInfo, GenesisReveal, GroupKeyReveal, PrevId,
    PrevWitness, ScriptKeyType, SerializedKey,
};
use taproot_assets_types::commitment::TapCommitmentVersion;
use taproot_assets_types::proof::{CommitmentProof, MetaReveal, Proof, TaprootProof};

use crate::TaprootOps;
use crate::verify::{group_key_reveal, taproot_proof};

/// Transition version that enables STXO proofs.
const PROOF_VERSION_V1: u32 = 1;
/// Length in bytes of a compressed public key.
const COMPRESSED_KEY_LEN: usize = 33;
/// NUMS key used for burn key derivation.
const NUMS_COMPRESSED_KEY: [u8; COMPRESSED_KEY_LEN] = [
    0x02, 0x7c, 0x79, 0xb9, 0xb2, 0x6e, 0x46, 0x38, 0x95, 0xee, 0xf5, 0x67, 0x9d, 0x85, 0x58, 0x94,
    0x2c, 0x86, 0xc4, 0xad, 0x22, 0x33, 0xad, 0xef, 0x01, 0xbc, 0x3e, 0x6d, 0x54, 0x0b, 0x36, 0x53,
    0xfe,
];
/// TLV type for the meta reveal encoding field.
const META_REVEAL_ENCODING_TYPE: u64 = 0;
/// TLV type for the meta reveal data field.
const META_REVEAL_DATA_TYPE: u64 = 2;

/// Map of output indexes to the STXO script keys they must prove.
type P2TROutputsSTXOs = BTreeMap<u32, BTreeSet<SerializedKey>>;
/// TapCommitment versions observed per output.
type CommittedVersions = BTreeMap<u32, Vec<TapCommitmentVersion>>;

/// Minimal witness data needed to determine genesis status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisWitnessInput {
    /// Previous input reference for the witness.
    pub prev_id: Option<PrevId>,
    /// Whether the witness includes any transaction witness data.
    pub has_tx_witness: bool,
    /// Whether the witness includes a split commitment.
    pub has_split_commitment: bool,
}

/// Minimal asset data required for genesis reveal verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAssetInput {
    /// Asset genesis identifier, if present.
    pub asset_genesis_id: Option<Sha256Hash>,
    /// Whether the asset declares membership in an asset group.
    pub has_asset_group: bool,
    /// Previous witnesses used to determine genesis status.
    pub prev_witnesses: Vec<GenesisWitnessInput>,
}

/// Minimal input required to verify genesis and meta reveal constraints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisRevealInput {
    /// Previous outpoint referenced by the proof.
    pub prev_out: OutPoint,
    /// Output index from the inclusion proof.
    pub inclusion_output_index: u32,
    /// Genesis reveal payload, if present.
    pub genesis_reveal: Option<GenesisReveal>,
    /// Meta reveal payload, if present.
    pub meta_reveal: Option<MetaReveal>,
    /// Asset fields required for genesis verification.
    pub asset: GenesisAssetInput,
}

impl GenesisRevealInput {
    /// Builds a genesis reveal input from a full proof.
    pub fn from_proof(proof: &Proof) -> Self {
        GenesisRevealInput {
            prev_out: proof.prev_out,
            inclusion_output_index: proof.inclusion_proof.output_index,
            genesis_reveal: proof.genesis_reveal.clone(),
            meta_reveal: proof.meta_reveal.clone(),
            asset: genesis_asset_input_from_asset(&proof.asset),
        }
    }
}

fn genesis_asset_input_from_asset(asset: &Asset) -> GenesisAssetInput {
    let prev_witnesses = asset
        .prev_witnesses
        .iter()
        .map(|witness| GenesisWitnessInput {
            prev_id: witness.prev_id.clone(),
            has_tx_witness: !witness.tx_witness.is_empty(),
            has_split_commitment: witness.split_commitment.is_some(),
        })
        .collect();

    GenesisAssetInput {
        asset_genesis_id: asset.asset_genesis.as_ref().map(|genesis| genesis.asset_id),
        has_asset_group: asset.asset_group.is_some(),
        prev_witnesses,
    }
}

/// SHA-256 hashing interface used by proof verification.
pub trait Sha256Hasher {
    /// Returns the SHA-256 digest of the provided bytes.
    fn hash(&self, data: &[u8]) -> [u8; 32];
}

/// Default SHA-256 hasher backed by `bitcoin::hashes`.
#[derive(Debug, Clone, Copy, Default)]
pub struct BitcoinSha256Hasher;

impl Sha256Hasher for BitcoinSha256Hasher {
    /// Hashes the input using `bitcoin::hashes::sha256`.
    fn hash(&self, data: &[u8]) -> [u8; 32] {
        Sha256Hash::hash(data).to_byte_array()
    }
}

/// Proof verification stage used for error reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofStage {
    /// Inclusion proof verification stage.
    Inclusion,
    /// Exclusion proof verification stage.
    Exclusion,
    /// Split root proof verification stage.
    SplitRoot,
    /// STXO proof verification stage.
    Stxo,
}

impl core::fmt::Display for ProofStage {
    /// Formats the stage for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ProofStage::Inclusion => write!(f, "inclusion"),
            ProofStage::Exclusion => write!(f, "exclusion"),
            ProofStage::SplitRoot => write!(f, "split_root"),
            ProofStage::Stxo => write!(f, "stxo"),
        }
    }
}

/// Errors returned by proof verification helpers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Taproot proof verification failed at a specific stage.
    TaprootProof {
        /// Stage where verification failed.
        stage: ProofStage,
        /// Underlying taproot proof error.
        source: taproot_proof::Error,
    },
    /// Group key reveal verification failed.
    GroupKeyReveal(group_key_reveal::Error),
    /// Split root proof is missing for a split commitment asset.
    MissingSplitRootProof,
    /// A transfer-root asset is missing required STXO proofs.
    MissingStxoProofs,
    /// A transfer-root asset is missing STXO proofs for an output.
    MissingStxoInputProofs,
    /// Missing commitment proof required to verify STXO proofs.
    MissingCommitmentProof,
    /// Missing STXO asset for a script key in the proof.
    MissingStxoAsset {
        /// Script key that lacks a corresponding STXO asset.
        key: SerializedKey,
    },
    /// The asset has no witnesses when STXO proofs are required.
    MissingAssetWitnesses,
    /// A witness is missing its PrevID.
    MissingPrevId,
    /// Script key length is invalid for an asset.
    InvalidAssetScriptKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        actual: usize,
    },
    /// The NUMS key used for burn derivation is invalid.
    InvalidNumsKey,
    /// Tap tweak scalar for burn key derivation is invalid.
    InvalidBurnKeyTweak,
    /// Mixed TapCommitment versions found across proofs.
    MixedCommitmentVersions,
    /// Commitment proofs are missing for taproot outputs.
    InvalidCommitmentProof,
    /// Genesis reveal is present for a non-genesis asset.
    NonGenesisAssetWithGenesisReveal,
    /// Meta reveal is present for a non-genesis asset.
    NonGenesisAssetWithMetaReveal,
    /// Genesis reveal is required for a genesis asset.
    GenesisRevealRequired,
    /// Genesis reveal is missing its base genesis information.
    GenesisRevealMissingBase,
    /// Genesis reveal prev out does not match the proof prev out.
    GenesisRevealPrevOutMismatch,
    /// Genesis reveal requires a meta reveal when meta hash is non-zero.
    GenesisRevealMetaRevealRequired,
    /// Genesis reveal meta hash does not match the meta reveal hash.
    GenesisRevealMetaHashMismatch,
    /// Genesis reveal output index does not match the inclusion proof.
    GenesisRevealOutputIndexMismatch,
    /// Genesis reveal asset ID does not match the asset genesis.
    GenesisRevealAssetIdMismatch,
    /// Asset genesis information is missing.
    MissingAssetGenesis,
}

impl core::fmt::Display for Error {
    /// Formats the error for display.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error::TaprootProof { stage, source } => {
                write!(f, "taproot proof {} error: {}", stage, source)
            }
            Error::GroupKeyReveal(err) => core::fmt::Display::fmt(err, f),
            Error::MissingSplitRootProof => write!(f, "missing split root proof"),
            Error::MissingStxoProofs => write!(f, "missing STXO proofs"),
            Error::MissingStxoInputProofs => write!(f, "missing STXO input proofs"),
            Error::MissingCommitmentProof => write!(f, "missing commitment proof"),
            Error::MissingStxoAsset { key } => {
                write!(f, "missing STXO asset for key {:?}", key)
            }
            Error::MissingAssetWitnesses => write!(f, "asset has no witnesses"),
            Error::MissingPrevId => write!(f, "witness missing PrevID"),
            Error::InvalidAssetScriptKeyLength { expected, actual } => write!(
                f,
                "asset script key length {}, expected {}",
                actual, expected
            ),
            Error::InvalidNumsKey => write!(f, "invalid NUMS key"),
            Error::InvalidBurnKeyTweak => write!(f, "invalid burn key tweak"),
            Error::MixedCommitmentVersions => write!(f, "mixed commitment versions"),
            Error::InvalidCommitmentProof => write!(f, "invalid commitment proof"),
            Error::NonGenesisAssetWithGenesisReveal => {
                write!(f, "non-genesis asset with genesis reveal")
            }
            Error::NonGenesisAssetWithMetaReveal => write!(f, "non-genesis asset with meta reveal"),
            Error::GenesisRevealRequired => write!(f, "genesis reveal required"),
            Error::GenesisRevealMissingBase => write!(f, "genesis reveal missing base"),
            Error::GenesisRevealPrevOutMismatch => write!(f, "genesis reveal prev out mismatch"),
            Error::GenesisRevealMetaRevealRequired => {
                write!(f, "genesis reveal meta reveal required")
            }
            Error::GenesisRevealMetaHashMismatch => {
                write!(f, "genesis reveal meta hash mismatch")
            }
            Error::GenesisRevealOutputIndexMismatch => {
                write!(f, "genesis reveal output index mismatch")
            }
            Error::GenesisRevealAssetIdMismatch => write!(f, "genesis reveal asset id mismatch"),
            Error::MissingAssetGenesis => write!(f, "missing asset genesis"),
        }
    }
}

/// Verifies genesis and meta reveal constraints for a proof.
pub fn verify_genesis_reveal(proof: &Proof) -> Result<(), Error> {
    verify_genesis_reveal_input(&GenesisRevealInput::from_proof(proof))
}

/// Verifies genesis and meta reveal constraints using the supplied SHA-256 hasher.
pub fn verify_genesis_reveal_with_hasher<H: Sha256Hasher>(
    proof: &Proof,
    hasher: &H,
) -> Result<(), Error> {
    verify_genesis_reveal_input_with_hasher(&GenesisRevealInput::from_proof(proof), hasher)
}

/// Verifies genesis and meta reveal constraints for a minimal input.
pub fn verify_genesis_reveal_input(input: &GenesisRevealInput) -> Result<(), Error> {
    verify_genesis_reveal_input_with_hasher(input, &BitcoinSha256Hasher)
}

/// Verifies genesis and meta reveal constraints for a minimal input using the supplied hasher.
pub fn verify_genesis_reveal_input_with_hasher<H: Sha256Hasher>(
    input: &GenesisRevealInput,
    hasher: &H,
) -> Result<(), Error> {
    let is_genesis = is_genesis_asset_input(&input.asset);
    let has_genesis_reveal = input.genesis_reveal.is_some();
    let has_meta_reveal = input.meta_reveal.is_some();

    if !is_genesis {
        if has_genesis_reveal {
            return Err(Error::NonGenesisAssetWithGenesisReveal);
        }
        if has_meta_reveal {
            return Err(Error::NonGenesisAssetWithMetaReveal);
        }
        return Ok(());
    }

    if !has_genesis_reveal {
        return Err(Error::GenesisRevealRequired);
    }

    verify_genesis_reveal_fields_input(input, hasher)
}

/// Verifies that the genesis reveal matches input and asset fields.
fn verify_genesis_reveal_fields_input<H: Sha256Hasher>(
    input: &GenesisRevealInput,
    hasher: &H,
) -> Result<(), Error> {
    let reveal = input
        .genesis_reveal
        .as_ref()
        .ok_or(Error::GenesisRevealRequired)?;
    let genesis = reveal
        .genesis_base
        .as_ref()
        .ok_or(Error::GenesisRevealMissingBase)?;

    if genesis.genesis_point != input.prev_out {
        return Err(Error::GenesisRevealPrevOutMismatch);
    }

    if genesis.output_index != input.inclusion_output_index {
        return Err(Error::GenesisRevealOutputIndexMismatch);
    }

    let zero_meta = zero_meta_hash();
    match input.meta_reveal.as_ref() {
        None => {
            if genesis.meta_hash != zero_meta {
                return Err(Error::GenesisRevealMetaRevealRequired);
            }
        }
        Some(meta) => {
            let meta_hash = meta_reveal_hash_with_hasher(meta, hasher);
            if genesis.meta_hash != meta_hash {
                return Err(Error::GenesisRevealMetaHashMismatch);
            }
        }
    }

    let asset_genesis_id = input
        .asset
        .asset_genesis_id
        .ok_or(Error::MissingAssetGenesis)?;
    let reveal_asset_id = compute_asset_id_with_hasher(genesis, hasher);
    if reveal_asset_id != asset_genesis_id {
        return Err(Error::GenesisRevealAssetIdMismatch);
    }

    Ok(())
}

/// Verifies inclusion, split root, and exclusion proofs for a state transition proof.
pub fn verify_proofs<O: TaprootOps>(
    ops: &O,
    proof: &Proof,
) -> Result<taproot_proof::TapCommitment, Error> {
    let tap_commitment = verify_inclusion_proof(ops, proof)?;

    if has_split_commitment_witness(&proof.asset) {
        if proof.split_root_proof.is_none() {
            return Err(Error::MissingSplitRootProof);
        }
        verify_split_root_proof(ops, proof)?;
    }

    let exclusion_version = verify_exclusion_proofs(ops, proof)?;
    if let Some(version) = exclusion_version {
        if !is_similar_tap_commitment_version(tap_commitment.version, version) {
            return Err(Error::MixedCommitmentVersions);
        }
    }

    Ok(tap_commitment)
}

/// Verifies the inclusion proof for the resulting asset.
pub fn verify_inclusion_proof<O: TaprootOps>(
    ops: &O,
    proof: &Proof,
) -> Result<taproot_proof::TapCommitment, Error> {
    let commitment = taproot_proof::verify_taproot_proof_with_commitment(
        ops,
        &proof.anchor_tx,
        &proof.inclusion_proof,
        &proof.asset,
        true,
    )
    .map_err(|err| Error::TaprootProof {
        stage: ProofStage::Inclusion,
        source: err,
    })?
    .ok_or(Error::MissingCommitmentProof)?;

    let need_stxo_proofs = is_version_v1(proof.version) && is_transfer_root(&proof.asset);
    let has_stxo_proofs = proof
        .inclusion_proof
        .commitment_proof
        .as_ref()
        .map_or(false, |commitment| !commitment.stxo_proofs.is_empty());

    if need_stxo_proofs && !has_stxo_proofs {
        return Err(Error::MissingStxoProofs);
    }

    if !is_transfer_root(&proof.asset) || !has_stxo_proofs {
        return Ok(commitment);
    }

    let out_idx = proof.inclusion_proof.output_index;
    let (asset_map, stxo_keys) = collect_stxo_assets(&proof.asset)?;
    let mut p2tr_outputs = BTreeMap::new();
    p2tr_outputs.insert(out_idx, stxo_keys);

    verify_stxo_proof_set(
        ops,
        &proof.anchor_tx,
        &proof.inclusion_proof,
        &asset_map,
        &mut p2tr_outputs,
        true,
    )?;

    if !p2tr_outputs.is_empty() {
        return Err(Error::MissingStxoInputProofs);
    }

    Ok(commitment)
}

/// Verifies the split root proof for split commitment assets.
pub fn verify_split_root_proof<O: TaprootOps>(ops: &O, proof: &Proof) -> Result<(), Error> {
    let split_proof = proof
        .split_root_proof
        .as_ref()
        .ok_or(Error::MissingSplitRootProof)?;
    let root_asset = split_root_asset(&proof.asset)?;
    taproot_proof::verify_taproot_proof(ops, &proof.anchor_tx, split_proof, root_asset, true)
        .map_err(|err| Error::TaprootProof {
            stage: ProofStage::SplitRoot,
            source: err,
        })
}

/// Verifies the exclusion proofs and returns the observed TapCommitment version.
pub fn verify_exclusion_proofs<O: TaprootOps>(
    ops: &O,
    proof: &Proof,
) -> Result<Option<TapCommitmentVersion>, Error> {
    let mut p2tr_outputs = BTreeSet::new();
    for (idx, output) in proof.anchor_tx.output.iter().enumerate() {
        let index = idx as u32;
        if index == proof.inclusion_proof.output_index {
            continue;
        }
        if output.script_pubkey.is_p2tr() {
            p2tr_outputs.insert(index);
        }
    }

    if p2tr_outputs.is_empty() {
        return Ok(None);
    }

    let mut outputs_for_v0 = p2tr_outputs.clone();
    let commit_versions = verify_v0_exclusion_proofs(ops, proof, &mut outputs_for_v0)?;
    if commit_versions.is_empty() {
        return Ok(None);
    }

    let need_stxo_proofs = is_version_v1(proof.version) && is_transfer_root(&proof.asset);
    let has_stxo_proofs = proof
        .exclusion_proofs
        .first()
        .and_then(|proof| proof.commitment_proof.as_ref())
        .map_or(false, |commitment| !commitment.stxo_proofs.is_empty());

    if need_stxo_proofs && !has_stxo_proofs {
        return Err(Error::MissingStxoProofs);
    }

    if !is_transfer_root(&proof.asset) || !has_stxo_proofs {
        return assert_version_consistency(&commit_versions);
    }

    verify_v1_exclusion_proofs(ops, proof, p2tr_outputs)?;
    assert_version_consistency(&commit_versions)
}

/// Verifies all v0 exclusion proofs and returns observed commitment versions.
fn verify_v0_exclusion_proofs<O: TaprootOps>(
    ops: &O,
    proof: &Proof,
    p2tr_outputs: &mut BTreeSet<u32>,
) -> Result<CommittedVersions, Error> {
    let mut commit_versions = BTreeMap::new();
    for exclusion_proof in &proof.exclusion_proofs {
        let derived = taproot_proof::verify_taproot_proof_with_commitment(
            ops,
            &proof.anchor_tx,
            exclusion_proof,
            &proof.asset,
            false,
        )
        .map_err(|err| Error::TaprootProof {
            stage: ProofStage::Exclusion,
            source: err,
        })?;

        p2tr_outputs.remove(&exclusion_proof.output_index);

        if let Some(commitment) = derived {
            commit_versions
                .entry(exclusion_proof.output_index)
                .or_insert_with(Vec::new)
                .push(commitment.version);
        }
    }

    if !p2tr_outputs.is_empty() {
        return Err(Error::InvalidCommitmentProof);
    }

    Ok(commit_versions)
}

/// Verifies all v1 exclusion proofs, including STXO proofs.
fn verify_v1_exclusion_proofs<O: TaprootOps>(
    ops: &O,
    proof: &Proof,
    p2tr_outputs: BTreeSet<u32>,
) -> Result<(), Error> {
    let (asset_map, stxo_keys) = collect_stxo_assets(&proof.asset)?;
    let mut p2tr_outputs_stxo = BTreeMap::new();
    for out_idx in p2tr_outputs {
        p2tr_outputs_stxo.insert(out_idx, stxo_keys.clone());
    }

    for exclusion_proof in &proof.exclusion_proofs {
        if exclusion_proof.tapscript_proof.is_some() {
            p2tr_outputs_stxo.remove(&exclusion_proof.output_index);
            continue;
        }

        verify_stxo_proof_set(
            ops,
            &proof.anchor_tx,
            exclusion_proof,
            &asset_map,
            &mut p2tr_outputs_stxo,
            false,
        )?;
    }

    if !p2tr_outputs_stxo.is_empty() {
        return Err(Error::MissingStxoInputProofs);
    }

    Ok(())
}

/// Verifies a set of STXO proofs against the provided output tracking map.
fn verify_stxo_proof_set<O: TaprootOps>(
    ops: &O,
    anchor_tx: &Transaction,
    base_proof: &TaprootProof,
    asset_map: &BTreeMap<SerializedKey, Asset>,
    p2tr_outputs: &mut P2TROutputsSTXOs,
    inclusion: bool,
) -> Result<(), Error> {
    let base_commitment = base_proof
        .commitment_proof
        .as_ref()
        .ok_or(Error::MissingCommitmentProof)?;

    for (key, stxo_proof) in &base_commitment.stxo_proofs {
        let stxo_asset = asset_map
            .get(key)
            .ok_or(Error::MissingStxoAsset { key: *key })?;
        let stxo_combined = make_stxo_proof(base_proof, base_commitment, stxo_proof);

        taproot_proof::verify_taproot_proof(ops, anchor_tx, &stxo_combined, stxo_asset, inclusion)
            .map_err(|err| Error::TaprootProof {
                stage: ProofStage::Stxo,
                source: err,
            })?;

        let out_idx = stxo_combined.output_index;
        if let Some(keys) = p2tr_outputs.get_mut(&out_idx) {
            keys.remove(key);
            if keys.is_empty() {
                p2tr_outputs.remove(&out_idx);
            }
        }
    }

    Ok(())
}

/// Constructs an STXO proof from a base proof and a specific commitment proof.
fn make_stxo_proof(
    base_proof: &TaprootProof,
    base_commitment: &CommitmentProof,
    stxo_proof: &taproot_assets_types::commitment::Proof,
) -> TaprootProof {
    TaprootProof {
        output_index: base_proof.output_index,
        internal_key: base_proof.internal_key,
        commitment_proof: Some(CommitmentProof {
            proof: stxo_proof.clone(),
            tap_sibling_preimage: base_commitment.tap_sibling_preimage.clone(),
            stxo_proofs: BTreeMap::new(),
            unknown_odd_types: BTreeMap::new(),
        }),
        tapscript_proof: base_proof.tapscript_proof.clone(),
        unknown_odd_types: base_proof.unknown_odd_types.clone(),
    }
}

/// Asserts all commitment versions are mutually compatible.
fn assert_version_consistency(
    versions: &CommittedVersions,
) -> Result<Option<TapCommitmentVersion>, Error> {
    let mut values = versions.values();
    let first_versions = match values.next() {
        Some(versions) => versions,
        None => return Ok(None),
    };
    let first = *first_versions
        .first()
        .ok_or(Error::InvalidCommitmentProof)?;

    for versions in versions.values() {
        for version in versions {
            if !is_similar_tap_commitment_version(first, *version) {
                return Err(Error::MixedCommitmentVersions);
            }
        }
    }

    Ok(Some(first))
}

/// Returns true if two TapCommitment versions are compatible.
fn is_similar_tap_commitment_version(
    left: TapCommitmentVersion,
    right: TapCommitmentVersion,
) -> bool {
    if left == TapCommitmentVersion::V2 {
        return right == TapCommitmentVersion::V2;
    }

    matches!(left, TapCommitmentVersion::V0 | TapCommitmentVersion::V1)
        && matches!(right, TapCommitmentVersion::V0 | TapCommitmentVersion::V1)
}

/// Returns true if the proof uses the v1 transition format.
fn is_version_v1(version: u32) -> bool {
    version == PROOF_VERSION_V1
}

/// Returns true if the asset has a split commitment witness.
fn has_split_commitment_witness(asset: &Asset) -> bool {
    asset.prev_witnesses.len() == 1 && is_split_commit_witness(&asset.prev_witnesses[0])
}

/// Returns true if the witness is a split commitment witness.
fn is_split_commit_witness(witness: &PrevWitness) -> bool {
    witness.prev_id.is_some() && witness.tx_witness.is_empty() && witness.split_commitment.is_some()
}

/// Returns true if the asset represents a genesis asset.
fn is_genesis_asset(asset: &Asset) -> bool {
    has_genesis_witness(asset) || has_genesis_witness_for_group(asset)
}

/// Returns true if the input represents a genesis asset.
fn is_genesis_asset_input(asset: &GenesisAssetInput) -> bool {
    has_genesis_witness_input(asset) || has_genesis_witness_for_group_input(asset)
}

/// Returns true if the asset has a plain genesis witness.
fn has_genesis_witness(asset: &Asset) -> bool {
    if asset.prev_witnesses.len() != 1 {
        return false;
    }

    let witness = &asset.prev_witnesses[0];
    if witness.prev_id.is_none()
        || !witness.tx_witness.is_empty()
        || witness.split_commitment.is_some()
    {
        return false;
    }

    is_zero_prev_id(witness.prev_id.as_ref().expect("checked above"))
}

/// Returns true if the input has a plain genesis witness.
fn has_genesis_witness_input(asset: &GenesisAssetInput) -> bool {
    if asset.prev_witnesses.len() != 1 {
        return false;
    }

    let witness = &asset.prev_witnesses[0];
    if witness.prev_id.is_none() || witness.has_tx_witness || witness.has_split_commitment {
        return false;
    }

    is_zero_prev_id(witness.prev_id.as_ref().expect("checked above"))
}

/// Returns true if the asset has a genesis witness for an asset group.
fn has_genesis_witness_for_group(asset: &Asset) -> bool {
    if asset.asset_group.is_none() || asset.prev_witnesses.len() != 1 {
        return false;
    }

    let witness = &asset.prev_witnesses[0];
    if witness.prev_id.is_none()
        || witness.tx_witness.is_empty()
        || witness.split_commitment.is_some()
    {
        return false;
    }

    is_zero_prev_id(witness.prev_id.as_ref().expect("checked above"))
}

/// Returns true if the input has a genesis witness for an asset group.
fn has_genesis_witness_for_group_input(asset: &GenesisAssetInput) -> bool {
    if !asset.has_asset_group || asset.prev_witnesses.len() != 1 {
        return false;
    }

    let witness = &asset.prev_witnesses[0];
    if witness.prev_id.is_none() || !witness.has_tx_witness || witness.has_split_commitment {
        return false;
    }

    is_zero_prev_id(witness.prev_id.as_ref().expect("checked above"))
}

/// Returns true if the asset represents a transfer root.
fn is_transfer_root(asset: &Asset) -> bool {
    !is_genesis_asset(asset) && !has_split_commitment_witness(asset)
}

/// Returns the split root asset for a split commitment witness.
fn split_root_asset(asset: &Asset) -> Result<&Asset, Error> {
    let witness = asset
        .prev_witnesses
        .first()
        .ok_or(Error::MissingSplitRootProof)?;
    let split_commitment = witness
        .split_commitment
        .as_ref()
        .ok_or(Error::MissingSplitRootProof)?;
    Ok(split_commitment.root_asset.as_ref())
}

/// Returns true if the PrevID is the all-zero genesis reference.
fn is_zero_prev_id(prev_id: &PrevId) -> bool {
    prev_id.out_point.txid == Txid::from_byte_array([0u8; 32])
        && prev_id.out_point.vout == 0
        && prev_id.asset_id.to_byte_array() == [0u8; 32]
        && prev_id.script_key.bytes == [0u8; COMPRESSED_KEY_LEN]
}

/// Collects STXO assets and the associated script key set.
fn collect_stxo_assets(
    asset: &Asset,
) -> Result<(BTreeMap<SerializedKey, Asset>, BTreeSet<SerializedKey>), Error> {
    if !is_transfer_root(asset) {
        return Ok((BTreeMap::new(), BTreeSet::new()));
    }

    if asset.prev_witnesses.is_empty() {
        return Err(Error::MissingAssetWitnesses);
    }

    let mut asset_map = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for witness in &asset.prev_witnesses {
        let stxo_asset = make_spent_asset(witness)?;
        let key = serialized_key_from_script_key(&stxo_asset.script_key)?;
        keys.insert(key);
        asset_map.insert(key, stxo_asset);
    }

    Ok((asset_map, keys))
}

/// Builds a minimal asset that represents a spent input for STXO proofs.
fn make_spent_asset(witness: &PrevWitness) -> Result<Asset, Error> {
    let prev_id = witness.prev_id.as_ref().ok_or(Error::MissingPrevId)?;
    let script_key = derive_burn_script_key(prev_id)?;
    Ok(make_alt_leaf_asset(script_key))
}

/// Builds a minimal alt leaf asset for STXO verification.
fn make_alt_leaf_asset(script_key: SerializedKey) -> Asset {
    Asset {
        version: AssetVersion::V0,
        asset_genesis: Some(empty_genesis_info()),
        amount: 0,
        lock_time: 0,
        relative_lock_time: 0,
        script_version: 0,
        script_key: script_key.bytes.to_vec(),
        script_key_is_local: false,
        asset_group: None,
        chain_anchor: None,
        prev_witnesses: Vec::new(),
        split_commitment_root: None,
        is_spent: false,
        lease_owner: Vec::new(),
        lease_expiry: 0,
        is_burn: false,
        script_key_declared_known: false,
        script_key_has_script_path: false,
        decimal_display: None,
        script_key_type: ScriptKeyType::Burn,
    }
}

/// Constructs the empty genesis info used by alt leaf assets.
fn empty_genesis_info() -> GenesisInfo {
    let genesis_point = OutPoint {
        txid: Txid::from_byte_array([0u8; 32]),
        vout: 0,
    };
    let mut genesis = GenesisInfo {
        genesis_point,
        name: String::new(),
        meta_hash: Sha256Hash::from_byte_array([0u8; 32]),
        asset_id: Sha256Hash::from_byte_array([0u8; 32]),
        asset_type: AssetType::Normal,
        output_index: 0,
    };
    genesis.asset_id = compute_asset_id(&genesis);
    genesis
}

/// Computes an asset ID from genesis information.
fn compute_asset_id(genesis: &GenesisInfo) -> Sha256Hash {
    compute_asset_id_with_hasher(genesis, &BitcoinSha256Hasher)
}

/// Computes an asset ID from genesis information using the supplied hasher.
fn compute_asset_id_with_hasher<H: Sha256Hasher>(genesis: &GenesisInfo, hasher: &H) -> Sha256Hash {
    let outpoint_bytes = serialize(&genesis.genesis_point);
    let tag_hash = hasher.hash(genesis.name.as_bytes());

    let mut buf = Vec::with_capacity(outpoint_bytes.len() + 32 + 32 + 4 + 1);
    buf.extend_from_slice(&outpoint_bytes);
    buf.extend_from_slice(&tag_hash);
    buf.extend_from_slice(&genesis.meta_hash.to_byte_array());
    buf.extend_from_slice(&genesis.output_index.to_be_bytes());
    buf.push(asset_type_byte(genesis.asset_type));

    Sha256Hash::from_byte_array(hasher.hash(&buf))
}

/// Returns the sha256 hash of a meta reveal TLV encoding using the supplied hasher.
fn meta_reveal_hash_with_hasher<H: Sha256Hasher>(meta: &MetaReveal, hasher: &H) -> Sha256Hash {
    let encoded = encode_meta_reveal(meta);
    Sha256Hash::from_byte_array(hasher.hash(&encoded))
}

/// Encodes a meta reveal as a TLV byte stream.
fn encode_meta_reveal(meta: &MetaReveal) -> Vec<u8> {
    let mut out = Vec::new();
    encode_record(META_REVEAL_ENCODING_TYPE, &[meta.meta_type as u8], &mut out);
    encode_record(META_REVEAL_DATA_TYPE, &meta.data, &mut out);
    for (tlv_type, value) in meta.unknown_odd_types.iter() {
        encode_record(*tlv_type, value, &mut out);
    }
    out
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

/// Returns a zero meta hash value.
fn zero_meta_hash() -> Sha256Hash {
    Sha256Hash::from_byte_array([0u8; 32])
}

/// Returns the protocol byte for an asset type.
fn asset_type_byte(asset_type: AssetType) -> u8 {
    match asset_type {
        AssetType::Normal => 0,
        AssetType::Collectible => 1,
    }
}

/// Converts a script key byte slice into a SerializedKey.
fn serialized_key_from_script_key(bytes: &[u8]) -> Result<SerializedKey, Error> {
    if bytes.len() != COMPRESSED_KEY_LEN {
        return Err(Error::InvalidAssetScriptKeyLength {
            expected: COMPRESSED_KEY_LEN,
            actual: bytes.len(),
        });
    }
    let mut array = [0u8; COMPRESSED_KEY_LEN];
    array.copy_from_slice(bytes);
    Ok(SerializedKey { bytes: array })
}

/// Returns the x-only serialized form of a compressed key.
fn schnorr_key_bytes(key: &SerializedKey) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&key.bytes[1..]);
    bytes
}

/// Serializes a PrevID for burn key derivation.
fn serialize_prev_id_for_burn(prev_id: &PrevId) -> Vec<u8> {
    let outpoint_bytes = serialize(&prev_id.out_point);
    let mut buf = Vec::with_capacity(outpoint_bytes.len() + 32 + 32);
    buf.extend_from_slice(&outpoint_bytes);
    buf.extend_from_slice(&prev_id.asset_id.to_byte_array());
    buf.extend_from_slice(&schnorr_key_bytes(&prev_id.script_key));
    buf
}

/// Derives the burn script key for a given PrevID.
fn derive_burn_script_key(prev_id: &PrevId) -> Result<SerializedKey, Error> {
    let nums_xonly = nums_xonly_key()?;
    let tweak_data = serialize_prev_id_for_burn(prev_id);
    let tweak = tap_tweak_scalar(nums_xonly, &tweak_data)?;
    let secp = Secp256k1::verification_only();
    let (tweaked, _) = nums_xonly
        .add_tweak(&secp, &tweak)
        .map_err(|_| Error::InvalidBurnKeyTweak)?;

    let mut bytes = [0u8; COMPRESSED_KEY_LEN];
    bytes[0] = 0x02;
    bytes[1..].copy_from_slice(&tweaked.serialize());
    Ok(SerializedKey { bytes })
}

/// Returns the NUMS x-only internal key used for burn derivation.
fn nums_xonly_key() -> Result<XOnlyPublicKey, Error> {
    let pubkey = bitcoin::secp256k1::PublicKey::from_slice(&NUMS_COMPRESSED_KEY)
        .map_err(|_| Error::InvalidNumsKey)?;
    let (xonly, _) = pubkey.x_only_public_key();
    Ok(xonly)
}

/// Computes the TapTweak scalar for the given internal key and tweak data.
fn tap_tweak_scalar(internal_key: XOnlyPublicKey, tweak_data: &[u8]) -> Result<Scalar, Error> {
    let mut eng = TapTweakHash::engine();
    eng.input(&internal_key.serialize());
    eng.input(tweak_data);
    let hash = TapTweakHash::from_engine(eng);
    Scalar::from_be_bytes(hash.to_byte_array()).map_err(|_| Error::InvalidBurnKeyTweak)
}

/// Input for the Taproot commitment claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaprootClaimInput {
    /// The Taproot proof to verify.
    pub taproot_proof: TaprootProof,
    /// The asset being proven.
    pub asset: Asset,
    /// The expected Taproot output key, derived from the anchor claim.
    pub expected_taproot_output_key: [u8; 32],
    /// Whether this is an inclusion proof.
    pub inclusion: bool,
}

/// Output for the Taproot commitment claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaprootClaimOutput {
    /// The Taproot output key that was verified against.
    pub taproot_output_key: [u8; 32],
    /// The output index proven by this claim.
    pub output_index: u32,
    /// The derived Taproot Asset commitment.
    pub tap_commitment: taproot_proof::TapCommitment,
}

/// Input for the STXO claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StxoClaimInput {
    /// The Taproot proof containing STXO proofs.
    pub taproot_proof: TaprootProof,
    /// Asset that contains the prev witness set used to derive STXO keys.
    pub asset: Asset,
    /// Proof version of the enclosing proof.
    pub proof_version: u32,
    /// The expected Taproot output key.
    pub expected_taproot_output_key: [u8; 32],
    /// Whether the STXO proofs are inclusion proofs (true) or exclusion proofs (false).
    pub inclusion: bool,
}

/// Output for the STXO claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StxoClaimOutput {
    /// The Taproot output key that was verified against.
    pub taproot_output_key: [u8; 32],
    /// The output index proven by this claim.
    pub output_index: u32,
    /// The list of script keys that were successfully verified.
    pub verified_keys: Vec<SerializedKey>,
}

/// Input for the asset integrity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetClaimInput {
    /// Previous outpoint referenced by the proof.
    pub prev_out: OutPoint,
    /// Output index from the inclusion proof.
    pub inclusion_output_index: u32,
    /// Proof version of the enclosing proof.
    pub proof_version: u32,
    /// The asset being verified.
    pub asset: Asset,
    /// Genesis reveal payload, if present.
    pub genesis_reveal: Option<GenesisReveal>,
    /// Meta reveal payload, if present.
    pub meta_reveal: Option<MetaReveal>,
    /// Group key reveal payload, if present.
    pub group_key_reveal: Option<GroupKeyReveal>,
}

impl AssetClaimInput {
    /// Builds an asset integrity input from a full proof.
    pub fn from_proof(proof: &Proof) -> Self {
        AssetClaimInput {
            prev_out: proof.prev_out,
            inclusion_output_index: proof.inclusion_proof.output_index,
            proof_version: proof.version,
            asset: proof.asset.clone(),
            genesis_reveal: proof.genesis_reveal.clone(),
            meta_reveal: proof.meta_reveal.clone(),
            group_key_reveal: proof.group_key_reveal.clone(),
        }
    }
}

/// Output for the asset integrity claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetClaimOutput {
    /// Asset ID derived from genesis information.
    pub asset_id: [u8; 32],
    /// Group key, if the asset is grouped.
    pub group_key: Option<SerializedKey>,
    /// Meta hash, if one is set.
    pub meta_hash: Option<[u8; 32]>,
    /// Proof version committed by the claim.
    pub proof_version: u32,
    /// True if the asset represents a transfer root.
    pub is_transfer_root: bool,
    /// True if the asset has a split commitment witness.
    pub has_split_commitment: bool,
    /// True if STXO proofs are required for this asset and proof version.
    pub stxo_required: bool,
}

/// Verifies the Taproot commitment claim.
pub fn verify_taproot_claim_with_ops<O: TaprootOps>(
    ops: &O,
    input: &TaprootClaimInput,
) -> Result<TaprootClaimOutput, Error> {
    let expected_key =
        XOnlyPublicKey::from_slice(&input.expected_taproot_output_key).map_err(|_| {
            Error::TaprootProof {
                stage: if input.inclusion {
                    ProofStage::Inclusion
                } else {
                    ProofStage::Exclusion
                },
                source: taproot_proof::Error::InvalidTaprootOutputKey,
            }
        })?;

    let commitment = taproot_proof::verify_taproot_proof_with_commitment_and_key(
        ops,
        expected_key,
        &input.taproot_proof,
        &input.asset,
        input.inclusion,
    )
    .map_err(|err| Error::TaprootProof {
        stage: if input.inclusion {
            ProofStage::Inclusion
        } else {
            ProofStage::Exclusion
        },
        source: err,
    })?
    .ok_or(Error::MissingCommitmentProof)?;

    Ok(TaprootClaimOutput {
        taproot_output_key: input.expected_taproot_output_key,
        output_index: input.taproot_proof.output_index,
        tap_commitment: commitment,
    })
}

/// Verifies the STXO claim.
pub fn verify_stxo_claim_with_ops<O: TaprootOps>(
    ops: &O,
    input: &StxoClaimInput,
) -> Result<StxoClaimOutput, Error> {
    let expected_key =
        XOnlyPublicKey::from_slice(&input.expected_taproot_output_key).map_err(|_| {
            Error::TaprootProof {
                stage: ProofStage::Stxo,
                source: taproot_proof::Error::InvalidTaprootOutputKey,
            }
        })?;

    let is_transfer_root = is_transfer_root(&input.asset);
    let has_stxo_proofs = input
        .taproot_proof
        .commitment_proof
        .as_ref()
        .map_or(false, |commitment| !commitment.stxo_proofs.is_empty());
    let need_stxo_proofs = is_version_v1(input.proof_version) && is_transfer_root;

    if input.taproot_proof.tapscript_proof.is_some() {
        return Ok(StxoClaimOutput {
            taproot_output_key: input.expected_taproot_output_key,
            output_index: input.taproot_proof.output_index,
            verified_keys: Vec::new(),
        });
    }

    if need_stxo_proofs && !has_stxo_proofs {
        return Err(Error::MissingStxoProofs);
    }

    if !is_transfer_root || !has_stxo_proofs {
        return Ok(StxoClaimOutput {
            taproot_output_key: input.expected_taproot_output_key,
            output_index: input.taproot_proof.output_index,
            verified_keys: Vec::new(),
        });
    }

    let (asset_map, mut remaining_keys) = collect_stxo_assets(&input.asset)?;
    let base_commitment = input
        .taproot_proof
        .commitment_proof
        .as_ref()
        .ok_or(Error::MissingCommitmentProof)?;

    let mut verified_keys = Vec::new();

    for (key, stxo_proof) in &base_commitment.stxo_proofs {
        let stxo_asset = asset_map
            .get(key)
            .ok_or(Error::MissingStxoAsset { key: *key })?;

        let stxo_combined = make_stxo_proof(&input.taproot_proof, base_commitment, stxo_proof);

        taproot_proof::verify_taproot_proof_with_commitment_and_key(
            ops,
            expected_key,
            &stxo_combined,
            stxo_asset,
            input.inclusion,
        )
        .map_err(|err| Error::TaprootProof {
            stage: ProofStage::Stxo,
            source: err,
        })?;

        remaining_keys.remove(key);
        verified_keys.push(*key);
    }

    if !remaining_keys.is_empty() {
        return Err(Error::MissingStxoInputProofs);
    }

    // Sort verified keys for deterministic output.
    verified_keys.sort();

    Ok(StxoClaimOutput {
        taproot_output_key: input.expected_taproot_output_key,
        output_index: input.taproot_proof.output_index,
        verified_keys,
    })
}

/// Verifies the asset integrity claim.
pub fn verify_asset_claim_with_ops<O: TaprootOps>(
    ops: &O,
    input: &AssetClaimInput,
) -> Result<AssetClaimOutput, Error> {
    let genesis_input = GenesisRevealInput {
        prev_out: input.prev_out,
        inclusion_output_index: input.inclusion_output_index,
        genesis_reveal: input.genesis_reveal.clone(),
        meta_reveal: input.meta_reveal.clone(),
        asset: genesis_asset_input_from_asset(&input.asset),
    };

    verify_genesis_reveal_input(&genesis_input)?;

    group_key_reveal::verify_group_key_reveal_with_asset(
        ops,
        &input.asset,
        input.group_key_reveal.as_ref(),
    )
    .map_err(Error::GroupKeyReveal)?;

    let asset_genesis = input
        .asset
        .asset_genesis
        .as_ref()
        .ok_or(Error::MissingAssetGenesis)?;
    let meta_hash = if asset_genesis.meta_hash == zero_meta_hash() {
        None
    } else {
        Some(asset_genesis.meta_hash.to_byte_array())
    };
    let group_key = asset_group_key_from_asset(&input.asset)?;
    let is_transfer_root = is_transfer_root(&input.asset);
    let has_split_commitment = has_split_commitment_witness(&input.asset);
    let stxo_required = is_version_v1(input.proof_version) && is_transfer_root;

    Ok(AssetClaimOutput {
        asset_id: asset_genesis.asset_id.to_byte_array(),
        group_key,
        meta_hash,
        proof_version: input.proof_version,
        is_transfer_root,
        has_split_commitment,
        stxo_required,
    })
}

fn asset_group_key_from_asset(asset: &Asset) -> Result<Option<SerializedKey>, Error> {
    let asset_group = match asset.asset_group.as_ref() {
        Some(group) => group,
        None => return Ok(None),
    };
    let key_bytes = if !asset_group.tweaked_group_key.is_empty() {
        asset_group.tweaked_group_key.as_slice()
    } else {
        asset_group.raw_group_key.as_slice()
    };
    if key_bytes.len() != 33 {
        return Err(Error::GroupKeyReveal(
            group_key_reveal::Error::InvalidGroupKeyLength {
                expected: 33,
                actual: key_bytes.len(),
            },
        ));
    }

    let mut bytes = [0u8; 33];
    bytes.copy_from_slice(key_bytes);
    Ok(Some(SerializedKey { bytes }))
}
