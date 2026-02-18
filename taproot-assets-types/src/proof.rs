// --- Proof structures (corresponding to Go's `proof` package) ---

use alloc::collections::{BTreeMap, BTreeSet};
use bitcoin::PublicKey;
pub use bitcoin::TxMerkleNode;
use bitcoin::consensus::Decodable;
use bitcoin::hashes::Hash;
use bitcoin::io::Read;
use serde::{Deserialize, Serialize};

use crate::alloc::string::ToString;
use alloc::{format, vec::Vec};

use crate::asset::SerializedKey;
use crate::commitment::TapscriptPreimage;
use crate::error::Error;
use crate::tlv::{Stream, Type};

/// Represents a raw proof file, typically a byte vector.
/// This was at the top of the original proof.rs file.
pub type RawProofFile = Vec<u8>;

/// Represents a full commitment proof for an asset. It can either prove inclusion or exclusion of
/// an asset within a Taproot Asset commitment.
/// This corresponds to `proof.CommitmentProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentProof {
    /// The underlying Merkle proof structure from the commitment module.
    /// This was `commitment.Proof` in Go.
    pub proof: crate::commitment::Proof,

    /// TapSiblingPreimage is an optional preimage of a tap node used to
    /// hash together with the Taproot Asset commitment leaf node to arrive
    /// at the tapscript root of the expected output.
    pub tap_sibling_preimage: Option<TapscriptPreimage>,

    /// STXOProofs are proofs keyed by serialized script key for v1 assets.
    pub stxo_proofs: BTreeMap<SerializedKey, crate::commitment::Proof>,

    /// UnknownOddTypes is a map of unknown odd types that were encountered
    /// during decoding. This map is used to preserve unknown types that we
    /// don't know of yet, so we can still encode them back when serializing.
    /// This enables forward compatibility with future versions of the
    /// protocol as it allows new odd (optional) types to be added without
    /// breaking old clients that don't yet fully understand them.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV Types for CommitmentProof (based on Go's proof/records.go)
// No explicit type for the proof.Proof itself, assuming it's the primary content or handled differently.
const COMMITMENT_PROOF_TAP_SIBLING_PREIMAGE_TYPE: Type = Type(5);
/// TLV type for the STXO proof map within a commitment proof.
const COMMITMENT_PROOF_STXO_PROOFS_TYPE: Type = Type(7);
// Type for the Merkle Proof itself is not directly specified here for CommitmentProof's TLV stream.
// It's often the core data. Let's assume it's decoded from the main stream if no specific type.
// For now, we will assume CommitmentMerkleProof::decode_tlv handles its own format from a reader.

impl CommitmentProof {
    fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut asset_proof: Option<crate::commitment::AssetProof> = None;
        let mut taproot_asset_proof: Option<crate::commitment::TaprootAssetProof> = None;
        let mut tap_sibling_preimage: Option<TapscriptPreimage> = None;
        let mut stxo_proofs: Option<BTreeMap<SerializedKey, crate::commitment::Proof>> = None;
        let mut unknown_odd_types = BTreeMap::new();

        // These type constants correspond to the underlying commitment.Proof fields
        const PROOF_ASSET_PROOF_TYPE: Type = Type(0);
        const PROOF_TAPROOT_ASSET_PROOF_TYPE: Type = Type(2);

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                // Handle the fields from the underlying commitment.Proof
                PROOF_ASSET_PROOF_TYPE => {
                    asset_proof = Some(crate::commitment::AssetProof::decode_tlv(
                        record.value_reader(),
                    )?);
                }
                PROOF_TAPROOT_ASSET_PROOF_TYPE => {
                    taproot_asset_proof = Some(crate::commitment::TaprootAssetProof::decode_tlv(
                        record.value_reader(),
                    )?);
                }
                // Handle the CommitmentProof-specific field
                COMMITMENT_PROOF_TAP_SIBLING_PREIMAGE_TYPE => {
                    tap_sibling_preimage =
                        Some(TapscriptPreimage::decode_tlv(record.value_reader())?);
                }
                COMMITMENT_PROOF_STXO_PROOFS_TYPE => {
                    stxo_proofs = Some(decode_commitment_proofs(record.value_reader())?);
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        // As per BOLT #1: even, unknown types are an error.
                        return Err(Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }

        // Build the underlying commitment.Proof
        let commitment_proof = crate::commitment::Proof {
            asset_proof,
            taproot_asset_proof: taproot_asset_proof.ok_or(Error::MissingTlvField(
                "CommitmentProof.proof.taproot_asset_proof".to_string(),
            ))?,
            unknown_odd_types: BTreeMap::new(), // Handle these separately for CommitmentProof
        };

        Ok(CommitmentProof {
            proof: commitment_proof,
            tap_sibling_preimage,
            stxo_proofs: stxo_proofs.unwrap_or_default(),
            unknown_odd_types,
        })
    }
}

/// TapscriptProof represents a proof of a Taproot output not including a
/// Taproot Asset commitment.
/// This corresponds to `proof.TapscriptProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TapscriptProof {
    /// TapPreimage1 is the preimage for a TapNode at depth 0 or 1.
    pub tap_preimage1: Option<TapscriptPreimage>,

    /// TapPreimage2, if specified, is the pair preimage for TapPreimage1 at
    /// depth 1.
    pub tap_preimage2: Option<TapscriptPreimage>,

    /// Bip86 indicates this is a normal BIP-0086 wallet output.
    pub bip86: bool,

    /// UnknownOddTypes is a map of unknown odd types encountered during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV Types for TapscriptProof (based on Go's proof/records.go)
const TAPSCRIPT_PROOF_TAP_PREIMAGE1_TYPE: Type = Type(1);
const TAPSCRIPT_PROOF_TAP_PREIMAGE2_TYPE: Type = Type(3);
const TAPSCRIPT_PROOF_BIP86_TYPE: Type = Type(4);

impl TapscriptProof {
    fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut tap_preimage1: Option<TapscriptPreimage> = None;
        let mut tap_preimage2: Option<TapscriptPreimage> = None;
        let mut bip86: Option<bool> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                TAPSCRIPT_PROOF_TAP_PREIMAGE1_TYPE => {
                    tap_preimage1 = Some(TapscriptPreimage::decode_tlv(record.value_reader())?);
                }
                TAPSCRIPT_PROOF_TAP_PREIMAGE2_TYPE => {
                    tap_preimage2 = Some(TapscriptPreimage::decode_tlv(record.value_reader())?);
                }
                TAPSCRIPT_PROOF_BIP86_TYPE => {
                    if record.value().len() != 1 {
                        return Err(Error::InvalidTlvValue(
                            TAPSCRIPT_PROOF_BIP86_TYPE.0,
                            "Length must be 1 for bool".to_string(),
                        ));
                    }
                    bip86 = Some(record.value()[0] != 0);
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

        Ok(TapscriptProof {
            tap_preimage1,
            tap_preimage2,
            bip86: bip86.ok_or(Error::MissingTlvField("TapscriptProof.bip86".to_string()))?,
            unknown_odd_types,
        })
    }
}

/// TaprootProof represents a proof that reveals the partial contents to a
/// tapscript tree within a taproot output.
/// This corresponds to `proof.TaprootProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaprootProof {
    /// OutputIndex is the index of the output for which the proof applies.
    pub output_index: u32,

    /// InternalKey is the internal key of the taproot output at OutputIndex.
    pub internal_key: PublicKey,

    /// CommitmentProof represents a commitment proof for an asset, proving
    /// inclusion or exclusion of an asset within a Taproot Asset commitment.
    pub commitment_proof: Option<CommitmentProof>,

    /// TapscriptProof represents a taproot control block to prove that a
    /// taproot output is not committing to a Taproot Asset commitment.
    ///
    /// NOTE: This field will be set only if the output does NOT contain a
    /// valid Taproot Asset commitment.
    pub tapscript_proof: Option<TapscriptProof>,

    /// UnknownOddTypes is a map of unknown odd types that were encountered
    /// during decoding. This map is used to preserve unknown types that we
    /// don't know of yet, so we can still encode them back when serializing.
    /// This enables forward compatibility with future versions of the
    /// protocol as it allows new odd (optional) types to be added without
    /// breaking old clients that don't yet fully understand them.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV types for TaprootProof fields (from external/taproot-assets-upstream/proof/records.go)
const TAPROOT_PROOF_OUTPUT_INDEX_TYPE: Type = Type(0);
const TAPROOT_PROOF_INTERNAL_KEY_TYPE: Type = Type(2);
const TAPROOT_PROOF_COMMITMENT_PROOF_TYPE: Type = Type(3);
const TAPROOT_PROOF_TAPSCRIPT_PROOF_TYPE: Type = Type(5);

/// Maximum number of taproot proofs allowed in a single record.
const MAX_NUM_TAPROOT_PROOFS: u64 = 1_000_000 / 43;
/// Maximum size in bytes for a single taproot proof blob.
const MAX_TAPROOT_PROOF_SIZE_BYTES: u64 = 65_535;

impl TaprootProof {
    /// Decodes a TaprootProof from a TLV byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_tlv(bytes)
    }

    fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);

        let mut output_index: Option<u32> = None;
        let mut internal_key: Option<PublicKey> = None;
        let mut commitment_proof: Option<CommitmentProof> = None;
        let mut tapscript_proof: Option<TapscriptProof> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                TAPROOT_PROOF_OUTPUT_INDEX_TYPE => {
                    let mut u32_bytes = [0u8; 4];
                    record
                        .value_reader()
                        .read_exact(&mut u32_bytes)
                        .map_err(Error::Io)?;
                    output_index = Some(u32::from_be_bytes(u32_bytes));
                }
                TAPROOT_PROOF_INTERNAL_KEY_TYPE => {
                    let pubkey_bytes: Vec<u8> = record.value().to_vec();
                    // Attempt to parse as compressed (33 bytes) or uncompressed (65 bytes)
                    internal_key = Some(PublicKey::from_slice(&pubkey_bytes).map_err(|e| {
                        Error::BitcoinSerialization(format!("Invalid internal key: {}", e))
                    })?);
                }
                TAPROOT_PROOF_COMMITMENT_PROOF_TYPE => {
                    commitment_proof = Some(
                        CommitmentProof::decode_tlv(record.value_reader()).map_err(|e| {
                            Error::TlvStream(format!("CommitmentProof decode failed: {}", e))
                        })?,
                    );
                }
                TAPROOT_PROOF_TAPSCRIPT_PROOF_TYPE => {
                    tapscript_proof = Some(TapscriptProof::decode_tlv(record.value_reader())?);
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        // As per BOLT #1: even, unknown types are an error.
                        return Err(Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }

        Ok(TaprootProof {
            output_index: output_index.ok_or(Error::MissingTlvField(
                "TaprootProof.output_index".to_string(),
            ))?,
            internal_key: internal_key.ok_or(Error::MissingTlvField(
                "TaprootProof.internal_key".to_string(),
            ))?,
            commitment_proof,
            tapscript_proof,
            unknown_odd_types,
        })
    }
}

/// Reads a Bitcoin-style compact-size integer from the reader.
fn read_varint<R: Read>(r: &mut R) -> Result<u64, Error> {
    let mut first_byte = [0u8; 1];
    r.read_exact(&mut first_byte).map_err(Error::Io)?;

    match first_byte[0] {
        253 => {
            let mut u16_bytes = [0u8; 2];
            r.read_exact(&mut u16_bytes).map_err(Error::Io)?;
            Ok(u16::from_be_bytes(u16_bytes) as u64)
        }
        254 => {
            let mut u32_bytes = [0u8; 4];
            r.read_exact(&mut u32_bytes).map_err(Error::Io)?;
            Ok(u32::from_be_bytes(u32_bytes) as u64)
        }
        255 => {
            let mut u64_bytes = [0u8; 8];
            r.read_exact(&mut u64_bytes).map_err(Error::Io)?;
            Ok(u64::from_be_bytes(u64_bytes))
        }
        _ => Ok(first_byte[0] as u64),
    }
}

/// Reads a length-prefixed byte vector capped by `max_len`.
fn read_inline_var_bytes<R: Read>(r: &mut R, max_len: u64) -> Result<Vec<u8>, Error> {
    let len = read_varint(r)?;
    if len > max_len {
        return Err(Error::BitcoinSerialization(format!(
            "inline var bytes too large: {} (max: {})",
            len, max_len
        )));
    }

    let mut bytes = alloc::vec![0u8; len as usize];
    r.read_exact(&mut bytes).map_err(Error::Io)?;
    Ok(bytes)
}

/// Decodes a list of taproot proofs using the inline-var-bytes format.
fn decode_taproot_proofs<R: Read>(mut r: R) -> Result<Vec<TaprootProof>, Error> {
    let num_proofs = read_varint(&mut r)?;
    if num_proofs > MAX_NUM_TAPROOT_PROOFS {
        return Err(Error::BitcoinSerialization(
            "too many taproot proofs".to_string(),
        ));
    }

    let mut proofs = Vec::with_capacity(num_proofs as usize);
    for _ in 0..num_proofs {
        let proof_bytes = read_inline_var_bytes(&mut r, MAX_TAPROOT_PROOF_SIZE_BYTES)?;
        let proof = TaprootProof::decode_tlv(bitcoin::io::Cursor::new(&proof_bytes))?;
        proofs.push(proof);
    }

    Ok(proofs)
}

/// Decodes additional input proof files in the same format as Go's proof file list.
fn decode_additional_inputs<R: Read>(mut r: R) -> Result<Vec<File>, Error> {
    let num_inputs = read_varint(&mut r)?;
    if num_inputs > u16::MAX as u64 {
        return Err(Error::BitcoinSerialization(
            "too many additional inputs".to_string(),
        ));
    }

    let mut inputs = Vec::with_capacity(num_inputs as usize);
    for _ in 0..num_inputs {
        let input_bytes = read_inline_var_bytes(&mut r, FILE_MAX_SIZE_BYTES)?;
        let input_file = File::from_bytes(&input_bytes)?;
        inputs.push(input_file);
    }

    Ok(inputs)
}

/// Decodes alt leaves encoded using the inline-var-bytes list format.
fn decode_alt_leaves(bytes: &[u8]) -> Result<Vec<crate::asset::Asset>, Error> {
    if bytes.len() as u64 > ALT_LEAVES_MAX_SIZE_BYTES {
        return Err(Error::InvalidTlvValue(
            PROOF_ALT_LEAVES_TYPE.0,
            format!("alt leaves payload too large: {} bytes", bytes.len()),
        ));
    }

    let mut cursor = bitcoin::io::Cursor::new(bytes);
    let num_leaves = read_varint(&mut cursor)?;
    let mut leaves = Vec::with_capacity(num_leaves as usize);
    let mut leaf_keys = BTreeSet::new();

    for _ in 0..num_leaves {
        let leaf_bytes = read_inline_var_bytes(&mut cursor, ALT_LEAVES_MAX_SIZE_BYTES)?;
        let leaf = crate::asset::decode_alt_leaf(&leaf_bytes)?;
        if leaf.script_key.len() != 33 {
            return Err(Error::InvalidTlvValue(
                PROOF_ALT_LEAVES_TYPE.0,
                format!(
                    "alt leaf script key length must be 33, got {}",
                    leaf.script_key.len()
                ),
            ));
        }

        let mut key_bytes = [0u8; 33];
        key_bytes.copy_from_slice(&leaf.script_key);
        let key = SerializedKey { bytes: key_bytes };
        if !leaf_keys.insert(key) {
            return Err(Error::InvalidTlvValue(
                PROOF_ALT_LEAVES_TYPE.0,
                "duplicate alt leaf script key".to_string(),
            ));
        }

        leaves.push(leaf);
    }

    Ok(leaves)
}

/// Decodes the STXO commitment proof map keyed by serialized script keys.
fn decode_commitment_proofs<R: Read>(
    mut r: R,
) -> Result<BTreeMap<SerializedKey, crate::commitment::Proof>, Error> {
    let num_proofs = read_varint(&mut r)?;
    if num_proofs > MAX_NUM_TAPROOT_PROOFS {
        return Err(Error::BitcoinSerialization(
            "too many commitment proofs".to_string(),
        ));
    }

    let mut proofs = BTreeMap::new();
    for _ in 0..num_proofs {
        let mut key_bytes = [0u8; 33];
        r.read_exact(&mut key_bytes).map_err(Error::Io)?;

        let proof_bytes = read_inline_var_bytes(&mut r, MAX_TAPROOT_PROOF_SIZE_BYTES)?;
        let proof = crate::commitment::Proof::decode_tlv(bitcoin::io::Cursor::new(&proof_bytes))?;
        proofs.insert(SerializedKey { bytes: key_bytes }, proof);
    }

    Ok(proofs)
}

/// Decodes a meta reveal TLV stream.
fn decode_meta_reveal<R: Read>(r: R) -> Result<MetaReveal, Error> {
    let mut stream = Stream::new(r);
    let mut meta_type: Option<MetaType> = None;
    let mut data: Option<Vec<u8>> = None;
    let mut unknown_odd_types = BTreeMap::new();

    while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
        match record.tlv_type() {
            META_REVEAL_ENCODING_TYPE => {
                if record.value().len() != 1 {
                    return Err(Error::InvalidTlvValue(
                        META_REVEAL_ENCODING_TYPE.0,
                        "Length must be 1 for meta type".to_string(),
                    ));
                }
                meta_type = Some(match record.value()[0] {
                    0 => MetaType::Opaque,
                    1 => MetaType::Json,
                    other => {
                        return Err(Error::InvalidTlvValue(
                            META_REVEAL_ENCODING_TYPE.0,
                            format!("Unknown meta type: {}", other),
                        ));
                    }
                });
            }
            META_REVEAL_DATA_TYPE => {
                data = Some(record.value().to_vec());
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

    Ok(MetaReveal {
        meta_type: meta_type.ok_or(Error::MissingTlvField("MetaReveal.meta_type".to_string()))?,
        data: data.ok_or(Error::MissingTlvField("MetaReveal.data".to_string()))?,
        unknown_odd_types,
    })
}

/// A Merkle proof that a transaction is included in a block.
/// This corresponds to `proof.TxMerkleProof` in Go.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxMerkleProof {
    /// The list of sibling hashes along the Merkle path from the transaction
    /// up to the root.
    pub nodes: Vec<TxMerkleNode>,

    /// Direction bits: `false` means the node is on the left, `true` means on the right.
    /// The bits correspond to entries in `nodes`.
    pub bits: Vec<bool>,
}

/// Meta data type for genesis reveals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaType {
    /// Opaque metadata bytes.
    Opaque = 0,
    /// JSON metadata bytes.
    Json = 1,
}

/// Meta reveal data included in proof files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetaReveal {
    /// The meta data type.
    pub meta_type: MetaType,
    /// The raw meta data bytes.
    pub data: Vec<u8>,
    /// Unknown odd types for forward compatibility.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

impl TxMerkleProof {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_tlv(bytes)
    }

    /// Reads a variable-length integer from a reader.
    fn read_varint<R: Read>(r: &mut R) -> Result<u64, Error> {
        let mut first_byte = [0u8; 1];
        r.read_exact(&mut first_byte).map_err(Error::Io)?;

        match first_byte[0] {
            253 => {
                let mut u16_bytes = [0u8; 2];
                r.read_exact(&mut u16_bytes).map_err(Error::Io)?;
                Ok(u16::from_be_bytes(u16_bytes) as u64)
            }
            254 => {
                let mut u32_bytes = [0u8; 4];
                r.read_exact(&mut u32_bytes).map_err(Error::Io)?;
                Ok(u32::from_be_bytes(u32_bytes) as u64)
            }
            255 => {
                let mut u64_bytes = [0u8; 8];
                r.read_exact(&mut u64_bytes).map_err(Error::Io)?;
                Ok(u64::from_be_bytes(u64_bytes))
            }
            _ => Ok(first_byte[0] as u64),
        }
    }

    /// Unpacks a bit-packed byte slice into a boolean vector.
    fn unpack_bits_from_slice(packed_bytes: &[u8]) -> Vec<bool> {
        let mut bits = Vec::with_capacity(packed_bytes.len() * 8);
        for i in 0..(packed_bytes.len() * 8) {
            let byte_index = i / 8;
            let bit_index = i % 8; // Use little-endian bit ordering like Go
            let bit = (packed_bytes[byte_index] >> bit_index) & 1;
            bits.push(bit == 1);
        }
        bits
    }

    /// Decodes a `TxMerkleProof` from a TLV-like format.
    ///
    /// The format consists of:
    /// 1. A VarInt for the number of nodes.
    /// 2. The nodes themselves (32 bytes each).
    /// 3. A VarInt for the length of the packed bits byte slice.
    /// 4. The packed bits byte slice.
    fn decode_tlv<R: Read>(mut r: R) -> Result<Self, Error> {
        const MERKLE_PROOF_MAX_NODES: u64 = 512;

        let num_nodes = Self::read_varint(&mut r)?;

        if num_nodes > MERKLE_PROOF_MAX_NODES {
            return Err(Error::TlvStream(format!(
                "Merkle proof has too many nodes: {}",
                num_nodes
            )));
        }

        let mut nodes = Vec::with_capacity(num_nodes as usize);
        for _ in 0..num_nodes {
            let mut hash_bytes = [0u8; 32];
            r.read_exact(&mut hash_bytes).map_err(Error::Io)?;
            nodes.push(TxMerkleNode::from_byte_array(hash_bytes));
        }

        let mut packed_bits = Vec::<u8>::new();
        r.read_to_limit(&mut packed_bits, num_nodes)
            .map_err(Error::Io)?;

        // let packed_bits_len = Self::read_varint(&mut r)?;

        // // Calculate maximum packed bits length using same logic as Go's packedBitsLen:
        // // (bits + 8 - 1) / 8 to round up to nearest byte
        // let max_packed_bits_len = (num_nodes + 8 - 1) / 8;
        // if packed_bits_len > max_packed_bits_len {
        //     return Err(Error::TlvStream(format!(
        //         "Packed bits length too large: maximum {}, got {}",
        //         max_packed_bits_len, packed_bits_len
        //     )));
        // }

        // let mut packed_bits = alloc::vec![0u8; packed_bits_len as usize];
        // r.read_exact(&mut packed_bits).map_err(Error::Io)?;

        let all_bits = Self::unpack_bits_from_slice(&packed_bits);

        // Take only the first num_nodes bits, exactly like Go does with bits[:len(p.Nodes)]
        let bits = all_bits.into_iter().take(num_nodes as usize).collect();

        Ok(TxMerkleProof { nodes, bits })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// Version is the version of the state transition proof.
    pub version: u32,

    /// PrevOut is the previous on-chain outpoint of the asset. This outpoint
    /// is that of the first on-chain input. Outpoints which correspond to
    /// the other inputs can be found in AdditionalInputs.
    pub prev_out: bitcoin::OutPoint,

    /// BlockHeader is the current block header committing to the on-chain
    /// transaction attempting an asset state transition.
    pub block_header: bitcoin::block::Header,

    /// BlockHeight is the height of the current block committing to the
    /// on-chain transaction attempting an asset state transition.
    pub block_height: u32,

    /// AnchorTx is the on-chain transaction attempting the asset state
    /// transition.
    pub anchor_tx: bitcoin::Transaction,

    /// TxMerkleProof is the merkle proof for AnchorTx used to prove its
    /// inclusion within BlockHeader.
    pub tx_merkle_proof: TxMerkleProof,

    /// Asset is the resulting asset after its state transition.
    pub asset: crate::asset::Asset,

    /// InclusionProof is the TaprootProof proving the new inclusion of the
    /// resulting asset within AnchorTx.
    pub inclusion_proof: TaprootProof,

    /// ExclusionProofs is the set of TaprootProofs proving the exclusion of
    /// the resulting asset from all other Taproot outputs within AnchorTx.
    pub exclusion_proofs: Vec<TaprootProof>,

    /// SplitRootProof is an optional TaprootProof needed if this asset is
    /// the result of a split. SplitRootProof proves inclusion of the root
    /// asset of the split.
    pub split_root_proof: Option<TaprootProof>,

    /// MetaReveal is the data that was revealed to prove the derivation of the
    /// meta data hash contained in the genesis asset.
    ///
    /// NOTE: This field is optional, and can only be specified if the asset
    /// above is a genesis asset. If specified, then verifiers _should_ also
    /// verify the hashes match up.
    pub meta_reveal: Option<MetaReveal>,

    /// AdditionalInputs is a nested full proof for any additional inputs
    /// found within the resulting asset.
    pub additional_inputs: Vec<File>,

    /// ChallengeWitness is an optional virtual transaction witness that
    /// serves as an ownership proof for the asset. If this is non-nil, then
    /// it is a valid transfer witness for a 1-input, 1-output virtual
    /// transaction that spends the asset in this proof and sends it to the
    /// NUMS key, to prove that the creator of the proof is able to produce
    /// a valid signature to spend the asset.
    pub challenge_witness: Option<bitcoin::Witness>,

    /// GenesisReveal is the Genesis information for an asset, that must be
    /// provided for minting proofs, and must be empty for non-minting
    /// proofs. This allows for derivation of the asset ID. If the asset is
    /// part of an asset group, the Genesis information is also used for
    /// re-derivation of the asset group key.
    pub genesis_reveal: Option<crate::asset::GenesisReveal>,

    /// GroupKeyReveal contains the data required to derive the final tweaked
    /// group key for an asset group.
    ///
    /// NOTE: This field is mandatory for the group anchor (i.e., the initial
    /// minting tranche of an asset group). Subsequent minting tranches
    /// require only a valid signature for the previously revealed group key.
    pub group_key_reveal: Option<crate::asset::GroupKeyReveal>,

    /// AltLeaves represent data used to construct an Asset commitment, that
    /// was inserted in the output anchor Tap commitment. These data-carrying
    /// leaves are used for a purpose distinct from representing individual
    /// Taproot Assets.
    pub alt_leaves: Vec<crate::asset::Asset>,

    /// UnknownOddTypes is a map of unknown odd types that were encountered
    /// during decoding. This map is used to preserve unknown types that we
    /// don't know of yet, so we can still encode them back when serializing.
    /// This enables forward compatibility with future versions of the
    /// protocol as it allows new odd (optional) types to be added without
    /// breaking old clients that don't yet fully understand them.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV Types for Proof (based on Go's proof/records.go)
const PROOF_VERSION_TYPE: Type = Type(0);
const PROOF_PREV_OUT_TYPE: Type = Type(2);
const PROOF_BLOCK_HEADER_TYPE: Type = Type(4);
const PROOF_ANCHOR_TX_TYPE: Type = Type(6);
const PROOF_TX_MERKLE_PROOF_TYPE: Type = Type(8);
const PROOF_ASSET_LEAF_TYPE: Type = Type(10);
const PROOF_INCLUSION_PROOF_TYPE: Type = Type(12);
const PROOF_EXCLUSION_PROOFS_TYPE: Type = Type(13);
const PROOF_SPLIT_ROOT_PROOF_TYPE: Type = Type(15);
const PROOF_META_REVEAL_TYPE: Type = Type(17);
const PROOF_ADDITIONAL_INPUTS_TYPE: Type = Type(19);
const PROOF_CHALLENGE_WITNESS_TYPE: Type = Type(21);
const PROOF_BLOCK_HEIGHT_TYPE: Type = Type(22);
const PROOF_GENESIS_REVEAL_TYPE: Type = Type(23);
const PROOF_GROUP_KEY_REVEAL_TYPE: Type = Type(25);
const PROOF_ALT_LEAVES_TYPE: Type = Type(27);

/// TLV type for the meta reveal encoding field.
const META_REVEAL_ENCODING_TYPE: Type = Type(0);
/// TLV type for the meta reveal data field.
const META_REVEAL_DATA_TYPE: Type = Type(2);

/// Maximum total size of the alt leaves payload.
const ALT_LEAVES_MAX_SIZE_BYTES: u64 = u16::MAX as u64;

// Magic bytes for individual proofs (not proof files)
const PROOF_PREFIX_MAGIC_BYTES: [u8; 4] = [0x54, 0x41, 0x50, 0x50]; // "TAPP"

impl Proof {
    /// Decodes a Proof from a TLV byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode_tlv(bytes)
    }

    fn decode_tlv<R: Read>(mut r: R) -> Result<Self, Error> {
        // Read and verify magic bytes for individual proofs
        let mut magic_bytes = [0u8; 4];
        r.read_exact(&mut magic_bytes).map_err(Error::Io)?;

        if magic_bytes != PROOF_PREFIX_MAGIC_BYTES {
            return Err(Error::BitcoinSerialization(format!(
                "Invalid proof magic bytes, expected {:?}, got {:?}",
                PROOF_PREFIX_MAGIC_BYTES, magic_bytes
            )));
        }

        let mut stream = Stream::new(r);

        let mut version: Option<u32> = None;
        let mut prev_out: Option<bitcoin::OutPoint> = None;
        let mut block_header: Option<bitcoin::block::Header> = None;
        let mut block_height: Option<u32> = None;
        let mut anchor_tx: Option<bitcoin::Transaction> = None;
        let mut tx_merkle_proof: Option<TxMerkleProof> = None;
        let mut asset: Option<crate::asset::Asset> = None;
        let mut inclusion_proof: Option<TaprootProof> = None;
        let mut exclusion_proofs: Option<Vec<TaprootProof>> = None;
        let mut split_root_proof: Option<TaprootProof> = None;
        let mut meta_reveal: Option<MetaReveal> = None;
        let mut additional_inputs: Option<Vec<File>> = None;
        let mut challenge_witness: Option<bitcoin::Witness> = None;
        let mut genesis_reveal: Option<crate::asset::GenesisReveal> = None;
        let mut group_key_reveal: Option<crate::asset::GroupKeyReveal> = None;
        let mut alt_leaves: Option<Vec<crate::asset::Asset>> = None;
        let mut unknown_odd_types = BTreeMap::new();

        while let Some(record) = stream.next_record().map_err(Error::TlvStream)? {
            match record.tlv_type() {
                PROOF_VERSION_TYPE => {
                    let mut u32_bytes = [0u8; 4];
                    record
                        .value_reader()
                        .read_exact(&mut u32_bytes)
                        .map_err(Error::Io)?;
                    version = Some(u32::from_be_bytes(u32_bytes));
                }
                PROOF_PREV_OUT_TYPE => {
                    // Decode OutPoint (32 bytes hash + 4 bytes index)
                    let mut hash_bytes = [0u8; 32];
                    let mut reader = record.value_reader();
                    reader.read_exact(&mut hash_bytes).map_err(Error::Io)?;
                    let mut index_bytes = [0u8; 4];
                    reader.read_exact(&mut index_bytes).map_err(Error::Io)?;
                    let index = u32::from_be_bytes(index_bytes);
                    prev_out = Some(bitcoin::OutPoint {
                        txid: bitcoin::Txid::from_byte_array(hash_bytes),
                        vout: index,
                    });
                }
                PROOF_BLOCK_HEADER_TYPE => {
                    let header_bytes = record.value();
                    block_header = Some(
                        bitcoin::block::Header::consensus_decode(&mut bitcoin::io::Cursor::new(
                            header_bytes,
                        ))
                        .map_err(|e| {
                            Error::BitcoinSerialization(format!("Invalid block header: {}", e))
                        })?,
                    );
                }
                PROOF_BLOCK_HEIGHT_TYPE => {
                    let mut u32_bytes = [0u8; 4];
                    record
                        .value_reader()
                        .read_exact(&mut u32_bytes)
                        .map_err(Error::Io)?;
                    block_height = Some(u32::from_be_bytes(u32_bytes));
                }
                PROOF_ANCHOR_TX_TYPE => {
                    // Decode bitcoin::Transaction using consensus_decode
                    let tx_bytes = record.value();
                    anchor_tx = Some(
                        bitcoin::Transaction::consensus_decode(&mut bitcoin::io::Cursor::new(
                            tx_bytes,
                        ))
                        .map_err(|e| {
                            Error::BitcoinSerialization(format!(
                                "Invalid anchor transaction: {}",
                                e
                            ))
                        })?,
                    );
                }
                PROOF_TX_MERKLE_PROOF_TYPE => {
                    tx_merkle_proof = Some(TxMerkleProof::decode_tlv(record.value_reader())?);
                }
                PROOF_ASSET_LEAF_TYPE => {
                    // Decode asset.Asset using proper TLV decoding
                    asset = Some(crate::asset::Asset::decode_tlv(record.value_reader())?);
                }
                PROOF_INCLUSION_PROOF_TYPE => {
                    inclusion_proof = Some(TaprootProof::decode_tlv(record.value_reader())?);
                }
                PROOF_EXCLUSION_PROOFS_TYPE => {
                    exclusion_proofs = Some(decode_taproot_proofs(record.value_reader())?);
                }
                PROOF_SPLIT_ROOT_PROOF_TYPE => {
                    split_root_proof = Some(TaprootProof::decode_tlv(record.value_reader())?);
                }
                PROOF_META_REVEAL_TYPE => {
                    meta_reveal = Some(decode_meta_reveal(record.value_reader())?);
                }
                PROOF_ADDITIONAL_INPUTS_TYPE => {
                    additional_inputs = Some(decode_additional_inputs(record.value_reader())?);
                }
                PROOF_CHALLENGE_WITNESS_TYPE => {
                    // Decode bitcoin::Witness using consensus_decode
                    let witness_bytes = record.value();
                    challenge_witness = Some(
                        bitcoin::Witness::consensus_decode(&mut bitcoin::io::Cursor::new(
                            witness_bytes,
                        ))
                        .map_err(|e| {
                            Error::BitcoinSerialization(format!("Invalid challenge witness: {}", e))
                        })?,
                    );
                }
                PROOF_GENESIS_REVEAL_TYPE => {
                    let genesis_info = crate::asset::decode_genesis_info(record.value_reader())
                        .map_err(|e| {
                            Error::TlvStream(format!("GenesisReveal decode failed: {}", e))
                        })?;
                    genesis_reveal = Some(crate::asset::GenesisReveal {
                        genesis_base: Some(genesis_info),
                        asset_type: crate::asset::AssetType::Normal,
                        amount: 0,
                        meta_reveal: None,
                    });
                }
                PROOF_GROUP_KEY_REVEAL_TYPE => {
                    group_key_reveal = Some(crate::asset::decode_group_key_reveal(record.value())?);
                }
                PROOF_ALT_LEAVES_TYPE => {
                    alt_leaves = Some(decode_alt_leaves(record.value())?);
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
            version: version.ok_or(Error::MissingTlvField("Proof.version".to_string()))?,
            prev_out: prev_out.ok_or(Error::MissingTlvField("Proof.prev_out".to_string()))?,
            block_header: block_header
                .ok_or(Error::MissingTlvField("Proof.block_header".to_string()))?,
            block_height: block_height
                .ok_or(Error::MissingTlvField("Proof.block_height".to_string()))?,
            anchor_tx: anchor_tx.ok_or(Error::MissingTlvField("Proof.anchor_tx".to_string()))?,
            tx_merkle_proof: tx_merkle_proof
                .ok_or(Error::MissingTlvField("Proof.tx_merkle_proof".to_string()))?,
            asset: asset.ok_or(Error::MissingTlvField("Proof.asset".to_string()))?,
            inclusion_proof: inclusion_proof
                .ok_or(Error::MissingTlvField("Proof.inclusion_proof".to_string()))?,
            exclusion_proofs: exclusion_proofs.unwrap_or_default(),
            split_root_proof,
            meta_reveal,
            additional_inputs: additional_inputs.unwrap_or_default(),
            challenge_witness,
            genesis_reveal,
            group_key_reveal,
            alt_leaves: alt_leaves.unwrap_or_default(),
            unknown_odd_types,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct File {
    /// Version is the version of the proof file.
    pub version: u32,

    /// Proofs are the proofs contained within the proof file starting from
    /// the genesis proof. Each proof includes its chained hash.
    pub proofs: Vec<HashedProof>,
}

/// HashedProof is a struct that contains an encoded proof and its chained
/// checksum.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HashedProof {
    /// ProofBytes is the encoded proof that is hashed.
    pub proof_bytes: Vec<u8>,

    /// Hash is the SHA256 sum of (prev_hash || proof).
    pub hash: [u8; 32],
}

// Constants from Go implementation
const FILE_MAX_NUM_PROOFS: u64 = 420000;
const FILE_MAX_PROOF_SIZE_BYTES: u64 = 128 * 1024 * 1024; // 128 MiB
/// Maximum size of a proof file in bytes.
const FILE_MAX_SIZE_BYTES: u64 = 500 * 1024 * 1024;

// Magic bytes for proof files
const FILE_PREFIX_MAGIC_BYTES: [u8; 4] = [0x54, 0x41, 0x50, 0x46]; // "TAPF"

impl File {
    /// Decodes a File from a byte slice.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        Self::decode(bytes)
    }

    /// Decodes a proof file from a byte slice.
    fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut cursor = bitcoin::io::Cursor::new(bytes);
        Self::decode_from_reader(&mut cursor)
    }

    /// Decodes a proof file from a reader.
    fn decode_from_reader<R: Read>(r: &mut R) -> Result<Self, Error> {
        // Read and verify magic bytes
        let mut magic_bytes = [0u8; 4];
        r.read_exact(&mut magic_bytes).map_err(Error::Io)?;

        if magic_bytes != FILE_PREFIX_MAGIC_BYTES {
            return Err(Error::BitcoinSerialization(format!(
                "Invalid file magic bytes, expected {:?}, got {:?}",
                FILE_PREFIX_MAGIC_BYTES, magic_bytes
            )));
        }

        // Read version (4 bytes, big endian)
        let mut version_bytes = [0u8; 4];
        r.read_exact(&mut version_bytes).map_err(Error::Io)?;
        let version = u32::from_be_bytes(version_bytes);

        // Read number of proofs (varint)
        let num_proofs = Self::read_varint(r)?;

        // Cap the number of proofs to avoid OOM attacks
        if num_proofs > FILE_MAX_NUM_PROOFS {
            return Err(Error::BitcoinSerialization(format!(
                "Too many proofs in file: {} (max: {})",
                num_proofs, FILE_MAX_NUM_PROOFS
            )));
        }

        let mut proofs = Vec::with_capacity(num_proofs as usize);
        let mut prev_hash = [0u8; 32]; // Start with zero hash

        for _ in 0..num_proofs {
            // Read proof size (varint)
            let proof_size = Self::read_varint(r)?;

            // Cap the size of an individual proof
            if proof_size > FILE_MAX_PROOF_SIZE_BYTES {
                return Err(Error::BitcoinSerialization(format!(
                    "Proof in file too large: {} bytes (max: {})",
                    proof_size, FILE_MAX_PROOF_SIZE_BYTES
                )));
            }

            // Read proof bytes
            let mut proof_bytes = Vec::with_capacity(proof_size as usize);
            proof_bytes.resize(proof_size as usize, 0u8);
            r.read_exact(&mut proof_bytes).map_err(Error::Io)?;

            // Read proof hash (32 bytes)
            let mut proof_hash = [0u8; 32];
            r.read_exact(&mut proof_hash).map_err(Error::Io)?;

            // Calculate expected hash: SHA256(prev_hash || proof_bytes)
            let expected_hash = Self::hash_proof(&proof_bytes, &prev_hash);

            // Verify hash matches
            if proof_hash != expected_hash {
                return Err(Error::BitcoinSerialization(
                    "Invalid proof file checksum".to_string(),
                ));
            }

            proofs.push(HashedProof {
                proof_bytes,
                hash: proof_hash,
            });

            // Update prev_hash for next iteration
            prev_hash = proof_hash;
        }

        Ok(File { version, proofs })
    }

    /// Reads a variable-length integer from a reader.
    fn read_varint<R: Read>(r: &mut R) -> Result<u64, Error> {
        let mut first_byte = [0u8; 1];
        r.read_exact(&mut first_byte).map_err(Error::Io)?;

        match first_byte[0] {
            253 => {
                let mut u16_bytes = [0u8; 2];
                r.read_exact(&mut u16_bytes).map_err(Error::Io)?;
                Ok(u16::from_be_bytes(u16_bytes) as u64)
            }
            254 => {
                let mut u32_bytes = [0u8; 4];
                r.read_exact(&mut u32_bytes).map_err(Error::Io)?;
                Ok(u32::from_be_bytes(u32_bytes) as u64)
            }
            255 => {
                let mut u64_bytes = [0u8; 8];
                r.read_exact(&mut u64_bytes).map_err(Error::Io)?;
                Ok(u64::from_be_bytes(u64_bytes))
            }
            _ => Ok(first_byte[0] as u64),
        }
    }

    /// Hashes a proof's content together with the previous hash:
    /// SHA256(prev_hash || proof_bytes)
    fn hash_proof(proof_bytes: &[u8], prev_hash: &[u8; 32]) -> [u8; 32] {
        use bitcoin::hashes::{Hash, sha256::Hash as Sha256Hash};

        // Create a combined buffer: prev_hash || proof_bytes
        let mut combined = Vec::with_capacity(32 + proof_bytes.len());
        combined.extend_from_slice(prev_hash);
        combined.extend_from_slice(proof_bytes);

        // Hash the combined buffer
        Sha256Hash::hash(&combined).to_byte_array()
    }

    /// Returns true if the file does not contain any proofs.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Returns the number of proofs contained in this file.
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }

    /// Returns the proof at the given index.
    pub fn proof_at(&self, index: usize) -> Result<Proof, Error> {
        if index >= self.proofs.len() {
            return Err(Error::BitcoinSerialization(format!(
                "Invalid index {}",
                index
            )));
        }

        Proof::from_bytes(&self.proofs[index].proof_bytes)
    }

    /// Returns the last proof in the chain of proofs.
    pub fn last_proof(&self) -> Result<Proof, Error> {
        if self.is_empty() {
            return Err(Error::BitcoinSerialization(
                "No proof available".to_string(),
            ));
        }

        self.proof_at(self.proofs.len() - 1)
    }

    /// Returns the raw proof at the given index as a byte slice.
    pub fn raw_proof_at(&self, index: usize) -> Result<Vec<u8>, Error> {
        if index >= self.proofs.len() {
            return Err(Error::BitcoinSerialization(format!(
                "Invalid index {}",
                index
            )));
        }

        Ok(self.proofs[index].proof_bytes.clone())
    }

    /// Returns the raw last proof in the chain of proofs as a byte slice.
    pub fn raw_last_proof(&self) -> Result<Vec<u8>, Error> {
        if self.is_empty() {
            return Err(Error::BitcoinSerialization(
                "No proof available".to_string(),
            ));
        }

        self.raw_proof_at(self.proofs.len() - 1)
    }
}
