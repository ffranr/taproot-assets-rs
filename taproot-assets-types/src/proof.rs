// --- Proof structures (corresponding to Go's `proof` package) ---

use alloc::collections::BTreeMap;
use bitcoin::hashes::Hash;
use bitcoin::io::Read;
use bitcoin::PublicKey;
pub use bitcoin::TxMerkleNode;
use serde::{Deserialize, Serialize};

use crate::alloc::string::ToString;
use alloc::{format, vec::Vec};

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
    pub tap_sibling_preimage: Option<crate::commitment::TapscriptPreimage>,

    /// UnknownOddTypes is a map of unknown odd types that were encountered
    /// during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV Types for CommitmentProof (based on Go's proof/records.go)
// No explicit type for the proof.Proof itself, assuming it's the primary content or handled differently.
const COMMITMENT_PROOF_TAP_SIBLING_PREIMAGE_TYPE: Type = Type(5);
// Type for the Merkle Proof itself is not directly specified here for CommitmentProof's TLV stream.
// It's often the core data. Let's assume it's decoded from the main stream if no specific type.
// For now, we will assume CommitmentMerkleProof::decode_tlv handles its own format from a reader.

impl CommitmentProof {
    fn decode_tlv<R: Read>(r: R) -> Result<Self, Error> {
        let mut stream = Stream::new(r);
        let mut asset_proof: Option<crate::commitment::AssetProof> = None;
        let mut taproot_asset_proof: Option<crate::commitment::TaprootAssetProof> = None;
        let mut tap_sibling_preimage: Option<TapscriptPreimage> = None;
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
    pub tap_preimage1: Option<crate::commitment::TapscriptPreimage>,

    /// TapPreimage2, if specified, is the pair preimage for TapPreimage1 at
    /// depth 1.
    pub tap_preimage2: Option<crate::commitment::TapscriptPreimage>,

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

    /// CommitmentProof represents a commitment proof for an asset.
    pub commitment_proof: Option<CommitmentProof>,

    /// TapscriptProof represents a proof that a taproot output is not committing
    /// to a Taproot Asset commitment.
    pub tapscript_proof: Option<TapscriptProof>,

    /// UnknownOddTypes is a map of unknown odd types encountered during decoding.
    pub unknown_odd_types: BTreeMap<u64, Vec<u8>>,
}

// TLV types for TaprootProof fields (from external/taproot-assets-upstream/proof/records.go)
const TAPROOT_PROOF_OUTPUT_INDEX_TYPE: Type = Type(0);
const TAPROOT_PROOF_INTERNAL_KEY_TYPE: Type = Type(2);
const TAPROOT_PROOF_COMMITMENT_PROOF_TYPE: Type = Type(3);
const TAPROOT_PROOF_TAPSCRIPT_PROOF_TYPE: Type = Type(5);

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

        let packed_bits_len = Self::read_varint(&mut r)?;

        // Calculate maximum packed bits length using same logic as Go's packedBitsLen:
        // (bits + 8 - 1) / 8 to round up to nearest byte
        let max_packed_bits_len = (num_nodes + 8 - 1) / 8;
        if packed_bits_len > max_packed_bits_len {
            return Err(Error::TlvStream(format!(
                "Packed bits length too large: maximum {}, got {}",
                max_packed_bits_len, packed_bits_len
            )));
        }

        let mut packed_bits = alloc::vec![0u8; packed_bits_len as usize];
        r.read_exact(&mut packed_bits).map_err(Error::Io)?;

        let all_bits = Self::unpack_bits_from_slice(&packed_bits);

        // Take only the first num_nodes bits, exactly like Go does with bits[:len(p.Nodes)]
        let bits = all_bits.into_iter().take(num_nodes as usize).collect();

        Ok(TxMerkleProof { nodes, bits })
    }
}

/// This struct represents the result of decoding either a proof file or a single
/// issuence/transfer proof. It contains all the information needed to verify the validity
/// of an asset state and prove asset ownership.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proof {
    /// The index depth of the decoded proof, with 0 being the latest proof.
    /// This field indicates which proof within a proof file has been decoded.
    pub proof_at_depth: u32,

    /// The total number of proofs contained in the decoded proof file (this will
    /// always be 1 if a single mint/transition proof was given as the raw_proof
    /// instead of a file).
    pub number_of_proofs: u32,

    /// The asset referenced in the proof. This is the resulting asset after its
    /// state transition.
    pub asset: crate::asset::Asset,

    /// The reveal meta data associated with the proof, if available.
    /// This field is optional and can only be specified if the asset
    /// above is a genesis asset.
    pub meta_reveal: Option<crate::asset::AssetMeta>,

    /// The merkle proof for AnchorTx used to prove its inclusion within
    /// BlockHeader.
    pub tx_merkle_proof: TxMerkleProof,

    /// The TaprootProof proving the new inclusion of the resulting asset
    /// within AnchorTx.
    pub inclusion_proof: TaprootProof,

    /// The set of TaprootProofs proving the exclusion of the resulting asset
    /// from all other Taproot outputs within AnchorTx.
    pub exclusion_proofs: Vec<TaprootProof>,

    /// An optional TaprootProof needed if this asset is the result of a split.
    /// SplitRootProof proves inclusion of the root asset of the split.
    pub split_root_proof: Option<TaprootProof>,

    /// The number of additional nested full proofs for any inputs found within
    /// the resulting asset.
    pub num_additional_inputs: u32,

    /// ChallengeWitness is an optional virtual transaction witness that serves
    /// as an ownership proof for the asset. If this is non-nil, then it is a
    /// valid transfer witness for a 1-input, 1-output virtual transaction that
    /// spends the asset in this proof and sends it to the NUMS key, to prove
    /// that the creator of the proof is able to produce a valid signature to
    /// spend the asset.
    pub challenge_witness: Option<bitcoin::Witness>,

    /// Indicates whether the state transition this proof represents is a burn,
    /// meaning that the assets were provably destroyed and can no longer be
    /// spent.
    pub is_burn: bool,

    /// GenesisReveal is an optional field that is the Genesis information for
    /// the asset. This is required for minting proofs and must be empty for
    /// non-minting proofs. This allows for derivation of the asset ID.
    pub genesis_reveal: Option<crate::asset::GenesisReveal>,

    /// GroupKeyReveal is an optional field that includes the information needed
    /// to derive the tweaked group key. This field is mandatory for the group
    /// anchor (i.e., the initial minting tranche of an asset group). Subsequent
    /// minting tranches require only a valid signature for the previously revealed
    /// group key.
    pub group_key_reveal: Option<crate::asset::GroupKeyReveal>,
}
