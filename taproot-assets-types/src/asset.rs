use crate::error::Error;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::{BlockHash, OutPoint, Witness};
use core::convert::TryFrom;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

pub type AssetID = Sha256Hash;

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[repr(u8)]
/// The version of the Taproot Asset.
pub enum AssetVersion {
    /// V0 is the default asset version. This version will include
    /// the witness vector in the leaf for a tap commitment.
    V0 = 0,
    /// V1 is the asset version that leaves out the witness vector
    /// from the MS-SMT leaf encoding.
    V1 = 1,
}

impl AssetVersion {
    pub(crate) fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(AssetVersion::V0),
            1 => Ok(AssetVersion::V1),
            _ => Err(Error::InvalidTlvValue(
                0,
                format!("Unknown AssetVersion: {}", val),
            )),
        }
    }
}

impl TryFrom<i32> for AssetVersion {
    type Error = String;

    fn try_from(value: i32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AssetVersion::V0),
            1 => Ok(AssetVersion::V1),
            _ => Err(format!("Invalid AssetVersion value: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// The type of the asset.
pub enum AssetType {
    ///
    /// Indicates that an asset is capable of being split/merged, with each of the
    /// units being fungible, even across a key asset ID boundary (assuming the
    /// key group is the same).
    Normal,
    ///
    /// Indicates that an asset is a collectible, meaning that each of the other
    /// items under the same key group are not fully fungible with each other.
    /// Collectibles also cannot be split or merged.
    Collectible,
}

impl TryFrom<i32> for AssetType {
    type Error = String;

    fn try_from(value: i32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AssetType::Normal),
            1 => Ok(AssetType::Collectible),
            _ => Err(format!("Invalid AssetType value: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
/// The type of the script key.
pub enum ScriptKeyType {
    ///
    /// The type of script key is not known. This should only be stored for assets
    /// where we don't know the internal key of the script key (e.g. for
    /// imported proofs).
    Unknown,
    ///
    /// The script key is a normal BIP-86 key. This means that the internal key is
    /// turned into a Taproot output key by applying a BIP-86 tweak to it.
    Bip86,
    ///
    /// The script key is a key that contains a script path that is defined by the
    /// user and is therefore external to the tapd wallet. Spending this key
    /// requires providing a specific witness and must be signed through the vPSBT
    /// signing flow.
    ScriptPathExternal,
    ///
    /// The script key is a specific un-spendable key that indicates a burnt asset.
    /// Assets with this key type can never be spent again, as a burn key is a
    /// tweaked NUMS key that nobody knows the private key for.
    Burn,
    ///
    /// The script key is a specific un-spendable key that indicates a tombstone
    /// output. This is only the case for zero-value assets that result from a
    /// non-interactive (TAP address) send where no change was left over.
    Tombstone,
    ///
    /// The script key is used for an asset that resides within a Taproot Asset
    /// Channel. That means the script key is either a funding key (OP_TRUE), a
    /// commitment output key (to_local, to_remote, htlc), or a HTLC second-level
    /// transaction output key. Keys related to channels are not shown in asset
    /// balances (unless specifically requested) and are never used for coin
    /// selection.
    Channel,
}

impl TryFrom<i32> for ScriptKeyType {
    type Error = String;

    fn try_from(value: i32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(ScriptKeyType::Unknown),
            1 => Ok(ScriptKeyType::Bip86),
            2 => Ok(ScriptKeyType::ScriptPathExternal),
            3 => Ok(ScriptKeyType::Burn),
            4 => Ok(ScriptKeyType::Tombstone),
            5 => Ok(ScriptKeyType::Channel),
            _ => Err(format!("Invalid ScriptKeyType value: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Base genesis information for an asset.
pub struct GenesisInfo {
    /// The first outpoint of the transaction that created the asset (txid:vout).
    pub genesis_point: OutPoint,
    /// The name of the asset.
    pub name: String,
    /// The hash of the meta data for this genesis asset.
    pub meta_hash: Sha256Hash,
    /// The asset ID that uniquely identifies the asset.
    pub asset_id: AssetID,
    /// The type of the asset.
    pub asset_type: AssetType,
    ///
    /// The index of the output that carries the unique Taproot Asset commitment in
    /// the genesis transaction.
    pub output_index: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Information related to the key group of an asset (if it exists).
pub struct AssetGroup {
    /// The raw group key which is a normal public key.
    pub raw_group_key: Vec<u8>,
    ///
    /// The tweaked group key, which is derived based on the genesis point and also
    /// asset type.
    pub tweaked_group_key: Vec<u8>,
    ///
    /// A witness that authorizes a specific asset to be part of the asset group
    /// specified by the above key.
    pub asset_witness: Vec<u8>,
    ///
    /// The root hash of a tapscript tree, which enables future issuance authorized
    /// with a script witness.
    pub tapscript_root: Option<Sha256Hash>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Describes where in the chain an asset is currently anchored.
pub struct AnchorInfo {
    /// The transaction that anchors the Taproot Asset commitment where the asset
    ///   resides.
    pub anchor_tx: bitcoin::Transaction,
    /// The hash of the block which contains the anchor transaction above.
    pub anchor_block_hash: BlockHash,
    /// The outpoint (txid:vout) that stores the Taproot Asset commitment.
    pub anchor_outpoint: OutPoint,
    ///
    /// The raw internal key that was used to create the anchor Taproot output key.
    pub internal_key: Vec<u8>,
    ///
    /// The Taproot merkle root hash of the anchor output the asset was committed
    /// to. If there is no Tapscript sibling, this is equal to the Taproot Asset
    /// root commitment hash.
    pub merkle_root: Sha256Hash,
    ///
    /// The serialized preimage of a Tapscript sibling, if there was one. If this
    /// is empty, then the merkle_root hash is equal to the Taproot root hash of the
    /// anchor output.
    pub tapscript_sibling: Vec<u8>,
    /// The height of the block which contains the anchor transaction.
    pub block_height: u32,
    /// The UTC Unix timestamp of the block containing the anchor transaction.
    pub block_timestamp: i64,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Represents a previous input asset.
pub struct PrevInputAsset {
    /// The old/current location of the Taproot Asset commitment that was spent
    /// as an input.
    pub anchor_point: OutPoint,
    /// The ID of the asset that was spent.
    pub asset_id: AssetID,
    /// The script key of the asset that was spent.
    pub script_key: Vec<u8>,
    /// The amount of the asset that was spent.
    pub amount: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Decimal display dictates how to display the amount of an asset.
pub struct DecimalDisplay {
    ///
    /// Decimal display dictates the number of decimal places to shift the amount to
    /// the left converting from Taproot Asset integer representation to a
    /// UX-recognizable fractional quantity.
    ///
    /// For example, if the decimal_display value is 2 and there's 100 of those
    /// assets, then a wallet would display the amount as "1.00". This field is
    /// intended as information for wallets that display balances and has no impact
    /// on the behavior of the daemon or any other part of the protocol. This value
    /// is encoded in the MetaData field as a JSON field, therefore it is only
    /// compatible with assets that have a JSON MetaData field.
    pub decimal_display: u32,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Represents a Taproot Asset.
pub struct Asset {
    /// The version of the Taproot Asset.
    pub version: AssetVersion,
    /// The base genesis information of an asset. This information never changes.
    pub asset_genesis: Option<GenesisInfo>,
    /// The total amount of the asset stored in this Taproot Asset UTXO.
    pub amount: u64,
    /// An optional locktime, as with Bitcoin transactions.
    pub lock_time: i32,
    /// An optional relative lock time, same as Bitcoin transactions.
    pub relative_lock_time: i32,
    /// The version of the script, only version 0 is defined at present.
    pub script_version: i32,
    /// The script key of the asset, which can be spent under Taproot semantics.
    pub script_key: Vec<u8>,
    /// Indicates whether the script key is known to the wallet of the lnd node
    /// connected to the Taproot Asset daemon.
    pub script_key_is_local: bool,
    /// The information related to the key group of an asset (if it exists).
    pub asset_group: Option<AssetGroup>,
    /// Describes where in the chain the asset is currently anchored.
    pub chain_anchor: Option<AnchorInfo>,
    /// Previous witnesses for the asset.
    pub prev_witnesses: Vec<PrevWitness>,
    /// Indicates whether the asset has been spent.
    pub is_spent: bool,
    /// If the asset has been leased, this is the owner (application ID) of the
    /// lease.
    pub lease_owner: Vec<u8>,
    /// If the asset has been leased, this is the expiry of the lease as a Unix
    /// timestamp in seconds.
    pub lease_expiry: i64,
    /// Indicates whether this transfer was an asset burn. If true, the number of
    /// assets in this output are destroyed and can no longer be spent.
    pub is_burn: bool,
    /// Deprecated, use script_key_type instead!
    /// Indicates whether this script key has either been derived by the local
    /// wallet or was explicitly declared to be known by using the
    /// DeclareScriptKey RPC. Knowing the key conceptually means the key belongs
    /// to the local wallet or is at least known by a software that operates on
    /// the local wallet. The flag is never serialized in proofs, so this is
    /// never explicitly set for keys foreign to the local wallet. Therefore, if
    /// this method returns true for a script key, it means the asset with the
    /// script key will be shown in the wallet balance.
    pub script_key_declared_known: bool,
    /// Deprecated, use script_key_type instead!
    /// Indicates whether the script key is known to have a Tapscript spend path,
    /// meaning that the Taproot merkle root tweak is not empty. This will only
    /// ever be true if either script_key_is_local or script_key_internals_known
    /// is true as well, since the presence of a Tapscript spend path cannot be
    /// determined for script keys that aren't known to the wallet of the local
    /// tapd node.
    pub script_key_has_script_path: bool,
    /// This field defines a decimal display value that may be present. If this
    /// field is null, it means the presence of a decimal display field is
    /// unknown in the current context.
    pub decimal_display: Option<DecimalDisplay>,
    /// The type of the script key. This type is either user-declared when custom
    /// script keys are added, or automatically determined by the daemon for
    /// standard operations (e.g. BIP-86 keys, burn keys, tombstone keys, channel
    /// related keys).
    pub script_key_type: ScriptKeyType,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AssetMetaType {
    Opaque,
    Json,
}

impl TryFrom<i32> for AssetMetaType {
    type Error = String;

    fn try_from(value: i32) -> core::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(AssetMetaType::Opaque),
            1 => Ok(AssetMetaType::Json),
            _ => Err(format!("Invalid AssetMetaType value: {}", value)),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct AssetMeta {
    pub data: Vec<u8>,
    pub meta_type: AssetMetaType,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct GenesisReveal {
    pub genesis_base: Option<GenesisInfo>,
    pub asset_type: AssetType,
    pub amount: u64,
    pub meta_reveal: Option<AssetMeta>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct GroupKeyReveal {
    pub raw_group_key: Vec<u8>,
    pub tapscript_root: Option<Sha256Hash>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Represents a commitment to a split of an asset.
pub struct SplitCommitment {
    /// The root asset of the split commitment.
    pub root_asset: Option<Box<Asset>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
/// Represents a previous witness.
pub struct PrevWitness {
    /// Previous input asset ID.
    pub prev_id: Option<PrevInputAsset>,
    /// Transaction witness.
    pub tx_witness: Witness,
    /// Split commitment.
    pub split_commitment: Option<SplitCommitment>,
}

// TLV Types for Asset (based on Go's asset/records.go)
const ASSET_LEAF_VERSION: crate::tlv::Type = crate::tlv::Type(0);
const ASSET_LEAF_GENESIS: crate::tlv::Type = crate::tlv::Type(2);
const ASSET_LEAF_AMOUNT: crate::tlv::Type = crate::tlv::Type(6);
const ASSET_LEAF_LOCK_TIME: crate::tlv::Type = crate::tlv::Type(7);
const ASSET_LEAF_RELATIVE_LOCK_TIME: crate::tlv::Type = crate::tlv::Type(9);
const ASSET_LEAF_PREV_WITNESS: crate::tlv::Type = crate::tlv::Type(11);
const ASSET_LEAF_SCRIPT_VERSION: crate::tlv::Type = crate::tlv::Type(14);
const ASSET_LEAF_SCRIPT_KEY: crate::tlv::Type = crate::tlv::Type(16);
const ASSET_LEAF_GROUP_KEY: crate::tlv::Type = crate::tlv::Type(17);
const ASSET_LEAF_TYPE: crate::tlv::Type = crate::tlv::Type(4);

impl Asset {
    /// Decodes an Asset from a TLV byte slice.
    pub fn decode_tlv<R: bitcoin::io::Read>(r: R) -> Result<Self, crate::error::Error> {
        let mut stream = crate::tlv::Stream::new(r);
        let mut version: Option<AssetVersion> = None;
        let mut genesis: Option<GenesisInfo> = None;
        let mut amount: Option<u64> = None;
        let mut lock_time: Option<u64> = None;
        let mut relative_lock_time: Option<u64> = None;
        let mut prev_witnesses: Option<Vec<PrevWitness>> = None;
        let mut script_version: Option<u16> = None;
        let mut script_key: Option<Vec<u8>> = None;
        let mut group_key: Option<AssetGroup> = None;
        let mut unknown_odd_types = alloc::collections::BTreeMap::new();
        let mut asset_type: Option<AssetType> = None;

        while let Some(record) = stream
            .next_record()
            .map_err(crate::error::Error::TlvStream)?
        {
            match record.tlv_type() {
                ASSET_LEAF_VERSION => {
                    if record.value().len() != 1 {
                        return Err(crate::error::Error::InvalidTlvValue(
                            ASSET_LEAF_VERSION.0,
                            String::from("Length must be 1 for version"),
                        ));
                    }
                    version = Some(AssetVersion::from_u8(record.value()[0])?);
                }
                ASSET_LEAF_GENESIS => {
                    genesis = Some(GenesisInfo {
                        genesis_point: bitcoin::OutPoint::default(),
                        name: String::new(),
                        meta_hash: Sha256Hash::const_hash(&[]),
                        asset_id: AssetID::const_hash(&[]),
                        asset_type: asset_type.unwrap_or(AssetType::Normal),
                        output_index: 0,
                    });
                }
                ASSET_LEAF_AMOUNT => {
                    // Decode varint for amount
                    let mut cursor = bitcoin::io::Cursor::new(record.value());
                    amount = Some(Self::read_varint(&mut cursor)?);
                }
                ASSET_LEAF_LOCK_TIME => {
                    // Decode varint for lock time
                    let mut cursor = bitcoin::io::Cursor::new(record.value());
                    let lock_time_val = Self::read_varint(&mut cursor)?;
                    lock_time = Some(lock_time_val);
                }
                ASSET_LEAF_RELATIVE_LOCK_TIME => {
                    // Decode varint for relative lock time
                    let mut cursor = bitcoin::io::Cursor::new(record.value());
                    let relative_lock_time_val = Self::read_varint(&mut cursor)?;
                    relative_lock_time = Some(relative_lock_time_val);
                }
                ASSET_LEAF_PREV_WITNESS => {
                    // For now, we'll create an empty vector
                    // TODO: Implement proper PrevWitness TLV decoding
                    prev_witnesses = Some(Vec::new());
                }
                ASSET_LEAF_SCRIPT_VERSION => {
                    if record.value().len() != 2 {
                        return Err(crate::error::Error::InvalidTlvValue(
                            ASSET_LEAF_SCRIPT_VERSION.0,
                            String::from("Length must be 2 for script version"),
                        ));
                    }
                    script_version =
                        Some(u16::from_be_bytes([record.value()[0], record.value()[1]]));
                }
                ASSET_LEAF_SCRIPT_KEY => {
                    script_key = Some(record.value().to_vec());
                }
                ASSET_LEAF_GROUP_KEY => {
                    // For now, we'll create a simplified AssetGroup
                    // TODO: Implement proper AssetGroup TLV decoding
                    group_key = Some(AssetGroup {
                        raw_group_key: record.value().to_vec(),
                        tweaked_group_key: Vec::new(),
                        asset_witness: Vec::new(),
                        tapscript_root: None,
                    });
                }
                ASSET_LEAF_TYPE => {
                    if record.value().len() != 1 {
                        return Err(crate::error::Error::InvalidTlvValue(
                            ASSET_LEAF_TYPE.0,
                            String::from("Length must be 1 for asset type"),
                        ));
                    }
                    asset_type = Some(match record.value()[0] {
                        0 => AssetType::Normal,
                        1 => AssetType::Collectible,
                        _ => {
                            return Err(crate::error::Error::InvalidTlvValue(
                                ASSET_LEAF_TYPE.0,
                                format!("Unknown asset type: {}", record.value()[0]),
                            ))
                        }
                    });
                }
                type_val => {
                    if type_val.is_odd() {
                        unknown_odd_types.insert(type_val.0, record.value().to_vec());
                    } else {
                        return Err(crate::error::Error::UnknownTlvType(type_val.0));
                    }
                }
            }
        }

        Ok(Asset {
            version: version.ok_or(crate::error::Error::MissingTlvField(
                "Asset.version".to_string(),
            ))?,
            asset_genesis: genesis,
            amount: amount.unwrap_or(0),
            lock_time: lock_time.map(|v| v as i32).unwrap_or(0),
            relative_lock_time: relative_lock_time.map(|v| v as i32).unwrap_or(0),
            script_version: script_version.map(|v| v as i32).unwrap_or(0),
            script_key: script_key.unwrap_or_default(),
            script_key_is_local: false, // Not encoded in TLV
            asset_group: group_key,
            chain_anchor: None, // Not encoded in TLV
            prev_witnesses: prev_witnesses.unwrap_or_default(),
            is_spent: false,                         // Not encoded in TLV
            lease_owner: Vec::new(),                 // Not encoded in TLV
            lease_expiry: 0,                         // Not encoded in TLV
            is_burn: false,                          // Not encoded in TLV
            script_key_declared_known: false,        // Not encoded in TLV
            script_key_has_script_path: false,       // Not encoded in TLV
            decimal_display: None,                   // Not encoded in TLV
            script_key_type: ScriptKeyType::Unknown, // Not encoded in TLV
        })
    }

    /// Reads a variable-length integer from a reader.
    fn read_varint<R: bitcoin::io::Read>(r: &mut R) -> Result<u64, crate::error::Error> {
        let mut first_byte = [0u8; 1];
        r.read_exact(&mut first_byte)
            .map_err(crate::error::Error::Io)?;

        match first_byte[0] {
            253 => {
                let mut u16_bytes = [0u8; 2];
                r.read_exact(&mut u16_bytes)
                    .map_err(crate::error::Error::Io)?;
                Ok(u16::from_be_bytes(u16_bytes) as u64)
            }
            254 => {
                let mut u32_bytes = [0u8; 4];
                r.read_exact(&mut u32_bytes)
                    .map_err(crate::error::Error::Io)?;
                Ok(u32::from_be_bytes(u32_bytes) as u64)
            }
            255 => {
                let mut u64_bytes = [0u8; 8];
                r.read_exact(&mut u64_bytes)
                    .map_err(crate::error::Error::Io)?;
                Ok(u64::from_be_bytes(u64_bytes))
            }
            _ => Ok(first_byte[0] as u64),
        }
    }
}
