use crate::error::Error;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::{BlockHash, OutPoint, Witness};
use core::convert::TryFrom;

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
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
    /// The block hash the contains the anchor transaction above.
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
