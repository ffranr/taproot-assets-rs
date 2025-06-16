pub mod client;
pub use client::Client;

pub mod convert;

// Include the generated Rust code from prost-build under the taprpc module
pub mod taprpc {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/taprpc.rs"));

    pub mod types {
        use taproot_assets_types as types;

        use serde::{Deserialize, Serialize};

        #[derive(Debug, Clone, Eq, PartialEq, Hash)]
        pub struct ListAssetsResponse {
            pub assets: Vec<types::asset::Asset>,
            pub unconfirmed_transfers: u64,
            pub unconfirmed_mints: u64,
        }

        #[derive(Debug, Clone, Eq, PartialEq, Hash)]
        pub struct ExportProofResponse {
            pub raw_proof_file: Vec<u8>,
            pub genesis_point: Option<bitcoin::OutPoint>,
        }

        #[derive(Debug, Clone, Eq, PartialEq)]
        pub struct VerifyProofResponse {
            pub valid: bool,
            pub decoded_proof: Option<DecodedProof>,
        }

        /// This struct represents the result of decoding either a proof file or a single
        /// issuence/transfer proof. It contains all the information needed to verify the validity
        /// of an asset state and prove asset ownership.
        #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
        pub struct DecodedProof {
            /// The index depth of the decoded proof, with 0 being the latest proof.
            /// This field indicates which proof within a proof file has been decoded.
            pub proof_at_depth: u32,

            /// The total number of proofs contained in the decoded proof file (this will
            /// always be 1 if a single mint/transition proof was given as the raw_proof
            /// instead of a file).
            pub number_of_proofs: u32,

            /// The asset referenced in the proof. This is the resulting asset after its
            /// state transition.
            pub asset: types::asset::Asset,

            /// The reveal meta data associated with the proof, if available.
            /// This field is optional and can only be specified if the asset
            /// above is a genesis asset.
            pub meta_reveal: Option<types::asset::AssetMeta>,

            /// The merkle proof for AnchorTx used to prove its inclusion within
            /// BlockHeader.
            pub tx_merkle_proof: types::proof::TxMerkleProof,

            /// The TaprootProof proving the new inclusion of the resulting asset
            /// within AnchorTx.
            pub inclusion_proof: types::proof::TaprootProof,

            /// The set of TaprootProofs proving the exclusion of the resulting asset
            /// from all other Taproot outputs within AnchorTx.
            pub exclusion_proofs: Vec<types::proof::TaprootProof>,

            /// An optional TaprootProof needed if this asset is the result of a split.
            /// SplitRootProof proves inclusion of the root asset of the split.
            pub split_root_proof: Option<types::proof::TaprootProof>,

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
            pub genesis_reveal: Option<types::asset::GenesisReveal>,

            /// GroupKeyReveal is an optional field that includes the information needed
            /// to derive the tweaked group key. This field is mandatory for the group
            /// anchor (i.e., the initial minting tranche of an asset group). Subsequent
            /// minting tranches require only a valid signature for the previously revealed
            /// group key.
            pub group_key_reveal: Option<types::asset::GroupKeyReveal>,
        }
    }
}
