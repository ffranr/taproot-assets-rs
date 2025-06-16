pub mod client;
pub use client::Client;

pub mod convert;

// Include the generated Rust code from prost-build under the taprpc module
pub mod taprpc {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/generated/taprpc.rs"));

    pub mod types {
        use taproot_assets_types as types;

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
            pub decoded_proof: Option<types::proof::Proof>,
        }
    }
}
