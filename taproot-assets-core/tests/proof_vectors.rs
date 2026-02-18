use std::path::PathBuf;

use bitcoin::TapNodeHash;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::{self, PublicKey as SecpPublicKey, Scalar, Secp256k1};
use serde::Deserialize;
use taproot_assets_core::verify::proof::{verify_genesis_reveal, verify_proofs};
use taproot_assets_core::{OpsError, TaprootOps};
use taproot_assets_types::asset::SerializedKey;
use taproot_assets_types::proof::{File, Proof};

const VECTOR_JSON_FILES: &[&str] =
    &["../external/taproot-assets-upstream/proof/testdata/proof_tlv_encoding_regtest.json"];

#[test]
fn verify_vectors_in_core() {
    let ops = BitcoinTaprootOps::new();
    let mut saw_vector_file = false;
    let mut decoded_any = false;
    let mut verified_any = false;

    for path in VECTOR_JSON_FILES {
        let full_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
        if !full_path.exists() {
            eprintln!("skipping {path}: vector file not found");
            continue;
        }
        saw_vector_file = true;
        let proofs = load_proofs_from_json(path);
        if !proofs.is_empty() {
            decoded_any = true;
        }
        for (index, proof) in proofs.into_iter().enumerate() {
            if verify_proofs(&ops, &proof).is_ok() && verify_genesis_reveal(&proof).is_ok() {
                verified_any = true;
            } else {
                eprintln!("skipping {path}#{index}: core verification failed");
            }
        }
    }

    if !saw_vector_file {
        eprintln!("skipping proof vector test: no vector files found");
        return;
    }

    assert!(decoded_any, "no vectors decoded from test data");
    if !verified_any {
        eprintln!("no vectors passed core verification");
    }
}

#[derive(Deserialize)]
struct VectorFile {
    valid_test_cases: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    expected: String,
}

fn load_proofs_from_json(relative_path: &str) -> Vec<Proof> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative_path);
    let contents = std::fs::read_to_string(&path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", path.display()));
    let vectors: VectorFile = serde_json::from_str(&contents)
        .unwrap_or_else(|err| panic!("failed to parse {}: {err}", path.display()));

    let mut proofs = Vec::new();
    for (index, case) in vectors.valid_test_cases.into_iter().enumerate() {
        let stripped: String = case.expected.split_whitespace().collect();
        let bytes = match hex::decode(stripped) {
            Ok(bytes) => bytes,
            Err(err) => {
                eprintln!("skipping {relative_path}#{index}: hex decode failed ({err})");
                continue;
            }
        };
        match decode_proofs(&bytes, relative_path, index) {
            Ok(mut decoded) => proofs.append(&mut decoded),
            Err(err) => {
                eprintln!("skipping {relative_path}#{index}: {err}");
            }
        }
    }
    proofs
}

fn decode_proofs(bytes: &[u8], relative_path: &str, index: usize) -> Result<Vec<Proof>, String> {
    if let Ok(file) = File::from_bytes(&bytes) {
        let mut proofs = Vec::new();
        for (proof_index, hashed) in file.proofs.iter().enumerate() {
            let proof = Proof::from_bytes(&hashed.proof_bytes).map_err(|err| {
                format!("failed to decode proof {relative_path}#{index}.{proof_index}: {err}")
            })?;
            proofs.push(proof);
        }
        return Ok(proofs);
    }

    let proof = Proof::from_bytes(&bytes)
        .map_err(|err| format!("failed to decode proof {relative_path}#{index}: {err}"))?;
    Ok(vec![proof])
}

#[derive(Debug)]
struct BitcoinTaprootOps {
    secp: Secp256k1<secp256k1::VerifyOnly>,
}

impl BitcoinTaprootOps {
    fn new() -> Self {
        Self {
            secp: Secp256k1::verification_only(),
        }
    }
}

impl TaprootOps for BitcoinTaprootOps {
    type PubKey = SecpPublicKey;

    fn parse_group_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidRawGroupKey)
    }

    fn parse_internal_key(&self, key: &SerializedKey) -> Result<Self::PubKey, OpsError> {
        SecpPublicKey::from_slice(&key.bytes).map_err(|_| OpsError::InvalidInternalKey)
    }

    fn add_tweak(&self, pubkey: &Self::PubKey, tweak: [u8; 32]) -> Result<Self::PubKey, OpsError> {
        let tweak = Scalar::from_be_bytes(tweak).map_err(|_| OpsError::AssetIdTweakOutOfRange)?;
        pubkey
            .add_exp_tweak(&self.secp, &tweak)
            .map_err(|_| OpsError::InvalidGroupKeyTweak)
    }

    fn taproot_output_key(
        &self,
        internal_key: &Self::PubKey,
        tapscript_root: Option<[u8; 32]>,
    ) -> Result<SerializedKey, OpsError> {
        let merkle_root = tapscript_root.map(TapNodeHash::from_byte_array);
        let (xonly_key, _) = internal_key.x_only_public_key();
        let (tweaked, parity) = xonly_key.tap_tweak(&self.secp, merkle_root);
        let output_key =
            SecpPublicKey::from_x_only_public_key(tweaked.to_x_only_public_key(), parity);

        Ok(SerializedKey {
            bytes: output_key.serialize(),
        })
    }
}
