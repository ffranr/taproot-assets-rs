use super::*;
use bincode::{config::standard, serde::encode_to_vec};
use std::{fs::File, io::Write};

static INIT_LOGGER: std::sync::Once = std::sync::Once::new();

fn init_logger() {
    INIT_LOGGER.call_once(|| {
        env_logger::builder()
            .is_test(true) // Prevents logs from interfering with test output capture
            .filter_level(log::LevelFilter::Debug)
            .try_init()
            .ok(); // Ignore error if already initialized
    });
}

#[tokio::test]
async fn test_connect_tapd_getinfo() -> Result<()> {
    let root_dir = "/tmp/itest-tapd3945117514";

    let tls_cert_path = "/home/user/tapd-itest-cert/tls_ca.cert";

    let macaroon_path = format!("{}/data/regtest/admin.macaroon", root_dir);
    let destination_uri = "https://127.0.0.1:19656".to_string();
    let domain_name = "localhost".to_string();

    let mut client =
        Client::connect(destination_uri, macaroon_path, tls_cert_path, domain_name).await?;

    let get_info_res = client.get_info().await?;

    println!("get_info_res: {:?}", get_info_res);
    Ok(())
}

#[tokio::test]
async fn test_connect_tapd_listassets() -> Result<()> {
    let root_dir = "/tmp/itest-tapd2907364423";

    let tls_cert_path = "/home/user/tapd-itest-cert/tls_ca.cert";

    let macaroon_path = format!("{}/data/regtest/admin.macaroon", root_dir);
    let destination_uri = "https://127.0.0.1:19658".to_string();
    let domain_name = "localhost".to_string();

    let mut client =
        Client::connect(destination_uri, macaroon_path, tls_cert_path, domain_name).await?;

    let res = client
        .list_assets(
            false,
            false,
            false,
            false,
            0,
            0,
            Vec::<u8>::new(),
            None,
            None,
            Some(crate::taprpc::ScriptKeyTypeQuery {
                r#type: Some(crate::taprpc::script_key_type_query::Type::ExplicitType(1)),
            }),
        )
        .await?;

    println!("res: {:?}", res);
    Ok(())
}

#[tokio::test]
async fn test_connect_tapd_fetch_proof() -> Result<()> {
    init_logger();

    let root_dir = "/tmp/itest-tapd845014239";
    let tls_cert_path = "/home/user/tapd-itest-cert/tls_ca.cert";

    let macaroon_path = format!("{}/data/regtest/admin.macaroon", root_dir);
    let destination_uri = "https://127.0.0.1:19658".to_string();
    let domain_name = "localhost".to_string();

    let mut client =
        Client::connect(destination_uri, macaroon_path, tls_cert_path, domain_name).await?;

    log::info!("Calling list_assets");
    let res = client
        .list_assets(
            false,
            false,
            false,
            false,
            0,
            0,
            Vec::<u8>::new(),
            None,
            None,
            Some(crate::taprpc::ScriptKeyTypeQuery {
                r#type: Some(crate::taprpc::script_key_type_query::Type::ExplicitType(1)),
            }),
        )
        .await?;

    log::info!("list_assets response assets count: {:?}", res.assets.len());
    assert!(!res.assets.is_empty());

    log::info!("Exporting raw proof");
    let asset = &res.assets[0];
    let genesis = asset.asset_genesis.as_ref().unwrap();

    let export_resp = client
        .export_proof(
            genesis.asset_id,
            asset.script_key.clone(),
            None, // Some(genesis.genesis_point),
        )
        .await?;
    log::info!(
        "retrieved raw proof of size: {:?}",
        export_resp.raw_proof_file.len()
    );

    // Write the raw proof file to a binary file.
    let raw_proof_file_path = "/home/user/dev/tmp/itest-proof-file.bin";
    let mut raw_file = File::create(raw_proof_file_path)?;
    raw_file.write_all(&export_resp.raw_proof_file)?;
    log::info!("Wrote raw proof to file: {:?}", raw_proof_file_path);

    log::info!("Decoding raw proof file");
    let decode_resp = client
        .verify_proof(
            export_resp.raw_proof_file.clone(),
            export_resp.genesis_point,
        )
        .await?;
    log::info!("retreived decoded proof: valid={:?}", decode_resp.valid);

    // Unpack the proof.
    let proof = decode_resp.decoded_proof.unwrap();

    print!("proof: {:?}", proof);

    // Write/dump the proof to a binary file.
    let proof_file_path = "/home/user/dev/tmp/itest-decoded-proof.bin";
    let encoded = encode_to_vec(&proof, standard()).unwrap();
    let mut file = File::create(proof_file_path)?;
    file.write_all(&encoded)?;
    log::info!("Wrote proof to file: {:?}", proof_file_path);

    // Also save the raw proof file for TLV decoding tests
    let raw_proof_file_path = "/home/user/dev/tmp/itest-proof-raw.bin";
    let mut raw_file = File::create(raw_proof_file_path)?;
    raw_file.write_all(&export_resp.raw_proof_file)?;
    log::info!("Wrote raw proof to file: {:?}", raw_proof_file_path);

    Ok(())
}
