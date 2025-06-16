use crate::taprpc::taproot_assets_client::TaprootAssetsClient;
use std::{fs, path::Path};
use thiserror::Error;
use tonic::codegen::InterceptedService;
use tonic::metadata::{MetadataKey, MetadataValue};
use tonic::service::Interceptor;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

use taproot_assets_types as types;

#[cfg(test)]
mod tests;

/// A type alias for a TaprootAssetsClient with macaroon authentication.
pub type RpcClient = TaprootAssetsClient<InterceptedService<Channel, MacaroonInterceptor>>;

/// Public error type for this crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Transport(#[from] tonic::transport::Error),

    #[error("gRPC call failed: {0}")]
    GrpcStatus(#[from] tonic::Status),

    #[error("Conversion error: {0}")]
    Conversion(#[from] crate::convert::ConversionError),
}

pub type Result<T> = std::result::Result<T, ClientError>;

pub struct Client {
    inner: RpcClient,
}

impl Client {
    /// Creates a new client from an existing RpcClient.
    pub fn new(inner: RpcClient) -> Self {
        Self { inner }
    }

    /// Connects to a tapd instance.
    ///
    /// # Arguments
    /// * `dst_uri` - The destination URI (e.g., "https://localhost:port").
    /// * `macaroon_path` - Path to the macaroon file.
    /// * `server_ca_cert_path` - Path to the server's root CA certificate file.
    /// * `expected_server_domain` - The domain name to verify against the server's certificate.
    ///
    /// # Returns
    /// A new Client instance.
    pub async fn connect(
        dst_uri: String,
        macaroon_path: impl AsRef<Path>,
        server_ca_cert_path: impl AsRef<Path>,
        expected_server_domain: String,
    ) -> Result<Self> {
        let rpc_client = connect_rpc(
            dst_uri,
            macaroon_path,
            server_ca_cert_path,
            expected_server_domain,
        )
        .await?;
        Ok(Self::new(rpc_client))
    }

    /// Retrieves information about the tapd instance.
    pub async fn get_info(&mut self) -> Result<crate::taprpc::GetInfoResponse> {
        let request = crate::taprpc::GetInfoRequest {};
        let response = self.inner.get_info(request).await?;
        Ok(response.into_inner())
    }

    /// Lists assets.
    pub async fn list_assets(
        &mut self,
        with_witness: bool,
        include_spent: bool,
        include_leased: bool,
        include_unconfirmed_mints: bool,
        min_amount: u64,
        max_amount: u64,
        group_key: Vec<u8>,
        script_key: Option<crate::taprpc::ScriptKey>,
        anchor_outpoint: Option<crate::taprpc::OutPoint>,
        script_key_type: Option<crate::taprpc::ScriptKeyTypeQuery>,
    ) -> Result<crate::taprpc::types::ListAssetsResponse> {
        let request = crate::taprpc::ListAssetRequest {
            with_witness,
            include_spent,
            include_leased,
            include_unconfirmed_mints,
            min_amount,
            max_amount,
            group_key,
            script_key,
            anchor_outpoint,
            script_key_type,
        };
        let rpc_response = self.inner.list_assets(request).await?.into_inner();

        // Perform the conversion using TryFrom.
        let domain_response = crate::taprpc::types::ListAssetsResponse::try_from(rpc_response)?;
        Ok(domain_response)
    }

    /// ExportProof exports the latest raw proof file anchored at the specified script_key.
    pub async fn export_proof(
        &mut self,
        asset_id: types::asset::AssetID,
        script_key: Vec<u8>,
        outpoint: Option<bitcoin::OutPoint>,
    ) -> Result<crate::taprpc::types::ExportProofResponse> {
        let rpc_outpoint = outpoint.map(|op| crate::taprpc::OutPoint {
            txid: <bitcoin::Txid as AsRef<[u8; 32]>>::as_ref(&op.txid).to_vec(),
            output_index: op.vout,
        });

        let request = crate::taprpc::ExportProofRequest {
            asset_id: <bitcoin::hashes::sha256::Hash as AsRef<[u8; 32]>>::as_ref(&asset_id)
                .to_vec(),
            script_key,
            outpoint: rpc_outpoint,
        };

        log::debug!("Calling export_proof RPC endpoint");
        let rpc_response = self.inner.export_proof(request).await?.into_inner();
        log::debug!("Got export_proof RPC endpoint response");

        log::debug!("Converting export_proof RPC endpoint response to domain response");
        let domain_response = crate::taprpc::types::ExportProofResponse::try_from(rpc_response)?;
        log::debug!("Successfully converted export_proof RPC endpoint response to domain response");

        Ok(domain_response)
    }

    pub async fn verify_proof(
        &mut self,
        raw_proof_file: Vec<u8>,
        genesis_point: Option<bitcoin::OutPoint>,
    ) -> Result<crate::taprpc::types::VerifyProofResponse> {
        let genesis_point_str = if let Some(genesis_point) = genesis_point {
            genesis_point.to_string()
        } else {
            "".to_string()
        };

        let request = crate::taprpc::ProofFile {
            raw_proof_file,
            genesis_point: genesis_point_str,
        };

        let rpc_response = self.inner.verify_proof(request).await?.into_inner();

        // Parse response.
        let domain_response = crate::taprpc::types::VerifyProofResponse::try_from(rpc_response)?;

        Ok(domain_response)
    }
}

/// Connects to a tapd instance for testing, using a specific server CA certificate.
///
/// # Arguments
/// * `dst_uri` - The destination URI (e.g., "https://localhost:port").
/// * `macaroon_path` - Path to the macaroon file.
/// * `server_ca_cert_path` - Path to the server's root CA certificate file.
/// * `expected_server_domain` - The domain name to verify against the server's certificate.
///
/// # Returns
/// A TaprootAssetsClient configured for the test connection.
async fn connect_rpc(
    dst_uri: String,
    macaroon_path: impl AsRef<Path>,
    server_ca_cert_path: impl AsRef<Path>,
    expected_server_domain: String,
) -> Result<RpcClient> {
    ensure_crypto_default_provider();

    // Load the CA certificate
    let pem = fs::read_to_string(server_ca_cert_path)?;
    let ca = Certificate::from_pem(pem);

    // Create TLS configuration
    let tls_config = ClientTlsConfig::new()
        .ca_certificate(ca)
        .domain_name(expected_server_domain);

    // Read the macaroon file
    let macaroon = fs::read(macaroon_path)?;
    let interceptor = MacaroonInterceptor::new(macaroon);

    let mut endpoint: Endpoint = dst_uri.try_into()?;
    endpoint = endpoint.tls_config(tls_config)?;

    let channel = endpoint.connect().await?;

    Ok(TaprootAssetsClient::with_interceptor(channel, interceptor))
}

static INIT_CRYPTO: std::sync::Once = std::sync::Once::new();

// Ensures the default crypto provider is installed for TLS.
fn ensure_crypto_default_provider() {
    INIT_CRYPTO.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install provider");
    });
}

/// Interceptor to add macaroon to each gRPC request.
#[derive(Clone)]
pub struct MacaroonInterceptor {
    macaroon_hex: MetadataValue<tonic::metadata::Ascii>,
}

impl MacaroonInterceptor {
    fn new(bytes: Vec<u8>) -> Self {
        let macaroon_hex = MetadataValue::try_from(hex::encode(bytes)).expect("hex is valid ASCII");
        Self { macaroon_hex }
    }
}

impl Interceptor for MacaroonInterceptor {
    fn call(&mut self, mut req: Request<()>) -> std::result::Result<Request<()>, Status> {
        req.metadata_mut().insert(
            MetadataKey::from_static("macaroon"),
            self.macaroon_hex.clone(),
        );

        Ok(req)
    }
}
