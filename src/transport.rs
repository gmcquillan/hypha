use std::net::SocketAddr;
use std::sync::Arc;

use quinn::{ClientConfig, Endpoint, ServerConfig};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::crypto::NodeKeypair;
use crate::{HyphaError, Result};

/// Create a QUIC server endpoint with a self-signed cert from the node keypair.
pub fn make_server_endpoint(
    keypair: &NodeKeypair,
    bind_addr: SocketAddr,
) -> Result<Endpoint> {
    let (cert_der, key_der) = keypair.generate_tls_cert()?;
    let server_config = configure_server(cert_der.clone(), key_der)?;
    let client_config = configure_client();

    let mut endpoint = Endpoint::server(server_config, bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

/// Create a QUIC client-only endpoint.
pub fn make_client_endpoint(bind_addr: SocketAddr) -> Result<Endpoint> {
    let client_config = configure_client();
    let mut endpoint = Endpoint::client(bind_addr)?;
    endpoint.set_default_client_config(client_config);
    Ok(endpoint)
}

fn configure_server(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<ServerConfig> {
    let server_crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|e| HyphaError::Crypto(format!("server TLS config: {e}")))?;

    Ok(ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| HyphaError::Crypto(format!("QUIC server config: {e}")))?,
    )))
}

fn configure_client() -> ClientConfig {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();

    ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
            .expect("valid QUIC client config"),
    ))
}

/// Accept any server certificate — verification happens at the Hypha protocol layer
/// (we verify the pubkey in the cert matches the expected pubkey from the invite/pin).
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // We verify identity at the Hypha handshake layer, not TLS layer.
        // The self-signed cert's pubkey is checked against the expected key
        // from the invite token or TOFU pin.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

/// Extract the TLS exporter value for channel binding (RFC 5705).
/// Both peers calling this with the same label get the same value,
/// binding the Hypha handshake to this specific TLS session.
pub fn extract_tls_exporter(conn: &quinn::Connection) -> Result<[u8; 32]> {
    let mut output = [0u8; 32];
    conn.export_keying_material(&mut output, b"hypha-channel-binding", b"")
        .map_err(|e| HyphaError::Crypto(format!("TLS exporter failed: {e:?}")))?;
    Ok(output)
}

/// Extract the peer's TLS certificate from a quinn connection.
/// Returns the first certificate in the peer's chain (the leaf cert).
pub fn extract_peer_cert(conn: &quinn::Connection) -> Result<rustls::pki_types::CertificateDer<'static>> {
    let peer_identity = conn
        .peer_identity()
        .ok_or_else(|| HyphaError::Crypto("no peer identity available".into()))?;

    let certs = peer_identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .map_err(|_| HyphaError::Crypto("unexpected peer identity type".into()))?;

    certs
        .into_iter()
        .next()
        .ok_or_else(|| HyphaError::Crypto("peer certificate chain is empty".into()))
}

/// Extract the Ed25519 public key from a peer's TLS certificate.
/// Returns None if the cert doesn't use Ed25519.
pub fn extract_pubkey_from_cert(cert_der: &CertificateDer<'_>) -> Result<[u8; 32]> {
    let (_remainder, cert) = x509_parser::parse_x509_certificate(cert_der.as_ref())
        .map_err(|e| HyphaError::Crypto(format!("failed to parse certificate: {e}")))?;

    let pubkey_data = &cert.public_key().subject_public_key.data;
    if pubkey_data.len() == 32 {
        let mut key = [0u8; 32];
        key.copy_from_slice(pubkey_data);
        Ok(key)
    } else {
        Err(HyphaError::Crypto(format!(
            "unexpected public key length: {} (expected 32)",
            pubkey_data.len()
        )))
    }
}
