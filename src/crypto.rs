use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use rcgen::CertificateParams;
use sha2::Sha256;
use std::path::Path;

use crate::{HyphaError, Result};

type HmacSha256 = Hmac<Sha256>;

/// A node's Ed25519 keypair — the foundation of all Hypha authentication.
/// Not an identity; just a device key.
#[derive(Debug)]
pub struct NodeKeypair {
    signing_key: SigningKey,
}

impl NodeKeypair {
    /// Generate a new random keypair.
    pub fn generate() -> Self {
        Self {
            signing_key: SigningKey::generate(&mut OsRng),
        }
    }

    /// Load a keypair from a file, or generate and save one if it doesn't exist.
    pub fn load_or_generate(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            let key_bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| HyphaError::Crypto("invalid key file length".into()))?;
            Ok(Self {
                signing_key: SigningKey::from_bytes(&key_bytes),
            })
        } else {
            let kp = Self::generate();
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, kp.signing_key.to_bytes())?;
            Ok(kp)
        }
    }

    /// Get the public key bytes (32 bytes).
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signing_key.verifying_key().to_bytes()
    }

    /// Get the verifying (public) key.
    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a message.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    /// Get a reference to the signing key (needed for TLS cert generation).
    pub fn signing_key(&self) -> &SigningKey {
        &self.signing_key
    }

    /// Generate a self-signed TLS certificate from this keypair.
    /// The cert exists only because QUIC requires one structurally.
    pub fn generate_tls_cert(&self) -> Result<(rustls::pki_types::CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>)> {
        // Generate a separate rcgen keypair for the TLS certificate.
        // We can't easily inject our Ed25519 key into rcgen 0.13's API,
        // so we generate a fresh keypair for TLS. The Hypha protocol layer
        // handles identity verification via the handshake, not the TLS cert.
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| HyphaError::Crypto(format!("failed to generate TLS keypair: {e}")))?;

        let params = CertificateParams::new(vec!["hypha.local".into()])
            .map_err(|e| HyphaError::Crypto(format!("failed to create cert params: {e}")))?;

        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| HyphaError::Crypto(format!("failed to self-sign cert: {e}")))?;

        let cert_der = cert.der().clone();
        let key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()),
        );

        Ok((cert_der, key_der))
    }
}

/// Generate a random 32-byte nonce for challenge-response.
pub fn generate_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    rand::Rng::fill(&mut OsRng, &mut nonce);
    nonce
}

/// Compute HMAC-SHA256(nonce, secret).
pub fn compute_hmac(nonce: &[u8; 32], secret: &[u8; 32]) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(nonce);
    let result = mac.finalize();
    let bytes: [u8; 32] = result.into_bytes().into();
    bytes
}

/// Verify an HMAC-SHA256 value (constant-time comparison).
pub fn verify_hmac(nonce: &[u8; 32], secret: &[u8; 32], expected: &[u8; 32]) -> bool {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key size");
    mac.update(nonce);
    mac.verify_slice(expected).is_ok()
}

/// Verify an Ed25519 signature.
pub fn verify_signature(pubkey: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> Result<()> {
    let verifying_key = VerifyingKey::from_bytes(pubkey)
        .map_err(|e| HyphaError::Crypto(format!("invalid public key: {e}")))?;
    let sig = Signature::from_bytes(signature);
    verifying_key
        .verify(message, &sig)
        .map_err(|e| HyphaError::Crypto(format!("signature verification failed: {e}")))?;
    Ok(())
}

/// Build the message that gets signed during handshake: nonce ‖ tls_exporter.
pub fn build_signed_payload(nonce: &[u8; 32], tls_exporter: &[u8; 32]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(64);
    payload.extend_from_slice(nonce);
    payload.extend_from_slice(tls_exporter);
    payload
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_keypair_generate_and_sign_verify() {
        let kp = NodeKeypair::generate();
        let message = b"hello hypha";
        let sig = kp.sign(message);
        assert!(verify_signature(&kp.public_key_bytes(), message, &sig).is_ok());
    }

    #[test]
    fn test_keypair_bad_signature_fails() {
        let kp = NodeKeypair::generate();
        let other = NodeKeypair::generate();
        let message = b"hello hypha";
        let sig = kp.sign(message);
        assert!(verify_signature(&other.public_key_bytes(), message, &sig).is_err());
    }

    #[test]
    fn test_keypair_persistence() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("key");

        let kp1 = NodeKeypair::load_or_generate(&path).unwrap();
        let pk1 = kp1.public_key_bytes();

        let kp2 = NodeKeypair::load_or_generate(&path).unwrap();
        let pk2 = kp2.public_key_bytes();

        assert_eq!(pk1, pk2);
    }

    #[test]
    fn test_hmac_roundtrip() {
        let nonce = generate_nonce();
        let secret: [u8; 32] = rand::random();
        let hmac = compute_hmac(&nonce, &secret);
        assert!(verify_hmac(&nonce, &secret, &hmac));
    }

    #[test]
    fn test_hmac_wrong_secret_fails() {
        let nonce = generate_nonce();
        let secret: [u8; 32] = rand::random();
        let wrong_secret: [u8; 32] = rand::random();
        let hmac = compute_hmac(&nonce, &secret);
        assert!(!verify_hmac(&nonce, &wrong_secret, &hmac));
    }

    #[test]
    fn test_build_signed_payload() {
        let nonce = [1u8; 32];
        let tls_exp = [2u8; 32];
        let payload = build_signed_payload(&nonce, &tls_exp);
        assert_eq!(payload.len(), 64);
        assert_eq!(&payload[..32], &[1u8; 32]);
        assert_eq!(&payload[32..], &[2u8; 32]);
    }

    #[test]
    fn test_tls_cert_generation() {
        let kp = NodeKeypair::generate();
        let result = kp.generate_tls_cert();
        assert!(result.is_ok());
    }
}
