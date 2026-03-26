use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::{HyphaError, Result};

/// A capability token that grants specific permissions to a peer.
/// Created by the issuer, given to a peer out-of-band.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityToken {
    /// Random unique identifier (16 bytes), used for revocation and lookup.
    #[serde(with = "serde_bytes")]
    pub token_id: Vec<u8>,

    /// Secret used in HMAC proof-of-possession (32 bytes). Never sent over wire.
    #[serde(with = "serde_bytes")]
    pub token_secret: Vec<u8>,

    /// What the holder can do (e.g., "search", "seed").
    pub scopes: Vec<String>,

    /// Ed25519 public key of the issuer (32 bytes).
    #[serde(with = "serde_bytes")]
    pub issuer_pubkey: Vec<u8>,

    /// How to reach the issuer (IP:port, DNS name, etc.).
    pub connection_hints: Vec<String>,

    /// How many peers can pin this token (default: 1).
    pub max_claims: u32,

    /// Unix timestamp after which the token cannot be claimed.
    pub expires_at: Option<u64>,
}

/// Configuration for creating a new invite.
pub struct InviteConfig {
    pub scopes: Vec<String>,
    pub max_claims: u32,
    pub expires_in: Option<Duration>,
    pub connection_hints: Vec<String>,
}

impl CapabilityToken {
    /// Create a new capability token.
    pub fn new(issuer_pubkey: [u8; 32], config: InviteConfig) -> Self {
        let mut token_id = vec![0u8; 16];
        rand::Rng::fill(&mut OsRng, token_id.as_mut_slice());

        let mut token_secret = vec![0u8; 32];
        rand::Rng::fill(&mut OsRng, token_secret.as_mut_slice());

        let expires_at = config.expires_in.map(|d| {
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + d.as_secs()
        });

        Self {
            token_id,
            token_secret,
            scopes: config.scopes,
            issuer_pubkey: issuer_pubkey.to_vec(),
            connection_hints: config.connection_hints,
            max_claims: config.max_claims,
            expires_at,
        }
    }

    /// Serialize to a hypha:// invite link.
    pub fn to_link(&self) -> Result<String> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf)
            .map_err(|e| HyphaError::Serialization(format!("token encode: {e}")))?;
        Ok(format!("hypha://{}", URL_SAFE_NO_PAD.encode(&buf)))
    }

    /// Parse a hypha:// invite link back to a token.
    pub fn from_link(link: &str) -> Result<Self> {
        let encoded = link
            .strip_prefix("hypha://")
            .ok_or_else(|| HyphaError::Serialization("invalid invite link prefix".into()))?;
        let bytes = URL_SAFE_NO_PAD
            .decode(encoded)
            .map_err(|e| HyphaError::Serialization(format!("base64 decode: {e}")))?;
        let token: Self = ciborium::from_reader(bytes.as_slice())
            .map_err(|e| HyphaError::Serialization(format!("token decode: {e}")))?;
        Ok(token)
    }

    /// Check if this token has expired.
    pub fn is_expired(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now > expires_at
        } else {
            false
        }
    }

    /// Get the token_id as a fixed-size array.
    pub fn token_id_array(&self) -> Result<[u8; 16]> {
        self.token_id
            .as_slice()
            .try_into()
            .map_err(|_| HyphaError::Crypto("invalid token_id length".into()))
    }

    /// Get the token_secret as a fixed-size array.
    pub fn token_secret_array(&self) -> Result<[u8; 32]> {
        self.token_secret
            .as_slice()
            .try_into()
            .map_err(|_| HyphaError::Crypto("invalid token_secret length".into()))
    }

    /// Get the issuer pubkey as a fixed-size array.
    pub fn issuer_pubkey_array(&self) -> Result<[u8; 32]> {
        self.issuer_pubkey
            .as_slice()
            .try_into()
            .map_err(|_| HyphaError::Crypto("invalid issuer_pubkey length".into()))
    }
}

/// Hex-encode a token_id for display purposes.
pub fn token_id_hex(token_id: &[u8]) -> String {
    token_id
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_token() -> CapabilityToken {
        CapabilityToken::new(
            [42u8; 32],
            InviteConfig {
                scopes: vec!["search".into(), "stats".into()],
                max_claims: 1,
                expires_in: Some(Duration::from_secs(3600)),
                connection_hints: vec!["192.168.1.50:4433".into()],
            },
        )
    }

    #[test]
    fn test_token_creation() {
        let token = make_test_token();
        assert_eq!(token.token_id.len(), 16);
        assert_eq!(token.token_secret.len(), 32);
        assert_eq!(token.scopes, vec!["search", "stats"]);
        assert_eq!(token.issuer_pubkey, vec![42u8; 32]);
        assert_eq!(token.max_claims, 1);
        assert!(token.expires_at.is_some());
    }

    #[test]
    fn test_link_roundtrip() {
        let token = make_test_token();
        let link = token.to_link().unwrap();
        assert!(link.starts_with("hypha://"));

        let parsed = CapabilityToken::from_link(&link).unwrap();
        assert_eq!(token.token_id, parsed.token_id);
        assert_eq!(token.token_secret, parsed.token_secret);
        assert_eq!(token.scopes, parsed.scopes);
        assert_eq!(token.issuer_pubkey, parsed.issuer_pubkey);
        assert_eq!(token.connection_hints, parsed.connection_hints);
        assert_eq!(token.max_claims, parsed.max_claims);
        assert_eq!(token.expires_at, parsed.expires_at);
    }

    #[test]
    fn test_invalid_link_prefix() {
        let result = CapabilityToken::from_link("http://not-a-hypha-link");
        assert!(result.is_err());
    }

    #[test]
    fn test_not_expired() {
        let token = make_test_token();
        assert!(!token.is_expired());
    }

    #[test]
    fn test_expired() {
        let mut token = make_test_token();
        token.expires_at = Some(0); // epoch — definitely expired
        assert!(token.is_expired());
    }

    #[test]
    fn test_no_expiry() {
        let token = CapabilityToken::new(
            [42u8; 32],
            InviteConfig {
                scopes: vec!["search".into()],
                max_claims: 1,
                expires_in: None,
                connection_hints: vec![],
            },
        );
        assert!(token.expires_at.is_none());
        assert!(!token.is_expired());
    }

    #[test]
    fn test_token_id_hex() {
        assert_eq!(token_id_hex(&[0xde, 0xad, 0xbe, 0xef]), "deadbeef");
    }
}
