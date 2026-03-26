use crate::crypto::{self, NodeKeypair};
use crate::messages::{self, Challenge, ClaimProof, Message, PinnedProof, Rejected, Welcome};
use crate::store::PeerStore;
use crate::{HyphaError, Result};

use std::time::{SystemTime, UNIX_EPOCH};
use tracing::debug;

/// Run the server (issuer) side of the handshake.
/// Sends Challenge, receives proof, validates, returns Welcome or Rejected.
pub async fn server_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    keypair: &NodeKeypair,
    store: &PeerStore,
    tls_exporter: &[u8; 32],
    key_created_at: u64,
) -> Result<AuthenticatedPeer> {
    // 1. Send challenge
    debug!("server: sending challenge");
    let nonce = crypto::generate_nonce();
    let challenge = Message::Challenge(Challenge {
        nonce: nonce.to_vec(),
    });
    messages::write_message(send, &challenge).await?;
    debug!("server: challenge sent, waiting for proof");

    // 2. Receive proof
    let proof = messages::read_message(recv).await?;
    debug!("server: received proof");

    match proof {
        Message::ClaimProof(claim) => {
            handle_claim_proof(send, &nonce, &claim, keypair, store, tls_exporter, key_created_at)
                .await
        }
        Message::PinnedProof(pinned) => {
            handle_pinned_proof(send, &nonce, &pinned, keypair, store, tls_exporter, key_created_at)
                .await
        }
        _ => {
            let reject = Message::Rejected(Rejected {
                reason: "unexpected message type during handshake".into(),
            });
            messages::write_message(send, &reject).await?;
            Err(HyphaError::HandshakeFailed {
                detail: "unexpected message type".into(),
            })
        }
    }
}

async fn handle_claim_proof(
    send: &mut quinn::SendStream,
    nonce: &[u8; 32],
    claim: &ClaimProof,
    _keypair: &NodeKeypair,
    store: &PeerStore,
    tls_exporter: &[u8; 32],
    key_created_at: u64,
) -> Result<AuthenticatedPeer> {
    // Look up token
    let token_id: [u8; 16] = claim
        .token_id
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid token_id length".into(),
        })?;

    let token = store.get_token(&token_id)?.ok_or_else(|| {
        HyphaError::HandshakeFailed {
            detail: "unknown token".into(),
        }
    })?;

    // Check revocation
    if token.revoked {
        let reject = Message::Rejected(Rejected {
            reason: "token revoked".into(),
        });
        messages::write_message(send, &reject).await?;
        return Err(HyphaError::Rejected {
            reason: "token revoked".into(),
        });
    }

    // Check expiry
    if let Some(expires_at) = token.expires_at {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > expires_at {
            let reject = Message::Rejected(Rejected {
                reason: "token expired".into(),
            });
            messages::write_message(send, &reject).await?;
            return Err(HyphaError::InviteExpired);
        }
    }

    // Check max claims
    if token.claims_count >= token.max_claims {
        let reject = Message::Rejected(Rejected {
            reason: "token fully claimed".into(),
        });
        messages::write_message(send, &reject).await?;
        return Err(HyphaError::InviteFullyClaimed);
    }

    // Verify HMAC (proves token possession)
    let secret: [u8; 32] = token
        .token_secret
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::Crypto("invalid secret length".into()))?;

    let hmac: [u8; 32] = claim
        .hmac
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid hmac length".into(),
        })?;

    if !crypto::verify_hmac(nonce, &secret, &hmac) {
        let reject = Message::Rejected(Rejected {
            reason: "invalid token proof".into(),
        });
        messages::write_message(send, &reject).await?;
        return Err(HyphaError::HandshakeFailed {
            detail: "HMAC verification failed".into(),
        });
    }

    // Verify signature (proves key ownership + channel binding)
    let peer_pubkey: [u8; 32] = claim
        .pubkey
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid pubkey length".into(),
        })?;

    let sig: [u8; 64] = claim
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid signature length".into(),
        })?;

    let signed_payload = crypto::build_signed_payload(nonce, tls_exporter);
    crypto::verify_signature(&peer_pubkey, &signed_payload, &sig).map_err(|_| {
        HyphaError::HandshakeFailed {
            detail: "signature verification failed".into(),
        }
    })?;

    // Pin the peer's pubkey to this token
    store.pin_claim(&token_id, &peer_pubkey)?;

    // Send Welcome
    let welcome = Message::Welcome(Welcome {
        capabilities: token.scopes.clone(),
        key_created_at,
    });
    messages::write_message(send, &welcome).await?;

    Ok(AuthenticatedPeer {
        pubkey: peer_pubkey,
        token_id: token_id.to_vec(),
        scopes: token.scopes,
    })
}

async fn handle_pinned_proof(
    send: &mut quinn::SendStream,
    nonce: &[u8; 32],
    pinned: &PinnedProof,
    _keypair: &NodeKeypair,
    store: &PeerStore,
    tls_exporter: &[u8; 32],
    key_created_at: u64,
) -> Result<AuthenticatedPeer> {
    // Look up token
    let token_id: [u8; 16] = pinned
        .token_id
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid token_id length".into(),
        })?;

    let token = store.get_token(&token_id)?.ok_or_else(|| {
        HyphaError::HandshakeFailed {
            detail: "unknown token".into(),
        }
    })?;

    if token.revoked {
        let reject = Message::Rejected(Rejected {
            reason: "token revoked".into(),
        });
        messages::write_message(send, &reject).await?;
        return Err(HyphaError::Rejected {
            reason: "token revoked".into(),
        });
    }

    // We need the peer's pubkey from the TLS connection to verify the pin.
    // For now, we extract it from the signature verification:
    // The caller should provide the peer's cert pubkey. For the PoC, we'll
    // verify the sig against all pinned keys for this token.

    // Get all pinned pubkeys for this token
    let sig: [u8; 64] = pinned
        .sig
        .as_slice()
        .try_into()
        .map_err(|_| HyphaError::HandshakeFailed {
            detail: "invalid signature length".into(),
        })?;

    let signed_payload = crypto::build_signed_payload(nonce, tls_exporter);

    // Try to find which pinned key signed this
    // In practice, we'd get the peer pubkey from TLS cert and just verify directly.
    // For PoC, we check against pinned keys for this token.
    let peer_pubkey = find_signing_peer(store, &token_id, &signed_payload, &sig)?;

    let welcome = Message::Welcome(Welcome {
        capabilities: token.scopes.clone(),
        key_created_at,
    });
    messages::write_message(send, &welcome).await?;

    Ok(AuthenticatedPeer {
        pubkey: peer_pubkey,
        token_id: token_id.to_vec(),
        scopes: token.scopes,
    })
}

/// Find which pinned peer produced this signature.
fn find_signing_peer(
    store: &PeerStore,
    token_id: &[u8; 16],
    message: &[u8],
    sig: &[u8; 64],
) -> Result<[u8; 32]> {
    // Query all pins for this token
    let peers = store.list_peers()?;
    for (pubkey_bytes, _record) in &peers {
        if pubkey_bytes.len() == 32 && store.is_pinned(token_id, pubkey_bytes)? {
            let mut pubkey = [0u8; 32];
            pubkey.copy_from_slice(pubkey_bytes);
            if crypto::verify_signature(&pubkey, message, sig).is_ok() {
                return Ok(pubkey);
            }
        }
    }
    Err(HyphaError::HandshakeFailed {
        detail: "no pinned key matches signature".into(),
    })
}

/// Run the client side of the handshake for a new invite claim.
pub async fn client_claim_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    keypair: &NodeKeypair,
    token_id: &[u8],
    token_secret: &[u8; 32],
    tls_exporter: &[u8; 32],
) -> Result<Welcome> {
    // 1. Receive challenge
    debug!("client: waiting for challenge");
    let challenge = messages::read_message(recv).await?;
    debug!("client: received challenge");
    let nonce: [u8; 32] = match challenge {
        Message::Challenge(c) => c
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| HyphaError::HandshakeFailed {
                detail: "invalid nonce length".into(),
            })?,
        _ => {
            return Err(HyphaError::HandshakeFailed {
                detail: "expected Challenge message".into(),
            })
        }
    };

    // 2. Compute proof
    let hmac = crypto::compute_hmac(&nonce, token_secret);
    let signed_payload = crypto::build_signed_payload(&nonce, tls_exporter);
    let sig = keypair.sign(&signed_payload);

    let claim = Message::ClaimProof(ClaimProof {
        token_id: token_id.to_vec(),
        hmac: hmac.to_vec(),
        pubkey: keypair.public_key_bytes().to_vec(),
        sig: sig.to_vec(),
        tls_binding: tls_exporter.to_vec(),
    });
    debug!("client: sending claim proof");
    messages::write_message(send, &claim).await?;
    debug!("client: claim proof sent, waiting for welcome");

    // 3. Receive Welcome or Rejected
    let response = messages::read_message(recv).await?;
    debug!("client: received response");
    match response {
        Message::Welcome(w) => Ok(w),
        Message::Rejected(r) => Err(HyphaError::Rejected { reason: r.reason }),
        _ => Err(HyphaError::HandshakeFailed {
            detail: "unexpected response to claim".into(),
        }),
    }
}

/// Run the client side of the handshake for a returning pinned connection.
pub async fn client_pinned_handshake(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    keypair: &NodeKeypair,
    token_id: &[u8],
    tls_exporter: &[u8; 32],
) -> Result<Welcome> {
    // 1. Receive challenge
    let challenge = messages::read_message(recv).await?;
    let nonce: [u8; 32] = match challenge {
        Message::Challenge(c) => c
            .nonce
            .as_slice()
            .try_into()
            .map_err(|_| HyphaError::HandshakeFailed {
                detail: "invalid nonce length".into(),
            })?,
        _ => {
            return Err(HyphaError::HandshakeFailed {
                detail: "expected Challenge message".into(),
            })
        }
    };

    // 2. Send proof
    let signed_payload = crypto::build_signed_payload(&nonce, tls_exporter);
    let sig = keypair.sign(&signed_payload);

    let proof = Message::PinnedProof(PinnedProof {
        token_id: token_id.to_vec(),
        sig: sig.to_vec(),
        tls_binding: tls_exporter.to_vec(),
    });
    messages::write_message(send, &proof).await?;

    // 3. Receive Welcome or Rejected
    let response = messages::read_message(recv).await?;
    match response {
        Message::Welcome(w) => Ok(w),
        Message::Rejected(r) => Err(HyphaError::Rejected { reason: r.reason }),
        _ => Err(HyphaError::HandshakeFailed {
            detail: "unexpected response to pinned proof".into(),
        }),
    }
}

/// Result of a successful handshake.
#[derive(Debug)]
pub struct AuthenticatedPeer {
    pub pubkey: [u8; 32],
    pub token_id: Vec<u8>,
    pub scopes: Vec<String>,
}
