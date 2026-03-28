use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use tracing::{info, warn};

use crate::capability::{CapabilityToken, InviteConfig};
use crate::crypto::NodeKeypair;
use crate::exchange::{Exchange, HandlerFn};
use crate::stream::{self, StreamManager, SubscribeHandlerFn, SubscriptionStream, SubscriptionReceiver};
use crate::handshake;
use crate::messages::{self, Message};
use crate::store::PeerStore;
use crate::transport;
use crate::{HyphaError, Result};

/// Configuration for a Hypha node.
pub struct NodeConfig {
    /// Directory for storing keys and database.
    pub data_dir: PathBuf,
    /// When the node's key was created (unix timestamp).
    pub key_created_at: u64,
}

/// A handle to a connected, authenticated peer.
pub struct Peer {
    pub pubkey: [u8; 32],
    pub scopes: Vec<String>,
    pub token_id: Vec<u8>,
    connection: quinn::Connection,
    exchange: Arc<Exchange>,
    stream_mgr: Arc<StreamManager>,
}

impl Peer {
    /// Send a request to this peer and wait for a response.
    pub async fn request(&self, scope: &str, body: &[u8]) -> Result<Vec<u8>> {
        // Allocate request ID
        let (req_id, _rx) = self.exchange.prepare_request().await;

        // Open a bidirectional stream
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|_| HyphaError::ConnectionLost)?;

        // Send request
        let msg = Message::Request(messages::Request {
            req_id,
            scope: scope.to_string(),
            body: body.to_vec(),
        });
        messages::write_message(&mut send, &msg).await?;

        // Read response
        let response = messages::read_message(&mut recv).await?;
        match response {
            Message::Response(r) => {
                if r.status == messages::status::OK {
                    Ok(r.body)
                } else if r.status == messages::status::FORBIDDEN {
                    Err(HyphaError::Forbidden {
                        scope: scope.to_string(),
                    })
                } else {
                    Err(HyphaError::RemoteError {
                        status: r.status,
                        message: String::from_utf8_lossy(&r.body).into(),
                    })
                }
            }
            _ => Err(HyphaError::HandshakeFailed {
                detail: "unexpected response type".into(),
            }),
        }
    }

    /// Open a subscription to this peer for the given scope.
    pub async fn subscribe(&self, scope: &str, body: &[u8]) -> Result<SubscriptionStream> {
        let sub_id = self.stream_mgr.next_sub_id().await;

        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|_| HyphaError::ConnectionLost)?;

        let msg = Message::Subscribe(messages::Subscribe {
            sub_id,
            scope: scope.to_string(),
            body: body.to_vec(),
        });
        messages::write_message(&mut send, &msg).await?;

        let response = messages::read_message(&mut recv).await?;
        match response {
            Message::Response(r) => {
                if r.status == messages::status::OK {
                    Ok(SubscriptionStream::new(sub_id, send, recv))
                } else if r.status == messages::status::FORBIDDEN {
                    Err(HyphaError::Forbidden {
                        scope: scope.to_string(),
                    })
                } else {
                    Err(HyphaError::RemoteError {
                        status: r.status,
                        message: String::from_utf8_lossy(&r.body).into(),
                    })
                }
            }
            _ => Err(HyphaError::HandshakeFailed {
                detail: "unexpected response to subscribe".into(),
            }),
        }
    }
}

/// A Hypha node — the main entry point for the library.
pub struct HyphaNode {
    keypair: Arc<NodeKeypair>,
    store: Arc<PeerStore>,
    exchange: Arc<Exchange>,
    stream_mgr: Arc<StreamManager>,
    key_created_at: u64,
    endpoint: Option<quinn::Endpoint>,
}

impl HyphaNode {
    /// Open or create a node, loading or generating the keypair.
    pub fn open(config: NodeConfig) -> Result<Self> {
        let key_path = config.data_dir.join("node.key");
        let db_path = config.data_dir.join("hypha.db");

        std::fs::create_dir_all(&config.data_dir)?;
        let keypair = NodeKeypair::load_or_generate(&key_path)?;
        let store = PeerStore::open(&db_path)?;

        info!(
            pubkey = hex::encode(keypair.public_key_bytes()),
            "node initialized"
        );

        Ok(Self {
            keypair: Arc::new(keypair),
            store: Arc::new(store),
            exchange: Arc::new(Exchange::new()),
            stream_mgr: Arc::new(StreamManager::new()),
            key_created_at: config.key_created_at,
            endpoint: None,
        })
    }

    /// Get this node's public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key_bytes()
    }

    /// Start listening for incoming connections.
    /// Returns the actual bound address (useful when port 0 is specified).
    pub async fn listen(&mut self, addr: SocketAddr) -> Result<SocketAddr> {
        let endpoint = transport::make_server_endpoint(&self.keypair, addr)?;
        let actual_addr = endpoint.local_addr()?;
        info!(requested = %addr, actual = %actual_addr, "listening for connections");
        self.endpoint = Some(endpoint.clone());

        let keypair = self.keypair.clone();
        let store = self.store.clone();
        let exchange = self.exchange.clone();
        let stream_mgr = self.stream_mgr.clone();
        let key_created_at = self.key_created_at;

        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let keypair = keypair.clone();
                let store = store.clone();
                let exchange = exchange.clone();
                let stream_mgr = stream_mgr.clone();

                tokio::spawn(async move {
                    match incoming.await {
                        Ok(conn) => {
                            if let Err(e) = handle_connection(
                                conn,
                                &keypair,
                                &store,
                                &exchange,
                                stream_mgr,
                                key_created_at,
                            )
                            .await
                            {
                                warn!("connection handler error: {e}");
                            }
                        }
                        Err(e) => {
                            warn!("failed to accept connection: {e}");
                        }
                    }
                });
            }
        });

        Ok(actual_addr)
    }

    /// Create a new invite token.
    pub fn create_invite(&self, config: InviteConfig) -> Result<CapabilityToken> {
        let token = CapabilityToken::new(self.keypair.public_key_bytes(), config);

        // Store the token
        self.store.insert_token(
            &token.token_id,
            &token.token_secret,
            &token.scopes,
            token.max_claims,
            token.expires_at,
        )?;

        Ok(token)
    }

    /// Claim an invite link and establish a connection.
    pub async fn claim_invite(&self, link: &str) -> Result<Peer> {
        let token = CapabilityToken::from_link(link)?;

        if token.is_expired() {
            return Err(HyphaError::InviteExpired);
        }

        // Try connection hints in order
        for hint in &token.connection_hints {
            let addr: SocketAddr = hint
                .parse()
                .map_err(|e| HyphaError::Internal(format!("invalid address hint: {e}")))?;

            match self.connect_and_claim(addr, &token).await {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    warn!(addr = %hint, "connection hint failed: {e}");
                    continue;
                }
            }
        }

        Err(HyphaError::PeerUnreachable { last_seen: None })
    }

    async fn connect_and_claim(&self, addr: SocketAddr, token: &CapabilityToken) -> Result<Peer> {
        // Create client endpoint — bind to same address family as target
        let bind_addr: SocketAddr = if addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let endpoint = transport::make_client_endpoint(bind_addr)?;

        info!(%addr, "connecting to peer");
        let connecting = endpoint
            .connect(addr, "hypha.local")
            .map_err(|e| HyphaError::Internal(format!("connect: {e}")))?;

        let connection = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            connecting,
        )
        .await
        .map_err(|_| {
            warn!(%addr, "connection timed out");
            HyphaError::Timeout
        })?
        .map_err(|e| {
            warn!(%addr, error = %e, "connection failed");
            HyphaError::Internal(format!("connection: {e}"))
        })?;

        info!(%addr, "QUIC connection established, starting handshake");

        // Open a bidirectional stream for the handshake
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|_| HyphaError::ConnectionLost)?;

        // Send handshake initiation byte to trigger server's accept_bi
        // (QUIC may not signal the stream to the peer until data is written)
        send.write_all(&[0x00])
            .await
            .map_err(|e| HyphaError::Internal(format!("handshake init write: {e}")))?;

        // Verify the server's TLS cert pubkey matches the invite's issuer_pubkey.
        // This prevents MITM — we only proceed if we're talking to the right node.
        let expected_pubkey = token.issuer_pubkey_array()?;
        let server_cert = transport::extract_peer_cert(&connection)?;
        let server_pubkey = transport::extract_pubkey_from_cert(&server_cert)?;
        if server_pubkey != expected_pubkey {
            return Err(HyphaError::HandshakeFailed {
                detail: format!(
                    "server cert pubkey mismatch: expected {}, got {}",
                    hex::encode(expected_pubkey),
                    hex::encode(server_pubkey),
                ),
            });
        }

        // Extract real TLS exporter for channel binding
        let tls_exporter = transport::extract_tls_exporter(&connection)?;

        let token_secret = token.token_secret_array()?;
        let welcome = handshake::client_claim_handshake(
            &mut send,
            &mut recv,
            &self.keypair,
            &token.token_id,
            &token_secret,
            &tls_exporter,
        )
        .await?;

        // Store the peer (no token_id on the claiming side — the token
        // lives in the issuer's store, not ours)
        let issuer_pubkey = token.issuer_pubkey_array()?;
        self.store.upsert_peer(
            &issuer_pubkey,
            &addr.to_string(),
            None,
        )?;

        info!(
            peer = hex::encode(issuer_pubkey),
            scopes = ?welcome.capabilities,
            "claimed invite successfully"
        );

        Ok(Peer {
            pubkey: issuer_pubkey,
            scopes: welcome.capabilities,
            token_id: token.token_id.clone(),
            connection,
            exchange: self.exchange.clone(),
            stream_mgr: self.stream_mgr.clone(),
        })
    }

    /// Revoke a previously issued token.
    pub fn revoke(&self, token_id: &[u8]) -> Result<()> {
        self.store.revoke_token(token_id)?;
        info!(token = hex::encode(token_id), "token revoked");
        Ok(())
    }

    /// Register a request handler for a scope.
    pub async fn on_request<F, Fut>(&self, scope: &str, handler: F)
    where
        F: Fn(messages::Request) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<Vec<u8>>> + Send + 'static,
    {
        let handler: HandlerFn = Arc::new(move |req| Box::pin(handler(req)));
        self.exchange.register_handler(scope, handler).await;
    }

    /// Register a subscribe handler for a scope.
    pub async fn on_subscribe<F, Fut>(&self, scope: &str, handler: F)
    where
        F: Fn(stream::Subscription) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<SubscriptionReceiver>> + Send + 'static,
    {
        let handler: SubscribeHandlerFn = Arc::new(move |sub| Box::pin(handler(sub)));
        self.stream_mgr.register_handler(scope, handler).await;
    }

    /// Get a reference to the peer store.
    pub fn store(&self) -> &PeerStore {
        &self.store
    }
}

/// Handle an accepted connection — run handshake, then process messages.
async fn handle_connection(
    conn: quinn::Connection,
    keypair: &NodeKeypair,
    store: &PeerStore,
    exchange: &Exchange,
    stream_mgr: Arc<StreamManager>,
    key_created_at: u64,
) -> Result<()> {
    let remote = conn.remote_address();
    info!(%remote, "accepted connection");

    // Accept the first bidirectional stream for the handshake
    info!("waiting to accept bi stream for handshake");
    let (mut send, mut recv) = conn
        .accept_bi()
        .await
        .map_err(|_| HyphaError::ConnectionLost)?;
    info!("accepted bi stream, reading init byte");

    // Read the handshake initiation byte
    let mut init_byte = [0u8; 1];
    recv.read_exact(&mut init_byte)
        .await
        .map_err(|e| HyphaError::HandshakeFailed {
            detail: format!("failed to read init byte: {e}"),
        })?;
    info!("starting handshake");

    // Extract real TLS exporter for channel binding
    let tls_exporter = transport::extract_tls_exporter(&conn)?;

    let peer = handshake::server_handshake(
        &mut send,
        &mut recv,
        keypair,
        store,
        &tls_exporter,
        key_created_at,
    )
    .await?;

    info!(
        peer = hex::encode(peer.pubkey),
        scopes = ?peer.scopes,
        "peer authenticated"
    );

    // Update peer's last-known address
    store.upsert_peer(
        &peer.pubkey,
        &remote.to_string(),
        Some(&peer.token_id),
    )?;

    // Message processing loop — accept streams and handle requests
    loop {
        match conn.accept_bi().await {
            Ok((send, mut recv)) => {
                let scopes = peer.scopes.clone();
                match messages::read_message(&mut recv).await {
                    Ok(Message::Request(req)) => {
                        let mut send = send;
                        exchange.handle_request(req, &scopes, &mut send).await?;
                    }
                    Ok(Message::Subscribe(sub_msg)) => {
                        let stream_mgr = stream_mgr.clone();
                        tokio::spawn(async move {
                            if let Err(e) = stream::handle_subscribe(
                                &stream_mgr,
                                sub_msg,
                                &scopes,
                                send,
                                recv,
                            )
                            .await
                            {
                                warn!("subscribe handler error: {e}");
                            }
                        });
                    }
                    Ok(Message::Whereis(w)) => {
                        let mut send = send;
                        if let Some(ls) =
                            crate::discovery::handle_whereis(store, &w)?
                        {
                            let msg = Message::LastSeen(ls);
                            messages::write_message(&mut send, &msg).await?;
                        }
                    }
                    Ok(Message::AddrUpdate(au)) => {
                        crate::discovery::handle_addr_update(store, &peer.pubkey, &au)?;
                    }
                    Ok(_) => {
                        warn!("unexpected message type in session");
                    }
                    Err(_) => {
                        // Stream closed or error — connection may still be alive
                        break;
                    }
                }
            }
            Err(_) => {
                // Connection closed
                info!(peer = hex::encode(peer.pubkey), "peer disconnected");
                break;
            }
        }
    }

    Ok(())
}

// Hex encoding helper (small, no extra dependency needed beyond what we have)
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }
}
