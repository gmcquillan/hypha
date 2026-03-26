pub mod capability;
pub mod crypto;
pub mod discovery;
pub mod exchange;
pub mod handshake;
pub mod messages;
pub mod node;
pub mod store;
pub mod transport;

pub use node::HyphaNode;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum HyphaError {
    // Connection errors
    #[error("peer unreachable (last seen: {last_seen:?})")]
    PeerUnreachable { last_seen: Option<u64> },

    #[error("handshake failed: {detail}")]
    HandshakeFailed { detail: String },

    // Auth errors
    #[error("rejected: {reason}")]
    Rejected { reason: String },

    #[error("forbidden: scope '{scope}' not granted")]
    Forbidden { scope: String },

    #[error("invite expired")]
    InviteExpired,

    #[error("invite fully claimed")]
    InviteFullyClaimed,

    // Application errors
    #[error("remote error (status {status}): {message}")]
    RemoteError { status: u8, message: String },

    #[error("bad request: {0}")]
    BadRequest(String),

    #[error("internal error: {0}")]
    Internal(String),

    // Transport errors
    #[error("connection lost")]
    ConnectionLost,

    #[error("timeout")]
    Timeout,

    // Infrastructure errors
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("quinn connection error: {0}")]
    Connection(#[from] quinn::ConnectionError),
}

pub type Result<T> = std::result::Result<T, HyphaError>;
