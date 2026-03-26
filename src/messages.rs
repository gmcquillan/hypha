use serde::{Deserialize, Serialize};

use crate::{HyphaError, Result};

/// Message type identifiers on the wire.
pub mod msg_type {
    pub const CHALLENGE: u8 = 0x01;
    pub const CLAIM_PROOF: u8 = 0x02;
    pub const PINNED_PROOF: u8 = 0x03;
    pub const WELCOME: u8 = 0x04;
    pub const REJECTED: u8 = 0x05;
    pub const KEY_ROTATION: u8 = 0x06;
    pub const KEY_ROTATION_ACK: u8 = 0x07;
    pub const WHEREIS: u8 = 0x08;
    pub const LAST_SEEN: u8 = 0x09;
    pub const REQUEST: u8 = 0x0A;
    pub const RESPONSE: u8 = 0x0B;
    pub const ADDR_UPDATE: u8 = 0x0C;
    pub const SUBSCRIBE: u8 = 0x0D;
    pub const EVENT: u8 = 0x0E;
    pub const UNSUBSCRIBE: u8 = 0x0F;
}

/// Response status codes.
pub mod status {
    pub const OK: u8 = 0x00;
    pub const ERROR: u8 = 0x01;
    pub const FORBIDDEN: u8 = 0x02;
    pub const NOT_FOUND: u8 = 0x03;
}

/// All protocol messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Message {
    Challenge(Challenge),
    ClaimProof(ClaimProof),
    PinnedProof(PinnedProof),
    Welcome(Welcome),
    Rejected(Rejected),
    KeyRotation(KeyRotation),
    KeyRotationAck,
    Whereis(Whereis),
    LastSeen(LastSeen),
    Request(Request),
    Response(Response),
    AddrUpdate(AddrUpdate),
    Subscribe(Subscribe),
    Event(Event),
    Unsubscribe(Unsubscribe),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    #[serde(with = "serde_bytes")]
    pub nonce: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClaimProof {
    #[serde(with = "serde_bytes")]
    pub token_id: Vec<u8>, // 16 bytes
    #[serde(with = "serde_bytes")]
    pub hmac: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub pubkey: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>, // 64 bytes
    #[serde(with = "serde_bytes")]
    pub tls_binding: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinnedProof {
    #[serde(with = "serde_bytes")]
    pub token_id: Vec<u8>, // 16 bytes
    #[serde(with = "serde_bytes")]
    pub sig: Vec<u8>, // 64 bytes
    #[serde(with = "serde_bytes")]
    pub tls_binding: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Welcome {
    pub capabilities: Vec<String>,
    pub key_created_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rejected {
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotation {
    #[serde(with = "serde_bytes")]
    pub new_pubkey: Vec<u8>, // 32 bytes
    #[serde(with = "serde_bytes")]
    pub old_sig: Vec<u8>, // 64 bytes
    #[serde(with = "serde_bytes")]
    pub new_sig: Vec<u8>, // 64 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Whereis {
    #[serde(with = "serde_bytes")]
    pub peer_pubkey: Vec<u8>, // 32 bytes
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LastSeen {
    pub addr: String,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub req_id: u32,
    pub scope: String,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub req_id: u32,
    pub status: u8,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddrUpdate {
    pub addrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscribe {
    pub sub_id: u32,
    pub scope: String,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Event {
    pub sub_id: u32,
    #[serde(with = "serde_bytes")]
    pub body: Vec<u8>,
    pub dropped_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Unsubscribe {
    pub sub_id: u32,
}

impl Message {
    /// Get the wire type byte for this message.
    pub fn type_byte(&self) -> u8 {
        match self {
            Message::Challenge(_) => msg_type::CHALLENGE,
            Message::ClaimProof(_) => msg_type::CLAIM_PROOF,
            Message::PinnedProof(_) => msg_type::PINNED_PROOF,
            Message::Welcome(_) => msg_type::WELCOME,
            Message::Rejected(_) => msg_type::REJECTED,
            Message::KeyRotation(_) => msg_type::KEY_ROTATION,
            Message::KeyRotationAck => msg_type::KEY_ROTATION_ACK,
            Message::Whereis(_) => msg_type::WHEREIS,
            Message::LastSeen(_) => msg_type::LAST_SEEN,
            Message::Request(_) => msg_type::REQUEST,
            Message::Response(_) => msg_type::RESPONSE,
            Message::AddrUpdate(_) => msg_type::ADDR_UPDATE,
            Message::Subscribe(_) => msg_type::SUBSCRIBE,
            Message::Event(_) => msg_type::EVENT,
            Message::Unsubscribe(_) => msg_type::UNSUBSCRIBE,
        }
    }
}

/// Encode a message into a length-prefixed frame.
/// Wire format: [length: u32 BE] [type: u8] [cbor payload]
pub fn encode_frame(msg: &Message) -> Result<Vec<u8>> {
    let type_byte = msg.type_byte();

    // Serialize the inner payload to CBOR
    let payload = serialize_payload(msg)?;

    let frame_len = 1 + payload.len(); // type byte + payload
    let mut frame = Vec::with_capacity(4 + frame_len);
    frame.extend_from_slice(&(frame_len as u32).to_be_bytes());
    frame.push(type_byte);
    frame.extend_from_slice(&payload);

    Ok(frame)
}

/// Decode a message from a length-prefixed frame.
/// Returns the message and the number of bytes consumed.
pub fn decode_frame(data: &[u8]) -> Result<(Message, usize)> {
    if data.len() < 5 {
        return Err(HyphaError::Serialization("frame too short".into()));
    }

    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    let total = 4 + len;

    if data.len() < total {
        return Err(HyphaError::Serialization("incomplete frame".into()));
    }

    let type_byte = data[4];
    let payload = &data[5..total];

    let msg = deserialize_payload(type_byte, payload)?;
    Ok((msg, total))
}

fn serialize_payload(msg: &Message) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    match msg {
        Message::Challenge(m) => ciborium::into_writer(m, &mut buf),
        Message::ClaimProof(m) => ciborium::into_writer(m, &mut buf),
        Message::PinnedProof(m) => ciborium::into_writer(m, &mut buf),
        Message::Welcome(m) => ciborium::into_writer(m, &mut buf),
        Message::Rejected(m) => ciborium::into_writer(m, &mut buf),
        Message::KeyRotation(m) => ciborium::into_writer(m, &mut buf),
        Message::KeyRotationAck => ciborium::into_writer(&(), &mut buf),
        Message::Whereis(m) => ciborium::into_writer(m, &mut buf),
        Message::LastSeen(m) => ciborium::into_writer(m, &mut buf),
        Message::Request(m) => ciborium::into_writer(m, &mut buf),
        Message::Response(m) => ciborium::into_writer(m, &mut buf),
        Message::AddrUpdate(m) => ciborium::into_writer(m, &mut buf),
        Message::Subscribe(m) => ciborium::into_writer(m, &mut buf),
        Message::Event(m) => ciborium::into_writer(m, &mut buf),
        Message::Unsubscribe(m) => ciborium::into_writer(m, &mut buf),
    }
    .map_err(|e| HyphaError::Serialization(format!("cbor encode: {e}")))?;
    Ok(buf)
}

fn deserialize_payload(type_byte: u8, payload: &[u8]) -> Result<Message> {
    let msg = match type_byte {
        msg_type::CHALLENGE => {
            Message::Challenge(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::CLAIM_PROOF => {
            Message::ClaimProof(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::PINNED_PROOF => {
            Message::PinnedProof(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::WELCOME => Message::Welcome(ciborium::from_reader(payload).map_err(cbor_err)?),
        msg_type::REJECTED => {
            Message::Rejected(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::KEY_ROTATION => {
            Message::KeyRotation(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::KEY_ROTATION_ACK => {
            let _: () = ciborium::from_reader(payload).map_err(cbor_err)?;
            Message::KeyRotationAck
        }
        msg_type::WHEREIS => Message::Whereis(ciborium::from_reader(payload).map_err(cbor_err)?),
        msg_type::LAST_SEEN => {
            Message::LastSeen(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::REQUEST => Message::Request(ciborium::from_reader(payload).map_err(cbor_err)?),
        msg_type::RESPONSE => {
            Message::Response(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::ADDR_UPDATE => {
            Message::AddrUpdate(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::SUBSCRIBE => {
            Message::Subscribe(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        msg_type::EVENT => Message::Event(ciborium::from_reader(payload).map_err(cbor_err)?),
        msg_type::UNSUBSCRIBE => {
            Message::Unsubscribe(ciborium::from_reader(payload).map_err(cbor_err)?)
        }
        _ => {
            return Err(HyphaError::Serialization(format!(
                "unknown message type: 0x{type_byte:02x}"
            )))
        }
    };
    Ok(msg)
}

fn cbor_err(e: ciborium::de::Error<std::io::Error>) -> HyphaError {
    HyphaError::Serialization(format!("cbor decode: {e}"))
}

/// Read a complete frame from a QUIC recv stream.
pub async fn read_message(recv: &mut quinn::RecvStream) -> Result<Message> {
    // Read length prefix (4 bytes)
    let mut len_buf = [0u8; 4];
    recv.read_exact(&mut len_buf)
        .await
        .map_err(|e| HyphaError::Serialization(format!("failed to read frame length: {e}")))?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len == 0 {
        return Err(HyphaError::Serialization("empty frame".into()));
    }

    // Read type + payload
    let mut frame_buf = vec![0u8; len];
    recv.read_exact(&mut frame_buf)
        .await
        .map_err(|e| HyphaError::Serialization(format!("failed to read frame body: {e}")))?;

    let type_byte = frame_buf[0];
    let payload = &frame_buf[1..];
    deserialize_payload(type_byte, payload)
}

/// Write a message to a QUIC send stream.
pub async fn write_message(send: &mut quinn::SendStream, msg: &Message) -> Result<()> {
    let frame = encode_frame(msg)?;
    send.write_all(&frame)
        .await
        .map_err(|e| HyphaError::Serialization(format!("failed to write frame: {e}")))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(msg: Message) {
        let frame = encode_frame(&msg).unwrap();
        let (decoded, consumed) = decode_frame(&frame).unwrap();
        assert_eq!(consumed, frame.len());
        // Compare type bytes as a basic check
        assert_eq!(msg.type_byte(), decoded.type_byte());
    }

    #[test]
    fn test_challenge_roundtrip() {
        roundtrip(Message::Challenge(Challenge {
            nonce: vec![42u8; 32],
        }));
    }

    #[test]
    fn test_claim_proof_roundtrip() {
        roundtrip(Message::ClaimProof(ClaimProof {
            token_id: vec![1u8; 16],
            hmac: vec![2u8; 32],
            pubkey: vec![3u8; 32],
            sig: vec![4u8; 64],
            tls_binding: vec![5u8; 32],
        }));
    }

    #[test]
    fn test_pinned_proof_roundtrip() {
        roundtrip(Message::PinnedProof(PinnedProof {
            token_id: vec![1u8; 16],
            sig: vec![2u8; 64],
            tls_binding: vec![3u8; 32],
        }));
    }

    #[test]
    fn test_welcome_roundtrip() {
        roundtrip(Message::Welcome(Welcome {
            capabilities: vec!["search".into(), "stats".into()],
            key_created_at: 1711400000,
        }));
    }

    #[test]
    fn test_rejected_roundtrip() {
        roundtrip(Message::Rejected(Rejected {
            reason: "token revoked".into(),
        }));
    }

    #[test]
    fn test_key_rotation_roundtrip() {
        roundtrip(Message::KeyRotation(KeyRotation {
            new_pubkey: vec![1u8; 32],
            old_sig: vec![2u8; 64],
            new_sig: vec![3u8; 64],
        }));
    }

    #[test]
    fn test_key_rotation_ack_roundtrip() {
        roundtrip(Message::KeyRotationAck);
    }

    #[test]
    fn test_whereis_roundtrip() {
        roundtrip(Message::Whereis(Whereis {
            peer_pubkey: vec![1u8; 32],
        }));
    }

    #[test]
    fn test_last_seen_roundtrip() {
        roundtrip(Message::LastSeen(LastSeen {
            addr: "192.168.1.50:4433".into(),
            timestamp: 1711400000,
        }));
    }

    #[test]
    fn test_request_roundtrip() {
        roundtrip(Message::Request(Request {
            req_id: 42,
            scope: "search".into(),
            body: b"rust async patterns".to_vec(),
        }));
    }

    #[test]
    fn test_response_roundtrip() {
        roundtrip(Message::Response(Response {
            req_id: 42,
            status: status::OK,
            body: b"results here".to_vec(),
        }));
    }

    #[test]
    fn test_addr_update_roundtrip() {
        roundtrip(Message::AddrUpdate(AddrUpdate {
            addrs: vec!["10.0.0.1:4433".into(), "192.168.1.5:4433".into()],
        }));
    }

    #[test]
    fn test_subscribe_roundtrip() {
        roundtrip(Message::Subscribe(Subscribe {
            sub_id: 1,
            scope: "index:updates".into(),
            body: b"filter=rust".to_vec(),
        }));
    }

    #[test]
    fn test_event_roundtrip() {
        roundtrip(Message::Event(Event {
            sub_id: 1,
            body: b"new page indexed".to_vec(),
            dropped_count: 0,
        }));
    }

    #[test]
    fn test_unsubscribe_roundtrip() {
        roundtrip(Message::Unsubscribe(Unsubscribe { sub_id: 1 }));
    }

    #[test]
    fn test_unknown_type_fails() {
        let result = deserialize_payload(0xFF, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_incomplete_frame_fails() {
        let result = decode_frame(&[0, 0, 0, 10, 0x01]); // claims 10 bytes but only has 1
        assert!(result.is_err());
    }
}
