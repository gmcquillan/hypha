use crate::messages::{self, AddrUpdate, LastSeen, Message, Whereis};
use crate::store::PeerStore;
use crate::Result;


/// Handle an incoming Whereis query.
/// Returns Some(LastSeen) if we know the peer, None otherwise (silence = unknown).
pub fn handle_whereis(store: &PeerStore, query: &Whereis) -> Result<Option<LastSeen>> {
    if let Some(record) = store.get_peer(&query.peer_pubkey)? {
        if let (Some(addr), Some(timestamp)) = (record.last_addr, record.last_seen) {
            return Ok(Some(LastSeen { addr, timestamp }));
        }
    }
    Ok(None)
}

/// Build an AddrUpdate message with the node's current addresses.
pub fn build_addr_update(addrs: &[String]) -> Message {
    Message::AddrUpdate(AddrUpdate {
        addrs: addrs.to_vec(),
    })
}

/// Process an incoming AddrUpdate from a peer — update their stored address.
pub fn handle_addr_update(
    store: &PeerStore,
    peer_pubkey: &[u8],
    update: &AddrUpdate,
) -> Result<()> {
    if let Some(addr) = update.addrs.first() {
        store.upsert_peer(peer_pubkey, addr, None)?;
    }
    Ok(())
}

/// Send a Whereis query on a stream and wait for LastSeen response.
/// Returns None on timeout (5 seconds) or if the peer doesn't know.
pub async fn query_whereis(
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    target_pubkey: &[u8; 32],
) -> Result<Option<LastSeen>> {
    let msg = Message::Whereis(Whereis {
        peer_pubkey: target_pubkey.to_vec(),
    });
    messages::write_message(send, &msg).await?;

    // Wait for response with timeout
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        messages::read_message(recv),
    )
    .await
    {
        Ok(Ok(Message::LastSeen(ls))) => Ok(Some(ls)),
        Ok(Ok(_)) => Ok(None), // unexpected message type, treat as unknown
        Ok(Err(_)) => Ok(None),
        Err(_) => Ok(None), // timeout — silence = unknown
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handle_whereis_known_peer() {
        let store = PeerStore::open_memory().unwrap();
        let pubkey = vec![1u8; 32];
        store
            .upsert_peer(&pubkey, "10.0.0.1:4433", None)
            .unwrap();

        let query = Whereis {
            peer_pubkey: pubkey.clone(),
        };
        let result = handle_whereis(&store, &query).unwrap();
        assert!(result.is_some());
        let ls = result.unwrap();
        assert_eq!(ls.addr, "10.0.0.1:4433");
    }

    #[test]
    fn test_handle_whereis_unknown_peer() {
        let store = PeerStore::open_memory().unwrap();
        let query = Whereis {
            peer_pubkey: vec![99u8; 32],
        };
        let result = handle_whereis(&store, &query).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_handle_addr_update() {
        let store = PeerStore::open_memory().unwrap();
        let pubkey = vec![1u8; 32];
        store
            .upsert_peer(&pubkey, "10.0.0.1:4433", None)
            .unwrap();

        let update = AddrUpdate {
            addrs: vec!["10.0.0.2:4433".into()],
        };
        handle_addr_update(&store, &pubkey, &update).unwrap();

        let record = store.get_peer(&pubkey).unwrap().unwrap();
        assert_eq!(record.last_addr.as_deref(), Some("10.0.0.2:4433"));
    }

    #[test]
    fn test_build_addr_update() {
        let msg = build_addr_update(&["10.0.0.1:4433".into()]);
        match msg {
            Message::AddrUpdate(au) => {
                assert_eq!(au.addrs, vec!["10.0.0.1:4433"]);
            }
            _ => panic!("expected AddrUpdate"),
        }
    }
}
