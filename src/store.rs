use rusqlite::Connection;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::Result;

/// Persistent storage for peer data, tokens, and pins.
/// Thread-safe via internal Mutex.
pub struct PeerStore {
    conn: Mutex<Connection>,
}

impl PeerStore {
    /// Open or create the peer store database.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_tables()?;
        Ok(store)
    }

    /// Open an in-memory store (for testing).
    pub fn open_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Mutex::new(conn),
        };
        store.init_tables()?;
        Ok(store)
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().expect("peer store mutex poisoned")
    }

    fn init_tables(&self) -> Result<()> {
        self.conn().execute_batch(
            "CREATE TABLE IF NOT EXISTS tokens (
                token_id BLOB PRIMARY KEY,
                token_secret BLOB NOT NULL,
                scopes TEXT NOT NULL,
                max_claims INTEGER NOT NULL DEFAULT 1,
                claims_count INTEGER NOT NULL DEFAULT 0,
                revoked INTEGER NOT NULL DEFAULT 0,
                expires_at INTEGER,
                created_at INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pins (
                token_id BLOB NOT NULL,
                peer_pubkey BLOB NOT NULL,
                pinned_at INTEGER NOT NULL,
                PRIMARY KEY (token_id, peer_pubkey),
                FOREIGN KEY (token_id) REFERENCES tokens(token_id)
            );

            CREATE TABLE IF NOT EXISTS peers (
                pubkey BLOB PRIMARY KEY,
                last_addr TEXT,
                last_seen INTEGER,
                token_id BLOB,
                FOREIGN KEY (token_id) REFERENCES tokens(token_id)
            );",
        )?;
        Ok(())
    }

    /// Store an issued token.
    pub fn insert_token(
        &self,
        token_id: &[u8],
        token_secret: &[u8],
        scopes: &[String],
        max_claims: u32,
        expires_at: Option<u64>,
    ) -> Result<()> {
        let scopes_str = scopes.join(",");
        let now = now_unix();
        self.conn().execute(
            "INSERT INTO tokens (token_id, token_secret, scopes, max_claims, expires_at, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            rusqlite::params![token_id, token_secret, scopes_str, max_claims, expires_at, now],
        )?;
        Ok(())
    }

    /// Look up a token by id. Returns (secret, scopes, max_claims, claims_count, revoked, expires_at).
    pub fn get_token(
        &self,
        token_id: &[u8],
    ) -> Result<Option<TokenRecord>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT token_secret, scopes, max_claims, claims_count, revoked, expires_at
             FROM tokens WHERE token_id = ?1",
        )?;
        let result = stmt.query_row(rusqlite::params![token_id], |row| {
            let secret: Vec<u8> = row.get(0)?;
            let scopes_str: String = row.get(1)?;
            let max_claims: u32 = row.get(2)?;
            let claims_count: u32 = row.get(3)?;
            let revoked: bool = row.get(4)?;
            let expires_at: Option<u64> = row.get(5)?;
            Ok(TokenRecord {
                token_secret: secret,
                scopes: scopes_str.split(',').map(String::from).collect(),
                max_claims,
                claims_count,
                revoked,
                expires_at,
            })
        });
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Increment claims count and pin a pubkey to a token.
    pub fn pin_claim(&self, token_id: &[u8], peer_pubkey: &[u8]) -> Result<()> {
        let now = now_unix();
        self.conn().execute(
            "UPDATE tokens SET claims_count = claims_count + 1 WHERE token_id = ?1",
            rusqlite::params![token_id],
        )?;
        self.conn().execute(
            "INSERT OR REPLACE INTO pins (token_id, peer_pubkey, pinned_at) VALUES (?1, ?2, ?3)",
            rusqlite::params![token_id, peer_pubkey, now],
        )?;
        Ok(())
    }

    /// Check if a pubkey is pinned to a token.
    pub fn is_pinned(&self, token_id: &[u8], peer_pubkey: &[u8]) -> Result<bool> {
        let count: i64 = self.conn().query_row(
            "SELECT COUNT(*) FROM pins WHERE token_id = ?1 AND peer_pubkey = ?2",
            rusqlite::params![token_id, peer_pubkey],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Revoke a token.
    pub fn revoke_token(&self, token_id: &[u8]) -> Result<()> {
        self.conn().execute(
            "UPDATE tokens SET revoked = 1 WHERE token_id = ?1",
            rusqlite::params![token_id],
        )?;
        Ok(())
    }

    /// Update a peer's last-known address.
    pub fn upsert_peer(
        &self,
        pubkey: &[u8],
        addr: &str,
        token_id: Option<&[u8]>,
    ) -> Result<()> {
        let now = now_unix();
        self.conn().execute(
            "INSERT INTO peers (pubkey, last_addr, last_seen, token_id)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(pubkey) DO UPDATE SET last_addr = ?2, last_seen = ?3",
            rusqlite::params![pubkey, addr, now, token_id],
        )?;
        Ok(())
    }

    /// Get a peer's last-known address.
    pub fn get_peer(&self, pubkey: &[u8]) -> Result<Option<PeerRecord>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT last_addr, last_seen, token_id FROM peers WHERE pubkey = ?1",
        )?;
        let result = stmt.query_row(rusqlite::params![pubkey], |row| {
            Ok(PeerRecord {
                last_addr: row.get(0)?,
                last_seen: row.get(1)?,
                token_id: row.get(2)?,
            })
        });
        match result {
            Ok(record) => Ok(Some(record)),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// List all known peers.
    pub fn list_peers(&self) -> Result<Vec<(Vec<u8>, PeerRecord)>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT pubkey, last_addr, last_seen, token_id FROM peers",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, Vec<u8>>(0)?,
                PeerRecord {
                    last_addr: row.get(1)?,
                    last_seen: row.get(2)?,
                    token_id: row.get(3)?,
                },
            ))
        })?;
        let mut peers = Vec::new();
        for row in rows {
            peers.push(row?);
        }
        Ok(peers)
    }

    /// Get scopes for a pinned peer (via their token).
    pub fn get_peer_scopes(&self, peer_pubkey: &[u8]) -> Result<Vec<String>> {
        let conn = self.conn();
        let mut stmt = conn.prepare(
            "SELECT t.scopes FROM tokens t
             INNER JOIN pins p ON t.token_id = p.token_id
             WHERE p.peer_pubkey = ?1 AND t.revoked = 0",
        )?;
        let result = stmt.query_row(rusqlite::params![peer_pubkey], |row| {
            let scopes_str: String = row.get(0)?;
            Ok(scopes_str.split(',').map(String::from).collect())
        });
        match result {
            Ok(scopes) => Ok(scopes),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(vec![]),
            Err(e) => Err(e.into()),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TokenRecord {
    pub token_secret: Vec<u8>,
    pub scopes: Vec<String>,
    pub max_claims: u32,
    pub claims_count: u32,
    pub revoked: bool,
    pub expires_at: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub last_addr: Option<String>,
    pub last_seen: Option<u64>,
    pub token_id: Option<Vec<u8>>,
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let store = PeerStore::open_memory().unwrap();
        let token_id = vec![1u8; 16];
        let secret = vec![2u8; 32];
        let scopes = vec!["search".into(), "stats".into()];

        store
            .insert_token(&token_id, &secret, &scopes, 3, Some(9999999999))
            .unwrap();

        let record = store.get_token(&token_id).unwrap().unwrap();
        assert_eq!(record.token_secret, secret);
        assert_eq!(record.scopes, scopes);
        assert_eq!(record.max_claims, 3);
        assert_eq!(record.claims_count, 0);
        assert!(!record.revoked);
    }

    #[test]
    fn test_pin_and_check() {
        let store = PeerStore::open_memory().unwrap();
        let token_id = vec![1u8; 16];
        let secret = vec![2u8; 32];
        let pubkey = vec![3u8; 32];

        store
            .insert_token(&token_id, &secret, &["search".into()], 1, None)
            .unwrap();

        assert!(!store.is_pinned(&token_id, &pubkey).unwrap());
        store.pin_claim(&token_id, &pubkey).unwrap();
        assert!(store.is_pinned(&token_id, &pubkey).unwrap());

        let record = store.get_token(&token_id).unwrap().unwrap();
        assert_eq!(record.claims_count, 1);
    }

    #[test]
    fn test_revoke() {
        let store = PeerStore::open_memory().unwrap();
        let token_id = vec![1u8; 16];
        store
            .insert_token(&token_id, &[2u8; 32], &["search".into()], 1, None)
            .unwrap();

        store.revoke_token(&token_id).unwrap();
        let record = store.get_token(&token_id).unwrap().unwrap();
        assert!(record.revoked);
    }

    #[test]
    fn test_peer_upsert_and_get() {
        let store = PeerStore::open_memory().unwrap();
        let pubkey = vec![1u8; 32];

        store
            .upsert_peer(&pubkey, "192.168.1.50:4433", None)
            .unwrap();
        let record = store.get_peer(&pubkey).unwrap().unwrap();
        assert_eq!(record.last_addr.as_deref(), Some("192.168.1.50:4433"));

        // Update addr
        store
            .upsert_peer(&pubkey, "10.0.0.1:4433", None)
            .unwrap();
        let record = store.get_peer(&pubkey).unwrap().unwrap();
        assert_eq!(record.last_addr.as_deref(), Some("10.0.0.1:4433"));
    }

    #[test]
    fn test_list_peers() {
        let store = PeerStore::open_memory().unwrap();
        store
            .upsert_peer(&[1u8; 32], "10.0.0.1:4433", None)
            .unwrap();
        store
            .upsert_peer(&[2u8; 32], "10.0.0.2:4433", None)
            .unwrap();

        let peers = store.list_peers().unwrap();
        assert_eq!(peers.len(), 2);
    }

    #[test]
    fn test_get_peer_scopes() {
        let store = PeerStore::open_memory().unwrap();
        let token_id = vec![1u8; 16];
        let pubkey = vec![3u8; 32];

        store
            .insert_token(
                &token_id,
                &[2u8; 32],
                &["search".into(), "stats".into()],
                1,
                None,
            )
            .unwrap();
        store.pin_claim(&token_id, &pubkey).unwrap();

        let scopes = store.get_peer_scopes(&pubkey).unwrap();
        assert_eq!(scopes, vec!["search", "stats"]);
    }

    #[test]
    fn test_unknown_token_returns_none() {
        let store = PeerStore::open_memory().unwrap();
        assert!(store.get_token(&[99u8; 16]).unwrap().is_none());
    }
}
