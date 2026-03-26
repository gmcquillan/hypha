# Hypha: A Capability-Based Cooperation Protocol

**Date:** 2026-03-26
**Status:** Design spec — pre-implementation
**Language:** Rust (reference implementation)
**Repo:** Separate project from Rhizome; Rhizome is the first consumer

## Problem

P2P and fediverse systems lack a lightweight cooperation layer that lets small applications find each other, authenticate capabilities rather than people, and exchange data — without accounts, key management ceremonies, bootstrap infrastructure, or centralized registries.

Existing tools each solve one piece (Hyperswarm: discovery, SSB: auth, libp2p: transport) but nobody has built the thin glue layer that combines them into something an application developer can adopt in an afternoon.

## Design Principles

1. **No identity, only capabilities.** Peers authenticate what they can *do*, not who they *are*. Device keys are invisible infrastructure, not social identity.
2. **No infrastructure beyond the peers themselves.** No bootstrap nodes, no relay services, no CAs. Peers help each other reconnect (Whereis). Any node can optionally act as a relay.
3. **Pairwise, not network.** Hypha defines authenticated channels between two peers. Networks emerge from many pairwise connections, but Hypha doesn't model or manage the network.
4. **Application-agnostic.** Hypha moves authenticated bytes. It doesn't know or care about search queries, bookmarks, or any particular application domain.
5. **Spec-first.** The protocol spec is the primary deliverable. The Rust library is a reference implementation.

## Core Concepts

### Node

A running instance of an application using Hypha. Each node has:

- An **Ed25519 keypair** (auto-generated on first run, stored locally)
- A **self-signed TLS certificate** derived from the keypair (exists only because QUIC requires one structurally)
- A **peer store** mapping known peer public keys to last-seen addresses and pinned capabilities
- A set of **request handlers** registered by the application

### Capability Token

A signed blob that grants specific permissions. Created by an issuer, given to a peer out-of-band (chat, email, QR code).

Fields:

| Field | Type | Description |
|-------|------|-------------|
| `token_id` | `[u8; 16]` | Random unique identifier, used for revocation |
| `token_secret` | `[u8; 32]` | Secret used in HMAC proof-of-possession (never sent over wire) |
| `scopes` | `Vec<String>` | What the holder can do (e.g., `"search"`, `"seed"`) |
| `issuer_pubkey` | `[u8; 32]` | Ed25519 public key of the issuer |
| `connection_hints` | `Vec<Addr>` | How to reach the issuer (IP:port, DNS name, relay hint) |
| `max_claims` | `u32` | How many peers can pin this token (default: 1) |
| `expires_at` | `Option<u64>` | Unix timestamp after which the token cannot be claimed |

Serialized as a URL-safe string for sharing: `hypha://<base64url-encoded-token>`

### Channel

An authenticated, encrypted bidirectional QUIC stream between two nodes. Established via the handshake protocol (below). All subsequent messages flow over this channel.

### Scopes

Simple strings that the application defines. Hypha enforces exact-match membership: a peer can only send `Request` or `Subscribe` messages with scopes present in their `Welcome.capabilities` list. Unauthorized requests are rejected at the protocol layer — the application handler never sees them.

Scopes can use hierarchical conventions (e.g., `"search:read"`, `"search:admin"`) but Hypha treats them as opaque strings with exact matching only.

## Trust Model

There is no certificate authority. Trust is established through out-of-band invite exchange and TOFU key-pinning.

| Trust question | Answer |
|---|---|
| Who issued the cert? | The node itself (self-signed) |
| Who is the CA? | Nobody. There is no CA. |
| How do you verify a peer? | The invite link contains the expected pubkey |
| What about returning connections? | TOFU — the key was pinned on first use |
| What if a node regenerates its key? | It's a new identity. Old pins won't match. New invite required. |

The "CA" is the friendship — the fact that Alice texted Bob the invite link through a channel they already trust.

## Handshake Protocol

### First Connection (Invite Claim)

```
Initiator (has invite token)             Issuer (created the token)
─────────────────────────────────────────────────────────────────────
1. QUIC connect to connection_hint address
2. Verify server cert pubkey matches issuer_pubkey from invite
   (ABORT if mismatch — wrong server or MITM)
3.                         ◄─── Challenge { nonce: [u8; 32] }
4. ──── ClaimProof {
         token_id: token_id,
         hmac: HMAC-SHA256(nonce, token_secret),
         pubkey: initiator_ed25519_pubkey,
         sig: sign(initiator_privkey, nonce ‖ tls_exporter),
         tls_binding: tls_exporter_value
       } ────►
5.                         Issuer verifies:
                           - Looks up token by token_id
                           - HMAC matches (proves token possession)
                           - Signature valid (proves key ownership)
                           - TLS binding matches (channel binding)
                           - Token not expired, not revoked
                           - claims_count < max_claims
6.                         Issuer pins initiator_pubkey to token
7.                         ◄─── Welcome { capabilities, key_created_at }
   OR
7.                         ◄─── Rejected { reason }
```

Security properties:
- **Issuer verified before sending proof:** Step 2 ensures the initiator never reveals the HMAC to an imposter
- **Token never crosses the wire:** Only the HMAC proof-of-possession is sent
- **Key ownership proven:** Signature over nonce prevents pubkey spoofing
- **Channel binding:** TLS exporter value binds auth to this specific QUIC session (RFC 5705)

### Returning Connection (TOFU-Pinned)

```
Returning peer                           Issuer
─────────────────────────────────────────────────────────────────────
1. QUIC connect (try last-known addr, then Whereis fallback)
2. Verify server cert pubkey matches stored pin
3.                         ◄─── Challenge { nonce: [u8; 32] }
4. ──── PinnedProof {
         token_id: [u8; 16],
         sig: sign(peer_privkey, nonce ‖ tls_exporter),
         tls_binding: tls_exporter_value
       } ────►
5.                         Issuer verifies:
                           - token_id exists and is not revoked
                           - pubkey (from TLS cert) matches pin for this token
                           - Signature valid, TLS binding matches
6.                         ◄─── Welcome { capabilities, key_created_at }
```

### Revocation

The issuer maintains a local revocation list of token_ids. When a revoked token is presented, step 5/6 returns `Rejected { reason: "token revoked" }` and the channel is closed.

## Key Rotation

Nodes can rotate their Ed25519 keypair without requiring new invites for every peer.

### Rotation Announcement (over existing authenticated channel)

```
Rotating node                            Peer
─────────────────────────────────────────────────────────────────────
1. ──── KeyRotation {
         new_pubkey: [u8; 32],
         old_sig: sign(old_privkey, new_pubkey),
         new_sig: sign(new_privkey, old_pubkey)
       } ────►
2.                         Peer verifies:
                           - old_sig valid (old key authorized rotation)
                           - new_sig valid (new key proves possession)
3.                         Peer updates stored pin: old → new
4.                         ◄─── KeyRotationAck {}
```

Cross-signatures prevent both attacker-injected rotations (would need old private key) and pointing to someone else's key (would need new private key).

### Grace Period

After rotation, a node accepts both old and new keys for a configurable window (recommended: 7 days). When a peer connects with the old key, the node sends `KeyRotation` before `Welcome`. After the grace period, the old key is rejected.

### Rotation Policy

Hypha does not enforce rotation schedules. It provides:

- `key_created_at` in every `Welcome` message (peers know the key's age)
- A `StaleKey` event emitted to the application when a peer's key exceeds a configurable age threshold (default: 6 months)
- The application decides the policy (warn, suggest rotation, or ignore)

## Peer Discovery & Reconnection

### Whereis Protocol

When a peer's last-known address fails, the node asks other connected peers:

```
Seeking node                             Other peer
─────────────────────────────────────────────────────────────────────
──── Whereis { peer_pubkey: [u8; 32] } ────►
                            Checks peer store for matching pubkey
◄─── LastSeen { addr, timestamp } ────
 OR  (no response if unknown — seeker uses a configurable timeout, default 5s, and treats silence as "unknown")
```

The seeking node tries addresses from most-recent timestamp first.

### Address Updates

When a node detects its address has changed (new connection from a different IP, or periodic self-check), it proactively pushes:

```
──── AddrUpdate { addrs: [SocketAddr] } ────►
```

to all connected peers. This keeps Whereis responses fresh without polling.

### Connection Hints: Ordered Fallback

Connection hints are a list tried in order:
1. Last-known direct address (from peer store, may be fresher than invite hint)
2. Addresses returned by Whereis from other peers
3. Original hints from the invite token
4. Optional relay (any Hypha node acting as relay)

### Optional Relay Mode

Any Hypha node can opt into acting as a relay for peers that cannot establish direct connections (double-NAT scenario). The relay:

- Forwards opaque encrypted bytes between two peers identified by a rendezvous token
- Reports the observed external address of connecting peers (solves "what's my IP?" without a separate service)
- Never sees decrypted content or capabilities
- Is not a special binary — it's a mode flag on a regular Hypha node

Relay support is optional and deferred to post-PoC.

### Network Partition Recovery

If all peers go offline simultaneously and all IP addresses change before anyone reconnects, no peer can find any other — every stored address is stale and no one is online to answer Whereis queries. TOFU pins and keys remain valid, but addresses are lost.

This is a known limitation of the peer-as-rendezvous model. Mitigation strategies (not implemented in PoC):

1. **Re-share invite links with updated hints.** An existing invite link with a fresh connection hint (current IP) serves as a reconnection token. No new invite or re-authentication needed — the TOFU pin is still valid. This is manual but requires zero infrastructure.
2. **Well-known rendezvous point.** A DNS name or static address that group members agree on. A cheap VPS running a Hypha node that just answers Whereis queries. Lightweight, but reintroduces a single point of coordination.
3. **Out-of-band address dead drop.** Peers optionally publish their current address to a shared location (DNS TXT record, paste service, shared file) that other peers know to check. Opt-in, no Hypha-specific infrastructure.

In practice, this scenario requires every peer in a group to be on dynamic IPs with no stable address, and all to go offline long enough for every IP to rotate. For groups where at least one member has a stable address (VPS, static home IP, DynDNS), the normal Whereis protocol handles reconnection.

## Wire Format

### Framing

Messages are length-prefixed frames over QUIC streams:

```
┌──────────────┬──────────────┬──────────────────────────────┐
│ length (4B)  │ type (1B)    │ payload (length - 1 bytes)   │
└──────────────┴──────────────┴──────────────────────────────┘
```

- `length`: u32 big-endian, size of type + payload
- `type`: single byte message type identifier
- `payload`: CBOR-encoded (RFC 8949) message body

### Why CBOR

- Self-describing: no separate schema files needed
- Compact binary encoding
- Handles mixed binary blobs (signatures, keys) and structured data naturally
- IETF standard with mature Rust support (`ciborium` crate)

### Message Types

| Type | Name | Direction | Purpose |
|------|------|-----------|---------|
| `0x01` | Challenge | Issuer → Peer | Nonce for authentication |
| `0x02` | ClaimProof | Peer → Issuer | First-time invite claim |
| `0x03` | PinnedProof | Peer → Issuer | Returning peer authentication |
| `0x04` | Welcome | Issuer → Peer | Auth success, granted scopes |
| `0x05` | Rejected | Issuer → Peer | Auth failure with reason |
| `0x06` | KeyRotation | Either | Cross-signed key change |
| `0x07` | KeyRotationAck | Either | Key change confirmed |
| `0x08` | Whereis | Either | Peer address lookup |
| `0x09` | LastSeen | Either | Peer address response |
| `0x0A` | Request | Either | Application request |
| `0x0B` | Response | Either | Application response |
| `0x0C` | AddrUpdate | Either | Proactive address push |
| `0x0D` | Subscribe | Either | Open event stream |
| `0x0E` | Event | Either | Stream event data |
| `0x0F` | Unsubscribe | Either | Close event stream |

### Message Schemas

**Challenge:**
```
{ nonce: bytes(32) }
```

**ClaimProof:**
```
{ token_id: bytes(16), hmac: bytes(32), pubkey: bytes(32), sig: bytes(64), tls_binding: bytes(32) }
```

**PinnedProof:**
```
{ token_id: bytes(16), sig: bytes(64), tls_binding: bytes(32) }
```

**Welcome:**
```
{ capabilities: [string], key_created_at: uint }
```

**Rejected:**
```
{ reason: string }
```

**KeyRotation:**
```
{ new_pubkey: bytes(32), old_sig: bytes(64), new_sig: bytes(64) }
```

**KeyRotationAck:**
```
{}
```

**Whereis:**
```
{ peer_pubkey: bytes(32) }
```

**LastSeen:**
```
{ addr: string, timestamp: uint }
```

**Request:**
```
{ req_id: uint, scope: string, body: bytes }
```

**Response:**
```
{ req_id: uint, status: uint, body: bytes }
```

Response status codes:
- `0x00` OK
- `0x01` Error (application error)
- `0x02` Forbidden (scope not granted)
- `0x03` Not Found

**AddrUpdate:**
```
{ addrs: [string] }
```

**Subscribe:**
```
{ sub_id: uint, scope: string, body: bytes }
```

**Event:**
```
{ sub_id: uint, body: bytes, dropped_count: uint }
```

**Unsubscribe:**
```
{ sub_id: uint }
```

## Library API Surface

The Rust library exposes these core types and functions:

### Node Lifecycle

```rust
// Create or load a node (generates keypair on first run)
let node = HyphaNode::open(config)?;

// Start listening for incoming connections
node.listen("0.0.0.0:4433").await?;
```

### Creating & Managing Invites

```rust
// Create an invite token
let invite = node.create_invite(InviteConfig {
    scopes: vec!["search".into(), "stats".into()],
    max_claims: 1,
    expires_in: Some(Duration::from_secs(7 * 86400)),
})?;

// Serialize to shareable link
let link: String = invite.to_link(); // hypha://base64url...

// Revoke a token
node.revoke(token_id)?;
```

### Claiming Invites & Connecting

```rust
// Claim an invite (first-time connection)
let peer = node.claim_invite("hypha://...").await?;

// Send a request
let response = peer.request("search", b"rust async").await?;

// Subscribe to events
let mut sub = peer.subscribe("index:updates", b"domain=*.example.com").await?;
while let Some(event) = sub.next().await {
    // handle event
}
```

### Registering Handlers

```rust
// Request handler
node.on_request("search", |req: HyphaRequest| async move {
    let query = std::str::from_utf8(&req.body)?;
    let results = engine.search(query).await?;
    Ok(serialize(&results)?)
});

// Subscribe handler
node.on_subscribe("index:updates", |sub: HyphaSubscription| async move {
    let (tx, rx) = channel(buffer_size);
    engine.on_indexed(move |page| { tx.send(serialize(&page)).ok(); });
    Ok(rx)
});
```

### Error Types

```rust
enum HyphaError {
    // Connection errors
    PeerUnreachable { last_seen: Option<u64> },
    HandshakeFailed { detail: String },

    // Auth errors
    Rejected { reason: String },
    Forbidden { scope: String },
    InviteExpired,
    InviteFullyClaimed,

    // Application errors
    RemoteError { status: u8, message: String },
    BadRequest(String),
    Internal(String),

    // Transport errors
    ConnectionLost,
    Timeout,
}
```

## Integration Examples

### Rhizome: Search Federation

```rust
// Alice creates an invite for Bob
let invite = node.create_invite(InviteConfig {
    scopes: vec!["search".into(), "stats".into()],
    max_claims: 1,
    expires_in: Some(Duration::from_secs(7 * 86400)),
})?;
println!("Send this to Bob: {}", invite.to_link());

// Alice registers her search handler
node.on_request("search", |req| async {
    let query = std::str::from_utf8(&req.body)?;
    let results = engine.search(query, 10).await?;
    Ok(serialize(&results)?)
});

// Bob claims and searches
let alice = node.claim_invite("hypha://...").await?;
let response = alice.request("search", b"rust async patterns").await?;
let results: Vec<SearchResult> = deserialize(&response.body)?;
// Fuse with local results via RRF, same as Rhizome does today
```

### Collaborative Seed Sharing

```rust
// Charlie creates a group invite for up to 5 friends
let invite = node.create_invite(InviteConfig {
    scopes: vec!["seed".into()],
    max_claims: 5,
    expires_in: Some(Duration::from_secs(30 * 86400)),
})?;

// Charlie handles incoming seeds
node.on_request("seed", |req| async {
    let url = std::str::from_utf8(&req.body)?;
    seedlist.add(url, "from-friends").await?;
    Ok(b"accepted".to_vec())
});

// Diana claims and pushes a URL
let charlie = node.claim_invite("hypha://...")?;
charlie.request("seed", b"https://fasterthanli.me/articles").await?;
```

### Non-Rhizome: Shared Bookmarks App

```rust
// Hypha is application-agnostic — same protocol, different app
node.on_request("bookmark:add", |req| async {
    let bookmark: Bookmark = deserialize(&req.body)?;
    db.insert_shared_bookmark(bookmark, req.peer_pubkey).await?;
    Ok(b"saved".to_vec())
});

node.on_request("bookmark:list", |req| async {
    let bookmarks = db.shared_bookmarks().await?;
    Ok(serialize(&bookmarks)?)
});
```

### Reconnection After IP Change

```rust
// Bob's laptop moves networks. From the app's perspective, invisible:
let response = bob.request("search", b"sourdough starter").await?;
// Hypha automatically:
// 1. Tries last-known addr → timeout
// 2. Whereis(bob_pubkey) to other connected peers
// 3. Charlie responds: LastSeen { addr: 10.0.0.42:4433, timestamp: ... }
// 4. Connects to new addr, PinnedProof handshake succeeds
// 5. Updates stored addr, returns response
```

## Crate Structure

```
hypha/
├── Cargo.toml
├── docs/
│   └── 2026-03-26-hypha-design.md   ← This spec
├── src/
│   ├── lib.rs               ← Public API (HyphaNode, HyphaError, etc.)
│   ├── node.rs              ← Node lifecycle, listener, peer store
│   ├── capability.rs        ← Token creation, TOFU pinning, revocation
│   ├── handshake.rs         ← Challenge/ClaimProof/PinnedProof logic
│   ├── transport.rs         ← QUIC setup (quinn), TLS cert from Ed25519
│   ├── messages.rs          ← Wire format, CBOR serialization
│   ├── exchange.rs          ← Request/Response dispatch, scope enforcement
│   ├── stream.rs            ← Subscribe/Event/Unsubscribe, backpressure
│   ├── discovery.rs         ← Whereis, AddrUpdate, mDNS (LAN)
│   ├── relay.rs             ← Optional relay mode
│   └── crypto.rs            ← Ed25519 ops, HMAC, TLS exporter binding
└── examples/
    ├── ping_pong.rs         ← Minimal two-node example
    └── search_federation.rs ← Rhizome-like search query federation
```

## PoC Scope

Implement for the initial proof of concept:

- Node lifecycle (keypair generation, storage, listen)
- Capability token creation and serialization to invite links
- Full handshake (Challenge → ClaimProof/PinnedProof → Welcome/Rejected)
- TOFU key-pinning
- Peer store (pubkey → addr mapping, persistence)
- Request/Response with scope enforcement
- Whereis/LastSeen for reconnection
- AddrUpdate for proactive address sharing
- Basic CLI for testing (`hypha invite`, `hypha claim`, `hypha request`)

Deferred to post-PoC:

- Subscribe/Event streaming
- Key rotation (included in spec, implement later)
- Relay mode
- mDNS LAN discovery
- Backpressure tuning

## Security Considerations

- **No identity:** Device keys are not people. Hypha cannot and should not be used to identify humans.
- **Invite link sensitivity:** Invite links are bearer tokens until claimed. Treat them like passwords — share through trusted channels, use short expiry for sensitive scopes.
- **Sybil resistance:** Hypha has no built-in sybil resistance. A malicious actor with multiple invite links can create multiple pinned identities. Applications that need rate-limiting should implement it at the application layer using scope-based counters.
- **Forward secrecy:** Provided by QUIC's TLS 1.3 at the transport layer. Hypha's Ed25519 keys are for authentication only.
- **Metadata exposure:** Whereis queries reveal social graph information (who is looking for whom). Acceptable for "friends cooperating" threat model; applications requiring metadata privacy should not use Whereis.
