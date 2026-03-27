# Hypha

A capability-based cooperation protocol for peer-to-peer applications.

Hypha lets small applications find each other, authenticate using capabilities rather than identities, and exchange data -- without accounts, key management ceremonies, bootstrap servers, or central registries. You share a link, your peer claims it, and you're connected.

## Why Hypha?

Most P2P systems ask you to manage cryptographic identities, register with a DHT, or run bootstrap infrastructure before you can do anything useful. Hypha takes a different approach:

- **No identity** -- Device keys exist but are invisible infrastructure, not social identities. You never need to verify a fingerprint or manage a web of trust.
- **No infrastructure** -- No bootstrap servers, relay nodes, or registries. Peers connect directly and discover each other through their existing connections.
- **Capabilities, not permissions** -- Access is granted by sharing a link. If you have the link, you can connect. Revocation is immediate.
- **Application-agnostic** -- Hypha moves authenticated bytes between peers. Your application decides what those bytes mean.

## How It Works

### The Core Flow

```
Alice                                          Bob
  |                                              |
  |  1. Create invite (scopes, expiry, hints)    |
  |  2. Share link out-of-band (chat, QR, etc.)  |
  |  ─────────── hypha://base64... ────────────> |
  |                                              |
  |  3. Bob connects to Alice via QUIC           |
  |  <────────── TLS + QUIC ──────────────────── |
  |                                              |
  |  4. Challenge-response handshake             |
  |  ──────────── Challenge(nonce) ────────────> |
  |  <─────────── ClaimProof(HMAC, sig) ──────── |
  |  ──────────── Welcome(scopes) ─────────────> |
  |                                              |
  |  5. Authenticated request/response           |
  |  <─── Request("search", "rust async") ────── |
  |  ─── Response("results for: rust async") ──> |
```

### Capability Tokens

An invite is a capability token containing:

| Field | Purpose |
|-------|---------|
| `token_id` | Unique identifier for tracking and revocation |
| `token_secret` | Proof-of-possession key (never sent over the wire) |
| `scopes` | What the bearer can do (e.g., `"search"`, `"seed"`) |
| `issuer_pubkey` | Ed25519 public key of the issuer |
| `connection_hints` | How to reach the issuer (`ip:port`) |
| `max_claims` | How many peers can claim this invite |
| `expires_at` | Optional expiration timestamp |

Tokens are serialized as `hypha://<base64url(cbor(token))>` links that you share however you like -- paste into a chat, embed in a QR code, email to a friend.

### Authentication

Hypha uses a challenge-response handshake with three security properties:

1. **Issuer verified before secret exposure** -- The claimer checks the TLS certificate's public key against the token's `issuer_pubkey` before sending any proof.
2. **Token never crosses the wire** -- The claimer proves possession via `HMAC-SHA256(nonce, token_secret)` without revealing the secret itself.
3. **Channel binding** -- Signatures include a TLS exporter value (RFC 5705) that ties authentication to the specific TLS session, preventing replay attacks.

After the first connection, Hypha uses **TOFU (Trust on First Use)** key pinning. The issuer remembers which public key claimed each token, so returning peers authenticate with just a signature -- no token needed.

### Scope Enforcement

Scopes are enforced at the protocol layer. If Bob was granted `["search"]` but sends a request with scope `"admin"`, Hypha rejects it with `Forbidden` before it reaches your application code.

### Peer Discovery

When peers change IP addresses, Hypha provides two mechanisms for reconnection:

- **Whereis** -- Ask connected peers if they know a target's current address
- **AddrUpdate** -- Proactively push your new address to connected peers

No central registry required. Peers find each other through the connections they already have.

## Quick Start

### Build

```bash
cargo build --release
```

### Initialize a Node

```bash
# Creates a keypair and database in .hypha/
hypha init
```

### Create and Share an Invite

```bash
# Start listening
hypha listen --port 4433

# In another terminal: create an invite
hypha invite --scopes search,echo --hint 192.168.1.100:4433 --max-claims 1

# Output:
# Share this link:
# hypha://eyJ0b2tlbl9pZCI6...
```

### Claim an Invite

```bash
# On the other machine
hypha claim "hypha://eyJ0b2tlbl9pZCI6..."

# Output:
# Connected to peer: a1b2c3...
# Granted scopes: ["search", "echo"]
```

### Manage Peers

```bash
# List known peers
hypha peers

# Revoke a token
hypha revoke <token-id-hex>
```

## Library Usage

Hypha is both a CLI tool and a Rust library. Here's how to use it programmatically:

### Setting Up a Node

```rust
use hypha::HyphaNode;
use hypha::node::NodeConfig;
use hypha::capability::InviteConfig;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Create and configure a node
    let mut node = HyphaNode::open(NodeConfig {
        data_dir: ".hypha".into(),
        key_created_at: 1711411200, // unix timestamp
    })?;

    // Register request handlers
    node.on_request("search", |req| async move {
        let query = String::from_utf8_lossy(&req.body);
        Ok(format!("results for: {query}").into_bytes())
    }).await;

    // Start listening
    let addr = node.listen("0.0.0.0:4433".parse()?).await?;
    println!("Listening on {addr}");

    // Create an invite
    let token = node.create_invite(InviteConfig {
        scopes: vec!["search".into()],
        max_claims: 3,
        expires_in: Some(Duration::from_secs(3600)),
        connection_hints: vec![addr.to_string()],
    })?;

    let link = token.to_link()?;
    println!("Share this: {link}");

    tokio::signal::ctrl_c().await?;
    Ok(())
}
```

### Claiming an Invite and Sending Requests

```rust
let node = HyphaNode::open(config)?;

// Claim the invite
let peer = node.claim_invite("hypha://eyJ0b2tlbl9pZCI6...").await?;
println!("Connected! Scopes: {:?}", peer.scopes);

// Send requests
let response = peer.request("search", b"rust async patterns").await?;
println!("Got: {}", String::from_utf8_lossy(&response));
```

### Revoking Access

```rust
// Immediately revoke a token -- no new claims will be accepted
node.revoke(&token.token_id)?;
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Application                       │
│              (your code, any format)                 │
├─────────────────────────────────────────────────────┤
│  Exchange         │  Discovery       │  Capability   │
│  request/response │  whereis, addr   │  tokens,      │
│  scope enforcement│  updates         │  revocation   │
├─────────────────────────────────────────────────────┤
│  Handshake                                           │
│  challenge-response, TOFU pinning, channel binding   │
├─────────────────────────────────────────────────────┤
│  Transport                                           │
│  QUIC (quinn) + TLS 1.3 (rustls)                    │
├─────────────────────────────────────────────────────┤
│  Crypto                          │  Store            │
│  Ed25519, HMAC-SHA256,           │  SQLite (peers,   │
│  self-signed certs               │  tokens, pins)    │
└─────────────────────────────────────────────────────┘
```

### Module Overview

| Module | Purpose |
|--------|---------|
| `node` | Main entry point. Node lifecycle, connection handling, public API |
| `capability` | Token creation, serialization to `hypha://` links, expiry/revocation |
| `crypto` | Ed25519 keypairs, HMAC proof-of-possession, TLS certificate generation |
| `handshake` | Challenge-response authentication, TOFU pinning |
| `transport` | QUIC endpoint setup, certificate extraction |
| `messages` | Wire protocol -- 15 message types, CBOR-encoded with length-prefixed frames |
| `exchange` | Request/response dispatch with scope enforcement |
| `discovery` | Whereis queries and address update propagation |
| `store` | SQLite persistence for peers, tokens, and TOFU pins |

## Wire Protocol

All messages are CBOR-encoded (RFC 8949) with a 4-byte big-endian length prefix:

```
┌──────────┬──────────────────────────────┐
│ len (4B) │ CBOR-encoded message         │
└──────────┴──────────────────────────────┘
```

Message types:

| Category | Messages |
|----------|----------|
| **Auth** | `Challenge`, `ClaimProof`, `PinnedProof`, `Welcome`, `Rejected`, `KeyRotation`, `KeyRotationAck` |
| **Exchange** | `Request`, `Response` (status: OK, ERROR, FORBIDDEN, NOT_FOUND) |
| **Discovery** | `Whereis`, `LastSeen`, `AddrUpdate` |
| **Streaming** | `Subscribe`, `Event`, `Unsubscribe` (planned) |

## Security Model

### Threat Model

Hypha is designed for **friends cooperating** -- small groups of peers that choose to connect. It is not designed for anonymous networks or adversarial environments.

### Properties

| Property | How |
|----------|-----|
| **Confidentiality** | TLS 1.3 (forward secrecy via QUIC/rustls) |
| **Authentication** | Ed25519 signatures + HMAC proof-of-possession |
| **Replay prevention** | TLS exporter channel binding (RFC 5705) |
| **Authorization** | Capability scopes enforced at protocol layer |
| **Revocation** | Immediate, checked on every new claim |
| **Key pinning** | TOFU -- first connection pins the key |

### What Hypha Does Not Do

- **Sybil resistance** -- Applications implement rate-limiting via scopes
- **Anonymity** -- Whereis queries reveal the social graph between peers
- **NAT traversal** -- Requires at least one peer to be directly reachable (relay mode planned)

## Project Status

Hypha is in **proof-of-concept** stage. The core protocol works end-to-end:

- Node lifecycle (keypair generation, persistence)
- Capability tokens (creation, serialization, expiry, revocation)
- Full handshake (challenge-response, TOFU pinning, channel binding)
- Request/response with scope enforcement
- Peer discovery (Whereis, AddrUpdate)
- CLI for basic operations

### Planned

- Subscribe/Event streaming with backpressure
- Key rotation (spec complete, implementation planned)
- Optional relay mode for double-NAT scenarios
- mDNS LAN discovery

## Testing

```bash
# Run all tests
cargo test

# Run integration tests (full handshake, scope enforcement, revocation)
cargo test --test integration
```

## License

MIT OR Apache-2.0
