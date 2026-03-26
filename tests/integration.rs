use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hypha::capability::InviteConfig;
use hypha::node::NodeConfig;
use hypha::HyphaNode;
use tempfile::TempDir;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn make_node(dir: &TempDir, name: &str) -> HyphaNode {
    let data_dir = dir.path().join(name);
    HyphaNode::open(NodeConfig {
        data_dir,
        key_created_at: now_unix(),
    })
    .expect("failed to create node")
}

#[tokio::test]
async fn test_invite_claim_request_response() {
    let dir = TempDir::new().unwrap();

    // --- Alice (server/issuer) ---
    let mut alice = make_node(&dir, "alice");

    // Register handlers before listening
    alice
        .on_request("search", |req| async move {
            let query = String::from_utf8_lossy(&req.body);
            Ok(format!("results for: {query}").into_bytes())
        })
        .await;

    alice
        .on_request("echo", |req| async move { Ok(req.body.clone()) })
        .await;

    // Listen on port 0 — OS assigns a free port
    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .expect("alice listen failed");
    println!("Alice listening on {alice_addr}");

    // Alice creates an invite with the actual bound address
    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["search".into(), "echo".into()],
            max_claims: 1,
            expires_in: Some(Duration::from_secs(3600)),
            connection_hints: vec![alice_addr.to_string()],
        })
        .expect("create invite failed");

    let invite_link = token.to_link().expect("to_link failed");
    println!("Invite link created");

    // --- Bob (client/claimer) ---
    let bob = make_node(&dir, "bob");

    // Bob claims the invite
    let peer = bob
        .claim_invite(&invite_link)
        .await
        .expect("claim invite failed");

    println!("Bob connected to Alice: {:?}", peer.scopes);
    assert_eq!(peer.scopes, vec!["search", "echo"]);

    // Bob sends a search request
    let response = peer
        .request("search", b"rust async patterns")
        .await
        .expect("search request failed");
    let response_str = String::from_utf8_lossy(&response);
    assert_eq!(response_str, "results for: rust async patterns");
    println!("Search response: {response_str}");

    // Bob sends an echo request
    let echo_response = peer
        .request("echo", b"hello hypha")
        .await
        .expect("echo request failed");
    assert_eq!(echo_response, b"hello hypha");
    println!("Echo response OK");
}

#[tokio::test]
async fn test_forbidden_scope() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    alice
        .on_request("search", |_req| async move { Ok(b"ok".to_vec()) })
        .await;

    alice
        .on_request("admin", |_req| async move { Ok(b"secret stuff".to_vec()) })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Invite only grants "search" scope
    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["search".into()],
            max_claims: 1,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&token.to_link().unwrap()).await.unwrap();

    // Search should work
    let result = peer.request("search", b"test").await;
    assert!(result.is_ok());

    // Admin should be forbidden
    let result = peer.request("admin", b"hack").await;
    assert!(matches!(result, Err(hypha::HyphaError::Forbidden { .. })));
    println!("Forbidden scope correctly rejected");
}

#[tokio::test]
async fn test_invite_max_claims_enforced() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    alice
        .on_request("ping", |_| async move { Ok(b"pong".to_vec()) })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Invite with max_claims = 1
    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["ping".into()],
            max_claims: 1,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let link = token.to_link().unwrap();

    // First claim should succeed
    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&link).await;
    assert!(peer.is_ok(), "First claim failed: {:?}", peer.err());

    // Second claim with same invite should fail
    let charlie = make_node(&dir, "charlie");
    let result = charlie.claim_invite(&link).await;
    assert!(result.is_err(), "Second claim should have failed");
    println!("Max claims correctly enforced");
}

#[tokio::test]
async fn test_revocation() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    alice
        .on_request("ping", |_| async move { Ok(b"pong".to_vec()) })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["ping".into()],
            max_claims: 5,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let link = token.to_link().unwrap();

    // Bob claims before revocation — should work
    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&link).await;
    assert!(peer.is_ok(), "Pre-revocation claim failed: {:?}", peer.err());

    // Alice revokes the token
    alice.revoke(&token.token_id).expect("revoke failed");

    // Charlie tries to claim after revocation — should fail
    let charlie = make_node(&dir, "charlie");
    let result = charlie.claim_invite(&link).await;
    assert!(result.is_err(), "Post-revocation claim should have failed");
    println!("Revocation correctly enforced");
}
