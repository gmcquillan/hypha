# Streaming Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Subscribe/Event/Unsubscribe streaming to Hypha so peers can open long-lived subscriptions with bounded backpressure and drop counting.

**Architecture:** New `stream.rs` module contains all streaming types and logic (StreamManager, Subscription, SubscriptionSender, SubscriptionStream, EventData). `node.rs` gains `on_subscribe()` and `Peer::subscribe()` methods plus Subscribe dispatch in the connection handler. Wire messages already exist in `messages.rs`.

**Tech Stack:** Rust, tokio (mpsc channels, select!, spawn), quinn (QUIC bidi streams), existing CBOR wire format.

**Spec:** `docs/2026-03-27-streaming-design.md`

---

## File Structure

| File | Action | Responsibility |
|------|--------|---------------|
| `src/stream.rs` | Create | StreamManager, SubscribeHandlerFn, Subscription, SubscriptionSender, SubscriptionStream, EventData, handle_subscribe(), event send loop |
| `src/lib.rs` | Modify (line 9, add module; line 11, add re-export) | Add `pub mod stream;` and re-export key types |
| `src/node.rs` | Modify | Add StreamManager to HyphaNode, on_subscribe() method, Peer::subscribe() method, Subscribe dispatch in handle_connection |
| `tests/integration.rs` | Modify | Add 4 streaming integration tests |

---

### Task 1: SubscriptionSender and drop counting

**Files:**
- Create: `src/stream.rs`
- Modify: `src/lib.rs`

- [ ] **Step 1: Create `src/stream.rs` with SubscriptionSender and unit tests**

Write the `SubscriptionSender` struct, `EventData` struct, and `Subscription` struct with its `channel()` method. Include unit tests for drop counting.

```rust
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::Result;

/// Data returned to the subscriber for each event.
pub struct EventData {
    pub body: Vec<u8>,
    pub dropped_count: u32,
}

/// Passed to subscribe handlers. Contains the subscription request details.
pub struct Subscription {
    pub sub_id: u32,
    pub scope: String,
    pub body: Vec<u8>,
}

impl Subscription {
    /// Create a bounded channel for sending events to this subscriber.
    /// Returns a sender (for the application) and a receiver (for the runtime's event loop).
    pub fn channel(&self, buffer_size: usize) -> (SubscriptionSender, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(buffer_size);
        let sender = SubscriptionSender {
            tx,
            dropped: Arc::new(AtomicU32::new(0)),
        };
        (sender, rx)
    }
}

/// Application-facing sender for pushing events into a subscription.
/// Never blocks on backpressure -- drops events and counts them instead.
pub struct SubscriptionSender {
    tx: mpsc::Sender<Vec<u8>>,
    dropped: Arc<AtomicU32>,
}

impl SubscriptionSender {
    /// Send an event to the subscriber. If the channel is full, the event is
    /// dropped and the internal drop counter increments. Returns Err only if
    /// the subscription has ended (receiver closed).
    pub fn send(&self, data: Vec<u8>) -> Result<()> {
        match self.tx.try_send(data) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
                Ok(())
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                Err(crate::HyphaError::ConnectionLost)
            }
        }
    }

    /// Get a reference to the drop counter (used by the event send loop).
    pub(crate) fn dropped_counter(&self) -> Arc<AtomicU32> {
        self.dropped.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_subscription_sender_delivers_events() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        let (tx, mut rx) = sub.channel(8);

        tx.send(b"event1".to_vec()).unwrap();
        tx.send(b"event2".to_vec()).unwrap();

        assert_eq!(rx.recv().await.unwrap(), b"event1");
        assert_eq!(rx.recv().await.unwrap(), b"event2");
    }

    #[tokio::test]
    async fn test_subscription_sender_counts_drops() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        // Channel with buffer of 2
        let (tx, _rx) = sub.channel(2);

        // Fill the channel
        tx.send(b"event1".to_vec()).unwrap();
        tx.send(b"event2".to_vec()).unwrap();

        // These should be dropped
        tx.send(b"event3".to_vec()).unwrap();
        tx.send(b"event4".to_vec()).unwrap();
        tx.send(b"event5".to_vec()).unwrap();

        assert_eq!(tx.dropped.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_subscription_sender_errors_on_closed_receiver() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        let (tx, rx) = sub.channel(8);
        drop(rx);

        let result = tx.send(b"event".to_vec());
        assert!(result.is_err());
    }
}
```

- [ ] **Step 2: Add `pub mod stream;` to `src/lib.rs`**

Add after the existing `pub mod transport;` line (line 9 of `src/lib.rs`):

```rust
pub mod stream;
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test stream::tests -v`
Expected: 3 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/stream.rs src/lib.rs
git commit -m "feat: add SubscriptionSender with drop counting"
```

---

### Task 2: StreamManager (handler registration and sub_id allocation)

**Files:**
- Modify: `src/stream.rs`

- [ ] **Step 1: Write unit tests for StreamManager**

Append to the `tests` module in `src/stream.rs`:

```rust
    #[tokio::test]
    async fn test_stream_manager_register_handler() {
        let mgr = StreamManager::new();
        let handler: SubscribeHandlerFn = Arc::new(|_sub| {
            Box::pin(async {
                let (_, rx) = mpsc::channel(8);
                Ok(rx)
            })
        });
        mgr.register_handler("events", handler).await;

        let handlers = mgr.handlers.read().await;
        assert!(handlers.contains_key("events"));
        assert!(!handlers.contains_key("unknown"));
    }

    #[tokio::test]
    async fn test_stream_manager_sub_id_allocation() {
        let mgr = StreamManager::new();
        let id1 = mgr.next_sub_id().await;
        let id2 = mgr.next_sub_id().await;
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test stream::tests -v`
Expected: FAIL -- `StreamManager` and `SubscribeHandlerFn` not defined

- [ ] **Step 3: Implement StreamManager**

Add to `src/stream.rs`, above the `tests` module:

```rust
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;

use tokio::sync::{Mutex, RwLock};

/// Type alias for an async subscribe handler function.
/// Receives a Subscription, returns a Receiver that the runtime reads events from.
pub type SubscribeHandlerFn = Arc<
    dyn Fn(Subscription) -> Pin<Box<dyn Future<Output = Result<mpsc::Receiver<Vec<u8>>>> + Send>>
        + Send
        + Sync,
>;

/// Manages registered subscribe handlers and sub_id allocation.
pub struct StreamManager {
    pub(crate) handlers: RwLock<HashMap<String, SubscribeHandlerFn>>,
    next_id: Mutex<u32>,
}

impl Default for StreamManager {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamManager {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            next_id: Mutex::new(1),
        }
    }

    /// Register a handler for a subscribe scope.
    pub async fn register_handler(&self, scope: &str, handler: SubscribeHandlerFn) {
        self.handlers
            .write()
            .await
            .insert(scope.to_string(), handler);
    }

    /// Allocate the next subscription ID.
    pub async fn next_sub_id(&self) -> u32 {
        let mut id = self.next_id.lock().await;
        let sub_id = *id;
        *id = id.wrapping_add(1);
        sub_id
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test stream::tests -v`
Expected: 5 tests pass (3 from Task 1 + 2 new)

- [ ] **Step 5: Commit**

```bash
git add src/stream.rs
git commit -m "feat: add StreamManager with handler registration"
```

---

### Task 3: handle_subscribe (producer-side dispatch and event send loop)

**Files:**
- Modify: `src/stream.rs`

- [ ] **Step 1: Add handle_subscribe function**

Add to `src/stream.rs`, below the `StreamManager` impl:

```rust
use crate::messages::{self, Message, Response, Event as EventMsg};

/// Handle an incoming Subscribe message on the producer side.
/// Checks scope, dispatches to handler, runs the event send loop.
pub async fn handle_subscribe(
    stream_mgr: &StreamManager,
    sub_msg: crate::messages::Subscribe,
    peer_scopes: &[String],
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let sub_id = sub_msg.sub_id;

    // Scope enforcement
    if !peer_scopes.contains(&sub_msg.scope) {
        let reject = Message::Response(Response {
            req_id: 0,
            status: crate::messages::status::FORBIDDEN,
            body: format!("scope '{}' not granted", sub_msg.scope).into_bytes(),
        });
        messages::write_message(&mut send, &reject).await?;
        return Ok(());
    }

    // Look up handler
    let handler = {
        let handlers = stream_mgr.handlers.read().await;
        handlers.get(&sub_msg.scope).cloned()
    };

    let handler = match handler {
        Some(h) => h,
        None => {
            let reject = Message::Response(Response {
                req_id: 0,
                status: crate::messages::status::NOT_FOUND,
                body: format!("no handler for scope '{}'", sub_msg.scope).into_bytes(),
            });
            messages::write_message(&mut send, &reject).await?;
            return Ok(());
        }
    };

    // Create Subscription and dispatch to handler
    let subscription = Subscription {
        sub_id: sub_msg.sub_id,
        scope: sub_msg.scope,
        body: sub_msg.body,
    };

    let mut event_rx = match handler(subscription).await {
        Ok(rx) => rx,
        Err(e) => {
            let reject = Message::Response(Response {
                req_id: 0,
                status: crate::messages::status::ERROR,
                body: e.to_string().into_bytes(),
            });
            messages::write_message(&mut send, &reject).await?;
            return Ok(());
        }
    };

    // Send OK ack -- subscription is active
    let ack = Message::Response(Response {
        req_id: 0,
        status: crate::messages::status::OK,
        body: vec![],
    });
    messages::write_message(&mut send, &ack).await?;

    // Event send loop: read from channel, write to QUIC stream.
    // Concurrently watch for Unsubscribe from the subscriber.
    let dropped = Arc::new(AtomicU32::new(0));

    loop {
        tokio::select! {
            event_data = event_rx.recv() => {
                match event_data {
                    Some(body) => {
                        let drop_count = dropped.swap(0, Ordering::Relaxed);
                        let event = Message::Event(EventMsg {
                            sub_id,
                            body,
                            dropped_count: drop_count,
                        });
                        if messages::write_message(&mut send, &event).await.is_err() {
                            break; // Subscriber gone
                        }
                    }
                    None => {
                        // Handler dropped its sender -- subscription ended
                        break;
                    }
                }
            }
            unsub = messages::read_message(&mut recv) => {
                match unsub {
                    Ok(Message::Unsubscribe(_)) => {
                        break; // Clean unsubscribe
                    }
                    _ => {
                        break; // Stream error or unexpected message
                    }
                }
            }
        }
    }

    Ok(())
}
```

Note: The `dropped` counter in `handle_subscribe` is internal to the event send loop. The `SubscriptionSender::dropped` counter is separate -- it's used when the application calls `SubscriptionSender::send()`. The handler's pattern is to create a `SubscriptionSender` via `sub.channel()`, spawn a task that calls `sender.send()`, and return the `rx`. The event send loop reads the `dropped` counter from the `SubscriptionSender` via the shared `Arc<AtomicU32>`.

We need to adjust the design: the handler needs to return both the receiver and the drop counter. Let's change the handler return type and `Subscription::channel()`:

Replace the `Subscription::channel()` method and `handle_subscribe` to thread the drop counter through properly:

```rust
impl Subscription {
    /// Create a bounded channel for sending events to this subscriber.
    /// Returns a sender (for the application) and a SubscriptionReceiver (for the runtime).
    pub fn channel(&self, buffer_size: usize) -> (SubscriptionSender, SubscriptionReceiver) {
        let (tx, rx) = mpsc::channel(buffer_size);
        let dropped = Arc::new(AtomicU32::new(0));
        let sender = SubscriptionSender {
            tx,
            dropped: dropped.clone(),
        };
        let receiver = SubscriptionReceiver {
            rx,
            dropped,
        };
        (sender, receiver)
    }
}

/// Runtime-side receiver that pairs with a SubscriptionSender.
/// Carries the shared drop counter so the event loop can read it.
pub struct SubscriptionReceiver {
    pub(crate) rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) dropped: Arc<AtomicU32>,
}
```

And update the handler type:

```rust
pub type SubscribeHandlerFn = Arc<
    dyn Fn(Subscription) -> Pin<Box<dyn Future<Output = Result<SubscriptionReceiver>> + Send>>
        + Send
        + Sync,
>;
```

- [ ] **Step 2: Update unit tests for the new SubscriptionReceiver type**

Update the existing `test_subscription_sender_delivers_events` test and the StreamManager test to use `SubscriptionReceiver`:

In `test_subscription_sender_delivers_events`:
```rust
    #[tokio::test]
    async fn test_subscription_sender_delivers_events() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        let (tx, mut sub_rx) = sub.channel(8);

        tx.send(b"event1".to_vec()).unwrap();
        tx.send(b"event2".to_vec()).unwrap();

        assert_eq!(sub_rx.rx.recv().await.unwrap(), b"event1");
        assert_eq!(sub_rx.rx.recv().await.unwrap(), b"event2");
    }
```

In `test_subscription_sender_errors_on_closed_receiver`:
```rust
    #[tokio::test]
    async fn test_subscription_sender_errors_on_closed_receiver() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        let (tx, sub_rx) = sub.channel(8);
        drop(sub_rx);

        let result = tx.send(b"event".to_vec());
        assert!(result.is_err());
    }
```

In `test_stream_manager_register_handler`:
```rust
    #[tokio::test]
    async fn test_stream_manager_register_handler() {
        let mgr = StreamManager::new();
        let handler: SubscribeHandlerFn = Arc::new(|sub| {
            Box::pin(async move {
                let (_, rx) = sub.channel(8);
                Ok(rx)
            })
        });
        mgr.register_handler("events", handler).await;

        let handlers = mgr.handlers.read().await;
        assert!(handlers.contains_key("events"));
        assert!(!handlers.contains_key("unknown"));
    }
```

- [ ] **Step 3: Run tests to verify they pass**

Run: `cargo test stream::tests -v`
Expected: 5 tests pass

- [ ] **Step 4: Commit**

```bash
git add src/stream.rs
git commit -m "feat: add handle_subscribe with event send loop"
```

---

### Task 4: SubscriptionStream (subscriber-side API)

**Files:**
- Modify: `src/stream.rs`

- [ ] **Step 1: Add SubscriptionStream and EventData to `src/stream.rs`**

Add below the `handle_subscribe` function:

```rust
/// Subscriber-side handle to an active subscription.
/// Call `next()` to receive events, `unsubscribe()` to stop.
pub struct SubscriptionStream {
    sub_id: u32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    unsubscribed: bool,
}

impl SubscriptionStream {
    /// Create a new SubscriptionStream (called internally by Peer::subscribe).
    pub(crate) fn new(
        sub_id: u32,
        send: quinn::SendStream,
        recv: quinn::RecvStream,
    ) -> Self {
        Self {
            sub_id,
            send,
            recv,
            unsubscribed: false,
        }
    }

    /// Receive the next event. Returns None when the producer ends the subscription.
    pub async fn next(&mut self) -> Option<EventData> {
        match messages::read_message(&mut self.recv).await {
            Ok(Message::Event(e)) => Some(EventData {
                body: e.body,
                dropped_count: e.dropped_count,
            }),
            _ => None, // Stream closed, error, or unexpected message
        }
    }

    /// Explicitly unsubscribe. Sends the Unsubscribe message to the producer.
    pub async fn unsubscribe(&mut self) -> Result<()> {
        if !self.unsubscribed {
            let msg = Message::Unsubscribe(crate::messages::Unsubscribe {
                sub_id: self.sub_id,
            });
            // Best-effort send -- if the stream is already closed, that's fine
            let _ = messages::write_message(&mut self.send, &msg).await;
            self.unsubscribed = true;
        }
        Ok(())
    }
}

impl Drop for SubscriptionStream {
    fn drop(&mut self) {
        if !self.unsubscribed {
            // Best-effort: reset the stream to signal the producer.
            // We can't send Unsubscribe here (async), but resetting the
            // QUIC stream causes the producer's recv/send to error out.
            let _ = self.send.reset(quinn::VarInt::from_u32(0));
        }
    }
}
```

- [ ] **Step 2: Run `cargo check` to verify it compiles**

Run: `cargo check`
Expected: No errors

- [ ] **Step 3: Commit**

```bash
git add src/stream.rs
git commit -m "feat: add SubscriptionStream subscriber-side API"
```

---

### Task 5: Wire into HyphaNode and Peer

**Files:**
- Modify: `src/node.rs`

- [ ] **Step 1: Add StreamManager to HyphaNode**

In `src/node.rs`, add the import at the top (alongside the existing exchange import):

```rust
use crate::stream::{self, StreamManager, SubscribeHandlerFn, SubscriptionStream};
```

Add `stream_mgr` field to `HyphaNode` struct:

```rust
pub struct HyphaNode {
    keypair: Arc<NodeKeypair>,
    store: Arc<PeerStore>,
    exchange: Arc<Exchange>,
    stream_mgr: Arc<StreamManager>,
    key_created_at: u64,
    endpoint: Option<quinn::Endpoint>,
}
```

Update `HyphaNode::open()` to initialize it:

```rust
        Ok(Self {
            keypair: Arc::new(keypair),
            store: Arc::new(store),
            exchange: Arc::new(Exchange::new()),
            stream_mgr: Arc::new(StreamManager::new()),
            key_created_at: config.key_created_at,
            endpoint: None,
        })
```

- [ ] **Step 2: Add `on_subscribe()` method to HyphaNode**

Add after the existing `on_request` method:

```rust
    /// Register a subscribe handler for a scope.
    pub async fn on_subscribe<F, Fut>(&self, scope: &str, handler: F)
    where
        F: Fn(stream::Subscription) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<stream::SubscriptionReceiver>> + Send + 'static,
    {
        let handler: SubscribeHandlerFn = Arc::new(move |sub| Box::pin(handler(sub)));
        self.stream_mgr.register_handler(scope, handler).await;
    }
```

- [ ] **Step 3: Add `subscribe()` method to Peer**

Add `stream_mgr` field to `Peer`:

```rust
pub struct Peer {
    pub pubkey: [u8; 32],
    pub scopes: Vec<String>,
    pub token_id: Vec<u8>,
    connection: quinn::Connection,
    exchange: Arc<Exchange>,
    stream_mgr: Arc<StreamManager>,
}
```

Add the `subscribe` method to the `Peer` impl block:

```rust
    /// Open a subscription to this peer for the given scope.
    pub async fn subscribe(&self, scope: &str, body: &[u8]) -> Result<SubscriptionStream> {
        let sub_id = self.stream_mgr.next_sub_id().await;

        // Open a bidi stream for this subscription
        let (mut send, mut recv) = self
            .connection
            .open_bi()
            .await
            .map_err(|_| HyphaError::ConnectionLost)?;

        // Send Subscribe message
        let msg = Message::Subscribe(messages::Subscribe {
            sub_id,
            scope: scope.to_string(),
            body: body.to_vec(),
        });
        messages::write_message(&mut send, &msg).await?;

        // Read the ack/reject response
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
```

- [ ] **Step 4: Update Peer construction sites to include stream_mgr**

In `claim_invite` (the `Ok(Peer { ... })` block near the end of `connect_and_claim`), add the `stream_mgr` field:

```rust
        Ok(Peer {
            pubkey: issuer_pubkey,
            scopes: welcome.capabilities,
            token_id: token.token_id.clone(),
            connection,
            exchange: self.exchange.clone(),
            stream_mgr: self.stream_mgr.clone(),
        })
```

- [ ] **Step 5: Pass StreamManager into handle_connection and dispatch Subscribe messages**

Update `handle_connection` signature to accept `stream_mgr`:

```rust
async fn handle_connection(
    conn: quinn::Connection,
    keypair: &NodeKeypair,
    store: &PeerStore,
    exchange: &Exchange,
    stream_mgr: Arc<StreamManager>,
    key_created_at: u64,
) -> Result<()> {
```

Update the `listen()` method to clone and pass `stream_mgr`:

```rust
        let stream_mgr = self.stream_mgr.clone();

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
```

In the message processing loop inside `handle_connection`, add the `Subscribe` match arm. The key difference from Request handling: Subscribe dispatches into `handle_subscribe` which takes ownership of the send/recv streams (it runs the event loop on them). So we spawn it as a separate task instead of handling it inline:

```rust
                    Ok(Message::Subscribe(sub_msg)) => {
                        let scopes = peer.scopes.clone();
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
```

This goes in the `match messages::read_message(...)` block, alongside the existing `Ok(Message::Request(req))` arm.

- [ ] **Step 6: Run `cargo check` to verify compilation**

Run: `cargo check`
Expected: No errors

- [ ] **Step 7: Run existing tests to verify no regressions**

Run: `cargo test`
Expected: All existing tests pass

- [ ] **Step 8: Commit**

```bash
git add src/node.rs
git commit -m "feat: wire streaming into HyphaNode and Peer"
```

---

### Task 6: Integration test -- basic subscribe/receive/end

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Write the test**

Add to `tests/integration.rs`:

```rust
#[tokio::test]
async fn test_subscribe_receive_events() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    // Register a subscribe handler that sends 3 events then ends
    alice
        .on_subscribe("events", |sub| async move {
            let (tx, rx) = sub.channel(64);
            tokio::spawn(async move {
                for i in 0..3 {
                    if tx.send(format!("event-{i}").into_bytes()).is_err() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                // tx is dropped here -- subscription ends
            });
            Ok(rx)
        })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["events".into()],
            max_claims: 1,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&token.to_link().unwrap()).await.unwrap();

    let mut sub = peer.subscribe("events", b"").await.unwrap();

    // Receive all 3 events
    let e1 = sub.next().await.unwrap();
    assert_eq!(e1.body, b"event-0");
    assert_eq!(e1.dropped_count, 0);

    let e2 = sub.next().await.unwrap();
    assert_eq!(e2.body, b"event-1");

    let e3 = sub.next().await.unwrap();
    assert_eq!(e3.body, b"event-2");

    // Producer ended -- next returns None
    let end = sub.next().await;
    assert!(end.is_none());
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test test_subscribe_receive_events -- --nocapture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add basic subscribe/receive/end integration test"
```

---

### Task 7: Integration test -- subscribe forbidden scope

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Write the test**

Add to `tests/integration.rs`:

```rust
#[tokio::test]
async fn test_subscribe_forbidden_scope() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    alice
        .on_subscribe("secret", |sub| async move {
            let (_, rx) = sub.channel(8);
            Ok(rx)
        })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    // Only grant "search" scope, not "secret"
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

    let result = peer.subscribe("secret", b"").await;
    assert!(matches!(result, Err(hypha::HyphaError::Forbidden { .. })));
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test test_subscribe_forbidden_scope -- --nocapture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add subscribe forbidden scope test"
```

---

### Task 8: Integration test -- backpressure drop counting

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Write the test**

Add to `tests/integration.rs`:

```rust
#[tokio::test]
async fn test_subscribe_backpressure_drops() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    // Handler with a tiny buffer (2) that sends many events quickly
    alice
        .on_subscribe("firehose", |sub| async move {
            let (tx, rx) = sub.channel(2);
            tokio::spawn(async move {
                for i in 0..20 {
                    if tx.send(format!("evt-{i}").into_bytes()).is_err() {
                        break;
                    }
                }
                // Keep tx alive so the subscription doesn't end immediately.
                // Wait for the subscriber to unsubscribe or disconnect.
                tokio::time::sleep(Duration::from_secs(5)).await;
                drop(tx);
            });
            Ok(rx)
        })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["firehose".into()],
            max_claims: 1,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&token.to_link().unwrap()).await.unwrap();

    let mut sub = peer.subscribe("firehose", b"").await.unwrap();

    // Read events -- at least one should show dropped_count > 0
    let mut saw_drops = false;
    for _ in 0..10 {
        match sub.next().await {
            Some(e) => {
                if e.dropped_count > 0 {
                    saw_drops = true;
                    break;
                }
            }
            None => break,
        }
    }

    assert!(saw_drops, "expected to see dropped events due to backpressure");
    sub.unsubscribe().await.unwrap();
}
```

- [ ] **Step 2: Run the test**

Run: `cargo test test_subscribe_backpressure_drops -- --nocapture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add backpressure drop counting test"
```

---

### Task 9: Integration test -- unsubscribe cleanup

**Files:**
- Modify: `tests/integration.rs`

- [ ] **Step 1: Write the test**

Add to `tests/integration.rs`:

```rust
#[tokio::test]
async fn test_subscribe_unsubscribe_cleanup() {
    let dir = TempDir::new().unwrap();

    let mut alice = make_node(&dir, "alice");

    let sender_done = Arc::new(tokio::sync::Notify::new());
    let sender_done_clone = sender_done.clone();

    // Handler that sends events in a loop until the subscription ends
    alice
        .on_subscribe("stream", |sub| async move {
            let (tx, rx) = sub.channel(64);
            let done = sender_done_clone;
            tokio::spawn(async move {
                let mut i = 0u32;
                loop {
                    if tx.send(format!("msg-{i}").into_bytes()).is_err() {
                        break; // Receiver dropped (unsubscribed)
                    }
                    i += 1;
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                done.notify_one();
            });
            Ok(rx)
        })
        .await;

    let alice_addr = alice
        .listen("127.0.0.1:0".parse().unwrap())
        .await
        .unwrap();

    let token = alice
        .create_invite(InviteConfig {
            scopes: vec!["stream".into()],
            max_claims: 1,
            expires_in: None,
            connection_hints: vec![alice_addr.to_string()],
        })
        .unwrap();

    let bob = make_node(&dir, "bob");
    let peer = bob.claim_invite(&token.to_link().unwrap()).await.unwrap();

    let mut sub = peer.subscribe("stream", b"").await.unwrap();

    // Read a few events
    let e1 = sub.next().await.unwrap();
    assert!(e1.body.starts_with(b"msg-"));

    let _e2 = sub.next().await.unwrap();

    // Unsubscribe
    sub.unsubscribe().await.unwrap();

    // The producer's sender should detect the unsubscribe and exit.
    // Wait up to 2 seconds for the notification.
    tokio::time::timeout(Duration::from_secs(2), sender_done.notified())
        .await
        .expect("producer did not detect unsubscribe within timeout");
}
```

Note: This test requires `use std::sync::Arc;` at the top of the test file. Check if it's already imported -- if not, add it.

- [ ] **Step 2: Run the test**

Run: `cargo test test_subscribe_unsubscribe_cleanup -- --nocapture`
Expected: PASS

- [ ] **Step 3: Commit**

```bash
git add tests/integration.rs
git commit -m "test: add unsubscribe cleanup test"
```

---

### Task 10: Run full test suite and final commit

- [ ] **Step 1: Run all tests**

Run: `cargo test`
Expected: All tests pass (existing + 9 new)

- [ ] **Step 2: Run clippy**

Run: `cargo clippy -- -D warnings`
Expected: No warnings

- [ ] **Step 3: Fix any clippy issues if needed**

- [ ] **Step 4: Final commit if any cleanup was needed**

```bash
git add -A
git commit -m "chore: clippy cleanup for streaming feature"
```
