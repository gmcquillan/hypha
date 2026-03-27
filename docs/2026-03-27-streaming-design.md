# Streaming (Subscribe/Event/Unsubscribe) Design

## Summary

Add streaming support to Hypha: peers can open long-lived subscriptions to receive a series of events from another peer. Builds on the existing wire format (Subscribe, Event, Unsubscribe messages are already defined) and follows the same patterns as request/response.

## Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Backpressure model | Bounded channel with drop counting | Producer is never blocked by a slow/malicious remote peer. `dropped_count` lets subscriber detect gaps and recover. Same model as broadcast systems and real-time telemetry. |
| Directionality | Either side can subscribe (symmetric) | Matches how requests already work. In a cooperation network either peer may have data the other wants. |
| Mid-stream updates | Not supported | Subscriber sends `Subscribe`, receives `Event`s, sends `Unsubscribe`. To change filters, unsubscribe and resubscribe. Keeps the model simple. |
| Transport mapping | One bidi QUIC stream per subscription | QUIC streams are cheap and provide per-stream flow control. Stream lifetime = subscription lifetime. Matches the one-stream-per-request pattern already in use. |
| Default buffer size | 64 events | Configurable per subscription via the handler. Large enough for normal operation, small enough to bound memory. |

## Subscription Lifecycle

1. Subscriber opens a bidi QUIC stream.
2. Subscriber sends `Subscribe { sub_id, scope, body }`.
3. Producer checks scope against peer's granted capabilities.
   - If unauthorized: sends `Response { req_id: 0, status: FORBIDDEN, body }`, closes stream. Subscriber gets `Err(HyphaError::Forbidden)`.
   - If no handler registered: sends `Response { req_id: 0, status: NOT_FOUND, body }`, closes stream. Subscriber gets `Err(HyphaError::RemoteError)`.
4. Producer dispatches to the registered handler. Handler returns a `Receiver<Vec<u8>>`.
5. Producer sends `Response { req_id: 0, status: OK, body: [] }` as an acknowledgment that the subscription is active. This unblocks the subscriber before any events arrive.
6. Producer's event send loop reads from the receiver and writes `Event { sub_id, body, dropped_count }` messages to the stream.
7. If the bounded channel is full when the application tries to send, the event is dropped and an internal counter increments. The next successfully sent event carries the accumulated `dropped_count`, then the counter resets to 0.
8. Termination (any of these):
   - Subscriber sends `Unsubscribe { sub_id }` -- producer drops the receiver, handler's sender errors on next send.
   - Subscriber closes or resets the stream -- same effect.
   - Handler drops its sender -- producer's event loop sees the receiver end, closes its send side. Subscriber's `next()` returns `None`.
   - Connection lost -- QUIC stream errors propagate to both sides.

## Wire Messages (already defined)

These messages already exist in `messages.rs`. No wire format changes needed.

```
Subscribe { sub_id: u32, scope: String, body: Vec<u8> }
Event     { sub_id: u32, body: Vec<u8>, dropped_count: u32 }
Unsubscribe { sub_id: u32 }
```

Scope rejection reuses the existing `Response` message with `FORBIDDEN` or `NOT_FOUND` status (with `req_id: 0` since there's no request ID in the subscription flow).

## Producer-Side Architecture

### Handler Registration

Application registers subscribe handlers on `HyphaNode`, mirroring `on_request`:

```rust
node.on_subscribe("index:updates", |sub: Subscription| async move {
    let (tx, rx) = sub.channel(64); // bounded channel, 64-event buffer

    // Application pushes events into tx on its own schedule.
    // When tx is dropped, the subscription ends.
    // If the channel is full, tx.try_send() fails and the drop counter increments.

    Ok(rx)
}).await;
```

### Subscription Struct (passed to handler)

```rust
pub struct Subscription {
    pub sub_id: u32,
    pub scope: String,
    pub body: Vec<u8>,
}
```

`Subscription::channel(buffer_size)` returns `(SubscriptionSender, Receiver<Vec<u8>>)`. The `SubscriptionSender` wraps a bounded `tokio::sync::mpsc::Sender` and tracks drop counts internally.

### SubscriptionSender

```rust
pub struct SubscriptionSender {
    tx: tokio::sync::mpsc::Sender<Vec<u8>>,
    dropped: Arc<AtomicU32>,
}
```

`SubscriptionSender::send(&self, data: Vec<u8>)` attempts `tx.try_send()`. On failure (channel full), increments `dropped` and returns `Ok(())` (non-blocking, never errors from backpressure). Only errors if the receiver is closed (subscription ended).

### Event Send Loop (runtime-owned)

The runtime spawns a task per subscription that:

1. Reads from the `Receiver<Vec<u8>>`
2. Reads and resets the `dropped` counter
3. Writes `Event { sub_id, body, dropped_count }` to the QUIC send stream
4. On receiver close (handler dropped sender): closes the send side, exits
5. On write error (subscriber gone): exits (cleanup happens automatically)

Concurrently, it reads from the QUIC recv stream watching for `Unsubscribe`. On receipt, it drops the receiver and exits.

### StreamManager

```rust
pub struct StreamManager {
    handlers: RwLock<HashMap<String, SubscribeHandlerFn>>,
    next_sub_id: Mutex<u32>,
}
```

Mirrors `Exchange` in structure. Owns handler registration and sub_id allocation for the producer side.

## Subscriber-Side API

### Opening a Subscription

```rust
let mut sub = peer.subscribe("index:updates", b"filter=rust").await?;
```

`peer.subscribe()`:
1. Allocates a `sub_id` (atomic counter on the subscriber side)
2. Opens a bidi QUIC stream
3. Sends `Subscribe { sub_id, scope, body }`
4. Reads the first message from the recv stream (the ack)
   - If `Response` with `OK`: subscription accepted, return `SubscriptionStream`
   - If `Response` with `FORBIDDEN`: return `Err(HyphaError::Forbidden)`
   - If `Response` with `NOT_FOUND`: return `Err(HyphaError::RemoteError)`
5. Returns `SubscriptionStream`

### SubscriptionStream

```rust
pub struct SubscriptionStream {
    sub_id: u32,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    unsubscribed: bool,
    // No buffering needed -- ack/reject is a Response, events come after
}
```

**`next(&mut self) -> Option<EventData>`** -- Reads the next `Event` message from the recv stream. Returns `None` when the producer closes its send side. Returns `Some(EventData { body, dropped_count })`.

**`unsubscribe(&mut self)`** -- Sends `Unsubscribe { sub_id }`, sets `unsubscribed = true`.

**`Drop`** -- If `unsubscribed` is false, resets the QUIC stream (best-effort, non-async). The producer sees the reset and cleans up.

### EventData (returned to subscriber)

```rust
pub struct EventData {
    pub body: Vec<u8>,
    pub dropped_count: u32,
}
```

## Changes to Existing Modules

### `node.rs`

- Add `StreamManager` to `HyphaNode` (alongside existing `Exchange`)
- Add `on_subscribe()` method to `HyphaNode` (mirrors `on_request()`)
- Add `subscribe()` method to `Peer`
- In `handle_connection`'s message loop, match `Message::Subscribe` and dispatch to `StreamManager`

### `lib.rs`

- Add `pub mod stream;`
- Re-export `SubscriptionStream` and `EventData` if appropriate

### No changes to:

- `messages.rs` (wire format already defined)
- `exchange.rs` (streaming is independent)
- `capability.rs`, `crypto.rs`, `handshake.rs`, `transport.rs`, `store.rs`, `discovery.rs`

## New Module: `stream.rs`

Contains:
- `SubscribeHandlerFn` type alias
- `StreamManager` struct
- `Subscription` struct (handler input)
- `SubscriptionSender` struct (application sends events through this)
- `SubscriptionStream` struct (subscriber receives events through this)
- `EventData` struct
- `handle_subscribe()` function (scope enforcement, handler dispatch, event send loop)

## Testing Plan

### Integration Tests

1. **`test_subscribe_receive_events`** -- Alice registers a handler that sends 3 events then drops the sender. Bob subscribes, receives all 3, `next()` returns `None`.

2. **`test_subscribe_forbidden_scope`** -- Bob has `["search"]` scope, tries to subscribe to `"admin"`. Gets `Forbidden` error.

3. **`test_subscribe_backpressure_drops`** -- Alice's handler sends events faster than Bob reads (Bob sleeps between reads). Bob sees `dropped_count > 0` on a subsequent event.

4. **`test_subscribe_unsubscribe_cleanup`** -- Bob subscribes, receives some events, calls `unsubscribe()`. Alice's handler sees its sender fail on next send.

### Unit Tests (in `stream.rs`)

- Handler registration and lookup
- `sub_id` allocation increments
- `SubscriptionSender` drop counting (send to full channel, verify count)
