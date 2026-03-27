use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::sync::{Mutex, RwLock};

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
    /// Returns a sender (for the application) and a SubscriptionReceiver (for the runtime).
    pub fn channel(&self, buffer_size: usize) -> (SubscriptionSender, SubscriptionReceiver) {
        let (tx, rx) = mpsc::channel(buffer_size);
        let dropped = Arc::new(AtomicU32::new(0));
        let sender = SubscriptionSender {
            tx,
            dropped: dropped.clone(),
        };
        let receiver = SubscriptionReceiver { rx, dropped };
        (sender, receiver)
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
            Err(mpsc::error::TrySendError::Closed(_)) => Err(crate::HyphaError::ConnectionLost),
        }
    }

    /// Get a reference to the drop counter (used by the event send loop).
    pub(crate) fn dropped_counter(&self) -> Arc<AtomicU32> {
        self.dropped.clone()
    }
}

/// Runtime-side receiver that pairs with a SubscriptionSender.
/// Carries the shared drop counter so the event loop can read it.
pub struct SubscriptionReceiver {
    pub(crate) rx: mpsc::Receiver<Vec<u8>>,
    pub(crate) dropped: Arc<AtomicU32>,
}

/// Type alias for an async subscribe handler function.
/// Receives a Subscription, returns a SubscriptionReceiver that the runtime reads events from.
pub type SubscribeHandlerFn = Arc<
    dyn Fn(Subscription) -> Pin<Box<dyn Future<Output = Result<SubscriptionReceiver>> + Send>>
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
        let (tx, mut sub_rx) = sub.channel(8);

        tx.send(b"event1".to_vec()).unwrap();
        tx.send(b"event2".to_vec()).unwrap();

        assert_eq!(sub_rx.rx.recv().await.unwrap(), b"event1");
        assert_eq!(sub_rx.rx.recv().await.unwrap(), b"event2");
    }

    #[tokio::test]
    async fn test_subscription_sender_counts_drops() {
        let sub = Subscription {
            sub_id: 1,
            scope: "test".into(),
            body: vec![],
        };
        let (tx, _rx) = sub.channel(2);

        tx.send(b"event1".to_vec()).unwrap();
        tx.send(b"event2".to_vec()).unwrap();

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
        let (tx, sub_rx) = sub.channel(8);
        drop(sub_rx);

        let result = tx.send(b"event".to_vec());
        assert!(result.is_err());
    }

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

    #[tokio::test]
    async fn test_stream_manager_sub_id_allocation() {
        let mgr = StreamManager::new();
        let id1 = mgr.next_sub_id().await;
        let id2 = mgr.next_sub_id().await;
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }
}
