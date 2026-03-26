use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{oneshot, Mutex, RwLock};

use crate::messages::{self, Message, Request, Response};
use crate::Result;

/// Type alias for an async request handler function.
pub type HandlerFn = Arc<
    dyn Fn(Request) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send>> + Send + Sync,
>;

/// Manages registered request handlers and scope enforcement.
pub struct Exchange {
    handlers: RwLock<HashMap<String, HandlerFn>>,
    pending_responses: Mutex<HashMap<u32, oneshot::Sender<Response>>>,
    next_req_id: Mutex<u32>,
}

impl Default for Exchange {
    fn default() -> Self {
        Self::new()
    }
}

impl Exchange {
    pub fn new() -> Self {
        Self {
            handlers: RwLock::new(HashMap::new()),
            pending_responses: Mutex::new(HashMap::new()),
            next_req_id: Mutex::new(1),
        }
    }

    /// Register a handler for a scope.
    pub async fn register_handler(&self, scope: &str, handler: HandlerFn) {
        self.handlers
            .write()
            .await
            .insert(scope.to_string(), handler);
    }

    /// Allocate a new request ID and register a response channel.
    pub async fn prepare_request(&self) -> (u32, oneshot::Receiver<Response>) {
        let mut id = self.next_req_id.lock().await;
        let req_id = *id;
        *id = id.wrapping_add(1);

        let (tx, rx) = oneshot::channel();
        self.pending_responses.lock().await.insert(req_id, tx);
        (req_id, rx)
    }

    /// Handle an incoming request — enforce scope, dispatch to handler.
    pub async fn handle_request(
        &self,
        req: Request,
        peer_scopes: &[String],
        send: &mut quinn::SendStream,
    ) -> Result<()> {
        // Scope enforcement
        if !peer_scopes.contains(&req.scope) {
            let response = Message::Response(Response {
                req_id: req.req_id,
                status: crate::messages::status::FORBIDDEN,
                body: format!("scope '{}' not granted", req.scope).into_bytes(),
            });
            messages::write_message(send, &response).await?;
            return Ok(());
        }

        // Dispatch to handler
        let handlers = self.handlers.read().await;
        if let Some(handler) = handlers.get(&req.scope) {
            let handler = handler.clone();
            let req_id = req.req_id;
            match handler(req).await {
                Ok(body) => {
                    let response = Message::Response(Response {
                        req_id,
                        status: crate::messages::status::OK,
                        body,
                    });
                    messages::write_message(send, &response).await?;
                }
                Err(e) => {
                    let response = Message::Response(Response {
                        req_id,
                        status: crate::messages::status::ERROR,
                        body: e.to_string().into_bytes(),
                    });
                    messages::write_message(send, &response).await?;
                }
            }
        } else {
            let response = Message::Response(Response {
                req_id: req.req_id,
                status: crate::messages::status::NOT_FOUND,
                body: format!("no handler for scope '{}'", req.scope).into_bytes(),
            });
            messages::write_message(send, &response).await?;
        }

        Ok(())
    }

    /// Handle an incoming response — route to the waiting caller.
    pub async fn handle_response(&self, resp: Response) {
        let mut pending = self.pending_responses.lock().await;
        if let Some(tx) = pending.remove(&resp.req_id) {
            let _ = tx.send(resp);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_lookup_handler() {
        let exchange = Exchange::new();
        let handler: HandlerFn = Arc::new(|_req| Box::pin(async { Ok(b"pong".to_vec()) }));
        exchange.register_handler("ping", handler).await;

        let handlers = exchange.handlers.read().await;
        assert!(handlers.contains_key("ping"));
        assert!(!handlers.contains_key("unknown"));
    }

    #[tokio::test]
    async fn test_request_id_allocation() {
        let exchange = Exchange::new();
        let (id1, _rx1) = exchange.prepare_request().await;
        let (id2, _rx2) = exchange.prepare_request().await;
        assert_eq!(id1, 1);
        assert_eq!(id2, 2);
    }

    #[tokio::test]
    async fn test_response_routing() {
        let exchange = Exchange::new();
        let (req_id, rx) = exchange.prepare_request().await;

        let response = Response {
            req_id,
            status: crate::messages::status::OK,
            body: b"result".to_vec(),
        };
        exchange.handle_response(response).await;

        let received = rx.await.unwrap();
        assert_eq!(received.body, b"result");
    }
}
