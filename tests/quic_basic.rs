use hypha::crypto::NodeKeypair;
use hypha::transport;
use std::net::SocketAddr;

#[tokio::test]
async fn test_basic_quic_connection() {
    let kp = NodeKeypair::generate();
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();

    let server = transport::make_server_endpoint(&kp, addr).unwrap();
    let server_addr = server.local_addr().unwrap();

    let (tx, rx) = tokio::sync::oneshot::channel::<Vec<u8>>();

    // Server accepts one stream, echoes data, signals completion
    let server_task = tokio::spawn(async move {
        let incoming = server.accept().await.unwrap();
        let conn = incoming.await.unwrap();
        let (mut send, mut recv) = conn.accept_bi().await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = recv.read(&mut buf).await.unwrap().unwrap();
        send.write_all(&buf[..n]).await.unwrap();
        send.finish().unwrap();
        // Wait for client to confirm receipt before dropping
        rx.await.unwrap();
    });

    // Client connects, sends data, reads echo
    let client_bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let client = transport::make_client_endpoint(client_bind).unwrap();

    let conn = client
        .connect(server_addr, "hypha.local")
        .unwrap()
        .await
        .unwrap();

    let (mut send, mut recv) = conn.open_bi().await.unwrap();
    send.write_all(b"hello").await.unwrap();
    send.finish().unwrap();

    let data = recv.read_to_end(1024).await.unwrap();
    assert_eq!(data, b"hello");

    // Signal server it's safe to drop
    tx.send(data).unwrap();
    server_task.await.unwrap();
}
