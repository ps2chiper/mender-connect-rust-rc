//! Local-socket tests for the websocket heartbeat primitives.

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, encode};
use mender_connect_rust::transport::{Transport, TransportEvent};

const TEST_TIMEOUT: Duration = Duration::from_secs(3);

/// Server sends a Ping and waits for the client's automatic Pong. The client
/// must report the Ping event and the server must observe the matching reply.
#[tokio::test]
async fn server_ping_is_flushed_and_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        ws.send(Message::Ping(b"hb-1".to_vec().into()))
            .await
            .unwrap();

        let msg = tokio::time::timeout(TEST_TIMEOUT, ws.next())
            .await
            .expect("timed out waiting for the automatic pong")
            .expect("stream ended before the pong")
            .expect("websocket error while waiting for the pong");

        match msg {
            Message::Pong(payload) => assert_eq!(&payload[..], b"hb-1"),
            other => panic!("expected pong, got {other:?}"),
        }
    });

    let url = format!("ws://{addr}");
    let mut transport = Transport::connect(&url, "token").await.unwrap();

    let event = tokio::time::timeout(TEST_TIMEOUT, transport.receive_event())
        .await
        .expect("timed out waiting for the ping event")
        .expect("receive_event failed");

    assert!(matches!(event, TransportEvent::Ping));

    server.await.unwrap();
}

/// Client `send_ping` produces a real websocket Ping observed by the server;
/// the server's Pong is surfaced as a `Pong` event.
#[tokio::test]
async fn client_ping_round_trip() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        let msg = tokio::time::timeout(TEST_TIMEOUT, ws.next())
            .await
            .expect("timed out waiting for the client ping")
            .expect("stream ended before the ping")
            .expect("websocket error while waiting for the ping");

        match msg {
            Message::Ping(payload) => {
                assert_eq!(&payload[..], b"ping-payload");
                // Flush the automatic pong queued by tungstenite on read.
                ws.flush().await.unwrap();
            }
            other => panic!("expected ping, got {other:?}"),
        }
    });

    let url = format!("ws://{addr}");
    let mut transport = Transport::connect(&url, "token").await.unwrap();

    transport.send_ping(b"ping-payload").await.unwrap();

    let event = tokio::time::timeout(TEST_TIMEOUT, transport.receive_event())
        .await
        .expect("timed out waiting for the pong event")
        .expect("receive_event failed");

    assert!(matches!(event, TransportEvent::Pong));

    server.await.unwrap();
}

/// Oversized ping payloads are rejected locally before any write.
#[tokio::test]
async fn oversized_ping_payload_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let _ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        tokio::time::sleep(TEST_TIMEOUT).await;
    });

    let url = format!("ws://{addr}");
    let mut transport = Transport::connect(&url, "token").await.unwrap();

    let payload = vec![0u8; 126];
    let result = transport.send_ping(&payload).await;
    assert!(result.is_err(), "oversized ping payload must be rejected");

    server.abort();
}

/// The `receive` compatibility wrapper still delivers a binary application
/// message after intervening heartbeat frames.
#[tokio::test]
async fn receive_wrapper_skips_heartbeats() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();

        ws.send(Message::Ping(b"hb".to_vec().into())).await.unwrap();
        ws.send(Message::Pong(b"hb".to_vec().into())).await.unwrap();

        let application = ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::CONTROL,
                msg_type: "pong".to_owned(),
                session_id: "heartbeat-wrapper".to_owned(),
                ..ProtoHdr::default()
            },
            body: b"application marker".to_vec(),
        };
        let encoded = encode(&application).unwrap();
        ws.send(Message::Binary(encoded.into())).await.unwrap();

        // Drain the automatic pong produced by the client's ping handling.
        let _ = tokio::time::timeout(TEST_TIMEOUT, ws.next()).await;
    });

    let url = format!("ws://{addr}");
    let mut transport = Transport::connect(&url, "token").await.unwrap();

    let message = tokio::time::timeout(TEST_TIMEOUT, transport.receive())
        .await
        .expect("timed out waiting for the application message")
        .expect("receive failed");

    let message = message.expect("wrapper must deliver the application message");
    assert_eq!(message.header.proto, ProtoType::CONTROL);
    assert_eq!(message.header.msg_type, "pong");
    assert_eq!(message.header.session_id, "heartbeat-wrapper");
    assert_eq!(message.body, b"application marker");

    server.await.unwrap();
}
