//! Public-API integration tests for `PortForwardManager` lifecycle handling.
//!
//! Every helper returns `anyhow::Result`; no `unwrap`/`expect`/`panic` is used.
//! All socket waits are bounded by a two second timeout and no test spawns its
//! own tasks: the accepted sockets are owned directly by the test body, so the
//! read-only production code cannot leak server tasks.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

use mender_connect_rust::port_forward::ConnectionKey;
use mender_connect_rust::port_forward_manager::PortForwardManager;
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, encode};

/// Upper bound for any socket wait or event wait in these tests.
const STEP: Duration = Duration::from_secs(2);

fn is_v1(proto: &ProtoType) -> bool {
    matches!(*proto, ProtoType::PORT_FORWARD)
}

fn header(proto: &ProtoType, msg_type: &str, session: &str, id: &str) -> ProtoHdr {
    let mut properties = BTreeMap::new();
    properties.insert(
        "connection_id".to_owned(),
        Value::String(id.to_owned().into()),
    );
    ProtoHdr {
        proto: *proto,
        msg_type: msg_type.to_owned(),
        session_id: session.to_owned(),
        properties,
    }
}

fn key_of(proto: &ProtoType, session: &str, id: &str) -> Result<ConnectionKey> {
    let key = ConnectionKey::from_header(&header(proto, "new", session, id))?;
    ensure!(&key.proto() == proto, "key protocol correlation mismatch");
    ensure!(key.session() == session, "key session correlation mismatch");
    ensure!(key.id() == id, "key id correlation mismatch");
    Ok(key)
}

#[derive(serde::Serialize)]
struct NewBody<'a> {
    remote_host: &'a str,
    remote_port: u16,
    protocol: &'a str,
}

fn new_message(proto: &ProtoType, session: &str, id: &str, port: u16) -> Result<ProtoMsg> {
    let body = encode(&NewBody {
        remote_host: "127.0.0.1",
        remote_port: port,
        protocol: "tcp",
    })?;
    Ok(ProtoMsg {
        header: header(proto, "new", session, id),
        body,
    })
}

fn message(
    proto: &ProtoType,
    session: &str,
    id: &str,
    msg_type: &str,
    body: Vec<u8>,
) -> Result<ProtoMsg> {
    Ok(key_of(proto, session, id)?.message(msg_type, body))
}

fn assert_correlation(
    msg: &ProtoMsg,
    proto: &ProtoType,
    msg_type: &str,
    session: &str,
    id: &str,
) -> Result<()> {
    ensure!(
        &msg.header.proto == proto,
        "unexpected proto: {}",
        msg.header.proto
    );
    ensure!(
        msg.header.msg_type == msg_type,
        "expected {msg_type}, got {}",
        msg.header.msg_type
    );
    ensure!(
        msg.header.session_id == session,
        "unexpected session id: {}",
        msg.header.session_id
    );
    let connection_id = match msg.header.properties.get("connection_id") {
        Some(Value::String(value)) => value
            .as_str()
            .ok_or_else(|| anyhow!("connection_id is not valid utf-8"))?,
        _ => return Err(anyhow!("missing or non-string connection_id")),
    };
    ensure!(
        connection_id == id,
        "unexpected connection_id: {connection_id}"
    );
    Ok(())
}

/// Accept the worker's connect attempt and the matching `new` acknowledgement,
/// both bounded by one deadline (sequential accept then next valid here).
async fn accepted_and_ack(
    manager: &mut PortForwardManager,
    listener: &TcpListener,
    proto: &ProtoType,
    session: &str,
    id: &str,
) -> Result<TcpStream> {
    let (stream, msg) = timeout(STEP, async {
        let accepted = listener.accept().await?;
        let msg = manager.next_message().await?;
        anyhow::Ok((accepted.0, msg))
    })
    .await
    .context("timed out waiting for connect plus new ack")??;
    assert_correlation(&msg, proto, "new", session, id)?;
    ensure!(msg.body.is_empty(), "new acknowledgement must be empty");
    Ok(stream)
}

async fn expect_message(
    manager: &mut PortForwardManager,
    proto: &ProtoType,
    msg_type: &str,
    session: &str,
    id: &str,
) -> Result<ProtoMsg> {
    let msg = timeout(STEP, manager.next_message())
        .await
        .context("timed out waiting for manager message")??;
    assert_correlation(&msg, proto, msg_type, session, id)?;
    Ok(msg)
}

async fn read_exact_bytes(socket: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    timeout(STEP, socket.read_exact(&mut buf))
        .await
        .context("timed out reading forwarded bytes")??;
    Ok(buf)
}

#[tokio::test]
async fn roundtrip_stop_and_key_reuse_per_protocol() -> Result<()> {
    for proto in [ProtoType::PORT_FORWARD, ProtoType::PORT_FORWARD_V2] {
        let mut manager = PortForwardManager::new();
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let session = "session-loop";
        let id = "conn-loop";

        // A fresh `new` is accepted immediately without an inline reply.
        let replies = manager
            .handle(new_message(&proto, session, id, port)?)
            .await?;
        ensure!(replies.is_empty(), "new must not reply inline");

        let mut socket = accepted_and_ack(&mut manager, &listener, &proto, session, id).await?;

        // Client -> socket binary payload.
        let payload: Vec<u8> = vec![0x00, 0xff, 0x10, 0x7f];
        let replies = manager
            .handle(message(&proto, session, id, "forward", payload.clone())?)
            .await?;
        ensure!(replies.is_empty(), "forward must not reply inline");
        ensure!(
            read_exact_bytes(&mut socket, payload.len()).await? == payload,
            "socket received unexpected bytes"
        );
        if is_v1(&proto) {
            expect_message(&mut manager, &proto, "ack", session, id).await?;
        }

        // Socket -> client echo becomes an outbound forward message.
        let echo = b"server-echo".to_vec();
        timeout(STEP, socket.write_all(&echo))
            .await
            .context("timed out writing forward echo")??;
        let out = expect_message(&mut manager, &proto, "forward", session, id).await?;
        ensure!(out.body == echo, "unexpected outbound body");
        if is_v1(&proto) {
            manager
                .handle(message(&proto, session, id, "ack", Vec::new())?)
                .await?;
        }

        // Duplicate `new` for a live connection is rejected.
        let replies = manager
            .handle(new_message(&proto, session, id, port)?)
            .await?;
        ensure!(replies.len() == 1, "duplicate new must yield one error");
        assert_correlation(&replies[0], &proto, "error", session, id)?;

        // A foreign session id must not reach the tracked connection.
        let wrong = "session-other";
        let replies = manager
            .handle(message(&proto, wrong, id, "forward", b"nope".to_vec())?)
            .await?;
        ensure!(replies.len() == 1, "wrong-session forward must error");
        assert_correlation(&replies[0], &proto, "error", wrong, id)?;
        let replies = manager
            .handle(message(&proto, wrong, id, "stop", Vec::new())?)
            .await?;
        ensure!(replies.len() == 1, "wrong-session stop must error");
        assert_correlation(&replies[0], &proto, "error", wrong, id)?;

        // The valid connection is untouched by those rejected requests.
        let alive = b"still-alive".to_vec();
        manager
            .handle(message(&proto, session, id, "forward", alive.clone())?)
            .await?;
        ensure!(
            read_exact_bytes(&mut socket, alive.len()).await? == alive,
            "valid socket stopped working"
        );

        // Explicit stop replies synchronously and closes the socket.
        let replies = manager
            .handle(message(&proto, session, id, "stop", Vec::new())?)
            .await?;
        ensure!(replies.len() == 1, "stop must reply once");
        assert_correlation(&replies[0], &proto, "stop", session, id)?;
        let mut tail = [0u8; 1];
        let read = timeout(STEP, socket.read(&mut tail))
            .await
            .context("timed out waiting for EOF")??;
        ensure!(read == 0, "socket should be at EOF after stop");
        drop(socket);

        // Key reuse immediately after stop: the new generation owns the key.
        let replies = manager
            .handle(new_message(&proto, session, id, port)?)
            .await?;
        ensure!(replies.is_empty(), "reused key new must not reply inline");
        let mut socket = accepted_and_ack(&mut manager, &listener, &proto, session, id).await?;

        // Queue an outbound marker from this generation into the shared event
        // queue. Nothing signals "the worker enqueued the event", so a short
        // bounded sleep lets the worker read the bytes and enqueue the forward
        // event WITHOUT consuming it here. The marker therefore sits in the
        // FIFO queue ahead of everything the replacement generation produces.
        timeout(STEP, socket.write_all(b"OLD-MARKER"))
            .await
            .context("timed out writing old marker")??;
        timeout(STEP, tokio::time::sleep(Duration::from_millis(200)))
            .await
            .context("marker synchronisation timed out")?;

        let replies = manager
            .handle(message(&proto, session, id, "stop", Vec::new())?)
            .await?;
        ensure!(replies.len() == 1, "second stop must reply once");
        assert_correlation(&replies[0], &proto, "stop", session, id)?;
        drop(socket);

        // Reopening the SAME key must survive the queued stale marker.
        let replies = manager
            .handle(new_message(&proto, session, id, port)?)
            .await?;
        ensure!(replies.is_empty(), "replacement new must not reply inline");
        let mut socket = accepted_and_ack(&mut manager, &listener, &proto, session, id).await?;

        let fresh = b"FRESH-ECHO".to_vec();
        timeout(STEP, socket.write_all(&fresh))
            .await
            .context("timed out writing fresh echo")??;
        let out = expect_message(&mut manager, &proto, "forward", session, id).await?;
        ensure!(out.body == fresh, "stale generation event leaked through");
        ensure!(
            out.body.as_slice() != b"OLD-MARKER".as_slice(),
            "old marker leaked through"
        );
    }
    Ok(())
}

#[tokio::test]
async fn natural_eof_allows_immediate_key_reuse() -> Result<()> {
    let proto = ProtoType::PORT_FORWARD_V2;
    let mut manager = PortForwardManager::new();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let session = "session-eof";
    let id = "conn-eof";

    let replies = manager
        .handle(new_message(&proto, session, id, port)?)
        .await?;
    ensure!(replies.is_empty(), "new must not reply inline");
    let socket = accepted_and_ack(&mut manager, &listener, &proto, session, id).await?;

    // Peer close is a natural EOF, reported as a stop notification.
    drop(socket);
    let stop = expect_message(&mut manager, &proto, "stop", session, id).await?;
    ensure!(stop.body.is_empty(), "stop notification must be empty");

    // Reuse the key before the trailing `Finished` is consumed.
    let replies = manager
        .handle(new_message(&proto, session, id, port)?)
        .await?;
    ensure!(replies.is_empty(), "reuse after EOF must not reply inline");
    let mut socket = accepted_and_ack(&mut manager, &listener, &proto, session, id).await?;

    let payload = b"after-eof".to_vec();
    manager
        .handle(message(&proto, session, id, "forward", payload.clone())?)
        .await?;
    ensure!(
        read_exact_bytes(&mut socket, payload.len()).await? == payload,
        "reused connection did not forward after EOF"
    );
    Ok(())
}

#[tokio::test]
async fn connect_failure_then_immediate_key_reuse() -> Result<()> {
    let proto = ProtoType::PORT_FORWARD_V2;
    let mut manager = PortForwardManager::new();
    let session = "session-fail";
    let id = "conn-fail";

    // Reserve then release a port so the worker connect attempt fails.
    let dead = TcpListener::bind("127.0.0.1:0").await?;
    let dead_port = dead.local_addr()?.port();
    drop(dead);

    let replies = manager
        .handle(new_message(&proto, session, id, dead_port)?)
        .await?;
    ensure!(replies.is_empty(), "new must not reply inline");
    let err = expect_message(&mut manager, &proto, "error", session, id).await?;
    ensure!(!err.body.is_empty(), "connect failure needs a reason");

    // Immediately retry the same key against a live listener.
    let live = TcpListener::bind("127.0.0.1:0").await?;
    let live_port = live.local_addr()?.port();
    let replies = manager
        .handle(new_message(&proto, session, id, live_port)?)
        .await?;
    ensure!(replies.is_empty(), "retry new must not reply inline");
    let mut socket = accepted_and_ack(&mut manager, &live, &proto, session, id).await?;

    let payload = b"live".to_vec();
    manager
        .handle(message(&proto, session, id, "forward", payload.clone())?)
        .await?;
    ensure!(
        read_exact_bytes(&mut socket, payload.len()).await? == payload,
        "stale Finished removed the replacement generation"
    );
    Ok(())
}

#[tokio::test]
async fn destination_policy_applies_before_connect_across_protocol_versions() -> Result<()> {
    use mender_connect_rust::config::ForwardDestination;
    use mender_connect_rust::port_forward::Network;

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    for proto in [
        ProtoType::PORT_FORWARD,
        ProtoType::PORT_FORWARD_V2,
        ProtoType::PORT_FORWARD_V3,
    ] {
        let rule = ForwardDestination {
            address: addr.ip(),
            port: addr.port().try_into()?,
            protocol: Network::Tcp,
        };
        let mut manager = PortForwardManager::with_allowed_destinations(Some(vec![rule]));
        for (host, protocol, port) in [
            ("localhost", "tcp", addr.port()),
            ("127.0.0.2", "tcp", addr.port()),
            ("127.0.0.1", "udp", addr.port()),
            ("127.0.0.1", "tcp", if addr.port() == 1 { 2 } else { 1 }),
        ] {
            let mut msg = new_message(&proto, "sid", "id", port)?;
            msg.body = encode(&NewBody {
                remote_host: host,
                remote_port: port,
                protocol,
            })?;
            let reply = manager.handle(msg).await?;
            ensure!(reply.len() == 1, "expected immediate rejection");
            assert_correlation(&reply[0], &proto, "error", "sid", "id")?;
        }
        let open = new_message(&proto, "sid", "id", addr.port())?;
        let mut deny_all = PortForwardManager::with_allowed_destinations(Some(vec![]));
        ensure!(deny_all.handle(open.clone()).await?.len() == 1);
        ensure!(manager.handle(open).await?.is_empty());
        let _socket = accepted_and_ack(&mut manager, &listener, &proto, "sid", "id").await?;
        manager.close_all().await?;
    }
    Ok(())
}

#[tokio::test]
async fn v3_large_frames_require_agreement_and_preserve_writes_during_eof_drain() -> Result<()> {
    let proto = ProtoType::PORT_FORWARD_V3;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let mut manager = PortForwardManager::new();
    let id = "bulk:flow";
    let key = key_of(&proto, "sid", id)?;
    let mut open = new_message(&proto, "sid", id, port)?;
    ensure!(manager.handle(open.clone()).await?.is_empty());
    let legacy = accepted_and_ack(&mut manager, &listener, &proto, "sid", id).await?;
    let payload = vec![0x5a; 32 * 1024];
    let rejected = manager
        .handle(key.message("forward", payload.clone()))
        .await?;
    ensure!(rejected.len() == 1);
    assert_correlation(&rejected[0], &proto, "error", "sid", id)?;
    manager.close_all().await?;
    drop(legacy);

    open.body = encode(
        &serde_json::json!({"protocol":"tcp","remote_host":"127.0.0.1",
        "remote_port":port,"flow_control":true,"tcp_frame_size":32768}),
    )?;
    ensure!(manager.handle(open).await?.is_empty());
    let (target, _) = timeout(STEP, listener.accept()).await??;
    let accept = expect_message(&mut manager, &proto, "new", "sid", id).await?;
    let options: serde_json::Value = mender_connect_rust::protocol::decode(&accept.body)?;
    ensure!(options["tcp_frame_size"] == 32768);
    manager.close_all().await?;
    drop(target);

    let mut open = new_message(&proto, "sid", id, port)?;
    open.body = encode(
        &serde_json::json!({"protocol":"tcp","remote_host":"127.0.0.1",
        "remote_port":port,"flow_control":true,"tcp_frame_size":32768,"tcp_max_frame_size":262144}),
    )?;
    ensure!(manager.handle(open).await?.is_empty());
    let (mut target, _) = timeout(STEP, listener.accept()).await??;
    let accept = expect_message(&mut manager, &proto, "new", "sid", id).await?;
    let options: serde_json::Value = mender_connect_rust::protocol::decode(&accept.body)?;
    ensure!(options["tcp_frame_size"] == 262144);
    let payload = vec![0x42; 262144];
    target.write_all(b"tail").await?;
    target.shutdown().await?;
    let tail = expect_message(&mut manager, &proto, "forward", "sid", id).await?;
    ensure!(tail.body == b"tail");
    // Wait with the final ACK deliberately withheld. The worker must still
    // deliver the opposite direction and shut down its write half in order.
    ensure!(
        timeout(Duration::from_millis(25), manager.next_message())
            .await
            .is_err()
    );
    ensure!(
        manager
            .handle(key.message("forward", payload.clone()))
            .await?
            .is_empty()
    );
    ensure!(
        manager
            .handle(key.message("half_close", vec![]))
            .await?
            .is_empty()
    );
    let mut received = Vec::new();
    timeout(STEP, target.read_to_end(&mut received)).await??;
    ensure!(received == payload);
    ensure!(
        manager
            .handle(key.message("ack", 1u32.to_be_bytes().to_vec()))
            .await?
            .is_empty()
    );
    expect_message(&mut manager, &proto, "half_close", "sid", id).await?;
    expect_message(&mut manager, &proto, "stop", "sid", id).await?;
    Ok(())
}

#[tokio::test]
async fn udp_v3_batches_preserve_datagrams_in_both_directions() -> Result<()> {
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let proto = ProtoType::PORT_FORWARD_V3;
    let id = "udp-batch:flow";
    let mut manager = PortForwardManager::new();
    let mut open = new_message(&proto, "sid", id, target.local_addr()?.port())?;
    open.body = encode(
        &serde_json::json!({"protocol":"udp","remote_host":"127.0.0.1","remote_port":target.local_addr()?.port(),"flow_control":true,"udp_batch_v1":true}),
    )?;
    ensure!(manager.handle(open).await?.is_empty());
    let accepted = expect_message(&mut manager, &proto, "new", "sid", id).await?;
    let options: serde_json::Value = mender_connect_rust::protocol::decode(&accepted.body)?;
    ensure!(options["udp_batch_v1"] == true);
    let key = key_of(&proto, "sid", id)?;
    manager
        .handle(key.message("forward", vec![0, 0, 0, 0, 0, 1, 42]))
        .await?;
    let ack = expect_message(&mut manager, &proto, "ack", "sid", id).await?;
    ensure!(ack.body == 1u32.to_be_bytes());
    let mut buf = [0; 10];
    let (n, peer) = timeout(STEP, target.recv_from(&mut buf)).await??;
    ensure!(n == 0);
    let (n, _) = timeout(STEP, target.recv_from(&mut buf)).await??;
    ensure!(n == 1 && buf[0] == 42);
    target.send_to(&[], peer).await?;
    target.send_to(&[42], peer).await?;
    let frame = expect_message(&mut manager, &proto, "forward", "sid", id).await?;
    let mut body = frame.body.get(2..).context("missing batch span")?.to_vec();
    if body == [0, 0] {
        let next = expect_message(&mut manager, &proto, "forward", "sid", id).await?;
        body.extend_from_slice(next.body.get(2..).context("missing second span")?);
    }
    ensure!(body == [0, 0, 0, 1, 42]);
    manager.close_all().await?;
    Ok(())
}
