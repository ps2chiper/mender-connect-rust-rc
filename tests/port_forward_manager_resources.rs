//! Resource-lifecycle integration tests for the port-forward manager.
//!
//! These tests exercise real TCP sockets through [`PortForwardManager`]. The
//! tests own every accepted socket directly (no detached helper tasks), so the
//! only tasks running are the manager's supervised workers. The `close_*`
//! methods await their workers; `Drop` merely aborts them.
//!
//! Queue-constant regression context (from `port_forward_manager`):
//!   * MAX_ENTRIES      = 16
//!   * COMMAND_CAPACITY = 8
//!   * EVENT_CAPACITY   = 64
//!
//! The overflow/reclamation tests below are tuned to those exact bounds.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::time::Duration;

use anyhow::{Result, anyhow, bail};
use rmpv::Value;
use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{Instant, timeout};

use mender_connect_rust::port_forward::ConnectionKey;
use mender_connect_rust::port_forward_manager::PortForwardManager;
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, encode};

const V1: ProtoType = ProtoType::PORT_FORWARD;
const V2: ProtoType = ProtoType::PORT_FORWARD_V2;
const OP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Serialize)]
struct NewBody<'a> {
    remote_host: &'a str,
    remote_port: u16,
    protocol: &'a str,
}

fn make_key(proto: ProtoType, session: &str, id: &str) -> Result<ConnectionKey> {
    let mut properties = BTreeMap::new();
    properties.insert(
        "connection_id".to_owned(),
        Value::String(id.to_owned().into()),
    );
    let header = ProtoHdr {
        proto,
        msg_type: "new".to_owned(),
        session_id: session.to_owned(),
        properties,
    };
    ConnectionKey::from_header(&header)
}

fn new_message(key: &ConnectionKey, host: &str, port: u16, protocol: &str) -> Result<ProtoMsg> {
    let body = encode(&NewBody {
        remote_host: host,
        remote_port: port,
        protocol,
    })?;
    Ok(key.message("new", body))
}

fn connection_id(msg: &ProtoMsg) -> Option<String> {
    match msg.header.properties.get("connection_id") {
        Some(Value::String(value)) => value.as_str().map(str::to_owned),
        _ => None,
    }
}

async fn accept(listener: &TcpListener) -> Result<TcpStream> {
    let (sock, _) = timeout(OP_TIMEOUT, listener.accept()).await??;
    Ok(sock)
}

async fn next(manager: &mut PortForwardManager) -> Result<ProtoMsg> {
    timeout(OP_TIMEOUT, manager.next_message()).await?
}

async fn read_exact(sock: &mut TcpStream, buf: &mut [u8]) -> Result<()> {
    timeout(OP_TIMEOUT, sock.read_exact(buf)).await??;
    Ok(())
}

async fn write_all(sock: &mut TcpStream, data: &[u8]) -> Result<()> {
    timeout(OP_TIMEOUT, sock.write_all(data)).await??;
    Ok(())
}

/// Drain any buffered bytes until a bounded EOF (or reset) is observed.
async fn drain_to_eof(sock: &mut TcpStream) -> Result<()> {
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for socket EOF");
        }
        match timeout(remaining, sock.read(&mut buf)).await {
            Ok(Ok(0)) => return Ok(()),
            Ok(Ok(_)) => continue,
            Ok(Err(err)) if err.kind() == ErrorKind::ConnectionReset => return Ok(()),
            Ok(Err(err)) => return Err(err.into()),
            Err(_) => bail!("timed out waiting for socket EOF"),
        }
    }
}

#[tokio::test]
async fn capacity_and_session_lifecycle() -> Result<()> {
    let mut manager = PortForwardManager::new();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let mut established: Vec<(ConnectionKey, String, TcpStream)> = Vec::new();
    for i in 0..16usize {
        let sid = if i % 2 == 0 { "a" } else { "b" };
        let id = format!("conn{i}");
        let key = make_key(V2, sid, &id)?;
        let out = manager
            .handle(new_message(&key, "127.0.0.1", port, "tcp")?)
            .await?;
        assert!(out.is_empty(), "new is acknowledged asynchronously");
        let sock = accept(&listener).await?;
        let ev = next(&mut manager).await?;
        assert_eq!(ev.header.msg_type, "new");
        assert_eq!(ev.header.session_id, sid);
        assert_eq!(connection_id(&ev).as_deref(), Some(id.as_str()));
        established.push((key, sid.to_owned(), sock));
    }

    // A 17th connection exceeds capacity and is rejected synchronously.
    let overflow_key = make_key(V2, "a", "conn-overflow")?;
    let out = manager
        .handle(new_message(&overflow_key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].header.msg_type, "error");

    // Closing session "a" drops exactly its sockets; "b" stays usable.
    manager.close_session("a").await?;
    for (_, sid, sock) in established.iter_mut() {
        if sid == "a" {
            drain_to_eof(sock).await?;
        }
    }

    let b_pos = established
        .iter()
        .position(|(_, sid, _)| sid == "b")
        .ok_or_else(|| anyhow!("no surviving b connection"))?;
    let b_key = established[b_pos].0.clone();
    {
        let sock = &mut established[b_pos].2;
        let out = manager
            .handle(b_key.message("forward", b"ping".to_vec()))
            .await?;
        assert!(out.is_empty());
        let mut buf = [0u8; 4];
        read_exact(sock, &mut buf).await?;
        assert_eq!(&buf, b"ping");
    }

    // A stop carrying the wrong session id must not match any live entry.
    let wrong_sid = make_key(V2, "a", b_key.id())?;
    let out = manager
        .handle(wrong_sid.message("stop", Vec::new()))
        .await?;
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].header.msg_type, "error");

    // Closing everything drops the remaining "b" sockets.
    manager.close_all().await?;
    for (_, sid, sock) in established.iter_mut() {
        if sid == "b" {
            drain_to_eof(sock).await?;
        }
    }

    // Capacity is reusable after everything is released.
    let reuse_key = make_key(V2, "c", "reuse")?;
    let out = manager
        .handle(new_message(&reuse_key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty());
    let _reuse_sock = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");
    assert_eq!(connection_id(&ev).as_deref(), Some("reuse"));

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn drop_manager_closes_socket() -> Result<()> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let mut manager = PortForwardManager::new();

    let key = make_key(V2, "s", "drop")?;
    let out = manager
        .handle(new_message(&key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty());
    let mut sock = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");

    // `Drop` aborts every worker; the accepted socket must then see EOF.
    drop(manager);
    drain_to_eof(&mut sock).await?;
    Ok(())
}

#[tokio::test(flavor = "current_thread")]
async fn burst_input_is_bounded_and_admitted_without_reset() -> Result<()> {
    let mut manager = PortForwardManager::new();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    let burst_key = make_key(V2, "s", "burst")?;
    let healthy_key = make_key(V2, "s", "healthy")?;

    let out = manager
        .handle(new_message(&burst_key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty());
    let mut burst_sock = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");

    let out = manager
        .handle(new_message(&healthy_key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty());
    let mut healthy_sock = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");

    // Enqueue distinct 4096-byte frames without yielding to the worker and
    // without calling next_event, until admission is saturated: the 8-entry
    // command queue plus the single command retained by `handle` (pending). No
    // iteration may emit output or an error; the manager must never abort.
    const FRAME_LEN: usize = 4096;
    let mut frames: Vec<Vec<u8>> = Vec::new();
    for n in 0u8..9u8 {
        let mut payload = vec![0u8; FRAME_LEN];
        payload[0] = n;
        payload[1] = n.wrapping_mul(3);
        payload[FRAME_LEN - 1] = n;
        let out = manager
            .handle(burst_key.message("forward", payload.clone()))
            .await?;
        assert!(out.is_empty(), "admission must not emit on overflow path");
        frames.push(payload);
        if !manager.accepts_input() {
            break;
        }
    }
    assert!(
        !manager.accepts_input(),
        "burst must saturate bounded admission"
    );

    // While admission is pending, another `handle` must fail with an API usage
    // error and must not overwrite the already-queued data.
    assert!(
        manager
            .handle(burst_key.message("forward", vec![0xAB; FRAME_LEN]))
            .await
            .is_err(),
        "pending handle must be an API usage error"
    );

    let mut expected_burst: Vec<u8> = Vec::new();
    for frame in frames.iter() {
        expected_burst.extend_from_slice(frame);
    }

    // Make healthy OUTBOUND wire data ready: the worker emits it only after the
    // outbound burst drain completes, so it doubles as progress evidence.
    write_all(&mut healthy_sock, b"world").await?;

    // Drive admission without ever calling `handle` (that would be API misuse)
    // and without re-polling `next_event` while nothing can be produced.
    let mut healthy_output: Vec<u8> = Vec::new();
    let driver = async {
        while !manager.accepts_input() || healthy_output.len() < 5 {
            if let Some(msg) = manager.next_event().await? {
                assert_eq!(msg.header.proto, V2);
                assert_eq!(msg.header.session_id, "s");
                assert_eq!(msg.header.msg_type, "forward");
                assert_eq!(
                    connection_id(&msg).as_deref(),
                    Some("healthy"),
                    "only the healthy connection may emit wire output here"
                );
                healthy_output.extend_from_slice(&msg.body);
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    let remaining = deadline.saturating_duration_since(Instant::now());
    timeout(remaining, driver).await??;
    assert!(manager.accepts_input(), "admission must resume");
    assert_eq!(
        healthy_output, b"world",
        "healthy forward must be byte-exact"
    );

    // All burst frames must have been delivered outward, byte-exact and in
    // order, with no reset and no EOF.
    let mut burst_read = vec![0u8; expected_burst.len()];
    read_exact(&mut burst_sock, &mut burst_read).await?;
    assert_eq!(
        burst_read, expected_burst,
        "burst frames must be byte-exact"
    );

    // The gate is open: extra burst bytes and healthy inbound bytes both work.
    let extra = vec![0x5Au8; 512];
    let out = manager
        .handle(burst_key.message("forward", extra.clone()))
        .await?;
    assert!(out.is_empty());
    let mut buf = vec![0u8; extra.len()];
    read_exact(&mut burst_sock, &mut buf).await?;
    assert_eq!(buf, extra);

    let out = manager
        .handle(healthy_key.message("forward", b"hello".to_vec()))
        .await?;
    assert!(out.is_empty());
    let mut hello = [0u8; 5];
    read_exact(&mut healthy_sock, &mut hello).await?;
    assert_eq!(&hello, b"hello");

    // An explicit stop must reply with EXACTLY ONE stop frame for the burst
    // connection, not an empty acknowledgement.
    let stop = manager
        .handle(burst_key.message("stop", Vec::new()))
        .await?;
    assert_eq!(stop.len(), 1, "stop must reply with exactly one frame");
    assert_eq!(stop[0].header.msg_type, "stop");
    assert_eq!(stop[0].header.proto, V2);
    assert_eq!(stop[0].header.session_id, "s");
    assert_eq!(connection_id(&stop[0]).as_deref(), Some("burst"));
    drain_to_eof(&mut burst_sock).await?;

    // The same key is immediately reusable while the healthy connection stays
    // active.
    let reuse_key = make_key(V2, "s", "burst")?;
    let out = manager
        .handle(new_message(&reuse_key, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty());
    let _replacement = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");
    assert_eq!(connection_id(&ev).as_deref(), Some("burst"));

    manager.close_all().await?;
    drain_to_eof(&mut healthy_sock).await?;
    Ok(())
}

#[tokio::test]
async fn lost_finished_and_queued_output_reclaimed() -> Result<()> {
    timeout(Duration::from_secs(20), run_reclamation()).await??;
    Ok(())
}

async fn run_reclamation() -> Result<()> {
    let mut manager = PortForwardManager::new();
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();

    // 16 v1 (ack-gated) connections fill the entry table.
    let mut conns: Vec<(ConnectionKey, TcpStream)> = Vec::new();
    for i in 0..16usize {
        let id = format!("c{i}");
        let key = make_key(V1, "s", &id)?;
        let out = manager
            .handle(new_message(&key, "127.0.0.1", port, "tcp")?)
            .await?;
        assert!(out.is_empty());
        let sock = accept(&listener).await?;
        let ev = next(&mut manager).await?;
        assert_eq!(ev.header.msg_type, "new");
        assert_eq!(connection_id(&ev).as_deref(), Some(id.as_str()));
        conns.push((key, sock));
    }

    let (sel_key, mut sel_sock) = conns.remove(0);

    // Send 65 single-byte forwards serially. Reading the byte back confirms the
    // worker processed it (the ack is emitted before the next forward). The
    // first 64 acks fill the 64-slot event queue; the 65th ack then blocks.
    for n in 0..65u8 {
        let out = manager.handle(sel_key.message("forward", vec![n])).await?;
        assert!(out.is_empty());
        let mut buf = [0u8; 1];
        read_exact(&mut sel_sock, &mut buf).await?;
        assert_eq!(buf[0], n);
    }

    // Do NOT call next_message during ack-timeout / Finished-timeout window.
    // The 65th ack blocks ~4s, then the terminal Finished also times out ~4s.
    tokio::time::sleep(Duration::from_secs(9)).await;

    // Drain exactly the 64 queued acks; queued output must never be discarded.
    for _ in 0..64 {
        let ev = next(&mut manager).await?;
        assert_eq!(ev.header.msg_type, "ack");
        assert_eq!(ev.header.session_id, "s");
        assert_eq!(connection_id(&ev).as_deref(), Some(sel_key.id()));
        assert!(ev.body.is_empty());
    }

    // Immediately request a 17th distinct connection before any further
    // next_message call: with the queue now empty, `handle` reaps the finished
    // worker and frees capacity, so this is accepted synchronously.
    let key17 = make_key(V1, "s", "c16")?;
    let out = manager
        .handle(new_message(&key17, "127.0.0.1", port, "tcp")?)
        .await?;
    assert!(out.is_empty(), "capacity must be reclaimed");
    let _sock17 = accept(&listener).await?;
    let ev = next(&mut manager).await?;
    assert_eq!(ev.header.msg_type, "new");
    assert_eq!(connection_id(&ev).as_deref(), Some("c16"));

    // Remaining workers are cleaned up deterministically.
    manager.close_all().await?;
    Ok(())
}
