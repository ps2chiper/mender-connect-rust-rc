//! Native stalled-target backpressure regression tests.
//!
//! A real TCP target never reads on one connection, so the kernel receive
//! window closes and the worker's bounded socket write eventually times out.
//! A second healthy loopback connection proves that backpressure on one worker
//! does not starve output for unrelated traffic, and that the manager accepts a
//! fresh connection after the stalled worker is retired.
//!
//! Note: admission is globally serialised (a single input gate), so a stalled
//! worker holcenters the whole inbound path. Only *outbound* progress (healthy
//! forward output, ACKs, terminal errors) is serviced concurrently; unrelated
//! traffic is not free to be admitted while the gate is closed.
//!
//! No `unwrap`/`expect`/`panic`/`unsafe`; every helper returns
//! `anyhow::Result` and all waits are bounded by one absolute deadline.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, ensure};
use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket};
use tokio::time::timeout;

use mender_connect_rust::port_forward::ConnectionKey;
use mender_connect_rust::port_forward_manager::PortForwardManager;
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, decode, encode};

/// Absolute whole-test deadline, never reset.
const WHOLE: Duration = Duration::from_secs(15);
/// Small receive buffer so the stalled target saturates quickly.
const RECV_BUFFER: u32 = 4096;
/// Flood chunk (within the 8192 frame cap / 4096 forward body cap).
const CHUNK: usize = 4096;
/// Bounded flood iterations.
const MAX_FRAMES: usize = 4096;
const HEALTHY_MARKER: &[u8] = b"HEALTHY-MARKER";
const TAIL: &[u8] = b"POST-RECOVERY";
const WRITE_TIMEOUT_ERR: &str = "socket write timed out";
const SESSION: &str = "session-backpressure";
const STALLED_ID: &str = "conn-stalled";
const HEALTHY_ID: &str = "conn-healthy";

fn header(proto: ProtoType, msg_type: &str, id: &str) -> ProtoHdr {
    let mut properties = BTreeMap::new();
    properties.insert(
        "connection_id".to_owned(),
        Value::String(id.to_owned().into()),
    );
    ProtoHdr {
        proto,
        msg_type: msg_type.to_owned(),
        session_id: SESSION.to_owned(),
        properties,
    }
}

fn key_of(proto: ProtoType, id: &str) -> Result<ConnectionKey> {
    ConnectionKey::from_header(&header(proto, "new", id))
}

#[derive(serde::Serialize)]
struct NewBody<'a> {
    remote_host: &'a str,
    remote_port: u16,
    protocol: &'a str,
}

fn new_message(proto: ProtoType, id: &str, port: u16) -> Result<ProtoMsg> {
    let body = encode(&NewBody {
        remote_host: "127.0.0.1",
        remote_port: port,
        protocol: "tcp",
    })?;
    Ok(ProtoMsg {
        header: header(proto, "new", id),
        body,
    })
}

fn msg_id(msg: &ProtoMsg) -> Option<&str> {
    match msg.header.properties.get("connection_id") {
        Some(Value::String(value)) => value.as_str(),
        _ => None,
    }
}

/// Strict correlation: proto, msg type, session, connection id, empty body.
fn expect_msg(msg: &ProtoMsg, proto: ProtoType, typ: &str, id: &str) -> Result<()> {
    ensure!(
        msg.header.proto == proto,
        "proto mismatch: {}",
        msg.header.proto
    );
    ensure!(
        msg.header.msg_type == typ,
        "expected {typ}, got {}",
        msg.header.msg_type
    );
    ensure!(msg.header.session_id == SESSION, "session mismatch");
    ensure!(msg_id(msg) == Some(id), "connection_id mismatch");
    ensure!(msg.body.is_empty(), "{typ} body must be empty");
    Ok(())
}

#[derive(serde::Deserialize)]
struct ErrorBody {
    err: String,
    msgtype: String,
}

fn stalled_listener() -> Result<TcpListener> {
    let socket = TcpSocket::new_v4()?;
    socket.set_recv_buffer_size(RECV_BUFFER)?;
    socket.bind("127.0.0.1:0".parse()?)?;
    Ok(socket.listen(1)?)
}

async fn open(
    manager: &mut PortForwardManager,
    proto: ProtoType,
    id: &str,
    listener: &TcpListener,
) -> Result<tokio::net::TcpStream> {
    let port = listener.local_addr()?.port();
    ensure!(
        manager
            .handle(new_message(proto, id, port)?)
            .await?
            .is_empty(),
        "{id} new must not reply inline"
    );
    let (sock, _) = timeout(WHOLE, listener.accept())
        .await
        .context("timed out accepting target")??;
    Ok(sock)
}

async fn await_ack(manager: &mut PortForwardManager, proto: ProtoType, id: &str) -> Result<()> {
    let msg = timeout(WHOLE, manager.next_message())
        .await
        .context("timed out awaiting new ack")??;
    expect_msg(&msg, proto, "new", id)
}

async fn scenario(proto: ProtoType) -> Result<()> {
    let v1 = proto == ProtoType::PORT_FORWARD;
    let stalled = stalled_listener()?;
    let healthy = TcpListener::bind("127.0.0.1:0").await?;

    let mut manager = PortForwardManager::new();
    // Stalled target is kept but never read until cleanup.
    let stalled_sock = open(&mut manager, proto, STALLED_ID, &stalled).await?;
    await_ack(&mut manager, proto, STALLED_ID).await?;
    let mut healthy_sock = open(&mut manager, proto, HEALTHY_ID, &healthy).await?;
    await_ack(&mut manager, proto, HEALTHY_ID).await?;

    timeout(WHOLE, healthy_sock.write_all(HEALTHY_MARKER))
        .await
        .context("timed out writing healthy marker")??;

    let stalled_key = key_of(proto, STALLED_ID)?;
    let healthy_key = key_of(proto, HEALTHY_ID)?;
    let chunk = vec![0x5au8; CHUNK];

    let mut frames = 0usize;
    let mut waiting_ack = false;
    let mut producer_blocked = false;
    let mut saw_error = false;
    let mut saw_stop = false;
    let mut saw_pending = false;
    let mut healthy_out = 0usize;

    for _ in 0..MAX_FRAMES * 4 + 64 {
        if saw_error && saw_stop && manager.accepts_input() {
            break;
        }
        let take = !saw_error && !producer_blocked && manager.accepts_input() && !waiting_ack;
        if take {
            ensure!(
                frames < MAX_FRAMES,
                "flood frame cap reached without timeout"
            );
            let replies = manager
                .handle(stalled_key.message("forward", chunk.clone()))
                .await?;
            ensure!(replies.is_empty(), "forward must not reply inline");
            frames += 1;
            waiting_ack = v1;
            continue;
        }
        if !manager.accepts_input() {
            saw_pending = true;
        }
        if saw_error && !manager.accepts_input() {
            // Feed nothing new; the worker finishes retiring on its own.
        }
        // Once admission stays blocked, stop producing and observe the
        // worker's own terminal error. This also cancels and resumes a real
        // pending admission without inventing sender pacing or racing another
        // forward against an already-closed worker.
        let event = if !v1 && !producer_blocked && !manager.accepts_input() {
            match timeout(Duration::from_millis(100), manager.next_event()).await {
                Ok(result) => result?,
                Err(_) => {
                    producer_blocked = true;
                    continue;
                }
            }
        } else {
            timeout(WHOLE, manager.next_event())
                .await
                .context("timed out driving worker")??
        };
        let Some(msg) = event else { continue };
        ensure!(msg.header.proto == proto, "event proto mismatch");
        ensure!(msg.header.session_id == SESSION, "event session mismatch");
        let id = msg_id(&msg).ok_or_else(|| anyhow!("event without connection_id"))?;
        match msg.header.msg_type.as_str() {
            "error" => {
                ensure!(id == STALLED_ID, "unexpected error for {id}");
                let body: ErrorBody = decode(&msg.body).context("bad error body")?;
                ensure!(
                    body.err == WRITE_TIMEOUT_ERR,
                    "unexpected err {:?}",
                    body.err
                );
                ensure!(
                    body.msgtype == "forward",
                    "unexpected msgtype {:?}",
                    body.msgtype
                );
                saw_error = true;
            }
            "stop" => {
                ensure!(id == STALLED_ID, "unexpected stop for {id}");
                ensure!(msg.body.is_empty(), "stop body must be empty");
                saw_stop = true;
            }
            "ack" => {
                if id == STALLED_ID {
                    ensure!(v1 && waiting_ack, "unexpected stalled ack");
                    ensure!(msg.body.is_empty(), "ack body must be empty");
                    waiting_ack = false;
                } else {
                    ensure!(id == HEALTHY_ID && v1, "unexpected healthy ack");
                    ensure!(msg.body.is_empty(), "ack body must be empty");
                }
            }
            "forward" => {
                ensure!(id == HEALTHY_ID, "unexpected forward for {id}");
                ensure!(
                    healthy_out + msg.body.len() <= HEALTHY_MARKER.len(),
                    "healthy forward exceeds marker"
                );
                ensure!(
                    msg.body.as_slice()
                        == &HEALTHY_MARKER[healthy_out..healthy_out + msg.body.len()],
                    "healthy forward bytes mismatch"
                );
                healthy_out += msg.body.len();
                if v1 {
                    ensure!(manager.accepts_input(), "gate closed before healthy ack");
                    ensure!(
                        manager
                            .handle(healthy_key.message("ack", Vec::new()))
                            .await?
                            .is_empty(),
                        "ack must not reply inline"
                    );
                }
            }
            other => return Err(anyhow!("unexpected message type {other}")),
        }
    }

    ensure!(saw_error, "stalled write timeout error never surfaced");
    ensure!(saw_stop, "stalled stop never surfaced");
    ensure!(
        manager.accepts_input(),
        "input gate must reopen after retirement"
    );
    ensure!(
        healthy_out == HEALTHY_MARKER.len(),
        "healthy marker not fully forwarded"
    );
    // The failed write must not be acknowledged as successful in v1.
    ensure!(
        !v1 || waiting_ack,
        "failed v1 write must retain its unreturned credit"
    );
    if !v1 {
        ensure!(saw_pending, "v2 must observe a closed input gate");
    }

    ensure!(
        manager
            .handle(healthy_key.message("forward", TAIL.to_vec()))
            .await?
            .is_empty(),
        "recovery forward must not reply inline"
    );
    if v1 {
        let msg = timeout(WHOLE, manager.next_message())
            .await
            .context("timed out awaiting recovery ack")??;
        expect_msg(&msg, proto, "ack", HEALTHY_ID)?;
    }

    let mut tail = vec![0u8; TAIL.len()];
    timeout(WHOLE, healthy_sock.read_exact(&mut tail))
        .await
        .context("timed out reading healthy tail")??;
    ensure!(tail.as_slice() == TAIL, "healthy tail mismatch");

    timeout(WHOLE, manager.close_all())
        .await
        .context("timed out closing all connections")??;
    ensure!(manager.accepts_input(), "close_all must leave input armed");

    // All tail bytes were read above, so the first read here must be EOF.
    let mut probe = [0u8; 1];
    let n = timeout(WHOLE, healthy_sock.read(&mut probe))
        .await
        .context("timed out awaiting healthy EOF")??;
    ensure!(n == 0, "expected healthy EOF, read {n} bytes");

    // Dropping the undrained stalled socket is cleanup only; its buffered flood
    // bytes were never acknowledged as delivered.
    drop(stalled_sock);
    Ok(())
}

async fn run(proto: ProtoType) -> Result<()> {
    timeout(WHOLE, scenario(proto))
        .await
        .context("whole backpressure test deadline exceeded")?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_target_recovers_v1() -> Result<()> {
    run(ProtoType::PORT_FORWARD).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_target_recovers_v2() -> Result<()> {
    run(ProtoType::PORT_FORWARD_V2).await
}
