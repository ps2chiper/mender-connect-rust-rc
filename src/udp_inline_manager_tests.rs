//! Regression tests for inline managed-UDP forwarding in the port-forward
//! manager. These drive the real `PortForwardManager` API against real Tokio
//! UDP sockets; nothing is mocked at the protocol/socket level except the
//! explicit `force_busy_once` test hook used to provoke legacy fallback.

use std::collections::BTreeMap;
use std::future::Future;
use std::task::Poll;
use std::time::Duration;

use anyhow::{Result, anyhow};
use tokio::net::UdpSocket;
use tokio::time::timeout;

use super::*;
use crate::port_forward::ConnectionKey;
use crate::port_forward_worker::Command;
use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType};

/// Generous bound for manager events and worker acknowledgements.
const WAIT: Duration = Duration::from_secs(2);
/// Bounded wait used to assert *absence* of a datagram.
const NO_DATA: Duration = Duration::from_millis(50);

fn key() -> Result<ConnectionKey> {
    ConnectionKey::from_header(&ProtoHdr {
        proto: ProtoType::PORT_FORWARD,
        msg_type: "new".to_owned(),
        session_id: "inline-tests".to_owned(),
        properties: BTreeMap::from([("connection_id".to_owned(), rmpv::Value::from("conn"))]),
    })
}

fn new_message(key: &ConnectionKey, port: u16) -> Result<ProtoMsg> {
    let body = crate::protocol::encode(&serde_json::json!({
        // Native IPv6 loopback keeps test datagrams off WSL's 127.0.0.1 bridge.
        "remote_host": "::1",
        "remote_port": port,
        "protocol": "udp",
    }))?;
    Ok(key.message("new", body))
}

fn forward(key: &ConnectionKey, payload: &[u8]) -> ProtoMsg {
    key.message("forward", payload.to_vec())
}

fn ack(key: &ConnectionKey) -> ProtoMsg {
    key.message("ack", Vec::new())
}

/// Bind a loopback UDP target owned by the test's runtime.
///
/// Uses native IPv6 loopback: on WSL, 127.0.0.1 is routed through a separate
/// host bridge that drops payloads around the 1500-byte MTU, while `::1`
/// stays on Linux `lo` and delivers the full datagram.
async fn target() -> Result<UdpSocket> {
    Ok(UdpSocket::bind("[::1]:0").await?)
}

/// Receive exactly one datagram from `socket`, bounded by a test timeout.
async fn recv_exact(socket: &UdpSocket, expected: &[u8]) -> Result<()> {
    let mut buf = [0u8; 8192];
    let (len, _) = timeout(WAIT, socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow!("timed out waiting for datagram"))??;
    assert_eq!(&buf[..len], expected, "unexpected datagram payload");
    Ok(())
}

/// Assert no datagram arrives within a short bounded window.
async fn expect_no_datagram(socket: &UdpSocket) -> Result<()> {
    let mut buf = [0u8; 8192];
    match timeout(NO_DATA, socket.recv_from(&mut buf)).await {
        Err(_) => Ok(()),
        Ok(Ok((len, _))) => Err(anyhow!("unexpected datagram of {len} bytes")),
        Ok(Err(err)) => Err(anyhow!("socket error while expecting silence: {err}")),
    }
}

/// Open a managed UDP connection and consume the worker's `new` acknowledgement.
async fn open(manager: &mut PortForwardManager, key: &ConnectionKey, port: u16) -> Result<()> {
    let replies = timeout(WAIT, manager.handle(new_message(key, port)?)).await??;
    assert!(replies.is_empty(), "new must not reply synchronously");
    let message = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(message.header.msg_type, "new", "expected new ack");
    Ok(())
}

/// Warm the worker's inline writer and drain every warm acknowledgement.
async fn warm(manager: &mut PortForwardManager, key: &ConnectionKey) -> Result<()> {
    let replies = timeout(WAIT, manager.handle(forward(key, b"warm"))).await??;
    if replies.is_empty() {
        let message = timeout(WAIT, manager.next_message()).await??;
        assert_eq!(message.header.msg_type, "ack", "expected warm ack");
    } else {
        assert_eq!(replies.len(), 1, "unexpected warm reply count");
        assert_eq!(replies[0].header.msg_type, "ack");
    }
    Ok(())
}

/// Return only if the complete warmed handle operation finishes in one poll.
fn ready_handle(manager: &mut PortForwardManager, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
    let mut future = Box::pin(manager.handle(message));
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        Poll::Ready(result) => result,
        Poll::Pending => Err(anyhow!("warmed inline handle yielded")),
    }
}

#[tokio::test]
async fn warmed_inline_forwards_exact_and_bounded() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    for payload in [Vec::new(), vec![7u8; 4096]] {
        tokio::task::yield_now().await;
        let replies = ready_handle(&mut manager, forward(&key, &payload))?;
        assert_eq!(replies.len(), 1);
        assert_eq!(replies[0].header.msg_type, "ack");
        recv_exact(&peer, &payload).await?;
    }
    {
        let inner = manager.inner.get_mut();
        let entry = inner
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(
            entry.legacy_forwards, 0,
            "inline path must not reserve credits"
        );
        assert!(
            entry.udp_inline.is_some(),
            "expected managed shared UDP state"
        );
    }

    // One byte over the bound: rejected as a typed reply, never written.
    let oversized = vec![9u8; 4097];
    let replies = timeout(WAIT, manager.handle(forward(&key, &oversized))).await??;
    assert_eq!(replies.len(), 1, "oversize forward must reply once");
    assert_eq!(replies[0].header.msg_type, "error");
    expect_no_datagram(&peer).await?;

    assert!(
        manager.events.get_mut().is_empty(),
        "no worker events should be queued after inline handling"
    );
    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn busy_fallback_preserves_ordering_of_unconsumed_acks() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    let shared = manager
        .inner
        .get_mut()
        .entries
        .get(&key)
        .and_then(|entry| entry.udp_inline.clone())
        .ok_or_else(|| anyhow!("missing live UDP descriptor"))?;
    shared.force_busy_once()?;

    let replies = timeout(WAIT, manager.handle(forward(&key, b"alpha"))).await??;
    assert!(replies.is_empty(), "queued forward must not reply inline");
    let replies = timeout(WAIT, manager.handle(forward(&key, b"beta"))).await??;
    assert!(
        replies.is_empty(),
        "second queued forward must not reply inline"
    );
    {
        let inner = manager.inner.get_mut();
        let entry = inner
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(
            entry.legacy_forwards, 2,
            "two legacy credits must be reserved"
        );
    }

    // Worker processes forwards in submission order.
    recv_exact(&peer, b"alpha").await?;
    recv_exact(&peer, b"beta").await?;

    let first = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(first.header.msg_type, "ack");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(entry.legacy_forwards, 1);
    }

    let second = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(second.header.msg_type, "ack");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(entry.legacy_forwards, 0, "credits must reach zero exactly");
    }

    tokio::task::yield_now().await;
    let replies = ready_handle(&mut manager, forward(&key, b"gamma"))?;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.msg_type, "ack");
    recv_exact(&peer, b"gamma").await?;

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn forward_before_new_ack_uses_legacy_then_recovers() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    let replies = timeout(
        WAIT,
        manager.handle(new_message(&key, peer.local_addr()?.port())?),
    )
    .await??;
    assert!(replies.is_empty(), "new must not reply synchronously");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert!(
            matches!(entry.phase, Phase::Connecting),
            "worker must not be established yet"
        );
    }

    // Forward arrives while still connecting: queued through the legacy path.
    let replies = timeout(WAIT, manager.handle(forward(&key, b"early"))).await??;
    assert!(
        replies.is_empty(),
        "connecting forward must not reply inline"
    );
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(entry.legacy_forwards, 1);
    }

    let new_ack = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(new_ack.header.msg_type, "new");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert!(matches!(entry.phase, Phase::Established));
        assert_eq!(entry.legacy_forwards, 1, "new ack must not release credits");
    }

    let forwarded_ack = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(forwarded_ack.header.msg_type, "ack");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(entry.legacy_forwards, 0);
    }
    recv_exact(&peer, b"early").await?;

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn generation_reopen_skips_stale_ack_and_closes_old_descriptor() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    open(&mut manager, &key, peer.local_addr()?.port()).await?;

    let (old_shared, old_generation) = {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        let shared = entry
            .udp_inline
            .clone()
            .ok_or_else(|| anyhow!("missing shared udp"))?;
        (shared, entry.generation)
    };

    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    manager.close_session("inline-tests").await?;
    assert!(
        matches!(old_shared.try_forward(b"stale"), Attempt::Failed(_)),
        "closed descriptor must reject inline attempts"
    );
    assert!(
        manager.inner.get_mut().entries.is_empty(),
        "close_session must remove the entry"
    );

    // Reopen the same key: a new generation with fresh shared state.
    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    let new_generation = manager
        .inner
        .get_mut()
        .entries
        .get(&key)
        .ok_or_else(|| anyhow!("missing entry"))?
        .generation;
    assert!(new_generation > old_generation, "generation must advance");
    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    // Enqueue a stale ack from the retired generation before forcing busy.
    manager
        .event_tx
        .try_send(Event::Message {
            key: key.clone(),
            generation: old_generation,
            message: ack(&key),
        })
        .map_err(|err| anyhow!("failed to enqueue stale ack: {err}"))?;

    let shared = manager
        .inner
        .get_mut()
        .entries
        .get(&key)
        .and_then(|entry| entry.udp_inline.clone())
        .ok_or_else(|| anyhow!("missing live UDP descriptor"))?;
    shared.force_busy_once()?;

    let replies = timeout(WAIT, manager.handle(forward(&key, b"legit"))).await??;
    assert!(replies.is_empty(), "busy forward must not reply inline");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(entry.legacy_forwards, 1);
    }

    // The stale ack must be skipped silently, then the legit ack decrements.
    let message = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(message.header.msg_type, "ack");
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get_mut(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        assert_eq!(
            entry.legacy_forwards, 0,
            "stale ack must not touch the counter"
        );
    }
    recv_exact(&peer, b"legit").await?;

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn worker_failure_is_terminal_and_closes_descriptor() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    let shared = {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("missing entry"))?;
        entry
            .commands
            .clone()
            .send(Command::FailForward("test failure"))
            .await
            .map_err(|err| anyhow!("failed to inject failure: {err}"))?;
        entry
            .udp_inline
            .clone()
            .ok_or_else(|| anyhow!("missing shared udp"))?
    };

    let error = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(error.header.msg_type, "error");

    let stop = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(stop.header.msg_type, "stop");

    assert!(matches!(shared.try_forward(b"after"), Attempt::Failed(_)));
    expect_no_datagram(&peer).await?;
    manager.close_all().await?;
    Ok(())
}

#[tokio::test(start_paused = true)]
async fn worker_old_timer_recheck_keeps_live_connection() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();

    // Keep the paused clock from auto-advancing while we await UDP readiness.
    struct KeepAwake(tokio::task::JoinHandle<()>);
    impl Drop for KeepAwake {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    let mut keep_awake = KeepAwake(tokio::spawn(async {
        loop {
            tokio::task::yield_now().await;
        }
    }));

    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    warm(&mut manager, &key).await?;
    recv_exact(&peer, b"warm").await?;

    let shared = manager
        .inner
        .get_mut()
        .entries
        .get(&key)
        .and_then(|entry| entry.udp_inline.clone())
        .ok_or_else(|| anyhow!("missing live UDP descriptor"))?;
    tokio::time::advance(Duration::from_secs(599)).await;
    let replies = timeout(WAIT, manager.handle(forward(&key, b"before"))).await??;
    assert_eq!(
        replies.len(),
        1,
        "forward near the old deadline must stay inline"
    );
    assert_eq!(replies[0].header.msg_type, "ack");
    recv_exact(&peer, b"before").await?;

    // Cross the original deadline: the worker must recheck and stay alive.
    tokio::time::advance(Duration::from_secs(2)).await;
    tokio::task::yield_now().await;
    {
        let entry = manager
            .inner
            .get_mut()
            .entries
            .get(&key)
            .ok_or_else(|| anyhow!("worker retired despite live traffic"))?;
        assert!(matches!(entry.phase, Phase::Established));
        assert!(!entry.handle.is_finished(), "worker must still be running");
    }
    let replies = timeout(WAIT, manager.handle(forward(&key, b"after"))).await??;
    assert_eq!(replies.len(), 1, "forward after recheck must stay inline");
    assert_eq!(replies[0].header.msg_type, "ack");
    recv_exact(&peer, b"after").await?;

    // Past the rechecked deadline the worker emits a stop and closes.
    tokio::time::advance(Duration::from_secs(601)).await;
    let stop = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(stop.header.msg_type, "stop");

    assert!(matches!(shared.try_forward(b"probe"), Attempt::Failed(_)));
    keep_awake.0.abort();
    let _ = (&mut keep_awake.0).await;
    manager.close_all().await?;
    Ok(())
}
#[tokio::test]
async fn canceled_pending_admission_keeps_exactly_two_forward_credits() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    let shared = SharedUdp::new();
    let (commands, command_rx) = mpsc::channel(1);
    let (gate, gate_rx) = tokio::sync::oneshot::channel();
    let worker_key = key.clone();
    let worker_shared = shared.clone();
    let events = manager.event_tx.clone();
    let port = peer.local_addr()?.port();
    let handle = tokio::spawn(async move {
        if gate_rx.await.is_ok() {
            port_forward_worker::run_inner(
                worker_key,
                1,
                Network::Udp,
                "::1".into(),
                port,
                command_rx,
                events,
                port_forward_worker::WorkerMode::ManagedUdp(worker_shared),
            )
            .await;
        }
    });
    let inner = manager.inner.get_mut();
    inner.generation = 1;
    inner.entries.insert(
        key.clone(),
        Entry {
            tcp_frame_size: None,
            generation: 1,
            phase: Phase::Connecting,
            commands,
            handle,
            pending_message: None,
            udp_inline: Some(shared),
            legacy_forwards: 0,
        },
    );
    assert!(
        manager
            .handle(forward(&key, b"pending-a"))
            .await?
            .is_empty()
    );
    assert!(
        manager
            .handle(forward(&key, b"pending-b"))
            .await?
            .is_empty()
    );
    assert!(!manager.accepts_input());
    assert_eq!(manager.inner.get_mut().entries[&key].legacy_forwards, 2);
    {
        let mut future = Box::pin(manager.next_event());
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(future.as_mut().poll(&mut context).is_pending());
    }
    assert!(!manager.accepts_input());
    assert_eq!(manager.inner.get_mut().entries[&key].legacy_forwards, 2);
    gate.send(()).map_err(|_| anyhow!("worker gate closed"))?;
    let mut acks = 0;
    let mut saw_new = false;
    // At most New, two ACKs and one admission outcome can be produced.
    for _ in 0..4 {
        if manager.accepts_input() {
            break;
        }
        if let Some(message) = timeout(WAIT, manager.next_event()).await?? {
            match message.header.msg_type.as_str() {
                "new" => {
                    assert!(!saw_new);
                    saw_new = true;
                }
                "ack" => acks += 1,
                other => return Err(anyhow!("unexpected pending-admission frame: {other}")),
            }
        }
        assert_eq!(
            manager.inner.get_mut().entries[&key].legacy_forwards + acks,
            2,
            "admitting an already-counted pending command must not add a credit"
        );
    }
    assert!(manager.accepts_input());
    for _ in 0..3 {
        if saw_new && acks == 2 {
            break;
        }
        let message = timeout(WAIT, manager.next_message()).await??;
        match message.header.msg_type.as_str() {
            "new" => {
                assert!(!saw_new);
                saw_new = true;
            }
            "ack" => acks += 1,
            other => return Err(anyhow!("unexpected completion frame: {other}")),
        }
        assert_eq!(
            manager.inner.get_mut().entries[&key].legacy_forwards + acks,
            2
        );
    }
    assert!(saw_new);
    assert_eq!(acks, 2);
    assert_eq!(manager.inner.get_mut().entries[&key].legacy_forwards, 0);
    recv_exact(&peer, b"pending-a").await?;
    recv_exact(&peer, b"pending-b").await?;
    manager.close_all().await?;
    Ok(())
}
#[tokio::test]
async fn inline_ack_does_not_release_outbound_gate_or_truncate_oversize() -> Result<()> {
    let key = key()?;
    let peer = target().await?;
    let mut manager = PortForwardManager::new();
    open(&mut manager, &key, peer.local_addr()?.port()).await?;
    warm(&mut manager, &key).await?;
    let mut buffer = [0u8; 8192];
    let (len, client) = timeout(WAIT, peer.recv_from(&mut buffer)).await??;
    assert_eq!(&buffer[..len], b"warm");
    let shared = manager
        .inner
        .get_mut()
        .entries
        .get(&key)
        .and_then(|entry| entry.udp_inline.clone())
        .ok_or_else(|| anyhow!("missing descriptor"))?;
    peer.send_to(&[], client).await?;
    let first = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(first.header.msg_type, "forward");
    assert!(first.body.is_empty());
    let outbound = vec![0x42; 4096];
    peer.send_to(&outbound, client).await?;
    let replies = manager
        .handle(forward(&key, b"independent inbound"))
        .await?;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0].header.msg_type, "ack");
    recv_exact(&peer, b"independent inbound").await?;
    // The managed UDP worker is allowed a bounded ACK window. The independent
    // inbound ack must not release that credit, but the worker may already have
    // emitted the next outbound frame under the window.
    let second = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(second.header.msg_type, "forward");
    assert_eq!(second.body, outbound);
    assert!(
        timeout(NO_DATA, manager.next_message()).await.is_err(),
        "third outbound frame must wait for a peer ACK"
    );
    assert!(manager.handle(ack(&key)).await?.is_empty());
    peer.send_to(&vec![0x99; 4097], client).await?;
    let failure = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(
        failure.header.msg_type, "error",
        "oversize datagram must never become a truncated forward"
    );
    let stop = timeout(WAIT, manager.next_message()).await??;
    assert_eq!(stop.header.msg_type, "stop");
    assert!(matches!(shared.try_forward(b"closed"), Attempt::Failed(_)));
    manager.close_all().await?;
    Ok(())
}
