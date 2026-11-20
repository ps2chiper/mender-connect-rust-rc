//! Real local-socket tests for the port-forward worker.
//!
//! Every spawned worker and helper server/feeder task is wrapped in an
//! [`AbortGuard`] that aborts its task on drop, so a failing assertion can never
//! leak a background task. These tests use real sockets in real time; they do
//! not use `start_paused`, because virtual time can race OS I/O readiness.

use std::collections::BTreeMap;
use std::time::Duration;

use rmpv::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinHandle};
use tokio::time::timeout;

use mender_connect_rust::port_forward::{ConnectionKey, Network};
use mender_connect_rust::port_forward_worker::{Command, Event, run};
use mender_connect_rust::protocol::{ProtoHdr, ProtoType};

const WAIT: Duration = Duration::from_secs(2);

/// Unconditionally aborts the wrapped task when dropped, even on panic.
struct AbortGuard {
    handle: Option<JoinHandle<()>>,
}

impl AbortGuard {
    fn new(handle: JoinHandle<()>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    async fn abort_and_join(&mut self) -> Result<(), JoinError> {
        match self.handle.take() {
            Some(handle) => {
                handle.abort();
                handle.await
            }
            None => Ok(()),
        }
    }
}

impl Drop for AbortGuard {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// A running worker driven through a bounded command channel and observed
/// through a bounded event channel.
struct Worker {
    commands: mpsc::Sender<Command>,
    events: mpsc::Receiver<Event>,
    guard: AbortGuard,
    key: ConnectionKey,
    generation: u64,
}

fn make_key(proto: ProtoType) -> ConnectionKey {
    let mut properties = BTreeMap::new();
    properties.insert("connection_id".to_owned(), Value::String("conn-1".into()));
    let header = ProtoHdr {
        proto,
        msg_type: "new".to_owned(),
        session_id: "session-1".to_owned(),
        properties,
    };
    ConnectionKey::from_header(&header).expect("valid connection key")
}

fn spawn_worker(
    key: ConnectionKey,
    network: Network,
    host: String,
    port: u16,
    capacity: usize,
) -> Worker {
    let (commands_tx, commands_rx) = mpsc::channel(capacity);
    let (events_tx, events_rx) = mpsc::channel(capacity);
    let generation = 42u64;
    let run_key = key.clone();
    let handle = tokio::spawn(async move {
        run(
            run_key,
            generation,
            network,
            host,
            port,
            commands_rx,
            events_tx,
        )
        .await;
    });
    Worker {
        commands: commands_tx,
        events: events_rx,
        guard: AbortGuard::new(handle),
        key,
        generation,
    }
}

async fn recv_event(worker: &mut Worker) -> Event {
    match timeout(WAIT, worker.events.recv()).await {
        Ok(Some(event)) => event,
        Ok(None) => panic!("event channel closed unexpectedly"),
        Err(_) => panic!("timed out waiting for a worker event"),
    }
}

fn assert_message(event: &Event, worker: &Worker, typ: &str, body: &[u8]) {
    let Event::Message {
        key,
        generation,
        message,
    } = event
    else {
        panic!("expected a `{typ}` message, got Finished");
    };
    assert_eq!(key, &worker.key, "connection identity");
    assert_eq!(*generation, worker.generation, "generation");
    assert_eq!(message.header.msg_type.as_str(), typ, "message type");
    assert_eq!(message.header.proto, worker.key.proto(), "proto");
    assert_eq!(
        message.header.session_id.as_str(),
        worker.key.session(),
        "session"
    );
    assert_eq!(message.body, body, "message body");
}

async fn assert_no_event(worker: &mut Worker, within: Duration) {
    match timeout(within, worker.events.recv()).await {
        Err(_) => {}
        Ok(Some(_)) => panic!("received an unexpected event before acknowledgement"),
        Ok(None) => panic!("event channel closed unexpectedly"),
    }
}

fn decode_error_body(body: &[u8]) -> (String, String) {
    let mut cursor = body;
    let value = rmpv::decode::read_value(&mut cursor).expect("decode error body");
    let mut err = String::new();
    let mut msgtype = String::new();
    if let Some(entries) = value.as_map() {
        for (key, value) in entries {
            match key.as_str() {
                Some("err") => {
                    if let Some(text) = value.as_str() {
                        err = text.to_owned();
                    }
                }
                Some("msgtype") => {
                    if let Some(text) = value.as_str() {
                        msgtype = text.to_owned();
                    }
                }
                _ => {}
            }
        }
    }
    (err, msgtype)
}

#[tokio::test]
async fn tcp_v2_binary_echo() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0u8; 1024];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(len) => {
                        let chunk = buf.get(..len).unwrap_or(&[]).to_vec();
                        if stream.write_all(&chunk).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD_V2);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    worker
        .commands
        .send(Command::Forward(b"hello\0tcp\xff".to_vec()))
        .await
        .expect("send forward");
    let echo = recv_event(&mut worker).await;
    assert_message(&echo, &worker, "forward", b"hello\0tcp\xff");
}

#[tokio::test]
async fn udp_v2_binary_echo() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = server.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((len, peer)) = server.recv_from(&mut buf).await {
            let chunk = buf
                .get(..len)
                .expect("UDP read stayed within buffer")
                .to_vec();
            if server.send_to(&chunk, peer).await.is_err() {
                break;
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD_V2);
    let mut worker = spawn_worker(key, Network::Udp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    worker
        .commands
        .send(Command::Forward(b"ping\0udp\xff".to_vec()))
        .await
        .expect("send forward");
    let echo = recv_event(&mut worker).await;
    assert_message(&echo, &worker, "forward", b"ping\0udp\xff");
}

/// Full v1 UDP datagram roundtrip across the outbound-ack gate.
///
/// The reply must be `new`, then an incoming-forward acknowledgement, then the
/// echoed binary datagram. Because the worker gates further socket reads until
/// the peer acks outbound data, a second binary datagram can only complete once
/// the test sends `Command::Ack`.
#[tokio::test]
async fn udp_v1_binary_echo_across_ack_gate() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = server.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        let mut buf = [0u8; 1024];
        while let Ok((len, peer)) = server.recv_from(&mut buf).await {
            let chunk = buf
                .get(..len)
                .expect("UDP read stayed within buffer")
                .to_vec();
            if server.send_to(&chunk, peer).await.is_err() {
                break;
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD);
    let mut worker = spawn_worker(key, Network::Udp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    let first = b"\x00\xffudp-one\xff\x00".to_vec();
    worker
        .commands
        .send(Command::Forward(first.clone()))
        .await
        .expect("send forward");

    // v1 acknowledges the incoming forward direction before any echo is seen.
    let ack = recv_event(&mut worker).await;
    assert_message(&ack, &worker, "ack", &[]);

    // The echo of the outbound datagram arrives as a forward and sets the
    // pending ack, which disables further socket reads.
    let echo = recv_event(&mut worker).await;
    assert_message(&echo, &worker, "forward", &first);

    // Release the ack gate, then exercise a second binary datagram roundtrip.
    worker
        .commands
        .send(Command::Ack(1))
        .await
        .expect("send ack");

    let second = b"\xff\x00udp-two\x00\xff".to_vec();
    worker
        .commands
        .send(Command::Forward(second.clone()))
        .await
        .expect("send forward");

    let ack2 = recv_event(&mut worker).await;
    assert_message(&ack2, &worker, "ack", &[]);

    let echo2 = recv_event(&mut worker).await;
    assert_message(&echo2, &worker, "forward", &second);
}

#[tokio::test]
async fn tcp_v1_outbound_gate_blocks_second_forward_until_ack() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let _server = AbortGuard::new(tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            if stream.write_all(b"first").await.is_err() {
                return;
            }
            // Hold the second chunk until the test releases it.
            let _ = release_rx.await;
            let _ = stream.write_all(b"second").await;
            let mut sink = [0u8; 64];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    let first = recv_event(&mut worker).await;
    assert_message(&first, &worker, "forward", b"first");

    // The outbound forward now has a pending ack, so reads are gated. Even once
    // the server writes the second chunk, no forward event may appear.
    let _ = release_tx.send(());
    assert_no_event(&mut worker, Duration::from_millis(300)).await;

    worker
        .commands
        .send(Command::Ack(1))
        .await
        .expect("send ack");
    let second = recv_event(&mut worker).await;
    assert_message(&second, &worker, "forward", b"second");
}

#[tokio::test]
async fn incoming_forward_ack_does_not_stall_outbound_reading() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            // Wait until the worker has written the forwarded byte, then emit
            // an outbound chunk of our own.
            let mut buf = [0u8; 16];
            let _ = stream.read(&mut buf).await;
            let _ = stream.write_all(b"y").await;
            let mut sink = [0u8; 16];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    worker
        .commands
        .send(Command::Forward(b"x".to_vec()))
        .await
        .expect("send forward");

    // The inbound forward is acknowledged without setting `pending_ack`.
    let ack = recv_event(&mut worker).await;
    assert_message(&ack, &worker, "ack", &[]);

    // Outbound reading must continue: the server's chunk arrives as a forward.
    let outbound = recv_event(&mut worker).await;
    assert_message(&outbound, &worker, "forward", b"y");
}

#[tokio::test]
async fn udp_zero_length_datagram_roundtrip() {
    let server = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = server.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        let mut buf = [0u8; 16];
        while let Ok((len, peer)) = server.recv_from(&mut buf).await {
            let chunk = buf
                .get(..len)
                .expect("UDP read stayed within buffer")
                .to_vec();
            if server.send_to(&chunk, peer).await.is_err() {
                break;
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD_V2);
    let mut worker = spawn_worker(key, Network::Udp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    worker
        .commands
        .send(Command::Forward(Vec::new()))
        .await
        .expect("send empty forward");
    let echo = recv_event(&mut worker).await;
    // A zero-length UDP read is an empty datagram, not EOF.
    assert_message(&echo, &worker, "forward", &[]);
}

#[tokio::test]
async fn abort_while_pending_v1_ack_terminates_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"data").await;
            let mut sink = [0u8; 16];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 8);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    // Reading the server chunk sets `pending_ack`, gating further reads.
    let pending = recv_event(&mut worker).await;
    assert_message(&pending, &worker, "forward", b"data");

    let joined = timeout(WAIT, worker.guard.abort_and_join())
        .await
        .expect("worker abort stayed bounded");
    assert!(
        joined.is_err(),
        "aborted worker task must not complete normally"
    );
}

#[tokio::test]
async fn abort_while_output_queue_full_terminates_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let _server = AbortGuard::new(tokio::spawn(async move {
        if let Ok((mut stream, _)) = listener.accept().await {
            let _ = stream.write_all(b"z").await;
            let mut sink = [0u8; 16];
            loop {
                match stream.read(&mut sink).await {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD_V2);
    // Capacity 1: the setup `new` fills the queue, so the next outbound send
    // blocks and the worker must still abort cleanly.
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 1);

    // Never drain the events: let the worker fill the slot and block on send.
    tokio::time::sleep(Duration::from_millis(250)).await;

    let joined = timeout(WAIT, worker.guard.abort_and_join())
        .await
        .expect("worker abort stayed bounded");
    assert!(
        joined.is_err(),
        "aborted worker task must not complete normally"
    );
}

#[tokio::test]
async fn connect_failure_reports_new_msgtype() {
    // Reserve then drop a port so nothing is listening on it.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);

    let key = make_key(ProtoType::PORT_FORWARD);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 8);

    match recv_event(&mut worker).await {
        Event::Message { message, .. } => {
            assert_eq!(message.header.msg_type.as_str(), "error");
            let (err, msgtype) = decode_error_body(&message.body);
            assert_eq!(msgtype, "new", "failed message type must be `new`");
            assert!(!err.is_empty(), "error body must carry a reason");
        }
        Event::Finished { .. } => panic!("expected an error message before Finished"),
    }

    match recv_event(&mut worker).await {
        Event::Finished { .. } => {}
        Event::Message { .. } => panic!("expected Finished after the error message"),
    }
}

/// The server must emit its marker only after the feeder is already flooding
/// the command channel, so a biased `select!` that always prefers commands
/// would genuinely starve the socket read instead of passing trivially.
#[tokio::test]
async fn sustained_incoming_traffic_does_not_starve_marker_reads() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("local addr");
    let (release_tx, release_rx) = oneshot::channel::<()>();
    let _server = AbortGuard::new(tokio::spawn(async move {
        let Ok((mut stream, _)) = listener.accept().await else {
            return;
        };
        let mut sink = [0u8; 1024];
        let mut release_rx = release_rx;

        // Drain forwarded payloads until the test releases the marker. The
        // server itself emits nothing before that release.
        let released = loop {
            tokio::select! {
                res = &mut release_rx => {
                    break res.is_ok();
                }
                read = stream.read(&mut sink) => {
                    match read {
                        Ok(0) | Err(_) => return,
                        Ok(_) => {}
                    }
                }
            }
        };
        if !released {
            return;
        }
        if stream.write_all(b"MARKER").await.is_err() {
            return;
        }

        // Keep draining so the worker never sees a spurious EOF.
        loop {
            match stream.read(&mut sink).await {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }));

    let key = make_key(ProtoType::PORT_FORWARD_V2);
    let mut worker = spawn_worker(key, Network::Tcp, "127.0.0.1".to_owned(), addr.port(), 4);

    let new = recv_event(&mut worker).await;
    assert_message(&new, &worker, "new", &[]);

    // Continuously flood inbound forwards so the command channel stays busy and
    // competes with socket reads. The feeder signals once it is actively
    // sending; the task is abort-guarded and terminates when the channel closes.
    let (active_tx, active_rx) = oneshot::channel::<()>();
    let feeder_tx = worker.commands.clone();
    let _feeder = AbortGuard::new(tokio::spawn(async move {
        let mut active_tx = Some(active_tx);
        loop {
            if feeder_tx
                .send(Command::Forward(b"payload".to_vec()))
                .await
                .is_err()
            {
                break;
            }
            if let Some(tx) = active_tx.take() {
                let _ = tx.send(());
            }
        }
    }));

    // Only once the feeder has scored a successful send do we arm the marker.
    timeout(WAIT, active_rx)
        .await
        .expect("feeder never became active")
        .expect("feeder active signal dropped");
    release_tx.send(()).expect("release marker");

    let marker = timeout(WAIT, async {
        loop {
            match worker.events.recv().await {
                Some(Event::Message { message, .. }) => {
                    if message.header.msg_type.as_str() == "forward"
                        && message.body == b"MARKER".to_vec()
                    {
                        return true;
                    }
                }
                Some(Event::Finished { .. }) => return false,
                None => return false,
            }
        }
    })
    .await;

    assert_eq!(
        marker,
        Ok(true),
        "the target marker was starved by sustained incoming commands"
    );
}
