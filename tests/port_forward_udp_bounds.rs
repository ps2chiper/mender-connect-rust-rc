use std::collections::BTreeMap;
use std::time::Duration;

use mender_connect_rust::port_forward::{ConnectionKey, Network};
use mender_connect_rust::port_forward_worker::{Command, Event, run};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(2);

struct Worker(tokio::task::JoinHandle<()>);
impl Drop for Worker {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn message(events: &mut mpsc::Receiver<Event>, kind: &str) -> ProtoMsg {
    match timeout(WAIT, events.recv())
        .await
        .expect("bounded event")
        .expect("live event channel")
    {
        Event::Message { message, .. } => {
            assert_eq!(message.header.msg_type, kind);
            message
        }
        Event::Finished { .. } => panic!("worker finished before {kind}"),
    }
}

async fn udp_bounds(proto: ProtoType) {
    let target = UdpSocket::bind("[::1]:0").await.expect("owned target");
    let key = ConnectionKey::from_header(&ProtoHdr {
        proto,
        msg_type: "new".into(),
        session_id: "udp-bounds".into(),
        properties: BTreeMap::from([("connection_id".into(), rmpv::Value::from("connection"))]),
    })
    .expect("valid fixture identity");
    let (commands, command_rx) = mpsc::channel(8);
    let (event_tx, mut events) = mpsc::channel(8);
    let mut worker = Worker(tokio::spawn(run(
        key,
        7,
        Network::Udp,
        "::1".into(),
        target.local_addr().expect("target address").port(),
        command_rx,
        event_tx,
    )));
    message(&mut events, "new").await;
    commands
        .send(Command::Forward(b"seed".to_vec()))
        .await
        .expect("discovery command");
    let mut buffer = [0u8; 32];
    let (count, client) = timeout(WAIT, target.recv_from(&mut buffer))
        .await
        .expect("bounded discovery")
        .expect("discovery receive");
    assert_eq!(&buffer[..count], b"seed");
    if proto == ProtoType::PORT_FORWARD {
        message(&mut events, "ack").await;
    }
    for size in [0, 4096] {
        let payload = vec![0x42; size];
        target
            .send_to(&payload, client)
            .await
            .expect("owned datagram send");
        let frame = message(&mut events, "forward").await;
        assert_eq!(
            frame.body, payload,
            "empty and exact-limit datagrams stay intact"
        );
        if proto == ProtoType::PORT_FORWARD {
            commands.send(Command::Ack).await.expect("v1 ACK");
        }
    }
    target
        .send_to(&vec![0x99; 4097], client)
        .await
        .expect("oversize datagram send");
    // No `forward` prefix may precede the terminal typed error.
    let failure = message(&mut events, "error").await;
    let body: BTreeMap<String, rmpv::Value> =
        rmp_serde::from_slice(&failure.body).expect("typed error body");
    assert_eq!(
        body.get("msgtype").and_then(rmpv::Value::as_str),
        Some("forward")
    );
    let reason = body
        .get("err")
        .and_then(rmpv::Value::as_str)
        .expect("error reason");
    assert!(
        reason.contains("udp") && reason.contains("4096"),
        "{reason}"
    );
    message(&mut events, "stop").await;
    assert!(matches!(
        timeout(WAIT, events.recv()).await.expect("bounded finish"),
        Some(Event::Finished { .. })
    ));
    timeout(WAIT, &mut worker.0)
        .await
        .expect("worker exits")
        .expect("worker did not panic");
    assert!(
        timeout(WAIT, events.recv())
            .await
            .expect("closed event channel")
            .is_none()
    );
}

#[tokio::test]
async fn v1_udp_preserves_empty_and_limit_datagrams_rejects_oversize_without_prefix() {
    udp_bounds(ProtoType::PORT_FORWARD).await;
}

#[tokio::test]
async fn v2_udp_preserves_empty_and_limit_datagrams_rejects_oversize_without_prefix() {
    udp_bounds(ProtoType::PORT_FORWARD_V2).await;
}
