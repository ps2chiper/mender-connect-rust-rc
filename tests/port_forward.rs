use std::collections::BTreeMap;

use mender_connect_rust::port_forward::{
    ConnectionKey, ForwardRequest, Network, error_reply, parse,
};
use mender_connect_rust::protocol::{ProtoHdr, ProtoMsg, ProtoType, decode, encode};
use rmpv::Value;

fn cid(value: &str) -> Value {
    Value::from(value)
}

fn header(proto: ProtoType, msg_type: &str, session: &str, connection: Option<Value>) -> ProtoHdr {
    let mut properties = BTreeMap::new();
    if let Some(value) = connection {
        properties.insert("connection_id".to_owned(), value);
    }
    ProtoHdr {
        proto,
        msg_type: msg_type.to_owned(),
        session_id: session.to_owned(),
        properties,
    }
}

fn message(
    proto: ProtoType,
    msg_type: &str,
    session: &str,
    connection: Option<Value>,
    body: Vec<u8>,
) -> ProtoMsg {
    ProtoMsg {
        header: header(proto, msg_type, session, connection),
        body,
    }
}

fn key(proto: ProtoType, session: &str, connection: &str) -> ConnectionKey {
    ConnectionKey::from_header(&header(proto, "new", session, Some(cid(connection))))
        .expect("valid key")
}

fn new_message(body: Vec<u8>) -> ProtoMsg {
    message(ProtoType::PORT_FORWARD, "new", "sid", Some(cid("c1")), body)
}

#[derive(serde::Serialize)]
struct NewBody<'a> {
    remote_host: &'a str,
    remote_port: u16,
    protocol: &'a str,
}

#[derive(serde::Serialize)]
struct NoHost<'a> {
    remote_port: u16,
    protocol: &'a str,
}

#[derive(serde::Serialize)]
struct NoPort<'a> {
    remote_host: &'a str,
    protocol: &'a str,
}

#[derive(serde::Serialize)]
struct NoProto<'a> {
    remote_host: &'a str,
    remote_port: u16,
}

#[derive(serde::Deserialize)]
struct ErrorBody {
    err: String,
    msgtype: String,
}

fn new_body(host: &str, port: u16, protocol: &str) -> Vec<u8> {
    encode(&NewBody {
        remote_host: host,
        remote_port: port,
        protocol,
    })
    .expect("encode new body")
}

#[test]
fn key_rejects_unsupported_protocol() {
    let hdr = header(ProtoType::SHELL, "new", "sid", Some(cid("c1")));
    assert!(ConnectionKey::from_header(&hdr).is_err());
}

#[test]
fn key_rejects_empty_missing_and_wrong_type_cid() {
    assert!(
        ConnectionKey::from_header(&header(ProtoType::PORT_FORWARD, "new", "sid", None)).is_err()
    );
    assert!(
        ConnectionKey::from_header(&header(
            ProtoType::PORT_FORWARD,
            "new",
            "sid",
            Some(cid(""))
        ))
        .is_err()
    );
    assert!(
        ConnectionKey::from_header(&header(
            ProtoType::PORT_FORWARD,
            "new",
            "sid",
            Some(Value::from(7u8))
        ))
        .is_err()
    );
}

#[test]
fn key_rejects_bad_session_and_id_lengths() {
    assert!(
        ConnectionKey::from_header(&header(ProtoType::PORT_FORWARD, "new", "", Some(cid("c1"))))
            .is_err()
    );
    let long = "a".repeat(129);
    let long_session = header(ProtoType::PORT_FORWARD, "new", &long, Some(cid("c1")));
    assert!(ConnectionKey::from_header(&long_session).is_err());
    let long_id = header(ProtoType::PORT_FORWARD, "new", "sid", Some(cid(&long)));
    assert!(ConnectionKey::from_header(&long_id).is_err());
}

#[test]
fn key_accepts_boundary_lengths() {
    let max = "a".repeat(128);
    let k = key(ProtoType::PORT_FORWARD, &max, &max);
    assert_eq!(k.session().len(), 128);
    assert_eq!(k.id().len(), 128);
}

#[test]
fn keys_differ_for_same_cid() {
    let a = key(ProtoType::PORT_FORWARD, "s1", "c1");
    let b = key(ProtoType::PORT_FORWARD, "s2", "c1");
    let c = key(ProtoType::PORT_FORWARD_V2, "s1", "c1");
    assert_ne!(a, b);
    assert_ne!(a, c);
}

#[test]
fn new_parses_tcp_and_udp() {
    match parse(new_message(new_body("example", 80, "tcp"))).expect("tcp") {
        ForwardRequest::New {
            network,
            host,
            port,
            ..
        } => {
            assert_eq!(network, Network::Tcp);
            assert_eq!(host, "example");
            assert_eq!(port, 80);
        }
        _ => panic!("expected New"),
    }
    match parse(new_message(new_body("example", 53, "udp"))).expect("udp") {
        ForwardRequest::New { network, .. } => assert_eq!(network, Network::Udp),
        _ => panic!("expected New"),
    }
}

#[test]
fn new_rejects_malformed_and_missing_fields() {
    assert!(parse(new_message(vec![0xc1, 0xff])).is_err());
    assert!(
        parse(new_message(
            encode(&NoHost {
                remote_port: 80,
                protocol: "tcp"
            })
            .unwrap()
        ))
        .is_err()
    );
    assert!(
        parse(new_message(
            encode(&NoPort {
                remote_host: "h",
                protocol: "tcp"
            })
            .unwrap()
        ))
        .is_err()
    );
    assert!(
        parse(new_message(
            encode(&NoProto {
                remote_host: "h",
                remote_port: 80
            })
            .unwrap()
        ))
        .is_err()
    );
}

#[test]
fn new_rejects_invalid_values() {
    assert!(parse(new_message(new_body("h", 0, "tcp"))).is_err());
    assert!(parse(new_message(new_body("h", 80, "sctp"))).is_err());
    assert!(parse(new_message(new_body("bad\u{0}host", 80, "tcp"))).is_err());
    assert!(parse(new_message(new_body("bad\u{1}host", 80, "tcp"))).is_err());
    assert!(parse(new_message(new_body(&"a".repeat(254), 80, "tcp"))).is_err());
    assert!(parse(new_message(new_body(&"a".repeat(253), 80, "tcp"))).is_ok());
}

#[test]
fn v2_uses_larger_forward_frames_but_v1_stays_at_4k() {
    let v2_payload = vec![0x5a; 7_680];
    match parse(message(
        ProtoType::PORT_FORWARD_V2,
        "forward",
        "sid",
        Some(cid("c1")),
        v2_payload.clone(),
    ))
    .expect("7.5 KiB v2 forward body")
    {
        ForwardRequest::Forward { body, .. } => assert_eq!(body, v2_payload),
        _ => panic!("expected Forward"),
    }
    assert!(
        parse(message(
            ProtoType::PORT_FORWARD_V2,
            "forward",
            "sid",
            Some(cid("c1")),
            vec![0; 7_681],
        ))
        .is_err(),
        "v2 body over the server-safe frame limit must fail"
    );
    assert!(
        parse(message(
            ProtoType::PORT_FORWARD,
            "forward",
            "sid",
            Some(cid("c1")),
            vec![0; 4097],
        ))
        .is_err(),
        "v1 keeps its 4 KiB body limit"
    );
}

#[test]
fn forward_body_size_bounds() {
    let ok = message(
        ProtoType::PORT_FORWARD,
        "forward",
        "sid",
        Some(cid("c1")),
        vec![0u8; 4096],
    );
    match parse(ok).expect("4096 accepted") {
        ForwardRequest::Forward { body, .. } => assert_eq!(body.len(), 4096),
        _ => panic!("expected Forward"),
    }
    let big = message(
        ProtoType::PORT_FORWARD,
        "forward",
        "sid",
        Some(cid("c1")),
        vec![0u8; 4097],
    );
    assert!(parse(big).is_err());
}

#[test]
fn ack_only_for_v1_and_unknown_type_rejected() {
    assert!(matches!(
        parse(message(
            ProtoType::PORT_FORWARD,
            "ack",
            "sid",
            Some(cid("c1")),
            vec![]
        ))
        .expect("ack v1"),
        ForwardRequest::Ack { .. }
    ));
    assert!(matches!(
        parse(message(
            ProtoType::PORT_FORWARD_V2,
            "ack",
            "sid",
            Some(cid("c1")),
            vec![]
        ))
        .expect("ack v2"),
        ForwardRequest::Ack { .. }
    ));
    assert!(
        parse(message(
            ProtoType::PORT_FORWARD,
            "bogus",
            "sid",
            Some(cid("c1")),
            vec![]
        ))
        .is_err()
    );
}

#[test]
fn v3_ack_body_carries_batch_count() {
    match parse(message(
        ProtoType::PORT_FORWARD_V3,
        "ack",
        "sid",
        Some(cid("c1")),
        vec![0, 0, 0, 4],
    ))
    .expect("v3 ack")
    {
        ForwardRequest::Ack { count, .. } => assert_eq!(count, 4),
        _ => panic!("expected Ack"),
    }
    match parse(message(
        ProtoType::PORT_FORWARD_V3,
        "ack",
        "sid",
        Some(cid("c1")),
        vec![],
    ))
    .expect("v3 ack without body")
    {
        ForwardRequest::Ack { count, .. } => assert_eq!(count, 1),
        _ => panic!("expected Ack"),
    }
}

#[test]
fn error_reply_preserves_header_and_encodes_body() {
    let hdr = header(ProtoType::PORT_FORWARD_V2, "new", "sid", Some(cid("c1")));
    let reply = error_reply(&hdr, "boom").expect("error reply");
    assert_eq!(reply.header.proto, ProtoType::PORT_FORWARD_V2);
    assert_eq!(reply.header.msg_type, "error");
    assert_eq!(reply.header.session_id, "sid");
    match reply.header.properties.get("connection_id") {
        Some(Value::String(value)) => assert_eq!(value.as_str(), Some("c1")),
        _ => panic!("missing connection_id"),
    }
    let body: ErrorBody = decode(&reply.body).expect("decode error body");
    assert_eq!(body.err, "boom");
    assert_eq!(body.msgtype, "new");
}
