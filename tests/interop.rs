use std::collections::HashSet;

use mender_connect_rust::protocol::{Accept, Open, ProtoMsg, ProtoType, decode, encode_message};
use rmpv::Value;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    wire_hex: String,
}

fn load_fixtures() -> Vec<Fixture> {
    serde_json::from_str(include_str!("fixtures/go-protocol.json")).expect("fixture JSON")
}

fn assert_properties(message: &ProtoMsg, expected: &[(&str, Value)]) {
    assert_eq!(
        message.header.properties.len(),
        expected.len(),
        "property count"
    );
    for (key, value) in expected {
        assert_eq!(
            message.header.properties.get(*key),
            Some(value),
            "property {key}"
        );
    }
}

#[test]
fn decodes_all_go_generated_fixtures() {
    let fixtures = load_fixtures();
    assert_eq!(fixtures.len(), 8);

    let mut seen = HashSet::new();
    for fixture in fixtures {
        let wire = hex::decode(&fixture.wire_hex).expect("fixture hex");
        let message: ProtoMsg =
            decode(&wire).unwrap_or_else(|error| panic!("{}: {error}", fixture.name));

        match fixture.name.as_str() {
            "minimal" => {
                assert_eq!(message.header.proto, ProtoType::SHELL);
                assert_eq!(message.header.msg_type, "");
                assert_eq!(message.header.session_id, "");
                assert!(message.header.properties.is_empty());
                assert!(message.body.is_empty());
            }
            "shell_binary" => {
                assert_eq!(message.header.proto, ProtoType::SHELL);
                assert_eq!(message.header.msg_type, "shell");
                assert_eq!(message.header.session_id, "trial-session");
                assert_properties(&message, &[("status", Value::from(1i64))]);
                assert_eq!(message.body, vec![0, 1, 127, 128, 255]);
            }
            "transfer_offset" => {
                assert_eq!(message.header.proto, ProtoType::FILE_TRANSFER);
                assert_eq!(message.header.msg_type, "file_chunk");
                assert_eq!(message.header.session_id, "transfer-session");
                assert_properties(&message, &[("offset", Value::from(4096i64))]);
                assert_eq!(message.body, b"reference data".to_vec());
            }
            "open" => {
                assert_eq!(message.header.proto, ProtoType::CONTROL);
                assert_eq!(message.header.msg_type, "open");
                assert_eq!(message.header.session_id, "trial-session");
                assert!(message.header.properties.is_empty());
                assert_eq!(
                    message.body,
                    hex::decode("81a876657273696f6e739101").unwrap()
                );
                let open: Open = decode(&message.body).expect("Open body");
                assert_eq!(open.versions, vec![1]);
            }
            "accept" => {
                assert_eq!(message.header.proto, ProtoType::CONTROL);
                assert_eq!(message.header.msg_type, "accept");
                assert_eq!(message.header.session_id, "trial-session");
                assert!(message.header.properties.is_empty());
                assert_eq!(
                    message.body,
                    hex::decode(
                        "82a776657273696f6e01a970726f746f636f6c7396cd0001cd0002cd0003cd0004cd0102cd0103"
                    )
                    .unwrap()
                );
                let accept: Accept = decode(&message.body).expect("Accept body");
                assert_eq!(accept.version, 1);
                assert_eq!(
                    accept.protocols,
                    vec![
                        ProtoType::SHELL,
                        ProtoType::FILE_TRANSFER,
                        ProtoType::PORT_FORWARD,
                        ProtoType::MENDER_CLIENT,
                        ProtoType::FILE_TRANSFER_V2,
                        ProtoType::PORT_FORWARD_V2,
                    ]
                );
            }
            "unknown_protocol" => {
                assert_eq!(message.header.proto, ProtoType(32768));
                assert_eq!(message.header.msg_type, "");
                assert_eq!(message.header.session_id, "");
                assert_properties(&message, &[("custom", Value::from("preserved"))]);
                assert!(message.body.is_empty());
            }
            "filetransfer_v2" => {
                assert_eq!(message.header.proto, ProtoType::FILE_TRANSFER_V2);
                assert_eq!(message.header.msg_type, "ack");
                assert_eq!(message.header.session_id, "v2");
                assert!(message.header.properties.is_empty());
                assert!(message.body.is_empty());
            }
            "portforward_v2" => {
                assert_eq!(message.header.proto, ProtoType::PORT_FORWARD_V2);
                assert_eq!(message.header.msg_type, "stop");
                assert_eq!(message.header.session_id, "v2");
                assert!(message.header.properties.is_empty());
                assert!(message.body.is_empty());
            }
            other => panic!("unexpected fixture {other}"),
        }

        assert!(
            seen.insert(fixture.name.clone()),
            "duplicate fixture {}",
            fixture.name
        );
    }
}

#[test]
fn reencodes_transfer_offset_with_fixed_i64_marker() {
    let fixtures = load_fixtures();
    let fixture = fixtures
        .iter()
        .find(|fixture| fixture.name == "transfer_offset")
        .expect("transfer_offset fixture");
    let wire = hex::decode(&fixture.wire_hex).expect("fixture hex");
    let message: ProtoMsg = decode(&wire).expect("decode fixture");
    let encoded = encode_message(&message).expect("encode_message");

    let key = [0xa6, b'o', b'f', b'f', b's', b'e', b't'];
    let position = encoded
        .windows(key.len())
        .position(|window| window == key)
        .expect("offset key present");
    assert_eq!(encoded[position + key.len()], 0xd3);
    assert_eq!(
        &encoded[position + key.len() + 1..position + key.len() + 9],
        &4096i64.to_be_bytes()
    );
}
