use std::collections::BTreeMap;

use mender_connect_rust::protocol::{
    Accept, Error as ErrorBody, MAX_DECODE_DEPTH, Open, ProtoHdr, ProtoMsg, ProtoType, decode,
    encode, encode_message,
};
use rmpv::Value;

fn hex(bytes: &str) -> Vec<u8> {
    bytes
        .split_whitespace()
        .map(|byte| u8::from_str_radix(byte, 16).unwrap())
        .collect()
}

#[test]
fn protocol_numbers_match_the_reference_values() {
    assert_eq!(
        [
            ProtoType::SHELL.0,
            ProtoType::FILE_TRANSFER.0,
            ProtoType::PORT_FORWARD.0,
            ProtoType::MENDER_CLIENT.0,
            ProtoType::FILE_TRANSFER_V2.0,
            ProtoType::PORT_FORWARD_V2.0,
            ProtoType::CONTROL.0,
        ],
        [1, 2, 3, 4, 0x102, 0x103, 0xffff]
    );
}

#[test]
fn encodes_named_maps_binary_body_and_dynamic_properties() {
    let mut properties = BTreeMap::new();
    properties.insert("x".to_owned(), Value::from(7i64));
    properties.insert("y".to_owned(), Value::from("z"));

    let message = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "open".to_owned(),
            session_id: "s1".to_owned(),
            properties,
        },
        body: vec![0xde, 0xad],
    };

    let expected = hex("82 a3 68 64 72 84
         a5 70 72 6f 74 6f 01
         a3 74 79 70 a4 6f 70 65 6e
         a3 73 69 64 a2 73 31
         a5 70 72 6f 70 73 82 a1 78 07 a1 79 a1 7a
         a4 62 6f 64 79 c4 02 de ad");

    assert_eq!(encode(&message).unwrap(), expected);

    let decoded: ProtoMsg = decode(&expected).unwrap();
    assert_eq!(decoded, message);
}

#[test]
fn omits_optional_fields_when_empty() {
    let message = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            ..ProtoHdr::default()
        },
        body: Vec::new(),
    };

    let expected = hex("81 a3 68 64 72 81 a5 70 72 6f 74 6f 01");
    assert_eq!(encode(&message).unwrap(), expected);

    let decoded: ProtoMsg = decode(&expected).unwrap();
    assert_eq!(decoded.header.proto, ProtoType::SHELL);
    assert!(decoded.header.msg_type.is_empty());
    assert!(decoded.header.session_id.is_empty());
    assert!(decoded.header.properties.is_empty());
    assert!(decoded.body.is_empty());
}

#[test]
fn preserves_unknown_protocol_numbers() {
    let data = hex("81 a3 68 64 72 81 a5 70 72 6f 74 6f cd 42 42");
    let message: ProtoMsg = decode(&data).unwrap();
    assert_eq!(message.header.proto, ProtoType(0x4242));
}

#[test]
fn rejects_malformed_input() {
    let error = decode::<ProtoMsg>(&[]).unwrap_err();
    assert!(error.to_string().contains("malformed"));

    assert!(decode::<ProtoMsg>(&hex("81 a3 68 64")).is_err());
}

#[test]
fn rejects_trailing_bytes_and_excessive_depth() {
    let message = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            ..ProtoHdr::default()
        },
        body: Vec::new(),
    };

    let mut data = encode(&message).unwrap();
    data.push(0xc0);
    let error = decode::<ProtoMsg>(&data).unwrap_err();
    assert!(error.to_string().contains("trailing"));

    let mut nested = vec![0x91; MAX_DECODE_DEPTH + 1];
    nested.push(0xc0);
    assert!(decode::<Value>(&nested).is_err());
}

#[test]
fn decodes_explicit_nil_body_for_shell_new_envelope() {
    let frame = hex("82 a3 68 64 72 84
        a5 70 72 6f 74 6f 01
        a3 74 79 70 a3 6e 65 77
        a3 73 69 64 a5 70 72 6f 62 65
        a5 70 72 6f 70 73 80
        a4 62 6f 64 79 c0");

    let message: ProtoMsg = decode(&frame).unwrap();
    assert_eq!(message.header.proto, ProtoType::SHELL);
    assert_eq!(message.header.msg_type, "new");
    assert_eq!(message.header.session_id, "probe");
    assert!(message.header.properties.is_empty());
    assert!(message.body.is_empty());
}

#[test]
fn decodes_absent_and_empty_binary_bodies_as_empty_bytes() {
    let absent = hex("81 a3 68 64 72 81 a5 70 72 6f 74 6f 01");
    let absent_message: ProtoMsg = decode(&absent).unwrap();
    assert!(absent_message.body.is_empty());

    let empty_binary = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 c4 00");
    let empty_message: ProtoMsg = decode(&empty_binary).unwrap();
    assert!(empty_message.body.is_empty());
}

#[test]
fn decodes_nonempty_binary_and_prior_string_and_array_body_forms() {
    let binary = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 c4 02 de ad");
    let binary_message: ProtoMsg = decode(&binary).unwrap();
    assert_eq!(binary_message.body, vec![0xde, 0xad]);

    let string = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 a2 68 69");
    let string_message: ProtoMsg = decode(&string).unwrap();
    assert_eq!(string_message.body, b"hi");

    let array = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 92 01 02");
    let array_message: ProtoMsg = decode(&array).unwrap();
    assert_eq!(array_message.body, vec![1, 2]);
}

#[test]
fn rejects_number_map_and_invalid_sequence_bodies() {
    let number = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 01");
    assert!(decode::<ProtoMsg>(&number).is_err());

    let map = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 80");
    assert!(decode::<ProtoMsg>(&map).is_err());

    let invalid_sequence = hex("82 a3 68 64 72 81 a5 70 72 6f 74 6f 01
         a4 62 6f 64 79 91 c0");
    assert!(decode::<ProtoMsg>(&invalid_sequence).is_err());
}

#[test]
fn control_messages_use_the_expected_named_keys() {
    let open = Open { versions: vec![1] };
    let open_bytes = hex("81 a8 76 65 72 73 69 6f 6e 73 91 01");
    assert_eq!(encode(&open).unwrap(), open_bytes);
    assert_eq!(decode::<Open>(&open_bytes).unwrap(), open);

    let accept = Accept {
        version: 1,
        protocols: vec![ProtoType::SHELL, ProtoType::FILE_TRANSFER_V2],
    };
    let accept_bytes = hex("82 a7 76 65 72 73 69 6f 6e 01
         a9 70 72 6f 74 6f 63 6f 6c 73 92 01 cd 01 02");
    assert_eq!(encode(&accept).unwrap(), accept_bytes);
    assert_eq!(decode::<Accept>(&accept_bytes).unwrap(), accept);

    let error = ErrorBody {
        error: "denied".to_owned(),
        close: true,
        ..ErrorBody::default()
    };
    let error_bytes = hex("82 a3 65 72 72 a6 64 65 6e 69 65 64 a5 63 6c 6f 73 65 c3");
    assert_eq!(encode(&error).unwrap(), error_bytes);
    assert_eq!(decode::<ErrorBody>(&error_bytes).unwrap(), error);
}

fn offset_marker_and_bytes(bytes: &[u8]) -> (u8, [u8; 8]) {
    let key = [0xa6, b'o', b'f', b'f', b's', b'e', b't'];
    let position = bytes
        .windows(key.len())
        .position(|window| window == key)
        .expect("offset key present");
    let marker = bytes[position + key.len()];
    let mut value = [0u8; 8];
    value.copy_from_slice(&bytes[position + key.len() + 1..position + key.len() + 9]);
    (marker, value)
}

fn file_transfer_message(proto: ProtoType, offset: Value) -> ProtoMsg {
    let mut properties = BTreeMap::new();
    properties.insert("offset".to_owned(), offset);
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: "file_chunk".to_owned(),
            session_id: "s".to_owned(),
            properties,
        },
        body: b"data".to_vec(),
    }
}

#[test]
fn encode_message_uses_fixed_i64_marker_for_offsets() {
    for proto in [ProtoType::FILE_TRANSFER, ProtoType::FILE_TRANSFER_V2] {
        for (offset, expected) in [
            (0i64, 0i64.to_be_bytes()),
            (1, 1i64.to_be_bytes()),
            (4096, 4096i64.to_be_bytes()),
            (i64::MAX, i64::MAX.to_be_bytes()),
        ] {
            let message = file_transfer_message(proto, Value::from(offset));
            let encoded = encode_message(&message).unwrap();
            let (marker, value) = offset_marker_and_bytes(&encoded);
            assert_eq!(marker, 0xd3, "proto {proto} offset {offset}");
            assert_eq!(value, expected, "proto {proto} offset {offset}");
        }
    }
}

#[test]
fn encode_message_rejects_invalid_offsets() {
    for proto in [ProtoType::FILE_TRANSFER, ProtoType::FILE_TRANSFER_V2] {
        let non_integer = file_transfer_message(proto, Value::from("x"));
        assert!(encode_message(&non_integer).is_err());

        let negative = file_transfer_message(proto, Value::from(-1i64));
        assert!(encode_message(&negative).is_err());
    }
}

#[test]
fn encode_message_matches_generic_encode_for_non_file_transfer() {
    let mut properties = BTreeMap::new();
    properties.insert("x".to_owned(), Value::from(7i64));
    let shell = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::SHELL,
            msg_type: "shell".to_owned(),
            session_id: "s1".to_owned(),
            properties,
        },
        body: vec![0xde, 0xad],
    };
    assert_eq!(encode_message(&shell).unwrap(), encode(&shell).unwrap());

    let control = ProtoMsg {
        header: ProtoHdr {
            proto: ProtoType::CONTROL,
            msg_type: "open".to_owned(),
            session_id: "s1".to_owned(),
            properties: BTreeMap::new(),
        },
        body: encode(&Open { versions: vec![1] }).unwrap(),
    };
    assert_eq!(encode_message(&control).unwrap(), encode(&control).unwrap());
}

#[test]
fn encode_message_roundtrips_through_strict_decode() {
    let message = file_transfer_message(ProtoType::FILE_TRANSFER, Value::from(4096i64));
    let encoded = encode_message(&message).unwrap();
    let decoded: ProtoMsg = decode(&encoded).unwrap();
    assert_eq!(decoded, message);
}
