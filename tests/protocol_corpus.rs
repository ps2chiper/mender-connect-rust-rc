//! Deterministic hostile-wire corpus. No filesystem/network side effects.
use mender_connect_rust::file_transfer_schema::{GetFile, StatFile, UploadRequest};
use mender_connect_rust::protocol::{Accept, Open, ProtoMsg, decode, encode_message};
use mender_connect_rust::transport::{encode_outbound_message, validate_inbound_message};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    name: String,
    wire_hex: String,
}

fn exercise(bytes: &[u8]) {
    if let Ok(message) = decode::<ProtoMsg>(bytes) {
        let _ = validate_inbound_message(&message);
        let _ = encode_message(&message);
        let _ = encode_outbound_message(&message);
    }
    let _ = decode::<Open>(bytes);
    let _ = decode::<Accept>(bytes);
    let _ = decode::<GetFile>(bytes);
    let _ = decode::<StatFile>(bytes);
    let _ = decode::<UploadRequest>(bytes);
}

#[test]
fn every_truncated_upstream_fixture_is_rejected() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/go-protocol.json")).unwrap();
    for fixture in fixtures {
        let wire = hex::decode(fixture.wire_hex).unwrap();
        assert!(decode::<ProtoMsg>(&wire).is_ok(), "{}", fixture.name);
        for end in 0..wire.len() {
            assert!(
                decode::<ProtoMsg>(wire.get(..end).unwrap()).is_err(),
                "{} truncated at {end}",
                fixture.name
            );
        }
    }
}

#[test]
fn single_bit_mutations_of_upstream_frames_never_panic() {
    let fixtures: Vec<Fixture> =
        serde_json::from_str(include_str!("fixtures/go-protocol.json")).unwrap();
    for fixture in fixtures {
        let wire = hex::decode(fixture.wire_hex).unwrap();
        for position in 0..wire.len() {
            for bit in 0..8 {
                let mut mutated = wire.clone();
                *mutated.get_mut(position).unwrap() ^= 1_u8.checked_shl(bit).unwrap();
                exercise(&mutated);
            }
        }
    }
}

fn byte(seed: &mut u64) -> u8 {
    // Explicit modulo-2^64 arithmetic is the deterministic corpus generator,
    // not arithmetic on any application or untrusted-input length.
    *seed = seed
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    u8::try_from(*seed >> 56).unwrap()
}

#[test]
fn bounded_random_and_declared_length_corpus_never_panics() {
    let mut seed = 0x5eaf_27d1_0000_0001_u64;
    for iteration in 0..10_000 {
        let length = if iteration % 157 == 0 {
            8192
        } else {
            usize::from(byte(&mut seed)) * 4
        };
        let mut wire = vec![0; length];
        for value in &mut wire {
            *value = byte(&mut seed);
        }
        exercise(&wire);
    }
    // A tiny packet must not turn its declared four-GiB collection/string/bin
    // lengths into an allocation of that size before reporting truncation.
    for marker in [0xc6, 0xc9, 0xdb, 0xdd, 0xdf] {
        exercise(&[marker, 0xff, 0xff, 0xff, 0xff]);
    }
}
