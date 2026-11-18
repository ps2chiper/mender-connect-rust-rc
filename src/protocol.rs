//! MessagePack schemas used by the Mender device connect protocol.
//!
//! Encoding uses named MessagePack maps and binary bodies so that the wire
//! format matches the Go `go-lib-micro/ws` structures used by mender-connect.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Cursor;

use rmpv::Value;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

/// Maximum nesting depth accepted by [`decode`].
pub const MAX_DECODE_DEPTH: usize = 128;

/// Protocol identifier carried in `ProtoHdr::proto`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProtoType(pub u16);

impl ProtoType {
    pub const INVALID: Self = Self(0);
    pub const SHELL: Self = Self(1);
    pub const FILE_TRANSFER: Self = Self(2);
    pub const PORT_FORWARD: Self = Self(3);
    pub const MENDER_CLIENT: Self = Self(4);
    pub const FILE_TRANSFER_V2: Self = Self(0x102);
    pub const PORT_FORWARD_V2: Self = Self(0x103);
    pub const CONTROL: Self = Self(0xffff);

    pub fn is_unspecified(&self) -> bool {
        self.0 == Self::INVALID.0
    }
}

impl Default for ProtoType {
    fn default() -> Self {
        Self::INVALID
    }
}

impl From<u16> for ProtoType {
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl fmt::Display for ProtoType {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// Header of a `ProtoMsg`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct ProtoHdr {
    #[serde(rename = "proto")]
    pub proto: ProtoType,
    #[serde(default, rename = "typ", skip_serializing_if = "String::is_empty")]
    pub msg_type: String,
    #[serde(default, rename = "sid", skip_serializing_if = "String::is_empty")]
    pub session_id: String,
    #[serde(default, rename = "props", skip_serializing_if = "BTreeMap::is_empty")]
    pub properties: BTreeMap<String, Value>,
}

/// A device connect protocol message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProtoMsg {
    #[serde(rename = "hdr")]
    pub header: ProtoHdr,
    #[serde(
        default,
        rename = "body",
        serialize_with = "serde_bytes::serialize",
        deserialize_with = "deserialize_body",
        skip_serializing_if = "Vec::is_empty"
    )]
    pub body: Vec<u8>,
}

/// Deserialize a protocol body, treating both an absent field and an explicit
/// MessagePack nil as an empty byte vector.
fn deserialize_body<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let body = Option::<serde_bytes::ByteBuf>::deserialize(deserializer)?;
    Ok(body.map(|body| body.into_vec()).unwrap_or_default())
}

/// Control message body used to initiate a protocol handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Open {
    #[serde(default, rename = "versions")]
    pub versions: Vec<i64>,
}

/// Control message body accepting a protocol handshake.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Accept {
    #[serde(default, rename = "version")]
    pub version: i64,
    #[serde(default, rename = "protocols")]
    pub protocols: Vec<ProtoType>,
}

/// Control message body describing an error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Error {
    #[serde(default, rename = "err")]
    pub error: String,
    #[serde(default, rename = "close")]
    pub close: bool,
    #[serde(default, rename = "code", skip_serializing_if = "is_zero_i64")]
    pub code: i64,
    #[serde(
        default,
        rename = "msgproto",
        skip_serializing_if = "ProtoType::is_unspecified"
    )]
    pub message_proto: ProtoType,
    #[serde(default, rename = "msgtype", skip_serializing_if = "String::is_empty")]
    pub message_type: String,
    #[serde(default, rename = "msgid", skip_serializing_if = "String::is_empty")]
    pub message_id: String,
}

fn is_zero_i64(value: &i64) -> bool {
    *value == 0
}

/// Errors returned by protocol encoding and decoding.
#[derive(Debug)]
pub enum ProtocolError {
    Encode(rmp_serde::encode::Error),
    Decode(rmp_serde::decode::Error),
    EncodeRmp(rmp::encode::ValueWriteError),
    InvalidOffset(String),
    TrailingBytes { position: usize, length: usize },
    SizeOverflow(String),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(error) => {
                write!(formatter, "failed to encode MessagePack value: {error}")
            }
            Self::Decode(error) => {
                write!(formatter, "malformed MessagePack input: {error}")
            }
            Self::EncodeRmp(error) => {
                write!(formatter, "failed to encode MessagePack value: {error}")
            }
            Self::InvalidOffset(reason) => {
                write!(formatter, "invalid file transfer offset property: {reason}")
            }
            Self::TrailingBytes { position, length } => write!(
                formatter,
                "trailing bytes after MessagePack value: consumed {position} of {length} bytes"
            ),
            Self::SizeOverflow(reason) => {
                write!(formatter, "value too large to encode: {reason}")
            }
        }
    }
}

impl std::error::Error for ProtocolError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encode(error) => Some(error),
            Self::Decode(error) => Some(error),
            Self::EncodeRmp(error) => Some(error),
            Self::InvalidOffset(_) => None,
            Self::TrailingBytes { .. } => None,
            Self::SizeOverflow(_) => None,
        }
    }
}

impl From<rmp_serde::encode::Error> for ProtocolError {
    fn from(error: rmp_serde::encode::Error) -> Self {
        Self::Encode(error)
    }
}

impl From<rmp_serde::decode::Error> for ProtocolError {
    fn from(error: rmp_serde::decode::Error) -> Self {
        Self::Decode(error)
    }
}

impl From<rmp::encode::ValueWriteError> for ProtocolError {
    fn from(error: rmp::encode::ValueWriteError) -> Self {
        Self::EncodeRmp(error)
    }
}

/// Serialize a value as a named MessagePack map.
pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, ProtocolError> {
    rmp_serde::to_vec_named(value).map_err(ProtocolError::Encode)
}

/// Deserialize exactly one MessagePack value.
///
/// Trailing bytes are rejected, and nesting is bounded by
/// [`MAX_DECODE_DEPTH`].
pub fn decode<T: DeserializeOwned>(data: &[u8]) -> Result<T, ProtocolError> {
    let mut cursor = Cursor::new(data);
    let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
    deserializer.set_max_depth(MAX_DECODE_DEPTH);
    let value = T::deserialize(&mut deserializer).map_err(ProtocolError::Decode)?;
    drop(deserializer);

    let position = usize::try_from(cursor.position())
        .map_err(|_| ProtocolError::SizeOverflow("decoded position exceeds usize".to_owned()))?;
    if position != data.len() {
        return Err(ProtocolError::TrailingBytes {
            position,
            length: data.len(),
        });
    }

    Ok(value)
}

/// Check that `len` fits in a MessagePack `u32` length field.
fn checked_len_u32(len: usize, what: &str) -> Result<u32, ProtocolError> {
    u32::try_from(len).map_err(|_| {
        ProtocolError::SizeOverflow(format!("{what} length {len} exceeds MessagePack u32 limit"))
    })
}

/// Serialize a protocol message for the wire, matching the Go reference
/// encoder.
///
/// This is identical to [`encode`] except that the `offset` property of
/// `FILE_TRANSFER` and `FILE_TRANSFER_V2` frames is always written as a
/// fixed-width signed 64-bit integer (`0xd3`). The Go file transfer handler
/// type-asserts `header.Properties["offset"].(int64)`, so a minimized
/// integer would be rejected at runtime.
pub fn encode_message(message: &ProtoMsg) -> Result<Vec<u8>, ProtocolError> {
    let header = &message.header;
    let has_body = !message.body.is_empty();

    // Validate every length that will be written as a MessagePack u32 length
    // before writing anything, so an oversized value cannot produce a
    // truncated or corrupt frame.
    checked_len_u32(header.msg_type.len(), "msg_type")?;
    checked_len_u32(header.session_id.len(), "session_id")?;
    let properties_len = checked_len_u32(header.properties.len(), "properties")?;
    for key in header.properties.keys() {
        checked_len_u32(key.len(), "property key")?;
    }
    checked_len_u32(message.body.len(), "body")?;

    let mut buffer = Vec::new();

    rmp::encode::write_map_len(&mut buffer, if has_body { 2 } else { 1 })?;
    rmp::encode::write_str(&mut buffer, "hdr")?;

    let mut header_len = 1u32;
    if !header.msg_type.is_empty() {
        header_len += 1;
    }
    if !header.session_id.is_empty() {
        header_len += 1;
    }
    if !header.properties.is_empty() {
        header_len += 1;
    }
    rmp::encode::write_map_len(&mut buffer, header_len)?;

    rmp::encode::write_str(&mut buffer, "proto")?;
    rmp::encode::write_uint(&mut buffer, u64::from(header.proto.0))?;

    if !header.msg_type.is_empty() {
        rmp::encode::write_str(&mut buffer, "typ")?;
        rmp::encode::write_str(&mut buffer, &header.msg_type)?;
    }
    if !header.session_id.is_empty() {
        rmp::encode::write_str(&mut buffer, "sid")?;
        rmp::encode::write_str(&mut buffer, &header.session_id)?;
    }
    if !header.properties.is_empty() {
        rmp::encode::write_str(&mut buffer, "props")?;
        rmp::encode::write_map_len(&mut buffer, properties_len)?;

        let fixed_offset = matches!(
            header.proto,
            ProtoType::FILE_TRANSFER | ProtoType::FILE_TRANSFER_V2
        );

        for (key, value) in &header.properties {
            rmp::encode::write_str(&mut buffer, key)?;
            if fixed_offset && key == "offset" {
                let offset = match value {
                    Value::Integer(integer) => integer.as_i64(),
                    _ => None,
                };
                let offset = offset.ok_or_else(|| {
                    ProtocolError::InvalidOffset(
                        "offset property must be an integer representable as i64".to_owned(),
                    )
                })?;
                if offset < 0 {
                    return Err(ProtocolError::InvalidOffset(
                        "offset property must not be negative".to_owned(),
                    ));
                }
                rmp::encode::write_i64(&mut buffer, offset)?;
            } else {
                rmpv::encode::write_value(&mut buffer, value)?;
            }
        }
    }

    if has_body {
        rmp::encode::write_str(&mut buffer, "body")?;
        rmp::encode::write_bin(&mut buffer, &message.body)?;
    }

    Ok(buffer)
}
