use std::collections::BTreeMap;

use anyhow::{Result, bail};
use rmpv::Value;
use serde::{Deserialize, Serialize};

use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType, decode, encode};

const MAX_FIELD_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ConnectionKey {
    proto: ProtoType,
    session: String,
    id: String,
    /// v2 peers can request the ACK-based client-to-device flow-control
    /// extension in the `new` header. It is deliberately opt-in so a stock v2
    /// peer that never acknowledges frames keeps the original unpaced path.
    flow_control: bool,
}

impl ConnectionKey {
    pub fn from_header(header: &ProtoHdr) -> Result<Self> {
        if !matches!(
            header.proto,
            ProtoType::PORT_FORWARD | ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
        ) {
            bail!("unsupported protocol for port forward: {}", header.proto);
        }
        let session = header.session_id.as_str();
        if session.is_empty() || session.len() > MAX_FIELD_LEN {
            bail!("invalid session id length");
        }
        let id = match header.properties.get("connection_id") {
            Some(Value::String(value)) => value
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("connection_id is not valid utf-8"))?,
            Some(_) => bail!("connection_id must be a string"),
            None => bail!("missing connection_id property"),
        };
        if id.is_empty() || id.len() > MAX_FIELD_LEN {
            bail!("invalid connection_id length");
        }
        let flow_control = id.ends_with(":flow")
            || match header.properties.get("flow_control") {
                Some(Value::Boolean(value)) => *value,
                Some(Value::String(value)) => value.as_str() == Some("true"),
                _ => false,
            };
        Ok(Self {
            proto: header.proto,
            session: session.to_owned(),
            id: id.to_owned(),
            flow_control,
        })
    }

    pub fn proto(&self) -> ProtoType {
        self.proto
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn flow_control(&self) -> bool {
        self.flow_control
    }

    pub fn message(&self, typ: &str, body: Vec<u8>) -> ProtoMsg {
        let mut properties = BTreeMap::new();
        properties.insert(
            "connection_id".to_owned(),
            Value::String(self.id.clone().into()),
        );
        ProtoMsg {
            header: ProtoHdr {
                proto: self.proto,
                msg_type: typ.to_owned(),
                session_id: self.session.clone(),
                properties,
            },
            body,
        }
    }
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    err: &'a str,
    msgtype: &'a str,
}

pub fn error_reply(header: &ProtoHdr, error: &str) -> Result<ProtoMsg> {
    let body = encode(&ErrorBody {
        err: error,
        msgtype: &header.msg_type,
    })?;
    let mut properties = BTreeMap::new();
    if let Some(Value::String(value)) = header.properties.get("connection_id")
        && let Some(text) = value.as_str()
    {
        properties.insert("connection_id".to_owned(), Value::String(text.into()));
    }
    Ok(ProtoMsg {
        header: ProtoHdr {
            proto: header.proto,
            msg_type: "error".to_owned(),
            session_id: header.session_id.clone(),
            properties,
        },
        body,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

#[derive(Debug)]
pub enum ForwardRequest {
    New {
        key: ConnectionKey,
        network: Network,
        host: String,
        port: u16,
    },
    Forward {
        key: ConnectionKey,
        body: Vec<u8>,
    },
    Ack {
        key: ConnectionKey,
        count: u32,
    },
    Stop {
        key: ConnectionKey,
    },
}

#[derive(Deserialize)]
struct NewBody {
    remote_host: String,
    remote_port: u16,
    protocol: String,
    #[serde(default)]
    flow_control: bool,
}

const MAX_HOST_LEN: usize = 253;
const MAX_FORWARD_BODY: usize = 4096;
const V2_MAX_FORWARD_BODY: usize = 7680;

pub fn parse(message: ProtoMsg) -> Result<ForwardRequest> {
    let key = ConnectionKey::from_header(&message.header)?;
    match message.header.msg_type.as_str() {
        "new" => {
            let body: NewBody = decode(&message.body)?;
            let network = match body.protocol.as_str() {
                "tcp" => Network::Tcp,
                "udp" => Network::Udp,
                other => bail!("unsupported protocol: {other}"),
            };
            if body.remote_host.is_empty() || body.remote_host.len() > MAX_HOST_LEN {
                bail!("invalid remote_host length");
            }
            if body.remote_host.chars().any(char::is_control) {
                bail!("remote_host contains control characters");
            }
            if body.remote_port == 0 {
                bail!("remote_port must be non-zero");
            }
            let mut key = key;
            key.flow_control = body.flow_control || key.flow_control;
            Ok(ForwardRequest::New {
                key,
                network,
                host: body.remote_host,
                port: body.remote_port,
            })
        }
        "forward" => {
            let max_body = if matches!(
                key.proto(),
                ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
            ) {
                V2_MAX_FORWARD_BODY
            } else {
                MAX_FORWARD_BODY
            };
            if message.body.len() > max_body {
                bail!("forward body too large");
            }
            Ok(ForwardRequest::Forward {
                key,
                body: message.body,
            })
        }
        "ack" => {
            if !matches!(
                key.proto(),
                ProtoType::PORT_FORWARD | ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
            ) {
                bail!("ack only supported for port-forward protocols");
            }
            let count = if key.proto() == ProtoType::PORT_FORWARD_V3 {
                message
                    .body
                    .get(..4)
                    .and_then(|bytes| bytes.try_into().ok())
                    .map(u32::from_be_bytes)
                    .unwrap_or(1)
            } else {
                1
            };
            Ok(ForwardRequest::Ack { key, count })
        }
        "stop" => Ok(ForwardRequest::Stop { key }),
        other => bail!("unsupported message type: {other}"),
    }
}
