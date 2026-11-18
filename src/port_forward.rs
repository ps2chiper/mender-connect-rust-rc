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
}

impl ConnectionKey {
    pub fn from_header(header: &ProtoHdr) -> Result<Self> {
        if !matches!(
            header.proto,
            ProtoType::PORT_FORWARD | ProtoType::PORT_FORWARD_V2
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
        Ok(Self {
            proto: header.proto,
            session: session.to_owned(),
            id: id.to_owned(),
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
}

const MAX_HOST_LEN: usize = 253;
const MAX_FORWARD_BODY: usize = 4096;

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
            Ok(ForwardRequest::New {
                key,
                network,
                host: body.remote_host,
                port: body.remote_port,
            })
        }
        "forward" => {
            if message.body.len() > MAX_FORWARD_BODY {
                bail!("forward body too large");
            }
            Ok(ForwardRequest::Forward {
                key,
                body: message.body,
            })
        }
        "ack" => {
            if key.proto() != ProtoType::PORT_FORWARD {
                bail!("ack only supported for PORT_FORWARD");
            }
            Ok(ForwardRequest::Ack { key })
        }
        "stop" => Ok(ForwardRequest::Stop { key }),
        other => bail!("unsupported message type: {other}"),
    }
}
