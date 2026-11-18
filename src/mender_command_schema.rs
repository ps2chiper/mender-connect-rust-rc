//! Bounded schema helpers for the Mender client command handler.
//!
//! This module only validates and rewrites the small MessagePack envelope used
//! by `MenderClient` commands. It deliberately never interprets bodies or
//! properties as arguments, paths or environment values: ignored data is
//! budgeted, then dropped before returning.

use std::collections::BTreeMap;

use anyhow::{Result, bail};
use rmpv::Value;

use crate::protocol::{ProtoHdr, ProtoMsg, ProtoType};

/// Maximum accepted length (bytes) of the command type string.
const MAX_TYPE_LEN: usize = 64;
/// Maximum accepted length (bytes) of the session id string.
const MAX_SID_LEN: usize = 128;
/// Maximum accepted length (bytes) of a request body.
const MAX_BODY_LEN: usize = 65536;
/// Maximum accepted number of header properties.
const MAX_PROPS: usize = 32;
/// Total node/byte budget applied to all ignored property values.
const MAX_BUDGET: usize = 65536;
/// Maximum nesting depth inspected while budgeting property values.
const MAX_DEPTH: usize = 16;
/// Fixed cost charged per visited MessagePack node.
const NODE_COST: usize = 16;
/// Maximum length (bytes) of an echoed error diagnostic.
const MAX_ERROR_LEN: usize = 1024;

/// Supported Mender client command kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CommandKind {
    CheckUpdate,
    SendInventory,
}

impl CommandKind {
    /// Canonical wire name of the command.
    pub(super) fn argument(self) -> &'static str {
        match self {
            Self::CheckUpdate => "check-update",
            Self::SendInventory => "send-inventory",
        }
    }

    fn from_argument(value: &str) -> Option<Self> {
        match value {
            "check-update" => Some(Self::CheckUpdate),
            "send-inventory" => Some(Self::SendInventory),
            _ => None,
        }
    }
}

/// A validated command request with a sanitized header.
#[derive(Debug)]
pub(super) struct Request {
    pub header: ProtoHdr,
    pub command: CommandKind,
}

/// Validate an incoming `MenderClient` command message.
pub(super) fn parse(message: ProtoMsg) -> Result<Request> {
    let ProtoMsg { header, body } = message;
    let ProtoHdr {
        proto,
        msg_type,
        session_id,
        properties,
    } = header;

    if proto != ProtoType::MENDER_CLIENT {
        bail!("unexpected protocol for command: {}", proto);
    }
    if msg_type.len() > MAX_TYPE_LEN {
        bail!("command type exceeds {MAX_TYPE_LEN} bytes");
    }
    let command = CommandKind::from_argument(&msg_type)
        .ok_or_else(|| anyhow::anyhow!("unsupported command type {msg_type:?}"))?;
    if session_id.len() > MAX_SID_LEN {
        bail!("session id exceeds {MAX_SID_LEN} bytes");
    }
    if session_id.chars().any(char::is_control) {
        bail!("session id contains control characters");
    }
    if body.len() > MAX_BODY_LEN {
        bail!("command body exceeds {MAX_BODY_LEN} bytes");
    }
    charge_properties(&properties)?;

    // Only the fields needed to answer are retained; ignored properties and
    // the request body are dropped here.
    drop(properties);
    drop(body);

    Ok(Request {
        header: ProtoHdr {
            proto,
            msg_type,
            session_id,
            properties: BTreeMap::new(),
        },
        command,
    })
}

/// Build a bounded reply echoing `proto`, type and session id.
///
/// The echoed type and session id are truncated on a character boundary when
/// an invalid request supplied oversized values, so a rejection can never
/// produce an unbounded response. The request body is never reflected.
pub(super) fn reply(header: &ProtoHdr, error: Option<&str>) -> ProtoMsg {
    let status: i64 = if error.is_some() { 2 } else { 1 };
    let mut properties = BTreeMap::new();
    properties.insert("status".to_owned(), Value::from(status));

    let body = match error {
        Some(message) => truncate_utf8(message, MAX_ERROR_LEN).into_bytes(),
        None => Vec::new(),
    };

    ProtoMsg {
        header: ProtoHdr {
            proto: header.proto,
            msg_type: truncate_utf8(&header.msg_type, MAX_TYPE_LEN),
            session_id: truncate_utf8(&header.session_id, MAX_SID_LEN),
            properties,
        },
        body,
    }
}

/// Truncate a string to at most `max` bytes on a UTF-8 character boundary.
fn truncate_utf8(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value.get(..end).map(str::to_owned).unwrap_or_default()
}

/// Subtract `cost` from the remaining budget, rejecting on underflow.
fn charge_budget(budget: &mut usize, cost: usize) -> Result<()> {
    *budget = budget
        .checked_sub(cost)
        .ok_or_else(|| anyhow::anyhow!("ignored property budget exceeded"))?;
    Ok(())
}

/// Recursively budget a single ignored property value.
fn charge_value(value: &Value, budget: &mut usize, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        bail!("ignored property nesting exceeds {MAX_DEPTH} levels");
    }
    charge_budget(budget, NODE_COST)?;
    match value {
        Value::Nil | Value::Boolean(_) | Value::Integer(_) | Value::F32(_) | Value::F64(_) => {
            Ok(())
        }
        Value::String(text) => {
            let len = text
                .as_str()
                .ok_or_else(|| anyhow::anyhow!("ignored property string is not valid UTF-8"))?
                .len();
            charge_budget(budget, len)
        }
        Value::Binary(bytes) => charge_budget(budget, bytes.len()),
        Value::Array(items) => {
            for item in items {
                charge_value(item, budget, depth + 1)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            for (key, item) in entries {
                charge_value(key, budget, depth + 1)?;
                charge_value(item, budget, depth + 1)?;
            }
            Ok(())
        }
        Value::Ext(_, data) => charge_budget(budget, data.len()),
    }
}

/// Bound the ignored header properties (keys included) before dropping them.
fn charge_properties(properties: &BTreeMap<String, Value>) -> Result<()> {
    if properties.len() > MAX_PROPS {
        bail!("header properties exceed {MAX_PROPS}: {}", properties.len());
    }
    let mut budget = MAX_BUDGET;
    for (key, value) in properties {
        charge_budget(&mut budget, key.len())?;
        charge_value(value, &mut budget, 0)?;
    }
    Ok(())
}
