//! Websocket transport for the Mender device connect endpoint.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use futures_util::{SinkExt, StreamExt};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::handshake::client::Request;
use tokio_tungstenite::tungstenite::http::header::{AUTHORIZATION, HeaderValue};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
};
use url::Url;

use crate::protocol::{ProtoMsg, decode, encode_message};

pub const DEVICE_CONNECT_PATH: &str = "/api/devices/v1/deviceconnect/connect";
pub const MAX_INBOUND_MESSAGE_SIZE: usize = 8192;
// Extra envelope space for the largest negotiated TCP v3 data frame.
const MAX_V3_MESSAGE_SIZE: usize = crate::port_forward::V3_TCP_FRAME_SIZE + 512;
/// Maximum number of bytes allowed for inbound protocol header fields such as
/// the session id, message type, property keys, and routing identifiers.
pub const MAX_HEADER_FIELD_BYTES: usize = 128;
/// Maximum number of properties allowed on an inbound protocol message.
pub const MAX_INBOUND_PROPERTIES: usize = 32;
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(4);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// State retained across cancelled futures for an inbound ping whose
/// automatic pong has not yet been fully flushed.
struct PendingPing {
    /// Absolute deadline for flushing the automatic pong. It is set once when
    /// the inbound ping is observed and never reset on retry.
    flush_deadline: tokio::time::Instant,
    /// Whether a write has already flushed the queued automatic pong. The
    /// inbound ping notification is retained until it is returned by the
    /// receive helper.
    flushed: bool,
}

/// A connected device connect websocket.
pub struct Transport {
    websocket: WebSocketStream<MaybeTlsStream<TcpStream>>,
    pending_ping: Option<PendingPing>,
}

/// A single event read from the device connect websocket.
pub enum TransportEvent {
    /// A decoded binary protocol message.
    Message(ProtoMsg),
    /// An inbound websocket ping. The automatic pong has already been flushed.
    Ping,
    /// An inbound websocket pong.
    Pong,
    /// The websocket was closed or the stream ended.
    Closed,
}

/// Derive the websocket endpoint from a configured server URL.
///
/// The server path is replaced with the device connect path. Query strings,
/// fragments and any userinfo are not forwarded.
pub fn derive_connect_url(server_url: &str) -> Result<Url> {
    let mut url = Url::parse(server_url).context("invalid server URL")?;

    if url.host_str().is_none() {
        bail!("server URL must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("server URL must not contain credentials");
    }

    let websocket_scheme = match url.scheme() {
        "http" | "ws" => "ws",
        "https" | "wss" => "wss",
        other => bail!("unsupported server URL scheme: {other}"),
    };

    url.set_scheme(websocket_scheme)
        .map_err(|_| anyhow!("failed to set websocket URL scheme"))?;
    url.set_path(DEVICE_CONNECT_PATH);
    url.set_query(None);
    url.set_fragment(None);

    Ok(url)
}

/// Reject missing or header-unsafe JWT tokens.
pub fn validate_token(token: &str) -> Result<()> {
    if token.trim().is_empty() {
        bail!("JWT token must not be empty");
    }
    if token.chars().any(char::is_control) {
        bail!("JWT token contains invalid control characters");
    }
    Ok(())
}

fn bearer_header(token: &str) -> Result<HeaderValue> {
    validate_token(token)?;
    let mut value = HeaderValue::from_str(&format!("Bearer {token}"))
        .context("JWT token cannot be represented in an HTTP header")?;
    value.set_sensitive(true);
    Ok(value)
}

/// Build the websocket handshake request. This is public so URL and header
/// behavior can be tested without opening a connection.
pub fn build_connect_request(server_url: &str, token: &str) -> Result<Request> {
    let url = derive_connect_url(server_url)?;
    validate_token(token)?;

    let mut request = url
        .as_str()
        .into_client_request()
        .context("failed to build the websocket handshake request")?;
    request
        .headers_mut()
        .insert(AUTHORIZATION, bearer_header(token)?);

    Ok(request)
}

/// Return `true` when `error` was caused by a websocket handshake that was
/// rejected with HTTP status 401 (Unauthorized).
///
/// Inspects the complete typed error source chain produced by
/// [`Transport::connect`], matching only a `tungstenite::Error::Http` whose
/// status is exactly 401. Timeouts, TCP errors, HTTP 503 and HTTP 403 do not
/// qualify. No error-string matching is performed.
pub fn is_unauthorized_error(error: &anyhow::Error) -> bool {
    use tokio_tungstenite::tungstenite::Error as WsError;
    error
        .chain()
        .any(|cause| match cause.downcast_ref::<WsError>() {
            Some(WsError::Http(response)) => response.status().as_u16() == 401,
            _ => false,
        })
}

fn websocket_config() -> WebSocketConfig {
    let mut config = WebSocketConfig::default();
    config.max_message_size = Some(MAX_V3_MESSAGE_SIZE);
    config.max_frame_size = Some(MAX_V3_MESSAGE_SIZE);
    config
}

/// Build a rustls client configuration using an explicitly selected crypto
/// provider.
///
/// The provider is chosen per-configuration instead of being installed
/// process-wide via `install_default`, so constructing this config does not
/// rely on any global default and cannot panic when none is installed.
/// Standard, non-weak protocol versions are used and client certificate
/// authentication is disabled. Hostname verification stays at the library
/// default and no custom/dangerous verifier is used.
fn tls_client_config(roots: rustls::RootCertStore) -> Result<rustls::ClientConfig> {
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .context("failed to configure supported TLS protocol versions")?;

    Ok(builder.with_root_certificates(roots).with_no_client_auth())
}

/// Build a `wss` connector that trusts the platform native root store.
///
/// Native certificate loading is synchronous, matching the upstream
/// implementation; this assumes the platform certificate store is on a
/// responsive filesystem. Partial parsing failures are tolerated as long as at
/// least one valid root remains, matching upstream behavior. Certificate
/// contents, paths, and other secrets are never logged.
fn native_tls_connector() -> Result<Connector> {
    let native = rustls_native_certs::load_native_certs();

    let mut roots = rustls::RootCertStore::empty();
    let (added, _ignored) = roots.add_parsable_certificates(native.certs);
    if added == 0 {
        bail!("no valid native TLS root certificates could be loaded");
    }

    Ok(Connector::Rustls(Arc::new(tls_client_config(roots)?)))
}

/// Validate the semantic bounds of an inbound protocol message.
///
/// The decoded message must fit within the inbound frame size before reaching
/// application dispatch. This enforces bounded header fields (session id,
/// message type, property keys, and the `connection_id`/`msgid` routing
/// identifiers) and a bounded property count so that a small inbound frame
/// cannot be reflected into an oversized outbound frame downstream.
///
/// Error messages are static and never interpolate untrusted input. Empty
/// header values remain allowed; the protocol handler decides whether an empty
/// session id or message type is meaningful.
pub fn validate_inbound_message(message: &ProtoMsg) -> Result<()> {
    let header = &message.header;

    if header.session_id.len() > MAX_HEADER_FIELD_BYTES {
        bail!("inbound protocol message session id exceeds the length limit");
    }
    if header.msg_type.len() > MAX_HEADER_FIELD_BYTES {
        bail!("inbound protocol message type exceeds the length limit");
    }
    if header.properties.len() > MAX_INBOUND_PROPERTIES {
        bail!("inbound protocol message has too many properties");
    }
    for key in header.properties.keys() {
        if key.len() > MAX_HEADER_FIELD_BYTES {
            bail!("inbound protocol message property key exceeds the length limit");
        }
    }
    for routing in ["connection_id", "msgid"] {
        if let Some(value) = header.properties.get(routing) {
            match value.as_str() {
                Some(text) => {
                    if text.len() > MAX_HEADER_FIELD_BYTES {
                        bail!(
                            "inbound protocol message routing identifier exceeds the length limit"
                        );
                    }
                }
                None => {
                    bail!("inbound protocol message routing identifier must be a string");
                }
            }
        }
    }

    Ok(())
}

fn within_wire_limit(message: &ProtoMsg, encoded_size: usize) -> bool {
    encoded_size <= MAX_INBOUND_MESSAGE_SIZE
        || (message.header.proto == crate::protocol::ProtoType::PORT_FORWARD_V3
            && message.header.msg_type == "forward"
            && message.body.len() <= crate::port_forward::V3_TCP_FRAME_SIZE
            && encoded_size <= message.body.len().saturating_add(512)
            && encoded_size <= MAX_V3_MESSAGE_SIZE)
}

/// Encode an outbound protocol message with the inbound size bound.
///
/// This intentionally applies only the size limit and not the inbound
/// semantic header validation: outbound responses may legitimately carry
/// larger routing identifiers than a peer is allowed to send. The encoded
/// message must fit within [`MAX_INBOUND_MESSAGE_SIZE`] so that both
/// directions share a consistent cap.
pub fn encode_outbound_message(message: &ProtoMsg) -> Result<Vec<u8>> {
    let encoded = encode_message(message).context("failed to encode the protocol message")?;
    if !within_wire_limit(message, encoded.len()) {
        bail!("outbound protocol message exceeds the size limit");
    }
    Ok(encoded)
}

/// Compute the absolute write deadline for an outbound websocket write.
///
/// While an inbound ping is pending but not yet flushed, the write budget is
/// bounded by the earlier of `now + WRITE_TIMEOUT` and the stored absolute
/// pong flush deadline. Returns `None` when that stored deadline has already
/// elapsed and the write must not start.
fn write_deadline(pending: &Option<PendingPing>) -> Option<tokio::time::Instant> {
    let now = tokio::time::Instant::now();
    let budget = now + WRITE_TIMEOUT;
    match pending {
        Some(state) if !state.flushed => {
            if state.flush_deadline <= now {
                None
            } else {
                Some(budget.min(state.flush_deadline))
            }
        }
        _ => Some(budget),
    }
}

/// Send an encoded protocol message with the size bound and a bounded write
/// timeout, keeping any pending pong notification intact.
async fn send_message_with_state<S>(
    websocket: &mut WebSocketStream<S>,
    pending: &mut Option<PendingPing>,
    message: &ProtoMsg,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let encoded = encode_outbound_message(message)?;

    let deadline = match write_deadline(pending) {
        Some(deadline) => deadline,
        None => bail!("timed out writing the websocket message"),
    };

    tokio::time::timeout_at(deadline, websocket.send(Message::Binary(encoded.into())))
        .await
        .context("timed out writing the websocket message")?
        .context("failed to write the websocket message")?;

    // A successful write flushes any queued automatic pong: record that the
    // flush has occurred while retaining the ping notification for the receive
    // helper.
    if let Some(state) = pending.as_mut() {
        state.flushed = true;
    }

    Ok(())
}

/// Send a websocket ping with the payload bound and a bounded write timeout,
/// keeping any pending pong notification intact.
async fn send_ping_with_state<S>(
    websocket: &mut WebSocketStream<S>,
    pending: &mut Option<PendingPing>,
    payload: &[u8],
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if payload.len() > 125 {
        bail!("ping payload exceeds 125 bytes");
    }

    let deadline = match write_deadline(pending) {
        Some(deadline) => deadline,
        None => bail!("timed out writing the websocket ping"),
    };

    tokio::time::timeout_at(
        deadline,
        websocket.send(Message::Ping(payload.to_vec().into())),
    )
    .await
    .context("timed out writing the websocket ping")?
    .context("failed to write the websocket ping")?;

    if let Some(state) = pending.as_mut() {
        state.flushed = true;
    }

    Ok(())
}

/// Read a single relevant websocket event, preserving cancellation-safe
/// pending pong state across cancelled futures.
async fn receive_event_with_state<S>(
    websocket: &mut WebSocketStream<S>,
    pending: &mut Option<PendingPing>,
) -> Result<TransportEvent>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    loop {
        // A completed write may already have flushed an inbound ping's
        // automatic pong; return the retained notification without waiting.
        if pending.as_ref().is_some_and(|state| state.flushed) {
            *pending = None;
            return Ok(TransportEvent::Ping);
        }

        // Flush a previously latched automatic pong using the same stored
        // absolute deadline across retries; never reset it.
        if let Some(state) = pending.as_ref() {
            let deadline = state.flush_deadline;
            if deadline <= tokio::time::Instant::now() {
                bail!("timed out flushing the automatic pong");
            }
            tokio::time::timeout_at(deadline, websocket.flush())
                .await
                .context("timed out flushing the automatic pong")?
                .context("failed to flush the automatic pong")?;
            *pending = None;
            return Ok(TransportEvent::Ping);
        }

        let message = match websocket.next().await {
            Some(Ok(message)) => message,
            Some(Err(error)) => {
                return Err(anyhow::Error::new(error).context("failed to read a websocket message"));
            }
            None => return Ok(TransportEvent::Closed),
        };

        match message {
            Message::Binary(data) => {
                if data.len() > MAX_V3_MESSAGE_SIZE {
                    bail!("inbound websocket message exceeds the size limit");
                }
                let message = decode(&data).context("failed to decode the protocol message")?;
                if !within_wire_limit(&message, data.len()) {
                    bail!("inbound protocol message exceeds the size limit");
                }
                validate_inbound_message(&message)
                    .context("inbound protocol message failed validation")?;
                return Ok(TransportEvent::Message(message));
            }
            Message::Close(_) => return Ok(TransportEvent::Closed),
            Message::Text(_) => {
                bail!("received an unexpected text websocket frame");
            }
            Message::Ping(_) => {
                // Latch the pending pong BEFORE the first flush await so a
                // cancelled future cannot lose it, then loop to flush under
                // the stored absolute deadline.
                *pending = Some(PendingPing {
                    flush_deadline: tokio::time::Instant::now() + WRITE_TIMEOUT,
                    flushed: false,
                });
                continue;
            }
            Message::Pong(_) => return Ok(TransportEvent::Pong),
            _ => continue,
        }
    }
}

impl Transport {
    /// Connect to the device connect endpoint with native TLS trust roots.
    pub async fn connect(server_url: &str, token: &str) -> Result<Self> {
        let request = build_connect_request(server_url, token)?;

        // Select the connector explicitly: a `wss` endpoint uses the native
        // root store with an explicitly configured crypto provider, while
        // plain `ws` uses no TLS at all.
        let connector = match request.uri().scheme_str() {
            Some("wss") => native_tls_connector()?,
            _ => Connector::Plain,
        };

        // ACK-driven forwarding needs prompt small writes. Disabling Nagle
        // avoids startup delays that can fill the UDP receive buffer before
        // the first forwarded datagram reaches the peer.
        const DISABLE_NAGLE: bool = true;

        let (websocket, _response) = tokio::time::timeout(
            CONNECT_TIMEOUT,
            connect_async_tls_with_config(
                request,
                Some(websocket_config()),
                DISABLE_NAGLE,
                Some(connector),
            ),
        )
        .await
        .context("timed out connecting to the device connect endpoint")?
        .context("failed to connect to the device connect endpoint")?;

        Ok(Self {
            websocket,
            pending_ping: None,
        })
    }

    /// Send a protocol message with a bounded write timeout.
    ///
    /// If this future is cancelled or times out, the websocket may be left in
    /// an indeterminate state and must not be reused. Drop the transport and
    /// reconnect instead.
    pub async fn send(&mut self, message: &ProtoMsg) -> Result<()> {
        send_message_with_state(&mut self.websocket, &mut self.pending_ping, message).await
    }

    /// Send a websocket ping with a bounded write timeout.
    ///
    /// The payload must be at most 125 bytes. If this future is cancelled or
    /// times out, the websocket may be left in an indeterminate state and must
    /// not be reused. Drop the transport and reconnect instead.
    pub async fn send_ping(&mut self, payload: &[u8]) -> Result<()> {
        send_ping_with_state(&mut self.websocket, &mut self.pending_ping, payload).await
    }

    /// Read exactly one relevant websocket event.
    ///
    /// Binary frames are decoded into protocol messages with the existing size
    /// limit and validation. An inbound ping has its automatic pong flushed
    /// under the write timeout before the event is returned. A close frame or
    /// end of stream yields [`TransportEvent::Closed`]. Internal frame variants
    /// are skipped.
    pub async fn receive_event(&mut self) -> Result<TransportEvent> {
        receive_event_with_state(&mut self.websocket, &mut self.pending_ping).await
    }

    /// Read the next binary protocol message, skipping heartbeat frames.
    ///
    /// This is a compatibility wrapper over [`Transport::receive_event`] that
    /// returns only application messages. A close frame or end of stream
    /// returns `None`.
    pub async fn receive(&mut self) -> Result<Option<ProtoMsg>> {
        loop {
            match self.receive_event().await? {
                TransportEvent::Message(message) => return Ok(Some(message)),
                TransportEvent::Closed => return Ok(None),
                TransportEvent::Ping | TransportEvent::Pong => continue,
            }
        }
    }

    /// Close the websocket with a bounded write timeout.
    ///
    /// If this future is cancelled or times out, the connection is not
    /// reusable. Reconnection supervision is intentionally not implemented in
    /// this milestone.
    pub async fn close(mut self) -> Result<()> {
        tokio::time::timeout(WRITE_TIMEOUT, SinkExt::close(&mut self.websocket))
            .await
            .context("timed out closing the websocket")?
            .context("failed to close the websocket")?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{ProtoHdr, ProtoType};

    #[test]
    fn builds_explicit_provider_config_without_global_default() {
        // Constructing this config proves an explicit crypto provider is
        // selected per-config: no process-global default needs to be present.
        let config = tls_client_config(rustls::RootCertStore::empty())
            .expect("explicit provider config should build");
        let _connector = Connector::Rustls(Arc::new(config));
    }

    #[test]
    fn derives_websocket_url_without_query_or_fragment() {
        let url = derive_connect_url("https://mender.example:8443/ignored/path?token=no#fragment")
            .unwrap();

        assert_eq!(url.scheme(), "wss");
        assert_eq!(url.host_str(), Some("mender.example"));
        assert_eq!(url.port(), Some(8443));
        assert_eq!(url.path(), DEVICE_CONNECT_PATH);
        assert_eq!(url.query(), None);
        assert_eq!(url.fragment(), None);
    }

    #[test]
    fn maps_http_and_ws_schemes() {
        assert_eq!(
            derive_connect_url("http://example.com").unwrap().scheme(),
            "ws"
        );
        assert_eq!(
            derive_connect_url("ws://example.com").unwrap().scheme(),
            "ws"
        );
        assert_eq!(
            derive_connect_url("wss://example.com").unwrap().scheme(),
            "wss"
        );
    }

    #[test]
    fn rejects_invalid_urls_schemes_and_empty_tokens() {
        assert!(derive_connect_url("not a URL").is_err());
        assert!(derive_connect_url("https://").is_err());
        assert!(derive_connect_url("ftp://example.com").is_err());
        assert!(derive_connect_url("https://user:pass@example.com").is_err());
        assert!(validate_token("").is_err());
        assert!(validate_token("   ").is_err());
        assert!(build_connect_request("https://example.com", "").is_err());
        assert!(build_connect_request("https://example.com", "bad\ntoken").is_err());
    }

    #[test]
    fn builds_bearer_authorization_header() {
        let request = build_connect_request("https://mender.example/base", "secret-token").unwrap();

        assert_eq!(
            request.uri().to_string(),
            "wss://mender.example/api/devices/v1/deviceconnect/connect"
        );
        let authorization = request.headers().get(AUTHORIZATION).unwrap();
        assert_eq!(authorization.to_str().unwrap(), "Bearer secret-token");
        assert!(authorization.is_sensitive());
    }

    fn build(value: serde_json::Value) -> ProtoMsg {
        let object = value.as_object().cloned().unwrap_or_default();
        let msg_type = object
            .get("typ")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        let session_id = object
            .get("sid")
            .and_then(|value| value.as_str())
            .unwrap_or_default()
            .to_string();
        let mut properties = std::collections::BTreeMap::new();
        if let Some(serde_json::Value::Object(props)) = object.get("props") {
            for (key, value) in props {
                let value = rmpv::ext::to_value(value).unwrap_or(rmpv::Value::Nil);
                properties.insert(key.clone(), value);
            }
        }
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type,
                session_id,
                properties,
            },
            body: Vec::new(),
        }
    }

    fn msg_with_props(properties: std::collections::BTreeMap<String, rmpv::Value>) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "shell".to_string(),
                session_id: "s".to_string(),
                properties,
            },
            body: Vec::new(),
        }
    }

    fn header(typ: &str, sid: &str) -> ProtoMsg {
        build(serde_json::json!({
            "typ": typ,
            "sid": sid,
            "props": {}
        }))
    }

    #[test]
    fn accepts_empty_session_id() {
        assert!(validate_inbound_message(&header("shell", "")).is_ok());
    }

    #[test]
    fn accepts_header_fields_at_byte_limit() {
        let sid = "s".repeat(MAX_HEADER_FIELD_BYTES);
        let typ = "t".repeat(MAX_HEADER_FIELD_BYTES);
        assert!(validate_inbound_message(&header(&typ, &sid)).is_ok());
    }

    #[test]
    fn rejects_header_fields_over_byte_limit() {
        let sid = "s".repeat(MAX_HEADER_FIELD_BYTES + 1);
        assert!(validate_inbound_message(&header("shell", &sid)).is_err());

        let typ = "t".repeat(MAX_HEADER_FIELD_BYTES + 1);
        assert!(validate_inbound_message(&header(&typ, "sid")).is_err());
    }

    #[test]
    fn counts_multibyte_utf8_for_header_limit() {
        // U+00E9 is two bytes in UTF-8.
        let ok = "\u{e9}".repeat(MAX_HEADER_FIELD_BYTES / 2);
        assert!(validate_inbound_message(&header("shell", &ok)).is_ok());

        let too_long = "\u{e9}".repeat(MAX_HEADER_FIELD_BYTES / 2 + 1);
        assert!(validate_inbound_message(&header("shell", &too_long)).is_err());
    }

    #[test]
    fn limits_property_count() {
        let mut props = serde_json::Map::new();
        for index in 0..MAX_INBOUND_PROPERTIES {
            props.insert(format!("k{index}"), serde_json::json!("v"));
        }
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_ok());

        props.insert("extra".to_string(), serde_json::json!("v"));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_err());
    }

    #[test]
    fn limits_property_key_length() {
        let ok = "k".repeat(MAX_HEADER_FIELD_BYTES);
        let mut props = serde_json::Map::new();
        props.insert(ok, serde_json::json!("v"));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_ok());

        let too_long = "k".repeat(MAX_HEADER_FIELD_BYTES + 1);
        let mut props = serde_json::Map::new();
        props.insert(too_long, serde_json::json!("v"));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_err());
    }

    #[test]
    fn limits_routing_identifier_length() {
        let ok = "c".repeat(MAX_HEADER_FIELD_BYTES);
        let mut props = serde_json::Map::new();
        props.insert("connection_id".to_string(), serde_json::json!(ok));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_ok());

        let too_long = "c".repeat(MAX_HEADER_FIELD_BYTES + 1);
        let mut props = serde_json::Map::new();
        props.insert("connection_id".to_string(), serde_json::json!(too_long));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_err());
    }

    #[test]
    fn rejects_non_string_routing_identifier() {
        let mut props = serde_json::Map::new();
        props.insert("msgid".to_string(), serde_json::json!(7));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_err());
    }

    #[test]
    fn allows_ordinary_file_offset_property() {
        let mut props = serde_json::Map::new();
        props.insert("offset".to_string(), serde_json::json!(1_048_576u64));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(validate_inbound_message(&msg).is_ok());
    }

    #[test]
    fn accepts_arbitrary_non_routing_property_values() {
        let mut props = std::collections::BTreeMap::new();
        props.insert("binary".to_string(), rmpv::Value::Ext(42, vec![1, 2, 3]));
        assert!(validate_inbound_message(&msg_with_props(props)).is_ok());
    }

    #[test]
    fn accepts_non_string_property_map_keys() {
        let mut props = std::collections::BTreeMap::new();
        props.insert(
            "nested".to_string(),
            rmpv::Value::Map(vec![(
                rmpv::Value::Integer(1.into()),
                rmpv::Value::String("v".into()),
            )]),
        );
        assert!(validate_inbound_message(&msg_with_props(props)).is_ok());
    }

    #[test]
    fn rejects_nil_routing_identifier() {
        let mut props = std::collections::BTreeMap::new();
        props.insert("connection_id".to_string(), rmpv::Value::Nil);
        assert!(validate_inbound_message(&msg_with_props(props)).is_err());
    }

    fn encoded_len_with_padding(padding: usize) -> usize {
        let mut props = serde_json::Map::new();
        props.insert("pad".to_string(), serde_json::json!("x".repeat(padding)));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        encode_message(&msg).unwrap().len()
    }

    fn padding_for_len(target: usize) -> usize {
        let mut low = 0usize;
        let mut high = target * 2;
        while low < high {
            let mid = low + (high - low) / 2;
            if encoded_len_with_padding(mid) < target {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low
    }

    #[test]
    fn extended_wire_budget_only_applies_to_v3_forward_payloads() {
        use crate::port_forward::V3_TCP_FRAME_SIZE;
        use crate::protocol::ProtoType;
        let mut message = build(serde_json::json!({"typ":"forward","sid":"s"}));
        message.body = vec![1; V3_TCP_FRAME_SIZE];
        message.header.proto = ProtoType::PORT_FORWARD_V2;
        assert!(encode_outbound_message(&message).is_err());
        message.header.proto = ProtoType::PORT_FORWARD_V3;
        assert!(encode_outbound_message(&message).is_ok());
        message.body.push(1);
        assert!(encode_outbound_message(&message).is_err());
        message.body.pop();
        message.header.msg_type = "ack".into();
        assert!(encode_outbound_message(&message).is_err());
    }

    #[test]
    fn outbound_accepts_at_limit_and_rejects_over() {
        let padding = padding_for_len(MAX_INBOUND_MESSAGE_SIZE);
        let mut props = serde_json::Map::new();
        props.insert("pad".to_string(), serde_json::json!("x".repeat(padding)));
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        let encoded = encode_outbound_message(&msg).unwrap();
        assert_eq!(encoded.len(), MAX_INBOUND_MESSAGE_SIZE);

        let mut props = serde_json::Map::new();
        props.insert(
            "pad".to_string(),
            serde_json::json!("x".repeat(padding + 1)),
        );
        let msg = build(serde_json::json!({"typ": "shell", "sid": "s", "props": props}));
        assert!(encode_outbound_message(&msg).is_err());
    }
}

#[cfg(test)]
mod nodelay_tests {
    use super::*;
    use tokio::net::TcpListener;

    const STEP: Duration = Duration::from_secs(3);

    #[tokio::test]
    async fn connect_enables_tcp_nodelay_on_loopback() -> Result<()> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let server_url = format!("ws://{}", listener.local_addr()?);
        let mut server = tokio::spawn(async move {
            let (stream, _) = tokio::time::timeout(STEP, listener.accept()).await??;
            let mut websocket =
                tokio::time::timeout(STEP, tokio_tungstenite::accept_async(stream)).await??;
            while let Some(message) = websocket.next().await {
                if matches!(message?, Message::Close(_)) {
                    break;
                }
            }
            Ok::<(), anyhow::Error>(())
        });
        // Close the client before joining its server; joining first would
        // wait forever for a close frame that the test had not sent yet.
        let outcome: Result<()> = async {
            let transport =
                tokio::time::timeout(STEP, Transport::connect(&server_url, "loopback-test-token"))
                    .await??;
            let stream = match transport.websocket.get_ref() {
                MaybeTlsStream::Plain(stream) => stream,
                _ => bail!("expected a plain loopback websocket"),
            };
            anyhow::ensure!(stream.nodelay()?, "TCP_NODELAY was not enabled");
            tokio::time::timeout(STEP, transport.close()).await??;
            Ok(())
        }
        .await;
        if outcome.is_err() {
            server.abort();
        }
        let joined = tokio::time::timeout(STEP, &mut server).await;
        if joined.is_err() {
            server.abort();
            let _ = tokio::time::timeout(STEP, &mut server).await;
        }
        outcome?;
        joined.context("timed out joining loopback server")???;
        Ok(())
    }
}

#[cfg(test)]
mod ping_cancellation_tests {
    use super::*;
    use crate::protocol::{ProtoHdr, ProtoType};
    use std::collections::VecDeque;
    use std::io;
    use std::pin::Pin;
    use std::sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    use std::task::{Context, Poll};
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio_tungstenite::tungstenite::{WebSocket, protocol::Role};

    #[derive(Default)]
    struct Gate {
        incoming: Mutex<VecDeque<u8>>,
        outgoing: Mutex<Vec<u8>>,
        writable: AtomicBool,
        read_bytes: AtomicUsize,
        write_polls: AtomicUsize,
    }
    struct GateIo(Arc<Gate>);
    impl AsyncRead for GateIo {
        fn poll_read(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let mut input = match self.0.incoming.lock() {
                Ok(x) => x,
                Err(_) => return Poll::Ready(Err(io::Error::other("test input mutex poisoned"))),
            };
            let mut count = 0;
            while buf.remaining() > 0 {
                let Some(byte) = input.pop_front() else { break };
                buf.put_slice(&[byte]);
                count += 1;
            }
            self.0.read_bytes.fetch_add(count, Ordering::SeqCst);
            if count == 0 {
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }
    }
    impl AsyncWrite for GateIo {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.write_polls.fetch_add(1, Ordering::SeqCst);
            if !self.0.writable.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
            let mut output = match self.0.outgoing.lock() {
                Ok(x) => x,
                Err(_) => return Poll::Ready(Err(io::Error::other("test output mutex poisoned"))),
            };
            output.extend_from_slice(bytes);
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    async fn stream(bytes: &[u8]) -> Result<(Arc<Gate>, WebSocketStream<GateIo>)> {
        let gate = Arc::new(Gate::default());
        gate.incoming
            .lock()
            .map_err(|_| anyhow!("test mutex poisoned"))?
            .extend(bytes);
        let socket = WebSocketStream::from_raw_socket(
            GateIo(gate.clone()),
            Role::Client,
            Some(websocket_config()),
        )
        .await;
        Ok((gate, socket))
    }
    async fn cancel_ping(
        socket: &mut WebSocketStream<GateIo>,
        pending: &mut Option<PendingPing>,
        gate: &Gate,
    ) {
        let sibling = tokio::select! { biased; _ = receive_event_with_state(socket, pending) => false, _ = std::future::ready(()) => true };
        assert!(
            sibling,
            "ready sibling must cancel while pong flush is Pending"
        );
        assert_eq!(
            gate.read_bytes.load(Ordering::SeqCst),
            3,
            "Ping was consumed"
        );
        assert!(
            gate.write_polls.load(Ordering::SeqCst) > 0,
            "pong flush was actually polled"
        );
    }
    fn output() -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::SHELL,
                msg_type: "shell".into(),
                session_id: "fixture".into(),
                ..ProtoHdr::default()
            },
            body: b"output".to_vec(),
        }
    }
    fn outgoing(gate: &Gate) -> Result<Vec<u8>> {
        Ok(gate
            .outgoing
            .lock()
            .map_err(|_| anyhow!("test mutex poisoned"))?
            .clone())
    }
    fn check_frames(gate: &Gate, count: usize, expected: &str) -> Result<()> {
        let mut peer =
            WebSocket::from_raw_socket(io::Cursor::new(outgoing(gate)?), Role::Server, None);
        let mut pong = false;
        let mut other = false;
        for _ in 0..count {
            match peer.read()? {
                Message::Pong(p) if p.as_ref() == b"x" => pong = true,
                Message::Binary(_) if expected == "binary" => other = true,
                Message::Ping(p) if expected == "ping" && p.as_ref() == b"probe" => other = true,
                _ => {}
            }
        }
        assert!(pong, "automatic pong frame must remain intact");
        if count > 1 {
            assert!(other, "subsequent outbound frame must remain intact");
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn canceled_ping_replayed_exactly_once() -> Result<()> {
        let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
        let mut pending = None;
        cancel_ping(&mut socket, &mut pending, &gate).await;
        gate.writable.store(true, Ordering::SeqCst);
        assert!(matches!(
            tokio::time::timeout(
                Duration::from_secs(1),
                receive_event_with_state(&mut socket, &mut pending)
            )
            .await??,
            TransportEvent::Ping
        ));
        check_frames(&gate, 1, "")?;
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                receive_event_with_state(&mut socket, &mut pending)
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn successful_send_keeps_flushed_ping_notification() -> Result<()> {
        let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
        let mut pending = None;
        cancel_ping(&mut socket, &mut pending, &gate).await;
        gate.writable.store(true, Ordering::SeqCst);
        send_message_with_state(&mut socket, &mut pending, &output()).await?;
        check_frames(&gate, 2, "binary")?;
        tokio::time::advance(WRITE_TIMEOUT + Duration::from_secs(1)).await;
        assert!(matches!(
            receive_event_with_state(&mut socket, &mut pending).await?,
            TransportEvent::Ping
        ));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(10),
                receive_event_with_state(&mut socket, &mut pending)
            )
            .await
            .is_err()
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn successful_send_ping_keeps_flushed_notification() -> Result<()> {
        let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
        let mut pending = None;
        cancel_ping(&mut socket, &mut pending, &gate).await;
        gate.writable.store(true, Ordering::SeqCst);
        send_ping_with_state(&mut socket, &mut pending, b"probe").await?;
        check_frames(&gate, 2, "ping")?;
        tokio::time::advance(WRITE_TIMEOUT + Duration::from_secs(1)).await;
        assert!(matches!(
            receive_event_with_state(&mut socket, &mut pending).await?,
            TransportEvent::Ping
        ));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn canceled_flush_retains_absolute_deadline() -> Result<()> {
        let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
        let mut pending = None;
        cancel_ping(&mut socket, &mut pending, &gate).await;
        tokio::time::advance(Duration::from_secs(3)).await;
        let start = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(2),
            receive_event_with_state(&mut socket, &mut pending),
        )
        .await;
        assert!(
            matches!(result, Ok(Err(_))),
            "original four-second deadline must beat a new two-second wait"
        );
        assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1));
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn expired_pending_ping_cannot_be_bypassed_by_any_writer() -> Result<()> {
        let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
        let mut pending = None;
        cancel_ping(&mut socket, &mut pending, &gate).await;
        tokio::time::advance(WRITE_TIMEOUT + Duration::from_secs(1)).await;
        gate.writable.store(true, Ordering::SeqCst);
        assert!(
            send_message_with_state(&mut socket, &mut pending, &output())
                .await
                .is_err()
        );
        assert!(
            send_ping_with_state(&mut socket, &mut pending, b"probe")
                .await
                .is_err()
        );
        assert!(
            receive_event_with_state(&mut socket, &mut pending)
                .await
                .is_err()
        );
        assert!(
            outgoing(&gate)?.is_empty(),
            "expired write must fail before touching the socket"
        );
        Ok(())
    }

    #[tokio::test(flavor = "current_thread", start_paused = true)]
    async fn every_writer_uses_remaining_original_ping_budget() -> Result<()> {
        for ping in [false, true] {
            let (gate, mut socket) = stream(&[0x89, 1, b'x']).await?;
            let mut pending = None;
            cancel_ping(&mut socket, &mut pending, &gate).await;
            tokio::time::advance(Duration::from_secs(3)).await;
            let start = tokio::time::Instant::now();
            let write = async {
                if ping {
                    send_ping_with_state(&mut socket, &mut pending, b"probe").await
                } else {
                    send_message_with_state(&mut socket, &mut pending, &output()).await
                }
            };
            let result = tokio::time::timeout(Duration::from_secs(2), write).await;
            assert!(
                matches!(result, Ok(Err(_))),
                "write must use remaining one second, not a new four-second budget"
            );
            assert_eq!(tokio::time::Instant::now() - start, Duration::from_secs(1));
            assert!(outgoing(&gate)?.is_empty());
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn non_ping_frames_still_return_without_write() -> Result<()> {
        for (bytes, kind) in [(vec![0x8a, 1, b'x'], "pong"), (vec![0x88, 0], "close")] {
            let (gate, mut socket) = stream(&bytes).await?;
            let mut pending = None;
            let event = tokio::time::timeout(
                Duration::from_secs(1),
                receive_event_with_state(&mut socket, &mut pending),
            )
            .await??;
            assert!(matches!(
                (kind, event),
                ("pong", TransportEvent::Pong) | ("close", TransportEvent::Closed)
            ));
            assert_eq!(gate.write_polls.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn binary_frame_still_validates_header_bounds() -> Result<()> {
        for length in [128, 129] {
            let mut message = output();
            message.header.session_id = "s".repeat(length);
            let body = encode_message(&message)?;
            let len = u16::try_from(body.len())?;
            let mut bytes = vec![0x82, 126];
            bytes.extend_from_slice(&len.to_be_bytes());
            bytes.extend(body);
            let (gate, mut socket) = stream(&bytes).await?;
            let mut pending = None;
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                receive_event_with_state(&mut socket, &mut pending),
            )
            .await?;
            if length == 128 {
                assert!(matches!(result?, TransportEvent::Message(_)));
            } else {
                assert!(result.is_err());
            }
            assert_eq!(gate.write_polls.load(Ordering::SeqCst), 0);
        }
        Ok(())
    }
}
