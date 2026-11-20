//! Bounded Tokio worker owning exactly one port-forward socket.
//!
//! A manager task owns the `JoinHandle` of this worker. Aborting that handle
//! drops the socket, buffers and channels owned here; no detached tasks are
//! spawned. All network work happens inside this single async worker, and every
//! output send is bounded so that cleanup can never hang on a full channel.
//!
//! In *managed mode* the manager supplies a [`SharedUdp`] handle. The worker
//! installs its connected UDP socket into that state, performs all outbound UDP
//! writes through the bounded fallback [`SharedUdp::send`] path and tracks the
//! shared TTL alongside its local inactivity deadline. A [`CloseOnDrop`] guard
//! is created *before* any validation or connect work so every termination and
//! abort path closes the shared state before terminal events are emitted.

use std::io;
use std::sync::Arc;

use anyhow::{Result, anyhow};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::mpsc;
use tokio::time::{Duration, Instant, timeout};

use crate::port_forward::{ConnectionKey, Network, error_reply};
use crate::protocol::{ProtoMsg, ProtoType};
use crate::udp_inline::{CloseOnDrop, SharedUdp};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(4);
const IO_TIMEOUT: Duration = Duration::from_secs(4);
const SEND_TIMEOUT: Duration = Duration::from_secs(4);
const INACTIVITY_TIMEOUT: Duration = Duration::from_secs(600);
const MAX_HOST_LEN: usize = 253;
const MAX_READ: usize = 4096;
const MAX_WRITE: usize = 4096;
/// v2 TCP uses the larger frame size borrowed from a raw-stream tunnel; v1
/// and UDP retain the upstream 4 KiB wire limit.
const V2_MAX_FRAME: usize = 7680;
/// Maximum number of v1 UDP outbound frames that may await a peer ack.
/// The upstream v1 protocol uses one credit per frame; allowing a bounded
/// window keeps the UDP receive path ahead of the socket buffer instead of
/// serializing every datagram on a full WebSocket round-trip.
const ACK_WINDOW: usize = 32;
// Deviceconnect subscribes with a 25-message channel. Leave room for ACKs and control frames.
const V3_TCP_ACK_WINDOW: usize = 16;

/// Driver command for the worker.
#[derive(Debug)]
pub enum Command {
    Forward(Vec<u8>),
    Ack(u32),
    HalfClose,
    /// The manager already attempted an opportunistic inline send and it hard
    /// failed (or partially failed). The worker must report a typed `forward`
    /// error without performing *any* socket write or retry.
    FailForward(&'static str),
}

/// Worker output reported to the manager.
pub enum Event {
    Message {
        key: ConnectionKey,
        generation: u64,
        message: ProtoMsg,
    },
    Finished {
        key: ConnectionKey,
        generation: u64,
    },
}

/// Ready input selected from commands or the socket.
enum Input {
    /// A command from the driver; `None` means the command channel closed.
    Command(Option<Command>),
    /// A read result from the socket.
    Read(io::Result<usize>),
}

/// Why the worker stopped.
enum Exit {
    /// Command channel closed; exit without any outbound message.
    Quiet,
    /// Terminal condition that only notifies the peer via a `stop` message
    /// (normal EOF, inactivity timeout, or a read-side failure).
    Stop,
    /// Terminal failure that reports a typed error reply. `msgtype` names the
    /// protocol message type that failed (`new`, `forward`, or `ack`). When
    /// `notify_stop` is set, an established connection also emits a `stop`
    /// before `Finished`.
    Error {
        msgtype: &'static str,
        reason: String,
        notify_stop: bool,
    },
}

/// Connected socket abstraction so the select loop stays uniform for TCP/UDP.
enum Socket {
    Tcp(TcpStream),
    /// Plain (unmanaged) UDP socket used by the legacy public [`run`] entry
    /// point.
    Udp(UdpSocket),
    /// Managed UDP socket shared with the parent via [`SharedUdp`]. Reads use
    /// the `Arc`; writes go through the bounded fallback send.
    ManagedUdp(Arc<UdpSocket>, SharedUdp),
}

impl Socket {
    async fn read_into(&mut self, buffer: &mut [u8], tcp_limit: usize) -> io::Result<usize> {
        match self {
            Socket::Tcp(stream) => {
                let tcp_buffer = buffer.get_mut(..tcp_limit).ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "tcp read buffer is smaller than the read limit",
                    )
                })?;
                stream.read(tcp_buffer).await
            }
            Socket::Udp(socket) => {
                let udp_buffer = buffer
                    .get_mut(..(MAX_READ + 1).min(buffer.len()))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "udp read buffer is smaller than the read limit",
                        )
                    })?;
                socket.recv(udp_buffer).await
            }
            Socket::ManagedUdp(socket, _shared) => {
                let udp_buffer = buffer
                    .get_mut(..(MAX_READ + 1).min(buffer.len()))
                    .ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "udp read buffer is smaller than the read limit",
                        )
                    })?;
                socket.recv(udp_buffer).await
            }
        }
    }

    async fn shutdown_write(&mut self) -> io::Result<()> {
        match self {
            Socket::Tcp(stream) => {
                socket2::SockRef::from(&*stream).shutdown(std::net::Shutdown::Write)
            }
            Socket::Udp(_) | Socket::ManagedUdp(_, _) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "half-close requires a TCP socket",
            )),
        }
    }

    async fn write_chunk(&mut self, data: &[u8]) -> io::Result<()> {
        match self {
            Socket::Tcp(stream) => stream.write_all(data).await,
            Socket::Udp(socket) => {
                let sent = socket.send(data).await?;
                if sent != data.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "partial udp datagram write",
                    ));
                }
                Ok(())
            }
            Socket::ManagedUdp(_socket, shared) => {
                // Bounded absolute 4s budget; serializes the actual send
                // against expiry/close in the shared state. The caller's
                // existing 4s timeout remains the outer limit.
                shared.send(data).await
            }
        }
    }
}

/// Wait for the next command or socket read.
///
/// The two "ready" sources are polled through an unbiased `select!` so that a
/// flood of driver commands cannot starve socket reads (and vice versa). When a
/// v1 ack is outstanding (`read_enabled == false`) reads are disabled entirely
/// and only commands are awaited, which is part of the outbound-ack gate.
async fn next_input(
    commands: &mut mpsc::Receiver<Command>,
    socket: &mut Socket,
    buffer: &mut [u8],
    read_enabled: bool,
    tcp_limit: usize,
) -> Input {
    if read_enabled {
        tokio::select! {
            command = commands.recv() => Input::Command(command),
            read = socket.read_into(buffer, tcp_limit) => Input::Read(read),
        }
    } else {
        Input::Command(commands.recv().await)
    }
}

/// Connect the worker socket under a bounded timeout.
async fn connect(network: Network, host: &str, port: u16) -> Result<Socket> {
    match network {
        Network::Tcp => {
            let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect((host, port)))
                .await
                .map_err(|_| anyhow!("tcp connect timed out"))?
                .map_err(|err| anyhow!("tcp connect failed: {err}"))?;
            let sock = socket2::SockRef::from(&stream);
            let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
            let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
            Ok(Socket::Tcp(stream))
        }
        Network::Udp => {
            // Resolve, bind and connect must share one overall budget so a
            // stalled phase cannot extend the total setup window.
            let socket = timeout(CONNECT_TIMEOUT, connect_udp(host, port))
                .await
                .map_err(|_| anyhow!("udp setup timed out"))??;
            Ok(Socket::Udp(socket))
        }
    }
}

/// Resolve a target, bind a matching-family socket and connect it. Runs under
/// the single caller-provided timeout; never builds `host:port` strings.
async fn connect_udp(host: &str, port: u16) -> Result<UdpSocket> {
    let mut addrs = lookup_host((host, port)).await?;
    let target = addrs
        .next()
        .ok_or_else(|| anyhow!("udp address resolution returned no address"))?;
    let bind_address = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind_address).await?;
    socket.connect(target).await?;
    let sock = socket2::SockRef::from(&socket);
    let _ = sock.set_recv_buffer_size(4 * 1024 * 1024);
    let _ = sock.set_send_buffer_size(4 * 1024 * 1024);
    Ok(socket)
}

async fn send_event(events: &mpsc::Sender<Event>, event: Event) -> Result<()> {
    match timeout(SEND_TIMEOUT, events.send(event)).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(err)) => Err(anyhow!("event channel closed: {err}")),
        Err(_) => Err(anyhow!("event send timed out")),
    }
}

async fn send_message(
    events: &mpsc::Sender<Event>,
    key: &ConnectionKey,
    generation: u64,
    message: ProtoMsg,
) -> Result<()> {
    send_event(
        events,
        Event::Message {
            key: key.clone(),
            generation,
            message,
        },
    )
    .await
}

/// Build a typed error reply referencing the protocol message type that failed,
/// falling back to a plain message of that same type if encoding fails.
fn error_message(key: &ConnectionKey, msgtype: &str, reason: &str) -> ProtoMsg {
    let template = key.message(msgtype, Vec::new());
    match error_reply(&template.header, reason) {
        Ok(message) => message,
        Err(_) => template,
    }
}

/// Drive one port-forward connection until it terminates (legacy path).
///
/// Unchanged public signature; delegates to the shared inner driver without a
/// managed UDP state.
pub async fn run(
    key: ConnectionKey,
    generation: u64,
    network: Network,
    host: String,
    port: u16,
    commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
) {
    run_inner(
        key,
        generation,
        network,
        host,
        port,
        commands,
        events,
        WorkerMode::Standard,
    )
    .await;
}

pub(crate) enum WorkerMode {
    Standard,
    ManagedUdp(SharedUdp),
    LargeTcp(usize),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn run_inner(
    key: ConnectionKey,
    generation: u64,
    network: Network,
    host: String,
    port: u16,
    mut commands: mpsc::Receiver<Command>,
    events: mpsc::Sender<Event>,
    mode: WorkerMode,
) {
    let exit = work(
        &key,
        generation,
        network,
        &host,
        port,
        &mut commands,
        &events,
        mode,
    )
    .await;

    match exit {
        Exit::Quiet => {}
        Exit::Stop => {
            let stop = key.message("stop", Vec::new());
            let _ = send_message(&events, &key, generation, stop).await;
        }
        Exit::Error {
            msgtype,
            reason,
            notify_stop,
        } => {
            let message = error_message(&key, msgtype, &reason);
            let _ = send_message(&events, &key, generation, message).await;
            if notify_stop {
                // Established connection hit a terminal write error: notify the
                // peer with a stop message before finishing.
                let stop = key.message("stop", Vec::new());
                let _ = send_message(&events, &key, generation, stop).await;
            }
        }
    }

    let _ = send_event(
        &events,
        Event::Finished {
            key: key.clone(),
            generation,
        },
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
async fn work(
    key: &ConnectionKey,
    generation: u64,
    network: Network,
    host: &str,
    port: u16,
    commands: &mut mpsc::Receiver<Command>,
    events: &mpsc::Sender<Event>,
    mode: WorkerMode,
) -> Exit {
    use crate::port_forward::TcpFrameAccept;
    let tcp_frame_size = match mode {
        WorkerMode::LargeTcp(size) => Some(size),
        _ => None,
    };
    let managed = match mode {
        WorkerMode::ManagedUdp(shared) => Some(shared),
        _ => None,
    };
    // Create the closing guard first so that *every* later termination or
    // abort path drops (and therefore closes) the shared state before the
    // terminal events are emitted by `run_inner`.
    let _close = managed.as_ref().map(|s| CloseOnDrop::new(s.clone()));

    // Reject a managed request that could never be satisfied by this worker:
    // only v1 port-forward UDP connections are eligible.
    if managed.is_some() {
        if !matches!(network, Network::Udp) {
            return Exit::Error {
                msgtype: "new",
                reason: "managed udp forwarding requires network=udp".to_owned(),
                notify_stop: false,
            };
        }
        if !matches!(key.proto(), ProtoType::PORT_FORWARD) {
            return Exit::Error {
                msgtype: "new",
                reason: "managed udp forwarding requires proto=PORT_FORWARD".to_owned(),
                notify_stop: false,
            };
        }
    }

    // Validate the connection target at the worker boundary as well; the
    // manager-facing API still passes a plain `u16`.
    if port == 0 {
        return Exit::Error {
            msgtype: "new",
            reason: "remote_port must be non-zero".to_owned(),
            notify_stop: false,
        };
    }
    if host.is_empty() || host.len() > MAX_HOST_LEN || host.chars().any(char::is_control) {
        return Exit::Error {
            msgtype: "new",
            reason: "invalid remote_host".to_owned(),
            notify_stop: false,
        };
    }

    let connected_socket = match connect(network, host, port).await {
        Ok(socket) => socket,
        Err(err) => {
            return Exit::Error {
                msgtype: "new",
                reason: err.to_string(),
                notify_stop: false,
            };
        }
    };

    // In managed mode publish the connected socket to the parent before the
    // successful "new" reply so the manager can start inline forwarding.
    let mut socket = match (managed, connected_socket) {
        (Some(shared), Socket::Udp(socket)) => {
            let socket = Arc::new(socket);
            if let Err(err) = shared.install(Arc::clone(&socket)) {
                return Exit::Error {
                    msgtype: "new",
                    reason: format!("managed udp install failed: {err}"),
                    notify_stop: false,
                };
            }
            Socket::ManagedUdp(socket, shared)
        }
        (_, socket) => socket,
    };

    // Announce the established connection before any socket data. The
    // successful response uses the "new" type for both v1 and v2.
    let accept = if let Some(size) = tcp_frame_size {
        match crate::protocol::encode(&TcpFrameAccept {
            tcp_frame_size: size,
        }) {
            Ok(body) => body,
            Err(err) => {
                return Exit::Error {
                    msgtype: "new",
                    reason: err.to_string(),
                    notify_stop: false,
                };
            }
        }
    } else {
        Vec::new()
    };
    let connected = key.message("new", accept);
    if send_message(events, key, generation, connected)
        .await
        .is_err()
    {
        return Exit::Quiet;
    }

    let requires_ack = matches!(key.proto(), ProtoType::PORT_FORWARD)
        || (matches!(
            key.proto(),
            ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
        ) && key.flow_control());
    // v2 emits ACKs only when the peer opted into flow control through the
    // routed connection-id suffix. A stock v2 peer keeps the original unpaced
    // path. v1 always acknowledges.
    let send_ack = requires_ack;
    let is_tcp = matches!(network, Network::Tcp);
    let is_managed = matches!(socket, Socket::ManagedUdp(..));
    let v3_tcp = is_tcp && key.proto() == ProtoType::PORT_FORWARD_V3;
    let ack_window = if requires_ack && v3_tcp {
        V3_TCP_ACK_WINDOW
    } else if requires_ack
        && ((is_managed && matches!(network, Network::Udp))
            || matches!(
                key.proto(),
                ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
            ))
    {
        ACK_WINDOW
    } else {
        1
    };
    let shared = match &socket {
        Socket::ManagedUdp(_, shared) => Some(shared.clone()),
        _ => None,
    };
    // Number of outbound "forward" frames emitted by this worker that the
    // peer has not acknowledged yet. Socket reads are disabled only when the
    // bounded window is full; inbound writes still work while acks drain.
    let mut in_flight = 0usize;
    let mut v3_pending_acks = 0usize;
    let mut peer_half_closed = false;
    let mut target_eof = false;
    let mut half_close_sent = false;
    let tcp_limit = if let Some(size) = tcp_frame_size {
        size
    } else if matches!(
        key.proto(),
        ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
    ) && is_tcp
    {
        V2_MAX_FRAME
    } else {
        MAX_READ
    };
    let max_write = if is_tcp { tcp_limit } else { MAX_WRITE };
    let mut buffer = vec![0u8; tcp_limit.max(MAX_READ + 1)];
    let mut deadline = Instant::now() + INACTIVITY_TIMEOUT;

    loop {
        // Drain target output without dropping client writes or half-closes
        // that arrive while the final batch of ACKs is crossing the network.
        if target_eof && in_flight == 0 {
            if !half_close_sent {
                if send_message(
                    events,
                    key,
                    generation,
                    key.message("half_close", Vec::new()),
                )
                .await
                .is_err()
                {
                    return Exit::Quiet;
                }
                half_close_sent = true;
                deadline = Instant::now() + INACTIVITY_TIMEOUT;
            }
            if peer_half_closed {
                return Exit::Stop;
            }
        }
        // Compute the effective wake deadline. Managed mode uses the shared
        // deadline directly: the local deadline may already have been expired
        // and then extended inline, so taking the minimum would keep firing an
        // immediately-expired timer forever. The legacy local deadline only
        // applies when no shared state exists. A closed or failing shared state
        // is terminal.
        let wake_deadline = if is_managed {
            match &shared {
                Some(shared) => match shared.deadline() {
                    Ok(shared_deadline) => shared_deadline,
                    Err(_) => return Exit::Stop,
                },
                None => return Exit::Stop,
            }
        } else {
            deadline
        };

        let input = tokio::select! {
            // Biased so the inactivity timer is always checked first and busy
            // command/data traffic cannot starve expiry.
            biased;

            _ = tokio::time::sleep_until(wake_deadline) => {
                if let Some(shared) = &shared {
                    // Inline extensions of the TTL are observed here; only a
                    // genuinely expired/failed state is terminal.
                    match shared.expire() {
                        Ok(false) => {
                            // Deadline moved forward by an inline send; simply
                            // recompute and keep going.
                            continue;
                        }
                        Ok(true) | Err(_) => return Exit::Stop,
                    }
                }
                return Exit::Stop;
            }
            input = next_input(
                commands,
                &mut socket,
                &mut buffer[..],
                !target_eof && (!requires_ack || in_flight < ack_window),
                tcp_limit,
            ) => input,
        };

        match input {
            Input::Command(None) => {
                return Exit::Quiet;
            }
            Input::Command(Some(Command::FailForward(reason))) => {
                // Hard/partial inline failure already surfaced by the manager:
                // report it without any socket write or retry.
                return Exit::Error {
                    msgtype: "forward",
                    reason: reason.to_owned(),
                    notify_stop: true,
                };
            }
            Input::Command(Some(Command::HalfClose)) => {
                if !v3_tcp {
                    return Exit::Error {
                        msgtype: "half_close",
                        reason: "half_close requires TCP v3".to_owned(),
                        notify_stop: false,
                    };
                }
                if peer_half_closed {
                    continue;
                }
                match timeout(IO_TIMEOUT, socket.shutdown_write()).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        return Exit::Error {
                            msgtype: "half_close",
                            reason: format!("target half-close failed: {err}"),
                            notify_stop: true,
                        };
                    }
                    Err(_) => {
                        return Exit::Error {
                            msgtype: "half_close",
                            reason: "target half-close timed out".to_owned(),
                            notify_stop: true,
                        };
                    }
                }
                peer_half_closed = true;
            }
            Input::Command(Some(Command::Ack(count))) => {
                if !requires_ack {
                    // v2 peers ACK our forwarded data as a courtesy; the
                    // unpaced v2 read path has no outbound credit to release.
                    if matches!(
                        key.proto(),
                        ProtoType::PORT_FORWARD_V2 | ProtoType::PORT_FORWARD_V3
                    ) {
                        continue;
                    }
                    return Exit::Error {
                        msgtype: "ack",
                        reason: "ack not supported for this protocol".to_owned(),
                        notify_stop: false,
                    };
                }
                // Idempotent: spurious acks never create extra credits.
                // v3 batches several target-to-client frames into one ACK.
                let released = usize::try_from(count).unwrap_or(usize::MAX);
                in_flight = in_flight.saturating_sub(released);
                if target_eof && in_flight > 0 && released > 0 {
                    deadline = Instant::now() + IO_TIMEOUT;
                }
            }
            Input::Command(Some(Command::Forward(data))) => {
                if data.len() > max_write {
                    return Exit::Error {
                        msgtype: "forward",
                        reason: "forward payload exceeds limit".to_owned(),
                        notify_stop: false,
                    };
                }
                match timeout(IO_TIMEOUT, socket.write_chunk(&data)).await {
                    Ok(Ok(())) => {}
                    Ok(Err(err)) => {
                        return Exit::Error {
                            msgtype: "forward",
                            reason: format!("socket write failed: {err}"),
                            notify_stop: true,
                        };
                    }
                    Err(_) => {
                        return Exit::Error {
                            msgtype: "forward",
                            reason: "socket write timed out".to_owned(),
                            notify_stop: true,
                        };
                    }
                }
                // A successful managed send already refreshed the shared TTL;
                // the local bookkeeping is still kept up to date.
                deadline = Instant::now() + INACTIVITY_TIMEOUT;
                if send_ack {
                    // Acknowledge the received forward direction. This must not
                    // touch `in_flight`, which tracks outbound data awaiting a
                    // peer ack; outbound reading therefore keeps flowing.
                    let v3 = matches!(key.proto(), ProtoType::PORT_FORWARD_V3);
                    let ack_every = if v3 && is_tcp { 4 } else { 1 };
                    v3_pending_acks += 1;
                    if v3_pending_acks < ack_every {
                        deadline = Instant::now() + INACTIVITY_TIMEOUT;
                        continue;
                    }
                    let ack_body = if v3 {
                        let body = u32::try_from(v3_pending_acks)
                            .unwrap_or(u32::MAX)
                            .to_be_bytes()
                            .to_vec();
                        v3_pending_acks = 0;
                        body
                    } else {
                        Vec::new()
                    };
                    let ack = key.message("ack", ack_body);
                    if send_message(events, key, generation, ack).await.is_err() {
                        return Exit::Quiet;
                    }
                }
            }
            Input::Read(Err(_)) => {
                return Exit::Stop;
            }
            Input::Read(Ok(len)) => {
                if len == 0 && is_tcp {
                    if v3_tcp {
                        target_eof = true;
                        deadline = Instant::now() + IO_TIMEOUT;
                        continue;
                    }
                    // Do not emit stop until every previously queued outbound
                    // frame has been acknowledged by the peer. Without this
                    // drain a fast target EOF races the WebSocket relay and
                    // truncates the tail.
                    if requires_ack {
                        while in_flight > 0 {
                            match timeout(IO_TIMEOUT, commands.recv()).await {
                                Ok(Some(Command::Ack(count))) => {
                                    let released = usize::try_from(count).unwrap_or(usize::MAX);
                                    in_flight = in_flight.saturating_sub(released);
                                }
                                Ok(Some(Command::Forward(_)))
                                | Ok(Some(Command::FailForward(_))) => {}
                                Ok(Some(Command::HalfClose)) => {}
                                Ok(None) => return Exit::Quiet,
                                Err(_) => return Exit::Stop,
                            }
                        }
                    }
                    return Exit::Stop;
                }
                if !is_tcp && len > MAX_READ {
                    return Exit::Error {
                        msgtype: "forward",
                        reason: "udp datagram exceeds 4096 byte limit".to_owned(),
                        notify_stop: true,
                    };
                }
                let Some(data) = buffer.get(..len) else {
                    return Exit::Stop;
                };
                deadline = Instant::now() + INACTIVITY_TIMEOUT;
                if let Some(shared) = &shared {
                    // Renew the managed TTL after a successful read; a closed
                    // or failing state is terminal.
                    if shared.refresh().is_err() {
                        return Exit::Stop;
                    }
                }
                // A zero-length UDP read is an empty datagram, not EOF.
                let message = key.message("forward", data.to_vec());
                if send_message(events, key, generation, message)
                    .await
                    .is_err()
                {
                    return Exit::Quiet;
                }
                if requires_ack {
                    // Only now that outbound data was emitted do we consume one
                    // credit. Reads continue until the bounded window is full.
                    in_flight = in_flight.saturating_add(1);
                }
            }
        }
    }
}
