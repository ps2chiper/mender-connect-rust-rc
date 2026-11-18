//! Async client for the Mender Authentication1 D-Bus interface.

use std::time::Duration;

use anyhow::{Context, Result, bail};
use futures_util::StreamExt;
use tokio::sync::mpsc;

pub const DBUS_SERVICE: &str = "io.mender.AuthenticationManager";
pub const DBUS_OBJECT_PATH: &str = "/io/mender/AuthenticationManager";
pub const DBUS_INTERFACE: &str = "io.mender.Authentication1";
pub const DBUS_METHOD_TIMEOUT: Duration = Duration::from_secs(5);
pub const DBUS_SIGNAL_TIMEOUT: Duration = Duration::from_secs(10);

#[zbus::proxy(
    interface = "io.mender.Authentication1",
    default_service = "io.mender.AuthenticationManager",
    default_path = "/io/mender/AuthenticationManager"
)]
pub trait Authentication1 {
    fn get_jwt_token(&self) -> zbus::Result<(String, String)>;

    fn fetch_jwt_token(&self) -> zbus::Result<bool>;

    #[zbus(signal)]
    fn jwt_token_state_change(&self, token: &str, server_url: &str) -> zbus::Result<()>;
}

/// Client for the Mender Authentication1 interface.
///
/// Tokens are returned to callers but are never logged by this module. This
/// type intentionally does not implement `Debug`.
#[derive(Clone)]
pub struct AuthClient {
    connection: zbus::Connection,
}

enum SubscriptionEvent {
    Ready,
    Token { token: String, server_url: String },
    Error(String),
}

/// A continuous `JwtTokenStateChange` subscription.
///
/// The subscription remains active until it is dropped. Call [`Self::next`]
/// repeatedly instead of creating a new subscription for every event. This
/// type intentionally does not implement `Debug`.
pub struct JwtTokenStateChangeSubscription {
    receiver: mpsc::Receiver<SubscriptionEvent>,
    task: tokio::task::JoinHandle<()>,
}

impl JwtTokenStateChangeSubscription {
    /// Wait until the D-Bus signal subscription is established.
    pub async fn wait_ready(&mut self) -> Result<()> {
        match self.receiver.recv().await {
            Some(SubscriptionEvent::Ready) => Ok(()),
            Some(SubscriptionEvent::Error(error)) => bail!("{error}"),
            Some(SubscriptionEvent::Token { .. }) => {
                bail!("JwtTokenStateChange subscription produced a token before becoming ready")
            }
            None => bail!("JwtTokenStateChange subscription ended before becoming ready"),
        }
    }

    /// Receive the next token state change.
    ///
    /// Returns `Ok(None)` when the subscription has ended.
    pub async fn next(&mut self) -> Result<Option<(String, String)>> {
        loop {
            match self.receiver.recv().await {
                Some(SubscriptionEvent::Token { token, server_url }) => {
                    return Ok(Some((token, server_url)));
                }
                Some(SubscriptionEvent::Error(error)) => bail!("{error}"),
                Some(SubscriptionEvent::Ready) => continue,
                None => return Ok(None),
            }
        }
    }
}

impl Drop for JwtTokenStateChangeSubscription {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl AuthClient {
    /// Connect to the production system bus.
    pub async fn connect_system() -> Result<Self> {
        let connection = zbus::Connection::system()
            .await
            .context("failed to connect to the system D-Bus")?;
        Ok(Self::from_connection(connection))
    }

    /// Build a client from an existing connection, allowing mock-bus tests.
    pub fn from_connection(connection: zbus::Connection) -> Self {
        Self { connection }
    }

    /// Call `GetJwtToken`. The timeout covers proxy creation and the call.
    pub async fn get_jwt_token(&self) -> Result<(String, String)> {
        let response = tokio::time::timeout(DBUS_METHOD_TIMEOUT, async {
            let proxy = Authentication1Proxy::new(&self.connection).await?;
            proxy.get_jwt_token().await
        })
        .await
        .context("timed out calling GetJwtToken")?
        .context("GetJwtToken D-Bus call failed")?;

        Ok(response)
    }

    /// Call `FetchJwtToken`. The timeout covers proxy creation and the call.
    pub async fn fetch_jwt_token(&self) -> Result<bool> {
        let response = tokio::time::timeout(DBUS_METHOD_TIMEOUT, async {
            let proxy = Authentication1Proxy::new(&self.connection).await?;
            proxy.fetch_jwt_token().await
        })
        .await
        .context("timed out calling FetchJwtToken")?
        .context("FetchJwtToken D-Bus call failed")?;

        Ok(response)
    }

    /// Create a continuous `JwtTokenStateChange` subscription.
    ///
    /// This must be called from a Tokio runtime. The subscription remains
    /// active until dropped; do not resubscribe after every received signal.
    pub fn subscribe_jwt_token_state_change(&self) -> JwtTokenStateChangeSubscription {
        let connection = self.connection.clone();
        let (sender, receiver) = mpsc::channel(16);

        let task = tokio::spawn(async move {
            let proxy = match Authentication1Proxy::new(&connection).await {
                Ok(proxy) => proxy,
                Err(error) => {
                    let _ = sender
                        .send(SubscriptionEvent::Error(format!(
                            "failed to create the Authentication1 D-Bus proxy: {error}"
                        )))
                        .await;
                    return;
                }
            };

            let mut signals = match proxy.receive_jwt_token_state_change().await {
                Ok(signals) => signals,
                Err(error) => {
                    let _ = sender
                        .send(SubscriptionEvent::Error(format!(
                            "failed to subscribe to JwtTokenStateChange: {error}"
                        )))
                        .await;
                    return;
                }
            };

            if sender.send(SubscriptionEvent::Ready).await.is_err() {
                return;
            }

            while let Some(signal) = signals.next().await {
                match signal.args() {
                    Ok(arguments) => {
                        let event = SubscriptionEvent::Token {
                            token: arguments.token.to_string(),
                            server_url: arguments.server_url.to_string(),
                        };
                        if sender.send(event).await.is_err() {
                            return;
                        }
                    }
                    Err(error) => {
                        let _ = sender
                            .send(SubscriptionEvent::Error(format!(
                                "failed to decode JwtTokenStateChange arguments: {error}"
                            )))
                            .await;
                        return;
                    }
                }
            }

            let _ = sender
                .send(SubscriptionEvent::Error(
                    "JwtTokenStateChange stream ended".to_owned(),
                ))
                .await;
        });

        JwtTokenStateChangeSubscription { receiver, task }
    }

    /// One-shot helper for a single `JwtTokenStateChange` event.
    ///
    /// This creates a fresh subscription for one event. Use
    /// [`Self::subscribe_jwt_token_state_change`] for continuous handling.
    pub async fn wait_for_jwt_token_state_change(&self) -> Result<(String, String)> {
        self.wait_for_jwt_token_state_change_with_timeout(DBUS_SIGNAL_TIMEOUT)
            .await
    }

    /// One-shot helper with a caller-provided timeout.
    ///
    /// This creates a fresh subscription for one event. Use
    /// [`Self::subscribe_jwt_token_state_change`] for continuous handling.
    pub async fn wait_for_jwt_token_state_change_with_timeout(
        &self,
        timeout: Duration,
    ) -> Result<(String, String)> {
        let mut subscription = self.subscribe_jwt_token_state_change();

        tokio::time::timeout(timeout, async {
            subscription.wait_ready().await?;
            match subscription.next().await? {
                Some(event) => Ok(event),
                None => bail!("JwtTokenStateChange subscription ended"),
            }
        })
        .await
        .context("timed out waiting for JwtTokenStateChange")?
    }
}
