//! TEST-ONLY mock of the Mender Authentication1 D-Bus interface.
//!
//! This example is for local integration work only. It connects exclusively to
//! the session bus, refuses to run without `DBUS_SESSION_BUS_ADDRESS`, and
//! returns a test token plus the endpoint read from the supplied file. It is
//! not a production authentication service.
//!
//! The mock keeps token and endpoint in shared state. `GetJwtToken` increments a
//! get counter and returns a snapshot of that state. The initial endpoint comes
//! from the file argument; the initial token comes from
//! `MENDER_TRIAL_INITIAL_TOKEN` when that variable exists (an empty value is
//! valid), otherwise `trial-local-token`.
//!
//! TEST-ONLY control interface: `io.mender.TrialControl` is exported at the
//! same object path. Its `SetState(token, endpoint)` method updates the shared
//! state and then emits the real `io.mender.Authentication1.JwtTokenStateChange`
//! signal from this service connection. Its `GetFetchCount()` method returns
//! the number of `FetchJwtToken` calls observed so far. This interface is only
//! for local tests and must never be added to production library/auth code.
//!
//! TEST-ONLY additional control methods (also on `io.mender.TrialControl`):
//! * `SetStateQuiet(token, endpoint)` updates the current token/endpoint tuple
//!   *without* emitting any signal, so tests can stage the cached state the way
//!   a real HTTP auth failure leaves a previously authorized token in place.
//! * `GetGetCount()` returns the number of `GetJwtToken` calls observed so far.
//! * `SetFetchState(token, endpoint)` records a pending tuple. The *next*
//!   successful `FetchJwtToken` that is not intercepted by false/empty/revoke
//!   injection will put that tuple into current state and emit
//!   `JwtTokenStateChange`, then consume the pending tuple. This lets 401-style
//!   tests keep the currently cached old token until a forced fetch swaps it.
//!
//! TEST-ONLY revocation behavior: if `MENDER_TRIAL_REVOKE_ON_FETCH` equals
//! `"1"`, a call to `FetchJwtToken` first sets the current token to empty and
//! emits `JwtTokenStateChange("", endpoint)` from this service connection, then
//! returns `true`. If emitting the signal fails, `FetchJwtToken` returns
//! `false`. When the variable is absent (or any other value), `FetchJwtToken`
//! simply returns `true`; it does not authorize an empty initial token. Tests
//! should call `SetState` to authorize.
//!
//! TEST-ONLY failure injection: `MENDER_TRIAL_FETCH_FALSE_COUNT` (default `0`)
//! makes the first that many `FetchJwtToken` calls return `false` without
//! emitting a signal or authorizing. Subsequent calls behave exactly as
//! described above (including `MENDER_TRIAL_REVOKE_ON_FETCH`). Every
//! `FetchJwtToken` call is counted and can be read via
//! `io.mender.TrialControl.GetFetchCount()`.
//!
//! TEST-ONLY empty-fetch injection: `MENDER_TRIAL_FETCH_EMPTY_COUNT` (default
//! `0`) is the number of "empty" fetches to simulate after the false-failure
//! injection is exhausted. For each of the first that many *successful* fetches
//! (i.e. not already intercepted by `MENDER_TRIAL_FETCH_FALSE_COUNT`), the mock
//! decrements the counter, clears the current token, emits
//! `JwtTokenStateChange("", endpoint)`, and returns `true`. This simulates the
//! official HTTP auth path returning an empty token on failure. Once this
//! counter reaches zero, `MENDER_TRIAL_REVOKE_ON_FETCH` retains its behavior.
//! False/empty/revoke injection always takes precedence over a pending
//! `SetFetchState` tuple and never consumes it until it is actually used.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use clap::Parser;
use mender_connect_rust::auth::{DBUS_OBJECT_PATH, DBUS_SERVICE};
use tokio::sync::RwLock;

const TEST_TOKEN: &str = "trial-local-token";

#[derive(Debug, Parser)]
#[command(
    name = "mock-auth",
    about = "TEST-ONLY session-bus mock of io.mender.Authentication1"
)]
struct Args {
    /// File containing the websocket endpoint to return from GetJwtToken.
    endpoint_file: PathBuf,
}

struct State {
    token: String,
    endpoint: String,
    fetch_count: u32,
    fetch_false_remaining: u32,
    /// Number of remaining "empty fetch" injections to simulate.
    fetch_empty_remaining: u32,
    /// Counter of `GetJwtToken` calls observed so far.
    get_count: u32,
    /// Pending tuple to install on the next successful, non-intercepted fetch.
    fetch_state: Option<(String, String)>,
}

type SharedState = Arc<RwLock<State>>;

/// A single `FetchJwtToken` decision, computed under the shared write lock and
/// executed (including any signal emission) after the lock is released.
enum FetchAction {
    /// Injection: return `false`, no state change, no signal.
    Fail,
    /// Default path: return `true`, no signal.
    Silent,
    /// Empty-fetch or revoke: emit an empty token, then return `true`.
    EmitEmpty { endpoint: String },
    /// Configured success: install and emit the pending tuple.
    EmitConfigured { token: String, endpoint: String },
}

struct MockAuthentication {
    state: SharedState,
    connection: zbus::Connection,
}

impl MockAuthentication {
    /// Emit `JwtTokenStateChange` from the service connection. Returns `false`
    /// if the emitter cannot be created or the signal cannot be sent.
    async fn emit_state_change(&self, token: &str, endpoint: &str) -> bool {
        let emitter =
            match zbus::object_server::SignalEmitter::new(&self.connection, DBUS_OBJECT_PATH) {
                Ok(emitter) => emitter,
                Err(_) => return false,
            };
        Self::jwt_token_state_change(&emitter, token, endpoint)
            .await
            .is_ok()
    }
}

#[zbus::interface(name = "io.mender.Authentication1")]
impl MockAuthentication {
    async fn get_jwt_token(&self) -> (String, String) {
        let mut state = self.state.write().await;
        state.get_count = state.get_count.saturating_add(1);
        (state.token.clone(), state.endpoint.clone())
    }

    async fn fetch_jwt_token(&self) -> bool {
        // Compute the decision and apply all shared-state mutations under a
        // single write lock, then drop the lock before emitting any signal.
        let action = {
            let mut state = self.state.write().await;
            state.fetch_count = state.fetch_count.saturating_add(1);

            if state.fetch_false_remaining > 0 {
                // False-failure injection takes precedence and does not touch
                // the pending successful tuple.
                state.fetch_false_remaining -= 1;
                FetchAction::Fail
            } else if state.fetch_empty_remaining > 0 {
                // Simulated official HTTP auth failure: clear the token and
                // emit an empty state change. Does not consume fetch_state.
                state.fetch_empty_remaining -= 1;
                state.token.clear();
                FetchAction::EmitEmpty {
                    endpoint: state.endpoint.clone(),
                }
            } else if env::var("MENDER_TRIAL_REVOKE_ON_FETCH").as_deref() == Ok("1") {
                // Revocation injection, active only once the empty counter is
                // exhausted. Does not consume fetch_state.
                state.token.clear();
                FetchAction::EmitEmpty {
                    endpoint: state.endpoint.clone(),
                }
            } else if let Some((token, endpoint)) = state.fetch_state.take() {
                // A pending successful fetch is applied and consumed now.
                state.token = token.clone();
                state.endpoint = endpoint.clone();
                FetchAction::EmitConfigured { token, endpoint }
            } else {
                // Default behavior: succeed without any signal.
                FetchAction::Silent
            }
        };

        match action {
            FetchAction::Fail => false,
            FetchAction::Silent => true,
            FetchAction::EmitEmpty { endpoint } => self.emit_state_change("", &endpoint).await,
            FetchAction::EmitConfigured { token, endpoint } => {
                self.emit_state_change(&token, &endpoint).await
            }
        }
    }

    #[zbus(signal)]
    async fn jwt_token_state_change(
        emitter: &zbus::object_server::SignalEmitter<'_>,
        token: &str,
        server_url: &str,
    ) -> zbus::Result<()>;
}

struct TrialControl {
    state: SharedState,
    connection: zbus::Connection,
}

#[zbus::interface(name = "io.mender.TrialControl")]
impl TrialControl {
    async fn set_state(&self, token: String, endpoint: String) -> zbus::fdo::Result<()> {
        {
            let mut state = self.state.write().await;
            state.token = token.clone();
            state.endpoint = endpoint.clone();
        }

        let emitter = zbus::object_server::SignalEmitter::new(&self.connection, DBUS_OBJECT_PATH)
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        MockAuthentication::jwt_token_state_change(&emitter, &token, &endpoint)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        Ok(())
    }

    async fn get_fetch_count(&self) -> u32 {
        self.state.read().await.fetch_count
    }

    /// TEST-ONLY: update the current token/endpoint tuple without emitting any
    /// signal. Used to stage cached state for auth-failure tests.
    async fn set_state_quiet(&self, token: String, endpoint: String) {
        let mut state = self.state.write().await;
        state.token = token;
        state.endpoint = endpoint;
    }

    /// TEST-ONLY: report how many `GetJwtToken` calls have been observed.
    async fn get_get_count(&self) -> u32 {
        self.state.read().await.get_count
    }

    /// TEST-ONLY: install a pending tuple that the next successful
    /// `FetchJwtToken` (not intercepted by false/empty/revoke injection) will
    /// apply and emit. Does not modify current state or emit a signal now.
    async fn set_fetch_state(&self, token: String, endpoint: String) {
        let mut state = self.state.write().await;
        state.fetch_state = Some((token, endpoint));
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    if env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        bail!(
            "DBUS_SESSION_BUS_ADDRESS is not set; run this TEST-ONLY mock under dbus-run-session"
        );
    }

    let args = Args::parse();
    let endpoint = std::fs::read_to_string(&args.endpoint_file).with_context(|| {
        format!(
            "failed to read endpoint file {}",
            args.endpoint_file.display()
        )
    })?;
    let endpoint = endpoint.trim().to_owned();
    if endpoint.is_empty() {
        bail!("endpoint file {} is empty", args.endpoint_file.display());
    }

    let initial_token =
        env::var("MENDER_TRIAL_INITIAL_TOKEN").unwrap_or_else(|_| TEST_TOKEN.to_owned());
    let fetch_false_remaining = env::var("MENDER_TRIAL_FETCH_FALSE_COUNT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let fetch_empty_remaining = env::var("MENDER_TRIAL_FETCH_EMPTY_COUNT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(0);
    let state = Arc::new(RwLock::new(State {
        token: initial_token,
        endpoint,
        fetch_count: 0,
        fetch_false_remaining,
        fetch_empty_remaining,
        get_count: 0,
        fetch_state: None,
    }));

    let connection = zbus::Connection::session()
        .await
        .context("failed to connect to the session D-Bus")?;
    connection
        .request_name(DBUS_SERVICE)
        .await
        .context("failed to request the AuthenticationManager service name")?;
    connection
        .object_server()
        .at(
            DBUS_OBJECT_PATH,
            MockAuthentication {
                state: state.clone(),
                connection: connection.clone(),
            },
        )
        .await
        .context("failed to register the mock Authentication1 interface")?;
    connection
        .object_server()
        .at(
            DBUS_OBJECT_PATH,
            TrialControl {
                state,
                connection: connection.clone(),
            },
        )
        .await
        .context("failed to register the TEST-ONLY TrialControl interface")?;

    eprintln!("TEST-ONLY mock Authentication1 service is running on the session bus");
    eprintln!("  service: {DBUS_SERVICE}");
    eprintln!("  path: {DBUS_OBJECT_PATH}");
    eprintln!("  credentials: TEST-ONLY");
    eprintln!("  control interface: io.mender.TrialControl");
    eprintln!("press ctrl-c to stop");

    tokio::signal::ctrl_c()
        .await
        .context("failed to wait for ctrl-c")?;
    Ok(())
}
