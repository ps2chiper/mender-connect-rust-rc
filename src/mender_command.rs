//! Bounded asynchronous owner of the Mender command worker.
//!
//! Protocol 4 accepts only the literal `check-update` / `send-inventory`
//! allowlist from a current account. Bodies and properties are budgeted then
//! ignored. At most one command runs at a time; the worker uses a fixed
//! `PATH`-only environment with no agent secrets. The kernel and filesystem
//! are assumed responsive, an external child reaper is forbidden, and the
//! worker's session kill cannot contain descendants that escaped the session.
//!
//! `Drop` can only signal cancellation. The blocking worker owns cleanup and
//! polls at least every 100 ms; call [`MenderCommandManager::close_all`] to
//! await verified cleanup explicitly.

#[path = "mender_command_schema.rs"]
mod schema;
#[path = "mender_command_worker.rs"]
mod worker;

pub use worker::CommandCleanupFailure;

#[cfg(test)]
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
#[cfg(test)]
use std::time::Duration;

use anyhow::Result;
use tokio::task::JoinHandle;

use crate::protocol::ProtoMsg;

/// A running command task together with its cancel guard and request SID.
struct Entry {
    handle: JoinHandle<Result<ProtoMsg>>,
    cancel: Arc<AtomicBool>,
    session_id: String,
}

impl Drop for Entry {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
    }
}

/// Serializes and supervises at most one command worker.
pub struct MenderCommandManager {
    entry: Option<Entry>,
    fatal: Option<CommandCleanupFailure>,
    config: worker::Config,
}

impl Default for MenderCommandManager {
    fn default() -> Self {
        Self::new()
    }
}

impl MenderCommandManager {
    /// Create a manager using the fixed production allowlist and deadlines.
    pub fn new() -> Self {
        Self {
            entry: None,
            fatal: None,
            config: worker::Config::production(),
        }
    }

    /// Test-only fixture configuration with exactly one candidate.
    #[cfg(test)]
    pub fn with_fixture(path: PathBuf, execution: Duration, cleanup: Duration) -> Result<Self> {
        if !path.is_absolute() {
            anyhow::bail!("fixture path must be absolute");
        }
        if execution.is_zero() || execution > Duration::from_secs(60) {
            anyhow::bail!("fixture execution deadline out of bounds");
        }
        if cleanup.is_zero() || cleanup > Duration::from_secs(5) {
            anyhow::bail!("fixture cleanup deadline out of bounds");
        }
        Ok(Self {
            entry: None,
            fatal: None,
            config: worker::Config {
                candidates: vec![path],
                execution,
                cleanup,
            },
        })
    }

    /// Validate and launch the supplied message, returning immediate wire output.
    pub async fn handle(&mut self, message: ProtoMsg) -> Result<Vec<ProtoMsg>> {
        if let Some(marker) = &self.fatal {
            return Err(anyhow::Error::new(marker.clone()));
        }

        // Copy only bounded scalars into a fallback before consuming the input;
        // this header is never executed and never carries the original body.
        let fallback = schema::reply(&message.header, None).header;

        // Reap a finished worker into bounded output before validating the
        // incoming message so a completed reply is never silently dropped.
        let mut out = Vec::new();
        let all_finished = self
            .entry
            .as_ref()
            .is_some_and(|entry| entry.handle.is_finished());
        if all_finished && let Some(reply) = self.join_active().await? {
            out.push(reply);
        }

        let request = match schema::parse(message) {
            Ok(request) => request,
            Err(err) => {
                out.push(schema::reply(&fallback, Some(&format!("{err:#}"))));
                return Ok(out);
            }
        };

        if self.entry.is_some() {
            out.push(schema::reply(
                &request.header,
                Some("command already in progress"),
            ));
            return Ok(out);
        }

        let session_id = request.header.session_id.clone();
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = Arc::clone(&cancel);
        let config = self.config.clone();
        let handle =
            tokio::task::spawn_blocking(move || worker::run(request, config, worker_cancel));
        self.entry = Some(Entry {
            handle,
            cancel,
            session_id,
        });
        Ok(out)
    }

    /// Await the active worker and return its single wire reply, if one exists.
    pub async fn next_message(&mut self) -> Result<Option<ProtoMsg>> {
        if self.entry.is_none() {
            if let Some(marker) = &self.fatal {
                return Err(anyhow::Error::new(marker.clone()));
            }
            return Ok(None);
        }
        self.join_active().await
    }

    /// Report whether a worker entry is still owned (possibly already finished).
    pub fn has_pending(&self) -> bool {
        self.entry.is_some()
    }

    /// Cancel and await verified cleanup, discarding any normal wire reply.
    pub(crate) fn request_cancel_all(&self) {
        if let Some(entry) = self.entry.as_ref() {
            entry.cancel.store(true, Ordering::Release);
        }
    }

    pub async fn close_all(&mut self) -> Result<()> {
        self.request_cancel_all();
        if self.entry.is_some() {
            self.join_active().await?;
        }
        if let Some(marker) = &self.fatal {
            return Err(anyhow::Error::new(marker.clone()));
        }
        Ok(())
    }

    /// Cancel only the active command whose request SID matches `sid`.
    pub async fn close_session(&mut self, sid: &str) -> Result<()> {
        let matches = self
            .entry
            .as_ref()
            .is_some_and(|entry| entry.session_id == sid);
        if !matches {
            return Ok(());
        }
        if let Some(entry) = self.entry.as_ref() {
            entry.cancel.store(true, Ordering::Release);
        }
        self.join_active().await?;
        if let Some(marker) = &self.fatal {
            return Err(anyhow::Error::new(marker.clone()));
        }
        Ok(())
    }

    /// Await the stored worker, remove the entry, and classify a fatal outcome.
    async fn join_active(&mut self) -> Result<Option<ProtoMsg>> {
        // Borrow the stored handle in place: aborting this future leaves the
        // manager owning the cancel guard, so no stray worker loses cancellation.
        let joined = match self.entry.as_mut() {
            Some(entry) => (&mut entry.handle).await,
            None => return Ok(None),
        };
        self.entry.take();
        self.resolve(joined)
    }

    /// Convert a join result to a reply or a cached fatal cleanup marker.
    fn resolve(
        &mut self,
        joined: std::result::Result<Result<ProtoMsg>, tokio::task::JoinError>,
    ) -> Result<Option<ProtoMsg>> {
        match joined {
            Ok(Ok(reply)) => Ok(Some(reply)),
            Ok(Err(err)) => {
                let marker = classify_worker_error(err);
                self.fatal = Some(marker.clone());
                Err(anyhow::Error::new(marker))
            }
            Err(join_err) => {
                let cause = anyhow::Error::new(join_err).context("command worker task failed");
                let marker = CommandCleanupFailure::new(cause);
                self.fatal = Some(marker.clone());
                Err(anyhow::Error::new(marker))
            }
        }
    }
}

/// Preserve a typed cleanup marker, otherwise conservatively type the error.
fn classify_worker_error(err: anyhow::Error) -> CommandCleanupFailure {
    match err.downcast::<CommandCleanupFailure>() {
        Ok(marker) => marker,
        Err(err) => CommandCleanupFailure::new(
            err.context("command worker failed without a typed cleanup marker"),
        ),
    }
}

#[cfg(test)]
impl MenderCommandManager {
    #[allow(dead_code)] // This module is also compiled independently by integration tests.
    pub(crate) fn install_teardown_probe(
        &mut self,
    ) -> anyhow::Result<(
        std::sync::Arc<std::sync::atomic::AtomicBool>,
        tokio::sync::oneshot::Sender<()>,
    )> {
        if self.entry.is_some() {
            anyhow::bail!("probe manager is not empty");
        }
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (release, gate) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            let _ = gate.await;
            Ok(ProtoMsg {
                header: crate::protocol::ProtoHdr::default(),
                body: Vec::new(),
            })
        });
        self.entry = Some(Entry {
            handle,
            cancel: cancel.clone(),
            session_id: "probe-command".into(),
        });
        Ok((cancel, release))
    }
}

/// Deterministic, subprocess-free tests for the manager handoff state machine.
///
/// These construct [`Entry`] values directly with controlled
/// `JoinHandle<Result<ProtoMsg>>` tasks so that the observed integration-test
/// nondeterminism can be shown to be a *test-identification* issue, not a
/// production wire-semantics bug. The prior-worker reply is always identified
/// by its request SID: a completed prior worker may legitimately report a
/// status-2 timeout under full-suite load, and identifying by status alone would
/// misclassify the newly launched worker's later reply as the handoff.
#[cfg(test)]
mod handoff_tests {
    use std::collections::BTreeMap;

    use rmpv::Value;

    use super::*;
    use crate::protocol::{ProtoHdr, ProtoType};

    /// A reply-shaped message with an explicit request SID and status.
    fn shaped_reply(msg_type: &str, sid: &str, status: i64) -> ProtoMsg {
        let mut properties = BTreeMap::new();
        properties.insert("status".to_owned(), Value::from(status));
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::MENDER_CLIENT,
                msg_type: msg_type.to_owned(),
                session_id: sid.to_owned(),
                properties,
            },
            body: Vec::new(),
        }
    }

    /// A schema-valid `check-update` request for the given SID.
    fn valid_request(sid: &str) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::MENDER_CLIENT,
                msg_type: "check-update".to_owned(),
                session_id: sid.to_owned(),
                properties: BTreeMap::new(),
            },
            body: Vec::new(),
        }
    }

    /// A schema-invalid request (unknown command type) for the given SID.
    fn invalid_request(sid: &str) -> ProtoMsg {
        ProtoMsg {
            header: ProtoHdr {
                proto: ProtoType::MENDER_CLIENT,
                msg_type: "bogus-type".to_owned(),
                session_id: sid.to_owned(),
                properties: BTreeMap::new(),
            },
            body: Vec::new(),
        }
    }

    fn status_of(message: &ProtoMsg) -> Option<i64> {
        message
            .header
            .properties
            .get("status")
            .and_then(Value::as_i64)
    }

    /// A `JoinHandle<Result<ProtoMsg>>` that is deterministically already
    /// finished. The spawned future has no await points, so on the
    /// current-thread test runtime a single yield runs it to completion; the
    /// bounded loop never sleeps and cannot spin forever.
    async fn finished_handle(reply: ProtoMsg) -> JoinHandle<Result<ProtoMsg>> {
        let handle = tokio::spawn(async move { Ok(reply) });
        let mut spins = 0u32;
        while !handle.is_finished() && spins < 1024 {
            tokio::task::yield_now().await;
            spins += 1;
        }
        assert!(handle.is_finished(), "spawned reply did not settle");
        handle
    }

    /// A manager whose configured worker cannot touch any real binary: the
    /// single absent candidate yields an ordinary status-2 reply without
    /// executing anything.
    fn inert_manager() -> MenderCommandManager {
        MenderCommandManager::with_fixture(
            PathBuf::from("/nonexistent/mender-handoff-fixture"),
            Duration::from_millis(500),
            Duration::from_millis(500),
        )
        .expect("inert fixture configuration is valid")
    }

    // A completed prior worker must (1) deliver its own reply immediately and
    // (2) have the new request launched in the same `handle` call. The prior
    // reply is identified by its request SID, so a status-2 timeout observation
    // can never be mistaken for a dropped handoff.
    #[tokio::test]
    async fn completed_prior_emits_old_reply_and_launches_new() {
        let mut manager = inert_manager();
        let old_reply = shaped_reply("check-update", "old", 1);
        let handle = finished_handle(old_reply).await;
        manager.entry = Some(Entry {
            handle,
            cancel: Arc::new(AtomicBool::new(false)),
            session_id: "old".to_owned(),
        });
        assert!(manager.has_pending(), "prior worker is owned");

        let out = manager
            .handle(valid_request("new"))
            .await
            .expect("handoff must not error");
        let delivered = out
            .iter()
            .find(|msg| msg.header.session_id == "old")
            .expect("completed prior reply must be delivered");
        assert_eq!(status_of(delivered), Some(1));
        assert_eq!(
            manager
                .entry
                .as_ref()
                .map(|entry| entry.session_id.as_str()),
            Some("new"),
            "new worker must be launched in the same handle call"
        );

        manager.close_all().await.expect("cleanup is bounded");
        assert!(!manager.has_pending());
    }

    // A busy prior worker must never be lost or replaced: the new request is
    // rejected while the owned entry (identified by SID) is retained.
    #[tokio::test]
    async fn busy_prior_worker_is_never_lost() {
        let mut manager = inert_manager();
        let gate = Arc::new(AtomicBool::new(false));
        let worker_gate = Arc::clone(&gate);
        let handle = tokio::spawn(async move {
            while !worker_gate.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
            Ok(shaped_reply("check-update", "old", 1))
        });
        // Let the gated task reach its pending yield loop deterministically.
        tokio::task::yield_now().await;
        assert!(!handle.is_finished(), "gated prior worker stays busy");
        manager.entry = Some(Entry {
            handle,
            cancel: Arc::new(AtomicBool::new(false)),
            session_id: "old".to_owned(),
        });

        let out = manager
            .handle(valid_request("new"))
            .await
            .expect("busy rejection must not error");
        assert_eq!(out.len(), 1, "busy request gets exactly one reply");
        assert_eq!(status_of(&out[0]), Some(2), "busy request uses status 2");
        assert_eq!(
            manager
                .entry
                .as_ref()
                .map(|entry| entry.session_id.as_str()),
            Some("old"),
            "the busy prior worker must be retained"
        );

        gate.store(true, Ordering::Release);
        manager.close_all().await.expect("cleanup is bounded");
        assert!(!manager.has_pending());
    }

    // A completed prior worker plus an INVALID new request must (1) deliver the
    // prior reply and (2) reject the new request in the same `handle` call,
    // without launching a worker. This is the deterministic counterpart of the
    // polling integration coverage; identifying the prior reply by SID keeps a
    // status-2 prior outcome from being mistaken for the handoff.
    #[tokio::test]
    async fn completed_prior_with_invalid_new_request_yields_both_replies() {
        let mut manager = inert_manager();
        let handle = finished_handle(shaped_reply("check-update", "old", 1)).await;
        manager.entry = Some(Entry {
            handle,
            cancel: Arc::new(AtomicBool::new(false)),
            session_id: "old".to_owned(),
        });
        assert!(manager.has_pending(), "prior worker is owned");

        let out = manager
            .handle(invalid_request("new"))
            .await
            .expect("invalid handoff must not error");
        assert_eq!(out.len(), 2, "old reply plus new rejection");
        assert!(
            out.iter().any(|msg| msg.header.session_id == "old"
                && msg.header.msg_type == "check-update"
                && status_of(msg) == Some(1)),
            "completed prior reply must be delivered"
        );
        assert!(
            out.iter()
                .any(|msg| msg.header.session_id == "new" && status_of(msg) == Some(2)),
            "the invalid request is rejected in the same call"
        );
        assert!(
            !manager.has_pending(),
            "an invalid request must not launch a worker"
        );

        manager.close_all().await.expect("cleanup is bounded");
        assert!(!manager.has_pending());
    }
}
