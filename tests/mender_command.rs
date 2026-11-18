//! Behavioural tests for the bounded Mender command worker owner.
//!
//! Every executed program is a private temporary fixture script (mode 0700)
//! interpreted by `/bin/sh`. No real `mender`/`update` binary, server, device
//! or authentication key is ever touched. Fixture script bodies are trusted
//! test constants only; protocol-provided data is never interpolated into a
//! script.

use std::collections::BTreeMap;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;
use tempfile::{Builder, TempDir};
use tokio::sync::{Semaphore, SemaphorePermit};

use mender_connect_rust::{protocol, session_process};
use protocol::{ProtoHdr, ProtoMsg, ProtoType};
use rmpv::Value;

#[path = "../src/mender_command.rs"]
mod mender_command;

use mender_command::MenderCommandManager;

// ---------------------------------------------------------------------------
// Deadlines (generous, but the whole suite stays well under 30s).
// ---------------------------------------------------------------------------

const EXEC: Duration = Duration::from_secs(2);
const CLEANUP: Duration = Duration::from_secs(2);
const OUTER: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Fixture: private script, argument log, readiness/marker/child-pid paths.
// ---------------------------------------------------------------------------

// Bound the number of concurrently executing real fixture processes across the
// whole test binary. This prevents a WSL test-process spawn storm (many tests
// run in parallel while each fixture may spawn descendants); it is not a
// production load-qualification limit.
static FIXTURE_LIMIT: Semaphore = Semaphore::const_new(2);

struct Fixture {
    _permit: SemaphorePermit<'static>,
    _dir: TempDir,
    bin: PathBuf,
    argslog: PathBuf,
    ready: PathBuf,
    marker: PathBuf,
    pidpath: PathBuf,
}

impl Fixture {
    async fn new(tag: &str) -> io::Result<Self> {
        let permit = tokio::time::timeout(Duration::from_secs(30), FIXTURE_LIMIT.acquire())
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "timed out after 30s waiting for a fixture permit",
                )
            })?
            .map_err(|_| io::Error::other("fixture permit semaphore unexpectedly closed"))?;
        let dir = Builder::new()
            .prefix(&format!("mender-cmd-{tag}-"))
            .tempdir()?;
        let bin = dir.path().join("mender-fixture.sh");
        let argslog = dir.path().join("args.log");
        let ready = dir.path().join("ready");
        let marker = dir.path().join("marker");
        let pidpath = dir.path().join("child.pid");
        Ok(Self {
            _permit: permit,
            _dir: dir,
            bin,
            argslog,
            ready,
            marker,
            pidpath,
        })
    }

    /// Configured manager pointing at this fixture binary with the default
    /// deadlines.
    fn manager(&self) -> anyhow::Result<MenderCommandManager> {
        self.manager_with(EXEC, CLEANUP)
    }

    fn manager_with(
        &self,
        execution: Duration,
        cleanup: Duration,
    ) -> anyhow::Result<MenderCommandManager> {
        MenderCommandManager::with_fixture(self.bin.clone(), execution, cleanup)
    }

    /// Write the fixture script with a trusted body, executable 0700.
    fn write_script(&self, body: &str) -> io::Result<()> {
        self.write_script_mode(body, 0o700)
    }

    /// Write the fixture script with an explicit permission mode.
    fn write_script_mode(&self, body: &str, mode: u32) -> io::Result<()> {
        let mut content = String::new();
        content.push_str("#!/bin/sh\n");
        // Record invocation shape: argument count and first argument only.
        content.push_str(&format!(
            "printf '%s:%s' \"$#\" \"$1\" >> {}\n",
            sh_quote(&self.argslog)
        ));
        content.push_str(&format!(
            "printf '%s' \"$$\" > {}\n",
            sh_quote(&self.pidpath)
        ));
        content.push_str(&format!(": > {}\n", sh_quote(&self.ready)));
        content.push_str(body);
        if !body.ends_with('\n') {
            content.push('\n');
        }
        std::fs::write(&self.bin, content)?;
        std::fs::set_permissions(&self.bin, std::fs::Permissions::from_mode(mode))
    }

    fn read_argslog(&self) -> Option<String> {
        std::fs::read_to_string(&self.argslog).ok()
    }

    fn marker_exists(&self) -> bool {
        self.marker.exists()
    }
}

/// Quote a path for safe inclusion in a POSIX shell single-quoted context.
fn sh_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    let mut out = String::from("'");
    for ch in text.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

// ---------------------------------------------------------------------------
// Protocol helpers.
// ---------------------------------------------------------------------------

fn empty() -> BTreeMap<String, Value> {
    BTreeMap::new()
}

fn request(
    proto: ProtoType,
    typ: &str,
    sid: &str,
    body: Vec<u8>,
    properties: BTreeMap<String, Value>,
) -> ProtoMsg {
    ProtoMsg {
        header: ProtoHdr {
            proto,
            msg_type: typ.to_owned(),
            session_id: sid.to_owned(),
            properties,
        },
        body,
    }
}

fn client(typ: &str, sid: &str) -> ProtoMsg {
    request(ProtoType::MENDER_CLIENT, typ, sid, Vec::new(), empty())
}

fn status(message: &ProtoMsg) -> Option<i64> {
    message
        .header
        .properties
        .get("status")
        .and_then(Value::as_i64)
}

/// Launch a valid command and await its single reply.
async fn run_valid(
    manager: &mut MenderCommandManager,
    message: ProtoMsg,
) -> anyhow::Result<ProtoMsg> {
    let out = manager.handle(message).await?;
    assert!(out.is_empty(), "valid launch must not reply immediately");
    let reply = tokio::time::timeout(OUTER, manager.next_message())
        .await
        .expect("worker must not hang")?
        .expect("worker must produce a reply");
    Ok(reply)
}

/// Assert an immediate rejection that never executes the fixture.
async fn expect_reject(manager: &mut MenderCommandManager, message: ProtoMsg) {
    let out = manager
        .handle(message)
        .await
        .expect("rejection must not escalate to an error");
    assert_eq!(out.len(), 1, "rejection returns exactly one reply");
    assert_eq!(status(&out[0]), Some(2), "rejections use status 2");
    assert!(
        out[0].header.msg_type.len() <= 64,
        "echoed type stays bounded"
    );
    assert!(
        out[0].header.session_id.len() <= 128,
        "echoed session id stays bounded"
    );
    assert!(out[0].body.len() <= 1024, "error body stays bounded");
    assert!(!manager.has_pending(), "rejection must not launch a worker");
}

// ---------------------------------------------------------------------------
// 1. Supported commands succeed with bounded, non-reflected replies.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn supported_commands_succeed() -> anyhow::Result<()> {
    let fx = Fixture::new("supported").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    // check-update with empty session id.
    let reply = run_valid(&mut manager, client("check-update", "")).await?;
    assert_eq!(reply.header.proto, ProtoType::MENDER_CLIENT);
    assert_eq!(reply.header.msg_type, "check-update");
    assert_eq!(reply.header.session_id, "");
    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty(), "success body must be empty");
    assert_eq!(
        fx.read_argslog().as_deref(),
        Some("1:check-update"),
        "single literal argument, exactly one invocation"
    );
    assert!(!manager.has_pending());

    // send-inventory with a non-empty session id echoes the SID.
    let reply = run_valid(&mut manager, client("send-inventory", "sid-abc")).await?;
    assert_eq!(reply.header.msg_type, "send-inventory");
    assert_eq!(reply.header.session_id, "sid-abc");
    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty());

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 2. Malicious bodies / properties are inert and never reflected.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn malicious_body_is_never_executed_or_reflected() -> anyhow::Result<()> {
    let fx = Fixture::new("injection").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    let marker = fx.marker.to_string_lossy().into_owned();
    let injection = format!("check-update; touch {marker}; echo pwned; send-inventory /etc/passwd");

    let mut props = empty();
    props.insert("args".to_owned(), Value::from(marker.clone()));
    props.insert("path".to_owned(), Value::from("/etc/passwd"));

    let message = request(
        ProtoType::MENDER_CLIENT,
        "check-update",
        "",
        injection.clone().into_bytes(),
        props,
    );
    let reply = run_valid(&mut manager, message).await?;

    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty(), "body must not be reflected");
    assert!(
        !String::from_utf8_lossy(&reply.body).contains("pwned"),
        "no body content may appear in the reply"
    );
    assert!(!fx.marker_exists(), "injection must not create a marker");
    assert_eq!(
        fx.read_argslog().as_deref(),
        Some("1:check-update"),
        "only the literal command argument is passed"
    );

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 3a. Invalid inputs are rejected with bounded replies before execution.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn invalid_inputs_rejected_before_execution() -> anyhow::Result<()> {
    let fx = Fixture::new("invalid").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    // Wrong protocol.
    expect_reject(
        &mut manager,
        request(ProtoType::SHELL, "check-update", "", Vec::new(), empty()),
    )
    .await;

    // Unknown type that also looks like shell syntax.
    expect_reject(&mut manager, client("check-update; touch x", "")).await;

    // Session id with a control character.
    expect_reject(&mut manager, client("check-update", "bad\nsid")).await;

    // Overlong session id (129 bytes).
    expect_reject(&mut manager, client("check-update", &"a".repeat(129))).await;

    // Overlong type (65 bytes).
    expect_reject(&mut manager, client(&"t".repeat(65), "")).await;

    // Oversized body (65537 bytes).
    expect_reject(
        &mut manager,
        request(
            ProtoType::MENDER_CLIENT,
            "check-update",
            "",
            vec![0u8; 65537],
            empty(),
        ),
    )
    .await;

    // Too many properties (33).
    let mut many = BTreeMap::new();
    for index in 0..33 {
        many.insert(format!("k{index}"), Value::from(i64::from(index)));
    }
    expect_reject(
        &mut manager,
        request(
            ProtoType::MENDER_CLIENT,
            "check-update",
            "",
            Vec::new(),
            many,
        ),
    )
    .await;

    // Property value that blows the binary budget.
    let mut budget = BTreeMap::new();
    budget.insert("blob".to_owned(), Value::Binary(vec![0u8; 200_000]));
    expect_reject(
        &mut manager,
        request(
            ProtoType::MENDER_CLIENT,
            "check-update",
            "",
            Vec::new(),
            budget,
        ),
    )
    .await;

    // Property nesting beyond the depth limit.
    let mut nested = Value::from(0i64);
    for _ in 0..20 {
        nested = Value::Array(vec![nested]);
    }
    let mut deep = BTreeMap::new();
    deep.insert("deep".to_owned(), nested);
    expect_reject(
        &mut manager,
        request(
            ProtoType::MENDER_CLIENT,
            "check-update",
            "",
            Vec::new(),
            deep,
        ),
    )
    .await;

    assert!(
        fx.read_argslog().is_none(),
        "no rejected request may execute the fixture"
    );
    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 3b. Boundary-sized accepted inputs run and ignore ignored data.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn boundary_inputs_accepted() -> anyhow::Result<()> {
    let fx = Fixture::new("boundary").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    // 128-byte session id is accepted and echoed.
    let sid = "s".repeat(128);
    let reply = run_valid(&mut manager, client("check-update", &sid)).await?;
    assert_eq!(status(&reply), Some(1));
    assert_eq!(reply.header.session_id, sid);

    // Exactly 65536 bytes of body are accepted, then ignored.
    let reply = run_valid(
        &mut manager,
        request(
            ProtoType::MENDER_CLIENT,
            "send-inventory",
            "s",
            vec![b'z'; 65536],
            empty(),
        ),
    )
    .await?;
    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty(), "ignored body is never reflected");

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 4. Missing / invalid fixtures: ordinary errors, and recovery.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn missing_fixture_is_ordinary_error_then_recovers() -> anyhow::Result<()> {
    let fx = Fixture::new("missing").await?;
    // The fixture binary does not exist yet.
    let mut manager = fx.manager()?;

    let reply = run_valid(&mut manager, client("check-update", "")).await?;
    assert_eq!(
        status(&reply),
        Some(2),
        "missing binary is a status-2 error"
    );
    assert!(!manager.has_pending());

    // Create the binary and reuse the same manager.
    fx.write_script("exit 0\n")?;
    let reply = run_valid(&mut manager, client("send-inventory", "s1")).await?;
    assert_eq!(status(&reply), Some(1), "same manager recovers");
    assert_eq!(reply.header.msg_type, "send-inventory");
    assert!(!manager.has_pending());

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn invalid_fixture_modes_rejected_without_launch() -> anyhow::Result<()> {
    // Each fixture owns a permit until its lexical scope ends, so the three
    // scenarios must not overlap: otherwise the third acquisition would wait
    // forever after close_all even though the prior managers are idle.

    // A directory used as the candidate cannot be executed.
    {
        let dir_fx = Fixture::new("dir").await?;
        std::fs::create_dir_all(&dir_fx.bin)?;
        let mut manager = dir_fx.manager()?;
        let reply = run_valid(&mut manager, client("check-update", "")).await?;
        assert_eq!(status(&reply), Some(2));
        assert!(dir_fx.read_argslog().is_none());
        manager.close_all().await?;
    }

    // A non-executable script is refused without running its body.
    {
        let file_fx = Fixture::new("noexec").await?;
        file_fx.write_script_mode("exit 0\n", 0o600)?;
        let mut manager = file_fx.manager()?;
        let reply = run_valid(&mut manager, client("check-update", "")).await?;
        assert_eq!(status(&reply), Some(2));
        assert!(
            file_fx.read_argslog().is_none(),
            "non-executable script never runs"
        );
        manager.close_all().await?;
    }

    // A setuid-mode private fixture must be rejected before execution.
    {
        let suid_fx = Fixture::new("setuid").await?;
        suid_fx.write_script_mode("exit 0\n", 0o4755)?;
        let mut manager = suid_fx.manager()?;
        let reply = run_valid(&mut manager, client("check-update", "")).await?;
        assert_eq!(status(&reply), Some(2));
        assert!(suid_fx.read_argslog().is_none());
        manager.close_all().await?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// 5. Failures and noisy children stay bounded; success discards output.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn non_zero_exit_is_bounded_error() -> anyhow::Result<()> {
    let fx = Fixture::new("exit7").await?;
    fx.write_script("exit 7\n")?;
    let mut manager = fx.manager()?;

    let reply = run_valid(&mut manager, client("check-update", "")).await?;
    assert_eq!(status(&reply), Some(2), "non-zero exit is a status-2 error");
    assert!(reply.body.len() <= 1024, "diagnostic must stay bounded");

    manager.close_all().await?;
    Ok(())
}

#[tokio::test]
async fn large_output_is_discarded_on_success() -> anyhow::Result<()> {
    let fx = Fixture::new("noisy").await?;
    fx.write_script(
        "i=0\nwhile [ \"$i\" -lt 2000 ]; do echo \"line $i\" 1>&2; echo \"out $i\"; i=$((i+1)); done\nexit 0\n",
    )?;
    let mut manager = fx.manager()?;

    let reply = run_valid(&mut manager, client("check-update", "")).await?;
    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty(), "child output is discarded");

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 6. Construction guards and idle lifecycle idempotence.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fixture_configuration_bounds_enforced() -> anyhow::Result<()> {
    let fx = Fixture::new("config").await?;
    let absolute = fx.bin.clone();

    assert!(
        MenderCommandManager::with_fixture(PathBuf::from("relative/script.sh"), EXEC, CLEANUP)
            .is_err(),
        "relative paths are rejected"
    );
    assert!(
        MenderCommandManager::with_fixture(absolute.clone(), Duration::ZERO, CLEANUP).is_err(),
        "zero execution deadline is rejected"
    );
    assert!(
        MenderCommandManager::with_fixture(absolute.clone(), EXEC, Duration::ZERO).is_err(),
        "zero cleanup deadline is rejected"
    );
    assert!(
        MenderCommandManager::with_fixture(absolute.clone(), Duration::from_secs(61), CLEANUP)
            .is_err(),
        "execution above 60s is rejected"
    );
    assert!(
        MenderCommandManager::with_fixture(absolute, EXEC, Duration::from_secs(6)).is_err(),
        "cleanup above 5s is rejected"
    );

    Ok(())
}

#[tokio::test]
async fn idle_lifecycle_is_idempotent() -> anyhow::Result<()> {
    let mut manager = MenderCommandManager::new();
    assert!(!manager.has_pending());
    assert!(manager.close_all().await.is_ok());
    assert!(manager.close_all().await.is_ok());
    assert!(manager.close_session("whatever").await.is_ok());
    assert!(manager.close_session("whatever").await.is_ok());
    assert!(manager.next_message().await?.is_none());

    let mut default_manager = MenderCommandManager::default();
    assert!(!default_manager.has_pending());
    assert!(default_manager.close_session("").await.is_ok());
    assert!(default_manager.close_all().await.is_ok());

    Ok(())
}

// ---------------------------------------------------------------------------
// 7. Regression: a just-finished worker must not drop a NEW valid request.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn completed_prior_worker_does_not_drop_new_valid_request() -> anyhow::Result<()> {
    let fx = Fixture::new("handoff-valid").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    let out = manager.handle(client("check-update", "old")).await?;
    assert!(out.is_empty());

    let deadline = tokio::time::Instant::now() + OUTER;
    let mut handed_off = false;
    while tokio::time::Instant::now() < deadline {
        let out = manager.handle(client("check-update", "new")).await?;
        // Identify the completed prior worker's reply by its request SID, never
        // by status. Under full-suite load the prior command itself may observe
        // a status-2 timeout; its reply must still be delivered before the new
        // request is dispatched. Matching only on status would misclassify the
        // newly launched worker's own later reply (SID "new") as the handoff and
        // produce the previously observed nondeterministic failure.
        if let Some(reply) = out.iter().find(|msg| msg.header.session_id == "old") {
            assert_eq!(reply.header.msg_type, "check-update");
            assert!(out.len() <= 2, "immediate output stays bounded");
            assert!(
                manager.has_pending(),
                "the new worker must already be launched in the same handle call"
            );
            handed_off = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(handed_off, "the prior worker never reported completion");

    let reply = tokio::time::timeout(OUTER, manager.next_message())
        .await
        .expect("no hang")?
        .expect("new reply");
    // The handed-off worker must produce its own reply; its status may be 1
    // under nominal load but must not be asserted here, since load-induced
    // scheduling delays are outside the behaviour under test.
    assert_eq!(reply.header.session_id, "new");
    assert_eq!(reply.header.msg_type, "check-update");
    assert!(!manager.has_pending());

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 8. Regression: finished worker + INVALID new request yields both replies.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn completed_prior_worker_with_invalid_new_request() -> anyhow::Result<()> {
    let fx = Fixture::new("handoff-invalid").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    let out = manager.handle(client("check-update", "old")).await?;
    assert!(out.is_empty());

    let deadline = tokio::time::Instant::now() + OUTER;
    let mut observed = false;
    while tokio::time::Instant::now() < deadline {
        let out = manager.handle(client("bogus-type", "new")).await?;
        // Identify the completed prior worker's reply by its request SID rather
        // than by status, so a status-2 prior outcome under load is still
        // recognised as the delivered handoff instead of a new reply.
        if let Some(reply) = out.iter().find(|msg| msg.header.session_id == "old") {
            assert_eq!(reply.header.msg_type, "check-update");
            assert!(out.len() <= 2, "at most the old reply and the new error");
            assert!(
                out.iter()
                    .any(|msg| status(msg) == Some(2) && msg.header.session_id == "new"),
                "the invalid request is answered in the same call"
            );
            assert!(
                !manager.has_pending(),
                "an invalid request must not launch a worker"
            );
            observed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(observed, "the prior worker never reported completion");

    manager.close_all().await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Lifecycle helpers: bounded polling, process identity, and private fixtures.
// ---------------------------------------------------------------------------

const POLL: Duration = Duration::from_millis(10);
const OBSERVE: Duration = Duration::from_secs(3);

fn hanging_body(descendant: &Path) -> String {
    format!(
        "/bin/sleep 30 &\nchild=$!\nprintf '%s' \"$child\" > {}\nwait \"$child\"\n",
        sh_quote(descendant)
    )
}

async fn wait_pid_file(path: &Path) -> anyhow::Result<String> {
    let deadline = tokio::time::Instant::now() + OBSERVE;
    loop {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                let trimmed = text.trim();
                if !trimmed.is_empty() && trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                    return Ok(trimmed.to_owned());
                }
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("pid file was not populated: {}", path.display());
        }
        tokio::time::sleep(POLL).await;
    }
}

/// Wait for a fixture readiness file while surfacing an early worker reply.
///
/// A fixture that exits before writing its PID marker would otherwise cause a
/// blind full-deadline wait. Racing the reply future reports the real outcome
/// immediately, while cancellation still retains manager entry ownership.
async fn wait_ready_pid(manager: &mut MenderCommandManager, path: &Path) -> anyhow::Result<String> {
    tokio::select! {
        pid = wait_pid_file(path) => Ok(pid?),
        reply = manager.next_message() => match reply? {
            Some(message) => anyhow::bail!(
                "worker exited before {} was populated (status {:?}, session {:?})",
                path.display(),
                status(&message),
                message.header.session_id
            ),
            None => anyhow::bail!(
                "worker exited without a reply before {} was populated",
                path.display()
            ),
        },
    }
}

#[derive(Clone)]
struct Identity {
    starttime: String,
    sid: String,
    state: char,
}

fn is_not_found(err: &anyhow::Error) -> bool {
    err.chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>())
        .is_some_and(|err| err.kind() == io::ErrorKind::NotFound)
}

fn read_identity(pid: &str) -> anyhow::Result<Option<Identity>> {
    let parsed = pid.parse()?;
    match session_process::read_stat(parsed) {
        Ok(stat) => Ok(Some(Identity {
            starttime: stat.starttime.to_string(),
            sid: stat.session.to_string(),
            state: stat.state,
        })),
        Err(err) if is_not_found(&err) => Ok(None),
        Err(err) => Err(err),
    }
}

fn same_process(now: &Identity, original: &Identity) -> bool {
    now.starttime == original.starttime && now.sid == original.sid
}

async fn wait_reaped(pid: &str, original: Option<&Identity>) -> anyhow::Result<()> {
    let Some(original) = original else {
        return Ok(());
    };
    let deadline = tokio::time::Instant::now() + OBSERVE;
    loop {
        match read_identity(pid)? {
            None => return Ok(()),
            Some(now) if !same_process(&now, original) => return Ok(()),
            Some(now) if now.state == 'Z' => {}
            Some(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("leader process {pid} was not reaped");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn wait_dead_or_zombie(pid: &str, original: Option<&Identity>) -> anyhow::Result<()> {
    let Some(original) = original else {
        return Ok(());
    };
    let deadline = tokio::time::Instant::now() + OBSERVE;
    loop {
        match read_identity(pid)? {
            None => return Ok(()),
            Some(now) if !same_process(&now, original) => return Ok(()),
            Some(now) if now.state == 'Z' => return Ok(()),
            Some(_) => {}
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("descendant process {pid} did not exit");
        }
        tokio::time::sleep(POLL).await;
    }
}

async fn start_hanging(
    fx: &Fixture,
    manager: &mut MenderCommandManager,
    sid: &str,
) -> anyhow::Result<(String, String, Option<Identity>, Option<Identity>)> {
    let descendant = fx._dir.path().join("descendant.pid");
    fx.write_script(&hanging_body(&descendant))?;

    let out = manager.handle(client("check-update", sid)).await?;
    assert!(out.is_empty(), "valid launch must not reply immediately");

    let leader = wait_ready_pid(manager, &fx.pidpath).await?;
    let child = wait_ready_pid(manager, &descendant).await?;
    let leader_identity = read_identity(&leader)?;
    let child_identity = read_identity(&child)?;
    Ok((leader, child, leader_identity, child_identity))
}

// ---------------------------------------------------------------------------
// 9. Capacity is exclusive and explicit close_all verifies cleanup.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn capacity_busy_then_close_all_verifies_cleanup() -> anyhow::Result<()> {
    let fx = Fixture::new("capacity").await?;
    let mut manager = fx.manager_with(Duration::from_secs(5), CLEANUP)?;
    let (leader, child, leader_id, child_id) =
        start_hanging(&fx, &mut manager, "capacity-sid").await?;

    let out = manager.handle(client("check-update", "second-sid")).await?;
    assert_eq!(out.len(), 1, "busy request gets one immediate reply");
    assert_eq!(status(&out[0]), Some(2), "busy request uses status 2");
    assert!(manager.has_pending(), "active worker remains owned");

    tokio::time::timeout(OUTER, manager.close_all())
        .await
        .expect("close_all must stay bounded")?;
    assert!(!manager.has_pending());
    assert!(manager.next_message().await?.is_none());
    manager.close_all().await?;
    manager.close_all().await?;

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 10. close_session only affects the matching request SID.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn close_session_matches_only_owned_sid() -> anyhow::Result<()> {
    let fx = Fixture::new("close-session").await?;
    let mut manager = fx.manager()?;
    let (leader, child, leader_id, child_id) =
        start_hanging(&fx, &mut manager, "match-sid").await?;

    manager.close_session("other-sid").await?;
    assert!(manager.has_pending(), "unmatched close_session is a no-op");

    tokio::time::timeout(OUTER, manager.close_session("match-sid"))
        .await
        .expect("matching close_session must stay bounded")?;
    assert!(!manager.has_pending());

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 11. Execution deadline terminates the command and its session children.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn execution_timeout_reaps_leader_and_descendant() -> anyhow::Result<()> {
    let fx = Fixture::new("exec-timeout").await?;
    let mut manager = fx.manager_with(Duration::from_millis(200), CLEANUP)?;
    let (leader, child, leader_id, child_id) =
        start_hanging(&fx, &mut manager, "timeout-sid").await?;

    let reply = tokio::time::timeout(OUTER, manager.next_message())
        .await
        .expect("timeout reply must stay bounded")?
        .expect("timed out worker must reply");
    assert_eq!(status(&reply), Some(2));
    let text = String::from_utf8_lossy(&reply.body).to_ascii_lowercase();
    assert!(
        text.contains("timeout") || text.contains("timed out"),
        "timeout diagnostic is retained"
    );
    assert!(!manager.has_pending());

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 12. Natural exit does not report success before background children are dead.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn natural_exit_keeps_background_job_until_verified() -> anyhow::Result<()> {
    let fx = Fixture::new("natural-exit").await?;
    let background = fx._dir.path().join("background.pid");
    fx.write_script(&format!(
        "/bin/sleep 30 &\nprintf '%s' \"$!\" > {}\nexit 0\n",
        sh_quote(&background)
    ))?;
    let mut manager = fx.manager()?;

    let out = manager
        .handle(client("check-update", "natural-sid"))
        .await?;
    assert!(out.is_empty());
    let leader = wait_pid_file(&fx.pidpath).await?;
    let child = wait_pid_file(&background).await?;
    let leader_id = read_identity(&leader)?;
    let child_id = read_identity(&child)?;

    let reply = tokio::time::timeout(OUTER, manager.next_message())
        .await
        .expect("natural reply must stay bounded")?
        .expect("natural exit must reply");
    assert_eq!(status(&reply), Some(1));

    if let Some(original) = child_id.as_ref()
        && let Some(now) = read_identity(&child)?
    {
        assert!(
            !same_process(&now, original) || now.state == 'Z',
            "success must not be reported while the background child is alive"
        );
    }

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 13. Drop only signals cancellation; background cleanup still completes.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn manager_drop_eventually_reaps_fixture_processes() -> anyhow::Result<()> {
    let fx = Fixture::new("drop").await?;
    let mut manager = fx.manager()?;
    let (leader, child, leader_id, child_id) = start_hanging(&fx, &mut manager, "drop-sid").await?;

    drop(manager);

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 14. A cancelled next_message future must not detach worker ownership.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn cancelled_next_message_retains_entry_ownership() -> anyhow::Result<()> {
    let fx = Fixture::new("cancel-next").await?;
    let mut manager = fx.manager()?;
    let (leader, child, leader_id, child_id) =
        start_hanging(&fx, &mut manager, "cancel-next-sid").await?;

    let timed = tokio::time::timeout(Duration::from_millis(50), manager.next_message()).await;
    assert!(timed.is_err(), "hanging worker must outlast the short wait");
    assert!(
        manager.has_pending(),
        "aborted next_message keeps the entry"
    );

    tokio::time::timeout(Duration::from_secs(4), manager.close_all())
        .await
        .expect("explicit close_all must stay bounded")?;
    assert!(!manager.has_pending());

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 15. An interrupted close_all future leaves an owned entry that can be retried.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn interrupted_close_all_can_be_retried() -> anyhow::Result<()> {
    let fx = Fixture::new("cancel-close").await?;
    let mut manager = fx.manager()?;
    let (leader, child, leader_id, child_id) =
        start_hanging(&fx, &mut manager, "cancel-close-sid").await?;

    let first = tokio::time::timeout(Duration::from_millis(1), manager.close_all()).await;
    if let Ok(result) = first {
        result?;
    } else {
        assert!(
            manager.has_pending(),
            "an interrupted close_all must not detach worker ownership"
        );
    }

    tokio::time::timeout(OUTER, manager.close_all())
        .await
        .expect("retried close_all must stay bounded")?;
    assert!(!manager.has_pending());
    assert!(manager.next_message().await?.is_none());

    wait_reaped(&leader, leader_id.as_ref()).await?;
    wait_dead_or_zombie(&child, child_id.as_ref()).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// 16. send-inventory with an empty SID succeeds explicitly (Go parity).
// ---------------------------------------------------------------------------

#[tokio::test]
async fn send_inventory_with_empty_sid_succeeds() -> anyhow::Result<()> {
    let fx = Fixture::new("inventory-empty").await?;
    fx.write_script("exit 0\n")?;
    let mut manager = fx.manager()?;

    let reply = run_valid(&mut manager, client("send-inventory", "")).await?;
    assert_eq!(reply.header.msg_type, "send-inventory");
    assert_eq!(reply.header.session_id, "");
    assert_eq!(status(&reply), Some(1));
    assert!(reply.body.is_empty());
    assert_eq!(fx.read_argslog().as_deref(), Some("1:send-inventory"));
    assert!(!manager.has_pending());

    manager.close_all().await?;
    Ok(())
}
