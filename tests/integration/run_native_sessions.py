#!/usr/bin/env python3
"""Independent native mender-connect session harness controller.

This controller is TEST HARNESS ONLY. It runs under ``dbus-run-session`` and
launches, in order:

* an independent Go protocol peer (loopback WebSocket server), built from the
  local upstream assessment module + vendor tree with no network access;
* the compiled test-only ``mock_auth`` example, providing the Authentication1
  interface on the private session D-Bus with a constant fixture token and the
  peer's loopback endpoint;
* the frozen candidate daemon (a byte-identical copy of the release binary)
  pointed at an owned configuration and a deliberately missing fallback path.

The harness never exports tokens, headers, payloads or environment dumps. Only
redacted, behavioural JSON is written under an explicit ``--report-dir`` that
must live beneath the sign-off reports mount path.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import pwd
import secrets
import shutil
import signal
import subprocess
import time
from pathlib import Path

os.umask(0o077)

# Constant dummy fixture token. This is NOT a real credential.
FIXTURE_TOKEN = "mender-trial-fixture-token-not-a-real-secret"
WS_PATH = "/api/devices/v1/deviceconnect/connect"
OVERALL_BUDGET = 100.0
REDACT_SENTINEL = "<redacted>"

# Absolute Windows mount location that the exported report MUST live under.
REPORT_BASE = Path(
    "/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/reports/mender-rust-signoff"
)

PEER_SRC = Path(__file__).resolve().parent / "native_sessions_peer.go"
ASSESSMENT_MODULE = Path(
    os.environ.get(
        "MENDER_ASSESSMENT_MODULE",
        str(Path.home() / ".local/share/duo-aider/mender-rust-assessment/mender-connect"),
    )
)


def fail(message):
    raise SystemExit(message)


def write_private(path: Path, text: str):
    path.write_text(text)
    os.chmod(path, 0o600)


def write_private_bytes(path: Path, data: bytes):
    path.write_bytes(data)
    os.chmod(path, 0o600)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Controller:
    def __init__(self, daemon: Path, expected_sha: str, report_dir: Path):
        self.daemon = daemon
        self.expected_sha = expected_sha
        self.report_dir = report_dir
        self.processes = []  # list of (name, Popen)
        self.master_env = dict(os.environ)
        self.started = time.monotonic()
        self.run_dir = None
        self.work_dir = None
        self.peer_output = None
        self.report = {
            "scope": "native protocol peer sessions (loopback WS, private session D-Bus)",
            "qemu_used": False,
            "release_sha256": expected_sha,
            "native_arch": platform.machine(),
            "started_utc": now_iso(),
            "checks": {},
            "cleanup": {},
            "passed": False,
            "errors": [],
        }

    # -- setup helpers -----------------------------------------------------
    def remaining(self):
        return OVERALL_BUDGET - (time.monotonic() - self.started)

    def check(self, name, value):
        self.report["checks"][name] = bool(value)
        if not value:
            self.report["passed"] = False

    def until(self, predicate, seconds, message):
        deadline = min(self.started + OVERALL_BUDGET, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.report["errors"].append(message)
        raise RuntimeError(message)

    def wait_for_peer(self, peer_proc, auth_proc, daemon_proc):
        budget = max(30, min(95, self.remaining()))
        deadline = min(self.started + OVERALL_BUDGET, time.monotonic() + budget)
        while time.monotonic() < deadline:
            if peer_proc.poll() is not None:
                return
            if daemon_proc.poll() is not None:
                self.report["errors"].append(
                    "daemon exited before peer scenarios completed"
                )
                raise RuntimeError("daemon exited before peer scenarios completed")
            if auth_proc.poll() is not None:
                self.report["errors"].append(
                    "auth exited before peer scenarios completed"
                )
                raise RuntimeError("auth exited before peer scenarios completed")
            time.sleep(0.05)
        self.report["errors"].append("peer did not exit within budget")
        raise RuntimeError("peer did not exit within budget")

    def spawn(self, name, argv, env):
        log_path = self.run_dir / (name + ".log")
        stream = open(log_path, "w")
        os.chmod(log_path, 0o600)
        proc = subprocess.Popen(
            argv,
            env=env,
            stdout=stream,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        stream.close()
        self.processes.append((name, proc))
        return proc

    def proc_by_name(self, name):
        for candidate_name, proc in self.processes:
            if candidate_name == name:
                return proc
        return None

    def freeze_daemon(self):
        if not self.daemon.is_absolute():
            fail("--daemon must be an absolute path")
        if not self.daemon.is_file():
            fail("--daemon does not exist")
        digest = hashlib.sha256(self.daemon.read_bytes()).hexdigest()
        if digest != self.expected_sha:
            fail("candidate binary does not match --expected-sha256")
        frozen = self.run_dir / "daemon"
        shutil.copyfile(self.daemon, frozen)
        os.chmod(frozen, 0o500)
        frozen_digest = hashlib.sha256(frozen.read_bytes()).hexdigest()
        if frozen_digest != self.expected_sha:
            fail("frozen copy digest mismatch")
        self.report["frozen_sha256"] = frozen_digest
        return frozen

    def build_peer(self):
        if not PEER_SRC.is_file():
            fail("peer source missing")
        build_dir = ASSESSMENT_MODULE / ("native_sessions_peer_build_" + secrets.token_hex(4))
        build_dir.mkdir(mode=0o700)
        try:
            shutil.copyfile(PEER_SRC, build_dir / "main.go")
            os.chmod(build_dir / "main.go", 0o600)
            peer_bin = self.run_dir / "peer"
            env = dict(self.master_env)
            env.update(
                {
                    "GOFLAGS": "-mod=vendor",
                    "GOPROXY": "off",
                    "GOSUMDB": "off",
                    "GOTOOLCHAIN": "local",
                    "CGO_ENABLED": "0",
                }
            )
            result = subprocess.run(
                ["go", "build", "-o", str(peer_bin), "./" + build_dir.name],
                cwd=str(ASSESSMENT_MODULE),
                env=env,
                capture_output=True,
                text=True,
                timeout=min(90, max(10, self.remaining())),
            )
            if result.returncode != 0:
                # Preserve only the private compiler diagnostic for review; it
                # never contains generated secrets.
                log_path = self.run_dir / "go-build-error.log"
                write_private(
                    log_path, (result.stdout or "") + (result.stderr or "")
                )
                self.report["build_error_log"] = str(log_path)
                self.report["errors"].append("go build failed")
                raise RuntimeError("go build failed")
            os.chmod(peer_bin, 0o500)
            return peer_bin
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def write_config(self, username):
        # Exact native configuration schema (top-level PascalCase keys).
        config = {
            "User": username,
            "ShellCommand": "/bin/bash",
            "ShellArguments": ["--noprofile", "--norc"],
            "Terminal": {"Width": 80, "Height": 24},
            "Sessions": {"StopExpired": False},
            "FileTransfer": {"Disable": False},
            "PortForward": {"Disable": False},
            "MenderClient": {"Disable": True},
        }
        cfg = self.run_dir / "connect.json"
        write_private(cfg, json.dumps(config, indent=2))
        return cfg

    # -- main flow ---------------------------------------------------------
    def run(self):
        if not self.master_env.get("DBUS_SESSION_BUS_ADDRESS"):
            fail("Launch under dbus-run-session")
        user = pwd.getpwuid(os.getuid())
        if user.pw_uid == 0:
            fail("must run as a non-root user")
        self.report["effective_user"] = user.pw_name

        label = "native-sessions-" + datetime.datetime.now(
            datetime.timezone.utc
        ).strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
        base = Path.home() / ".local/share/duo-aider/mender-rust-trial"
        base.mkdir(parents=True, exist_ok=True)
        self.run_dir = base / label
        self.run_dir.mkdir(mode=0o700)
        os.chmod(self.run_dir, 0o700)
        self.work_dir = self.run_dir / "work"
        self.work_dir.mkdir(mode=0o700)
        os.chmod(self.work_dir, 0o700)
        self.report["private_state"] = str(self.run_dir)

        frozen = self.freeze_daemon()
        mock_auth = self.locate_mock_auth()
        peer_bin = self.build_peer()

        endpoint_file = self.run_dir / "ws-endpoint"
        self.peer_output = self.run_dir / "peer-result.json"

        # 1) start the independent peer; it writes the loopback endpoint base.
        peer_proc = self.spawn(
            "peer",
            [
                str(peer_bin),
                "--ws-path",
                WS_PATH,
                "--token",
                FIXTURE_TOKEN,
                "--workdir",
                str(self.work_dir),
                "--endpoint-file",
                str(endpoint_file),
                "--output",
                str(self.peer_output),
            ],
            self.master_env,
        )
        self.until(lambda: endpoint_file.is_file(), 20, "peer endpoint not published")

        # 2) start the test-only mock_auth with the fixture token + endpoint.
        auth_env = dict(self.master_env)
        auth_env["MENDER_TRIAL_INITIAL_TOKEN"] = FIXTURE_TOKEN
        auth_proc = self.spawn("mock-auth", [str(mock_auth), str(endpoint_file)], auth_env)

        # 3) start the frozen daemon against owned config + missing fallback.
        cfg = self.write_config(user.pw_name)
        missing_fallback = self.run_dir / "missing-fallback-owned.json"
        daemon_env = dict(self.master_env)
        daemon_proc = self.spawn(
            "daemon",
            [
                str(frozen),
                "daemon",
                "--test-session-bus",
                "--config",
                str(cfg),
                "--fallback-config",
                str(missing_fallback),
            ],
            daemon_env,
        )

        # 4) Wait for the peer to complete its bounded scenarios. Result-file
        # existence alone is NOT success: the peer process must exit cleanly.
        # Abort immediately if the daemon or auth mock exits while the peer is
        # still running, rather than sleeping out the whole budget.
        self.wait_for_peer(peer_proc, auth_proc, daemon_proc)
        self.report["peer_exit_code"] = peer_proc.returncode
        self.check("peer_exit_success", peer_proc.returncode == 0)
        self.check("peer_result_present", bool(self.peer_output and self.peer_output.is_file()))

        # 5) The auth mock and daemon must not have exited unexpectedly.
        auth_alive = auth_proc.poll() is None
        daemon_alive = daemon_proc.poll() is None
        self.check("auth_did_not_exit_unexpectedly", auth_alive)
        self.check("daemon_did_not_exit_unexpectedly", daemon_alive)

        self.merge_peer_result()

    def locate_mock_auth(self):
        # Compiled test example is named with an underscore: ``mock_auth``.
        targets = Path(self.daemon)
        candidates = [
            targets.parent / "examples" / "mock_auth",  # target/release/examples
            targets.parent.parent / "examples" / "mock_auth",
            targets.parent.parent / "debug" / "examples" / "mock_auth",
            targets.parent.parent / "release" / "examples" / "mock_auth",
        ]
        seen = set()
        for candidate in candidates:
            if candidate in seen:
                continue
            seen.add(candidate)
            if candidate.is_file() and os.access(candidate, os.X_OK):
                self.report["mock_auth_path"] = str(candidate)
                return candidate
        self.report["errors"].append("compiled mock_auth example not found")
        raise RuntimeError("compiled mock_auth example not found")

    # -- owned-child discovery (avoid reused-PID hazards) -----------------
    def _stat_starttime(self, pid):
        try:
            text = Path("/proc/%d/stat" % pid).read_text()
        except OSError:
            return None
        try:
            rparen = text.rindex(")")
            fields = text[rparen + 2 :].split()
            # Field 22 (1-based) is starttime; after the "(comm)" the next token
            # is field 3 (state), so starttime is index 19.
            return int(fields[19])
        except (ValueError, IndexError):
            return None

    def _children_of(self, pid):
        result = []
        task_dir = Path("/proc/%d/task" % pid)
        try:
            tids = list(task_dir.iterdir())
        except OSError:
            return result
        for tid in tids:
            try:
                text = (tid / "children").read_text()
            except OSError:
                continue
            for token in text.split():
                try:
                    result.append(int(token))
                except ValueError:
                    pass
        return result

    def snapshot_descendants(self):
        recorded = {}
        stack = [proc.pid for _, proc in self.processes if proc.poll() is None]
        seen = set()
        while stack:
            pid = stack.pop()
            if pid in seen:
                continue
            seen.add(pid)
            for child in self._children_of(pid):
                start = self._stat_starttime(child)
                if start is not None:
                    recorded[child] = start
                stack.append(child)
        return recorded

    def _living_descendants(self, recorded):
        alive = []
        for pid, start in recorded.items():
            if self._stat_starttime(pid) == start:
                alive.append(pid)
        return alive

    # -- teardown + report -------------------------------------------------
    def _graceful_stop(self, name, proc):
        if proc.poll() is not None:
            return False
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            return False
        try:
            proc.wait(timeout=8)
            return proc.returncode == 0
        except subprocess.TimeoutExpired:
            if proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.report["cleanup"][name + "_killed"] = False
            return False

    def _terminate_pid(self, pid, start):
        if self._stat_starttime(pid) != start:
            return
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if self._stat_starttime(pid) != start:
                return
            time.sleep(0.05)
        if self._stat_starttime(pid) == start:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                return

    def terminate_all(self):
        # Snapshot owned descendants BEFORE stopping so we can verify they are
        # reaped and never confuse them with a reused PID.
        descendants = self.snapshot_descendants()
        graceful = {}
        for name, proc in reversed(self.processes):
            graceful[name] = self._graceful_stop(name, proc)
            self.report["cleanup"].setdefault("exit_codes", {})[name] = proc.returncode
        self.report["cleanup"]["graceful_sigterm"] = graceful

        # Give the daemon a bounded window to reap its own shell children.
        deadline = time.monotonic() + 5
        while self._living_descendants(descendants) and time.monotonic() < deadline:
            time.sleep(0.1)
        for pid in self._living_descendants(descendants):
            self._terminate_pid(pid, descendants[pid])
        remaining = self._living_descendants(descendants)

        self.report["cleanup"]["owned_children_reaped"] = not remaining
        self.report["cleanup"]["parent_processes_reaped"] = all(
            proc.poll() is not None for _, proc in self.processes
        )

    def scrub(self, value):
        if isinstance(value, str):
            return value.replace(FIXTURE_TOKEN, REDACT_SENTINEL)
        if isinstance(value, dict):
            return {self.scrub(k): self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value

    def merge_peer_result(self):
        peer_output = self.peer_output
        if peer_output and peer_output.is_file():
            try:
                peer = json.loads(peer_output.read_text())
            except (OSError, json.JSONDecodeError):
                peer = {"ok": False}
            for key in (
                "ok",
                "endpoint_path",
                "native_arch",
                "qemu_used",
                "frame_counts",
                "durations_seconds",
                "sessions",
                "control_version",
                "control_protocols",
            ):
                if key in peer:
                    self.report[key] = peer[key]
            for name, ok in (peer.get("checks") or {}).items():
                self.check(name, ok)
            self.check("peer_reported_ok", bool(peer.get("ok")))
            for err in peer.get("errors") or []:
                self.report["errors"].append(self.scrub(err))
        else:
            self.check("peer_reported_ok", False)

    def export(self):
        self.report["elapsed_seconds"] = round(time.monotonic() - self.started, 3)
        self.report["finished_utc"] = now_iso()
        checks_ok = bool(self.report["checks"]) and all(self.report["checks"].values())
        cleanup_ok = bool(
            self.report["cleanup"].get("owned_children_reaped", False)
            and self.report["cleanup"].get("parent_processes_reaped", False)
            and self.report["cleanup"].get("graceful_sigterm", {}).get("daemon", False)
            and self.report["cleanup"].get("exit_codes", {}).get("daemon") == 0
        )
        self.report["passed"] = checks_ok and not self.report["errors"] and cleanup_ok
        cleaned = self.scrub(self.report)
        cleaned["passed"] = self.report["passed"]
        self.report_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.report_dir, 0o700)
        label = self.run_dir.name if self.run_dir else "native-sessions-unknown"
        out = self.report_dir / (label + ".json")
        write_private(out, json.dumps(cleaned, indent=2))
        print(json.dumps(cleaned, indent=2))
        return self.report["passed"]


def validate_report_dir(value):
    report_dir = Path(value)
    if not report_dir.is_absolute():
        fail("--report-dir must be an absolute path")
    report_root = os.path.realpath(str(REPORT_BASE))
    target = os.path.realpath(str(report_dir))
    if target != report_root and not target.startswith(report_root + os.sep):
        fail("--report-dir must be beneath " + str(REPORT_BASE))
    return report_dir


def main():
    parser = argparse.ArgumentParser(description="Native mender-connect session harness")
    parser.add_argument("--daemon", required=True, help="absolute path to the release daemon")
    parser.add_argument("--expected-sha256", required=True, help="expected release binary digest")
    parser.add_argument(
        "--report-dir", required=True, help="absolute export dir under the sign-off mount path"
    )
    args = parser.parse_args()

    expected = args.expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        fail("--expected-sha256 must be a 64-char lowercase hex digest")

    report_dir = validate_report_dir(args.report_dir)
    controller = Controller(Path(args.daemon), expected, report_dir)
    try:
        controller.run()
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - fixed diagnostic only
        controller.report["errors"].append(type(error).__name__)
        controller.report["passed"] = False
    finally:
        controller.terminate_all()
        passed = controller.export() if controller.run_dir else False
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
