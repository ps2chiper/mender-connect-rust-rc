#!/usr/bin/env python3
"""Independent native file-transfer limits activation harness.

TEST HARNESS ONLY. Runs under dbus-run-session, builds the loopback Go peer
from the local vendored assessment module, starts the test-only mock_auth and
runs the frozen candidate daemon against an owned work root with enabled byte
limits. Reports only fixed, redacted behavioural JSON.
"""

import argparse
import datetime
import hashlib
import json
import os
import platform
import pwd
import re
import secrets
import shutil
import signal
import subprocess
import time
from pathlib import Path

os.umask(0o077)

FIXTURE_TOKEN = "mender-trial-fixture-token-not-a-real-secret"
WS_PATH = "/api/devices/v1/deviceconnect/connect"
OVERALL_BUDGET = 50.0
REDACT_SENTINEL = "<redacted>"
DAEMON_LOG_LIMIT = 1024 * 1024

REPORT_BASE = Path(
    "/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/reports/mender-rust-signoff"
)
PEER_SRC = Path(__file__).resolve().parent / "native_limits_peer.go"
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


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Controller:
    def __init__(self, daemon: Path, expected_sha: str, report_dir: Path):
        self.daemon = daemon
        self.expected_sha = expected_sha
        self.report_dir = report_dir
        self.processes = []
        self.master_env = dict(os.environ)
        self.started = time.monotonic()
        self.run_dir = None
        self.work_dir = None
        self.peer_output = None
        self.report = {
            "scope": "native limits activation counter persistence (loopback WS, private session D-Bus)",
            "qemu_used": False,
            "release_sha256": expected_sha,
            "native_arch": platform.machine(),
            "started_utc": now_iso(),
            "checks": {},
            "cleanup": {},
            "passed": False,
            "errors": [],
        }

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

    def freeze_daemon(self):
        if not self.daemon.is_absolute() or not self.daemon.is_file():
            fail("--daemon must be an absolute existing file")
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
        build_dir = ASSESSMENT_MODULE / ("native_limits_peer_build_" + secrets.token_hex(4))
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
                log_path = self.run_dir / "go-build-error.log"
                write_private(log_path, (result.stdout or "") + (result.stderr or ""))
                self.report["build_error_log"] = str(log_path)
                self.report["errors"].append("go build failed")
                raise RuntimeError("go build failed")
            os.chmod(peer_bin, 0o500)
            return peer_bin
        finally:
            shutil.rmtree(build_dir, ignore_errors=True)

    def write_config(self, username):
        config = {
            "User": username,
            "ShellCommand": "/bin/bash",
            "ShellArguments": ["--noprofile", "--norc"],
            "Terminal": {"Disable": True},
            "Sessions": {"StopExpired": False},
            "FileTransfer": {"Disable": False},
            "PortForward": {"Disable": True},
            "MenderClient": {"Disable": True},
            "Limits": {
                "Enabled": True,
                "FileTransfer": {
                    "Chroot": str(self.work_dir),
                    "Umask": "0022",
                    "MaxFileSize": 1048576,
                    "Counters": {
                        "MaxBytesTxPerMinute": 1,
                        "MaxBytesRxPerMinute": 0,
                    },
                },
            },
        }
        cfg = self.run_dir / "connect.json"
        write_private(cfg, json.dumps(config, indent=2))
        return cfg

    def locate_mock_auth(self):
        targets = Path(self.daemon)
        candidates = [
            targets.parent / "examples" / "mock_auth",
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

    def wait_for_peer(self, peer_proc, auth_proc, daemon_proc):
        deadline = min(self.started + OVERALL_BUDGET, time.monotonic() + max(20, self.remaining()))
        while time.monotonic() < deadline:
            if peer_proc.poll() is not None:
                return
            if daemon_proc.poll() is not None:
                self.report["errors"].append("daemon exited before peer completed")
                raise RuntimeError("daemon exited before peer completed")
            if auth_proc.poll() is not None:
                self.report["errors"].append("auth exited before peer completed")
                raise RuntimeError("auth exited before peer completed")
            time.sleep(0.05)
        self.report["errors"].append("peer did not exit within budget")
        raise RuntimeError("peer did not exit within budget")

    def run(self):
        if not self.master_env.get("DBUS_SESSION_BUS_ADDRESS"):
            fail("Launch under dbus-run-session")
        user = pwd.getpwuid(os.getuid())
        if user.pw_uid == 0:
            fail("must run as a non-root user")
        self.report["effective_user"] = user.pw_name

        label = "native-limits-" + datetime.datetime.now(
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

        auth_env = dict(self.master_env)
        auth_env["MENDER_TRIAL_INITIAL_TOKEN"] = FIXTURE_TOKEN
        auth_proc = self.spawn("mock-auth", [str(mock_auth), str(endpoint_file)], auth_env)

        cfg = self.write_config(user.pw_name)
        missing_fallback = self.run_dir / "missing-fallback-owned.json"
        daemon_proc = self.spawn(
            "daemon",
            [
                str(frozen),
                "--debug",
                "daemon",
                "--test-session-bus",
                "--config",
                str(cfg),
                "--fallback-config",
                str(missing_fallback),
            ],
            dict(self.master_env),
        )

        self.wait_for_peer(peer_proc, auth_proc, daemon_proc)
        self.report["peer_exit_code"] = peer_proc.returncode
        self.check("peer_exit_success", peer_proc.returncode == 0)
        self.check("peer_result_present", bool(self.peer_output and self.peer_output.is_file()))
        self.check("auth_did_not_exit_unexpectedly", auth_proc.poll() is None)
        self.check("daemon_did_not_exit_unexpectedly", daemon_proc.poll() is None)
        self.merge_peer_result()

    def merge_peer_result(self):
        if not (self.peer_output and self.peer_output.is_file()):
            self.check("peer_reported_ok", False)
            return
        try:
            peer = json.loads(self.peer_output.read_text())
        except (OSError, json.JSONDecodeError):
            peer = {"ok": False}
        for key in ("ok", "endpoint_path", "qemu_used", "frame_counts", "durations_seconds"):
            if key in peer:
                self.report[key] = peer[key]
        for name, ok in (peer.get("checks") or {}).items():
            self.check(name, ok)
        self.check("peer_reported_ok", bool(peer.get("ok")))
        for err in peer.get("errors") or []:
            self.report["errors"].append(self.scrub(err))

    def _stat_starttime(self, pid):
        try:
            text = Path("/proc/%d/stat" % pid).read_text()
        except OSError:
            return None
        try:
            rparen = text.rindex(")")
            fields = text[rparen + 2 :].split()
            return int(fields[19])
        except (ValueError, IndexError):
            return None

    def _children_of(self, pid):
        result = []
        try:
            tids = list(Path("/proc/%d/task" % pid).iterdir())
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
        return [pid for pid, start in recorded.items() if self._stat_starttime(pid) == start]

    def _graceful_stop(self, proc):
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
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
            return False

    def terminate_all(self):
        descendants = self.snapshot_descendants()
        graceful = {}
        for name, proc in reversed(self.processes):
            graceful[name] = self._graceful_stop(proc)
            self.report["cleanup"].setdefault("exit_codes", {})[name] = proc.returncode
        self.report["cleanup"]["graceful_sigterm"] = graceful
        deadline = time.monotonic() + 5
        while self._living_descendants(descendants) and time.monotonic() < deadline:
            time.sleep(0.1)
        for pid in self._living_descendants(descendants):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        self.report["cleanup"]["owned_children_reaped"] = not self._living_descendants(descendants)
        self.report["cleanup"]["parent_processes_reaped"] = all(
            proc.poll() is not None for _, proc in self.processes
        )

    def _daemon_log_failure(self, readable=False):
        self.check("daemon_log_bounded_read", readable)
        self.check("daemon_log_no_fixture_token", False)
        self.check("daemon_log_fixed_redacted_format", False)
        self.check("daemon_connected_at_least_2", False)
        self.check("daemon_disconnected_at_least_2", False)
        self.check("daemon_connecting_before_connected", False)

    def inspect_daemon_log(self):
        if not self.run_dir:
            self._daemon_log_failure(False)
            return
        log_path = self.run_dir / "daemon.log"
        try:
            size = log_path.stat().st_size
        except OSError:
            self._daemon_log_failure(False)
            return
        if not log_path.is_file() or size > DAEMON_LOG_LIMIT:
            self._daemon_log_failure(False)
            return
        try:
            with log_path.open('rb') as stream:
                raw = stream.read(DAEMON_LOG_LIMIT + 1)
        except OSError:
            self._daemon_log_failure(False)
            return
        if len(raw) > DAEMON_LOG_LIMIT:
            self._daemon_log_failure(False)
            return
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            self._daemon_log_failure(False)
            return
        self.check("daemon_log_bounded_read", True)
        self.check("daemon_log_no_fixture_token", FIXTURE_TOKEN not in text)
        event_re = re.compile(r"\bevent=(connecting|connected|disconnected)\b")
        fixed_lines = {
            "level=DEBUG event=connecting msg=connecting to server",
            "level=DEBUG event=connected msg=connection established",
            "level=DEBUG event=disconnected msg=connection closed",
        }
        events = []
        fixed_ok = True
        for line in text.splitlines():
            matches = event_re.findall(line)
            if not matches:
                continue
            if FIXTURE_TOKEN in line or line not in fixed_lines:
                fixed_ok = False
            events.extend(matches)
        self.check("daemon_log_fixed_redacted_format", fixed_ok and bool(events))
        connected = events.count("connected")
        disconnected = events.count("disconnected")
        self.report["daemon_event_counts"] = {
            "connected": connected,
            "disconnected": disconnected,
        }
        self.check("daemon_connected_at_least_2", connected >= 2)
        self.check("daemon_disconnected_at_least_2", disconnected >= 2)
        pending = False
        ordered = True
        for event in events:
            if event == "connecting":
                pending = True
            elif event == "connected":
                if not pending:
                    ordered = False
                pending = False
            elif event == "disconnected":
                pending = False
        self.check("daemon_connecting_before_connected", ordered and connected >= 1)

    def scrub(self, value):
        if isinstance(value, str):
            return value.replace(FIXTURE_TOKEN, REDACT_SENTINEL)
        if isinstance(value, dict):
            return {self.scrub(k): self.scrub(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.scrub(v) for v in value]
        return value

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
        label = self.run_dir.name if self.run_dir else "native-limits-unknown"
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
    parser = argparse.ArgumentParser(description="Native limits activation harness")
    parser.add_argument("--daemon", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--report-dir", required=True)
    args = parser.parse_args()

    expected = args.expected_sha256.strip().lower()
    if len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        fail("--expected-sha256 must be a 64-char lowercase hex digest")

    controller = Controller(Path(args.daemon), expected, validate_report_dir(args.report_dir))
    try:
        controller.run()
    except SystemExit:
        raise
    except Exception as error:  # noqa: BLE001 - fixed diagnostic only
        controller.report["errors"].append(type(error).__name__)
        controller.report["passed"] = False
    finally:
        controller.terminate_all()
        controller.inspect_daemon_log()
        passed = controller.export() if controller.run_dir else False
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
