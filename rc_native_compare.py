#!/usr/bin/env python3
"""Bounded native side-by-side harness for the Rust RC and upstream Go daemon.

Runs one implementation per invocation against the same Go protocol peer and
mock Authentication1 service. TEST HARNESS ONLY; no real server or credentials.
"""
import argparse
import hashlib
import json
import os
import platform
import pwd
import secrets
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path("/home/jason/releases/mender-connect-rust-0.1.0-rc.1")
PEER_SRC = ROOT / "tests/integration/native_sessions_peer.go"
ASSESS = Path.home() / ".local/share/duo-aider/mender-rust-assessment/mender-connect"
MOCK_AUTH = ROOT / "target/debug/examples/mock_auth"
TOKEN = "mender-trial-fixture-token-not-a-real-secret"
WS_PATH = "/api/devices/v1/deviceconnect/connect"
BUDGET = 125.0


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def build_peer(run_dir):
    build_dir = ASSESS / ("rc_native_peer_" + secrets.token_hex(4))
    build_dir.mkdir(mode=0o700)
    try:
        shutil.copyfile(PEER_SRC, build_dir / "main.go")
        peer_bin = run_dir / "peer"
        env = dict(os.environ)
        env.update({
            "GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOSUMDB": "off",
            "GOTOOLCHAIN": "local", "CGO_ENABLED": "0",
        })
        subprocess.run(
            ["go", "build", "-o", str(peer_bin), "./" + build_dir.name],
            cwd=str(ASSESS), env=env, check=True, timeout=90,
            capture_output=True, text=True,
        )
        os.chmod(peer_bin, 0o500)
        return peer_bin
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


def stop(proc, name, results):
    if proc is None or proc.poll() is not None:
        results[name] = None if proc is None else proc.returncode
        return
    try:
        os.killpg(proc.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
    results[name] = proc.returncode


def main():
    global PEER_SRC
    ap = argparse.ArgumentParser()
    ap.add_argument("--implementation", choices=["rust", "go"], required=True)
    ap.add_argument("--binary", required=True)
    ap.add_argument("--expected-sha256", required=True)
    ap.add_argument("--report", required=True)
    ap.add_argument("--peer-source", default=str(PEER_SRC))
    ap.add_argument("--config", required=True)
    ap.add_argument("--limits", action="store_true")
    args = ap.parse_args()
    PEER_SRC = Path(args.peer_source)

    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        raise SystemExit("launch under dbus-run-session")
    if os.geteuid() == 0:
        raise SystemExit("must run as non-root")
    binary = Path(args.binary).resolve()
    if not binary.is_file():
        raise SystemExit("binary not found")
    expected = args.expected_sha256.strip().lower()
    if len(expected) != 64 or sha(binary) != expected:
        raise SystemExit("binary SHA-256 mismatch")
    if not MOCK_AUTH.is_file():
        raise SystemExit("mock_auth example missing")

    started = time.monotonic()
    user = pwd.getpwuid(os.getuid()).pw_name
    label = "rc-native-" + args.implementation + "-" + time.strftime("%Y%m%d%H%M%S") + "-" + secrets.token_hex(3)
    run_dir = Path.home() / ".local/share/duo-aider/mender-rust-trial" / label
    run_dir.mkdir(mode=0o700)
    work = run_dir / "work"
    work.mkdir(mode=0o700)

    cfg = run_dir / "connect.json"
    config = {
        "User": user,
        "ShellCommand": "/bin/bash",
        "ShellArguments": ["--noprofile", "--norc"],
        "Terminal": {"Width": 80, "Height": 24},
        "Sessions": {"StopExpired": False},
        "FileTransfer": {"Disable": False},
        "PortForward": {"Disable": False},
        "MenderClient": {"Disable": True},
    }
    if args.limits:
        config["Limits"] = {
            "Enabled": True,
            "FileTransfer": {
                "Chroot": str(work),
                "AllowOverwrite": True,
                "Umask": "0077",
                "MaxFileSize": 1048576,
                "Counters": {
                    "MaxBytesTxPerMinute": 10485760,
                    "MaxBytesRxPerMinute": 10485760,
                },
            },
        }
    cfg.write_text(json.dumps(config, indent=2))
    os.chmod(cfg, 0o600)
    missing = run_dir / "missing-fallback.json"
    endpoint = run_dir / "ws-endpoint"
    peer_result = run_dir / "peer-result.json"
    peer_bin = build_peer(run_dir)

    processes = []
    results = {}
    report = {
        "scope": "functional side-by-side native protocol peer, loopback WS, private session D-Bus",
        "implementation": args.implementation,
        "binary": str(binary),
        "binary_sha256": expected,
        "peer_source_sha256": sha(PEER_SRC),
        "qemu_used": False,
        "native_arch": platform.machine(),
        "started_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "checks": {},
        "errors": [],
        "passed": False,
    }

    peer = auth = daemon = None
    try:
        peer = subprocess.Popen(
            [str(peer_bin), "--ws-path", WS_PATH, "--token", TOKEN,
             "--workdir", str(work), "--endpoint-file", str(endpoint),
             "--output", str(peer_result)],
            env=dict(os.environ), stdout=open(run_dir / "peer.log", "w"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        processes.append(("peer", peer))
        deadline = time.monotonic() + 20
        while not endpoint.is_file():
            if peer.poll() is not None:
                raise RuntimeError("peer exited before endpoint publication")
            if time.monotonic() > deadline:
                raise RuntimeError("peer endpoint publication timed out")
            time.sleep(0.05)

        auth_env = dict(os.environ)
        auth_env["MENDER_TRIAL_INITIAL_TOKEN"] = TOKEN
        auth = subprocess.Popen(
            [str(MOCK_AUTH), str(endpoint)],
            env=auth_env, stdout=open(run_dir / "auth.log", "w"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        processes.append(("auth", auth))

        daemon_env = dict(os.environ)
        if args.implementation == "rust":
            daemon_cmd = [str(binary), "daemon", "--test-session-bus",
                          "--config", str(cfg), "--fallback-config", str(missing)]
        else:
            daemon_env["DBUS_SYSTEM_BUS_ADDRESS"] = os.environ["DBUS_SESSION_BUS_ADDRESS"]
            daemon_cmd = [str(binary), "--config", str(cfg),
                          "--fallback-config", str(missing), "daemon"]
        daemon = subprocess.Popen(
            daemon_cmd, env=daemon_env,
            stdout=open(run_dir / "daemon.log", "w"),
            stderr=subprocess.STDOUT, start_new_session=True,
        )
        processes.append(("daemon", daemon))

        deadline = time.monotonic() + 115
        while peer.poll() is None:
            if daemon.poll() is not None:
                raise RuntimeError("daemon exited before peer completed")
            if auth.poll() is not None:
                raise RuntimeError("auth exited before peer completed")
            if time.monotonic() > deadline:
                raise RuntimeError("peer did not finish within 115s")
            time.sleep(0.05)

        report["peer_exit"] = peer.returncode
        report["checks"]["peer_exit_success"] = peer.returncode == 0
        if peer_result.is_file():
            peer_data = json.loads(peer_result.read_text())
            report["peer_result"] = peer_data
            report["checks"].update(peer_data.get("checks") or {})
            report["checks"]["peer_reported_ok"] = bool(peer_data.get("ok"))
            report["errors"].extend(peer_data.get("errors") or [])
        else:
            report["checks"]["peer_result_present"] = False
    except Exception as exc:
        report["errors"].append(type(exc).__name__ + ": " + str(exc))
    finally:
        stop(daemon, "daemon_exit", results)
        stop(auth, "auth_exit", results)
        stop(peer, "peer_exit_final", results)

    report["exit_codes"] = results
    report["elapsed_seconds"] = round(time.monotonic() - started, 2)
    checks_ok = bool(report["checks"]) and all(report["checks"].values())
    cleanup_ok = results.get("daemon_exit") in (0, -15) and results.get("auth_exit") in (0, -15)
    report["passed"] = checks_ok and not report["errors"] and cleanup_ok
    report["private_state"] = str(run_dir)
    report["run_dir"] = str(run_dir)
    Path(args.report).write_text(json.dumps(report, indent=2))
    print(json.dumps({k: report[k] for k in (
        "implementation", "passed", "checks", "errors", "exit_codes",
        "peer_exit", "elapsed_seconds", "private_state")}, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())