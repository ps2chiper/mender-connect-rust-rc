#!/usr/bin/env python3
"""Prepare, but never launch, the native x86_64 mixed soak assets."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

ROOT = Path.home() / ".local/share/duo-aider/mender-rust-trial"
SOURCE_ASSETS = ROOT / "soak-fourhour-udp-guard-release-resources"
CANDIDATE = Path(
    "/home/jason/projects/mender-connect-rust-trial/target/release/mender-connect-rust"
)
LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
REQUIRED_SOURCE = (
    "run-calibrated-soak.py",
    "monitor-highwater-calibrated.py",
    "peer",
    "mock-auth",
    "peer-source",
)

LAUNCH_SOURCE = '''#!/usr/bin/env python3
"""Pin this process tree to the first permitted CPU and exec the prepared soak."""
import argparse
import hashlib
import json
import os
import platform
import re
import time
from pathlib import Path

LABEL_RE = re.compile(r"^[A-Za-z0-9-]{1,40}$")
OVERRIDE_ENV = (
    "SOAK_FORCE_SHELL_INTERLEAVE",
    "SOAK_DIAGNOSTIC",
    "SOAK_DIAGNOSTICS",
    "SOAK_DISABLE_DEMUX",
    "SOAK_DEMUX_DISABLED",
    "MENDER_CONNECT_DISABLE_DEMUX",
    "SOAK_DISABLE_ASSERTIONS",
    "SOAK_RELAX",
)
ASSETS = Path(__file__).resolve().parent
RUNNER = ASSETS / "run-calibrated-soak.py"
MONITOR = ASSETS / "monitor-highwater-calibrated.py"
MANIFEST = ASSETS / "manifest.json"
RUNTIME_REPORT = ASSETS / "launch-runtime.json"


def fail(message):
    raise SystemExit("launch_x64_mixed_soak: " + message)


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path):
    if path.is_dir():
        digest = hashlib.sha256()
        for item in sorted(path.rglob("*")):
            relative = item.relative_to(path).as_posix().encode()
            if item.is_symlink():
                digest.update(b"L\\0" + relative + b"\\0" + os.readlink(item).encode() + b"\\0")
            elif item.is_file():
                digest.update(b"F\\0" + relative + b"\\0" + sha256_file(item).encode() + b"\\0")
            elif item.is_dir():
                digest.update(b"D\\0" + relative + b"\\0")
        return digest.hexdigest()
    return sha256_file(path)


def load_and_verify_manifest(label, seconds):
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail("manifest unavailable: " + str(error))
    if manifest.get("label") != label:
        fail("manifest label mismatch")
    if manifest.get("seconds") != seconds:
        fail("manifest duration mismatch")
    if manifest.get("qemu") is not False:
        fail("manifest does not declare qemu=false")
    if manifest.get("architecture") != "x86_64":
        fail("manifest architecture is not x86_64")
    expected_hashes = manifest.get("sha256")
    if not isinstance(expected_hashes, dict) or not expected_hashes:
        fail("manifest has no SHA256 inventory")
    for name, expected in expected_hashes.items():
        path = ASSETS / name
        if not path.exists():
            fail("manifest asset missing: " + name)
        actual = sha256_path(path)
        if actual != expected:
            fail("manifest hash mismatch: " + name)
    return manifest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True)
    parser.add_argument("--seconds", required=True, type=int)
    arguments = parser.parse_args()
    if not LABEL_RE.fullmatch(arguments.label):
        fail("label must be 1..40 simple alnum/hyphen characters")
    if not 30 <= arguments.seconds <= 3600:
        fail("seconds must be 30..3600")
    if platform.system() != "Linux":
        fail("Linux is required")
    if platform.machine() != "x86_64":
        fail("x86_64 is required")
    load_and_verify_manifest(arguments.label, arguments.seconds)
    permitted = sorted(os.sched_getaffinity(0))
    if not permitted:
        fail("no permitted CPU is available")
    selected = permitted[0]
    os.sched_setaffinity(0, {selected})
    actual = sorted(os.sched_getaffinity(0))
    if actual != [selected]:
        fail("affinity pin did not apply exactly")
    environment = dict(os.environ)
    removed = sorted(name for name in OVERRIDE_ENV if name in environment)
    for name in OVERRIDE_ENV:
        environment.pop(name, None)
    hard_stop = time.time() + arguments.seconds + 120
    environment["SOAK_ORIGINAL_AFFINITY"] = json.dumps(permitted)
    environment["SOAK_SELECTED_CPU"] = str(selected)
    environment["SOAK_HARD_STOP_UNIX"] = f"{hard_stop:.6f}"
    command = [
        "dbus-run-session",
        "--",
        "python3",
        str(RUNNER),
        arguments.label,
        "--seconds",
        str(arguments.seconds),
        "--tls",
    ]
    report = {
        "label": arguments.label,
        "seconds": arguments.seconds,
        "architecture": platform.machine(),
        "qemu": False,
        "permitted_before_pin": permitted,
        "selected_cpu": selected,
        "controller_actual": actual,
        "hard_stop_unix": hard_stop,
        "removed_override_env": removed,
        "runner": str(RUNNER),
        "monitor": str(MONITOR),
        "manifest": str(MANIFEST),
        "exec_argv": command,
    }
    temporary = RUNTIME_REPORT.with_name(RUNTIME_REPORT.name + ".tmp")
    temporary.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    temporary.replace(RUNTIME_REPORT)
    os.execvpe("dbus-run-session", command, environment)


if __name__ == "__main__":
    main()
'''


def fail(message: str) -> "None":
    raise SystemExit("prepare_x64_mixed_soak: " + message)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_path(path: Path) -> str:
    if path.is_dir():
        digest = hashlib.sha256()
        for item in sorted(path.rglob("*")):
            relative = item.relative_to(path).as_posix().encode()
            if item.is_symlink():
                digest.update(b"L\0" + relative + b"\0" + os.readlink(item).encode() + b"\0")
            elif item.is_file():
                digest.update(b"F\0" + relative + b"\0" + sha256_file(item).encode() + b"\0")
            elif item.is_dir():
                digest.update(b"D\0" + relative + b"\0")
        return digest.hexdigest()
    return sha256_file(path)


def is_x86_64_elf(path: Path) -> bool:
    with path.open("rb") as stream:
        header = stream.read(20)
    if len(header) != 20 or header[:4] != b"\x7fELF":
        return False
    return header[4] == 2 and header[5] == 1 and int.from_bytes(header[18:20], "little") == 62


def adapt_exact(text: str, old: str, new: str, expected: int, description: str) -> str:
    found = text.count(old)
    if found != expected:
        fail(
            "adaptation mismatch for "
            + description
            + ": expected "
            + str(expected)
            + " occurrence(s), found "
            + str(found)
        )
    return text.replace(old, new)


def make_executable(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    os.chmod(path, mode | stat.S_IXUSR)


def build_updated_peer(assets_dir: Path) -> None:
    source = Path(__file__).resolve().parent / "mixed_soak_peer"
    expected = {"fourhour_file_peer.go", "fourhour_file_failures.go",
                "fourhour_file_commands.go", "fourhour_file_mixed.go",
                "resource_soak.go", "demux_expect_test.go"}
    files = {f.name for f in source.iterdir() if f.is_file()}
    if files != expected or any((source / n).is_symlink() for n in expected):
        fail("unexpected updated mixed-peer source inventory")
    shutil.copytree(source, assets_dir / "peer-source")
    module = Path.home() / ".local/share/duo-aider/mender-rust-assessment/mender-connect"
    if not (module / "go.mod").is_file() or not (module / "vendor").is_dir():
        fail("offline vendored module is unavailable")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home()),
           "GOFLAGS": "-mod=vendor", "GOPROXY": "off", "GOSUMDB": "off",
           "GOTOOLCHAIN": "local", "CGO_ENABLED": "0"}
    with tempfile.TemporaryDirectory(prefix="signoff-mixed-build-", dir=module) as work:
        build = Path(work)
        for name in expected:
            shutil.copy2(assets_dir / "peer-source" / name, build / name)
        result = subprocess.run(["go", "build", "-o", str(assets_dir / "peer"),
                                 "./" + build.name], cwd=module, env=env,
                                capture_output=True, text=True, timeout=90)
        if result.returncode:
            (assets_dir / "peer-build.log").write_text(result.stdout + result.stderr)
            fail("updated offline peer build failed; private build log retained")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--label", required=True)
    parser.add_argument("--seconds", required=True, type=int)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--limits-enabled", action="store_true")
    arguments = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", arguments.expected_sha256):
        fail("explicit lower-case SHA256 required")
    label = arguments.label
    seconds = arguments.seconds

    if not LABEL_RE.fullmatch(label):
        fail("label must be 1..40 simple alnum/hyphen characters")
    if not 30 <= seconds <= 3600:
        fail("seconds must be 30..3600")
    if platform.system() != "Linux":
        fail("Linux is required")
    if platform.machine() != "x86_64":
        fail("x86_64 is required")
    if not SOURCE_ASSETS.is_dir():
        fail("trusted calibrated assets directory is missing: " + str(SOURCE_ASSETS))
    for name in REQUIRED_SOURCE:
        if not (SOURCE_ASSETS / name).exists():
            fail("trusted calibrated asset is missing: " + name)
    if not CANDIDATE.is_file():
        fail("candidate binary is missing: " + str(CANDIDATE))

    candidate_hash = sha256_file(CANDIDATE)
    if candidate_hash != arguments.expected_sha256:
        fail("candidate SHA256 mismatch: " + candidate_hash)
    if not is_x86_64_elf(CANDIDATE):
        fail("candidate is not a little-endian x86_64 ELF binary")

    state_dir = ROOT / ("soak-fourhour-" + label)
    assets_dir = ROOT / ("native-x64-" + label + "-resources")
    if state_dir.exists():
        fail("state path already exists; label must be unique per run: " + str(state_dir))
    if assets_dir.exists():
        fail("assets path already exists; label must be unique per run: " + str(assets_dir))

    created_assets = False
    try:
        assets_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
        created_assets = True

        build_updated_peer(assets_dir)
        shutil.copy2(SOURCE_ASSETS / "mock-auth", assets_dir / "mock-auth")
        shutil.copy2(CANDIDATE, assets_dir / "frozen-daemon")

        for name in ("peer", "mock-auth", "frozen-daemon"):
            make_executable(assets_dir / name)
        os.chmod(assets_dir / "frozen-daemon", 0o555)

        frozen_hash = sha256_file(assets_dir / "frozen-daemon")
        if frozen_hash != candidate_hash:
            fail("frozen-daemon hash does not match the verified candidate")

        runner_text = (SOURCE_ASSETS / "run-calibrated-soak.py").read_text(encoding="utf-8")
        runner_text = adapt_exact(
            runner_text,
            "frozen=root/'soak-fourhour-udp-guard-release-resources'",
            "frozen=root/'" + assets_dir.name + "'",
            1,
            "runner frozen anchor",
        )
        runner_text = adapt_exact(
            runner_text,
            "'scenario':'30min-wss-single-cpu-calibrated'",
            "'scenario':'native-x64-calibrated'",
            1,
            "runner scenario",
        )

        if arguments.limits_enabled:
            anchor = "    (state/'config.json').write_text(json.dumps(config))"
            policy = "    config['Limits']={'Enabled':True,'FileTransfer':{'Chroot':str(state),'AllowOverwrite':True,'Umask':'0000','MaxFileSize':1048576,'Counters':{'MaxBytesTxPerMinute':0,'MaxBytesRxPerMinute':0}}}"
            runner_text = adapt_exact(runner_text, anchor, policy + "\n" + anchor, 1, "enabled file-limit profile")

        monitor_text = (SOURCE_ASSETS / "monitor-highwater-calibrated.py").read_text(
            encoding="utf-8"
        )
        monitor_text = adapt_exact(
            monitor_text,
            "state=Path.home()/'.local/share/duo-aider/mender-rust-trial/soak-fourhour-udp-guard-release-wss-30min-single-cpu'",
            "state=Path.home()/'.local/share/duo-aider/mender-rust-trial/soak-fourhour-"
            + label
            + "'",
            1,
            "monitor state anchor",
        )
        monitor_text = adapt_exact(
            monitor_text,
            "while time.monotonic()-started<2100:",
            "while time.monotonic()-started<" + str(seconds + 120) + ":",
            1,
            "monitor bounded lifetime",
        )

        runner_path = assets_dir / "run-calibrated-soak.py"
        monitor_path = assets_dir / "monitor-highwater-calibrated.py"
        launch_path = assets_dir / "launch.py"
        runner_path.write_text(runner_text, encoding="utf-8")
        monitor_path.write_text(monitor_text, encoding="utf-8")
        launch_path.write_text(LAUNCH_SOURCE, encoding="utf-8")
        os.chmod(runner_path, 0o444)
        os.chmod(monitor_path, 0o444)
        os.chmod(launch_path, 0o555)

        inventory = {
            "frozen-daemon": sha256_file(assets_dir / "frozen-daemon"),
            "peer": sha256_file(assets_dir / "peer"),
            "mock-auth": sha256_file(assets_dir / "mock-auth"),
            "peer-source": sha256_path(assets_dir / "peer-source"),
            "run-calibrated-soak.py": sha256_file(runner_path),
            "monitor-highwater-calibrated.py": sha256_file(monitor_path),
            "launch.py": sha256_file(launch_path),
        }

        manifest = {
            "schema": "native-x64-mixed-soak-preparation-v1",
            "label": label,
            "seconds": seconds,
            "state": str(state_dir),
            "assets_dir": str(assets_dir),
            "launch": str(launch_path),
            "launch_argv": [
                "python3",
                str(launch_path),
                "--label",
                label,
                "--seconds",
                str(seconds),
            ],
            "candidate": str(CANDIDATE),
            "candidate_sha256": candidate_hash,
            "limits_enabled": arguments.limits_enabled,
            "architecture": "x86_64",
            "platform_machine": platform.machine(),
            "qemu": False,
            "chosen_cpu": "first permitted CPU pinned at launch; see launch-runtime.json",
            "chosen_cpu_runtime_report": str(assets_dir / "launch-runtime.json"),
            "hard_stop_seconds_after_launch": seconds + 120,
            "source_assets": str(SOURCE_ASSETS),
            "adaptations": {
                "runner_frozen_anchor": assets_dir.name,
                "runner_scenario": "native-x64-calibrated",
                "monitor_state": state_dir.name,
                "monitor_bounded_lifetime_seconds": seconds + 120,
            },
            "sha256": inventory,
        }
        manifest_path = assets_dir / "manifest.json"
        manifest_tmp = assets_dir / "manifest.json.tmp"
        manifest_tmp.write_text(
            json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
        )
        os.chmod(manifest_tmp, 0o444)
        manifest_tmp.replace(manifest_path)

        print(launch_path)
    except BaseException:
        if created_assets:
            pass  # Preserve owned partial assets as failure evidence.
        raise


if __name__ == "__main__":
    main()
