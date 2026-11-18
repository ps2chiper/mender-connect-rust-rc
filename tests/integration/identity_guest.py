#!/usr/bin/env python3
"""Source-only isolated credential-transition fixture.

This file is a local, opt-in test harness. It performs no privileged action
unless it is invoked with an explicit ``--run`` by a real root process. It is
intended for parent review before any execution. It does not install packages,
contact a Mender server, use host SSH keys, create host accounts, or start QEMU.

The guest environment is a private bubblewrap sandbox built from a freshly
frozen copy of the helper and bwrap under a new root-only run directory. The
guest controller is PID-isolated root in the sandbox; it authenticates the
helper over a private Unix socket, drives five bounded credential-transition
cases, and writes only redacted boolean/numeric proofs.

The workspace base may be owned by root or the fixed task UID (1000) but must
not be group/other writable; the run directory itself must be a new root-owned
0700 directory. Reports are written to the exact fixed Windows report directory
where DrvFS does not enforce POSIX owner/mode, so only the real file at that
fixed location is verified and Windows ACLs govern access. Raw payloads and logs
stay root-private inside the Linux run directory. Frozen probe source is made
readonly-readable (0444) so the target UID can read it, while controller and
binaries stay non-writable.

Capability diagnostics note:
The first observed run failed at the controller capability preflight
(``caps_ok`` false) before any helper case ran, while the private PID/net/mount
namespaces, readonly /proc and the identity uid/gid maps all passed. Bubblewrap
capability restriction semantics (``--cap-drop``/``--cap-add``) are coupled to
the user-namespace/uid-switch setup: when bwrap runs as real root and the target
stays root with no ``--unshare-user``, the requested drop may not be reflected
in the exec'd process's permitted/effective/bounding/ambient sets in the way
this fixture assumed. Rather than silently relax the intended exact
permitted/effective/bounding restriction, the controller now records bounded
numeric CapInh/CapPrm/CapEff/CapBnd/CapAmb values and a per-set boolean
breakdown in the private result, and the host sanitizer forwards them to the
fixed report so the parent can distinguish exactly which capability set
diverges from the intended {CAP_SETUID, CAP_SETGID, CAP_KILL} mask.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
import stat
import subprocess
import sys
import tempfile

WORKSPACE = "/home/jason/.local/share/duo-aider/mender-rust-trial"
BWRAP_SOURCE = (
    "/home/jason/.local/share/duo-aider/mender-rust-live-sandbox/runtime/usr/bin/bwrap"
)
ALLOWED_HELPER = '/home/jason/projects/mender-connect-rust-trial/target/release/mender-connect-session-helper'
ALLOWED_LAUNCHER = (
    WORKSPACE
    + "/prototypes/signoff-identity-helper/target/release/mender-connect-identity-guest-launcher"
)
ALLOWED_PTY_PROBE = '/home/jason/projects/mender-connect-rust-trial/target/release/examples/identity_pty_probe'
ALLOWED_PTY_TARGET = '/home/jason/projects/mender-connect-rust-trial/tests/integration/identity_pty_target.py'
ALLOWED_REPORT_DIR = '/mnt/c/Users/Jason Duhamell/Documents/ChatGPT/Milk V Duo/reports/mender-rust-signoff'
REPORT_PREFIX = "identity_guest_report-"
MANIFEST_PREFIX = "identity_guest_manifest-"
REPORT_SUFFIX = ".json"
# CAP_SETUID|CAP_SETGID|CAP_KILL: the exact permitted/effective/bounding mask
# the launcher installs before exec'ing the fixed controller (224).
ALLOWED_CAP_MASK = (1 << 5) | (1 << 6) | (1 << 7)
# CAP_SETPCAP (bit 8) is added only to the initial bwrap setup so the launcher
# can reduce its own bounding set down to ALLOWED_CAP_MASK (setup mask 480).
CAP_SETPCAP_BIT = 1 << 8
SETUP_CAP_MASK = ALLOWED_CAP_MASK | CAP_SETPCAP_BIT
MAX_CAP_BITS_MASK = (1 << 64) - 1
TARGET_UID = 65534
TARGET_GID = 65534
TASK_UID = 1000
MAX_FREEZE_BYTES = 64 * 1024 * 1024
MAX_GUEST_RESULT_BYTES = 1024 * 1024
MAX_PTY_REPORT_BYTES = 64 * 1024
BWRAP_TIMEOUT_SECONDS = 75
CASE_NAMES = (
    "success",
    "wrong_parent",
    "unknown_user",
    "root_target",
    "exec_failure",
    "pty",
    "missing_home",
)

PROBE_SOURCE = r'''#!/usr/bin/env python3
import json
import os
import sys


def read_caps():
    values = {}
    try:
        with open("/proc/self/status", "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                key, separator, rest = line.partition(":")
                if not separator:
                    continue
                if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    try:
                        values[key] = int(rest.strip(), 16)
                    except ValueError:
                        values[key] = -1
    except OSError:
        return {}
    return values


def extra_fds():
    result = []
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return result
    for name in names:
        if not name.isdigit():
            continue
        fd = int(name)
        if fd <= 2:
            continue
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except OSError:
            continue
        if target == "/proc/self/fd" or target.endswith("/fd"):
            continue
        result.append(fd)
    return sorted(result)


def proc_readonly():
    try:
        with open("/proc/mounts", "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "/proc":
                    return "ro" in fields[3].split(",")
    except OSError:
        pass
    return False


def main():
    uid_real, uid_eff, uid_saved = os.getresuid()
    gid_real, gid_eff, gid_saved = os.getresgid()
    caps = read_caps()
    keys = set(os.environ)
    allowed = {"HOME", "USER", "LOGNAME", "TERM", "PATH", "LANG"}
    forbidden = ("LD_", "MENDER", "OPENROUTER")
    proof = {
        "uid_real": int(uid_real),
        "uid_effective": int(uid_eff),
        "uid_saved": int(uid_saved),
        "gid_real": int(gid_real),
        "gid_effective": int(gid_eff),
        "gid_saved": int(gid_saved),
        "groups": sorted(int(group) for group in os.getgroups()),
        "cap_inh": int(caps.get("CapInh", -1)),
        "cap_prm": int(caps.get("CapPrm", -1)),
        "cap_eff": int(caps.get("CapEff", -1)),
        "cap_bnd": int(caps.get("CapBnd", -1)),
        "cap_amb": int(caps.get("CapAmb", -1)),
        "open_fds": extra_fds(),
        "cwd": os.getcwd(),
        "home": os.environ.get("HOME", ""),
        "env_allowed_only": bool(keys <= allowed),
        "env_marker_absent": not any(key.startswith(forbidden) for key in keys),
        "proc_readonly": bool(proc_readonly()),
        "host_home_absent": not os.path.exists("/home/jason"),
        "device_absent": not os.path.exists("/device"),
    }
    sys.stdout.write(json.dumps(proof, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''

CONTROLLER_SOURCE = r'''#!/usr/bin/env python3
import json
import os
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import traceback

HELPER = "/helper"
PROBE = "/probe.py"
PYTHON = "/usr/bin/python3"
SOCKET_DIR = "/run/controller"
WORK = "/work"
HOME = "/work/home/trial"
RESULT = "/work/result.json"
SENTINEL = "/work/sentinel"
PTY_PROBE = "/pty-probe"
PTY_REPORT = "/work/pty-probe-report.json"
MISSING_HOME = "/work/missing-home"
MAX_FRAME = 16384
MAX_PTY_REPORT_BYTES = 65536
CASE_TIMEOUT = 10.0
PTY_TIMEOUT = 25.0
CASE_NAMES = (
    "success",
    "wrong_parent",
    "unknown_user",
    "root_target",
    "exec_failure",
    "pty",
    "missing_home",
)
ALLOWED_CAP_MASK = (1 << 5) | (1 << 6) | (1 << 7)
CAP_SYS_ADMIN = 1 << 21
TARGET_UID_VALUE = 65534
TARGET_GID_VALUE = 65534

children = []
case_results = {}


def monotonic():
    return time.monotonic()


def deadline(seconds):
    return monotonic() + seconds


def remaining(deadline_value):
    left = deadline_value - monotonic()
    if left <= 0:
        raise TimeoutError("deadline")
    return left


def recv_exact(sock, size, deadline_value):
    data = bytearray()
    while len(data) < size:
        sock.settimeout(remaining(deadline_value))
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise EOFError("peer closed")
        data.extend(chunk)
    return bytes(data)


def read_frame(sock, deadline_value):
    header = recv_exact(sock, 4, deadline_value)
    length = int.from_bytes(header, "big")
    if length > MAX_FRAME:
        raise ValueError("frame too large")
    return json.loads(recv_exact(sock, length, deadline_value).decode("utf-8"))


def send_frame(sock, value, deadline_value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_FRAME:
        raise ValueError("frame too large")
    sock.settimeout(remaining(deadline_value))
    sock.sendall(len(payload).to_bytes(4, "big") + payload)


def peer_credentials(sock):
    raw = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", raw)
    return int(pid), int(uid), int(gid)


def extra_fds():
    result = []
    try:
        names = os.listdir("/proc/self/fd")
    except OSError:
        return result
    for name in names:
        if not name.isdigit():
            continue
        fd = int(name)
        if fd <= 2:
            continue
        try:
            target = os.readlink("/proc/self/fd/" + name)
        except OSError:
            continue
        if target == "/proc/self/fd" or target.endswith("/fd"):
            continue
        result.append(fd)
    return sorted(result)


def read_caps():
    values = {}
    try:
        with open("/proc/self/status", "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                key, separator, rest = line.partition(":")
                if not separator:
                    continue
                if key in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"):
                    try:
                        values[key] = int(rest.strip(), 16)
                    except ValueError:
                        values[key] = -1
    except OSError:
        return {}
    return values


def caps_diagnostics(caps):
    def bounded(name):
        value = caps.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            return int(value)
        return -1

    return {
        "cap_inh": bounded("CapInh"),
        "cap_prm": bounded("CapPrm"),
        "cap_eff": bounded("CapEff"),
        "cap_bnd": bounded("CapBnd"),
        "cap_amb": bounded("CapAmb"),
    }


def capability_checks(caps):
    effective = caps.get("CapEff")
    permitted = caps.get("CapPrm")
    inheritable = caps.get("CapInh")
    bounding = caps.get("CapBnd")
    ambient = caps.get("CapAmb")
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in (effective, permitted, inheritable, bounding, ambient)
    ):
        return {"present": False}
    return {
        "present": True,
        "effective_ok": effective == ALLOWED_CAP_MASK,
        "permitted_ok": permitted == ALLOWED_CAP_MASK,
        "bounding_ok": bounding == ALLOWED_CAP_MASK,
        "inheritable_ok": (inheritable & ~ALLOWED_CAP_MASK) == 0,
        "ambient_ok": ambient == 0,
        "no_sys_admin": ((effective | permitted | bounding) & CAP_SYS_ADMIN) == 0,
    }


def read_id_map(path):
    entries = []
    try:
        with open(path, "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) != 3:
                    continue
                try:
                    inside, _outside, length = (int(field, 10) for field in fields)
                except ValueError:
                    continue
                if inside < 0 or length <= 0:
                    continue
                entries.append((inside, length))
    except OSError:
        return []
    return entries


def map_covers(entries, value):
    return any(start <= value < start + length for start, length in entries)


def map_covers_required(path):
    required = (0, TARGET_UID_VALUE, TARGET_GID_VALUE)
    entries = read_id_map(path)
    if not entries:
        return False
    return all(map_covers(entries, value) for value in required)


def uid_map_ok():
    return map_covers_required("/proc/self/uid_map")


def gid_map_ok():
    return map_covers_required("/proc/self/gid_map")


def proc_readonly():
    try:
        with open("/proc/mounts", "r", encoding="ascii", errors="replace") as handle:
            for line in handle:
                fields = line.split()
                if len(fields) >= 4 and fields[1] == "/proc":
                    return "ro" in fields[3].split(",")
    except OSError:
        pass
    return False


def namespace_inode(name):
    return int(os.stat("/proc/self/ns/" + name).st_ino)


def make_socket_dir():
    if os.path.lexists(SOCKET_DIR):
        raise RuntimeError("socket directory already exists")
    os.mkdir(SOCKET_DIR, 0o700)
    os.chmod(SOCKET_DIR, 0o700)
    info = os.lstat(SOCKET_DIR)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise RuntimeError("socket directory verification failed")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise RuntimeError("socket directory mode verification failed")


def open_sentinel():
    fd = os.open(SENTINEL, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    os.fchmod(fd, 0o600)
    os.set_inheritable(fd, True)
    return fd


def make_listener(name):
    path = os.path.join(SOCKET_DIR, "case-" + name + ".sock")
    if os.path.lexists(path):
        os.unlink(path)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    listener.listen(1)
    return listener, path


def spawn_helper(path, expected_parent, sentinel_fd, home=HOME):
    environment = {"PATH": "/usr/bin:/bin", "HOME": home}
    process = subprocess.Popen(
        [HELPER, "--socket", path, "--parent-pid", str(expected_parent)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        pass_fds=(sentinel_fd,),
        close_fds=True,
        start_new_session=True,
    )
    children.append(process)
    return process


def accept_verified(listener, process, deadline_value):
    listener.settimeout(remaining(deadline_value))
    connection, _address = listener.accept()
    pid, uid, _gid = peer_credentials(connection)
    if pid != process.pid or uid != 0:
        connection.close()
        raise RuntimeError("untrusted helper peer")
    return connection


def request_object(target_user, shell, arguments, challenge):
    return {
        "target_user": target_user,
        "shell": shell,
        "arguments": arguments,
        "term": "xterm-256color",
        "challenge": challenge,
    }


def validate_ready(ready, challenge):
    if not isinstance(ready, dict):
        return False
    capabilities = ready.get("capabilities")
    if not isinstance(capabilities, dict):
        return False
    return (
        ready.get("status") == "ready"
        and ready.get("challenge") == challenge
        and isinstance(ready.get("pid"), int)
        and isinstance(ready.get("sid"), int)
        and isinstance(ready.get("pgid"), int)
        and ready.get("uid") == TARGET_UID_VALUE
        and ready.get("gid") == TARGET_GID_VALUE
        and ready.get("groups") == [TARGET_GID_VALUE]
        and capabilities.get("effective_empty") is True
        and capabilities.get("permitted_empty") is True
        and capabilities.get("inheritable_empty") is True
        and capabilities.get("ambient_empty") is True
        and capabilities.get("keep_caps_clear") is True
    )


def validate_probe(probe, expected_cwd, expected_home):
    if not isinstance(probe, dict):
        return False
    return (
        probe.get("uid_real") == TARGET_UID_VALUE
        and probe.get("uid_effective") == TARGET_UID_VALUE
        and probe.get("uid_saved") == TARGET_UID_VALUE
        and probe.get("gid_real") == TARGET_GID_VALUE
        and probe.get("gid_effective") == TARGET_GID_VALUE
        and probe.get("gid_saved") == TARGET_GID_VALUE
        and probe.get("groups") == [TARGET_GID_VALUE]
        and probe.get("cap_inh") == 0
        and probe.get("cap_prm") == 0
        and probe.get("cap_eff") == 0
        and probe.get("cap_amb") == 0
        and probe.get("open_fds") == []
        and probe.get("cwd") == expected_cwd
        and probe.get("home") == expected_home
        and probe.get("env_allowed_only") is True
        and probe.get("env_marker_absent") is True
        and probe.get("proc_readonly") is True
        and probe.get("host_home_absent") is True
        and probe.get("device_absent") is True
    )


def success_case(
    challenge,
    username="trial",
    expected_cwd="/work/home/trial",
    expected_home=HOME,
    name="success",
):
    result = {"passed": False, "exit_code": -1}
    deadline_value = deadline(CASE_TIMEOUT)
    listener = None
    path = None
    sentinel_fd = -1
    connection = None
    try:
        listener, path = make_listener(name)
        sentinel_fd = open_sentinel()
        process = spawn_helper(path, os.getpid(), sentinel_fd, expected_home)
        os.close(sentinel_fd)
        sentinel_fd = -1
        connection = accept_verified(listener, process, deadline_value)
        send_frame(
            connection,
            request_object(username, PYTHON, [PROBE], challenge),
            deadline_value,
        )
        ready = read_frame(connection, deadline_value)
        actual_pid = process.pid
        actual_sid = os.getsid(process.pid)
        actual_pgid = os.getpgid(process.pid)
        connection.close()
        connection = None
        output, _error = process.communicate(timeout=remaining(deadline_value))
        result["exit_code"] = int(process.returncode)
        try:
            probe = json.loads(output.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            probe = None
        ready_ok = validate_ready(ready, challenge)
        probe_ok = validate_probe(probe, expected_cwd, expected_home)
        identity_ok = (
            isinstance(ready, dict)
            and ready.get("pid") == actual_pid
            and ready.get("sid") == actual_sid
            and ready.get("pgid") == actual_pgid
            and actual_sid == actual_pid
            and actual_pgid == actual_pid
        )
        match_ok = (
            isinstance(probe, dict)
            and isinstance(ready, dict)
            and ready.get("uid") == probe.get("uid_effective")
            and ready.get("gid") == probe.get("gid_effective")
            and ready.get("groups") == probe.get("groups")
        )
        result["ready_ok"] = bool(ready_ok)
        result["probe_ok"] = bool(probe_ok)
        result["identity_ok"] = bool(identity_ok)
        result["match_ok"] = bool(match_ok)
        result["uid"] = int(TARGET_UID_VALUE)
        result["gid"] = int(TARGET_GID_VALUE)
        result["open_fd_count"] = (
            len(probe.get("open_fds", [])) if isinstance(probe, dict) else -1
        )
        result["cap_effective"] = (
            int(probe.get("cap_eff", -1)) if isinstance(probe, dict) else -1
        )
        result["passed"] = bool(
            process.returncode == 0 and ready_ok and probe_ok and identity_ok and match_ok
        )
        return result
    except BaseException:
        traceback.print_exc()
        result["passed"] = False
        return result
    finally:
        if connection is not None:
            connection.close()
        if sentinel_fd >= 0:
            os.close(sentinel_fd)
        if listener is not None:
            listener.close()
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def wrong_parent_case():
    result = {"passed": False, "exit_code": -1}
    listener = None
    path = None
    sentinel_fd = -1
    try:
        listener, path = make_listener("wrong_parent")
        sentinel_fd = open_sentinel()
        expected = os.getpid() + 1
        process = spawn_helper(path, expected, sentinel_fd)
        os.close(sentinel_fd)
        sentinel_fd = -1
        result["exit_code"] = int(process.wait(timeout=5))
        listener.settimeout(0.5)
        connected = False
        try:
            stray, _address = listener.accept()
            stray.close()
            connected = True
        except socket.timeout:
            connected = False
        result["connection_seen"] = bool(connected)
        result["passed"] = bool(process.returncode == 2 and not connected)
        return result
    except BaseException:
        traceback.print_exc()
        result["passed"] = False
        return result
    finally:
        if sentinel_fd >= 0:
            os.close(sentinel_fd)
        if listener is not None:
            listener.close()
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def rejection_case(name, target_user, challenge):
    result = {"passed": False, "exit_code": -1}
    deadline_value = deadline(CASE_TIMEOUT)
    listener = None
    path = None
    sentinel_fd = -1
    connection = None
    try:
        listener, path = make_listener(name)
        sentinel_fd = open_sentinel()
        process = spawn_helper(path, os.getpid(), sentinel_fd)
        os.close(sentinel_fd)
        sentinel_fd = -1
        connection = accept_verified(listener, process, deadline_value)
        send_frame(
            connection,
            request_object(target_user, PYTHON, [PROBE], challenge),
            deadline_value,
        )
        unexpected = False
        try:
            read_frame(connection, deadline_value)
            unexpected = True
        except EOFError:
            unexpected = False
        output, _error = process.communicate(timeout=remaining(deadline_value))
        result["exit_code"] = int(process.returncode)
        result["unexpected_frame"] = bool(unexpected)
        result["passed"] = bool(
            not unexpected and process.returncode == 2 and output == b""
        )
        return result
    except BaseException:
        traceback.print_exc()
        result["passed"] = False
        return result
    finally:
        if connection is not None:
            connection.close()
        if sentinel_fd >= 0:
            os.close(sentinel_fd)
        if listener is not None:
            listener.close()
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def exec_failure_case(challenge):
    result = {"passed": False, "exit_code": -1}
    deadline_value = deadline(CASE_TIMEOUT)
    listener = None
    path = None
    sentinel_fd = -1
    connection = None
    try:
        listener, path = make_listener("exec_failure")
        sentinel_fd = open_sentinel()
        process = spawn_helper(path, os.getpid(), sentinel_fd)
        os.close(sentinel_fd)
        sentinel_fd = -1
        connection = accept_verified(listener, process, deadline_value)
        send_frame(
            connection,
            request_object("trial", "/work/owned-missing-executable", [PROBE], challenge),
            deadline_value,
        )
        ready = read_frame(connection, deadline_value)
        failure = read_frame(connection, deadline_value)
        output, _error = process.communicate(timeout=remaining(deadline_value))
        result["exit_code"] = int(process.returncode)
        result["ready_ok"] = bool(validate_ready(ready, challenge))
        result["exec_failed_ok"] = bool(
            isinstance(failure, dict) and failure.get("status") == "exec-failed"
        )
        result["stdout_empty"] = bool(output == b"")
        result["passed"] = bool(
            result["ready_ok"]
            and result["exec_failed_ok"]
            and result["stdout_empty"]
            and process.returncode == 2
        )
        return result
    except BaseException:
        traceback.print_exc()
        result["passed"] = False
        return result
    finally:
        if connection is not None:
            connection.close()
        if sentinel_fd >= 0:
            os.close(sentinel_fd)
        if listener is not None:
            listener.close()
        if path is not None:
            try:
                os.unlink(path)
            except OSError:
                pass


def read_bounded_report(path, limit):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise RuntimeError("pty report file verification failed")
    if info.st_size > limit:
        raise ValueError("pty report too large")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        data = bytearray()
        while True:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            data.extend(chunk)
            if len(data) > limit:
                raise ValueError("pty report too large")
    finally:
        os.close(fd)
    return json.loads(bytes(data).decode("utf-8"))


def validate_pty_report(report):
    if not isinstance(report, dict):
        return False
    names = (
        "ok",
        "identity",
        "env",
        "fd",
        "tty",
        "ping",
        "resize",
        "background",
        "leader_ended",
        "background_ended",
    )
    return all(report.get(name) is True for name in names)


def pty_case():
    result = {"passed": False, "exit_code": -1}
    if os.path.lexists(PTY_REPORT):
        os.unlink(PTY_REPORT)
    fd = os.open(
        PTY_REPORT,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    process = None
    try:
        os.fchmod(fd, 0o600)
        environment = {
            "PATH": "/usr/bin:/bin",
            "HOME": HOME,
            "LANG": "C",
            "MENDER_TRIAL_PARENT_MARKER": "1",
        }
        process = subprocess.Popen(
            [PTY_PROBE],
            stdin=subprocess.DEVNULL,
            stdout=fd,
            stderr=subprocess.DEVNULL,
            env=environment,
            close_fds=True,
            start_new_session=True,
        )
        children.append(process)
        os.close(fd)
        fd = -1
        try:
            result["exit_code"] = int(process.wait(timeout=PTY_TIMEOUT))
        except subprocess.TimeoutExpired:
            result["timed_out"] = True
            try:
                process.terminate()
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass
            result["exit_code"] = int(
                process.returncode if process.returncode is not None else -1
            )
        report = read_bounded_report(PTY_REPORT, MAX_PTY_REPORT_BYTES)
        result["report_ok"] = bool(validate_pty_report(report))
        if isinstance(report, dict):
            for name in (
                "identity",
                "env",
                "fd",
                "tty",
                "ping",
                "resize",
                "background",
                "leader_ended",
                "background_ended",
            ):
                result[name + "_ok"] = report.get(name) is True
        result["passed"] = bool(
            result["exit_code"] == 0
            and result.get("timed_out") is not True
            and result["report_ok"]
        )
        return result
    except BaseException:
        traceback.print_exc()
        result["passed"] = False
        return result
    finally:
        if fd >= 0:
            os.close(fd)


def cleanup_children():
    for process in list(children):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
    for process in list(children):
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                pass
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def write_result(result):
    payload = json.dumps(result, sort_keys=True, separators=(",", ":")).encode("utf-8")
    fd = os.open(RESULT, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, payload)
    finally:
        os.close(fd)


def main():
    result = {
        "controller_root": bool(os.geteuid() == 0 and os.getuid() == 0),
        "fd_leak_free": False,
        "caps_ok": False,
        "caps": {},
        "caps_checks": {},
        "uid_map_ok": False,
        "gid_map_ok": False,
        "proc_readonly": False,
        "ns_pid": -1,
        "ns_net": -1,
        "ns_mnt": -1,
        "cases": {},
        "all_passed": False,
    }
    try:
        result["fd_leak_free"] = bool(extra_fds() == [])
        controller_caps = read_caps()
        result["caps"] = caps_diagnostics(controller_caps)
        checks = capability_checks(controller_caps)
        result["caps_checks"] = checks
        result["caps_ok"] = bool(all(checks.values()))
        result["uid_map_ok"] = bool(uid_map_ok())
        result["gid_map_ok"] = bool(gid_map_ok())
        result["proc_readonly"] = bool(proc_readonly())
        result["ns_pid"] = namespace_inode("pid")
        result["ns_net"] = namespace_inode("net")
        result["ns_mnt"] = namespace_inode("mnt")
        if not (
            result["caps_ok"]
            and result["uid_map_ok"]
            and result["gid_map_ok"]
        ):
            sys.stderr.write("credential/id-map proof failed before cases\n")
            raise RuntimeError("credential capability or id-map proof failed")
        make_socket_dir()
        challenge = os.urandom(16).hex()
        result["cases"]["success"] = success_case(challenge)
        result["cases"]["missing_home"] = success_case(
            challenge,
            username="trialmissing",
            expected_cwd="/",
            expected_home=MISSING_HOME,
            name="missing_home",
        )
        result["cases"]["wrong_parent"] = wrong_parent_case()
        result["cases"]["unknown_user"] = rejection_case(
            "unknown_user", "unknown-trial-user", challenge
        )
        result["cases"]["root_target"] = rejection_case(
            "root_target", "root", challenge
        )
        result["cases"]["exec_failure"] = exec_failure_case(challenge)
        result["cases"]["pty"] = pty_case()
        result["all_passed"] = bool(
            result["controller_root"]
            and result["fd_leak_free"]
            and result["caps_ok"]
            and result["uid_map_ok"]
            and result["gid_map_ok"]
            and result["proc_readonly"]
            and all(
                result["cases"].get(name, {}).get("passed") is True
                for name in CASE_NAMES
            )
        )
    except BaseException:
        traceback.print_exc()
        result["all_passed"] = False
    finally:
        cleanup_children()
        try:
            write_result(result)
        except BaseException:
            traceback.print_exc()
    return 0 if result["all_passed"] else 2


if __name__ == "__main__":
    sys.exit(main())
'''


class FixtureError(RuntimeError):
    """Raised when a host-side freeze or setup proof fails."""


def is_hex_sha256(value):
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(char in "0123456789abcdef" for char in value.lower())


def write_all(fd, data):
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise FixtureError("short write")
        view = view[written:]


def verify_regular_owned(path, expected_mode):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise FixtureError("not a regular file")
    if info.st_uid != 0:
        raise FixtureError("file is not root-owned")
    if info.st_mode & 0o6000:
        raise FixtureError("file has setuid/setgid bits")
    if stat.S_IMODE(info.st_mode) != expected_mode:
        raise FixtureError("unexpected file mode")
    return info


def sha256_file(path):
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FREEZE_BYTES:
                raise FixtureError("frozen file too large")
            digest.update(chunk)
    finally:
        os.close(fd)
    return digest.hexdigest()


def copy_verified(source, destination, expected, mode=0o555):
    resolved = os.path.realpath(source)
    source_fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        source_info = os.fstat(source_fd)
        if not stat.S_ISREG(source_info.st_mode):
            raise FixtureError("source is not a regular file")
        if source_info.st_mode & 0o6000:
            raise FixtureError("source has setuid/setgid bits")
        destination_fd = os.open(
            destination,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
            0o600,
        )
        try:
            digest = hashlib.sha256()
            total = 0
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > MAX_FREEZE_BYTES:
                    raise FixtureError("frozen file too large")
                digest.update(chunk)
                write_all(destination_fd, chunk)
            if digest.hexdigest() != expected:
                raise FixtureError("frozen hash mismatch")
            os.fchmod(destination_fd, mode)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    verify_regular_owned(destination, mode)
    if sha256_file(destination) != expected:
        raise FixtureError("copied byte hash mismatch")


def write_frozen_text(destination, text, mode=0o555):
    data = text.encode("utf-8")
    if b"\x00" in data or len(data) > MAX_FREEZE_BYTES:
        raise FixtureError("invalid frozen source")
    fd = os.open(
        destination,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        write_all(fd, data)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    verify_regular_owned(destination, mode)


def write_simple(path, data, mode):
    payload = data.encode("utf-8")
    fd = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        write_all(fd, payload)
        os.fchmod(fd, mode)
    finally:
        os.close(fd)
    verify_regular_owned(path, mode)


def make_directory(path, mode):
    os.mkdir(path, mode)
    os.chmod(path, mode)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0:
        raise FixtureError("directory verification failed")
    if stat.S_IMODE(info.st_mode) != mode:
        raise FixtureError("directory mode verification failed")
    return path


def is_descendant(root, path):
    root_real = os.path.realpath(root)
    path_real = os.path.realpath(path)
    try:
        return os.path.commonpath([root_real, path_real]) == root_real
    except ValueError:
        return False


def create_run_directory():
    base = os.path.realpath(WORKSPACE)
    base_info = os.lstat(base)
    if not stat.S_ISDIR(base_info.st_mode):
        raise FixtureError("workspace base is not a directory")
    if base_info.st_uid not in (0, TASK_UID):
        raise FixtureError("workspace base is not owned by root or the task user")
    if base_info.st_mode & 0o022:
        raise FixtureError("workspace base is group or other writable")
    path = tempfile.mkdtemp(prefix="identity-guest-", dir=base)
    os.chmod(path, 0o700)
    info = os.lstat(path)
    if not stat.S_ISDIR(info.st_mode):
        raise FixtureError("run directory is not a directory")
    if info.st_uid != 0:
        raise FixtureError("run directory is not root-owned")
    if stat.S_IMODE(info.st_mode) != 0o700:
        raise FixtureError("run directory is not mode 0700")
    if not is_descendant(base, path):
        raise FixtureError("run directory is not a workspace descendant")
    return path


def prepare_report_directory(requested):
    if os.path.realpath(requested) != os.path.realpath(ALLOWED_REPORT_DIR):
        raise FixtureError("report directory outside the allowed workspace path")
    info = os.lstat(ALLOWED_REPORT_DIR)
    if not stat.S_ISDIR(info.st_mode):
        raise FixtureError("report directory is not a real directory")
    if info.st_uid not in (0, TASK_UID):
        raise FixtureError("report directory is not owned by root or the task user")
    return ALLOWED_REPORT_DIR


def verify_report_file(path, report_directory):
    """Verify a report is a regular file at the fixed allowed location.

    The Windows DrvFS report directory does not enforce POSIX owner or mode, so
    the 0600 request is best-effort and not asserted here; Windows ACLs govern
    access. Only sanitized proofs are ever written to this location.
    """
    if os.path.dirname(os.path.realpath(path)) != os.path.realpath(report_directory):
        raise FixtureError("report file is outside the fixed report directory")
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode):
        raise FixtureError("report is not a regular file")
    if info.st_mode & 0o6000:
        raise FixtureError("report has setuid/setgid bits")
    return info


def write_unique_report(report_directory, prefix, report):
    payload = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode("utf-8")
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=REPORT_SUFFIX, dir=report_directory)
    try:
        try:
            write_all(fd, payload)
            os.fchmod(fd, 0o600)
        finally:
            os.close(fd)
        verify_report_file(path, report_directory)
        return path
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def namespace_inode(name):
    return int(os.stat("/proc/self/ns/" + name).st_ino)


def build_bwrap_arguments(
    run_directory,
    work_directory,
    etc_directory,
    helper,
    launcher,
    controller,
    probe,
    pty_probe,
    pty_target,
):
    return [
        os.path.join(run_directory, "bwrap"),
        "--unshare-pid",
        "--unshare-net",
        "--unshare-ipc",
        "--unshare-uts",
        "--die-with-parent",
        "--new-session",
        "--cap-drop",
        "ALL",
        "--cap-add",
        "CAP_SETUID",
        "--cap-add",
        "CAP_SETGID",
        "--cap-add",
        "CAP_KILL",
        "--cap-add",
        "CAP_SETPCAP",
        "--ro-bind",
        "/usr",
        "/usr",
        "--tmpfs",
        "/usr/libexec",
        "--ro-bind",
        helper,
        "/usr/libexec/mender-connect-session-helper",
        "--ro-bind",
        etc_directory,
        "/etc",
        "--ro-bind",
        helper,
        "/helper",
        "--ro-bind",
        launcher,
        "/launcher",
        "--ro-bind",
        controller,
        "/controller.py",
        "--ro-bind",
        probe,
        "/probe.py",
        "--ro-bind",
        pty_probe,
        "/pty-probe",
        "--ro-bind",
        pty_target,
        "/pty-target.py",
        "--bind",
        work_directory,
        "/work",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/run",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--symlink",
        "usr/bin",
        "/bin",
        "--symlink",
        "usr/lib",
        "/lib",
        "--symlink",
        "usr/lib64",
        "/lib64",
        "--remount-ro",
        "/proc",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/work/home/trial",
        "--chdir",
        "/work",
        "--",
        "/launcher",
    ]


def sanitized_launcher_env():
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": "/root",
        "LANG": "C",
        "LC_ALL": "C",
    }


def build_manifest(
    run_directory,
    work_directory,
    etc_directory,
    helper,
    launcher,
    bwrap,
    controller,
    probe,
    pty_probe,
    pty_target,
    stdout_log,
    stderr_log,
    expected_helper,
    expected_launcher,
    expected_bwrap,
    expected_pty_probe,
    expected_pty_target,
    bwrap_arguments,
):
    mounts = [
        {"type": "ro-bind", "source": "/usr", "destination": "/usr"},
        {"type": "tmpfs", "source": "tmpfs", "destination": "/usr/libexec"},
        {
            "type": "ro-bind",
            "source": helper,
            "destination": "/usr/libexec/mender-connect-session-helper",
        },
        {"type": "ro-bind", "source": etc_directory, "destination": "/etc"},
        {"type": "ro-bind", "source": helper, "destination": "/helper"},
        {"type": "ro-bind", "source": launcher, "destination": "/launcher"},
        {"type": "ro-bind", "source": controller, "destination": "/controller.py"},
        {"type": "ro-bind", "source": probe, "destination": "/probe.py"},
        {"type": "ro-bind", "source": pty_probe, "destination": "/pty-probe"},
        {"type": "ro-bind", "source": pty_target, "destination": "/pty-target.py"},
        {"type": "bind", "source": work_directory, "destination": "/work"},
        {"type": "tmpfs", "source": "tmpfs", "destination": "/tmp"},
        {"type": "tmpfs", "source": "tmpfs", "destination": "/run"},
        {"type": "proc", "source": "proc", "destination": "/proc"},
        {"type": "dev", "source": "dev", "destination": "/dev"},
    ]
    return {
        "version": 1,
        "bwrap_command": bwrap_arguments,
        "cap_drop": "ALL",
        "cap_add": ["CAP_SETUID", "CAP_SETGID", "CAP_KILL", "CAP_SETPCAP"],
        "setup_cap_mask": SETUP_CAP_MASK,
        "cap_mask": ALLOWED_CAP_MASK,
        "mounts": mounts,
        "frozen_hashes": {
            "helper": expected_helper,
            "launcher": expected_launcher,
            "bwrap": expected_bwrap,
            "controller": sha256_file(controller),
            "probe": sha256_file(probe),
            "pty_probe": sha256_file(pty_probe),
            "pty_target": sha256_file(pty_target),
        },
        "paths": {
            "run_directory": run_directory,
            "work_directory": work_directory,
            "etc_directory": etc_directory,
            "helper": helper,
            "launcher": launcher,
            "bwrap": bwrap,
            "controller": controller,
            "probe": probe,
            "pty_probe": pty_probe,
            "pty_target": pty_target,
            "stdout_log": stdout_log,
            "stderr_log": stderr_log,
        },
    }


def read_guest_result(path):
    info = os.lstat(path)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0:
        raise FixtureError("guest result file verification failed")
    if info.st_size > MAX_GUEST_RESULT_BYTES:
        raise FixtureError("guest result file too large")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        data = b""
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
            if len(data) > MAX_GUEST_RESULT_BYTES:
                raise FixtureError("guest result too large")
    finally:
        os.close(fd)
    return json.loads(data.decode("utf-8"))


def bounded_cap_value(value):
    if isinstance(value, int) and not isinstance(value, bool):
        if 0 <= value <= MAX_CAP_BITS_MASK:
            return int(value)
    return -1


def sanitize_caps(raw, names):
    source = raw if isinstance(raw, dict) else {}
    return {name: bounded_cap_value(source.get(name)) for name in names}


def sanitize_caps_checks(raw):
    source = raw if isinstance(raw, dict) else {}
    names = (
        "present",
        "effective_ok",
        "permitted_ok",
        "bounding_ok",
        "inheritable_ok",
        "ambient_ok",
        "no_sys_admin",
    )
    return {name: source.get(name) is True for name in names}


def sanitize_guest(guest):
    cases = guest.get("cases") if isinstance(guest.get("cases"), dict) else {}
    output = {}
    for name in CASE_NAMES:
        entry = cases.get(name) if isinstance(cases.get(name), dict) else {}
        output[name] = {"passed": entry.get("passed") is True}
    return {
        "controller_root": guest.get("controller_root") is True,
        "fd_leak_free": guest.get("fd_leak_free") is True,
        "caps_ok": guest.get("caps_ok") is True,
        "caps": sanitize_caps(
            guest.get("caps"), ("cap_inh", "cap_prm", "cap_eff", "cap_bnd", "cap_amb")
        ),
        "caps_checks": sanitize_caps_checks(guest.get("caps_checks")),
        "uid_map_ok": guest.get("uid_map_ok") is True,
        "gid_map_ok": guest.get("gid_map_ok") is True,
        "proc_readonly": guest.get("proc_readonly") is True,
        "all_passed": guest.get("all_passed") is True,
        "ns_pid": guest.get("ns_pid") if isinstance(guest.get("ns_pid"), int) else -1,
        "ns_net": guest.get("ns_net") if isinstance(guest.get("ns_net"), int) else -1,
        "ns_mnt": guest.get("ns_mnt") if isinstance(guest.get("ns_mnt"), int) else -1,
        "cases": output,
    }


def namespaces_differ(guest):
    for name in ("pid", "net", "mnt"):
        guest_inode = guest.get("ns_" + name)
        if not isinstance(guest_inode, int) or guest_inode <= 0:
            return False
        if guest_inode == namespace_inode(name):
            return False
    return True


def parse_arguments(argv):
    parser = argparse.ArgumentParser(add_help=True)
    parser.add_argument("--run", action="store_true")
    parser.add_argument("--helper", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--launcher-sha256", required=True)
    parser.add_argument("--bwrap-sha256", required=True)
    parser.add_argument("--pty-probe-sha256", required=True)
    parser.add_argument("--pty-target-sha256", required=True)
    parser.add_argument("--report-dir", required=True)
    return parser.parse_args(argv)


def main(argv=None):
    arguments = parse_arguments(sys.argv[1:] if argv is None else argv)
    real_root = os.getuid() == 0 and os.geteuid() == 0
    if not arguments.run or not real_root:
        sys.stderr.write("refusing: explicit --run and real root are required\n")
        return 2

    report = {
        "run_requested": True,
        "real_root": True,
        "argument_restriction_ok": False,
        "frozen_ok": False,
        "bwrap_launched": False,
        "bwrap_exit_code": -1,
        "timed_out": False,
        "guest_result_ok": False,
        "guest_all_passed": False,
        "guest_caps_ok": False,
        "guest_caps": {
            "cap_inh": -1,
            "cap_prm": -1,
            "cap_eff": -1,
            "cap_bnd": -1,
            "cap_amb": -1,
        },
        "guest_caps_checks": {},
        "guest_uid_map_ok": False,
        "guest_gid_map_ok": False,
        "namespaces_differ": False,
        "case_success": False,
        "case_wrong_parent": False,
        "case_unknown_user": False,
        "case_root_target": False,
        "case_exec_failure": False,
        "case_pty": False,
        "case_missing_home": False,
        "success_uid": -1,
        "success_gid": -1,
        "success_open_fd_count": -1,
        "success_cap_effective": -1,
        "run_dir_retained": False,
        "all_passed": False,
    }

    report_directory = None
    try:
        if os.path.realpath(arguments.helper) != os.path.realpath(ALLOWED_HELPER):
            raise FixtureError("helper path is outside the prototype target")
        if os.path.realpath(arguments.report_dir) != os.path.realpath(ALLOWED_REPORT_DIR):
            raise FixtureError("report directory is outside the allowed path")
        expected_helper = arguments.expected_sha256.lower()
        expected_bwrap = arguments.bwrap_sha256.lower()
        expected_launcher = arguments.launcher_sha256.lower()
        expected_pty_probe = arguments.pty_probe_sha256.lower()
        expected_pty_target = arguments.pty_target_sha256.lower()
        if not (
            is_hex_sha256(expected_helper)
            and is_hex_sha256(expected_bwrap)
            and is_hex_sha256(expected_launcher)
            and is_hex_sha256(expected_pty_probe)
            and is_hex_sha256(expected_pty_target)
        ):
            raise FixtureError("sha256 arguments must be 64 hex characters")
        report_directory = prepare_report_directory(arguments.report_dir)
        report["argument_restriction_ok"] = True

        run_directory = create_run_directory()
        report["run_dir_retained"] = True

        etc_directory = make_directory(os.path.join(run_directory, "etc"), 0o755)
        work_directory = make_directory(os.path.join(run_directory, "work"), 0o755)
        home_parent = make_directory(os.path.join(work_directory, "home"), 0o755)
        fixture_home = make_directory(os.path.join(home_parent, "trial"), 0o700)
        if not is_descendant(run_directory, fixture_home):
            raise FixtureError("fixture home is not a run-directory descendant")
        os.chown(fixture_home, TARGET_UID, TARGET_GID, follow_symlinks=False)
        os.chmod(fixture_home, 0o700)
        home_info = os.lstat(fixture_home)
        if home_info.st_uid != TARGET_UID or home_info.st_gid != TARGET_GID:
            raise FixtureError("fixture home ownership verification failed")
        if stat.S_IMODE(home_info.st_mode) != 0o700:
            raise FixtureError("fixture home mode verification failed")

        passwd = (
            "root:x:0:0:root:/root:/bin/sh\n"
            "trial:x:65534:65534:trial:/work/home/trial:/usr/bin/python3\n"
            "trialmissing:x:65534:65534:trialmissing:/work/missing-home:/usr/bin/python3\n"
        )
        group = "root:x:0:\ntrial:x:65534:\ntrialmissing:x:65534:\n"
        nsswitch = "passwd: files\ngroup: files\n"
        write_simple(os.path.join(etc_directory, "passwd"), passwd, 0o644)
        write_simple(os.path.join(etc_directory, "group"), group, 0o644)
        write_simple(os.path.join(etc_directory, "nsswitch.conf"), nsswitch, 0o644)

        helper_frozen = os.path.join(run_directory, "helper")
        launcher_frozen = os.path.join(run_directory, "launcher")
        bwrap_frozen = os.path.join(run_directory, "bwrap")
        controller_frozen = os.path.join(run_directory, "controller.py")
        probe_frozen = os.path.join(run_directory, "probe.py")
        pty_probe_frozen = os.path.join(run_directory, "identity_pty_probe")
        pty_target_frozen = os.path.join(run_directory, "identity_pty_target.py")
        copy_verified(ALLOWED_HELPER, helper_frozen, expected_helper)
        copy_verified(ALLOWED_LAUNCHER, launcher_frozen, expected_launcher)
        copy_verified(BWRAP_SOURCE, bwrap_frozen, expected_bwrap)
        copy_verified(ALLOWED_PTY_PROBE, pty_probe_frozen, expected_pty_probe)
        copy_verified(
            ALLOWED_PTY_TARGET, pty_target_frozen, expected_pty_target, 0o444
        )
        write_frozen_text(controller_frozen, CONTROLLER_SOURCE)
        write_frozen_text(probe_frozen, PROBE_SOURCE, 0o444)
        report["frozen_ok"] = True

        private_logs = make_directory(os.path.join(run_directory, "logs"), 0o700)
        stdout_path = os.path.join(private_logs, "bwrap.stdout.log")
        stderr_path = os.path.join(private_logs, "bwrap.stderr.log")

        bwrap_arguments = build_bwrap_arguments(
            run_directory,
            work_directory,
            etc_directory,
            helper_frozen,
            launcher_frozen,
            controller_frozen,
            probe_frozen,
            pty_probe_frozen,
            pty_target_frozen,
        )
        manifest = build_manifest(
            run_directory,
            work_directory,
            etc_directory,
            helper_frozen,
            launcher_frozen,
            bwrap_frozen,
            controller_frozen,
            probe_frozen,
            pty_probe_frozen,
            pty_target_frozen,
            stdout_path,
            stderr_path,
            expected_helper,
            expected_launcher,
            expected_bwrap,
            expected_pty_probe,
            expected_pty_target,
            bwrap_arguments,
        )
        report["manifest_path"] = write_unique_report(
            report_directory, MANIFEST_PREFIX, manifest
        )
        report["manifest"] = manifest
        with open(stdout_path, "wb") as stdout_log, open(
            stderr_path, "wb"
        ) as stderr_log:
            os.chmod(stdout_path, 0o600)
            os.chmod(stderr_path, 0o600)
            process = subprocess.Popen(
                bwrap_arguments,
                stdin=subprocess.DEVNULL,
                stdout=stdout_log,
                stderr=stderr_log,
                env=sanitized_launcher_env(),
                close_fds=True,
                start_new_session=True,
            )
            report["bwrap_launched"] = True

        try:
            report["bwrap_exit_code"] = int(process.wait(timeout=BWRAP_TIMEOUT_SECONDS))
        except subprocess.TimeoutExpired:
            report["timed_out"] = True
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except OSError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass
            report["bwrap_exit_code"] = int(
                process.returncode if process.returncode is not None else -1
            )

        guest_path = os.path.join(work_directory, "result.json")
        guest = read_guest_result(guest_path)
        sanitized = sanitize_guest(guest)
        report["guest_result_ok"] = True
        report["guest_all_passed"] = sanitized["all_passed"]
        report["guest_caps_ok"] = sanitized["caps_ok"]
        report["guest_caps"] = sanitized["caps"]
        report["guest_caps_checks"] = sanitized["caps_checks"]
        report["guest_uid_map_ok"] = sanitized["uid_map_ok"]
        report["guest_gid_map_ok"] = sanitized["gid_map_ok"]
        report["namespaces_differ"] = bool(namespaces_differ(sanitized))
        for name in CASE_NAMES:
            report["case_" + name] = (
                sanitized["cases"].get(name, {}).get("passed") is True
            )
        success = (
            guest.get("cases", {}).get("success", {})
            if isinstance(guest.get("cases"), dict)
            else {}
        )
        if isinstance(success, dict):
            if isinstance(success.get("uid"), int):
                report["success_uid"] = success["uid"]
            if isinstance(success.get("gid"), int):
                report["success_gid"] = success["gid"]
            if isinstance(success.get("open_fd_count"), int):
                report["success_open_fd_count"] = success["open_fd_count"]
            if isinstance(success.get("cap_effective"), int):
                report["success_cap_effective"] = success["cap_effective"]
    except BaseException as error:
        sys.stderr.write("fixture failure: " + type(error).__name__ + "\n")
    finally:
        if report_directory is not None:
            try:
                report["all_passed"] = bool(
                    report["argument_restriction_ok"]
                    and report["frozen_ok"]
                    and report["bwrap_launched"]
                    and not report["timed_out"]
                    and report["bwrap_exit_code"] == 0
                    and report["guest_result_ok"]
                    and report["guest_all_passed"]
                    and report["guest_caps_ok"]
                    and report["guest_uid_map_ok"]
                    and report["guest_gid_map_ok"]
                    and report["namespaces_differ"]
                    and all(report["case_" + name] is True for name in CASE_NAMES)
                )
                report_path = write_unique_report(
                    report_directory, REPORT_PREFIX, report
                )
                sys.stderr.write("report: " + os.path.basename(report_path) + "\n")
            except BaseException as error:
                sys.stderr.write("report failure: " + type(error).__name__ + "\n")
                report["all_passed"] = False
    return 0 if report["all_passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
