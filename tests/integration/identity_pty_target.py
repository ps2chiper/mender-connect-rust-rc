#!/usr/bin/python3
"""TEST-ONLY identity/PTY target (source-only; not executed here).

Runs as the fixed synthetic account `trial` (uid/gid 65534). Disables terminal
ECHO, emits one fixed proof line of JSON booleans, then answers only the fixed
commands `ping`, `size` and `background`. No arbitrary commands are accepted.
"""
import fcntl
import json
import os
import struct
import subprocess
import sys
import termios

EXPECTED_ID = 65534
ALLOWED_ENV = frozenset({"HOME", "USER", "LOGNAME", "TERM", "PATH", "LANG"})
ZERO_CAPS = ("CapInh", "CapPrm", "CapEff", "CapAmb")


def emit(marker, payload=None):
    text = marker if payload is None else marker + " " + json.dumps(
        payload, separators=(",", ":"))
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


def disable_echo():
    try:
        attrs = termios.tcgetattr(0)
        attrs[3] &= ~termios.ECHO
        termios.tcsetattr(0, termios.TCSANOW, attrs)
    except termios.error:
        pass


def priv_status():
    caps, groups = {name: -1 for name in ZERO_CAPS}, []
    try:
        with open("/proc/self/status") as handle:
            for line in handle:
                if line.startswith("Cap") and ":" in line:
                    name, _, value = line.partition(":")
                    caps[name.strip()] = int(value.strip(), 16)
                elif line.startswith("Groups:"):
                    _, _, value = line.partition(":")
                    groups = [int(token) for token in value.split()]
    except (OSError, ValueError):
        return None, []
    return caps, groups


def no_extra_fds():
    for name in os.listdir("/proc/self/fd"):
        try:
            fd = int(name)
        except ValueError:
            continue
        if fd <= 2 or not _fd_alive(fd):
            continue
        return False
    return True


def _fd_alive(fd):
    try:
        os.fstat(fd)
        return True
    except OSError:
        return False


def env_subset_ok():
    keys = set(os.environ)
    return (keys.issubset(ALLOWED_ENV)
            and {"HOME", "USER", "LOGNAME", "TERM"}.issubset(keys))


def winsize():
    try:
        raw = fcntl.ioctl(0, termios.TIOCGWINSZ, b"\x00" * 8)
        rows, cols = struct.unpack("HHHH", raw)[:2]
        return int(rows), int(cols)
    except OSError:
        return 0, 0


def emit_proof():
    caps, groups = priv_status()
    ruid, euid, suid = os.getresuid()
    rgid, egid, sgid = os.getresgid()
    emit("PROOF", {
        "uid_ok": ruid == euid == suid == EXPECTED_ID,
        "gid_ok": rgid == egid == sgid == EXPECTED_ID,
        "saved_ok": suid == EXPECTED_ID and sgid == EXPECTED_ID,
        "primary_group_ok": egid == EXPECTED_ID and EXPECTED_ID in groups,
        "caps_zero": caps is not None
        and all(caps.get(name, 1) == 0 for name in ZERO_CAPS),
        "fds_ok": no_extra_fds(),
        "env_ok": env_subset_ok(),
        "tty_ok": os.isatty(0) and os.isatty(1),
    })


def handle_background():
    proc = subprocess.Popen(["/usr/bin/sleep", "120"], process_group=0)
    try:
        pgid, sid = os.getpgid(proc.pid), os.getsid(proc.pid)
    except OSError:
        pgid, sid = proc.pid, -1
    emit("BACKGROUND", {"pid": proc.pid, "pgid": pgid, "sid": sid})


def main():
    disable_echo()
    emit_proof()
    for raw in sys.stdin:
        cmd = raw.strip()
        if cmd == "ping":
            emit("PONG")
        elif cmd == "size":
            emit("SIZE", dict(zip(("rows", "cols"), winsize())))
        elif cmd == "background":
            handle_background()


if __name__ == "__main__":
    main()
