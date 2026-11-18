#!/usr/bin/env python3
"""Prepare and run a local-only x86_64 terminal stability soak."""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

BASE = Path.home() / '.local/share/duo-aider/mender-rust-live-sandbox'
EXPECTED_BINARY_SHA = ''  # Required explicit CLI hash, assigned once by main.
LABEL_RE = re.compile(r'[A-Za-z0-9-]{1,8}')
PROJECT_BINARY = Path.home() / 'projects/mender-connect-rust-trial/target/release/mender-connect-rust'
REPO_ROOT = Path.home() / '.local/share/duo-aider/mender-rust-assessment/mender-connect'


def _sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b''):
            digest.update(chunk)
    return digest.hexdigest()


def _json_sha(value):
    data = json.dumps(value, sort_keys=True, separators=(',', ':')).encode()
    return hashlib.sha256(data).hexdigest()


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_seconds(value, source='seconds'):
    if not _is_int(value):
        raise ValueError(source + ' must be an integer number of seconds')
    if not 30 <= value <= 3600:
        raise ValueError(source + ' must be between 30 and 3600 inclusive')
    return value


def _require_platform():
    if platform.machine() != 'x86_64':
        raise RuntimeError('this harness requires an x86_64 host')
    if platform.system() != 'Linux':
        raise RuntimeError('this harness requires a Linux host')


def _state_for(label):
    if not isinstance(label, str) or LABEL_RE.fullmatch(label) is None:
        raise ValueError('label must be 1..8 simple alphanumeric/hyphen characters')
    return BASE / ('s-' + label)


def _tree_hashes(root):
    root = Path(root)
    values = {}
    for path in sorted(root.rglob('*')):
        if path.is_file() or path.is_symlink():
            values[path.relative_to(root).as_posix()] = _sha256(path)
    return values


def _verify_x86_64(path):
    header = Path(path).read_bytes()[:20]
    if len(header) < 20 or header[:4] != b'\x7fELF':
        raise RuntimeError('candidate is not an ELF file: ' + str(path))
    if header[4] != 2 or header[5] != 1:
        raise RuntimeError('candidate is not 64-bit little-endian ELF: ' + str(path))
    machine = int.from_bytes(header[18:20], 'little')
    if machine != 62:
        raise RuntimeError('candidate ELF machine is not x86_64: ' + str(path))


def _find_project_binary():
    candidate = PROJECT_BINARY
    if not candidate.is_file():
        raise RuntimeError('current project binary is missing at exact path: ' + str(candidate))
    digest = _sha256(candidate)
    if digest != EXPECTED_BINARY_SHA:
        raise RuntimeError('mender-connect-rust SHA-256 mismatch: ' + digest)
    _verify_x86_64(candidate)
    return candidate


def _find_repo():
    candidate = REPO_ROOT
    if not (candidate / 'go.mod').is_file():
        raise RuntimeError('mender-connect repository is missing go.mod at exact path: ' + str(candidate))
    if not (candidate / 'vendor').is_dir():
        raise RuntimeError('mender-connect repository is missing vendor at exact path: ' + str(candidate))
    return candidate


def _outer_command():
    path = BASE / 'outer-command.json'
    command = json.loads(path.read_text())
    if not isinstance(command, list) or not all(isinstance(item, str) for item in command):
        raise RuntimeError('outer-command.json must contain a string array')
    if '--die-with-parent' not in command:
        raise RuntimeError('original outer command must retain --die-with-parent')
    return command


def _rewrite_command(command, state):
    replacements = {
        str(BASE / 'proof/observer.sock'): str(state / 'proof/observer.sock'),
        str(BASE / 'bundle/etc'): str(state / 'bundle/etc'),
        str(BASE / 'bundle'): str(state / 'bundle'),
        str(BASE / 'work'): str(state / 'work'),
        str(BASE / 'proof'): str(state / 'proof'),
    }
    ordered = sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True)
    result = []
    for item in command:
        value = item
        for old, new in ordered:
            if value == old:
                value = new
                break
        result.append(value)
    if '--die-with-parent' not in result:
        raise RuntimeError('rewritten outer command lost --die-with-parent')
    return result


def _find_inner_shell(bundle):
    direct = bundle / 'inner-shell'
    if direct.is_file():
        return direct
    matches = [path for path in bundle.rglob('inner-shell') if path.is_file()]
    if len(matches) != 1:
        raise RuntimeError('expected exactly one inner-shell in bundle')
    return matches[0]


def _guest_helper_block():
    return r'''resources_path=proof/'resources.jsonl'
resource_state={'started':None,'last':0.0,'baseline':None,'peaks':{'fd':0,'threads':0,'rss_kib':0},'samples':0}
def _sample_resources(pid,now):
 status=Path('/proc/'+str(pid)+'/status').read_text()
 rss_kib=0;threads=0
 for line in status.splitlines():
  if line.startswith('VmRSS:'):rss_kib=int(line.split()[1])
  elif line.startswith('Threads:'):threads=int(line.split()[1])
 fd_count=len(os.listdir('/proc/'+str(pid)+'/fd'))
 elapsed=max(0.0,now-resource_state['started'])
 sample={'t':round(elapsed,3),'pid':pid,'fd':fd_count,'threads':threads,'rss_kib':rss_kib}
 with resources_path.open('a') as handle:handle.write(json.dumps(sample,separators=(',',':'))+'\n')
 resource_state['samples']+=1
 resource_state['peaks']['fd']=max(resource_state['peaks']['fd'],fd_count)
 resource_state['peaks']['threads']=max(resource_state['peaks']['threads'],threads)
 resource_state['peaks']['rss_kib']=max(resource_state['peaks']['rss_kib'],rss_kib)
 if fd_count>96 or threads>32 or rss_kib>196608:raise RuntimeError('Sandbox resource ceiling exceeded')
 if elapsed>=30:
  if resource_state['baseline'] is None:
   resource_state['baseline']={'fd':fd_count,'rss_kib':rss_kib}
  else:
   baseline=resource_state['baseline']
   if fd_count>baseline['fd']+8 or rss_kib>baseline['rss_kib']+32768:raise RuntimeError('Sandbox resource warmed baseline exceeded')
 return sample'''


def _instrument_guest(text):
    old_out = "out={'mode':mode,'uid':os.geteuid(),'network_namespace':os.readlink('/proc/self/ns/net'),'host_home_absent':not Path('/home/jason').exists(),'device_mount_absent':not Path('/device').exists(),'private_bus':True}"
    if text.count(old_out) != 1:
        raise RuntimeError('guest.py fixed metadata line not found exactly once')
    text = text.replace(old_out, old_out + '\n' + _guest_helper_block())

    old_daemon = " daemon=launch('rust-daemon',['/runtime/mender-connect-rust','daemon','--test-session-bus','--config',str(proof/'connect.json'),'--fallback-config','/proof/absent.json'])"
    if text.count(old_daemon) != 1:
        raise RuntimeError('guest.py daemon launch line not found exactly once')
    new_daemon = old_daemon + "\n (proof/'daemon.pid').write_text(str(daemon.pid))\n resource_state['started']=time.monotonic()\n resource_state['last']=resource_state['started']"
    text = text.replace(old_daemon, new_daemon)

    old_loop = " while time.monotonic()<deadline and not (proof/'result.json').exists():\n  if daemon.poll() is not None:raise RuntimeError('Sandbox daemon exited early')\n  time.sleep(.05)"
    new_loop = " while time.monotonic()<deadline and not (proof/'result.json').exists():\n  if daemon.poll() is not None:raise RuntimeError('Sandbox daemon exited early')\n  now=time.monotonic()\n  if now-resource_state['last']>=1.0:\n   resource_state['last']=now\n   _sample_resources(int((proof/'daemon.pid').read_text()),now)\n  time.sleep(.05)"
    if text.count(old_loop) != 1:
        raise RuntimeError('guest.py daemon poll loop not found exactly once')
    text = text.replace(old_loop, new_loop)

    old_write = " (proof/'guest-result.json').write_text(json.dumps(out,indent=2))"
    new_write = " out['resource_peaks']=resource_state['peaks']\n out['resource_samples']=resource_state['samples']\n if resource_state['baseline'] is not None:out['resource_baseline']=resource_state['baseline']\n" + old_write
    if text.count(old_write) != 1:
        raise RuntimeError('guest.py result write line not found exactly once')
    text = text.replace(old_write, new_write)
    return text


def cmd_prepare(args):
    _require_platform()
    seconds = _validate_seconds(args.seconds, '--seconds')
    state = _state_for(args.label)
    script_dir = Path(__file__).resolve().parent
    state.mkdir(mode=0o700, parents=True, exist_ok=False)
    (state / 'work').mkdir(mode=0o700)
    (state / 'proof').mkdir(mode=0o700)

    observer_sock = state / 'proof/observer.sock'
    if len(os.fsencode(str(observer_sock))) >= 108:
        raise RuntimeError('observer.sock path must be fewer than 108 bytes')

    original_command = _outer_command()
    original_command_sha = _sha256(BASE / 'outer-command.json')

    bundle_src = BASE / 'terminal3-bundle'
    if not bundle_src.is_dir():
        raise RuntimeError('terminal3-bundle is missing')
    shutil.copytree(bundle_src, state / 'bundle')
    shutil.copytree(BASE / 'bundle/etc', state / 'bundle/etc', dirs_exist_ok=True)
    (state / 'bundle/etc/shells').write_text('/bin/sh\n/bin/bash\n/runtime/inner-shell\n')

    inner_shell = _find_inner_shell(state / 'bundle')
    if b'--die-with-parent' in inner_shell.read_bytes():
        raise RuntimeError('inner-shell must not contain --die-with-parent')

    source_bin = _find_project_binary()
    frozen_bin = state / 'bundle/mender-connect-rust'
    if frozen_bin.exists() or frozen_bin.is_symlink():
        frozen_bin.unlink()
    shutil.copy2(source_bin, frozen_bin)
    frozen_bin_sha = _sha256(frozen_bin)
    if frozen_bin_sha != EXPECTED_BINARY_SHA:
        raise RuntimeError('frozen mender-connect-rust SHA-256 mismatch')

    command = _rewrite_command(original_command, state)
    (state / 'outer-command.json').write_text(json.dumps(command, indent=2) + '\n')

    guest = state / 'bundle/guest.py'
    guest_text = guest.read_text()
    old_deadline = "else 280 if mode=='approved-features'"
    if guest_text.count(old_deadline) != 1:
        raise RuntimeError('guest.py approved-features deadline not found exactly once')
    guest_text = guest_text.replace(old_deadline, "else %d if mode=='approved-features'" % (seconds + 30))
    guest.write_text(_instrument_guest(guest_text))

    peer_source = BASE / 'local-peer-source'
    if not peer_source.is_dir():
        raise RuntimeError('local-peer-source is missing')
    shutil.copytree(peer_source, state / 'source')

    pty_peers = [path for path in (state / 'source').rglob('sandbox_pty_peer.go')]
    if len(pty_peers) != 1:
        raise RuntimeError('expected exactly one sandbox_pty_peer.go in local-peer-source')
    peer_go = pty_peers[0].parent / 'x64_terminal_stability_peer.go'
    pty_peers[0].unlink()

    fourhour = [path for path in (state / 'source').rglob('fourhour_file_peer.go') if path.is_file()]
    if len(fourhour) != 1:
        raise RuntimeError('expected exactly one fourhour_file_peer.go in local-peer-source')
    fourhour_go = fourhour[0]
    fourhour_text = fourhour_go.read_text()
    watchdog = 'time.After(80 * time.Second)'
    if fourhour_text.count(watchdog) != 1:
        raise RuntimeError('fourhour_file_peer.go time.After(80 * time.Second) not found exactly once')
    fourhour_go.write_text(fourhour_text.replace(watchdog, 'time.After(%d * time.Second)' % (seconds + 90)))

    go_files_before = sorted(str(path) for path in (state / 'source').rglob('*.go') if not path.name.endswith('_test.go'))
    if not go_files_before:
        raise RuntimeError('no Go source files found in copied peer source')
    subprocess.run(['gofmt', '-w'] + go_files_before, check=True, timeout=60)

    supplied_peer_go = script_dir / 'x64_terminal_stability_peer.go'
    if not supplied_peer_go.is_file():
        raise RuntimeError('x64_terminal_stability_peer.go must sit alongside this script')
    supplied_peer_sha = _sha256(supplied_peer_go)
    shutil.copy2(supplied_peer_go, peer_go)
    if _sha256(peer_go) != supplied_peer_sha:
        raise RuntimeError('x64_terminal_stability_peer.go changed while being staged')

    go_files = sorted(str(path) for path in (state / 'source').rglob('*.go') if not path.name.endswith('_test.go'))
    repo = _find_repo()
    build_env = os.environ.copy()
    build_env['GOPROXY'] = 'off'
    build_env['GOSUMDB'] = 'off'
    peer_bin = state / 'peer'
    subprocess.run(['go', 'build', '-mod=vendor', '-o', str(peer_bin)] + go_files,
                   cwd=str(repo), env=build_env, check=True, timeout=90)
    _verify_x86_64(peer_bin)
    peer_sha = _sha256(peer_bin)
    controller_sha = _sha256(Path(__file__).resolve())

    bundle_hashes = _tree_hashes(state / 'bundle')
    source_hashes = _tree_hashes(state / 'source')
    manifest = {
        'label': args.label,
        'seconds': seconds,
        'state': str(state),
        'command': command,
        'command_sha256': _json_sha(command),
        'binary': {'path': str(frozen_bin), 'sha256': frozen_bin_sha, 'expected_sha256': EXPECTED_BINARY_SHA},
        'bundle': {'root': 'bundle', 'files': bundle_hashes},
        'peer': {'path': str(peer_bin), 'sha256': peer_sha},
        'source': {'root': 'source', 'files': source_hashes,
                   'x64_terminal_stability_peer.go': _sha256(peer_go)},
        'controller': {'path': str(Path(__file__).resolve()), 'sha256': controller_sha},
        'observer_sock': str(observer_sock),
        'original_outer_command_sha256': original_command_sha,
        'architecture': 'x86_64',
        'local_dummy_only': True,
        'qemu': False,
    }
    manifest_path = state / 'manifest.json'
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n')
    print(manifest_path)
    return 0


def _teardown(processes):
    for process in reversed(processes):
        if process.poll() is not None:
            continue
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass


def _load_json_or_none(path):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return None


def _peaks_from_jsonl(path):
    peaks = {'fd': 0, 'threads': 0, 'rss_kib': 0}
    try:
        for line in Path(path).read_text().splitlines():
            if not line.strip():
                continue
            sample = json.loads(line)
            peaks['fd'] = max(peaks['fd'], int(sample.get('fd', 0)))
            peaks['threads'] = max(peaks['threads'], int(sample.get('threads', 0)))
            peaks['rss_kib'] = max(peaks['rss_kib'], int(sample.get('rss_kib', 0)))
    except Exception:
        return None
    return peaks


def _command_matches(manifest, state):
    try:
        if _sha256(BASE / 'outer-command.json') != manifest.get('original_outer_command_sha256'):
            return False
        expected = _rewrite_command(_outer_command(), state)
        return (manifest.get('command') == expected and
                manifest.get('command_sha256') == _json_sha(expected))
    except Exception:
        return False


def _source_matches(manifest, state):
    try:
        source = manifest.get('source') or {}
        files = source.get('files')
        if not isinstance(files, dict):
            return False
        if _tree_hashes(state / 'source') != files:
            return False
        return _sha256(state / 'source/x64_terminal_stability_peer.go') == source.get('x64_terminal_stability_peer.go')
    except Exception:
        return False


def _verify_manifest_assets(manifest, state):
    errors = []
    if not isinstance(manifest, dict):
        return ['manifest is not a JSON object']
    if manifest.get('label') != state.name[2:]:
        errors.append('manifest label mismatch')
    if manifest.get('state') != str(state):
        errors.append('manifest state mismatch')

    command = manifest.get('command')
    if not isinstance(command, list) or not command or not all(isinstance(item, str) for item in command):
        errors.append('manifest command is not a string array')
    else:
        if not _command_matches(manifest, state):
            errors.append('manifest confinement command does not exactly match rewritten original')
        if not Path(command[0]).is_file():
            errors.append('manifest command executable missing')

    controller = manifest.get('controller') or {}
    if _sha256(Path(__file__).resolve()) != controller.get('sha256'):
        errors.append('controller source hash changed')

    binary = manifest.get('binary') or {}
    try:
        if _sha256(state / 'bundle/mender-connect-rust') != binary.get('sha256'):
            errors.append('candidate binary hash changed')
    except Exception as error:
        errors.append('candidate binary hash unavailable: ' + str(error))
    if binary.get('sha256') != EXPECTED_BINARY_SHA:
        errors.append('candidate binary is not the frozen build')

    peer = manifest.get('peer') or {}
    try:
        if _sha256(state / 'peer') != peer.get('sha256'):
            errors.append('peer binary hash changed')
    except Exception as error:
        errors.append('peer binary hash unavailable: ' + str(error))

    if not _source_matches(manifest, state):
        errors.append('source hash set changed')

    expected_bundle = (manifest.get('bundle') or {}).get('files')
    if not isinstance(expected_bundle, dict):
        errors.append('bundle file manifest missing')
    elif _tree_hashes(state / 'bundle') != expected_bundle:
        errors.append('bundle hash set changed')

    for path in (state / 'bundle/mender-connect-rust', state / 'peer'):
        try:
            _verify_x86_64(path)
        except Exception as error:
            errors.append(str(error))
    return errors


def _peer_result_ok(peer, exit_code):
    return (isinstance(peer, dict) and
            isinstance(peer.get('passed'), list) and
            len(peer['passed']) > 0 and
            all(isinstance(item, str) and item for item in peer['passed']) and
            'error' not in peer and
            exit_code == 0)


def _guest_result_ok(guest, exit_code):
    if not isinstance(guest, dict) or exit_code != 0 or guest.get('passed') is not True:
        return False
    if 'remaining_shell_or_sleep' not in guest:
        return False
    remaining = guest.get('remaining_shell_or_sleep')
    return remaining == []


def _metrics_ok(metrics, seconds):
    if not isinstance(metrics, dict) or seconds is None:
        return False
    if metrics.get('passed') is not True:
        return False
    soak_seconds = metrics.get('soak_seconds')
    if not _is_int(soak_seconds) or soak_seconds != seconds:
        return False
    elapsed = metrics.get('elapsed_seconds')
    if not _is_number(elapsed) or elapsed < seconds:
        return False
    commands = metrics.get('commands')
    if not _is_int(commands) or commands < 2:
        return False
    if metrics.get('resize_verified') is not True:
        return False
    pings = metrics.get('pings')
    if not _is_int(pings) or pings < (1 if seconds >= 90 else 0):
        return False
    if seconds >= 90:
        pongs = metrics.get('pongs')
        if not _is_int(pongs) or pongs < pings:
            return False
    return True


def _resources_ok(peaks, samples):
    if not _is_int(samples) or samples <= 0:
        return False
    if not isinstance(peaks, dict):
        return False
    limits = {'fd': 96, 'threads': 32, 'rss_kib': 196608}
    for key, limit in limits.items():
        value = peaks.get(key)
        if not _is_int(value) or value <= 0 or value > limit:
            return False
    return True


def cmd_run(args):
    _require_platform()
    state = _state_for(args.label)
    summary_path = state / 'summary.json'
    processes = []
    handles = []
    started = time.monotonic()
    manifest = None
    seconds = None
    peer = None
    guest = None
    summary = {
        'passed': False,
        'label': args.label,
        'seconds': None,
        'state': str(state),
        'architecture': 'x86_64',
        'local_dummy_only': True,
        'qemu': False,
        'elapsed_seconds': None,
        'error': None,
        'exits': {'peer': None, 'guest': None},
        'peer': None,
        'stability_metrics': None,
        'guest': None,
        'resource_peaks': None,
        'resource_samples': None,
        'candidate': {'sha256_before': None, 'sha256_after': None, 'unchanged': False},
        'controller': {'sha256_before': None, 'sha256_after': None, 'unchanged': False},
        'command': {'sha256_before': None, 'sha256_after': None, 'unchanged': False},
        'assets': {'manifest_verified': False, 'bundle_unchanged': False,
                   'peer_unchanged': False, 'source_unchanged': False,
                   'command_unchanged': False},
        'hashes_unchanged': False,
    }
    try:
        if not state.is_dir():
            raise RuntimeError('state directory is missing; run prepare first')
        manifest_path = state / 'manifest.json'
        if not manifest_path.is_file():
            raise RuntimeError('state manifest is missing')
        manifest = json.loads(manifest_path.read_text())
        if not isinstance(manifest, dict):
            raise RuntimeError('state manifest must be a JSON object')
        seconds = _validate_seconds(manifest.get('seconds'), 'manifest seconds')
        summary['seconds'] = seconds

        errors = _verify_manifest_assets(manifest, state)
        if errors:
            raise RuntimeError('; '.join(errors))
        summary['assets']['manifest_verified'] = True
        summary['candidate']['sha256_before'] = manifest['binary']['sha256']
        summary['controller']['sha256_before'] = manifest['controller']['sha256']
        summary['command']['sha256_before'] = manifest.get('command_sha256')

        allowed = sorted(os.sched_getaffinity(0))
        if not allowed:
            raise RuntimeError('no permitted CPU available')
        first_cpu = allowed[0]
        os.sched_setaffinity(0, {first_cpu})

        proof = state / 'proof'
        peer_log = (proof / 'peer-soak.log').open('w')
        handles.append(peer_log)
        peer = subprocess.Popen([str(state / 'peer'), str(proof), 'sandbox'],
                                env={'PATH': '/usr/bin:/bin', 'SOAK_SECONDS': str(seconds)},
                                cwd=str(state), stdout=peer_log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        processes.append(peer)
        try:
            os.sched_setaffinity(peer.pid, {first_cpu})
        except (OSError, ProcessLookupError):
            pass

        socket_end = time.monotonic() + 5
        while not (proof / 'observer.sock').exists():
            if peer.poll() is not None:
                raise RuntimeError('offline peer exited before socket readiness')
            if time.monotonic() > socket_end:
                raise RuntimeError('offline peer socket timeout')
            time.sleep(0.05)

        guest_log = (proof / 'guest-soak.log').open('w')
        handles.append(guest_log)
        guest = subprocess.Popen(manifest['command'],
                                 env={'PATH': '/usr/bin:/bin', 'HOME': '/work',
                                      'MENDER_TRIAL_INITIAL_TOKEN': 'trial-local-token',
                                      'SANDBOX_MODE': 'approved-features'},
                                 cwd=str(state), stdout=guest_log, stderr=subprocess.STDOUT,
                                 start_new_session=True)
        processes.append(guest)
        try:
            os.sched_setaffinity(guest.pid, {first_cpu})
        except (OSError, ProcessLookupError):
            pass

        deadline = started + seconds + 90
        while time.monotonic() < deadline:
            if peer.poll() is not None and guest.poll() is not None:
                break
            time.sleep(0.1)
        if peer.poll() is None or guest.poll() is None:
            raise RuntimeError('combined soak deadline exceeded')
    except Exception as error:
        summary['error'] = str(error)
    finally:
        _teardown(processes)
        for handle in handles:
            handle.close()

        if peer is not None:
            summary['exits']['peer'] = peer.returncode
        if guest is not None:
            summary['exits']['guest'] = guest.returncode

        if state.is_dir():
            proof = state / 'proof'
            if summary['peer'] is None:
                summary['peer'] = _load_json_or_none(proof / 'result.json')
            if summary['stability_metrics'] is None:
                summary['stability_metrics'] = _load_json_or_none(proof / 'stability-metrics.json')
            if summary['guest'] is None:
                summary['guest'] = _load_json_or_none(proof / 'guest-result.json')
            if isinstance(summary['guest'], dict):
                summary['resource_samples'] = summary['guest'].get('resource_samples')
                if summary['resource_peaks'] is None:
                    summary['resource_peaks'] = summary['guest'].get('resource_peaks')
            if summary['resource_peaks'] is None:
                summary['resource_peaks'] = _peaks_from_jsonl(proof / 'resources.jsonl')

            candidate_after = _sha256(state / 'bundle/mender-connect-rust') if (state / 'bundle/mender-connect-rust').is_file() else None
            controller_after = _sha256(Path(__file__).resolve())
            peer_after = _sha256(state / 'peer') if (state / 'peer').is_file() else None
            summary['candidate']['sha256_after'] = candidate_after
            summary['controller']['sha256_after'] = controller_after
            summary['candidate']['unchanged'] = summary['candidate']['sha256_before'] is not None and candidate_after == summary['candidate']['sha256_before']
            summary['controller']['unchanged'] = summary['controller']['sha256_before'] is not None and controller_after == summary['controller']['sha256_before']

            expected_peer = manifest.get('peer', {}).get('sha256') if isinstance(manifest, dict) else None
            summary['assets']['peer_unchanged'] = expected_peer is not None and peer_after == expected_peer
            summary['assets']['source_unchanged'] = _source_matches(manifest, state) if isinstance(manifest, dict) else False
            summary['assets']['command_unchanged'] = _command_matches(manifest, state) if isinstance(manifest, dict) else False
            if isinstance(manifest, dict):
                try:
                    summary['command']['sha256_after'] = _json_sha(_rewrite_command(_outer_command(), state))
                except Exception:
                    summary['command']['sha256_after'] = None
                summary['command']['unchanged'] = (summary['command']['sha256_before'] is not None and
                                                   summary['command']['sha256_after'] == summary['command']['sha256_before'] and
                                                   summary['assets']['command_unchanged'])
            if isinstance(manifest, dict):
                summary['assets']['bundle_unchanged'] = _tree_hashes(state / 'bundle') == (manifest.get('bundle') or {}).get('files')
            else:
                summary['assets']['bundle_unchanged'] = False

            summary['hashes_unchanged'] = bool(summary['candidate']['unchanged'] and
                                               summary['controller']['unchanged'] and
                                               summary['command']['unchanged'] and
                                               summary['assets']['bundle_unchanged'] and
                                               summary['assets']['peer_unchanged'] and
                                               summary['assets']['source_unchanged'] and
                                               summary['assets']['command_unchanged'])

            peer_ok = _peer_result_ok(summary['peer'], summary['exits']['peer'])
            guest_ok = _guest_result_ok(summary['guest'], summary['exits']['guest'])
            metrics_ok = _metrics_ok(summary['stability_metrics'], seconds)
            resources_ok = _resources_ok(summary['resource_peaks'], summary['resource_samples'])
            summary['passed'] = bool(summary['error'] is None and
                                     summary['assets']['manifest_verified'] and
                                     peer_ok and guest_ok and metrics_ok and resources_ok and
                                     summary['hashes_unchanged'])
            summary['elapsed_seconds'] = round(time.monotonic() - started, 3)
            summary_path.write_text(json.dumps(summary, indent=2) + '\n')
        else:
            summary['elapsed_seconds'] = round(time.monotonic() - started, 3)

    if summary_path.is_file():
        print(summary_path)
    return 0 if summary['passed'] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description='local x86_64 terminal stability soak controller')
    subparsers = parser.add_subparsers(dest='command', required=True)
    prepare = subparsers.add_parser('prepare')
    prepare.add_argument('--label', required=True)
    prepare.add_argument('--seconds', required=True, type=int, choices=range(30, 3601))
    prepare.add_argument('--expected-sha256', required=True)
    prepare.set_defaults(func=cmd_prepare)
    run = subparsers.add_parser('run')
    run.add_argument('--label', required=True)
    run.add_argument('--expected-sha256', required=True)
    run.set_defaults(func=cmd_run)
    args = parser.parse_args(argv)
    if not re.fullmatch(r'[0-9a-f]{64}', args.expected_sha256):
        raise SystemExit('Explicit lower-case SHA256 required')
    global EXPECTED_BINARY_SHA
    EXPECTED_BINARY_SHA = args.expected_sha256
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
