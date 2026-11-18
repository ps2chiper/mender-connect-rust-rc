# RC 0.1.0-rc.1 — real-server/WAN/TLS matrix

> **Superseded status note:** after the Go comparison, blocker 3 is closed by the documented v1 WAN envelope in `RC-WAN-GO-COMPARISON.md`. WAN reconnect/heartbeat remains an explicit caveat. The measurements below are the Rust-side evidence.

Date: 2026-11-17 (America/New_York)
Binary: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Server: `https://mender.zapto.org` (remote, TLS)
Guest: disposable native Ubuntu 24.04 WSL2 namespace; private session bus; official Mender Auth test credentials.

## Functional matrix

Run `cli-x64-20261118044210.json`: **32/32 pass**, including:

- Terminal over the remote server.
- 1 MiB upload + download; byte-for-byte match. Upload 2.07 s, download 2.42 s in the best run (1.9–2.7 s across runs).
- TCP port-forward through `mender-cli port-forward` with 10 round-trip latency samples and a 1 MiB echoed payload.
- UDP port-forward through the real server with paced traffic.
- TLS certificate verification: **TLSv1.3, Verification OK**.

## Measured WAN behavior

| Metric | Result |
|---|---|
| TCP port-forward median RTT | **118–124 ms** |
| TCP port-forward p95 RTT | **184–203 ms** |
| TCP v1 bulk (1 MiB, 64 KiB chunks) | **26–44 s**, **0.19–0.32 Mb/s** |
| 1 MiB file transfer | **1.9–2.7 s** per direction |
| TLS | TLSv1.3, verified |

The TCP port-forward rate is latency-bound: v1 waits for an ACK per frame, and at ~120 ms RTT the 1 MiB transfer collapses to 0.19–0.32 Mb/s. This is far below the local v1 result (tens of Mb/s) and is a real-server/WAN limitation, not a functional failure.

## Paced UDP finding

A true paced sweep (`cli-x64-20261118044536.json`) sent 100 datagrams at each target rate:

| Target rate | Replies | Loss |
|---:|---:|---:|
| **10 pps** | **100/100** | **0%** |
| 20 pps | 51/100 | 49% |
| 50 pps | 0/100 | 100% |
| 100 pps | 0/100 | 100% |

A separate fresh 100 pps run (`cli-x64-20261118044359.json`) returned **23/100** replies with 77% loss and 552 ms median latency. Above roughly 10 pps, the real-server UDP port-forward path is not holding the offered load in this environment.

The sweep’s later zeros also coincide with the possibility that the `mender-cli` port-forward process/session ended before those rates; the run did not preserve a liveness assertion per rate. Either way, **sustained paced UDP above 10 pps is not qualified**, and the failure is in the server/CLI path available here, not proven to be in the RC.

## Version coverage

**v2 protocol is explicitly out of scope per user direction** because the `mender-cli` side is also broken. The real server/CLI negotiated **port-forward v1** (`proto 3`) for these tests; file transfer also used v1 (`proto 2`). No v2 qualification is claimed.

- **v1 TCP/UDP over real TLS/WAN:** functionally exercised; TCP throughput and UDP pacing are poor at WAN latency.
- **v2 port-forward and v2 file transfer over real server/WAN:** excluded by scope.

## Verdict

Blocker 3 is **not closed**:

1. Functional terminal/file-transfer/TCP/UDP/TLS paths pass.
2. TCP v1 bulk is 0.19–0.32 Mb/s at ~120 ms RTT; v1’s ACK-per-frame behavior is the likely cause.
3. Paced UDP is only clean at ~10 pps here; 20 pps and above lose or stall.
4. v2 forwarding/file-transfer is excluded by scope; no v2 qualification is claimed.
5. WAN reconnect/heartbeat behavior was not exercised.

**What would close it:** an accepted WAN performance envelope (TCP rate and UDP pacing), plus WAN reconnect/heartbeat evidence. The RC’s local v2 implementation is no longer part of this blocker.

## Evidence

- `reports/mender-rust-mender-cli-x64/cli-x64-20261118044210.json` — 32/32 functional WAN/TLS matrix.
- `reports/mender-rust-mender-cli-x64/cli-x64-20261118044536.json` — paced UDP sweep; 10 pps pass, 20+ fail.
- `reports/mender-rust-mender-cli-x64/cli-x64-20261118044359.json` — fresh 100 pps: 23/100.
- `trial-tools/live_wan_matrix_rc.py`, `trial-tools/live_wan_udp_sweep_rc.py` — harnesses.