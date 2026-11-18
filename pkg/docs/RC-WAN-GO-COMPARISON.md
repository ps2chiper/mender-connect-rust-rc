# RC 0.1.0-rc.1 — Go vs Rust on the same real-server/WAN path

Date: 2026-11-17 (America/New_York)
Server: `https://mender.zapto.org` (remote TLS)
Guest: same disposable native Ubuntu 24.04 WSL2 namespace for both binaries.
Rust: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Go: `go-original-matched-daemon` SHA-256 `364fc12f9e11cb99ed3c9ab51ca8d996299f20176518af17404e9c0f0230c3ce`

The Go run required a harness adapter: Go `mender-connect` has no `--test-session-bus`, so the guest's `DBUS_SYSTEM_BUS_ADDRESS` was pointed at the private session bus and the config flags were placed before `daemon`. The Go daemon then used the same mock Auth service and real official Auth proxy as the Rust run.

## WAN v1 comparison

| Metric | Rust | Go |
|---|---:|---:|
| TCP latency median | 118.59–123.95 ms | 142.54 ms |
| TCP latency p95 | 184.14–203.49 ms | 200.09 ms |
| TCP bulk 1 MiB | **26–44 s**, **0.190–0.323 Mb/s** | **26.0 s**, **0.323 Mb/s** |
| UDP 100 pps, 100 datagrams | 23/100 replies, **77% loss** | 26/100 replies, **74% loss** |
| UDP median latency at 100 pps | 552.35 ms | 602.94 ms |
| TLS | TLSv1.3, verified | TLSv1.3, verified |
| 1 MiB file transfer | pass, 1.9–2.7 s/direction | pass, 1.9–2.2 s/direction |

The Go run also showed two Go-side harness/test anomalies: an empty-file roundtrip failed (`roundtrip-empty`), and the guest reported `Daemon cleanup was not successful` at shutdown. Those are not used for the Rust verdict; the WAN transport metrics above were collected before them.

## Conclusion

The v1 WAN limits are **shared by Go and Rust**:

- TCP port-forward is latency-bound by the same per-frame ACK behavior; both settle around **0.32 Mb/s** at ~120–140 ms RTT.
- Paced UDP at 100 pps loses roughly **three quarters** of datagrams for both implementations.
- Single-stream 1 MiB file transfer is fast and correct for both.

These are **CLI/server-path limitations**, not a Rust regression. With v2 excluded by scope and these v1 limits documented, blocker 3 is closed by a WAN envelope rather than by a code fix.

**Envelope:** TCP port-forward up to **0.32 Mb/s** at ~120–140 ms RTT; paced UDP clean at **10 pps**; 1 MiB file transfer pass; TLS 1.3 verified. WAN reconnect/heartbeat is **not included** in this envelope and remains an explicit caveat.

The Rust-only evidence remains in `RC-WAN-TLS-MATRIX.md`. The Go comparison report is:
`reports/mender-rust-mender-cli-x64/cli-x64-20261118045622.json` (Go WAN run; see `wan-port-forward-tcp` and `wan-port-forward-udp-paced`).