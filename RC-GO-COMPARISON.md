# Go comparison — mender-connect-rust 0.1.0-rc.1

Direct comparison of the Rust release candidate against the upstream Go
`mender-connect` daemon on native Ubuntu 24.04 WSL2 x86-64. No QEMU, no physical
hardware, no WAN, no production Mender server.

## Reference

- Go binary: `go-original-matched-daemon`
- SHA-256: `364fc12f9e11cb99ed3c9ab51ca8d996299f20176518af17404e9c0f0230c3ce`
- Runtime: Go 1.22.2, upstream revision `ba393f11b6317f756bb86c5f3963061903728c01`
- Rust candidate: `mender-connect-rust 0.1.0-rc.1`, SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`

## Functional side-by-side

Both daemons were run separately against the same independent Go protocol peer
(`tests/integration/native_sessions_peer.go`, SHA-256
`1eefe70874a879b6b586e5a7cd44ecd6259350c28058ce7c8fcecae76d065849`) and the
same test-only Authentication1 mock on a private session bus. The peer drives
terminal, control, file-transfer v1/v2, and port-forward protocol scenarios on
loopback WebSocket.

| Implementation | Result | Checks | Peer exit | Daemon exit | Elapsed |
|---|---|---:|---:|---:|---:|
| Rust RC | PASS | 38/38 | 0 | 0 | 70.7 s |
| Go reference | PASS | 38/38 | 0 | 0 | 79.3 s |

The asserted check maps are identical:
`set(rust.checks.items()) ^ set(go.checks.items()) == {}`. Control version and
advertised protocol set also match: `version 1`, protocols `[1, 2, 3, 258, 259]`.

One non-asserted frame-count difference was observed: the Go run recorded
`shell_trailing_output = 1`; the Rust run did not record that key. It did not
change any peer check or result.

This is a protocol-level functional comparison against a peer, not the full
Mender server workflow matrix.

## UDP matrix — 5 s screen

All twelve previously qualified profile/rate points were run once at 3 x 5 s
for each implementation. Every run passed the fixed-rate validator with zero
observed loss, duplicates, or reordering.

| Profile | Go median Mbps | Rust RC median Mbps | Go loss | Rust loss |
|---|---:|---:|---:|---:|
| v1 1400 to_device | 32.82 | 32.85 | 0 | 0 |
| v1 1400 from_device | 22.38 | 22.38 | 0 | 0 |
| v1 1400 full_duplex | 32.71 / 33.53 | 33.07 / 33.54 | 0 | 0 |
| v1 4096 to_device | 95.42 | 96.00 | 0 | 0 |
| v1 4096 from_device | 32.76 | 32.75 | 0 | 0 |
| v1 4096 full_duplex | 64.98 / 65.43 | 65.29 / 65.44 | 0 | 0 |
| v2 1400 to_device | 178.04 | 177.83 | 0 | 0 |
| v2 1400 from_device | 89.07 | 89.13 | 0 | 0 |
| v2 1400 full_duplex | 88.62 / 88.55 | 88.67 / 88.67 | 0 | 0 |
| v2 4096 to_device | 261.21 | 261.13 | 0 | 0 |
| v2 4096 from_device | 65.49 | 65.48 | 0 | 0 |
| v2 4096 full_duplex | 65.43 / 65.40 | 65.44 / 65.44 | 0 | 0 |

Full-duplex cells are to-device / from-device. These are 5-second screening
observations, not the 60-second acceptance gate.

## UDP 60 s gate

Rust RC was run at 3 x 60 s for every qualified rate. The Go reference was run
fresh at 3 x 60 s on the two initially failing v1 full-duplex profiles; the
remaining Go profiles use the frozen 60 s acceptance evidence. A 10-repeat
control was then run on v1 4096 full-duplex for both implementations.

| Profile | Rust RC 60 s | Rust from-device loss | Go 60 s |
|---|---|---|---|
| v1 1400 to_device | PASS | 0 | PASS (prior) |
| v1 1400 from_device | PASS | 0 | PASS (prior) |
| v1 1400 full_duplex | **FAIL → PASS on rerun** | initial 275 / 727 / 849 (0.15–0.47%); rerun 0 | PASS (fresh, 0) |
| v1 4096 to_device | PASS | 0 | PASS (prior) |
| v1 4096 from_device | PASS | 0 | PASS (prior) |
| v1 4096 full_duplex | **FAIL → inconclusive** | initial 0 / 39 / 33; rerun 3 / 0 / 0; 10-repeat control below | 3/10 repeats passed in control |
| v2 1400 to_device | PASS | 0 | PASS (prior) |
| v2 1400 from_device | PASS | 0 | PASS (prior) |
| v2 1400 full_duplex | PASS | 0 | PASS (prior) |
| v2 4096 to_device | PASS | 0 | PASS (prior) |
| v2 4096 from_device | PASS | 0 | PASS (prior) |
| v2 4096 full_duplex | PASS | 0 | PASS (prior) |

The v1 full-duplex rows are the only non-passing profiles. In both, the
to-device row was clean and the from-device row lost packets; the 5 s screen
did not expose this.

### v1 4096 full-duplex: 10-repeat control

Ten independent repeats, each three fresh 60 s trials at 65.536 Mb/s:

| Implementation | Repeats passed | Trials lossy | Total from-device lost | Median lossy trial | Max |
|---|---:|---:|---:|---:|---:|
| Rust RC | 5/10 | 7/30 | 2,390 packets | 32 | 2,217 (1.85%) |
| Go reference | 3/10 | 14/30 | 2,569 packets | 79 | 1,431 (1.20%) |

All loss was from-device; to-device lost zero in all 60 trials. Most losses were
single digits to tens of packets; both implementations also produced one large
excursion. The Go reference failed more often than the RC in this sample.

### Failure isolation

- Predecessor `26eaacbbb7ade5a370d42f11a98cecc11e1a39d3974894c2b744c3d0d67d1380`
  was rerun on the two initially failing profiles: v1 1400 full-duplex failed
  2/3 trials (37 and 148 lost packets, one clean trial); v1 4096 full-duplex
  passed 3/3.
- The 10-repeat control shows v1 4096 full-duplex is not reproducible for either
  implementation. The earlier single clean Go 3 x 60 s run was not representative.
- Therefore the v1 1400 failure is intermittent and not unique to the version
  rebuild; the v1 4096 failure is a gate/environment limitation at 65.536 Mb/s,
  not an RC-specific regression.
- The RC cannot claim zero-loss at v1 4096 full-duplex on this host, but neither
  can the Go reference. A zero-loss claim would require a lower declared rate or
  a more isolated host/CPU environment.

## Scope limits

- Local loopback only: UDP target on IPv6 `::1`, WebSocket control on IPv4 `127.0.0.1`.
- Private session D-Bus and test-only authentication; not the installed Mender Auth service.
- 32-CPU host, native x64; no QEMU or physical hardware.
- Functional peer tests do not cover live-server PortForward/MenderClient/update workflows.
- Throughput numbers are local observations, not a WAN or production capacity claim.