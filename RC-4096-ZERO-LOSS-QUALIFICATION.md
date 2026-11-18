# v1 UDP 4096 full-duplex zero-loss qualification

Date: 2026-11-18 (America/New_York)
Candidate: `mender-connect-rust 0.1.0-rc.2`
Daemon SHA-256: `2d329d1fdc050f52cfb3c2b4df83b64a3557b8f94369425e740487620238845e`
Helper SHA-256: `ab2933e718f4f502203c7b6a2716684d4162058eb3904dad0c4de7ef3b1d9a1c`
Target: native Ubuntu 24.04 WSL2 x86-64 only. No QEMU, no physical hardware,
no WAN, no server.

## Result

**10 / 10 independent repeats passed; 30 / 30 trials passed; 60 / 60
per-direction measurements had zero lost, duplicate and reordered packets.**

- Profile: v1 UDP, 4096-byte datagrams, full duplex
- Requested rate: 65.536 Mb/s per direction
- Each repeat: three fresh 60-second trials
- Delivered goodput range: **65.415–65.433 Mb/s** (both directions)
- Peer source and daemon SHA-256 were checked before and after every run
- No harness errors; all ten reports have `passed: true`

Per-repeat aggregate losses:

| Repeat | Trials | Loss/dup/reorder |
|---:|---:|---:|
| 1 | 3 | 0 |
| 2 | 3 | 0 |
| 3 | 3 | 0 |
| 4 | 3 | 0 |
| 5 | 3 | 0 |
| 6 | 3 | 0 |
| 7 | 3 | 0 |
| 8 | 3 | 0 |
| 9 | 3 | 0 |
| 10 | 3 | 0 |

Reports: `udp-window-rust-rc2-rep-01.json` … `udp-window-rust-rc2-rep-10.json`.

## Fix

The v1 ACK credit was being used as a one-datagram stop-and-wait gate. At
4096 bytes and 65.536 Mb/s the ACK round trip exceeded the 0.5 ms inter-packet
interval, so the daemon's UDP receive socket overflowed.

- Rust managed v1 UDP now uses a bounded 32-frame ACK window
  (`src/port_forward_worker.rs`).
- The Go CLI now uses a 64-frame ACK window and buffered queues
  (`cmd/portforward_udp.go`; commit `060a594`).
- The Go UDP acceptance peer uses a 64-frame bounded window so the test sender
  is not the bottleneck. Peer source hashes are in each report.

## Verification

```text
cargo test --all-targets --locked
```

passed all targets, including the updated managed-UDP ACK-window regression
test.

```text
GOPROXY=off go test -tags nopkcs11 ./cmd \
  -run TestUDPPortForwarderBoundedWindowWithoutAcks -count=1 -v
```

passed; 16 local datagrams produced 16 forward frames with no ACK sent.

## Boundary

This closes blocker 7 for the stated local loopback profile only. It does not
qualify WAN UDP, v2, IPv4 loopback on this WSL host, rootfs update/reboot,
physical hardware, QEMU, or production credentials.