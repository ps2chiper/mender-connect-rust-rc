# v1 4096 full-duplex loss characterization

Profile: UDP v1, 4096-byte datagrams, full duplex, 65.536 Mb/s per direction.
Native Ubuntu 24.04 WSL2 x86-64, local IPv6 `::1` UDP target, IPv4 loopback
WebSocket control, private session D-Bus and test-only authentication. No QEMU,
WAN, or production server.

Method: ten independent repeats per implementation. Each repeat is three fresh
60-second trials at the frozen rate. Both binaries are frozen by SHA and the
same peer source is used.

## Results

| Implementation | Repeats passed | Trials lossy | Total from-device lost | Lossy-trial median | Max lost |
|---|---:|---:|---:|---:|---:|
| Rust RC `21e54ac…` | 5 / 10 | 7 / 30 | 2,390 packets | 32 | 2,217 (1.85%) |
| Go `364fc12f…` | 3 / 10 | 14 / 30 | 2,569 packets | 79 | 1,431 (1.20%) |

Per-repeat from-device losses (three trials per repeat):

| Repeat | Rust RC | Go reference |
|---:|---|---|
| 1 | 0, 0, 0 | 122, 73, 0 |
| 2 | 0, 0, 0 | 0, 0, 7 |
| 3 | 0, 3, 0 | 0, 0, 0 |
| 4 | 0, 0, 0 | 105, 0, 100 |
| 5 | 0, 0, 12 | 0, 0, 0 |
| 6 | 0, 0, 0 | 1431, 0, 72 |
| 7 | 0, 0, 2217 | 175, 171, 0 |
| 8 | 0, 0, 0 | 67, 15, 79 |
| 9 | 0, 0, 51 | 0, 73, 79 |
| 10 | 32, 71, 4 | 0, 0, 0 |

## Observations

- **All loss is from-device.** Across 60 trials and both implementations,
  to-device lost zero packets.
- Failures are intermittent and occur in trial 1, 2 or 3; there is no fixed
  warm-up slot.
- Most losses are small (single digits to tens of packets). Occasional large
  excursions occur on both implementations (Rust 2,217; Go 1,431).
- Throughput remains near the requested rate. Rust from-device goodput ranged
  64.15–65.44 Mb/s; Go 64.54–65.36 Mb/s. The large-loss trials are slower.
- The Go reference is **not** clean at this profile. It failed 7/10 repeats in
  this sample. The earlier single clean Go 3 x 60 s run was not representative.

## Interpretation

The 60-second zero-loss gate at v1 4096 full-duplex, 65.536 Mb/s is not
reproducible on this host for either implementation. This is not an
RC-specific regression: the reference loses more often in this sample. The
likely limit is the WSL loopback/UDP path or host scheduling at this exact
offered rate, not Rust product code.

The RC therefore cannot claim zero-loss parity at this profile, but neither can
the reference. A stricter zero-loss claim would require a lower declared rate,
a more isolated host/CPU environment, or socket-drop attribution during the
failing trials.

## Artifacts

- Rust reports: `rc-udp-4096-rep-01.json` … `rc-udp-4096-rep-10.json`
- Go reports: `rc-udp-4096-go-rep-01.json` … `rc-udp-4096-go-rep-10.json`