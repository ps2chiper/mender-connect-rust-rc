# RC 0.1.0-rc.1 — long-duration stability qualification

Date: 2026-11-17 (America/New_York)
Binary: `mender-connect-rust` SHA-256 `21e54ac08c5453261b5ba61ec6c1f70132ee83e717163d6e9ff0e2050cfe8ee4`
Scope: installed real-server terminal soak + local mixed forwarding/file-transfer TLS soak.

## Criterion

Relative budgets are measured from the same run's warmed baseline, not from a fixed historical thread count:

- Thread growth: baseline + 4.
- FD growth: baseline + 8.
- RSS growth: baseline + 32 MiB.
- Absolute ceilings remain 64 threads, 96 FDs, 192 MiB RSS.

This replaces the obsolete absolute baseline-plus-four rule that produced the historical 13-vs-12 thread failure. The current runtime has a main thread plus sixteen Tokio worker threads; a terminal session adds two session threads, so a warmed baseline of 19 is expected. The old 12-thread threshold was below the current fixed worker-pool size, so hitting 13 was not a leak.

## Installed real-server WAN terminal soak

Evidence: `rc-wan-installed-35min.json`

- Duration: **2104 s** (35 min); 69 terminal commands through `mender-cli terminal` and the installed `mender-connect-rust.service`.
- Transport: remote `https://mender.zapto.org`, system-bus Mender Auth.
- Baseline: threads **19**, FDs **14**, RSS **7,424 KiB**.
- Peak: threads **19**, FDs **14**, RSS **7,424 KiB**.
- First/last quarter means: threads 18.345 → 18.326; FDs 14 → 14; RSS 7,424 → 7,424.
- Checks: terminal alive, daemon alive, thread growth, FD growth, RSS growth — all **pass**.

## Local mixed forwarding/file-transfer TLS soak

Evidence: `rc-mixed-local-30min.json`

- Duration: **1801.449 s** (30 min), 1,800 quiescent cycles.
- Operations: 10,800 forward connections, 4,320 downloads, 4,320 uploads, 3,600 stats, 3,600 zero-length UDP datagrams, 1,800 mixed closes.
- Baseline: threads **19**, FDs **11**, RSS **8,704 KiB**.
- Peak: threads **20**, FDs **18**, RSS **8,704 KiB**.
- Quiescent first/last quarter means: threads 18.964 → 19; FDs 11 → 11; RSS 8,704 → 8,704.
- Peer checks: same daemon/WebSocket lifetime, v1/v2 byte-exact atomic transfers and key reuse, TCP/UDP v1/v2 echo including zero datagrams, mixed-close cleanup — all pass.
- No tracked descendant leftovers and no upload staging leftovers.
- Harness assets and binary hash unchanged.

## Harness correction

The first local mixed attempt failed at cycle 49 because the independent peer treated an RC control `ping` as an unexpected upload reply. This was a **peer harness defect**, not resource growth. The peer was patched to answer control pings with pongs and rebuilt (`peer` SHA-256 `9f29b4134bc40486658e4502e72ac97149997eb306bbc968dc00399b57cc2042`), then the full 30-minute run passed.

## Verdict

**Blocker 4 is closed.**

- Relative thread/FD/RSS growth is enforced and passed over 35 minutes against the installed service and real server.
- A separate 30-minute mixed TLS soak exercised forwarding and file transfer with 1,800 quiescent cycles and no resource growth or cleanup leaks.
- The historical 13-vs-12 failure is explained by an obsolete fixed threshold below the current worker-pool baseline, not by unbounded growth.

This qualifies the tested 30–35 minute window. It is not a multi-hour soak and does not replace long-term production observation.