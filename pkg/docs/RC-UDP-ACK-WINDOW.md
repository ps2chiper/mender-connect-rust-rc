# UDP v1 ACK-window fix and zero-loss qualification

Date: 2026-11-18 (America/New_York)
Scope: native Ubuntu 24.04 WSL2 x86-64, local IPv6 loopback UDP target, IPv4
loopback WebSocket control, private session D-Bus, test-only authentication.
No QEMU, no physical hardware, no WAN.

## Root cause

The v1 port-forward protocol has one ACK per forwarded datagram, but the
implementations treated that as a **one-datagram-in-flight stop-and-wait gate**:

- Rust managed UDP worker disabled all socket reads while one outbound frame
  was awaiting a peer ACK.
- The Go `mender-cli` UDP forwarder waited for every ACK before reading the next
  local datagram.

At the required 65.536 Mb/s / 4096-byte profile (about 2,000 datagrams/s), a
full-duplex ACK round trip was longer than the inter-packet interval, so the
UDP receive socket overflowed. The loss was from-device (daemon -> peer), with
the peer's `to_device` direction already clean.

## Fix

Rust: `src/port_forward_worker.rs` now tracks `in_flight` and allows a bounded
32-frame v1 managed-UDP ACK window. TCP, unmanaged UDP and v2 retain the
original one-credit behavior.

Go CLI: `cmd/portforward_udp.go` now uses a 64-credit `ackWindow` channel,
buffered local/WS queues and a mutex-protected UDP source address. The old
`sync.WaitGroup` stop-and-wait gate is removed.

The UDP acceptance peer also uses a 64-frame bounded window so the test driver
is not itself the sender bottleneck. The peer source hashes are recorded in
every report.

## Rust regression tests

```text
cargo test --all-targets --locked
```

All targets passed, including the updated managed-UDP ACK-window test.

## CLI regression test

```text
GOPROXY=off go test -tags nopkcs11 ./cmd \
  -run TestUDPPortForwarderBoundedWindowWithoutAcks -count=1 -v
```

The test starts the real `UDPPortForwarder`, sends 16 local UDP datagrams and
receives all 16 forward frames **without sending any ACK**. The old
one-in-flight implementation stalls after one frame. The test uses `::1`
because this WSL host does not deliver 4096-byte IPv4 loopback UDP reliably.

## Qualification result

Ten independent repeats, each three 60-second trials, at 4096-byte full duplex
and 65.536 Mb/s per direction. See
`RC-4096-ZERO-LOSS-QUALIFICATION.md` and the ten
`udp-window-rust-rc2-rep-*.json` reports.

## Exclusions

This does not qualify WAN UDP, v2, IPv4 loopback on this host, rootfs updates,
physical hardware or QEMU.