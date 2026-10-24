# ADR-0042: Retain miniport TX packets during service backpressure

- **Status:** Accepted
- **Date:** 2026-10-24
- **Scope:** user-mode handling of packets already removed from the miniport TX FIFO. This is source-level reliability behavior; it does not claim a working installed-driver path.

## Context

The NDIS miniport completes a send successfully once the raw-IP packet is copied into its bounded TX queue. `IOCTL_BALANCIFY_DEQUEUE_TX` removes a packet before the service passes it to `Service::send_ip_packet`. The service can return `Action::Hold` when congestion or rate limiting temporarily prevents scheduling, or `Action::Refused` when no uplink is currently eligible. The service loop previously ignored both actions, permanently losing a packet after the driver had completed its send successfully.

## Decision

- Keep at most one dequeued raw-IP packet in a user-mode pending slot.
- On each 10 ms driver-poll tick, retry the pending packet first. Treat any result with no `Action::Send` as deferred and retain the original packet bytes. This includes `Hold`, `Refused`, and an unexpectedly empty action list.
- Dequeue later packets only after the pending packet has been accepted by the service scheduler. Process no more than 64 packets per poll tick. This preserves FIFO and leaves the remaining bounded backlog in the driver queue to provide backpressure.
- Once an `Action::Send` is produced, pass the scheduled datagrams to the UDP adapter and release the pending packet. A subsequent socket-send failure remains fatal to the service rather than silently claiming delivery.
- Keep the pending slot in memory only. Invalid packets remain rejected at the driver/service validation boundary; no retry survives service shutdown, device removal, or process restart.

## Consequences

- Temporary congestion/rate limiting and temporarily unavailable uplinks no longer cause an immediate silent drop after `DEQUEUE_TX` has popped a packet.
- The additional user-mode storage is bounded to one packet (at most 9000 bytes), and FIFO ordering is retained while the driver queue provides pressure signaling.
- Repeated `Hold`/`Refused` attempts may increment the service's existing attempt-oriented counters more than once for one packet. Queue age/drop policy, persistent retries, and runtime packet-path behavior remain open for later evidence-driven design.
- Rust tests cover the retry decision for `Send`, `Hold`, `Refused`, and empty outcomes. Windows driver installation, IOCTL behavior, Driver Verifier, HVCI, and end-to-end validation remain pending.
