# ADR-0043: require peer coordination for transport key updates

- **Date:** 2026-10-24
- **Status:** accepted
- **Scope:** secure tunnel key-update behavior; no change to the handshake wire format

## Context

The service previously replaced its transmit and receive ciphers locally when either a packet-count or elapsed-time threshold was reached. The secure relay's `RelaySession::rekey` was not called, and the current tunnel protocol has no authenticated key-update message, acknowledgement, epoch number, or old/new-key overlap. The client could therefore switch epochs while the relay continued using the previous keys, causing authenticated traffic to be dropped. Packet loss and asymmetric timing make independent threshold triggers unsafe even if both endpoints implement the same threshold.

## Decision

- Do not rotate a live session's ciphers from `Service::tick` or from relay-local timers.
- Keep the packet/time thresholds as a due signal only. Expose `update_required` in the support bundle and add a warning that the keys were not rotated.
- `Service::rekey_with` is only for keys delivered by a peer-coordinated handshake; locally deriving matching-looking ciphers is not sufficient protocol coordination.
- Remove the unused relay-local rekey method so it cannot be mistaken for an active coordinated update.
- Require a future protocol design to specify authenticated update/ack, epoch transition, retransmission and loss recovery, old/new key acceptance bounds, sequence/replay-state handling, and time/packet threshold behavior before automatic rotation is restored.

## Consequences

- Reaching the configured threshold no longer silently breaks an otherwise working encrypted session. The service continues on the current key and reports that a coordinated update is due.
- This is not a complete forward-secrecy key-update implementation. Long-lived sessions do not rotate keys automatically, so the security-hardening acceptance claim remains pending until a coordinated protocol is implemented and tested.
- Crypto-layer one-way derivation tests remain useful for the KDF primitive, but they are not evidence of live transport-key synchronization.

## Regression coverage

`crates/service/tests/rekey_safety.rs` uses a real `TunnelCipher` sender and peer `Receiver` to test both packet-count and elapsed-time thresholds. Each scenario ticks the client at the threshold and verifies the peer still authenticates and delivers subsequent traffic while diagnostics report that an update is due and no local rotation occurred.
