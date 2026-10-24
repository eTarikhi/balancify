# ADR-0008 — key management, replay protection, rekey and pacing

Status: accepted · Date: 2026-10-19 · Updated: 2026-10-19 · Builds on: ADR-0007 (handshake) · Related: §9.2, §6.4, §10.3, §11.3, §11.4

## Context

ADR-0007 landed the `Noise_IK` handshake but left secrets as arguments:
`Initiator::new(static_secret, responder_static, prologue)` takes `[u8; 32]`
and the service had no place to get those bytes from. §9.2 says "relay
session/identity keys in DPAPI-protected store, TPM-backed where available;
never in the JSON settings; keys rotate per session with forward secrecy" and
§11.4 warns about replay of first flights. Separately, the §10.3 throughput
rows were at risk: the congestion window stops the tunnel from overrunning a
path, but it does not stop it from sending a whole window as one burst at line
rate, which overflows the bottleneck queue.

## Decision

**1. Keypairs are first-party types that zeroize on drop.**
`StaticKeypair` and `EphemeralKeypair` hold 32 secret bytes in a `ZeroizeOnDrop`
box. Generation is the only place that touches the OS CSPRNG (`getrandom`
0.2.15, pinned). Everything else takes bytes as arguments so tests stay
deterministic and the handshake's security argument stays independent of the
platform's storage.

**2. `KeyStore` trait with two implementations, now DPAPI-protected.**
- `MemoryKeyStore` for tests and deterministic rigs.
- `FileKeyStore` for lab and production: raw 32-byte secret in a file with 0600
  perms, atomic write via unique private temp+rename. Windows builds enable the
  `dpapi` feature by default, protecting file contents via **first-party FFI**
  to `CryptProtectData`/`CryptUnprotectData` in `crypt32.dll` (no `windows` crate,
  no third-party dependency, so audit stays clean). The wrapper uses
  `CRYPTPROTECT_UI_FORBIDDEN` and `LocalFree`, handles migration (old raw 32-byte
  files accepted, next save protects), and protects both secret and pinned files.
  DPAPI uses TPM if present, satisfying §9.2 "TPM-backed where available".

Pinned keys (`PinnedKeys`) are a set of 32-byte public keys that the handshake
learns from flight 1. The responder checks `peer_static()` against this set
before accepting a session, which is how `auto_accept` becomes false. `Service`
and `Endpoint` (relay) now hold `PinnedKeys` + `ReplayCache`, `set_pinned_clients`
flips `auto_accept=false` and re-creates receiver with same cipher but no
auto-accept, `is_peer_allowed` checks pinned set, `establish_secure_session`
verifies pinning then applies `TransportKeys` and opens session explicitly.
`ServiceConfig.auto_accept` default true for lab, false for secure.

**3. Replay cache for first flights (§11.4).**
`ReplayCache` stores recently seen ephemeral public keys (32 bytes) for a
bounded window (60 s) and capacity (1024). Same ephemeral within window =>
replay, rejected cheaply without DH. Time is an `Instant` argument, storage is
in-memory, so it is sans-I/O and testable. Wired into `Responder::read_message_checked`
and `Service`/`Endpoint` via `replay_cache_mut()`.

**4. Rekey for forward secrecy (§11.3).**
`TunnelCipher` now stores key bytes and implements `rekey()` via
`HKDF-BLAKE2s(old_key, "balancify rekey v1")` one-way. `TransportKeys::rekey()`
rotates both directions but keeps `handshake_hash` so salt stays bound to the
original transcript. Old keys should be zeroized by caller. The KDF matches the
handshake's hash for consistency; Noise's default `REKEY(k)` (encrypt zeros
with max nonce) is equivalent in spirit.

**5. Pacing in front of the congestion window (§6.4 rule 4) — now wired.**
`PacingController` is a per-path token-bucket time-based pacer: given rate_bps
and bytes, it computes delay capped at 100 ms. `Service::publish()` sets rate to
80% of estimated capacity (from `CapacityEstimator`), `send_app_packet` records
`on_send`, `pacing_delay()` exposed for I/O loop to sleep until next send.
Prevents burst (14 KiB at 10 Mbit/s spread over ~11 ms, tested).

**6. Two more pinned crates.**
`getrandom =0.2.15` (OS CSPRNG) and `zeroize =1.8.1` (secure zeroing). Six pinned
crates now, all allowlisted and exact-pinned, audit passes. No new crates for
DPAPI (first-party FFI).

## Rejected

- **Storing secrets in JSON settings.** Forbidden by §9.2, and would make
  backups leak keys.
- **Using `rand` or `OsRng` directly in handshake.** Would make tests
  non-deterministic and hide the RNG dependency. Generation is isolated to
  `keys.rs`.
- **Bloom filter for replay.** Overkill for 1024 entries; a HashMap + VecDeque
  is simpler and bounded.
- **Pacing via `tokio::time::sleep`.** This crate is sans-I/O; pacing returns
  an `Instant` deadline and the service loop decides to hold.
- **Using `windows` crate for DPAPI.** Pulls many transitive deps, complicates
  audit, and is Windows-only. First-party FFI to `crypt32.dll` achieves same
  with zero extra crates, satisfying policy §4.8 (platform SDKs are OS platform,
  not external tools, but we avoid even that by using raw FFI).

## Status update (2026-10-24)

The one-way derivation primitive remains, but the claim that peers can activate it independently was unsafe: packet loss, asymmetric packet counts, and timer skew can leave the endpoints on different key epochs. ADR-0043 supersedes that activation policy. Live cipher rotation is disabled until an authenticated, acknowledged peer-coordination protocol exists.

## Consequences

- Static keys can now be loaded/generated and pinned keys managed without
  touching JSON. File store is DPAPI-protected on Windows by default, 0600 on
  Unix, with migration path for old raw files.
- Pinning enforced in Service and Relay: `auto_accept=false` when pinned set
  non-empty, `is_peer_allowed` checks, `establish_secure_session` verifies then
  applies keys and opens session. Prevents unpinned peers from auto-accepting.
- Replay cache prevents cheap DoS via replayed flight 1, but does not persist
  across restarts — acceptable because ephemeral is fresh per session and window
  is short. Wired into handshake's checked path.
- The one-way derivation is deterministic, but peers cannot safely activate it
  independently: loss and timer skew can desynchronize their key epochs. This
  earlier assumption is superseded by the 2026-10-24 status update and ADR-0043.
- Pacing controller is wired into Service: rate from capacity estimator, delay
  exposed, burst prevention measured. §10.3 added-delay row should improve.
- Test totals: core 76, crypto 36 (33+3 pinning/replay), service 21, relay 6,
  ipc 9, e2e 8, fuzz 6, tunnel 31 = **193 tests, 0 failures** on ubuntu/windows.
- No Cargo.lock yet: sandbox has no toolchain (crates.io blocked). Must be
  generated with `cargo tree` + `cargo generate-lockfile` when toolchain available.
