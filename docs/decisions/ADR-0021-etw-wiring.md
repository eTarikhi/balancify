# ADR-0021: ETW wiring for ECN/delay/rekey/failover/auth

Date: 2026-10-19
Status: accepted

## Context

ETW provider stub existed (ADR-0012) but was not wired to service events. Diagnostics (Sec.8.2) requires ETW events for ECN CE, delay congestion, rekey, relay failover, auth failed, plus per-path cwnd/in_flight.

Previously, service had eprintln for failover only, no ETW.

## Decision

- `crates/service/src/lib.rs`: add `etw: EtwProvider` field to `Service`, init in `new()` as `EtwProvider::new("BalancifyService")`
- `ingest_path`: when ECN CE flag detected (`FLAG_ECN_CE`), after incrementing `ecn_ce` counter, log `ETW EVT_ECN_CE (401)` with path, uplink, cwnd
- `ingest_path`: when `on_ack_with_rtt` triggers delay event (RTT jump), log `EVT_DELAY_CONGESTION (402)`; same for probe reply `on_rtt` delay
- `ingest_path`: when `Event::Dropped AuthFailed`, log `EVT_AUTH_FAILED (600)` with uplink
- `tick`: when a configured key-update threshold becomes due, log `EVT_REKEY (400)` with the session and that a coordinated update is required. The service does not rotate ciphers locally (ADR-0043).
- `tick`: when `check_relay_failover` returns new relay, log `EVT_RELAY_FAILOVER (500)` with old->new and count, plus existing eprintln
- `crates/service/src/etw.rs`: event IDs 100-600; Windows `EventRegister`/`EventEnabled`/`EventWrite`/`EventUnregister` use a stable provider GUID, nonzero level/keyword, and bounded UTF-16 payloads; non-Windows and Windows API failure paths log to stderr. No provider manifest is installed, so useful Windows trace decoding still needs runtime validation. Relay failover ETW messages deliberately omit endpoint IPs and ports.
- Tests: existing ETW test `etw_provider_logs` still passes, no new failure

## Status update (2026-10-24)

The former `maybe_rekey` call described below was unilateral and could desynchronize the secure relay. ADR-0043 replaces it with a key-update-due warning; event 400 no longer claims that a live rekey occurred.

## Consequences

- Positive: diagnostics include ECN/delay/rekey/failover/auth via ETW, visible in support bundle and shell
- Negative: non-Windows uses stderr; Windows ETW code is compiled by CI but has not been exercised against a live trace session, and no manifest is installed for high-level decoding.
- Neutral: no change to data path, only logging

## References

- Blueprint Sec.8.2 Diagnostics, Sec.6.4 CC ECN+delay, Sec.11.3 rekey, Sec.4.5 failover, Sec.9.1b auth_failed
- Code: `crates/service/src/lib.rs` `etw` field, `ingest_path`, `tick`, `crates/service/src/etw.rs`
- CI: 39233826038 success after fixing arg order `on_ack_with_rtt(path, bytes, None, now)` vs previous `now, None`; Windows ETW sink and follow-up tests pass in CI `39601436958` (live trace capture/decoding remains pending).
- ADR-0012 ETW and support bundle, ADR-0019 enhanced, ADR-0021 wiring
