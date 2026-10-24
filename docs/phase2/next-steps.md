# Next steps — continuous development without stopping

Date: 2026-10-23
Status: continuous on `arena/81ef53da-balancify`; PR #19 remains open at `02409cf` (IPv6 boundary regressions `9be616f`; deterministic parser stress `02409cf`). Latest push CI `39922008067` and PR CI `39922014929` passed all six jobs, including unsigned x64/ARM64 WDK compile/link, PE machine-type, mitigation-flag, unsigned-status verification, Windows and Ubuntu Rust tests, lab tests, and dependency/crypto audit. Hardware/product gates remain pending.

User instruction: "continue the development process without stopping to report" — keep building features, fixing bugs, pushing CI, not stopping after each small change.

## What was done in this continuous session (since ADR-0015)

- ETW wiring for ECN/delay/key-update-due/failover/auth (Service etw field, ingest_path ECN CE 401 + delay 402 + auth_failed 600, tick threshold warning 400 + failover 500, relay ecn_echoed + total_ecn_echoed + sweep + stats 6-tuple; coordinated live rekey remains pending per ADR-0043)
- Fixed non-ASCII Sec. markers (Sec. instead of Sec., -- instead of --) to avoid Rust 2021 prefix errors (E0308, unknown prefix, unknown start of token \u{a7})
- Fixed format! escaping (remove backslash+quote) and on_ack_with_rtt arg order (None, now)
- Support bundle per-path ECN/delay diag (cc methods ecn_ce, delay_events_path, rtt_min, rtt_last, CongestionDiag per_path Vec<PathCongestionDiag> with cwnd/in_flight/ecn_ce/delay_events/rtt_min/last_ms, test bundle_includes_per_path_ecn_delay)
- Driver WDF control device + IOCTLs (SET_MTU, GET_STATS, INJECT_NBL, SET_QUANTA) for G2 S2b, length-validated, WdfDriverCreate, BalancifyCreateControlDevice in MiniportInitializeEx, non-ASCII fixed
- Merged PR #18 added pinned x64 and ARM64 WDK/VS 2022 compile-link CI with diagnostics and unsigned artifacts; push run 39799406998 passed all six jobs, including PE and INF contract verification. Static review makes SET_MTU reject changes that would diverge from NDIS-cached initialization/restart MTU attributes. Signed install, Verifier/HVCI, VM, and packet path remain pending.
- App shell relay & bundle modes (Sec.8.2) — render relay stats, support bundle redacted, ECN/delay counters
- ECN bench (cwnd 80% ECN vs 50% loss, delay 10% reduction, per-path ECN/delay/rtt_min/last)
- Docs: ADR-0021 ETW wiring, ADR-0022 support bundle per-path, ADR-0023 relay ECN stats, ADR-0024 driver WDF control, ADR-0025 app shell relay & bundle, ADR-0026 ECN bench, plus continuous-development-log, security-hardening, test-coverage
- Control-frame authentication/replay hardening and relay/session idle protections; wire v2 selective FlowAck for peer-receipt capacity sampling, with bounded per-session accounting and duplicate re-ACK (CI 39476560004).
- Client transport hardening (per-user absolute state roots, relay-source filtering, fatal UDP send errors, and single-use handshake responses) merged in PR #6; prior PR #5 was closed as superseded.
- FlowData selective repair merged in PR #7 / ADR-0036: retain bounded plaintext until authenticated FlowAck, reinject once after RTO on an alternate path, and rely on replay rejection plus duplicate re-ACK to preserve at-most-once delivery. Tunnel and service timer regressions, including uplink removal before retry, pass.
- PR #9/#10 and ADR-0037 established NdisMediumIP/raw-IP handling, OID and MTU parameter support, paused-injection rejection, owned NBL buffers, and a portable-tested pause drain state machine. PR #19 adds the bounded reverse TX queue and service polling (ADR-0040); `SET_QUANTA` remains unsupported until a driver scheduler consumes it. Current x64/ARM64 WDK builds and unsigned PE/INF checks pass in CI. This does not establish installation or runtime behavior.
- ETW uplink-up/down and bond-revert events were already implemented (ADR-0027 / commit 655d91d). Commit `7bb90d7` adds the real Windows EventRegister/EventWrite sink and event-payload tests; CI `39602034920` passed on Windows and Ubuntu, including relay-endpoint redaction. A live trace session and useful decoding remain unverified; no manifest is installed.

Current validation: PR CI `39922014929` passed all six jobs; Rust summaries report 305 Ubuntu / 304 Windows tests. Local CI suite: 24 Python tests, including 12 driver OID/INF contract checks, plus four portable C fixtures run under strict warnings and again with AddressSanitizer/UndefinedBehaviorSanitizer, including 12,000 deterministic malformed/near-valid parser mutations per execution. These are source/build checks, not runtime acceptance.

## What remains (ordered, still without stopping)

1. **Driver S2b runtime test through miniport**: the source now includes receive injection and reverse TX queue/dequeue; x64 and ARM64 WDK compile/link are verified in CI. Test-sign, install, and validate the bidirectional real-UDP tunnel path through NDIS on an isolated Hyper-V VM with Driver Verifier and HVCI. The queue is volatile and its source/CI status is not evidence of packet-path operation.
2. **Real S2c/throughput validation**: use the explicitly confirmed netem runner only on disposable interfaces; raw link results alone are not BalanciFy bonding evidence. Add adapter-level capture and record 10-repetition statistics. No lab result is claimed; Rig B remains pending.
3. **Throughput rows on Rig B**: run `throughput.rs` + iperf3 on wired 1 Gbps and Wi-Fi 6 300 Mbit/s, secure mode, pacing at 80% capacity, per-flow off/on; measure aggregate/single-flow/failover/added delay (target <=3ms) and CPU/Gbit/s. Local service-path benchmarks are not network evidence.
4. **Driver packaging and clean-machine validation**: package self-contained .NET 10 + WinAppSDK runtimes, verify installer rollback/offline provisioning and SBOM sidecar on a clean VM.
5. **HVCI readiness trio**: Driver Verifier with code-integrity, HLK HVCI readiness test, and a VBS/Memory-Integrity-enabled machine (S15).
6. **SBOM/VEX S13**: CI generates SPDX 2.3 and SPDX 3.0.1 JSON-LD inventories from the locked production graph, validates SPDX 3.0.1 with official JSON Schema + SHACL, and publishes both as run artifacts. Still required: reviewed VEX statements from current advisory data and clean-machine installer sidecar verification.
7. **Client binary + GUI IPC**: client handshake now fails closed with pinned identities by default; move from the protocol/lab CLI and loopback adapter to the WinUI 3 shell and production IPC transport/authentication.

## Process

- Keep CI green at all times: each push must pass Ubuntu + Windows + lab checks + dependency/crypto audit (305 Linux / 304 Windows Rust tests; current SPDX 2.3/3.0.1 SBOM tests and SPDX validators also run)
- Use `gh run list --limit 1 --branch arena/81ef53da-balancify --json databaseId,conclusion` + commit check-runs to verify CI.
- Fix bugs using web resources (RFC 8684 Sec.3.3, RFC 6356 LIA, DRR, RFC 6928) + deep thinking, deep learning, repeating, then continue developing app based on criteria (blueprint)
- No third-party kernel component in data path (C2), only vetted/pinned crates, PassThrough test-only must never ship (Phase-4 audit)
- Workspace dependency policy: `[workspace.dependencies]` intentionally empty per blueprint Sec.4.8 — do not add unpinned dependencies casually

## References

- Blueprint Sec.4.5 failover, Sec.4.7.4 per-flow sessions, Sec.4.8 dependency policy, Sec.6.1 TAP-like adapter, Sec.6.2 WRH + flow classes, Sec.6.3 capacity, Sec.6.4 DRR + pacing + CC, Sec.6.5 health hysteresis, Sec.6.6 NAT keepalive, Sec.8.2 Diagnostics, Sec.8.3 installer, Sec.9.2 IPC + handshake, Sec.9.3 signing, Sec.9.5 HVCI, Sec.10.1 Rig A/B, Sec.10.3 acceptance rows, Sec.11.2 Wintun exception, S13 SBOM/VEX, S15 HVCI trio
- ADRs 0003-0041
- Latest active-branch CI: push `39922008067` and PR `39922014929` success; latest head `02409cf`
- ADR-0038 through ADR-0043 cover secure service startup, bounded raw-IP ingress, miniport TX queue/retry, kernel packet-boundary validation, and coordinated key-update safety
