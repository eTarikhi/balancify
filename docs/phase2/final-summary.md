> Measurement correction (2026-10-20): historical `throughput.rs` and `analyze.py` demo figures are not evidence of network performance. The analyzer now requires actual iperf3 JSON; all Rig B acceptance rows remain pending. See `docs/phase2/throughput-rows.md`.

# Final summary — continuous development without stopping to report

Date: 2026-10-19 → 2026-10-21
Status: historical baseline at 36d65eb; active Arena continuation and current gates are recorded below.

## Active Arena continuation (2026-10-21)

Current Arena branch: `arena/1e00c990-balancify`, commit `1980d6d`; PR #14 is open. PR #13 was merged as `6856b498d00f6863007fd8a7def9805ed6a954bc`. Push CI run `39672966928` and PR #14 run `39672975335` passed all four jobs on Ubuntu 24.04 and Windows, including Rust tests/build/SBOM validation, lab tools and workflow-contract tests, and dependency/crypto audit. Linux workflows are pinned to Ubuntu 24.04, Pages actions use exact Node 24-compatible releases, IPC string decoding rejects invalid UTF-8, and installer default journals use exclusive path reservation with Unix mode `0600`. PR #14 body reflects the latest changes. Production named-pipe authentication, live ETW trace decoding, WDK/NDIS build/runtime, HVCI, real netem/Rig B performance, clean-machine installation, reviewed VEX, actual Pages deployment, persisted cache, and production WinUI/IPC remain unverified; do not infer completion from historical baselines.

Continue the roadmap autonomously and keep this report synchronized with verified commits and CI; do not report interim status to the user.

New since 5fc3af0: Cargo.lock gap closed and dependency audit passes; driver project HVCI flags and lab harness documentation were added. Historical correction (2026-10-20): `sbom.sh v2` (6c9a52f) emitted handwritten SPDX-3-shaped JSON with placeholder vulnerability IDs. That output was not standards-valid and is not an SBOM/VEX deliverable. The SPDX 2.3 locked-graph generator remains available and makes no vulnerability claims. A 2026-10-21 follow-up adds a parallel SPDX 3.0.1 JSON-LD generator and official JSON Schema + SHACL CI gate; review VEX and clean-machine installer validation remain pending. Other entries in this historical baseline describe planned lab profiles and tooling, not measurements or hardware validation.

Historical CI runs passed those commits' checks, including the run that carried the invalid SBOM placeholder; CI success did not establish SPDX/VEX validity. Current continuation CI run 39484151181 passed Ubuntu/Windows tests, release build, lab/policy checks, and SPDX 2.3 standards-parser validation.

Per-flow retx (session,seq) + flow ACK + driver source changes + HVCI flags + Cargo.lock + software harnesses + report visualizations — CI-verified as code/build checks only. No WDK, hardware, SPDX 3.0, or VEX validation is implied.

Next still: netem S2c real, driver S2b real VM Verifier 0x209BB + HLK HVCIMemoryIntegrity + VBS/MI, throughput Rig B real iperf3, HVCI trio real, WinUI3 shell, soak+Verifier+compat, RC+attestation+rollback, GA.

## What was done in this entire continuous session (from ADR-0015 to now)

### Bug fixes (from CI failures)

- `pacing-bench.rs` E0599 `delay_for` not found -> `delay_until_next(0, t)` (PacingController API: `delay_until_next`, `next_send_time`, `on_send(path, bytes, now)`, `set_rate(path, rate)`)
- `drr-bench.rs` unused imports `UplinkId, FlowKey, SenderConfig, Receiver, ReceiverConfig` -> cleaned to `Sender, Crypto`
- `service/src/lib.rs` non-ASCII Sec. markers (`§`, `—`, `–`, `…`, `’`, `‘`, `“`, `”`, `•`, `→`, `←`, `≤`, `≥`, `−`, `↔`) replaced with ASCII `Sec.`, `--`, `-`, `...`, `'`, `"`, `*`, `->`, `<-`, `<=`, `>=`, `-`, `<->` to avoid Rust 2021 prefix errors (E0308, unknown prefix, unknown start of token \u{a7})
- `service/src/lib.rs` format! escaping `&format!(\\"ECN CE...` -> `&format!("ECN CE...` by replacing backslash+quote with quote globally
- `service/src/lib.rs` arg order `on_ack_with_rtt(path, bytes, now, None)` -> `on_ack_with_rtt(path, bytes, None, now)` (rtt Option before now, per congestion.rs:134)
- `driver/src/miniport.c` and `ioctl.c` and `README.md` non-ASCII replaced similarly
- `throughput.rs` E0107 missing generics `Service` -> `Service<TunnelCipher>`, and policy violation `PassThrough` string in comment triggered audit (grep -rl "PassThrough") — fixed by using real TunnelCipher and removing string
- `tunnel/src/lib.rs` per-flow retx refactor: `Sent` now has session field, `retx` keyed by (session,seq), `next_seq_for` per-session, `remember(session, seq, ...)`, `on_ack_for_session`, `duplicate_with_session`, `reinjections_due` preserves session

CI progression: 39232571739 failure non-ASCII, 39233028939 failure prefix, 39233548995 failure arg order, 39233826038 success, 39234128363 success per-path diag, 39234403709 success, 39234666177 success, 39234937199 success, 39235214291 success, 39235545738 success driver, 39235817239 success, 39236091314 success app, 39236360963 success, 39236639218 success ECN bench, 39236895693 success, 39237159469 success, 39237431952 success test coverage, 39237683235 success next steps, 39237951269 success final-summary, 39238213860 success ci-history, 39266364959 success ETW uplink/bond, 39266694119 success ADR-0027, 39267073764 success non-ASCII+flow ack, 39267418909 success ADR-0028, 39267743843 failure throughput PassThrough, 39268156078 failure Service generic, 39269493593 pending docs, then 4761969 success throughput real cipher, 4d05142 success per-flow retx + flow ACK + driver S2b, f89a617 success ADR-0029/0030, 5fc3af0 success docs update

### Features added (in order)

- **ETW wiring** (Service etw field, ingest_path ECN CE 401 + delay 402 + auth_failed 600, tick rekey 400 + failover 500, relay ecn_echoed + total_ecn_echoed + sweep + stats 6-tuple) — ADR-0021
- **Support bundle per-path ECN/delay diag** (cc methods ecn_ce, delay_events_path, rtt_min, rtt_last, CongestionDiag per_path Vec<PathCongestionDiag> with cwnd/in_flight/ecn_ce/delay_events/rtt_min/last_ms, test bundle_includes_per_path_ecn_delay) — ADR-0022
- **Relay ECN echo stats** (RelaySession ecn_echoed, SecureRelay total_ecn_echoed, sweep accumulation, stats 6-tuple, print ecn) — ADR-0023
- **Driver WDF control device + IOCTLs** (SET_MTU 0x800, GET_STATS 0x801, INJECT_NBL 0x802, SET_QUANTA 0x803, length-validated, WdfDriverCreate, BalancifyCreateControlDevice in MiniportInitializeEx) — ADR-0024, for G2 S2b
- **App shell relay & bundle modes** (Sec.8.2) — render relay stats, support bundle redacted, ECN/delay counters — ADR-0025
- **ECN bench** (cwnd 80% ECN vs 50% loss, delay 10% reduction, per-path ECN/delay/rtt_min/last) — ADR-0026
- **ETW uplink up/down + bond reverted** (publish() clones prev_uplinks, compares prev.state != curr.state, logs EVT_UPLINK_UP 200 / EVT_UPLINK_DOWN 201 with id, prev->curr, rtt, cap; observe_bond_gain logs EVT_BOND_REVERTED 300 when flipped) — ADR-0027, commit 655d91d
- **Flow-level ACK explicit** (CapacityEstimator on_flow_ack, PolicyEngine wrapper, non-ASCII clean all crates) — ADR-0028, commit 0d8f2b1
- **Throughput harness with ECN/delay profiles** (10 reps, 1000x1200B, bonded/single/lossy/ECN/delay, mean/median/p95/spread, gain, loss penalty, real TunnelCipher) — commit 4761969
- **Per-flow retx keyed by (session,seq) + per-session seq spaces** (Sent includes session, RetxEntry includes session, retx BTreeMap<(u64,u64), RetxEntry>, session_seqs authoritative, next_seq_for per-session, remember(session, seq, ...), on_ack_for_session, duplicate_with_session, reinjections_due preserves session, service uses duplicate_with_session and on_ack_for_session) — ADR-0029, commit 4d05142
- **Explicit flow-level ACK integration + driver S2b NBL indication** (PolicyEngine on_flow_ack wrapper, Service ingest_path detects FlowData and calls on_flow_ack + on_ack for each Payload, miniport NBL pool via NdisAllocateNetBufferListPool, ioctl INJECT_NBL allocates MDL via NdisAllocateMdl, NBL via NdisAllocateNetBufferAndNetBufferList, indicates via NdisMIndicateReceiveNetBufferLists, Return path frees MDL chain via NdisFreeMdl) — ADR-0030, commit 4d05142
- **HVCI readiness trio + SBOM/VEX SPDX 3.0** (hvci-readiness.md documents Verifier 0x209BB + code integrity, HLK HVCIMemoryIntegrity, VBS/Memory-Integrity VM with Secure Boot/vTPM/test-signing, driver uses NonPagedPoolNx, no executable pools, no RWX, proper MDL freeing, NBL pool, SDDL, METHOD_BUFFERED, length validation; historical SBOM/VEX placeholder was invalid and has been removed; current SPDX 2.3 generator uses locked Cargo metadata and makes no VEX claims) — ADR-0031, commit 5fc3af0
- **Throughput harness scope correction (2026-10-20):** local `throughput.rs` exercises software processing only; historical simulated gain/penalty/delay output is not networking evidence. `throughput-rows.md` now records the proper Rig B method; real acceptance remains pending.
- **Docs**: ADR-0021..0031, continuous-development-log, security-hardening, test-coverage, next-steps, ci-history, lab-progress (updated with per-flow retx, flow ACK, driver S2b NBL pool, HVCI, SBOM), throughput-rows, hvci-readiness, final-summary

### Test coverage

- Latest active-branch CI run 39531428626 passed 261 Rust tests on Ubuntu and 260 on Windows, plus seven Python SBOM tests and SPDX 2.3 parser validation. Earlier Windows/Ubuntu runner failures were corrected (E0503 borrow checker, missing Counters fields, truncated test tail, FlowClass/BondClass mismatch, WindowsEtwHandle case, bench imports, rate-limiter burst, non-ASCII markers, format! escaping, ACK argument order, Service generic, PassThrough audit guard).
- Core: 85+ tests (bond, congestion 13, flowtable, health, keepalive, mtu, pacing 7, placement, policy, ratelimit 3, rules, scoring)
- Crypto: 36 tests (AEAD 8, handshake 12, keys, store, replay 5, rekey 3)
- IPC: 9 tests (contract v1, truncation, Counters 10 fields)
- Relay: 12 tests (Endpoint 6, SecureRelay 6)
- Service: 30+ tests (bonded, flow-level, duplicate, no healthy, idle session, unanswered probe, capacity sample, sleep/resume, NAT rebind, full window Hold, ack reopen, keepalives+probe, probe reply RTT+capacity, IPC status, rule edits, event rate, self-test, bond revert, MTU, metered, loss failover, secure handshake, pinning, failover, key-update due + secure peer synchronization regression, per-flow, per-class, rate limiter, ECN/delay wire, bundle per-path)
- Tunnel: 31 tests (DRR proportionality 3000:1000, quantum < packet, idle cannot bank burst, sender numbers, without paths refuses, ack frees retx, retx bounded, ECN flag 0x04, per-session seq)
- E2E: prior 9 scenarios plus packet-count and elapsed-time key-update threshold cases (real TunnelCipher client and peer Receiver); historical Rust totals above predate ADR-0043.
- Fuzz: 6 tests (20k rounds each, no panic, no invented payload, caps bound memory, length checks, replay cannot manufacture)
- App: 0, Installer: 2, plus benches (drr, pacing, ecn, crypto) and throughput.rs (real cipher, 5 profiles)

## Next (still without stopping)

- Real netem S2c: netem-rig.sh profiles delay-gap 40ms, lossy 1%, asymmetric 200M/50M, cellular 100ms+2%+20Mbit, 10 reps median/p95/spread Sec.10.1 on Linux gateway with tc + iperf3
- Driver S2b real VM: test-signed load with new NBL pool + INJECT_NBL via NdisMIndicateReceiveNetBufferLists on Hyper-V VM with Driver Verifier 0x209BB + code integrity, VBS/Memory-Integrity on, Secure Boot, vTPM, re-run S2a socket test through miniport
- Cargo.lock is refreshed from the successful Ubuntu runner's Cargo resolution; local dependency-policy audit passes. Re-run generation/audit when changing dependencies.
- Throughput Rig B real: wired 1Gbps/Wi-Fi 6 300M, secure Noise_IK, pacing 80%, per-flow on/off, iperf3, added delay <=3ms, CPU/Gbit via crypto-bench+ETW, 10 reps median/p95/spread, record in throughput-rows.md + lab-progress.md
- HVCI trio S15 real: Verifier, HLK HVCI readiness test, VBS/Memory-Integrity VM, document in hvci-readiness.md
- SPDX/VEX S13: SPDX 2.3 and standards-valid SPDX 3.0.1 inventories now generate, validate, and publish in CI; the installer journals/copies both. Remaining: reviewed VEX from current advisory data and clean-machine verification of both sidecars.
- WinUI3 shell: Home, Rules, Relay & account, Diagnostics, tray flyout, 1Hz telemetry, last-known-good + stale markers, accessibility, self-contained .NET 10 + WinAppSDK runtimes bundled, offline installer per §4.8 rev 2.1
- Soak + Verifier + compat matrix: 72h soak, random flaps, 100 sleep/resume with Verifier standard+random, compat matrix VPN clients, security suites, Hyper-V, WSL2, Memory Integrity on/off (G5, G6)
- RC + final attestation + SBOM/VEX + rollback drill (G7), GA + winget + status page (G8)

## References

- Blueprint Sec.4.5 failover, Sec.4.7.4 per-flow sessions, Sec.4.8 dependency policy, Sec.6.1 TAP-like adapter, Sec.6.2 WRH + flow classes, Sec.6.3 capacity, Sec.6.4 DRR + pacing + CC, Sec.6.5 health hysteresis, Sec.6.6 NAT keepalive, Sec.8.2 Diagnostics, Sec.8.3 installer, Sec.9.2 IPC + handshake, Sec.9.3 signing, Sec.9.5 HVCI, Sec.10.1 Rig A/B, Sec.10.3 acceptance rows, Sec.11.2 Wintun exception, S13 SBOM/VEX, S15 HVCI trio
- ADRs 0002-0036
- Historical baseline CI: 5fc3af0; active continuation CI: 39531428626
