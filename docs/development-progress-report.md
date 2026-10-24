# Balancify — Development Progress Report

**As of:** 23 October 2026 (Asia/Tehran)<br>
**Repository state:** `main` at merge commit [`a1ec9b0`](https://github.com/eTarikhi/BalanciFy/commit/a1ec9b059c695ca0dc7926fff6a6f651a8da2499); active continuation: `arena/81ef53da-balancify`, PR [#19](https://github.com/eTarikhi/BalanciFy/pull/19) open; latest PR head `02409cf` (packet-boundary code `9be616f`; deterministic parser stress `02409cf`)<br>
**Latest verified PR CI:** [Run 39922014929](https://github.com/eTarikhi/BalanciFy/actions/runs/39922014929) — all six jobs succeeded; 305 Linux / 304 Windows Rust tests, pinned x64/ARM64 WDK builds, and static PE/INF checks passed.<br>
**Overall status:** active engineering prototype; **not release-ready**. G2–G8 acceptance remains open; G1 formal sign-off was not found in the repository evidence reviewed for this report.

> **Measurement and evidence rule.** This report separates source/CI evidence from Windows driver execution, network measurements and release validation. Passing Rust tests or a synthetic benchmark does not prove that the product works through an NDIS driver, meets throughput/latency targets, installs offline, or is ready for release. Percent-complete figures and velocity forecasts are omitted where no auditable basis exists.

## Executive snapshot

![Status and gate dashboard](assets/progress/status-dashboard-2026-10-23.svg)

The project has a substantial first-party Rust software foundation: current PR CI passes on Ubuntu and Windows with 305 and 304 Rust tests, the dependency/crypto audit and lab-tool checks pass, and pinned x64/ARM64 WDK compile/link plus static PE/INF checks pass. Those driver artifacts are unsigned and have not been installed or exercised in a Windows VM. The service and miniport now have source for both directions: tunnel-delivered packets can be injected into NDIS, while OS-originated raw-IP packets enter a bounded driver TX queue and are polled into `Service::send_ip_packet`. Neither direction has been exercised against an installed driver, and bidirectional packet-path acceptance remains open. The app remains a Rust CLI rather than the planned WinUI 3 desktop application. The 11 acceptance items listed in the throughput/clean-machine plan have no accepted results.

### Current decision view

| Dimension | Evidence-based position | Decision implication |
|---|---|---|
| Software integration | Latest PR CI: 6/6 jobs pass; 305 Linux / 304 Windows Rust tests pass | Continue software development; the CI baseline is healthy |
| Driver / OS integration | Pinned x64/ARM64 WDK compile/link, PE mitigation/unsigned checks, and INF source-contract tests pass. Optional injection and bounded reverse TX queue/polling source paths exist; portable C packet checks validate IP lengths, IPv6 extension bounds, and TCP/UDP header boundaries. No signed install, Driver Verifier, HVCI or packet-path runtime result. | G2 remains open; unsigned builds and source paths do not establish an operational miniport |
| Network performance | Software microbenchmarks exist; no real netem S2c or Rig B run | No throughput, added-delay, CPU/Gbit or failover acceptance claim |
| User-facing product | Rust lab CLI and loopback IPC exist; production WinUI/.NET GUI and authenticated named-pipe service transport do not | Production UX and IPC remain unimplemented |
| Installer / release | Journal and rollback logic are tested; no signed offline bundle or clean-machine install record | G4/G5 and release readiness remain open |
| Supply chain | SPDX 2.3 and SPDX 3.0.1 generation/validation are part of CI | Inventory pipeline exists; reviewed VEX, signing, and installer-sidecar validation remain open |
| Documentation deployment | The main-branch deployment attempt [39793993235](https://github.com/eTarikhi/BalanciFy/actions/runs/39793993235) failed; its cause has not been investigated in this continuation. | Portal content is maintained in source, but deployment is not verified and the site is not claimed live. |

## 1. Retrospective analysis — work completed and evidence

### 1.1 Architecture and governance

The repository contains **42 ADR documents (ADR-0002 through ADR-0043)** and a technical blueprint (rev 2.1) describing a self-contained Windows multi-WAN product: first-party NDIS miniport, first-party datagram tunnel, cooperating relay/server mode, authenticated service/UI IPC, WinUI 3 client, offline installer, supply-chain artifacts and eight go/no-go gates. The blueprint estimates **47–58 weeks to GA for a 5–6 engineer team**. That is a planning estimate, not a current forecast: there is no approved resource-loaded schedule, sprint-size history, or baseline-to-actual report in the repository.

| Milestone | Work delivered | Verification and caveat |
|---|---|---|
| **First-party software foundation** | Control plane, traffic placement and flow classes; health and capacity models; congestion, pacing and DRR; tunnel framing/reorder/reinjection; crypto, identity, replay and rekey; relay/server-mode lab binary. | Cross-platform Rust unit and simulation tests; coordinated live rekey remains pending under ADR-0043. No real NDIS path or real multi-WAN result. |
| **Protocol/security hardening** | Per-session sequence/retransmission state, authenticated FlowAck/FlowData repair, key storage/DPAPI, pinning, fail-closed client/service transport defaults, replay and source filtering, exact authenticated handshake session-echo validation. | Latest CI includes crypto/service/client suites; external review and production service/IPC remain pending. |
| **Diagnostics and lab tooling** | IPC v1, loopback lab service adapter, telemetry and redacted support bundle, ETW event-writing source, netem safety/analyzer tools, software benchmarks. | Contract tests and tool tests pass; no live ETW trace, real netem acceptance, or Rig B evidence. |
| **PR #13 · installer/service hardening** | Transactional SPDX sidecar handling, journal persistence and rollback, fail-closed lab service transport, Home stale-state behavior, loopback-only client policy; source-level driver and SBOM/ETW hardening also landed in earlier merged work. | PR #13 merged 21 Oct 2026; associated CI passed. Driver work remains source-only. |
| **PR #14 · CI and installer hardening** | Ubuntu 24.04 Linux runner pins, Node 24-compatible Pages actions, CI pin contract tests, strict installer CLI parsing, unique exclusively reserved/private default journals, strict UTF-8 IPC decoding. | PR #14 merged as `e3f2e24`; merge CI run 39688256976 passed all four jobs. Pages deployment separately failed at Setup Pages. |
| **PR #19 · driver evidence and raw-IP ingress** | Verify x64/ARM64 unsigned artifacts' PE architecture, mitigation flags and certificate-table state; add bounded IPv4/IPv6 flow parsing, optional `INJECT_NBL`, a 64-slot miniport TX queue with `DEQUEUE_TX` service polling, and kernel IPv4/IPv6 TCP/UDP structural validation aligned with the service parser, including exact unfragmented UDP/IP payload lengths and IPv6 UDP regression coverage (ADR-0041); run portable C fixtures under AddressSanitizer and UndefinedBehaviorSanitizer, including 12,000 deterministic malformed/near-valid IPv4/IPv6 length mutations per test run. Refresh evidence report and static portal. | PR #19 remains open. CI run 39922014929 passed all six jobs, including 305/304 Rust tests and both WDK builds. The driver binaries are unsigned; neither packet direction has been exercised against an installed driver. InfVerif was not retained after its runner invocation failed without retrievable diagnostics. |

**Legacy visualization warning:** the older PNG dashboards under `docs/assets/progress/` contain unsupported completion/velocity percentages and stale gate labels. This report intentionally does not reuse them; the dated 2026-10-23 SVGs linked below are the current evidence-based visuals.

### 1.2 Technical work by subsystem

| Workstream | Implemented in source / tests | Verification boundary |
|---|---|---|
| **Core policy and scheduling** | Link health/hysteresis, capacity estimation, flow classification/rules, weighted rendezvous placement, flow affinity, per-flow/per-class sessions, bonding gain tracking, MTU/keepalive policy, rate limiting, per-path congestion control, ECN/delay response, pacing and DRR integration. | Unit tests in CI. These tests validate control logic, not live adapter behavior or link performance. |
| **Tunnel and recovery** | First-party versioned frame handling, authenticated AEAD framing, sequence/reorder handling, duplicate/reinjection behavior, per-session sequence/retransmission state, FlowData and selective FlowAck repair, failover logic and sleep/resume state handling. | Unit, end-to-end simulation and fuzz-style tests; a real UDP socket test exists. No driver-path or multi-WAN hardware acceptance. |
| **Crypto and identity** | Noise_IK-style authenticated handshake, ChaCha20-Poly1305, pinned identities, replay protection, key-update derivation (coordinated live rekey pending under ADR-0043), zeroization and platform-aware key storage (including Windows DPAPI). | Crypto and client/service policy tests in CI; no external security review or production deployment validation. |
| **Service and relay** | Sans-I/O service core, secure lab transport policy, loopback-only TCP IPC adapter, event subscriptions, telemetry snapshots, endpoint filtering and fail-closed identity/pinning. The service parses bounded raw IP, injects received tunnel payloads through opt-in `INJECT_NBL`, and polls queued NDIS TX packets into the tunnel after a session is established. | Service and relay tests pass. The binary still uses simulated uplinks and loopback TCP IPC; both device paths are source/CI-only and not runtime-tested. This is not a production Windows service or authenticated named-pipe implementation. |
| **IPC and app shell** | IPC v1 request/response/event framing, bounded payloads, strict UTF-8 decoding, client timeout/stale-state behavior, redacted support bundle, Rust CLI modes for Home/Rules/Diagnostics/Tray/Relay/Bundle. | IPC/app tests pass. Production named-pipe ACL/caller authentication, persistent UI state and the WinUI 3/.NET 10 UI are not delivered. |
| **NDIS/WDF driver** | C source for a first-party miniport/control device, raw-IP medium, bounded OIDs, packet checks, owned NBL/MDL handling, pause/return lifecycle hardening and restricted control-device SDDL. Both directions have source: `INJECT_NBL` for service-to-OS packets and a 64-slot bounded TX FIFO plus `DEQUEUE_TX` for OS-to-service packets. The WDK-independent C validator checks TCP/UDP boundaries and IPv6 extension traversal before retaining/indicating packets; service and driver validators require exact unfragmented UDP/IP payload lengths. | Pinned x64/ARM64 WDK compile/link and unsigned PE architecture/mitigation checks pass in CI; INF source contracts pass. No signed install, Driver Verifier, HVCI/HLK run, or runtime packet-path test. |
| **Installer** | Lab CLI parsing, dry-run flow, journal JSON serialization/permissions, exclusive reservation of default journal paths, transactional sidecar-copy/rollback logic, collision and failure tests. | Rust tests cover logic only. No production MSI/bootstrapper, bundled runtime, offline VM install/uninstall, power-loss recovery or rollback drill. |
| **Supply chain and CI** | Locked dependency graph and crypto policy audit; SPDX 2.3 and SPDX 3.0.1 inventory generation, validation and CI artifacts; Linux jobs pinned to Ubuntu 24.04; Pages workflow actions updated to exact releases. | PR run 39922014929 passes all six software/static CI jobs. This proves source/build/test/policy checks, not driver signing or deployment. No reviewed VEX or release attestation. |
| **Observability and lab tooling** | ETW event-writing source, telemetry and redacted support bundle, netem safety tooling, analysis utilities, software microbenchmarks, HVCI and clean-machine procedures. | No live ETW trace decode, netem measurement, real Rig B measurement, or HVCI/clean-machine procedure execution. |

### 1.3 Current test evidence

The latest verified PR check run publishes the following test counts (zero-test binaries omitted). The one-test difference is in the client suite between operating systems. These are PR-branch results, not a merged-main baseline.

![Rust test counts from latest PR CI](assets/progress/test-evidence-2026-10-23.svg)

| Suite | Ubuntu | Windows |
|---|---:|---:|
| Core | 83 | 83 |
| Service library | 59 | 59 |
| Service binary | 10 | 10 |
| Crypto | 39 | 39 |
| Tunnel | 35 | 35 |
| Relay | 13 | 13 |
| IPC | 18 | 18 |
| Installer | 12 | 12 |
| Client | 13 | 12 |
| App | 8 | 8 |
| End-to-end | 9 | 9 |
| Fuzz/property tests | 6 | 6 |
| **Total** | **305** | **304** |

PR run 39922014929 also passed the dependency/crypto policy audit, lab analysis/tool tests, and pinned x64/ARM64 WDK compile/link plus static PE and INF source-contract checks. Driver artifacts are unsigned and do not establish an install, runtime packet path, HVCI or product acceptance result; see `.github/workflows/ci.yml` and `docs/phase2/lab-progress.md`.

### 1.4 Momentum and velocity

![Delivery signal: integration versus acceptance evidence](assets/progress/delivery-signal-2026-10-23.svg)

**Software integration remains green:** PR #19 is open; PR CI run 39922014929 passed all six jobs on PR head `02409cf`, including sanitizer-enabled portable C tests and 12,000 deterministic parser mutations, Ubuntu and Windows workspace tests, x64/ARM64 WDK builds, static PE checks, dependency audit and lab-tool tests. The portal source is refreshed with this evidence, but deployment is unverified and is not claimed live.

**Velocity is not quantified.** The repository does not contain a consistent sprint cadence, estimated story-point history, stable backlog denominator, staffing record, or approved phase dates. Commit counts and test counts are not substitutes for scope-normalized throughput. Consequently this report provides no velocity slope, burn-down percentage, or completion percentage. A measured velocity/burn-down chart should be added only after agreeing a work-unit scheme and maintaining dated sprint snapshots.

## 2. Prospective planning — dependencies and deliverables

### 2.1 Dependency-aware roadmap

![Blueprint phase schedule ranges and current G2 blocker](assets/progress/roadmap-sequence-2026-10-23.svg)

The diagram transcribes the blueprint’s original phase-duration ranges. It does not locate “today” on those ranges: actual resource-loaded start/end dates are absent, and software work has advanced ahead of some gate evidence. Treat the ranges as planning inputs to re-baseline, not commitments.

### 2.2 Proposed deliverables and sequencing

The horizons below are **proposed planning windows after the required resources are assigned**, not booked dates. The existing blueprint estimates remain the only documented duration baseline.

| Horizon / phase | Deliverable | Dependencies and exit evidence | Lead / external prerequisite |
|---|---|---|---|
| **T0–2 weeks: unblock G2** | x64/ARM64 compile/link, unsigned PE/INF source checks, `INJECT_NBL`, and bounded TX queue/polling source paths are now present. Next, set up a disposable test-signed Windows VM and execute driver load, IOCTL, steering and bidirectional packet-path smoke tests. | WDK/VS source builds are available in CI; still required: test-signed driver, Secure Boot/vTPM-compatible VM, Driver Verifier plan and runtime packet evidence. G2 requires steering evidence across ≥3 adapter classes plus tunnel operation through the first-party miniport; current CI does not satisfy this. | Driver engineer; Windows/WDK lab access; test-signing setup. |
| **After G2: Phase 3 / G3** | Benchmark driver packet-path latency/CPU/memory; execute Driver Verifier with code-integrity, HLK HVCI readiness, and VBS/Memory Integrity VM tests; perform Partner Center/attestation dry run; finalize IPC contract and GUI wireframes. | G2 closed; WDK-built/test-signed driver; instrumented Windows VM; Partner Center slot and signing strategy. G3 exits only with measurement, HVCI and signing evidence. | Driver/performance/release engineering; signing enrollment and external service lead times. |
| **After G3: Phase 4 / G4** | Complete service-to-adapter packet path, production authenticated named-pipe IPC, WinUI 3/.NET 10 shell, self-host/relay packaging, offline installer/bootstrapper, and real Rig B acceptance set. | G3; signed driver path; real wired/Wi-Fi/cellular test rig and relay; 10-repeat data collection; installer runtime bundle and acceptance definitions. G4 includes 11 planned acceptance items in `throughput-rows.md` / `clean-machine-test.md`; none has recorded passing evidence at this snapshot. | Systems, UI and packaging engineers; Rig B; clean Windows VM farm. |
| **Phase 5 / G5 (blueprint 6–8 weeks)** | Internal alpha, 72-hour soak, random link flaps, 100 sleep/resume cycles, Driver Verifier, crash/dump path, clean install/uninstall. | G4; test-signed/signed driver; stable release candidate; offline x64/ARM64 VMs with HVCI on/off. | Test/support engineering; soak rig and VM matrix. |
| **Phase 6 / G6 (blueprint 8 weeks)** | Compatibility matrix for VPN/AV/Hyper-V/WSL2/Memory Integrity; external security review, including driver and fuzz results; docs site live. | G5; supported Windows images; reviewer booking; Pages configuration. | Security reviewer and compatibility lab. |
| **Phase 7 / G7 (blueprint 4–6 weeks)** | RC, final attestation, signed installer/update feed, reviewed VEX, SBOM release validation, service+driver rollback drill and signed checklist. | G6; signing submission queue; current advisory data and reviewed impact analysis; complete rollback implementation. | Release/security engineering; Partner Center/attestation. |
| **Phase 8 / G8 (blueprint 2 weeks + field observation)** | GA distribution (download/winget), support runbooks, status page and opt-in telemetry; observe initial field stability. | G7; distribution validation, operational owner and support readiness. | Release/operations/support. |

**Near-term critical path:** test-signed miniport install/runtime smoke test → validate both service/NDIS packet directions and adapter steering → G2 closure → G3 performance/HVCI/signing → G4 real adapter/Rig B/clean install. GUI, installer bundling and VEX work can progress in parallel, but they cannot substitute for these gates.

### 2.3 Risks and management actions

| Risk | Impact | Current signal | Mitigation / decision needed |
|---|---|---|---|
| Driver runtime or service/NDIS lifecycle fails | Critical-path schedule and system stability | WDK x64/ARM64 compile/link and static artifact checks pass; no signed install, Verifier, HVCI or packet-path run | Assign NDIS/WDK owner and lab; track test-signing, verifier and adapter smoke results as separate gate artifacts. |
| Product performance differs from software simulation | Core value proposition unproven | No Rig B or real netem data; benchmark is CPU-side | Collect raw 10-run data only through the driver and relay; retain baselines and instrumentation. |
| Production IPC/GUI remain absent | Product not user-operable | Loopback TCP lab adapter and CLI only | Define authenticated named-pipe ACL/caller identity, then implement and test against the service. |
| Installer is not a distributable product | Cannot validate offline install, recovery or uninstall | Journal logic only; no signed bundle/clean VM run | Assign packaging engineer; create clean VM matrix and failure-injection rollback test. |
| Signing/HVCI/VEX/external review lead time | Release gate delay | Procedures and SBOM inventory exist; executions/review not recorded | Start signing coordination and reviewer booking before G3/G6; record external dependencies and dates. |
| Pages deployment is unverified | No public docs/distribution site | Main deployment run `39793993235` failed; the cause was not investigated in this continuation | Investigate the failed deployment with repository administration, then verify the published URL before claiming the portal is live. |
| Schedule/velocity estimates could mislead stakeholders | Poor forecasting | No sized backlog or resource-loaded plan | Establish owners, work-unit sizing, iteration cadence, planned-vs-actual dates before publishing burndown/ETA. |

## 3. Strategic alignment — position relative to the product strategy

![Strategic alignment matrix](assets/progress/strategic-alignment-2026-10-23.svg)

The strategy is **aligned at the architecture and source-foundation level**, but not yet at the end-to-end product-evidence level:

1. **C1 — multi-WAN aggregation:** core scheduling, tunnel, recovery and simulated end-to-end behavior exist; first-party miniport source now has bidirectional queue/injection paths, but runtime integration and real acceptance are absent. This is the principal proof gap.
2. **C2 — self-contained runtime:** dependency policy and audit are implemented and pass CI. A real bundle-content audit remains necessary at release.
3. **C3 — offline provisioning:** journal/rollback/sidecar source logic has tests, but no signed offline installer or clean-machine trial exists.
4. **C4 — minimal/supply-chain dependencies:** lockfile audit and SPDX 2.3/3.0.1 CI pipeline exist. Reviewed VEX and final release attestation do not.
5. **C5 — staged execution and governance:** blueprint, ADRs and gate procedures exist, but formal G1 sign-off, staffed owners, schedule baselines and exit artifacts are not evidenced in this snapshot.

### Gate register

| Gate | Required exit criterion (short form) | Status as of report | Evidence needed to close |
|---|---|---|---|
| **G1** | Decisions, policy, signing strategy and enrollment | **Unverified** | Store/review formal decision and enrollment/signing evidence; do not infer pass from ADRs alone. |
| **G2** | Steering plus first-party tunnel through test-signed miniport | **Open** | ≥3 adapter classes; test-signed install and runtime steering; end-to-end bidirectional miniport/driver test on a rig. WDK compile/link is already covered by CI. |
| **G3** | Driver performance, HVCI trio, signing dry-run | **Blocked by G2** | Packet-path metrics; Verifier/HLK/VBS-MI results; accepted signing dry-run. |
| **G4** | Real §10.3 acceptance and clean-machine offline provisioning | **Pending** | 11 acceptance items; real rig, signed driver, offline install/uninstall and rollback evidence. |
| **G5** | Soak and Verifier clean | **Pending** | 72-hour run, flaps/resume matrix, no crashes/leaks, clean install matrix. |
| **G6** | External review and compatibility matrix | **Pending** | Review report with no unresolved high-severity issue; matrix across supported configurations. |
| **G7** | RC checklist, attestation, SBOM/VEX and rollback proof | **Partial foundations only** | Final signing/attestation, reviewed VEX, release SBOM validation and rollback drill. |
| **G8** | Field stability and production operations | **Pending** | GA distribution, support/status operations and field observation. |

### Strategic conclusion

Balancify has a credible, testable first-party software base, healthy cross-platform CI, and now a pinned x64/ARM64 WDK compile/link baseline. Its strategic differentiator—usable, reliable aggregation through its own signed Windows driver—has not crossed the hardware-integration gate. The project trajectory is therefore **software-foundation complete enough to justify the next validation investment, but product readiness remains contingent on G2–G4 evidence**. Additional software-only feature counts will not reduce the main risk as efficiently as test-signed VM access and Rig B acceptance.

## Sources, definitions and reproducibility

- Current PR #19 CI/check summaries: [run 39922014929](https://github.com/eTarikhi/BalanciFy/actions/runs/39922014929), PR head `02409cf` (packet-boundary code `9be616f`); all six jobs passed. PR remains open, so these results are not merged-main evidence.
- Documentation deployment: [main run 39793993235](https://github.com/eTarikhi/BalanciFy/actions/runs/39793993235) failed; the cause has not been investigated in this continuation. The portal is not claimed live.
- Product gates and 47–58 week phase estimate: `docs/technical-blueprint.md`, especially §11.1–§11.3. Estimates assume a 5–6 engineer team and require re-baselining.
- Demonstrated behavior and limitations: `docs/phase2/lab-progress.md`.
- Proposed empirical acceptance and methodology: `docs/phase2/throughput-rows.md` and `docs/phase2/clean-machine-test.md`.
- Driver/HVCI status and procedure: `docs/phase2/hvci-readiness.md`, `driver/README.md`, `driver/src/`.
- Dependency/inventory and CI definitions: `.github/workflows/ci.yml`, `tools/ci/`, `Cargo.lock`.
- Test counts above are transcribed from PR #19 GitHub Actions check summaries, not locally inferred. All strategic status labels are evidence labels, not percentage-completion estimates.
