# Test coverage — 261 Linux / 260 Windows Rust tests + 7 SBOM tool tests, what is covered

Date: 2026-10-22
Status: continuous; push run 39799406998 and PR run 39799412825 passed all six jobs, including unsigned x64/ARM64 WDK compile/link, PE architecture/mitigation/unsigned-status checks, INF contract tests, and the fail-closed MTU contract test. The counts below are that historical snapshot; the 2026-10-24 rekey safety regression and revised behavior are documented in ADR-0043, and the current Rust total awaits the next full-profile run.

## Counts

- core: 83 tests
  - bond.rs: WRH minimal disruption, removing uplink moves only flows that were on it
  - congestion.rs: 13 tests (slow start, halving once per burst, floor, per-path independence, LIA, ECN 80% vs 50% loss, burst once, delay detection 10% reduction, ack_with_rtt, ecn_ce, delay_events_path, rtt_min/last)
  - flowtable.rs: flow affinity, eviction, etc.
  - health.rs: health hysteresis fast drop / slow return Sec.6.5
  - keepalive.rs: keepalive scheduler per-path, traffic arms timers, expire_all
  - mtu.rs: adapter MTU min(live path MTU) - overhead, Sec.6.1
  - pacing.rs: paces at configured rate, allows when idle, respects max delay, per-path, forget/reset, rate update, prevents burst 14KB at 10Mbit/s spread over ~11ms, 7 tests
  - placement.rs: WRH placement
  - policy.rs: PolicyEngine wrapper for on_flow_packet
  - ratelimit.rs: TokenBucket allow within burst, hold when over, refill over time, 3 tests
  - rules.rs: FlowClass classification, curated defaults, duplicate eligible
  - scoring.rs: CapacityEstimator on_packet_sent, on_flow_packet, rolls window, notes traffic, suppresses idle probe, ACK pacing window, sleep/resume restarts window >90 Mbit/s vs stale <80
- crypto: 39 tests
  - lib.rs: 10 tests (16-byte tag only overhead, plaintext absent from ciphertext, every bit position refused, header bound as AAD, nonce separated by frame kind/path/seq/salt/key, kind authenticated in the nonce and header, 1024 nonces distinct, wrong-length key refused, 20-payload stream end-to-end)
  - handshake.rs: 12 tests (both sides derive same two keys, pinned relay identity authenticates, every byte of flight 1 authenticated, prologue binds context, initiator static travels encrypted, fresh ephemeral gives fresh session, flights out of order refused, truncations refused, negotiated keys drive tunnel lane, pinning enforced both sides, replay cache rejects second flight)
  - keys.rs: static keypair derives public, ephemeral zeroized on drop, pinned keys pin/unpin, OS RNG distinct
  - store.rs: memory store generates/remembers, pinned keys roundtrip, file store roundtrips/rejects corrupt, private temporary permissions and pre-created symlink safety
  - replay.rs: 5 tests (new ephemeral not replay, same within window is replay, expired not replay, capacity evicts oldest, different ephemerals not replay)
  - lib.rs rekey: 3 tests (rekey changes key but keeps salt, rekey deterministic and one-way, transport keys rekey both directions)
- ipc: 17 tests (wire contract, message round-trips, truncation/partial-frame handling, strict decoding, stable opcodes, loopback-only binding, fragmented/pipelined transport, event push, malformed-frame rejection, and 60-second timeout for idle unsubscribed clients)
- relay: 27 tests
  - Endpoint: two_paths_with_delay_gap_reassemble_in_order, ignores_garbage, deduplicates_duplicate_mode_copy, answers_probes, drains_gap_after_hold_cap, ordered_stream_survives_a_real_udp_socket
  - SecureRelay: relay_handshake_failure_logs_are_rate_limited, relay_sweep_scheduler_uses_elapsed_time_not_fresh_instant_age, relay_state_dir_resolution_uses_one_default_and_rejects_empty_override, relay_refuses_a_corrupt_pinned_client_store, listen_port_configuration_rejects_partial_or_empty_lists, forward_address_configuration_fails_closed_on_invalid_values, connected_forward_socket_rejects_unexpected_udp_sources, forwarding_socket_lookup_does_not_cross_sessions, secure_handshake_creates_session, secure_relay_rejects_duplicate_session_id_without_replacing_session, secure_relay_rejects_noncanonical_session_payload_length, failed_handshake_response_can_remove_the_unreachable_session, secure_relay_rejects_unpinned_client, secure_relay_rejects_replay, secure_tunnel_after_handshake, relay_peer_rebinding_requires_a_fresh_authenticated_frame, secure_relay_enforces_rate_limit_and_session_cap, handshake_rate_limit_tracking_is_bounded_under_source_churn, global_handshake_limiter_bounds_bursts_and_refills_smoothly, secure_relay_rate_limits_handshakes_per_ip, relay_session_idle_timer_ignores_unauthenticated_datagrams
- service: 40+ tests
  - bonded_flow_is_striped_across_both_uplinks, flow_level_mode_keeps_a_flow_on_one_uplink, duplicate_mode_sends_critical_packets_twice, no_healthy_uplink_refuses_instead_of_black_holing, an_idle_peer_session_releases_its_slot, an_unanswered_probe_is_forgotten_after_the_probe_timeout, a_capacity_sample_lands_on_the_uplink_that_carried_the_data, sleep_resume_abandons_dead_state_and_requires_reprobing, a_nat_rebinding_rekeys_the_path_and_keeps_the_session, a_full_window_holds_the_packet_instead_of_dropping_it, acknowledgements_reopen_the_window, tick_emits_keepalives_and_a_bounded_probe, probe_reply_becomes_rtt_and_capacity, forged_ack_does_not_refresh_relay_liveness, ipc_status_reflects_the_live_system, ipc_rule_edits_reach_the_classifier, ipc_rejects_an_absurd_event_rate, ipc_telemetry_snapshot_contains_warnings_and_counter_values, ipc_support_bundle_returns_complete_redacted_json_over_the_contract, self_test_reports_no_capacity_before_probes, bond_revert_event_carries_the_measured_gain, adapter_mtu_follows_the_narrowest_live_path, metered_uplink_stays_out_until_the_user_allows_it, uplink_loss_fails_over_and_flows_keep_their_affinity, secure_handshake_establishes_transport_keys, handshake_rejects_wrong_session_echo_without_installing_keys, handshake_rejects_malformed_session_echo_without_installing_keys, pinning_enforced_rejects_unpinned_relay, relay_failover_switches_on_timeout, packet_threshold_marks_update_due_without_unilateral_cipher_rotation, time_threshold_marks_update_due_without_unilateral_cipher_rotation, per_flow_sessions_assign_distinct_ids, per_class_sessions_assign_distinct_ids, rate_limiter_holds_when_over_limit, flow_level_capacity_uses_peer_acknowledgements, flow_level_tick_reinjects_unacknowledged_data_on_another_uplink, ecn_and_delay_wire_via_ingest, bundle_includes_per_path_ecn_delay, support_bundle_reports_relay_presence_without_exposing_endpoint, json_string_escaping_handles_quotes_slashes_and_controls
- tunnel: 35 tests
  - DRR proportionality 3000:1000 quanta give exactly 15:5 packets over 20 MTU-scale sends, FlowData has an independent nonce/replay sequence without gapping ordered Data, unacknowledged FlowData is reinjected on an alternate path after RTO and a duplicate is re-ACKed without delivery, all control frames including FlowAck require AEAD authentication and reject replay, selective FlowAck state is session-scoped and bounded, keepalives use fresh nonce sequences, sender_without_paths_refuses_rather_than_panicking, ack_frees_the_retx_window_and_reports_bytes, retx_window_is_bounded, etc.
  - ECN: ack_with_ecn FLAG_ECN_CE=0x04
- e2e: 9 tests (striped_flow_is_reordered_back_across_a_40ms_delay_gap, reinjection_recovers_a_lost_packet_inside_the_hold_cap, unplugging_an_uplink_mid_transfer_keeps_the_stream_alive, flow_level_mode_is_not_held_up_by_the_other_path, duplicate_mode_delivers_each_packet_once, shell_and_service_speak_contract_v1_over_a_stream, secure_handshake_over_real_udp_delivers_encrypted_stream, etc.)
- fuzz: 6 tests (20k rounds each for datagram and IPC-frame loops, no panic, no invented payload, session and hold caps bound memory, length checks hold, replay cannot manufacture delivery)
- client: 13 Linux / 12 Windows tests (missing identity fails closed, release builds reject insecure mode, debug lab requires explicit opt-in and loopback, pinned relay resolution, malformed/all-zero key rejection, per-user state-directory override, absolute-path validation, platform fallback selection, unexpected relay-source filtering, duplicate handshake-response rejection)
- app: 0 tests (lab CLI)
- installer: 4 tests (journaled transactional/dry-run plus required SBOM copy and missing-SBOM rejection)
- SBOM tool: 7 Python tests for locked-graph closure, dev-dependency exclusion, license/checksum preservation, invalid-license handling, VEX omission, missing graph rejection, and atomic writes; CI also validates the generated document using `spdx-tools` 0.8.5.
- crypto bench, drr-bench, pacing-bench, ecn-bench, throughput.rs, etc. (binaries, not tests)

Total: 260 Rust tests on Linux and 259 on Windows (the Unix-only state-path test is cfg-gated), plus 7 Python SBOM tests and standards-parser validation. The latest aggregate handshake-limiter regression has been added since the recorded CI run. Current local contract checks add 24 Python CI tests (including PE architecture, mitigation-flag, unsigned-artifact parser, and portal-status cases) and 10 driver packet/OID/INF tests; project XML parsing and `git diff --check` also pass. Earlier runner failures were corrected (E0503 borrow checker in delay detection, missing Counters fields, truncated test tail, FlowClass/BondClass mismatch, WindowsEtwHandle case, bench imports, rate-limiter burst, non-ASCII markers, format! escaping, and ACK argument order).

## Gaps (deliberate, in scope for rest of Phase 2/3)

- `Cargo.lock` is committed and checked by the dependency audit; no lockfile regeneration was needed for this phase.
- Simulated paths are not netem (delay and loss applied to frames in discrete-time rig, S2c real measurements pending, harness exists netem-rig.sh + throughput.rs)
- x64 and ARM64 WDK compile/link, PE machine-type, DYNAMIC_BASE/FORCE_INTEGRITY/NX_COMPAT and unsigned-status checks, and INF architecture/version contract tests passed in push run 39799406998 using pinned WDK 10.0.26100.6584 with signing disabled; both `.sys` artifacts are unsigned and are not installation/runtime evidence.
- Miniport in the loop is not yet the S2b socket path: test-signed installation, Driver Verifier, HVCI/VM, and packet-path tests remain pending.
- Wire-v2 FlowData has authenticated selective FlowAck and bounded alternate-path RTO repair; CI tests tunnel and service behavior, but real network loss/reordering and NDIS integration remain untested.
- Retransmission entries and cumulative ACK matching are keyed by `(session, seq)`; per-session Data sequence spaces coexist with a shared bounded byte budget.
- Wintun fallback is stub, not real Wintun.dll bundling (feature-gated, exception file check, ADR-0009)
- Throughput rows simulated, not real Rig B (wired 1 Gbps, Wi-Fi 6 300 Mbit/s, secure mode, pacing 80% capacity, per-flow off/on, 10 reps, iperf3 pending)

## References

- Blueprint Sec.10.3 acceptance rows, Sec.10.1 10 reps median/p95/spread, Sec.6.4 DRR+pacing+CC, S13 SBOM/VEX, C2/C4
- CI: 39476560004 success on Ubuntu and Windows, release build, lab safety tests, and dependency/crypto audit
