//! Balancify desktop shell -- IPC client that renders service status
//! This is a lab CLI that mimics the WinUI shell's behavior over IPC v1 (Sec.8.2).
//! The real WinUI 3 / .NET 10 shell would use the same IPC contract over a named pipe.
//! This CLI connects via TCP loopback (for CI/Linux) and renders Home, Rules, Diagnostics.
//! Enhanced with per-path ECN/delay, bond gain, uplink up/down, rekey, relay failover,
//! per-flow sessions, Rig B throughput, HVCI, SBOM.

use balancify_ipc::{
    decode_frame, encode_frame, Counters, Event, FrameKind, Request, Response,
    FRAME_HEADER_LEN, MAX_PAYLOAD, StatusSnapshot,
};
use std::io::{Read, Write};
use std::net::{TcpStream, SocketAddr};
use std::time::{Duration, Instant};

fn parse_ipc_addr(value: Option<&str>) -> std::io::Result<SocketAddr> {
    let addr = value
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid IPC socket address"))?
        .unwrap_or_else(|| "127.0.0.1:5000".parse().unwrap());
    if !addr.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "lab IPC client is restricted to loopback addresses",
        ));
    }
    Ok(addr)
}

fn main() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let addr = parse_ipc_addr(args.get(1).map(String::as_str))?;
    let mode = args.get(2).map(|s| s.as_str()).unwrap_or("home");

    println!("Balancify shell -- connecting to {} mode={}", addr, mode);
    let mut stream = TcpStream::connect(addr)?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    stream.set_write_timeout(Some(Duration::from_secs(2)))?;

    // Send requests based on mode
    match mode {
        "home" => {
            let mut last_good: Option<LastKnownGoodHome> = None;
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                if let Response::Status(snapshot) = &resp {
                    let now = Instant::now();
                    if let Some(cache) = last_good.as_mut() {
                        cache.refresh_status(snapshot.clone(), now);
                    } else {
                        last_good = Some(LastKnownGoodHome::new(snapshot.clone(), now));
                    }
                }
                render_home(resp);
            }
            // Subscribe to events at 1 Hz. Preserve the last-known-good view if
            // the request or acknowledgement fails after the initial snapshot.
            let subscription_result = send_request(
                &mut stream,
                &Request::SubscribeEvents { interval_hz: 1 },
            )
            .and_then(|()| recv_response(&mut stream));
            match subscription_result {
                Ok(Some(Response::Ack)) => {
                    println!("Subscribed to events at 1 Hz, listening for 5 events...");
                    for _ in 0..5 {
                        match recv_event(&mut stream) {
                            Ok(Some(ev)) => {
                                let now = Instant::now();
                                if let Some(cache) = last_good.as_mut() {
                                    let was_stale = cache.stale_reason().is_some();
                                    cache.apply_event(&ev, now);
                                    if !was_stale && cache.stale_reason().is_some() {
                                        render_stale_home(cache, now);
                                    }
                                }
                                render_event(ev);
                            }
                            Ok(None) => {
                                render_connection_stale_home(
                                    last_good.as_mut(),
                                    "No event arrived before the IPC read timeout; showing cached status as stale.",
                                );
                                break;
                            }
                            Err(error) => {
                                render_connection_stale_home(
                                    last_good.as_mut(),
                                    &format!("IPC event stream failed: {error}; showing cached status as stale."),
                                );
                                break;
                            }
                        }
                    }
                }
                Ok(Some(response)) => render_connection_stale_home(
                    last_good.as_mut(),
                    &format!("Event subscription was not accepted: {:?}; showing cached status as stale.", response),
                ),
                Ok(None) => render_connection_stale_home(
                    last_good.as_mut(),
                    "Service closed the IPC connection before acknowledging the event subscription; showing cached status as stale.",
                ),
                Err(error) => render_connection_stale_home(
                    last_good.as_mut(),
                    &format!("Could not subscribe to IPC events: {error}; showing cached status as stale."),
                ),
            }
        }
        "rules" => {
            send_request(&mut stream, &Request::ListFlowRules)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_rules(resp);
            }
            send_request(&mut stream, &Request::ListUplinks)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_uplinks(resp);
            }
        }
        "diagnostics" => {
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_diagnostics(resp);
            }
            send_request(&mut stream, &Request::RunSelfTest)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_selftest(resp);
            }
        }
        "tray" => {
            // Tray flyout: minimal status
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_tray(resp);
            }
        }
        "relay" => {
            // Relay & account screen (Sec.8.2)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_relay(resp);
            }
        }
        "bundle" => {
            // Export the service's redacted support diagnostics over IPC v1.
            send_request(&mut stream, &Request::GetSupportBundle)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_bundle(resp);
            }
        }
        "perflow" => {
            // Per-flow sessions (Sec.4.7.4, ADR-0029)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_perflow(resp);
            }
        }
        "rigb" => {
            // Rig B throughput (Sec.10.3)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_rigb(resp);
            }
        }
        "hvci" => {
            // HVCI readiness (S15)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_hvci(resp);
            }
        }
        "sbom" => {
            // SBOM/VEX (S13)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_sbom(resp);
            }
        }
        "failover" => {
            // Failover convergence <=2s (Sec.10.3, Sec.4.5)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_failover(resp);
            }
        }
        "soak" => {
            // Soak 72h + random flaps + 100 resume (G5)
            send_request(&mut stream, &Request::GetStatus)?;
            if let Some(resp) = recv_response(&mut stream)? {
                render_soak(resp);
            }
        }
        _ => {
            println!("Unknown mode {}, available: home, rules, diagnostics, tray, relay, bundle, perflow, rigb, hvci, sbom, failover, soak", mode);
        }
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct LastKnownGoodHome {
    snapshot: StatusSnapshot,
    last_seen: Instant,
    connection_stale: bool,
    snapshot_stale_reason: Option<&'static str>,
}

impl LastKnownGoodHome {
    fn new(snapshot: StatusSnapshot, now: Instant) -> Self {
        Self {
            snapshot,
            last_seen: now,
            connection_stale: false,
            snapshot_stale_reason: None,
        }
    }

    fn refresh_status(&mut self, snapshot: StatusSnapshot, now: Instant) {
        self.snapshot = snapshot;
        self.last_seen = now;
        self.connection_stale = false;
        self.snapshot_stale_reason = None;
    }

    fn apply_event(&mut self, event: &Event, now: Instant) {
        self.last_seen = now;
        match event {
            Event::Stats(counters) => self.snapshot.counters = *counters,
            Event::UplinkStateChanged { id, state } => {
                if let Some(uplink) = self.snapshot.uplinks.iter_mut().find(|uplink| uplink.id == *id) {
                    uplink.state = *state;
                } else {
                    self.snapshot_stale_reason = Some("an unknown uplink changed state");
                }
            }
            Event::PolicyChanged { revision } => {
                self.snapshot.policy_revision = *revision;
                self.snapshot_stale_reason = Some("policy changed; full status refresh required");
            }
            Event::BondReverted { .. } => {
                self.snapshot_stale_reason = Some("bond placement changed; full status refresh required");
            }
            Event::Warning { .. } => {}
        }
    }

    fn mark_connection_stale(&mut self) {
        self.connection_stale = true;
    }

    fn stale_reason(&self) -> Option<&'static str> {
        if self.connection_stale {
            Some("IPC event stream timed out or disconnected")
        } else {
            self.snapshot_stale_reason
        }
    }

    fn age(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_seen)
    }
}

fn render_stale_home(cache: &LastKnownGoodHome, now: Instant) {
    let age = cache.age(now);
    let reason = cache.stale_reason().unwrap_or("status is cached");
    eprintln!(
        "[STALE] showing last-known-good Home status ({:.1}s old): {}",
        age.as_secs_f64(),
        reason
    );
    render_home(Response::Status(cache.snapshot.clone()));
}

fn render_connection_stale_home(cache: Option<&mut LastKnownGoodHome>, message: &str) {
    eprintln!("{message}");
    if let Some(cache) = cache {
        cache.mark_connection_stale();
        render_stale_home(cache, Instant::now());
    } else {
        println!("No last-known-good service snapshot is available.");
    }
}

fn send_request(stream: &mut TcpStream, req: &Request) -> std::io::Result<()> {
    let payload = req.encode();
    let mut frame = Vec::new();
    encode_frame(FrameKind::Request, &payload, &mut frame).unwrap();
    stream.write_all(&frame)?;
    Ok(())
}

fn read_frame(stream: &mut TcpStream) -> std::io::Result<Option<(FrameKind, Vec<u8>)>> {
    read_frame_inner(stream, false)
}

fn read_frame_inner(
    stream: &mut TcpStream,
    idle_timeout_returns_none: bool,
) -> std::io::Result<Option<(FrameKind, Vec<u8>)>> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    // A timeout is a harmless idle poll only if no byte of a frame has arrived.
    // Once a frame starts, any timeout is a truncated frame and must be surfaced.
    match stream.read(&mut header[..1]) {
        Ok(0) => return Ok(None),
        Ok(1) => {}
        Ok(_) => unreachable!("one-byte read cannot exceed the buffer"),
        Err(error)
            if idle_timeout_returns_none
                && (error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error),
    }
    stream.read_exact(&mut header[1..])?;
    let len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    if len > MAX_PAYLOAD {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "IPC frame exceeds maximum payload"));
    }
    let mut frame = header.to_vec();
    frame.resize(FRAME_HEADER_LEN + len, 0);
    stream.read_exact(&mut frame[FRAME_HEADER_LEN..])?;
    let (kind, payload, consumed) = decode_frame(&frame)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "incomplete IPC frame"))?;
    if consumed != frame.len() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "trailing bytes after IPC frame"));
    }
    Ok(Some((kind, payload.to_vec())))
}

fn recv_response(stream: &mut TcpStream) -> std::io::Result<Option<Response>> {
    match read_frame(stream)? {
        None => Ok(None),
        Some((FrameKind::Response, payload)) => Response::decode(&payload)
            .map(Some)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid IPC response payload")),
        Some(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected IPC response frame")),
    }
}

fn recv_event(stream: &mut TcpStream) -> std::io::Result<Option<Event>> {
    let frame = read_frame_inner(stream, true)?;
    match frame {
        None => Ok(None),
        Some((FrameKind::Event, payload)) => Event::decode(&payload)
            .map(Some)
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid IPC event payload")),
        Some(_) => Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "expected IPC event frame")),
    }
}

fn render_home(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Home ===");
            println!("Service version: {} schema: {}", s.service_version, s.schema_version);
            println!("Bond: {} Duplicate: {} Allow metered: {} MTU: {}", s.bond_enabled, s.duplicate_mode, s.allow_metered, s.adapter_mtu);
            println!("Policy rev: {} Rules rev: {} Active flows: {}", s.policy_revision, s.rules_revision, s.active_flows);
            println!("Uplinks:");
            for u in &s.uplinks {
                println!("  id={} state={} rtt={}ms loss={}‰ cap={}bps weight={}‰ metered={} eligible={}",
                    u.id, u.state, u.rtt_ms, u.loss_permille, u.capacity_bps, u.weight_permille, u.metered, u.eligible);
            }
            render_counters(&s.counters);
            println!("ETW: 200 UPLINK_UP, 201 DOWN, 300 BOND_REVERTED, 400 REKEY, 401 ECN_CE, 402 DELAY, 500 FAILOVER, 600 AUTH_FAILED");
        }
        _ => println!("Unexpected response: {:?}", resp),
    }
}

fn render_rules(resp: Response) {
    match resp {
        Response::FlowRules(rules) => {
            println!("=== Flow Rules ({} rules) ===", rules.len());
            for r in rules {
                println!("  id={} name={} class={} pinned={} prio={} proto={} ports={}-{} dup={}",
                    r.id, r.name, r.class, r.pinned_uplink, r.priority, r.proto, r.port_start, r.port_end, r.duplicate);
            }
            println!("Plain-language preview: This rule sends Zoom over lowest-latency healthy link (Sec.8.2)");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_uplinks(resp: Response) {
    match resp {
        Response::Uplinks(list) => {
            println!("=== Uplinks ({} uplinks) ===", list.len());
            for u in list {
                println!("  id={} state={} rtt={}ms loss={}‰ cap={}bps", u.id, u.state, u.rtt_ms, u.loss_permille, u.capacity_bps);
            }
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_diagnostics(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Diagnostics (Sec.8.2, Sec.9.2 redacted) ===");
            println!("Version: {} policy_rev={} rules_rev={} active_flows={}", s.service_version, s.policy_revision, s.rules_revision, s.active_flows);
            render_counters(&s.counters);
            println!("ECN CE: {} (80% reduction, milder than loss 50%) Delay events: {} (10% reduction)", s.counters.ecn_ce, s.counters.delay_events);
            println!("Per-path diag (from support bundle): cwnd/in_flight/ecn_ce/delay_events/rtt_min/last_ms (see support/mod.rs)");
            for u in &s.uplinks {
                println!("  uplink id={} cap={}bps rtt={}ms eligible={} — cwnd/in_flight from cc.window/in_flight, ECN/delay from cc.ecn_ce/delay_events_path", u.id, u.capacity_bps, u.rtt_ms, u.eligible);
            }
            println!("Bond gain tracker: auto-disable <15% gain reverts class to flow-level, emits BondReverted event 300");
            println!("Rekey: packets_since_rekey, last_rekey_ago_secs, forward secrecy 1h/1M packets, ETW 400");
            println!("Relay: current + failover count, convergence <=2s, ETW 500 failover, 600 auth failed, history (time, convergence)");
            println!("Uplink failover: count + convergence <=2s Sec.10.3 Sec.4.5, ETW 200 UP 201 DOWN, history (id, time, convergence), target full rate <=2s after unplug");
            println!("Support bundle JSON includes: relay_failover_count, relay_conv_ms, uplink_failover_count, uplink_conv_ms, cwnd/in_flight per uplink, congestion diag loss/ecn/delay+paths per_path Vec<PathCongestionDiag> cwnd/in_flight/ecn_ce/delay_events/rtt_min/last_ms, rekey diag, relay stats, ETW export, route table, adapter state");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_selftest(resp: Response) {
    match resp {
        Response::SelfTest { passed, detail } => {
            println!("=== Self-test ===");
            println!("Passed: {} Detail: {}", passed, detail);
            println!("Clean-machine offline provisioning: install->self-test->uninstall->clean (Sec.10.3)");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_tray(resp: Response) {
    match resp {
        Response::Status(s) => {
            let up_count = s.uplinks.iter().filter(|u| u.eligible).count();
            println!("Tray: {} uplinks up, {} flows, bond={}, dup={}", up_count, s.active_flows, s.bond_enabled, s.duplicate_mode);
            println!("Active mode + any down uplink, one-click pause/resume, keyboard + screen-reader operable (Sec.8.2)");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_relay(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Relay & Account (Sec.8.2) ===");
            println!("Service version: {} schema: {}", s.service_version, s.schema_version);
            println!("Counters: ecn={} delay={} loss via cwnd? (see diagnostics)", s.counters.ecn_ce, s.counters.delay_events);
            println!("Relay: region/address, key status, connection test button, secondary relay state, failover count");
            for u in &s.uplinks {
                println!("  uplink id={} cap={}bps rtt={}ms eligible={}", u.id, u.capacity_bps, u.rtt_ms, u.eligible);
            }
            println!("Connection test is the support call preventer (Sec.8.2)");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_bundle(resp: Response) {
    match resp {
        Response::SupportBundle(json) => {
            println!("=== Redacted Support Bundle (Sec.8.2, Sec.9.2) ===");
            println!("{json}");
        }
        _ => println!("Unexpected support-bundle response: {:?}", resp),
    }
}

fn render_perflow(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Per-flow Sessions (Sec.4.7.4, ADR-0029) ===");
            println!("Active flows: {} — each flow gets own session id (next_session_id starting 1000), seq per session, retx keyed by (session,seq)", s.active_flows);
            println!("Per-flow > per-class > default precedence, session cap 64, evicts oldest on cap");
            println!("Per-session seq spaces: true per-session demux without collision, aligns with RFC 8684 Sec.3.3");
            println!("Flow-level capacity: on_flow_packet (sent) + on_flow_ack (acked) in scoring.rs, policy.rs wrapper, ingest_path detects FlowData and calls on_flow_ack + on_ack");
            render_counters(&s.counters);
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_rigb(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Rig B Throughput (Sec.10.3) ===");
            println!("Hardware: Rig B per §10.1 — Windows 11 24H2 x64+ARM64, wired 1 Gbps, Wi-Fi 6 300 Mbit/s, USB 5G, relay Linux in-region, driver test-signed, HVCI on/off, VBS on");
            println!("Software: release build, secure mode Noise_IK, pacing 80% capacity (publish sets 80% + floor 1 Mbit/s), per-flow on/off, per-class off/on");
            println!("Traffic: iperf3 TCP 16 parallel flows aggregate, 1 TCP flow single-flow, UDP 1 flow, curated workloads");
            println!("Acceptance rows: aggregate >=90% sum after overhead, single-flow >=70% sum both links, mismatched >=100% best (no regression else auto-revert §6.4.6), added delay <=3ms wired lab, loss/reordering <=0.1%, failover <=2s, CPU & memory report first limits after S2, power delta, stability 72h soak + random flaps + 100 resume, compatibility matrix, clean-machine provisioning offline VM");
            render_counters(&s.counters);
            println!("Synthetic harness/placeholder output only: not measured on Rig B and not acceptance evidence; use `docs/phase2/throughput-rows.md` for real lab measurements.");
            println!("Real Rig B pending — harness throughput.rs has 5 profiles + Rig B + per-flow on/off + aggregate 16 flows + added delay + CPU/Gbit estimation via crypto-bench + ETW");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_hvci(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== HVCI Readiness Trio (S15, Sec.9.4, Sec.9.5) ===");
            println!("Requirement: Driver Verifier with code-integrity 0x209BB, HLK HVCIMemoryIntegrity test, VBS/Memory-Integrity VM with Secure Boot/vTPM/test-signing");
            println!("Code: miniport.c NBL pool via NdisAllocateNetBufferListPool(fAllocateNetBuffer=TRUE), ioctl.c length validation SDDL METHOD_BUFFERED, NonPagedPoolNx NormalPoolPriority, no RWX, MDL freeing via NdisFreeMdl, /integritycheck /DYNAMICBASE /NXCOMPAT /Qspectre, PoolTag BlaB, Spectre mitigation");
            println!("Build: msbuild driver/balancify.vcxproj /p:Configuration=Release /p:Platform=x64 — targets SDK 10.0.26100.0; CI pins WDK 10.0.26100.6584 for x64 and ARM64.");
            println!("Test: verifier /standard /driver balancify.sys, HLK Studio HVCIMemoryIntegrity, Hyper-V VM Gen2 Secure Boot on vTPM VBS, bcdedit testsigning on, pnputil add-driver, msinfo32 VBS Running MI enabled");
            render_counters(&s.counters);
            println!("Status: pinned x64/ARM64 WDK compile/link and unsigned PE checks pass in CI; signed installation, Driver Verifier, HVCI/VM, and packet-path validation remain pending.");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_sbom(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== SBOM status (S13) ===");
            println!("Generate the current SPDX 2.3 inventory with: sh tools/ci/sbom.sh [version] [output]");
            println!("The inventory comes from cargo metadata --locked and includes declared license metadata, source checksums, and dependency relationships.");
            println!("CI generates SPDX 2.3 and SPDX 3.0.1 inventories from the locked production graph and validates both; no VEX or vulnerability-status claims are generated.");
            println!("The installer includes both generated sidecars and fails if either is missing; clean-machine install and reviewed VEX remain pending.");
            render_counters(&s.counters);
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_failover(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Failover Convergence <=2s (Sec.10.3, Sec.4.5) ===");
            println!("Uplink failover: unplugging_an_uplink_mid_transfer_keeps_the_stream_alive — adapter removed moment packet provably in flight, in-flight reinjected on survivor, 100/100 delivered in order, no refusals");
            println!("Relay failover: primary + secondary, failover on 10s no ACK, back-and-forth, failover count, convergence measured first ACK after failover");
            println!("Target: transfer continues, full rate <=2s, ETW 200 UPLINK_UP, 201 DOWN, 500 FAILOVER, support bundle relay_failover_count, relay_conv_ms, uplink_failover_count, uplink_conv_ms, history (id/time/convergence)");
            println!("Real measurement: netem-rig.sh failover profile, tc loss 100% simulate unplug, 100ms throughput log, pktmon + Wireshark at adapter and per-uplink, ETW -> WPA");
            render_counters(&s.counters);
            println!("Simulated: throughput.rs failover profile mean Mbps + convergence ms, soak.rs random flaps 1000 iterations");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_soak(resp: Response) {
    match resp {
        Response::Status(s) => {
            println!("=== Soak 72h + Random Flaps + 100 Resume (G5, G6 compat matrix) ===");
            println!("Stability: 72h continuous traffic, random link flaps, 100 sleep/resume cycles, Verifier standard+random, no crash, no leaked route/filter/handle/IOCTL buffer");
            println!("Compat matrix: VPN clients, security suites, Hyper-V, WSL2, Memory Integrity on/off documented with workaround/incompatibility");
            println!("Soak harness: crates/service/src/bin/soak.rs 1000 iterations, 10 packets per iteration, random flap every 100 (remove_uplink_at + add_uplink + publish), sleep/resume every 10 (resume_from_sleep + tick keepalives), ECN every 200, delay jump every 300, loss every 100, tick for keepalives/rekey/failover/probes, checks pending_probes <=8, sessions <=64, held <=1000, support bundle per-path ECN/delay cwnd/in_flight");
            println!("ETW: 100-600 events, WPA CPU sampling, working set bounded, power delta via telemetry, 72h soak + random flaps + 100 resume with Verifier");
            render_counters(&s.counters);
            println!("Real: requires Rig B hardware + Hyper-V VM Gen2 Secure Boot/vTPM/VBS + pinned WDK 10.0.26100.6584 + Driver Verifier 0x209BB + HLK HVCIMemoryIntegrity + Memory Integrity");
        }
        _ => println!("Unexpected: {:?}", resp),
    }
}

fn render_counters(c: &Counters) {
    println!("Counters: stripped={} forwarded={} dups={} reinj={} delivered={} ooo={} refused={} auth_fail={} ecn={} delay={}",
        c.packets_stripped, c.packets_forwarded, c.duplicates_sent, c.reinjections, c.delivered, c.out_of_order, c.refused, c.auth_failed, c.ecn_ce, c.delay_events);
}

fn render_event(ev: Event) {
    match ev {
        Event::PolicyChanged { revision } => println!("[event] Policy changed rev={}", revision),
        Event::UplinkStateChanged { id, state } => println!("[event] Uplink {} state -> {} — ETW 200 UP 201 DOWN", id, state),
        Event::BondReverted { class, gain_permille } => println!("[event] Bond reverted class={} gain={}‰ — ETW 300, auto-disable <15% gain", class, gain_permille),
        Event::Stats(c) => {
            println!("[event] Stats: stripped={} forwarded={} ecn={} delay={} — 1 Hz telemetry", c.packets_stripped, c.packets_forwarded, c.ecn_ce, c.delay_events);
        }
        Event::Warning { code } => println!("[event] Warning code={} — Sec.4.5 failure modes", code),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balancify_ipc::UplinkInfo;
    use std::net::TcpListener;

    fn tcp_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        let (server, _) = listener.accept().unwrap();
        (client, server)
    }

    fn snapshot() -> StatusSnapshot {
        StatusSnapshot {
            service_version: "test".to_string(),
            schema_version: 1,
            policy_revision: 1,
            rules_revision: 1,
            bond_enabled: true,
            duplicate_mode: false,
            allow_metered: false,
            adapter_mtu: 1440,
            uplinks: vec![UplinkInfo {
                id: 0,
                state: 1,
                rtt_ms: 10,
                loss_permille: 0,
                capacity_bps: 1_000_000,
                weight_permille: 1000,
                metered: false,
                eligible: true,
            }],
            active_flows: 0,
            counters: Counters::default(),
        }
    }

    #[test]
    fn ipc_client_address_is_strictly_loopback_only() {
        assert_eq!(parse_ipc_addr(None).unwrap(), "127.0.0.1:5000".parse().unwrap());
        assert_eq!(parse_ipc_addr(Some("[::1]:5000")).unwrap(), "[::1]:5000".parse().unwrap());
        assert_eq!(
            parse_ipc_addr(Some("192.0.2.10:5000")).unwrap_err().kind(),
            std::io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            parse_ipc_addr(Some("not-an-address")).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn event_idle_timeout_is_only_ignored_before_frame_bytes_arrive() {
        let (mut client, _server) = tcp_pair();
        client.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        assert!(recv_event(&mut client).unwrap().is_none());

        let (mut client, mut server) = tcp_pair();
        client.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        server.write_all(&[1]).unwrap();
        let error = recv_event(&mut client).unwrap_err();
        assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn event_payload_timeout_propagates_after_frame_starts() {
        let (mut client, mut server) = tcp_pair();
        client.set_read_timeout(Some(Duration::from_millis(30))).unwrap();
        let mut frame = Vec::new();
        encode_frame(FrameKind::Event, &[0xaa, 0xbb], &mut frame).unwrap();
        server.write_all(&frame[..FRAME_HEADER_LEN + 1]).unwrap();
        let error = recv_event(&mut client).unwrap_err();
        assert!(matches!(error.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock));
    }

    #[test]
    fn stats_event_refreshes_last_known_good_counters_and_timestamp() {
        let start = Instant::now();
        let mut cache = LastKnownGoodHome::new(snapshot(), start);
        let later = start + Duration::from_secs(1);
        cache.apply_event(
            &Event::Stats(Counters { packets_forwarded: 7, ..Counters::default() }),
            later,
        );
        assert_eq!(cache.snapshot.counters.packets_forwarded, 7);
        assert_eq!(cache.age(later), Duration::ZERO);
        assert_eq!(cache.stale_reason(), None);
    }

    #[test]
    fn uplink_event_updates_cached_state_without_replacing_other_metrics() {
        let now = Instant::now();
        let mut cache = LastKnownGoodHome::new(snapshot(), now);
        cache.apply_event(&Event::UplinkStateChanged { id: 0, state: 2 }, now);
        assert_eq!(cache.snapshot.uplinks[0].state, 2);
        assert_eq!(cache.snapshot.uplinks[0].rtt_ms, 10);
        assert_eq!(cache.stale_reason(), None);
    }

    #[test]
    fn policy_change_marks_snapshot_stale_until_a_full_status_refresh() {
        let now = Instant::now();
        let mut cache = LastKnownGoodHome::new(snapshot(), now);
        cache.apply_event(&Event::PolicyChanged { revision: 2 }, now);
        assert_eq!(cache.snapshot.policy_revision, 2);
        assert_eq!(cache.stale_reason(), Some("policy changed; full status refresh required"));
        cache.apply_event(&Event::Stats(Counters::default()), now + Duration::from_secs(1));
        assert_eq!(cache.stale_reason(), Some("policy changed; full status refresh required"));
        cache.refresh_status(snapshot(), now + Duration::from_secs(2));
        assert_eq!(cache.stale_reason(), None);
    }

    #[test]
    fn subscription_failure_renders_and_marks_the_cached_home_stale() {
        let now = Instant::now();
        let mut cache = LastKnownGoodHome::new(snapshot(), now);
        render_connection_stale_home(Some(&mut cache), "subscription rejected");
        assert_eq!(cache.stale_reason(), Some("IPC event stream timed out or disconnected"));
    }

    #[test]
    fn event_stream_timeout_stays_stale_until_a_full_status_refresh() {
        let now = Instant::now();
        let mut cache = LastKnownGoodHome::new(snapshot(), now);
        cache.mark_connection_stale();
        assert_eq!(cache.stale_reason(), Some("IPC event stream timed out or disconnected"));
        cache.apply_event(&Event::Warning { code: 1 }, now + Duration::from_secs(2));
        assert_eq!(cache.stale_reason(), Some("IPC event stream timed out or disconnected"));
        cache.refresh_status(snapshot(), now + Duration::from_secs(3));
        assert_eq!(cache.stale_reason(), None);
        assert_eq!(cache.age(now + Duration::from_secs(3)), Duration::ZERO);
    }
}
