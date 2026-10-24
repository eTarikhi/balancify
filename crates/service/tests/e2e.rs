//! End-to-end scenarios: the real service core, the real tunnel lane and the
//! real IPC contract, driven over a **simulated** multi-path network.
//!
//! What this file is: a deterministic, repeatable regression gate for the
//! behaviours Sec.6 promises -- in-order delivery across a delay gap, reinjection
//! after loss, failover when an uplink disappears, and the shell protocol.
//!
//! What this file is **not**: a measurement. Simulated delays are not netem,
//! and a passing test here says nothing about throughput on Rig B. The Sec.10.3
//! acceptance numbers still have to be produced on the real rig; until then
//! they stay *proposed* (blueprint Sec.10.3).

use std::collections::{BTreeMap, BTreeSet};
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use balancify_core::{FlowKey, UplinkId};
use balancify_ipc::{self as ipc, FrameKind as IpcFrameKind};
use balancify_service::{Action, Service, ServiceConfig};
use balancify_tunnel::{FrameKind, Header, PassThrough, Receiver, ReceiverConfig};

// ------------------------------------------------------------------ the rig

#[derive(Debug, Clone)]
struct PathProfile {
    delay: Duration,
    /// Drop the first N frames sent on this path (deterministic loss tests).
    drop_first: u32,
    /// Drop every Nth frame on this path, for sustained-loss tests. 0 = never.
    drop_every: u32,
}

impl PathProfile {
    fn new(delay: Duration) -> Self { Self { delay, drop_first: 0, drop_every: 0 } }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    ToServer,
    ToClient,
}

/// Discrete-time network: every frame carries the step at which it lands.
struct SimNet {
    t0: Instant,
    step: Duration,
    clock: u64,
    inflight: Vec<(u64, Dir, UplinkId, Vec<u8>)>,
    uplinks: BTreeMap<UplinkId, PathProfile>,
    sent_on_path: BTreeMap<u8, u32>,
    load: BTreeMap<u8, u64>,
    lost: u64,
    /// Uplinks that have been unplugged: frames sent on them vanish.
    unplugged: BTreeSet<u8>,
}

impl SimNet {
    fn new(step: Duration) -> Self {
        Self {
            t0: Instant::now(),
            step,
            clock: 0,
            inflight: Vec::new(),
            uplinks: BTreeMap::new(),
            sent_on_path: BTreeMap::new(),
            load: BTreeMap::new(),
            lost: 0,
            unplugged: BTreeSet::new(),
        }
    }

    /// Client->server frames the rig handed to this uplink: the load it carried.
    fn uplink_load(&self, uplink: UplinkId) -> u64 {
        self.load.get(&uplink.0).copied().unwrap_or(0)
    }

    fn now(&self) -> Instant { self.t0 + self.step * (self.clock as u32) }
    fn advance(&mut self) { self.clock += 1; }
    fn lost(&self) -> u64 { self.lost }
    fn unplug(&mut self, uplink: UplinkId) { self.unplugged.insert(uplink.0); }

    fn push(&mut self, dir: Dir, uplink: UplinkId, bytes: Vec<u8>) {
        let n = self.sent_on_path.entry(uplink.0).or_insert(0);
        *n += 1;
        if dir == Dir::ToServer {
            *self.load.entry(uplink.0).or_insert(0) += 1;
        }
        let profile = self.uplinks.get(&uplink).cloned().unwrap_or_else(|| PathProfile::new(self.step));
        if self.unplugged.contains(&uplink.0) {
            self.lost += 1;
            return;
        }
        if *n <= profile.drop_first {
            self.lost += 1;
            return;
        }
        if profile.drop_every > 0 && *n % profile.drop_every == 0 {
            self.lost += 1;
            return;
        }
        let steps = (profile.delay.as_millis() / self.step.as_millis()).max(1) as u64;
        self.inflight.push((self.clock + steps, dir, uplink, bytes));
    }

    fn take_due(&mut self, dir: Dir) -> Vec<(UplinkId, Vec<u8>)> {
        let clock = self.clock;
        let mut due = Vec::new();
        self.inflight.retain(|(at, d, uplink, bytes)| {
            if *d == dir && *at <= clock {
                due.push((*uplink, bytes.clone()));
                false
            } else {
                true
            }
        });
        due
    }
}

/// The far end: the first-party receiver, standing in for the in-binary
/// cooperating endpoint (Sec.4.7 T1).
struct Server {
    rx: Receiver<PassThrough>,
    delivered: Vec<Vec<u8>>,
}

impl Server {
    fn new(hold_cap: Duration) -> Self {
        let cfg = ReceiverConfig { hold_cap, ..ReceiverConfig::default() };
        Self { rx: Receiver::new(PassThrough, cfg), delivered: Vec::new() }
    }

    /// Feed a datagram; returns the frames that must go back to the client.
    fn ingest(&mut self, dg: &[u8], now: Instant) -> Vec<Vec<u8>> {
        let mut replies = Vec::new();
        let mut events = self.rx.ingest(dg, now);
        events.extend(self.rx.drain(now)); // hold-cap tick (Sec.6.4 rule 3)
        for ev in events {
            match ev {
                balancify_tunnel::Event::Payload { data, .. } => self.delivered.push(data),
                other => {
                    if let Some(frame) = self.rx.reply_for(&other) { replies.push(frame); }
                }
            }
        }
        replies
    }

    fn out_of_order(&self) -> u64 { self.rx.counters().out_of_order }
    fn duplicates(&self) -> u64 { self.rx.counters().duplicates }
}

fn sa(p: u16) -> SocketAddr { SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), p)) }
fn peer(p: u16) -> SocketAddr { SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 9), p)) }

/// A realistic MTU-scale payload. Packet size matters here: DRR quanta are
/// bytes-per-millisecond of capacity, so 12-byte "packets" would let one path
/// win hundreds of turns in a row and the rig would stop looking like bonding.
fn pkt(i: usize) -> Vec<u8> {
    let mut v = format!("packet-{i:04}").into_bytes();
    v.resize(1200, b'.');
    v
}

/// Small payload for the duplicate-mode scenario: Sec.6.4 rule 5 only ever
/// duplicates packets at or under 256 bytes.
fn small_pkt(i: usize) -> Vec<u8> {
    let mut v = format!("query-{i:04}").into_bytes();
    v.resize(64, 0);
    v
}

/// Compare a delivered stream payload-by-payload, so a failure names the packet
/// instead of dumping ~100 KB of bytes.
fn assert_stream(got: &[Vec<u8>], count: usize, small: bool) {
    assert_eq!(got.len(), count, "expected {count} payloads, got {}", got.len());
    for i in 0..count {
        let want = if small { small_pkt(i) } else { pkt(i) };
        assert!(got[i] == want, "payload {i} is wrong or out of order");
    }
}

/// True when the tunnel would not take the packet because every eligible path
/// is inside its congestion window (Sec.6.4 rule 4). The rig then waits a step and
/// offers the packet again, which is what the miniport's queue does.
fn is_held(actions: &[Action]) -> bool {
    actions.iter().any(|a| matches!(a, Action::Hold { .. }))
}

/// Bring a service up with `paths` probed healthy and a published snapshot.
///
/// The probe RTT is only what the *control plane* believes; the wire delay is
/// configured separately on the rig, which is the point of having a rig.
fn client_with(paths: &[(UplinkId, Duration, u64)], now: Instant, cfg: ServiceConfig) -> Service<PassThrough> {
    let mut s = Service::new(cfg, PassThrough, PassThrough);
    for (id, rtt, capacity) in paths {
        s.add_uplink(*id, *capacity, false, 1500, now);
        for _ in 0..5 {
            s.on_probe_ok(*id, *rtt, now);
        }
    }
    assert!(s.publish(now));
    s
}

fn dispatch(net: &mut SimNet, actions: Vec<Action>) -> Vec<Vec<u8>> {
    let mut delivered = Vec::new();
    for a in actions {
        match a {
            Action::Send { uplink, bytes } => net.push(Dir::ToServer, uplink, bytes),
            Action::Deliver { data } => delivered.push(data),
            Action::Refused { flow, .. } => panic!("the rig always has a healthy path; refused {flow:?}"),
            Action::Hold { .. } => panic!("a held packet must be retried by the caller, not dispatched"),
        }
    }
    delivered
}

/// One step of simulated time: advance the clock, land whatever is due in both
/// directions, and run the client's timer.
fn step(net: &mut SimNet, client: &mut Service<PassThrough>, server: &mut Server) {
    net.advance();
    let now = net.now();
    for (uplink, bytes) in net.take_due(Dir::ToServer) {
        for reply in server.ingest(&bytes, now) {
            net.push(Dir::ToClient, uplink, reply);
        }
    }
    for (uplink, bytes) in net.take_due(Dir::ToClient) {
        let actions = client.ingest_path(uplink, &bytes, now);
        dispatch(net, actions);
    }
    let actions = client.tick(now);
    dispatch(net, actions);
}

// --------------------------------------------------------------- scenarios

/// Sec.6.4 rules 1-3: packets of one flow striped over a 40 ms delay gap must
/// still be released in order, because the reorder hold cap (80 ms) is larger
/// than the gap.
#[test]
fn striped_flow_is_reordered_back_across_a_40ms_delay_gap() {
    const PACKETS: usize = 80;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    net.uplinks.insert(UplinkId(1), PathProfile::new(Duration::from_millis(50)));

    let cfg = ServiceConfig { session: 42, seed: 0xC0FFEE, ..ServiceConfig::default() };
    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(50), 100_000_000),
        ],
        net.now(),
        cfg,
    );
    let mut server = Server::new(Duration::from_millis(80));
    let flow = FlowKey::new(6, sa(4000), peer(443));

    let mut sent = 0usize;
    let mut paths_used = BTreeSet::new();
    for _ in 0..4_000 {
        let now = net.now();
        // Two packets per 5 ms step: comfortably below either path's capacity.
        for _ in 0..2 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &pkt(sent), now);
            if is_held(&actions) { break; } // every window is full: retry next step
            for a in &actions {
                if let Action::Send { uplink, .. } = a { paths_used.insert(*uplink); }
            }
            dispatch(&mut net, actions);
            sent += 1;
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert_eq!(paths_used.len(), 2, "bond mode must stripe over both uplinks: {paths_used:?}");
    assert_stream(&server.delivered, PACKETS, false);
    assert_eq!(server.out_of_order(), 0, "an 80 ms hold cap absorbs a 40 ms gap (Sec.6.4 rule 3)");
    assert_eq!(net.lost(), 0);
    assert_eq!(client.counters().refused, 0);
    assert!(client.counters().packets_stripped as usize >= PACKETS);
}

/// Sec.6.4 rule 5: packets lost on one path are reinjected on another and the
/// stream still arrives complete and in order, with no cap expiry.
#[test]
fn reinjection_recovers_lost_packets_inside_the_hold_cap() {
    const PACKETS: usize = 40;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    let mut slow = PathProfile::new(Duration::from_millis(50));
    slow.drop_first = 2; // the first two frames that take the slow path vanish
    net.uplinks.insert(UplinkId(1), slow);

    // RTO 30 ms: the copies leave long before the 80 ms hold cap expires.
    let cfg = ServiceConfig { rto: Duration::from_millis(30), ..ServiceConfig::default() };
    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(50), 100_000_000),
        ],
        net.now(),
        cfg,
    );
    let mut server = Server::new(Duration::from_millis(80));
    let flow = FlowKey::new(6, sa(4001), peer(443));

    let mut sent = 0usize;
    for _ in 0..4_000 {
        let now = net.now();
        for _ in 0..2 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &pkt(sent), now);
            if is_held(&actions) { break; }
            dispatch(&mut net, actions);
            sent += 1;
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert_stream(&server.delivered, PACKETS, false);
    assert_eq!(net.lost(), 2, "the rig dropped exactly the two seeded packets");
    assert!(client.counters().reinjections >= 2, "each loss triggers a reinjection: {:?}", client.counters());
    assert_eq!(server.out_of_order(), 0, "recovery happened inside the hold cap");
}

/// Sec.4.5 / Sec.10.3 failover: unplugging an uplink mid-transfer must not lose the
/// transfer. In-flight packets on the dead path are reinjected on the survivor.
#[test]
fn unplugging_an_uplink_mid_transfer_keeps_the_stream_alive() {
    const PACKETS: usize = 100;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    net.uplinks.insert(UplinkId(1), PathProfile::new(Duration::from_millis(30)));

    let cfg = ServiceConfig { rto: Duration::from_millis(30), ..ServiceConfig::default() };
    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(30), 100_000_000),
        ],
        net.now(),
        cfg,
    );
    let mut server = Server::new(Duration::from_millis(80));
    let flow = FlowKey::new(6, sa(4002), peer(443));

    let mut sent = 0usize;
    let mut killed = false;
    let mut paths_before = BTreeSet::new();
    let mut paths_after = BTreeSet::new();
    for _ in 0..8_000 {
        let now = net.now();
        for _ in 0..2 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &pkt(sent), now);
            if is_held(&actions) { break; }
            let mut on_slow = false;
            for a in &actions {
                if let Action::Send { uplink, .. } = a {
                    if killed { paths_after.insert(*uplink); } else { paths_before.insert(*uplink); }
                    if *uplink == UplinkId(1) { on_slow = true; }
                }
            }
            dispatch(&mut net, actions);
            sent += 1;
            // Kill the moment a packet is on the slow path, once both paths are
            // in use. That packet is provably still in flight -- its 30 ms delay
            // is six rig steps -- so the failure has something to lose and only
            // reinjection can recover it. Choosing the moment this way keeps
            // the scenario independent of the exact DRR burst schedule.
            if on_slow && !killed && paths_before.contains(&UplinkId(0)) {
                net.unplug(UplinkId(1));
                client.remove_uplink(UplinkId(1));
                client.publish(now);
                killed = true;
            }
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert!(killed);
    assert_eq!(paths_before.len(), 2, "both uplinks were in use before the failure: {paths_before:?}");
    assert_eq!(paths_after, BTreeSet::from([UplinkId(0)]), "only the survivor carries traffic afterwards");
    assert_stream(&server.delivered, PACKETS, false);
    assert!(client.counters().reinjections > 0, "in-flight packets were moved off the dead path");
    assert_eq!(client.counters().refused, 0);
}

/// Sec.6.2 vs Sec.6.4: with bonding off, a flow rides one uplink and is never held up
/// by the other path's delay -- the flow-level lane must not reorder.
#[test]
fn flow_level_mode_is_not_held_up_by_the_other_path() {
    const PACKETS: usize = 40;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    net.uplinks.insert(UplinkId(1), PathProfile::new(Duration::from_millis(120)));

    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(120), 100_000_000),
        ],
        net.now(),
        ServiceConfig::default(),
    );
    client.handle(ipc::Request::SetBondMode { enabled: false }, net.now());
    let mut server = Server::new(Duration::from_millis(80));
    let flow = FlowKey::new(6, sa(4003), peer(443));

    let mut sent = 0usize;
    let mut used = BTreeSet::new();
    for _ in 0..4_000 {
        let now = net.now();
        for _ in 0..2 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &pkt(sent), now);
            if is_held(&actions) { break; }
            for a in &actions {
                if let Action::Send { uplink, .. } = a { used.insert(*uplink); }
            }
            dispatch(&mut net, actions);
            sent += 1;
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert_eq!(used.len(), 1, "a non-striped flow stays on one uplink: {used:?}");
    assert_stream(&server.delivered, PACKETS, false);
    assert_eq!(server.out_of_order(), 0);
    assert_eq!(server.duplicates(), 0);
}

/// Duplicate mode (Sec.6.4 rule 5) must cost bandwidth, never correctness: the
/// inner stream still sees each packet exactly once, in order.
#[test]
fn duplicate_mode_delivers_each_packet_once() {
    const PACKETS: usize = 20;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    net.uplinks.insert(UplinkId(1), PathProfile::new(Duration::from_millis(20)));

    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(20), 100_000_000),
        ],
        net.now(),
        ServiceConfig::default(),
    );
    client.handle(ipc::Request::SetDuplicateMode { enabled: true }, net.now());
    let mut server = Server::new(Duration::from_millis(80));
    // DNS: latency-sensitive and duplicate-eligible in the curated rules.
    let flow = FlowKey::new(17, sa(4004), peer(53));

    let mut sent = 0usize;
    for _ in 0..2_000 {
        let now = net.now();
        for _ in 0..2 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &small_pkt(sent), now);
            if is_held(&actions) { break; }
            dispatch(&mut net, actions);
            sent += 1;
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert!(client.counters().duplicates_sent > 0, "duplicate mode must have fired");
    assert!(server.duplicates() > 0, "the endpoint must have seen the copies");
    assert_stream(&server.delivered, PACKETS, true);
}

/// The shell's whole view of the product, over the wire: encode request frames,
/// let the service handle them, decode the response frames (Phase 3 M6).
#[test]
fn shell_and_service_speak_contract_v1_over_a_stream() {
    let now = Instant::now();
    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(12), 200_000_000),
            (UplinkId(1), Duration::from_millis(45), 100_000_000),
        ],
        now,
        ServiceConfig::default(),
    );
    let flow = FlowKey::new(6, sa(4005), peer(443));
    let mut sink = SimNet::new(Duration::from_millis(5));
    let actions = client.send_app_packet(&flow, None, b"hello", now);
    dispatch(&mut sink, actions);

    // One stream, three requests back to back -- the last one cut short.
    let mut stream = Vec::new();
    stream.extend(ipc::frame_request(&ipc::Request::Ping));
    stream.extend(ipc::frame_request(&ipc::Request::GetStatus));
    stream.extend(ipc::frame_request(&ipc::Request::ListFlowRules));
    stream.truncate(stream.len() - 3);

    let mut responses = Vec::new();
    let mut offset = 0;
    while let Some((kind, payload, consumed)) =
        ipc::decode_frame(&stream[offset..]).expect("a partial frame is not an error")
    {
        assert_eq!(kind, IpcFrameKind::Request, "expected a request frame");
        let req = ipc::Request::decode(payload).expect("well-formed request");
        responses.push(client.handle(req, now));
        offset += consumed;
    }
    assert_eq!(responses.len(), 2, "the truncated third request waits for more bytes");

    assert!(matches!(responses[0], ipc::Response::Pong { .. }));
    let ipc::Response::Status(snap) = &responses[1] else { panic!("expected a status snapshot"); };
    assert_eq!(snap.uplinks.len(), 2);
    assert_eq!(snap.adapter_mtu, 1440);
    assert_eq!(snap.active_flows, 1);
    assert!(snap.uplinks.iter().any(|u| u.weight_permille == 1000 && u.eligible));
    assert!(snap.uplinks.iter().all(|u| u.state == ipc::STATE_UP));

    // and the response itself survives the framing
    let encoded = ipc::frame_response(&responses[1]);
    let (kind, payload, consumed) = ipc::decode_frame(&encoded).unwrap().unwrap();
    assert_eq!(kind, IpcFrameKind::Response);
    assert_eq!(consumed, encoded.len());
    assert_eq!(ipc::Response::decode(payload), Some(responses[1].clone()));
}

/// Garbage off the wire must be dropped at the door. Note what this test can
/// *not* claim: with the lab null cipher there is no authentication, so a
/// well-formed frame is accepted. The reject path itself is covered by the
/// tunnel's tamper test; real authentication arrives with the Phase-4 handshake.
#[test]
fn unparseable_datagrams_are_dropped_at_the_door() {
    let now = Instant::now();
    let mut client = client_with(
        &[(UplinkId(0), Duration::from_millis(12), 200_000_000)],
        now,
        ServiceConfig::default(),
    );
    let short = vec![0u8; 19]; // one byte short of a header
    for junk in [b"".as_slice(), b"\x00\x01".as_slice(), short.as_slice()] {
        assert!(client.ingest_path(UplinkId(0), junk, now).is_empty());
    }
    assert_eq!(client.counters().delivered, 0);

    // Lab form auto-accepts a session it has never seen. That is a documented
    // property of the lab rig, not a security claim (Sec.9.2).
    let mut frame = Vec::new();
    Header::new(FrameKind::Data, 0, 999, 0).encode(&mut frame);
    frame.extend_from_slice(b"lab-form");
    let actions = client.ingest_path(UplinkId(0), &frame, now);
    assert!(
        actions.iter().any(|a| matches!(a, Action::Deliver { .. })),
        "lab form auto-accepts; the Phase-4 handshake must not"
    );
    assert_eq!(client.counters().delivered, 1);
}

/// Sec.6.4 rule 4: a path that keeps losing packets shrinks its window, so the
/// scheduler shifts the flow to the clean path. Nothing is lost, because the
/// losses are reinjected elsewhere, and congestion produces backpressure
/// rather than drops.
#[test]
fn a_lossy_path_carries_less_than_a_clean_one() {
    const PACKETS: usize = 200;
    let mut net = SimNet::new(Duration::from_millis(5));
    net.uplinks.insert(UplinkId(0), PathProfile::new(Duration::from_millis(10)));
    let mut lossy = PathProfile::new(Duration::from_millis(10));
    lossy.drop_every = 3; // every third frame on this path vanishes
    net.uplinks.insert(UplinkId(1), lossy);

    let cfg = ServiceConfig { rto: Duration::from_millis(30), ..ServiceConfig::default() };
    let mut client = client_with(
        &[
            (UplinkId(0), Duration::from_millis(10), 200_000_000),
            (UplinkId(1), Duration::from_millis(10), 100_000_000),
        ],
        net.now(),
        cfg,
    );
    let mut server = Server::new(Duration::from_millis(80));
    let flow = FlowKey::new(6, sa(4006), peer(443));

    let mut sent = 0usize;
    for _ in 0..20_000 {
        let now = net.now();
        for _ in 0..4 {
            if sent >= PACKETS { break; }
            let actions = client.send_app_packet(&flow, None, &pkt(sent), now);
            if is_held(&actions) { break; }
            dispatch(&mut net, actions);
            sent += 1;
        }
        step(&mut net, &mut client, &mut server);
        if server.delivered.len() >= PACKETS { break; }
    }

    assert_stream(&server.delivered, PACKETS, false);
    let clean = net.uplink_load(UplinkId(0));
    let dirty = net.uplink_load(UplinkId(1));
    assert!(clean > dirty, "the clean path carries more: clean {clean}, lossy {dirty}");
    assert!(
        client.window(UplinkId(1)) < client.window(UplinkId(0)),
        "the lossy path's window shrank: {} vs {}",
        client.window(UplinkId(1)),
        client.window(UplinkId(0))
    );
    assert!(client.counters().held > 0, "the tunnel applied backpressure instead of overrunning");
    assert_eq!(client.counters().refused, 0, "congestion holds packets, it does not refuse them");
    assert!(net.lost() > 0, "the rig really did drop frames");
}

/// Secure handshake end-to-end over real UDP sockets: client Service initiates
/// Noise_IK, relay SecureRelay handles msg1, replies msg2, then tunnel data
/// flows encrypted and is reordered correctly.
#[test]
fn secure_handshake_over_real_udp_delivers_encrypted_stream() {
    use balancify_crypto::{PinnedKeys, StaticKeypair};
    use balancify_service::ServiceConfig;
    use balancify_tunnel::ReceiverConfig;
    use std::net::UdpSocket;
    use std::time::{Duration, Instant};

    // Relay keypair
    let relay_kp = StaticKeypair::generate();
    let client_kp = StaticKeypair::generate();

    // Bind relay socket
    let relay_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    relay_sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
    let relay_addr = relay_sock.local_addr().unwrap();

    // Bind client socket
    let client_sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    client_sock.set_read_timeout(Some(Duration::from_secs(2))).unwrap();

    // SecureRelay state (simplified, single session)
    let mut relay_state = {
        // We reuse the SecureRelay logic from relay crate via direct crypto
        // For this test we implement minimal responder handling inline
        struct TestRelay {
            static_kp: StaticKeypair,
            pinned: PinnedKeys,
            replay: balancify_crypto::ReplayCache,
            session: Option<(u64, balancify_tunnel::Receiver<balancify_crypto::TunnelCipher>, balancify_tunnel::Sender<balancify_crypto::TunnelCipher>)>,
        }
        TestRelay {
            static_kp: relay_kp.clone(),
            pinned: PinnedKeys::new(),
            replay: balancify_crypto::ReplayCache::with_defaults(),
            session: None,
        }
    };

    // Service as client with dummy ciphers, will be replaced after handshake
    let dummy_key = [0u8; 32];
    let dummy_salt = [0u8; 3];
    let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
    let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
    let cfg = ServiceConfig { session: 999, seed: 0xBEEF, auto_accept: false, ..ServiceConfig::default() };
    let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
    svc.set_static_keypair(client_kp.clone());
    let mut pinned_relays = PinnedKeys::new();
    pinned_relays.pin(relay_kp.public_bytes());
    svc.set_pinned_relays(pinned_relays);
    svc.add_uplink(UplinkId(0), 200_000_000, false, 1500, Instant::now());
    for _ in 0..5 { svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), Instant::now()); }
    svc.publish(Instant::now());

    // Client initiates handshake
    let msg1_framed = svc.initiate_handshake(relay_kp.public_bytes(), b"balancify handshake v1").expect("initiate");
    client_sock.send_to(&msg1_framed, relay_addr).unwrap();

    // Relay receives msg1
    let mut buf = [0u8; 65535];
    let (n, client_addr) = relay_sock.recv_from(&mut buf).unwrap();
    assert!(n >= 2 && buf[0] == 0xFF && buf[1] == 0x01, "must be handshake msg1");
    let msg1 = &buf[2..n];

    let mut responder = balancify_crypto::Responder::new(relay_state.static_kp.secret_bytes(), b"balancify handshake v1");
    let payload = responder.read_message_checked(
        msg1,
        Some(&relay_state.pinned),
        Some(&mut relay_state.replay),
        Some(Instant::now()),
    ).expect("relay reads msg1");
    assert_eq!(payload, 999u64.to_be_bytes());

    let eph_r = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
    let (msg2, transport_keys_relay) = responder.write_message(eph_r, &999u64.to_be_bytes()).expect("relay msg2");

    // Store relay session
    let recv_cipher = transport_keys_relay.recv_cipher().unwrap();
    let send_cipher = transport_keys_relay.send_cipher().unwrap();
    let rx_cfg = ReceiverConfig { hold_cap: Duration::from_millis(80), idle_timeout: Duration::from_secs(120), auto_accept: false, max_sessions: 64 };
    let mut rx = balancify_tunnel::Receiver::new(recv_cipher, rx_cfg);
    rx.open_session(999, Instant::now());
    let tx = balancify_tunnel::Sender::with_config(999, send_cipher, vec![(0, 2000)], balancify_tunnel::SenderConfig::default());
    relay_state.session = Some((999, rx, tx));

    // Relay sends msg2 framed
    let mut msg2_framed = Vec::with_capacity(2 + msg2.len());
    msg2_framed.push(0xFF);
    msg2_framed.push(0x02);
    msg2_framed.extend_from_slice(&msg2);
    relay_sock.send_to(&msg2_framed, client_addr).unwrap();

    // Client receives msg2
    let (n2, _) = client_sock.recv_from(&mut buf).unwrap();
    assert!(n2 >= 2 && buf[0] == 0xFF && buf[1] == 0x02);
    let now = Instant::now();
    svc.handle_handshake_msg2(&buf[..n2], now).expect("client handles msg2");
    assert_eq!(svc.sessions(), 1);

    // Client sends encrypted data via service
    let flow = FlowKey::new(6, sa(5000), peer(443));
    let actions = svc.send_app_packet(&flow, None, b"hello secure world", now);
    let mut sent_bytes = None;
    for a in actions {
        if let Action::Send { bytes, .. } = a { sent_bytes = Some(bytes); }
    }
    let frame = sent_bytes.expect("must send");
    client_sock.send_to(&frame, relay_addr).unwrap();

    // Relay receives tunnel frame
    let (n3, _) = relay_sock.recv_from(&mut buf).unwrap();
    if buf[0] != balancify_tunnel::WIRE_VERSION {
        eprintln!("Unexpected frame version {} kind {} len {} first bytes {:02x?}", buf[0], buf.get(1).copied().unwrap_or(255), n3, &buf[..n3.min(16)]);
        // If it's handshake, try to handle as handshake (maybe client re-sent)
        if buf[0] == 0xFF {
            eprintln!("Got handshake frame instead of tunnel, attempting to handle");
        }
    }
    assert_eq!(buf[0], balancify_tunnel::WIRE_VERSION, "must be tunnel version");
    let (payloads, replies) = {
        let (_id, ref mut rx, ref mut tx) = relay_state.session.as_mut().unwrap();
        let mut payloads = Vec::new();
        let mut replies = Vec::new();
        for ev in rx.ingest(&buf[..n3], now) {
            match ev {
                balancify_tunnel::Event::Payload { data, .. } => payloads.push(data),
                balancify_tunnel::Event::Ack { path, seq, .. } => {
                    let sent = tx.ack(path, seq);
                    replies.push(sent.bytes);
                }
                _ => {}
            }
        }
        (payloads, replies)
    };
    assert_eq!(payloads.len(), 1);
    assert_eq!(payloads[0], b"hello secure world");
    assert!(!replies.is_empty(), "must ACK");

    // Relay sends ACK back
    for reply in replies {
        relay_sock.send_to(&reply, client_addr).unwrap();
    }

    // Client receives ACK
    let (n4, _) = client_sock.recv_from(&mut buf).unwrap();
    let actions = svc.ingest_path(UplinkId(0), &buf[..n4], now);
    // ACK should be processed, no delivery
    assert!(actions.is_empty() || actions.iter().all(|a| matches!(a, Action::Send { .. })), "ACK should not deliver payload");
}
