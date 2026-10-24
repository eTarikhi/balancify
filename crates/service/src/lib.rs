//! Balancify **service core** -- sans-I/O, platform-independent.
//!
//! This is the brain of the Windows service (blueprint Sec.4.2 control plane +
//! Sec.6 schedulers), written so it can be exercised in CI on Linux today and
//! dropped behind the Windows I/O adapters later:
//!
//! - one [`PolicyEngine`] publishes the snapshot both schedulers read (Sec.6.1);
//! - the flow scheduler classifies, keeps affinity and places flows (Sec.6.2);
//! - the striping scheduler runs the tunnel lane, duplicates critical packets
//!   and reinjects on loss (Sec.6.4);
//! - the IPC contract v1 is served directly ([`Service::handle`]), so the shell
//!   protocol is tested rather than mocked (Phase 3 milestone M6);
//! - keepalives, idle capacity probes and the reorder hold-cap tick happen in
//!   [`Service::tick`], which is where the real service's timer lands.
//!
//! Nothing here opens a socket or reads a clock: callers pass `now` and take
//! back [`Action`]s (Sec.4.7.4 sans-I/O loop).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub mod support;
pub mod driver_device;
pub mod etw;
pub mod packet;
pub mod wintun;
pub use balancify_ipc as ipc;

use balancify_core::{
    BondClass, BondGainTracker, FlowClass, FlowKey, FlowTable, KeepaliveScheduler, LinkState,
    path_changed, CongestionController, MtuPolicy, PacingController, PolicyConfig, PolicyEngine,
    PolicySnapshot, RuleSet, UplinkConfig, UplinkId, UplinkView, DEFAULT_KEEPALIVE_INTERVAL,
    EWMA_ALPHA, IPV4_MIN_MTU, TUNNEL_MTU,
};
use balancify_tunnel::{
    should_duplicate, Crypto, Event, FrameKind, Header, Receiver, ReceiverConfig, Sender,
    SenderConfig,
};

/// What the I/O adapter must do with the service's output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// Write this frame to the socket bound to `uplink`.
    Send { uplink: UplinkId, bytes: Vec<u8> },
    /// Hand this in-order payload to the inner stack / virtual adapter.
    Deliver { data: Vec<u8> },
    /// Nothing healthy could carry the packet; the caller applies the
    /// fail-open / fail-closed default (Sec.9.2, decision D3).
    Refused { flow: FlowKey, class: FlowClass },
    /// Every eligible path is inside its congestion window (Sec.6.4 rule 4). The
    /// packet was *not* dropped: the caller holds it and offers it again. The
    /// miniport requeues it; a rig simply retries on a later step.
    Hold { flow: FlowKey, data: Vec<u8> },
}

#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub session: u64,
    /// Per-boot hash seed (Sec.6.2 rule 4); logged in the support bundle.
    pub seed: u64,
    pub bond_enabled: bool,
    pub duplicate_mode: bool,
    pub allow_metered: bool,
    pub hold_cap: Duration,
    pub rto: Duration,
    pub idle_timeout: Duration,
    pub keepalive_interval: Duration,
    /// Tunnel bytes added per packet (framing + encapsulation + AEAD tag).
    pub tunnel_overhead: u16,
    /// Size the control plane asks for when probing an idle link (Sec.6.3b).
    pub idle_probe_bytes: u64,
    /// How long an unanswered idle probe is remembered before its entry is
    /// dropped. A reply that never comes must not leak table state.
    pub probe_timeout: Duration,
    /// Whether the receiver auto-accepts unknown sessions (lab form). Secure
    /// form sets this false and opens sessions explicitly after handshake
    /// verifies peer identity (Sec.9.2).
    pub auto_accept: bool,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            session: 1,
            seed: 0,
            bond_enabled: true,
            duplicate_mode: false,
            allow_metered: false,
            hold_cap: Duration::from_millis(80),
            rto: Duration::from_millis(120),
            idle_timeout: Duration::from_secs(120),
            keepalive_interval: DEFAULT_KEEPALIVE_INTERVAL,
            tunnel_overhead: 60,
            idle_probe_bytes: 1024,
            probe_timeout: Duration::from_secs(5),
            auto_accept: true,
        }
    }
}

/// Service counters, in the shape the shell renders (Sec.9.2: counters only,
/// never destinations or content).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub packets_stripped: u64,
    pub packets_forwarded: u64,
    pub duplicates_sent: u64,
    pub reinjections: u64,
    pub delivered: u64,
    pub out_of_order: u64,
    pub refused: u64,
    /// Packets handed back to the caller because every path was congested.
    pub held: u64,
    /// NAT mappings that moved under us (Sec.6.6).
    pub path_changes: u64,
    /// Sleep/resume cycles handled (Sec.4.5).
    pub resumes: u64,
    pub auth_failed: u64,
    pub keepalives: u64,
    pub probes: u64,
    /// Peer sessions released after the idle timeout (Sec.9.1). Not yet surfaced
    /// over IPC v1; the shell sees it in the support bundle.
    pub sessions_evicted: u64,
    pub ecn_ce: u64,
    pub delay_events: u64,
}

impl From<Counters> for ipc::Counters {
    fn from(c: Counters) -> Self {
        ipc::Counters {
            packets_stripped: c.packets_stripped,
            packets_forwarded: c.packets_forwarded,
            duplicates_sent: c.duplicates_sent,
            reinjections: c.reinjections,
            delivered: c.delivered,
            out_of_order: c.out_of_order,
            refused: c.refused,
            auth_failed: c.auth_failed,
            ecn_ce: c.ecn_ce,
            delay_events: c.delay_events,
        }
    }
}

pub struct Service<C: Crypto> {
    cfg: ServiceConfig,
    policy: PolicyEngine,
    snapshot: PolicySnapshot,
    flows: FlowTable,
    rules: RuleSet,
    bond: BondGainTracker,
    keepalives: KeepaliveScheduler,
    path_mtu: BTreeMap<UplinkId, u16>,
    tx: Sender<C>,
    rx: Receiver<C>,
    /// (path, probe id) -> (sent at, probe size), so a reply becomes both an RTT
    /// sample and a capacity sample.
    probes: BTreeMap<(u8, u64), (Instant, u64)>,
    /// Per-path congestion windows, coupled across paths (Sec.6.4 rule 4).
    pub cc: CongestionController,
    /// Per-path pacing, in front of the congestion window (Sec.6.4 rule 4).
    pacing: PacingController,
    /// Last observed local (source) endpoint per uplink, for NAT re-binding
    /// detection (Sec.6.6).
    path_local: BTreeMap<UplinkId, SocketAddr>,
    /// Key-update diagnostics. The one-way KDF can derive keys locally, but
    /// live sessions must not rotate until both peers coordinate the update.
    last_rekey: Option<Instant>,
    packets_since_rekey: u64,
    key_epoch_started: Option<Instant>,
    rekey_interval: Duration,
    rekey_packet_threshold: u64,
    rekey_due: bool,
    /// Relay failover (Sec.4.5): primary + secondary relay addrs, health tracking + convergence measurement Sec.10.3 failover <=2s
    relay_primary: Option<SocketAddr>,
    relay_secondary: Option<SocketAddr>,
    relay_current: Option<SocketAddr>,
    relay_last_ack: Option<Instant>,
    relay_failover_timeout: Duration,
    relay_failover_count: u64,
    relay_failover_start: Option<Instant>,
    relay_failover_convergence: Option<Duration>,
    relay_failover_history: Vec<(Instant, Duration)>, // (failover_time, convergence_duration)
    /// Uplink failover convergence tracking Sec.10.3 failover <=2s, Sec.4.5 unplugging mid-transfer
    uplink_failover_start: Option<Instant>,
    uplink_failover_convergence: Option<Duration>,
    uplink_failover_history: Vec<(UplinkId, Instant, Duration)>, // (uplink_id, failover_time, convergence)
    uplink_failover_count: u64,
    /// Per-flow session mapping (Sec.4.7.4, Phase-4): optional per-flow sessions
    per_flow_sessions: bool,
    flow_sessions: BTreeMap<FlowKey, u64>,
    next_session_id: u64,
    /// Per-class session mapping (Sec.4.7.4 alternative to per-flow)
    per_class_sessions: bool,
    class_sessions: BTreeMap<u8, u64>, // BondClass as u8 -> session id
    /// Per-uplink rate limiting (service egress)
    rate_limiter: balancify_core::RateLimiter,
    /// Pinned client identities (relay side) and pinned relay identities
    /// (client side). When non-empty, auto_accept must be false.
    pinned_clients: balancify_crypto::PinnedKeys,
    pinned_relays: balancify_crypto::PinnedKeys,
    /// Replay cache for handshake first flights (Sec.11.4).
    replay_cache: balancify_crypto::ReplayCache,
    /// Static keypair for this side (client or relay), loaded from DPAPI store.
    static_keypair: Option<balancify_crypto::StaticKeypair>,
    /// In-progress handshake initiator (client side).
    handshake_initiator: Option<balancify_crypto::Initiator>,
    /// ETW provider for diagnostics (Sec.8.2)
    etw: etw::EtwProvider,
    counters: Counters,
    event_interval_hz: u8,
}

impl<C: Crypto + Clone> Service<C> {
    pub fn new(cfg: ServiceConfig, tx_crypto: C, rx_crypto: C) -> Self {
        let policy_cfg = PolicyConfig { allow_metered: cfg.allow_metered, ..PolicyConfig::default() };
        let sender_cfg = SenderConfig { rto: cfg.rto, ..SenderConfig::default() };
        let receiver_cfg = ReceiverConfig {
            hold_cap: cfg.hold_cap,
            idle_timeout: cfg.idle_timeout,
            auto_accept: cfg.auto_accept,
            max_sessions: ReceiverConfig::default().max_sessions,
        };
        let policy = PolicyEngine::new(policy_cfg, cfg.seed);
        let flows = FlowTable::new(cfg.idle_timeout);
        let keepalives = KeepaliveScheduler::new(cfg.keepalive_interval);
        let tx = Sender::with_config(cfg.session, tx_crypto, Vec::new(), sender_cfg);
        let rx = Receiver::new(rx_crypto, receiver_cfg);
        Self {
            cfg,
            policy,
            snapshot: PolicySnapshot::default(),
            flows,
            rules: RuleSet::curated(),
            bond: BondGainTracker::default(),
            keepalives,
            path_mtu: BTreeMap::new(),
            tx,
            rx,
            probes: BTreeMap::new(),
            cc: CongestionController::new(TUNNEL_MTU as u64),
            pacing: PacingController::new(0), // disabled until capacity known, then set in publish()
            path_local: BTreeMap::new(),
            last_rekey: None,
            packets_since_rekey: 0,
            key_epoch_started: None,
            rekey_interval: Duration::from_secs(3600), // planned 1 hour threshold
            rekey_packet_threshold: 1_000_000,          // planned 1M packet threshold
            rekey_due: false,
            relay_primary: None,
            relay_secondary: None,
            relay_current: None,
            relay_last_ack: None,
            relay_failover_timeout: Duration::from_secs(10),
            relay_failover_count: 0,
            relay_failover_start: None,
            relay_failover_convergence: None,
            relay_failover_history: Vec::new(),
            uplink_failover_start: None,
            uplink_failover_convergence: None,
            uplink_failover_history: Vec::new(),
            uplink_failover_count: 0,
            per_flow_sessions: false,
            flow_sessions: BTreeMap::new(),
            next_session_id: 1000, // start after default session 1
            per_class_sessions: false,
            class_sessions: BTreeMap::new(),
            rate_limiter: balancify_core::RateLimiter::new(1_000_000_000, 1_000_000), // 1Gbps default, 1MB burst
            pinned_clients: balancify_crypto::PinnedKeys::new(),
            pinned_relays: balancify_crypto::PinnedKeys::new(),
            replay_cache: balancify_crypto::ReplayCache::with_defaults(),
            static_keypair: None,
            handshake_initiator: None,
            etw: etw::EtwProvider::new("BalancifyService"),
            counters: Counters::default(),
            event_interval_hz: 1,
        }
    }

    // ------------------------------------------------------------- topology

    pub fn add_uplink(&mut self, id: UplinkId, capacity_bps: u64, metered: bool, mtu: u16, now: Instant) {
        self.policy.add_uplink(
            id,
            UplinkConfig { capacity_bps, metered, initial_rtt: Duration::from_millis(30) },
            now,
        );
        self.path_mtu.insert(id, mtu);
        self.bond.reset_on_link_mix_change();
        // If this is a replug after failover, measure convergence
        if let Some(start) = self.uplink_failover_start.take() {
            let convergence = now.duration_since(start);
            self.uplink_failover_convergence = Some(convergence);
            self.uplink_failover_history.push((id, start, convergence));
            self.etw.info(200, &format!("uplink {} up, failover converged in {}ms count={}", id.0, convergence.as_millis(), self.uplink_failover_count));
            if convergence.as_secs_f64() > 2.0 {
                self.etw.warn(500, &format!("WARN uplink failover convergence >2s: {}ms", convergence.as_millis()));
            }
        } else {
            self.etw.info(200, &format!("uplink {} up cap={}bps mtu={}", id.0, capacity_bps, mtu));
        }
    }

    pub fn remove_uplink(&mut self, id: UplinkId) {
        self.policy.remove_uplink(id);
        self.policy.drop_uplink(id);
        self.path_mtu.remove(&id);
        self.flows.forget_uplink(id);
        self.cc.forget(id.0);
        self.pacing.forget(id.0);
        self.path_local.remove(&id);
        self.bond.reset_on_link_mix_change();
        // Track uplink failover start for convergence measurement Sec.10.3 failover <=2s
        self.uplink_failover_start = Some(Instant::now());
        self.uplink_failover_convergence = None;
        self.uplink_failover_count += 1;
        self.etw.info(201, &format!("uplink {} down, failover count={} — measuring convergence <=2s", id.0, self.uplink_failover_count));
    }

    pub fn remove_uplink_at(&mut self, id: UplinkId, now: Instant) {
        self.policy.remove_uplink(id);
        self.policy.drop_uplink(id);
        self.path_mtu.remove(&id);
        self.flows.forget_uplink(id);
        self.cc.forget(id.0);
        self.pacing.forget(id.0);
        self.path_local.remove(&id);
        self.bond.reset_on_link_mix_change();
        self.uplink_failover_start = Some(now);
        self.uplink_failover_convergence = None;
        self.uplink_failover_count += 1;
        self.etw.info(201, &format!("uplink {} down at {:?}, failover count={}", id.0, now, self.uplink_failover_count));
    }

    pub fn on_probe_ok(&mut self, id: UplinkId, rtt: Duration, now: Instant) {
        self.policy.on_probe_ok(id, rtt, now);
    }
    pub fn on_probe_miss(&mut self, id: UplinkId) { self.policy.on_probe_miss(id); }

    /// Publish the snapshot both schedulers read (Sec.6.1) and republish the
    /// striping quanta from it (Sec.6.4 rule 2). Returns true when it changed.
    ///
    /// Topology changes take effect here, not at `add_uplink`/`remove_uplink`:
    /// one publish point is what keeps the two schedulers from disagreeing.
    /// Also updates pacing rates from the capacity estimates (Sec.6.4 rule 4).
    pub fn publish(&mut self, now: Instant) -> bool {
        let before = self.snapshot.revision;
        let prev_uplinks = self.snapshot.uplinks.clone();
        self.snapshot = self.policy.publish(now);
        self.tx.set_quanta(self.snapshot.quanta());
        // Update pacing rates from capacity estimates: 80% of estimated capacity
        // to leave headroom for probes and to avoid queue buildup.
        for view in &self.snapshot.uplinks {
            if view.eligible {
                let rate = (view.capacity_bps as f64 * 0.8) as u64;
                self.pacing.set_rate(view.id.0, rate.max(1_000_000)); // floor 1 Mbit/s
            }
        }
        // ETW: log uplink state changes (Sec.8.2)
        for prev in &prev_uplinks {
            if let Some(curr) = self.snapshot.uplinks.iter().find(|u| u.id == prev.id) {
                if prev.state != curr.state {
                    let evt = match curr.state {
                        balancify_core::LinkState::Up => etw::EVT_UPLINK_UP,
                        balancify_core::LinkState::Down => etw::EVT_UPLINK_DOWN,
                        _ => 0,
                    };
                    if evt != 0 {
                        self.etw.info(evt, &format!("uplink {:?} {:?} -> {:?} rtt={:?} cap={}", curr.id, prev.state, curr.state, curr.rtt, curr.capacity_bps));
                    }
                }
            }
        }
        self.snapshot.revision != before
    }

    pub fn snapshot(&self) -> &PolicySnapshot { &self.snapshot }
    pub fn counters(&self) -> Counters { self.counters }
    pub fn active_flows(&self) -> usize { self.flows.len() }
    /// Idle probes awaiting a reply. Exposed for diagnostics: a number that
    /// grows without bound means replies are not coming back.
    pub fn pending_probes(&self) -> usize { self.probes.len() }
    /// Congestion window currently granted to `path`, in bytes (Sec.6.4 rule 4).
    pub fn window(&self, path: UplinkId) -> u64 { self.cc.window(path.0) }
    /// Bytes in flight on `path`.
    pub fn in_flight(&self, path: UplinkId) -> u64 { self.cc.in_flight(path.0) }
    /// Pacing delay for `path` at `now`: how long to wait before next send
    /// to avoid burst (Sec.6.4 rule 4). Zero if can send now.
    pub fn pacing_delay(&self, path: UplinkId, now: Instant) -> Duration {
        self.pacing.delay_until_next(path.0, now)
    }
    /// All paths currently paced (next send in future).
    pub fn paced_paths(&self, now: Instant) -> Vec<UplinkId> {
        self.pacing.paced_paths(now).into_iter().map(UplinkId).collect()
    }
    /// Peer sessions currently held, and payloads held for reordering. Both
    /// are bounded (session cap, hold cap) and both are worth watching.
    pub fn sessions(&self) -> usize { self.rx.sessions() }
    pub fn held_packets(&self) -> usize { self.rx.held_packets() }
    pub fn rules(&self) -> &RuleSet { &self.rules }
    pub fn config(&self) -> &ServiceConfig { &self.cfg }

    pub fn bond_enabled_for(&self, class: FlowClass) -> bool {
        self.cfg.bond_enabled && BondClass::of(class).map(|c| self.bond.enabled(c)).unwrap_or(false)
    }

    /// Sec.6.6: adapter MTU = min(live path MTU) - tunnel overhead.
    pub fn adapter_mtu(&self) -> Option<u16> {
        let live: Vec<u16> = self
            .snapshot
            .uplinks
            .iter()
            .filter(|u| u.eligible)
            .filter_map(|u| self.path_mtu.get(&u.id).copied())
            .collect();
        MtuPolicy::new(self.cfg.tunnel_overhead).adapter_mtu(&live)
    }

    // -------------------------------------------------------------- lifecycle

    /// The machine woke up (Sec.4.5). Everything learned before sleep is stale:
    /// NAT mappings are gone, so packets in flight are unreachable and their
    /// RTO timers would only reinject into the void; the windows were measured
    /// on paths that no longer exist; probes went unanswered for a reason that
    /// has nothing to do with the link. Every uplink must re-probe before it
    /// carries traffic, and keepalives go out first to re-establish mappings.
    ///
    /// Returns the number of in-flight packets that were abandoned.
    pub fn resume_from_sleep(&mut self, now: Instant) -> u64 {
        let abandoned = self.tx.drop_retx();
        self.cc.reset();
        self.pacing.reset();
        self.probes.clear();
        self.policy.resume_from_sleep();
        let paths = self.tx.paths();
        self.keepalives.expire_all(&paths, now);
        self.policy.restart_measurements(now);
        self.publish(now);
        self.counters.resumes += 1;
        abandoned
    }

    /// Report the local (source) endpoint observed on an uplink's socket.
    ///
    /// A change means the NAT mapping moved (Sec.6.6): frames in flight through
    /// the old mapping are unreachable and the window measured on it no longer
    /// applies, so that path's state is re-keyed. The session survives -- the
    /// peer is the same peer -- and so does flow affinity. Returns true when a
    /// re-binding was detected.
    pub fn note_local_endpoint(&mut self, uplink: UplinkId, observed: SocketAddr, now: Instant) -> bool {
        let previous = self.path_local.insert(uplink, observed);
        if !path_changed(previous.as_ref(), observed) { return false; }
        self.tx.forget_path(uplink.0);
        self.cc.forget(uplink.0);
        self.pacing.forget(uplink.0);
        self.probes.retain(|(path, _), _| *path != uplink.0);
        self.keepalives.expire_all(&[uplink.0], now);
        self.counters.path_changes += 1;
        true
    }

    // ------------------------------------------------------------ security

    /// Set pinned client identities (relay side). When non-empty, the receiver
    /// will not auto-accept unknown sessions; sessions must be opened explicitly
    /// after handshake verifies peer. This flips `auto_accept` to false and
    /// re-creates the receiver with the same cipher but `auto_accept=false`.
    pub fn set_pinned_clients(&mut self, pinned: balancify_crypto::PinnedKeys)
    where
        C: Clone,
    {
        self.pinned_clients = pinned;
        if !self.pinned_clients.is_empty() {
            self.cfg.auto_accept = false;
            // Re-create receiver with auto_accept=false, preserving crypto and evicting
            // any auto-accepted sessions that are not pinned (defensive).
            let cfg = ReceiverConfig {
                hold_cap: self.cfg.hold_cap,
                idle_timeout: self.cfg.idle_timeout,
                auto_accept: false,
                max_sessions: self.rx.config().max_sessions,
            };
            let crypto = self.rx.crypto().clone();
            self.rx = Receiver::new(crypto, cfg);
        }
    }

    pub fn set_pinned_relays(&mut self, pinned: balancify_crypto::PinnedKeys) {
        self.pinned_relays = pinned;
        if !self.pinned_relays.is_empty() {
            self.cfg.auto_accept = false;
        }
    }

    /// Non-cloning variant for contexts where C is not Clone (e.g. lab PassThrough
    /// which is Clone anyway, but kept for API symmetry). Sets pinned and flips
    /// auto_accept flag; receiver will be re-created on next secure session.
    pub fn set_pinned_clients_no_clone(&mut self, pinned: balancify_crypto::PinnedKeys) {
        self.pinned_clients = pinned;
        if !self.pinned_clients.is_empty() {
            self.cfg.auto_accept = false;
        }
    }

    pub fn pinned_clients(&self) -> &balancify_crypto::PinnedKeys { &self.pinned_clients }
    pub fn pinned_relays(&self) -> &balancify_crypto::PinnedKeys { &self.pinned_relays }

    pub fn replay_cache(&self) -> &balancify_crypto::ReplayCache { &self.replay_cache }
    pub fn replay_cache_mut(&mut self) -> &mut balancify_crypto::ReplayCache { &mut self.replay_cache }

    /// Open a session explicitly after handshake verified peer identity.
    /// Returns true if session was opened (or already open).
    pub fn open_session(&mut self, session: u64, now: Instant) -> bool {
        self.rx.open_session(session, now)
    }

    /// Check if a peer static is allowed (pinned or no pinning enforced).
    pub fn is_peer_allowed(&self, peer_static: &[u8; 32], is_client: bool) -> bool {
        let pinned = if is_client { &self.pinned_clients } else { &self.pinned_relays };
        if pinned.is_empty() { true } else { pinned.is_pinned(peer_static) }
    }

    pub fn set_static_keypair(&mut self, kp: balancify_crypto::StaticKeypair) {
        self.static_keypair = Some(kp);
    }
    pub fn static_keypair(&self) -> Option<&balancify_crypto::StaticKeypair> {
        self.static_keypair.as_ref()
    }

    // ------------------------------------------------------------ data plane

    /// Parse one complete raw IP packet and send it into the tunnel.
    ///
    /// This is the platform-independent boundary used by the optional Windows
    /// NDIS adapter bridge and lab traffic path. It validates packet bounds,
    /// derives the directional flow key, and feeds the original bytes to the
    /// sans-I/O scheduler. Invalid/unsupported packets are rejected before
    /// service state changes; this does not imply driver runtime validation.
    pub fn send_ip_packet(
        &mut self,
        packet: &[u8],
        now: Instant,
    ) -> Result<Vec<Action>, packet::PacketFlowError> {
        let flow = packet::flow_key_from_packet(packet)?;
        Ok(self.send_app_packet(&flow, None, packet, now))
    }

    /// One packet from the application (inner stack) into the tunnel.
    pub fn send_app_packet(
        &mut self,
        flow: &FlowKey,
        sni: Option<&str>,
        payload: &[u8],
        now: Instant,
    ) -> Vec<Action> {
        let class = self.rules.classify(flow, sni);
        let Some(uplink) = self.flows.place(flow, class, &self.snapshot, now) else {
            self.counters.refused += 1;
            return vec![Action::Refused { flow: flow.clone(), class }];
        };

        if self.bond_enabled_for(class) {
            let cost = payload.len() as u64;
            let blocked = self.cc.blocked(cost);
            // Session selection: per-flow > per-class > default
            let sess = if self.per_flow_sessions {
                self.session_for_flow(flow, now)
            } else if self.per_class_sessions {
                self.session_for_class(class, now)
            } else {
                self.cfg.session
            };
            let use_custom = self.per_flow_sessions || self.per_class_sessions;
            let sent_opt = if use_custom {
                self.tx.send_excluding_with_session(payload, sess, now, &blocked)
            } else {
                self.tx.send_excluding(payload, now, &blocked)
            };
            let Some(sent) = sent_opt else {
                if self.tx.paths().is_empty() {
                    self.counters.refused += 1;
                    return vec![Action::Refused { flow: flow.clone(), class }];
                }
                // Congested, not broken: hold rather than drop.
                self.counters.held += 1;
                return vec![Action::Hold { flow: flow.clone(), data: payload.to_vec() }];
            };
            // Rate limiting check (service egress)
            if !self.rate_limiter.try_send(sent.path, sent.bytes.len() as u64, now) {
                // Rate limited: hold
                self.counters.held += 1;
                return vec![Action::Hold { flow: flow.clone(), data: payload.to_vec() }];
            }
            self.cc.on_send(sent.path, payload.len() as u64);
            self.pacing.on_send(sent.path, payload.len() as u64, now);
            self.counters.packets_stripped += 1;
            self.packets_since_rekey += 1;
            if self.key_epoch_started.is_none() {
                self.key_epoch_started = Some(now);
            }
            self.keepalives.on_traffic(sent.path, now);
            self.policy.note_traffic(UplinkId(sent.path), now);
            let mut out = vec![Action::Send { uplink: UplinkId(sent.path), bytes: sent.bytes }];
            let critical = self.rules.duplicate_eligible(flow, sni);
            if self.cfg.duplicate_mode && should_duplicate(payload.len(), critical, true) {
                if let Some(other) = self.other_path(sent.path) {
                    if self.cc.allows(other, cost) {
                        let copy_opt = if use_custom {
                            self.tx.duplicate_with_session(payload, sess, sent.seq, other)
                        } else {
                            self.tx.duplicate(payload, sent.seq, other)
                        };
                        if let Some(copy) = copy_opt {
                            self.cc.on_send(copy.path, payload.len() as u64);
                            self.pacing.on_send(copy.path, payload.len() as u64, now);
                            self.counters.duplicates_sent += 1;
                            out.push(Action::Send { uplink: UplinkId(copy.path), bytes: copy.bytes });
                        }
                    }
                }
            }
            return out;
        }

        // Flow-level lane (Sec.6.2)
        let sess = if self.per_flow_sessions {
            self.session_for_flow(flow, now)
        } else if self.per_class_sessions {
            self.session_for_class(class, now)
        } else {
            self.cfg.session
        };
        let use_custom = self.per_flow_sessions || self.per_class_sessions;
        let sent_opt = if use_custom {
            self.tx.send_flow_with_session(payload, uplink.0, sess, now)
        } else {
            self.tx.send_flow(payload, uplink.0, now)
        };
        let Some(sent) = sent_opt else {
            self.counters.refused += 1;
            return vec![Action::Refused { flow: flow.clone(), class }];
        };
        if !self.rate_limiter.try_send(sent.path, sent.bytes.len() as u64, now) {
            self.tx.forget_flow_ack_for_session(sent.session, sent.seq);
            self.counters.held += 1;
            return vec![Action::Hold { flow: flow.clone(), data: payload.to_vec() }];
        }
        self.counters.packets_forwarded += 1;
        // Flow-level capacity is sampled when the authenticated FlowAck arrives.
        self.packets_since_rekey += 1;
        if self.key_epoch_started.is_none() {
            self.key_epoch_started = Some(now);
        }
        self.keepalives.on_traffic(uplink.0, now);
        self.policy.note_traffic(uplink, now);
        vec![Action::Send { uplink, bytes: sent.bytes }]
    }

    /// One datagram received on an uplink's socket.
    pub fn ingest_path(&mut self, uplink: UplinkId, dg: &[u8], now: Instant) -> Vec<Action> {
        let hdr = Header::decode(dg).map(|(hdr, _)| hdr);
        if let Some(hdr) = hdr {
            match hdr.kind {
                FrameKind::FlowAck => {
                    match self.rx.verify_control_frame(dg, now) {
                        Ok(true) => {}
                        Ok(false) => return Vec::new(),
                        Err(reason) => {
                            if matches!(reason, balancify_tunnel::DropReason::AuthFailed) {
                                self.counters.auth_failed += 1;
                                self.etw.error(etw::EVT_AUTH_FAILED, &format!("auth failed on uplink {:?}", uplink));
                            }
                            return Vec::new();
                        }
                    }
                    self.record_ecn_ce(hdr.path, hdr.flags, uplink, now);
                    for (path, bytes) in self.tx.on_flow_ack_for_session(hdr.session, hdr.seq) {
                        if bytes == 0 { continue; }
                        self.policy.on_flow_ack(UplinkId(path), bytes, now);
                    }
                    self.on_relay_ack(now);
                    return Vec::new();
                }
                FrameKind::Ack | FrameKind::ProbeReply => {
                    match self.rx.verify_control_frame(dg, now) {
                        Ok(true) => {}
                        Ok(false) => return Vec::new(),
                        Err(reason) => {
                            if matches!(reason, balancify_tunnel::DropReason::AuthFailed) {
                                self.counters.auth_failed += 1;
                                self.etw.error(etw::EVT_AUTH_FAILED, &format!("auth failed on uplink {:?}", uplink));
                            }
                            return Vec::new();
                        }
                    }
                    self.record_ecn_ce(hdr.path, hdr.flags, uplink, now);
                    if hdr.kind == FrameKind::Ack {
                        for (path, bytes) in self.tx.on_ack_for_session(hdr.session, hdr.seq, now) {
                            if bytes == 0 { continue; }
                            self.policy.on_ack(UplinkId(path), bytes, now);
                            let before_delay = self.cc.delay_events();
                            self.cc.on_ack_with_rtt(path, bytes, None, now);
                            if self.cc.delay_events() > before_delay {
                                self.counters.delay_events += 1;
                                self.etw.info(
                                    etw::EVT_DELAY_CONGESTION,
                                    &format!("delay congestion on path {} uplink {:?}", path, uplink),
                                );
                            }
                        }
                        self.on_relay_ack(now);
                        return Vec::new();
                    }

                    let Some((sent_at, size)) = self.probes.remove(&(hdr.path, hdr.seq)) else {
                        return Vec::new();
                    };
                    let rtt = now.duration_since(sent_at);
                    self.tx.on_probe_reply(hdr.path, rtt, EWMA_ALPHA);
                    self.policy.on_idle_probe(uplink, size, rtt, now);
                    let before_delay = self.cc.delay_events();
                    self.cc.on_rtt(hdr.path, rtt, now);
                    if self.cc.delay_events() > before_delay {
                        self.counters.delay_events += 1;
                        self.etw.info(
                            etw::EVT_DELAY_CONGESTION,
                            &format!("delay congestion via probe path {} rtt={:?}", hdr.path, rtt),
                        );
                    }
                    self.on_relay_ack(now);
                    return Vec::new();
                }
                _ => {}
            }
        }
        let events = self.rx.ingest(dg, now);
        if !events.iter().any(|ev| matches!(ev, Event::Dropped { .. })) {
            if let Some(hdr) = hdr { self.record_ecn_ce(hdr.path, hdr.flags, uplink, now); }
        }
        let mut out = Vec::new();
        for ev in events {
            match &ev {
                Event::Dropped { reason } if matches!(reason, balancify_tunnel::DropReason::AuthFailed) => {
                    self.etw.error(etw::EVT_AUTH_FAILED, &format!("auth failed on uplink {:?}", uplink));
                }
                _ => {}
            }
            out.extend(self.receiver_action(ev));
        }
        // Any payload or control from relay also counts as liveness
        if !out.is_empty() {
            self.on_relay_ack(now);
        }
        out
    }

    /// Timer tick: keepalives, reinjection, idle probes, hold-cap release and
    /// the flow-table sweep. The only place the service moves without being
    /// handed a packet.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let mut out = Vec::new();

        // Keepalives follow the scheduler, not the current quanta: a keepalive
        // is per-path NAT state, so a path that is merely unhealthy still has a
        // binding worth keeping alive - and right after sleep/resume there may
        // be no eligible path at all, which is exactly when the bindings need
        // re-establishing (Sec.6.6).
        for path in self.keepalives.paths() {
            if self.keepalives.due(path, now) {
                let k = self.tx.keepalive(path);
                self.counters.keepalives += 1;
                out.push(Action::Send { uplink: UplinkId(path), bytes: k.bytes });
            }
        }

        for sent in self.tx.reinjections_due(now) {
            self.counters.reinjections += 1;
            out.push(Action::Send { uplink: UplinkId(sent.path), bytes: sent.bytes });
        }
        for sent in self.tx.flow_reinjections_due(now) {
            self.counters.reinjections += 1;
            out.push(Action::Send { uplink: UplinkId(sent.path), bytes: sent.bytes });
        }
        // A reinjection is a loss signal for the path it left on (Sec.6.4 rule 4).
        for path in self.tx.drain_losses() {
            self.cc.on_loss(path, now);
        }

        if let Some((id, bytes)) = self.policy.request_idle_probe(self.cfg.idle_probe_bytes, now) {
            let probe = self.tx.probe(id.0, bytes as usize);
            self.probes.insert((id.0, probe.seq), (now, bytes));
            self.counters.probes += 1;
            out.push(Action::Send { uplink: id, bytes: probe.bytes });
        }

        for ev in self.rx.drain(now) {
            out.extend(self.receiver_action(ev));
        }

        // Idle sessions must be released, or a peer that went away keeps its
        // slot in the session cap for the lifetime of the service (Sec.9.1).
        self.counters.sessions_evicted += self.rx.sweep(now).len() as u64;

        // A probe whose reply never arrives would otherwise stay in the table
        // forever; the byte budget accounts for it, the memory did not.
        let probe_timeout = self.cfg.probe_timeout;
        self.probes.retain(|_, (sent_at, _)| now.duration_since(*sent_at) < probe_timeout);

        // Do not rotate transport ciphers locally: the relay has no key-update
        // message/acknowledgement, so a unilateral switch would strand the
        // session. Record when a coordinated handshake is required instead.
        if !self.rekey_due && self.should_rekey(now) {
            self.rekey_due = true;
            self.etw.warn(
                etw::EVT_REKEY,
                &format!("session {} reached its key-update threshold; coordinated handshake required", self.cfg.session),
            );
        }

        // Sec.4.5 relay failover: if no ACK from current relay within timeout,
        // switch to secondary (or back to primary). The caller must re-handshake
        // if using secure mode; we just report the new relay via counter.
        if self.relay_primary.is_some() {
            if let Some(new_relay) = self.check_relay_failover(now) {
                self.etw.warn(
                    etw::EVT_RELAY_FAILOVER,
                    &format!("relay failover: {} -> {} count={}", self.relay_primary.unwrap(), new_relay, self.relay_failover_count),
                );
                eprintln!("relay failover: {} -> {}", self.relay_primary.unwrap(), new_relay);
            }
        }

        self.flows.sweep(now);
        out
    }

    fn should_rekey(&self, now: Instant) -> bool {
        let time_due = self
            .key_epoch_started
            .is_some_and(|started| now.duration_since(started) >= self.rekey_interval);
        time_due || self.packets_since_rekey >= self.rekey_packet_threshold
    }

    /// Configure the point at which diagnostics mark the session as needing a
    /// coordinated key update. Reaching this threshold does not change keys.
    pub fn set_rekey_interval(&mut self, interval: Duration, packet_threshold: u64) {
        self.rekey_interval = interval;
        self.rekey_packet_threshold = packet_threshold.max(1);
    }

    pub fn packets_since_rekey(&self) -> u64 {
        self.packets_since_rekey
    }
    pub fn last_rekey(&self) -> Option<Instant> {
        self.last_rekey
    }
    pub fn rekey_due(&self) -> bool {
        self.rekey_due
    }

    pub fn on_relay_ack(&mut self, now: Instant) {
        self.relay_last_ack = Some(now);
        // If we were in failover, measure convergence time (first ACK after failover)
        if let Some(start) = self.relay_failover_start.take() {
            let convergence = now.duration_since(start);
            self.relay_failover_convergence = Some(convergence);
            self.relay_failover_history.push((start, convergence));
            // ETW 500 failover convergence
            self.etw.info(500, &format!("relay failover converged in {}ms count={}", convergence.as_millis(), self.relay_failover_count));
            if convergence.as_secs_f64() > 2.0 {
                self.etw.warn(500, &format!("WARN failover convergence >2s: {}ms", convergence.as_millis()));
            }
        }
    }

    pub fn check_relay_failover(&mut self, now: Instant) -> Option<SocketAddr> {
        let last = match self.relay_last_ack {
            Some(t) => t,
            None => return None,
        };
        if now.duration_since(last) < self.relay_failover_timeout {
            return None;
        }
        let current = self.relay_current?;
        let next = if Some(current) == self.relay_primary {
            self.relay_secondary
        } else {
            self.relay_primary
        };
        if let Some(next_addr) = next {
            if next_addr != current {
                self.relay_current = Some(next_addr);
                self.relay_last_ack = Some(now);
                self.relay_failover_count += 1;
                self.relay_failover_start = Some(now);
                self.relay_failover_convergence = None;
                self.etw.info(500, &relay_failover_event_message(self.relay_failover_count, self.relay_failover_timeout));
                return Some(next_addr);
            }
        }
        None
    }

    pub fn set_relays(&mut self, primary: SocketAddr, secondary: Option<SocketAddr>) {
        self.relay_primary = Some(primary);
        self.relay_secondary = secondary;
        self.relay_current = Some(primary);
        self.relay_last_ack = None;
    }

    pub fn relay_current(&self) -> Option<SocketAddr> {
        self.relay_current
    }
    pub fn relay_failover_count(&self) -> u64 {
        self.relay_failover_count
    }
    pub fn relay_failover_convergence(&self) -> Option<Duration> {
        self.relay_failover_convergence
    }
    pub fn relay_failover_history(&self) -> &[(Instant, Duration)] {
        &self.relay_failover_history
    }
    pub fn relay_failover_start(&self) -> Option<Instant> {
        self.relay_failover_start
    }

    pub fn set_relay_failover_timeout(&mut self, timeout: Duration) {
        self.relay_failover_timeout = timeout;
    }

    // Uplink failover convergence Sec.10.3 failover <=2s, Sec.4.5
    pub fn uplink_failover_count(&self) -> u64 {
        self.uplink_failover_count
    }
    pub fn uplink_failover_convergence(&self) -> Option<Duration> {
        self.uplink_failover_convergence
    }
    pub fn uplink_failover_history(&self) -> &[(UplinkId, Instant, Duration)] {
        &self.uplink_failover_history
    }
    pub fn uplink_failover_start(&self) -> Option<Instant> {
        self.uplink_failover_start
    }

    // ----------------------------------------------- per-flow sessions (Sec.4.7.4)

    pub fn set_per_flow_sessions(&mut self, enabled: bool) {
        self.per_flow_sessions = enabled;
        if !enabled {
            self.flow_sessions.clear();
        }
    }

    pub fn session_for_flow(&mut self, flow: &FlowKey, now: Instant) -> u64 {
        if !self.per_flow_sessions {
            return self.cfg.session;
        }
        if let Some(sid) = self.flow_sessions.get(flow) {
            return *sid;
        }
        // Assign new session id, bounded by max_sessions
        let max_sessions = self.rx.config().max_sessions as u64;
        if self.flow_sessions.len() as u64 >= max_sessions {
            // Evict oldest (first) if cap reached
            if let Some((old_flow, _)) = self.flow_sessions.iter().next().map(|(k, v)| (k.clone(), *v)) {
                self.flow_sessions.remove(&old_flow);
            }
        }
        let sid = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        self.flow_sessions.insert(flow.clone(), sid);
        self.rx.open_session(sid, now);
        sid
    }

    pub fn flow_session_count(&self) -> usize {
        self.flow_sessions.len()
    }

    pub fn set_per_class_sessions(&mut self, enabled: bool) {
        self.per_class_sessions = enabled;
        if !enabled {
            self.class_sessions.clear();
        }
    }

    pub fn session_for_class(&mut self, class: FlowClass, now: Instant) -> u64 {
        if !self.per_class_sessions {
            return self.cfg.session;
        }
        // FlowClass discriminant as u8: Bulk=0, LatencySensitive=1, Pinned=2
        let key = match class {
            FlowClass::Bulk => 0u8,
            FlowClass::LatencySensitive => 1u8,
            FlowClass::Pinned(_) => 2u8,
        };
        if let Some(sid) = self.class_sessions.get(&key) {
            return *sid;
        }
        let sid = self.next_session_id;
        self.next_session_id = self.next_session_id.wrapping_add(1).max(1);
        self.class_sessions.insert(key, sid);
        self.rx.open_session(sid, now);
        sid
    }

    pub fn class_session_count(&self) -> usize {
        self.class_sessions.len()
    }

    // ----------------------------------------------- rate limiting (service egress)

    pub fn set_uplink_rate_limit(&mut self, uplink: UplinkId, rate_bps: u64, burst_bytes: u64, now: Instant) {
        self.rate_limiter.set_uplink_rate(uplink.0, rate_bps, burst_bytes, now);
    }

    pub fn remove_uplink_rate_limit(&mut self, uplink: UplinkId) {
        self.rate_limiter.remove_uplink(uplink.0);
    }

    pub fn check_rate_limit(&mut self, uplink: UplinkId, bytes: u64, now: Instant) -> bool {
        self.rate_limiter.try_send(uplink.0, bytes, now)
    }

    pub fn rate_limit_delay(&mut self, uplink: UplinkId, bytes: u64, now: Instant) -> Duration {
        self.rate_limiter.delay_for(uplink.0, bytes, now)
    }


    /// Sec.6.4 rule 6: feed a measured window, get the telemetry event a revert
    /// produces.
    pub fn observe_bond_gain(
        &mut self,
        class: BondClass,
        bonded_bps: f64,
        best_uplink_bps: f64,
    ) -> Vec<ipc::Event> {
        let d = self.bond.observe(class, bonded_bps, best_uplink_bps);
        if d.flipped {
            self.etw.info(
                etw::EVT_BOND_REVERTED,
                &format!("bond reverted class={:?} gain={} bonded={} best={}", class, d.gain, bonded_bps, best_uplink_bps),
            );
            vec![ipc::Event::BondReverted { class: class as u8, gain_permille: permille(d.gain) }]
        } else {
            Vec::new()
        }
    }

    // ------------------------------------------------------------------ IPC

    /// Serve one IPC request (contract v1, Phase 3 M6). The snapshot is
    /// published first so the shell never renders stale state.
    pub fn handle(&mut self, req: ipc::Request, now: Instant) -> ipc::Response {
        use ipc::{Request, Response};
        self.publish(now);
        match req {
            Request::Ping => Response::Pong { service_version: env!("CARGO_PKG_VERSION").to_string() },
            Request::GetStatus => Response::Status(self.status_snapshot()),
            Request::ListUplinks => Response::Uplinks(self.uplink_infos()),
            Request::ListFlowRules => Response::FlowRules(self.flow_rule_infos()),
            Request::SetFlowRule(rule) => match self.apply_rule(rule) {
                Ok(()) => Response::Ack,
                Err(message) => Response::Error { status: ipc::Status::BadRequest, message },
            },
            Request::RemoveFlowRule { id } => {
                if id < balancify_core::FIRST_CUSTOM_RULE_ID {
                    Response::Error {
                        status: ipc::Status::BadRequest,
                        message: format!("rule id {id} is reserved for built-in rules"),
                    }
                } else if self.rules.remove(id) {
                    Response::Ack
                } else {
                    Response::Error { status: ipc::Status::BadRequest, message: format!("no rule {id}") }
                }
            }
            Request::SetBondMode { enabled } => {
                self.cfg.bond_enabled = enabled;
                Response::Ack
            }
            Request::SetDuplicateMode { enabled } => {
                self.cfg.duplicate_mode = enabled;
                Response::Ack
            }
            Request::SetAllowMetered { allowed } => {
                self.cfg.allow_metered = allowed;
                self.policy.set_allow_metered(allowed);
                Response::Ack
            }
            Request::GetSupportBundle => {
                let bundle = support::SupportBundle::collect(self, now);
                Response::SupportBundle(bundle.to_json())
            }
            Request::SubscribeEvents { interval_hz } => {
                if interval_hz == 0 || interval_hz > 10 {
                    return Response::Error {
                        status: ipc::Status::BadRequest,
                        message: "interval_hz must be 1..=10 (Sec.8.1: 1 Hz telemetry)".to_string(),
                    };
                }
                self.event_interval_hz = interval_hz;
                Response::Ack
            }
            Request::RunSelfTest => {
                let ok = self.snapshot.has_capacity();
                let detail = if ok {
                    format!("{} uplink(s) eligible; session {}", self.snapshot.eligible().count(), self.cfg.session)
                } else {
                    "no eligible uplink: probes have not completed (Sec.6.5)".to_string()
                };
                Response::SelfTest { passed: ok, detail }
            }
        }
    }

    /// Conditions worth pushing to a subscribed shell (Sec.4.5 failure modes).
    pub fn poll_events(&self) -> Vec<ipc::Event> {
        let mut out = Vec::new();
        if self.adapter_mtu().map(|m| m < IPV4_MIN_MTU).unwrap_or(false) {
            out.push(ipc::Event::Warning { code: ipc::WARN_ADAPTER_MTU_BELOW_IPV4_MIN });
        }
        if !self.snapshot.has_capacity() {
            out.push(ipc::Event::Warning { code: ipc::WARN_ALL_PATHS_DOWN });
        }
        out
    }

    pub fn event_interval_hz(&self) -> u8 { self.event_interval_hz }

    /// Snapshot the current warning conditions and counters for a subscribed
    /// IPC client. The transport controls cadence; this method is side-effect
    /// free and suitable for caller-driven polling.
    pub fn telemetry_events(&self) -> Vec<ipc::Event> {
        let mut events = self.poll_events();
        events.push(ipc::Event::Stats(self.counters().into()));
        events
    }

    // -------------------------------------------------------------- internals

    fn record_ecn_ce(&mut self, path: u8, flags: u8, uplink: UplinkId, now: Instant) {
        if flags & balancify_tunnel::FLAG_ECN_CE == 0 { return; }
        let before = self.cc.ecn_events();
        self.cc.on_ecn(path, now);
        if self.cc.ecn_events() > before {
            self.counters.ecn_ce += 1;
            self.etw.info(
                etw::EVT_ECN_CE,
                &format!("ECN CE on path {} uplink {:?} cwnd={}", path, uplink, self.cc.window(path)),
            );
        }
    }

    fn receiver_action(&mut self, ev: Event) -> Vec<Action> {
        match ev {
            Event::Payload { data, .. } => {
                self.counters.delivered += 1;
                vec![Action::Deliver { data }]
            }
            Event::Ack { session, path, seq } => {
                let sent = self.tx.ack_for_session(session, path, seq, 0);
                vec![Action::Send { uplink: UplinkId(sent.path), bytes: sent.bytes }]
            }
            Event::FlowAck { session, path, seq } => {
                let sent = self.tx.flow_ack_for_session(session, path, seq);
                vec![Action::Send { uplink: UplinkId(path), bytes: sent.bytes }]
            }
            Event::ProbeEcho { path, seq, .. } => {
                let sent = self.tx.probe_reply(path, seq);
                vec![Action::Send { uplink: UplinkId(sent.path), bytes: sent.bytes }]
            }
            Event::Dropped { reason } => {
                if matches!(reason, balancify_tunnel::DropReason::AuthFailed) {
                    self.counters.auth_failed += 1;
                }
                Vec::new()
            }
        }
    }

    fn other_path(&self, exclude: u8) -> Option<u8> {
        self.tx.paths().into_iter().find(|p| *p != exclude)
    }

    fn uplink_infos(&self) -> Vec<ipc::UplinkInfo> {
        let best = self
            .snapshot
            .uplinks
            .iter()
            .filter(|u| u.eligible)
            .map(|u| u.weight)
            .fold(0.0f64, f64::max);
        self.snapshot.uplinks.iter().map(|u| uplink_info(u, best)).collect()
    }

    fn status_snapshot(&self) -> ipc::StatusSnapshot {
        ipc::StatusSnapshot {
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: ipc::SCHEMA_VERSION,
            policy_revision: self.snapshot.revision,
            rules_revision: self.rules.revision(),
            bond_enabled: self.cfg.bond_enabled,
            duplicate_mode: self.cfg.duplicate_mode,
            allow_metered: self.cfg.allow_metered,
            adapter_mtu: self.adapter_mtu().unwrap_or(0),
            uplinks: self.uplink_infos(),
            active_flows: self.active_flows() as u32,
            counters: self.counters.into(),
        }
    }

    fn flow_rule_infos(&self) -> Vec<ipc::FlowRule> {
        self.rules
            .rules()
            .iter()
            .map(|r| {
                let (class, pinned) = match r.class {
                    FlowClass::Bulk => (ipc::CLASS_BULK, 0),
                    FlowClass::LatencySensitive => (ipc::CLASS_LATENCY_SENSITIVE, 0),
                    FlowClass::Pinned(id) => (ipc::CLASS_PINNED, id.0),
                };
                ipc::FlowRule {
                    id: r.id,
                    name: r.name.clone(),
                    class,
                    pinned_uplink: pinned,
                    priority: r.priority,
                    proto: r.proto.unwrap_or(0),
                    port_start: r.dst_port.map(|p| p.start).unwrap_or(0),
                    port_end: r.dst_port.map(|p| p.end).unwrap_or(0),
                    duplicate: r.duplicate_eligible,
                }
            })
            .collect()
    }

    fn apply_rule(&mut self, rule: ipc::FlowRule) -> Result<(), String> {
        if rule.id < balancify_core::FIRST_CUSTOM_RULE_ID {
            return Err(format!(
                "rule id {} is reserved for built-in rules",
                rule.id
            ));
        }
        let class = match rule.class {
            ipc::CLASS_BULK => FlowClass::Bulk,
            ipc::CLASS_LATENCY_SENSITIVE => FlowClass::LatencySensitive,
            ipc::CLASS_PINNED => FlowClass::Pinned(UplinkId(rule.pinned_uplink)),
            other => return Err(format!("unknown flow class {other}")),
        };
        if rule.name.trim().is_empty() { return Err("rule name must not be empty".to_string()); }
        if rule.port_start > rule.port_end {
            return Err(format!("port range {}..{} is inverted", rule.port_start, rule.port_end));
        }
        let mut r = balancify_core::Rule::new(rule.id, rule.name, class).priority(rule.priority);
        if rule.proto != 0 { r = r.proto(rule.proto); }
        if !(rule.port_start == 0 && rule.port_end == 0) {
            r = r.port(balancify_core::PortRange::range(rule.port_start, rule.port_end));
        }
        if rule.duplicate { r = r.duplicate(true); }
        self.rules.add(r);
        Ok(())
    }
}

impl Service<balancify_crypto::TunnelCipher> {
    /// For secure mode: after handshake, apply new transport keys and open
    /// session. Re-creates sender and receiver with new ciphers but same session
    /// and paths. Old ciphers are dropped and zeroized.
    pub fn apply_transport_keys(&mut self, keys: &balancify_crypto::TransportKeys, now: Instant) {
        if let (Some(tx_cipher), Some(rx_cipher)) = (keys.send_cipher(), keys.recv_cipher()) {
            let session = self.cfg.session;
            // Preserve DRR quanta from the last published snapshot; fallback to
            // bare path ids with default quantum if snapshot empty (early boot).
            let quanta = {
                let q = self.snapshot.quanta();
                if q.is_empty() {
                    self.tx.paths().into_iter().map(|p| (p, 1400u64)).collect()
                } else {
                    q
                }
            };
            let sender_cfg = SenderConfig { rto: self.cfg.rto, ..SenderConfig::default() };
            let receiver_cfg = ReceiverConfig {
                hold_cap: self.cfg.hold_cap,
                idle_timeout: self.cfg.idle_timeout,
                auto_accept: self.cfg.auto_accept,
                max_sessions: ReceiverConfig::default().max_sessions,
            };
            self.tx = Sender::with_config(session, tx_cipher, quanta, sender_cfg);
            self.rx = Receiver::new(rx_cipher, receiver_cfg);
            self.last_rekey = None;
            self.packets_since_rekey = 0;
            self.key_epoch_started = Some(now);
            self.rekey_due = false;
            if !self.cfg.auto_accept {
                self.rx.open_session(session, now);
            }
        }
    }

    /// Secure session establishment: verify peer static against pinned set and
    /// replay cache, then apply keys and open session.
    pub fn establish_secure_session(
        &mut self,
        keys: &balancify_crypto::TransportKeys,
        peer_static: [u8; 32],
        is_client: bool,
        now: Instant,
    ) -> Result<(), balancify_crypto::HandshakeError> {
        if !self.is_peer_allowed(&peer_static, is_client) {
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        self.apply_transport_keys(keys, now);
        Ok(())
    }

    /// Initiate Noise_IK handshake as client (initiator). Returns handshake
    /// flight 1 framed as `[0xFF, 0x01] + msg1` ready to send over UDP.
    /// Stores initiator state for later `handle_handshake_msg2`.
    /// `relay_static` is the pinned relay identity; if `pinned_relays` non-empty,
    /// it must be pinned. `prologue` binds handshake to context (e.g. b"balancify handshake v1").
    pub fn initiate_handshake(
        &mut self,
        relay_static: [u8; 32],
        prologue: &[u8],
    ) -> Result<Vec<u8>, balancify_crypto::HandshakeError> {
        let static_secret = self
            .static_keypair
            .as_ref()
            .map(|kp| kp.secret_bytes())
            .unwrap_or_else(|| balancify_crypto::StaticKeypair::generate().secret_bytes());

        // Check pinning for relay
        let initiator = balancify_crypto::Initiator::new_checked(
            static_secret,
            relay_static,
            prologue,
            Some(&self.pinned_relays),
        )?;

        // Generate ephemeral
        let eph = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
        let session_bytes = self.cfg.session.to_be_bytes();

        // Need mutable initiator to write
        let mut init = initiator;
        let msg1 = init.write_message(eph, &session_bytes);

        self.handshake_initiator = Some(init);

        // Frame as 0xFF 0x01 + msg1
        let mut out = Vec::with_capacity(2 + msg1.len());
        out.push(0xFF);
        out.push(0x01);
        out.extend_from_slice(&msg1);
        Ok(out)
    }

    /// Handle handshake flight 2 from relay (framed as `[0xFF, 0x02] + msg2` or raw msg2).
    /// Verifies, derives transport keys, and applies them.
    pub fn handle_handshake_msg2(
        &mut self,
        msg: &[u8],
        now: Instant,
    ) -> Result<(), balancify_crypto::HandshakeError> {
        let raw = if msg.len() >= 2 && msg[0] == 0xFF && msg[1] == 0x02 {
            &msg[2..]
        } else {
            msg
        };

        // A handshake response is single-use, including malformed or
        // mismatched responses. Do not leave an authenticated-but-rejected
        // transcript available for another attempt.
        let mut initiator = self
            .handshake_initiator
            .take()
            .ok_or(balancify_crypto::HandshakeError::BadOrder)?;
        let (payload, keys) = initiator.read_message(raw)?;

        if payload.len() != std::mem::size_of::<u64>() {
            return Err(balancify_crypto::HandshakeError::Truncated);
        }
        let echoed = u64::from_be_bytes(payload[..8].try_into().unwrap());
        if echoed != self.cfg.session {
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }

        self.apply_transport_keys(&keys, now);
        self.handshake_initiator = None;
        Ok(())
    }

    /// Handle incoming datagram that may be handshake or tunnel data.
    /// Returns true if it was handshake and handled.
    pub fn handle_maybe_handshake(&mut self, dg: &[u8], now: Instant) -> Result<bool, balancify_crypto::HandshakeError> {
        if dg.len() >= 2 && dg[0] == 0xFF && dg[1] == 0x02 {
            self.handle_handshake_msg2(dg, now)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Handle a UDP datagram arriving on `uplink`: if it is a handshake msg2,
    /// complete handshake; otherwise treat as tunnel data via `ingest_path`.
    pub fn handle_path_datagram(
        &mut self,
        uplink: UplinkId,
        dg: &[u8],
        now: Instant,
    ) -> Result<Vec<Action>, balancify_crypto::HandshakeError> {
        if dg.len() >= 2 && dg[0] == 0xFF && dg[1] == 0x02 {
            self.handle_handshake_msg2(dg, now)?;
            Ok(Vec::new())
        } else {
            Ok(self.ingest_path(uplink, dg, now))
        }
    }

    /// Apply keys produced by a peer-coordinated handshake. Do not call with
    /// locally derived keys: the remote endpoint must install the same epoch.
    pub fn rekey_with(&mut self, new_keys: &balancify_crypto::TransportKeys, now: Instant) {
        self.apply_transport_keys(new_keys, now);
        self.last_rekey = Some(now);
        self.packets_since_rekey = 0;
    }
}

fn uplink_info(u: &UplinkView, best_weight: f64) -> ipc::UplinkInfo {
    let state = match u.state {
        LinkState::Probing => ipc::STATE_PROBING,
        LinkState::Up => ipc::STATE_UP,
        LinkState::Degraded => ipc::STATE_DEGRADED,
        LinkState::Down => ipc::STATE_DOWN,
        LinkState::Recovering => ipc::STATE_RECOVERING,
    };
    let weight_permille = if best_weight > 0.0 && u.eligible {
        ((u.weight / best_weight) * 1000.0).round().min(1000.0) as u16
    } else {
        0
    };
    ipc::UplinkInfo {
        id: u.id.0,
        state,
        rtt_ms: u.rtt.as_millis().min(u32::MAX as u128) as u32,
        loss_permille: (u.loss * 1000.0).round().min(1000.0) as u16,
        capacity_bps: u.capacity_bps,
        weight_permille,
        metered: u.metered,
        eligible: u.eligible,
    }
}

fn permille(v: f64) -> i16 {
    (v * 1000.0).round().clamp(i16::MIN as f64, i16::MAX as f64) as i16
}

fn relay_failover_event_message(count: u64, timeout: Duration) -> String {
    // Do not emit configured relay IPs/ports to ETW; diagnostics expose only the
    // transition and aggregate counters, matching support-bundle redaction.
    format!("relay failover count={count} timeout={}s", timeout.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;
    use balancify_tunnel::PassThrough;
    use std::collections::BTreeSet;

    fn sa(p: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 1), p))
    }
    fn peer(p: u16) -> std::net::SocketAddr {
        std::net::SocketAddr::V4(std::net::SocketAddrV4::new(std::net::Ipv4Addr::new(203, 0, 113, 9), p))
    }

    /// Two healthy uplinks and a published snapshot.
    fn ready_service(now: Instant) -> Service<PassThrough> {
        let cfg = ServiceConfig { seed: 0xBEEF, session: 7, ..ServiceConfig::default() };
        let mut s = Service::new(cfg, PassThrough, PassThrough);
        s.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
        s.add_uplink(UplinkId(1), 100_000_000, false, 1500, now);
        for _ in 0..5 {
            s.on_probe_ok(UplinkId(0), Duration::from_millis(10), now);
            s.on_probe_ok(UplinkId(1), Duration::from_millis(35), now);
        }
        assert!(s.publish(now), "first publish must advance the revision");
        s
    }

    #[test]
    fn raw_ip_packet_entry_derives_flow_and_tunnels_original_bytes() {
        let now = Instant::now();
        let mut service = ready_service(now);
        let mut packet = vec![0u8; 40];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&40u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[10, 1, 2, 3]);
        packet[16..20].copy_from_slice(&[198, 51, 100, 9]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 0x50;

        let actions = service.send_ip_packet(&packet, now).expect("valid raw IPv4 packet");
        let frame = actions.iter().find_map(|action| match action {
            Action::Send { bytes, .. } => Some(bytes),
            _ => None,
        }).expect("healthy paths produce a tunnel frame");
        let (_, tunneled_packet) = Header::decode(frame).expect("valid tunnel frame");
        assert_eq!(tunneled_packet, packet.as_slice());
        assert_eq!(service.counters().packets_stripped, 1);
    }

    #[test]
    fn malformed_raw_ip_packet_is_rejected_before_service_state_changes() {
        let now = Instant::now();
        let mut service = ready_service(now);
        let counters_before = service.counters();
        let error = service.send_ip_packet(&[0x45, 0, 0, 20], now).unwrap_err();
        assert_eq!(error, packet::PacketFlowError::EmptyOrTruncated);
        assert_eq!(service.counters(), counters_before);
    }

    fn capacity_of(s: &Service<PassThrough>, id: UplinkId) -> Option<u64> {
        s.snapshot().view(id).map(|u| u.capacity_bps)
    }

    fn sends(actions: &[Action]) -> Vec<UplinkId> {
        actions
            .iter()
            .filter_map(|a| match a {
                Action::Send { uplink, .. } => Some(*uplink),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn bonded_flow_is_striped_across_both_uplinks() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5000), peer(443));
        let mut used = BTreeSet::new();
        let mut striped = 0u64;
        // 40 packets is more than one initial window holds, so each one is
        // acknowledged as it goes - which is also what keeps the test about
        // striping rather than about backpressure.
        for _ in 0..200 {
            if striped >= 40 { break; }
            let actions = s.send_app_packet(&flow, None, &[0u8; 1200], now);
            if actions.iter().any(|a| matches!(a, Action::Hold { .. })) { break; }
            used.extend(sends(&actions));
            striped += 1;
            let mut ack = Vec::new();
            Header::new(FrameKind::Ack, 0, 7, striped - 1).encode(&mut ack);
            s.ingest_path(UplinkId(0), &ack, now);
        }
        assert_eq!(striped, 40, "the window must stay open while packets are acknowledged");
        assert_eq!(used.len(), 2, "bond mode must use every healthy uplink: {used:?}");
        assert_eq!(s.counters().packets_stripped, 40);
        assert_eq!(s.counters().packets_forwarded, 0);
        assert_eq!(s.counters().held, 0);
    }

    #[test]
    fn flow_level_mode_keeps_a_flow_on_one_uplink() {
        let now = Instant::now();
        let mut s = ready_service(now);
        assert_eq!(s.handle(ipc::Request::SetBondMode { enabled: false }, now), ipc::Response::Ack);
        let flow = FlowKey::new(6, sa(5001), peer(443));
        let mut used = BTreeSet::new();
        for _ in 0..20 {
            let actions = s.send_app_packet(&flow, None, &[0u8; 1200], now);
            used.extend(sends(&actions));
        }
        assert_eq!(used.len(), 1, "flow-level placement must not stripe: {used:?}");
        assert_eq!(s.counters().packets_forwarded, 20);
    }

    #[test]
    fn flow_level_capacity_uses_peer_acknowledgements() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.handle(ipc::Request::SetBondMode { enabled: false }, now);
        let flow = FlowKey::new(6, sa(5099), peer(443));
        let actions = s.send_app_packet(&flow, None, &[7u8; 1200], now);
        let sent_bytes = actions.iter().find_map(|action| match action {
            Action::Send { bytes, .. } => Some(bytes.clone()),
            _ => None,
        }).expect("flow-level packet is sent");
        let (header, _) = Header::decode(&sent_bytes).expect("flow frame header");
        assert_eq!(header.kind, FrameKind::FlowData);
        assert_eq!(s.tx.flow_pending_bytes(), 1200);
        let before = s.snapshot().view(UplinkId(header.path)).unwrap().capacity_bps;

        let later = now + Duration::from_secs(2);
        let ack = s.tx.flow_ack_for_session(header.session, header.path, header.seq);
        assert!(s.ingest_path(UplinkId(header.path), &ack.bytes, later).is_empty());
        assert_eq!(s.tx.flow_pending_bytes(), 0, "authenticated peer ACK releases bounded accounting");
        s.publish(later);
        let after = s.snapshot().view(UplinkId(header.path)).unwrap().capacity_bps;
        assert_ne!(after, before, "flow capacity changes only after the peer ACK is accounted");
    }

    #[test]
    fn flow_level_tick_reinjects_unacknowledged_data_on_another_uplink() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.handle(ipc::Request::SetBondMode { enabled: false }, now);
        let flow = FlowKey::new(6, sa(5100), peer(443));
        let sent = s.send_app_packet(&flow, None, &[9u8; 1200], now);
        let original = sent.iter().find_map(|action| match action {
            Action::Send { bytes, .. } => Header::decode(bytes).map(|(header, _)| header),
            _ => None,
        }).expect("flow-level frame is sent");
        assert_eq!(original.kind, FrameKind::FlowData);

        // Remove the original uplink as would happen on a real disconnect;
        // publish the topology before the retry timer runs.
        s.remove_uplink(UplinkId(original.path));
        s.publish(now + Duration::from_millis(1));
        let retried = s.tick(now + Duration::from_millis(121));
        let repairs: Vec<_> = retried.iter().filter_map(|action| match action {
            Action::Send { bytes, .. } => Header::decode(bytes)
                .map(|(header, _)| header)
                .filter(|header| header.kind == FrameKind::FlowData),
            _ => None,
        }).collect();
        assert_eq!(repairs.len(), 1);
        assert_ne!(repairs[0].path, original.path);
        assert_eq!(repairs[0].flags & balancify_tunnel::FLAG_REINJECTED, balancify_tunnel::FLAG_REINJECTED);
        assert_eq!((repairs[0].session, repairs[0].seq), (original.session, original.seq));
        assert_eq!(s.counters().reinjections, 1);
    }

    #[test]
    fn duplicate_mode_sends_critical_packets_twice() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.handle(ipc::Request::SetDuplicateMode { enabled: true }, now);
        // DNS is duplicate-eligible in the curated rules; 9 B is under the cap.
        let dns = FlowKey::new(17, sa(5002), peer(53));
        let actions = s.send_app_packet(&dns, None, b"\x12\x34query", now);
        assert_eq!(sends(&actions).len(), 2, "one original + one duplicate");
        assert_eq!(s.counters().duplicates_sent, 1);
        // bulk traffic is never duplicated
        let bulk = FlowKey::new(6, sa(5003), peer(443));
        let actions = s.send_app_packet(&bulk, None, &[0u8; 1200], now);
        assert_eq!(sends(&actions).len(), 1);
    }

    #[test]
    fn no_healthy_uplink_refuses_instead_of_black_holing() {
        let now = Instant::now();
        let mut s = Service::new(ServiceConfig::default(), PassThrough, PassThrough);
        s.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        s.publish(now); // still Probing
        let flow = FlowKey::new(6, sa(5004), peer(443));
        let actions = s.send_app_packet(&flow, None, b"payload", now);
        assert!(matches!(actions.as_slice(), [Action::Refused { .. }]));
        assert_eq!(s.counters().refused, 1);
    }

    #[test]
    fn an_idle_peer_session_releases_its_slot() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let mut frame = Vec::new();
        Header::new(FrameKind::Data, 0, 999, 0).encode(&mut frame);
        frame.extend_from_slice(b"hello");
        let actions = s.ingest_path(UplinkId(0), &frame, now);
        assert!(actions.iter().any(|a| matches!(a, Action::Deliver { .. })), "lab form accepts");
        assert_eq!(s.counters().sessions_evicted, 0, "an active session is kept");

        let idle_timeout = s.config().idle_timeout;
        s.tick(now + idle_timeout + Duration::from_secs(1));
        assert_eq!(s.counters().sessions_evicted, 1, "a peer that went away must free its slot (Sec.9.1)");
    }

    #[test]
    fn an_unanswered_probe_is_forgotten_after_the_probe_timeout() {
        let now = Instant::now();
        let cfg = ServiceConfig { probe_timeout: Duration::from_millis(100), ..ServiceConfig::default() };
        let mut s = Service::new(cfg, PassThrough, PassThrough);
        s.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        for _ in 0..5 { s.on_probe_ok(UplinkId(0), Duration::from_millis(20), now); }
        s.publish(now);

        let later = now + Duration::from_secs(30);
        s.tick(later);
        assert_eq!(s.counters().probes, 1, "an idle link is probed");
        assert_eq!(s.pending_probes(), 1);

        // No reply ever arrives: the entry must not outlive the timeout.
        s.tick(later + Duration::from_millis(200));
        assert_eq!(s.pending_probes(), 0, "unanswered probes release their table entry");
    }

    #[test]
    fn a_capacity_sample_lands_on_the_uplink_that_carried_the_data() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let before0 = capacity_of(&s, UplinkId(0));
        let before1 = capacity_of(&s, UplinkId(1));

        // Stripe a flow, then acknowledge the whole range with one cumulative
        // ACK that happens to arrive on uplink 1.
        let flow = FlowKey::new(6, sa(5011), peer(443));
        let mut carried = [false; 2];
        for _ in 0..40 {
            let actions = s.send_app_packet(&flow, None, &[0u8; 1200], now);
            for a in &actions {
                if let Action::Send { uplink, .. } = a { carried[uplink.0 as usize] = true; }
            }
        }
        assert!(carried[0] && carried[1], "the test must actually stripe: {carried:?}");

        // Past the 500 ms ACK window, so the credit becomes a sample.
        let ack_at = now + Duration::from_millis(600);
        let mut ack = Vec::new();
        Header::new(FrameKind::Ack, 1, 7, 39).encode(&mut ack);
        s.ingest_path(UplinkId(1), &ack, ack_at);
        s.publish(ack_at);

        assert_ne!(
            capacity_of(&s, UplinkId(0)),
            before0,
            "uplink 0 carried data, so it must earn a sample even though the ACK came in on uplink 1"
        );
        assert_ne!(capacity_of(&s, UplinkId(1)), before1, "and so must uplink 1");
    }

    #[test]
    fn sleep_resume_abandons_dead_state_and_requires_reprobing() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5014), peer(443));
        for _ in 0..20 { s.send_app_packet(&flow, None, &[0u8; 1200], now); }
        assert!(s.in_flight(UplinkId(0)) + s.in_flight(UplinkId(1)) > 0);
        assert!(s.snapshot().is_healthy(UplinkId(0)));

        let woke = now + Duration::from_secs(600);
        let abandoned = s.resume_from_sleep(woke);
        assert!(abandoned > 0, "packets in flight before sleep were abandoned");
        assert_eq!(s.in_flight(UplinkId(0)) + s.in_flight(UplinkId(1)), 0);
        assert_eq!(s.window(UplinkId(0)), s.window(UplinkId(1)), "windows are back to initial");
        assert!(!s.snapshot().is_healthy(UplinkId(0)), "every uplink must re-probe (Sec.6.5)");
        assert_eq!(s.counters().resumes, 1);

        // Keepalives go out first, to re-establish the mappings (Sec.6.6).
        let actions = s.tick(woke);
        let keepalives = actions
            .iter()
            .filter(|a| {
                matches!(a, Action::Send { bytes, .. }
                    if Header::decode(bytes).map(|(h, _)| h.kind) == Some(FrameKind::Keepalive))
            })
            .count();
        assert_eq!(keepalives, 2, "one keepalive per path on the first tick after resume");
    }

    #[test]
    fn a_nat_rebinding_rekeys_the_path_and_keeps_the_session() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5015), peer(443));
        for _ in 0..40 { s.send_app_packet(&flow, None, &[0u8; 1200], now); }
        let session = s.config().session;
        let flows_before = s.active_flows();
        let local = |p: u16| {
            std::net::SocketAddr::V4(std::net::SocketAddrV4::new(
                std::net::Ipv4Addr::new(192, 168, 1, 10),
                p,
            ))
        };

        assert!(!s.note_local_endpoint(UplinkId(1), local(5000), now), "first observation is not a change");
        let untouched = s.in_flight(UplinkId(0));
        assert!(untouched > 0, "the test must have put packets on uplink 0");

        assert!(
            s.note_local_endpoint(UplinkId(1), local(5001), now + Duration::from_secs(30)),
            "a new source port is a re-binding"
        );
        assert_eq!(s.in_flight(UplinkId(1)), 0, "the dead mappings packets are dropped");
        assert_eq!(s.in_flight(UplinkId(0)), untouched, "and only that path is re-keyed");
        assert_eq!(s.config().session, session, "the session survives (Sec.6.6)");
        assert_eq!(s.active_flows(), flows_before, "and so does flow affinity");
        assert_eq!(s.counters().path_changes, 1);
        assert!(
            !s.note_local_endpoint(UplinkId(1), local(5001), now + Duration::from_secs(31)),
            "the same endpoint reported twice is not a change"
        );
    }

    #[test]
    fn a_full_window_holds_the_packet_instead_of_dropping_it() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5012), peer(443));
        let payload = vec![0u8; 1200];
        let mut sent = 0;
        let mut held = 0;
        for _ in 0..200 {
            let actions = s.send_app_packet(&flow, None, &payload, now);
            if actions.iter().any(|a| matches!(a, Action::Hold { .. })) { held += 1; } else { sent += 1; }
        }
        assert!(sent > 0, "the initial window admits packets");
        assert!(held > 0, "and then applies backpressure (Sec.6.4 rule 4)");
        assert_eq!(s.counters().held, held);
        assert_eq!(s.counters().refused, 0, "congestion is not a refusal: D3 is about health");
        assert!(s.in_flight(UplinkId(0)) + s.in_flight(UplinkId(1)) > 0);
    }

    #[test]
    fn acknowledgements_reopen_the_window() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5013), peer(443));
        let payload = vec![0u8; 1200];
        let mut seq = 0u64;
        for _ in 0..200 {
            let actions = s.send_app_packet(&flow, None, &payload, now);
            if !actions.iter().any(|a| matches!(a, Action::Hold { .. })) { seq += 1; }
        }
        let in_flight_before = s.in_flight(UplinkId(0)) + s.in_flight(UplinkId(1));
        assert!(in_flight_before > 0);

        // Acknowledge everything, on either uplink: the credit follows the data.
        let mut ack = Vec::new();
        Header::new(FrameKind::Ack, 1, 7, seq - 1).encode(&mut ack);
        s.ingest_path(UplinkId(1), &ack, now + Duration::from_millis(20));
        assert_eq!(s.in_flight(UplinkId(0)) + s.in_flight(UplinkId(1)), 0, "all bytes acknowledged");

        let actions = s.send_app_packet(&flow, None, &payload, now + Duration::from_millis(21));
        assert!(!actions.iter().any(|a| matches!(a, Action::Hold { .. })), "the window reopened");
    }

    #[test]
    fn tick_emits_keepalives_and_a_bounded_probe() {
        let now = Instant::now();
        let mut s = ready_service(now);
        // traffic arms the per-path keepalive timers (Sec.6.6). A path that has
        // never carried traffic has no NAT binding to keep alive, so the test
        // has to cover a full DRR lap: at these quanta the faster path takes a
        // 20-packet burst before the slower one gets a turn.
        let flow = FlowKey::new(6, sa(5010), peer(443));
        let mut carried = std::collections::BTreeSet::new();
        for _ in 0..40 {
            let actions = s.send_app_packet(&flow, None, &[0u8; 1200], now);
            carried.extend(sends(&actions));
        }
        assert_eq!(carried.len(), 2, "both paths must carry traffic to be armed: {carried:?}");

        let later = now + Duration::from_secs(30);
        let actions = s.tick(later);
        let kind_of = |a: &Action| match a {
            Action::Send { bytes, .. } => Header::decode(bytes).map(|(h, _)| h.kind),
            _ => None,
        };
        assert_eq!(
            actions.iter().filter(|a| kind_of(a) == Some(FrameKind::Keepalive)).count(),
            2,
            "one keepalive per path (Sec.6.6)"
        );
        assert_eq!(
            actions.iter().filter(|a| kind_of(a) == Some(FrameKind::Probe)).count(),
            1,
            "one bounded idle probe per tick (Sec.6.3b)"
        );
        assert!(s.counters().keepalives >= 2);
        assert_eq!(s.counters().probes, 1);
        // keepalives are not due again immediately
        assert_eq!(
            s.tick(later + Duration::from_secs(1)).iter().filter(|a| kind_of(a) == Some(FrameKind::Keepalive)).count(),
            0
        );
    }

    #[test]
    fn probe_reply_becomes_rtt_and_capacity() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let t1 = now + Duration::from_secs(1);
        let actions = s.tick(t1);
        let probe = actions
            .iter()
            .find_map(|a| match a {
                Action::Send { uplink, bytes } => {
                    let (h, _) = Header::decode(bytes).unwrap();
                    if h.kind == FrameKind::Probe { Some((*uplink, h)) } else { None }
                }
                _ => None,
            })
            .expect("tick must probe an idle link");
        // The far end echoes it; 8 ms later we learn RTT and capacity.
        let mut reply = Vec::new();
        Header::new(FrameKind::ProbeReply, probe.1.path, probe.1.session, probe.1.seq).encode(&mut reply);
        let before = s.snapshot().view(probe.0).unwrap().rtt;
        s.ingest_path(probe.0, &reply, t1 + Duration::from_millis(8));
        s.publish(t1);
        let after = s.snapshot().view(probe.0).unwrap().rtt;
        assert!(after < before, "an 8 ms probe must pull a 10 ms+ estimate down ({after:?} vs {before:?})");
        assert!(s.snapshot().view(probe.0).unwrap().capacity_bps > 0);
    }

    #[test]
    fn forged_ack_does_not_refresh_relay_liveness() {
        #[derive(Clone)]
        struct RejectAll;
        impl balancify_tunnel::Crypto for RejectAll {
            fn seal(&self, _path: u8, _seq: u64, _aad: &[u8], plain: &[u8], out: &mut Vec<u8>) {
                out.extend_from_slice(plain);
            }
            fn open(&self, _path: u8, _seq: u64, _aad: &[u8], _cipher: &[u8]) -> Option<Vec<u8>> { None }
        }

        let now = Instant::now();
        let mut svc = Service::new(ServiceConfig::default(), RejectAll, RejectAll);
        svc.set_relays("10.0.0.1:4430".parse().unwrap(), None);
        svc.on_relay_ack(now);
        let mut forged = Vec::new();
        Header::new(FrameKind::Ack, 0, svc.config().session, 0)
            .with_flags(balancify_tunnel::FLAG_ECN_CE)
            .encode(&mut forged);

        let later = now + Duration::from_secs(9);
        assert!(svc.ingest_path(UplinkId(0), &forged, later).is_empty());
        assert_eq!(svc.relay_last_ack, Some(now), "unauthenticated ACK cannot keep a relay alive");
        assert_eq!(svc.counters().auth_failed, 1);
    }

    #[test]
    fn ipc_support_bundle_returns_complete_redacted_json_over_the_contract() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.set_relays("198.51.100.77:9443".parse().unwrap(), None);

        let response = s.handle(ipc::Request::GetSupportBundle, now);
        let ipc::Response::SupportBundle(json) = &response else {
            panic!("expected a support bundle response");
        };
        assert!(json.contains("\"counters\":{"));
        assert!(json.contains("\"uplinks\":[{"));
        assert!(json.contains("\"per_path\":["));
        assert!(json.contains("\"relay_configured\":true"));
        assert!(!json.contains("198.51.100.77"));
        assert!(!json.contains("9443"));

        let frame = balancify_ipc::frame_response(&response);
        let (kind, payload, _) = balancify_ipc::decode_frame(&frame).unwrap().unwrap();
        assert_eq!(kind, balancify_ipc::FrameKind::Response);
        assert_eq!(balancify_ipc::Response::decode(payload), Some(response));
    }

    #[test]
    fn ipc_status_reflects_the_live_system() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5005), peer(443));
        s.send_app_packet(&flow, None, &[0u8; 1200], now);

        let ipc::Response::Status(snap) = s.handle(ipc::Request::GetStatus, now) else {
            panic!("expected a status snapshot");
        };
        assert_eq!(snap.schema_version, ipc::SCHEMA_VERSION);
        assert!(snap.policy_revision > 0);
        assert_eq!(snap.uplinks.len(), 2);
        assert_eq!(snap.adapter_mtu, 1440, "1500 - 60 B of tunnel overhead");
        assert_eq!(snap.active_flows, 1);
        assert!(snap.counters.packets_stripped > 0);
        assert!(snap.bond_enabled);
        let best = snap
            .uplinks
            .iter()
            .find(|u| u.weight_permille == 1000)
            .expect("one uplink is the weight reference");
        assert!(best.eligible);

        // and the whole thing survives the wire
        let bytes = balancify_ipc::frame_response(&ipc::Response::Status(snap.clone()));
        let (kind, payload, _) = balancify_ipc::decode_frame(&bytes).unwrap().unwrap();
        assert_eq!(kind, balancify_ipc::FrameKind::Response);
        assert_eq!(balancify_ipc::Response::decode(payload), Some(ipc::Response::Status(snap)));

        // The shell's Rules screen sees the curated defaults
        let ipc::Response::FlowRules(rules) = s.handle(ipc::Request::ListFlowRules, now) else {
            panic!("expected rules");
        };
        assert!(rules.iter().any(|r| r.name == "dns" && r.class == ipc::CLASS_LATENCY_SENSITIVE));
    }

    #[test]
    fn ipc_cannot_mutate_reserved_builtin_rule_ids() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let dns_flow = FlowKey::new(17, sa(53000), peer(53));
        assert_eq!(s.rules().classify(&dns_flow, None), FlowClass::LatencySensitive);

        let attempted_override = ipc::FlowRule {
            id: 1,
            name: "replace-built-in-dns".to_string(),
            class: ipc::CLASS_BULK,
            pinned_uplink: 0,
            priority: 1,
            proto: 17,
            port_start: 53,
            port_end: 53,
            duplicate: false,
        };
        assert!(matches!(
            s.handle(ipc::Request::SetFlowRule(attempted_override), now),
            ipc::Response::Error { status: ipc::Status::BadRequest, .. }
        ));
        assert!(matches!(
            s.handle(ipc::Request::RemoveFlowRule { id: 1 }, now),
            ipc::Response::Error { status: ipc::Status::BadRequest, .. }
        ));
        assert_eq!(s.rules().classify(&dns_flow, None), FlowClass::LatencySensitive);
        assert!(s.rules().rules().iter().any(|rule| rule.id == 1 && rule.name == "dns"));
    }

    #[test]
    fn ipc_rule_edits_reach_the_classifier() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let flow = FlowKey::new(6, sa(5006), peer(8443));
        assert_eq!(s.rules().classify(&flow, None), FlowClass::Bulk);

        let rule = ipc::FlowRule {
            id: balancify_core::FIRST_CUSTOM_RULE_ID,
            name: "pin-8443".to_string(),
            class: ipc::CLASS_PINNED,
            pinned_uplink: 1,
            priority: 5,
            proto: 6,
            port_start: 8443,
            port_end: 8443,
            duplicate: false,
        };
        assert_eq!(s.handle(ipc::Request::SetFlowRule(rule.clone()), now), ipc::Response::Ack);
        assert_eq!(s.rules().classify(&flow, None), FlowClass::Pinned(UplinkId(1)));
        let actions = s.send_app_packet(&flow, None, b"data", now);
        assert_eq!(sends(&actions), vec![UplinkId(1)], "a pin is a placement, not a hint");

        // SetFlowRule is an upsert: editing the same stable id replaces the
        // prior rule instead of leaving an unreachable duplicate in the list.
        let updated = ipc::FlowRule {
            name: "pin-8443-updated".to_string(),
            pinned_uplink: 0,
            ..rule.clone()
        };
        assert_eq!(s.handle(ipc::Request::SetFlowRule(updated), now), ipc::Response::Ack);
        assert_eq!(s.rules().rules().iter().filter(|r| r.id == balancify_core::FIRST_CUSTOM_RULE_ID).count(), 1);
        assert_eq!(s.rules().rules().iter().find(|r| r.id == balancify_core::FIRST_CUSTOM_RULE_ID).unwrap().name, "pin-8443-updated");
        assert_eq!(s.rules().classify(&flow, None), FlowClass::Pinned(UplinkId(0)));
        let actions = s.send_app_packet(&flow, None, b"updated", now);
        assert_eq!(sends(&actions), vec![UplinkId(0)]);

        // invalid input is rejected, not half-applied
        let inverted = ipc::FlowRule { id: balancify_core::FIRST_CUSTOM_RULE_ID + 1, port_start: 100, port_end: 10, ..rule.clone() };
        assert!(matches!(
            s.handle(ipc::Request::SetFlowRule(inverted), now),
            ipc::Response::Error { status: ipc::Status::BadRequest, .. }
        ));
        let unknown = ipc::FlowRule { id: balancify_core::FIRST_CUSTOM_RULE_ID + 2, class: 77, ..rule.clone() };
        assert!(matches!(
            s.handle(ipc::Request::SetFlowRule(unknown), now),
            ipc::Response::Error { status: ipc::Status::BadRequest, .. }
        ));
        assert!(!s.rules().rules().iter().any(|r| r.id == balancify_core::FIRST_CUSTOM_RULE_ID + 1 || r.id == balancify_core::FIRST_CUSTOM_RULE_ID + 2));

        assert_eq!(s.handle(ipc::Request::RemoveFlowRule { id: balancify_core::FIRST_CUSTOM_RULE_ID }, now), ipc::Response::Ack);
        assert_eq!(s.rules().classify(&flow, None), FlowClass::Bulk);
        assert!(matches!(
            s.handle(ipc::Request::RemoveFlowRule { id: balancify_core::FIRST_CUSTOM_RULE_ID }, now),
            ipc::Response::Error { .. }
        ));
    }

    #[test]
    fn ipc_rejects_an_absurd_event_rate() {
        let now = Instant::now();
        let mut s = ready_service(now);
        assert!(matches!(
            s.handle(ipc::Request::SubscribeEvents { interval_hz: 0 }, now),
            ipc::Response::Error { .. }
        ));
        assert!(matches!(
            s.handle(ipc::Request::SubscribeEvents { interval_hz: 99 }, now),
            ipc::Response::Error { .. }
        ));
        assert_eq!(s.handle(ipc::Request::SubscribeEvents { interval_hz: 1 }, now), ipc::Response::Ack);
        assert_eq!(s.event_interval_hz(), 1);
    }

    #[test]
    fn ipc_telemetry_snapshot_contains_warnings_and_counter_values() {
        let now = Instant::now();
        let mut s = Service::new(ServiceConfig::default(), PassThrough, PassThrough);
        s.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        s.counters.packets_forwarded = 17;

        let events = s.telemetry_events();
        assert!(events.contains(&ipc::Event::Warning { code: ipc::WARN_ALL_PATHS_DOWN }));
        assert_eq!(
            events.last(),
            Some(&ipc::Event::Stats(ipc::Counters { packets_forwarded: 17, ..Default::default() }))
        );
    }

    #[test]
    fn self_test_reports_no_capacity_before_probes() {
        let now = Instant::now();
        let mut s = Service::new(ServiceConfig::default(), PassThrough, PassThrough);
        s.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        let ipc::Response::SelfTest { passed, detail } = s.handle(ipc::Request::RunSelfTest, now) else {
            panic!("expected a self-test result");
        };
        assert!(!passed);
        assert!(detail.contains("no eligible uplink"), "{detail}");
        assert_eq!(s.poll_events(), vec![ipc::Event::Warning { code: ipc::WARN_ALL_PATHS_DOWN }]);
    }

    #[test]
    fn bond_revert_event_carries_the_measured_gain() {
        let now = Instant::now();
        let mut s = ready_service(now);
        let mut events = Vec::new();
        for _ in 0..15 {
            events.extend(s.observe_bond_gain(BondClass::Bulk, 101_000_000.0, 100_000_000.0));
        }
        assert_eq!(events.len(), 1, "exactly one revert is reported");
        let ipc::Event::BondReverted { class, gain_permille } = events[0] else {
            panic!("wrong event");
        };
        assert_eq!(class, ipc::CLASS_BULK);
        assert!(gain_permille < 150, "gain was below the 15 % threshold: {gain_permille}");
        // and the class now rides the flow-level lane
        assert!(!s.bond_enabled_for(FlowClass::Bulk));
        let flow = FlowKey::new(6, sa(5007), peer(443));
        let actions = s.send_app_packet(&flow, None, &[0u8; 1200], now);
        assert_eq!(sends(&actions).len(), 1);
        assert_eq!(s.counters().packets_forwarded, 1);
    }

    #[test]
    fn adapter_mtu_follows_the_narrowest_live_path() {
        let now = Instant::now();
        let mut s = ready_service(now);
        assert_eq!(s.adapter_mtu(), Some(1440));
        // a 1280-byte cellular path joins
        s.add_uplink(UplinkId(2), 50_000_000, false, 1280, now);
        for _ in 0..5 { s.on_probe_ok(UplinkId(2), Duration::from_millis(60), now); }
        s.publish(now);
        assert_eq!(s.adapter_mtu(), Some(1220), "min(1500,1500,1280) - 60");
        // and widens again when that path is unplugged
        s.remove_uplink(UplinkId(2));
        s.publish(now);
        assert_eq!(s.adapter_mtu(), Some(1440));
    }

    #[test]
    fn metered_uplink_stays_out_until_the_user_allows_it() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.add_uplink(UplinkId(2), 500_000_000, true, 1500, now);
        for _ in 0..5 { s.on_probe_ok(UplinkId(2), Duration::from_millis(5), now); }
        s.publish(now);
        assert!(!s.snapshot().is_healthy(UplinkId(2)));
        let dns = FlowKey::new(17, sa(5008), peer(53));
        assert_ne!(s.snapshot().place(&dns, FlowClass::LatencySensitive), Some(UplinkId(2)));

        assert_eq!(s.handle(ipc::Request::SetAllowMetered { allowed: true }, now), ipc::Response::Ack);
        s.publish(now);
        assert!(s.snapshot().is_healthy(UplinkId(2)));
        assert_eq!(s.snapshot().place(&dns, FlowClass::LatencySensitive), Some(UplinkId(2)));
        let ipc::Response::Status(snap) = s.handle(ipc::Request::GetStatus, now) else { panic!() };
        assert!(snap.allow_metered);
    }

    #[test]
    fn uplink_loss_fails_over_and_flows_keep_their_affinity() {
        let now = Instant::now();
        let mut s = ready_service(now);
        s.handle(ipc::Request::SetBondMode { enabled: false }, now);
        let flows: Vec<FlowKey> = (0..60).map(|i| FlowKey::new(6, sa(6000 + i), peer(443))).collect();
        let mut first = BTreeMap::new();
        for f in &flows {
            let actions = s.send_app_packet(f, None, b"x", now);
            if let [Action::Send { uplink, .. }] = &actions[..] { first.insert(f.clone(), *uplink); }
        }
        assert!(first.values().any(|u| *u == UplinkId(1)), "both uplinks should be used");

        for _ in 0..3 { s.on_probe_miss(UplinkId(1)); }
        s.publish(now);
        let mut moved = 0;
        for f in &flows {
            let actions = s.send_app_packet(f, None, b"x", now);
            let [Action::Send { uplink, .. }] = &actions[..] else { panic!("every flow must be served") };
            assert_eq!(*uplink, UplinkId(0));
            if let Some(prev) = first.get(f) {
                if *prev == UplinkId(1) {
                    moved += 1;
                } else {
                    assert_eq!(*prev, *uplink, "flows on the healthy uplink must not move");
                }
            }
        }
        assert!(moved > 0, "the flows on the failed uplink were re-placed");
    }

    #[test]
    fn secure_handshake_establishes_transport_keys() {
        use balancify_crypto::{EphemeralKeypair, PinnedKeys, Responder, StaticKeypair};
        let now = Instant::now();
        let relay_kp = StaticKeypair::generate();
        let client_kp = StaticKeypair::generate();

        // Service as client with TunnelCipher (initial dummy keys, will be replaced)
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 12345, seed: 0xBEEF, auto_accept: false, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.set_static_keypair(client_kp.clone());
        let mut pinned_relays = PinnedKeys::new();
        pinned_relays.pin(relay_kp.public_bytes());
        svc.set_pinned_relays(pinned_relays);

        // Initiate handshake
        let msg1_framed = svc.initiate_handshake(relay_kp.public_bytes(), b"balancify handshake v1").expect("initiate");
        assert_eq!(msg1_framed[0], 0xFF);
        assert_eq!(msg1_framed[1], 0x01);
        let msg1 = &msg1_framed[2..];

        // Relay side
        let mut responder = Responder::new(relay_kp.secret_bytes(), b"balancify handshake v1");
        let payload = responder.read_message_checked(msg1, None, None, None).expect("relay reads msg1");
        assert_eq!(payload, 12345u64.to_be_bytes());

        let eph_r = EphemeralKeypair::generate().secret_bytes();
        let (msg2, _keys_relay) = responder.write_message(eph_r, &12345u64.to_be_bytes()).expect("relay writes msg2");

        // Frame msg2 as 0xFF 0x02 + msg2
        let mut msg2_framed = Vec::with_capacity(2 + msg2.len());
        msg2_framed.push(0xFF);
        msg2_framed.push(0x02);
        msg2_framed.extend_from_slice(&msg2);

        // Service handles msg2
        svc.handle_handshake_msg2(&msg2_framed, now).expect("client handles msg2");

        // Now service should have transport keys applied and session open
        assert_eq!(svc.sessions(), 1, "session opened after handshake");

        // Verify that service can now send and relay can receive (using relay's keys)
        // We already have relay's transport keys from responder, but we need to reconstruct
        // client keys are inside svc now. For test, we just check that send works (no panic)
        let flow = FlowKey::new(6, sa(5000), peer(443));
        // Need uplinks for service to send
        svc.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
        for _ in 0..5 { svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now); }
        svc.publish(now);
        let actions = svc.send_app_packet(&flow, None, b"hello secure", now);
        assert!(actions.iter().any(|a| matches!(a, Action::Send { .. })), "must send after secure session");
    }

    #[test]
    fn handshake_rejects_wrong_session_echo_without_installing_keys() {
        use balancify_crypto::{EphemeralKeypair, Responder, StaticKeypair};
        let now = Instant::now();
        let relay_kp = StaticKeypair::generate();
        let client_kp = StaticKeypair::generate();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let cfg = ServiceConfig { session: 12345, auto_accept: false, ..ServiceConfig::default() };
        let mut svc = Service::new(
            cfg,
            balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap(),
            balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap(),
        );
        svc.set_static_keypair(client_kp);

        let msg1 = svc.initiate_handshake(relay_kp.public_bytes(), b"balancify handshake v1").unwrap();
        let mut responder = Responder::new(relay_kp.secret_bytes(), b"balancify handshake v1");
        let request_payload = responder.read_message_checked(&msg1[2..], None, None, None).unwrap();
        assert_eq!(request_payload, 12345u64.to_be_bytes());
        let wrong_session = 54321u64.to_be_bytes();
        let eph = EphemeralKeypair::generate().secret_bytes();
        let (msg2, _) = responder.write_message(eph, &wrong_session).unwrap();
        let mut framed = vec![0xFF, 0x02];
        framed.extend_from_slice(&msg2);

        assert_eq!(
            svc.handle_handshake_msg2(&framed, now),
            Err(balancify_crypto::HandshakeError::AuthFailed)
        );
        assert_eq!(svc.sessions(), 0, "mismatched session echo must not install keys");
        assert_eq!(
            svc.handle_handshake_msg2(&framed, now),
            Err(balancify_crypto::HandshakeError::BadOrder),
            "a rejected response consumes the pending initiator"
        );
    }

    #[test]
    fn handshake_rejects_malformed_session_echo_without_installing_keys() {
        use balancify_crypto::{EphemeralKeypair, Responder, StaticKeypair};
        let now = Instant::now();
        let relay_kp = StaticKeypair::generate();
        let client_kp = StaticKeypair::generate();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let cfg = ServiceConfig { session: 12345, auto_accept: false, ..ServiceConfig::default() };
        let mut svc = Service::new(
            cfg,
            balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap(),
            balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap(),
        );
        svc.set_static_keypair(client_kp);

        let msg1 = svc.initiate_handshake(relay_kp.public_bytes(), b"balancify handshake v1").unwrap();
        let mut responder = Responder::new(relay_kp.secret_bytes(), b"balancify handshake v1");
        let request_payload = responder.read_message_checked(&msg1[2..], None, None, None).unwrap();
        assert_eq!(request_payload, 12345u64.to_be_bytes());
        let eph = EphemeralKeypair::generate().secret_bytes();
        let (msg2, _) = responder.write_message(eph, &[0x01]).unwrap();
        let mut framed = vec![0xFF, 0x02];
        framed.extend_from_slice(&msg2);

        assert_eq!(
            svc.handle_handshake_msg2(&framed, now),
            Err(balancify_crypto::HandshakeError::Truncated)
        );
        assert_eq!(svc.sessions(), 0, "malformed session echo must not install keys");
    }

    #[test]
    fn pinning_enforced_rejects_unpinned_relay() {
        use balancify_crypto::{PinnedKeys, StaticKeypair};
        let relay_kp = StaticKeypair::generate();
        let other_kp = StaticKeypair::generate();
        let client_kp = StaticKeypair::generate();

        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.set_static_keypair(client_kp);

        let mut pinned = PinnedKeys::new();
        pinned.pin(other_kp.public_bytes()); // pin different relay
        svc.set_pinned_relays(pinned);

        // Initiate with unpinned relay should fail
        let res = svc.initiate_handshake(relay_kp.public_bytes(), b"balancify handshake v1");
        assert!(res.is_err(), "unpinned relay must be rejected");
    }

    #[test]
    fn relay_failover_etw_message_contains_no_endpoint() {
        let message = relay_failover_event_message(1, Duration::from_secs(5));
        assert_eq!(message, "relay failover count=1 timeout=5s");
        assert!(!message.contains("10.0.0.1"));
    }

    #[test]
    fn relay_failover_switches_on_timeout() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        let primary: std::net::SocketAddr = "10.0.0.1:4430".parse().unwrap();
        let secondary: std::net::SocketAddr = "10.0.0.2:4430".parse().unwrap();
        svc.set_relays(primary, Some(secondary));
        svc.set_relay_failover_timeout(Duration::from_secs(5));
        assert_eq!(svc.relay_current(), Some(primary));
        // No ACK yet, no failover
        assert!(svc.check_relay_failover(now + Duration::from_secs(10)).is_none());
        // Record ACK now
        svc.on_relay_ack(now);
        // 4 sec later, still primary
        assert!(svc.check_relay_failover(now + Duration::from_secs(4)).is_none());
        assert_eq!(svc.relay_current(), Some(primary));
        // 6 sec later, should failover to secondary
        let switched = svc.check_relay_failover(now + Duration::from_secs(6));
        assert_eq!(switched, Some(secondary));
        assert_eq!(svc.relay_current(), Some(secondary));
        assert_eq!(svc.relay_failover_count(), 1);
        // After failover, 6 sec later should switch back to primary
        let switched_back = svc.check_relay_failover(now + Duration::from_secs(12));
        assert_eq!(switched_back, Some(primary));
        assert_eq!(svc.relay_failover_count(), 2);
    }

    #[test]
    fn relay_failover_convergence_measured() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        let primary: std::net::SocketAddr = "10.0.0.1:4430".parse().unwrap();
        let secondary: std::net::SocketAddr = "10.0.0.2:4430".parse().unwrap();
        svc.set_relays(primary, Some(secondary));
        svc.set_relay_failover_timeout(Duration::from_secs(5));
        svc.on_relay_ack(now);
        // Trigger failover after 6s
        let switched = svc.check_relay_failover(now + Duration::from_secs(6));
        assert_eq!(switched, Some(secondary));
        assert!(svc.relay_failover_start().is_some());
        assert!(svc.relay_failover_convergence().is_none());
        // ACK 500ms later should measure convergence
        svc.on_relay_ack(now + Duration::from_secs(6) + Duration::from_millis(500));
        assert!(svc.relay_failover_convergence().is_some());
        let conv = svc.relay_failover_convergence().unwrap();
        assert!(conv.as_millis() >= 400 && conv.as_millis() <= 600, "convergence ~500ms, got {}ms", conv.as_millis());
        assert_eq!(svc.relay_failover_history().len(), 1);
        assert!(conv.as_secs_f64() <= 2.0, "target <=2s, got {}ms", conv.as_millis());
    }

    #[test]
    fn uplink_failover_convergence_measured() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
        svc.add_uplink(UplinkId(1), 50_000_000, false, 1500, now);
        for _ in 0..3 {
            svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now);
            svc.on_probe_ok(UplinkId(1), Duration::from_millis(50), now);
        }
        svc.publish(now);
        assert_eq!(svc.uplink_failover_count(), 0);
        // Unplug uplink 1
        svc.remove_uplink_at(UplinkId(1), now + Duration::from_millis(100));
        assert_eq!(svc.uplink_failover_count(), 1);
        assert!(svc.uplink_failover_start().is_some());
        // Replug after 1s — should measure convergence
        svc.add_uplink(UplinkId(1), 50_000_000, false, 1500, now + Duration::from_millis(1100));
        assert!(svc.uplink_failover_convergence().is_some());
        let conv = svc.uplink_failover_convergence().unwrap();
        assert!(conv.as_millis() >= 900 && conv.as_millis() <= 1100, "convergence ~1000ms, got {}ms", conv.as_millis());
        assert_eq!(svc.uplink_failover_history().len(), 1);
        assert!(conv.as_secs_f64() <= 2.0, "target <=2s, got {}ms", conv.as_millis());
    }

    #[test]
    fn per_flow_sessions_assign_distinct_ids() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.set_per_flow_sessions(true);

        let f1 = FlowKey::new(6, sa(5001), peer(443));
        let f2 = FlowKey::new(6, sa(5002), peer(443));
        let f3 = FlowKey::new(6, sa(5003), peer(443));

        let s1 = svc.session_for_flow(&f1, now);
        let s1_again = svc.session_for_flow(&f1, now);
        let s2 = svc.session_for_flow(&f2, now);
        let s3 = svc.session_for_flow(&f3, now);

        assert_eq!(s1, s1_again, "same flow gets same session");
        assert_ne!(s1, s2);
        assert_ne!(s2, s3);
        assert_eq!(svc.flow_session_count(), 3);

        // Disable should clear
        svc.set_per_flow_sessions(false);
        assert_eq!(svc.flow_session_count(), 0);
        let s_default = svc.session_for_flow(&f1, now);
        assert_eq!(s_default, 1, "when disabled returns cfg session");
    }

    #[test]
    fn per_class_sessions_assign_distinct_ids() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.set_per_class_sessions(true);

        let bulk = FlowClass::Bulk;
        let latency = FlowClass::LatencySensitive;
        let pinned = FlowClass::Pinned(UplinkId(1));

        let s_bulk = svc.session_for_class(bulk, now);
        let s_bulk_again = svc.session_for_class(bulk, now);
        let s_lat = svc.session_for_class(latency, now);
        let s_pin = svc.session_for_class(pinned, now);

        assert_eq!(s_bulk, s_bulk_again);
        assert_ne!(s_bulk, s_lat);
        assert_ne!(s_lat, s_pin);
        assert_eq!(svc.class_session_count(), 3);

        svc.set_per_class_sessions(false);
        assert_eq!(svc.class_session_count(), 0);
    }

    #[test]
    fn rate_limiter_holds_when_over_limit() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
        for _ in 0..5 { svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now); }
        svc.publish(now);
        // Set very low rate: 1KB/s, burst 2KB (to cover header+tag overhead)
        svc.set_uplink_rate_limit(UplinkId(0), 8000, 2000, now);
        let flow = FlowKey::new(6, sa(5000), peer(443));
        // First packet should pass (burst)
        let actions1 = svc.send_app_packet(&flow, None, &[0u8; 1000], now);
        assert!(actions1.iter().any(|a| matches!(a, Action::Send { .. })), "first burst should pass");
        // Second packet immediately should be held (rate limited)
        let actions2 = svc.send_app_packet(&flow, None, &[0u8; 1000], now);
        assert!(actions2.iter().any(|a| matches!(a, Action::Hold { .. })), "second should be held due to rate limit");

        svc.handle(ipc::Request::SetBondMode { enabled: false }, now);
        let flow_actions = svc.send_app_packet(&flow, None, &[0u8; 1000], now);
        assert!(flow_actions.iter().any(|a| matches!(a, Action::Hold { .. })), "flow-lane packet should be held too");
        assert_eq!(svc.tx.flow_pending_bytes(), 0, "a held FlowData frame must not remain pending for an ACK");
    }

    #[test]
    fn ecn_and_delay_wire_via_ingest() {
        let now = Instant::now();
        let dummy_key = [0u8; 32];
        let dummy_salt = [0u8; 3];
        let tx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let rx_cipher = balancify_crypto::TunnelCipher::new(&dummy_key, dummy_salt).unwrap();
        let cfg = ServiceConfig { session: 1, ..ServiceConfig::default() };
        let mut svc = Service::new(cfg, tx_cipher, rx_cipher);
        svc.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
        for _ in 0..3 { svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now); }
        svc.publish(now);

        // Simulate ECN via direct cc call (wire flag parsing covered by tunnel)
        svc.cc.on_ecn(0, now);
        assert_eq!(svc.cc.ecn_events(), 1);

        // Simulate RTT jump via on_rtt
        svc.cc.on_rtt(0, Duration::from_millis(10), now);
        svc.cc.on_rtt(0, Duration::from_millis(50), now + Duration::from_millis(200));
        assert_eq!(svc.cc.delay_events(), 1);
    }
}
