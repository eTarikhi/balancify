//! Balancify first-party datagram lane (blueprint Sec.6.4, Sec.4.8 rev 2).
//!
//! Carriage: UDP datagrams, never TCP (Sec.6.4 rule 4 -- no TCP-over-TCP).
//! Every tunnel packet carries (version, kind, path, flags, session, seq). The
//! receiving endpoint (in-binary server mode, Sec.4.7 T1) releases payloads in
//! order through a reorder buffer whose hold time is capped so one slow path
//! cannot stall a flow (Sec.6.4 rule 3).
//!
//! Frame kinds cover the control traffic Sec.6.5/Sec.6.6 require *inside* the tunnel:
//! authenticated health probes (not raw ICMP, so they survive CGNAT), per-path
//! NAT keepalives (<= 25 s), cumulative Data ACKs for reinjection, and
//! authenticated selective FlowAck frames that drive flow-level capacity
//! estimation (Sec.6.3) and bounded alternate-path repair for non-striped
//! FlowData packets.
//!
//! Crypto: the [`Crypto`] trait isolates the AEAD. Phase 2/3 tests use
//! [`PassThrough`], which is compiled **only** under `cfg(test)` or the
//! `lab-crypto` feature and is rejected by the CI policy audit in shipped
//! builds (ADR-0002). Phase 4 swaps in ChaCha20-Poly1305 under the Noise-style
//! handshake via a vetted vendored crate (Sec.4.8 policy rule c).
//!
//! # Sans-I/O
//! [`Sender`] and [`Receiver`] never touch a socket: they take datagrams and a
//! monotonic `now`, and return what to send. The I/O adapter (bound per-uplink
//! sockets now, our miniport in Phase 3) is a separate, thin layer (Sec.4.7.4).

use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

/// Wire format revision. Version 2 adds the selective FlowAck frame kind;
/// both ends must agree and mismatches are dropped rather than guessed at
/// (Sec.9.2 "message schema versioned and length-checked").
pub const WIRE_VERSION: u8 = 2;
/// version u8 + kind u8 + path u8 + flags u8 + session u64 + seq u64
pub const HEADER_LEN: usize = 20;

/// Sec.6.4 rule 5 duplicate mode: this frame is a copy sent on a second uplink.
pub const FLAG_DUPLICATE: u8 = 0x01;
/// Re-sent on another path after the reinjection RTO expired.
pub const FLAG_REINJECTED: u8 = 0x02;
/// ECN CE mark seen on outer packet (Sec.6.4 rule 4 ECN extension).
pub const FLAG_ECN_CE: u8 = 0x04;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameKind {
    /// Tunnel payload for the inner stack.
    Data,
    /// NAT keepalive (Sec.6.6); carries no payload.
    Keepalive,
    /// Health/capacity probe (Sec.6.5, Sec.6.3b); payload is probe padding.
    Probe,
    /// Echo of a probe, used for RTT.
    ProbeReply,
    /// Cumulative acknowledgement: `seq` is the highest contiguous seq seen.
    Ack,
    /// Flow-level lane: one packet of a flow that is *not* striped. It has a
    /// dedicated per-session sequence for nonce uniqueness and replay rejection,
    /// but is delivered immediately without cross-path reordering (Sec.6.2 vs
    /// Sec.6.4). Payload is the inner packet, forwarded as-is.
    FlowData,
    /// Selective acknowledgement for one frame in the independent FlowData lane.
    FlowAck,
}

impl FrameKind {
    pub const fn as_u8(self) -> u8 {
        match self {
            FrameKind::Data => 0,
            FrameKind::Keepalive => 1,
            FrameKind::Probe => 2,
            FrameKind::ProbeReply => 3,
            FrameKind::Ack => 4,
            FrameKind::FlowData => 5,
            FrameKind::FlowAck => 6,
        }
    }
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => FrameKind::Data,
            1 => FrameKind::Keepalive,
            2 => FrameKind::Probe,
            3 => FrameKind::ProbeReply,
            4 => FrameKind::Ack,
            5 => FrameKind::FlowData,
            6 => FrameKind::FlowAck,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub version: u8,
    pub kind: FrameKind,
    pub path: u8,
    pub flags: u8,
    pub session: u64,
    /// Data: packet sequence. Ack: highest contiguous seq. FlowAck: acknowledged
    /// FlowData sequence. Probe/ProbeReply: probe id (echoed). Keepalive: unused (0).
    pub seq: u64,
}

impl Header {
    pub fn new(kind: FrameKind, path: u8, session: u64, seq: u64) -> Self {
        Self { version: WIRE_VERSION, kind, path, flags: 0, session, seq }
    }
    pub fn with_flags(mut self, flags: u8) -> Self { self.flags = flags; self }

    pub fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.version);
        out.push(self.kind.as_u8());
        out.push(self.path);
        out.push(self.flags);
        out.extend_from_slice(&self.session.to_be_bytes());
        out.extend_from_slice(&self.seq.to_be_bytes());
    }

    pub fn decode(buf: &[u8]) -> Option<(Self, &[u8])> {
        if buf.len() < HEADER_LEN { return None; }
        let version = buf[0];
        if version != WIRE_VERSION { return None; }
        let kind = FrameKind::from_u8(buf[1])?;
        let session = u64::from_be_bytes(buf[4..12].try_into().ok()?);
        let seq = u64::from_be_bytes(buf[12..20].try_into().ok()?);
        Some((Self { version, kind, path: buf[2], flags: buf[3], session, seq }, &buf[HEADER_LEN..]))
    }
}

/// AEAD boundary (see module docs). Implementations must be thread-safe.
pub trait Crypto: Send + Sync {
    fn seal(&self, path: u8, seq: u64, aad: &[u8], plain: &[u8], out: &mut Vec<u8>);
    fn open(&self, path: u8, seq: u64, aad: &[u8], cipher: &[u8]) -> Option<Vec<u8>>;
    /// Optional one-way key derivation primitive. This does not coordinate a
    /// live peer update; callers must not activate the returned cipher until
    /// both endpoints have authenticated the same key epoch. Default returns None.
    fn rekey(&self) -> Option<Self>
    where
        Self: Sized,
    {
        None
    }
}

/// Test-only null cipher. MUST NOT ship: compiled only for tests / the
/// `lab-crypto` feature, and the CI policy audit fails a release build that
/// contains it (ADR-0002).
#[cfg(any(test, feature = "lab-crypto"))]
#[derive(Default, Clone, Copy, Debug, PartialEq, Eq)]
pub struct PassThrough;

#[cfg(any(test, feature = "lab-crypto"))]
impl Crypto for PassThrough {
    fn seal(&self, _p: u8, _s: u64, _aad: &[u8], plain: &[u8], out: &mut Vec<u8>) { out.extend_from_slice(plain); }
    fn open(&self, _p: u8, _s: u64, _aad: &[u8], cipher: &[u8]) -> Option<Vec<u8>> { Some(cipher.to_vec()) }
}

// ------------------------------------------------------------------ sender

#[derive(Debug, Clone)]
pub struct SenderConfig {
    /// Time after which an unacknowledged packet is reinjected on another path.
    /// Proposed 120 ms (tune against the measured delay gap, Sec.6.4 rule 3).
    pub rto: Duration,
    /// Retransmission window memory ceiling (proposed 4 MiB).
    pub max_retx_bytes: usize,
    /// A packet is reinjected at most this many times (proposed 1).
    pub max_reinjections: u8,
    /// One packet-sized unit charged to DRR per selection (proposed 1400 B).
    pub drr_unit: u64,
}

impl Default for SenderConfig {
    fn default() -> Self {
        Self {
            rto: Duration::from_millis(120),
            max_retx_bytes: 4 * 1024 * 1024,
            max_reinjections: 1,
            drr_unit: 1400,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct PathStats {
    pub sent: u64,
    pub acked: u64,
    /// Packets declared lost by the reinjection timer.
    pub lost: u64,
    pub reinjections: u64,
    pub probes: u64,
    pub rtt_ewma_ms: Option<f64>,
}

impl PathStats {
    pub fn rtt(&self) -> Option<Duration> { self.rtt_ewma_ms.map(Duration::from_secs_f64) }
    pub fn loss(&self) -> f64 {
        let total = self.sent + self.lost;
        if total == 0 { 0.0 } else { self.lost as f64 / total as f64 }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct SenderCounters {
    pub data_frames: u64,
    /// Packets sent on the flow-level (non-striped) lane.
    pub flow_packets: u64,
    pub duplicates: u64,
    pub reinjections: u64,
    pub keepalives: u64,
    pub probes: u64,
    pub bytes_sealed: u64,
    pub retx_evictions: u64,
    pub flow_ack_evictions: u64,
}

/// One emitted frame: what to write, and where.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sent {
    pub path: u8,
    pub seq: u64,
    pub session: u64,
    pub kind: FrameKind,
    pub bytes: Vec<u8>,
}

struct RetxEntry {
    plain: Vec<u8>,
    path: u8,
    sent_at: Instant,
    reinjections: u8,
}

struct FlowAckEntry {
    plain: Vec<u8>,
    path: u8,
    bytes: usize,
    sent_at: Instant,
    reinjections: u8,
}

/// Sender: numbers packets, selects the egress path per packet (Sec.6.4 rule 2),
/// keeps a bounded retransmission window and reinjects on loss (Sec.6.4 rule 5).
/// Retransmission is keyed by (session, seq) per Sec.4.7.4 ADR-0011.
pub struct Sender<C: Crypto> {
    pub session: u64,
    next_probe_id: u64,
    crypto: C,
    cfg: SenderConfig,
    drr: DeficitRoundRobin,
    retx: BTreeMap<(u64, u64), RetxEntry>, // (session, seq)
    retx_bytes: usize,
    /// Ordered Data sequence per session (Sec.4.7.4).
    session_seqs: BTreeMap<u64, u64>,
    /// FlowData uses an independent sequence lane so these packets cannot leave
    /// gaps in the ordered Data stream.
    flow_seqs: BTreeMap<u64, u64>,
    /// Bounded outstanding FlowData plaintext/retry state, retired by an
    /// authenticated selective FlowAck.
    flow_pending: BTreeMap<(u64, u64), FlowAckEntry>,
    flow_pending_bytes: usize,
    /// Keepalives also need fresh nonces despite carrying no application data.
    keepalive_seq: u64,
    /// Paths that just lost a packet, drained by the control plane.
    losses: Vec<u8>,
    stats: BTreeMap<u8, PathStats>,
    counters: SenderCounters,
}

impl<C: Crypto> Sender<C> {
    pub fn new(session: u64, crypto: C, paths: Vec<(u8, u64)>) -> Self {
        Self::with_config(session, crypto, paths, SenderConfig::default())
    }

    pub fn with_config(session: u64, crypto: C, paths: Vec<(u8, u64)>, cfg: SenderConfig) -> Self {
        let mut seqs = BTreeMap::new();
        seqs.insert(session, 0);
        let mut flow_seqs = BTreeMap::new();
        flow_seqs.insert(session, 0);
        Self {
            session,
            next_probe_id: 0,
            crypto,
            cfg,
            drr: DeficitRoundRobin::new(paths),
            retx: BTreeMap::new(),
            retx_bytes: 0,
            session_seqs: seqs,
            flow_seqs,
            flow_pending: BTreeMap::new(),
            flow_pending_bytes: 0,
            keepalive_seq: 0,
            losses: Vec::new(),
            stats: BTreeMap::new(),
            counters: SenderCounters::default(),
        }
    }

    fn next_seq_for(&mut self, session: u64) -> u64 {
        // Per-session ordered Data sequence (ADR-0011).
        let entry = self.session_seqs.entry(session).or_insert(0);
        let cur = *entry;
        *entry += 1;
        cur
    }

    fn next_flow_seq_for(&mut self, session: u64) -> u64 {
        let entry = self.flow_seqs.entry(session).or_insert(0);
        let cur = *entry;
        *entry += 1;
        cur
    }

    /// Update path quanta when the control plane republishes weights (Sec.6.1).
    pub fn set_quanta(&mut self, paths: Vec<(u8, u64)>) { self.drr = DeficitRoundRobin::new(paths); }
    pub fn paths(&self) -> Vec<u8> { self.drr.paths() }
    pub fn counters(&self) -> SenderCounters { self.counters }
    pub fn retx_bytes(&self) -> usize { self.retx_bytes }
    pub fn flow_pending_bytes(&self) -> usize { self.flow_pending_bytes }
    /// Paths on which a packet was just declared lost, drained. The control
    /// plane feeds these to the per-path congestion controller (Sec.6.4 rule 4).
    pub fn drain_losses(&mut self) -> Vec<u8> { std::mem::take(&mut self.losses) }

    /// Drop the retransmit state for one path and forget its statistics. Used
    /// when a NAT mapping moves: frames in flight through the old mapping are
    /// unreachable, and their RTO timers would only reinject into the void
    /// (Sec.6.6 "re-key path, keep session"). Returns the packets dropped.
    pub fn forget_path(&mut self, path: u8) -> u64 {
        let stale: Vec<(u64, u64)> = self
            .retx
            .iter()
            .filter(|(_, e)| e.path == path)
            .map(|(k, _)| *k)
            .collect();
        for k in &stale {
            if let Some(e) = self.retx.remove(k) {
                self.retx_bytes = self.retx_bytes.saturating_sub(e.plain.len());
            }
        }
        let stale_flow: Vec<(u64, u64)> = self
            .flow_pending
            .iter()
            .filter(|(_, entry)| entry.path == path)
            .map(|(key, _)| *key)
            .collect();
        for key in &stale_flow {
            if let Some(entry) = self.flow_pending.remove(key) {
                self.flow_pending_bytes = self.flow_pending_bytes.saturating_sub(entry.bytes);
            }
        }
        self.stats.remove(&path);
        (stale.len() + stale_flow.len()) as u64
    }

    /// Drop the whole retransmission and flow-ack windows. Sleep/resume
    /// invalidates every mapping at once (Sec.4.5).
    pub fn drop_retx(&mut self) -> u64 {
        let n = self.retx.len() + self.flow_pending.len();
        self.retx.clear();
        self.retx_bytes = 0;
        self.flow_pending.clear();
        self.flow_pending_bytes = 0;
        n as u64
    }
    pub fn in_flight(&self) -> usize { self.retx.len() }
    pub fn next_seq(&self) -> u64 {
        self.session_seqs.get(&self.session).copied().unwrap_or(0)
    }
    pub fn next_seq_for_session(&self, session: u64) -> u64 {
        self.session_seqs.get(&session).copied().unwrap_or(0)
    }
    pub fn path_stats(&self, path: u8) -> PathStats { self.stats.get(&path).copied().unwrap_or_default() }
    pub fn config(&self) -> &SenderConfig { &self.cfg }
    pub fn crypto(&self) -> &C { &self.crypto }

    /// Emit one Data frame for `plain`. `None` when no path can carry it --
    /// the caller then applies the fail-open/fail-closed default (D3).
    pub fn send(&mut self, plain: &[u8], now: Instant) -> Option<Sent> {
        self.send_excluding(plain, now, &[])
    }

    /// Like [`Sender::send`], but never picks a path the caller has blocked.
    /// The service blocks paths whose congestion window is full, so a congested
    /// uplink sheds load to the others instead of being overrun (Sec.6.4 rule 4).
    /// `None` when no path can carry the packet; the caller then holds it.
    pub fn send_excluding(&mut self, plain: &[u8], now: Instant, blocked: &[u8]) -> Option<Sent> {
        self.send_excluding_with_session(plain, self.session, now, blocked)
    }

    /// Sec.6.4 rule 5 duplicate mode: the same payload and seq on a second path.
    /// The receiver deduplicates by seq, so the copy is free at the inner stack
    /// and buys tail latency for small critical packets.
    /// Default session variant (backward compat).
    pub fn duplicate(&mut self, plain: &[u8], seq: u64, path: u8) -> Option<Sent> {
        self.duplicate_with_session(plain, self.session, seq, path)
    }

    pub fn duplicate_with_session(&mut self, plain: &[u8], session: u64, seq: u64, path: u8) -> Option<Sent> {
        if !self.paths().contains(&path) { return None; }
        let bytes = self.frame_with_session(FrameKind::Data, path, session, seq, FLAG_DUPLICATE, plain);
        self.counters.duplicates += 1;
        self.counters.bytes_sealed += bytes.len() as u64;
        self.stat(path).sent += 1;
        Some(Sent { path, seq, session, kind: FrameKind::Data, bytes })
    }

    /// Flow-level lane (Sec.6.2): send one packet of a non-striped flow on a
    /// specific uplink. It has a per-session FlowData sequence for nonce and
    /// replay safety, receives a selective FlowAck, and can be repaired on a
    /// different path after the retransmission timeout. It is never ordered
    /// with the striped Data lane.
    pub fn send_flow(&mut self, plain: &[u8], path: u8, now: Instant) -> Option<Sent> {
        self.send_flow_with_session(plain, path, self.session, now)
    }

    pub fn send_flow_with_session(&mut self, plain: &[u8], path: u8, session: u64, now: Instant) -> Option<Sent> {
        if !self.paths().contains(&path) { return None; }
        let seq = self.next_flow_seq_for(session);
        let bytes = self.frame_with_session(FrameKind::FlowData, path, session, seq, 0, plain);
        self.counters.flow_packets += 1;
        self.counters.bytes_sealed += bytes.len() as u64;
        self.stat(path).sent += 1;
        self.remember_flow_ack(session, seq, plain, path, now);
        Some(Sent { path, seq, session, kind: FrameKind::FlowData, bytes })
    }

    pub fn send_with_session(&mut self, plain: &[u8], session: u64, now: Instant) -> Option<Sent> {
        self.send_excluding_with_session(plain, session, now, &[])
    }

    pub fn send_excluding_with_session(&mut self, plain: &[u8], session: u64, now: Instant, blocked: &[u8]) -> Option<Sent> {
        let path = self.drr.next_filtered(plain.len().max(1) as u64, blocked)?;
        let seq = self.next_seq_for(session);
        let bytes = self.frame_with_session(FrameKind::Data, path, session, seq, 0, plain);
        self.counters.data_frames += 1;
        self.counters.bytes_sealed += bytes.len() as u64;
        self.stat(path).sent += 1;
        self.remember(session, seq, plain, path, now);
        Some(Sent { path, seq, session, kind: FrameKind::Data, bytes })
    }

    /// Per-path NAT keepalive (Sec.6.6). Uses its own nonce sequence, separate
    /// from ordered application Data.
    pub fn keepalive(&mut self, path: u8) -> Sent {
        let seq = self.keepalive_seq;
        self.keepalive_seq += 1;
        let bytes = self.frame(FrameKind::Keepalive, path, seq, 0, &[]);
        self.counters.keepalives += 1;
        Sent { path, seq, session: self.session, kind: FrameKind::Keepalive, bytes }
    }

    /// Health / capacity probe (Sec.6.5 probes are tunnel control messages;
    /// Sec.6.3b bounded idle probes). `pad` is the probe size the control plane
    /// granted from the probe budget.
    pub fn probe(&mut self, path: u8, pad: usize) -> Sent {
        let id = self.next_probe_id;
        self.next_probe_id += 1;
        let bytes = self.frame(FrameKind::Probe, path, id, 0, &vec![0u8; pad]);
        self.counters.probes += 1;
        self.stat(path).probes += 1;
        Sent { path, seq: id, session: self.session, kind: FrameKind::Probe, bytes }
    }

    /// Answer to a probe; the peer measures RTT from it.
    pub fn probe_reply(&self, path: u8, probe_id: u64) -> Sent {
        let bytes = self.frame(FrameKind::ProbeReply, path, probe_id, 0, &[]);
        Sent { path, seq: probe_id, session: self.session, kind: FrameKind::ProbeReply, bytes }
    }

    /// Cumulative ACK for everything up to and including `up_to` on default session.
    pub fn ack(&self, path: u8, up_to: u64) -> Sent {
        self.ack_with_flags(path, up_to, 0)
    }

    pub fn ack_with_flags(&self, path: u8, up_to: u64, flags: u8) -> Sent {
        self.ack_for_session(self.session, path, up_to, flags)
    }

    pub fn ack_for_session(&self, session: u64, path: u8, up_to: u64, flags: u8) -> Sent {
        let bytes = self.frame_with_session(FrameKind::Ack, path, session, up_to, flags, &[]);
        Sent { path, seq: up_to, session, kind: FrameKind::Ack, bytes }
    }

    pub fn flow_ack_for_session(&self, session: u64, path: u8, up_to: u64) -> Sent {
        let bytes = self.frame_with_session(FrameKind::FlowAck, path, session, up_to, 0, &[]);
        Sent { path, seq: up_to, session, kind: FrameKind::FlowAck, bytes }
    }

    pub fn ack_with_ecn(&self, path: u8, up_to: u64) -> Sent {
        self.ack_with_flags(path, up_to, FLAG_ECN_CE)
    }

    pub fn ack_with_ecn_for_session(&self, session: u64, path: u8, up_to: u64) -> Sent {
        self.ack_for_session(session, path, up_to, FLAG_ECN_CE)
    }

    /// Record a probe reply: RTT sample for this path (Sec.6.3).
    pub fn on_probe_reply(&mut self, path: u8, rtt: Duration, alpha: f64) {
        let s = self.stat(path);
        let next = rtt.as_secs_f64();
        s.rtt_ewma_ms = Some(match s.rtt_ewma_ms {
            Some(prev) => prev * (1.0 - alpha) + next * alpha,
            None => next,
        });
    }

    /// Record a cumulative ACK. Returns the newly acknowledged payload bytes
    /// grouped by the path that actually carried them.
    ///
    /// A connection-level cumulative ACK frees the send buffer no matter which
    /// path delivered it, but a capacity sample belongs to the path that
    /// carried the data -- RFC 8684 Sec.3.3 keeps subflow-level and
    /// connection-level acknowledgement separate for exactly this reason.
    /// Attributing the whole range to the path the ACK arrived on would inflate
    /// that path's estimate and starve the others of samples, which corrupts
    /// the DRR quanta (Sec.6.3a, Sec.6.4 rule 2).
    ///
    /// Now keyed by (session, seq) per ADR-0011.
    pub fn on_ack(&mut self, up_to: u64, _now: Instant) -> Vec<(u8, u64)> {
        self.on_ack_for_session(self.session, up_to, _now)
    }

    pub fn on_ack_for_session(&mut self, session: u64, up_to: u64, _now: Instant) -> Vec<(u8, u64)> {
        // Collect keys where session matches and seq <= up_to
        let keys: Vec<(u64, u64)> = self
            .retx
            .range((session, 0)..=(session, up_to))
            .map(|(k, _)| *k)
            .collect();
        let mut per_path: Vec<(u8, u64)> = Vec::new();
        for k in keys {
            let Some(entry) = self.retx.remove(&k) else { continue };
            self.retx_bytes = self.retx_bytes.saturating_sub(entry.plain.len());
            self.stat(entry.path).acked += 1;
            let bytes = entry.plain.len() as u64;
            match per_path.iter_mut().find(|(p, _)| *p == entry.path) {
                Some(slot) => slot.1 += bytes,
                None => per_path.push((entry.path, bytes)),
            }
        }
        per_path
    }

    /// Apply a selective FlowAck to the independent FlowData sequence lane.
    /// Returns the acknowledged payload bytes and original uplink for capacity
    /// accounting. Pending state is bounded independently of retransmission.
    pub fn on_flow_ack_for_session(&mut self, session: u64, up_to: u64) -> Vec<(u8, u64)> {
        let Some(entry) = self.flow_pending.remove(&(session, up_to)) else { return Vec::new() };
        self.flow_pending_bytes = self.flow_pending_bytes.saturating_sub(entry.bytes);
        vec![(entry.path, entry.bytes as u64)]
    }

    /// Forget accounting for a FlowData frame that the adapter ultimately did
    /// not transmit (for example, when the service rate limiter holds it).
    pub fn forget_flow_ack_for_session(&mut self, session: u64, seq: u64) {
        if let Some(entry) = self.flow_pending.remove(&(session, seq)) {
            self.flow_pending_bytes = self.flow_pending_bytes.saturating_sub(entry.bytes);
        }
    }

    /// Reinjection timer (Sec.6.4 rule 5): packets unacknowledged past the RTO are
    /// re-sent on a *different* path. Returns the frames to emit.
    pub fn reinjections_due(&mut self, now: Instant) -> Vec<Sent> {
        let rto = self.cfg.rto;
        let max_re = self.cfg.max_reinjections;
        let due: Vec<(u64, u64)> = self
            .retx
            .iter()
            .filter(|(_, e)| e.reinjections < max_re && now.duration_since(e.sent_at) >= rto)
            .map(|(k, _)| *k)
            .collect();

        let mut out = Vec::with_capacity(due.len());
        for (session, seq) in due {
            let (plain, old_path) = match self.retx.get(&(session, seq)) {
                Some(e) => (e.plain.clone(), e.path),
                None => continue,
            };
            let Some(new_path) = self.drr.next_excluding(old_path, plain.len().max(1) as u64) else {
                continue; // single-path session: reinjection would buy nothing
            };
            let bytes = self.frame_with_session(FrameKind::Data, new_path, session, seq, FLAG_REINJECTED, &plain);
            self.counters.reinjections += 1;
            self.counters.bytes_sealed += bytes.len() as u64;
            if let Some(e) = self.retx.get_mut(&(session, seq)) {
                e.path = new_path;
                e.sent_at = now;
                e.reinjections += 1;
            }
            self.stat(old_path).lost += 1;
            self.losses.push(old_path);
            let s = self.stat(new_path);
            s.reinjections += 1;
            s.sent += 1;
            out.push(Sent { path: new_path, seq, session, kind: FrameKind::Data, bytes });
        }
        out
    }

    /// Selectively repair unacknowledged FlowData packets on another active path.
    /// A duplicate is replay-detected by the receiver and re-ACKed without being
    /// delivered twice. FlowData retains its independent sequence space.
    pub fn flow_reinjections_due(&mut self, now: Instant) -> Vec<Sent> {
        let rto = self.cfg.rto;
        let max_re = self.cfg.max_reinjections;
        let due: Vec<(u64, u64)> = self
            .flow_pending
            .iter()
            .filter(|(_, entry)| {
                entry.reinjections < max_re && now.duration_since(entry.sent_at) >= rto
            })
            .map(|(key, _)| *key)
            .collect();

        let mut out = Vec::with_capacity(due.len());
        for (session, seq) in due {
            let (plain, old_path) = match self.flow_pending.get(&(session, seq)) {
                Some(entry) => (entry.plain.clone(), entry.path),
                None => continue,
            };
            let Some(new_path) = self.drr.next_excluding(old_path, plain.len().max(1) as u64) else {
                continue;
            };
            let bytes = self.frame_with_session(
                FrameKind::FlowData,
                new_path,
                session,
                seq,
                FLAG_REINJECTED,
                &plain,
            );
            self.counters.reinjections += 1;
            self.counters.bytes_sealed += bytes.len() as u64;
            if let Some(entry) = self.flow_pending.get_mut(&(session, seq)) {
                entry.path = new_path;
                entry.sent_at = now;
                entry.reinjections += 1;
            }
            self.stat(old_path).lost += 1;
            self.losses.push(old_path);
            let stats = self.stat(new_path);
            stats.reinjections += 1;
            stats.sent += 1;
            out.push(Sent {
                path: new_path,
                seq,
                session,
                kind: FrameKind::FlowData,
                bytes,
            });
        }
        out
    }

    fn remember(&mut self, session: u64, seq: u64, plain: &[u8], path: u8, now: Instant) {
        self.retx_bytes += plain.len();
        self.retx.insert(
            (session, seq),
            RetxEntry { plain: plain.to_vec(), path, sent_at: now, reinjections: 0 },
        );
        while self.retx_bytes > self.cfg.max_retx_bytes {
            let Some((_, oldest)) = self.retx.pop_first() else { break; };
            self.retx_bytes = self.retx_bytes.saturating_sub(oldest.plain.len());
            self.counters.retx_evictions += 1;
        }
    }

    fn remember_flow_ack(&mut self, session: u64, seq: u64, plain: &[u8], path: u8, now: Instant) {
        let bytes = plain.len();
        if bytes > self.cfg.max_retx_bytes { return; }
        self.flow_pending_bytes = self.flow_pending_bytes.saturating_add(bytes);
        self.flow_pending.insert((session, seq), FlowAckEntry {
            plain: plain.to_vec(),
            path,
            bytes,
            sent_at: now,
            reinjections: 0,
        });
        while self.flow_pending_bytes > self.cfg.max_retx_bytes
            || self.flow_pending.len() > MAX_PENDING_FLOW_ACKS
        {
            let Some((_, oldest)) = self.flow_pending.pop_first() else { break; };
            self.flow_pending_bytes = self.flow_pending_bytes.saturating_sub(oldest.bytes);
            self.counters.flow_ack_evictions += 1;
        }
    }

    fn frame(&self, kind: FrameKind, path: u8, seq: u64, flags: u8, plain: &[u8]) -> Vec<u8> {
        self.frame_with_session(kind, path, self.session, seq, flags, plain)
    }

    fn frame_with_session(&self, kind: FrameKind, path: u8, session: u64, seq: u64, flags: u8, plain: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + plain.len());
        Header::new(kind, path, session, seq).with_flags(flags).encode(&mut out);
        let header = out.clone();
        self.crypto.seal(path, seq, &header, plain, &mut out);
        out
    }

    fn stat(&mut self, path: u8) -> &mut PathStats {
        self.stats.entry(path).or_default()
    }
}

// --------------------------------------------------------------------- DRR

/// Deficit round robin with quanta proportional to estimated capacity (Sec.6.4 rule 2).
#[derive(Debug, Clone)]
pub struct DeficitRoundRobin {
    paths: Vec<(u8, u64)>, // (path id, quantum bytes/round)
    deficit: Vec<i64>,
    idx: usize,
}

impl DeficitRoundRobin {
    pub fn new(paths: Vec<(u8, u64)>) -> Self {
        // Every path starts with one quantum of credit. The scheduler credits on
        // arrival, so without this the first path in the list would wait a whole
        // lap for its first turn.
        let deficit = paths.iter().map(|(_, q)| *q as i64).collect();
        Self { paths, deficit, idx: 0 }
    }
    pub fn paths(&self) -> Vec<u8> { self.paths.iter().map(|(p, _)| *p).collect() }
    pub fn quanta(&self) -> &[(u8, u64)] { &self.paths }
    pub fn is_empty(&self) -> bool { self.paths.is_empty() }

    /// One packet-sized unit (1400 B proposed) is charged per selection.
    pub fn next(&mut self) -> Option<u8> { self.next_with_cost(1400) }
    pub fn next_with_cost(&mut self, cost: u64) -> Option<u8> { self.pick(cost, &[]) }
    /// Skip `exclude` (used by reinjection so the copy leaves on another path).
    pub fn next_excluding(&mut self, exclude: u8, cost: u64) -> Option<u8> {
        self.pick(cost, &[exclude])
    }
    /// Skip every path the caller has blocked -- e.g. the ones whose congestion
    /// window is full (Sec.6.4 rule 4).
    pub fn next_filtered(&mut self, cost: u64, blocked: &[u8]) -> Option<u8> {
        self.pick(cost, blocked)
    }

    fn pick(&mut self, cost: u64, blocked: &[u8]) -> Option<u8> {
        let n = self.paths.len();
        if n == 0 { return None; }
        let c = cost as i64;
        // Deficit round robin (blueprint Sec.6.4 rule 2): the quantum is credited
        // once per visit, and a path keeps its turn (and its credit) while that
        // credit can still pay for a packet -- so bytes sent stay proportional
        // to the quanta. Credit carries over, so a path whose quantum is
        // smaller than one packet is served once it has saved up; the cap at
        // quantum + one packet stops a path that has been idle from banking a
        // burst. The guard covers the degenerate case where no path can pay.
        let mut guard = 0;
        loop {
            guard += 1;
            if guard > 4 * n + 4 { return None; }
            let candidate = self.paths[self.idx].0;
            if !blocked.contains(&candidate) && self.deficit[self.idx] >= c {
                self.deficit[self.idx] -= c;
                return Some(candidate);
            }
            self.idx = (self.idx + 1) % n;
            let q = self.paths[self.idx].1 as i64;
            self.deficit[self.idx] += q;
            let cap = q + c;
            if self.deficit[self.idx] > cap { self.deficit[self.idx] = cap; }
        }
    }
}

// ----------------------------------------------------------- reorder buffer

/// Receiver reorder buffer (Sec.6.4 rule 3): releases in order; on hold-cap expiry
/// releases out-of-order and advances (inner TCP recovers; measured trade-off Sec.10.3).
pub struct ReorderBuffer {
    next_seq: u64,
    hold: BTreeMap<u64, Vec<u8>>,
    cap: Duration,
    stalled_at: Option<Instant>,
    pub released_out_of_order: u64,
}

impl ReorderBuffer {
    pub fn new(cap: Duration) -> Self {
        Self { next_seq: 0, hold: BTreeMap::new(), cap, stalled_at: None, released_out_of_order: 0 }
    }
    /// Insert a payload; false when it is a duplicate or too late to matter.
    pub fn push(&mut self, seq: u64, payload: Vec<u8>) -> bool {
        if seq < self.next_seq { return false; } // duplicate/late beyond window
        self.hold.insert(seq, payload).is_none()
    }
    /// Next sequence number the buffer is waiting for.
    pub fn next_expected(&self) -> u64 { self.next_seq }
    pub fn held(&self) -> usize { self.hold.len() }

    /// Release everything deliverable at `now`.
    pub fn pop_ready(&mut self, now: Instant) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        loop {
            if let Some(p) = self.hold.remove(&self.next_seq) {
                self.next_seq += 1;
                self.stalled_at = None;
                out.push(p);
                continue;
            }
            if self.hold.is_empty() { self.stalled_at = None; break; }
            let stalled = *self.stalled_at.get_or_insert(now);
            if now.duration_since(stalled) >= self.cap {
                // cap expiry: skip the gap, release what we have in seq order
                let (_, p) = self.hold.pop_first().expect("non-empty");
                self.released_out_of_order += 1;
                self.next_seq = self.hold.keys().next().copied().unwrap_or(self.next_seq + 1);
                out.push(p);
                self.stalled_at = None;
                continue;
            }
            break;
        }
        out
    }
}

/// Speculative duplication policy (Sec.6.4 rule 5): duplicate small critical packets.
pub fn should_duplicate(plain_len: usize, critical: bool, duplicate_mode: bool) -> bool {
    duplicate_mode && critical && plain_len <= 256
}

// ----------------------------------------------------------------- receiver

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    BadHeader,
    UnknownFrame,
    UnknownSession,
    SessionLimit,
    AuthFailed,
}

/// What the receiver wants the I/O adapter to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// In-order payload for the inner stack.
    Payload { session: u64, path: u8, data: Vec<u8> },
    /// Send a cumulative ACK for the ordered Data lane.
    Ack { session: u64, path: u8, seq: u64 },
    /// Send a selective ACK for one independent FlowData packet.
    FlowAck { session: u64, path: u8, seq: u64 },
    /// A probe arrived; echo it with [`Sender::probe_reply`].
    ProbeEcho { session: u64, path: u8, seq: u64 },
    Dropped { reason: DropReason },
}

const REPLAY_WINDOW: u64 = 1024;
const MAX_PENDING_FLOW_ACKS: usize = 4096;

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: BTreeSet<u64>,
}

impl ReplayWindow {
    fn accept(&mut self, seq: u64) -> bool {
        if self.highest.map_or(false, |highest| seq < highest.saturating_sub(REPLAY_WINDOW - 1))
            || !self.seen.insert(seq)
        {
            return false;
        }
        self.highest = Some(self.highest.map_or(seq, |highest| highest.max(seq)));
        if let Some(highest) = self.highest {
            let oldest = highest.saturating_sub(REPLAY_WINDOW - 1);
            self.seen.retain(|seen| *seen >= oldest);
        }
        true
    }
}

#[derive(Debug, Clone)]
pub struct ReceiverConfig {
    /// Reorder hold cap (Sec.6.4 rule 3: gap + 10 ms, hard cap proposed 80 ms).
    pub hold_cap: Duration,
    pub max_sessions: usize,
    pub idle_timeout: Duration,
    /// Lab/server-mode default: accept a session on its first packet. The
    /// Phase-4 handshake sets this false and opens sessions explicitly.
    pub auto_accept: bool,
}

impl Default for ReceiverConfig {
    fn default() -> Self {
        Self {
            hold_cap: Duration::from_millis(80),
            max_sessions: 64,
            idle_timeout: Duration::from_secs(120),
            auto_accept: true,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct ReceiverCounters {
    pub frames: u64,
    pub delivered: u64,
    pub out_of_order: u64,
    /// Redundant frames discarded: duplicate-mode copies (Sec.6.4 rule 5) and
    /// reinjected copies that lost the race with the original.
    pub duplicates: u64,
    pub auth_failed: u64,
    pub dropped: u64,
    pub keepalives: u64,
    pub probes: u64,
}

struct SessionState {
    buf: ReorderBuffer,
    last_acked: Option<u64>,
    reported_ooo: u64,
    flow_replay: ReplayWindow,
    control_replay: BTreeMap<u8, ReplayWindow>,
    last_peer_ack: Option<u64>,
    last_activity: Instant,
    /// Path the last frame for this session arrived on; used for the ACK and
    /// for cap-expiry releases that happen on a timer tick.
    last_path: u8,
}

/// Receiving endpoint: verifies, de-duplicates, reorders and releases payloads
/// in order, and reports the control actions the adapter must take.
pub struct Receiver<C: Crypto> {
    crypto: C,
    cfg: ReceiverConfig,
    sessions: BTreeMap<u64, SessionState>,
    counters: ReceiverCounters,
}

impl<C: Crypto> Receiver<C> {
    pub fn new(crypto: C, cfg: ReceiverConfig) -> Self {
        Self { crypto, cfg, sessions: BTreeMap::new(), counters: ReceiverCounters::default() }
    }
    pub fn with_defaults(crypto: C) -> Self { Self::new(crypto, ReceiverConfig::default()) }
    pub fn counters(&self) -> ReceiverCounters { self.counters }
    pub fn sessions(&self) -> usize { self.sessions.len() }

    /// Payloads held for reordering across every session. Exposed because it
    /// is the memory a peer can make us occupy (Sec.9.1 adversary (b)); the hold
    /// cap is what bounds it.
    pub fn held_packets(&self) -> usize { self.sessions.values().map(|s| s.buf.held()).sum() }
    pub fn config(&self) -> &ReceiverConfig { &self.cfg }
    pub fn crypto(&self) -> &C { &self.crypto }

    /// Open a session explicitly (production path once the handshake lands).
    pub fn open_session(&mut self, session: u64, now: Instant) -> bool {
        if self.sessions.len() >= self.cfg.max_sessions { return false; }
        self.sessions
            .entry(session)
            .or_insert_with(|| SessionState {
                buf: ReorderBuffer::new(self.cfg.hold_cap),
                last_acked: None,
                reported_ooo: 0,
                flow_replay: ReplayWindow::default(),
                control_replay: BTreeMap::new(),
                last_peer_ack: None,
                last_activity: now,
                last_path: 0,
            });
        true
    }

    fn check_session_admission(&mut self, session: u64) -> Result<(), DropReason> {
        if self.sessions.contains_key(&session) { return Ok(()); }
        let reason = if !self.cfg.auto_accept {
            DropReason::UnknownSession
        } else if self.sessions.len() >= self.cfg.max_sessions {
            DropReason::SessionLimit
        } else {
            return Ok(());
        };
        self.counters.dropped += 1;
        Err(reason)
    }

    fn accept_authenticated_session(&mut self, session: u64, now: Instant) {
        if !self.sessions.contains_key(&session) {
            let opened = self.open_session(session, now);
            debug_assert!(opened, "session admission was checked before authenticating");
        }
    }

    /// Authenticate a control datagram handled by a higher-level service path.
    /// The return value is `Ok(false)` for an authenticated replay; malformed,
    /// unknown-session, and unauthenticated frames return a drop reason.
    pub fn verify_control_frame(&mut self, dg: &[u8], now: Instant) -> Result<bool, DropReason> {
        let Some((hdr, body)) = Header::decode(dg) else {
            self.counters.dropped += 1;
            return Err(DropReason::BadHeader);
        };
        self.counters.frames += 1;
        self.authenticate_control(hdr, &dg[..HEADER_LEN], body, now)
    }

    /// Feed one tunnel datagram.
    pub fn ingest(&mut self, dg: &[u8], now: Instant) -> Vec<Event> {
        let Some((hdr, body)) = Header::decode(dg) else {
            self.counters.dropped += 1;
            return vec![Event::Dropped { reason: DropReason::BadHeader }];
        };
        self.counters.frames += 1;
        match hdr.kind {
            FrameKind::Keepalive | FrameKind::Ack | FrameKind::FlowAck | FrameKind::ProbeReply => {
                match self.authenticate_control(hdr, &dg[..HEADER_LEN], body, now) {
                    Ok(true) => {
                        if hdr.kind == FrameKind::Keepalive { self.counters.keepalives += 1; }
                        Vec::new()
                    }
                    Ok(false) => Vec::new(),
                    Err(reason) => vec![Event::Dropped { reason }],
                }
            }
            FrameKind::FlowData => self.ingest_flow_data(hdr, &dg[..HEADER_LEN], body, now),
            FrameKind::Probe => match self.authenticate_control(hdr, &dg[..HEADER_LEN], body, now) {
                Ok(true) => {
                    self.counters.probes += 1;
                    vec![Event::ProbeEcho { session: hdr.session, path: hdr.path, seq: hdr.seq }]
                }
                Ok(false) => Vec::new(),
                Err(reason) => vec![Event::Dropped { reason }],
            },
            FrameKind::Data => self.ingest_data(hdr, &dg[..HEADER_LEN], body, now),
        }
    }

    /// Timer tick (Sec.6.4 rule 3): release anything the hold cap has now let
    /// through, even if no new datagram arrived. Without this, a flow whose
    /// missing packet never comes back would stall until the peer sends again.
    pub fn drain(&mut self, now: Instant) -> Vec<Event> {
        let ids: Vec<(u64, u8)> = self.sessions.iter().map(|(id, s)| (*id, s.last_path)).collect();
        let mut out = Vec::new();
        for (session, path) in ids {
            out.extend(self.release(session, path, now));
        }
        out
    }

    /// Build the reply frame an [`Event`] asks for (Data ACK, FlowAck, probe
    /// echo), sealed with this endpoint's cipher. `None` for events that need no reply.
    pub fn reply_for(&self, ev: &Event) -> Option<Vec<u8>> {
        let (kind, session, path, seq) = match *ev {
            Event::Ack { session, path, seq } => (FrameKind::Ack, session, path, seq),
            Event::FlowAck { session, path, seq } => (FrameKind::FlowAck, session, path, seq),
            Event::ProbeEcho { session, path, seq } => (FrameKind::ProbeReply, session, path, seq),
            _ => return None,
        };
        let mut out = Vec::with_capacity(HEADER_LEN);
        Header::new(kind, path, session, seq).encode(&mut out);
        let header = out.clone();
        self.crypto.seal(path, seq, &header, &[], &mut out);
        Some(out)
    }

    /// Evict idle sessions; returns the evicted session ids.
    pub fn sweep(&mut self, now: Instant) -> Vec<u64> {
        let timeout = self.cfg.idle_timeout;
        let stale: Vec<u64> = self
            .sessions
            .iter()
            .filter(|(_, s)| now.duration_since(s.last_activity) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        for id in &stale { self.sessions.remove(id); }
        stale
    }

    fn authenticate_control(
        &mut self,
        hdr: Header,
        header_bytes: &[u8],
        body: &[u8],
        now: Instant,
    ) -> Result<bool, DropReason> {
        if !matches!(hdr.kind, FrameKind::Keepalive | FrameKind::Probe | FrameKind::ProbeReply | FrameKind::Ack | FrameKind::FlowAck) {
            self.counters.dropped += 1;
            return Err(DropReason::UnknownFrame);
        }
        self.check_session_admission(hdr.session)?;
        let Some(plain) = self.crypto.open(hdr.path, hdr.seq, header_bytes, body) else {
            self.counters.auth_failed += 1;
            self.counters.dropped += 1;
            return Err(DropReason::AuthFailed);
        };
        if hdr.kind != FrameKind::Probe && !plain.is_empty() {
            self.counters.dropped += 1;
            return Err(DropReason::UnknownFrame);
        }
        self.accept_authenticated_session(hdr.session, now);

        let state = self.sessions.get_mut(&hdr.session).expect("session ensured above");
        let accepted = match hdr.kind {
            FrameKind::Ack => {
                if state.last_peer_ack.map_or(false, |last| hdr.seq <= last) {
                    false
                } else {
                    state.last_peer_ack = Some(hdr.seq);
                    true
                }
            }
            _ => state.control_replay.entry(hdr.kind.as_u8()).or_default().accept(hdr.seq),
        };
        if !accepted {
            self.counters.duplicates += 1;
        } else {
            state.last_activity = now;
            state.last_path = hdr.path;
        }
        Ok(accepted)
    }

    fn ingest_flow_data(&mut self, hdr: Header, header_bytes: &[u8], body: &[u8], now: Instant) -> Vec<Event> {
        if let Err(reason) = self.check_session_admission(hdr.session) {
            return vec![Event::Dropped { reason }];
        }
        let Some(plain) = self.crypto.open(hdr.path, hdr.seq, header_bytes, body) else {
            self.counters.auth_failed += 1;
            self.counters.dropped += 1;
            return vec![Event::Dropped { reason: DropReason::AuthFailed }];
        };

        self.accept_authenticated_session(hdr.session, now);
        let state = self.sessions.get_mut(&hdr.session).expect("session accepted above");
        if !state.flow_replay.accept(hdr.seq) {
            self.counters.duplicates += 1;
            return vec![Event::FlowAck { session: hdr.session, path: hdr.path, seq: hdr.seq }];
        }
        state.last_activity = now;
        state.last_path = hdr.path;
        self.counters.delivered += 1;
        vec![
            Event::Payload { session: hdr.session, path: hdr.path, data: plain },
            Event::FlowAck { session: hdr.session, path: hdr.path, seq: hdr.seq },
        ]
    }

    fn ingest_data(&mut self, hdr: Header, header_bytes: &[u8], body: &[u8], now: Instant) -> Vec<Event> {
        if let Err(reason) = self.check_session_admission(hdr.session) {
            return vec![Event::Dropped { reason }];
        }
        // Verified before anything is buffered: an unauthentic frame must not
        // be able to occupy reorder-buffer memory (Sec.9.1 adversary (b)).
        let Some(plain) = self.crypto.open(hdr.path, hdr.seq, header_bytes, body) else {
            self.counters.auth_failed += 1;
            self.counters.dropped += 1;
            return vec![Event::Dropped { reason: DropReason::AuthFailed }];
        };

        self.accept_authenticated_session(hdr.session, now);
        {
            let state = self.sessions.get_mut(&hdr.session).expect("session accepted above");
            // A redundant copy is one whose seq we have already seen -- either
            // the duplicate-mode copy (Sec.6.4 rule 5) or a reinjected copy that
            // lost the race with the original. Count it once, when it is
            // discarded, so the counter means "redundant frames absorbed".
            // (Counting the flag as well would report every duplicate-mode
            // packet twice, once here and once in the reorder buffer.)
            if !state.buf.push(hdr.seq, plain) {
                self.counters.duplicates += 1;
                return Vec::new(); // duplicate of a held or already-delivered packet
            }
            state.last_activity = now;
            state.last_path = hdr.path;
        }
        self.release(hdr.session, hdr.path, now)
    }

    /// Release everything the reorder buffer can hand up, and ACK the new
    /// contiguous edge. Shared by [`Receiver::ingest`] and [`Receiver::drain`].
    fn release(&mut self, session: u64, path: u8, now: Instant) -> Vec<Event> {
        let mut out = Vec::new();
        let Some(state) = self.sessions.get_mut(&session) else { return out; };
        let ready = state.buf.pop_ready(now);
        out.reserve(ready.len() + 1);
        for data in ready {
            self.counters.delivered += 1;
            out.push(Event::Payload { session, path, data });
        }

        let ooo = state.buf.released_out_of_order;
        if ooo > state.reported_ooo {
            self.counters.out_of_order += ooo - state.reported_ooo;
            state.reported_ooo = ooo;
        }

        // Cumulative ACK: only when the contiguous edge actually moved.
        let expected = state.buf.next_expected();
        if expected > 0 {
            let ack_seq = expected - 1;
            if state.last_acked.map(|a| ack_seq > a).unwrap_or(true) {
                state.last_acked = Some(ack_seq);
                out.push(Event::Ack { session, path, seq: ack_seq });
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip_and_truncation() {
        let h = Header::new(FrameKind::Data, 3, 0x1122_3344_5566_7788, 42).with_flags(FLAG_DUPLICATE);
        let mut buf = Vec::new();
        h.encode(&mut buf);
        buf.extend_from_slice(b"payload");
        let (d, rest) = Header::decode(&buf).unwrap();
        assert_eq!(d, h);
        assert_eq!(rest, b"payload");
        assert_eq!(buf.len(), HEADER_LEN + 7);
        assert!(Header::decode(&buf[..HEADER_LEN - 1]).is_none(), "short header rejected");
    }

    #[test]
    fn header_rejects_bad_version_and_unknown_kind() {
        let mut buf = Vec::new();
        Header::new(FrameKind::Data, 0, 1, 0).encode(&mut buf);
        buf[0] = WIRE_VERSION + 1;
        assert!(Header::decode(&buf).is_none(), "unknown wire version must be dropped, not guessed");
        let mut legacy = Vec::new();
        Header::new(FrameKind::Data, 0, 1, 0).encode(&mut legacy);
        legacy[0] = 1;
        assert!(Header::decode(&legacy).is_none(), "wire v1 peers must not misinterpret FlowAck-enabled v2 sessions");
        let mut buf = Vec::new();
        Header::new(FrameKind::Data, 0, 1, 0).encode(&mut buf);
        buf[1] = 99;
        assert!(Header::decode(&buf).is_none());
    }

    #[test]
    fn every_frame_kind_roundtrips() {
        for kind in [FrameKind::Data, FrameKind::Keepalive, FrameKind::Probe, FrameKind::ProbeReply, FrameKind::Ack, FrameKind::FlowData, FrameKind::FlowAck] {
            let mut buf = Vec::new();
            Header::new(kind, 7, 9, 1234).encode(&mut buf);
            let (d, _) = Header::decode(&buf).unwrap();
            assert_eq!(d.kind, kind);
        }
    }

    #[test]
    fn drr_proportional_to_quanta() {
        let mut d = DeficitRoundRobin::new(vec![(0, 3000), (1, 1000)]);
        let mut c = [0u32; 2];
        for _ in 0..400 { c[d.next().unwrap() as usize] += 1; }
        let ratio = c[0] as f64 / c[1] as f64;
        assert!((2.7..3.3).contains(&ratio), "expected ~3:1, got {} ({:?})", ratio, c);
    }

    #[test]
    fn drr_exclusion_is_used_by_reinjection() {
        let mut d = DeficitRoundRobin::new(vec![(0, 1000), (1, 1000), (2, 1000)]);
        for _ in 0..20 {
            let p = d.next_excluding(1, 100).unwrap();
            assert_ne!(p, 1, "excluded path must never be chosen");
        }
        let mut only = DeficitRoundRobin::new(vec![(4, 1000)]);
        assert_eq!(only.next_excluding(4, 100), None, "nothing else to send on");
        let empty = DeficitRoundRobin::new(vec![]);
        assert!(empty.is_empty());
    }

    #[test]
    fn drr_does_not_hang_on_degenerate_quanta() {
        let mut d = DeficitRoundRobin::new(vec![(0, 0), (1, 0)]);
        assert_eq!(d.next_with_cost(1400), None, "zero quanta => no path, not a spin");
    }

    #[test]
    fn reorder_releases_in_order_and_waits() {
        let mut rb = ReorderBuffer::new(Duration::from_millis(80));
        let t0 = Instant::now();
        rb.push(1, b"one".to_vec());
        rb.push(0, b"zero".to_vec());
        let r = rb.pop_ready(t0);
        assert_eq!(r, vec![b"zero".to_vec(), b"one".to_vec()]);
        assert_eq!(rb.next_expected(), 2);
        // gap: seq 3 arrives before 2 -> held
        rb.push(3, b"three".to_vec());
        assert!(rb.pop_ready(t0).is_empty());
        assert_eq!(rb.held(), 1);
        rb.push(2, b"two".to_vec());
        let r = rb.pop_ready(t0);
        assert_eq!(r, vec![b"two".to_vec(), b"three".to_vec()]);
        assert_eq!(rb.released_out_of_order, 0);
    }

    #[test]
    fn reorder_cap_expiry_does_not_stall_flow() {
        let mut rb = ReorderBuffer::new(Duration::from_millis(40));
        let t0 = Instant::now();
        rb.push(1, b"one".to_vec());   // seq 0 lost
        rb.push(2, b"two".to_vec());
        assert!(rb.pop_ready(t0).is_empty());
        // Cap expiry skips the gap and releases the deliverable backlog in order.
        let r = rb.pop_ready(t0 + Duration::from_millis(45));
        assert_eq!(r, vec![b"one".to_vec(), b"two".to_vec()]);
        assert_eq!(rb.released_out_of_order, 1);
        assert!(rb.pop_ready(t0 + Duration::from_millis(46)).is_empty());
    }

    #[test]
    fn reorder_flags_duplicates() {
        let mut rb = ReorderBuffer::new(Duration::from_millis(40));
        let t0 = Instant::now();
        assert!(rb.push(0, b"a".to_vec()));
        assert!(!rb.push(0, b"a".to_vec()), "duplicate of a held packet");
        rb.pop_ready(t0);
        assert!(!rb.push(0, b"a".to_vec()), "duplicate of a delivered packet");
    }

    #[test]
    fn sender_numbers_and_spreads() {
        let mut s = Sender::new(7, PassThrough, vec![(0, 3000), (1, 1000)]);
        let t0 = Instant::now();
        let mut counts = [0u32; 2];
        let mut seqs = Vec::new();
        // MTU-scale payloads. DRR credits one quantum per visit and charges the
        // packet, so the split is only proportional when a quantum is at least
        // one packet wide -- which is what placement guarantees by flooring
        // quanta at TUNNEL_MTU (Sec.6.3).
        let payload = vec![7u8; 1400];
        for i in 0..20 {
            let sent = s.send(&payload, t0).expect("paths available");
            let (h, rest) = Header::decode(&sent.bytes).unwrap();
            assert_eq!(h.session, 7);
            assert_eq!(h.kind, FrameKind::Data);
            assert_eq!(h.path, sent.path);
            assert_eq!(h.seq, sent.seq);
            assert_eq!(rest, payload.as_slice());
            if i == 0 {
                assert_eq!(sent.path, 0, "the first path gets a turn first, not a full lap later");
            }
            seqs.push(h.seq);
            counts[sent.path as usize] += 1;
        }
        assert_eq!(seqs, (0..20).collect::<Vec<u64>>());
        // Quantum ratio 3000:1000 must show up in the packet split.
        assert_eq!(counts, [15, 5], "bytes sent stay proportional to the quanta");
        assert_eq!(s.in_flight(), 20);
    }

    #[test]
    fn drr_serves_a_path_whose_quantum_is_smaller_than_one_packet() {
        // A quantum below one packet must not starve the path: credit carries
        // over until it can pay.
        let mut drr = DeficitRoundRobin::new(vec![(0, 5000), (1, 600)]);
        let mut counts = [0u32; 2];
        for _ in 0..40 {
            let p = drr.next_with_cost(1400).expect("a path can always pay eventually");
            counts[p as usize] += 1;
        }
        assert!(counts[1] > 0, "the small-quantum path must be served: {counts:?}");
        assert!(counts[0] > counts[1], "and still in proportion: {counts:?}");
    }

    #[test]
    fn drr_cannot_bank_a_burst_after_being_idle() {
        // A path that has been skipped for a long time must not come back with
        // an unbounded deficit and take over the round.
        let mut drr = DeficitRoundRobin::new(vec![(0, 1400), (1, 1400)]);
        for _ in 0..1000 {
            // Only path 0 is eligible (path 1 excluded), so path 1 keeps being
            // visited and credited without ever sending.
            assert_eq!(drr.next_excluding(1, 1400), Some(0));
        }
        let mut counts = [0u32; 2];
        for _ in 0..20 {
            let p = drr.next_with_cost(1400).unwrap();
            counts[p as usize] += 1;
        }
        // Equal quanta share equally, up to DRR's one-packet slack: the capped
        // credit lets the returning path lead by a packet, not take the round.
        // Without the cap it would bank 1400 visits of credit and take all 20.
        let skew = counts[0] as i32 - counts[1] as i32;
        assert!(skew.abs() <= 2, "the returning path must not bank a burst: {counts:?}");
    }

    #[test]
    fn sender_without_paths_refuses_rather_than_panicking() {
        let mut s = Sender::new(1, PassThrough, vec![]);
        assert!(s.send(b"payload", Instant::now()).is_none(), "fail-closed: caller decides (D3)");
    }

    #[test]
    fn ack_frees_the_retx_window_and_reports_bytes() {
        let mut s = Sender::new(3, PassThrough, vec![(0, 1000)]);
        let t0 = Instant::now();
        for i in 0..5 { s.send(&vec![b'x'; 100], t0 + Duration::from_millis(i)).unwrap(); }
        assert_eq!(s.retx_bytes(), 500);
        let acked = s.on_ack(2, t0);
        assert_eq!(acked, vec![(0, 300)], "three packets of 100 B, credited to the path that sent them");
        assert_eq!(s.retx_bytes(), 200);
        assert_eq!(s.in_flight(), 2);
        assert_eq!(s.path_stats(0).acked, 3);
        assert_eq!(s.on_ack(2, t0), Vec::new(), "already-acked range reports nothing");
    }

    #[test]
    fn a_cumulative_ack_is_credited_to_the_paths_that_carried_the_data() {
        // Striping means one cumulative ACK covers packets that left on
        // several paths. Crediting the whole range to the path the ACK arrived
        // on would inflate that path's capacity estimate and starve the others
        // of samples (Sec.6.3a, RFC 8684 Sec.3.3), so the accounting is per path.
        let mut s = Sender::new(9, PassThrough, vec![(0, 250), (1, 150)]);
        let t0 = Instant::now();
        let mut carried = [0u64; 2];
        for _ in 0..8 {
            let sent = s.send(&vec![b'y'; 100], t0).unwrap();
            carried[sent.path as usize] += 100;
        }
        assert!(carried[0] > 0 && carried[1] > 0, "the test must actually stripe: {carried:?}");

        // The ACK happens to arrive on path 1. That must not decide anything.
        let mut acked = s.on_ack(7, t0);
        acked.sort();
        assert_eq!(acked, vec![(0, carried[0]), (1, carried[1])],
            "each path is credited with the bytes it carried");
        assert_eq!(s.path_stats(0).acked + s.path_stats(1).acked, 8);
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.retx_bytes(), 0);
    }

    #[test]
    fn forget_path_drops_only_that_paths_retransmit_state() {
        let mut s = Sender::new(11, PassThrough, vec![(0, 250), (1, 150)]);
        let t0 = Instant::now();
        for _ in 0..8 { s.send(&vec![b'z'; 100], t0).unwrap(); }
        assert_eq!(s.in_flight(), 8);

        let dropped = s.forget_path(1);
        assert!(dropped > 0, "the test must have striped onto path 1");
        let left = 8 - dropped as usize;
        assert_eq!(s.in_flight(), left);
        assert_eq!(s.retx_bytes(), left * 100, "the byte accounting follows the packets");
        assert_eq!(s.forget_path(1), 0, "nothing is left on that path");

        assert_eq!(s.drop_retx() as usize, left);
        assert_eq!(s.in_flight(), 0);
        assert_eq!(s.retx_bytes(), 0);
    }

    #[test]
    fn retx_window_is_bounded() {
        let cfg = SenderConfig { max_retx_bytes: 1000, ..SenderConfig::default() };
        let mut s = Sender::with_config(1, PassThrough, vec![(0, 1000)], cfg);
        let t0 = Instant::now();
        for _ in 0..50 { s.send(&vec![0u8; 100], t0).unwrap(); }
        assert!(s.retx_bytes() <= 1000, "window stays within its ceiling, got {}", s.retx_bytes());
        assert!(s.counters().retx_evictions > 0);
    }

    #[test]
    fn reinjection_moves_the_packet_to_another_path() {
        let cfg = SenderConfig { rto: Duration::from_millis(50), ..SenderConfig::default() };
        let mut s = Sender::with_config(9, PassThrough, vec![(0, 1000), (1, 1000)], cfg);
        let t0 = Instant::now();
        let first = s.send(b"critical".as_ref(), t0).unwrap();
        assert!(s.reinjections_due(t0 + Duration::from_millis(10)).is_empty(), "not yet due");
        let due = s.reinjections_due(t0 + Duration::from_millis(60));
        assert_eq!(due.len(), 1);
        let re = &due[0];
        assert_eq!(re.seq, first.seq);
        assert_ne!(re.path, first.path, "reinjection must leave on a different path");
        let (h, rest) = Header::decode(&re.bytes).unwrap();
        assert_eq!(h.flags & FLAG_REINJECTED, FLAG_REINJECTED);
        assert_eq!(rest, b"critical");
        assert_eq!(s.counters().reinjections, 1);
        assert_eq!(s.path_stats(first.path).lost, 1);
        // at most max_reinjections copies
        assert!(s.reinjections_due(t0 + Duration::from_millis(200)).is_empty());
    }

    #[test]
    fn duplicate_mode_reuses_the_sequence_number() {
        let mut s = Sender::new(2, PassThrough, vec![(0, 1000), (1, 1000)]);
        let t0 = Instant::now();
        let first = s.send(b"syn".as_ref(), t0).unwrap();
        let other = if first.path == 0 { 1 } else { 0 };
        let copy = s.duplicate(b"syn".as_ref(), first.seq, other).unwrap();
        assert_eq!(copy.seq, first.seq);
        assert_eq!(copy.path, other);
        let (h, _) = Header::decode(&copy.bytes).unwrap();
        assert_eq!(h.flags & FLAG_DUPLICATE, FLAG_DUPLICATE);
        assert_eq!(s.next_seq(), 1, "a duplicate consumes no new sequence number");
        assert!(s.duplicate(b"syn".as_ref(), first.seq, 9).is_none(), "unknown path");
    }

    #[test]
    fn control_frames_carry_no_data_sequence() {
        let mut s = Sender::new(5, PassThrough, vec![(0, 1000)]);
        let t0 = Instant::now();
        s.send(b"data".as_ref(), t0).unwrap();
        let k = s.keepalive(0);
        let k2 = s.keepalive(0);
        let p = s.probe(0, 64);
        let r = s.probe_reply(0, p.seq);
        let a = s.ack(0, 0);
        assert_ne!(k.seq, k2.seq, "successive keepalives must not reuse a nonce");
        for f in [&k, &k2, &p, &r, &a] {
            let (h, _) = Header::decode(&f.bytes).unwrap();
            assert_ne!(h.kind, FrameKind::Data);
        }
        assert_eq!(s.next_seq(), 1, "control traffic must not open gaps in the data stream");
        assert_eq!(s.counters().keepalives, 2);
        assert_eq!(s.counters().probes, 1);
        let (ph, pbody) = Header::decode(&p.bytes).unwrap();
        assert_eq!(ph.kind, FrameKind::Probe);
        assert_eq!(pbody.len(), 64, "probe padding is the granted probe size");
    }

    #[test]
    fn flow_data_has_a_nonce_sequence_without_gapping_data_and_rejects_replay() {
        let t0 = Instant::now();
        let mut tx = Sender::new(51, PassThrough, vec![(0, 1000)]);
        let flow0 = tx.send_flow(b"flow-0", 0, t0).unwrap();
        let flow1 = tx.send_flow(b"flow-1", 0, t0).unwrap();
        let data = tx.send(b"ordered", t0).unwrap();
        assert_eq!((flow0.seq, flow1.seq), (0, 1));
        assert_eq!(data.seq, 0, "FlowData does not create a missing Data sequence");

        let mut rx = Receiver::with_defaults(PassThrough);
        assert!(rx.ingest(&flow0.bytes, t0).iter().any(|e| matches!(e, Event::Payload { data, .. } if data.as_slice() == b"flow-0")));
        let replay_events = rx.ingest(&flow0.bytes, t0);
        assert!(!replay_events.iter().any(|e| matches!(e, Event::Payload { .. })), "a replay is not delivered twice");
        assert!(replay_events.iter().any(|e| matches!(e, Event::FlowAck { seq: 0, .. })), "a replay elicits the original selective FlowAck");
        assert!(rx.ingest(&flow1.bytes, t0).iter().any(|e| matches!(e, Event::Payload { data, .. } if data.as_slice() == b"flow-1")));
        assert!(rx.ingest(&data.bytes, t0).iter().any(|e| matches!(e, Event::Payload { data, .. } if data.as_slice() == b"ordered")));
        assert_eq!(rx.counters().duplicates, 1);

        let cfg = ReceiverConfig { idle_timeout: Duration::from_secs(60), ..ReceiverConfig::default() };
        let mut idle_rx = Receiver::new(PassThrough, cfg);
        idle_rx.ingest(&flow0.bytes, t0);
        idle_rx.ingest(&flow0.bytes, t0 + Duration::from_secs(30));
        assert_eq!(idle_rx.sweep(t0 + Duration::from_secs(61)), vec![51], "a replay cannot refresh session liveness");
    }

    #[test]
    fn flow_ack_is_selective_session_scoped_and_bounded() {
        let now = Instant::now();
        let cfg = SenderConfig { max_retx_bytes: 10, ..SenderConfig::default() };
        let mut tx = Sender::with_config(52, PassThrough, vec![(0, 1000), (1, 1000)], cfg);
        let a = tx.send_flow_with_session(b"a", 0, 52, now).unwrap();
        let b = tx.send_flow_with_session(b"bb", 1, 52, now).unwrap();
        let other_session = tx.send_flow_with_session(b"c", 0, 99, now).unwrap();
        assert_eq!(tx.flow_pending_bytes(), 4);
        let mut rx = Receiver::with_defaults(PassThrough);
        let mut control_rx = Receiver::with_defaults(PassThrough);
        control_rx.open_session(52, now);
        let out_of_order = rx.ingest(&b.bytes, now);
        let ack_b = out_of_order.into_iter().find(|ev| matches!(ev, Event::FlowAck { seq: 1, .. })).expect("independent FlowData packet can be acked immediately");
        let ack_b_bytes = rx.reply_for(&ack_b).expect("FlowAck reply encoded");
        let (ack_b_header, _) = Header::decode(&ack_b_bytes).expect("valid reply frame");
        assert_eq!(ack_b_header.kind, FrameKind::FlowAck);
        assert_eq!(control_rx.verify_control_frame(&ack_b_bytes, now), Ok(true));
        assert_eq!(tx.on_flow_ack_for_session(ack_b_header.session, ack_b_header.seq), vec![(1, 2)]);

        let events = rx.ingest(&a.bytes, now);
        let ack_a = events.into_iter().find(|ev| matches!(ev, Event::FlowAck { seq: 0, .. })).expect("second packet acknowledged independently");
        let ack_a_bytes = rx.reply_for(&ack_a).expect("FlowAck reply encoded");
        let (ack_a_header, _) = Header::decode(&ack_a_bytes).expect("valid reply frame");
        assert_eq!(control_rx.verify_control_frame(&ack_a_bytes, now), Ok(true));
        assert_eq!(tx.on_flow_ack_for_session(ack_a_header.session, ack_a_header.seq), vec![(0, 1)]);
        assert_eq!(tx.flow_pending_bytes(), 1, "an ACK in session 52 cannot release session 99 state");
        assert_eq!(tx.on_flow_ack_for_session(99, other_session.seq), vec![(0, 1)]);
        assert_eq!(tx.flow_pending_bytes(), 0);
        assert_eq!(control_rx.verify_control_frame(&ack_a_bytes, now), Ok(false), "FlowAck replay is rejected");

        let bounded_cfg = SenderConfig { max_retx_bytes: 2, ..SenderConfig::default() };
        let mut bounded = Sender::with_config(53, PassThrough, vec![(0, 1000)], bounded_cfg);
        for _ in 0..5 { let _ = bounded.send_flow(b"x", 0, now); }
        assert!(bounded.flow_pending_bytes() <= 2);
        assert!(bounded.flow_pending.len() <= 4096);
        assert!(bounded.counters().flow_ack_evictions > 0);
    }

    #[test]
    fn unacked_flow_data_is_reinjected_and_duplicate_is_reacked_once() {
        let t0 = Instant::now();
        let cfg = SenderConfig {
            rto: Duration::from_millis(10),
            max_reinjections: 1,
            ..SenderConfig::default()
        };
        let mut tx = Sender::with_config(61, PassThrough, vec![(0, 1000), (1, 1000)], cfg);
        let original = tx.send_flow(b"repair me", 0, t0).unwrap();
        assert!(tx.flow_reinjections_due(t0 + Duration::from_millis(9)).is_empty());

        let due = tx.flow_reinjections_due(t0 + Duration::from_millis(10));
        assert_eq!(due.len(), 1);
        let repaired = &due[0];
        assert_eq!(repaired.kind, FrameKind::FlowData);
        assert_eq!(repaired.path, 1, "repair must leave on a different path");
        assert_eq!((repaired.session, repaired.seq), (original.session, original.seq));
        let (header, body) = Header::decode(&repaired.bytes).unwrap();
        assert_eq!(header.flags & FLAG_REINJECTED, FLAG_REINJECTED);
        assert_eq!(body, b"repair me");
        assert_eq!(tx.flow_pending_bytes(), b"repair me".len());
        assert_eq!(tx.drain_losses(), vec![0]);
        assert!(tx.flow_reinjections_due(t0 + Duration::from_millis(20)).is_empty());

        let mut rx = Receiver::with_defaults(PassThrough);
        let initial = rx.ingest(&original.bytes, t0);
        assert!(initial.iter().any(|event| matches!(event, Event::Payload { data, .. } if data.as_slice() == b"repair me")));
        let duplicate = rx.ingest(&repaired.bytes, t0 + Duration::from_millis(10));
        assert!(!duplicate.iter().any(|event| matches!(event, Event::Payload { .. })), "repair must not duplicate delivery");
        let ack = duplicate.iter().find(|event| matches!(event, Event::FlowAck { .. })).expect("duplicate repair is re-ACKed");
        let ack_bytes = rx.reply_for(ack).expect("FlowAck response is encoded");
        let (ack_header, _) = Header::decode(&ack_bytes).unwrap();
        assert_eq!(tx.on_flow_ack_for_session(ack_header.session, ack_header.seq), vec![(1, 9)]);
        assert_eq!(tx.flow_pending_bytes(), 0);
        assert_eq!(tx.counters().reinjections, 1);
    }

    #[test]
    fn control_frames_require_authentication_and_reject_replay() {
        struct RejectAll;
        impl Crypto for RejectAll {
            fn seal(&self, _path: u8, _seq: u64, _aad: &[u8], plain: &[u8], out: &mut Vec<u8>) {
                out.extend_from_slice(plain);
            }
            fn open(&self, _path: u8, _seq: u64, _aad: &[u8], _cipher: &[u8]) -> Option<Vec<u8>> { None }
        }

        let now = Instant::now();
        let mut tx = Sender::new(17, PassThrough, vec![(0, 1000)]);
        let ack = tx.ack(0, 12);
        let mut rx = Receiver::with_defaults(PassThrough);
        assert_eq!(rx.verify_control_frame(&ack.bytes, now), Ok(true));
        assert_eq!(rx.verify_control_frame(&ack.bytes, now), Ok(false), "an authenticated ACK replay is ignored");
        let newer_ack = tx.ack(0, 13);
        assert_eq!(rx.verify_control_frame(&newer_ack.bytes, now), Ok(true));
        assert_eq!(rx.verify_control_frame(&ack.bytes, now), Ok(false), "a stale cumulative ACK is ignored");
        assert_eq!(rx.counters().duplicates, 2);

        let mut strict = Receiver::with_defaults(RejectAll);
        assert_eq!(strict.verify_control_frame(&ack.bytes, now), Err(DropReason::AuthFailed));
        assert_eq!(strict.counters().auth_failed, 1);

        let flow_ack = tx.flow_ack_for_session(17, 0, 8);
        let mut strict_flow_ack = Receiver::with_defaults(RejectAll);
        assert_eq!(strict_flow_ack.verify_control_frame(&flow_ack.bytes, now), Err(DropReason::AuthFailed));
        assert_eq!(strict_flow_ack.sessions(), 0, "an unauthenticated FlowAck cannot allocate a session");

        let probe = tx.probe(0, 24);
        let mut rx = Receiver::with_defaults(PassThrough);
        assert!(rx.ingest(&probe.bytes, now).iter().any(|event| matches!(event, Event::ProbeEcho { .. })));
        assert!(rx.ingest(&probe.bytes, now).is_empty(), "a replayed probe cannot cause another response");
        let mut strict = Receiver::with_defaults(RejectAll);
        assert_eq!(strict.ingest(&probe.bytes, now), vec![Event::Dropped { reason: DropReason::AuthFailed }]);
    }

    #[test]
    fn probe_reply_feeds_path_rtt() {
        let mut s = Sender::new(5, PassThrough, vec![(0, 1000)]);
        s.on_probe_reply(0, Duration::from_millis(20), 0.5);
        s.on_probe_reply(0, Duration::from_millis(40), 0.5);
        let rtt = s.path_stats(0).rtt().unwrap();
        assert!(rtt > Duration::from_millis(25) && rtt < Duration::from_millis(35), "ewma ~30 ms, got {rtt:?}");
    }

    #[test]
    fn receiver_delivers_in_order_and_acks_progress() {
        let mut s = Sender::new(11, PassThrough, vec![(0, 1000), (1, 1000)]);
        let mut rx = Receiver::with_defaults(PassThrough);
        let t0 = Instant::now();
        let mut wire: Vec<Sent> = (0..10).map(|i| s.send(format!("m{i}").as_bytes(), t0).unwrap()).collect();
        // deliver 1..9 first, then 0: nothing may be released before seq 0
        wire.sort_by_key(|f| if f.seq == 0 { 99 } else { f.seq });
        let mut got = Vec::new();
        let mut last_ack = None;
        for f in &wire {
            for ev in rx.ingest(&f.bytes, t0) {
                match ev {
                    Event::Payload { data, .. } => got.push(String::from_utf8(data).unwrap()),
                    Event::Ack { seq, .. } => last_ack = Some(seq),
                    other => panic!("unexpected {other:?}"),
                }
            }
        }
        assert_eq!(got, (0..10).map(|i| format!("m{i}")).collect::<Vec<_>>());
        assert_eq!(last_ack, Some(9));
        assert_eq!(rx.counters().delivered, 10);
        assert_eq!(rx.counters().out_of_order, 0);
    }

    #[test]
    fn receiver_deduplicates_a_double_sent_packet() {
        let mut s = Sender::new(12, PassThrough, vec![(0, 1000), (1, 1000)]);
        let mut rx = Receiver::with_defaults(PassThrough);
        let t0 = Instant::now();
        let f = s.send(b"syn".as_ref(), t0).unwrap();
        let copy = s.duplicate(b"syn".as_ref(), f.seq, 1 - f.path).unwrap();
        let mut got = Vec::new();
        for frame in [&f.bytes, &copy.bytes] {
            for ev in rx.ingest(frame, t0) {
                if let Event::Payload { data, .. } = ev { got.push(data); }
            }
        }
        assert_eq!(got, vec![b"syn".to_vec()], "the inner stack sees the packet once");
        assert!(rx.counters().duplicates > 0);
        assert_eq!(rx.counters().delivered, 1);
    }

    #[test]
    fn receiver_echoes_probes_and_counts_keepalives() {
        let mut s = Sender::new(13, PassThrough, vec![(0, 1000)]);
        let mut rx = Receiver::with_defaults(PassThrough);
        let t0 = Instant::now();
        let probe = s.probe(0, 32);
        let events = rx.ingest(&probe.bytes, t0);
        assert_eq!(events, vec![Event::ProbeEcho { session: 13, path: 0, seq: probe.seq }]);
        let reply = s.probe_reply(0, probe.seq);
        assert!(rx.ingest(&reply.bytes, t0).is_empty(), "the sender handles its own replies");
        let k = s.keepalive(0);
        assert!(rx.ingest(&k.bytes, t0).is_empty());
        assert_eq!(rx.counters().probes, 1);
        assert_eq!(rx.counters().keepalives, 1);
    }

    #[test]
    fn replies_are_decodable_by_the_peer() {
        let mut s = Sender::new(51, PassThrough, vec![(0, 1000)]);
        let mut rx = Receiver::with_defaults(PassThrough);
        let t0 = Instant::now();
        let f = s.send(b"hello".as_ref(), t0).unwrap();
        let events = rx.ingest(&f.bytes, t0);
        let replies: Vec<Vec<u8>> = events.iter().filter_map(|e| rx.reply_for(e)).collect();
        assert_eq!(replies.len(), 1);
        let (h, _) = Header::decode(&replies[0]).unwrap();
        assert_eq!(h.kind, FrameKind::Ack);
        assert_eq!(h.session, 51);
        assert_eq!(h.seq, 0);
        assert_eq!(s.on_ack(h.seq, t0), vec![(h.path, 5)], "five payload bytes acknowledged");
        assert_eq!(s.in_flight(), 0);

        let probe = s.probe(0, 16);
        let echoed: Vec<Vec<u8>> = rx.ingest(&probe.bytes, t0).iter().filter_map(|e| rx.reply_for(e)).collect();
        let (ph, _) = Header::decode(&echoed[0]).unwrap();
        assert_eq!(ph.kind, FrameKind::ProbeReply);
        assert_eq!(ph.seq, probe.seq);
    }

    #[test]
    fn receiver_rejects_garbage_and_tampered_frames() {
        /// Cipher that fails to open anything (stands in for a bad AEAD tag).
        struct RejectAll;
        impl Crypto for RejectAll {
            fn seal(&self, _p: u8, _s: u64, _aad: &[u8], plain: &[u8], out: &mut Vec<u8>) { out.extend_from_slice(plain); }
            fn open(&self, _p: u8, _s: u64, _aad: &[u8], _c: &[u8]) -> Option<Vec<u8>> { None }
        }

        let mut rx = Receiver::with_defaults(PassThrough);
        let t0 = Instant::now();
        assert_eq!(rx.ingest(b"short", t0), vec![Event::Dropped { reason: DropReason::BadHeader }]);
        assert_eq!(rx.ingest(&[0u8; 4], t0), vec![Event::Dropped { reason: DropReason::BadHeader }]);

        let mut s = Sender::new(21, PassThrough, vec![(0, 1000)]);
        let f = s.send(b"payload".as_ref(), t0).unwrap();
        let mut strict = Receiver::with_defaults(RejectAll);
        assert_eq!(strict.ingest(&f.bytes, t0), vec![Event::Dropped { reason: DropReason::AuthFailed }]);
        assert_eq!(strict.counters().auth_failed, 1);
        assert_eq!(strict.counters().delivered, 0, "unauthentic data never reaches the inner stack");
        assert_eq!(strict.sessions(), 0, "an unauthenticated frame cannot allocate a session");
    }

    #[test]
    fn receiver_refuses_unknown_sessions_when_not_auto_accepting() {
        let mut s = Sender::new(31, PassThrough, vec![(0, 1000)]);
        let t0 = Instant::now();
        let f = s.send(b"x".as_ref(), t0).unwrap();
        let flow = s.send_flow(b"flow", 0, t0).unwrap();

        let cfg = ReceiverConfig { auto_accept: false, ..ReceiverConfig::default() };
        let mut rx = Receiver::new(PassThrough, cfg);
        assert_eq!(rx.ingest(&f.bytes, t0), vec![Event::Dropped { reason: DropReason::UnknownSession }]);
        assert_eq!(rx.ingest(&flow.bytes, t0), vec![Event::Dropped { reason: DropReason::UnknownSession }]);
        assert!(rx.open_session(31, t0));
        let events = rx.ingest(&f.bytes, t0);
        assert!(events.iter().any(|e| matches!(e, Event::Payload { .. })));
        let flow_events = rx.ingest(&flow.bytes, t0);
        assert!(flow_events.iter().any(|e| matches!(e, Event::Payload { data, .. } if data.as_slice() == b"flow")));
    }

    #[test]
    fn receiver_caps_session_count() {
        let cfg = ReceiverConfig { max_sessions: 2, ..ReceiverConfig::default() };
        let mut rx = Receiver::new(PassThrough, cfg);
        let t0 = Instant::now();
        for session in [1u64, 2, 3] {
            let mut s = Sender::new(session, PassThrough, vec![(0, 1000)]);
            let f = s.send(b"x".as_ref(), t0).unwrap();
            let events = rx.ingest(&f.bytes, t0);
            if session == 3 {
                assert_eq!(events, vec![Event::Dropped { reason: DropReason::SessionLimit }]);
            }
        }
        assert_eq!(rx.sessions(), 2);
    }

    #[test]
    fn receiver_evicts_idle_sessions() {
        let cfg = ReceiverConfig { idle_timeout: Duration::from_secs(60), ..ReceiverConfig::default() };
        let mut rx = Receiver::new(PassThrough, cfg);
        let t0 = Instant::now();
        let mut s = Sender::new(41, PassThrough, vec![(0, 1000)]);
        let f = s.send(b"x".as_ref(), t0).unwrap();
        rx.ingest(&f.bytes, t0);
        assert_eq!(rx.sessions(), 1);
        assert!(rx.sweep(t0 + Duration::from_secs(30)).is_empty());
        assert_eq!(rx.sweep(t0 + Duration::from_secs(61)), vec![41]);
        assert_eq!(rx.sessions(), 0);
    }

    #[test]
    fn drain_releases_a_gap_the_peer_never_filled() {
        let cfg = ReceiverConfig { hold_cap: Duration::from_millis(40), ..ReceiverConfig::default() };
        let mut rx = Receiver::new(PassThrough, cfg);
        let mut s = Sender::new(61, PassThrough, vec![(0, 1000), (1, 1000)]);
        let t0 = Instant::now();
        let all: Vec<Sent> = (0..3).map(|i| s.send(format!("d{i}").as_bytes(), t0).unwrap()).collect();
        for f in all.iter().skip(1) {
            // seq 0 is lost for good: nothing may be delivered yet
            assert!(!rx.ingest(&f.bytes, t0).iter().any(|e| matches!(e, Event::Payload { .. })));
        }
        assert_eq!(rx.counters().delivered, 0);
        assert!(rx.drain(t0 + Duration::from_millis(10)).is_empty(), "inside the hold cap");
        // No further datagram ever arrives: only the timer tick can unstick it.
        let released = rx.drain(t0 + Duration::from_millis(45));
        let payloads: Vec<Vec<u8>> = released
            .iter()
            .filter_map(|e| match e { Event::Payload { data, .. } => Some(data.clone()), _ => None })
            .collect();
        assert_eq!(payloads, vec![b"d1".to_vec(), b"d2".to_vec()]);
        assert_eq!(rx.counters().out_of_order, 1, "the skipped gap is counted, not hidden");
        assert!(released.iter().any(|e| matches!(e, Event::Ack { .. })), "the peer must learn the new edge");
    }

    #[test]
    fn duplicate_policy_rules() {
        assert!(should_duplicate(64, true, true));
        assert!(!should_duplicate(1000, true, true), "large packets never duplicated");
        assert!(!should_duplicate(64, false, true));
        assert!(!should_duplicate(64, true, false), "mode off");
    }
}
