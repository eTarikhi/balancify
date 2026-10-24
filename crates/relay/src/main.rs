//! Balancify in-binary cooperating endpoint ("server mode"), blueprint Sec.4.7.

use balancify_tunnel::{Crypto, Event, Receiver, ReceiverConfig, Sender, SenderConfig};
use std::collections::BTreeMap;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

pub struct Endpoint<C: Crypto> {
    rx: Receiver<C>,
    delivered: u64,
    pinned_clients: balancify_crypto::PinnedKeys,
    replay_cache: balancify_crypto::ReplayCache,
}

impl<C: Crypto> Endpoint<C> {
    pub fn new(crypto: C, cfg: ReceiverConfig) -> Self {
        Self {
            rx: Receiver::new(crypto, cfg),
            delivered: 0,
            pinned_clients: balancify_crypto::PinnedKeys::new(),
            replay_cache: balancify_crypto::ReplayCache::with_defaults(),
        }
    }
    pub fn set_pinned_clients(&mut self, pinned: balancify_crypto::PinnedKeys)
    where C: Clone,
    {
        self.pinned_clients = pinned;
        if !self.pinned_clients.is_empty() {
            let cfg = ReceiverConfig {
                hold_cap: self.rx.config().hold_cap,
                idle_timeout: self.rx.config().idle_timeout,
                auto_accept: false,
                max_sessions: self.rx.config().max_sessions,
            };
            let crypto = self.rx.crypto().clone();
            self.rx = Receiver::new(crypto, cfg);
        }
    }
    pub fn set_pinned_clients_no_clone(&mut self, pinned: balancify_crypto::PinnedKeys) {
        self.pinned_clients = pinned;
    }
    pub fn pinned_clients(&self) -> &balancify_crypto::PinnedKeys { &self.pinned_clients }
    pub fn replay_cache(&self) -> &balancify_crypto::ReplayCache { &self.replay_cache }
    pub fn replay_cache_mut(&mut self) -> &mut balancify_crypto::ReplayCache { &mut self.replay_cache }
    pub fn open_session(&mut self, session: u64, now: Instant) -> bool { self.rx.open_session(session, now) }
    pub fn is_peer_allowed(&self, peer_static: &[u8; 32]) -> bool {
        if self.pinned_clients.is_empty() { true } else { self.pinned_clients.is_pinned(peer_static) }
    }
    pub fn ingest(&mut self, dg: &[u8], now: Instant) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut payloads = Vec::new();
        let mut replies = Vec::new();
        for ev in self.rx.ingest(dg, now) {
            match ev {
                Event::Payload { data, .. } => { self.delivered += 1; payloads.push(data); }
                other => { if let Some(frame) = self.rx.reply_for(&other) { replies.push(frame); } }
            }
        }
        (payloads, replies)
    }
    pub fn drain(&mut self, now: Instant) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut payloads = Vec::new();
        let mut replies = Vec::new();
        for ev in self.rx.drain(now) {
            match ev {
                Event::Payload { data, .. } => { self.delivered += 1; payloads.push(data); }
                other => { if let Some(frame) = self.rx.reply_for(&other) { replies.push(frame); } }
            }
        }
        (payloads, replies)
    }
    pub fn delivered(&self) -> u64 { self.delivered }
    pub fn out_of_order_releases(&self) -> u64 { self.rx.counters().out_of_order }
    pub fn duplicates_seen(&self) -> u64 { self.rx.counters().duplicates }
    pub fn sessions(&self) -> usize { self.rx.sessions() }
    pub fn sweep(&mut self, now: Instant) -> Vec<u64> { self.rx.sweep(now) }
    pub fn counters(&self) -> balancify_tunnel::ReceiverCounters { self.rx.counters() }
}

impl Endpoint<balancify_crypto::TunnelCipher> {
    pub fn apply_transport_keys(&mut self, keys: &balancify_crypto::TransportKeys, now: Instant) {
        if let Some(rx_cipher) = keys.recv_cipher() {
            let cfg = self.rx.config().clone();
            let auto_accept = cfg.auto_accept;
            self.rx = Receiver::new(rx_cipher, cfg);
            if !auto_accept { self.rx.open_session(1, now); }
        }
    }
    pub fn establish_secure_session(
        &mut self,
        keys: &balancify_crypto::TransportKeys,
        peer_static: [u8; 32],
        now: Instant,
    ) -> Result<(), balancify_crypto::HandshakeError> {
        if !self.is_peer_allowed(&peer_static) {
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        self.apply_transport_keys(keys, now);
        Ok(())
    }
}

const HANDSHAKE_VERSION: u8 = 0xFF;
const HANDSHAKE_MSG1: u8 = 0x01;
const HANDSHAKE_MSG2: u8 = 0x02;
const PROLOGUE: &[u8] = b"balancify handshake v1";
const MAX_TRACKED_HANDSHAKE_IPS: usize = 4096;
const GLOBAL_HANDSHAKE_BURST: f64 = 200.0;
const GLOBAL_HANDSHAKE_RATE_PER_SECOND: f64 = 100.0;

fn default_state_dir() -> std::path::PathBuf {
    #[cfg(windows)]
    {
        std::env::var_os("ProgramData")
            .map(|path| std::path::PathBuf::from(path).join("Balancify"))
            .unwrap_or_else(|| std::path::PathBuf::from("/tmp/balancify"))
    }
    #[cfg(not(windows))]
    {
        std::path::PathBuf::from("/tmp/balancify")
    }
}

fn resolve_state_dir(
    configured: Option<std::ffi::OsString>,
    default: std::path::PathBuf,
) -> std::io::Result<std::path::PathBuf> {
    match configured {
        Some(path) if !path.is_empty() => Ok(path.into()),
        Some(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "BALANCIFY_STATE_DIR must not be empty",
        )),
        None => Ok(default),
    }
}

fn load_pinned_clients(
    store: &impl balancify_crypto::KeyStore,
) -> std::io::Result<balancify_crypto::PinnedKeys> {
    store.load_pinned().map_err(|error| {
        std::io::Error::other(format!("failed to load pinned client identities: {error}"))
    })
}

fn create_forward_socket(upstream: std::net::SocketAddr) -> std::io::Result<UdpSocket> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.set_read_timeout(Some(Duration::from_millis(10)))?;
    socket.connect(upstream)?;
    Ok(socket)
}

fn forward_socket_for_session(
    forward_socks: &BTreeMap<u64, UdpSocket>,
    session_id: u64,
) -> Option<&UdpSocket> {
    forward_socks.get(&session_id)
}

fn sweep_due(last_sweep: &mut Instant, now: Instant, interval: Duration) -> bool {
    if now.duration_since(*last_sweep) < interval {
        return false;
    }
    *last_sweep = now;
    true
}

fn failure_log_due(last_failure_log: &mut Option<Instant>, now: Instant, interval: Duration) -> bool {
    if last_failure_log.is_some_and(|last| now.duration_since(last) < interval) {
        return false;
    }
    *last_failure_log = Some(now);
    true
}

fn parse_listen_ports(value: Option<&str>) -> std::io::Result<Vec<u16>> {
    let Some(value) = value else { return Ok(vec![4430, 4431]); };
    if value.trim().is_empty() {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "listen port list must not be empty"));
    }
    let mut ports = Vec::new();
    for raw_port in value.split(',') {
        let raw_port = raw_port.trim();
        if raw_port.is_empty() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "listen port list contains an empty entry"));
        }
        let port = raw_port.parse::<u16>().map_err(|error| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("invalid listen port '{raw_port}': {error}"))
        })?;
        if ports.contains(&port) {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("duplicate listen port: {port}")));
        }
        ports.push(port);
    }
    Ok(ports)
}

fn parse_listen_args(args: &[String]) -> std::io::Result<Vec<u16>> {
    if args.len() > 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "expected one comma-separated listen-port argument",
        ));
    }
    parse_listen_ports(args.first().map(String::as_str))
}

fn parse_forward_addr(
    setting: Result<String, std::env::VarError>,
) -> std::io::Result<Option<std::net::SocketAddr>> {
    match setting {
        Ok(value) => {
            let address = value.parse::<std::net::SocketAddr>().map_err(|error| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("invalid BALANCIFY_FORWARD_ADDR '{value}': {error}"),
                )
            })?;
            if address.port() == 0 || address.ip().is_unspecified() {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "BALANCIFY_FORWARD_ADDR must use a nonzero port and a specified IP address",
                ));
            }
            Ok(Some(address))
        },
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(error) => Err(std::io::Error::other(format!("invalid BALANCIFY_FORWARD_ADDR setting: {error}"))),
    }
}

struct RateLimiter {
    /// Token bucket: tokens in bytes, refill rate bytes/sec
    tokens: u64,
    max_tokens: u64,
    refill_rate: u64,
    last_refill: Instant,
    /// Packet rate limit: packets per second
    packet_tokens: u64,
    max_packet_tokens: u64,
    packet_refill_rate: u64,
}

impl RateLimiter {
    fn new(max_bytes_per_sec: u64, max_pps: u64, now: Instant) -> Self {
        Self {
            tokens: max_bytes_per_sec,
            max_tokens: max_bytes_per_sec,
            refill_rate: max_bytes_per_sec,
            last_refill: now,
            packet_tokens: max_pps,
            max_packet_tokens: max_pps,
            packet_refill_rate: max_pps,
        }
    }
    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        if elapsed <= 0.0 {
            return;
        }
        let add_bytes = (elapsed * self.refill_rate as f64) as u64;
        self.tokens = (self.tokens + add_bytes).min(self.max_tokens);
        let add_pkts = (elapsed * self.packet_refill_rate as f64) as u64;
        self.packet_tokens = (self.packet_tokens + add_pkts).min(self.max_packet_tokens);
        self.last_refill = now;
    }
    fn try_consume(&mut self, bytes: usize, now: Instant) -> bool {
        self.refill(now);
        if self.tokens < bytes as u64 || self.packet_tokens == 0 {
            return false;
        }
        self.tokens -= bytes as u64;
        self.packet_tokens -= 1;
        true
    }
}

struct RelaySession {
    id: u64,
    peer_static: [u8; 32],
    peer_addr: std::net::SocketAddr,
    rx: Receiver<balancify_crypto::TunnelCipher>,
    tx: Sender<balancify_crypto::TunnelCipher>,
    last_activity: Instant,
    bytes_forwarded: u64,
    packets_forwarded: u64,
    ecn_echoed: u64,
    rate_limiter: RateLimiter,
    created_at: Instant,
}

impl RelaySession {
    fn new(
        id: u64,
        peer_static: [u8; 32],
        peer_addr: std::net::SocketAddr,
        recv_cipher: balancify_crypto::TunnelCipher,
        send_cipher: balancify_crypto::TunnelCipher,
        now: Instant,
    ) -> Self {
        let rx_cfg = ReceiverConfig {
            hold_cap: Duration::from_millis(80),
            idle_timeout: Duration::from_secs(120),
            auto_accept: false,
            max_sessions: 64,
        };
        let tx_cfg = SenderConfig::default();
        let mut rx = Receiver::new(recv_cipher, rx_cfg);
        rx.open_session(id, now);
        let tx = Sender::with_config(id, send_cipher, vec![(0, 2000), (1, 2000)], tx_cfg);
        // Default limits: 100 Mbit/s, 10k pps per session (Sec.4.4 B4 rate-limited)
        let rate_limiter = RateLimiter::new(12_500_000, 10_000, now);
        Self {
            id,
            peer_static,
            peer_addr,
            rx,
            tx,
            last_activity: now,
            bytes_forwarded: 0,
            packets_forwarded: 0,
            ecn_echoed: 0,
            rate_limiter,
            created_at: now,
        }
    }
    fn ingest(&mut self, dg: &[u8], now: Instant) -> (Vec<Vec<u8>>, Vec<Vec<u8>>, bool) {
        let before = self.rx.counters();
        let mut payloads = Vec::new();
        let mut replies = Vec::new();
        let simulate_ecn = std::env::var("BALANCIFY_SIMULATE_ECN").map(|v| v == "1").unwrap_or(false);
        for ev in self.rx.ingest(dg, now) {
            match ev {
                Event::Payload { data, .. } => payloads.push(data),
                Event::Ack { session, path, seq } => {
                    if simulate_ecn { self.ecn_echoed += 1; }
                    let flags = if simulate_ecn { balancify_tunnel::FLAG_ECN_CE } else { 0 };
                    replies.push(self.tx.ack_for_session(session, path, seq, flags).bytes);
                }
                Event::FlowAck { session, path, seq } => {
                    replies.push(self.tx.flow_ack_for_session(session, path, seq).bytes);
                }
                Event::ProbeEcho { path, seq, .. } => {
                    let sent = self.tx.probe_reply(path, seq);
                    replies.push(sent.bytes);
                }
                _ => {}
            }
        }
        let after = self.rx.counters();
        let authenticated = after.frames > before.frames
            && after.dropped == before.dropped
            && after.duplicates == before.duplicates;
        if authenticated {
            self.last_activity = now;
        }
        (payloads, replies, authenticated)
    }
    fn drain(&mut self, now: Instant) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
        let mut payloads = Vec::new();
        let mut replies = Vec::new();
        let simulate_ecn = std::env::var("BALANCIFY_SIMULATE_ECN").map(|v| v == "1").unwrap_or(false);
        for ev in self.rx.drain(now) {
            match ev {
                Event::Payload { data, .. } => payloads.push(data),
                Event::Ack { session, path, seq } => {
                    if simulate_ecn { self.ecn_echoed += 1; }
                    let flags = if simulate_ecn { balancify_tunnel::FLAG_ECN_CE } else { 0 };
                    replies.push(self.tx.ack_for_session(session, path, seq, flags).bytes);
                }
                Event::FlowAck { session, path, seq } => {
                    replies.push(self.tx.flow_ack_for_session(session, path, seq).bytes);
                }
                Event::ProbeEcho { path, seq, .. } => {
                    let sent = self.tx.probe_reply(path, seq);
                    replies.push(sent.bytes);
                }
                _ => {}
            }
        }
        (payloads, replies)
    }
}

/// Smooth global handshake admission limits protect crypto work from spoofed-IP churn.
struct HandshakeLimiter {
    tokens: f64,
    last_refill: Instant,
}

impl HandshakeLimiter {
    fn new(now: Instant) -> Self {
        Self { tokens: GLOBAL_HANDSHAKE_BURST, last_refill: now }
    }

    fn try_consume(&mut self, now: Instant) -> bool {
        let elapsed = now.saturating_duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * GLOBAL_HANDSHAKE_RATE_PER_SECOND)
            .min(GLOBAL_HANDSHAKE_BURST);
        self.last_refill = now;
        if self.tokens < 1.0 {
            return false;
        }
        self.tokens -= 1.0;
        true
    }
}

struct SecureRelay {
    static_keypair: balancify_crypto::StaticKeypair,
    pinned_clients: balancify_crypto::PinnedKeys,
    replay_cache: balancify_crypto::ReplayCache,
    sessions: BTreeMap<u64, RelaySession>,
    prologue: Vec<u8>,
    // Abuse controls (Sec.4.4 B4, Sec.9.1)
    max_sessions: usize,
    max_sessions_per_ip: usize,
    handshake_attempts: BTreeMap<std::net::IpAddr, (u64, Instant)>, // ip -> (count, window_start)
    global_handshake_limiter: HandshakeLimiter,
    total_bytes_forwarded: u64,
    total_packets_forwarded: u64,
    total_handshakes: u64,
    total_rejected: u64,
    total_ecn_echoed: u64,
}

impl SecureRelay {
    fn new(static_keypair: balancify_crypto::StaticKeypair, pinned_clients: balancify_crypto::PinnedKeys) -> Self {
        Self {
            static_keypair,
            pinned_clients,
            replay_cache: balancify_crypto::ReplayCache::with_defaults(),
            sessions: BTreeMap::new(),
            prologue: PROLOGUE.to_vec(),
            max_sessions: 1024,
            max_sessions_per_ip: 8,
            handshake_attempts: BTreeMap::new(),
            global_handshake_limiter: HandshakeLimiter::new(Instant::now()),
            total_bytes_forwarded: 0,
            total_packets_forwarded: 0,
            total_handshakes: 0,
            total_rejected: 0,
            total_ecn_echoed: 0,
        }
    }
    fn is_peer_allowed(&self, peer_static: &[u8; 32]) -> bool {
        if self.pinned_clients.is_empty() { true } else { self.pinned_clients.is_pinned(peer_static) }
    }
    fn check_rate_limit_handshake(&mut self, peer: std::net::SocketAddr, now: Instant) -> bool {
        let ip = peer.ip();
        let window = Duration::from_secs(60);
        let max_per_window = 10; // 10 handshakes per minute per IP
        if !self.handshake_attempts.contains_key(&ip)
            && self.handshake_attempts.len() >= MAX_TRACKED_HANDSHAKE_IPS
        {
            // Bound state under source-address churn; evict the oldest window entry.
            if let Some(oldest_ip) = self.handshake_attempts.iter()
                .min_by_key(|(_, (_, window_start))| *window_start)
                .map(|(tracked_ip, _)| *tracked_ip)
            {
                self.handshake_attempts.remove(&oldest_ip);
            }
        }
        let entry = self.handshake_attempts.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= window {
            *entry = (1, now);
            true
        } else if entry.0 >= max_per_window {
            false
        } else {
            entry.0 += 1;
            true
        }
    }
    fn sessions_for_ip(&self, ip: std::net::IpAddr) -> usize {
        self.sessions.values().filter(|s| s.peer_addr.ip() == ip).count()
    }
    fn remove_session(&mut self, id: u64) -> bool {
        if let Some(session) = self.sessions.remove(&id) {
            self.total_ecn_echoed += session.ecn_echoed;
            true
        } else {
            false
        }
    }
    fn handle_msg1(
        &mut self,
        msg1: &[u8],
        peer: std::net::SocketAddr,
        now: Instant,
    ) -> Result<(Vec<u8>, u64), balancify_crypto::HandshakeError> {
        // Abuse: global session cap
        if self.sessions.len() >= self.max_sessions {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        // Abuse: per-IP session cap
        if self.sessions_for_ip(peer.ip()) >= self.max_sessions_per_ip {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        // Cheap per-IP admission first so one over-quota source cannot drain the global bucket.
        if !self.check_rate_limit_handshake(peer, now) {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        // Bound aggregate unauthenticated crypto work even when source IPs are spoofed.
        if !self.global_handshake_limiter.try_consume(now) {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        let mut responder = balancify_crypto::Responder::new(self.static_keypair.secret_bytes(), &self.prologue);
        let payload = match responder.read_message_checked(
            msg1,
            Some(&self.pinned_clients),
            Some(&mut self.replay_cache),
            Some(now),
        ) {
            Ok(payload) => payload,
            Err(error) => {
                self.total_rejected += 1;
                return Err(error);
            }
        };
        if payload.len() != std::mem::size_of::<u64>() {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::Truncated);
        }
        let session_id = u64::from_be_bytes(payload[..8].try_into().unwrap());
        let peer_static = match responder.peer_static() {
            Some(peer_static) => peer_static,
            None => {
                self.total_rejected += 1;
                return Err(balancify_crypto::HandshakeError::AuthFailed);
            }
        };
        if !self.is_peer_allowed(&peer_static) {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        if self.sessions.contains_key(&session_id) {
            self.total_rejected += 1;
            return Err(balancify_crypto::HandshakeError::AuthFailed);
        }
        let eph = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
        let resp_payload = session_id.to_be_bytes().to_vec();
        let (msg2, transport_keys) = match responder.write_message(eph, &resp_payload) {
            Ok(result) => result,
            Err(error) => {
                self.total_rejected += 1;
                return Err(error);
            }
        };
        let recv_cipher = match transport_keys.recv_cipher() {
            Some(cipher) => cipher,
            None => {
                self.total_rejected += 1;
                return Err(balancify_crypto::HandshakeError::AuthFailed);
            }
        };
        let send_cipher = match transport_keys.send_cipher() {
            Some(cipher) => cipher,
            None => {
                self.total_rejected += 1;
                return Err(balancify_crypto::HandshakeError::AuthFailed);
            }
        };
        let session = RelaySession::new(session_id, peer_static, peer, recv_cipher, send_cipher, now);
        self.sessions.insert(session_id, session);
        self.total_handshakes += 1;
        Ok((msg2, session_id))
    }
    fn ingest_tunnel(
        &mut self,
        dg: &[u8],
        peer: std::net::SocketAddr,
        now: Instant,
    ) -> Option<(Vec<Vec<u8>>, Vec<Vec<u8>>, bool)> {
        let Some((hdr, _)) = balancify_tunnel::Header::decode(dg) else {
            self.total_rejected += 1;
            return None;
        };
        let session_id = hdr.session;
        // Rate limiting per session
        let Some(session) = self.sessions.get_mut(&session_id) else {
            self.total_rejected += 1;
            return None;
        };
        if !session.rate_limiter.try_consume(dg.len(), now) {
            // Drop frame if over limit -- counts as abuse, but don't kill session
            self.total_rejected += 1;
            return Some((Vec::new(), Vec::new(), false));
        }
        let (payloads, replies, authenticated) = session.ingest(dg, now);
        if authenticated {
            // Only an authenticated, non-replayed frame may move the peer mapping.
            session.peer_addr = peer;
        }
        // Account forwarded bytes
        for p in &payloads {
            session.bytes_forwarded += p.len() as u64;
            session.packets_forwarded += 1;
            self.total_bytes_forwarded += p.len() as u64;
            self.total_packets_forwarded += 1;
        }
        if !authenticated {
            self.total_rejected += 1;
        }
        Some((payloads, replies, authenticated))
    }
    fn drain_all(&mut self, now: Instant) -> Vec<(u64, Vec<Vec<u8>>, Vec<Vec<u8>>)> {
        let mut out = Vec::new();
        for (id, sess) in self.sessions.iter_mut() {
            let (p, r) = sess.drain(now);
            if !p.is_empty() || !r.is_empty() { out.push((*id, p, r)); }
        }
        out
    }
    fn sweep(&mut self, now: Instant) -> Vec<u64> {
        let idle_timeout = Duration::from_secs(120);
        let stale: Vec<u64> = self.sessions.iter()
            .filter(|(_, s)| now.duration_since(s.last_activity) >= idle_timeout)
            .map(|(id, _)| *id).collect();
        for id in &stale {
            self.remove_session(*id);
        }
        // Sweep old handshake attempt entries
        let window = Duration::from_secs(60);
        self.handshake_attempts.retain(|_, (_, start)| now.duration_since(*start) < window * 2);
        stale
    }
    fn stats(&self) -> (usize, u64, u64, u64, u64, u64) {
        let ecn_sum: u64 = self.sessions.values().map(|s| s.ecn_echoed).sum::<u64>() + self.total_ecn_echoed;
        (
            self.sessions.len(),
            self.total_handshakes,
            self.total_rejected,
            self.total_bytes_forwarded,
            self.total_packets_forwarded,
            ecn_sum,
        )
    }
}

fn main() -> std::io::Result<()> { run() }

#[cfg(feature = "lab-crypto")]
fn run() -> std::io::Result<()> {
    use balancify_tunnel::PassThrough;
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(|s| s == "secure").unwrap_or(false) {
        return run_secure(args.into_iter().skip(1).collect());
    }
    let ports = parse_listen_args(&args)?;
    let sockets: Vec<UdpSocket> = ports.iter().map(|p| UdpSocket::bind(("0.0.0.0", *p))).collect::<Result<_, _>>()?;
    for s in &sockets { s.set_read_timeout(Some(Duration::from_millis(100)))?; }
    eprintln!("balancify-relay (lab form; lab-crypto = NO CONFIDENTIALITY): listening on UDP {:?}", ports);
    let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
    let mut dg = [0u8; 65535];
    let mut peers: Vec<Option<std::net::SocketAddr>> = vec![None; sockets.len()];
    loop {
        for (i, s) in sockets.iter().enumerate() {
            match s.recv_from(&mut dg) {
                Ok((n, peer)) => {
                    peers[i] = Some(peer);
                    let now = Instant::now();
                    let (payloads, replies) = ep.ingest(&dg[..n], now);
                    for frame in replies { let _ = s.send_to(&frame, peer); }
                    for payload in payloads { let _ = s.send_to(&payload, peer); }
                    ep.sweep(now);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    if let Some(peer) = peers[i] {
                        let now = Instant::now();
                        let (payloads, replies) = ep.drain(now);
                        for frame in replies { let _ = s.send_to(&frame, peer); }
                        for payload in payloads { let _ = s.send_to(&payload, peer); }
                    }
                }
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(not(feature = "lab-crypto"))]
fn run() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a.chars().next().map(|c| c.is_ascii_digit()).unwrap_or(false)) {
        eprintln!("balancify-relay: starting in secure mode (no lab-crypto)");
        return run_secure(args);
    }
    eprintln!(
        "balancify-relay: refusing to start without lab-crypto in lab mode.\n\
         This build carries no null cipher: use secure mode with keys.\n\
         Lab use: cargo run -p balancify-relay --features lab-crypto -- 4430,4431\n\
         Secure use: cargo run -p balancify-relay -- 4430,4431 (keys in $BALANCIFY_STATE_DIR or /tmp/balancify)"
    );
    let state_dir = resolve_state_dir(std::env::var_os("BALANCIFY_STATE_DIR"), default_state_dir())?;
    if state_dir.exists() {
        return run_secure(args);
    }
    std::process::exit(2)
}

fn run_secure(args: Vec<String>) -> std::io::Result<()> {
    use balancify_crypto::{FileKeyStore, KeyStore, PinnedKeys};
    let ports = parse_listen_args(&args)?;
    let state_dir = resolve_state_dir(std::env::var_os("BALANCIFY_STATE_DIR"), default_state_dir())?;
    let secret_path = state_dir.join("relay_secret.key");
    let pinned_path = state_dir.join("pinned_clients.keys");
    let mut store = FileKeyStore::new(&secret_path, &pinned_path);
    let keypair = match store.load_or_generate() {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("Failed to load/generate relay keypair from {:?}: {}", secret_path, e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, format!("{}", e)));
        }
    };
    let pinned = load_pinned_clients(&store).map_err(|error| {
        eprintln!("Failed to load pinned client identities from {:?}: {}", pinned_path, error);
        error
    })?;
    eprintln!("balancify-relay (secure mode): listening on UDP {:?}, state_dir={}, pinned_clients={}", ports, state_dir.display(), pinned.len());
    eprintln!("  relay public key: {:02x?}...", &keypair.public_bytes()[..8]);
    let sockets: Vec<UdpSocket> = ports.iter().map(|p| UdpSocket::bind(("0.0.0.0", *p))).collect::<Result<_, _>>()?;
    for s in &sockets { s.set_read_timeout(Some(Duration::from_millis(100)))?; }
    let mut relay = SecureRelay::new(keypair, pinned);
    let mut dg = [0u8; 65535];
    let mut peers: BTreeMap<u64, std::net::SocketAddr> = BTreeMap::new();
    // Optional upstream forwarding (Sec.4.2 data plane: relay decrypts, reorders, forwards from stable address)
    // If BALANCIFY_FORWARD_ADDR is set (e.g. 127.0.0.1:8080), decrypted payloads are forwarded via UDP
    // to that address, and replies are re-encrypted back to the client session.
    // If not set, we echo payloads (lab mode).
    let forward_addr = parse_forward_addr(std::env::var("BALANCIFY_FORWARD_ADDR"))?;
    if let Some(fa) = forward_addr {
        eprintln!("Forwarding enabled: decrypted payloads -> {} (stable egress)", fa);
    } else {
        eprintln!("Forwarding: echo mode (lab) -- set BALANCIFY_FORWARD_ADDR to enable upstream forwarding");
    }
    // Per-session forwarding sockets (one UDP socket per client session, bound to 0.0.0.0:0)
    // This gives us stable egress per session and lets us map replies back to session.
    let mut forward_socks: BTreeMap<u64, UdpSocket> = BTreeMap::new();
    let mut forward_buf = [0u8; 65535];
    let mut last_sweep = Instant::now();
    let mut last_handshake_failure_log = None;

    loop {
        for (_idx, s) in sockets.iter().enumerate() {
            match s.recv_from(&mut dg) {
                Ok((n, peer)) => {
                    let now = Instant::now();
                    if n >= 2 && dg[0] == HANDSHAKE_VERSION {
                        if dg[1] == HANDSHAKE_MSG1 {
                            let msg1 = &dg[2..n];
                            match relay.handle_msg1(msg1, peer, now) {
                                Ok((msg2, session_id)) => {
                                    let mut out = Vec::with_capacity(2 + msg2.len());
                                    out.push(HANDSHAKE_VERSION);
                                    out.push(HANDSHAKE_MSG2);
                                    out.extend_from_slice(&msg2);
                                    let forward_socket = if let Some(upstream) = forward_addr {
                                        match create_forward_socket(upstream) {
                                            Ok(socket) => Some(socket),
                                            Err(error) => {
                                                relay.remove_session(session_id);
                                                eprintln!("Failed to create forward socket for session {}: {}; handshake response not sent", session_id, error);
                                                None
                                            }
                                        }
                                    } else {
                                        None
                                    };
                                    if forward_addr.is_none() || forward_socket.is_some() {
                                        match s.send_to(&out, peer) {
                                            Ok(sent) if sent == out.len() => {
                                                peers.insert(session_id, peer);
                                                if let Some(socket) = forward_socket {
                                                    forward_socks.insert(session_id, socket);
                                                }
                                                eprintln!("Handshake: new session {} from {} (total sessions {})", session_id, peer, relay.sessions.len());
                                            }
                                            Ok(sent) => {
                                                relay.remove_session(session_id);
                                                eprintln!("Handshake response to {} sent only {}/{} bytes; session {} removed", peer, sent, out.len(), session_id);
                                            }
                                            Err(error) => {
                                                relay.remove_session(session_id);
                                                eprintln!("Handshake response to {} failed: {}; session {} removed", peer, error, session_id);
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    if failure_log_due(&mut last_handshake_failure_log, now, Duration::from_secs(1)) {
                                        eprintln!("Handshake msg1 from {} failed: {:?} (further errors are rate-limited)", peer, e);
                                    }
                                }
                            }
                        } else if failure_log_due(&mut last_handshake_failure_log, now, Duration::from_secs(1)) {
                            eprintln!("Unknown handshake kind {} from {} (further errors are rate-limited)", dg[1], peer);
                        }
                    } else if n >= 20 && dg[0] == balancify_tunnel::WIRE_VERSION {
                        // Decode session id for forwarding mapping
                        let session_id_opt = balancify_tunnel::Header::decode(&dg[..n]).map(|(h, _)| h.session);
                        if let Some((payloads, replies, authenticated)) = relay.ingest_tunnel(&dg[..n], peer, now) {
                            if authenticated {
                                if let Some(session_id) = session_id_opt {
                                    peers.insert(session_id, peer);
                                }
                            }
                            for frame in replies { let _ = s.send_to(&frame, peer); }
                            for payload in payloads {
                                if forward_addr.is_some() {
                                    if let Some(sid) = session_id_opt {
                                        // Never borrow another session's egress socket: its replies
                                        // are routed back through a different tunnel key.
                                        if let Some(fs) = forward_socket_for_session(&forward_socks, sid) {
                                            let _ = fs.send(&payload);
                                        }
                                    }
                                } else {
                                    let _ = s.send_to(&payload, peer);
                                }
                            }
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                    let now = Instant::now();
                    // Drain reorder buffers
                    for (session_id, payloads, replies) in relay.drain_all(now) {
                        if let Some(peer) = peers.get(&session_id) {
                            for frame in replies { let _ = s.send_to(&frame, peer); }
                            for payload in payloads {
                                if forward_addr.is_some() {
                                    if let Some(fs) = forward_socks.get(&session_id) {
                                        let _ = fs.send(&payload);
                                    }
                                } else {
                                    let _ = s.send_to(&payload, peer);
                                }
                            }
                        }
                    }
                    // Poll forwarding sockets for upstream replies
                    if forward_addr.is_some() {
                        let mut to_remove = Vec::new();
                        for (sid, fs) in forward_socks.iter() {
                            loop {
                                match fs.recv(&mut forward_buf) {
                                    Ok(n) => {
                                        if let Some(peer) = peers.get(sid) {
                                            if let Some(sess) = relay.sessions.get_mut(sid) {
                                                // Re-encrypt reply as tunnel data
                                                if let Some(sent) = sess.tx.send(&forward_buf[..n], now) {
                                                    let _ = s.send_to(&sent.bytes, peer);
                                                }
                                            }
                                        }
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => break,
                                    Err(_) => break,
                                }
                            }
                            // Check if session still exists, otherwise mark for removal
                            if !relay.sessions.contains_key(sid) {
                                to_remove.push(*sid);
                            }
                        }
                        for sid in to_remove {
                            forward_socks.remove(&sid);
                        }
                    }
                }
                Err(e) => return Err(e),
            }
            let maintenance_now = Instant::now();
            if sweep_due(&mut last_sweep, maintenance_now, Duration::from_secs(10)) {
                let evicted = relay.sweep(maintenance_now);
                for sid in evicted {
                    peers.remove(&sid);
                    forward_socks.remove(&sid);
                }
                let (sess_cnt, hs, rej, bytes, pkts, ecn) = relay.stats();
                if sess_cnt > 0 {
                    eprintln!("Stats: sessions={} handshakes={} rejected={} bytes={} pkts={} ecn={}", sess_cnt, hs, rej, bytes, pkts, ecn);
                }
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;
    use balancify_tunnel::{FrameKind, Header, PassThrough, Sender, Sent};

    #[test]
    fn relay_handshake_failure_logs_are_rate_limited() {
        let start = Instant::now();
        let mut last_log = None;
        let interval = Duration::from_secs(1);

        assert!(failure_log_due(&mut last_log, start, interval));
        assert!(!failure_log_due(&mut last_log, start + Duration::from_millis(500), interval));
        assert!(failure_log_due(&mut last_log, start + interval, interval));
    }

    #[test]
    fn relay_sweep_scheduler_uses_elapsed_time_not_fresh_instant_age() {
        let start = Instant::now();
        let mut last_sweep = start;
        let interval = Duration::from_secs(10);

        assert!(!sweep_due(&mut last_sweep, start + Duration::from_secs(9), interval));
        assert_eq!(last_sweep, start);
        assert!(sweep_due(&mut last_sweep, start + interval, interval));
        assert_eq!(last_sweep, start + interval);
        assert!(!sweep_due(&mut last_sweep, start + Duration::from_secs(19), interval));
        assert!(sweep_due(&mut last_sweep, start + Duration::from_secs(20), interval));
    }

    #[test]
    fn relay_state_dir_resolution_uses_one_default_and_rejects_empty_override() {
        let default = std::path::PathBuf::from("/test/default-state");
        assert_eq!(resolve_state_dir(None, default.clone()).unwrap(), default);
        assert_eq!(
            resolve_state_dir(Some(std::ffi::OsString::from("/custom/state")), std::path::PathBuf::new()).unwrap(),
            std::path::PathBuf::from("/custom/state"),
        );
        assert!(resolve_state_dir(Some(std::ffi::OsString::new()), std::path::PathBuf::new()).is_err());
    }

    #[test]
    fn relay_refuses_a_corrupt_pinned_client_store() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("balancify-relay-pins-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let secret_path = dir.join("secret.key");
        let pinned_path = dir.join("pinned.keys");
        let store = balancify_crypto::FileKeyStore::new(&secret_path, &pinned_path);

        assert!(load_pinned_clients(&store).unwrap().is_empty(), "a missing pin file remains an empty pin set");
        std::fs::write(&pinned_path, [0xff]).unwrap();
        assert!(load_pinned_clients(&store).is_err(), "corrupt pin state must not become an empty allow-all set");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn listen_port_configuration_rejects_partial_or_empty_lists() {
        assert_eq!(parse_listen_ports(None).unwrap(), vec![4430, 4431]);
        assert_eq!(parse_listen_ports(Some("4430, 4431")).unwrap(), vec![4430, 4431]);
        assert_eq!(parse_listen_args(&["4430,4431".to_string()]).unwrap(), vec![4430, 4431]);
        assert!(parse_listen_args(&["4430".to_string(), "4431".to_string()]).is_err());
        assert!(parse_listen_ports(Some("4430,not-a-port")).is_err());
        assert!(parse_listen_ports(Some("4430,")).is_err());
        assert!(parse_listen_ports(Some("")).is_err());
        assert!(parse_listen_ports(Some("4430,4430")).is_err());
    }

    #[test]
    fn forward_address_configuration_fails_closed_on_invalid_values() {
        assert_eq!(parse_forward_addr(Err(std::env::VarError::NotPresent)).unwrap(), None);
        assert_eq!(
            parse_forward_addr(Ok("127.0.0.1:8080".to_string())).unwrap(),
            Some("127.0.0.1:8080".parse().unwrap()),
        );
        assert!(parse_forward_addr(Ok("not-an-address".to_string())).is_err());
        assert!(parse_forward_addr(Ok("127.0.0.1:0".to_string())).is_err());
        assert!(parse_forward_addr(Ok("0.0.0.0:8080".to_string())).is_err());
    }

    #[test]
    fn connected_forward_socket_rejects_unexpected_udp_sources() {
        let upstream = UdpSocket::bind("127.0.0.1:0").unwrap();
        let forward = create_forward_socket(upstream.local_addr().unwrap()).unwrap();
        let forward_addr = forward.local_addr().unwrap();
        let rogue = UdpSocket::bind("127.0.0.1:0").unwrap();
        rogue.send_to(b"forged upstream", forward_addr).unwrap();

        let mut buf = [0u8; 64];
        let error = forward.recv(&mut buf).expect_err("connected UDP socket must filter other sources");
        assert!(matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut));

        upstream.send_to(b"expected upstream", forward_addr).unwrap();
        let n = forward.recv(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"expected upstream");
    }

    #[test]
    fn forwarding_socket_lookup_does_not_cross_sessions() {
        let socket_a = UdpSocket::bind("127.0.0.1:0").unwrap();
        let socket_b = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr_a = socket_a.local_addr().unwrap();
        let addr_b = socket_b.local_addr().unwrap();
        let forward_socks = BTreeMap::from([(10, socket_a), (20, socket_b)]);

        assert_eq!(forward_socket_for_session(&forward_socks, 10).unwrap().local_addr().unwrap(), addr_a);
        assert_eq!(forward_socket_for_session(&forward_socks, 20).unwrap().local_addr().unwrap(), addr_b);
        assert!(forward_socket_for_session(&forward_socks, 30).is_none());
    }

    #[test]
    fn two_paths_with_delay_gap_reassemble_in_order() {
        let mut send = Sender::new(1, PassThrough, vec![(0, 1000), (1, 1000)]);
        let t0 = Instant::now();
        let mut wire: Vec<Sent> = (0..40).map(|i| send.send(format!("p{:02}", i).as_bytes(), t0).unwrap()).collect();
        wire.sort_by_key(|f| f.seq + if f.path == 1 { 5 } else { 0 });
        let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
        let mut got: Vec<String> = Vec::new();
        let mut replies = 0;
        for f in &wire {
            let (payloads, out) = ep.ingest(&f.bytes, t0);
            replies += out.len();
            got.extend(payloads.into_iter().map(|p| String::from_utf8(p).unwrap()));
        }
        let expect: Vec<String> = (0..40).map(|i| format!("p{:02}", i)).collect();
        assert_eq!(got, expect);
        assert_eq!(ep.out_of_order_releases(), 0);
        assert!(replies > 0);
    }

    #[test]
    fn endpoint_ignores_garbage() {
        let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
        let now = Instant::now();
        assert!(ep.ingest(b"short", now).0.is_empty());
        assert!(ep.ingest(&[0u8; 4], now).0.is_empty());
        assert_eq!(ep.delivered(), 0);
    }

    #[test]
    fn endpoint_deduplicates_the_duplicate_mode_copy() {
        let mut send = Sender::new(2, PassThrough, vec![(0, 1000), (1, 1000)]);
        let t0 = Instant::now();
        let f = send.send(b"tls-clienthello".as_ref(), t0).unwrap();
        let copy = send.duplicate(b"tls-clienthello".as_ref(), f.seq, 1 - f.path).unwrap();
        let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
        let (a, _) = ep.ingest(&f.bytes, t0);
        let (b, _) = ep.ingest(&copy.bytes, t0);
        assert_eq!(a.len(), 1);
        assert!(b.is_empty());
        assert_eq!(ep.duplicates_seen(), 1);
        let mut send2 = Sender::new(4, PassThrough, vec![(0, 1000), (1, 1000)]);
        let g = send2.send(b"tls-clienthello".as_ref(), t0).unwrap();
        let copy2 = send2.duplicate(b"tls-clienthello".as_ref(), g.seq, 1 - g.path).unwrap();
        let mut ep2 = Endpoint::new(PassThrough, ReceiverConfig::default());
        let (first, _) = ep2.ingest(&copy2.bytes, t0);
        let (second, _) = ep2.ingest(&g.bytes, t0);
        assert_eq!(first.len(), 1);
        assert!(second.is_empty());
        assert_eq!(ep2.duplicates_seen(), 1);
    }

    #[test]
    fn relay_session_idle_timer_ignores_unauthenticated_datagrams() {
        let now = Instant::now();
        let key = [7u8; 32];
        let salt = [3u8; 3];
        let recv = balancify_crypto::TunnelCipher::new(&key, salt).unwrap();
        let send = balancify_crypto::TunnelCipher::new(&key, salt).unwrap();
        let addr = "127.0.0.1:9000".parse().unwrap();
        let mut session = RelaySession::new(12, [0u8; 32], addr, recv, send, now);
        let mut client = Sender::new(
            12,
            balancify_crypto::TunnelCipher::new(&key, salt).unwrap(),
            vec![(0, 1000)],
        );
        let valid_time = now + Duration::from_secs(1);
        let valid = client.send(b"accepted", valid_time).unwrap();
        session.ingest(&valid.bytes, valid_time);
        assert_eq!(session.last_activity, valid_time);

        let replay_time = valid_time + Duration::from_secs(100);
        let mut forged = Vec::new();
        Header::new(FrameKind::Keepalive, 0, 12, 7).encode(&mut forged);
        session.ingest(&forged, replay_time);
        assert_eq!(session.last_activity, valid_time, "an invalid tag cannot keep the relay session alive");
    }

    #[test]
    fn endpoint_answers_probes() {
        let mut send = Sender::new(3, PassThrough, vec![(0, 1000)]);
        let t0 = Instant::now();
        let probe = send.probe(0, 48);
        let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
        let (payloads, replies) = ep.ingest(&probe.bytes, t0);
        assert!(payloads.is_empty());
        assert_eq!(replies.len(), 1);
        let (h, _) = balancify_tunnel::Header::decode(&replies[0]).unwrap();
        assert_eq!(h.kind, balancify_tunnel::FrameKind::ProbeReply);
        assert_eq!(h.seq, probe.seq);
    }

    #[test]
    fn endpoint_drains_a_gap_after_the_hold_cap() {
        let cfg = ReceiverConfig { hold_cap: Duration::from_millis(40), ..ReceiverConfig::default() };
        let mut ep = Endpoint::new(PassThrough, cfg);
        let mut send = Sender::new(9, PassThrough, vec![(0, 1000), (1, 1000)]);
        let t0 = Instant::now();
        let all: Vec<Sent> = (0..3).map(|i| send.send(format!("g{}", i).as_bytes(), t0).unwrap()).collect();
        for f in all.iter().skip(1) {
            let (payloads, _) = ep.ingest(&f.bytes, t0);
            assert!(payloads.is_empty());
        }
        assert!(ep.drain(t0 + Duration::from_millis(5)).0.is_empty());
        let (payloads, replies) = ep.drain(t0 + Duration::from_millis(50));
        let got: Vec<String> = payloads.into_iter().map(|p| String::from_utf8(p).unwrap()).collect();
        assert_eq!(got, vec!["g1".to_string(), "g2".to_string()]);
        assert_eq!(ep.out_of_order_releases(), 1);
        assert!(!replies.is_empty());
        assert_eq!(ep.delivered(), 2);
    }

    #[test]
    fn ordered_stream_survives_a_real_udp_socket() {
        let client = UdpSocket::bind("127.0.0.1:0").unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").unwrap();
        server.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
        let server_addr = server.local_addr().unwrap();
        let mut send = Sender::new(77, PassThrough, vec![(0, 1000)]);
        let t0 = Instant::now();
        for i in 0..10 {
            let f = send.send(format!("u{}", i).as_bytes(), t0).unwrap();
            client.send_to(&f.bytes, server_addr).unwrap();
        }
        let mut ep = Endpoint::new(PassThrough, ReceiverConfig::default());
        let mut buf = [0u8; 65535];
        let mut got: Vec<String> = Vec::new();
        for _ in 0..10 {
            let (n, _) = server.recv_from(&mut buf).unwrap();
            let (payloads, _) = ep.ingest(&buf[..n], t0);
            got.extend(payloads.into_iter().map(|p| String::from_utf8(p).unwrap()));
        }
        got.sort();
        let mut expect: Vec<String> = (0..10).map(|i| format!("u{}", i)).collect();
        expect.sort();
        assert_eq!(got, expect);
        assert_eq!(ep.sessions(), 1);
    }

    #[test]
    fn secure_handshake_creates_session() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let session_id: u64 = 42;
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let eph_c = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
        let msg1 = initiator.write_message(eph_c, &session_id.to_be_bytes());
        let now = Instant::now();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let (msg2, sid) = relay.handle_msg1(&msg1, peer, now).expect("handshake ok");
        assert_eq!(sid, session_id);
        assert_eq!(relay.sessions.len(), 1);
        let (payload, _keys) = initiator.read_message(&msg2).expect("msg2 ok");
        assert_eq!(payload, session_id.to_be_bytes());
    }

    #[test]
    fn failed_handshake_response_can_remove_the_unreachable_session() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let session_id = 779u64;
        let msg1 = initiator.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &session_id.to_be_bytes(),
        );
        let peer = "127.0.0.1:1234".parse().unwrap();
        relay.handle_msg1(&msg1, peer, Instant::now()).expect("handshake establishes session");

        assert!(relay.remove_session(session_id));
        assert!(relay.sessions.is_empty());
        assert!(!relay.remove_session(session_id), "removal is idempotent");
    }

    #[test]
    fn secure_relay_rejects_duplicate_session_id_without_replacing_session() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let peer = "127.0.0.1:1234".parse().unwrap();
        let session_id = 42u64;
        let now = Instant::now();

        let mut first = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let first_msg = first.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &session_id.to_be_bytes(),
        );
        relay.handle_msg1(&first_msg, peer, now).expect("first handshake succeeds");

        let mut second = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let second_msg = second.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &session_id.to_be_bytes(),
        );
        assert!(
            relay.handle_msg1(&second_msg, peer, now + Duration::from_secs(1)).is_err(),
            "a fresh handshake must not reuse an active session id"
        );

        assert_eq!(relay.sessions.len(), 1);
        assert_eq!(relay.sessions[&session_id].created_at, now, "the original session must remain intact");
        assert_eq!(relay.total_handshakes, 1);
        assert_eq!(relay.total_rejected, 1);
    }

    #[test]
    fn secure_relay_rejects_noncanonical_session_payload_length() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let peer = "127.0.0.1:1234".parse().unwrap();
        let now = Instant::now();
        let mut trailing = 42u64.to_be_bytes().to_vec();
        trailing.push(0);

        for (offset, payload) in [vec![0x2a], trailing].into_iter().enumerate() {
            let mut initiator = balancify_crypto::Initiator::new(
                client_kp.secret_bytes(),
                relay_kp.public_bytes(),
                PROLOGUE,
            );
            let eph = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
            let msg1 = initiator.write_message(eph, &payload);
            assert!(
                relay.handle_msg1(&msg1, peer, now + Duration::from_secs(offset as u64)).is_err(),
                "noncanonical session payload length {} must be rejected",
                payload.len()
            );
        }
        assert!(relay.sessions.is_empty(), "malformed payloads must not create sessions");
        assert_eq!(relay.total_handshakes, 0);
        assert_eq!(relay.total_rejected, 2, "each malformed authenticated request is counted");
    }

    #[test]
    fn secure_relay_rejects_unpinned_client() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let other_kp = balancify_crypto::StaticKeypair::generate();
        let mut pinned = balancify_crypto::PinnedKeys::new();
        pinned.pin(other_kp.public_bytes());
        let mut relay = SecureRelay::new(relay_kp.clone(), pinned);
        let session_id: u64 = 99;
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let eph_c = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
        let msg1 = initiator.write_message(eph_c, &session_id.to_be_bytes());
        let now = Instant::now();
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert!(relay.handle_msg1(&msg1, peer, now).is_err());
        assert_eq!(relay.sessions.len(), 0);
        assert_eq!(relay.total_rejected, 1);
    }

    #[test]
    fn secure_relay_rejects_replay() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let session_id: u64 = 123;
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let eph = [0x11u8; 32];
        let msg1 = initiator.write_message(eph, &session_id.to_be_bytes());
        let now = Instant::now();
        let peer = "127.0.0.1:1234".parse().unwrap();
        assert!(relay.handle_msg1(&msg1, peer, now).is_ok());
        let mut initiator2 = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_replay = initiator2.write_message(eph, &session_id.to_be_bytes());
        assert!(relay.handle_msg1(&msg1_replay, peer, now + Duration::from_secs(1)).is_err());
        assert_eq!(relay.total_rejected, 1);
    }

    #[test]
    fn relay_peer_rebinding_requires_a_fresh_authenticated_frame() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let session_id = 778u64;
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1 = initiator.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &session_id.to_be_bytes(),
        );
        let now = Instant::now();
        let original_peer = "127.0.0.1:1234".parse().unwrap();
        let spoofed_peer = "127.0.0.2:2345".parse().unwrap();
        let rebound_peer = "127.0.0.3:3456".parse().unwrap();
        let (msg2, _) = relay.handle_msg1(&msg1, original_peer, now).unwrap();
        let (_, client_keys) = initiator.read_message(&msg2).unwrap();
        let mut client_tx = Sender::new(session_id, client_keys.send_cipher().unwrap(), vec![(0, 2000)]);

        let first = client_tx.send(b"before-rebind", now).unwrap();
        let (_, _, authenticated) = relay.ingest_tunnel(&first.bytes, original_peer, now).unwrap();
        assert!(authenticated);
        assert_eq!(relay.sessions[&session_id].peer_addr, original_peer);

        let mut forged = Vec::new();
        Header::new(FrameKind::Keepalive, 0, session_id, 900).encode(&mut forged);
        forged.extend_from_slice(&[0; 16]);
        let (_, _, authenticated) = relay
            .ingest_tunnel(&forged, spoofed_peer, now + Duration::from_secs(1))
            .unwrap();
        assert!(!authenticated);
        assert_eq!(relay.sessions[&session_id].peer_addr, original_peer, "unauthenticated traffic cannot hijack the peer route");
        assert_eq!(relay.total_rejected, 1, "unauthenticated tunnel frames are counted");

        let second_time = now + Duration::from_secs(2);
        let second = client_tx.send(b"after-rebind", second_time).unwrap();
        let (_, _, authenticated) = relay
            .ingest_tunnel(&second.bytes, rebound_peer, second_time)
            .unwrap();
        assert!(authenticated);
        assert_eq!(relay.sessions[&session_id].peer_addr, rebound_peer);
    }

    #[test]
    fn secure_tunnel_after_handshake() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        let session_id: u64 = 777;
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let eph_c = balancify_crypto::EphemeralKeypair::generate().secret_bytes();
        let msg1 = initiator.write_message(eph_c, &session_id.to_be_bytes());
        let now = Instant::now();
        let peer = "127.0.0.1:1234".parse().unwrap();
        let (msg2, _) = relay.handle_msg1(&msg1, peer, now).expect("handshake");
        let (payload, client_keys) = initiator.read_message(&msg2).expect("msg2");
        assert_eq!(payload, session_id.to_be_bytes());

        // Client now has transport keys, sends data
        let client_send = client_keys.send_cipher().unwrap();
        let mut client_tx = Sender::new(session_id, client_send, vec![(0, 2000)]);
        let frame = client_tx.send(b"hello secure world", now).unwrap();

        // Relay ingests
        let (payloads, replies, authenticated) = relay
            .ingest_tunnel(&frame.bytes, peer, now)
            .expect("session exists");
        assert!(authenticated);
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], b"hello secure world");
        assert!(!replies.is_empty(), "must ACK");
    }

    #[test]
    fn secure_relay_enforces_rate_limit_and_session_cap() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        relay.max_sessions = 2;
        relay.max_sessions_per_ip = 1;
        let now = Instant::now();
        let peer1: std::net::SocketAddr = "10.0.0.1:1234".parse().unwrap();
        let peer2: std::net::SocketAddr = "10.0.0.1:5678".parse().unwrap(); // same IP
        let peer3: std::net::SocketAddr = "10.0.0.2:1234".parse().unwrap(); // different IP

        // First handshake from peer1 should succeed
        let client_kp1 = balancify_crypto::StaticKeypair::generate();
        let mut initiator1 = balancify_crypto::Initiator::new(
            client_kp1.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_1 = initiator1.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &1u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1_1, peer1, now).is_ok());

        // Second handshake from same IP should fail (per-IP cap 1)
        let client_kp2 = balancify_crypto::StaticKeypair::generate();
        let mut initiator2 = balancify_crypto::Initiator::new(
            client_kp2.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_2 = initiator2.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &2u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1_2, peer2, now).is_err(), "per-IP cap should reject");

        // From different IP should succeed (global cap 2)
        let client_kp3 = balancify_crypto::StaticKeypair::generate();
        let mut initiator3 = balancify_crypto::Initiator::new(
            client_kp3.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_3 = initiator3.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &3u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1_3, peer3, now).is_ok());

        // Third IP now exceeds global cap
        let peer4: std::net::SocketAddr = "10.0.0.3:1234".parse().unwrap();
        let client_kp4 = balancify_crypto::StaticKeypair::generate();
        let mut initiator4 = balancify_crypto::Initiator::new(
            client_kp4.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_4 = initiator4.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &4u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1_4, peer4, now).is_err(), "global cap should reject");

        let (sessions, handshakes, rejected, _, _, _) = relay.stats();
        assert_eq!(sessions, 2);
        assert_eq!(handshakes, 2);
        assert!(rejected >= 2);
    }

    #[test]
    fn handshake_rate_limit_tracking_is_bounded_under_source_churn() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp, balancify_crypto::PinnedKeys::new());
        let now = Instant::now();
        let oldest_ip = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(1u32)),
            1234,
        );
        assert!(relay.check_rate_limit_handshake(oldest_ip, now - Duration::from_secs(55)));

        for address in 2..=MAX_TRACKED_HANDSHAKE_IPS as u32 {
            let peer = std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::from(address)),
                1234,
            );
            assert!(relay.check_rate_limit_handshake(peer, now));
        }
        assert_eq!(relay.handshake_attempts.len(), MAX_TRACKED_HANDSHAKE_IPS);

        let new_ip = std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(MAX_TRACKED_HANDSHAKE_IPS as u32 + 1)),
            1234,
        );
        assert!(relay.check_rate_limit_handshake(new_ip, now));
        assert_eq!(relay.handshake_attempts.len(), MAX_TRACKED_HANDSHAKE_IPS);
        assert!(!relay.handshake_attempts.contains_key(&oldest_ip.ip()));
        assert!(relay.handshake_attempts.contains_key(&new_ip.ip()));
    }

    #[test]
    fn global_handshake_limiter_bounds_bursts_and_refills_smoothly() {
        let start = Instant::now();
        let mut limiter = HandshakeLimiter::new(start);
        for _ in 0..GLOBAL_HANDSHAKE_BURST as usize {
            assert!(limiter.try_consume(start));
        }
        assert!(!limiter.try_consume(start));
        assert!(limiter.try_consume(start + Duration::from_millis(10)));
        assert!(!limiter.try_consume(start + Duration::from_millis(10)));
    }

    #[test]
    fn secure_relay_rate_limits_handshakes_per_ip() {
        let relay_kp = balancify_crypto::StaticKeypair::generate();
        let mut relay = SecureRelay::new(relay_kp.clone(), balancify_crypto::PinnedKeys::new());
        relay.max_sessions_per_ip = 100; // lift cap to test rate limit
        relay.max_sessions = 100;
        let now = Instant::now();
        let peer: std::net::SocketAddr = "192.168.1.1:1234".parse().unwrap();

        // 10 handshakes in same window should succeed, 11th fail
        for i in 0..10 {
            let client_kp = balancify_crypto::StaticKeypair::generate();
            let mut initiator = balancify_crypto::Initiator::new(
                client_kp.secret_bytes(),
                relay_kp.public_bytes(),
                PROLOGUE,
            );
            let msg1 = initiator.write_message(
                balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
                &(100 + i as u64).to_be_bytes(),
            );
            assert!(relay.handle_msg1(&msg1, peer, now).is_ok(), "handshake {} should ok", i);
        }
        // 11th in same minute should be rate limited
        let client_kp = balancify_crypto::StaticKeypair::generate();
        let mut initiator = balancify_crypto::Initiator::new(
            client_kp.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1 = initiator.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &999u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1, peer, now).is_err(), "11th should be rate limited");
        assert_eq!(relay.global_handshake_limiter.tokens, GLOBAL_HANDSHAKE_BURST - 10.0,
            "an over-quota IP must not drain the aggregate bucket");

        // After window, should succeed again
        let later = now + Duration::from_secs(61);
        let client_kp2 = balancify_crypto::StaticKeypair::generate();
        let mut initiator2 = balancify_crypto::Initiator::new(
            client_kp2.secret_bytes(),
            relay_kp.public_bytes(),
            PROLOGUE,
        );
        let msg1_later = initiator2.write_message(
            balancify_crypto::EphemeralKeypair::generate().secret_bytes(),
            &1000u64.to_be_bytes(),
        );
        assert!(relay.handle_msg1(&msg1_later, peer, later).is_ok(), "after window should ok");
    }
}
