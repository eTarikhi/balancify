//! Support bundle generation (Sec.8.2 Diagnostics, Sec.9.2 redaction)
//!
//! One-click bundle: logs (ETW export), route table, adapter state, version/signing info, redaction applied.
//! Redaction: no destinations, no content (Sec.9.2) -- only counters, error codes, and hashed flow keys.

use crate::{Service, Counters};
use std::time::Instant;

/// Redacted flow key for diagnostics -- hash of 5-tuple, not the tuple itself.
#[derive(Debug, Clone)]
pub struct RedactedFlow {
    pub hash: u64,
    pub class: u8,
    pub uplink: u8,
}

/// Support bundle (JSON-serializable for IPC, redacted).
#[derive(Debug, Clone)]
pub struct SupportBundle {
    pub timestamp: String,
    pub service_version: String,
    pub schema_version: u8,
    pub policy_revision: u64,
    pub counters: Counters,
    pub uplinks: Vec<UplinkDiag>,
    pub active_flows: usize,
    pub pending_probes: usize,
    pub sessions: usize,
    pub held_packets: usize,
    /// Whether a relay is configured, without including its address.
    pub relay_configured: bool,
    pub relay_failover_count: u64,
    pub relay_failover_convergence_ms: Option<u64>,
    pub uplink_failover_count: u64,
    pub uplink_failover_convergence_ms: Option<u64>,
    pub rekey: RekeyDiag,
    pub congestion: CongestionDiag,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct UplinkDiag {
    pub id: u8,
    pub state: String,
    pub rtt_ms: u32,
    pub loss_permille: u16,
    pub capacity_bps: u64,
    pub weight_permille: u16,
    pub metered: bool,
    pub eligible: bool,
    pub cwnd: u64,
    pub in_flight: u64,
}

#[derive(Debug, Clone)]
pub struct RekeyDiag {
    pub packets_since_rekey: u64,
    pub last_rekey_ago_secs: Option<u64>,
    /// True once an update threshold is reached; keys remain unchanged until a
    /// peer-coordinated handshake is implemented.
    pub update_required: bool,
}

#[derive(Debug, Clone)]
pub struct CongestionDiag {
    pub loss_events: u64,
    pub ecn_events: u64,
    pub delay_events: u64,
    pub paths: Vec<u8>,
    pub per_path: Vec<PathCongestionDiag>,
}

#[derive(Debug, Clone)]
pub struct PathCongestionDiag {
    pub id: u8,
    pub cwnd: u64,
    pub in_flight: u64,
    pub ecn_ce: u64,
    pub delay_events: u64,
    pub rtt_min_ms: Option<u64>,
    pub rtt_last_ms: Option<u64>,
}

impl SupportBundle {
    pub fn collect<C: balancify_tunnel::Crypto + Clone>(svc: &Service<C>, now: Instant) -> Self {
        let snap = svc.snapshot();
        let counters = svc.counters();
        let uplinks = snap.uplinks.iter().map(|u| {
            let cwnd = svc.cc.window(u.id.0 as u8) as u64;
            let in_flight = svc.cc.in_flight(u.id.0 as u8) as u64;
            UplinkDiag {
                id: u.id.0,
                state: format!("{:?}", u.state),
                rtt_ms: u.rtt.as_millis().min(u32::MAX as u128) as u32,
                loss_permille: (u.loss * 1000.0).round().min(1000.0) as u16,
                capacity_bps: u.capacity_bps,
                weight_permille: 0,
                metered: u.metered,
                eligible: u.eligible,
                cwnd,
                in_flight,
            }
        }).collect();

        let rekey = RekeyDiag {
            packets_since_rekey: svc.packets_since_rekey(),
            last_rekey_ago_secs: svc.last_rekey().map(|t| now.duration_since(t).as_secs()),
            update_required: svc.rekey_due(),
        };
        let mut warnings = Vec::new();
        if rekey.update_required {
            warnings.push(
                "A transport key-update threshold is due; keys were not rotated because the relay protocol has no coordinated update exchange."
                    .to_owned(),
            );
        }

        let paths = svc.cc.paths();
        let per_path = paths.iter().map(|p| {
            PathCongestionDiag {
                id: *p,
                cwnd: svc.cc.window(*p),
                in_flight: svc.cc.in_flight(*p),
                ecn_ce: svc.cc.ecn_ce(*p),
                delay_events: svc.cc.delay_events_path(*p),
                rtt_min_ms: svc.cc.rtt_min(*p).map(|d| d.as_millis() as u64),
                rtt_last_ms: svc.cc.rtt_last(*p).map(|d| d.as_millis() as u64),
            }
        }).collect();
        let congestion = CongestionDiag {
            loss_events: svc.cc.loss_events(),
            ecn_events: svc.cc.ecn_events(),
            delay_events: svc.cc.delay_events(),
            paths,
            per_path,
        };

        SupportBundle {
            timestamp: format!("{:?}", now),
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            schema_version: balancify_ipc::SCHEMA_VERSION,
            policy_revision: snap.revision,
            counters,
            uplinks,
            active_flows: svc.active_flows(),
            pending_probes: svc.pending_probes(),
            sessions: svc.sessions(),
            held_packets: svc.held_packets(),
            relay_configured: svc.relay_current().is_some(),
            relay_failover_count: svc.relay_failover_count(),
            relay_failover_convergence_ms: svc.relay_failover_convergence().map(|d| d.as_millis() as u64),
            uplink_failover_count: svc.uplink_failover_count(),
            uplink_failover_convergence_ms: svc.uplink_failover_convergence().map(|d| d.as_millis() as u64),
            rekey,
            congestion,
            warnings,
        }
    }

    pub fn to_json(&self) -> String {
        use std::fmt::Write as _;

        let mut json = String::with_capacity(1024);
        write!(
            json,
            "{{\"timestamp\":{},\"service_version\":{},\"schema_version\":{},\"policy_revision\":{},\"active_flows\":{},\"pending_probes\":{},\"sessions\":{},\"held_packets\":{},\"relay_configured\":{},\"relay_failover_count\":{},\"relay_failover_convergence_ms\":{},\"uplink_failover_count\":{},\"uplink_failover_convergence_ms\":{},\"counters\":{{\"packets_stripped\":{},\"packets_forwarded\":{},\"duplicates_sent\":{},\"reinjections\":{},\"delivered\":{},\"out_of_order\":{},\"refused\":{},\"held\":{},\"path_changes\":{},\"resumes\":{},\"auth_failed\":{},\"keepalives\":{},\"probes\":{},\"sessions_evicted\":{},\"ecn_ce\":{},\"delay_events\":{}}},\"uplinks\":[",
            json_quote(&self.timestamp),
            json_quote(&self.service_version),
            self.schema_version,
            self.policy_revision,
            self.active_flows,
            self.pending_probes,
            self.sessions,
            self.held_packets,
            self.relay_configured,
            self.relay_failover_count,
            json_optional_u64(self.relay_failover_convergence_ms),
            self.uplink_failover_count,
            json_optional_u64(self.uplink_failover_convergence_ms),
            self.counters.packets_stripped,
            self.counters.packets_forwarded,
            self.counters.duplicates_sent,
            self.counters.reinjections,
            self.counters.delivered,
            self.counters.out_of_order,
            self.counters.refused,
            self.counters.held,
            self.counters.path_changes,
            self.counters.resumes,
            self.counters.auth_failed,
            self.counters.keepalives,
            self.counters.probes,
            self.counters.sessions_evicted,
            self.counters.ecn_ce,
            self.counters.delay_events,
        )
        .expect("writing JSON into a String cannot fail");

        for (index, uplink) in self.uplinks.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            write!(
                json,
                "{{\"id\":{},\"state\":{},\"rtt_ms\":{},\"loss_permille\":{},\"capacity_bps\":{},\"weight_permille\":{},\"metered\":{},\"eligible\":{},\"cwnd\":{},\"in_flight\":{}}}",
                uplink.id,
                json_quote(&uplink.state),
                uplink.rtt_ms,
                uplink.loss_permille,
                uplink.capacity_bps,
                uplink.weight_permille,
                uplink.metered,
                uplink.eligible,
                uplink.cwnd,
                uplink.in_flight,
            )
            .expect("writing JSON into a String cannot fail");
        }

        write!(
            json,
            "],\"rekey\":{{\"packets_since_rekey\":{},\"last_rekey_ago_secs\":{},\"update_required\":{}}},\"congestion\":{{\"loss_events\":{},\"ecn_events\":{},\"delay_events\":{},\"paths\":[",
            self.rekey.packets_since_rekey,
            json_optional_u64(self.rekey.last_rekey_ago_secs),
            self.rekey.update_required,
            self.congestion.loss_events,
            self.congestion.ecn_events,
            self.congestion.delay_events,
        )
        .expect("writing JSON into a String cannot fail");
        for (index, path) in self.congestion.paths.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            write!(json, "{}", path).expect("writing JSON into a String cannot fail");
        }
        json.push_str("],\"per_path\":[");
        for (index, path) in self.congestion.per_path.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            write!(
                json,
                "{{\"id\":{},\"cwnd\":{},\"in_flight\":{},\"ecn_ce\":{},\"delay_events\":{},\"rtt_min_ms\":{},\"rtt_last_ms\":{}}}",
                path.id,
                path.cwnd,
                path.in_flight,
                path.ecn_ce,
                path.delay_events,
                json_optional_u64(path.rtt_min_ms),
                json_optional_u64(path.rtt_last_ms),
            )
            .expect("writing JSON into a String cannot fail");
        }
        json.push_str("]},\"warnings\":[");
        for (index, warning) in self.warnings.iter().enumerate() {
            if index != 0 {
                json.push(',');
            }
            json.push_str(&json_quote(warning));
        }
        json.push_str("]}");
        json
    }
}

fn json_quote(value: &str) -> String {
    use std::fmt::Write as _;

    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\u{08}' => quoted.push_str("\\b"),
            '\u{0c}' => quoted.push_str("\\f"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            ch if ch <= '\u{1f}' => {
                write!(quoted, "\\u{:04x}", ch as u32)
                    .expect("writing JSON into a String cannot fail");
            }
            ch => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}

fn json_optional_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |value| value.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Service, ServiceConfig};
    use balancify_core::{FlowKey, UplinkId};
    use balancify_tunnel::PassThrough;
    use std::time::{Duration, Instant};

    #[test]
    fn json_string_escaping_handles_quotes_slashes_and_controls() {
        assert_eq!(json_quote("quote\" slash\\ newline\n nul\0"), "\"quote\\\" slash\\\\ newline\\n nul\\u0000\"");
    }

    #[test]
    fn support_bundle_reports_relay_presence_without_exposing_endpoint() {
        let now = Instant::now();
        let mut svc = Service::new(ServiceConfig::default(), PassThrough, PassThrough);
        let relay = "198.51.100.42:9443".parse().unwrap();
        svc.set_relays(relay, None);

        let bundle = SupportBundle::collect(&svc, now);
        assert!(bundle.relay_configured);
        let json = bundle.to_json();
        assert!(json.contains("\"relay_configured\":true"));
        assert!(!json.contains("198.51.100.42"));
        assert!(!json.contains("9443"));
    }

    #[test]
    fn bundle_reports_due_key_update_without_claiming_rotation() {
        let now = Instant::now();
        let mut svc = Service::new(ServiceConfig::default(), PassThrough, PassThrough);
        svc.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        for _ in 0..5 {
            svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now);
        }
        assert!(svc.publish(now));
        svc.set_rekey_interval(Duration::from_secs(3600), 1);
        let flow = FlowKey::new(
            6,
            "10.0.0.1:5000".parse().unwrap(),
            "203.0.113.10:443".parse().unwrap(),
        );
        let actions = svc.send_app_packet(&flow, None, b"threshold", now);
        assert!(actions.iter().any(|action| matches!(action, crate::Action::Send { .. })));
        assert_eq!(svc.packets_since_rekey(), 1);
        let _ = svc.tick(now + Duration::from_secs(1));

        let bundle = SupportBundle::collect(&svc, now + Duration::from_secs(1));
        assert!(bundle.rekey.update_required);
        assert!(bundle.rekey.last_rekey_ago_secs.is_none());
        assert!(bundle
            .warnings
            .iter()
            .any(|warning| warning.contains("keys were not rotated")));
        let json = bundle.to_json();
        assert!(json.contains("\"update_required\":true"));
    }

    #[test]
    fn bundle_includes_per_path_ecn_delay() {
        let now = Instant::now();
        let cfg = ServiceConfig::default();
        let mut svc = Service::new(cfg, PassThrough, PassThrough);
        svc.add_uplink(UplinkId(0), 100_000_000, false, 1500, now);
        for _ in 0..3 {
            svc.on_probe_ok(UplinkId(0), Duration::from_millis(10), now);
        }
        svc.publish(now);
        svc.cc.on_ecn(0, now);
        svc.cc.on_rtt(0, Duration::from_millis(10), now);
        svc.cc.on_rtt(0, Duration::from_millis(50), now + Duration::from_millis(200));
        let bundle = SupportBundle::collect(&svc, now + Duration::from_millis(300));
        assert_eq!(bundle.congestion.ecn_events, 1);
        assert_eq!(bundle.congestion.delay_events, 1);
        assert_eq!(bundle.congestion.per_path.len(), 1);
        assert_eq!(bundle.congestion.per_path[0].ecn_ce, 1);
        assert_eq!(bundle.congestion.per_path[0].delay_events, 1);
        assert!(bundle.congestion.per_path[0].rtt_min_ms.is_some());
        let json = bundle.to_json();
        assert!(json.contains("\"ecn_events\":1"));
        assert!(json.contains("\"per_path\":[{\"id\":0"));
        assert!(json.contains("\"rtt_min_ms\":"));
        assert!(json.contains("\"counters\":{"));
    }
}
