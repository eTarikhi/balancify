//! Secure peer regression tests for key-update coordination.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::{Duration, Instant};

use balancify_core::{FlowKey, UplinkId};
use balancify_crypto::TunnelCipher;
use balancify_service::{Action, Service, ServiceConfig};
use balancify_tunnel::{Event, Receiver, ReceiverConfig};

fn socket(port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 0, 1), port))
}

fn secure_peers(session: u64, now: Instant) -> (Service<TunnelCipher>, Receiver<TunnelCipher>) {
    let salt = [0x31, 0x42, 0x53];
    let client_to_peer = [0x11; 32];
    let peer_to_client = [0x22; 32];
    let mut client = Service::new(
        ServiceConfig {
            session,
            seed: 0xBEEF,
            ..ServiceConfig::default()
        },
        TunnelCipher::new(&client_to_peer, salt).unwrap(),
        TunnelCipher::new(&peer_to_client, salt).unwrap(),
    );
    client.add_uplink(UplinkId(0), 200_000_000, false, 1500, now);
    for _ in 0..5 {
        client.on_probe_ok(UplinkId(0), Duration::from_millis(10), now);
    }
    assert!(client.publish(now));

    let mut peer = Receiver::new(
        TunnelCipher::new(&client_to_peer, salt).unwrap(),
        ReceiverConfig::default(),
    );
    peer.open_session(session, now);
    (client, peer)
}

fn sent_frame(actions: Vec<Action>) -> Vec<u8> {
    actions
        .into_iter()
        .find_map(|action| match action {
            Action::Send { bytes, .. } => Some(bytes),
            other => panic!("expected a tunnel send, got {other:?}"),
        })
        .expect("service should send the packet")
}

fn assert_delivers(
    receiver: &mut Receiver<TunnelCipher>,
    frame: &[u8],
    now: Instant,
    expected: &[u8],
) {
    let events = receiver.ingest(frame, now);
    assert!(
        events.iter().any(
            |event| matches!(event, Event::Payload { data, .. } if data.as_slice() == expected)
        ),
        "the peer must authenticate and deliver the frame"
    );
}

fn test_flow() -> FlowKey {
    FlowKey::new(6, socket(5000), socket(443))
}

#[test]
fn packet_threshold_marks_update_due_without_unilateral_cipher_rotation() {
    let now = Instant::now();
    let session = 0xA11CE;
    let (mut client, mut peer) = secure_peers(session, now);
    let flow = test_flow();

    client.set_rekey_interval(Duration::from_secs(3600), 1);
    let first = sent_frame(client.send_app_packet(&flow, None, b"before threshold", now));
    assert_delivers(&mut peer, &first, now, b"before threshold");

    // The service reaches its configured threshold. It must request a
    // coordinated update, not silently replace only its local ciphers.
    let _ = client.tick(now + Duration::from_secs(1));
    assert!(client.rekey_due(), "the packet threshold should be visible");
    assert_eq!(client.packets_since_rekey(), 1);
    assert_eq!(client.last_rekey(), None, "no key update was actually negotiated");

    let second_at = now + Duration::from_secs(2);
    let second = sent_frame(client.send_app_packet(&flow, None, b"after threshold", second_at));
    assert_delivers(&mut peer, &second, second_at, b"after threshold");
    assert_eq!(client.packets_since_rekey(), 2);
}

#[test]
fn time_threshold_marks_update_due_without_unilateral_cipher_rotation() {
    let now = Instant::now();
    let session = 0xA11CF;
    let (mut client, mut peer) = secure_peers(session, now);
    let flow = test_flow();

    client.set_rekey_interval(Duration::from_secs(1), u64::MAX);
    let first = sent_frame(client.send_app_packet(&flow, None, b"before time threshold", now));
    assert_delivers(&mut peer, &first, now, b"before time threshold");

    let due_at = now + Duration::from_secs(1);
    let _ = client.tick(due_at);
    assert!(client.rekey_due(), "the elapsed-time threshold should be visible");
    assert_eq!(client.last_rekey(), None, "no key update was actually negotiated");

    let second_at = now + Duration::from_secs(2);
    let second = sent_frame(client.send_app_packet(&flow, None, b"after time threshold", second_at));
    assert_delivers(&mut peer, &second, second_at, b"after time threshold");
}
