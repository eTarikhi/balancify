//! Payload protection for the tunnel lane.
//!
//! This crate owns no cryptography. The primitive is ChaCha20-Poly1305
//! (RFC 8439) from a vetted, audited crate at an exact pin: the blueprint is
//! explicit that we never roll our own primitives (Sec.4.8 policy rule c, and the
//! Sec.4.8 table row "Crypto primitives ... Policy exception: never roll our own
//! primitives"; see ADR-0006). What lives here is the part that *is* ours, and
//! the part that is easy to get wrong -- how one key becomes a per-packet nonce,
//! and what is authenticated but not encrypted.
//!
//! # Nonce discipline
//!
//! ChaCha20-Poly1305 fails catastrophically on nonce reuse: two messages sealed
//! under the same key and nonce leak their XOR, and an attacker can forge a
//! valid tag for a third. The nonce here is therefore neither random nor a
//! counter that could be lost or reset:
//!
//! ```text
//! nonce = (salt[0] XOR frame-kind)[1] || salt[1..3] || path[1] || seq_be[8]
//! ```
//!
//! * `seq` is unique within a frame-kind lane and session. Data frames use the
//!   ordered stream sequence; FlowData, keepalive, and probe lanes have their
//!   own counters. Reinjections and duplicate-mode copies reuse the *same*
//!   sequence number because they carry the same plaintext and must produce the
//!   same ciphertext.
//! * `frame-kind` domain-separates those independent sequence spaces. Without
//!   this, a FlowData sequence zero could reuse a Data or keepalive nonce.
//! * `path` separates the uplinks of one session and means a frame copied onto
//!   another path fails to open, so path-swapping is detected rather than
//!   silently accepted.
//! * `salt` separates sessions, so two sessions under one long-term key never
//!   share a nonce even if their sequence counters start at the same value.
//!
//! # What the AAD binds
//!
//! The tunnel passes the raw 20-byte frame header as additional authenticated
//! data. The header is not encrypted -- the receiver must read version, kind,
//! session, path, sequence and flags before it can decrypt -- but it *is*
//! covered by the tag, so none of those fields can be rewritten in flight.

pub mod handshake;
pub mod keys;
pub mod store;
pub mod replay;

pub use handshake::{HandshakeError, Initiator, Responder, TransportKeys, PROTOCOL_NAME};
pub use keys::{EphemeralKeypair, PinnedKeys, StaticKeypair};
pub use store::{FileKeyStore, KeyStore, MemoryKeyStore, StoreError};
pub use replay::{ReplayCache, DEFAULT_CAPACITY as REPLAY_CAPACITY, DEFAULT_WINDOW as REPLAY_WINDOW};

use balancify_tunnel::Crypto;
use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit, Nonce,
};

/// ChaCha20-Poly1305 key length (RFC 8439 Sec.2.3).
pub const KEY_LEN: usize = 32;
/// Bytes of the nonce that identify the session.
pub const SALT_LEN: usize = 3;
/// RFC 8439 Sec.4 nonce length.
pub const NONCE_LEN: usize = 12;
/// Poly1305 tag length, i.e. the per-frame overhead this cipher adds.
pub const TAG_LEN: usize = 16;

/// A ChaCha20-Poly1305 instance bound to one session's nonce salt.
///
/// Cheap to construct (no key schedule beyond the cipher's own), safe to share
/// across threads, and deliberately without an API that can produce a nonce the
/// caller chose. The key bytes are kept for rekeying and zeroized on drop.
pub struct TunnelCipher {
    inner: ChaCha20Poly1305,
    salt: [u8; SALT_LEN],
    key: [u8; KEY_LEN],
}

impl Clone for TunnelCipher {
    fn clone(&self) -> Self {
        // Re-create inner from stored key bytes; ChaCha20Poly1305::new_from_slice
        // cannot fail for a 32-byte key, but we handle it.
        let inner = ChaCha20Poly1305::new_from_slice(&self.key)
            .expect("stored 32-byte key must be valid");
        Self { inner, salt: self.salt, key: self.key }
    }
}

impl Drop for TunnelCipher {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        // inner's key is also zeroized on drop when the `zeroize` feature is enabled
        // in chacha20poly1305 (it uses zeroize internally).
    }
}

impl TunnelCipher {
    /// Build a cipher from a 32-byte key and the session's nonce salt.
    /// `None` if the key is the wrong length.
    pub fn new(key: &[u8; KEY_LEN], salt: [u8; SALT_LEN]) -> Option<Self> { Self::from_slice(key, salt) }

    /// As [`TunnelCipher::new`], for a key arriving as a slice (a config file, a
    /// handshake output). `None` rather than a panic on a wrong length.
    pub fn from_slice(key: &[u8], salt: [u8; SALT_LEN]) -> Option<Self> {
        if key.len() != KEY_LEN { return None; }
        let mut key_bytes = [0u8; KEY_LEN];
        key_bytes.copy_from_slice(key);
        let inner = ChaCha20Poly1305::new_from_slice(key).ok()?;
        Some(Self { inner, salt, key: key_bytes })
    }

    /// The nonce for one frame. Exposed because nonce uniqueness is the whole
    /// security argument and deserves a direct test.
    pub fn nonce_for(salt: [u8; SALT_LEN], path: u8, seq: u64) -> [u8; NONCE_LEN] {
        Self::nonce_for_kind(salt, path, seq, 0)
    }

    /// Domain-separated nonce for the wire frame kind in the authenticated header.
    pub fn nonce_for_kind(salt: [u8; SALT_LEN], path: u8, seq: u64, kind: u8) -> [u8; NONCE_LEN] {
        let mut nonce = [0u8; NONCE_LEN];
        nonce[..SALT_LEN].copy_from_slice(&salt);
        nonce[0] ^= kind;
        nonce[SALT_LEN] = path;
        nonce[SALT_LEN + 1..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }

    /// The same nonce in the cipher's own fixed-width type. `None` only if the
    /// length constant above ever stops matching the cipher's, which the test
    /// suite pins.
    fn typed_nonce(&self, path: u8, seq: u64, aad: &[u8]) -> Option<Nonce> {
        let kind = *aad.get(1)?;
        Nonce::try_from(Self::nonce_for_kind(self.salt, path, seq, kind).as_slice()).ok()
    }

    /// A salt folded from a session id, for the lab and for tests.
    ///
    /// This is a convenience, not a key-derivation function: folding 8 bytes
    /// into 3 can collide. The Phase-4 handshake derives a fresh key per
    /// session (Sec.9.2), at which point the salt is belt-and-braces rather than
    /// the only thing separating two sessions.
    pub fn salt_for_session(session: u64) -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        for (i, byte) in session.to_be_bytes().iter().enumerate() {
            salt[i % SALT_LEN] ^= byte;
        }
        salt
    }

    /// Derive the next one-way key from the current key. This is a KDF
    /// primitive, not a live transport update: peers must coordinate when the
    /// returned cipher becomes active or their session will desynchronize.
    /// Uses HKDF-BLAKE2s for consistency with the handshake's KDF.
    pub fn rekey(&self) -> Option<Self> { Self::rekey_from(&self.key, self.salt) }

    /// Rekey from explicit old key bytes, preserving the salt.
    pub fn rekey_from(old_key: &[u8; KEY_LEN], salt: [u8; SALT_LEN]) -> Option<Self> {
        let mut okm = [0u8; KEY_LEN];
        hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(&[0u8; 32]), old_key)
            .expand(b"balancify rekey v1", &mut okm)
            .ok()?;
        Self::new(&okm, salt)
    }

    pub fn salt(&self) -> [u8; SALT_LEN] { self.salt }

    #[cfg(test)]
    pub fn key_bytes(&self) -> [u8; KEY_LEN] { self.key }
}

impl Crypto for TunnelCipher {
    fn seal(&self, path: u8, seq: u64, aad: &[u8], plain: &[u8], out: &mut Vec<u8>) {
        let Some(nonce) = self.typed_nonce(path, seq, aad) else { return; };
        let sealed = self.inner.encrypt(&nonce, Payload { msg: plain, aad });
        if let Ok(ciphertext) = sealed {
            out.extend_from_slice(&ciphertext);
        }
    }

    fn open(&self, path: u8, seq: u64, aad: &[u8], cipher: &[u8]) -> Option<Vec<u8>> {
        let nonce = self.typed_nonce(path, seq, aad)?;
        self.inner.decrypt(&nonce, Payload { msg: cipher, aad }).ok()
    }

    fn rekey(&self) -> Option<Self> {
        self.rekey()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balancify_tunnel::{Event, Receiver, Sender, HEADER_LEN};
    use std::collections::BTreeSet;
    use std::time::Instant;

    const SESSION: u64 = 0x0BAD_F00D_0000_0001;
    const KEY: [u8; KEY_LEN] = [0x5Au8; KEY_LEN];
    const SALT: [u8; SALT_LEN] = [1, 2, 3];

    fn cipher() -> TunnelCipher { TunnelCipher::new(&KEY, SALT).expect("a 32-byte key is valid") }

    fn pair() -> (Sender<TunnelCipher>, Receiver<TunnelCipher>) {
        (
            Sender::new(SESSION, cipher(), vec![(0, 2000), (1, 2000)]),
            Receiver::with_defaults(cipher()),
        )
    }

    fn payloads(events: Vec<Event>) -> Vec<Vec<u8>> {
        events
            .into_iter()
            .filter_map(|ev| match ev {
                Event::Payload { data, .. } => Some(data),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn sealing_hides_the_payload_and_costs_sixteen_bytes() {
        let mut out = Vec::new();
        cipher().seal(0, 1, &[0u8; HEADER_LEN], b"top secret", &mut out);
        assert_eq!(out.len(), 10 + TAG_LEN, "the tag is the only overhead");
        assert!(
            !out.windows(3).any(|w| w == b"top"),
            "the plaintext must not appear in the ciphertext"
        );
    }

    #[test]
    fn a_flipped_bit_anywhere_in_the_body_is_refused() {
        let c = cipher();
        let header = [0u8; HEADER_LEN];
        let plain = b"the quick brown fox";
        let mut sealed = Vec::new();
        c.seal(0, 7, &header, plain, &mut sealed);

        for i in 0..sealed.len() {
            for shift in [0u32, 3, 7] {
                let mut tampered = sealed.clone();
                tampered[i] ^= 1 << shift;
                assert!(c.open(0, 7, &header, &tampered).is_none(), "byte {i} bit {shift} went unnoticed");
            }
        }
        assert_eq!(c.open(0, 7, &header, &sealed).expect("untouched ciphertext opens"), plain);
    }

    #[test]
    fn the_header_is_authenticated_so_it_cannot_be_rewritten() {
        let c = cipher();
        let mut sealed = Vec::new();
        c.seal(0, 7, &[0xAA; HEADER_LEN], b"payload", &mut sealed);
        assert!(c.open(0, 7, &[0xAA; HEADER_LEN], &sealed).is_some());
        assert!(
            c.open(0, 7, &[0xAB; HEADER_LEN], &sealed).is_none(),
            "the same tag must not verify against a different header"
        );
    }

    #[test]
    fn path_sequence_salt_and_key_all_separate_the_nonce() {
        let c = cipher();
        let header = [0u8; HEADER_LEN];
        let mut sealed = Vec::new();
        c.seal(0, 7, &header, b"payload", &mut sealed);

        assert!(c.open(1, 7, &header, &sealed).is_none(), "a frame copied onto another path must not open");
        assert!(c.open(0, 8, &header, &sealed).is_none(), "a frame replayed at another sequence must not open");
        let other_session = TunnelCipher::new(&KEY, [9, 9, 9]).expect("key");
        assert!(other_session.open(0, 7, &header, &sealed).is_none(), "another session's salt must not open it");
        let wrong_key = TunnelCipher::new(&[0x00u8; KEY_LEN], SALT).expect("key");
        assert!(wrong_key.open(0, 7, &header, &sealed).is_none(), "another key must not open it");
    }

    #[test]
    fn frame_kind_domain_separates_independent_sequence_lanes() {
        let data = TunnelCipher::nonce_for_kind(SALT, 0, 0, 0);
        let flow = TunnelCipher::nonce_for_kind(SALT, 0, 0, 5);
        let flow_ack = TunnelCipher::nonce_for_kind(SALT, 0, 0, 6);
        let keepalive = TunnelCipher::nonce_for_kind(SALT, 0, 0, 1);
        assert_ne!(data, flow);
        assert_ne!(data, keepalive);
        assert_ne!(flow, keepalive);
        assert_ne!(flow, flow_ack);
        assert_ne!(data, flow_ack);
        assert_ne!(keepalive, flow_ack);
    }

    #[test]
    fn frame_kind_is_in_the_nonce_domain_and_authenticated_header() {
        let c = cipher();
        let data_header = [0u8; HEADER_LEN];
        let mut flow_header = [0u8; HEADER_LEN];
        flow_header[1] = 5;
        let mut data_sealed = Vec::new();
        let mut flow_sealed = Vec::new();
        c.seal(0, 0, &data_header, b"same", &mut data_sealed);
        c.seal(0, 0, &flow_header, b"same", &mut flow_sealed);
        assert_ne!(data_sealed, flow_sealed);
        assert_eq!(c.open(0, 0, &data_header, &data_sealed).as_deref(), Some(&b"same"[..]));
        assert_eq!(c.open(0, 0, &flow_header, &flow_sealed).as_deref(), Some(&b"same"[..]));
        assert!(c.open(0, 0, &data_header, &flow_sealed).is_none());
        assert!(c.open(0, 0, &flow_header, &data_sealed).is_none());
    }

    #[test]
    fn nonces_never_repeat_across_paths_and_sequences() {
        let mut seen = BTreeSet::new();
        for path in 0..4u8 {
            for seq in 0..256u64 {
                assert!(seen.insert(TunnelCipher::nonce_for(SALT, path, seq)), "{path}/{seq} collided");
            }
        }
        assert_eq!(seen.len(), 1024);
        assert_ne!(
            TunnelCipher::salt_for_session(SESSION),
            TunnelCipher::salt_for_session(SESSION + 1),
            "adjacent session ids must not share a salt"
        );
    }

    #[test]
    fn a_key_of_the_wrong_length_is_refused() {
        assert!(TunnelCipher::from_slice(&[0u8; KEY_LEN - 1], SALT).is_none());
        assert!(TunnelCipher::from_slice(&[0u8; KEY_LEN + 1], SALT).is_none());
        assert!(TunnelCipher::from_slice(&[0u8; KEY_LEN], SALT).is_some());
    }

    #[test]
    fn the_lane_carries_a_stream_end_to_end_under_the_real_cipher() {
        let (mut tx, mut rx) = pair();
        let now = Instant::now();

        let mut frames = Vec::new();
        for i in 0..20u32 {
            let sent = tx.send(&format!("packet {i}").into_bytes(), now).expect("a path is free");
            assert!(sent.bytes.len() > HEADER_LEN + TAG_LEN);
            frames.push(sent.bytes);
        }

        let mut got = Vec::new();
        for dg in &frames {
            got.extend(payloads(rx.ingest(dg, now)));
        }
        got.extend(payloads(rx.drain(now)));

        assert_eq!(got.len(), 20, "every payload came back");
        assert_eq!(rx.counters().auth_failed, 0);
        assert_eq!(rx.counters().delivered, 20);
        let text: Vec<String> = got.into_iter().map(|b| String::from_utf8(b).expect("utf-8")).collect();
        assert_eq!(text[0], "packet 0");
        assert_eq!(text[19], "packet 19");
    }

    #[test]
    fn a_tampered_frame_is_refused_at_the_door_and_counted() {
        let (mut tx, mut rx) = pair();
        let now = Instant::now();
        let mut dg = tx.send(b"important", now).expect("a path is free").bytes;
        let last = dg.len() - 1;
        dg[last] ^= 0x01; // one bit in the Poly1305 tag

        let events = rx.ingest(&dg, now);
        assert!(payloads(events).is_empty(), "nothing reaches the inner stack");
        assert_eq!(rx.counters().delivered, 0);
        assert_eq!(rx.counters().auth_failed, 1, "and the refusal is visible in telemetry");
        assert_eq!(rx.counters().dropped, 1);
        assert_eq!(rx.sessions(), 0, "an unauthenticated frame cannot allocate a session");
    }

    #[test]
    fn rekey_produces_a_different_key_and_old_frames_fail() {
        let c = cipher();
        let rekeyed = c.rekey().expect("rekey must succeed");
        assert_ne!(c.key_bytes(), rekeyed.key_bytes(), "rekey must change the key");
        assert_eq!(c.salt(), rekeyed.salt(), "salt stays bound to transcript");

        let header = [0u8; HEADER_LEN];
        let mut sealed_old = Vec::new();
        c.seal(0, 0, &header, b"old", &mut sealed_old);
        assert!(rekeyed.open(0, 0, &header, &sealed_old).is_none(), "old key cannot open new key's frames and vice versa");
        let mut sealed_new = Vec::new();
        rekeyed.seal(0, 0, &header, b"new", &mut sealed_new);
        assert!(c.open(0, 0, &header, &sealed_new).is_none());
        assert_eq!(rekeyed.open(0, 0, &header, &sealed_new).unwrap(), b"new");
    }

    #[test]
    fn rekey_is_one_way() {
        // Derive two rekeys from same old key, they must be deterministic and
        // different from old, but same new key each time.
        let c = cipher();
        let r1 = c.rekey().unwrap();
        let r2 = c.rekey().unwrap();
        assert_eq!(r1.key_bytes(), r2.key_bytes(), "rekey is deterministic");
        let r3 = r1.rekey().unwrap();
        assert_ne!(r1.key_bytes(), r3.key_bytes(), "second rekey changes again");
    }

    #[test]
    fn transport_keys_rekey() {
        let keys = crate::TransportKeys {
            send: [0x11u8; 32],
            recv: [0x22u8; 32],
            handshake_hash: [0x33u8; 32],
        };
        let rekeyed = keys.rekey().expect("rekey");
        assert_ne!(keys.send, rekeyed.send);
        assert_ne!(keys.recv, rekeyed.recv);
        assert_eq!(keys.handshake_hash, rekeyed.handshake_hash);
        assert_eq!(keys.salt(), rekeyed.salt(), "salt stays bound to original transcript");
    }
}
