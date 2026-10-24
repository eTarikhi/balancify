//! Session establishment: a first-party implementation of the `Noise_IK`
//! handshake pattern over X25519, ChaCha20-Poly1305 and BLAKE2s.
//!
//! Why this pattern (Sec.9.2): the client pins the relay's identity key at
//! provisioning, which is exactly `IK`'s pre-message -- the initiator knows the
//! responder's static key before the first flight. That buys, in two messages:
//!
//! * **responder authentication** from the pinned key (a man-in-the-middle
//!   cannot complete the handshake without it),
//! * **initiator authentication**, because the initiator's static key is sent
//!   encrypted and covered by the transcript,
//! * **forward secrecy**, because both ephemerals are fresh per session and the
//!   transport keys are derived from the ephemeral-ephemeral DH,
//! * **channel binding**, via the handshake hash, which is what the tunnel
//!   nonce salt is taken from.
//!
//! The implementation follows the Noise specification's `SymmetricState`
//! definitions directly (Sec.5.2: `MixKey`, `MixHash`, `EncryptAndHash`,
//! `DecryptAndHash`, `Split`) and the `IK` message patterns (Sec.7.4). Note that
//! `MixKeyAndHash` is *not* used here: the specification reserves it for the
//! `psk` modifier, and this is the plain `IK` pattern.
//!
//! # What is deliberately not here
//!
//! * **Key storage and generation.** Secrets arrive as `[u8; 32]` arguments,
//!   including the ephemeral. That keeps this module sans-I/O and deterministic
//!   under test; the service sources ephemeral bytes from the platform CSPRNG
//!   and static keys from the DPAPI/TPM store (Sec.9.2).
//! * **A replay cache.** Freshness comes from the ephemerals; nothing here
//!   rejects a captured first flight being replayed at a *new* responder
//!   session, which is a session-management concern, not a key-agreement one.
//! * **Post-handshake rekeying.** Noise's `Rekey()` is not implemented; keys
//!   rotate per session because each session performs a fresh handshake.

use chacha20poly1305::{
    aead::{Aead, Payload},
    ChaCha20Poly1305, KeyInit,
};

use crate::{TunnelCipher, KEY_LEN, SALT_LEN};

/// `Noise_IK_25519_ChaChaPoly_BLAKE2s`. Longer than BLAKE2s's 32-byte output,
/// so `InitializeSymmetric` hashes it rather than padding it (Sec.5.2).
pub const PROTOCOL_NAME: &[u8] = b"Noise_IK_25519_ChaChaPoly_BLAKE2s";

const HASH_LEN: usize = 32;
const DH_LEN: usize = 32;
const TAG_LEN: usize = 16;
/// Handshake messages use nonce zero: the key changes after every `MixKey`, so
/// the counter never advances past zero (Sec.5.1).
const ZERO_NONCE: [u8; 12] = [0u8; 12];

/// The first flight is `e || EncryptAndHash(s) || EncryptAndHash(payload)`.
pub const MSG1_MIN_LEN: usize = DH_LEN + DH_LEN + TAG_LEN + TAG_LEN;
/// The second flight is `e || EncryptAndHash(payload)`.
pub const MSG2_MIN_LEN: usize = DH_LEN + TAG_LEN;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The message is shorter than the pattern requires.
    Truncated,
    /// The AEAD tag did not verify: wrong pinned key, tampering, or a message
    /// from a different session.
    AuthFailed,
    /// The caller read or wrote flights out of order.
    BadOrder,
}

/// The result of a completed handshake, from one side's point of view.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransportKeys {
    /// Key for frames this side sends.
    pub send: [u8; KEY_LEN],
    /// Key for frames this side receives.
    pub recv: [u8; KEY_LEN],
    /// The handshake hash, for channel binding (Sec.11.2).
    pub handshake_hash: [u8; HASH_LEN],
}

impl TransportKeys {
    /// The nonce salt for the tunnel cipher. Taken from the handshake hash so
    /// that transport nonces are bound to this transcript: reusing a key in a
    /// different session would not reuse a nonce.
    pub fn salt(&self) -> [u8; SALT_LEN] {
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&self.handshake_hash[..SALT_LEN]);
        salt
    }

    /// A [`TunnelCipher`] for the sending direction.
    pub fn send_cipher(&self) -> Option<TunnelCipher> { TunnelCipher::new(&self.send, self.salt()) }

    /// A [`TunnelCipher`] for the receiving direction.
    pub fn recv_cipher(&self) -> Option<TunnelCipher> { TunnelCipher::new(&self.recv, self.salt()) }

    /// Derive next keys for both directions. This is only a KDF operation; it
    /// does not notify or synchronize a peer. Live sessions must coordinate
    /// activation of the returned keys. The handshake hash remains unchanged,
    /// so the nonce salt stays bound to the original transcript.
    pub fn rekey(&self) -> Option<Self> {
        let send = {
            let mut okm = [0u8; KEY_LEN];
            hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(&[0u8; 32]), &self.send)
                .expand(b"balancify rekey v1 send", &mut okm)
                .ok()?;
            okm
        };
        let recv = {
            let mut okm = [0u8; KEY_LEN];
            hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(&[0u8; 32]), &self.recv)
                .expand(b"balancify rekey v1 recv", &mut okm)
                .ok()?;
            okm
        };
        Some(Self { send, recv, handshake_hash: self.handshake_hash })
    }
}

/// `SymmetricState` (spec Sec.5.2): a chaining key, a transcript hash, and an
/// optional AEAD key that is reset to empty by every `MixKey`.
struct SymmetricState {
    ck: [u8; HASH_LEN],
    h: [u8; HASH_LEN],
    k: Option<[u8; KEY_LEN]>,
}

impl SymmetricState {
    fn new(protocol_name: &[u8]) -> Self {
        use blake2::Digest;
        // Longer than HASHLEN, so h = HASH(protocol_name); ck = h; key empty.
        let h: [u8; HASH_LEN] = blake2::Blake2s256::digest(protocol_name).into();
        Self { ck: h, h, k: None }
    }

    fn mix_hash(&mut self, data: &[u8]) {
        use blake2::Digest;
        let mut hasher = blake2::Blake2s256::new();
        hasher.update(self.h);
        hasher.update(data);
        self.h = hasher.finalize().into();
    }

    /// `MixKey`: `ck, temp_k = HKDF(ck, ikm, 2)`, then re-key with `temp_k`.
    /// Blake2s's core uses a lazy buffer, so `Hmac<Blake2s256>` does not satisfy
    /// the `Eager` bound; `SimpleHmac` is the `no_std`-compatible workaround and
    /// is what `snow` and similar Noise implementations use for this hash.
    fn mix_key(&mut self, ikm: &[u8]) {
        let mut okm = [0u8; 2 * KEY_LEN];
        hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(&self.ck), ikm)
            .expand(b"", &mut okm)
            .unwrap_or_else(|_| okm.fill(0)); // 64 bytes is always a valid length
        self.ck.copy_from_slice(&okm[..KEY_LEN]);
        let mut k = [0u8; KEY_LEN];
        k.copy_from_slice(&okm[KEY_LEN..]);
        self.k = Some(k);
    }

    fn encrypt_and_hash(&mut self, plain: &[u8]) -> Vec<u8> {
        let out = match self.k {
            // A 32-byte key cannot be rejected and this AEAD has no length
            // limit, so the None arms are unreachable; emitting nothing fails
            // closed, where emitting the plaintext would not.
            Some(key) => seal(&key, plain, &self.h).unwrap_or_default(),
            None => plain.to_vec(), // no key yet: EncryptWithAd is the identity
        };
        self.mix_hash(&out);
        out
    }

    fn decrypt_and_hash(&mut self, cipher: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        let plain = match self.k {
            Some(key) => match open(&key, cipher, &self.h) {
                Some(p) => p,
                None => return Err(HandshakeError::AuthFailed),
            },
            None => cipher.to_vec(), // no key yet: DecryptWithAd is the identity
        };
        self.mix_hash(cipher);
        Ok(plain)
    }

    /// `Split`: `temp_k1, temp_k2 = HKDF(ck, zerolen, 2)`.
    fn split(&self) -> ([u8; KEY_LEN], [u8; KEY_LEN]) {
        let mut okm = [0u8; 2 * KEY_LEN];
        hkdf::SimpleHkdf::<blake2::Blake2s256>::new(Some(&self.ck), b"")
            .expand(b"", &mut okm)
            .unwrap_or_else(|_| okm.fill(0));
        let mut k1 = [0u8; KEY_LEN];
        let mut k2 = [0u8; KEY_LEN];
        k1.copy_from_slice(&okm[..KEY_LEN]);
        k2.copy_from_slice(&okm[KEY_LEN..]);
        (k1, k2)
    }

    fn keys(&self, initiator: bool) -> TransportKeys {
        let (k1, k2) = self.split();
        // c1 encrypts initiator-to-responder, c2 the other way (Sec.5.2).
        let (send, recv) = if initiator { (k1, k2) } else { (k2, k1) };
        TransportKeys { send, recv, handshake_hash: self.h }
    }
}

fn dh(secret: &x25519_dalek::StaticSecret, public: &x25519_dalek::PublicKey) -> [u8; DH_LEN] {
    *secret.diffie_hellman(public).as_bytes()
}

/// The handshake nonce. Handshake keys are replaced by every `MixKey`, so the
/// CipherState counter never advances (Sec.5.1) and the nonce is always zero.
fn zero_nonce() -> Option<chacha20poly1305::Nonce> {
    chacha20poly1305::Nonce::try_from(&ZERO_NONCE[..]).ok()
}

fn seal(key: &[u8; KEY_LEN], plain: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let nonce = zero_nonce()?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.encrypt(&nonce, Payload { msg: plain, aad }).ok()
}

fn open(key: &[u8; KEY_LEN], ciphertext: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    let nonce = zero_nonce()?;
    let cipher = ChaCha20Poly1305::new_from_slice(key).ok()?;
    cipher.decrypt(&nonce, Payload { msg: ciphertext, aad }).ok()
}

// ------------------------------------------------------------------ initiator

/// The client side: it knows the responder's static key in advance (pinned at
/// provisioning, Sec.9.2) and proves its own identity in the first flight.
pub struct Initiator {
    state: SymmetricState,
    s: x25519_dalek::StaticSecret,
    rs: x25519_dalek::PublicKey,
    e: Option<x25519_dalek::StaticSecret>,
    written: bool,
    done: bool,
}

impl std::fmt::Debug for Initiator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Initiator").field("written", &self.written).field("done", &self.done).finish()
    }
}

impl Initiator {
    /// `responder_static` is the pinned identity of the peer. Getting it wrong
    /// is not a configuration nuisance: the handshake will not complete.
    pub fn new(
        static_secret: [u8; 32],
        responder_static: [u8; 32],
        prologue: &[u8],
    ) -> Self {
        let s = x25519_dalek::StaticSecret::from(static_secret);
        let rs = x25519_dalek::PublicKey::from(responder_static);
        let mut state = SymmetricState::new(PROTOCOL_NAME);
        state.mix_hash(prologue);
        // The pre-message is the responder's static key: both sides hash it.
        state.mix_hash(rs.as_bytes());
        Self { state, s, rs, e: None, written: false, done: false }
    }

    /// Same as `new`, but checks that `responder_static` is in `pinned` if
    /// `pinned` is non-empty. Returns `AuthFailed` if not pinned.
    pub fn new_checked(
        static_secret: [u8; 32],
        responder_static: [u8; 32],
        prologue: &[u8],
        pinned: Option<&crate::keys::PinnedKeys>,
    ) -> Result<Self, HandshakeError> {
        if let Some(pinned) = pinned {
            if !pinned.is_empty() && !pinned.is_pinned(&responder_static) {
                return Err(HandshakeError::AuthFailed);
            }
        }
        Ok(Self::new(static_secret, responder_static, prologue))
    }

    /// Flight 1: `e, es, s, ss` then the encrypted payload.
    pub fn write_message(&mut self, ephemeral_secret: [u8; 32], payload: &[u8]) -> Vec<u8> {
        let e = x25519_dalek::StaticSecret::from(ephemeral_secret);
        let e_public = x25519_dalek::PublicKey::from(&e);

        let mut out = Vec::with_capacity(MSG1_MIN_LEN + payload.len());
        out.extend_from_slice(e_public.as_bytes());
        self.state.mix_hash(e_public.as_bytes());
        self.state.mix_key(&dh(&e, &self.rs)); // es

        let s_public = x25519_dalek::PublicKey::from(&self.s);
        out.extend_from_slice(&self.state.encrypt_and_hash(s_public.as_bytes()));
        self.state.mix_key(&dh(&self.s, &self.rs)); // ss
        out.extend_from_slice(&self.state.encrypt_and_hash(payload));

        self.e = Some(e);
        self.written = true;
        out
    }

    /// Flight 2: `e, ee, se`, returning the peer's payload and the transport
    /// keys.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(Vec<u8>, TransportKeys), HandshakeError> {
        if !self.written || self.done {
            return Err(HandshakeError::BadOrder);
        }
        if message.len() < MSG2_MIN_LEN {
            return Err(HandshakeError::Truncated);
        }
        let e = self.e.as_ref().ok_or(HandshakeError::BadOrder)?;

        let re = x25519_dalek::PublicKey::from(<[u8; DH_LEN]>::try_from(&message[..DH_LEN]).map_err(|_| HandshakeError::Truncated)?);
        self.state.mix_hash(re.as_bytes());
        self.state.mix_key(&dh(e, &re)); // ee
        self.state.mix_key(&dh(&self.s, &re)); // se

        let payload = self.state.decrypt_and_hash(&message[DH_LEN..])?;
        self.done = true;
        Ok((payload, self.state.keys(true)))
    }
}

// ------------------------------------------------------------------ responder

/// The relay/server side. It publishes its static key for pinning and learns
/// the initiator's identity from the first flight.
pub struct Responder {
    state: SymmetricState,
    s: x25519_dalek::StaticSecret,
    rs: Option<x25519_dalek::PublicKey>,
    /// The initiator's ephemeral, from flight 1; flight 2's `ee` needs it.
    re: Option<x25519_dalek::PublicKey>,
    read_first: bool,
    done: bool,
}

impl std::fmt::Debug for Responder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Responder").field("read_first", &self.read_first).field("done", &self.done).finish()
    }
}

impl Responder {
    pub fn new(static_secret: [u8; 32], prologue: &[u8]) -> Self {
        let s = x25519_dalek::StaticSecret::from(static_secret);
        let s_public = x25519_dalek::PublicKey::from(&s);
        let mut state = SymmetricState::new(PROTOCOL_NAME);
        state.mix_hash(prologue);
        // The same pre-message the initiator hashed: this side's own static key.
        state.mix_hash(s_public.as_bytes());
        Self { state, s, rs: None, re: None, read_first: false, done: false }
    }

    /// The static key to publish for pinning.
    pub fn public_key(&self) -> [u8; DH_LEN] { *x25519_dalek::PublicKey::from(&self.s).as_bytes() }

    /// The initiator's identity, available only once the first flight has
    /// verified. This is the hook for pinning clients as well as relays.
    pub fn peer_static(&self) -> Option<[u8; DH_LEN]> { self.rs.map(|k| *k.as_bytes()) }

    /// The initiator's ephemeral public, available after flight 1. Used for
    /// replay cache.
    pub fn peer_ephemeral(&self) -> Option<[u8; DH_LEN]> { self.re.map(|k| *k.as_bytes()) }

    /// Read flight 1 (`e, es, s, ss`), returning the initiator's payload.
    pub fn read_message(&mut self, message: &[u8]) -> Result<Vec<u8>, HandshakeError> {
        if self.read_first || self.done {
            return Err(HandshakeError::BadOrder);
        }
        if message.len() < MSG1_MIN_LEN {
            return Err(HandshakeError::Truncated);
        }
        let re = x25519_dalek::PublicKey::from(
            <[u8; DH_LEN]>::try_from(&message[..DH_LEN]).map_err(|_| HandshakeError::Truncated)?,
        );
        self.state.mix_hash(re.as_bytes());
        // es, responder side: DH(s, re).
        self.state.mix_key(&dh(&self.s, &re));

        // The initiator's static key, encrypted under a key that only the holder
        // of the pinned identity could have derived.
        let static_len = DH_LEN + TAG_LEN;
        if message.len() < DH_LEN + static_len + TAG_LEN {
            return Err(HandshakeError::Truncated);
        }
        let rs_bytes = self.state.decrypt_and_hash(&message[DH_LEN..DH_LEN + static_len])?;
        let rs = x25519_dalek::PublicKey::from(
            <[u8; DH_LEN]>::try_from(rs_bytes.as_slice()).map_err(|_| HandshakeError::AuthFailed)?,
        );
        // ss.
        self.state.mix_key(&dh(&self.s, &rs));

        let payload = self.state.decrypt_and_hash(&message[DH_LEN + static_len..])?;
        self.rs = Some(rs);
        self.re = Some(re);
        self.read_first = true;
        Ok(payload)
    }

    /// Read flight 1 with pinning and replay checks. If `pinned` is non-empty,
    /// the initiator's static must be in it. If `replay_cache` is Some, the
    /// ephemeral public is checked for replay.
    pub fn read_message_checked(
        &mut self,
        message: &[u8],
        pinned: Option<&crate::keys::PinnedKeys>,
        replay_cache: Option<&mut crate::replay::ReplayCache>,
        now: Option<std::time::Instant>,
    ) -> Result<Vec<u8>, HandshakeError> {
        let payload = self.read_message(message)?;

        // After verification, check pinning.
        if let Some(pinned) = pinned {
            if !pinned.is_empty() {
                if let Some(peer) = self.peer_static() {
                    if !pinned.is_pinned(&peer) {
                        return Err(HandshakeError::AuthFailed);
                    }
                } else {
                    return Err(HandshakeError::AuthFailed);
                }
            }
        }

        // Check replay cache: if ephemeral was seen recently, reject.
        if let (Some(cache), Some(now)) = (replay_cache, now) {
            if let Some(eph) = self.peer_ephemeral() {
                if cache.check_and_insert(eph, now) {
                    return Err(HandshakeError::AuthFailed);
                }
            }
        }

        Ok(payload)
    }

    /// Write flight 2 (`e, ee, se`), returning the frame to send and the
    /// transport keys.
    pub fn write_message(
        &mut self,
        ephemeral_secret: [u8; 32],
        payload: &[u8],
    ) -> Result<(Vec<u8>, TransportKeys), HandshakeError> {
        if !self.read_first || self.done {
            return Err(HandshakeError::BadOrder);
        }
        let re = self.re.ok_or(HandshakeError::BadOrder)?;
        let rs = self.rs.ok_or(HandshakeError::BadOrder)?;
        let e = x25519_dalek::StaticSecret::from(ephemeral_secret);
        let e_public = x25519_dalek::PublicKey::from(&e);

        let mut out = Vec::with_capacity(MSG2_MIN_LEN + payload.len());
        out.extend_from_slice(e_public.as_bytes());
        self.state.mix_hash(e_public.as_bytes());
        // ee.
        self.state.mix_key(&dh(&e, &re));
        // se, responder side: DH(e, rs).
        self.state.mix_key(&dh(&e, &rs));
        out.extend_from_slice(&self.state.encrypt_and_hash(payload));

        self.done = true;
        Ok((out, self.state.keys(false)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use balancify_tunnel::{Event, Receiver, Sender};
    use std::time::{Duration, Instant};

    const INIT_STATIC: [u8; 32] = [0x11u8; 32];
    const INIT_EPH: [u8; 32] = [0x22u8; 32];
    const RESP_STATIC: [u8; 32] = [0x33u8; 32];
    const RESP_EPH: [u8; 32] = [0x44u8; 32];
    const PROLOGUE: &[u8] = b"balancify session 7";

    /// The public half of a secret, i.e. what a peer actually pins.
    fn public_of(secret: [u8; 32]) -> [u8; 32] {
        let s = x25519_dalek::StaticSecret::from(secret);
        *x25519_dalek::PublicKey::from(&s).as_bytes()
    }

    fn pair() -> (Initiator, Responder) {
        (
            Initiator::new(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE),
            Responder::new(RESP_STATIC, PROLOGUE),
        )
    }

    fn complete() -> (TransportKeys, TransportKeys) {
        let (mut i, mut r) = pair();
        let m1 = i.write_message(INIT_EPH, b"client says hello");
        let p1 = r.read_message(&m1).expect("flight 1 verifies");
        assert_eq!(p1, b"client says hello");
        let (m2, resp) = r.write_message(RESP_EPH, b"relay says hello").expect("flight 2");
        let (p2, init) = i.read_message(&m2).expect("flight 2 verifies");
        assert_eq!(p2, b"relay says hello");
        (init, resp)
    }

    #[test]
    fn both_sides_derive_the_same_two_transport_keys() {
        let (init, resp) = complete();
        assert_eq!(init.send, resp.recv, "what the client sends, the relay receives");
        assert_eq!(init.recv, resp.send, "and the reverse");
        assert_ne!(init.send, init.recv, "the two directions must not share a key");
        assert_eq!(init.handshake_hash, resp.handshake_hash, "channel binding agrees");
    }

    #[test]
    fn the_pinned_identity_is_what_authenticates_the_relay() {
        // The client pins the wrong relay key: flight 1 still goes out (it cannot
        // know better), but the relay rejects it, because es and ss differ.
        let bogus = public_of([0x99u8; 32]);
        let mut i = Initiator::new(INIT_STATIC, bogus, PROLOGUE);
        let mut r = Responder::new(RESP_STATIC, PROLOGUE);
        let m1 = i.write_message(INIT_EPH, b"hello");
        assert_eq!(r.read_message(&m1), Err(HandshakeError::AuthFailed));
        assert_eq!(r.peer_static(), None, "no identity is learned from a bad flight");
    }

    #[test]
    fn every_part_of_the_first_flight_is_authenticated() {
        let (mut i, _) = pair();
        let m1 = i.write_message(INIT_EPH, b"abcd");
        assert!(m1.len() > 90, "the test must index real bytes");
        // One bit in the ephemeral, in the encrypted static, and in the payload.
        for idx in [0usize, 40, m1.len() - 1] {
            let mut tampered = m1.clone();
            tampered[idx] ^= 1;
            let mut r = Responder::new(RESP_STATIC, PROLOGUE);
            assert!(r.read_message(&tampered).is_err(), "byte {idx} went unnoticed");
        }
    }

    #[test]
    fn the_prologue_binds_the_handshake_to_its_context() {
        let mut i = Initiator::new(INIT_STATIC, public_of(RESP_STATIC), b"session A");
        let mut r = Responder::new(RESP_STATIC, b"session B");
        let m1 = i.write_message(INIT_EPH, b"hello");
        assert!(r.read_message(&m1).is_err(), "a mismatched prologue must not complete");
    }

    #[test]
    fn the_initiator_identity_travels_encrypted() {
        let (mut i, mut r) = pair();
        let m1 = i.write_message(INIT_EPH, b"hello");
        let init_public = public_of(INIT_STATIC);
        assert!(
            !m1.windows(32).any(|w| w == init_public),
            "the static key must never appear in the clear"
        );
        r.read_message(&m1).expect("flight 1 verifies");
        assert_eq!(r.peer_static(), Some(init_public), "and the relay still learns it");
    }

    #[test]
    fn a_fresh_ephemeral_gives_a_fresh_session() {
        let (mut i, _) = pair();
        let first = i.write_message(INIT_EPH, b"hello");
        let (mut i2, mut r2) = pair();
        let second = i2.write_message([0x55u8; 32], b"hello");
        assert_ne!(first, second, "reusing an ephemeral would reuse the nonce");

        let (_, keys_b) = {
            r2.read_message(&second).expect("flight 1 verifies");
            r2.write_message(RESP_EPH, b"hi").expect("flight 2")
        };
        let (_, keys_a) = {
            let mut r3 = Responder::new(RESP_STATIC, PROLOGUE);
            r3.read_message(&first).expect("flight 1 verifies");
            r3.write_message(RESP_EPH, b"hi").expect("flight 2")
        };
        assert_ne!(keys_a.send, keys_b.send, "different ephemerals, different transport keys");
        assert_ne!(keys_a.handshake_hash, keys_b.handshake_hash);
    }

    #[test]
    fn flights_out_of_order_are_refused() {
        let mut r = Responder::new(RESP_STATIC, PROLOGUE);
        assert_eq!(r.write_message(RESP_EPH, b"x").unwrap_err(), HandshakeError::BadOrder);
        let mut i = Initiator::new(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE);
        assert_eq!(i.read_message(&[0u8; MSG2_MIN_LEN]).unwrap_err(), HandshakeError::BadOrder);
    }

    #[test]
    fn short_messages_are_refused_rather_than_parsed() {
        let mut r = Responder::new(RESP_STATIC, PROLOGUE);
        for len in 0..MSG1_MIN_LEN {
            assert_eq!(r.read_message(&vec![0u8; len]), Err(HandshakeError::Truncated));
        }
        let mut i = Initiator::new(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE);
        i.write_message(INIT_EPH, b"x");
        for len in 0..MSG2_MIN_LEN {
            assert_eq!(i.read_message(&vec![0u8; len]), Err(HandshakeError::Truncated));
        }
    }

    #[test]
    fn the_transport_keys_drive_the_tunnel_lane() {
        let (init, resp) = complete();
        let mut tx = Sender::new(
            7,
            init.send_cipher().expect("a 32-byte key is valid"),
            vec![(0, 2000), (1, 2000)],
        );
        let mut rx = Receiver::with_defaults(resp.recv_cipher().expect("a 32-byte key is valid"));

        let now = Instant::now();
        let frame = tx.send(b"bonded traffic", now).expect("a path is free");
        let events = rx.ingest(&frame.bytes, now);
        assert!(
            events.iter().any(|e| matches!(e, Event::Payload { data, .. } if data == b"bonded traffic")),
            "the negotiated keys protect real frames: {events:?}"
        );
        assert_eq!(rx.counters().auth_failed, 0);

        // The opposite direction uses the other key, and only that one works.
        // A frame encrypted with `init.send` must not decrypt with `init.recv`
        // (which equals `resp.send`): different keys, same salt would otherwise
        // be nonce reuse if the keys were shared.
        let mut wrong = Receiver::with_defaults(init.recv_cipher().expect("key"));
        let frame2 = tx.send(b"more traffic", now).expect("a path is free");
        wrong.ingest(&frame2.bytes, now);
        assert_eq!(wrong.counters().delivered, 0, "a receiver holding the opposite direction key learns nothing");
        assert_eq!(wrong.counters().auth_failed, 1);
    }

    #[test]
    fn pinning_enforced_on_responder() {
        use crate::keys::PinnedKeys;
        let (mut i, _) = pair();
        let m1 = i.write_message(INIT_EPH, b"hello");

        // No pinning set => accepts any.
        let mut r2 = Responder::new(RESP_STATIC, PROLOGUE);
        assert!(r2.read_message_checked(&m1, None, None, None).is_ok());

        // Pin a different key => rejects.
        let mut pinned = PinnedKeys::new();
        pinned.pin([0x99u8; 32]);
        let mut r3 = Responder::new(RESP_STATIC, PROLOGUE);
        assert_eq!(
            r3.read_message_checked(&m1, Some(&pinned), None, None),
            Err(HandshakeError::AuthFailed)
        );

        // Pin the correct initiator key => accepts.
        let mut pinned2 = PinnedKeys::new();
        pinned2.pin(public_of(INIT_STATIC));
        let mut r4 = Responder::new(RESP_STATIC, PROLOGUE);
        assert!(r4.read_message_checked(&m1, Some(&pinned2), None, None).is_ok());
        assert_eq!(r4.peer_static(), Some(public_of(INIT_STATIC)));
    }

    #[test]
    fn replay_cache_rejects_second_flight() {
        use crate::replay::ReplayCache;
        let (mut i, _) = pair();
        let m1 = i.write_message(INIT_EPH, b"hello");
        let mut cache = ReplayCache::with_defaults();
        let now = Instant::now();

        let mut r1 = Responder::new(RESP_STATIC, PROLOGUE);
        assert!(r1.read_message_checked(&m1, None, Some(&mut cache), Some(now)).is_ok());
        assert_eq!(cache.len(), 1);

        // Same ephemeral again => replay.
        let mut r2 = Responder::new(RESP_STATIC, PROLOGUE);
        assert_eq!(
            r2.read_message_checked(&m1, None, Some(&mut cache), Some(now + Duration::from_secs(1))),
            Err(HandshakeError::AuthFailed)
        );
        assert_eq!(cache.len(), 1, "replay does not grow cache");
    }

    #[test]
    fn initiator_pinning_checked() {
        use crate::keys::PinnedKeys;
        let mut pinned = PinnedKeys::new();
        pinned.pin(public_of(RESP_STATIC));

        // Correct responder pinned => ok.
        assert!(Initiator::new_checked(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE, Some(&pinned)).is_ok());

        // Wrong responder not pinned => fails.
        let mut pinned2 = PinnedKeys::new();
        pinned2.pin([0x99u8; 32]);
        assert!(
            matches!(Initiator::new_checked(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE, Some(&pinned2)), Err(HandshakeError::AuthFailed))
        );

        // Empty pinned set => allows any (for bootstrapping).
        assert!(Initiator::new_checked(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE, Some(&PinnedKeys::new())).is_ok());
        assert!(Initiator::new_checked(INIT_STATIC, public_of(RESP_STATIC), PROLOGUE, None).is_ok());
    }
}
