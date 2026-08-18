// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// PAIRING — authenticates the QR sync channel.
//
// Satsmail's only transport is the camera: every sync QR is just pixels, and
// there is no way to tell a payload that came from your box from one that came
// from a fake page on the phone. This module closes that gap:
//
//   * The box generates a 32-byte random secret and shows it as a
//     `satsmail-pair:<hex>` QR on its /pair page.
//   * You scan it once; the secret is stored in the app's encrypted AppData
//     directory (fs::Location::AppData, `<encrypted>/appdata/<app-id>/`).
//   * Every sync payload after that carries an HMAC-SHA256 tag over the
//     canonical JSON (key = pairing secret). The Prime recomputes it and
//     refuses anything that doesn't match.
//
// Once paired, sync is default-deny: an unauthenticated (or mis-authenticated)
// QR is rejected outright, so a compromised screen can't feed fake balances.
//
// The HMAC is hand-rolled on top of the existing `sha2` dependency (RFC 2104:
// H(K XOR opad || H(K XOR ipad || m))) so no new crate is needed and there is
// no cross-compile risk. Verified against the RFC 4231 test vector in the
// unit tests.

use crate::sync::QrSyncPayload;
use sha2::{Digest, Sha256};
use std::io::{Read, Write};

/// HMAC block size for SHA-256 (bytes).
const BLOCK: usize = 64;
/// The file the pairing secret lives in, inside the app's AppData dir.
const PAIR_FILE: &str = "pair.json";
/// Plain-text prefix the box's /pair QR encodes: `satsmail-pair:<hex>`.
pub const PAIR_PREFIX: &str = "satsmail-pair:";

/// The persisted pairing state.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Pairing {
    /// The shared secret, hex-encoded (64 chars). Decoded to raw bytes for the
    /// HMAC key.
    pub secret_hex: String,
    /// Highest `generated_at` seen so far — cheap replay guard. Sync payloads
    /// whose timestamp is older than this are rejected.
    #[serde(default)]
    pub last_generated_at: i64,
}

impl Pairing {
    /// The raw HMAC key bytes.
    pub fn key(&self) -> Vec<u8> {
        hex::decode(&self.secret_hex).unwrap_or_default()
    }
}

/// Why a sync payload failed authentication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// No pairing secret stored — the device has never paired with a box.
    NotPaired,
    /// The payload carries no HMAC tag (old companion / fake QR).
    MissingTag,
    /// The HMAC tag doesn't match the payload (fake or tampered QR).
    BadTag,
    /// `generated_at` is older than the newest sync already applied — replay.
    Stale,
}

/// Load the pairing secret from AppData, if any.
///
/// `fs::Location::AppData` is the app's own encrypted RW directory
/// (`<encrypted>/appdata/<app-id>/`) and needs no extra permission — unlike
/// the airlock, which the host locks while plugged in.
pub fn load_pairing() -> Option<Pairing> {
    let filesystem = crate::FileSystem::default();
    let mut file = filesystem
        .open_file(PAIR_FILE.to_string(), fs::Location::AppData, fs::OpenFlags::READ_ONLY)
        .ok()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Store (or replace) the pairing secret and reset the replay counter.
pub fn save_pairing(secret_hex: &str) -> Result<(), fs::Error> {
    let pairing = Pairing { secret_hex: secret_hex.to_string(), last_generated_at: 0 };
    let filesystem = crate::FileSystem::default();
    let mut file = filesystem
        .open_file(PAIR_FILE.to_string(), fs::Location::AppData, fs::OpenFlags::CREATE)?;
    let json = serde_json::to_vec(&pairing).unwrap_or_default();
    file.write_all(&json)?;
    let _ = file.truncate();
    let _ = file.flush();
    Ok(())
}

/// Remove the pairing secret entirely.
pub fn clear_pairing() -> Result<(), fs::Error> {
    let filesystem = crate::FileSystem::default();
    filesystem.remove(PAIR_FILE.to_string(), fs::Location::AppData)
}

/// Persist a new `generated_at` high-water mark (best-effort).
pub fn bump_last_generated_at(ts: i64) {
    if let Some(mut p) = load_pairing() {
        if ts > p.last_generated_at {
            p.last_generated_at = ts;
            let filesystem = crate::FileSystem::default();
            if let Ok(mut file) = filesystem
                .open_file(PAIR_FILE.to_string(), fs::Location::AppData, fs::OpenFlags::CREATE)
            {
                if let Ok(json) = serde_json::to_vec(&p) {
                    let _ = file.write_all(&json);
                    let _ = file.truncate();
                    let _ = file.flush();
                }
            }
        }
    }
}

/// HMAC-SHA256 (RFC 2104), hand-rolled on the existing `sha2` crate.
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    // Hash the key down to one block if it's longer than the block size.
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k[..32].copy_from_slice(&digest);
    } else {
        k[..key.len()].copy_from_slice(key);
    }

    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5cu8; BLOCK];
    for (i, byte) in k.iter().enumerate() {
        ipad[i] ^= byte;
        opad[i] ^= byte;
    }

    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_digest = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    outer.finalize().into()
}

/// Constant-time byte comparison (no early exit on the first mismatch).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Canonical bytes to authenticate: the payload re-serialized WITHOUT its
/// `hmac` tag. The box signs exactly this (same struct field order, serde_json
/// emits in declaration order) and the device re-derives it after
/// deserialization, so the two sides agree byte-for-byte.
fn canonical_bytes(payload: &QrSyncPayload) -> Vec<u8> {
    let mut clone = payload.clone();
    clone.hmac = None;
    serde_json::to_vec(&clone).unwrap_or_default()
}

/// Authenticate a sync payload against a pairing (pure — no fs access).
///
/// * No tag / bad tag    → Err(MissingTag|BadTag) — fake or tampered QR
/// * generated_at stale  → Err(Stale)             — replayed old payload
/// * all good            → Ok(())
pub fn verify_sync_with(pairing: &Pairing, payload: &QrSyncPayload) -> Result<(), AuthError> {
    let Some(tag) = &payload.hmac else {
        return Err(AuthError::MissingTag);
    };

    if payload.generated_at < pairing.last_generated_at {
        return Err(AuthError::Stale);
    }

    let expected = hmac_sha256(&pairing.key(), &canonical_bytes(payload));
    let got = hex::decode(tag).map_err(|_| AuthError::BadTag)?;
    if !constant_time_eq(&expected, &got) {
        return Err(AuthError::BadTag);
    }
    Ok(())
}

/// Authenticate a sync payload against the stored pairing.
///
/// * Not paired          → Err(NotPaired)   (default-deny — the caller shows
///                                           "pair with box first")
/// * otherwise           → see `verify_sync_with`; on success the replay
///                         high-water mark is bumped
pub fn verify_sync(payload: &QrSyncPayload) -> Result<(), AuthError> {
    let Some(pairing) = load_pairing() else {
        return Err(AuthError::NotPaired);
    };
    verify_sync_with(&pairing, payload)?;
    bump_last_generated_at(payload.generated_at);
    Ok(())
}

/// True when a pairing secret is stored (drives the "paired" UI state).
pub fn is_paired() -> bool {
    load_pairing().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_matches_rfc4231_case_1() {
        // RFC 4231 test case 1: key = 0x0b * 20, data = "Hi There".
        let key = [0x0bu8; 20];
        let msg = b"Hi There";
        let expected =
            hex::decode("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
                .unwrap();
        assert_eq!(hmac_sha256(&key, msg).to_vec(), expected);
    }

    #[test]
    fn hmac_matches_rfc4231_case_2() {
        // key = "Jefe", data = "what do ya want for nothing?".
        let key: &[u8] = b"Jefe";
        let msg: &[u8] = b"what do ya want for nothing?";
        let expected =
            hex::decode("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
                .unwrap();
        assert_eq!(hmac_sha256(&key, msg).to_vec(), expected);
    }

    #[test]
    fn canonical_round_trip_is_byte_stable() {
        // The exact canonical JSON the companion signs (key order follows the
        // Rust struct declaration order): parse → strip hmac → re-serialize
        // must reproduce the bytes the box signed.
        let json = r#"{"balance_sats":123456,"generated_at":1787000000,"mails":[{"subject":"receive btc","amount":"+0.005","detail":"from bc1q…","status":"[3 confirmations]","fresh":false,"block_time":1786999000}],"utxos":[{"txid":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","vout":0,"script_hex":"5120aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899","value_sats":500000,"confirmed":true}],"fee_rates":{"low":1,"medium":3,"high":8},"broadcast_base":"http://192.168.0.14:8081/broadcast"}"#;
        let payload: QrSyncPayload = serde_json::from_str(json).unwrap();
        assert!(payload.hmac.is_none());
        // The re-serialized canonical bytes must be byte-identical to what the
        // box signed. Verify against the Node-side reference tag generated for
        // EXACTLY this JSON with secret 0b0b0b…0b (RFC 4231 key) — if the
        // canonical re-serialization drifted a single byte, the HMAC wouldn't
        // match.
        let key = [0x0bu8; 32];
        let tag = hex::encode(hmac_sha256(&key, &canonical_bytes(&payload)));
        // Reference tag computed by Node's crypto.createHmac over EXACTLY the
        // canonical JSON above with key 0x0b*32 (see the companion's signing
        // path). If canonical_bytes() ever re-serialized a single byte
        // differently, this assertion fails.
        assert_eq!(
            tag,
            "080b0d7fb45fd0d6360e2c48c699a4e57f73a409a0f8917e47e6f72eb4a94452"
        );
    }

    #[test]
    fn verify_rejects_bad_tag_and_stale() {
        let secret = hex::encode([0x0bu8; 32]);
        let pairing = Pairing { secret_hex: secret, last_generated_at: 0 };

        // A valid payload signed the way the box signs it.
        let canonical = r#"{"balance_sats":1,"generated_at":1787000001,"mails":[],"utxos":[],"fee_rates":{"low":1,"medium":3,"high":8},"broadcast_base":"http://127.0.0.1:8081/broadcast"}"#;
        let good_tag = hex::encode(hmac_sha256(&pairing.key(), canonical.as_bytes()));
        let good: QrSyncPayload =
            serde_json::from_str(&format!(r#"{{"balance_sats":1,"generated_at":1787000001,"mails":[],"utxos":[],"fee_rates":{{"low":1,"medium":3,"high":8}},"broadcast_base":"http://127.0.0.1:8081/broadcast","hmac":"{good_tag}"}}"#)).unwrap();
        assert_eq!(verify_sync_with(&pairing, &good), Ok(()));

        // Tamper with the balance → the tag no longer matches.
        let tampered: QrSyncPayload =
            serde_json::from_str(&format!(r#"{{"balance_sats":999,"generated_at":1787000001,"mails":[],"utxos":[],"fee_rates":{{"low":1,"medium":3,"high":8}},"broadcast_base":"http://127.0.0.1:8081/broadcast","hmac":"{good_tag}"}}"#)).unwrap();
        assert_eq!(verify_sync_with(&pairing, &tampered), Err(AuthError::BadTag));

        // A missing tag is its own error.
        let no_tag: QrSyncPayload = serde_json::from_str(canonical).unwrap();
        assert_eq!(verify_sync_with(&pairing, &no_tag), Err(AuthError::MissingTag));

        // A replayed (older) payload is rejected even with a valid tag.
        // Equality is allowed (re-scanning the same payload), strictly older
        // is a replay.
        let pairing2 = Pairing { secret_hex: hex::encode([0x0bu8; 32]), last_generated_at: 1787000002 };
        assert_eq!(verify_sync_with(&pairing2, &good), Err(AuthError::Stale));
        let pairing3 = Pairing { secret_hex: hex::encode([0x0bu8; 32]), last_generated_at: 1787000001 };
        assert_eq!(verify_sync_with(&pairing3, &good), Ok(()));
    }
}
