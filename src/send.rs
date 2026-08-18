// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SEND — the "> send" flow, cold-storage style.
//
// 1. scan a PSBT (UR2 animated QR from the companion wallet) with the camera
// 2. verify it against OUR master key (ngwallet::psbt::validate checks every
//    input/output derivation, catches fraudulent keys, determines the network)
// 3. preview the recipients + fee like an email draft ("to:", "amount:", "fee:")
// 4. sign with the device keys (bdk wallet, trust_witness_utxo like the
//    bitcoin app)
// 5. export the signed PSBT as an animated UR2 QR for the companion to
//    broadcast — the device itself never touches the network
//
// Optionally, when the hosted simulator is connected to bwt, the signed tx can
// also be broadcast directly via Electrum.

use ngwallet::{
    bdk_wallet::{
        bitcoin::{
            bip32::Xpriv,
            secp256k1::Secp256k1,
            Address, Amount, FeeRate, Network, NetworkKind, Psbt, ScriptBuf, TxOut,
        },
        KeychainKind,
    },
    bip39::MasterKey,
    psbt::{self, TransactionDetails},
};
use std::str::FromStr;
use slint_keyos_platform::{
    qrcode::encode_qr_parts,
    slint::{ModelRc, SharedString},
};

/// The parsed + verified PSBT waiting on the user's confirmation.
#[derive(Debug, Clone)]
pub struct PendingPsbt {
    pub psbt: Psbt,
    pub details: TransactionDetails,
    pub network: Network,
}

/// Deserialize PSBT bytes and validate them against the master key.
pub fn verify(bytes: &[u8], master: &MasterKey) -> anyhow::Result<PendingPsbt> {
    let psbt = Psbt::deserialize(bytes)?;

    let network_kind = psbt::validate_network(&psbt)?;
    let network = match network_kind {
        Some(NetworkKind::Main) => Network::Bitcoin,
        Some(NetworkKind::Test) => Network::Testnet4,
        None => Network::Bitcoin,
    };

    let secp = Secp256k1::new();
    let xpriv: Xpriv = Xpriv::new_master(network, &master.key.0)?;
    let details = psbt::validate(&secp, &xpriv, &psbt, network)?;

    Ok(PendingPsbt { psbt, details, network })
}

/// Sign the pending PSBT with the device keys. Returns the signed serialized
/// bytes ready for QR export / broadcast.
pub fn sign(pending: &PendingPsbt, master: &MasterKey) -> anyhow::Result<Vec<u8>> {
    let mut psbt = pending.psbt.clone();
    let signed = crate::wallet::sign_psbt(pending.network, master, &mut psbt)?;
    if !signed {
        anyhow::bail!("no inputs signed — key mismatch?");
    }
    log::info!("satsmail: signed={signed} (any inputs signed)");
    Ok(psbt.serialize())
}

/// Encode signed PSBT bytes as animated UR2 parts for the export screen.
pub fn signed_ur_parts(signed: &[u8], density: i32) -> ModelRc<SharedString> {
    let bytes = minicbor_bytes(signed);
    encode_qr_parts("psbt", bytes, density)
}

/// Compute the txid of a signed PSBT — the receipt the box should report
/// back after broadcasting. The txid is just a hash of the serialized tx, so
/// the Prime can compute it WITHOUT any network: it's the ground truth the
/// box's receipt is checked against in the broadcast-receipt loop.
pub fn signed_txid(signed: &[u8]) -> anyhow::Result<String> {
    let psbt = Psbt::deserialize(signed)?;
    let tx = psbt.extract_tx()?;
    Ok(tx.compute_txid().to_string())
}

/// The change output of a pending tx, if any, with its derivation path.
///
/// Change-address proof: the change output (the leftover coming back to us)
/// is matched against OUR internal keychain and reported with its exact
/// derivation path (e.g. `m/86'/0'/0'/1/3`), so a paranoid user can
/// independently re-derive it in a descriptor tool and confirm nothing weird
/// happened. Finding the address by scanning our own keychain IS the
/// on-device verification — a change output that doesn't derive from our
/// seed can never match. Returns None for an exact spend (no change) or when
/// the change index is outside the lookahead window.
pub fn change_proof(
    network: Network,
    master: &MasterKey,
    pending: &PendingPsbt,
) -> Option<(String, String)> {
    let change_addr = pending.details.outputs.iter().find_map(|o| match &o.kind {
        ngwallet::psbt::OutputKind::Change(addr) => Some(addr.clone()),
        _ => None,
    })?;
    let script = change_addr.script_pubkey();
    let wallet = crate::wallet::build_wallet(network, master).ok()?;
    for i in 0..crate::wallet::LOOKAHEAD_INTERNAL {
        let addr = wallet.peek_address(KeychainKind::Internal, i);
        if addr.address.script_pubkey() == script {
            let coin: u32 = if network == Network::Bitcoin { 0 } else { 1 };
            let path = format!("m/86'/{coin}'/{}'/1/{i}", crate::wallet::ACCOUNT_INDEX);
            return Some((change_addr.to_string(), path));
        }
    }
    None
}

/// Parse a broadcast-receipt QR text:
/// `satsmail-receipt:<status>:<txid>[:<confirmations>]` where status is
/// `mempool` or `confirmed`. Returns (status, lowercase txid, confs).
pub fn parse_receipt(text: &str) -> Option<(String, String, Option<u32>)> {
    let rest = text.trim().strip_prefix("satsmail-receipt:")?;
    let mut parts = rest.split(':');
    let status = parts.next()?;
    if status != "mempool" && status != "confirmed" {
        return None;
    }
    let txid = parts.next()?;
    if txid.len() != 64 || !txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let confs = parts.next().and_then(|n| n.parse::<u32>().ok());
    Some((status.to_string(), txid.to_lowercase(), confs))
}

/// Extract the fully-signed transaction hex, for direct broadcast via Electrum.
pub fn extract_tx_hex(pending: &PendingPsbt, master: &MasterKey) -> anyhow::Result<String> {
    let mut psbt = pending.psbt.clone();
    let signed = crate::wallet::sign_psbt(pending.network, master, &mut psbt)?;
    if !signed {
        anyhow::bail!("no inputs signed — key mismatch?");
    }
    log::info!("satsmail: re-signed={signed} for broadcast");
    let tx = psbt.extract_tx()?;
    use ngwallet::bdk_wallet::bitcoin::consensus::encode;
    Ok(encode::serialize_hex(&tx))
}

/// Build a coldcard-style pushtx URL for a signed transaction hex:
/// `<base>#t=<base64url(tx)>&c=<checksum>`. The phone's camera scans the QR,
/// opens the URL, and the box's `/broadcast` page decodes it and submits it to
/// its own bitcoind (same pattern as QXXX's pushtx page).
///
/// `base` must end in `#`, `?` or `&` (the fragment separator is appended).
pub fn pushtx_url(tx_hex: &str, base: &str) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Digest;

    let raw = hex::decode(tx_hex).unwrap_or_default();
    let t = URL_SAFE_NO_PAD.encode(&raw);
    let digest = sha2::Sha256::digest(&raw);
    let c = URL_SAFE_NO_PAD.encode(&digest[24..]); // rightmost 8 bytes
    let sep = if base.contains('?') || base.contains('#') || base.contains('&') { "" } else { "#" };
    format!("{base}{sep}t={t}&c={c}")
}

/// Parse a pushtx URL back into the tx hex it carries, validating the checksum
/// (used by the box's /broadcast page; kept here for round-trip tests).
pub fn parse_pushtx_url(url: &str) -> Option<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use sha2::Digest;

    let rest = url.split_once('#')?.1;
    let mut t: Option<String> = None;
    let mut c: Option<Vec<u8>> = None;
    for kv in rest.split('&') {
        let (k, v) = kv.split_once('=')?;
        match k {
            "t" => t = Some(v.to_string()),
            "c" => c = URL_SAFE_NO_PAD.decode(v).ok(),
            _ => {}
        }
    }
    let t = t?;
    let raw = URL_SAFE_NO_PAD.decode(t).ok()?;
    let digest = sha2::Sha256::digest(&raw);
    if let Some(want) = c {
        if want.len() != 8 || digest[24..] != want[..] {
            return None;
        }
    }
    Some(hex::encode(raw))
}

// The signed PSBT is CBOR-wrapped the same way the bitcoin app exports it.
fn minicbor_bytes(bytes: &[u8]) -> Vec<u8> {
    let bv = minicbor::bytes::ByteVec::from(bytes.to_vec());
    minicbor::to_vec(bv).unwrap_or_else(|_| bytes.to_vec())
}

/// Human summary for the preview page.
pub fn preview_lines(p: &PendingPsbt) -> (String, String, String) {
    let mut to = String::new();
    for out in &p.details.outputs {
        if let ngwallet::psbt::OutputKind::External(addr) = &out.kind {
            to = addr.to_string();
            break;
        }
    }
    let amount = crate::fmt_sats(p.details.display_total().to_sat());
    let fee = crate::fmt_sats(p.details.fee.to_sat());
    (to, amount, fee)
}

/// A compose-send draft: build a transaction ON-DEVICE from a scanned address,
/// a user-typed amount + fee rate, and the UTXOs from the last sync. No PSBT
/// from a companion wallet is needed — the device builds it itself from the
/// synced wallet state (the "compose-send loophole").
#[derive(Debug, Clone)]
pub struct ComposeDraft {
    /// The scanned recipient address (bc1p… / bc1q… — any valid Bitcoin addr).
    pub to: String,
    /// Amount to send, in satoshis.
    pub amount_sats: u64,
    /// Fee rate, in sat/vB.
    pub fee_rate_sat_vb: u64,
    /// Our UTXOs from the last sync — the only inputs the tx may spend.
    pub utxos: Vec<crate::sync::QrUtxo>,
}

/// Build + validate a PSBT from a compose draft, entirely on-device.
///
/// UTXOs are inserted into the bdk wallet's txout cache so coin selection can
/// see them; the tx is then built with `build_tx()` (bdk picks inputs to cover
/// amount + fee, change goes back to our own internal keychain). The result is
/// a `PendingPsbt` like the scanned-PSBT path, so the existing verify/preview/
/// sign machinery is reused unchanged.
pub fn build_compose(network: Network, master: &MasterKey, draft: &ComposeDraft) -> anyhow::Result<PendingPsbt> {
    let mut wallet = crate::wallet::build_wallet(network, master)?;

    // Feed the synced UTXOs into the wallet's txout cache.
    for u in &draft.utxos {
        let outpoint = format!("{}:{}", u.txid, u.vout)
            .parse()
            .map_err(|e| anyhow::anyhow!("bad outpoint {}:{}: {e}", u.txid, u.vout))?;
        let script = ScriptBuf::from_hex(&u.script_hex)
            .map_err(|e| anyhow::anyhow!("bad utxo script: {e}"))?;
        wallet.insert_txout(
            outpoint,
            TxOut {
                value: Amount::from_sat(u.value_sats),
                script_pubkey: script,
            },
        );
    }

    let to_addr = Address::from_str(&draft.to)
        .map_err(|e| anyhow::anyhow!("invalid address: {e}"))?
        .require_network(network)
        .map_err(|e| anyhow::anyhow!("address is not a {network} address: {e}"))?;

    let fee_rate = FeeRate::from_sat_per_vb(draft.fee_rate_sat_vb)
        .ok_or_else(|| anyhow::anyhow!("invalid fee rate"))?;
    let mut builder = wallet.build_tx();
    builder.add_recipient(to_addr.script_pubkey(), Amount::from_sat(draft.amount_sats));
    builder.fee_rate(fee_rate);
    let psbt = builder.finish().map_err(|e| anyhow::anyhow!("build failed: {e}"))?;

    // Validate the built PSBT against our master key (same as the scanned
    // path) so the preview lines + network check are identical.
    let secp = Secp256k1::new();
    let xpriv: Xpriv = Xpriv::new_master(network, &master.key.0)?;
    let details = psbt::validate(&secp, &xpriv, &psbt, network)?;

    Ok(PendingPsbt { psbt, details, network })
}

#[cfg(test)]
mod tests {
    use super::parse_receipt;

    // A valid 64-char hex txid.
    const TXID: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";

    #[test]
    fn receipt_parses_mempool() {
        let r = parse_receipt(&format!("satsmail-receipt:mempool:{TXID}"));
        assert_eq!(r, Some(("mempool".to_string(), TXID.to_string(), None)));
    }

    #[test]
    fn receipt_parses_confirmed_with_confs() {
        let r = parse_receipt(&format!("satsmail-receipt:confirmed:{TXID}:12"));
        assert_eq!(
            r,
            Some(("confirmed".to_string(), TXID.to_string(), Some(12)))
        );
    }

    #[test]
    fn receipt_is_case_insensitive_and_trims() {
        let upper = TXID.to_uppercase();
        let r = parse_receipt(&format!("  satsmail-receipt:mempool:{upper}  "));
        assert_eq!(r, Some(("mempool".to_string(), TXID.to_string(), None)));
    }

    #[test]
    fn receipt_rejects_garbage() {
        assert_eq!(parse_receipt("satsmail-receipt:mempool:short"), None);
        assert_eq!(parse_receipt("satsmail-receipt:unknown:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"), None);
        assert_eq!(parse_receipt("bc1p7yn23p5rwsgweaem9kxjuuuaxmv82hxtcexjjgnynm0vhwnsvc0qhugnaz"), None);
        assert_eq!(parse_receipt(""), None);
    }
}
