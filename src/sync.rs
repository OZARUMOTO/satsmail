// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SYNC — the live inbox.
//
// Walks the wallet's external + internal lookahead windows, queries the box's
// bwt (over Electrum) for every scripthash, and turns the raw history into
// SATSMAIL's "mail" rows:
//
//   * every tx that touched one of our scripts becomes a mail
//   * net flow = (our outputs) − (our inputs) → "receive btc" / "send btc"
//   * confirmations come from the tx; 0 = unconfirmed = unread
//   * balance = sum of every unspent output on our scripts
//
// The counterparty (from/to) is the first script in the tx that is NOT ours,
// decoded back to an address when possible.

use crate::electrum;
use ngwallet::bdk_wallet::bitcoin::Network;

/// One row in the inbox, mirroring the slint `MailItem` struct.
#[derive(Debug, Clone)]
pub struct Mail {
    pub subject: String, // "receive btc" / "send btc"
    pub amount: String,  // "+0.00566284"
    pub detail: String,  // "from bc1q…" / "to bc1q…"
    pub status: String,  // "[16 confirmations]"
    pub fresh: bool,     // unconfirmed = unread
    pub block_time: i64, // unix seconds; 0 when unconfirmed (for sorting)
}

/// The result of one sync pass.
#[derive(Debug, Clone)]
pub struct SyncResult {
    pub balance_sats: u64,
    pub mails: Vec<Mail>,
}

/// One mail row as carried by a sync QR. JSON-serializable so the companion
/// (phone/box) can render the wallet state and the Prime can ingest it — the
/// offline refresh path (no electrum on the device).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrMail {
    pub subject: String, // "receive btc" / "send btc"
    pub amount: String,  // "+0.00566284"
    pub detail: String,  // "from bc1q…" / "to bc1q…"
    pub status: String,  // "[16 confirmations]"
    pub fresh: bool,     // unconfirmed = unread
    pub block_time: i64, // unix seconds; 0 when unconfirmed (for sorting)
}

/// One unspent output on one of our scripts, as carried by the sync QR. The
/// compose-send flow feeds these into bdk so the tx can be built on-device
/// (no PSBT needed from a companion wallet).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrUtxo {
    pub txid: String,
    pub vout: u32,
    pub script_hex: String, // the script_pubkey of THIS output (ours)
    pub value_sats: u64,
    pub confirmed: bool,
}

/// Fee-rate presets (sat/vB) the companion recommends, from bwt estimatefee.
#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
pub struct QrFeeRates {
    pub low: u64,
    pub medium: u64,
    pub high: u64,
}

/// The full sync payload the companion encodes as an animated UR2 `bytes` QR:
/// the balance plus the mail rows. The Prime scans it and the inbox updates
/// exactly as if electrum had been reachable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QrSyncPayload {
    pub balance_sats: u64,
    pub generated_at: i64, // unix seconds, for the "stale sync" check
    pub mails: Vec<QrMail>,
    /// UTXOs on our scripts — used by compose-send to build the tx on-device.
    #[serde(default)]
    pub utxos: Vec<QrUtxo>,
    /// Recommended fee rates (sat/vB) for the compose-send fee presets.
    #[serde(default)]
    pub fee_rates: Option<QrFeeRates>,
    /// The companion's own broadcast page URL (e.g.
    /// `http://192.168.0.14:8081/broadcast`). The compose-send "done" screen
    /// renders a pushtx URL QR built on this base, so the phone camera can
    /// open the page and the box broadcasts via its own bitcoind.
    #[serde(default)]
    pub broadcast_base: Option<String>,
    /// HMAC-SHA256 tag over the canonical payload (key = the pairing secret
    /// established via the /pair QR). Set by the box, verified by the device
    /// (see `pair::verify_sync`). Skipped when serializing so the device can
    /// re-derive the exact bytes the box signed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac: Option<String>,
}

impl QrSyncPayload {
    /// Convert into the inbox's native `Mail` rows (most recent first).
    pub fn to_mails(&self) -> Vec<Mail> {
        let mut mails: Vec<Mail> = self
            .mails
            .iter()
            .map(|m| Mail {
                subject: m.subject.clone(),
                amount: m.amount.clone(),
                detail: m.detail.clone(),
                status: m.status.clone(),
                fresh: m.fresh,
                block_time: m.block_time,
            })
            .collect();
        mails.sort_by(|a, b| {
            if a.fresh != b.fresh {
                return if a.fresh { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
            }
            b.block_time.cmp(&a.block_time)
        });
        mails
    }
}

/// Run one full sync pass. Returns balance + mail rows (most recent first).
///
/// `scripts` is the pre-derived (external, internal) lookahead — the caller
/// derives it ONCE at seed load and reuses it, because re-deriving 30 taproot
/// addresses on the Prime's single core every 10 s starves the UI thread.
pub fn run(
    host: &str,
    port: u16,
    _network: Network,
    scripts: (Vec<String>, Vec<String>),
) -> Result<SyncResult, electrum::ElectrumError> {
    let (external_scripts, internal_scripts) = scripts;

    let mut all_scripts = external_scripts.clone();
    all_scripts.extend(internal_scripts.iter().cloned());

    // ── balance: every unspent output on our scripts ──────────────────────
    let mut balance_sats: u64 = 0;
    for script in &all_scripts {
        let scripthash = electrum::scripthash_hex(&hex::decode(script).unwrap_or_default());
        for utxo in electrum::list_unspent(host, port, &scripthash)? {
            balance_sats += utxo.value_sats;
        }
    }

    // ── history: every tx that touched any of our scripts ─────────────────
    let mut txids: Vec<String> = Vec::new();
    for script in &all_scripts {
        let scripthash = electrum::scripthash_hex(&hex::decode(script).unwrap_or_default());
        for entry in electrum::get_history(host, port, &scripthash)? {
            if !txids.contains(&entry.tx_hash) {
                txids.push(entry.tx_hash);
            }
        }
    }

    // ── per-tx net flow → mails ───────────────────────────────────────────
    let our_set: std::collections::HashSet<&String> =
        all_scripts.iter().collect();
    let mut mails: Vec<Mail> = Vec::new();

    for txid in &txids {
        let tx = electrum::get_tx_verbose(host, port, txid)?;

        let mut our_in: u64 = 0;
        let mut other_in: Option<String> = None; // first script we don't own (input side)
        for (value, script) in &tx.inputs {
            if our_set.contains(script) {
                our_in += value;
            } else if other_in.is_none() {
                other_in = Some(script.clone());
            }
        }

        let mut our_out: u64 = 0;
        let mut other_out: Option<String> = None; // first script we don't own (output side)
        for (value, script) in &tx.outputs {
            if our_set.contains(script) {
                our_out += value;
            } else if other_out.is_none() {
                other_out = Some(script.clone());
            }
        }

        let net = our_out as i128 - our_in as i128;
        if net == 0 {
            // Pure internal move (e.g. change re-consolidation) — not a mail.
            continue;
        }

        let fresh = tx.confirmations == 0;
        let status = if fresh {
            "[unconfirmed]".to_string()
        } else {
            format!("[{} confirmations]", tx.confirmations)
        };
        let block_time = if fresh { 0 } else { tx.block_time };

        let (subject, amount, detail) = if net > 0 {
            (
                "receive btc".to_string(),
                format!("+{}", crate::fmt_sats(net as u64)),
                match other_in {
                    Some(script) => format!("from {}", script_to_addr(&script)),
                    None => "from —".to_string(),
                },
            )
        } else {
            (
                "send btc".to_string(),
                format!("-{}", crate::fmt_sats(net.unsigned_abs() as u64)),
                match other_out {
                    Some(script) => format!("to {}", script_to_addr(&script)),
                    None => "to —".to_string(),
                },
            )
        };

        mails.push(Mail {
            subject,
            amount,
            detail,
            status,
            fresh,
            block_time,
        });
    }

    // Most recent first: unconfirmed on top, then by block time descending.
    mails.sort_by(|a, b| {
        if a.fresh != b.fresh {
            return if a.fresh { std::cmp::Ordering::Less } else { std::cmp::Ordering::Greater };
        }
        b.block_time.cmp(&a.block_time)
    });

    Ok(SyncResult { balance_sats, mails })
}

/// Best-effort: decode a script_hex into a (shortened) bech32/legacy address.
fn script_to_addr(script_hex: &str) -> String {
    let Ok(bytes) = hex::decode(script_hex) else {
        return short(script_hex);
    };
    match ngwallet::bdk_wallet::bitcoin::Address::from_script(
        &ngwallet::bdk_wallet::bitcoin::ScriptBuf::from_bytes(bytes),
        ngwallet::bdk_wallet::bitcoin::Network::Bitcoin.params(),
    ) {
        Ok(addr) => short(&addr.to_string()),
        Err(_) => short(script_hex),
    }
}

fn short(s: &str) -> String {
    if s.len() <= 16 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..8], &s[s.len() - 4..])
    }
}
