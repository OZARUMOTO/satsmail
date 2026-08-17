// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// SATSMAIL — a retro 2009 email client that happens to be a Bitcoin wallet.
//
// v2: REAL wallet. The inbox is live (bwt over Electrum on the box), the
// compose tab derives a real receive address from the device seed, and the
// "> send" tab scans a PSBT, verifies it against our master key, previews it
// like an email draft, signs it on-device, and exports the signed PSBT as an
// animated UR2 QR (or broadcasts it directly when the hosted simulator is
// talking to bwt).

use {
    ngwallet::bdk_wallet::bitcoin::Network,
    slint_keyos_platform::{
        app,
        gui_server_api::navigation::qrscanner::{ScanQrOptions, ScanQrResult},
        navigation::open_qr_scanner,
        slint::{ComponentHandle, ModelRc, SharedString, Timer, TimerMode, VecModel},
        spawn_local, spawn_worker,
    },
    std::cell::RefCell,
    std::io::Write,
    std::rc::Rc,
    std::time::Duration,
};

mod electrum;
mod send;
mod sync;
mod wallet;

security::use_api!();

/// The bwt instance on the box (Electrum JSON-RPC on plain TCP).
/// HOSTED-NOTE: only reachable from the hosted simulator; on hardware the
/// companion fronts this endpoint over quantum-link.
const ELECTRUM_HOST: &str = "127.0.0.1";
const ELECTRUM_PORT: u16 = 50001;

/// How often the inbox re-syncs (seconds). Only used on the hosted
/// simulator — on hardware the periodic sync is disabled because the
/// electrum endpoint is unreachable (see `spawn_sync_loop`).
#[cfg(not(keyos))]
const SYNC_INTERVAL_SECS: u64 = 10;

/// Application state shared across callbacks.
struct AppState {
    master: Option<crate::wallet::MasterKey>,
    /// Derived lookahead scripts (external, internal) — computed ONCE at seed
    /// load, reused by every sync tick. Re-deriving 30 taproot addresses on
    /// the Prime's single core every 10 s was what made the whole device lag.
    scripts: Option<(Vec<String>, Vec<String>)>,
    /// Receive address index (compose page increments it for a "new address").
    receive_index: u32,
    /// Last known inbox rows, for the tx detail page.
    mails: Vec<sync::Mail>,
    /// Verified-but-unsigned PSBT awaiting confirmation.
    pending: Option<send::PendingPsbt>,
    /// Signed PSBT bytes ready for QR export / broadcast.
    signed: Option<Vec<u8>>,
    /// True while a sync is in flight (guard against overlapping syncs).
    sync_in_flight: bool,
    /// UTXOs from the last sync — the inputs compose-send may spend.
    utxos: Vec<sync::QrUtxo>,
    /// Fee-rate presets (sat/vB) from the last sync, for the compose presets.
    fee_rates: Option<sync::QrFeeRates>,
    /// The companion's broadcast page URL from the last sync.
    broadcast_base: Option<String>,
    /// Compose-send draft (address + amount + fee) awaiting build.
    compose_draft: Option<send::ComposeDraft>,
    /// The pushtx URL QR for the compose done screen (built after signing).
    broadcast_url: Option<String>,
}

impl AppState {
    fn new() -> Self {
        Self {
            master: None,
            scripts: None,
            receive_index: 0,
            mails: Vec::new(),
            pending: None,
            signed: None,
            sync_in_flight: false,
            utxos: Vec::new(),
            fee_rates: None,
            broadcast_base: None,
            compose_draft: None,
            broadcast_url: None,
        }
    }
}

/// Format satoshis as a BTC string, 8 decimals max, trailing zeros trimmed.
pub fn fmt_sats(sats: u64) -> String {
    let whole = sats / 100_000_000;
    let frac = sats % 100_000_000;
    if frac == 0 {
        return whole.to_string();
    }
    let mut frac_s = format!("{frac:08}");
    while frac_s.ends_with('0') {
        frac_s.pop();
    }
    format!("{whole}.{frac_s}")
}

/// Parse a user-typed BTC amount string ("0.005", "1", ".5") into satoshis.
/// Returns None when the input is not a valid non-negative BTC amount.
pub fn parse_btc_to_sats(s: &str) -> Option<u64> {
    let t = s.trim();
    if t.is_empty() {
        return None;
    }
    let (whole, frac) = match t.split_once('.') {
        Some((w, f)) => (w, f),
        None => (t, ""),
    };
    if !whole.chars().all(|c| c.is_ascii_digit()) || !frac.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if frac.len() > 8 {
        return None; // sub-satoshi precision
    }
    let whole: u64 = if whole.is_empty() { 0 } else { whole.parse().ok()? };
    let mut frac_s = frac.to_string();
    while frac_s.len() < 8 {
        frac_s.push('0');
    }
    let frac: u64 = if frac_s.is_empty() { 0 } else { frac_s.parse().ok()? };
    whole.checked_mul(100_000_000)?.checked_add(frac)
}

app!("Sats Mail");

fn app_main(cx: AppContext, ui: AppWindow) {
    log_server::init_wait(env!("CARGO_CRATE_NAME")).unwrap();
    log::set_max_level(log::LevelFilter::Info);

    cx.config.enable_swipe_back.set(false);

    let state = Rc::new(RefCell::new(AppState::new()));
    let ui_weak = ui.as_weak();

    // ── 1. load the app-scoped seed (blocking SE IPC) on a worker ─────────
    // GetAppSeed carries a grantOnFirstUse permissionGroup: the prompt can
    // only display once this app is foregrounded, and calling it before the
    // window is visible makes the kernel deny the message outright. The SDK
    // wrapper panics on that denial, so the attempt is catch_unwind-guarded
    // and retried on a 2 s timer until the user approves (or pre-grants under
    // Settings → Apps → Sats Mail). Same shape as QXXX's seed retry.
    {
        let state = state.clone();
        let ui_weak = ui_weak.clone();
        spawn_local(async move {
            let network = Network::Bitcoin;
            let result = spawn_worker(async move {
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wallet::load_master(network)))
                    .ok()
                    .and_then(|r| r.ok())
            })
            .await;
            match result {
                Some(master) => {
                    log::info!("satsmail: app-scoped master key loaded");
                    state.borrow_mut().master = Some(master);
                    refresh_receive_address(&state, &ui_weak);
                    spawn_sync_loop(&state, &ui_weak);
                }
                None => {
                    log::warn!("satsmail: seed access pending — will retry");
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.global::<Callbacks>()
                            .set_sync_status("seed access pending — approve the prompt".into());
                    }
                    retry_seed_load(&state, &ui_weak);
                }
            }
        })
        .detach();
    }

    // ── 2. callbacks ──────────────────────────────────────────────────────
    ui.global::<Callbacks>().on_show_page({
        let ui = ui.as_weak();
        move |page| {
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_page(page);
            }
        }
    });

    ui.global::<Callbacks>().on_open_tx({
        let ui = ui.as_weak();
        let state = state.clone();
        move |idx| {
            let Some(ui) = ui.upgrade() else { return };
            let mails = state.borrow().mails.clone();
            if let Some(m) = mails.get(idx as usize) {
                let g = ui.global::<Callbacks>();
                g.set_tx_subject(m.subject.clone().into());
                g.set_tx_amount(m.amount.clone().into());
                g.set_tx_detail(m.detail.clone().into());
                g.set_tx_status(m.status.clone().into());
                g.set_page(3);
            }
        }
    });

    ui.global::<Callbacks>().on_new_address({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            state.borrow_mut().receive_index += 1;
            refresh_receive_address(&state, &ui);
        }
    });

    ui.global::<Callbacks>().on_export_xpub({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_export_status("exporting…".into());
            let master = state.borrow().master.clone();
            let Some(master) = master else {
                ui.global::<Callbacks>().set_export_status("no seed yet".into());
                return;
            };
            // Blocking fs IPC + derivation run on a worker, like every other
            // callback in this app — never on the UI thread.
            let ui = ui.as_weak();
            spawn_local(async move {
                let result = spawn_worker(async move {
                    let xpub = wallet::account_xpub(Network::Bitcoin, &master)?;
                    let export = export_xpub_to_airlock(&xpub);
                    Ok::<_, anyhow::Error>((xpub, export))
                })
                .await;
                let Some(ui) = ui.upgrade() else { return };
                match result {
                    Ok((_xpub, Ok(()))) => {
                        log::info!("satsmail: xpub exported to airlock");
                        ui.global::<Callbacks>()
                            .set_export_status("saved to airlock — plug the prime back in to grab satsmail-xpub.txt".into());
                    }
                    Ok((_, Err(AirlockExportError::Denied))) => {
                        log::error!("satsmail: airlock export DENIED — the fs server rejected GetAirlockWriteAccess");
                        ui.global::<Callbacks>().set_export_status(
                            "export failed — enable 'airlock files' permission in settings > apps > sats mail > permissions".into(),
                        );
                    }
                    Ok((_, Err(AirlockExportError::NotConnected))) => {
                        log::error!("satsmail: airlock not mounted — the host has the airlock volume locked while plugged in");
                        ui.global::<Callbacks>().set_export_status(
                            "export failed — unplug the prime from the computer first, then export (the airlock is locked while plugged in)".into(),
                        );
                    }
                    Ok((_, Err(AirlockExportError::Other(e)))) => {
                        log::error!("satsmail: airlock export failed: {e:?}");
                        ui.global::<Callbacks>().set_export_status(
                            format!("export failed: {:?}", e).into(),
                        );
                    }
                    Err(e) => {
                        log::error!("satsmail: export xpub derive failed {e:?}");
                        ui.global::<Callbacks>().set_export_status("export failed".into());
                    }
                }
            })
            .detach();
        }
    });

    ui.global::<Callbacks>().on_refresh({
        let ui = ui.as_weak();
        let state = state.clone();
        move || run_sync_once(&state, &ui)
    });

    ui.global::<Callbacks>().on_scan_sync({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_sync_status("scanning sync qr…".into());

            let opts = ScanQrOptions {
                header_title: "scan sync".into(),
                header_right_icon: "close".into(),
                ..ScanQrOptions::default()
            };
            let scan = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    ui.global::<Callbacks>().set_sync_status("sync cancelled".into());
                    return;
                }
                Err(e) => {
                    log::error!("satsmail: qr scanner error {e:?}");
                    ui.global::<Callbacks>().set_sync_status("scanner error".into());
                    return;
                }
            };

            // The companion encodes the sync payload as a UR2 `bytes` QR;
            // parse it into mails + balance and drop them into the inbox.
            let Some(payload) = parse_sync_ur(&scan) else {
                ui.global::<Callbacks>().set_sync_status("bad sync qr".into());
                return;
            };
            // Stash the compose-send inputs the payload carries (UTXOs, fee
            // presets, broadcast page) so the > send tab can build on-device.
            {
                let mut st = state.borrow_mut();
                st.utxos = payload.utxos.clone();
                st.fee_rates = payload.fee_rates;
                st.broadcast_base = payload.broadcast_base.clone();
            }
            let mails = payload.to_mails();
            log::info!(
                "satsmail: qr sync loaded {} mails, {} sats, {} utxos",
                mails.len(),
                payload.balance_sats,
                payload.utxos.len()
            );
            apply_mails(
                &state,
                &ui.as_weak(),
                mails,
                payload.balance_sats,
                &format!("qr sync: {} mails", payload.mails.len()),
            );
            // The QR payload carries the broadcast page URL — keep the done
            // screen's pushtx QR in sync with what the box actually serves.
            if let Some(base) = payload.broadcast_base.clone() {
                if let Some(ui) = ui.as_weak().upgrade() {
                    ui.global::<Callbacks>().set_broadcast_url(base.into());
                }
            }
        }
    });

    ui.global::<Callbacks>().on_scan_psbt({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_send_state(1); // scanning
            let master = state.borrow().master.clone();
            let Some(master) = master else {
                ui.global::<Callbacks>().set_send_state(5);
                return;
            };

            let opts = ScanQrOptions {
                header_title: "scan psbt".into(),
                header_right_icon: "close".into(),
                ..ScanQrOptions::default()
            };
            let scan = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    ui.global::<Callbacks>().set_send_state(0);
                    return;
                }
                Err(e) => {
                    log::error!("satsmail: qr scanner error {e:?}");
                    ui.global::<Callbacks>().set_send_state(5);
                    return;
                }
            };

            // Parse + verify on a worker.
            let ui = ui.as_weak();
            let state = state.clone();
            spawn_local(async move {
                let bytes = parse_psbt_bytes(&scan);
                let Some(bytes) = bytes else {
                    let Some(ui) = ui.upgrade() else { return };
                    ui.global::<Callbacks>().set_send_state(5);
                    return;
                };
                let result = spawn_worker(async move { send::verify(&bytes, &master) }).await;
                match result {
                    Ok(pending) => {
                        let Some(ui) = ui.upgrade() else { return };
                        let (to, amount, fee) = send::preview_lines(&pending);
                        let g = ui.global::<Callbacks>();
                        g.set_send_to(to.into());
                        g.set_send_amount(amount.into());
                        g.set_send_fee(fee.into());
                        g.set_send_broadcast("".into());
                        g.set_send_state(2); // preview
                        state.borrow_mut().pending = Some(pending);
                        state.borrow_mut().signed = None;
                    }
                    Err(e) => {
                        log::error!("satsmail: psbt verify failed {e:?}");
                        let Some(ui) = ui.upgrade() else { return };
                        let g = ui.global::<Callbacks>();
                        g.set_send_broadcast(format!("verify failed: {e}").into());
                        g.set_send_state(5);
                    }
                }
            })
            .detach();
        }
    });

    ui.global::<Callbacks>().on_sign_psbt({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_send_state(3); // signing
            let master = state.borrow().master.clone();
            let pending = state.borrow().pending.clone();
            let mode = state.borrow().compose_draft.is_some();
            let broadcast_base = state.borrow().broadcast_base.clone();
            let Some(master) = master else { return };
            let Some(pending) = pending else { return };

            // Keep a weak handle for the async completion handlers.
            let ui = ui.as_weak();
            let state = state.clone();
            spawn_local(async move {
                let result = spawn_worker(async move {
                    let signed = send::sign(&pending, &master)?;
                    // For compose-send, also build the pushtx URL QR on the
                    // worker (bdk extract + base64/sha — never on the UI thread).
                    let broadcast_url = if mode {
                        match broadcast_base {
                            Some(base) => {
                                let hex = send::extract_tx_hex(&pending, &master)?;
                                Some(send::pushtx_url(&hex, &base))
                            }
                            None => None,
                        }
                    } else {
                        None
                    };
                    Ok::<_, anyhow::Error>((signed, broadcast_url))
                })
                .await;
                match result {
                    Ok((signed, broadcast_url)) => {
                        let Some(ui) = ui.upgrade() else { return };
                        state.borrow_mut().signed = Some(signed);
                        state.borrow_mut().broadcast_url = broadcast_url.clone();
                        ui.global::<Callbacks>().set_send_broadcast("".into());
                        ui.global::<Callbacks>().set_broadcast_url(
                            broadcast_url.clone().unwrap_or_default().into(),
                        );
                        // Pre-render the pushtx-URL QR once here (UI thread,
                        // after the worker returns) instead of letting the
                        // Qrcode widget re-run Utils.qrcode on every send-page
                        // construction — same reason as the receive QR.
                        // slint::Image is not Send, so it's built after the
                        // await, mirroring QXXX's set_ui closure pattern.
                        if let Some(url) = &broadcast_url {
                            let img = slint_keyos_platform::qrcode::render(
                                url.as_bytes(),
                                slint_keyos_platform::slint::Color::from_rgb_u8(0, 0, 0),
                                slint_keyos_platform::slint::Color::from_rgb_u8(255, 255, 255),
                            );
                            ui.global::<Callbacks>().set_broadcast_qr(img);
                        }
                        ui.global::<Callbacks>().set_send_state(4); // done → QR
                    }
                    Err(e) => {
                        log::error!("satsmail: sign failed {e:?}");
                        let Some(ui) = ui.upgrade() else { return };
                        ui.global::<Callbacks>().set_send_broadcast(format!("sign failed: {e}").into());
                        ui.global::<Callbacks>().set_send_state(5);
                    }
                }
            })
            .detach();
        }
    });

    ui.global::<Callbacks>().on_cancel_send({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            state.borrow_mut().pending = None;
            state.borrow_mut().signed = None;
            state.borrow_mut().compose_draft = None;
            state.borrow_mut().broadcast_url = None;
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_send_mode(0);
                ui.global::<Callbacks>().set_send_state(0);
                ui.global::<Callbacks>().set_broadcast_qr(slint_keyos_platform::slint::Image::default());
            }
        }
    });

    ui.global::<Callbacks>().on_done_send({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            state.borrow_mut().pending = None;
            state.borrow_mut().signed = None;
            state.borrow_mut().compose_draft = None;
            state.borrow_mut().broadcast_url = None;
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_send_mode(0);
                ui.global::<Callbacks>().set_send_state(0);
                ui.global::<Callbacks>().set_broadcast_qr(slint_keyos_platform::slint::Image::default());
                ui.global::<Callbacks>().set_page(0);
            }
        }
    });

    ui.global::<Callbacks>().on_broadcast({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            let master = state.borrow().master.clone();
            let pending = state.borrow().pending.clone();
            let Some(master) = master else { return };
            let Some(pending) = pending else { return };

            // Keep a weak handle for the async completion handler.
            let ui = ui.as_weak();
            spawn_local(async move {
                let result = spawn_worker(async move {
                    let hex = send::extract_tx_hex(&pending, &master)?;
                    electrum::broadcast(ELECTRUM_HOST, ELECTRUM_PORT, &hex).map_err(anyhow::Error::from)
                })
                .await;
                let Some(ui) = ui.upgrade() else { return };
                let g = ui.global::<Callbacks>();
                match result {
                    Ok(txid) => {
                        g.set_send_broadcast(format!("broadcast ok {txid:.10}").into());
                    }
                    Err(e) => {
                        g.set_send_broadcast(format!("broadcast failed: {e}").into());
                    }
                }
            })
            .detach();
        }
    });

    ui.global::<Callbacks>().on_get_signed_ur({
        let state = state.clone();
        move |density| {
            let signed = state.borrow().signed.clone();
            match signed {
                Some(bytes) => send::signed_ur_parts(&bytes, density),
                None => ModelRc::default(),
            }
        }
    });

    // ── 3. compose-send — build the tx ON-DEVICE (no companion PSBT) ───────
    // state 6 = scan address, 7 = amount+fee, 8 = preview. Signing reuses the
    // psbt path (state 3 -> 4), but the done screen shows a pushtx URL QR
    // instead of an animated PSBT QR.

    ui.global::<Callbacks>().on_compose_send({
        let ui = ui.as_weak();
        move || {
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_send_mode(1); // compose
                ui.global::<Callbacks>().set_send_state(6); // scan address
            }
        }
    });

    ui.global::<Callbacks>().on_scan_address({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_send_state(6);

            let opts = ScanQrOptions {
                header_title: "scan address".into(),
                header_right_icon: "close".into(),
                ..ScanQrOptions::default()
            };
            let scan = match open_qr_scanner::<gui_permissions::GuiPermissions>(opts) {
                Ok(Some(s)) => s,
                Ok(None) => {
                    ui.global::<Callbacks>().set_send_state(0);
                    return;
                }
                Err(e) => {
                    log::error!("satsmail: qr scanner error {e:?}");
                    ui.global::<Callbacks>().set_send_broadcast("scanner error".into());
                    ui.global::<Callbacks>().set_send_state(5);
                    return;
                }
            };

            // A plain address QR comes back as raw text (ScanQrResult::Qr).
            let ScanQrResult::Qr { data, .. } = scan else {
                ui.global::<Callbacks>().set_send_broadcast("not an address qr".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            };
            let Ok(text) = String::from_utf8(data) else {
                ui.global::<Callbacks>().set_send_broadcast("bad address text".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            };
            let text = text.trim().to_string();
            if text.is_empty() {
                ui.global::<Callbacks>().set_send_broadcast("empty qr".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            }
            // Keep the raw scanned text; the address is validated at build.
            // Clone the utxos BEFORE the borrow_mut — borrowing the same
            // RefCell inside its own mutable borrow panics ("already borrowed").
            let utxos = state.borrow().utxos.clone();
            state.borrow_mut().compose_draft = Some(send::ComposeDraft {
                to: text.clone(),
                amount_sats: 0,
                fee_rate_sat_vb: 0,
                utxos,
            });
            ui.global::<Callbacks>().set_send_to(text.into());
            ui.global::<Callbacks>().set_send_state(7); // amount + fee
        }
    });

    // Amount changed (BTC string like "0.005" -> satoshis).
    ui.global::<Callbacks>().on_set_amount({
        let ui = ui.as_weak();
        let state = state.clone();
        move |amount: SharedString| {
            let sats = parse_btc_to_sats(&amount);
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_send_amount_input(amount);
                ui.global::<Callbacks>().set_send_amount_hint(
                    if sats.is_some() { "".into() } else { "invalid amount".into() },
                );
            }
            if let Some(d) = state.borrow_mut().compose_draft.as_mut() {
                d.amount_sats = sats.unwrap_or(0);
            }
        }
    });

    // Fee preset selected (0 = low, 1 = medium, 2 = high from the sync).
    ui.global::<Callbacks>().on_set_fee_preset({
        let ui = ui.as_weak();
        let state = state.clone();
        move |idx: i32| {
            let rate = state.borrow().fee_rates.map(|f| match idx {
                0 => f.low,
                1 => f.medium,
                _ => f.high,
            });
            if let Some(ui) = ui.upgrade() {
                let label = rate.map(|r| format!("{r} sat/vB")).unwrap_or_default();
                ui.global::<Callbacks>().set_send_fee_selected(label.into());
            }
            if let Some(d) = state.borrow_mut().compose_draft.as_mut() {
                d.fee_rate_sat_vb = rate.unwrap_or(0);
            }
        }
    });

    // Custom fee rate typed (sat/vB).
    ui.global::<Callbacks>().on_set_custom_fee({
        let ui = ui.as_weak();
        let state = state.clone();
        move |fee: SharedString| {
            let rate = fee.trim().parse::<u64>().ok().filter(|r| *r > 0);
            if let Some(ui) = ui.upgrade() {
                ui.global::<Callbacks>().set_send_custom_fee(fee);
                ui.global::<Callbacks>().set_send_fee_selected(
                    rate.map(|r| format!("{r} sat/vB")).unwrap_or_default().into(),
                );
            }
            if let Some(d) = state.borrow_mut().compose_draft.as_mut() {
                d.fee_rate_sat_vb = rate.unwrap_or(0);
            }
        }
    });

    // Build the tx on-device from the draft (address + amount + fee + utxos).
    ui.global::<Callbacks>().on_build_compose({
        let ui = ui.as_weak();
        let state = state.clone();
        move || {
            let Some(ui) = ui.upgrade() else { return };
            ui.global::<Callbacks>().set_send_state(3); // "building…" (signing state)
            let master = state.borrow().master.clone();
            let draft = state.borrow().compose_draft.clone();
            let Some(master) = master else {
                ui.global::<Callbacks>().set_send_broadcast("no seed".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            };
            let Some(draft) = draft else {
                ui.global::<Callbacks>().set_send_broadcast("scan an address first".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            };
            if draft.amount_sats == 0 {
                ui.global::<Callbacks>().set_send_broadcast("enter an amount".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            }
            if draft.fee_rate_sat_vb == 0 {
                ui.global::<Callbacks>().set_send_broadcast("pick a fee rate".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            }
            if draft.utxos.is_empty() {
                ui.global::<Callbacks>().set_send_broadcast("sync first — no utxos".into());
                ui.global::<Callbacks>().set_send_state(5);
                return;
            }

            let ui = ui.as_weak();
            let state = state.clone();
            spawn_local(async move {
                let result = spawn_worker(async move {
                    send::build_compose(Network::Bitcoin, &master, &draft)
                })
                .await;
                let Some(ui) = ui.upgrade() else { return };
                match result {
                    Ok(pending) => {
                        let (to, amount, fee) = send::preview_lines(&pending);
                        let g = ui.global::<Callbacks>();
                        g.set_send_to(to.into());
                        g.set_send_amount(amount.into());
                        g.set_send_fee(fee.into());
                        g.set_send_broadcast("".into());
                        g.set_send_state(8); // compose preview
                        state.borrow_mut().pending = Some(pending);
                        state.borrow_mut().signed = None;
                    }
                    Err(e) => {
                        log::error!("satsmail: compose build failed {e:?}");
                        let g = ui.global::<Callbacks>();
                        g.set_send_broadcast(format!("build failed: {e}").into());
                        g.set_send_state(5);
                    }
                }
            })
            .detach();
        }
    });

    // After signing a compose tx, render the pushtx URL QR (done state 4).
    ui.global::<Callbacks>().on_get_broadcast_url({
        let state = state.clone();
        move || state.borrow().broadcast_url.clone().unwrap_or_default().into()
    });

    ui.run().expect("UI running");
}

/// Parse the scanner result into raw PSBT bytes (UR2 → crypto-psbt / bytes).
fn parse_psbt_bytes(scan: &ScanQrResult) -> Option<Vec<u8>> {
    if let ScanQrResult::Ur2 { ur_type, data, .. } = scan {
        match foundation_urtypes::value::Value::from_ur(ur_type, data.as_slice()) {
            Ok(foundation_urtypes::value::Value::Psbt(bytes))
            | Ok(foundation_urtypes::value::Value::Bytes(bytes)) => Some(bytes.to_vec()),
            _ => None,
        }
    } else {
        None
    }
}

/// Why an airlock export failed, so the UI can say the REAL reason instead of
/// blaming the permission. The `file-system.airlock-files` permission being
/// toggled on is necessary but not sufficient: the airlock volume is only
/// writable by apps while the Prime is UNPLUGGED. When a computer is
/// connected, the mass-storage backend takes the volume over exclusively and
/// the fs server unmounts it (`AirlockState::Unmounted`) — so a plugged-in
/// device fails with `NoMedia` even with full permissions.
enum AirlockExportError {
    /// Permission not granted (`file-system.airlock-files`, grantOnFirstUse).
    Denied,
    /// The airlock volume isn't mounted — the host has it locked while plugged in.
    NotConnected,
    /// Anything else (I/O, FS internals).
    Other(fs::Error),
}

/// Write the account xpub to the Airlock — the virtual USB share that appears
/// when the Prime is plugged into a computer. The companion (and its bwt)
/// needs this exact string to watch satsmail's wallet.
///
/// Requires the `file-system.airlock-files` permissionGroup (grantOnFirstUse,
/// via GetAirlockReadAccess/GetAirlockWriteAccess): the first tap prompts to
/// approve it under Settings → Apps → Sats Mail → Permissions.
///
/// IMPORTANT: the airlock volume is only writable by apps while the Prime is
/// UNPLUGGED. While a computer is connected, mass-storage-emulation owns the
/// volume and the fs server unmounts it, so open_file fails with NoMedia.
/// The flow is: unplug → export → plug back in → grab satsmail-xpub.txt.
fn export_xpub_to_airlock(xpub: &str) -> Result<(), AirlockExportError> {
    const AIRLOCK_XPUB_PATH: &str = "satsmail-xpub.txt";
    log::info!("satsmail: export_xpub: creating fs connection");
    let filesystem = crate::FileSystem::default();
    log::info!("satsmail: export_xpub: open_file(\"{}\", Airlock, CREATE)", AIRLOCK_XPUB_PATH);
    let mut file = filesystem
        .open_file(
            AIRLOCK_XPUB_PATH.to_string(),
            fs::Location::Airlock,
            fs::OpenFlags::CREATE,
        )
        .map_err(|e| {
            log::error!("satsmail: export_xpub: open_file failed: {:?} (raw fs::Error)", e);
            match e {
                fs::Error::AccessDenied => AirlockExportError::Denied,
                fs::Error::NoMedia => AirlockExportError::NotConnected,
                other => AirlockExportError::Other(other),
            }
        })?;
    log::info!("satsmail: export_xpub: writing {} bytes", xpub.len());
    if file.write_all(xpub.as_bytes()).is_err() {
        return Err(AirlockExportError::Other(fs::Error::Io));
    }
    let _ = file.truncate(); // drop any stale trailing bytes from a prior export
    let _ = file.flush(); // best-effort: make the FAT image durable before close
    log::info!("satsmail: export_xpub: success");
    Ok(())
}

/// Re-derive the compose-page receive address at the current index, and keep
/// the account xpub (for the box's bwt) in sync.
fn refresh_receive_address(state: &Rc<RefCell<AppState>>, ui: &slint::Weak<AppWindow>) {
    let Some(ui) = ui.upgrade() else { return };
    let master = state.borrow().master.clone();
    let index = state.borrow().receive_index;
    let Some(master) = master else { return };
    match wallet::build_wallet(Network::Bitcoin, &master) {
        Ok(w) => {
            let addr = wallet::receive_address(&w, index);
            log::info!("satsmail: receive address #{index} = {addr}");
            ui.global::<Callbacks>().set_receive_address(addr.clone().into());
            // Pre-render the receive QR here (Rust, off the page-mount path).
            // The Qrcode widget would re-run Utils.qrcode on the UI thread on
            // every compose-page construction — that was the tab-switch hang.
            // QXXX renders the QR in Rust and shows it as an Image property.
            let img = slint_keyos_platform::qrcode::render(
                format!("bitcoin:{addr}").as_bytes(),
                slint_keyos_platform::slint::Color::from_rgb_u8(0, 0, 0),
                slint_keyos_platform::slint::Color::from_rgb_u8(255, 255, 255),
            );
            ui.global::<Callbacks>().set_receive_qr(img);
        }
        Err(e) => log::error!("satsmail: derive receive address failed {e:?}"),
    }
    match wallet::account_xpub(Network::Bitcoin, &master) {
        Ok(xpub) => ui.global::<Callbacks>().set_account_xpub(xpub.into()),
        Err(e) => log::error!("satsmail: derive account xpub failed {e:?}"),
    }
}

/// One sync pass: query bwt, push mails + balance into the UI.
fn run_sync_once(state: &Rc<RefCell<AppState>>, ui: &slint::Weak<AppWindow>) {
    let Some(ui) = ui.upgrade() else { return };
    let master = state.borrow().master.clone();
    let Some(master) = master else {
        ui.global::<Callbacks>().set_sync_status("no seed".into());
        return;
    };
    // Skip if a sync is already running (timer + manual refresh must not overlap).
    if state.borrow().sync_in_flight {
        return;
    }
    state.borrow_mut().sync_in_flight = true;

    // The lookahead scripts were derived once at seed load — reuse them. On
    // the Prime's single core, re-deriving 30 taproot addresses every tick
    // froze the UI for ~0.25-0.75 s each 10 s. Fall back to deriving in the
    // worker only if the cache is somehow missing.
    let scripts = state.borrow().scripts.clone();
    let host = ELECTRUM_HOST.to_string();
    let ui_weak = ui.as_weak();

    let state = state.clone();
    spawn_local(async move {
        let result = spawn_worker(async move {
            match scripts {
                Some(s) => sync::run(&host, ELECTRUM_PORT, Network::Bitcoin, s),
                None => {
                    let s = wallet::our_scripts(Network::Bitcoin, &master)
                        .map_err(|e| electrum::ElectrumError::BadResponse(e.to_string()))?;
                    sync::run(&host, ELECTRUM_PORT, Network::Bitcoin, s)
                }
            }
        })
        .await;
        state.borrow_mut().sync_in_flight = false;
        let Some(ui) = ui_weak.upgrade() else { return };
        let g = ui.global::<Callbacks>();
        match result {
            Ok(res) => {
                log::info!("satsmail: synced, {} mails, {} sats", res.mails.len(), res.balance_sats);
                apply_mails(&state, &ui_weak, res.mails, res.balance_sats, "electrum: online");
            }
            Err(e) => {
                log::warn!("satsmail: sync failed {e:?}");
                g.set_sync_status("electrum: offline".into());
            }
        }
    })
    .detach();
}

/// Push the synced fee presets (sat/vB) into the compose-send fee buttons.
fn push_fee_presets(state: &Rc<RefCell<AppState>>, ui: &AppWindow) {
    let fee = state.borrow().fee_rates;
    let g = ui.global::<Callbacks>();
    match fee {
        Some(f) => {
            g.set_send_fee_preset_low(format!("low {} sat/vB", f.low).into());
            g.set_send_fee_preset_med(format!("med {} sat/vB", f.medium).into());
            g.set_send_fee_preset_high(format!("high {} sat/vB", f.high).into());
        }
        None => {
            g.set_send_fee_preset_low("".into());
            g.set_send_fee_preset_med("".into());
            g.set_send_fee_preset_high("".into());
        }
    }
}

/// Push mail rows + balance into the inbox UI (shared by the electrum sync
/// and the QR sync paths).
fn apply_mails(
    state: &Rc<RefCell<AppState>>,
    ui: &slint::Weak<AppWindow>,
    mails: Vec<sync::Mail>,
    balance_sats: u64,
    status: &str,
) {
    let Some(ui) = ui.upgrade() else { return };
    state.borrow_mut().mails = mails.clone();

    let items: Vec<MailItem> = mails
        .iter()
        .map(|m| MailItem {
            subject: m.subject.clone().into(),
            amount: m.amount.clone().into(),
            detail: m.detail.clone().into(),
            status: m.status.clone().into(),
            fresh: m.fresh,
        })
        .collect();
    let unread = mails.iter().filter(|m| m.fresh).count() as i32;

    let g = ui.global::<Callbacks>();
    g.set_inbox(ModelRc::new(VecModel::from(items)));
    g.set_unread(unread);
    g.set_balance(format!("{} BTC", crate::fmt_sats(balance_sats)).into());
    g.set_sync_status(status.into());

    push_fee_presets(state, &ui);
}

/// Parse a scanner result into a QR sync payload (UR2 `bytes` -> JSON).
fn parse_sync_ur(scan: &ScanQrResult) -> Option<sync::QrSyncPayload> {
    if let ScanQrResult::Ur2 { ur_type, data, .. } = scan {
        match foundation_urtypes::value::Value::from_ur(ur_type, data.as_slice()) {
            Ok(foundation_urtypes::value::Value::Bytes(bytes)) => {
                serde_json::from_slice(bytes).ok()
            }
            _ => None,
        }
    } else {
        None
    }
}

/// Retry the seed load after a 2 s delay — the grantOnFirstUse prompt for
/// GetAppSeed can only be answered once the app is foregrounded, so the
/// first attempt (or a denied one) just schedules the next.
fn retry_seed_load(state: &Rc<RefCell<AppState>>, ui: &slint::Weak<AppWindow>) {
    let state = state.clone();
    let ui = ui.clone();
    let timer = Timer::default();
    timer.start(
        TimerMode::SingleShot,
        Duration::from_millis(2000),
        move || {
            if let Some(ui) = ui.upgrade() {
                let state = state.clone();
                let ui_weak = ui.as_weak();
                spawn_local(async move {
                    let network = Network::Bitcoin;
                    let result = spawn_worker(async move {
                        // Load the master key AND derive the lookahead scripts
                        // in one worker pass — the one-time ~300 ms of taproot
                        // derivation on the MCU must not touch the UI thread,
                        // and the sync loop reuses it instead of re-deriving
                        // every 10 s.
                        let master = std::panic::catch_unwind(
                            std::panic::AssertUnwindSafe(|| wallet::load_master(network)),
                        )
                        .ok()
                        .and_then(|r| r.ok());
                        let scripts = match &master {
                            Some(m) => wallet::our_scripts(network, m).ok(),
                            None => None,
                        };
                        (master, scripts)
                    })
                    .await;
                    match result {
                        (Some(master), scripts) => {
                            log::info!("satsmail: app-scoped master key loaded");
                            state.borrow_mut().master = Some(master);
                            state.borrow_mut().scripts = scripts;
                            refresh_receive_address(&state, &ui_weak);
                            spawn_sync_loop(&state, &ui_weak);
                        }
                        (None, _) => {
                            if let Some(ui) = ui_weak.upgrade() {
                                ui.global::<Callbacks>()
                                    .set_sync_status("seed access pending — approve the prompt".into());
                            }
                            retry_seed_load(&state, &ui_weak);
                        }
                    }
                })
                .detach();
            }
        },
    );
    // Keep the timer alive until it fires (single-shot).
    std::mem::forget(timer);
}

/// Kick off the periodic inbox sync (after the master key is loaded).
///
/// On hardware (`cfg(keyos)`) the Prime has no network — the electrum
/// endpoint is always unreachable, so a repeating timer would just spawn a
/// worker thread every 10 s that immediately fails. That thread-creation
/// overhead on the single-core MCU is what made the whole device lag while
/// satsmail was open. QXXX has no such timer. Gate the periodic sync
/// behind `cfg(not(keyos))`: on hardware the inbox is updated only via QR
/// scan; on the hosted simulator the live electrum feed keeps it current.
fn spawn_sync_loop(state: &Rc<RefCell<AppState>>, ui: &slint::Weak<AppWindow>) {
    #[cfg(keyos)]
    {
        let _ = (state, ui); // unused on device — inbox is QR-only
        if let Some(ui) = ui.upgrade() {
            ui.global::<Callbacks>()
                .set_sync_status("offline — scan QR to sync".into());
        }
        return;
    }

    #[cfg(not(keyos))]
    {
        let state = state.clone();
        let ui = ui.clone();

        // First sync shortly after launch.
        Timer::default().start(
            TimerMode::SingleShot,
            Duration::from_millis(600),
            {
                let state = state.clone();
                let ui = ui.clone();
                move || {
                    if let Some(ui) = ui.upgrade() {
                        run_sync_once(&state, &ui.as_weak());
                    }
                }
            },
        );

        // Then keep the inbox live.
        let timer = Timer::default();
        timer.start(
            TimerMode::Repeated,
            Duration::from_secs(SYNC_INTERVAL_SECS),
            move || {
                if let Some(ui) = ui.upgrade() {
                    run_sync_once(&state, &ui.as_weak());
                }
            },
        );
        // Keep the timer alive for the lifetime of the app.
        std::mem::forget(timer);
    }
}
