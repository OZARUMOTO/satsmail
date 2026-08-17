// SPDX-FileCopyrightText: 2026 Michael Totten <mike@ozaru.io>
// SPDX-License-Identifier: GPL-3.0-or-later
//
// WALLET — the cold-signing core of SATSMAIL.
//
// The device seed never leaves the secure element; this module reads the
// app-scoped seed once at startup (Security::app_seed — GetAppSeed, the only
// seed message a sideloaded app can be granted; the master seed GetSeed is
// ungrouped and Foundation-only), derives the BIP-0086 taproot (P2TR)
// descriptors, and builds an in-memory bdk wallet. Addresses come from
// `peek_address` (indexed, deterministic — `bc1p…`), signing goes through the
// same bdk wallet (key-path taproot spends), and PSBT validation uses
// ngwallet's `psbt::validate` against the master key so every input/output is
// checked against OUR derivation before it is shown or signed.
//
// TAPROOT ONLY: this wallet is deliberately single-script-type. It derives
// the BIP-86 account only — no legacy/segwit branch. Anything previously on
// satsmail's (app-scoped) BIP-84 addresses is intentionally not tracked;
// satsmail was set up fresh, so there is nothing to orphan.
//
// IMPORTANT: because the wallet derives from the APP-SCOPED seed (a
// deterministic per-app key, not the raw device seed), satsmail's wallet is
// its own — distinct from the built-in bitcoin app/Envoy wallet (taproot or
// otherwise). The companion's bwt must track THIS wallet's xpub (see
// `account_xpub`) for the inbox to see satsmail's funds. The built-in wallet
// never sees them, and vice versa.
//
// Nothing here persists: no redb, no account store. The wallet is rebuilt on
// demand from the master key, exactly like the bitcoin app does when it opens
// an account, minus the files.

use anyhow::Context;
use ngwallet::{
    bdk_wallet::{
        bitcoin::{
            bip32::{DerivationPath, Xpriv},
            secp256k1::Secp256k1,
            Network, Psbt,
        },
        KeychainKind, SignOptions, Wallet,
    },
    bip39::get_descriptors,
};
pub use ngwallet::bip39::MasterKey;

/// The account index. bwt on the box tracks xpub/84'/0'/0', so account 0.
pub const ACCOUNT_INDEX: u32 = 0;

/// How many addresses to scan in each direction during an inbox sync.
pub const LOOKAHEAD_EXTERNAL: u32 = 20;
pub const LOOKAHEAD_INTERNAL: u32 = 10;

/// Load the device app-scoped seed from the secure element.
///
/// Uses `app_seed()` (GetAppSeed), NOT `seed()` (GetSeed): the master seed is
/// ungrouped -> Foundation-only in the 1.4.0 permission model, so the kernel
/// denies it to sideloaded apps. GetAppSeed carries the
/// `device-secrets.app-scoped-seed` permissionGroup (grantOnFirstUse) and
/// returns a deterministic per-app seed derived from the device master seed.
///
/// Callers must gate this behind the app being foregrounded and wrap it in
/// `catch_unwind` — the SDK's blocking-archive wrapper panics if the kernel
/// refuses delivery while the grant is still pending.
pub fn load_master(network: Network) -> anyhow::Result<MasterKey> {
    let secp = Secp256k1::new();
    let security = crate::Security::default();
    let seed = security
        .app_seed()
        .context("reading app-scoped seed from secure element")?;
    MasterKey::from_entropy(&secp, network, seed.as_bytes(), "", None).context("derive master key")
}

/// Build an in-memory bdk wallet from the master key, using the taproot
/// (BIP-0086) descriptors for the given network + account index. TAPROOT
/// ONLY — this is the single script type satsmail tracks.
pub fn build_wallet(network: Network, master: &MasterKey) -> anyhow::Result<Wallet> {
    let descriptors = get_descriptors(&master.key.0, network, ACCOUNT_INDEX)
        .context("derive descriptors")?;
    // get_descriptors returns templates in order: 49, 44, 84, 86, 48_1, 48_2.
    let bip86 = descriptors
        .iter()
        .find(|d| d.bip() == "86")
        .ok_or_else(|| anyhow::anyhow!("BIP-0086 template missing"))?;

    // Descriptors carry the private keys (xprv), so the wallet can sign
    // key-path taproot spends.
    Wallet::create(
        bip86.descriptor_xprv(),
        bip86.change_descriptor_xprv(),
    )
    .network(network)
    .create_wallet_no_persist()
    .context("create wallet")
}

/// The BIP-86 account-0 xpub for this wallet — the exact string the box's
/// bwt needs to watch it (`bwt --descriptor 'tr(<xpub>)'` — taproot cannot
/// use the `:wpkh` shorthand). Satsmail's wallet derives from the app-scoped
/// seed, so this is NOT the built-in wallet's xpub: the companion must track
/// THIS one for the inbox to see satsmail's funds.
pub fn account_xpub(network: Network, master: &MasterKey) -> anyhow::Result<String> {
    let secp = Secp256k1::new();
    let xpriv: Xpriv = Xpriv::new_master(network, &master.key.0).context("master xpriv")?;
    let coin: u32 = if network == Network::Bitcoin { 0 } else { 1 };
    let path: DerivationPath = format!("m/86'/{coin}'/{ACCOUNT_INDEX}'")
        .parse()
        .context("parse account derivation path")?;
    let account = xpriv
        .derive_priv(&secp, &path)
        .context("derive account xpriv")?;
    Ok(ngwallet::bdk_wallet::bitcoin::bip32::Xpub::from_priv(&secp, &account).to_string())
}

/// Deterministically derive the external (receive) address at `index`.
pub fn receive_address(wallet: &Wallet, index: u32) -> String {
    wallet.peek_address(KeychainKind::External, index).address.to_string()
}

/// Sign a PSBT with the device keys. Returns whether any input was signed.
///
/// `try_finalize` is set like ngwallet does so `extract_tx()` works for the
/// compose-send broadcast path (a finalized PSBT still round-trips fine as a
/// UR2 psbt for the wallet-scan path).
pub fn sign_psbt(network: Network, master: &MasterKey, psbt: &mut Psbt) -> anyhow::Result<bool> {
    let wallet = build_wallet(network, master)?;
    let options = SignOptions {
        trust_witness_utxo: true,
        try_finalize: true,
        ..SignOptions::default()
    };
    wallet.sign(psbt, options).context("sign psbt")
}

/// All the script_pubkeys (as hex) for the external and internal lookahead
/// windows. Used by the inbox sync to recognize "our" scripts inside any
/// transaction, exactly like the vault auto-discovery does.
pub fn our_scripts(network: Network, master: &MasterKey) -> anyhow::Result<(Vec<String>, Vec<String>)> {
    let wallet = build_wallet(network, master)?;
    let mut external = Vec::new();
    for i in 0..LOOKAHEAD_EXTERNAL {
        let addr = wallet.peek_address(KeychainKind::External, i);
        external.push(hex::encode(addr.address.script_pubkey().to_bytes()));
    }
    let mut internal = Vec::new();
    for i in 0..LOOKAHEAD_INTERNAL {
        let addr = wallet.peek_address(KeychainKind::Internal, i);
        internal.push(hex::encode(addr.address.script_pubkey().to_bytes()));
    }
    Ok((external, internal))
}
