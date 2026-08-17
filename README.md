# Sats Mail

A retro 2009 email client that happens to be a Bitcoin wallet — **taproot only
(BIP-86)**. Sideloadable on Passport Prime. Fully offline on-device; the
inbox/balance syncs by scanning an animated QR served by a companion that talks
to bwt.

## Build

```bash
cd satsmail
foundation develop          # SDK-user Nix shell
foundation build -r         # compile + stage + sign → target/keyos/satsmail/
foundation pack -r          # → target/keyos/satsmail.app (installable archive)
```

Copy `target/keyos/satsmail.app` to a USB drive or the airlock, then install on
the Prime from **Settings → Apps → Install App**.

## Publisher

Sats Mail is signed with the **OZARUMOTO** publisher identity. See
[`PUBLISHER.md`](PUBLISHER.md) for the canonical publisher fingerprint and how
to verify it before allowing this publisher on hardware.

## License

GPL-3.0-or-later. Copyright 2026 Michael Totten <mike@ozaru.io>.
