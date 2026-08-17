# OZARUMOTO — Publisher Verification

This repository is the official out-of-band channel for verifying the OZARUMOTO
publisher identity used to sign Sats Mail (and future apps) for Passport Prime.

## Publisher identity

- **Name:** OZARUMOTO
- **Contact:** mikegotbtc@ozarumoto.dev
- **Support:** https://github.com/OZARUMOTO

## Canonical publisher fingerprint

```
Full:  43ea657dccce837db04339ad1bad565306903ec2d2cfe93bc2bda7479d4da7dd
Short: 43ea657d…9d4da7dd
```

The fingerprint is the SHA-256 digest of the compressed 33-byte secp256k1
public key, rendered as 64 lowercase hex characters. The short form (first and
last four bytes) is for recognition only — **compare the full fingerprint** when
allowing this publisher on hardware.

## How to verify

On Passport Prime, when Settings prompts to allow the OZARUMOTO publisher,
compare the fingerprint shown on the device against the one above. The device
displays the certificate's fingerprint before import; both passport-drive and
the firmware re-parse and verify the certificate before it is stored.

## DNS TXT convention

KeyOS v1 does not retrieve or verify this record — it is a publication
convention intended as a stable home for a future attestation service:

```text
_keyos-publisher.ozarumoto.dev TXT "v=1; k=secp256k1; fp=43ea657dccce837db04339ad1bad565306903ec2d2cfe93bc2bda7479d4da7dd"
```

## Signing identity

The signing material lives in `~/.foundation/signing/OZARUMOTO/`
(`certificate.crt`, `private.pem`, `public.pub`, `cosign2.toml`).
`app-config.toml` sets `signing-identity = "OZARUMOTO"`; builds are produced
with `foundation build -r && foundation pack -r`.
