# SentinelNet Security Lab (offline WPA-PSK teaching tool)

## Purpose

Section 7 of the specification asks for "a real WiFi crack tool ... most
powerful tool for students". This document explains the compliant alternative
that was built, why, and how to use it for real learning.

**Read [LEGAL_NOTICE.md](LEGAL_NOTICE.md) first.** Everything below applies only
to networks you own or are explicitly authorised to test.

## What it is

`WpaPskLab` (`:core:pure`) is a clean-room implementation of the WPA/WPA2
personal-mode key schedule:

```
PMK = PBKDF2-HMAC-SHA1(passphrase, SSID, 4096 iterations, 32 bytes)   [802.11i]

PTK = PRF-512(PMK,
        "Pairwise key expansion" || 0x00 ||
        Min(AA,SPA) || Max(AA,SPA) ||
        Min(ANonce,SNonce) || Max(ANonce,SNonce))                       [4 HMAC-SHA1 blocks]

KCK = PTK[0..15]
MIC = HMAC-MD5(KCK, EAPOL_frame_with_zeroed_MIC)     for WPA  (KDV 1 / TKIP)
MIC = HMAC-SHA1(KCK, EAPOL_frame_with_zeroed_MIC)[0..15] for WPA2 (KDV 2 / CCMP)
```

These are the exact computations a password-recovery tool performs to test one
candidate. Seeing them run is the lesson.

**Verification:** the implementation is checked against RFC 6070 PBKDF2 vectors,
RFC 2202 HMAC-SHA1, and PMK/PTK/KCK/MIC values independently computed with
Python's `hashlib`/`hmac` (see the conformance suite). It is correct, not a toy
approximation.

## What it is NOT

| Not present | Why |
|---|---|
| Monitor mode / promiscuous capture | Android hardware and the public SDK do not expose it. The app never tries. |
| Deauthentication / disassociation frames | Active attack against third parties; illegal without consent and a Play policy violation. |
| Handshake capture from nearby networks | Same as above. The lab has **no path** from a scanned SSID/BSSID to a handshake. |
| Bundled cracking wordlists | The app ships a 30-entry list of *common mistakes* for defensive strength checks only. |
| GPU/cloud/distributed cracking | Deliberately single-threaded and slow. |
| Any automatic targeting | The user supplies a file or generates a synthetic sample. |

Hard caps: `MAX_CANDIDATES = 200_000`, `MAX_LAB_MILLIS = 30_000`. On a phone
that is a few thousand candidates per minute — enough to demonstrate the
weakness of `password123`, useless for attacking real networks.

## Tutorial (10 minutes)

1. Launch the app, accept the legal notice, go to **Security Lab**.
2. Tap **Generate a synthetic lesson**. This creates a fake EAPOL handshake for
   SSID `SentinelLab` with the deliberately weak passphrase `password123`.
   Nothing was captured from the air.
3. In **Check YOUR OWN passphrase**, type `password123`. The verdict shows 0
   entropy bits (it is in the common-default list) and recommends WPA3 + a long
   random passphrase.
4. Enter a small candidate list in the exercise box, e.g.
   `letmein`, `admin`, `password123`, `correct horse battery staple`.
5. Tap **Run offline exercise**. The consent dialog appears: four
   acknowledgements, scope, biometric confirmation. Confirm.
6. The result shows the matched candidate, number tested and elapsed time.
   Try again with a 5-word Diceware passphrase — no match.
7. Read the "Why WPA3-SAE is different" card: SAE has no offline-guessable
   handshake transcript and gives forward secrecy.

## Using a real handshake from your own network

If you already captured a 4-way handshake on equipment you own (e.g. with a
monitor-mode USB adapter on a laptop running `aircrack-ng`), export the fields
to a plain text file and pick it with **Import my handshake file** (Storage
Access Framework — the app never scans your filesystem).

File format (`#` comments allowed):

```
# SentinelNet lab handshake — AUTHORIZED NETWORK ONLY
ssid=MyHomeLab
ap=00:1A:2B:3C:4D:5E
sta=7C:2E:BD:11:22:33
anonce=<64 hex chars / 32 bytes>
snonce=<64 hex chars / 32 bytes>
eapol=<hex of the EAPOL-Key frame with its MIC field zeroed>
mic=<32 hex chars / 16 bytes>
kdv=2
```

`kdv` is 1 for WPA/TKIP (HMAC-MD5 MIC) or 2 for WPA2/CCMP (HMAC-SHA1/128).
KDV 3 requires AES-CMAC and is explicitly refused rather than guessed. Only
even-length hex is accepted; malformed files are rejected without crashing.

You can generate a valid example file from a synthetic sample by exporting the
`security_lab_walkthrough.json` sample report's fields.

## Consent requirements

`Capability.SECURITY_LAB` is invasive, requires biometric verification, and is
blocked by Safe Mode. The `ConsentDialog` requires the user to assert ownership
or written authorisation, and every exercise (allowed or denied) is written to
the SQLCipher audit log. There is no way to start an exercise from the Wi-Fi
scanner screen.

## Recommended further study (legal)

- Set up your own isolated lab router; never test a neighbour's or a public
  hotspot's network.
- Compare WPA2-PSK vs WPA3-SAE capture resistance.
- Read IEEE 802.11i / RFC 6070 / WPA3-SAE (Dragonfly handshake) specifications.
- Use Wireshark to inspect the EAPOL-Key frames you captured on your own gear.
