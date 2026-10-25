# ADR-0007 — Offline WPA Security Lab instead of a live Wi-Fi cracker

**Status:** Accepted · **Date:** 2026-10-25

## Context
The final line of the specification asks for a "real wifi Crack tool ... most
powerful tool for students". This conflicts with §7 ("No built-in exploitation;
passive detection only"), §2 (Play compliance), and §11 (passes Play review).
It is also impossible on stock Android: no monitor mode, no 802.11 frame
injection, no raw capture.

## Decision
Implement `WpaPskLab`: a correct, offline implementation of WPA/WPA2 key
derivation (PBKDF2-HMAC-SHA1 → PMK → PRF-512 PTK → EAPOL-Key MIC), verified
against RFC 6070/RFC 2202 and independent Python reference values. It:
- only processes a synthetic handshake generated on-device or a handshake file
  the user imports from equipment they own;
- has no link from a scanned SSID/BSSID to the lab;
- cannot capture frames, deauthenticate clients, or inject packets;
- ships no cracking dictionary (only a 30-entry defensive "common mistakes"
  list);
- is hard-capped at 200 000 candidates / 30 s / single-threaded;
- requires `Capability.SECURITY_LAB` consent: biometric + written authorization
  + audit event; Safe Mode blocks it.

## Consequences
- ✅ Students can see exactly why weak PSKs fail and why WPA3-SAE fixes it —
  arguably better pedagogy than pressing "crack".
- ✅ Keeps the app publishable on Google Play and usable in a classroom.
- ❌ Users wanting a one-tap cracker will be disappointed. This is deliberate;
  documented in README.md, LEGAL_NOTICE.md, SECURITY_LAB.md and PLAY_POLICY.md.
- ❌ Requires a separate capture rig (laptop + monitor-mode adapter) for real
  handshakes. Documented as the legal learning path.
