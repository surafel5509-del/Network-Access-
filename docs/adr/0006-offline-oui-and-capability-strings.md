# ADR-0006 — Offline-first vendor and security identification

**Status:** Accepted · **Date:** 2026-10-25

## Context
Wi-Fi vendor lookup and security-type classification must work offline (spec:
offline-first). `WifiManager` provides a localised `capabilities` string on some
OEMs and no vendor name at all.

## Decision
- Ship a small bundled OUI table (`OuiLookup.SEED`) covering common
  infrastructure vendors; layer an updateable `assets/oui.csv` on top in Phase 5.
- Refuse vendor lookup for locally-administered (randomized) MACs — returning a
  vendor for a random address would be wrong.
- Parse security from uppercased ASCII capability tokens in a pure, unit-tested
  parser (`WifiCapabilitiesParser`), most-specific-first (SAE → OWE → EAP →
  WPA2 → WPA → WEP → WPS → OPEN).
- Privacy: no online MAC-vendor API unless the user explicitly enables online
  features.

## Consequences
- ✅ Works in airplane mode; deterministic results.
- ❌ Incomplete vendor coverage until the updateable DB ships.
- ❌ OEM-specific capability strings may still misclassify; reported as
  `UNKNOWN` rather than guessed.
