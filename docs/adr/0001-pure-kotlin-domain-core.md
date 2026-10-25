# ADR-0001 — A pure-Kotlin, dependency-free domain core

**Status:** Accepted · **Date:** 2026-10-25

## Context
The spec calls for Clean Architecture, a testable domain layer, native hot paths
and >70 % domain test coverage. Android unit tests normally need Robolectric or
an emulator, which makes the most safety-critical logic (consent gating,
scoring, crypto) the hardest to verify quickly.

## Decision
Put all business rules in `:core:pure` — a JVM-only Kotlin module with **zero**
Android and zero third-party dependencies. It contains the models, the consent
gate, scoring, channel analysis, OUI lookup, CVE hints, the WPA lab, packet
parsing, pcap writing and JSON/CSV reporting. A self-contained conformance suite
(`ConformanceSuite.kt`) runs with `kotlinc` + a JDK alone, or via
`./gradlew :core:pure:conformance`.

## Consequences
- ✅ The legal gate and crypto can be reviewed and tested without an emulator.
- ✅ Deterministic, reproducible reports (no reflection, stable field order).
- ✅ CI has a fast feedback job that needs no Android SDK.
- ❌ Some duplication with Android APIs (e.g. `java.util.Base64` instead of
  `android.util.Base64`) — accepted.
- ❌ No kotlinx.serialization in the core; a small JSON writer is maintained.

## Alternatives considered
- Kotlin Multiplatform — unnecessary for an Android-only app.
- Robolectric domain tests — slower, hides Android coupling.
