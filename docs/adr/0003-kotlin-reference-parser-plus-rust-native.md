# ADR-0003 — Two packet parsers: Kotlin reference + Rust hot path

**Status:** Accepted · **Date:** 2026-10-25

## Context
The spec wants Rust for native hot paths (packet parsing) and a native layer
behind a thin JNI facade. But shipping JNI before the grammar is proven leads
to memory-safety bugs and untestable code.

## Decision
- Implement the full metadata grammar in pure Kotlin first
  (`:core:pure/.../pcap`) as the **reference oracle**, with conformance tests
  for IPv4/IPv6/TCP/UDP/ICMP/DNS/Ethernet, DNS compression loops, truncated
  packets, pcap framing and flow tracking.
- Implement the same grammar in the dependency-free Rust crate
  `native/rust/sentinel-parser` with `cargo test` in CI and no `unsafe`.
- Use the Kotlin parser at runtime in the foundation; wire JNI in Phase 4 via
  `scripts/build-native.sh` (cargo-ndk) and a bounds-checked facade.
- Never return payload bytes from either parser.

## Consequences
- ✅ Grammar correctness is verified before native code is on the critical path.
- ✅ The Rust crate is auditable and builds offline.
- ❌ Temporary duplication; the conformance suite must be kept in sync with the
  Rust tests (they use identical synthetic packets).
