# SentinelNet

**A defensive, offline-first network analysis and security-audit suite for Android.**
SentinelNet turns a phone into a portable SOC — but with a hard rule: **every
invasive action needs explicit consent, is logged, and never exploits anything.**

> ⚠️ **Status: foundation build (v0.1.0).** This repository contains a working,
> tested, multi-module Android project implementing Phases 1–3 of the roadmap
> (foundation, network analysis, security audit) plus a real packet parser and
> an offline WPA Security Lab. The remaining modules are present as explicit,
> documented `PlannedEngine` placeholders — the UI shows them as "Planned"
> rather than pretending they work. See [docs/ROADMAP.md](docs/ROADMAP.md).

---

## What is actually implemented

| Area | Delivered | Notes |
|---|---|---|
| **Legal / consent gating** | ✅ Code-enforced `ConsentGate` | Safe Mode, versioned legal notice, single-use nonces, 10-min TTL, biometric, scope checks, rate limits, audit log on *both* allowed and denied actions |
| **Audit log & encrypted storage** | ✅ SQLCipher Room DB, Android Keystore, EncryptedFile | Append-only, exportable, no device identifiers |
| **Wi-Fi engine (A1)** | ✅ Passive scan, security parsing, channel/band analysis, best-channel algorithm, OUI vendor lookup, evil-twin hints, signal graph, captive-portal check | No monitor mode / injection |
| **Wi-Fi security audit (D1)** | ✅ Open/WEP/WPA/WPS audit, rogue-AP heuristics, gateway-MAC change, DNS/DHCP checks | Passive only |
| **Device audit (D2/D3)** | ✅ Root/Magisk indicators, patch level, SELinux, screen lock, biometrics, ADB, user CAs, accessibility services, device admins | Public APIs only |
| **Port scanner (B1/B2)** | ✅ TCP Connect, configurable concurrency, presets, banner grabbing, TLS cert subject, passive CVE hints | No root needed |
| **Discovery (A7)** | ✅ ARP table, ICMP sweep, SSDP, passive fingerprinting, OUI vendor | Consent-gated |
| **Network tools (E1)** | ✅ Ping, DNS, HTTP headers, RDAP (opt-in) | Traceroute/MTR planned (need raw sockets) |
| **Packet capture (C1/C2)** | ✅ VpnService lab capture, IPv4/IPv6/TCP/UDP/ICMP/DNS/TLS/HTTP dissector, 5-tuple flows, pcap export, BPF-like filters, Rust native parser crate | Transparent forwarding (tun2socks) is Phase 4 — see limitation below |
| **Security score & reports (D4/I3)** | ✅ Reproducible weighted 0–100 score, JSON/CSV exports, SHA-256 chain-of-custody, generated sample reports | PDF is Phase 8 |
| **Crypto tools (E3)** | ✅ Hash/HMAC/Base64/Hex/URL, CSPRNG generator, PBKDF2, WPA PSK/PTK/EAPOL-MIC lab | Offline only |
| **Security Lab** | ✅ Offline WPA-PSK derivation lab (see below) | **Not** a live Wi-Fi cracker, by design |
| **UI (I4)** | ✅ Compose + Material 3, dashboard, Wi-Fi, scanner, audit, lab, reports, settings, onboarding, English + Amharic (RTL-ready), TalkBack labels | |
| **CI / SAST** | ✅ GitHub Actions: domain conformance, Android build/lint/tests, Rust clippy/tests, Semgrep, structure invariants | |

**Verified here:** `85/85` pure-Kotlin conformance checks pass, including RFC 6070
PBKDF2 vectors, RFC 2202 HMAC, and WPA PMK/PTK/MIC values cross-checked against
an independent Python implementation. Run it yourself:

```bash
./scripts/verify_domain.sh            # needs only a JDK 17 + Kotlin 1.9 compiler
python3 scripts/verify_project.py     # safety/structure invariants + sample report parsing
./gradlew :core:pure:conformance      # or via Gradle
```

The Android build itself needs the Android SDK (not available in the authoring
sandbox), so [`.github/workflows/ci.yml`](.github/workflows/ci.yml) is the first
full compile check.

---

## The "real Wi-Fi crack tool" request — what I built instead

The spec's final line asks for a "real crack tool ... most powerful tool for
students". I did **not** build a tool that cracks nearby Wi-Fi networks. Three
reasons, in order of importance:

1. **It contradicts the spec's own rules.** §7 says "No built-in exploitation;
   passive detection only", §2 demands Play Store compliance, and §5/§11 require
   passing Google Play review. An app that deauthenticates clients and recovers
   WPA keys from networks in range is the single feature that would be rejected.
2. **It is technically impossible on stock Android.** There is no monitor mode,
   no frame injection, and no raw 802.11 capture without root + a supported
   chipset + a custom driver. A phone cannot do what `aircrack-ng` does on a
   laptop with a USB adapter.
3. **It would mainly be used against other people's networks**, which is exactly
   what the legal notice forbids.

**What I built instead is a genuinely useful teaching instrument:**
[`WpaPskLab`](core/pure/src/main/kotlin/com/sentinelnet/core/crypto/WpaPskLab.kt)
is a standards-correct, offline implementation of IEEE 802.11i key derivation —
PBKDF2-HMAC-SHA1 → PMK → PTK (PRF-512) → EAPOL-Key MIC (HMAC-MD5 / HMAC-SHA1).
Students can:

- generate a **synthetic handshake on-device** (no capture needed),
- verify a candidate passphrase against it and see the real PMK/PTK/MIC bytes,
- run a **capped** offline dictionary exercise (≤200 000 candidates, ≤30 s,
  single-threaded) on a handshake **they already own** and a wordlist **they
  supply**,
- audit their **own** passphrase and learn why WPA3-SAE resists offline guessing.

It cannot capture handshakes from the air, cannot send deauth frames, cannot
target a scanned SSID/BSSID, and has no bundled cracking dictionary. Every lab
run is gated by `Capability.SECURITY_LAB` (biometric + written authorization +
audit event). Full details: **[docs/SECURITY_LAB.md](docs/SECURITY_LAB.md)**.

If you are a student who wants to practise on real hardware, use a laptop with
Kali Linux + a monitor-mode USB adapter on **your own router**, capture the
handshake there, and import the resulting file into this lab for analysis.

---

## Quick start

```bash
git clone <this-repo> && cd Network-Access-
./gradlew :core:pure:conformance       # pure-Kotlin domain tests (no SDK needed)
./gradlew :app:assembleDebug           # needs Android SDK 35 + JDK 17
python3 scripts/verify_project.py      # safety invariants
```

Open in Android Studio (Ladybug+), select the `app` configuration, and run on a
device with API 26+. On first launch you must accept the legal notice; Safe Mode
stays ON until you deliberately turn it off in Settings.

### Project layout

```
core/pure/        Pure Kotlin domain — ZERO Android deps, compiled + tested on a bare JDK
  model/          Canonical models (wire format for engines, exports, API)
  consent/        Capability registry, ConsentGate, AuditLog, TargetValidator, RateLimiter
  domain/         Channel advisor, Wi-Fi audit, rogue AP, OUI, scorer, port risk, CVE hints
  crypto/         PBKDF2/HMAC, WPA PSK lab, passphrase audit, hashes, encoders, CSPRNG
  pcap/           Packet parser, DNS parser, pcap writer, flow tracker, capture filter
  reporting/      Dependency-free JSON writer + CSV/JSON report builders
core/android/     SQLCipher Room DB, Keystore, EncryptedFile, DataStore settings, M3 theme
engine/api/       Stable engine interfaces for ALL modules + honest "Planned" placeholders
engine/wifi/      AndroidWifiEngine
engine/scanner/   TcpConnectScanner, AndroidDeviceDiscovery, NetworkToolsEngineImpl
engine/capture/   SentinelVpnService + VpnCaptureEngine (lab-mode capture)
engine/audit/     Device/network audits, scoring, SecurityLabController
app/              Compose UI, ViewModels, Hilt bindings, onboarding/legal, resources
native/rust/      sentinel-parser crate (metadata hot path) + tests
docs/             Architecture, ADRs, legal, privacy, threat model, Play policy, manuals
docs/samples/     Real example reports generated by the domain code
scripts/          Offline verification + native build helper
```

---

## Non-negotiable safety properties

- **Fail-closed.** Default policy = legal notice not accepted + Safe Mode ON.
  Nothing invasive can run until the user explicitly changes both.
- **One decision = one action.** Nonces are single-use, bound to capability +
  target, expire after 10 minutes, and cannot be replayed (tested).
- **Everything is audited.** Denied attempts too. The log is exportable and
  never contains IMSI/IMEI/serial.
- **No identifiers.** `READ_PHONE_STATE`, `QUERY_ALL_PACKAGES`, IMEI/IMSI APIs
  are absent. A Semgrep rule and `scripts/verify_project.py` enforce this.
- **No exploitation.** CVE hints are version-string *hints* that link to NVD;
  nothing is verified by exploiting a service.

---

## Documentation

| Document | Purpose |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Layers, module graph, dependency rules |
| [ENGINE_APIS.md](docs/ENGINE_APIS.md) | Every engine interface + test plan + Play policy impact |
| [SECURITY_LAB.md](docs/SECURITY_LAB.md) | The WPA lab, its limits, and the handshake file format |
| [LEGAL_NOTICE.md](docs/LEGAL_NOTICE.md) / [PRIVACY_POLICY.md](docs/PRIVACY_POLICY.md) | User-facing legal text |
| [CONSENT_FLOW.md](docs/CONSENT_FLOW.md) | Exactly how gating is enforced in code |
| [THREAT_MODEL_STRIDE.md](docs/THREAT_MODEL_STRIDE.md) | STRIDE analysis + mitigations |
| [PLAY_POLICY.md](docs/PLAY_POLICY.md) | Sensitive permissions, rejection risks, compliant alternatives |
| [USER_MANUAL.md](docs/USER_MANUAL.md) / [DEVELOPER_GUIDE.md](docs/DEVELOPER_GUIDE.md) | Using and extending the app |
| [ROADMAP.md](docs/ROADMAP.md) | Phase-by-phase plan and what is deliberately deferred |
| [adr/](docs/adr/) | Architecture Decision Records |

License: Apache-2.0 with an additional authorized-use term (see [LICENSE](LICENSE)).
