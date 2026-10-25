# Threat model — STRIDE

Scope: SentinelNet v0.1.0 on a single Android device, offline-first, no backend.
Assets: audit log, scan results, pcap files, exported reports, DB passphrase,
user's Wi-Fi passphrase (transient), consent decisions, device integrity.

Trust boundaries:
- **TB1** Android OS / system services ↔ app
- **TB2** local network (untrusted) ↔ app
- **TB3** user ↔ UI (consent, biometric)
- **TB4** app ↔ exported file / share sheet
- **TB5** app ↔ optional online API (opt-in)
- **TB6** app ↔ native code (Rust/JNI, Phase 4)

| STRIDE | Threat | Example | Mitigation | Residual risk |
|---|---|---|---|---|
| **S**poofing | Fake consent decision injected into a ViewModel | Replayed `ConsentDecision` from a previous scan | Single-use nonce + capability + target binding + 10 min TTL + biometric; verified in conformance suite | An attacker with root + memory write can bypass; root detection reports this |
| **S**poofing | Rogue AP impersonating a known SSID | Evil twin with stronger signal | `RogueApDetector`: mixed OUI + >25 dBm outlier heuristics; WPA3-Enterprise advice | Heuristic, not proof; false positives on mesh networks |
| **S**poofing | ARP/DHCP spoofing on the LAN | Gateway MAC change | `NetworkAudit.gatewayChecks`, short-lease DHCP warning, DNS resolver review | Baseline set on first observation (TOFU); user must verify |
| **S**poofing | Untrusted CA installed for TLS interception | MITM proxy CA | User-CA enumeration in device audit; `networkSecurityConfig` trusts system CAs only | User can still install a CA; explicit warning shown |
| **T**ampering | Repackaged APK with the gate removed | Modified app on a third-party store | Play Integrity / signature check planned (Phase 8); Semgrep + structure checks in CI; no exported components except launcher | Not yet enforced at runtime — **open item** |
| **T**ampering | Editing the audit log after the fact | Delete rows to hide an unauthorised scan | Append-only DAO (no update/delete by id), SQLCipher at rest, SHA-256 report chain-of-custody | `clear()` exists for the "delete all data" privacy feature — this is user-visible |
| **T**ampering | Malicious packet crashes the parser | Crafted IPv4 header with tiny IHL | Bounds checks on every offset, `Truncated` returns null, Rust crate has no `unsafe`, fuzz target planned | Unbounded recursion in DNS compression pointers is capped at 16 jumps |
| **R**epudiation | User denies having run a scan | "I never scanned that subnet" | Every allowed *and denied* attempt audited with UTC time, capability, target, scope, session | Local log can be deleted via Settings — intentional privacy feature |
| **I**nformation disclosure | Leaking scan results / pcap | Cloud backup, logcat, exported files | `allowBackup=false`, data-extraction exclusions, no payload logging, EncryptedFile exports, SQLCipher DB | pcap in Phase 4 currently written plain to `filesDir/captures` — **open item, fix before release** |
| **I**nformation disclosure | Collecting device identifiers | IMEI/IMSI via TelephonyManager | Banned in code; Semgrep + `verify_project.py` enforce the ban; manifest omits phone-state permissions | None in this build |
| **I**nformation disclosure | Leaking the user's Wi-Fi passphrase | Lab logs or crash report | Kept in memory only, never logged/persisted; no crash-reporting SDK | Memory dump on a rooted device |
| **D**enial of service | Scan floods the LAN or drains battery | 65 535 ports × 512 threads | `RateLimiter` (12 invasive actions/min), `/24` sweep cap (1024 hosts), `MAX_CANDIDATES`/`MAX_LAB_MILLIS` lab caps, WorkManager for periodic work | A determined user can still lower settings; documented battery cost |
| **D**enial of service | VpnService breaks connectivity | Capture routes all traffic with no forwarding | Lab subnet only (`10.222.222.0/24`); real traffic unaffected; transparent forwarding deferred | None in this build |
| **D**enial of service | Memory exhaustion during capture | Millions of flows | `FlowTracker` bounded at 10 000 flows with eviction; streaming parse, no payload retention | Long captures still write pcap to disk — quota needed in Phase 4 |
| **E**levation of privilege | Another app starts an invasive engine | Exported component abuse | No exported components except launcher; VpnService `exported=false` + `BIND_VPN_SERVICE`; signature permission for bound services | Content provider grants URIs on explicit share only |
| **E**levation of privilege | Root/Shizuku misuse | Hidden su shell | No root/shizuku code in this build; capability declares the requirement; no shell exec except `getprop` | Future root features need a separate review |

## Mitigation matrix (priority)

| Priority | Action | Owner phase |
|---|---|---|
| P0 | Encrypt pcap files with EncryptedFile (currently plain in `filesDir`) | Phase 4 |
| P0 | Runtime signature / Play Integrity check | Phase 8 |
| P0 | Keep Safe Mode default ON and legal notice versioned | Done |
| P1 | Fuzz the Rust and Kotlin parsers with `cargo-fuzz` / randomised JVM inputs | Phase 4 |
| P1 | Per-export biometric re-auth and file quota | Phase 4 |
| P1 | Certificate pinning with real SPKI hashes for opt-in APIs | Phase 8 |
| P2 | Separate VPN session manager so capture and firewall cannot conflict | Phase 3 |
| P2 | Signed audit-log hash chain (Merkle) so deletion is detectable | Phase 8 |
