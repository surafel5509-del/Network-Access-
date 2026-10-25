# Roadmap & honest status

Legend: ✅ implemented & tested · 🟡 partial / scaffold · 🔴 not started

## Phase 1 — Foundation ✅
- [x] Multi-module Gradle project, version catalog, wrapper, CI, Semgrep
- [x] Hilt, Compose Material 3 design system, RTL (English + Amharic)
- [x] Onboarding with versioned legal notice and fail-closed Safe Mode
- [x] ConsentGate, capability registry, target validator, rate limiter, audit log
- [x] SQLCipher Room DB, Keystore, EncryptedSharedPreferences, EncryptedFile
- [x] Wi-Fi engine (scan, security parse, channel advisor, OUI, evil-twin hints)
- [x] Dashboard, Wi-Fi screen, settings, reports

## Phase 2 — Network analysis ✅ (mostly)
- [x] TCP Connect port scanner with presets, concurrency, banner grab, TLS subject
- [x] Passive CVE hinting with NVD links
- [x] Device discovery (ARP, ICMP, SSDP, fingerprinting)
- [x] Reproducible security score; JSON/CSV reports; generated sample reports
- [x] Ping, DNS lookup, HTTP headers, RDAP (opt-in)
- [ ] TCP/IP stack active probing / OS fingerprinting (root-only)
- [ ] Traceroute / MTR (need raw sockets or a TTL-settable socket)
- [ ] Force-directed topology map UI
- [ ] IPv6 scanning and UDP scan

## Phase 3 — Security audit ✅ / 🟡
- [x] Wi-Fi encryption audit, WPS, open-port risk
- [x] Gateway-MAC change, DNS resolver and rogue-DHCP heuristics
- [x] Device audit (root, patch, SELinux, lock, biometrics, ADB, user CAs, a11y)
- [x] Security score with category breakdown + remediation plan
- [x] Historical score table
- [ ] App permission matrix / trackers / exported components (needs a compliant
      alternative to `QUERY_ALL_PACKAGES`)
- [ ] Firewall / DNS sinkhole (needs a shared VPN session manager, ADR-0004)
- [ ] Threat intel APIs (NVD / CISA KEV / user-supplied keys)
- [ ] ARP spoofing / DNS leak / IPv6 RA / MITM detection as active tests

## Phase 4 — Packet capture 🟡
- [x] VpnService lab capture, raw IP packet reading
- [x] Protocol dissectors (IPv4/IPv6/TCP/UDP/ICMP/DNS/HTTP/TLS/SSDP/mDNS/DHCP/QUIC hint)
- [x] 5-tuple flow tracking, top talkers, capture filter
- [x] pcap export (LINKTYPE_RAW), Rust native parser + tests
- [x] Consent gating with biometric requirement
- [ ] **Transparent forwarding (tun2socks)** — required to capture real traffic
      without breaking connectivity. This is the main blocker.
- [ ] JNI bridge to the Rust parser + ABI builds
- [ ] EncryptedFile pcap storage (P0 threat-model item)
- [ ] pcapng, BPF compiler UI, HAR export, per-app attribution
- [ ] MITM proxy with user-installed CA (compliance review required)

## Phase 5 — Multi-network engines 🔴
BLE/BLE GATT, beacons/AirTag detection, NFC NDEF + tech enumeration, cellular
metrics (non-sensitive only), Wi-Fi Direct, USB Ethernet. Interfaces exist;
implementations are `PlannedEngine` placeholders.

## Phase 6 — Servers & offline messaging 🔴
Ktor HTTP/WS/FTP/WebDAV/SSH servers, file sharing, mesh messaging, X25519 +
AES-256-GCM E2E encryption. Interfaces exist; not implemented. Note: servers
must bind loopback/LAN only with a biometric gate and random first-run tokens.

## Phase 7 — Advanced tools & automation 🔴
QuickJS/Lua scripting, event triggers, OSINT recon (crt.sh, HIBP, user keys),
forensics timeline + signed evidence capture.

## Phase 8 — Hardening & release 🔴
Runtime signature/Play Integrity check, real certificate pins, PDF reports,
scheduled WorkManager reports, performance tuning, fuzzing, full accessibility
audit, >70 % domain coverage on all modules, Play Console declarations.

## Explicitly NOT planned

- A live Wi-Fi cracker / deauth tool / handshake capture-from-air. See
  [SECURITY_LAB.md](SECURITY_LAB.md) for the offline educational alternative.
- Any exploitation module, payload delivery or credential brute-forcing against
  third-party services.
- Collection of IMSI/IMEI/serial/advertising ID.
