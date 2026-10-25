# Privacy Policy

**Effective: 2026-10-25 · SentinelNet v0.1.0**

## Short version

SentinelNet is **offline-first and local-first**. Everything it learns about
your networks stays on your device in an encrypted database. There is no
account, no advertising, no analytics SDK, and no telemetry. We (the project)
receive nothing.

## What the app stores locally

| Data | Purpose | Protection |
|---|---|---|
| Audit log (capability, target IP, decision, timestamp, session id) | Prove authorised use | SQLCipher AES-256, append-only |
| Wi-Fi scan results | Analysis, channel advice | In memory; optional saved-network table |
| Discovered devices / open ports | Your scan results | In memory; explicit export only |
| Packet captures | Your capture | `filesDir`, EncryptedFile in Phase 4 |
| Reports and exports | Your records | EncryptedFile AES-256-GCM |
| Settings (Safe Mode, legal notice version, theme) | App behaviour | DataStore; secrets in Keystore-backed EncryptedSharedPreferences |
| Security score history | Trend chart | SQLCipher |

## What we never collect

- IMSI, IMEI, MEID, device serial, MAC of the phone itself, advertising ID,
  phone number, contacts, SMS, call logs, precise GPS trace.
- Raw packet payloads in logs or analytics. Only pcap files you explicitly
  export contain payload bytes.
- Your Wi-Fi passphrase. The Security Lab holds typed text in memory only and
  never persists, transmits or logs it.

The manifest deliberately omits `READ_PHONE_STATE`,
`READ_PRIVILEGED_PHONE_STATE`, `QUERY_ALL_PACKAGES`, `ACCESS_BACKGROUND_LOCATION`
and `PACKAGE_USAGE_STATS` from this build. CI enforces this with Semgrep and
`scripts/verify_project.py`.

## Network requests (opt-in only)

By default SentinelNet makes **no** outbound requests other than the user's own
scans. If you enable "Online features" in Settings, the following may be used:

- `rdap.org` — RDAP/WHOIS for a domain you type.
- `nvd.nist.gov` — CVE detail links (opened in your browser, not fetched).
- User-configured endpoints for threat intel (VirusTotal, AbuseIPDB, Shodan) —
  only if you supply your own API key. Keys are stored in Keystore-backed prefs.

Online features are off by default, every call is audited, responses are cached
locally, and no request includes identifiers about you or your device. To disable
completely: Settings → Online features → Off. To erase everything: Settings →
Delete all local data.

## Third-party SDKs

None for analytics, ads, crash reporting or attribution. Open-source libraries
used at build time are listed in [DEVELOPER_GUIDE.md](DEVELOPER_GUIDE.md).

## Data sharing

Exports (JSON/CSV/pcap/PDF) are files on your device. Sharing them is a manual
action through Android's share sheet. SentinelNet has no server, no backend and
no upload endpoint.

## Children

SentinelNet is a professional security tool intended for adults and supervised
students. It is not directed at children under 16.

## Changes

Material changes to this policy bump `CURRENT_NOTICE_VERSION`, which forces
re-consent at next launch.
