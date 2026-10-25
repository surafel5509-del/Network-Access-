# SentinelNet User Manual (v0.1.0 — foundation)

## 1. Install and first launch

1. Install the debug APK (or run from Android Studio) on a device with Android
   8.0 (API 26) or newer.
2. Grant location permission — Android requires it for Wi-Fi scanning. Grant
   notification permission on Android 13+ so capture status is visible.
3. Read the **Authorized use only** notice, switch the acknowledgement on, then
   tap **Accept the rules and continue**.
4. The app opens in **Safe Mode**. All invasive features are disabled. Only turn
   Safe Mode off in Settings when you are about to test a network you own.

## 2. Dashboard

- **Security score** — a weighted 0–100 score with a grade. It is computed from
  passive findings; the same findings always give the same score and fingerprint.
- **Quick actions** — refresh the Wi-Fi scan, run a full audit, open the Security
  Lab, or open Reports.
- **Recent alerts** — the top five findings by severity.
- **Modules** — shows each engine and whether it is Ready, Permission-blocked,
  Consent-required or Planned. Planned modules are honest placeholders.

## 3. Wi-Fi

Tap **Run Wi-Fi scan**. For each network you see SSID, BSSID, RSSI, channel,
band, security type, standard and vendor (from the bundled OUI table). The
**Best channel** card recommends 1/6/11 on 2.4 GHz based on a signal-weighted
congestion model — useful when your own router is on a crowded channel.

The **Security findings** card flags open networks, WEP, WPA/TKIP, WPS, hidden
SSIDs and possible evil twins (mixed vendor OUIs or an unusually strong clone).
These are hints, not proof — verify with the network owner.

## 4. Scanner

1. Enter the target IP (default `192.168.1.1`) and choose a port preset.
2. Tap **Start port scan**. A consent dialog appears.
3. Read the four statements, choose the authorisation scope, and confirm. If the
   capability needs biometrics, tap the biometric button first.
4. Results stream in as ports are probed. CVE hints are passive version-string
   matches with a link to NVD — they are **not** confirmed vulnerabilities.

**Discover devices** runs an ARP/ICMP sweep of a `/24` plus an SSDP probe.
Public targets require a second acknowledgement and a written justification.

If Safe Mode is ON the scan is denied and the denial is written to the audit log.

## 5. Audit

**Run security audit** collects Wi-Fi, network and device findings and computes
the category breakdown. **Prioritised remediation** lists fixes in severity
order. The **Audit trail** card shows the last 50 events; export the full log
from Settings.

## 6. Security Lab (read the disclaimer)

See [SECURITY_LAB.md](SECURITY_LAB.md) for the full tutorial. In short: generate
a synthetic handshake, check your own passphrase, and run a capped offline
exercise with your own wordlist. Biometric confirmation and full consent are
required. The app cannot capture real handshakes.

## 7. Reports

Exports are JSON/CSV files written to the app's private storage using
`EncryptedFile`. Sample reports are in [docs/samples](samples/). JSON reports
carry a SHA-256 chain-of-custody hash. To get a file off the device, use the
share sheet (Phase 4 adds a direct share action).

## 8. Settings

- **Safe Mode** (default ON) — disables port scans, discovery, capture,
  firewall, MITM and the Security Lab.
- **High contrast / AMOLED** — accessibility themes. RTL layout is automatic
  for Amharic, Arabic and Hebrew locales.
- **Opt-in online lookups** — off by default; enables RDAP and (later) CVE /
  threat-intel lookups. Every call is audited.
- **Export audit log / Delete all local data** — privacy controls.

## 9. Battery and data cost

| Feature | Typical cost |
|---|---|
| Wi-Fi scan | one binder call; OS throttles to ~4 scans / 2 min |
| Port scan (Top 100, /32) | ~1–3 s, 100 sockets, a few KB |
| /24 discovery | ~2–10 s, up to 254 probes |
| Security audit | <1 s, passive reads |
| Lab exercise | CPU-bound, hard-capped at 30 s |
| VpnService capture | ~1–3 % battery/hour depending on traffic (lab subnet only) |

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| "Permission" chip on Wi-Fi | Grant location permission and enable Wi-Fi |
| Scan denied: `SAFE_MODE_BLOCKS_INVASIVE` | Turn Safe Mode off in Settings, then retry |
| Scan denied: `NONCE_ALREADY_USED` | Start the action again — a fresh nonce is created each time |
| `LEGAL_NOTICE_NOT_ACCEPTED` after an update | Re-read and accept the updated legal notice |
| Biometric button unavailable | Enroll a fingerprint/device credential in Android Settings |
| No networks listed | Check location + Wi-Fi, then pull to refresh on the Dashboard |
